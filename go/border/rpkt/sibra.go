// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rpkt

import (
	"hash"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/scionproto/scion/go/border/metrics"
	"github.com/scionproto/scion/go/border/rcmn"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sibra_mgmt"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/ringbuf"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/sibra/flowmonitor"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
)

type SIBRACallbackArgs interface {
	GetCerealizablePacket() proto.Cerealizable
	Get()
	Put()
}

// External packet is used to encapsulate packets originating outside BR
type SIBRAExternalPacket struct {
	RtrPkt *RtrPkt
}

func (pckt SIBRAExternalPacket) GetCerealizablePacket() proto.Cerealizable {
	return &sibra_mgmt.ExternalPkt{RawPkt: pckt.RtrPkt.Raw}
}

func (pckt SIBRAExternalPacket) Get() {
	pckt.RtrPkt.RefInc(1)
}

func (pckt SIBRAExternalPacket) Put() {
	pckt.RtrPkt.Release()
}

// Internal packet is used by BR to send commands to SIBRA service
type SIBRAInternalPacket struct {
	Payload proto.Cerealizable
}

func (pckt SIBRAInternalPacket) GetCerealizablePacket() proto.Cerealizable {
	return pckt.Payload
}

func (pckt SIBRAInternalPacket) Get() {
	// We don't have ref counting here
}

func (pckt SIBRAInternalPacket) Put() {
	// We don't have ref counting here
}

func (r *RtrPkt) processSibraMgmtSelf(p *sibra_mgmt.Pld) (HookResult, error) {
	u, err := p.Union()
	if err != nil {
		return HookError, err
	}
	switch pld := u.(type) {
	default:
		return HookError, common.NewBasicError("Unsupported destination PathMgmt payload", nil,
			"type", common.TypeOf(pld))
	}
	return HookContinue, nil
}

// VerifySOF validates sibra packets at the border router.
// It is appended to the validation hook for all non segment setup requests
// Validated are:
// - ExpTick
// - TimeStamp
// - SOF
func (s *rSibraExtn) VerifySOF() (HookResult, error) {
	// validate reservation has not expired
	now := time.Now()
	if !now.Before(s.Info().ExpTick.Time()) {
		return HookError, common.NewBasicError("Reservation expired", nil,
			"now", now, "exp", s.Info().ExpTick.Time(), "fwd", s.Forward)
	}

	// REVIEW: (rafflc) Check of timestamp for non segment setup requests

	//validate TimeStamp
	if err := s.validateTimeStamp(); err != nil {
		return HookError, common.NewBasicError("Timestamp incorrect", err)
	}

	// validate SOF of this hop
	pLens := []uint8{s.PathLens[s.CurrSteady]}
	ids := []sibra.ID{s.IDs[s.CurrSteady]}
	if !s.Steady {
		pLens = s.PathLens
		ids = s.IDs
	}
	sofMac := s.rp.Ctx.Conf.SOFMacPool.Get().(hash.Hash)
	err := s.SOF().VerifyHVF(sofMac, s.Info(), ids, pLens, s.PldHash, s.TimeStamp)
	s.rp.Ctx.Conf.SOFMacPool.Put(sofMac)
	if err != nil {
		return HookError, err
	}
	return HookContinue, nil
}

// RouteSibraRequest is added as Routing hook for all sibra request packets
func (s *rSibraExtn) RouteSibraRequest() (HookResult, error) {
	if s.rp.DirFrom == rcmn.DirExternal {
		callbacks.sibraF(SIBRAExternalPacket{RtrPkt: s.rp})
		return HookFinish, nil
	}
	// If the packet is steady setup, there is no reservation block present
	// and it uses a regular scion path.
	if s.Setup {
		return HookContinue, nil
	}
	return s.forwardFromLocal()
}

// RouteSibraData is added as Routing hook for all sibra data packets
func (s *rSibraExtn) RouteSibraData() (HookResult, error) {
	switch s.rp.DirFrom {
	case rcmn.DirExternal:
		return s.forwardFromExternal()
	case rcmn.DirLocal:
		return s.forwardFromLocal()
	default:
		return HookError, common.NewBasicError("Unsupported forwarding DirFrom", nil,
			"dirFrom", s.rp.DirFrom)
	}
}

func (s *rSibraExtn) VerifyLocalFlowBW() (HookResult, error) {
	s.rp.SrcIA()

	flowInfo := flowmonitor.FlowInfo{
		BwCls:            s.Info().BwCls,
		PacketSize:       len(s.rp.Raw),
		ReservationId:    s.IDs[0],
		ReservationIndex: s.Info().Index,
		SourceIA:         s.rp.srcIA,
	}

	if callbacks.bandwidthLimitF(flowInfo, true) {
		return HookError, common.NewBasicError("Reserved bandwidht limit exceeded.", nil)
	} else {
		return HookContinue, nil
	}
}

func (s *rSibraExtn) VerifyTransitFlowBW() (HookResult, error) {
	s.rp.SrcIA()

	flowInfo := flowmonitor.FlowInfo{
		BwCls:            s.Info().BwCls,
		PacketSize:       len(s.rp.Raw),
		ReservationId:    s.IDs[0],
		ReservationIndex: s.Info().Index,
		SourceIA:         s.rp.srcIA,
	}

	if callbacks.bandwidthLimitF(flowInfo, false) {
		return HookError, common.NewBasicError("Reserved bandwidht limit exceeded.", nil)
	} else {
		return HookContinue, nil
	}
}

func (s *rSibraExtn) forwardFromExternal() (HookResult, error) {
	if s.LastHop() {
		if !s.rp.dstIA.Eq(s.rp.Ctx.Conf.IA) {
			return HookError, common.NewBasicError("Destination ISD-AS does not match",
				nil, "expected", s.rp.dstIA.Eq(s.rp.Ctx.Conf.IA), "actual", s.rp.dstIA)
		}
		if s.rp.CmnHdr.DstType != addr.HostTypeSVC {
			ot := overlay.OverlayFromIP(s.rp.dstHost.IP(), s.rp.Ctx.Conf.Topo.Overlay)
			dst := &topology.AddrInfo{
				Overlay:     ot,
				IP:          s.rp.dstHost.IP(),
				OverlayPort: overlay.EndhostPort,
			}
			s.rp.Egress = append(s.rp.Egress,
				EgressPair{s.rp.Ctx.LocSockOut, dst})
		} else {
			if _, err := s.rp.RouteResolveSVC(); err != nil {
				return HookError, err
			}
		}
	} else {
		if s.IsTransfer() {
			if err := s.incTransfer(); err != nil {
				return HookError, err
			}
		}
		if err := s.rp.validateLocalIF(s.rp.ifNext); err != nil {
			return HookError, err
		}
		nextBR := s.rp.Ctx.Conf.Topo.IFInfoMap[*s.rp.ifNext]
		nextAI := nextBR.InternalAddr.PublicAddrInfo(s.rp.Ctx.Conf.Topo.Overlay)
		ot := overlay.OverlayFromIP(nextAI.IP, s.rp.Ctx.Conf.Topo.Overlay)
		dst := &topology.AddrInfo{
			Overlay:     ot,
			IP:          nextAI.IP,
			L4Port:      nextAI.L4Port,
			OverlayPort: nextAI.L4Port,
		}
		s.rp.Egress = append(s.rp.Egress, EgressPair{s.rp.Ctx.LocSockOut, dst})
	}

	if !s.BestEffort {
		metrics.COLIBRIEphTrafficIn.With(
			prometheus.Labels{"direction": "external"}).Add(float64(s.Len()))
	}

	return s.egress()
}

func (s *rSibraExtn) incTransfer() error {
	if err := s.NextSOFIndex(); err != nil {
		return err
	}
	s.rp.ifNext = nil
	if _, err := s.rp.IFNext(); err != nil {
		return err
	}
	_, err := s.VerifySOF()
	return err
}

func (s *rSibraExtn) forwardFromLocal() (HookResult, error) {
	if err := s.NextSOFIndex(); err != nil {
		return HookError, nil
	}
	s.rp.Egress = append(s.rp.Egress, EgressPair{s.rp.Ctx.ExtSockOut[*s.rp.ifCurr], nil})

	if !s.BestEffort {
		metrics.COLIBRIEphTrafficIn.With(
			prometheus.Labels{"direction": "local"}).Add(float64(s.Len()))
	}

	return s.egress()
}

func (s *rSibraExtn) egress() (HookResult, error) {
	s.rp.RefInc(len(s.rp.Egress))
	// Call all egress functions.
	for _, epair := range s.rp.Egress {
		epair.S.Ring.Write(ringbuf.EntryList{&EgressRtrPkt{s.rp, epair.Dst}}, true)
		inSock := s.rp.Ingress.Sock
		if inSock == "" {
			inSock = "self"
		}

		metrics.ProcessSockSrcDst.With(
			prometheus.Labels{"inSock": inSock, "outSock": epair.S.Labels["sock"]}).Inc()
	}
	return HookFinish, nil
}

// validateTimeStamp checks if not too much time since creation of packet has elapsed.
// It does not handle segment setup requests
func (s *rSibraExtn) validateTimeStamp() error {
	now := time.Now()
	var nanoexpiration, nanotimestamp, hops uint64
	//get the number of hops already passed
	if s.Forward {
		hops = uint64(s.CurrHop + 1)
	} else {
		hops = uint64(s.TotalHops - s.CurrHop)
	}
	//convert the expiration tick in the first info field to Nanoseconds
	// first check if empty to avoid nullpointer exception
	if len(s.ActiveBlocks) < 1 {
		log.Debug("Empty packet received", "id", s.IDs, "steady", s.Steady,
			"forward", s.Forward, "BestEffort", s.BestEffort, "Request", s.IsRequest,
			"Version", s.Version, "SOFIndex", s.SOFIndex, "Pathlens", s.PathLens,
			"CurHop", s.CurrHop, "TotalHops", s.TotalHops, "CurrSteady", s.CurrSteady,
			"RelSOFIdy", s.RelSteadyHop, "TotalSteady", s.TotalSteady, "Block", s.ActiveBlocks)
		return nil
	}

	nanoexpiration = uint64(s.ActiveBlocks[0].Info.ExpTick) * sibra.ExpTicktoNano
	//convert the TimeStamp to Nanoseconds
	if s.Steady {
		nanotimestamp = uint64(float64(s.TimeStamp) * sibra.TStoNanoSteady)
	} else {
		nanotimestamp = uint64(float64(s.TimeStamp) * sibra.TStoNanoEphem)
	}
	//get the actual construction time
	constructed := nanoexpiration - nanotimestamp
	//check if too much time elapsed. request packets have more time
	if s.IsRequest {
		if constructed+sibra.MaxRequestHop*uint64(hops) < uint64(now.UnixNano()) {
			return common.NewBasicError("Too much time elapsed since packet construction", nil,
				"now", now, "constructed", time.Unix(0, int64(constructed)))
		}
	} else {
		if constructed+sibra.MaxDataHop*uint64(hops) < uint64(now.UnixNano()) {
			return common.NewBasicError("Too much time elapsed since packet construction", nil,
				"now", now, "constructed", time.Unix(0, int64(constructed)))
		}
	}
	return nil
}
