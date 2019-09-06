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

// IDEA: (rafflc) This file handles steady request packets in the
// sibra_srv. Packets are being forwarded to here either by border
// routers (transfer/transit/end AS) or by the client (start AS)

package adm

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/sibra/sbextn"
	"github.com/scionproto/scion/go/lib/sibra/sbreq"
	"github.com/scionproto/scion/go/lib/sibra/sbresv"
	"github.com/scionproto/scion/go/lib/spkt"
	libutil "github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/sibra_srv/conf"
	"github.com/scionproto/scion/go/sibra_srv/sbalgo"
	"github.com/scionproto/scion/go/sibra_srv/util"
)

type SteadyHandler struct{}

//////////////////////////////////////////
// Handle Reservation at the end AS
/////////////////////////////////////////

// TODO: (rafflc) If last hop, check all authenticators and the EPIC fields
// Before sending back, compute all new authenticators as well as EPIC fields
// IDEA: (rafflc) There is no special receiver for requests in a sibra_srv since all
// of it is already handled here.

func (h *SteadyHandler) HandleResvReqEndAS(pkt *conf.ExtPkt, r *sbreq.SteadyReq) error {
	log.Debug("Handling steady request on end AS", "id", pkt.Steady.GetCurrID())
	if err := h.sanityCheckReqEndAS(pkt, r); err != nil {
		return err
	}
	if err := h.validateSibraFields(pkt.Spkt); err != nil {
		return common.NewBasicError("Validation of SIBRA fields failed", err)
	}
	if err := AdmitSteadyResv(pkt, r, nil); err != nil {
		return err
	}
	if err := h.reversePkt(pkt); err != nil {
		return err
	}
	if pkt.Pld.Accepted && !r.EndProps.TelescopeBase() {
		if err := PromoteToSOFCreated(pkt); err != nil {
			return err
		}
	}
	return util.Forward(pkt)
}

func (h *SteadyHandler) sanityCheckReqEndAS(pkt *conf.ExtPkt, r *sbreq.SteadyReq) error {
	down := r.Info.PathType.Reversed()
	if !down && (pkt.Steady.SOFIndex+1 != pkt.Steady.PathLens[0]) {
		return common.NewBasicError("Invalid SOFIndex", nil, "expected",
			pkt.Steady.PathLens[0]-1, "actual", pkt.Steady.SOFIndex)
	}
	if down && (pkt.Steady.SOFIndex != 0) {
		return common.NewBasicError("Invalid SOFIndex", nil, "expected",
			0, "actual", pkt.Steady.SOFIndex)
	}
	return nil
}

func (h *SteadyHandler) HandleIdxConfEndAS(pkt *conf.ExtPkt, r *sbreq.ConfirmIndex) error {
	if err := h.validateSibraFields(pkt.Spkt); err != nil {
		return common.NewBasicError("Validation of SIBRA fields failed", err)
	}
	if err := Promote(pkt, r); err != nil {
		return err
	}
	if err := h.reversePkt(pkt); err != nil {
		return err
	}
	return util.Forward(pkt)
}

func (h *SteadyHandler) validateSibraFields(pkt *spkt.ScnPkt) error {
	// TODO (rafflc) Deal here with check of payload :)
	PldH, err := libutil.Calc32Hash(pkt.Pld.(common.RawBytes))
	if err != nil {
		common.NewBasicError("Computing PldHash failed", err)
	}
	keymac, err := libutil.GetAStoASHashKey("COLIBRI", pkt.DstIA, pkt.SrcIA)
	if err != nil {
		return common.NewBasicError("Unable to derive key", err)
	}
	var steady *sbextn.Steady
	for _, ext := range pkt.HBHExt {
		if ext.Type() == common.ExtnSIBRAType {
			steady = ext.(*sbextn.Steady)
			continue
		}
	}
	if err := steady.ValidateSibraDest(keymac, PldH); err != nil {
		return common.NewBasicError("Invalid SIBRA fields", err)
	}
	return nil
}

////////////////////////////////////
// Handle Reservation at the intermediate AS
////////////////////////////////////

// TODO: (rafflc) Add here checks and updates of authenticators for all functions

func (h *SteadyHandler) HandleResvReqHopAS(pkt *conf.ExtPkt, r *sbreq.SteadyReq) error {
	log.Debug("Handling steady request on hop AS", "id", pkt.Steady.GetCurrID())
	if err := AdmitSteadyResv(pkt, r, nil); err != nil {
		return err
	}
	return util.Forward(pkt)
}

func (h *SteadyHandler) HandleResvRepHopAS(pkt *conf.ExtPkt) error {
	log.Debug("Handling steady response on hop AS", "id", pkt.Steady.GetCurrID())
	if pkt.Pld.Accepted {
		if err := PromoteToSOFCreated(pkt); err != nil {
			return err
		}
	}
	return util.Forward(pkt)
}

func (h *SteadyHandler) HandleIdxConfHopAS(pkt *conf.ExtPkt, r *sbreq.ConfirmIndex) error {
	if err := Promote(pkt, r); err != nil {
		return err
	}
	return util.Forward(pkt)
}

/////////////////////////////////////////
// General functions
/////////////////////////////////////////

//TODO: (rafflc) Add here checks of the hop authenticators

func AdmitSteadyResv(pkt *conf.ExtPkt, r *sbreq.SteadyReq, metricsLables prometheus.Labels) error {
	ifids, err := util.GetResvIfids(pkt.Steady.Base, pkt.Spkt)
	if err != nil {
		return err
	}
	params := sbalgo.AdmParams{
		Ifids:      ifids,
		Extn:       pkt.Steady,
		Req:        r,
		Src:        pkt.Spkt.SrcIA,
		Accepted:   pkt.Pld.Accepted,
		PromLables: metricsLables,
	}
	res, err := pkt.Conf.SibraAlgo.AdmitSteady(params)
	if err != nil {
		return err
	}
	if pkt.Pld.Accepted && !res.Accepted {
		pkt.Pld.Accepted = false
		r.FailHop = pkt.Steady.SOFIndex
		log.Info("Fail reservation", "id", pkt.Steady.GetCurrID())
	}
	if res.AllocBw < r.AccBw {
		r.AccBw = res.AllocBw
	}
	r.OfferFields[pkt.Steady.SOFIndex].AllocBw = res.AllocBw
	r.OfferFields[pkt.Steady.SOFIndex].MaxBw = res.MaxBw
	r.OfferFields[pkt.Steady.SOFIndex].LineLen = sbresv.SOFieldLines
	return nil
}

func (h *SteadyHandler) reversePkt(pkt *conf.ExtPkt) error {
	// FIXME(roosd): Remove when reversing extensions is supported.
	if _, err := pkt.Steady.Reverse(); err != nil {
		return err
	}
	if err := pkt.Spkt.Reverse(); err != nil {
		return err
	}
	if err := pkt.Pld.Reverse(); err != nil {
		return err
	}
	pkt.Spkt.SrcHost = pkt.Conf.PublicAddr.Host
	// TODO (rafflc) Write SIBRA fields at source. Deal with PldHash somehow
	// keymac, err := libutil.GetAStoASHashKey("COLIBRI", pkt.Spkt.DstIA, pkt.Spkt.SrcIA)
	// if err != nil {
	// 	return common.NewBasicError("Unable to derive key", err)
	// }
	payload := make(common.RawBytes, pkt.Pld.Len())
	if _, err := pkt.Pld.WritePld(payload); err != nil {
		return common.NewBasicError("Failed to write payload", err)
	}
	// var steady *sbextn.Steady
	// for _, ext := range pkt.Spkt.HBHExt {
	// 	if ext.Type() == common.ExtnSIBRAType {
	// 		steady = ext.(*sbextn.Steady)
	// 		continue
	// 	}
	// }
	// err = steady.WriteSteadySource(keymac, payload)
	// if err != nil {
	// 	return common.NewBasicError("Unable to write steady reservation in steady_handler", err)
	// }
	return nil
}
