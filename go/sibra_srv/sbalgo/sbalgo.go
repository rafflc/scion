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

package sbalgo

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/sibra/sbextn"
	"github.com/scionproto/scion/go/lib/sibra/sbreq"
	"github.com/scionproto/scion/go/lib/sibra/sbresv"
)

type Algo interface {
	sync.Locker
	SteadyAdm
	EphemAdm
	ASBlacklist
}

type IFTuple struct {
	InIfid common.IFIDType
	EgIfid common.IFIDType
}

func (i IFTuple) Reverse() IFTuple {
	return IFTuple{
		InIfid: i.EgIfid,
		EgIfid: i.InIfid,
	}
}

func (a IFTuple) Eq(b IFTuple) bool {
	return a.EgIfid==b.EgIfid && a.InIfid==b.InIfid
}

type AdmParams struct {
	Ifids    IFTuple
	Extn     *sbextn.Steady
	Req      *sbreq.SteadyReq
	Src      addr.IA
	Accepted bool
	PromLables prometheus.Labels
}

type CleanParams struct {
	Ifids   IFTuple
	Src     addr.IA
	Id      sibra.ID
	LastMax sibra.Bps
	CurrMax sibra.Bps
	Dealloc sibra.Bps
	Remove  bool
}

type SteadyAdm interface {
	AdmitSteady(params AdmParams) (SteadyRes, error)
	Ideal(params AdmParams) sibra.Bps
	Available(ifids IFTuple, id sibra.ID) sibra.Bps
	AvailableForTelescope(src addr.IA, ifids IFTuple, id, baseId sibra.ID) (doneAdmission bool, available sibra.Bps, err error)
	AddSteadyResv(params AdmParams, alloc sibra.BwCls, knownBaseRes bool) error
	CleanSteadyResv(c CleanParams)
	PromoteToSOFCreated(ifids IFTuple, id sibra.ID, info *sbresv.Info) error
	PromoteToPending(ifids IFTuple, id sibra.ID, c *sbreq.ConfirmIndex) error
	PromoteToActive(ifids IFTuple, id sibra.ID, info *sbresv.Info, c *sbreq.ConfirmIndex) error
}

type EphemAdm interface {
	AdmitEphemSetup(steady *sbextn.Steady, p *sbreq.Pld, srcIA addr.IA) (EphemRes, error)
	AdmitEphemRenew(ephem *sbextn.Ephemeral, p *sbreq.Pld, srcIA addr.IA) (EphemRes, error)
	CleanEphemSetup(steady *sbextn.Steady, p *sbreq.Pld) (sbreq.FailCode, error)
	CleanEphemRenew(ephem *sbextn.Ephemeral, p *sbreq.Pld) (sbreq.FailCode, error)
}

type ASBlacklist interface {
	Blacklist(ia addr.IA, baseDuration time.Duration, reservationId sibra.ID)
	IsBlacklisted(ia addr.IA) bool
	RemoveFromBlacklist(ia addr.IA)
	CanRenew(sibra.ID) bool
}

type SteadyRes struct {
	// AllocBw is the allocated bandwidth
	AllocBw sibra.BwCls
	// MaxBw is the maximum acceptable bandwidth in case admission fails.
	MaxBw sibra.BwCls
	// MinBw is the minimal acceptable bandwidth in case admission fails.
	MinBw sibra.BwCls
	// Accepted indicates if the reservation is accepted.
	Accepted bool
}

type EphemRes struct {
	// AllocBw is the allocated bandwidth
	AllocBw sibra.BwCls
	// MaxBw is the maximum acceptable bandwidth in case admission fails.
	MaxBw sibra.BwCls
	// FailCode indicates the failure code when admission fails.
	FailCode sbreq.FailCode
}