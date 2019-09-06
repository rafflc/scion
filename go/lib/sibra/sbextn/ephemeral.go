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

package sbextn

import (
	"bytes"
	"fmt"
	"hash"
	"time"

	"github.com/scionproto/scion/go/lib/util"

	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/sibra/sbreq"
)

const InvalidEphemIdLen = "Invalid ephemeral reservation id length"

var _ common.Extension = (*Ephemeral)(nil)

// Ephemeral is the SIBRA ephemeral reservation extension header.
type Ephemeral struct {
	*Base
}

func EphemeralFromRaw(raw common.RawBytes) (*Ephemeral, error) {
	base, err := BaseFromRaw(raw)
	if err != nil {
		return nil, err
	}
	return EphemeralFromBase(base, raw)
}

//REVIEW: (rafflc) Increase starting point of reading from raw

func EphemeralFromBase(base *Base, raw common.RawBytes) (*Ephemeral, error) {
	e := &Ephemeral{base}
	off, end := MinBaseLen, MinBaseLen+sibra.EphemIDLen
	e.ParseID(raw[off:end])
	for i := 0; i < e.TotalSteady; i++ {
		off, end = end, end+sibra.SteadyIDLen
		e.ParseID(raw[off:end])
	}
	off = end + padding(end+common.ExtnSubHdrLen)
	if err := e.parseActiveBlock(raw[off:], e.TotalHops); err != nil {
		return nil, err
	}
	off += e.ActiveBlocks[0].Len()
	if off != len(raw) {
		return nil, common.NewBasicError(InvalidExtnLength, nil,
			"extn", e, "expected", off, "actual", len(raw))
	}
	return e, nil
}

// SteadyIds returns the steady reservation ids in the reservation direction.
func (e *Ephemeral) SteadyIds() []sibra.ID {
	return e.IDs[1:]
}

// IsSteadyTransfer indicates if the current hop is a transfer hop between two steady reservations.
func (e *Ephemeral) IsSteadyTransfer() bool {
	transFwd := e.CurrSteady < e.TotalSteady-1 && e.RelSteadyHop+1 == int(e.PathLens[e.CurrSteady])
	transRev := e.CurrSteady != 0 && e.RelSteadyHop == 0
	return transFwd || transRev
}

// ToRequest modifies the ephemeral extension to fit the request payload.
func (e *Ephemeral) ToRequest(p *sbreq.Pld) error {
	if p.Data.Steady() {
		return common.NewBasicError("Steady request not supported", nil, "req", p)
	}
	if !p.Data.Steady() && int(p.NumHops) != e.TotalHops {
		return common.NewBasicError("NumHops in SOFields and request mismatch", nil,
			"numHops", p.NumHops, "totalHops", e.TotalHops)
	}
	e.IsRequest = true
	e.BestEffort = false
	return nil
}

func (e *Ephemeral) Copy() common.Extension {
	raw, err := e.Pack()
	if assert.On {
		assert.Must(err == nil, "Packing must not fail")
	}
	c, err := EphemeralFromRaw(raw)
	if assert.On {
		assert.Must(err == nil, "Parsing must not fail")
	}
	return c
}

func (e *Ephemeral) String() string {
	return fmt.Sprintf("sbextn.Ephemeral (%dB): %s", e.Len(), e.IDs)
}

//REVIEW: (rafflc) Add new functions for handling TimeStamp and validation

// UpdateTimeStamp writes encoding for current time in TS
func (e *Ephemeral) UpdateTimeStamp() error {
	NanoTimeNow := time.Now().UnixNano()
	TimeStampNano := int64(e.ActiveBlocks[0].Info.ExpTick)*sibra.ExpTicktoNano - NanoTimeNow
	if TimeStampNano < 0 {
		return common.NewBasicError("Reservation not valid anymore", nil)
	}
	if TimeStampNano > 16000000000 {
		return common.NewBasicError("ExpTime too far in future", nil)
	}
	e.TimeStamp = uint32(float64(TimeStampNano) / sibra.TStoNanoEphem)
	return nil
}

//ValidateTimeStamp checks if the TimeStamp in the packet is valid
func (e *Ephemeral) ValidateTimeStamp() error {
	var nanoexpiration, nanotimestamp, hops uint64
	//get the number of hops already passed
	if e.Forward {
		hops = uint64(e.CurrHop + 1)
	} else {
		hops = uint64(e.TotalHops - e.CurrHop)
	}
	//convert the expiration tick in the first info field to Nanoseconds
	nanoexpiration = uint64(e.ActiveBlocks[0].Info.ExpTick) * sibra.ExpTicktoNano
	//convert the TimeStamp to Nanoseconds
	nanotimestamp = uint64(float64(e.TimeStamp) * sibra.TStoNanoEphem)
	//get the actual construction time
	constructed := nanoexpiration - nanotimestamp
	//check if too much time elapsed. request packets have more time
	now := time.Now()
	if e.IsRequest {
		if constructed+sibra.MaxRequestHop*uint64(hops) < uint64(now.UnixNano()) {
			return common.NewBasicError("Too much time elapsed since request packet construction", nil,
				"now", now, "constructed", time.Unix(0, int64(constructed)))
		}
	} else {
		if constructed+sibra.MaxDataHop*uint64(hops) < uint64(now.UnixNano()) {
			return common.NewBasicError("Too much time elapsed since data packet construction", nil,
				"now", now, "constructed", time.Unix(0, int64(constructed)))
		}
	}
	return nil
}

//ValidatePldHash checks if the PldHash in the packet is valid
func (e *Ephemeral) ValidatePldHash(PldH common.RawBytes) error {
	if !bytes.Equal(e.PldHash, PldH) {
		return common.NewBasicError("Bad Payload Hash", nil, "expected", e.PldHash, "actual", PldH)
	}
	return nil
}

//ValidateDVF checks if the Destination Validation Field in the packet is valid
func (e *Ephemeral) ValidateDVF(key hash.Hash) error {
	dvf, err := e.calcDVF(key)
	if err != nil {
		return common.NewBasicError("DVF Calculation failed", err)
	}
	if !bytes.Equal(e.DVF, dvf) {
		return common.NewBasicError("Bad DVF", nil, "expected", e.DVF, "actual", dvf)
	}
	return nil
}

//WriteEphemSource computes and writes PldHash, TS, DVF and
// all HVF in the Data SOF at the source host
func (e *Ephemeral) WriteEphemSource(key hash.Hash, b common.RawBytes) error {
	var err error
	if e.PldHash, err = util.Calc32Hash(b); err != nil {
		return common.NewBasicError("Writing PldHash failed", err)
	}
	if err = e.UpdateTimeStamp(); err != nil {
		return common.NewBasicError("Writing TimeStamp failed", err)
	}
	if e.DVF, err = e.calcDVF(key); err != nil {
		return common.NewBasicError("Writing Destination Validation Field failed", err)
	}
	err = e.ActiveBlocks[0].ToData(e.PldHash, e.TimeStamp)
	if err != nil {
		return common.NewBasicError("Writing SOF failed", err)
	}
	return nil
}

// ValidateSibraDest validates PldHash, DVF and TS at the endhost for packets
// sent over ephem SIBRA
func (e *Ephemeral) ValidateSibraDest(keymac hash.Hash, PldH common.RawBytes) error {
	// if err := e.ValidateTimeStamp(); err != nil {
	// 	return common.NewBasicError("TimeStamp validation failed", err)
	// }
	// if err := e.ValidatePldHash(PldH); err != nil {
	// 	return common.NewBasicError("PayloadHash validation failed", err)
	// }
	// if err := e.ValidateDVF(keymac); err != nil {
	// 	return common.NewBasicError("Destination Validation field validation failed", err)
	// }
	return nil
}

//computeDVF calculates and writes the Destination Validation Field
func (e *Ephemeral) calcDVF(key hash.Hash) (common.RawBytes, error) {
	input := make(common.RawBytes, maxDVFInputLen)
	common.Order.PutUint32(input[:4], e.TimeStamp)
	copy(input[4:8], e.PldHash)
	off := 8
	end := 8
	for i := range e.IDs {
		off, end = end, end+e.IDs[i].Len()
		e.IDs[i].Write(input[off:end])
	}
	DVFmac, err := util.Mac(key, input)
	if err != nil {
		return nil, err
	}
	return DVFmac[:DVFLen], nil
}
