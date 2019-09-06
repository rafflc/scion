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

	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/sibra/sbreq"
	"github.com/scionproto/scion/go/lib/util"
)

var _ common.Extension = (*Steady)(nil)

const InvalidSteadyIdLen = "Invalid steady reservation id length"

// Steady is the SIBRA steady reservation extension header.
type Steady struct {
	*Base
}

func SteadyFromRaw(raw common.RawBytes) (*Steady, error) {
	base, err := BaseFromRaw(raw)
	if err != nil {
		return nil, err
	}
	return SteadyFromBase(base, raw)
}

//REVIEW: (rafflc) Increase starting point of reading from raw

func SteadyFromBase(base *Base, raw common.RawBytes) (*Steady, error) {
	s := &Steady{Base: base}
	off, end := 0, MinBaseLen
	for i := 0; i < s.TotalSteady; i++ {
		off, end = end, end+sibra.SteadyIDLen
		s.ParseID(raw[off:end])
	}
	off = end + padding(end+common.ExtnSubHdrLen)
	if !s.Setup {
		for i := 0; i < s.TotalSteady; i++ {
			if err := s.parseActiveBlock(raw[off:], int(s.PathLens[i])); err != nil {
				return nil, err
			}
			off += s.ActiveBlocks[i].Len()
		}
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	switch {
	case s.BestEffort || s.IsRequest:
		if off != len(raw) {
			return nil, common.NewBasicError(InvalidExtnLength, nil,
				"extn", s, "expected", off, "actual", len(raw))
		}
		return s, nil
	default:
		return nil, common.NewBasicError("Steady traffic must be request or best effort", nil)
	}
}

func (s *Steady) validate() error {
	if !s.Steady {
		return common.NewBasicError("Base not steady", nil)
	}
	if err := s.ValidatePath(); err != nil {
		return err
	}
	return nil
}

// ValidatePath validates that the path types are compatible at the transfer hops.
func (s *Steady) ValidatePath() error {
	if len(s.ActiveBlocks) == 0 && s.Setup {
		return nil
	}
	if len(s.ActiveBlocks) < 1 || len(s.ActiveBlocks) > 3 {
		return common.NewBasicError("Invalid number of active blocks", nil,
			"num", len(s.ActiveBlocks))
	}
	prevPT := sibra.PathTypeNone
	for i, v := range s.ActiveBlocks {
		if !v.Info.PathType.ValidAfter(prevPT) {
			return common.NewBasicError("Incompatible path types", nil, "blockIdx", i,
				"prev", prevPT, "curr", v.Info.PathType)
		}

		prevPT = v.Info.PathType
	}
	return nil
}

// ToRequest modifies the steady extension and adds the provided request.
func (s *Steady) ToRequest(p *sbreq.Pld) error {
	if s.Steady && s.Setup {
		return common.NewBasicError("Steady setup requests cannot be transformed", nil)
	}
	if p.Data.Steady() && int(p.NumHops) != s.ActiveBlocks[0].NumHops() {
		return common.NewBasicError("NumHops in SOFields and request mismatch", nil,
			"numHops", p.NumHops, "tokenHops", s.ActiveBlocks[0].NumHops())
	}
	if !p.Data.Steady() && int(p.NumHops) != s.TotalHops {
		return common.NewBasicError("NumHops in SOFields and request mismatch", nil,
			"numHops", p.NumHops, "totalHops", s.TotalHops)
	}
	s.IsRequest = true
	s.BestEffort = false
	return nil
}

func (s *Steady) Copy() common.Extension {
	raw, err := s.Pack()
	if assert.On {
		assert.Must(err == nil, "Packing must not fail")
	}
	c, err := SteadyFromRaw(raw)
	if assert.On {
		assert.Must(err == nil, "Parsing must not fail")
	}
	return c
}

func (s *Steady) String() string {
	return fmt.Sprintf("sbextn.Steady (%dB): %s", s.Len(), s.IDs)
}

//REVIEW: (rafflc) Add new functions for handling TimeStamp  and validation

// UpdateTimeStamp writes encoding for current time in TS.
// setup requests are not handled
func (s *Steady) UpdateTimeStamp() error {
	if s.Setup {
		return nil
	}
	NanoTimeNow := time.Now().UnixNano()
	TimeStampNano := int64(s.ActiveBlocks[0].Info.ExpTick)*sibra.ExpTicktoNano - NanoTimeNow
	if TimeStampNano < 0 {
		return common.NewBasicError("Reservation not valid anymore", nil)
	}
	if TimeStampNano > 320000000000 {
		return common.NewBasicError("Reservation too far in future", nil)
	}
	s.TimeStamp = uint32(float64(TimeStampNano) / sibra.TStoNanoSteady)
	return nil
}

//ValidateTimeStamp checks if the TimeStamp in the packet is valid.
// setup requests are not handled
func (s *Steady) ValidateTimeStamp() error {
	if !s.Setup {
		var nanoexpiration, nanotimestamp, hops uint64
		//get the number of hops already passed
		if s.Forward {
			hops = uint64(s.CurrHop + 1)
		} else {
			hops = uint64(s.TotalHops - s.CurrHop)
		}
		//convert the expiration tick in the first info field to Nanoseconds
		nanoexpiration = uint64(s.ActiveBlocks[0].Info.ExpTick) * sibra.ExpTicktoNano
		//convert the TimeStamp to Nanoseconds
		nanotimestamp = uint64(float64(s.TimeStamp) * sibra.TStoNanoSteady)
		//get the actual construction time
		constructed := nanoexpiration - nanotimestamp
		//check if too much time elapsed. request packets have more time
		now := time.Now()
		if s.IsRequest {
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
	}
	return nil
}

//ValidatePldHash checks if the PldHash in the packet is valid
func (s *Steady) ValidatePldHash(PldH common.RawBytes) error {
	if !bytes.Equal(s.PldHash, PldH) {
		return common.NewBasicError("Bad Payload Hash", nil, "expected", s.PldHash, "actual", PldH)
	}
	return nil

}

//ValidateDVF checks if the Destination Validation Field in the packet is valid
func (s *Steady) ValidateDVF(key hash.Hash) error {
	dvf, err := s.calcDVF(key)
	if err != nil {
		return common.NewBasicError("DVF Calculation failed", err)
	}
	if !bytes.Equal(s.DVF, dvf) {
		return common.NewBasicError("Bad DVF", nil, "expected", s.DVF, "actual", dvf)
	}
	return nil
}

// WriteSteadySource computes and writes PldHash, TS, DVF and
// all HVF in the Data SOF at the source host
func (s *Steady) WriteSteadySource(key hash.Hash, b common.RawBytes) error {
	var err error
	if s.PldHash, err = util.Calc32Hash(b); err != nil {
		return common.NewBasicError("Writing PldHash failed", err)
	}
	if err = s.UpdateTimeStamp(); err != nil {
		return common.NewBasicError("Writing TimeStamp failed", err)
	}
	if s.DVF, err = s.calcDVF(key); err != nil {
		return common.NewBasicError("Writing Destination Validation Field failed", err)
	}
	for _, block := range s.ActiveBlocks {
		err = block.ToData(s.PldHash, s.TimeStamp)
		if err != nil {
			return common.NewBasicError("Writing SOF failed", err)
		}
	}
	return nil
}

// ValidateSibraDest validates PldHash, DVF and TS at the endhost for packets
// sent over steady SIBRA
func (s *Steady) ValidateSibraDest(keymac hash.Hash, PldH common.RawBytes) error {
	// if err := s.ValidateTimeStamp(); err != nil {
	// 	return common.NewBasicError("TimeStamp validation failed", err)
	// }
	// if err := s.ValidatePldHash(PldH); err != nil {
	// 	return common.NewBasicError("PayloadHash validation failed", err)
	// }
	// if err := s.ValidateDVF(keymac); err != nil {
	// 	return common.NewBasicError("Destination Validation field validation failed", err)
	// }
	return nil
}

//calcDVF calculates and returns the Destination Validation Field
func (s *Steady) calcDVF(key hash.Hash) (common.RawBytes, error) {
	input := make(common.RawBytes, maxDVFInputLen)
	common.Order.PutUint32(input[:4], s.TimeStamp)
	copy(input[4:8], s.PldHash)
	off := 8
	end := 8
	for i := range s.IDs {
		off, end = end, end+s.IDs[i].Len()
		s.IDs[i].Write(input[off:end])
	}
	DVFmac, err := util.Mac(key, input)
	if err != nil {
		return nil, err
	}
	return DVFmac[:DVFLen], nil
}
