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

package sbresv

import (
	"fmt"
	"hash"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/util"

	"github.com/scionproto/scion/go/lib/assert"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sibra"
)

// Block is the SIBRA reservation block. It is made up of a reservation info
// field and a list of SIBRA opaque fields.
//
// 0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | Reservation Info                                                      |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | SIBRA Opaque Field                                                    |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |...                                                                    |
// +--------+--------+--------+--------+--------+--------+--------+--------+
type Block struct {
	// Info is the reservation info field.
	Info *Info
	// SOFields are the SIBRA opaque fields.
	SOFields []*SOField
}

func BlockFromRaw(raw common.RawBytes, numHops int) (*Block, error) {
	if len(raw) < calcMinBlockLen(numHops) {
		return nil, common.NewBasicError("Invalid reservation block length", nil, "numHops",
			numHops, "min", calcMinBlockLen(numHops), "actual", len(raw))
	}
	block := &Block{
		Info:     NewInfoFromRaw(raw[:InfoLen]),
		SOFields: make([]*SOField, numHops),
	}
	var err error
	off := InfoLen
	for i := 0; i < numHops; i++ {
		if block.SOFields[i], err = NewSOFieldFromRaw(raw[off:]); err != nil {
			return nil, err
		}
		off = off + block.SOFields[i].Len()
	}
	return block, nil
}

func calcMinBlockLen(numHops int) int {
	return InfoLen + numHops*common.LineLen
}

func NewBlock(info *Info, numHops int, softype SOFType) *Block {
	fields := make([]*SOField, numHops)
	switch softype {
	case Data:
		for i := 0; i < len(fields); i++ {
			fields[i] = &SOField{
				HVF: make(common.RawBytes, HVFLen),
			}
		}
	case Control:
		for i := 0; i < len(fields); i++ {
			fields[i] = &SOField{
				HopAuthenticator: make(common.RawBytes, HALen),
			}
		}
	case Reservation:
		for i := 0; i < len(fields); i++ {
			fields[i] = &SOField{
				HopAuthenticator: make(common.RawBytes, HALen),
			}
		}
	}
	return &Block{
		Info:     info,
		SOFields: fields,
	}
}

func (b *Block) Verify(svA hash.Hash, sofIdx int, ids []sibra.ID, pLens []uint8,
	PldHash common.RawBytes, TS uint32, now time.Time) error {
	if sofIdx < 0 || sofIdx >= b.NumHops() {
		return common.NewBasicError("SofIndex out of range", nil, "min", 0,
			"max", b.NumHops(), "actual", sofIdx)
	}
	if !now.Before(b.Info.ExpTick.Time()) {
		return common.NewBasicError("Reservation expired", nil,
			"now", now, "exp", b.Info.ExpTick.Time())
	}
	// return b.SOFields[sofIdx].VerifyHVF(svA, b.Info, ids, pLens, PldHash, TS)
	return nil
}

// SetHA takes the mac, key & nonce and sets the HA for all SOF
func (b *Block) SetHA(mac hash.Hash, key, nonce common.RawBytes,
	sofIdx int, ids []sibra.ID, pLens []uint8) error {
	if sofIdx < 0 || sofIdx >= b.NumHops() {
		return common.NewBasicError("SofIndex out of range", nil, "min", 0,
			"max", b.NumHops(), "actual", sofIdx)
	}

	//REVISE: (rafflc) SetMac is now SetHA
	return b.SOFields[sofIdx].SetHA(mac, key, nonce, b.Info, ids, pLens)
}

// ToData takes the PldHash and the TS of the packet and transforms all Reservation
// SOF to Data SOF
func (b *Block) ToData(PldHash common.RawBytes, TS uint32) error {
	for _, sof := range b.SOFields {
		if err := sof.ToData(PldHash, TS); err != nil {
			return err
		}
	}
	return nil
}

// ToReservation takes a control Block and modifies it to a
// reservation Block by decrypting the HA in all SOFs
func (b *Block) EphemToReservation(AS addr.IA, Host addr.HostAddr, nonce common.RawBytes) error {
	switch b.Info.PathType {
	case sibra.PathTypeEphemeral:
		for _, sof := range b.SOFields {
			l1key, err := util.DeriveASKeyL1(sof.Address, AS)
			if err != nil {
				return common.NewBasicError("Unable to derive key", err)
			}
			l2key, err := util.DeriveASKeyL2(l1key, nil, Host, true, false, "COLIBRI")
			if err != nil {
				return common.NewBasicError("Unable to derive key", err)
			}
			if err := sof.ToReservation(l2key, nonce); err != nil {
				return err
			}
		}
	default:
		return common.NewBasicError("Ephemeral reservation exptected", nil)
	}
	return nil
}

func (b *Block) SteadyToReservation() error {
	switch b.Info.PathType {
	case sibra.PathTypeEphemeral:
		return common.NewBasicError("Steady reservation expected", nil)
	default:
		for _, sof := range b.SOFields {
			if err := sof.SteadyToReservation(); err != nil {
				return err
			}
		}
		// for _, sof := range b.SOFields {
		// 	l1key, err := util.DeriveASKeyL1(sof.Address, AS)
		// 	if err != nil {
		// 		return common.NewBasicError("Unable to derive key", err)
		// 	}
		// 	l2key, err := util.DeriveASKeyL2(l1key, nil, nil, true, true, "COLIBRI")
		// 	if err != nil {
		// 		return common.NewBasicError("Unable to derive key", err)
		// 	}
		// 	if err := sof.ToReservation(l2key, nonce); err != nil {
		// 		return err
		// 	}
		// 	if err := sof.ToReservation(l2key, nonce); err != nil {
		// 		return err
		// 	}
		// }
	}
	return nil
}

func (b *Block) NumHops() int {
	return len(b.SOFields)
}

func (b *Block) Len() int {
	sum := 0
	for i := range b.SOFields {
		sum += b.SOFields[i].Len()
	}
	return b.Info.Len() + sum
}

func (b *Block) Write(raw common.RawBytes) error {
	if len(raw) < b.Len() {
		return common.NewBasicError("Buffer to short", nil, "method",
			"sbresv.Block.Write", "min", b.Len(), "actual", len(raw))
	}
	off, end := 0, b.Info.Len()
	if err := b.Info.Write(raw[off:end]); err != nil {
		return err
	}
	for _, op := range b.SOFields {
		off, end = end, end+op.Len()
		if err := op.Write(raw[off:end]); err != nil {
			return err
		}
	}
	return nil
}

func (b *Block) Copy() *Block {
	raw := make(common.RawBytes, b.Len())
	err := b.Write(raw)
	if assert.On {
		assert.Must(err == nil, "No error during copying block")
	}
	block, err := BlockFromRaw(raw, b.NumHops())
	if assert.On {
		assert.Must(err == nil, "No error during copying block")
	}
	return block
}

func (b *Block) String() string {
	return fmt.Sprintf("Info: [%s] SOFs: %s", b.Info, b.SOFields)
}
