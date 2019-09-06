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

package sbcreate

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/sibra_mgmt"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/sibra/sbextn"
	"github.com/scionproto/scion/go/lib/sibra/sbreq"
	"github.com/scionproto/scion/go/lib/sibra/sbresv"
)

// TODO: (rafflc) Check this whole file

// NesSteadySetup creates a steady extension with the provided setup request.
func NewSteadySetup(r *sbreq.SteadyReq, id sibra.ID) (*sbextn.Steady, error) {
	if len(id) != sibra.SteadyIDLen {
		return nil, common.NewBasicError(sbextn.InvalidSteadyIdLen, nil,
			"expected", sibra.SteadyIDLen, "actual", len(id))
	}
	id = id.Copy()
	pathLen := uint8(len(r.OfferFields))
	ext := &sbextn.Steady{
		Base: &sbextn.Base{
			Steady:       true,
			Setup:        true,
			Forward:      !r.Info.PathType.Reversed(),
			IsRequest:    true,
			Version:      sibra.Version,
			PathLens:     []uint8{pathLen, 0, 0},
			IDs:          []sibra.ID{id},
			ActiveBlocks: make([]*sbresv.Block, 0),
		},
	}
	if !ext.Forward {
		ext.SOFIndex = pathLen - 1
	}
	ext.UpdateIndices()
	return ext, nil
}

// NewSteadyUse creates a steady extension which can be used to send steady traffic
// based on the provided block.
// NewSteadyUse is in contrast to NewEphemUse build to use and not to store?
func NewSteadyUse(id sibra.ID, block *sbresv.Block, fwd bool) (*sbextn.Steady, error) {
	if len(id) != sibra.SteadyIDLen {
		return nil, common.NewBasicError(sbextn.InvalidSteadyIdLen, nil,
			"expected", sibra.SteadyIDLen, "actual", len(id))
	}
	if block == nil {
		return nil, common.NewBasicError("Block must not be nil", nil)
	}
	id = id.Copy()
	pathLen := uint8(block.NumHops())
	ext := &sbextn.Steady{
		Base: &sbextn.Base{
			Steady:       true,
			Forward:      fwd,
			IsRequest:    false,
			Version:      sibra.Version,
			PathLens:     []uint8{pathLen, 0, 0},
			IDs:          []sibra.ID{id},
			ActiveBlocks: []*sbresv.Block{block.Copy()},
		},
	}
	if !ext.Forward {
		ext.SOFIndex = pathLen - 1
	}
	ext.UpdateIndices()
	return ext, nil
}

// REVISE: (rafflc) NewEphemUse gets information of admitted ephem reservation. Before being stored
// at the local sibrad, the reservation block is created
// Thus this is the place to convert the Control SOF to Reservation SOF :)
// NewEphemUse creates an ephemeral extension which can be used to send ephemeral
// traffic based on the provided reservation block.
func NewEphemUse(ids []sibra.ID, pathLens []uint8, block *sbresv.Block, fwd bool,
	AS addr.IA, Host addr.HostAddr, nonce common.RawBytes) (*sbextn.Ephemeral, error) {

	if len(ids) < 2 {
		return nil, common.NewBasicError("Invalid number of provided reservation ids", nil,
			"min", 2, "actual", len(ids))
	}
	if len(ids[0]) != sibra.EphemIDLen {
		return nil, common.NewBasicError(sbextn.InvalidEphemIdLen, nil,
			"expected", sibra.EphemIDLen, "actual", len(ids[0]))
	}
	for i := 1; i < len(ids); i++ {
		if len(ids[i]) != sibra.SteadyIDLen {
			return nil, common.NewBasicError(sbextn.InvalidSteadyIdLen, nil, "i", i,
				"expected", sibra.SteadyIDLen, "actual", len(ids[0]))
		}
	}
	if block == nil {
		return nil, common.NewBasicError("Block must not be nil", nil)
	}
	if len(pathLens) != 3 {
		return nil, common.NewBasicError("Invalid pathLens format", nil, "pathLens", pathLens)
	}
	idsCopy := make([]sibra.ID, len(ids))
	for i := range idsCopy {
		idsCopy[i] = ids[i].Copy()
	}
	reservationblock := block.Copy()
	if err := reservationblock.EphemToReservation(AS, Host, nonce); err != nil {
		return nil, common.NewBasicError("Failed to transform extension to reservation format", err)
	}
	ext := &sbextn.Ephemeral{
		Base: &sbextn.Base{
			Forward:      fwd,
			Version:      sibra.Version,
			PathLens:     []uint8{pathLens[0], pathLens[1], pathLens[2]},
			IDs:          idsCopy,
			ActiveBlocks: []*sbresv.Block{reservationblock},
		},
	}
	// IDEA: (rafflc) Why is UpdateIndices here called twice?
	if err := ext.UpdateIndices(); err != nil {
		return nil, err
	}
	if !ext.Forward {
		ext.SOFIndex = uint8(ext.TotalHops - 1)
	}
	if err := ext.UpdateIndices(); err != nil {
		return nil, err
	}
	return ext, nil
}

// NewSteadyBE creates a steady extension which can be used to send best effort traffic
// on the provided (possibly stitched) path.
func NewSteadyBE(bmetas []*sibra_mgmt.BlockMeta, fwd bool) (*sbextn.Steady, error) {
	if err := validatePath(bmetas); err != nil {
		return nil, common.NewBasicError("Invalid path", err)
	}
	pathLen := 0
	pathLens := make([]uint8, 3)
	ids := make([]sibra.ID, 0, 3)
	blocks := make([]*sbresv.Block, 0, 3)
	for i, bmeta := range bmetas {
		pathLens[i] = uint8(bmeta.Block.NumHops())
		pathLen += bmeta.Block.NumHops()
		ids = append(ids, bmeta.Id.Copy())
		// TODO: (rafflc) Change steady blocks to reservations (if not already reservations?)
		// I do not really understand so far from where these blocks come exactly
		// Thus I can't really decide how to handle it. Dummy function :)
		reservationblock := bmeta.Block.Copy()
		if err := reservationblock.SteadyToReservation(); err != nil {
			return nil, common.NewBasicError("Failed to transform extension to reservation format", err)
		}
		blocks = append(blocks, reservationblock)
	}
	ext := &sbextn.Steady{
		Base: &sbextn.Base{
			Steady:       true,
			BestEffort:   true,
			Forward:      fwd,
			IsRequest:    false,
			Version:      sibra.Version,
			PathLens:     pathLens,
			IDs:          ids,
			ActiveBlocks: blocks,
		},
	}
	if !ext.Forward {
		ext.SOFIndex = uint8(pathLen - 1)
	}
	ext.UpdateIndices()
	return ext, nil
}

func validatePath(bmetas []*sibra_mgmt.BlockMeta) error {
	if len(bmetas) < 1 || len(bmetas) > 3 {
		return common.NewBasicError("Invalid number of blocks", nil, "num", len(bmetas))
	}
	prevPT := sibra.PathTypeNone
	prevIA := bmetas[0].StartIA()
	for i, v := range bmetas {
		if !v.Block.Info.PathType.ValidAfter(prevPT) {
			return common.NewBasicError("Incompatible path types", nil, "blockIdx", i,
				"prev", prevPT, "curr", v.Block.Info.PathType)
		}
		if !v.StartIA().Eq(prevIA) {
			return common.NewBasicError("Incompatible IA", nil, "blockIdx", i,
				"prev", prevIA, "curr", v.StartIA())
		}
		prevIA = v.EndIA()
		prevPT = v.Block.Info.PathType
	}
	return nil
}
