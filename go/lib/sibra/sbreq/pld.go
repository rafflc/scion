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

// Package sbreq provides the implementation for the SIBRA request
// payload.

// REVIEW: (rafflc) Removal of TimeStamp from request payload

package sbreq

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sibra/sbresv"
)

const (
	// IDEA: (rafflc) The length is differnet here from the description
	// in the thesis. Asked Dominik about it, he said 16 is correct

	AuthLen = 16

	// REVISE: (rafflc) Removed TimeStamp from Payload, thus minLen -4

	minLen = common.LineLen - 4

	flagAccepted = 0x20
	flagResponse = 0x10
	flagType     = 0x0F
)

// REVISE: (rafflc) I am pretty confident that the Flags and the Type are switched
// and not as defined in the thesis.
// Authenticator in the sketch have been 8 bytes, altough they should be 16

var _ common.Payload = (*Pld)(nil)

// Pld is the basis for SIBRA request. It can either be a request
// or a response for a request.
//
// 0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |    Total Len    |--AR|Typ| NumHops|               Data                |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |	Data (var len.)													   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | Authenticator 1													   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | Authenticator 1 cont.												   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | Authenticator 2													   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | Authenticator 2 cont												   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//

// REVISE: (rafflc) Reorder struct in order to achieve better aligning?

type Pld struct {
	// Auths is a list of authenticators.
	Auths []common.RawBytes
	// Data is the request data
	Data Data
	// TotalLen is the byte length of the payload.
	TotalLen uint16
	// Type indicates the type of request.
	Type DataType
	// NumHops indicates the number of hops.
	NumHops uint8
	// Accepted indicates if the request is accepted so far.
	Accepted bool
	// Response indicates if this is a response.
	Response bool
}

// IDEA: (rafflc) Since this is in the payload part of the SCION packet,
// I think there is no alinging to 8 bytes required

func PldFromRaw(raw common.RawBytes) (*Pld, error) {
	if len(raw) < minLen {
		return nil, common.NewBasicError("Invalid SIBRA request pld length", nil,
			"min", minLen, "actual", len(raw))
	}
	b := &Pld{
		TotalLen: common.Order.Uint16(raw[:2]),
		Type:     DataType(raw[2] & flagType),
		Response: (raw[2] & flagResponse) != 0,
		Accepted: (raw[2] & flagAccepted) != 0,
		NumHops:  raw[3],
	}
	if len(raw) != int(b.TotalLen) {
		return nil, common.NewBasicError("Invalid request pld length", nil,
			"expected", b.TotalLen, "actual", len(raw))
	}
	if err := b.parseData(raw[minLen:]); err != nil {
		return nil, common.NewBasicError("Unable to parse data", err, "pld", b)
	}
	if err := b.parseAuths(raw[minLen+b.Data.Len():], int(b.NumHops)); err != nil {
		return nil, common.NewBasicError("Unable to parse auths", err, "pld", b)
	}
	return b, nil
}

func (p *Pld) parseData(raw common.RawBytes) error {
	var err error
	switch p.Type {
	case RSteadySetup, RSteadyRenewal, RSteadySetupTelescope:
		p.Data, err = p.parseSteadyResv(raw, int(p.NumHops))
	case RSteadyConfIndex:
		p.Data, err = ConfirmIndexFromRaw(raw)
	case REphmSetup, REphmRenewal:
		p.Data, err = p.parseEphemResv(raw, int(p.NumHops))
	case REphmCleanUp:
		p.Data, err = EphemCleanFromRaw(raw)
	case RSteadyTearDown, RSteadyCleanUp:
		return common.NewBasicError("Parsing not implemented", nil, "type", p.Type)
	default:
		return common.NewBasicError("Unknown request type", nil, "type", p.Type)
	}
	return err
}

func (p *Pld) parseSteadyResv(raw common.RawBytes, numHops int) (Data, error) {
	if p.Response && p.Accepted {
		return SteadySuccFromRaw(raw, p.Type, numHops)
	}
	return SteadyReqFromRaw(raw, p.Type, numHops)
}

func (p *Pld) parseEphemResv(raw common.RawBytes, numHops int) (Data, error) {
	setup := p.Type == REphmSetup
	if p.Accepted {
		return EphemReqFromRaw(raw, setup, numHops)
	}
	return EphemFailedFromRaw(raw, setup, numHops)
}

func (p *Pld) parseAuths(raw common.RawBytes, numHops int) error {
	if len(raw) != numHops*AuthLen {
		return common.NewBasicError("Invalid raw size for authenticators", nil,
			"numHops", numHops, "expected", numHops*AuthLen, "actual", len(raw))
	}
	p.Auths = make([]common.RawBytes, numHops)
	off, end := 0, AuthLen
	for i := range p.Auths {
		p.Auths[i] = raw[off:end]
		off, end = end, end+AuthLen
	}
	return nil
}

func (p *Pld) Reverse() error {
	if p.Response {
		return common.NewBasicError("Unable to reverse response", nil)
	}
	p.Response = true
	switch p.Type {
	case RSteadySetup, RSteadyRenewal, RSteadySetupTelescope:
		if p.Accepted {
			return p.reverseSteadyReq()
		}
	}
	return nil
}

func (p *Pld) reverseSteadyReq() error {
	req := p.Data.(*SteadyReq)
	info := req.Info.Copy()
	info.BwCls = req.AccBw
	p.Data = &SteadySucc{
		Block:    sbresv.NewBlock(info, int(p.NumHops), sbresv.Control),
		DataType: p.Type,
	}
	return nil
}

// REVIEW: (rafflc) Change length computation to account for removal of TS

func (p *Pld) Len() int {
	l := minLen + len(p.Auths)*AuthLen
	if p.Data != nil {
		return l + p.Data.Len()
	}
	return l
}

func (p *Pld) Copy() (common.Payload, error) {
	b := make(common.RawBytes, p.Len())
	_, err := p.WritePld(b)
	if err != nil {
		return nil, err
	}
	return PldFromRaw(b)
}

// REVIEW: (rafflc) Change offsets to account for removal of TS

func (p *Pld) WritePld(raw common.RawBytes) (int, error) {
	if p.Data == nil {
		return 0, common.NewBasicError("Data must not be nil", nil, "method", "sbreq.Pld.Write")
	}
	authOff := minLen + p.Data.Len()

	// REVIEW: (rafflc) Why had this variable the same name as a constant defined in this file?!
	bufferLen := p.Len()
	if len(raw) < bufferLen {
		return 0, common.NewBasicError("Buffer too short", nil, "method", "sbreq.Pld.Write",
			"min", bufferLen, "actual", len(raw))
	}
	common.Order.PutUint16(raw[:2], uint16(bufferLen))
	raw[2] = byte(p.Type)
	if p.Response {
		raw[2] |= flagResponse
	}
	if p.Accepted {
		raw[2] |= flagAccepted
	}
	raw[3] = p.NumHops
	p.Data.Write(raw[minLen:authOff])
	off, end := authOff, authOff+AuthLen

	// REVIEW: (rafflc) I think this was missing
	// If it really was wrong, the authenticators have probably never been tested.
	// Update: This has not been implemented so far
	for _, v := range p.Auths {
		copy(raw[off:end], v)
		off, end = end, end+AuthLen
	}
	return bufferLen, nil
}

func (p *Pld) String() string {
	return fmt.Sprintf("DataType: %s Response: %t Accepted: %t TotalLen %d NumHops %d",
		p.Type, p.Response, p.Accepted, p.TotalLen, p.NumHops)
}
