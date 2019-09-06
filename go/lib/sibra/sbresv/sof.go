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
	"bytes"
	"fmt"
	"hash"

	"crypto/aes"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sibra"
	"github.com/scionproto/scion/go/lib/util"
)

// TODO: REVISE: (rafflc) Create three different kind of SOF
// A: Data plane packets (Mac length 4 bytes)
// B: Control plane packets (Mac length x bytes(encrypted), maybe with info about AS)
// C: Reservation packets (Mac length x bytes(decrypted), maybe with DRKeys)
// During admission, control plane packets are being created
// When stored in sibra_srv or sibrad, control plane packets are converted to reservation packets
// When renewal, reservation packets are converted to control plane packets
// When data packets send, reservation packets are converted to data plane packets
//
// Not sure if I have to copy the fields when converting packets or not...

const (
	// maxPathIDsLen is the maximum space required to write all path ids.
	maxPathIDsLen = 3*sibra.SteadyIDLen + sibra.EphemIDLen
	// upadded is the unpadded input length for SIBRA opaque field MAC
	// computation. Sum of len(Ingress), len(Egress), len(Info), maxPathIDsLen,
	// len(pathLens), len(prev sof).
	unpadded = 3 + InfoLen + maxPathIDsLen + 3 + DataSOFieldLen
	// padding is the padding to make macInputLen a multiple of aes.BlockSize.
	padding = (aes.BlockSize - unpadded%aes.BlockSize) % aes.BlockSize
	// macInputLne is the input length for SIBRA opaque field MAC computation.
	macInputLen = unpadded + padding
	// HVFInputLen is the input length for SIBRA opaque field HVF calculation from HA
	HVFInputLen = 8 + HALen
	// MaxHAInputLen is the max input length for HA calculation
	// Ingress and Egress (3) + Infofield (8) + PathLens (3)
	// + IDs (1 ephem: 16 + 3 steady: 30 = 46) padding for aes.BlockSize (4)
	// = 64
	MaxHAInputLen = 3 + InfoLen + 3 + maxPathIDsLen + 4
	// HVFLen is the Data SIBRA opaque field HVF length.
	HVFLen = 4
	// HALen is the Control and Reservation SIBRA opaque field HA length.
	HALen = 16
	// ControlSOFieldLen is the length of a SIBRA opaque field in control plane packets.
	ControlSOFieldLen = 16 + 4 + 8
	// DataSOFieldLen is the length of a SIBRA opaque field in data plane packets.
	DataSOFieldLen = common.LineLen
	// ReservationSOFieldLen is the length of a SIBRA opaque field in reservation packets
	ReservationSOFieldLen = 16 + 4 + 8
	// SOFieldLines is the number of lines a SOField spans.
	SOFieldLines = DataSOFieldLen / common.LineLen
	// MinSOFLen is the minimum length a SOField has to have
	MinSOFLen = DataSOFieldLen

	flagType     = 0x03
	flagContinue = 0x80

	ErrorSOFBadHVF   = "Bad SOF HVF"
	ErrorSOFTooShort = "SOF too short"
	ErrorSOFBadHA    = "Bad SOF Hop Authenticator"
	ErrorInvalidType = "Invalid SOF Type"
)

// SOFType indicates the kind of SOField
type SOFType uint8

const (
	Data SOFType = iota
	Control
	Reservation
)

// TODO: (rafflc) Modify description of SOFs. Especially computation of MAC :)

// DataSOField is the SIBRA Opqaue Field used in data plane packets.
// It is used for forwarding SIBRA packets and describes the ingress/egress
// interfaces. A MAC is used to authenticate that this packet was issued
// for this reservation.
//
// Whether the previous or the next SOField is used as input for the mac
// depends on the path type specified in the reservation info field.
//
// When calculating the mac for stitched steady paths, only the reservation id
// and path length of the current steady block must be provided.
//
// Data SOF:
//
// 0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |c|   Typ| Ingress IF | Egress IF   | HVF 							   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// HVF: H(TS|PldHash|dec(HA))
//
// Control SOF:
//
// 0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |c|   Typ| Ingress IF | Egress IF   |   HopISD   |       HopAS		   | so now IA is 8 bytes...
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | enc(HA)															   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | enc(HA) (cont.)													   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// HA      = MAC_{K_{SV_{A_i}}}(IngressIFID_i | EgressIFID_i | SteadyInfo )
// enc(HA) = K_{SV_{A_i}}(HA)
//
// Reservation SOF:
//
// 0B       1        2        3        4        5        6        7
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |c|   Typ| Ingress IF | Egress IF   |   HopISD   |       HopAS		   | so now IA is 8 bytes...
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | dec(HA)															   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// | dec(HA) (cont.)													   |
// +--------+--------+--------+--------+--------+--------+--------+--------+
// dec(HA) = HA

type SOField struct {
	// HVF is the Hop Verification Field for this hop and packet
	// only used for Data SOF
	HVF common.RawBytes
	// HopAutenticator is the Authenticator for the Hop
	// in Reservation SOF, it is decrypted
	// in Control SOF, it is encrypted
	HopAuthenticator common.RawBytes
	// Address is the address of the corresponding hop.
	// The ISD-AS pair is 4 byte long only used for Control and Reservation SOF
	Address addr.IA
	// Ingress is the ingress interface.
	Ingress common.IFIDType
	// Egress is the egress interface.
	Egress common.IFIDType
	// Type indicates the type of the SOF field
	Type SOFType
	// Continue indicates if the SOF spans multiple lines.
	Continue bool
}

func NewSOFieldFromRaw(b common.RawBytes) (*SOField, error) {
	if len(b) < MinSOFLen {
		return nil, common.NewBasicError(ErrorSOFTooShort, nil,
			"min", MinSOFLen, "actual", len(b))
	}
	sof := &SOField{
		Continue: b[0]&flagContinue != 0,
		Type:     SOFType(b[0] & flagType),
		Ingress:  common.IFIDType(int(b[1])<<4 | int(b[2])>>4),
		Egress:   common.IFIDType((int(b[2])&0xF)<<8 | int(b[3])),
	}
	var err error
	switch sof.Type {
	case Data:
		err = sof.NewDataSOField(b[4:])
	case Control:
		err = sof.NewControlSOField(b[4:])
	case Reservation:
		err = sof.NewReservationSOField(b[4:])
	default:
		//as long as not everything is implemented, no type will result in Data
		sof.Type = Data
		err = sof.NewDataSOField(b[4:])
		//return nil, common.NewBasicError(ErrorInvalidType, nil)
	}
	if err != nil {
		return nil, err
	}
	return sof, nil
}

func (s *SOField) NewDataSOField(b common.RawBytes) error {
	s.HVF = b[0:HVFLen]
	return nil
}

func (s *SOField) NewControlSOField(b common.RawBytes) error {
	if len(b) < ControlSOFieldLen-4 {
		return common.NewBasicError(ErrorSOFTooShort, nil,
			"min", ControlSOFieldLen, "actual", len(b))
	}
	s.Address = addr.IAFromRaw(b[0:8])
	s.HopAuthenticator = b[8:]
	return nil
}

func (s *SOField) NewReservationSOField(b common.RawBytes) error {
	if len(b) < ReservationSOFieldLen-4 {
		return common.NewBasicError(ErrorSOFTooShort, nil,
			"min", ReservationSOFieldLen, "actual", len(b))
	}
	s.Address = addr.IAFromRaw(b[0:8])
	s.HopAuthenticator = (b[8:])
	return nil
}

// VerifyHVF verifies the hop verficiation field of a data SOF
// TODO: (rafflc) paramaters needed for CalcHA not defined yet.
func (s *SOField) VerifyHVF(svA hash.Hash, info *Info, ids []sibra.ID,
	pLens []uint8, PldHash common.RawBytes, TS uint32) error {

	decHA := make(common.RawBytes, HALen)
	var err error
	if decHA, err = s.CalcHA(svA, info, ids, pLens); err != nil {
		return common.NewBasicError("HVF validation failed", err)
	}
	hvf := make(common.RawBytes, HVFLen)
	if hvf, err = s.CalcHVF(PldHash, TS, decHA); err != nil {
		return common.NewBasicError("HVF validation failed", err)
	}
	if !bytes.Equal(s.HVF, hvf) {
		return common.NewBasicError(ErrorSOFBadHVF, nil, "expected", s.HVF, "actual", hvf)
	}
	return nil
}

// CalcHVF gets the PldHash, TimeStamp and decrypted Hop Authenticator
// and returns the per packet HVF.
// HVF = H(TS|PldHash|decHA)
func (s *SOField) CalcHVF(PldHash common.RawBytes, TS uint32,
	decHA common.RawBytes) (common.RawBytes, error) {

	if s.Type != Data {
		return nil, common.NewBasicError("HVF can only be calculated for Data SOF", nil)
	}

	all := make(common.RawBytes, HVFInputLen)
	common.Order.PutUint32(all[:4], TS)
	copy(all[4:8], PldHash)
	copy(all[8:], decHA)
	hvf := make(common.RawBytes, 4)
	var err error
	if hvf, err = util.Calc32Hash(all); err != nil {
		return nil, common.NewBasicError("HVF calculation failed", err)
	}
	return hvf, nil
}

// CalcHA gets HVF and other relevant fields and calculates decrypted HA
func (s *SOField) CalcHA(mac hash.Hash, info *Info, ids []sibra.ID,
	pLens []uint8) (common.RawBytes, error) {
	//MAC_{K_{SV_{A_i}}}(IngressIFID_i | EgressIFID_i | SteadyInfo [0:x])

	all := make(common.RawBytes, MaxHAInputLen)

	if err := s.writeIFIDs(all[:3]); err != nil {
		return nil, common.NewBasicError("Unable to write IFIDs", err)
	}
	off, end := 3, 3+info.Len()
	info.Write(all[off:end])
	for i := range ids {
		off, end = end, end+ids[i].Len()
		ids[i].Write(all[off:end])
	}
	off = 3 + info.Len() + maxPathIDsLen
	end = off + 3
	copy(all[off:end], pLens)
	decHA, err := util.Mac(mac, all)
	if err != nil {
		return nil, err
	}
	return decHA[:HALen], nil
}

// SetHA calculates the encrypted HA for this hop and writes it in the control SOF
func (s *SOField) SetHA(svA hash.Hash, key, nonce common.RawBytes, info *Info, ids []sibra.ID,
	pLens []uint8) error {
	var err error
	if s.HopAuthenticator, err = s.CalcHA(svA, info, ids, pLens); err != nil {
		return common.NewBasicError("Calculation of Hop Authenticator failed", err)
	}
	if err := s.encryptHA(key, nonce); err != nil {
		return common.NewBasicError("Encryption of Hop Authenticator failed", err)
	}
	return nil
}

// encryptHA takes a key and nonce and encrypts the value in s.HopAuthenticator with it
func (s *SOField) encryptHA(key, nonce common.RawBytes) error {
	encryptedHA, err := util.Encrypt(s.HopAuthenticator, key, nonce)
	if err != nil {
		return common.NewBasicError("Hop Authenticator encryption failed", err)
	}
	copy(s.HopAuthenticator, encryptedHA)
	return nil
}

// decryptHA takes a key and nonce and decrypts the value in s.HopAuthenticator with it
func (s *SOField) decryptHA(key, nonce common.RawBytes) error {
	decryptedHA, err := util.Decrypt(s.HopAuthenticator, key, nonce)
	if err != nil {
		return common.NewBasicError("Hop Authenticator decryption failed", err)
	}
	copy(s.HopAuthenticator, decryptedHA)
	return nil
}

// setHVFfromHA calculates the HVF using the decHA and writes it in the data SOF
func (s *SOField) setHVFfromHA(PldHash common.RawBytes, TS uint32) error {
	hvf, err := s.CalcHVF(PldHash, TS, s.HopAuthenticator)
	if err != nil {
		return err
	}
	copy(s.HVF, hvf)
	return nil
}

// ToReservation modifies the SOF from current type to Reservation.
func (s *SOField) ToReservation(key, nonce common.RawBytes) error {
	switch s.Type {
	case Data:
		return common.NewBasicError("Data SOF cannot be converted to Reservation SOF", nil)
	case Control:
		s.Type = Reservation
		if err := s.decryptHA(key, nonce); err != nil {
			return common.NewBasicError("Type convertion from Control to Reservation SOF failed", err)
		}
		// TODO: (rafflc) Modify other fields
	case Reservation:
		return nil
	default:
		return common.NewBasicError(ErrorInvalidType, nil)
	}
	return nil
}

//SteadyToReservation is used as dummy function since I am currentyl not sure how to
// handle steady reservations here exactly
func (s *SOField) SteadyToReservation() error {
	s.Type = Reservation
	return nil
}

// ToControl modifies the SOF from current type to Control.
// Caution: When converting from Reservation SOF type, make sure s is a copy of the reservation entry.
// Otherwise it will be overwritten
func (s *SOField) ToControl(key, nonce common.RawBytes) error {
	switch s.Type {
	case Data:
		return common.NewBasicError("Data SOF cannot be converted to Control SOF", nil)
	case Control:
		return nil
	case Reservation:
		s.Type = Control
		if err := s.encryptHA(key, nonce); err != nil {
			return common.NewBasicError("Type convertion from Reservation to Control SOF failed", err)
		}
		//TODO: (rafflc) Modify other fields
		return nil
	default:
		return common.NewBasicError(ErrorInvalidType, nil)
	}
}

// ToData modifies the SOF from current type to Data.
// Caution: When converting from Reservation SOF type, make sure s is a copy of the reservation entry.
// Otherwise it will be overwritten
func (s *SOField) ToData(PldHash common.RawBytes, TS uint32) error {
	switch s.Type {
	case Data:
		return common.NewBasicError("Already Data SOF", nil)
	case Control:
		return common.NewBasicError("Control SOF should not be converted to Data SOF", nil)
	case Reservation:
		s.Type = Data
		if err := s.setHVFfromHA(PldHash, TS); err != nil {
			return common.NewBasicError("Type convertion from Reservation to Data SOF failed", err)
		}
		//s.Key = 0
		s.HopAuthenticator = nil
		s.Address = addr.IA{}
		return nil
	default:
		return common.NewBasicError(ErrorInvalidType, nil)
	}
}

// Len returns the length for the corresponding type of s
func (s *SOField) Len() int {
	switch s.Type {
	case Data:
		return DataSOFieldLen
	case Control:
		return ControlSOFieldLen
	case Reservation:
		return ReservationSOFieldLen
	default:
		return 0
	}
}

func (s *SOField) Pack() common.RawBytes {
	b := make(common.RawBytes, s.Len())
	s.Write(b)
	return b
}

func (s *SOField) Write(b common.RawBytes) error {
	if len(b) < s.Len() {
		return common.NewBasicError("Buffer to short", nil, "method",
			"sbresv.SOField.Write", "min", s.Len(), "actual", len(b))
	}
	b[0] = byte(s.Type)
	if s.Continue {
		b[0] |= 0x80
	}
	if err := s.writeIFIDs(b[1:4]); err != nil {
		return common.NewBasicError("Unable to write IFIDs", err, "method",
			"sbresv.SOField.Write")
	}
	switch s.Type {
	case Data:
		copy(b[4:HVFLen+4], s.HVF)
	case Control:
		s.Address.Write(b[4:12])
		copy(b[12:HALen+12], s.HopAuthenticator)
	case Reservation:
		s.Address.Write(b[4:12])
		copy(b[12:HALen+12], s.HopAuthenticator)
	}
	return nil
}

func (s *SOField) writeIFIDs(b common.RawBytes) error {
	if len(b) < 3 {
		return common.NewBasicError("Buffer to short", nil, "min", 3, "actual", len(b))
	}
	b[0] = byte(s.Ingress >> 4)
	b[1] = byte((s.Ingress&0x0F)<<4 | s.Egress>>8)
	b[2] = byte(s.Egress & 0XFF)
	return nil
}

func (s *SOField) String() string {
	switch s.Type {
	case Data:
		return fmt.Sprintf("Type: Data, Ingress: %s Egress: %s HVF: %s", s.Ingress, s.Egress, s.HVF)
	case Control:
		return fmt.Sprintf("Type: Control, Ingress: %s Egress: %s encHA: %s", s.Ingress, s.Egress, s.HopAuthenticator)
	case Reservation:
		return fmt.Sprintf("Type: Reservation, Ingress: %s Egress: %s decHA: %s", s.Ingress, s.Egress, s.HopAuthenticator)
	default:
		return fmt.Sprintf("Invalid type")
	}
}

// func (s *SOField) Verify(mac hash.Hash, info *Info, ids []sibra.ID, pLens []uint8,
// 	sof common.RawBytes) error {

// 	switch s.Type {
// 	case Data:
// 		if mac, err := s.CalcMac(mac, info, ids, pLens, sof); err != nil {
// 			return err
// 		} else if !bytes.Equal(s.Mac, mac) {
// 			return common.NewBasicError(ErrorSOFBadMac, nil, "expected", s.Mac, "actual", mac)
// 		}
// 	case Control, Reservation:
// 		return common.NewBasicError("HA can't be verified", nil)
// 	default:
// 		return common.NewBasicError(ErrorInvalidType, nil)
// 	}
// 	return nil
// }

// func (s *SOField) SetMac(mac hash.Hash, info *Info, ids []sibra.ID, pLens []uint8,
// 	sof common.RawBytes) error {

// 	if s.Type != Data {
// 		return common.NewBasicError("Mac can only be set for Data SOF", nil)
// 	}

// 	tag, err := s.CalcMac(mac, info, ids, pLens, sof)
// 	if err != nil {
// 		return err
// 	}
// 	copy(s.Mac, tag)
// 	return nil
// }

// func (s *SOField) CalcMac(mac hash.Hash, info *Info, ids []sibra.ID, pLens []uint8,
// 	sof common.RawBytes) (common.RawBytes, error) {

// 	if s.Type != Data {
// 		return nil, common.NewBasicError("Mac can only be calculated for Data SOF", nil)
// 	}

// 	all := make(common.RawBytes, macInputLen)
// 	if err := s.writeIFIDs(all[:3]); err != nil {
// 		return nil, common.NewBasicError("Unable to write IFIDs", err)
// 	}
// 	off, end := 3, 3+info.Len()
// 	info.Write(all[off:end])
// 	for i := range ids {
// 		off, end = end, end+ids[i].Len()
// 		ids[i].Write(all[off:end])
// 	}
// 	off = 3 + info.Len() + maxPathIDsLen
// 	end = off + 3
// 	copy(all[off:end], pLens)
// 	if sof != nil {
// 		copy(all[end:end+len(sof)], sof)
// 	}
// 	tag, err := util.Mac(mac, all)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return tag[:MacLen], nil
// }
