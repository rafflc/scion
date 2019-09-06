// Copyright 2019 ETH Zurich
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

package util

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"github.com/scionproto/scion/go/lib/addr"

	"github.com/scionproto/scion/go/lib/common"
)

const (
	KeySize   = 32
	NonceSize = 12
)

// Encrypt encrypts text using key and nonce with aes gcm
func Encrypt(text, key, nonce common.RawBytes) (common.RawBytes, error) {
	if len(key) != KeySize {
		return nil, common.NewBasicError("Invalid key size", nil)
	}
	if len(nonce) != NonceSize {
		return nil, common.NewBasicError("Invalid nonce size", nil)
	}
	cipherblock, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, common.NewBasicError("Unable to create cipher", err)
	}
	gcm, err := cipher.NewGCM(cipherblock)
	if err != nil {
		return nil, common.NewBasicError("Unable to set up GCM", err)
	}
	encrypted := gcm.Seal(nil, []byte(nonce), []byte(text), nil)

	return encrypted, nil
}

// Decrypt decrypts text using key and nonce with aes gcm
func Decrypt(ciphertext, key, nonce common.RawBytes) (common.RawBytes, error) {
	if len(key) != KeySize {
		return nil, common.NewBasicError("Invalid key size", nil)
	}
	if len(nonce) != NonceSize {
		return nil, common.NewBasicError("Invalid nonce size", nil)
	}
	cipherblock, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, common.NewBasicError("Unable to create cipher", err)
	}
	gcm, err := cipher.NewGCM(cipherblock)
	if err != nil {
		return nil, common.NewBasicError("Unable to set up GCM", err)
	}
	decrypted, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return nil, common.NewBasicError("Unablt to open ciphertext", err)
	}
	return decrypted, nil
}

// DeriveASKeyL1 simulates on-the-fly derivation of L1 DRKeys.
// The key is derivable on the fly for AS1
func DeriveASKeyL1(AS1, AS2 addr.IA) (common.RawBytes, error) {

	byteAS1, _ := AS1.MarshalText()
	byteAS2, _ := AS2.MarshalText()

	l1 := len(byteAS1)
	l2 := len(byteAS2) + l1
	ASes := make(common.RawBytes, l2)
	copy(ASes[:l1], byteAS1)
	copy(ASes[l1:], byteAS2)
	L1Key, err := Calc256Hash(ASes)
	if err != nil {
		return nil, common.NewBasicError("Hash calculation failed", err)
	}

	return L1Key, nil
	//L1key := pbkdf2.Key(byteAS1, byteAS2, 1000, 16, sha256.New)
}

// DeriveASKeyL2 simulates on-the-fly derivation of L2 DRKeys
// h1Nil and h2Nil are set if H1 or H2 are nil
func DeriveASKeyL2(L1key common.RawBytes, H1, H2 addr.HostAddr,
	h1Nil, h2Nil bool, protocol string) (common.RawBytes, error) {
	lenL1 := len(L1key)
	byteprotocol := []byte(protocol)
	lenprot := len(byteprotocol)
	lentot := lenL1 + lenprot
	if h1Nil {
		if h2Nil {
			input := make(common.RawBytes, lentot)
			copy(input[:lenL1], L1key)
			copy(input[lenL1:], byteprotocol)
			L2key, err := Calc256Hash(input)
			if err != nil {
				return nil, common.NewBasicError("Hash calculation failed", err)
			}
			return L2key, nil
		}
		h2byte := H2.Pack()
		h2len := len(h2byte)
		lentot += h2len
		input := make(common.RawBytes, lentot)
		copy(input[:lenL1], L1key)
		copy(input[lenL1:lenprot+lenL1], byteprotocol)
		copy(input[lenprot+lenL1:], h2byte)
		L2key, err := Calc256Hash(input)
		if err != nil {
			return nil, common.NewBasicError("Hash calculation failed", err)
		}
		return L2key, nil

	}
	if h2Nil {
		h1byte := H1.Pack()
		h1len := len(h1byte)
		lentot += h1len
		input := make(common.RawBytes, lentot)
		copy(input[:lenL1], L1key)
		copy(input[lenL1:lenprot+lenL1], byteprotocol)
		copy(input[lenprot+lenL1:], h1byte)
		L2key, err := Calc256Hash(input)
		if err != nil {
			return nil, common.NewBasicError("Hash calculation failed", err)
		}
		return L2key, nil
	}
	h1byte := H1.Pack()
	h1len := len(h1byte)
	lentot += h1len
	h2byte := H2.Pack()
	h2len := len(h2byte)
	lentot += h2len
	input := make(common.RawBytes, lentot)
	copy(input[:lenL1], L1key)
	copy(input[lenL1:lenprot+lenL1], byteprotocol)
	copy(input[lenprot+lenL1:lenprot+lenL1+h1len], h1byte)
	copy(input[lenprot+lenL1+h1len:], h2byte)
	L2key, err := Calc256Hash(input)
	if err != nil {
		return nil, common.NewBasicError("Hash calculation failed", err)
	}
	return L2key, nil

}

// KeyToHash generates a hash from a bytekey
func KeyToHash(key common.RawBytes) (hash.Hash, error) {
	return InitMac(key)
}

// GetNonce returns the nonce used in the encryption of the packet
func GetNonce(TS uint32, PldHash, DVF common.RawBytes) common.RawBytes {
	nonce := make(common.RawBytes, NonceSize)
	common.Order.PutUint32(nonce[:4], TS)
	copy(nonce[4:8], PldHash)
	copy(nonce[8:12], DVF[:4])
	return nonce
}

// GetAStoASHashKey simulates DRKeys. It returns a hash that can be used as a symmetric
// key between the two ASes for the specified protocol.
// Derivable on the fly for AS1
func GetAStoASHashKey(protocol string, AS1, AS2 addr.IA) (hash.Hash, error) {
	l1key, err := DeriveASKeyL1(AS1, AS2)
	if err != nil {
		return nil, common.NewBasicError("L1 Key derivation failed", err)
	}
	l2key, err := DeriveASKeyL2(l1key, nil, nil, true, true, protocol)
	if err != nil {
		return nil, common.NewBasicError("L2 Key derivation failed", err)
	}
	keymac, err := KeyToHash(l2key)
	if err != nil {
		return nil, common.NewBasicError("key to hash failed", err)
	}
	return keymac, nil
}

// GetEtoEHashKey simulates DRKeys. It returns a hash that can be used as a symmetric
// key between two end hosts for the specified protocol.
// Derivable on the fly for AS1
func GetEtoEHashKey(protocol string, AS1, AS2 addr.IA,
	AS1Host, AS2Host addr.HostAddr) (hash.Hash, error) {
	l1key, err := DeriveASKeyL1(AS1, AS2)
	if err != nil {
		return nil, common.NewBasicError("L1 Key derivation failed", err)
	}
	l2key, err := DeriveASKeyL2(l1key, AS1Host, AS2Host, false, false, protocol)
	if err != nil {
		return nil, common.NewBasicError("L2 Key derivation failed", err)
	}
	keymac, err := KeyToHash(l2key)
	if err != nil {
		return nil, common.NewBasicError("key to hash failed", err)
	}
	return keymac, nil
}
