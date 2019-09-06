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
	"crypto/sha256"

	"github.com/scionproto/scion/go/lib/common"
)

// Calc32Hash calculates a 256 bit hash of b using SHA-256. The result then
// gets xored 8 times to obtain a 32 bit hash
func Calc32Hash(b common.RawBytes) (common.RawBytes, error) {

	sum256 := sha256.Sum256([]byte(b))
	hash32 := make(common.RawBytes, 4)
	hash32[0] = sum256[0] ^ sum256[4]
	hash32[1] = sum256[1] ^ sum256[5]
	hash32[2] = sum256[2] ^ sum256[6]
	hash32[3] = sum256[3] ^ sum256[7]
	for i := 2; i < 8; i++ {
		hash32[0] = hash32[0] ^ sum256[i*4]
		hash32[1] = hash32[1] ^ sum256[i*4+1]
		hash32[2] = hash32[2] ^ sum256[i*4+2]
		hash32[3] = hash32[3] ^ sum256[i*4+3]
	}
	return hash32, nil
}

// Calc256Hash calculates a 256 bit hash of b using SHA-256
func Calc256Hash(b common.RawBytes) (common.RawBytes, error) {

	hash256 := make(common.RawBytes, 32)
	sum256 := sha256.Sum256([]byte(b))
	for i := 0; i < 32; i++ {
		hash256[i] = sum256[i]
	}
	return hash256, nil
}
