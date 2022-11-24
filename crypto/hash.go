// Package crypto implements cryptographic types and functions used to prove integrity and ownership.
package crypto

import (
	"encoding/hex"
	"fmt"
)

// HASH_BYTE_SIZE is the hash length in bytes used by the Hash type.
const HASH_BYTE_SIZE = 32

// A Hash is a wrapper around the output of a (HASH_BYTE_SIZE * 8) bits hash function.
type Hash [HASH_BYTE_SIZE]uint8

// IsZero checks that the Hash is equal to zero (is unset or got invalidated).
func (h Hash) IsZero() bool {
	for i := 0; i < HASH_BYTE_SIZE; i++ {
		if h[i] != 0 {
			return false
		}
	}
	return true
}

// Bytes returns the byte slice representation of the Hash.
func (h Hash) Bytes() []byte {
	b := make([]byte, HASH_BYTE_SIZE)
	for i := 0; i < HASH_BYTE_SIZE; i++ {
		b[i] = h[i]
	}
	return b
}

// String returns the hexadecimal string representation of the Hash.
func (h Hash) String() string {
	return hex.EncodeToString(h.Bytes())
}

// HashFromString returns a Hash given a (HASH_BYTE_SIZE * 8) bits hexadecimal hash string.
func HashFromString(hstr string) (Hash, error) {
	hbyt, err := hex.DecodeString(hstr)
	if err != nil {
		return Hash{}, err
	}

	return HashFromBytes(hbyt)
}

// HashFromBytes returns a Hash given a HASH_BYTE_SIZE byte slice.
func HashFromBytes(b []byte) (Hash, error) {
	if len(b) != HASH_BYTE_SIZE {
		return Hash{}, fmt.Errorf("Byte slice length %d should match hash length %d", len(b), HASH_BYTE_SIZE)
	}

	var uints [HASH_BYTE_SIZE]uint8
	for i := 0; i < HASH_BYTE_SIZE; i++ {
		uints[i] = b[i]
	}

	return Hash(uints), nil
}
