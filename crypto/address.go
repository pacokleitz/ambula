package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// ADDR_BYTE_SIZE is the length of the Address in bytes
const ADDR_BYTE_SIZE = 32

// An Address is used to publicly identify a Blockchain account
type Address [ADDR_BYTE_SIZE]uint8

// IsOwner checks that the Address was derived from the PublicKey
func (addr Address) IsOwner(pk PublicKey) bool {
	hashedPublicKey := blake2b.Sum256(pk)
	return bytes.Equal(addr.Bytes(), hashedPublicKey[:])
}

// Bytes returns the byte slice representation of the Address
func (addr Address) Bytes() []byte {
	b := make([]byte, ADDR_BYTE_SIZE)
	for i := 0; i < ADDR_BYTE_SIZE; i++ {
		b[i] = addr[i]
	}
	return b
}

// String returns the hexadecimal string representation of the Address.
func (addr Address) String() string {
	return hex.EncodeToString(addr.Bytes())
}

// AddressFromString returns an Address given a (HASH_BYTE_SIZE * 8) bits hexadecimal address string.
func AddressFromString(hexAddress string) (Address, error) {
	b, err := hex.DecodeString(hexAddress)
	if err != nil {
		return Address{}, err
	}
	return AddressFromBytes(b)
}

// AddressFromBytes returns an Address given a HASH_BYTE_SIZE byte slice.
func AddressFromBytes(b []byte) (Address, error) {
	if len(b) != ADDR_BYTE_SIZE {
		return Address{}, fmt.Errorf("byte slice length %d should match address length %d", len(b), ADDR_BYTE_SIZE)
	}

	var uints [ADDR_BYTE_SIZE]uint8
	for i := 0; i < HASH_BYTE_SIZE; i++ {
		uints[i] = b[i]
	}

	return Address(uints), nil
}
