package types

import (
	"encoding/hex"
	"fmt"
)

const HASH_BYTE_SIZE = 32

type Hash [HASH_BYTE_SIZE]uint8

func (h Hash) IsZero() bool {
	for i := 0; i < HASH_BYTE_SIZE; i++ {
		if h[i] != 0 {
			return false
		}
	}
	return true
}

func (h Hash) ToBytes() []byte {
	b := make([]byte, HASH_BYTE_SIZE)
	for i := 0; i < HASH_BYTE_SIZE; i++ {
		b[i] = h[i]
	}
	return b
}

func (h Hash) String() string {
	return hex.EncodeToString(h.ToBytes())
}

func HashFromString(hstr string) (Hash, error) {
	hbyt, err := hex.DecodeString(hstr)
	if err != nil {
		return Hash{}, err
	}

	return HashFromBytes(hbyt)
}

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
