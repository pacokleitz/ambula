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

func (h Hash) ToSlice() []byte {
	b := make([]byte, HASH_BYTE_SIZE)
	for i := 0; i < HASH_BYTE_SIZE; i++ {
		b[i] = h[i]
	}
	return b
}

func (h Hash) String() string {
	return hex.EncodeToString(h.ToSlice())
}

func HashFromString(hstr string) Hash {
	hbyt, err := hex.DecodeString(hstr)
	if err != nil {
		panic(err)
	}

	return HashFromBytes(hbyt)
}

func HashFromBytes(b []byte) Hash {
	if len(b) != HASH_BYTE_SIZE {
		msg := fmt.Sprintf("given bytes with length %d should be %d", len(b), HASH_BYTE_SIZE)
		panic(msg)
	}

	var value [HASH_BYTE_SIZE]uint8
	for i := 0; i < HASH_BYTE_SIZE; i++ {
		value[i] = b[i]
	}

	return Hash(value)
}
