package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	HASH_LEGIT    = "d02b1c9fe0516a37c2497e2403c0320d502f87346aed2868d9b700402809b15a"
	HASH_TAMPERED = "c02b1c9fe0516a37c2487e2403c0320d502f87346aed2868d9b700402809b15a"
)

func TestHashConversion(t *testing.T) {
	// Create Hash from 32 bytes hex string.
	hashFromStr, err := HashFromString(HASH_LEGIT)
	assert.Nil(t, err)
	// Convert the Hash to bytes and use it as input for HashFromBytes to get a Hash
	hashFromByt, err := HashFromBytes(hashFromStr.Bytes())
	assert.Nil(t, err)
	// Check that the multiple conversions led to the original 32 bytes hex string.
	assert.Equal(t, hashFromStr.String(), hashFromByt.String())
	assert.Equal(t, HASH_LEGIT, hashFromByt.String())
}
