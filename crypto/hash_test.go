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
	hashFromStr, err := HashFromString(HASH_LEGIT)
	assert.Nil(t, err)
	hashFromByt, err := HashFromBytes(hashFromStr.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, hashFromStr.String(), hashFromByt.String())
	assert.Equal(t, HASH_LEGIT, hashFromByt.String())
}
