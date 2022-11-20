package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashConversion(t *testing.T) {
	hashStr := "d02b1c9fe0516a37c2497e2403c0320d502f87346aed2868d9b700402809b15a"
	hashFromStr := HashFromString(hashStr)
	hashFromSlice := HashFromBytes(hashFromStr.ToSlice())
	assert.Equal(t, hashFromStr.String(), hashFromSlice.String())
	assert.Equal(t, hashStr, hashFromSlice.String())
}
