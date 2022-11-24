package random

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomIntNegativ(t *testing.T) {
	_, err := RandomInt(-5)
	assert.Equal(t, err, InvalidUpperBound)
}

func TestRandomIntRandomness(t *testing.T) {
	randomVal1, err := RandomInt(math.MaxInt64)
	assert.Nil(t, err)

	randomVal2, err := RandomInt(math.MaxInt64)
	assert.Nil(t, err)

	// No way this fails
	assert.NotEqual(t, randomVal1, randomVal2)
}
