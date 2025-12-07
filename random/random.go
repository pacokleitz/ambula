// Package random implements utility routines for generating
// cryptographically secure random values.
package random

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	ErrInvalidUpperBound = errors.New("the RandomInt upper bound should be > 0")
)

// RandomInt returns a random Int64 between [0, upperBound).
func RandomInt(upperBound int64) (int64, error) {
	if upperBound < 0 {
		return 0, ErrInvalidUpperBound
	}

	randomValue, err := rand.Int(rand.Reader, big.NewInt(upperBound))
	if err != nil {
		return 0, err
	}

	return randomValue.Int64(), nil
}
