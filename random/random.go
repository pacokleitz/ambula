package random

import (
	"crypto/rand"
	"errors"
	"math/big"
)

var (
	InvalidUpperBound = errors.New("The RandomInt upper bound should be > 0.")
)

func RandomInt(upperBound int64) (int64, error) {
	if upperBound <= 0 {
		return 0, InvalidUpperBound
	}

	randomValue, err := rand.Int(rand.Reader, big.NewInt(upperBound))
	if err != nil {
		return 0, err
	}

	return randomValue.Int64(), nil
}
