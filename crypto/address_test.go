package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddressIsOwner(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.Nil(t, err)
	otherPrivKey, err := GeneratePrivateKey()
	assert.Nil(t, err)

	pubKey := privKey.PublicKey()
	otherPubKey := otherPrivKey.PublicKey()

	// Derive Address from PublicKey.
	address := pubKey.Address()

	// Check that the Address owns the PublicKey it was derived from.
	assert.True(t, address.IsOwner(pubKey))
	assert.False(t, address.IsOwner(otherPubKey))
}
