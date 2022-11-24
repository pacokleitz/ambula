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

	address := pubKey.Address()

	assert.True(t, address.IsOwner(pubKey))
	assert.False(t, address.IsOwner(otherPubKey))
}
