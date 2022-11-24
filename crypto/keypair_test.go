package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignVerify(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.Nil(t, err)
	pubKey := privKey.PublicKey()
	msg := []byte("hello ambula")

	sig, err := privKey.Sign(msg)
	assert.Nil(t, err)

	assert.True(t, sig.Verify(pubKey, msg))
}

func TestSignVerifyInvalid(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.Nil(t, err)
	pubKey := privKey.PublicKey()
	msg := []byte("hello ambula")

	sig, err := privKey.Sign(msg)
	assert.Nil(t, err)

	otherPrivKey, err := GeneratePrivateKey()
	assert.Nil(t, err)
	otherPubKey := otherPrivKey.PublicKey()

	assert.False(t, sig.Verify(otherPubKey, msg))
	assert.False(t, sig.Verify(pubKey, []byte("this was not signed")))
}
