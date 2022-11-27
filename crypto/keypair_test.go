package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignRecoverPublicKey(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.Nil(t, err)
	pubKey := privKey.PublicKey()
	msg := []byte("thisisa32bytesstringmadefortests")

	sig, err := privKey.Sign(msg)
	assert.Nil(t, err)

	sigPubKey, err := sig.PublicKey(msg)
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(sigPubKey, pubKey))
}

func TestSignRecoverublicKeyTampered(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.Nil(t, err)
	pubKey := privKey.PublicKey()
	msg := []byte("thisisa32bytesstringmadefortests")

	sig, err := privKey.Sign(msg)
	assert.Nil(t, err)

	sigPubKey, err := sig.PublicKey(msg)
	assert.Nil(t, err)

	tamperedMsg := []byte("XXXXisa32bytesstringmadefortests")
	alteredMsgSigPubKey, err := sig.PublicKey(tamperedMsg)
	assert.Nil(t, err)

	assert.False(t, bytes.Equal(alteredMsgSigPubKey, pubKey))
	assert.True(t, bytes.Equal(sigPubKey, pubKey))
}

func BenchmarkPublicKeyRecover(b *testing.B) {
	privKey, _ := GeneratePrivateKey()
	msg := []byte("thisisa32bytesstringmadefortests")

	sig, _ := privKey.Sign(msg)

	for i := 0; i < b.N; i++ {
		_, _ = sig.PublicKey(msg)
	}
}
