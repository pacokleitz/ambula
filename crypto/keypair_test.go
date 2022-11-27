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
	hash, _ := HashFromString(HASH_LEGIT)

	sig, err := privKey.Sign(hash)
	assert.Nil(t, err)

	sigPubKey, err := sig.PublicKey(hash)
	assert.Nil(t, err)
	assert.True(t, bytes.Equal(sigPubKey, pubKey))
}

func TestSignRecoverublicKeyTampered(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.Nil(t, err)
	pubKey := privKey.PublicKey()

	hash, _ := HashFromString(HASH_LEGIT)

	sig, err := privKey.Sign(hash)
	assert.Nil(t, err)

	sigPubKey, err := sig.PublicKey(hash)
	assert.Nil(t, err)

	tamperedHash, _ := HashFromString(HASH_TAMPERED)
	alteredMsgSigPubKey, err := sig.PublicKey(tamperedHash)
	assert.Nil(t, err)

	assert.False(t, bytes.Equal(alteredMsgSigPubKey, pubKey))
	assert.True(t, bytes.Equal(sigPubKey, pubKey))
}

func BenchmarkPublicKeyRecover(b *testing.B) {
	privKey, _ := GeneratePrivateKey()
	hash, _ := HashFromString(HASH_LEGIT)

	sig, _ := privKey.Sign(hash)

	for i := 0; i < b.N; i++ {
		_, _ = sig.PublicKey(hash)
	}
}
