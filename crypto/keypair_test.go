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
	hash, err := HashFromString(HASH_LEGIT)
	assert.Nil(t, err)

	// Sign a Hash
	sig, err := privKey.Sign(hash)
	assert.Nil(t, err)

	// Recover signer PublicKey from Hash
	sigPubKey, err := sig.PublicKey(hash)
	assert.Nil(t, err)

	// Check that the PublicKey is the one of the signer
	assert.True(t, bytes.Equal(sigPubKey, pubKey))
}

func TestSignRecoverublicKeyTampered(t *testing.T) {
	privKey, err := GeneratePrivateKey()
	assert.Nil(t, err)
	pubKey := privKey.PublicKey()
	hash, err := HashFromString(HASH_LEGIT)
	assert.Nil(t, err)

	// Sign a Hash
	sig, err := privKey.Sign(hash)
	assert.Nil(t, err)

	// Recover signer PublicKey from Hash
	sigPubKey, err := sig.PublicKey(hash)
	assert.Nil(t, err)

	// Compute another Hash used as tampered Hash
	tamperedHash, err := HashFromString(HASH_TAMPERED)
	assert.Nil(t, err)

	// Try to recover the signer PublicKey from the tampered Hash
	alteredMsgSigPubKey, err := sig.PublicKey(tamperedHash)
	assert.Nil(t, err)

	// Check that the publicKey recovered using tampered Hash is not the signer PublicKey
	assert.False(t, bytes.Equal(alteredMsgSigPubKey, pubKey))

	// Check that the publicKey recovered using the signed Hash is the signer PublicKey
	assert.True(t, bytes.Equal(sigPubKey, pubKey))
}

func BenchmarkPublicKeyRecover(b *testing.B) {
	privKey, _ := GeneratePrivateKey()
	hash, _ := HashFromString(HASH_LEGIT)
	sig, _ := privKey.Sign(hash)

	// Benchmark PublicKey recovery from Signature
	for i := 0; i < b.N; i++ {
		_, _ = sig.PublicKey(hash)
	}
}
