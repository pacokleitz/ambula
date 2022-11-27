package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"

	"golang.org/x/crypto/blake2b"

	"github.com/ethereum/go-ethereum/crypto"
)

// A PrivateKey is used for signing objects.
type PrivateKey struct {
	key *ecdsa.PrivateKey
}

// Sign returns the Signature of a slice of bytes of size 32 bytes.
func (k PrivateKey) Sign(hash Hash) (Signature, error) {
	sig, err := crypto.Sign(hash.Bytes(), k.key)
	if err != nil {
		return nil, err
	}

	return Signature(sig), nil
}

// NewPrivateKeyFromReader returns a random PrivateKey from a io.Reader entropy.
func NewPrivateKeyFromReader(r io.Reader) (PrivateKey, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return PrivateKey{}, err
	}

	return PrivateKey{
		key: key,
	}, nil
}

// GeneratePrivateKey returns a PrivateKey randomized using cryptographically secure entropy.
func GeneratePrivateKey() (PrivateKey, error) {
	return NewPrivateKeyFromReader(rand.Reader)
}

// PublicKey returns the PublicKey of the PrivateKey.
func (k PrivateKey) PublicKey() PublicKey {
	publicKey := k.key.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	return publicKeyBytes
}

// PublicKey is used to verify a PrivateKey signature.
type PublicKey []byte

// String returns a hexadecimal string encoding of the PublicKey.
func (k PublicKey) String() string {
	return hex.EncodeToString(k)
}

// Address returns the public Address corresponding to the PublicKey
func (k PublicKey) Address() Address {
	h := Hash(blake2b.Sum256(k))
	return Address(h)
}

// A Signature is used to prove that some data was signed by a PrivateKey.
type Signature []byte

// PublicKey returns the PublicKey of the Signature signer.
func (sig Signature) PublicKey(hash Hash) (PublicKey, error) {
	pubKey, err := crypto.Ecrecover(hash.Bytes(), sig)
	if err != nil {
		return nil, err
	}

	return PublicKey(pubKey), nil
}

// String returns a hexadecimal string encoding of the Signature.
func (sig Signature) String() string {
	return hex.EncodeToString(sig)
}
