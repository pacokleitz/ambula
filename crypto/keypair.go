package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"

	"golang.org/x/crypto/blake2b"
)

// A PrivateKey is used for signing objects.
type PrivateKey struct {
	key *ecdsa.PrivateKey
}

// Sign returns the Signature of a slice of bytes.
func (k PrivateKey) Sign(data []byte) (*Signature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.key, data)
	if err != nil {
		return nil, err
	}

	return &Signature{
		R: r,
		S: s,
	}, nil
}

// NewPrivateKeyFromReader returns a random PrivateKey from a io.Reader entropy.
func NewPrivateKeyFromReader(r io.Reader) (PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), r)
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
	return elliptic.MarshalCompressed(k.key.PublicKey, k.key.PublicKey.X, k.key.PublicKey.Y)
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
type Signature struct {
	S *big.Int
	R *big.Int
}

// String returns a hexadecimal string encoding of the Signature.
func (sig Signature) String() string {
	b := append(sig.S.Bytes(), sig.R.Bytes()...)
	return hex.EncodeToString(b)
}

// Verify checks that the Signature was signed by pubKey PublicKey for the data byte slice.
func (sig Signature) Verify(pubKey PublicKey, data []byte) bool {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubKey)
	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return ecdsa.Verify(key, data, sig.R, sig.S)
}
