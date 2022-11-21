package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
)

type PrivateKey struct {
	key *ecdsa.PrivateKey
}

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

func NewPrivateKeyFromReader(r io.Reader) (PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return PrivateKey{}, err
	}

	return PrivateKey{
		key: key,
	}, nil
}

func GeneratePrivateKey() (PrivateKey, error) {
	return NewPrivateKeyFromReader(rand.Reader)
}

func (k PrivateKey) PublicKey() PublicKey {
	return elliptic.MarshalCompressed(k.key.PublicKey, k.key.PublicKey.X, k.key.PublicKey.Y)
}

type PublicKey []byte

func (k PublicKey) String() string {
	return hex.EncodeToString(k)
}

type Signature struct {
	S *big.Int
	R *big.Int
}

func (sig Signature) String() string {
	b := append(sig.S.Bytes(), sig.R.Bytes()...)
	return hex.EncodeToString(b)
}

func (sig Signature) Verify(pubKey PublicKey, data []byte) bool {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pubKey)
	key := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return ecdsa.Verify(key, data, sig.R, sig.S)
}
