package core

import (
	"errors"
	"fmt"
	"math"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/pacokleitz/ambula/random"
	"github.com/pacokleitz/ambula/types"
)

var (
	TxMissingSignature = errors.New("The verified transaction has no signature.")
)

type Transaction struct {
	Data      []byte
	To        crypto.PublicKey
	Value     uint64
	From      crypto.PublicKey
	Signature *crypto.Signature
	Nonce     int64

	hash types.Hash
}

func NewTransaction(data []byte, to crypto.PublicKey, value uint64) *Transaction {
	// Temporary until possible to query existing nonces
	nonce, err := random.RandomInt(math.MaxInt64)
	if err != nil {
		panic(err)
	}

	return &Transaction{
		To:    to,
		Value: value,
		Data:  data,
		Nonce: nonce,
	}
}

func (tx *Transaction) Hash(hasher Hasher[*Transaction]) types.Hash {
	if tx.hash.IsZero() {
		tx.hash = hasher.Hash(tx)
	}
	return tx.hash
}

func (tx *Transaction) InvalidateHash() {
	tx.hash = types.Hash{}
}

func (tx *Transaction) Sign(privKey crypto.PrivateKey) error {
	hash := tx.Hash(TxHasher{})
	sig, err := privKey.Sign(hash.ToBytes())
	if err != nil {
		return err
	}

	tx.From = privKey.PublicKey()
	tx.Signature = sig

	return nil
}

func (tx *Transaction) Verify() error {
	if tx.Signature == nil {
		return TxMissingSignature
	}

	hash := tx.Hash(TxHasher{})
	if !tx.Signature.Verify(tx.From, hash.ToBytes()) {
		return fmt.Errorf("Tx [%s] signature verification failed.", hash.String())
	}

	return nil
}

func (tx *Transaction) Decode(dec Decoder[*Transaction]) error {
	return dec.Decode(tx)
}

func (tx *Transaction) Encode(enc Encoder[*Transaction]) error {
	return enc.Encode(tx)
}
