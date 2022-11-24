package core

import (
	"errors"
	"fmt"
	"math"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/pacokleitz/ambula/random"
)

var (
	TxMissingSignature = errors.New("The verified transaction has no signature.")
)

// A Transaction is the object consumed for every data or value
// modification in the Blockchain. A Transaction should be signed
// by the From sender and have the To receiver PublicKey.
type Transaction struct {
	Data      []byte
	To        crypto.Address
	Value     uint64
	From      crypto.PublicKey
	Signature *crypto.Signature
	Nonce     int64

	hash crypto.Hash
}

// NewTransaction returns a Transaction with a random Nonce.
func NewTransaction(data []byte, to crypto.Address, value uint64) *Transaction {
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

// Hash returns the Transaction Hash computed using the Hasher.
// It uses a cache and only recomputes the Hash if it is unset or was invalidated.
// Methods that mutates the Transaction should invalidate the Hash using InvalidateHash.
func (tx *Transaction) Hash(hasher Hasher[*Transaction]) crypto.Hash {
	if tx.hash.IsZero() {
		tx.hash = hasher.Hash(tx)
	}
	return tx.hash
}

// InvalidateHash invalidates the Transaction Hash cache.
func (tx *Transaction) InvalidateHash() {
	tx.hash = crypto.Hash{}
}

// Sign a Transaction by signing the Transaction Hash and set the From field.
func (tx *Transaction) Sign(privKey crypto.PrivateKey) error {
	hash := tx.Hash(TxHasher{})
	sig, err := privKey.Sign(hash.Bytes())
	if err != nil {
		return err
	}

	tx.From = privKey.PublicKey()
	tx.Signature = sig

	return nil
}

// Verify that the Transaction signature is valid.
func (tx *Transaction) Verify() error {
	if tx.Signature == nil {
		return TxMissingSignature
	}

	hash := tx.Hash(TxHasher{})
	if !tx.Signature.Verify(tx.From, hash.Bytes()) {
		return fmt.Errorf("Tx [%s] signature verification failed.", hash.String())
	}

	return nil
}

// Decode the Decoder into the Transaction.
func (tx *Transaction) Decode(dec Decoder[*Transaction]) error {
	return dec.Decode(tx)
}

// Encode the Transaction into the Encoder.
func (tx *Transaction) Encode(enc Encoder[*Transaction]) error {
	return enc.Encode(tx)
}
