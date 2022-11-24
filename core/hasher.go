package core

import (
	"bytes"
	"encoding/binary"

	"github.com/pacokleitz/ambula/crypto"
	"golang.org/x/crypto/blake2b"
)

// A Hasher is used to compute Hash objects for a type T.
type Hasher[T any] interface {
	Hash(T) crypto.Hash
}

// BlockHasher implements the Hasher interface for Block Header.
type BlockHasher struct{}

// Hash returns a Block Header Hash computed using blake2b 256bits.
func (BlockHasher) Hash(b *Header) crypto.Hash {
	h := blake2b.Sum256(b.Bytes())
	return crypto.Hash(h)
}

// TxHasher implements the Hasher interface for Transaction.
type TxHasher struct{}

// Hash returns a Transaction Hash computed using blake2b 256bits.
func (TxHasher) Hash(tx *Transaction) crypto.Hash {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, tx.To); err != nil {
		panic(err)
	}

	if err := binary.Write(buf, binary.LittleEndian, tx.Value); err != nil {
		panic(err)
	}

	if err := binary.Write(buf, binary.LittleEndian, tx.From); err != nil {
		panic(err)
	}

	if err := binary.Write(buf, binary.LittleEndian, tx.Nonce); err != nil {
		panic(err)
	}

	if err := binary.Write(buf, binary.LittleEndian, tx.Data); err != nil {
		panic(err)
	}

	return crypto.Hash(blake2b.Sum256(buf.Bytes()))
}
