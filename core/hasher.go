package core

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/crypto/blake2b"

	"github.com/pacokleitz/ambula/types"
)

type Hasher[T any] interface {
	Hash(T) types.Hash
}

type BlockHasher struct{}

func (BlockHasher) Hash(b *Header) types.Hash {
	h := blake2b.Sum256(b.Bytes())
	return types.Hash(h)
}

type TxHasher struct{}

func (TxHasher) Hash(tx *Transaction) types.Hash {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.LittleEndian, tx.Data); err != nil {
		panic(err)
	}

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

	return types.Hash(blake2b.Sum256(buf.Bytes()))
}
