package core

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/pacokleitz/ambula/types"
)

var (
	BlockMissingSignature = errors.New("The verified block has no signature.")
)

const PROTOCOL_VERSION = 1

type Header struct {
	Version       uint32
	DataHash      types.Hash
	PrevBlockHash types.Hash
	Height        uint32
	Timestamp     int64
}

func (h *Header) Bytes() []byte {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(h); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

type Block struct {
	*Header
	Transactions []*Transaction
	Validator    crypto.PublicKey
	Signature    *crypto.Signature

	headerHash types.Hash
}

func NewBlock(h *Header, txx []*Transaction) (*Block, error) {
	return &Block{
		Header:       h,
		Transactions: txx,
	}, nil
}

func NewBlockFromPrevHeader(prevHeader *Header, txx []*Transaction) (*Block, error) {
	dataHash, err := ComputeDataHash(txx)
	if err != nil {
		return nil, err
	}

	header := &Header{
		Version:       PROTOCOL_VERSION,
		Height:        prevHeader.Height + 1,
		DataHash:      dataHash,
		PrevBlockHash: BlockHasher{}.Hash(prevHeader),
		Timestamp:     time.Now().UnixNano(),
	}

	return NewBlock(header, txx)
}

func (b *Block) AddTx(tx *Transaction) error {
	b.Transactions = append(b.Transactions, tx)
	hash, err := ComputeDataHash(b.Transactions)
	if err != nil {
		return err
	}

	b.DataHash = hash
	b.InvalidateHeaderHash()
	return nil
}

func (b *Block) AddTxx(txx []*Transaction) error {
	b.Transactions = append(b.Transactions, txx...)
	hash, err := ComputeDataHash(b.Transactions)
	if err != nil {
		return err
	}

	b.DataHash = hash
	b.InvalidateHeaderHash()
	return nil
}

func (b *Block) Sign(privKey crypto.PrivateKey) error {
	headerHash := b.HeaderHash(BlockHasher{})
	sig, err := privKey.Sign(headerHash.ToBytes())
	if err != nil {
		return err
	}

	b.Validator = privKey.PublicKey()
	b.Signature = sig

	return nil
}

func (b *Block) Verify() error {
	if b.Signature == nil {
		return BlockMissingSignature
	}

	headerHash := b.HeaderHash(BlockHasher{})

	if !b.Signature.Verify(b.Validator, headerHash.ToBytes()) {
		return fmt.Errorf("Block [%s] header signature verification failed.", headerHash.String())
	}

	for _, tx := range b.Transactions {
		if err := tx.Verify(); err != nil {
			return err
		}
	}

	computedDataHash, err := ComputeDataHash(b.Transactions)
	if err != nil {
		return err
	}

	if computedDataHash != b.DataHash {
		return fmt.Errorf("Block [%s] data hash verification failed.", headerHash.String())
	}

	return nil
}

func (b *Block) Decode(dec Decoder[*Block]) error {
	return dec.Decode(b)
}

func (b *Block) Encode(enc Encoder[*Block]) error {
	return enc.Encode(b)
}

func (b *Block) HeaderHash(hasher Hasher[*Header]) types.Hash {
	if b.headerHash.IsZero() {
		b.headerHash = hasher.Hash(b.Header)
	}
	return b.headerHash
}

func (b *Block) InvalidateHeaderHash() {
	b.headerHash = types.Hash{}
}

func ComputeDataHash(txx []*Transaction) (types.Hash, error) {
	buf := &bytes.Buffer{}

	for _, tx := range txx {
		if err := tx.Encode(NewGobTxEncoder(buf)); err != nil {
			return types.Hash{}, err
		}
	}

	hash := blake2b.Sum256(buf.Bytes())
	return hash, nil
}
