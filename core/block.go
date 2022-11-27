// Package core implements core blockchain logic and datatypes.
package core

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/pacokleitz/ambula/crypto"
)

var (
	BlockMissingSignature = errors.New("The verified block has no signature.")
)

// PROTOCOL_VERSION represents the version of the Block format.
const PROTOCOL_VERSION = 1

// A Header is storing a Block metadatas.
type Header struct {
	Version       uint32
	DataHash      crypto.Hash
	PrevBlockHash crypto.Hash
	Height        uint32
	Timestamp     int64
}

// Bytes returns the byte slice representation of the Header.
func (h *Header) Bytes() []byte {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(h); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

// A Block contains a set of Transactions and the Signature of the Validator.
type Block struct {
	*Header
	Transactions []*Transaction
	Signature    crypto.Signature

	headerHash crypto.Hash
}

// NewBlock returns a pointer to a Block given a complete Header and a slice of Transactions.
func NewBlock(h *Header, txx []*Transaction) (*Block, error) {
	return &Block{
		Header:       h,
		Transactions: txx,
	}, nil
}

// NewBlockFromPrevHeader returns a Block initialized with the metadatas of the parent Block.
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

// AddTx adds a single Transaction to the Block and recompute the DataHash.
// This function invalidates the Block Hash cached.
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

// AddTx adds multiple Transactions to the Block and recompute the DataHash.
// This function invalidates the Block Hash cached.
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

// Sign computes the signature of the HeaderHash which certifies the content of the Block.
func (b *Block) Sign(privKey crypto.PrivateKey) error {
	headerHash := b.HeaderHash(BlockHasher{})
	sig, err := privKey.Sign(headerHash)
	if err != nil {
		return err
	}

	b.Signature = sig

	return nil
}

// VerifyData checks that the Block Transactions hash is matching the Header DataHash.
func (b *Block) VerifyData() error {
	if b.Signature == nil {
		return BlockMissingSignature
	}

	headerHash := b.HeaderHash(BlockHasher{})

	for _, tx := range b.Transactions {
		_, err := tx.Signer()
		if err != nil {
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

// Signer returns the PublicKey of the Block Signature signer.
func (b *Block) Signer() (crypto.PublicKey, error) {
	if b.Signature == nil {
		return nil, BlockMissingSignature
	}

	headerHash := b.HeaderHash(BlockHasher{})

	sigPubKey, err := b.Signature.PublicKey(headerHash)
	if err != nil {
		return nil, fmt.Errorf("Block [%s] header signature public key recovery failed.", headerHash.String())
	}

	return sigPubKey, nil
}

// Decode the Decoder into the Block.
func (b *Block) Decode(dec Decoder[*Block]) error {
	return dec.Decode(b)
}

// Encode the Block into the Encoder.
func (b *Block) Encode(enc Encoder[*Block]) error {
	return enc.Encode(b)
}

// HeaderHash returns the Block Header Hash computed using the Hasher.
// It uses a cache and only recomputes the Hash if it is unset or was invalidated.
// Methods that mutates the Block should invalidate the Hash using InvalidateHash.
func (b *Block) HeaderHash(hasher Hasher[*Header]) crypto.Hash {
	if b.headerHash.IsZero() {
		b.headerHash = hasher.Hash(b.Header)
	}
	return b.headerHash
}

// InvalidateHash invalidates the Block Hash cache.
func (b *Block) InvalidateHeaderHash() {
	b.headerHash = crypto.Hash{}
}

// ComputeDataHash computes the Hash of all the Block Transactions.
func ComputeDataHash(txx []*Transaction) (crypto.Hash, error) {
	buf := &bytes.Buffer{}

	for _, tx := range txx {
		if err := tx.Encode(NewGobTxEncoder(buf)); err != nil {
			return crypto.Hash{}, err
		}
	}

	hash := blake2b.Sum256(buf.Bytes())
	return hash, nil
}
