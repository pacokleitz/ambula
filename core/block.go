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
	ErrBlockMissingSignature = errors.New("the verified block has no signature")
	ErrBlockMissingProof     = errors.New("the verified block has no PoI proof")
)

// PROTOCOL_VERSION represents the version of the Block format.
const PROTOCOL_VERSION = 2 // Updated for PoI support

// A Header is storing a Block metadatas.
type Header struct {
	Version       uint32
	DataHash      crypto.Hash
	PrevBlockHash crypto.Hash
	Height        uint32
	Timestamp     int64
	Difficulty    Difficulty // PoI difficulty for this block
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

// A Block contains a set of Transactions and either a Signature (legacy) or a PoI Proof.
type Block struct {
	*Header
	Transactions []*Transaction
	Signature    crypto.Signature    // Legacy: simple signature (for testing/backward compatibility)
	Proof        *ProofOfInteraction // PoI proof (used in PoI consensus)

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
// For PoI blocks, this should be followed by VerifyProof().
func (b *Block) VerifyData() error {
	// Check that block has either signature or proof
	if b.Signature == nil && b.Proof == nil {
		return ErrBlockMissingSignature
	}

	headerHash := b.HeaderHash(BlockHasher{})

	// Verify all transactions are properly signed
	for _, tx := range b.Transactions {
		_, err := tx.Signer()
		if err != nil {
			return err
		}
	}

	// Verify data hash matches transactions
	computedDataHash, err := ComputeDataHash(b.Transactions)
	if err != nil {
		return err
	}

	if computedDataHash != b.DataHash {
		return fmt.Errorf("block [%s] data hash verification failed", headerHash.String())
	}

	return nil
}

// Signer returns the PublicKey of the Block Signature signer.
// For PoI blocks, use Initiator() instead.
func (b *Block) Signer() (crypto.PublicKey, error) {
	// Try PoI proof first
	if b.Proof != nil {
		return b.Initiator()
	}

	// Fallback to legacy signature
	if b.Signature == nil {
		return nil, ErrBlockMissingSignature
	}

	headerHash := b.HeaderHash(BlockHasher{})

	sigPubKey, err := b.Signature.PublicKey(headerHash)
	if err != nil {
		return nil, fmt.Errorf("block [%s] header signature public key recovery failed", headerHash.String())
	}

	return sigPubKey, nil
}

// SetProof sets the PoI proof for this block.
func (b *Block) SetProof(proof *ProofOfInteraction) {
	b.Proof = proof
}

// Initiator returns the PublicKey of the PoI initiator (block creator).
func (b *Block) Initiator() (crypto.PublicKey, error) {
	if b.Proof == nil {
		return nil, ErrBlockMissingProof
	}

	// Recover public key from initial signature
	prevBlockHash := b.PrevBlockHash
	pubKey, err := b.Proof.InitialSig.PublicKey(prevBlockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to recover initiator public key: %w", err)
	}

	return pubKey, nil
}

// VerifyProof verifies the PoI proof for this block.
// This checks that the proof is valid for the block's content and difficulty.
func (b *Block) VerifyProof(ctx PoIContext) error {
	if b.Proof == nil {
		return ErrBlockMissingProof
	}

	// Get the initiator public key
	initiator, err := b.Initiator()
	if err != nil {
		return fmt.Errorf("failed to get initiator: %w", err)
	}

	// Verify the PoI proof
	dependency := b.PrevBlockHash
	message := b.DataHash

	// Update context with block's difficulty
	ctx.Difficulty = b.Difficulty

	err = CheckPoI(b.Proof, initiator, dependency, message, ctx)
	if err != nil {
		return fmt.Errorf("PoI verification failed: %w", err)
	}

	return nil
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
