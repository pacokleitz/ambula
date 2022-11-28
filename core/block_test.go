package core

import (
	"bytes"
	"testing"
	"time"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/stretchr/testify/assert"
)

func TestBlockSign(t *testing.T) {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	b := randomBlockWithoutSignature(t, 0, crypto.Hash{})

	// Sign and check that the Signature was added to Block
	assert.Nil(t, b.Sign(privKey))
	assert.NotNil(t, b.Signature)
}

func TestBlockAddTx(t *testing.T) {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	b := randomBlockWithoutSignature(t, 0, crypto.Hash{})

	// Add a single signed Tx and check it was added
	singleTx := genTxWithoutSignature(t)
	assert.Nil(t, singleTx.Sign(privKey))
	assert.Nil(t, b.AddTx(singleTx))
	assert.Equal(t, b.Transactions, []*Transaction{singleTx})

	// Add a batch of Tx and check it was added
	multipleTx := []*Transaction{genTxWithoutSignature(t), genTxWithoutSignature(t)}
	assert.Nil(t, multipleTx[0].Sign(privKey))
	assert.Nil(t, multipleTx[1].Sign(privKey))
	assert.Nil(t, b.AddTxx(multipleTx))
	assert.Equal(t, b.Transactions, append([]*Transaction{singleTx}, multipleTx...))

	// Sign the Block
	assert.Nil(t, b.Sign(privKey))

	// Recover the PublicKey of the Block signer and compare it to the PublicKey matching the PrivateKey used for signing
	assert.Nil(t, b.VerifyData())

	// Recover the PublicKey of the Block signer and compare it to the PublicKey matching the PrivateKey used for signing
	blockSignerPublicKey, err := b.Signer()
	assert.Nil(t, err)
	assert.Equal(t, privKey.PublicKey().Address().String(), blockSignerPublicKey.Address().String())
}

func TestBlockDecodeEncode(t *testing.T) {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	b := randomBlockWithoutSignature(t, 1, crypto.Hash{})

	// Add multiple signed Tx to the Block
	multipleTx := []*Transaction{genTxWithoutSignature(t), genTxWithoutSignature(t)}
	assert.Nil(t, multipleTx[0].Sign(privKey))
	assert.Nil(t, multipleTx[1].Sign(privKey))
	assert.Nil(t, b.AddTxx(multipleTx))

	// Sign the Block
	assert.Nil(t, b.Sign(privKey))

	// Encode the block
	blockEncoded := &bytes.Buffer{}
	assert.Nil(t, b.Encode(NewGobBlockEncoder(blockEncoded)))

	// Decode the encoded block
	blockDecoded := new(Block)
	assert.Nil(t, blockDecoded.Decode(NewGobBlockDecoder(blockEncoded)))

	// Compare decoded block Header with original Header
	assert.Equal(t, b.Header, blockDecoded.Header)

	// Compare decoded block Transactions with original Transactions
	for i := 0; i < len(b.Transactions); i++ {
		b.Transactions[i].hash = crypto.Hash{}
		assert.Equal(t, b.Transactions[i], blockDecoded.Transactions[i])
	}

	// Compare decoded block Signature with original Signature
	assert.Equal(t, b.Signature, blockDecoded.Signature)
}

func randomBlockWithoutSignature(t *testing.T, height uint32, prevBlockHash crypto.Hash) *Block {
	header := &Header{
		Version:       1,
		PrevBlockHash: prevBlockHash,
		Height:        height,
		Timestamp:     time.Now().UnixNano(),
	}

	b, err := NewBlock(header, []*Transaction{})
	assert.Nil(t, err)

	dataHash, err := ComputeDataHash(b.Transactions)
	assert.Nil(t, err)

	b.Header.DataHash = dataHash

	return b
}
