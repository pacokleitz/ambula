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

	b := randomBlock(t, 0, crypto.Hash{})

	assert.Nil(t, b.Sign(privKey))
	assert.NotNil(t, b.Signature)
}

func TestBlockAddTx(t *testing.T) {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	b := randomBlock(t, 0, crypto.Hash{})

	singleTx := genTxWithSignature(t)
	assert.Nil(t, b.AddTx(singleTx))
	assert.Equal(t, b.Transactions, []*Transaction{singleTx})

	multipleTx := []*Transaction{genTxWithSignature(t), genTxWithSignature(t)}
	assert.Nil(t, b.AddTxx(multipleTx))
	assert.Equal(t, b.Transactions, append([]*Transaction{singleTx}, multipleTx...))

	assert.Nil(t, b.Sign(privKey))
	assert.Nil(t, b.Verify())
}

func TestVerifyBlock(t *testing.T) {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	b := randomBlock(t, 0, crypto.Hash{})

	// Sign and verify the block
	assert.Nil(t, b.Sign(privKey))
	assert.Nil(t, b.Verify())

	// Add a new tx to the block to invalidate signature
	assert.Nil(t, b.AddTx(genTxWithSignature(t)))
	assert.NotNil(t, b.Verify())

	// Refresh the signature to match content of the block
	assert.Nil(t, b.Sign(privKey))
	assert.Nil(t, b.Verify())

	// Switch the Validator of the block and try to verify signature
	otherPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	b.Validator = otherPrivKey.PublicKey()
	assert.NotNil(t, b.Verify())
}

func TestDecodeEncodeBlock(t *testing.T) {
	b := randomBlock(t, 1, crypto.Hash{})
	multipleTx := []*Transaction{genTxWithSignature(t), genTxWithSignature(t)}
	assert.Nil(t, b.AddTxx(multipleTx))

	blockEncoded := &bytes.Buffer{}
	assert.Nil(t, b.Encode(NewGobBlockEncoder(blockEncoded)))

	blockDecoded := new(Block)
	assert.Nil(t, blockDecoded.Decode(NewGobBlockDecoder(blockEncoded)))

	assert.Equal(t, b.Header, blockDecoded.Header)

	for i := 0; i < len(b.Transactions); i++ {
		b.Transactions[i].hash = crypto.Hash{}
		assert.Equal(t, b.Transactions[i], blockDecoded.Transactions[i])
	}

	assert.Equal(t, b.Validator, blockDecoded.Validator)
	assert.Equal(t, b.Signature, blockDecoded.Signature)
}

func randomBlock(t *testing.T, height uint32, prevBlockHash crypto.Hash) *Block {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

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
	assert.Nil(t, b.Sign(privKey))

	return b
}
