package core

import (
	"bytes"
	"testing"
	"time"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/pacokleitz/ambula/types"
	"github.com/stretchr/testify/assert"
)

func TestSignBlock(t *testing.T) {
	privKey := crypto.GeneratePrivateKey()
	b := randomBlock(t, 0, types.Hash{})

	assert.Nil(t, b.Sign(privKey))
	assert.NotNil(t, b.Signature)
}

func TestVerifyBlock(t *testing.T) {
	privKey := crypto.GeneratePrivateKey()
	b := randomBlock(t, 0, types.Hash{})

	// Sign and verify the block
	assert.Nil(t, b.Sign(privKey))
	assert.Nil(t, b.Verify())

	// Add a new tx to the block to invalidate signature
	b.AddTx(randomTxWithSignature(t))
	assert.NotNil(t, b.Verify())

	// Refresh the signature to match content of the block
	assert.Nil(t, b.Sign(privKey))
	assert.Nil(t, b.Verify())

	// Switch the Validator of the block and try to verify signature
	otherPrivKey := crypto.GeneratePrivateKey()
	b.Validator = otherPrivKey.PublicKey()
	assert.NotNil(t, b.Verify())
}

func TestDecodeEncodeBlock(t *testing.T) {
	b := randomBlock(t, 1, types.Hash{})
	buf := &bytes.Buffer{}
	assert.Nil(t, b.Encode(NewGobBlockEncoder(buf)))

	bDecode := new(Block)
	assert.Nil(t, bDecode.Decode(NewGobBlockDecoder(buf)))

	assert.Equal(t, b.Header, bDecode.Header)

	for i := 0; i < len(b.Transactions); i++ {
		b.Transactions[i].hash = types.Hash{}
		assert.Equal(t, b.Transactions[i], bDecode.Transactions[i])
	}

	assert.Equal(t, b.Validator, bDecode.Validator)
	assert.Equal(t, b.Signature, bDecode.Signature)
}

func randomBlock(t *testing.T, height uint32, prevBlockHash types.Hash) *Block {
	privKey := crypto.GeneratePrivateKey()
	tx := randomTxWithSignature(t)
	header := &Header{
		Version:       1,
		PrevBlockHash: prevBlockHash,
		Height:        height,
		Timestamp:     time.Now().UnixNano(),
	}

	b, err := NewBlock(header, []*Transaction{tx})
	assert.Nil(t, err)
	dataHash, err := ComputeDataHash(b.Transactions)
	assert.Nil(t, err)
	b.Header.DataHash = dataHash
	assert.Nil(t, b.Sign(privKey))

	return b
}
