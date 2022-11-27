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

	assert.Nil(t, b.Sign(privKey))
	assert.NotNil(t, b.Signature)
}

func TestBlockAddTx(t *testing.T) {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	b := randomBlockWithoutSignature(t, 0, crypto.Hash{})

	singleTx := genTxWithoutSignature(t)
	assert.Nil(t, singleTx.Sign(privKey))
	assert.Nil(t, b.AddTx(singleTx))
	assert.Equal(t, b.Transactions, []*Transaction{singleTx})

	multipleTx := []*Transaction{genTxWithoutSignature(t), genTxWithoutSignature(t)}
	assert.Nil(t, multipleTx[0].Sign(privKey))
	assert.Nil(t, multipleTx[1].Sign(privKey))
	assert.Nil(t, b.AddTxx(multipleTx))
	assert.Equal(t, b.Transactions, append([]*Transaction{singleTx}, multipleTx...))

	assert.Nil(t, b.Sign(privKey))

	blockSignerPublicKey, err := b.Verify()
	assert.Nil(t, err)
	assert.Equal(t, privKey.PublicKey().Address().String(), blockSignerPublicKey.Address().String())
}

func TestBlockDecodeEncode(t *testing.T) {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	b := randomBlockWithoutSignature(t, 1, crypto.Hash{})
	assert.Nil(t, b.Sign(privKey))
	multipleTx := []*Transaction{genTxWithoutSignature(t), genTxWithoutSignature(t)}
	assert.Nil(t, multipleTx[0].Sign(privKey))
	assert.Nil(t, multipleTx[1].Sign(privKey))
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
