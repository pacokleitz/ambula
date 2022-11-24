package core

import (
	"bytes"
	"testing"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSignVerifyTransaction(t *testing.T) {
	tx := genTxWithSignature(t)
	assert.NotNil(t, tx.Signature)
	assert.Nil(t, tx.Verify())
}

func TestVerifyTamperedTransactionReceiver(t *testing.T) {
	tx := genTxWithSignature(t)

	hackerPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	// Modify the receiver of the transaction after signature
	tx.To = hackerPrivKey.PublicKey().Address()
	tx.InvalidateHash()

	assert.NotNil(t, tx.Verify())
}

func TestVerifyTamperedTransactionSender(t *testing.T) {
	tx := genTxWithSignature(t)

	hackerPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	// Modify the sender of the transaction after signature
	tx.From = hackerPrivKey.PublicKey()

	assert.NotNil(t, tx.Verify())
}

func TestTxEncodeDecode(t *testing.T) {
	tx := genTxWithSignature(t)

	// Hash is a private field and can't be accessed by encoder so we ignore it
	tx.hash = crypto.Hash{}

	txEncoded := &bytes.Buffer{}
	assert.Nil(t, tx.Encode(NewGobTxEncoder(txEncoded)))

	txDecoded := new(Transaction)
	assert.Nil(t, txDecoded.Decode(NewGobTxDecoder(txEncoded)))
	assert.Equal(t, tx, txDecoded)
}

func genTxWithSignature(t *testing.T) *Transaction {
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	toPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	tx := NewTransaction([]byte("foo"), toPrivKey.PublicKey().Address(), 42)
	assert.Nil(t, tx.Sign(fromPrivKey))

	return tx
}
