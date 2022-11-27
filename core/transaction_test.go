package core

import (
	"bytes"
	"testing"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/stretchr/testify/assert"
)

func TestTransactionRecoverSigner(t *testing.T) {
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	tx := genTxWithoutSignature(t)
	assert.Nil(t, tx.Sign(fromPrivKey))
	assert.NotNil(t, tx.Signature)

	txSigner, err := tx.Signer()
	assert.Nil(t, err)
	assert.Equal(t, txSigner.Address().String(), fromPrivKey.PublicKey().Address().String())
}

func TestVerifyTamperedTransactionReceiver(t *testing.T) {
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	tx := genTxWithoutSignature(t)
	assert.Nil(t, tx.Sign(fromPrivKey))

	hackerPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	// Modify the receiver of the transaction after signature (we need invalidate the Hash cache manually)
	tx.To = hackerPrivKey.PublicKey().Address()
	tx.InvalidateHash()

	txSigner, err := tx.Signer()
	assert.Nil(t, err)
	assert.NotEqual(t, txSigner.Address().String(), fromPrivKey.PublicKey().Address().String())
}

func TestTxEncodeDecode(t *testing.T) {
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	tx := genTxWithoutSignature(t)
	assert.Nil(t, tx.Sign(fromPrivKey))

	// Hash is a private field and can't be accessed by encoder so we ignore it
	tx.hash = crypto.Hash{}

	txEncoded := &bytes.Buffer{}
	assert.Nil(t, tx.Encode(NewGobTxEncoder(txEncoded)))

	txDecoded := new(Transaction)
	assert.Nil(t, txDecoded.Decode(NewGobTxDecoder(txEncoded)))
	assert.Equal(t, tx, txDecoded)
}

func genTxWithoutSignature(t *testing.T) *Transaction {
	toPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	tx := NewTransaction([]byte("foo"), toPrivKey.PublicKey().Address(), 42)
	return tx
}
