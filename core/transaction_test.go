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

	// Generate a Tx and sign it.
	tx := genTxWithoutSignature(t)
	assert.Nil(t, tx.Sign(fromPrivKey))
	assert.NotNil(t, tx.Signature)

	// Recover the signer PublicKey from the Tx Signature.
	txSigner, err := tx.Signer()
	assert.Nil(t, err)

	// Check that the recovered PublicKey matches the signer PublicKey.
	assert.Equal(t, txSigner.Address().String(), fromPrivKey.PublicKey().Address().String())
}

func TestTransactionVerifyTamperedReceiver(t *testing.T) {
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	// Generate a Tx and sign it.
	tx := genTxWithoutSignature(t)
	assert.Nil(t, tx.Sign(fromPrivKey))

	hackerPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	// Modify the receiver of the transaction after signature (we need invalidate the Hash cache manually).
	tx.To = hackerPrivKey.PublicKey().Address()
	tx.InvalidateHash()

	// Recover the signer PublicKey from the Tx Signature.
	txSigner, err := tx.Signer()
	assert.Nil(t, err)

	// Check that the recovered PublicKey is not the one of the signer (because Tx data was tampered with).
	assert.NotEqual(t, txSigner.Address().String(), fromPrivKey.PublicKey().Address().String())
}

func TestTxEncodeDecode(t *testing.T) {
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)

	// Generate a Tx and sign it.
	tx := genTxWithoutSignature(t)
	assert.Nil(t, tx.Sign(fromPrivKey))

	// Hash is a private field and can't be accessed by encoder so we ignore it by zeroing it.
	tx.hash = crypto.Hash{}

	// Encode the Tx.
	txEncoded := &bytes.Buffer{}
	assert.Nil(t, tx.Encode(NewGobTxEncoder(txEncoded)))

	// Decode the encoded Tx.
	txDecoded := new(Transaction)
	assert.Nil(t, txDecoded.Decode(NewGobTxDecoder(txEncoded)))

	// Compare decoded Tx with original Tx.
	assert.Equal(t, tx, txDecoded)
}

func genTxWithoutSignature(t *testing.T) *Transaction {
	toPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	tx := NewTransaction([]byte("foo"), toPrivKey.PublicKey().Address(), 42)
	return tx
}
