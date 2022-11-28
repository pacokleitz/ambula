package core

import (
	"testing"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/stretchr/testify/assert"
)

func TestLedgerAccounts(t *testing.T) {
	// Get user privKey, pubKey and Address.
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	pubKey := privKey.PublicKey()
	address := pubKey.Address()

	// Create LedgerState and user Account.
	ledger := NewLedgerState()
	createdAcc := ledger.CreateAccount(address)

	// Get the Account from the LedgerState using the user Address.
	fetchedAcc, err := ledger.GetAccount(address)
	assert.Nil(t, err)

	// Check that the fetched Account matches the created account.
	assert.Equal(t, createdAcc, fetchedAcc)
}

func TestLedgerValueTransfer(t *testing.T) {
	// Get sender privKey, pubKey and Address.
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	fromPubKey := fromPrivKey.PublicKey()
	fromAddress := fromPubKey.Address()

	// Get receiver privKey, pubKey and Address.
	toPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	toPubKey := toPrivKey.PublicKey()
	toAddress := toPubKey.Address()

	// Create Ledgerstate and fund sender balance.
	ledger := NewLedgerState()
	fromAcc := ledger.CreateAccount(fromAddress)
	fromAcc.Balance += 100

	// Check that the balance was added.
	fromBalance, err := ledger.GetBalance(fromAddress)
	assert.Nil(t, err)
	assert.Equal(t, uint64(100), fromBalance)

	// Transfer to receiver address.
	err = ledger.Transfer(fromAddress, toAddress, 42)
	assert.Nil(t, err)

	// Check that the balance was substracted from sender account.
	fromBalance, err = ledger.GetBalance(fromAddress)
	assert.Nil(t, err)
	assert.Equal(t, uint64(58), fromBalance)

	// Check that the balance was added to uncreated receiver account.
	toBalance, err := ledger.GetBalance(toAddress)
	assert.Nil(t, err)
	assert.Equal(t, uint64(42), toBalance)
}

func TestLedgerValueWithoutFunds(t *testing.T) {
	// Get sender privKey, pubKey and Address.
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	fromPubKey := fromPrivKey.PublicKey()
	fromAddress := fromPubKey.Address()

	// Get receiver privKey, pubKey and Address.
	toPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	toPubKey := toPrivKey.PublicKey()
	toAddress := toPubKey.Address()

	// Create LedgerState and sender account.
	ledger := NewLedgerState()
	ledger.CreateAccount(fromAddress)

	// Try to transfer funds without provision.
	err = ledger.Transfer(fromAddress, toAddress, 1)
	assert.NotNil(t, err)
}
