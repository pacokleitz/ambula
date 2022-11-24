package core

import (
	"testing"

	"github.com/pacokleitz/ambula/crypto"
	"github.com/stretchr/testify/assert"
)

func TestLedgerAccounts(t *testing.T) {
	privKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	pubKey := privKey.PublicKey()
	address := pubKey.Address()

	ledger := NewLedgerState()
	createdAcc := ledger.CreateAccount(address)
	fetchedAcc, err := ledger.GetAccount(address)
	assert.Nil(t, err)

	assert.Equal(t, createdAcc, fetchedAcc)
}

func TestLedgerValueTransfer(t *testing.T) {
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	fromPubKey := fromPrivKey.PublicKey()
	fromAddress := fromPubKey.Address()

	toPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	toPubKey := toPrivKey.PublicKey()
	toAddress := toPubKey.Address()

	ledger := NewLedgerState()
	fromAcc := ledger.CreateAccount(fromAddress)

	fromAcc.Balance += 100

	fromBalance, err := ledger.GetBalance(fromAddress)
	assert.Nil(t, err)
	assert.Equal(t, uint64(100), fromBalance)

	err = ledger.Transfer(fromAddress, toAddress, 42)
	assert.Nil(t, err)

	fromBalance, err = ledger.GetBalance(fromAddress)
	assert.Nil(t, err)
	assert.Equal(t, uint64(58), fromBalance)

	toBalance, err := ledger.GetBalance(toAddress)
	assert.Nil(t, err)
	assert.Equal(t, uint64(42), toBalance)
}

func TestLedgerValueWithoutFunds(t *testing.T) {
	fromPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	fromPubKey := fromPrivKey.PublicKey()
	fromAddress := fromPubKey.Address()

	toPrivKey, err := crypto.GeneratePrivateKey()
	assert.Nil(t, err)
	toPubKey := toPrivKey.PublicKey()
	toAddress := toPubKey.Address()

	ledger := NewLedgerState()
	ledger.CreateAccount(fromAddress)

	err = ledger.Transfer(fromAddress, toAddress, 1)
	assert.NotNil(t, err)
}
