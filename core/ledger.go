package core

import (
	"fmt"
	"sync"

	"github.com/pacokleitz/ambula/crypto"
)

// An Account is an entry in the LedgerState.
type Account struct {
	Address crypto.Address
	Balance uint64
}

// The LedgerState is the datastructure storing and managing all Accounts.
type LedgerState struct {
	lock     sync.RWMutex
	accounts map[crypto.Address]*Account
}

// NewLedgerState initializes the LedgerState.
func NewLedgerState() *LedgerState {
	return &LedgerState{
		accounts: make(map[crypto.Address]*Account),
	}
}

// CreateAccount create a new Account in the LedgerState from an Address.
func (ls *LedgerState) CreateAccount(address crypto.Address) *Account {
	ls.lock.Lock()
	defer ls.lock.Unlock()

	acc := &Account{Address: address, Balance: 0}
	ls.accounts[address] = acc
	return acc
}

// GetAccount returns the Account matching an Address in the LedgerState.
func (s *LedgerState) GetAccount(address crypto.Address) (*Account, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.getAccountWithoutLock(address)
}

// GetAccount returns the Account matching an Address in the LedgerState without using thread-safe locking.
func (s *LedgerState) getAccountWithoutLock(address crypto.Address) (*Account, error) {
	acc, ok := s.accounts[address]
	if !ok {
		return nil, fmt.Errorf("Account %s can not be found in LedgerState.", address.String())
	}

	return acc, nil
}

// GetBalance returns the Balance in the LedgerState for an Address.
func (ls *LedgerState) GetBalance(address crypto.Address) (uint64, error) {
	ls.lock.RLock()
	defer ls.lock.RUnlock()

	acc, err := ls.getAccountWithoutLock(address)
	if err != nil {
		return 0, err
	}

	return acc.Balance, nil
}

// Transfer transfers a funds amount from one Address to another.
func (ls *LedgerState) Transfer(from, to crypto.Address, amount uint64) error {
	ls.lock.Lock()
	defer ls.lock.Unlock()

	fromAccount, err := ls.getAccountWithoutLock(from)
	if err != nil {
		return err
	}

	if fromAccount.Balance < amount {
		return fmt.Errorf("Account %s does not have sufficient funds for transfer.", fromAccount.Address.String())
	}

	if ls.accounts[to] == nil {
		ls.accounts[to] = &Account{
			Address: to,
			Balance: 0,
		}
	}

	if fromAccount.Balance != 0 {
		fromAccount.Balance -= amount
	}

	ls.accounts[to].Balance += amount

	return nil
}
