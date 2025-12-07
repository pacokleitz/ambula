// Package core implements PoI-based blockchain consensus.
package core

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/pacokleitz/ambula/crypto"
)

var (
	ErrBlockAlreadyExists = errors.New("block already exists in chain")
	ErrInvalidBlock       = errors.New("invalid block")
	ErrNoGenesisBlock     = errors.New("no genesis block in chain")
	ErrInvalidDependency  = errors.New("invalid dependency - not on longest chain")
)

const (
	// DIFFICULTY_ADJUSTMENT_INTERVAL is how often difficulty is adjusted (in blocks).
	DIFFICULTY_ADJUSTMENT_INTERVAL = 2016 // Same as Bitcoin

	// TARGET_BLOCK_TIME is the target time between blocks (in seconds).
	TARGET_BLOCK_TIME = 10.0 // 10 seconds for faster testing (Bitcoin uses 600s)

	// INITIAL_DIFFICULTY_MIN is the initial minimum tour length.
	INITIAL_DIFFICULTY_MIN = 5

	// INITIAL_DIFFICULTY_MAX is the initial maximum tour length.
	INITIAL_DIFFICULTY_MAX = 15
)

// Blockchain represents the PoI-based blockchain with consensus logic.
type Blockchain struct {
	mu sync.RWMutex

	// Chain storage
	blocks       map[string]*Block      // blockHash -> Block
	blocksByHeight map[uint32][]*Block   // height -> []*Block (for handling forks)

	// Chain state
	longestChain   []*Block               // The longest chain of blocks
	genesisBlock   *Block                 // The genesis block
	currentHeight  uint32                 // Height of the longest chain

	// PoI context
	nodes          []crypto.PublicKey     // Known nodes in the network
	difficulty     Difficulty             // Current difficulty

	// Ledger state
	ledger         *LedgerState           // Current ledger state

	// For PoI signature tracking
	messageTracker MessageTracker
}

// MessageTracker interface for tracking PoI messages to prevent double-touring.
type MessageTracker interface {
	CheckAndRecord(from crypto.Address, dependency crypto.Hash, message crypto.Hash) error
	Clear(dependency crypto.Hash)
}

// BlockchainConfig holds configuration for the blockchain.
type BlockchainConfig struct {
	Nodes      []crypto.PublicKey // Known nodes in the network
	Difficulty Difficulty         // Initial difficulty
}

// NewBlockchain creates a new blockchain with a genesis block.
func NewBlockchain(config BlockchainConfig, genesisBlock *Block) (*Blockchain, error) {
	if genesisBlock == nil {
		return nil, ErrNoGenesisBlock
	}

	// Set genesis block difficulty if not set
	if genesisBlock.Difficulty.Min == 0 {
		genesisBlock.Difficulty = config.Difficulty
	}

	bc := &Blockchain{
		blocks:         make(map[string]*Block),
		blocksByHeight: make(map[uint32][]*Block),
		longestChain:   make([]*Block, 0),
		genesisBlock:   genesisBlock,
		currentHeight:  0,
		nodes:          config.Nodes,
		difficulty:     config.Difficulty,
		ledger:         NewLedgerState(),
	}

	// Add genesis block to chain
	genesisHash := genesisBlock.HeaderHash(BlockHasher{})
	bc.blocks[genesisHash.String()] = genesisBlock
	bc.blocksByHeight[0] = []*Block{genesisBlock}
	bc.longestChain = append(bc.longestChain, genesisBlock)

	return bc, nil
}

// SetMessageTracker sets the message tracker for double-touring detection.
func (bc *Blockchain) SetMessageTracker(tracker MessageTracker) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.messageTracker = tracker
}

// Height returns the current height of the longest chain.
func (bc *Blockchain) Height() uint32 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.currentHeight
}

// GetBlock retrieves a block by its hash.
func (bc *Blockchain) GetBlock(hash crypto.Hash) (*Block, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	block, exists := bc.blocks[hash.String()]
	if !exists {
		return nil, fmt.Errorf("block %s not found", hash.String())
	}

	return block, nil
}

// GetBlockAtHeight returns all blocks at a given height (may be multiple due to forks).
func (bc *Blockchain) GetBlockAtHeight(height uint32) []*Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	return bc.blocksByHeight[height]
}

// LastBlock returns the last block in the longest chain.
func (bc *Blockchain) LastBlock() *Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if len(bc.longestChain) == 0 {
		return bc.genesisBlock
	}

	return bc.longestChain[len(bc.longestChain)-1]
}

// GetDifficulty returns the current difficulty.
func (bc *Blockchain) GetDifficulty() Difficulty {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.difficulty
}

// GetNodes returns the list of known nodes.
func (bc *Blockchain) GetNodes() []crypto.PublicKey {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Return a copy to prevent external modification
	nodes := make([]crypto.PublicKey, len(bc.nodes))
	copy(nodes, bc.nodes)
	return nodes
}

// GenerateBlock generates a new block with PoI proof.
// This implements the block generation algorithm from the paper (Section 4).
func (bc *Blockchain) GenerateBlock(
	initiator crypto.PrivateKey,
	transactions []*Transaction,
	signatureProvider func(SignatureRequest, crypto.PublicKey) (crypto.Signature, error),
) (*Block, error) {
	bc.mu.RLock()
	lastBlock := bc.LastBlock()
	difficulty := bc.difficulty
	nodes := bc.GetNodes()
	bc.mu.RUnlock()

	// Create block header
	dataHash, err := ComputeDataHash(transactions)
	if err != nil {
		return nil, fmt.Errorf("failed to compute data hash: %w", err)
	}

	prevBlockHash := lastBlock.HeaderHash(BlockHasher{})

	header := &Header{
		Version:       PROTOCOL_VERSION,
		Height:        lastBlock.Height + 1,
		DataHash:      dataHash,
		PrevBlockHash: prevBlockHash,
		Timestamp:     time.Now().UnixNano(),
		Difficulty:    difficulty,
	}

	// Create block
	block, err := NewBlock(header, transactions)
	if err != nil {
		return nil, fmt.Errorf("failed to create block: %w", err)
	}

	// Generate PoI proof
	ctx := PoIContext{
		Nodes:      nodes,
		Difficulty: difficulty,
	}

	proof, err := GeneratePoI(
		initiator,
		prevBlockHash,
		dataHash,
		ctx,
		signatureProvider,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PoI: %w", err)
	}

	block.SetProof(proof)

	return block, nil
}

// ValidateBlock validates a block before adding it to the chain.
// This checks:
// - Block structure is valid
// - All transactions are valid
// - PoI proof is valid
// - Difficulty is correct
func (bc *Blockchain) ValidateBlock(block *Block) error {
	if block == nil {
		return ErrInvalidBlock
	}

	// Check if block already exists
	blockHash := block.HeaderHash(BlockHasher{})
	bc.mu.RLock()
	if _, exists := bc.blocks[blockHash.String()]; exists {
		bc.mu.RUnlock()
		return ErrBlockAlreadyExists
	}
	nodes := bc.GetNodes()
	bc.mu.RUnlock()

	// Validate block data (transactions)
	if err := block.VerifyData(); err != nil {
		return fmt.Errorf("block data verification failed: %w", err)
	}

	// Validate PoI proof if present
	if block.Proof != nil {
		ctx := PoIContext{
			Nodes:      nodes,
			Difficulty: block.Difficulty,
		}

		if err := block.VerifyProof(ctx); err != nil {
			return fmt.Errorf("PoI proof verification failed: %w", err)
		}
	}

	// Check difficulty matches expected difficulty
	// (In a full implementation, we'd calculate expected difficulty based on recent blocks)

	return nil
}

// AddBlock adds a validated block to the blockchain.
// This implements fork resolution using the longest chain rule.
func (bc *Blockchain) AddBlock(block *Block) error {
	// Validate the block first
	if err := bc.ValidateBlock(block); err != nil {
		return err
	}

	bc.mu.Lock()
	defer bc.mu.Unlock()

	blockHash := block.HeaderHash(BlockHasher{})

	// Add block to storage
	bc.blocks[blockHash.String()] = block

	// Add to height index
	if bc.blocksByHeight[block.Height] == nil {
		bc.blocksByHeight[block.Height] = make([]*Block, 0)
	}
	bc.blocksByHeight[block.Height] = append(bc.blocksByHeight[block.Height], block)

	// Update longest chain if this block extends it
	if block.Height > bc.currentHeight {
		bc.longestChain = append(bc.longestChain, block)
		bc.currentHeight = block.Height

		// Adjust difficulty if needed
		if block.Height%DIFFICULTY_ADJUSTMENT_INTERVAL == 0 && block.Height > 0 {
			bc.adjustDifficulty()
		}

		// Clean up old message tracker entries
		if bc.messageTracker != nil {
			// Clear entries for the previous block's hash (which was the dependency for this block)
			// This prevents accepting new signature requests for blocks building on old dependencies
			if block.Height > 0 {
				// Clear the dependency that was just used (prev block hash)
				bc.messageTracker.Clear(block.PrevBlockHash)
			}
		}
	}

	return nil
}

// adjustDifficulty adjusts the difficulty based on recent block times.
// This implements the difficulty adjustment algorithm from the paper (Section 4).
func (bc *Blockchain) adjustDifficulty() {
	// Calculate average block time over the last interval
	if bc.currentHeight < DIFFICULTY_ADJUSTMENT_INTERVAL {
		return
	}

	startBlock := bc.longestChain[bc.currentHeight-DIFFICULTY_ADJUSTMENT_INTERVAL]
	endBlock := bc.longestChain[bc.currentHeight]

	timeDiff := float64(endBlock.Timestamp-startBlock.Timestamp) / 1e9 // Convert nanoseconds to seconds
	numBlocks := float64(DIFFICULTY_ADJUSTMENT_INTERVAL)
	actualBlockTime := timeDiff / numBlocks

	// Adjust difficulty
	newDifficulty := AdjustDifficulty(
		bc.difficulty,
		TARGET_BLOCK_TIME,
		actualBlockTime,
		len(bc.nodes),
	)

	bc.difficulty = newDifficulty
}

// CheckMessage checks if a PoI signature request is valid and not a double-touring attempt.
// This implements the checkMessage algorithm from the paper (Algorithm 2, lines 16-26).
func (bc *Blockchain) CheckMessage(
	from crypto.Address,
	dependency crypto.Hash,
	message crypto.Hash,
) error {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Check if dependency is on the longest chain
	lastBlock := bc.LastBlock()
	lastBlockHash := lastBlock.HeaderHash(BlockHasher{})

	if dependency != lastBlockHash {
		// Check if it's an older block on the longest chain
		isOnLongestChain := false
		for _, block := range bc.longestChain {
			if block.HeaderHash(BlockHasher{}) == dependency {
				isOnLongestChain = true
				break
			}
		}

		if !isOnLongestChain {
			return fmt.Errorf("%w: dependency %s not on longest chain",
				ErrInvalidDependency,
				dependency.String()[:8])
		}
	}

	// Check for double-touring using the message tracker
	if bc.messageTracker != nil {
		if err := bc.messageTracker.CheckAndRecord(from, dependency, message); err != nil {
			return err
		}
	}

	return nil
}

// HandleSignatureRequest handles a PoI signature request from another node.
// Returns the signature if the request is valid.
func (bc *Blockchain) HandleSignatureRequest(
	req SignatureRequest,
	nodePrivateKey crypto.PrivateKey,
) (crypto.Signature, error) {
	// Check if the request is valid (not double-touring, valid dependency)
	if err := bc.CheckMessage(req.From, req.Dependency, req.Message); err != nil {
		return nil, fmt.Errorf("invalid signature request: %w", err)
	}

	// Sign the request
	reqBytes := req.Bytes()
	reqHash := crypto.Hash(blake2b.Sum256(reqBytes))

	signature, err := nodePrivateKey.Sign(reqHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	return signature, nil
}
