package main

import (
	"fmt"
	"log"
	"time"

	"github.com/pacokleitz/ambula/core"
	"github.com/pacokleitz/ambula/crypto"
	"github.com/pacokleitz/ambula/network"
)

func main() {
	fmt.Println("=== Ambula: Proof-of-Interaction Blockchain Demo ===")
	fmt.Println()

	// Run the PoI blockchain demo
	if err := runPoIDemo(); err != nil {
		log.Fatal(err)
	}
}

// runPoIDemo demonstrates the Proof-of-Interaction blockchain with goroutines.
func runPoIDemo() error {
	fmt.Println("Setting up network with 10 nodes using goroutines and message passing...")

	// Create network of nodes
	numNodes := 10
	nodes := make([]crypto.PublicKey, numNodes)
	nodePrivKeys := make([]crypto.PrivateKey, numNodes)
	nodeAddresses := make([]network.NetAddr, numNodes)

	// Generate keys and addresses for all nodes
	for i := 0; i < numNodes; i++ {
		privKey, err := crypto.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		nodes[i] = privKey.PublicKey()
		nodePrivKeys[i] = privKey
		nodeAddresses[i] = network.NetAddr{
			Addr: fmt.Sprintf("node-%d", i),
			Net:  "local",
		}
	}

	fmt.Printf("Created %d nodes\n", numNodes)
	for i, node := range nodes {
		fmt.Printf("  Node %d (%s): %s...\n", i, nodeAddresses[i].Addr, node.String()[:16])
	}
	fmt.Println()

	// Create genesis block
	fmt.Println("Creating genesis block...")
	genesisHeader := &core.Header{
		Version:       core.PROTOCOL_VERSION,
		Height:        0,
		Timestamp:     time.Now().UnixNano(),
		Difficulty:    core.Difficulty{Min: core.INITIAL_DIFFICULTY_MIN, Max: core.INITIAL_DIFFICULTY_MAX},
	}

	genesisBlock, err := core.NewBlock(genesisHeader, []*core.Transaction{})
	if err != nil {
		return fmt.Errorf("failed to create genesis block: %w", err)
	}

	// Sign genesis block (for initialization only)
	if err := genesisBlock.Sign(nodePrivKeys[0]); err != nil {
		return fmt.Errorf("failed to sign genesis block: %w", err)
	}

	genesisHash := genesisBlock.HeaderHash(core.BlockHasher{})
	fmt.Printf("Genesis block created: %s\n", genesisHash.String()[:16])
	fmt.Printf("  Height: %d\n", genesisBlock.Height)
	fmt.Printf("  Difficulty: Min=%d, Max=%d (Mean=%.1f)\n",
		genesisBlock.Difficulty.Min,
		genesisBlock.Difficulty.Max,
		float64(genesisBlock.Difficulty.Mean()))
	fmt.Println()

	// Create node registry (maps public keys to addresses)
	fmt.Println("Setting up node registry...")
	registry := network.NewNodeRegistry()
	for i := 0; i < numNodes; i++ {
		registry.Register(nodes[i], nodeAddresses[i])
	}
	fmt.Println()

	// Create transports for all nodes
	fmt.Println("Creating network transports...")
	transports := make([]*network.LocalTransport, numNodes)
	for i := 0; i < numNodes; i++ {
		transports[i] = network.NewLocalTransport(nodeAddresses[i])
	}

	// Connect all transports to each other (fully connected mesh)
	fmt.Println("Connecting nodes in a mesh network...")
	for i := 0; i < numNodes; i++ {
		for j := 0; j < numNodes; j++ {
			if i != j {
				if err := transports[i].Connect(transports[j]); err != nil {
					return fmt.Errorf("failed to connect node %d to %d: %w", i, j, err)
				}
			}
		}
	}
	fmt.Printf("All %d nodes connected\n", numNodes)
	fmt.Println()

	// Create blockchain instances for each node (they start with same genesis)
	fmt.Println("Initializing blockchain on each node...")
	poiNodes := make([]*network.PoINode, numNodes)

	for i := 0; i < numNodes; i++ {
		// Each node gets its own blockchain instance
		blockchainConfig := core.BlockchainConfig{
			Nodes:      nodes,
			Difficulty: genesisBlock.Difficulty,
		}

		// Create a copy of the genesis block for this node
		genesisBlockCopy, err := core.NewBlock(genesisBlock.Header, genesisBlock.Transactions)
		if err != nil {
			return fmt.Errorf("failed to create genesis block copy: %w", err)
		}
		genesisBlockCopy.Signature = genesisBlock.Signature

		blockchain, err := core.NewBlockchain(blockchainConfig, genesisBlockCopy)
		if err != nil {
			return fmt.Errorf("failed to create blockchain for node %d: %w", i, err)
		}

		// Create PoI node
		nodeConfig := network.PoINodeConfig{
			Address:    nodeAddresses[i],
			PrivateKey: nodePrivKeys[i],
			Transport:  transports[i],
			Registry:   registry,
			Blockchain: blockchain,
		}

		poiNodes[i] = network.NewPoINode(nodeConfig)

		// Start the node's message processing loop
		if err := poiNodes[i].Start(); err != nil {
			return fmt.Errorf("failed to start node %d: %w", i, err)
		}
	}

	fmt.Printf("All %d nodes initialized and running\n", numNodes)
	fmt.Println()

	// Cleanup: stop all nodes when done
	defer func() {
		fmt.Println("\nStopping all nodes...")
		for i, node := range poiNodes {
			node.Stop()
			fmt.Printf("  Node %d stopped\n", i)
		}
	}()

	// Give nodes a moment to fully initialize their goroutines
	time.Sleep(100 * time.Millisecond)

	// Generate some blocks using PoI
	fmt.Println("=== Generating Blocks with Proof-of-Interaction ===")
	fmt.Println()

	numBlocksToGenerate := 3

	for blockNum := 0; blockNum < numBlocksToGenerate; blockNum++ {
		// Choose a random node to generate the block
		initiatorIdx := blockNum % numNodes
		initiatorNode := poiNodes[initiatorIdx]

		fmt.Printf("Block %d: Node %d (%s) attempting to generate block...\n",
			blockNum+1, initiatorIdx, nodeAddresses[initiatorIdx].Addr)

		// Create some sample transactions
		transactions := make([]*core.Transaction, 2)
		for i := 0; i < 2; i++ {
			toAddr := nodes[(initiatorIdx+i+1)%numNodes].Address()
			tx := core.NewTransaction(
				[]byte(fmt.Sprintf("tx %d from node %d", i, initiatorIdx)),
				toAddr,
				uint64((i+1)*100),
			)
			if err := tx.Sign(nodePrivKeys[initiatorIdx]); err != nil {
				return fmt.Errorf("failed to sign transaction: %w", err)
			}
			transactions[i] = tx
		}

		// Measure time to generate block
		startTime := time.Now()

		// Generate block with PoI using network communication
		// This will send signature requests over the network via goroutines
		block, err := initiatorNode.GenerateBlock(transactions)
		if err != nil {
			return fmt.Errorf("failed to generate block: %w", err)
		}

		generationTime := time.Since(startTime)

		// Add block to the initiator's blockchain
		if err := initiatorNode.AddBlock(block); err != nil {
			return fmt.Errorf("failed to add block to initiator's chain: %w", err)
		}

		// Broadcast block to all other nodes (simplified - in real impl, would use network)
		for i, node := range poiNodes {
			if i != initiatorIdx {
				if err := node.AddBlock(block); err != nil {
					log.Printf("Warning: Node %d failed to add block: %v", i, err)
				}
			}
		}

		// Give nodes time to process the new block and clear old message tracker entries
		time.Sleep(200 * time.Millisecond)

		// Display block info
		blockHash := block.HeaderHash(core.BlockHasher{})
		fmt.Printf("  ✓ Block generated successfully using network communication!\n")
		fmt.Printf("  Hash: %s\n", blockHash.String()[:16])
		fmt.Printf("  Height: %d\n", block.Height)
		fmt.Printf("  Transactions: %d\n", len(block.Transactions))
		fmt.Printf("  PoI Tour Length: %d\n", block.Proof.Length())
		fmt.Printf("  Generation Time: %v (includes network round-trips)\n", generationTime)
		fmt.Printf("  Difficulty: Min=%d, Max=%d (Mean=%.1f)\n",
			block.Difficulty.Min,
			block.Difficulty.Max,
			float64(block.Difficulty.Mean()))

		// Verify the block
		ctx := core.PoIContext{
			Nodes:      nodes,
			Difficulty: block.Difficulty,
		}
		if err := block.VerifyProof(ctx); err != nil {
			return fmt.Errorf("block verification failed: %w", err)
		}
		fmt.Printf("  ✓ PoI proof verified!\n")

		initiatorPubKey, _ := block.Initiator()
		fmt.Printf("  Initiator: %s...\n", initiatorPubKey.String()[:16])
		fmt.Println()

		// Small delay between blocks
		time.Sleep(100 * time.Millisecond)
	}

	// Display final blockchain state (from node 0's perspective)
	fmt.Println("=== Blockchain Summary ===")
	blockchain := poiNodes[0].GetBlockchain()
	fmt.Printf("Current Height: %d (from node 0's view)\n", blockchain.Height())
	fmt.Printf("Total Blocks: %d\n", blockchain.Height()+1) // +1 for genesis

	lastBlock := blockchain.LastBlock()
	lastBlockHash := lastBlock.HeaderHash(core.BlockHasher{})
	fmt.Printf("Last Block Hash: %s\n", lastBlockHash.String()[:16])

	difficulty := blockchain.GetDifficulty()
	fmt.Printf("Current Difficulty: Min=%d, Max=%d (Mean=%.1f)\n",
		difficulty.Min,
		difficulty.Max,
		float64(difficulty.Mean()))

	// Verify all nodes have the same chain
	fmt.Println("\nVerifying chain consistency across all nodes...")
	allConsistent := true
	for i := 1; i < numNodes; i++ {
		nodeChain := poiNodes[i].GetBlockchain()
		nodeHeight := nodeChain.Height()
		nodeLastBlock := nodeChain.LastBlock()
		nodeLastHash := nodeLastBlock.HeaderHash(core.BlockHasher{})

		if nodeHeight != blockchain.Height() {
			fmt.Printf("  ✗ Node %d has different height: %d\n", i, nodeHeight)
			allConsistent = false
		} else if nodeLastHash != lastBlockHash {
			fmt.Printf("  ✗ Node %d has different last block hash\n", i)
			allConsistent = false
		}
	}

	if allConsistent {
		fmt.Printf("  ✓ All %d nodes have consistent blockchain state!\n", numNodes)
	}

	fmt.Println("\n=== Demo Complete ===")
	fmt.Println("✓ Used goroutines with LocalTransport for message passing")
	fmt.Println("✓ Each node runs in its own goroutine")
	fmt.Println("✓ Signature requests sent over channels (network simulation)")
	fmt.Println("✓ Transport interface allows replacing with real TCP/UDP later")

	return nil
}
