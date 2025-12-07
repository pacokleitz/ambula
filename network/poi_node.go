// Package network implements PoI node with message-based communication.
package network

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/pacokleitz/ambula/core"
	"github.com/pacokleitz/ambula/crypto"
)

// PoINode represents a node in the PoI blockchain network.
// Each node runs in its own goroutine and communicates via Transport.
type PoINode struct {
	// Identity
	address    net.Addr
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey

	// Network
	transport Transport
	registry  *NodeRegistry // Maps public keys to network addresses

	// Blockchain
	blockchain *core.Blockchain

	// Message tracking
	messageTracker *PoIMessageTracker

	// Pending signature requests (for async responses)
	pendingRequests   map[string]chan *PoISignResponseMessage // requestID -> response channel
	pendingRequestsMu sync.RWMutex
	requestCounter    uint64 // Atomic counter for unique request IDs
	requestCounterMu  sync.Mutex

	// Control
	quitCh chan struct{}
	wg     sync.WaitGroup
}

// PoINodeConfig holds configuration for creating a PoI node.
type PoINodeConfig struct {
	Address    net.Addr
	PrivateKey crypto.PrivateKey
	Transport  Transport
	Registry   *NodeRegistry
	Blockchain *core.Blockchain
}

// NewPoINode creates a new PoI node.
func NewPoINode(config PoINodeConfig) *PoINode {
	node := &PoINode{
		address:         config.Address,
		privateKey:      config.PrivateKey,
		publicKey:       config.PrivateKey.PublicKey(),
		transport:       config.Transport,
		registry:        config.Registry,
		blockchain:      config.Blockchain,
		messageTracker:  NewPoIMessageTracker(),
		pendingRequests: make(map[string]chan *PoISignResponseMessage),
		quitCh:          make(chan struct{}),
	}

	// Set message tracker on blockchain
	config.Blockchain.SetMessageTracker(node.messageTracker)

	return node
}

// Start starts the node's message processing loop.
func (n *PoINode) Start() error {
	n.wg.Add(1)
	go n.run()
	return nil
}

// Stop stops the node.
func (n *PoINode) Stop() {
	close(n.quitCh)
	n.wg.Wait()
}

// run is the main message processing loop for the node.
func (n *PoINode) run() {
	defer n.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case rpc := <-n.transport.Consume():
			if err := n.handleRPC(rpc); err != nil {
				log.Printf("Node %s: error handling RPC: %v", n.address, err)
			}

		case <-ticker.C:
			// Periodic tasks (could add health checks, cleanup, etc.)

		case <-n.quitCh:
			return
		}
	}
}

// handleRPC handles an incoming RPC message.
func (n *PoINode) handleRPC(rpc RPC) error {
	// Read the message type (first byte)
	msgTypeByte := make([]byte, 1)
	if _, err := rpc.Payload.Read(msgTypeByte); err != nil {
		return fmt.Errorf("failed to read message type: %w", err)
	}
	msgType := MessageType(msgTypeByte[0])

	// Read the rest of the payload
	payloadData, err := io.ReadAll(rpc.Payload)
	if err != nil {
		return fmt.Errorf("failed to read payload: %w", err)
	}

	// Handle based on message type
	switch msgType {
	case MessageTypePoISignRequest:
		return n.handleSignatureRequest(rpc.From, payloadData)

	case MessageTypePoISignResponse:
		return n.handleSignatureResponse(payloadData)

	default:
		// Unknown message type - could log but not error
		return nil
	}
}

// handleSignatureRequest handles a PoI signature request from another node.
func (n *PoINode) handleSignatureRequest(from net.Addr, data []byte) error {
	// Decode the request
	req, err := DecodePoISignRequest(data)
	if err != nil {
		return fmt.Errorf("failed to decode signature request: %w", err)
	}

	// Handle the signature request using blockchain validation
	coreReq := core.SignatureRequest{
		Hash:       req.Hash,
		Dependency: req.Dependency,
		Message:    req.Message,
		From:       req.From,
	}

	signature, err := n.blockchain.HandleSignatureRequest(coreReq, n.privateKey)

	// Create response with request ID
	var response *PoISignResponseMessage
	if err != nil {
		response = &PoISignResponseMessage{
			RequestID: req.RequestID,
			Error:     err.Error(),
		}
	} else {
		response = &PoISignResponseMessage{
			RequestID: req.RequestID,
			Signature: signature,
		}
	}

	// Send response back
	return n.sendSignatureResponse(from, response)
}

// handleSignatureResponse handles a PoI signature response.
func (n *PoINode) handleSignatureResponse(data []byte) error {
	// Decode the response
	resp, err := DecodePoISignResponse(data)
	if err != nil {
		return fmt.Errorf("failed to decode signature response: %w", err)
	}

	// Find the pending request channel using the request ID
	n.pendingRequestsMu.RLock()
	ch, ok := n.pendingRequests[resp.RequestID]
	n.pendingRequestsMu.RUnlock()

	if !ok {
		// Request not found - may have timed out
		return nil
	}

	// Send response to the waiting channel
	select {
	case ch <- resp:
		// Successfully sent
	default:
		// Channel full or closed, ignore
	}

	return nil
}

// sendSignatureResponse sends a signature response to a peer.
func (n *PoINode) sendSignatureResponse(to net.Addr, response *PoISignResponseMessage) error {
	// Encode the response
	respData, err := response.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode response: %w", err)
	}

	// Prepend message type
	buf := &bytes.Buffer{}
	buf.WriteByte(byte(MessageTypePoISignResponse))
	buf.Write(respData)

	// Send via transport
	return n.transport.SendMessage(to, buf.Bytes())
}

// RequestSignature requests a signature from another node (used during PoI generation).
func (n *PoINode) RequestSignature(
	req core.SignatureRequest,
	servicePubKey crypto.PublicKey,
) (crypto.Signature, error) {
	// Look up the network address for this public key
	serviceAddr, err := n.registry.GetAddress(servicePubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to find address for service node: %w", err)
	}

	// Generate a unique request ID using atomic counter
	n.requestCounterMu.Lock()
	n.requestCounter++
	counter := n.requestCounter
	n.requestCounterMu.Unlock()

	reqID := fmt.Sprintf("%s-%d-%s",
		n.address.String(),
		counter,
		servicePubKey.String()[:8])

	// Create the request message
	reqMsg := &PoISignRequestMessage{
		RequestID:  reqID,
		Hash:       req.Hash,
		Dependency: req.Dependency,
		Message:    req.Message,
		From:       req.From,
	}

	// Encode the request
	reqData, err := reqMsg.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	// Prepend message type
	buf := &bytes.Buffer{}
	buf.WriteByte(byte(MessageTypePoISignRequest))
	buf.Write(reqData)

	// Create response channel
	respCh := make(chan *PoISignResponseMessage, 1)

	// Register pending request
	n.pendingRequestsMu.Lock()
	n.pendingRequests[reqID] = respCh
	n.pendingRequestsMu.Unlock()

	// Cleanup on return
	defer func() {
		n.pendingRequestsMu.Lock()
		delete(n.pendingRequests, reqID)
		n.pendingRequestsMu.Unlock()
		close(respCh)
	}()

	// Send the request
	if err := n.transport.SendMessage(serviceAddr, buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response with timeout
	timeout := time.After(5 * time.Second)
	select {
	case resp := <-respCh:
		if resp.Error != "" {
			return nil, fmt.Errorf("signature request failed: %s", resp.Error)
		}
		return resp.Signature, nil

	case <-timeout:
		return nil, fmt.Errorf("signature request timeout")
	}
}

// GenerateBlock generates a new block with PoI using network communication.
func (n *PoINode) GenerateBlock(transactions []*core.Transaction) (*core.Block, error) {
	// Create signature provider that uses network requests
	signatureProvider := func(req core.SignatureRequest, service crypto.PublicKey) (crypto.Signature, error) {
		return n.RequestSignature(req, service)
	}

	// Generate block using blockchain
	return n.blockchain.GenerateBlock(n.privateKey, transactions, signatureProvider)
}

// AddBlock adds a block to the blockchain.
func (n *PoINode) AddBlock(block *core.Block) error {
	return n.blockchain.AddBlock(block)
}

// GetBlockchain returns the node's blockchain.
func (n *PoINode) GetBlockchain() *core.Blockchain {
	return n.blockchain
}

// Address returns the node's network address.
func (n *PoINode) Address() net.Addr {
	return n.address
}

// PublicKey returns the node's public key.
func (n *PoINode) PublicKey() crypto.PublicKey {
	return n.publicKey
}

// NodeRegistry maps public keys to network addresses.
// This allows nodes to find each other on the network.
type NodeRegistry struct {
	mu        sync.RWMutex
	addrMap   map[string]net.Addr     // pubKey string -> address
	pubKeyMap map[string]crypto.PublicKey // address string -> pubKey
}

// NewNodeRegistry creates a new node registry.
func NewNodeRegistry() *NodeRegistry {
	return &NodeRegistry{
		addrMap:   make(map[string]net.Addr),
		pubKeyMap: make(map[string]crypto.PublicKey),
	}
}

// Register registers a node's public key and address.
func (r *NodeRegistry) Register(pubKey crypto.PublicKey, addr net.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pubKeyStr := string(pubKey)
	addrStr := addr.String()

	r.addrMap[pubKeyStr] = addr
	r.pubKeyMap[addrStr] = pubKey
}

// GetAddress returns the network address for a public key.
func (r *NodeRegistry) GetAddress(pubKey crypto.PublicKey) (net.Addr, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	addr, ok := r.addrMap[string(pubKey)]
	if !ok {
		return nil, fmt.Errorf("address not found for public key %s", pubKey.String()[:16])
	}

	return addr, nil
}

// GetPublicKey returns the public key for a network address.
func (r *NodeRegistry) GetPublicKey(addr net.Addr) (crypto.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pubKey, ok := r.pubKeyMap[addr.String()]
	if !ok {
		return nil, fmt.Errorf("public key not found for address %s", addr.String())
	}

	return pubKey, nil
}

// GetAllNodes returns all registered public keys.
func (r *NodeRegistry) GetAllNodes() []crypto.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()

	nodes := make([]crypto.PublicKey, 0, len(r.pubKeyMap))
	for _, pubKey := range r.pubKeyMap {
		nodes = append(nodes, pubKey)
	}

	return nodes
}
