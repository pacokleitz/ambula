// Package network implements PoI-specific network messaging.
package network

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"sync"

	"github.com/pacokleitz/ambula/core"
	"github.com/pacokleitz/ambula/crypto"
)

var (
	ErrDoubleTouringDetected = errors.New("double-touring attempt detected")
	ErrInvalidDependency     = errors.New("invalid dependency - not on longest chain")
)

// PoISignRequestMessage represents a request for a signature during PoI generation.
type PoISignRequestMessage struct {
	RequestID  string         // Unique request identifier
	Hash       crypto.Hash    // Current hash in the tour
	Dependency crypto.Hash    // Dependency (previous block hash)
	Message    crypto.Hash    // Message (Merkle root of transactions)
	From       crypto.Address // Address of the requesting node
}

// Bytes returns the byte representation for signing.
func (msg *PoISignRequestMessage) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(msg.Hash.Bytes())
	buf.Write(msg.Dependency.Bytes())
	buf.Write(msg.Message.Bytes())
	return buf.Bytes()
}

// Encode encodes the message to bytes.
func (msg *PoISignRequestMessage) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(msg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodePoISignRequest decodes a PoI signature request message.
func DecodePoISignRequest(data []byte) (*PoISignRequestMessage, error) {
	var msg PoISignRequestMessage
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// PoISignResponseMessage represents a signature response during PoI generation.
type PoISignResponseMessage struct {
	RequestID string           // Request ID this is responding to
	Signature crypto.Signature // The signature from the service node
	Error     string           // Error message if signing failed
}

// Encode encodes the response message to bytes.
func (msg *PoISignResponseMessage) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(msg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodePoISignResponse decodes a PoI signature response message.
func DecodePoISignResponse(data []byte) (*PoISignResponseMessage, error) {
	var msg PoISignResponseMessage
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// PoIPenaltyMessage reports a double-touring attempt.
type PoIPenaltyMessage struct {
	Offender crypto.Address // Address of the node attempting double-touring
	Proof1   struct {       // First proof of message with same dependency
		Dependency crypto.Hash
		Message1   crypto.Hash
	}
	Proof2 struct { // Second proof with same dependency, different message
		Message2 crypto.Hash
	}
}

// Encode encodes the penalty message to bytes.
func (msg *PoIPenaltyMessage) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(msg); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodePoIPenalty decodes a PoI penalty message.
func DecodePoIPenalty(data []byte) (*PoIPenaltyMessage, error) {
	var msg PoIPenaltyMessage
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// PoIMessageTracker tracks messages received from each node to detect double-touring.
// According to the paper (Section 4, Algorithm 2), if a node receives two messages from
// the same node with the same dependency but different messages, it's double-touring.
type PoIMessageTracker struct {
	mu       sync.RWMutex
	received map[string]map[string]crypto.Hash // [nodeAddress][dependency] -> message
}

// NewPoIMessageTracker creates a new message tracker.
func NewPoIMessageTracker() *PoIMessageTracker {
	return &PoIMessageTracker{
		received: make(map[string]map[string]crypto.Hash),
	}
}

// CheckAndRecord checks if a message is valid and records it.
// Returns an error if double-touring is detected.
// This implements the checkMessage algorithm from the paper (Algorithm 2, line 16-26).
func (t *PoIMessageTracker) CheckAndRecord(
	from crypto.Address,
	dependency crypto.Hash,
	message crypto.Hash,
) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	fromStr := from.String()
	depStr := dependency.String()

	// Initialize map for this node if needed
	if t.received[fromStr] == nil {
		t.received[fromStr] = make(map[string]crypto.Hash)
	}

	// Check if we've seen a message from this node with this dependency before
	if existingMsg, exists := t.received[fromStr][depStr]; exists {
		// If the message is different, it's double-touring!
		if existingMsg != message {
			return fmt.Errorf("%w: node %s sent two different messages (%s and %s) with dependency %s",
				ErrDoubleTouringDetected,
				fromStr,
				existingMsg.String()[:8],
				message.String()[:8],
				depStr[:8])
		}
		// Same message, same dependency - OK (might be a retry)
		return nil
	}

	// Record this message
	t.received[fromStr][depStr] = message
	return nil
}

// Clear removes old entries for a given dependency.
// This should be called when a new block is finalized to clean up memory.
func (t *PoIMessageTracker) Clear(dependency crypto.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()

	depStr := dependency.String()
	for _, deps := range t.received {
		delete(deps, depStr)
	}
}

// PoISignatureProvider is a function type that provides signatures for PoI generation.
// It's used by the consensus layer to request signatures from other nodes.
type PoISignatureProvider func(req core.SignatureRequest, service crypto.PublicKey) (crypto.Signature, error)

// CreateNetworkSignatureProvider creates a signature provider that uses the network transport.
// This is used during PoI generation to request signatures from other nodes over the network.
func CreateNetworkSignatureProvider(transport Transport) PoISignatureProvider {
	return func(req core.SignatureRequest, service crypto.PublicKey) (crypto.Signature, error) {
		// Create the request message
		reqMsg := &PoISignRequestMessage{
			Hash:       req.Hash,
			Dependency: req.Dependency,
			Message:    req.Message,
			From:       req.From,
		}

		// Encode the message
		reqData, err := reqMsg.Encode()
		if err != nil {
			return nil, fmt.Errorf("failed to encode PoI sign request: %w", err)
		}

		// Create the full message with header
		msgData := &bytes.Buffer{}
		msgData.WriteByte(byte(MessageTypePoISignRequest))
		msgData.Write(reqData)

		// TODO: Send to the service node and wait for response
		// This requires mapping PublicKey to network address
		// For now, return error - this will be implemented in the consensus layer
		return nil, errors.New("network signature provider not fully implemented - use in consensus layer")
	}
}
