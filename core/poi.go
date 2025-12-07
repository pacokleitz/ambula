// Package core implements Proof-of-Interaction (PoI) consensus mechanism.
package core

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"math/big"
	randpkg "math/rand"

	"golang.org/x/crypto/blake2b"

	"github.com/pacokleitz/ambula/crypto"
)

var (
	ErrInvalidPoI           = errors.New("invalid proof of interaction")
	ErrInvalidSignature     = errors.New("invalid signature in PoI")
	ErrInvalidPoILength     = errors.New("PoI length does not match expected tour length")
	ErrInvalidService       = errors.New("invalid service node in tour")
	ErrEmptyNodeList        = errors.New("node list cannot be empty")
	ErrInvalidDifficulty    = errors.New("invalid difficulty parameters")
)

// DEFAULT_SERVICE_SIZE is the default size of the service subset.
const DEFAULT_SERVICE_SIZE = 20

// Difficulty represents the PoI difficulty distribution parameters.
// Uses a uniform distribution between Min and Max for tour length.
type Difficulty struct {
	Min uint32 // Minimum tour length
	Max uint32 // Maximum tour length
}

// Mean returns the average tour length for this difficulty.
func (d Difficulty) Mean() uint32 {
	return (d.Min + d.Max) / 2
}

// Validate checks if the difficulty parameters are valid.
func (d Difficulty) Validate() error {
	if d.Min == 0 || d.Max == 0 {
		return ErrInvalidDifficulty
	}
	if d.Min > d.Max {
		return ErrInvalidDifficulty
	}
	return nil
}

// ProofOfInteraction represents a complete PoI proof.
// The proof consists of:
// - s0: Initial signature of dependency by the initiator
// - Tour steps: pairs of (signature from visited node, signature by initiator)
type ProofOfInteraction struct {
	InitialSig     crypto.Signature   // s0 = sign_u0(dependency)
	TourSignatures []crypto.Signature // [s1, sign_u0(s1), s2, sign_u0(s2), ..., sL, sign_u0(sL)]
}

// Bytes returns the byte representation of the PoI for hashing/encoding.
func (poi *ProofOfInteraction) Bytes() []byte {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(poi); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// Length returns the number of tour steps in this PoI.
func (poi *ProofOfInteraction) Length() int {
	return len(poi.TourSignatures) / 2
}

// createServices creates a pseudo-random subset of nodes based on a seed.
// This implements the createServices algorithm from the paper (Section 3.2).
// The subset size is min(20, n/2) as specified in the paper.
func createServices(nodes []crypto.PublicKey, seed crypto.Signature) []crypto.PublicKey {
	if len(nodes) == 0 {
		return []crypto.PublicKey{}
	}

	// Determine subset size: min(20, n/2)
	subsetSize := len(nodes) / 2
	if subsetSize > DEFAULT_SERVICE_SIZE {
		subsetSize = DEFAULT_SERVICE_SIZE
	}
	if subsetSize > len(nodes) {
		subsetSize = len(nodes)
	}

	// Create a deterministic RNG from the seed
	seedHash := blake2b.Sum256(seed)
	seedInt := new(big.Int).SetBytes(seedHash[:])
	rng := randpkg.New(randpkg.NewSource(seedInt.Int64()))

	// Shuffle nodes using Fisher-Yates algorithm
	nodesCopy := make([]crypto.PublicKey, len(nodes))
	copy(nodesCopy, nodes)

	for i := len(nodesCopy) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		nodesCopy[i], nodesCopy[j] = nodesCopy[j], nodesCopy[i]
	}

	// Return first subsetSize elements
	return nodesCopy[:subsetSize]
}

// tourLength generates a tour length based on the difficulty and seed.
// This implements the tourLength algorithm from the paper (Section 3.2).
// Uses uniform distribution between difficulty.Min and difficulty.Max.
func tourLength(difficulty Difficulty, seed crypto.Signature) (uint32, error) {
	if err := difficulty.Validate(); err != nil {
		return 0, err
	}

	// Create deterministic RNG from seed
	seedHash := blake2b.Sum256(seed)
	seedInt := new(big.Int).SetBytes(seedHash[:])
	rng := randpkg.New(randpkg.NewSource(seedInt.Int64()))

	// Generate random length in range [Min, Max]
	rangeSize := difficulty.Max - difficulty.Min + 1
	length := difficulty.Min + uint32(rng.Intn(int(rangeSize)))

	return length, nil
}

// PoIContext holds the context needed for PoI generation and verification.
type PoIContext struct {
	Nodes      []crypto.PublicKey // All nodes in the network
	Difficulty Difficulty         // Current difficulty
}

// SignatureRequest represents a request for signature during PoI tour.
type SignatureRequest struct {
	Hash       crypto.Hash    // Current hash in the tour
	Dependency crypto.Hash    // Dependency (previous block hash)
	Message    crypto.Hash    // Message (Merkle root of transactions)
	From       crypto.Address // Address of the requesting node
}

// Bytes returns the byte representation for signing.
func (sr *SignatureRequest) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(sr.Hash.Bytes())
	buf.Write(sr.Dependency.Bytes())
	buf.Write(sr.Message.Bytes())
	return buf.Bytes()
}

// GeneratePoI generates a Proof-of-Interaction for the given parameters.
// This implements the generatePoI algorithm from the paper (Section 3.2, Algorithm 2).
//
// Parameters:
// - initiator: The private key of the node generating the PoI
// - dependency: The hash of the previous block
// - message: The Merkle root of the current block's transactions
// - ctx: The PoI context (nodes, difficulty)
// - signatureProvider: Function to request signatures from other nodes
//
// Returns the generated PoI or an error.
func GeneratePoI(
	initiator crypto.PrivateKey,
	dependency crypto.Hash,
	message crypto.Hash,
	ctx PoIContext,
	signatureProvider func(SignatureRequest, crypto.PublicKey) (crypto.Signature, error),
) (*ProofOfInteraction, error) {
	if len(ctx.Nodes) == 0 {
		return nil, ErrEmptyNodeList
	}

	// Step 1: Sign the dependency to get s0
	s0, err := initiator.Sign(dependency)
	if err != nil {
		return nil, fmt.Errorf("failed to sign dependency: %w", err)
	}

	// Step 2: Create service subset S
	services := createServices(ctx.Nodes, s0)
	if len(services) == 0 {
		return nil, ErrEmptyNodeList
	}

	// Step 3: Determine tour length L
	length, err := tourLength(ctx.Difficulty, s0)
	if err != nil {
		return nil, fmt.Errorf("failed to determine tour length: %w", err)
	}

	// Step 4: Initialize PoI
	poi := &ProofOfInteraction{
		InitialSig:     s0,
		TourSignatures: make([]crypto.Signature, 0, length*2),
	}

	// Step 5: Compute initial hash h0 = H(s0 || m)
	currentHash := hashConcat(s0, message.Bytes())

	// Step 6: Perform the tour
	for i := uint32(0); i < length; i++ {
		// Determine next hop: next_hop = current_hash % |S|
		nextHopIndex := hashToIndex(currentHash, len(services))
		nextService := services[nextHopIndex]

		// Create signature request
		req := SignatureRequest{
			Hash:       currentHash,
			Dependency: dependency,
			Message:    message,
			From:       initiator.PublicKey().Address(),
		}

		// Request signature from the service node
		// s_i = sign_{u_i}(h_{i-1} || d || m)
		serviceSig, err := signatureProvider(req, nextService)
		if err != nil {
			return nil, fmt.Errorf("failed to get signature from service at step %d: %w", i, err)
		}

		// Add service signature to proof
		poi.TourSignatures = append(poi.TourSignatures, serviceSig)

		// Initiator signs the service signature
		// s'_i = sign_{u0}(s_i)
		initiatorSig, err := initiator.Sign(crypto.Hash(blake2b.Sum256(serviceSig)))
		if err != nil {
			return nil, fmt.Errorf("failed to sign service signature at step %d: %w", i, err)
		}

		// Add initiator signature to proof
		poi.TourSignatures = append(poi.TourSignatures, initiatorSig)

		// Update current hash: h_i = H(s'_i)
		currentHash = crypto.Hash(blake2b.Sum256(initiatorSig))
	}

	return poi, nil
}

// CheckPoI verifies a Proof-of-Interaction.
// This implements the checkPoI algorithm from the paper (Section 3.2, Algorithm 3).
//
// Parameters:
// - poi: The proof to verify
// - initiator: The public key of the node that generated the PoI
// - dependency: The hash of the previous block
// - message: The Merkle root of the block's transactions
// - ctx: The PoI context (nodes, difficulty)
//
// Returns nil if valid, error otherwise.
func CheckPoI(
	poi *ProofOfInteraction,
	initiator crypto.PublicKey,
	dependency crypto.Hash,
	message crypto.Hash,
	ctx PoIContext,
) error {
	if poi == nil {
		return ErrInvalidPoI
	}

	// Step 1: Verify s0 is a valid signature of dependency by initiator
	s0PubKey, err := poi.InitialSig.PublicKey(dependency)
	if err != nil {
		return fmt.Errorf("invalid initial signature: %w", err)
	}

	if !bytes.Equal(s0PubKey, initiator) {
		return fmt.Errorf("initial signature not from claimed initiator")
	}

	// Step 2: Recreate service subset S
	services := createServices(ctx.Nodes, poi.InitialSig)
	if len(services) == 0 {
		return ErrEmptyNodeList
	}

	// Step 3: Verify tour length L
	expectedLength, err := tourLength(ctx.Difficulty, poi.InitialSig)
	if err != nil {
		return fmt.Errorf("failed to determine expected tour length: %w", err)
	}

	actualLength := uint32(len(poi.TourSignatures) / 2)
	if actualLength != expectedLength {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidPoILength, expectedLength, actualLength)
	}

	// Step 4: Verify each step of the tour
	currentHash := hashConcat(poi.InitialSig, message.Bytes())

	for i := uint32(0); i < expectedLength; i++ {
		// Get signatures for this step
		serviceSigIdx := i * 2
		initiatorSigIdx := i*2 + 1

		if int(initiatorSigIdx) >= len(poi.TourSignatures) {
			return fmt.Errorf("PoI tour signatures incomplete at step %d", i)
		}

		serviceSig := poi.TourSignatures[serviceSigIdx]
		initiatorSig := poi.TourSignatures[initiatorSigIdx]

		// Verify next hop matches expected service
		nextHopIndex := hashToIndex(currentHash, len(services))
		expectedService := services[nextHopIndex]

		// Verify service signature: s_i = sign_{u_i}(h_{i-1} || d || m)
		reqBytes := &bytes.Buffer{}
		reqBytes.Write(currentHash.Bytes())
		reqBytes.Write(dependency.Bytes())
		reqBytes.Write(message.Bytes())
		reqHash := crypto.Hash(blake2b.Sum256(reqBytes.Bytes()))

		servicePubKey, err := serviceSig.PublicKey(reqHash)
		if err != nil {
			return fmt.Errorf("invalid service signature at step %d: %w", i, err)
		}

		if !bytes.Equal(servicePubKey, expectedService) {
			return fmt.Errorf("%w: at step %d, expected service %s, got %s",
				ErrInvalidService, i,
				crypto.PublicKey(expectedService).String(),
				crypto.PublicKey(servicePubKey).String())
		}

		// Verify initiator signature: s'_i = sign_{u0}(s_i)
		serviceSigHash := crypto.Hash(blake2b.Sum256(serviceSig))
		initiatorSigPubKey, err := initiatorSig.PublicKey(serviceSigHash)
		if err != nil {
			return fmt.Errorf("invalid initiator signature at step %d: %w", i, err)
		}

		if !bytes.Equal(initiatorSigPubKey, initiator) {
			return fmt.Errorf("initiator signature at step %d not from claimed initiator", i)
		}

		// Update current hash for next iteration
		currentHash = crypto.Hash(blake2b.Sum256(initiatorSig))
	}

	return nil
}

// hashConcat concatenates a signature and bytes, then hashes the result.
func hashConcat(sig crypto.Signature, data []byte) crypto.Hash {
	buf := &bytes.Buffer{}
	buf.Write(sig)
	buf.Write(data)
	return crypto.Hash(blake2b.Sum256(buf.Bytes()))
}

// hashToIndex converts a hash to an index in the range [0, n).
func hashToIndex(hash crypto.Hash, n int) int {
	if n == 0 {
		return 0
	}

	// Use first 8 bytes of hash as uint64
	hashBytes := hash.Bytes()
	var num uint64
	if len(hashBytes) >= 8 {
		num = binary.BigEndian.Uint64(hashBytes[:8])
	} else {
		// Pad with zeros if hash is shorter
		padded := make([]byte, 8)
		copy(padded, hashBytes)
		num = binary.BigEndian.Uint64(padded)
	}

	return int(num % uint64(n))
}

// EstimatedBlockTime calculates the expected time to generate a block.
// BlockTime = 2 * Mean(Difficulty) * CommunicationDelay
func EstimatedBlockTime(difficulty Difficulty, commDelay float64) float64 {
	return 2.0 * float64(difficulty.Mean()) * commDelay
}

// AdjustDifficulty adjusts the difficulty to maintain a target block time.
// This implements difficulty adjustment similar to Bitcoin (Section 4).
//
// Parameters:
// - currentDifficulty: The current difficulty
// - targetBlockTime: Target time between blocks (in seconds)
// - actualBlockTime: Actual average time for recent blocks
// - numNodes: Number of nodes in the network
//
// Returns the new difficulty.
func AdjustDifficulty(
	currentDifficulty Difficulty,
	targetBlockTime float64,
	actualBlockTime float64,
	numNodes int,
) Difficulty {
	if actualBlockTime <= 0 || targetBlockTime <= 0 {
		return currentDifficulty
	}

	// Calculate adjustment ratio
	ratio := actualBlockTime / targetBlockTime

	// Adjust the difficulty range
	// If blocks are too fast (ratio < 1), increase difficulty (longer tours)
	// If blocks are too slow (ratio > 1), decrease difficulty (shorter tours)
	newMean := uint32(float64(currentDifficulty.Mean()) / ratio)

	// Ensure minimum difficulty
	if newMean < 1 {
		newMean = 1
	}

	// Calculate new min/max to maintain same distribution shape
	// For uniform distribution: mean = (min + max) / 2
	// We maintain the same range size
	rangeSize := currentDifficulty.Max - currentDifficulty.Min
	newMin := newMean - rangeSize/2
	newMax := newMean + rangeSize/2

	if newMin < 1 {
		newMin = 1
		newMax = newMin + rangeSize
	}

	return Difficulty{
		Min: newMin,
		Max: newMax,
	}
}
