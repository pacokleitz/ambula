package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"

	"github.com/pacokleitz/ambula/crypto"
)

func TestDifficulty_Validate(t *testing.T) {
	tests := []struct {
		name    string
		diff    Difficulty
		wantErr bool
	}{
		{
			name:    "valid difficulty",
			diff:    Difficulty{Min: 10, Max: 100},
			wantErr: false,
		},
		{
			name:    "min is zero",
			diff:    Difficulty{Min: 0, Max: 100},
			wantErr: true,
		},
		{
			name:    "max is zero",
			diff:    Difficulty{Min: 10, Max: 0},
			wantErr: true,
		},
		{
			name:    "min greater than max",
			diff:    Difficulty{Min: 100, Max: 10},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.diff.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDifficulty_Mean(t *testing.T) {
	diff := Difficulty{Min: 10, Max: 100}
	expected := uint32(55)
	assert.Equal(t, expected, diff.Mean())
}

func TestCreateServices(t *testing.T) {
	// Create test nodes
	nodes := make([]crypto.PublicKey, 50)
	for i := 0; i < 50; i++ {
		privKey, err := crypto.GeneratePrivateKey()
		require.NoError(t, err)
		nodes[i] = privKey.PublicKey()
	}

	// Create a test seed
	privKey, _ := crypto.GeneratePrivateKey()
	hash := crypto.Hash(blake2b.Sum256([]byte("test")))
	seed, err := privKey.Sign(hash)
	require.NoError(t, err)

	// Test createServices
	services := createServices(nodes, seed)

	// Check subset size is min(20, n/2)
	expectedSize := 20 // min(20, 50/2) = 20
	assert.Equal(t, expectedSize, len(services))

	// Verify all services are from the original node list
	for _, service := range services {
		found := false
		for _, node := range nodes {
			if string(service) == string(node) {
				found = true
				break
			}
		}
		assert.True(t, found, "service node not found in original node list")
	}

	// Test determinism: same seed should produce same services
	services2 := createServices(nodes, seed)
	assert.Equal(t, len(services), len(services2), "createServices() not deterministic: different lengths")
	for i := range services {
		assert.Equal(t, string(services[i]), string(services2[i]), "createServices() not deterministic: node %d differs", i)
	}
}

func TestCreateServicesSmallNetwork(t *testing.T) {
	// Test with small network (< 20 nodes)
	nodes := make([]crypto.PublicKey, 10)
	for i := 0; i < 10; i++ {
		privKey, _ := crypto.GeneratePrivateKey()
		nodes[i] = privKey.PublicKey()
	}

	privKey, _ := crypto.GeneratePrivateKey()
	hash := crypto.Hash(blake2b.Sum256([]byte("test")))
	seed, _ := privKey.Sign(hash)

	services := createServices(nodes, seed)

	// Should be min(20, 10/2) = 5
	expectedSize := 5
	assert.Equal(t, expectedSize, len(services))
}

func TestTourLength(t *testing.T) {
	difficulty := Difficulty{Min: 10, Max: 100}

	privKey, _ := crypto.GeneratePrivateKey()
	hash := crypto.Hash(blake2b.Sum256([]byte("test")))
	seed, _ := privKey.Sign(hash)

	length, err := tourLength(difficulty, seed)
	require.NoError(t, err)

	// Check length is in valid range
	assert.GreaterOrEqual(t, length, difficulty.Min)
	assert.LessOrEqual(t, length, difficulty.Max)

	// Test determinism
	length2, _ := tourLength(difficulty, seed)
	assert.Equal(t, length, length2)
}

func TestGenerateAndCheckPoI(t *testing.T) {
	// Setup: Create network of nodes
	numNodes := 30
	nodes := make([]crypto.PublicKey, numNodes)
	nodePrivKeys := make(map[string]crypto.PrivateKey)

	for i := 0; i < numNodes; i++ {
		privKey, err := crypto.GeneratePrivateKey()
		require.NoError(t, err)
		nodes[i] = privKey.PublicKey()
		nodePrivKeys[string(privKey.PublicKey())] = privKey
	}

	// Create initiator
	initiatorPrivKey, err := crypto.GeneratePrivateKey()
	require.NoError(t, err)

	// Setup context
	difficulty := Difficulty{Min: 5, Max: 10}
	ctx := PoIContext{
		Nodes:      nodes,
		Difficulty: difficulty,
	}

	// Create dependency and message
	dependency := crypto.Hash(blake2b.Sum256([]byte("previous block hash")))
	message := crypto.Hash(blake2b.Sum256([]byte("merkle root")))

	// Create signature provider that simulates other nodes responding
	signatureProvider := func(req SignatureRequest, service crypto.PublicKey) (crypto.Signature, error) {
		// Find the private key for this service
		privKey, ok := nodePrivKeys[string(service)]
		require.True(t, ok, "service node not found in node list")

		// Sign the request
		reqBytes := req.Bytes()
		reqHash := crypto.Hash(blake2b.Sum256(reqBytes))
		return privKey.Sign(reqHash)
	}

	// Generate PoI
	poi, err := GeneratePoI(initiatorPrivKey, dependency, message, ctx, signatureProvider)
	require.NoError(t, err)
	require.NotNil(t, poi)

	// Verify PoI length is within expected range
	expectedLength, _ := tourLength(difficulty, poi.InitialSig)
	assert.Equal(t, expectedLength, uint32(poi.Length()))

	// Check PoI
	err = CheckPoI(poi, initiatorPrivKey.PublicKey(), dependency, message, ctx)
	assert.NoError(t, err)
}

func TestCheckPoIInvalidInitiator(t *testing.T) {
	// Setup similar to TestGenerateAndCheckPoI
	numNodes := 30
	nodes := make([]crypto.PublicKey, numNodes)
	nodePrivKeys := make(map[string]crypto.PrivateKey)

	for i := 0; i < numNodes; i++ {
		privKey, _ := crypto.GeneratePrivateKey()
		nodes[i] = privKey.PublicKey()
		nodePrivKeys[string(privKey.PublicKey())] = privKey
	}

	initiatorPrivKey, _ := crypto.GeneratePrivateKey()
	difficulty := Difficulty{Min: 5, Max: 10}
	ctx := PoIContext{
		Nodes:      nodes,
		Difficulty: difficulty,
	}

	dependency := crypto.Hash(blake2b.Sum256([]byte("previous block hash")))
	message := crypto.Hash(blake2b.Sum256([]byte("merkle root")))

	signatureProvider := func(req SignatureRequest, service crypto.PublicKey) (crypto.Signature, error) {
		privKey := nodePrivKeys[string(service)]
		reqBytes := req.Bytes()
		reqHash := crypto.Hash(blake2b.Sum256(reqBytes))
		return privKey.Sign(reqHash)
	}

	// Generate PoI
	poi, err := GeneratePoI(initiatorPrivKey, dependency, message, ctx, signatureProvider)
	require.NoError(t, err)

	// Try to verify with wrong initiator
	wrongInitiator, _ := crypto.GeneratePrivateKey()
	err = CheckPoI(poi, wrongInitiator.PublicKey(), dependency, message, ctx)
	assert.Error(t, err)
}

func TestCheckPoIWrongDependency(t *testing.T) {
	numNodes := 30
	nodes := make([]crypto.PublicKey, numNodes)
	nodePrivKeys := make(map[string]crypto.PrivateKey)

	for i := 0; i < numNodes; i++ {
		privKey, _ := crypto.GeneratePrivateKey()
		nodes[i] = privKey.PublicKey()
		nodePrivKeys[string(privKey.PublicKey())] = privKey
	}

	initiatorPrivKey, _ := crypto.GeneratePrivateKey()
	difficulty := Difficulty{Min: 5, Max: 10}
	ctx := PoIContext{
		Nodes:      nodes,
		Difficulty: difficulty,
	}

	dependency := crypto.Hash(blake2b.Sum256([]byte("previous block hash")))
	message := crypto.Hash(blake2b.Sum256([]byte("merkle root")))

	signatureProvider := func(req SignatureRequest, service crypto.PublicKey) (crypto.Signature, error) {
		privKey := nodePrivKeys[string(service)]
		reqBytes := req.Bytes()
		reqHash := crypto.Hash(blake2b.Sum256(reqBytes))
		return privKey.Sign(reqHash)
	}

	poi, _ := GeneratePoI(initiatorPrivKey, dependency, message, ctx, signatureProvider)

	// Try to verify with wrong dependency
	wrongDependency := crypto.Hash(blake2b.Sum256([]byte("wrong dependency")))
	err := CheckPoI(poi, initiatorPrivKey.PublicKey(), wrongDependency, message, ctx)
	assert.Error(t, err)
}

func TestAdjustDifficulty(t *testing.T) {
	tests := []struct {
		name            string
		currentDiff     Difficulty
		targetBlockTime float64
		actualBlockTime float64
		numNodes        int
		expectIncrease  bool
		expectDecrease  bool
	}{
		{
			name:            "blocks too fast - increase difficulty",
			currentDiff:     Difficulty{Min: 40, Max: 60},
			targetBlockTime: 10.0,
			actualBlockTime: 5.0,
			numNodes:        50,
			expectIncrease:  true,
			expectDecrease:  false,
		},
		{
			name:            "blocks too slow - decrease difficulty",
			currentDiff:     Difficulty{Min: 40, Max: 60},
			targetBlockTime: 10.0,
			actualBlockTime: 20.0,
			numNodes:        50,
			expectIncrease:  false,
			expectDecrease:  true,
		},
		{
			name:            "blocks on target - minimal change",
			currentDiff:     Difficulty{Min: 40, Max: 60},
			targetBlockTime: 10.0,
			actualBlockTime: 10.0,
			numNodes:        50,
			expectIncrease:  false,
			expectDecrease:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newDiff := AdjustDifficulty(tt.currentDiff, tt.targetBlockTime, tt.actualBlockTime, tt.numNodes)

			currentMean := tt.currentDiff.Mean()
			newMean := newDiff.Mean()

			if tt.expectIncrease {
				assert.Greater(t, newMean, currentMean, "expected difficulty to increase")
			}

			if tt.expectDecrease {
				assert.Less(t, newMean, currentMean, "expected difficulty to decrease")
			}

			if !tt.expectIncrease && !tt.expectDecrease {
				// Allow small rounding differences
				diff := int(newMean) - int(currentMean)
				assert.GreaterOrEqual(t, diff, -1, "expected difficulty to stay similar")
				assert.LessOrEqual(t, diff, 1, "expected difficulty to stay similar")
			}

			// Ensure new difficulty is valid
			assert.NoError(t, newDiff.Validate(), "adjusted difficulty should be valid")
		})
	}
}
