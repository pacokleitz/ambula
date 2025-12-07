package core

import (
	"testing"

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
			if (err != nil) != tt.wantErr {
				t.Errorf("Difficulty.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDifficulty_Mean(t *testing.T) {
	diff := Difficulty{Min: 10, Max: 100}
	expected := uint32(55)
	if got := diff.Mean(); got != expected {
		t.Errorf("Difficulty.Mean() = %v, want %v", got, expected)
	}
}

func TestCreateServices(t *testing.T) {
	// Create test nodes
	nodes := make([]crypto.PublicKey, 50)
	for i := 0; i < 50; i++ {
		privKey, err := crypto.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}
		nodes[i] = privKey.PublicKey()
	}

	// Create a test seed
	privKey, _ := crypto.GeneratePrivateKey()
	hash := crypto.Hash(blake2b.Sum256([]byte("test")))
	seed, err := privKey.Sign(hash)
	if err != nil {
		t.Fatalf("failed to create seed: %v", err)
	}

	// Test createServices
	services := createServices(nodes, seed)

	// Check subset size is min(20, n/2)
	expectedSize := 20 // min(20, 50/2) = 20
	if len(services) != expectedSize {
		t.Errorf("createServices() returned %d nodes, want %d", len(services), expectedSize)
	}

	// Verify all services are from the original node list
	for _, service := range services {
		found := false
		for _, node := range nodes {
			if string(service) == string(node) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("service node not found in original node list")
		}
	}

	// Test determinism: same seed should produce same services
	services2 := createServices(nodes, seed)
	if len(services) != len(services2) {
		t.Errorf("createServices() not deterministic: different lengths")
	}
	for i := range services {
		if string(services[i]) != string(services2[i]) {
			t.Errorf("createServices() not deterministic: node %d differs", i)
		}
	}
}

func TestCreateServices_SmallNetwork(t *testing.T) {
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
	if len(services) != expectedSize {
		t.Errorf("createServices() with small network returned %d nodes, want %d", len(services), expectedSize)
	}
}

func TestTourLength(t *testing.T) {
	difficulty := Difficulty{Min: 10, Max: 100}

	privKey, _ := crypto.GeneratePrivateKey()
	hash := crypto.Hash(blake2b.Sum256([]byte("test")))
	seed, _ := privKey.Sign(hash)

	length, err := tourLength(difficulty, seed)
	if err != nil {
		t.Fatalf("tourLength() error = %v", err)
	}

	// Check length is in valid range
	if length < difficulty.Min || length > difficulty.Max {
		t.Errorf("tourLength() = %d, want in range [%d, %d]", length, difficulty.Min, difficulty.Max)
	}

	// Test determinism
	length2, _ := tourLength(difficulty, seed)
	if length != length2 {
		t.Errorf("tourLength() not deterministic: %d != %d", length, length2)
	}
}

func TestGenerateAndCheckPoI(t *testing.T) {
	// Setup: Create network of nodes
	numNodes := 30
	nodes := make([]crypto.PublicKey, numNodes)
	nodePrivKeys := make(map[string]crypto.PrivateKey)

	for i := 0; i < numNodes; i++ {
		privKey, err := crypto.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}
		nodes[i] = privKey.PublicKey()
		nodePrivKeys[string(privKey.PublicKey())] = privKey
	}

	// Create initiator
	initiatorPrivKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("failed to generate initiator key: %v", err)
	}

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
		if !ok {
			t.Errorf("service node not found in node list")
			return nil, ErrInvalidService
		}

		// Sign the request
		reqBytes := req.Bytes()
		reqHash := crypto.Hash(blake2b.Sum256(reqBytes))
		return privKey.Sign(reqHash)
	}

	// Generate PoI
	poi, err := GeneratePoI(initiatorPrivKey, dependency, message, ctx, signatureProvider)
	if err != nil {
		t.Fatalf("GeneratePoI() error = %v", err)
	}

	// Verify PoI is not nil
	if poi == nil {
		t.Fatal("GeneratePoI() returned nil PoI")
	}

	// Verify PoI length is within expected range
	expectedLength, _ := tourLength(difficulty, poi.InitialSig)
	if uint32(poi.Length()) != expectedLength {
		t.Errorf("PoI length = %d, want %d", poi.Length(), expectedLength)
	}

	// Check PoI
	err = CheckPoI(poi, initiatorPrivKey.PublicKey(), dependency, message, ctx)
	if err != nil {
		t.Errorf("CheckPoI() error = %v", err)
	}
}

func TestCheckPoI_InvalidInitiator(t *testing.T) {
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
	if err != nil {
		t.Fatalf("GeneratePoI() error = %v", err)
	}

	// Try to verify with wrong initiator
	wrongInitiator, _ := crypto.GeneratePrivateKey()
	err = CheckPoI(poi, wrongInitiator.PublicKey(), dependency, message, ctx)
	if err == nil {
		t.Error("CheckPoI() should fail with wrong initiator, but succeeded")
	}
}

func TestCheckPoI_WrongDependency(t *testing.T) {
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
	if err == nil {
		t.Error("CheckPoI() should fail with wrong dependency, but succeeded")
	}
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

			if tt.expectIncrease && newMean <= currentMean {
				t.Errorf("expected difficulty to increase, but mean went from %d to %d", currentMean, newMean)
			}

			if tt.expectDecrease && newMean >= currentMean {
				t.Errorf("expected difficulty to decrease, but mean went from %d to %d", currentMean, newMean)
			}

			if !tt.expectIncrease && !tt.expectDecrease && newMean != currentMean {
				// Allow small rounding differences
				diff := int(newMean) - int(currentMean)
				if diff < -1 || diff > 1 {
					t.Errorf("expected difficulty to stay similar, but mean went from %d to %d", currentMean, newMean)
				}
			}

			// Ensure new difficulty is valid
			if err := newDiff.Validate(); err != nil {
				t.Errorf("adjusted difficulty is invalid: %v", err)
			}
		})
	}
}
