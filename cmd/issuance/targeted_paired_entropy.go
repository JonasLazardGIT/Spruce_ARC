package main

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/sha3"
)

const (
	targetedBenchmarkChildEnvironment = "SPRUCE_INTERNAL_TARGETED_BENCHMARK_CHILD"
	targetedBenchmarkSeedEnvironment  = "SPRUCE_INTERNAL_TARGETED_BENCHMARK_SEED"
)

var targetedEntropySwapMu sync.Mutex

type targetedLockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (r *targetedLockedReader) Read(dst []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r.Read(dst)
}

// withInternalTargetedEntropy is intentionally unreachable through flags.
// It exists only so the acceleration harness can compare baseline and
// candidate executions under an identical fresh seed. Production commands do
// not expose deterministic randomness.
func withInternalTargetedEntropy(run func() error) error {
	seedHex := os.Getenv(targetedBenchmarkSeedEnvironment)
	if seedHex == "" {
		return run()
	}
	if os.Getenv(targetedBenchmarkChildEnvironment) != "1" {
		return fmt.Errorf("internal targeted benchmark seed requires child guard")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return fmt.Errorf("invalid internal targeted benchmark seed")
	}
	shake := sha3.NewShake256()
	_, _ = shake.Write([]byte("SPRUCE/targeted-acceleration-v1/whole-run\x00"))
	_, _ = shake.Write(seed)
	reader := &targetedLockedReader{r: shake}

	targetedEntropySwapMu.Lock()
	defer targetedEntropySwapMu.Unlock()
	previous := cryptorand.Reader
	cryptorand.Reader = reader
	defer func() { cryptorand.Reader = previous }()
	return run()
}

func internalTargetedEntropyDigest() string {
	seedHex := os.Getenv(targetedBenchmarkSeedEnvironment)
	if seedHex == "" || os.Getenv(targetedBenchmarkChildEnvironment) != "1" {
		return ""
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return ""
	}
	sum := sha256.Sum256(seed)
	return hex.EncodeToString(sum[:])
}
