package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"testing"
)

func TestInternalTargetedEntropyRequiresGuardAndRepeats(t *testing.T) {
	seed := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	t.Setenv(targetedBenchmarkSeedEnvironment, seed)
	if err := withInternalTargetedEntropy(func() error { return nil }); err == nil {
		t.Fatal("unguarded deterministic entropy was accepted")
	}
	t.Setenv(targetedBenchmarkChildEnvironment, "1")
	read := func() []byte {
		out := make([]byte, 96)
		if err := withInternalTargetedEntropy(func() error {
			_, err := cryptorand.Read(out)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	first, second := read(), read()
	if !bytes.Equal(first, second) {
		t.Fatal("same internal seed did not reproduce entropy stream")
	}
	if len(internalTargetedEntropyDigest()) != 64 {
		t.Fatal("missing seed digest")
	}
}
