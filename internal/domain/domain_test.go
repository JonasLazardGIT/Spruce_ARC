package domain

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestNewDomain_Deterministic(t *testing.T) {
	seed := []byte("seed")
	d1, err := NewDomain(1038337, 1024, 16, 24, seed)
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	d2, err := NewDomain(1038337, 1024, 16, 24, seed)
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	if !bytes.Equal(u64sToBytes(d1.E), u64sToBytes(d2.E)) {
		t.Fatalf("domain not deterministic for same inputs")
	}

	d3, err := NewDomain(1038337, 1024, 16, 24, []byte("different"))
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	if bytes.Equal(u64sToBytes(d1.E), u64sToBytes(d3.E)) {
		t.Fatalf("domain unexpectedly identical for different seeds")
	}
}

func TestNewDomain_PartitioningAndDistinctness(t *testing.T) {
	d, err := NewDomain(1038337, 256, 8, 13, []byte("p"))
	if err != nil {
		t.Fatalf("NewDomain: %v", err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(d.E) != 256 || d.NLeaves != 256 {
		t.Fatalf("bad E sizing: len(E)=%d NLeaves=%d", len(d.E), d.NLeaves)
	}
	if len(d.Omega) != 8 {
		t.Fatalf("bad Omega size: %d", len(d.Omega))
	}
	if len(d.OmegaPrime) != 13 {
		t.Fatalf("bad OmegaPrime size: %d", len(d.OmegaPrime))
	}
	if d.TailStart != 21 {
		t.Fatalf("bad TailStart: %d", d.TailStart)
	}
	if len(d.Tail) != 256-21 {
		t.Fatalf("bad Tail size: %d", len(d.Tail))
	}

	rng := rand.New(rand.NewSource(1))
	indices, err := d.SampleTailIndices(10, rng)
	if err != nil {
		t.Fatalf("SampleTailIndices: %v", err)
	}
	if len(indices) != 10 {
		t.Fatalf("unexpected index count: %d", len(indices))
	}
	seen := map[int]struct{}{}
	for _, idx := range indices {
		if idx < d.TailStart || idx >= d.NLeaves {
			t.Fatalf("index out of tail range: %d", idx)
		}
		if _, ok := seen[idx]; ok {
			t.Fatalf("duplicate index: %d", idx)
		}
		seen[idx] = struct{}{}
	}
}

func TestNewDomainWithPrefix_PreservesPrefixAndIsDeterministic(t *testing.T) {
	q := uint64(1038337)
	nLeaves := 512
	s := 16
	ell := 24
	prefix := make([]uint64, s+ell)
	for i := range prefix {
		prefix[i] = uint64(i + 1)
	}
	d1, err := NewDomainWithPrefix(q, nLeaves, s, ell, prefix, nil)
	if err != nil {
		t.Fatalf("NewDomainWithPrefix: %v", err)
	}
	d2, err := NewDomainWithPrefix(q, nLeaves, s, ell, prefix, nil)
	if err != nil {
		t.Fatalf("NewDomainWithPrefix: %v", err)
	}
	if !bytes.Equal(u64sToBytes(d1.E), u64sToBytes(d2.E)) {
		t.Fatalf("prefixed domain not deterministic for same inputs")
	}
	if len(d1.E) != nLeaves {
		t.Fatalf("bad E sizing: len(E)=%d want %d", len(d1.E), nLeaves)
	}
	for i := 0; i < s+ell; i++ {
		if d1.E[i] != prefix[i]%q {
			t.Fatalf("prefix mismatch at %d: got %d want %d", i, d1.E[i], prefix[i]%q)
		}
	}
	if err := d1.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestNewDomain_InputValidation(t *testing.T) {
	if _, err := NewDomain(0, 10, 2, 1, nil); err == nil {
		t.Fatalf("expected error for q=0")
	}
	if _, err := NewDomain(17, 0, 2, 1, nil); err == nil {
		t.Fatalf("expected error for nLeaves=0")
	}
	if _, err := NewDomain(17, 10, 0, 1, nil); err == nil {
		t.Fatalf("expected error for s=0")
	}
	if _, err := NewDomain(17, 10, 2, -1, nil); err == nil {
		t.Fatalf("expected error for ell<0")
	}
	if _, err := NewDomain(17, 10, 9, 1, nil); err == nil {
		t.Fatalf("expected error for s+ell>=nLeaves")
	}
	if _, err := NewDomain(17, 17, 2, 1, nil); err == nil {
		t.Fatalf("expected error for nLeaves>=q")
	}

	if _, err := NewDomainWithPrefix(17, 10, 2, 1, []uint64{1, 2}, nil); err == nil {
		t.Fatalf("expected error for prefix length mismatch")
	}
	if _, err := NewDomainWithPrefix(17, 10, 2, 1, []uint64{1, 1, 2}, nil); err == nil {
		t.Fatalf("expected error for duplicate prefix elements")
	}
}

func u64sToBytes(vs []uint64) []byte {
	out := make([]byte, 0, len(vs)*8)
	var buf [8]byte
	for _, v := range vs {
		buf[0] = byte(v)
		buf[1] = byte(v >> 8)
		buf[2] = byte(v >> 16)
		buf[3] = byte(v >> 24)
		buf[4] = byte(v >> 32)
		buf[5] = byte(v >> 40)
		buf[6] = byte(v >> 48)
		buf[7] = byte(v >> 56)
		out = append(out, buf[:]...)
	}
	return out
}
