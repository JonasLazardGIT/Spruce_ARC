package prf

import (
	"path/filepath"
	"testing"
)

// A minimal sanity test with tiny parameters (not from the paper).
func TestPRFSanity(t *testing.T) {
	p := &Params{
		Q:        101,
		D:        5,
		LenKey:   2,
		LenNonce: 1,
		LenTag:   1,
		RF:       4,
		RP:       1,
		ME: [][]uint64{
			{1, 2, 3},
			{4, 5, 6},
			{7, 8, 10},
		},
		MI: [][]uint64{
			{2, 1, 0},
			{0, 3, 1},
			{1, 0, 2},
		},
		CExt: [][]uint64{
			{1, 1, 1},
			{2, 2, 2},
			{3, 3, 3},
			{4, 4, 4},
		},
		CInt: []uint64{5},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	key := []Elem{1, 2}
	nonce := []Elem{3}
	tag, err := Tag(key, nonce, p)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	if len(tag) != 1 {
		t.Fatalf("tag length = %d want 1", len(tag))
	}
	// Deterministic check on fixed params.
	const expected = Elem(42)
	if tag[0] != expected {
		t.Fatalf("tag[0]=%d want %d", tag[0], expected)
	}
}

func TestShippedCubicPRFDeterministicTag(t *testing.T) {
	p, err := LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		t.Fatalf("load params: %v", err)
	}
	if p.Q != 1017857 {
		t.Fatalf("q=%d want 1017857", p.Q)
	}
	if p.D != 3 {
		t.Fatalf("d=%d want 3", p.D)
	}
	key := make([]Elem, p.LenKey)
	nonce := make([]Elem, p.LenNonce)
	for i := range key {
		key[i] = Elem(i + 1)
	}
	for i := range nonce {
		nonce[i] = Elem(100 + i)
	}
	tag, err := Tag(key, nonce, p)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	want := []Elem{823264, 381021, 558018, 755845, 325805, 634673, 214609}
	if len(tag) != len(want) {
		t.Fatalf("tag length=%d want %d", len(tag), len(want))
	}
	for i := range want {
		if tag[i] != want[i] {
			t.Fatalf("tag[%d]=%d want %d", i, tag[i], want[i])
		}
	}
}
