package prf

import (
	"os"
	"path/filepath"
	"reflect"
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

func TestTag9ParamsFileLoadsSameStateWidth(t *testing.T) {
	base, err := LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		t.Fatalf("load base params: %v", err)
	}
	tag9, err := LoadBundledParams("prf_params_tag9.json")
	if err != nil {
		t.Fatalf("load tag9 params: %v", err)
	}
	if tag9.LenTag != 9 {
		t.Fatalf("tag9 LenTag=%d want 9", tag9.LenTag)
	}
	if tag9.LenKey != base.LenKey || tag9.LenNonce != base.LenNonce || tag9.T() != base.T() || tag9.RF != base.RF || tag9.RP != base.RP {
		t.Fatalf("tag9 changed non-tag shape: base=%+v tag9=%+v", base, tag9)
	}
	if tag9.SecPermBits != base.SecPermBits || tag9.SecPermBits == 0 {
		t.Fatalf("tag9 sec bits=%f base=%f", tag9.SecPermBits, base.SecPermBits)
	}
}

func TestTag10ParamsFileLoadsAndCrossesKeyNonceBoundary(t *testing.T) {
	base, err := LoadBundledParams("prf_params_tag9.json")
	if err != nil {
		t.Fatalf("load tag9 params: %v", err)
	}
	tag10, err := LoadBundledParams("prf_params_tag10.json")
	if err != nil {
		t.Fatalf("load tag10 params: %v", err)
	}
	if tag10.LenTag != 10 || tag10.LenKey != 8 {
		t.Fatalf("tag10 key/tag shape=(%d,%d)", tag10.LenKey, tag10.LenTag)
	}
	tag10Shape := *tag10
	tag10Shape.LenTag = base.LenTag
	if !reflect.DeepEqual(*base, tag10Shape) {
		t.Fatalf("tag10 changed non-tag shape: tag9=%+v tag10=%+v", base, tag10)
	}
	key := make([]Elem, tag10.LenKey)
	nonce := make([]Elem, tag10.LenNonce)
	for i := range key {
		key[i] = Elem(i + 1)
	}
	for i := range nonce {
		nonce[i] = Elem(100 + i)
	}
	tag, err := Tag(key, nonce, tag10)
	if err != nil {
		t.Fatalf("tag10: %v", err)
	}
	if len(tag) != 10 {
		t.Fatalf("tag10 output length=%d want 10", len(tag))
	}
	if tag[8] == 0 || tag[9] == 0 {
		t.Fatalf("tag10 nonce-feed-forward coordinates were zero: %v", tag[8:])
	}
}

func TestTag13ParamsFileLoadsAndProducesWiderTag(t *testing.T) {
	base, err := LoadBundledParams("prf_params_tag9.json")
	if err != nil {
		t.Fatalf("load tag9 params: %v", err)
	}
	tag13, err := LoadBundledParams("prf_params_tag13.json")
	if err != nil {
		t.Fatalf("load tag13 params: %v", err)
	}
	if tag13.LenTag != 13 {
		t.Fatalf("tag13 LenTag=%d want 13", tag13.LenTag)
	}
	tag13Shape := *tag13
	tag13Shape.LenTag = base.LenTag
	if !reflect.DeepEqual(*base, tag13Shape) {
		t.Fatalf("tag13 changed non-tag shape: tag9=%+v tag13=%+v", base, tag13)
	}
	key := make([]Elem, tag13.LenKey)
	nonce := make([]Elem, tag13.LenNonce)
	for i := range key {
		key[i] = Elem(i + 1)
	}
	for i := range nonce {
		nonce[i] = Elem(100 + i)
	}
	wider, err := Tag(key, nonce, tag13)
	if err != nil {
		t.Fatalf("tag13: %v", err)
	}
	prefix, err := Tag(key, nonce, base)
	if err != nil {
		t.Fatalf("tag9: %v", err)
	}
	if len(wider) != 13 {
		t.Fatalf("tag13 output length=%d want 13", len(wider))
	}
	for i := range prefix {
		if wider[i] != prefix[i] {
			t.Fatalf("tag13 output differs from the shared permutation at %d", i)
		}
	}
}

func TestLoadLocalOrBundledParamsKeepsRequestedTagWidth(t *testing.T) {
	params, digest, err := LoadLocalOrBundledParamsWithDigest(filepath.Join("missing", "prf_params_tag9.json"))
	if err != nil {
		t.Fatalf("load tag9 params by basename fallback: %v", err)
	}
	if params.LenTag != 9 {
		t.Fatalf("LenTag=%d want 9", params.LenTag)
	}
	if digest != "552f38ceaddf0ba0ddfc919602fcd7abfd85430f808bd1b1cf731bcd95ba438f" {
		t.Fatalf("tag9 parameter digest=%s", digest)
	}
}

func TestLoadLocalOrBundledTag10ParamsKeepsDigest(t *testing.T) {
	params, digest, err := LoadLocalOrBundledParamsWithDigest(filepath.Join("missing", "prf_params_tag10.json"))
	if err != nil {
		t.Fatalf("load tag10 params by basename fallback: %v", err)
	}
	if params.LenTag != 10 {
		t.Fatalf("LenTag=%d want 10", params.LenTag)
	}
	if digest != "93c97ee27c14f468250c3d249d8c98733ed1dee3aceeaffdfdafce5b220b8e48" {
		t.Fatalf("tag10 parameter digest=%s", digest)
	}
}

func TestLoadLocalOrBundledTag13ParamsKeepsDigest(t *testing.T) {
	params, digest, err := LoadLocalOrBundledParamsWithDigest(filepath.Join("missing", "prf_params_tag13.json"))
	if err != nil {
		t.Fatalf("load tag13 params by basename fallback: %v", err)
	}
	if params.LenTag != 13 {
		t.Fatalf("LenTag=%d want 13", params.LenTag)
	}
	if digest != "94462038554d296342ed088fcbbecd03165a8f1705fdf64346551a4eabe6b5dd" {
		t.Fatalf("tag13 parameter digest=%s", digest)
	}
}

func TestLoadLocalOrBundledParamsDoesNotHideInvalidLocalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prf_params_tag9.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadLocalOrBundledParamsWithDigest(path); err == nil {
		t.Fatal("invalid local parameter file silently fell back to bundled parameters")
	}
}
