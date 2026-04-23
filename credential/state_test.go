package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStateRoundTripWithVectorX0Metadata(t *testing.T) {
	chdirForCredentialTest(t)
	path := filepath.Join(t.TempDir(), "credential_state.json")
	want := State{
		Version:              StateVersion,
		M:                    [][]int64{{1, -1, 0}},
		K:                    [][]int64{{0, 2, -2}},
		R0:                   [][]int64{{1, 0, -1}, {2, -2, 1}, {0, 0, 0}, {-3, 1, 2}, {4, -4, 0}, {5, 0, -5}},
		R1:                   [][]int64{{1, -1, 1}},
		Z:                    [][]int64{{3, 0, -3}},
		X0Len:                6,
		X0CoeffBound:         5,
		TargetDim:            DefaultTargetDim,
		TargetHidingLambda:   DefaultTargetHidingLambda,
		SigS1:                []int64{1, -2, 3},
		SigS2:                []int64{-1, 2, -3},
		PackedNCols:          32,
		Com:                  [][]int64{{7, 8, 9}},
		RI0:                  [][]int64{{1, 2, 3}, {4, 5, 6}, {0, 0, 1}, {1, 0, 0}, {2, 2, 2}, {3, 3, 3}},
		RI1:                  [][]int64{{-1, 0, 1}},
		CredentialPublicPath: "Parameters/credential_public.demo.json",
		HashRelation:         HashRelationBBTran,
		BPath:                "Parameters/Bmatrix_bb_tran_x0len6.json",
		B:                    [][]int64{{0, 0, 0}, {1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {1, 1, 1}, {2, 2, 2}, {3, 3, 3}, {9, 8, 7}, {6, 5, 4}},
		PRFParamsPath:        "prf/prf_params.json",
		NTRUPublic:           [][]int64{{11, 12, 13}},
	}
	if err := SaveState(path, nil, want); err != nil {
		t.Fatalf("save state: %v", err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if got.Version != StateVersion {
		t.Fatalf("state version=%d want %d", got.Version, StateVersion)
	}
	if got.X0Len != want.X0Len || got.X0CoeffBound != want.X0CoeffBound || got.TargetDim != want.TargetDim || got.TargetHidingLambda != want.TargetHidingLambda {
		t.Fatalf("x0 metadata mismatch: got %+v want %+v", got, want)
	}
	if len(got.R0) != want.X0Len {
		t.Fatalf("r0 len=%d want %d", len(got.R0), want.X0Len)
	}
	if got.BPath != want.BPath || got.HashRelation != want.HashRelation || got.CredentialPublicPath != want.CredentialPublicPath {
		t.Fatalf("state public metadata mismatch: got %+v want %+v", got, want)
	}
}

func TestLoadStateLegacyVersionUpgradesDefaults(t *testing.T) {
	chdirForCredentialTest(t)
	path := filepath.Join(t.TempDir(), "legacy_state.json")
	legacy := map[string]any{
		"version":                1,
		"m":                      [][]int64{{1}},
		"k":                      [][]int64{{2}},
		"r0":                     [][]int64{{3}, {4}},
		"r1":                     [][]int64{{5}},
		"z":                      [][]int64{{6}},
		"credential_public_path": "Parameters/credential_public.demo.json",
		"hash_relation":          HashRelationBBTran,
		"b_path":                 "Parameters/Bmatrix.json",
	}
	raw, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("load legacy state: %v", err)
	}
	if got.Version != StateVersion {
		t.Fatalf("upgraded version=%d want %d", got.Version, StateVersion)
	}
	if got.X0Len != 2 {
		t.Fatalf("upgraded x0_len=%d want 2", got.X0Len)
	}
	if got.X0CoeffBound != 1 {
		t.Fatalf("upgraded x0_coeff_bound=%d want 1", got.X0CoeffBound)
	}
	if got.TargetDim != DefaultTargetDim || got.TargetHidingLambda != DefaultTargetHidingLambda {
		t.Fatalf("upgraded target defaults mismatch: %+v", got)
	}
}

func TestLoadStateRejectsUnknownVersion(t *testing.T) {
	chdirForCredentialTest(t)
	path := filepath.Join(t.TempDir(), "bad_state.json")
	raw := []byte(`{"version":99}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write bad state: %v", err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("LoadState succeeded on unsupported version")
	}
}
