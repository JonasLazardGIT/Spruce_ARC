package io

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBMatrixMetadataRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Bmatrix.json")
	coeffs := make([][]uint64, 8)
	for i := range coeffs {
		coeffs[i] = []uint64{uint64(i), uint64(i + 1), uint64(i + 2)}
	}
	if err := SaveBMatrixCoeffs(path, coeffs); err != nil {
		t.Fatalf("save B matrix: %v", err)
	}
	meta, err := LoadBMatrixMetadata(path)
	if err != nil {
		t.Fatalf("load B matrix: %v", err)
	}
	if meta.Version != BMatrixVersion {
		t.Fatalf("version=%d want %d", meta.Version, BMatrixVersion)
	}
	if meta.TargetDim != 1 {
		t.Fatalf("target_dim=%d want 1", meta.TargetDim)
	}
	if meta.X0Len != 5 {
		t.Fatalf("x0_len=%d want 5", meta.X0Len)
	}
	if meta.RingDegree != 3 {
		t.Fatalf("ring_degree=%d want 3", meta.RingDegree)
	}
	if len(meta.RowOrder) != len(coeffs) || meta.RowOrder[0] != "B0" || meta.RowOrder[len(meta.RowOrder)-1] != "B3" {
		t.Fatalf("unexpected row order: %v", meta.RowOrder)
	}
	if len(meta.B) != len(coeffs) {
		t.Fatalf("row count=%d want %d", len(meta.B), len(coeffs))
	}
}

func TestLoadBMatrixMetadataRejectsLegacyArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy_Bmatrix.json")
	legacy := map[string]any{
		"B": [][]uint64{
			{0, 1, 2},
			{3, 4, 5},
			{6, 7, 8},
			{9, 10, 11},
		},
	}
	raw, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy B: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write legacy B: %v", err)
	}
	if _, err := LoadBMatrixMetadata(path); err == nil {
		t.Fatal("legacy B matrix was silently upgraded")
	}
}

func TestBMatrixDoesNotImposeNonzeroB0(t *testing.T) {
	coeffs := [][]uint64{{0, 0, 0}, {1, 2, 3}, {4, 5, 6}, {7, 8, 9}}
	path := filepath.Join(t.TempDir(), "Bmatrix.json")
	if err := SaveBMatrixCoeffs(path, coeffs); err != nil {
		t.Fatalf("zero-valued B0 rejected despite having no nonzero condition: %v", err)
	}
	meta, err := LoadBMatrixMetadata(path)
	if err != nil {
		t.Fatalf("load zero-valued B0: %v", err)
	}
	if len(meta.B) != len(coeffs) || meta.B[0][0] != 0 {
		t.Fatalf("zero-valued B0 round trip mismatch: %+v", meta.B)
	}
	if err := ValidateBMatrixCanonical(meta.B, 11); err != nil {
		t.Fatalf("canonical B rejected: %v", err)
	}
	meta.B[2][1] = 11
	if err := ValidateBMatrixCanonical(meta.B, 11); err == nil {
		t.Fatal("noncanonical B coefficient accepted")
	}
}

func TestLoadBMatrixMetadataRejectsUnsupportedTargetDimension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Bmatrix.json")
	payload := BMatrixMetadata{
		Version:    BMatrixVersion,
		TargetDim:  2,
		X0Len:      1,
		RingDegree: 3,
		RowOrder:   []string{"B0", "B1", "B2[0]", "B3"},
		B:          [][]uint64{{0, 0, 0}, {1, 2, 3}, {4, 5, 6}, {7, 8, 9}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBMatrixMetadata(path); err == nil {
		t.Fatal("unsupported target_dim accepted")
	}
}

func TestSaveBMatrixRejectsEmptyPolynomials(t *testing.T) {
	if err := SaveBMatrixCoeffs(filepath.Join(t.TempDir(), "Bmatrix.json"), [][]uint64{{}, {}, {}, {}}); err == nil {
		t.Fatal("empty B-matrix polynomials accepted")
	}
}
