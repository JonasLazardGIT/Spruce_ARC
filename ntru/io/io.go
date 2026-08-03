package io

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	stdio "io"
	"math/bits"
	"os"
	"path/filepath"
)

const (
	BMatrixVersion        = 3
	SystemParamsVersionV2 = "ntru-params-v2"
	SystemParamsV2        = SystemParamsVersionV2
)

type BMatrixMetadata struct {
	Version    int        `json:"version"`
	TargetDim  int        `json:"target_dim"`
	X0Len      int        `json:"x0_len"`
	RingDegree int        `json:"ring_degree"`
	RowOrder   []string   `json:"row_order"`
	B          [][]uint64 `json:"B"`
}

type SystemParams struct {
	Version      string `json:"version"`
	ParamsDigest string `json:"params_digest"`
	N            int    `json:"n"`
	Q            uint64 `json:"q"`
	Beta         uint64 `json:"beta"`
}

type systemParamsV2Disk struct {
	Version      string `json:"version"`
	ParamsDigest string `json:"params_digest"`
	N            int    `json:"n"`
	Q            uint64 `json:"q"`
	K            int    `json:"k"`
	Beta         uint64 `json:"beta"`
	Bound        uint64 `json:"bound"`
}

// CanonicalParamsDigest returns the SHA-256 identity of the security-relevant
// v2 system parameters. The encoding is fixed-width and domain separated; it
// does not depend on JSON whitespace, field ordering, or path names.
func CanonicalParamsDigest(p SystemParams) (string, error) {
	if p.Version != "" && p.Version != SystemParamsV2 {
		return "", fmt.Errorf("unsupported NTRU params version %q (want %q)", p.Version, SystemParamsV2)
	}
	if err := validateParamsValues(p); err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("SPRUCE/NTRU/system-params/v2\x00"))
	var word [8]byte
	binary.BigEndian.PutUint64(word[:], uint64(p.N))
	_, _ = h.Write(word[:])
	binary.BigEndian.PutUint64(word[:], p.Q)
	_, _ = h.Write(word[:])
	binary.BigEndian.PutUint64(word[:], p.Beta)
	_, _ = h.Write(word[:])
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CanonicalizeParams validates p and fills its exact v2 version and digest.
// A non-empty conflicting version or digest is rejected rather than replaced.
func CanonicalizeParams(p SystemParams) (SystemParams, error) {
	digest, err := CanonicalParamsDigest(p)
	if err != nil {
		return SystemParams{}, err
	}
	if p.ParamsDigest != "" && p.ParamsDigest != digest {
		return SystemParams{}, fmt.Errorf("NTRU params digest mismatch: got %q want %q", p.ParamsDigest, digest)
	}
	p.Version = SystemParamsV2
	p.ParamsDigest = digest
	return p, nil
}

// ValidateParams requires an already-bound v2 parameter object.
func ValidateParams(p SystemParams) error {
	if p.Version != SystemParamsV2 {
		return fmt.Errorf("unsupported NTRU params version %q (want %q)", p.Version, SystemParamsV2)
	}
	if p.ParamsDigest == "" {
		return fmt.Errorf("missing NTRU params digest")
	}
	canonical, err := CanonicalizeParams(p)
	if err != nil {
		return err
	}
	if canonical.ParamsDigest != p.ParamsDigest {
		return fmt.Errorf("NTRU params digest mismatch")
	}
	return nil
}

func validateParamsValues(p SystemParams) error {
	if p.N <= 0 || p.Q <= 2 {
		return fmt.Errorf("invalid N/Q for params: N=%d Q=%d", p.N, p.Q)
	}
	if p.Q&1 == 0 {
		return fmt.Errorf("unsupported even Q=%d (expected odd modulus)", p.Q)
	}
	if p.Beta == 0 {
		return fmt.Errorf("invalid zero beta for params")
	}
	return nil
}

func SaveParams(path string, p SystemParams) error {
	canonical, err := CanonicalizeParams(p)
	if err != nil {
		return err
	}
	payload := systemParamsV2Disk{
		Version:      canonical.Version,
		ParamsDigest: canonical.ParamsDigest,
		N:            canonical.N,
		Q:            canonical.Q,
		K:            bits.Len64(canonical.Q - 1),
		Beta:         canonical.Beta,
		Bound:        canonical.Beta,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func LoadParams(path string, allowMismatch bool) (SystemParams, error) {
	var p SystemParams
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	var disk systemParamsV2Disk
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&disk); err != nil {
		return p, fmt.Errorf("decode NTRU params %s: %w", path, err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return p, fmt.Errorf("decode NTRU params %s: %w", path, err)
	}
	p = SystemParams{
		Version:      disk.Version,
		ParamsDigest: disk.ParamsDigest,
		N:            disk.N,
		Q:            disk.Q,
		Beta:         disk.Beta,
	}
	if err := ValidateParams(p); err != nil {
		return SystemParams{}, fmt.Errorf("invalid NTRU params %s: %w", path, err)
	}
	if disk.K != bits.Len64(p.Q-1) {
		return SystemParams{}, fmt.Errorf("invalid NTRU params %s: k=%d want %d", path, disk.K, bits.Len64(p.Q-1))
	}
	if disk.Bound != p.Beta {
		return SystemParams{}, fmt.Errorf("invalid NTRU params %s: bound=%d want beta=%d", path, disk.Bound, p.Beta)
	}
	if !allowMismatch {
		if p.N != 1024 {
			return p, fmt.Errorf("want N=1024, got %d", p.N)
		}
	}
	return p, nil
}

func requireJSONEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); err != stdio.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func LoadBMatrixMetadata(path string) (BMatrixMetadata, error) {
	var tmp BMatrixMetadata
	raw, err := os.ReadFile(path)
	if err != nil {
		return tmp, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tmp); err != nil {
		return tmp, fmt.Errorf("decode B matrix: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return tmp, fmt.Errorf("decode B matrix: %w", err)
	}
	if tmp.Version != BMatrixVersion {
		return tmp, fmt.Errorf("unsupported B-matrix schema %d; this build requires schema %d. No migration is supported; rerun setup and issuance", tmp.Version, BMatrixVersion)
	}
	if len(tmp.B) == 0 {
		return tmp, fmt.Errorf("empty B matrix")
	}
	rowLen := len(tmp.B[0])
	if rowLen == 0 {
		return tmp, fmt.Errorf("empty B-matrix polynomial")
	}
	for i := range tmp.B {
		if len(tmp.B[i]) != rowLen {
			return tmp, fmt.Errorf("b[%d] has length %d, want %d", i, len(tmp.B[i]), rowLen)
		}
	}
	if tmp.RingDegree != rowLen {
		return tmp, fmt.Errorf("b ring_degree=%d does not match coefficient length=%d", tmp.RingDegree, rowLen)
	}
	if tmp.TargetDim != 1 {
		return tmp, fmt.Errorf("unsupported target_dim=%d want 1", tmp.TargetDim)
	}
	if tmp.X0Len <= 0 {
		return tmp, fmt.Errorf("invalid x0_len=%d", tmp.X0Len)
	}
	if want := 2 + tmp.X0Len + 1; len(tmp.B) != want {
		return tmp, fmt.Errorf("b has %d rows, want %d for target_dim=%d x0_len=%d", len(tmp.B), want, tmp.TargetDim, tmp.X0Len)
	}
	wantOrder := make([]string, 0, len(tmp.B))
	wantOrder = append(wantOrder, "B0", "B1")
	for i := 0; i < tmp.X0Len; i++ {
		wantOrder = append(wantOrder, fmt.Sprintf("B2[%d]", i))
	}
	wantOrder = append(wantOrder, "B3")
	if len(tmp.RowOrder) != len(wantOrder) {
		return tmp, fmt.Errorf("b row_order entries=%d want %d", len(tmp.RowOrder), len(wantOrder))
	}
	for i := range wantOrder {
		if tmp.RowOrder[i] != wantOrder[i] {
			return tmp, fmt.Errorf("b row_order[%d]=%q want %q", i, tmp.RowOrder[i], wantOrder[i])
		}
	}
	return tmp, nil
}

// ValidateBMatrixCanonical checks the field encoding independently of the JSON
// schema. B0 has no nonzero or invertibility requirement: it is an ordinary
// independently uniform public polynomial and zero is a valid field value.
func ValidateBMatrixCanonical(coeffs [][]uint64, modulus uint64) error {
	if modulus <= 1 {
		return fmt.Errorf("invalid B-matrix modulus %d", modulus)
	}
	for i := range coeffs {
		for j, coefficient := range coeffs[i] {
			if coefficient >= modulus {
				return fmt.Errorf("b[%d][%d]=%d is not canonical modulo %d", i, j, coefficient, modulus)
			}
		}
	}
	return nil
}

func SaveBMatrixCoeffs(path string, coeffs [][]uint64) error {
	if len(coeffs) < 4 {
		return fmt.Errorf("b has %d rows, want >= 4", len(coeffs))
	}
	rowLen := len(coeffs[0])
	if rowLen == 0 {
		return fmt.Errorf("empty B-matrix polynomial")
	}
	for i := range coeffs {
		if len(coeffs[i]) != rowLen {
			return fmt.Errorf("b[%d] has length %d, want %d", i, len(coeffs[i]), rowLen)
		}
	}
	x0Len := len(coeffs) - 3
	rowOrder := []string{"B0", "B1"}
	for i := 0; i < x0Len; i++ {
		rowOrder = append(rowOrder, fmt.Sprintf("B2[%d]", i))
	}
	rowOrder = append(rowOrder, "B3")
	payload := BMatrixMetadata{
		Version:    BMatrixVersion,
		TargetDim:  1,
		X0Len:      x0Len,
		RingDegree: rowLen,
		RowOrder:   rowOrder,
		B:          coeffs,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
