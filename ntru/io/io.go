package io

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const BMatrixVersion = 2

type BMatrixMetadata struct {
	Version   int        `json:"version,omitempty"`
	TargetDim int        `json:"target_dim,omitempty"`
	X0Len     int        `json:"x0_len,omitempty"`
	RowOrder  []string   `json:"row_order,omitempty"`
	B         [][]uint64 `json:"B"`
}

type SystemParams struct {
	N    int    `json:"N"`
	Q    uint64 `json:"Q"`
	Beta uint64 `json:"beta"`
}

func SaveParams(path string, p SystemParams) error {
	if p.N <= 0 || p.Q == 0 {
		return fmt.Errorf("invalid N/Q for params: N=%d Q=%d", p.N, p.Q)
	}
	payload := map[string]any{
		"n":     p.N,
		"q":     p.Q,
		"beta":  p.Beta,
		"bound": p.Beta,
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
	var rawAny map[string]any
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(data, &rawAny); err != nil {
		return p, err
	}
	if v, ok := rawAny["N"]; ok {
		if f, ok := v.(float64); ok {
			p.N = int(f)
		}
	} else if v, ok := rawAny["n"]; ok {
		if f, ok := v.(float64); ok {
			p.N = int(f)
		}
	}
	if v, ok := rawAny["Q"]; ok {
		switch t := v.(type) {
		case float64:
			p.Q = uint64(t)
		case string:
			if q, err := parseQString(t); err == nil {
				p.Q = q
			} else {
				return p, err
			}
		}
	} else if v, ok := rawAny["q"]; ok {
		switch t := v.(type) {
		case float64:
			p.Q = uint64(t)
		case string:
			if q, err := parseQString(t); err == nil {
				p.Q = q
			} else {
				return p, err
			}
		}
	}
	if v, ok := rawAny["beta"]; ok {
		if f, ok := v.(float64); ok {
			p.Beta = uint64(f)
		}
	}
	if p.N == 0 || p.Q == 0 {
		return p, fmt.Errorf("invalid or missing N/Q in %s", path)
	}
	if !allowMismatch {
		if p.N != 1024 {
			return p, fmt.Errorf("want N=1024, got %d", p.N)
		}
		if (p.Q & 1) == 0 {
			return p, fmt.Errorf("unsupported even Q=%d (expected odd modulus)", p.Q)
		}
	}
	return p, nil
}

func parseQString(s string) (uint64, error) {
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if x, err := hex.DecodeString(s); err == nil {
		var q uint64
		for _, b := range x {
			q = (q << 8) | uint64(b)
		}
		return q, nil
	}
	var dec uint64
	if err := json.Unmarshal([]byte(s), &dec); err == nil {
		return dec, nil
	}
	return 0, fmt.Errorf("invalid Q string: %q", s)
}

func LoadBMatrixCoeffs(path string) ([][]uint64, error) {
	meta, err := LoadBMatrixMetadata(path)
	if err != nil {
		return nil, err
	}
	return meta.B, nil
}

func LoadBMatrixMetadata(path string) (BMatrixMetadata, error) {
	var tmp BMatrixMetadata
	raw, err := os.ReadFile(path)
	if err != nil {
		return tmp, err
	}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return tmp, err
	}
	if tmp.Version == 0 {
		tmp.Version = 1
	}
	if len(tmp.B) == 0 {
		return tmp, fmt.Errorf("empty B matrix")
	}
	rowLen := len(tmp.B[0])
	for i := range tmp.B {
		if len(tmp.B[i]) != rowLen {
			return tmp, fmt.Errorf("b[%d] has length %d, want %d", i, len(tmp.B[i]), rowLen)
		}
	}
	if tmp.Version == 1 {
		if len(tmp.B) != 4 {
			return tmp, fmt.Errorf("legacy b has %d rows, want 4", len(tmp.B))
		}
		tmp.TargetDim = 1
		tmp.X0Len = 1
		tmp.RowOrder = []string{"B0", "B1", "B2[0]", "B3"}
		return tmp, nil
	}
	if tmp.TargetDim <= 0 {
		return tmp, fmt.Errorf("invalid target_dim=%d", tmp.TargetDim)
	}
	if tmp.X0Len <= 0 {
		return tmp, fmt.Errorf("invalid x0_len=%d", tmp.X0Len)
	}
	if want := 2 + tmp.X0Len + 1; len(tmp.B) != want {
		return tmp, fmt.Errorf("b has %d rows, want %d for target_dim=%d x0_len=%d", len(tmp.B), want, tmp.TargetDim, tmp.X0Len)
	}
	if len(tmp.RowOrder) == 0 {
		tmp.RowOrder = make([]string, 0, len(tmp.B))
		tmp.RowOrder = append(tmp.RowOrder, "B0", "B1")
		for i := 0; i < tmp.X0Len; i++ {
			tmp.RowOrder = append(tmp.RowOrder, fmt.Sprintf("B2[%d]", i))
		}
		tmp.RowOrder = append(tmp.RowOrder, "B3")
	}
	return tmp, nil
}

func SaveBMatrixCoeffs(path string, coeffs [][]uint64) error {
	if len(coeffs) < 4 {
		return fmt.Errorf("b has %d rows, want >= 4", len(coeffs))
	}
	rowLen := len(coeffs[0])
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
		Version:   BMatrixVersion,
		TargetDim: 1,
		X0Len:     x0Len,
		RowOrder:  rowOrder,
		B:         coeffs,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
