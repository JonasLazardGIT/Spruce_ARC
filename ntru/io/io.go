package io

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type SystemParams struct {
	N    int    `json:"N"`
	Q    uint64 `json:"Q"`
	Beta uint64 `json:"beta"`
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
	var tmp struct {
		B [][]uint64 `json:"B"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return nil, err
	}
	if len(tmp.B) != 4 {
		return nil, fmt.Errorf("b has %d rows, want 4", len(tmp.B))
	}
	for i := range tmp.B {
		if len(tmp.B[i]) != 1024 {
			return nil, fmt.Errorf("b[%d] has length %d, want 1024", i, len(tmp.B[i]))
		}
	}
	return tmp.B, nil
}

func SaveBMatrixCoeffs(path string, coeffs [][]uint64) error {
	if len(coeffs) != 4 {
		return fmt.Errorf("b has %d rows, want 4", len(coeffs))
	}
	for i := range coeffs {
		if len(coeffs[i]) != 1024 {
			return fmt.Errorf("b[%d] has length %d, want 1024", i, len(coeffs[i]))
		}
	}
	payload := struct {
		B [][]uint64 `json:"B"`
	}{B: coeffs}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
