package prf

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
)

const canonicalParamsDomainV3 = "ARC-SPRUCE/poseidon2-params/v3"

// The strict-v3 profiles are compiled into the binary. Runtime paths remain
// operational configuration only: they may provide the same decoded profile,
// but they cannot replace these vetted relation constants.
//
//go:embed prf_params_tag9.json
var targetParamsTag9JSON []byte

//go:embed prf_params_tag10.json
var targetParamsTag10JSON []byte

//go:embed prf_params_tag13.json
var targetParamsTag13JSON []byte

func embeddedTargetParamsJSONV3(path string) ([]byte, error) {
	switch filepath.Base(path) {
	case "prf_params_tag9.json":
		return targetParamsTag9JSON, nil
	case "prf_params_tag10.json":
		return targetParamsTag10JSON, nil
	case "prf_params_tag13.json":
		return targetParamsTag13JSON, nil
	default:
		return nil, fmt.Errorf("unsupported strict-v3 PRF parameter profile %q", path)
	}
}

// EmbeddedTargetParamsFileDigestV3 returns the historical SHA-256 checksum of
// the exact embedded source file. Strict v3 checks this pinned identifier at
// startup, while the complete canonical constants remain the transcript
// binding (so this checksum is never the sole Fiat--Shamir binding).
func EmbeddedTargetParamsFileDigestV3(path string) (string, error) {
	raw, err := embeddedTargetParamsJSONV3(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// CanonicalParamsBytesV3 returns an injective binary encoding of every Params
// field consumed by the PRF permutation and input-trace relation. It is public
// statement material, not a digest of that material.
func CanonicalParamsBytesV3(params *Params) ([]byte, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("canonical PRF params: %w", err)
	}
	out := make([]byte, 0, 16+8*(16+2*params.T()*params.T()+params.RF*params.T()+params.RP))
	appendUint64 := func(value uint64) {
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], value)
		out = append(out, encoded[:]...)
	}
	appendInt := func(value int) { appendUint64(uint64(value)) }
	appendVector := func(values []uint64) {
		appendInt(len(values))
		for _, value := range values {
			appendUint64(value)
		}
	}
	appendMatrix := func(values [][]uint64) {
		appendInt(len(values))
		for _, row := range values {
			appendVector(row)
		}
	}

	appendUint64(uint64(len(canonicalParamsDomainV3)))
	out = append(out, canonicalParamsDomainV3...)
	appendUint64(params.Q)
	appendUint64(params.D)
	appendInt(params.LenKey)
	appendInt(params.LenNonce)
	appendInt(params.LenTag)
	appendInt(params.RF)
	appendInt(params.RP)
	appendUint64(math.Float64bits(params.SecPermBits))
	appendUint64(math.Float64bits(params.SecTruncBound))
	appendMatrix(params.ME)
	appendMatrix(params.MI)
	appendMatrix(params.CExt)
	appendVector(params.CInt)
	return out, nil
}

// LoadEmbeddedTargetParamsV3 loads one of the fixed strict publication profiles
// from bytes embedded at build time and returns its complete canonical form.
func LoadEmbeddedTargetParamsV3(path string) (*Params, []byte, error) {
	raw, err := embeddedTargetParamsJSONV3(path)
	if err != nil {
		return nil, nil, err
	}
	params, err := LoadParams(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("load embedded strict-v3 PRF params %q: %w", path, err)
	}
	canonical, err := CanonicalParamsBytesV3(params)
	if err != nil {
		return nil, nil, err
	}
	return params, canonical, nil
}

// LoadParamsFileWithCanonicalBytesV3 loads exactly path (without a fallback)
// and returns the decoded profile together with its complete canonical form.
func LoadParamsFileWithCanonicalBytesV3(path string) (*Params, []byte, error) {
	params, err := LoadParamsFromFile(path)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := CanonicalParamsBytesV3(params)
	if err != nil {
		return nil, nil, err
	}
	return params, canonical, nil
}
