package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const IntGenISISVerifierKeyVersion = 1

type IntGenISISVerifierKey struct {
	Version            int       `json:"version"`
	Profile            string    `json:"profile"`
	RingDegree         int       `json:"ring_degree"`
	PublicParamsDigest string    `json:"public_params_digest"`
	NTRUPublic         [][]int64 `json:"ntru_public"`
	SignatureBound     int64     `json:"signature_bound,omitempty"`
}

func SaveIntGenISISVerifierKey(path string, key IntGenISISVerifierKey) error {
	if key.Version == 0 {
		key.Version = IntGenISISVerifierKeyVersion
	}
	if err := key.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir verifier key dir: %w", err)
	}
	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS verifier key: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write IntGenISIS verifier key: %w", err)
	}
	return nil
}

func LoadIntGenISISVerifierKey(path string) (IntGenISISVerifierKey, error) {
	var key IntGenISISVerifierKey
	data, err := os.ReadFile(path)
	if err != nil {
		return key, fmt.Errorf("read IntGenISIS verifier key: %w", err)
	}
	if err := json.Unmarshal(data, &key); err != nil {
		return key, fmt.Errorf("unmarshal IntGenISIS verifier key: %w", err)
	}
	if err := key.Validate(); err != nil {
		return key, fmt.Errorf("validate IntGenISIS verifier key %s: %w", path, err)
	}
	return key, nil
}

func (key IntGenISISVerifierKey) Validate() error {
	if key.Version != IntGenISISVerifierKeyVersion {
		return fmt.Errorf("unsupported IntGenISIS verifier key version %d", key.Version)
	}
	profile, ok := LookupIntGenISISProfile(key.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", key.Profile)
	}
	if key.RingDegree != profile.N {
		return fmt.Errorf("ring_degree=%d want %d", key.RingDegree, profile.N)
	}
	if key.PublicParamsDigest == "" {
		return fmt.Errorf("missing public params digest")
	}
	if len(key.NTRUPublic) != 1 || len(key.NTRUPublic[0]) != profile.N {
		return fmt.Errorf("ntru_public dimensions=%dx? want 1x%d", len(key.NTRUPublic), profile.N)
	}
	if key.SignatureBound < 0 {
		return fmt.Errorf("signature_bound=%d", key.SignatureBound)
	}
	return nil
}

func (key IntGenISISVerifierKey) Digest() (string, error) {
	if err := key.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
