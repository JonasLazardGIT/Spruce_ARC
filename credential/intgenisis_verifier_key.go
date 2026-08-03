package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

const IntGenISISVerifierKeyVersion = 2

type IntGenISISVerifierKey struct {
	Version              int       `json:"version"`
	Profile              string    `json:"profile"`
	PresetID             string    `json:"preset_id"`
	PresetVersion        int       `json:"preset_version"`
	PresetManifestDigest string    `json:"preset_manifest_digest"`
	RingDegree           int       `json:"ring_degree"`
	PublicParamsDigest   string    `json:"public_params_digest"`
	NTRUPublic           [][]int64 `json:"ntru_public"`
	SignatureBound       int64     `json:"signature_bound"`
}

func SaveIntGenISISVerifierKey(path string, key IntGenISISVerifierKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS verifier key: %w", err)
	}
	if err := atomicWriteFile(path, append(data, '\n'), 0o644); err != nil {
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
	if err := decodeStrictVersionedJSON(data, &key, "IntGenISIS verifier-key", IntGenISISVerifierKeyVersion); err != nil {
		return key, fmt.Errorf("decode IntGenISIS verifier key: %w", err)
	}
	if err := key.Validate(); err != nil {
		return key, fmt.Errorf("validate IntGenISIS verifier key %s: %w", path, err)
	}
	return key, nil
}

func (key IntGenISISVerifierKey) Validate() error {
	if key.Version != IntGenISISVerifierKeyVersion {
		return noMigrationSchemaError("IntGenISIS verifier-key", key.Version, IntGenISISVerifierKeyVersion)
	}
	profile, ok := LookupIntGenISISProfile(key.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", key.Profile)
	}
	if key.RingDegree != profile.N {
		return fmt.Errorf("ring_degree=%d want %d", key.RingDegree, profile.N)
	}
	if err := validateDigestHex("verifier-key public params digest", key.PublicParamsDigest); err != nil {
		return err
	}
	if key.PresetID == "" || key.PresetVersion <= 0 || key.PresetManifestDigest == "" {
		return fmt.Errorf("incomplete verifier-key preset binding")
	}
	preset, ok := LookupIntGenISISPreset(key.PresetID)
	if !ok || key.PresetID != preset.CanonicalID || preset.Profile != key.Profile || preset.PresetVersion != key.PresetVersion || IntGenISISPresetManifestDigest(preset) != key.PresetManifestDigest {
		return fmt.Errorf("verifier-key preset manifest mismatch")
	}
	if len(key.NTRUPublic) != 1 || len(key.NTRUPublic[0]) != profile.N {
		return fmt.Errorf("ntru_public dimensions=%dx? want 1x%d", len(key.NTRUPublic), profile.N)
	}
	if key.SignatureBound <= 0 {
		return fmt.Errorf("signature_bound=%d must be positive", key.SignatureBound)
	}
	return nil
}

// ValidateAgainst binds a verifier key to one exact public-parameter artifact.
func (key IntGenISISVerifierKey) ValidateAgainst(public PublicParams) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if err := (&public).Validate(); err != nil {
		return err
	}
	digest, err := PublicParamsDigest(public)
	if err != nil {
		return err
	}
	if key.PublicParamsDigest != digest {
		return fmt.Errorf("verifier-key public params digest mismatch")
	}
	if key.Profile != public.Profile || key.RingDegree != public.RingDegree || key.PresetID != public.PresetID || key.PresetVersion != public.PresetVersion || key.PresetManifestDigest != public.PresetManifestDigest {
		return fmt.Errorf("verifier-key and public parameter bindings differ")
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
