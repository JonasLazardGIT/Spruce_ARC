package credential

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const (
	IntGenISISPresentationVersion  = 2
	IntGenISISVerifierStateVersion = 2
)

// IntGenISISPresentation is the public v2 envelope. Hidden slot material is
// intentionally absent: it exists only inside the PIOP witness.
type IntGenISISPresentation struct {
	Version              int             `json:"version"`
	PresetManifestDigest string          `json:"preset_manifest_digest"`
	PublicParamsDigest   string          `json:"public_params_digest"`
	VerifierKeyDigest    string          `json:"verifier_key_digest"`
	ContextDigest        string          `json:"context_digest"`
	Context              []int64         `json:"context"`
	Tag                  []int64         `json:"tag"`
	Proof                json.RawMessage `json:"proof"`
}

type IntGenISISVerifierState struct {
	Version            int                        `json:"version"`
	PublicParamsDigest string                     `json:"public_params_digest"`
	VerifierKeyDigest  string                     `json:"verifier_key_digest"`
	Seen               map[string]map[string]bool `json:"seen"`
}

func PublicParamsDigest(public PublicParams) (string, error) {
	if err := (&public).Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(public)
	if err != nil {
		return "", fmt.Errorf("marshal public params for digest: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func SaveIntGenISISPresentation(path string, pres IntGenISISPresentation) error {
	if err := pres.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pres, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS presentation: %w", err)
	}
	if err := atomicWriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write IntGenISIS presentation: %w", err)
	}
	return nil
}

func LoadIntGenISISPresentation(path string) (IntGenISISPresentation, error) {
	var pres IntGenISISPresentation
	data, err := os.ReadFile(path)
	if err != nil {
		return pres, fmt.Errorf("read IntGenISIS presentation: %w", err)
	}
	if err := decodeStrictVersionedJSON(data, &pres, "IntGenISIS presentation", IntGenISISPresentationVersion); err != nil {
		return pres, fmt.Errorf("decode IntGenISIS presentation: %w", err)
	}
	if err := pres.Validate(); err != nil {
		return pres, fmt.Errorf("validate IntGenISIS presentation %s: %w", path, err)
	}
	return pres, nil
}

func validateDigestHex(name, value string) error {
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != value {
		return fmt.Errorf("%s must be canonical lowercase 32-byte hex", name)
	}
	return nil
}

func lookupIntGenISISPresetByManifestDigest(digest string) (IntGenISISPreset, bool) {
	for _, name := range IntGenISISPresetNames() {
		preset, ok := LookupIntGenISISPreset(name)
		if ok && IntGenISISPresetManifestDigest(preset) == digest {
			return preset, true
		}
	}
	return IntGenISISPreset{}, false
}

func (pres IntGenISISPresentation) Validate() error {
	if pres.Version != IntGenISISPresentationVersion {
		return noMigrationSchemaError("IntGenISIS presentation", pres.Version, IntGenISISPresentationVersion)
	}
	for name, digest := range map[string]string{
		"preset manifest digest": pres.PresetManifestDigest,
		"public params digest":   pres.PublicParamsDigest,
		"verifier key digest":    pres.VerifierKeyDigest,
		"context digest":         pres.ContextDigest,
	} {
		if err := validateDigestHex(name, digest); err != nil {
			return err
		}
	}
	preset, ok := lookupIntGenISISPresetByManifestDigest(pres.PresetManifestDigest)
	if !ok {
		return fmt.Errorf("presentation is bound to an unknown preset manifest")
	}
	profile, ok := LookupIntGenISISProfile(preset.Profile)
	if !ok {
		return fmt.Errorf("presentation preset has unsupported profile %q", preset.Profile)
	}
	if len(pres.Context) != IntGenISISContextLaneCount {
		return fmt.Errorf("presentation context lanes=%d want %d", len(pres.Context), IntGenISISContextLaneCount)
	}
	tagLen, ok := IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok || len(pres.Tag) != tagLen {
		return fmt.Errorf("presentation tag lanes=%d want %d for PRF profile %q", len(pres.Tag), tagLen, preset.PRFProfile)
	}
	for name, values := range map[string][]int64{"context": pres.Context, "tag": pres.Tag} {
		for i, value := range values {
			if value < 0 || uint64(value) >= profile.Q {
				return fmt.Errorf("presentation %s[%d]=%d is not canonical modulo %d", name, i, value, profile.Q)
			}
		}
	}
	if len(pres.Proof) == 0 || !json.Valid(pres.Proof) || string(pres.Proof) == "null" {
		return fmt.Errorf("presentation proof is missing or invalid JSON")
	}
	var proofHeader struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(pres.Proof, &proofHeader); err != nil {
		return fmt.Errorf("decode presentation proof header: %w", err)
	}
	if proofHeader.SchemaVersion != IntGenISISProofSchemaVersionV2 {
		return noMigrationSchemaError("IntGenISIS proof", proofHeader.SchemaVersion, IntGenISISProofSchemaVersionV2)
	}
	return nil
}

// ValidateAgainst binds the public presentation envelope to the exact public
// parameters and verifier key used by the cryptographic verifier.
func (pres IntGenISISPresentation) ValidateAgainst(public PublicParams, key IntGenISISVerifierKey) error {
	if err := pres.Validate(); err != nil {
		return err
	}
	if err := key.ValidateAgainst(public); err != nil {
		return err
	}
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		return err
	}
	keyDigest, err := key.Digest()
	if err != nil {
		return err
	}
	if pres.PresetManifestDigest != public.PresetManifestDigest || pres.PublicParamsDigest != publicDigest || pres.VerifierKeyDigest != keyDigest {
		return fmt.Errorf("presentation/public/verifier-key binding mismatch")
	}
	return nil
}

func NewIntGenISISVerifierState(publicParamsDigest, verifierKeyDigest string) IntGenISISVerifierState {
	return IntGenISISVerifierState{
		Version:            IntGenISISVerifierStateVersion,
		PublicParamsDigest: publicParamsDigest,
		VerifierKeyDigest:  verifierKeyDigest,
		Seen:               make(map[string]map[string]bool),
	}
}

func (st *IntGenISISVerifierState) Validate() error {
	if st.Version != IntGenISISVerifierStateVersion {
		return noMigrationSchemaError("IntGenISIS verifier-state", st.Version, IntGenISISVerifierStateVersion)
	}
	if err := validateDigestHex("verifier-state public params digest", st.PublicParamsDigest); err != nil {
		return err
	}
	if err := validateDigestHex("verifier-state verifier key digest", st.VerifierKeyDigest); err != nil {
		return err
	}
	if st.Seen == nil {
		return fmt.Errorf("verifier state missing seen map")
	}
	for namespace, tags := range st.Seen {
		if err := validateDigestHex("verifier-state context namespace", namespace); err != nil {
			return err
		}
		if tags == nil {
			return fmt.Errorf("verifier-state context namespace %q has nil tag set", namespace)
		}
		for tagDigest, seen := range tags {
			if err := validateDigestHex("verifier-state tag digest", tagDigest); err != nil {
				return err
			}
			if !seen {
				return fmt.Errorf("verifier-state tag digest %q has false membership", tagDigest)
			}
		}
	}
	return nil
}

// ValidateAgainst checks that replay state is namespaced to the same public
// parameters and verifier key as the cryptographic verification operation.
func (st *IntGenISISVerifierState) ValidateAgainst(public PublicParams, key IntGenISISVerifierKey) error {
	if err := st.Validate(); err != nil {
		return err
	}
	if err := key.ValidateAgainst(public); err != nil {
		return err
	}
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		return err
	}
	keyDigest, err := key.Digest()
	if err != nil {
		return err
	}
	if st.PublicParamsDigest != publicDigest || st.VerifierKeyDigest != keyDigest {
		return fmt.Errorf("verifier state/public/verifier-key binding mismatch")
	}
	return nil
}

func LoadIntGenISISVerifierState(path string) (IntGenISISVerifierState, error) {
	var st IntGenISISVerifierState
	data, err := os.ReadFile(path)
	if err != nil {
		return st, fmt.Errorf("read IntGenISIS verifier state: %w", err)
	}
	if err := decodeStrictVersionedJSON(data, &st, "IntGenISIS verifier-state", IntGenISISVerifierStateVersion); err != nil {
		return st, fmt.Errorf("decode IntGenISIS verifier state: %w", err)
	}
	if err := st.Validate(); err != nil {
		return st, err
	}
	return st, nil
}

func SaveIntGenISISVerifierState(path string, st IntGenISISVerifierState) error {
	if err := st.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS verifier state: %w", err)
	}
	return atomicWriteFile(path, append(data, '\n'), 0o600)
}

func canonicalTagDigest(tag []int64) string {
	h := sha256.New()
	h.Write([]byte("ARC-SPRUCE/tag-state/v2"))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(tag)))
	h.Write(n[:])
	var scalar [8]byte
	for _, value := range tag {
		binary.BigEndian.PutUint64(scalar[:], uint64(value))
		h.Write(scalar[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (st *IntGenISISVerifierState) MarkPresentation(pres IntGenISISPresentation) error {
	if err := st.Validate(); err != nil {
		return err
	}
	if err := pres.Validate(); err != nil {
		return err
	}
	if st.PublicParamsDigest != pres.PublicParamsDigest || st.VerifierKeyDigest != pres.VerifierKeyDigest {
		return fmt.Errorf("presentation and verifier-state binding mismatch")
	}
	namespace := pres.ContextDigest
	if st.Seen[namespace] == nil {
		st.Seen[namespace] = make(map[string]bool)
	}
	tagDigest := canonicalTagDigest(pres.Tag)
	if st.Seen[namespace][tagDigest] {
		return fmt.Errorf("replayed IntGenISIS tag in presentation context")
	}
	st.Seen[namespace][tagDigest] = true
	return nil
}

// CheckAndMarkIntGenISISPresentation performs the durable state transition.
// Callers must cryptographically verify pres before invoking it.
func CheckAndMarkIntGenISISPresentation(path string, pres IntGenISISPresentation) error {
	if err := pres.Validate(); err != nil {
		return err
	}
	return withExclusiveFileLock(path, func() error {
		st := NewIntGenISISVerifierState(pres.PublicParamsDigest, pres.VerifierKeyDigest)
		loaded, err := LoadIntGenISISVerifierState(path)
		if err == nil {
			st = loaded
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := st.MarkPresentation(pres); err != nil {
			return err
		}
		return SaveIntGenISISVerifierState(path, st)
	})
}
