package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const IntGenISISHolderUsageStateVersion = 2

type IntGenISISHolderUsageState struct {
	Version               int              `json:"version"`
	PublicParamsDigest    string           `json:"public_params_digest"`
	PresetManifestDigest  string           `json:"preset_manifest_digest"`
	CredentialFingerprint string           `json:"credential_fingerprint"`
	NextSlotByContext     map[string]uint8 `json:"next_slot_by_context"`
}

func IntGenISISCredentialFingerprint(st IntGenISISState) (string, error) {
	if err := st.Validate(); err != nil {
		return "", err
	}
	if preset, ok := LookupIntGenISISPreset(st.PresetID); ok && preset.HolderUsageVersion == IntGenISISHolderUsageFormatVersionV3 {
		return "", fmt.Errorf("legacy JSON credential fingerprint is unavailable for strict-v3 preset %q; use IntGenISISCredentialFingerprintV3 with canonical state-v8", st.PresetID)
	}
	data, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("marshal credential state fingerprint: %w", err)
	}
	sum := sha256.Sum256(append([]byte("ARC-SPRUCE/credential-fingerprint/v2\x00"), data...))
	return hex.EncodeToString(sum[:]), nil
}

func NewIntGenISISHolderUsageState(publicParamsDigest, presetManifestDigest, credentialFingerprint string) IntGenISISHolderUsageState {
	return IntGenISISHolderUsageState{
		Version:               IntGenISISHolderUsageStateVersion,
		PublicParamsDigest:    publicParamsDigest,
		PresetManifestDigest:  presetManifestDigest,
		CredentialFingerprint: credentialFingerprint,
		NextSlotByContext:     make(map[string]uint8),
	}
}

func (st *IntGenISISHolderUsageState) Validate() error {
	if st.Version != IntGenISISHolderUsageStateVersion {
		return noMigrationSchemaError("IntGenISIS holder-usage-state", st.Version, IntGenISISHolderUsageStateVersion)
	}
	for name, digest := range map[string]string{
		"holder public params digest":   st.PublicParamsDigest,
		"holder preset manifest digest": st.PresetManifestDigest,
		"holder credential fingerprint": st.CredentialFingerprint,
	} {
		if err := validateDigestHex(name, digest); err != nil {
			return err
		}
	}
	if preset, ok := lookupIntGenISISPresetByManifestDigest(st.PresetManifestDigest); ok && preset.HolderUsageVersion == IntGenISISHolderUsageFormatVersionV3 {
		return fmt.Errorf("legacy holder-usage-state v2 is forbidden for strict-v3 preset %q; no migration or fallback is supported", preset.CanonicalID)
	}
	if st.NextSlotByContext == nil {
		return fmt.Errorf("holder usage state missing context map")
	}
	for context, next := range st.NextSlotByContext {
		if err := validateDigestHex("holder context digest", context); err != nil {
			return err
		}
		if uint32(next) > IntGenISISQuotaSlots {
			return fmt.Errorf("holder next slot %d exceeds quota %d", next, IntGenISISQuotaSlots)
		}
	}
	return nil
}

func LoadIntGenISISHolderUsageState(path string) (IntGenISISHolderUsageState, error) {
	var st IntGenISISHolderUsageState
	data, err := os.ReadFile(path)
	if err != nil {
		return st, fmt.Errorf("read holder usage state: %w", err)
	}
	if err := decodeStrictVersionedJSON(data, &st, "IntGenISIS holder-usage-state", IntGenISISHolderUsageStateVersion); err != nil {
		return st, fmt.Errorf("decode holder usage state: %w", err)
	}
	if err := st.Validate(); err != nil {
		return st, err
	}
	return st, nil
}

// ReserveIntGenISISSlot burns and durably persists a slot before proving.
func ReserveIntGenISISSlot(path, publicParamsDigest, presetManifestDigest, credentialFingerprint, contextDigest string) (uint8, error) {
	var reserved uint8
	err := withExclusiveFileLock(path, func() error {
		st := NewIntGenISISHolderUsageState(publicParamsDigest, presetManifestDigest, credentialFingerprint)
		loaded, err := LoadIntGenISISHolderUsageState(path)
		if err == nil {
			st = loaded
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := st.Validate(); err != nil {
			return err
		}
		if st.PublicParamsDigest != publicParamsDigest || st.PresetManifestDigest != presetManifestDigest || st.CredentialFingerprint != credentialFingerprint {
			return fmt.Errorf("holder usage state credential binding mismatch")
		}
		if err := validateDigestHex("context digest", contextDigest); err != nil {
			return err
		}
		next := st.NextSlotByContext[contextDigest]
		if uint32(next) >= IntGenISISQuotaSlots {
			return fmt.Errorf("presentation quota exhausted for context: %d slots already reserved", IntGenISISQuotaSlots)
		}
		reserved = next
		st.NextSlotByContext[contextDigest] = next + 1
		encoded, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal holder usage state: %w", err)
		}
		return atomicWriteFile(path, append(encoded, '\n'), 0o600)
	})
	return reserved, err
}
