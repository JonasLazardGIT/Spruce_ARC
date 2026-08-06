package credential

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const (
	IntGenISISHolderUsageStateVersionV3 = IntGenISISHolderUsageFormatVersionV3
	IntGenISISVerifierStateVersionV3    = 3

	holderUsageV3ContextDomain = "ARC-SPRUCE/intgenisis-holder-usage-v3/context"
	verifierV3ContextDomain    = "ARC-SPRUCE/intgenisis-verifier-state-v3/context"
	verifierV3TagDomain        = "ARC-SPRUCE/intgenisis-verifier-state-v3/tag"
)

// IntGenISISHolderUsageStateV3 is the target-only monotonic slot ledger.  Its
// bindings are configured-width SHAKE-256 values derived from the exact
// public parameters, verifier key, and canonical state-v8 bytes.  It is a
// local crash-safety record, not part of the presentation wire.
type IntGenISISHolderUsageStateV3 struct {
	Version               int              `json:"version"`
	PresetManifestDigest  string           `json:"preset_manifest_digest"`
	PublicBinding         string           `json:"public_binding"`
	VerifierKeyBinding    string           `json:"verifier_key_binding"`
	CredentialFingerprint string           `json:"credential_fingerprint"`
	NextSlotByContext     map[string]uint8 `json:"next_slot_by_context"`
}

// IntGenISISVerifierStateV3 is the target-only durable replay set.  Context
// and tag identifiers are derived from the trusted codec context and never
// copied from presentation bytes.
type IntGenISISVerifierStateV3 struct {
	Version              int                        `json:"version"`
	PresetManifestDigest string                     `json:"preset_manifest_digest"`
	PublicBinding        string                     `json:"public_binding"`
	VerifierKeyBinding   string                     `json:"verifier_key_binding"`
	Seen                 map[string]map[string]bool `json:"seen"`
}

type intGenISISUsageBindingsV3 struct {
	presetManifestDigest  string
	publicBinding         string
	verifierKeyBinding    string
	credentialFingerprint string
	bindingWidth          int
}

// IntGenISISCredentialFingerprintV3 derives the holder identifier from the
// canonical state-v8 wire and its configured-width public/key bindings.  It
// deliberately never hashes the legacy JSON state representation.
func IntGenISISCredentialFingerprintV3(st IntGenISISState, ctx IntGenISISStateCodecContext) (string, error) {
	wire, err := MarshalIntGenISISStateV8(st, ctx)
	if err != nil {
		return "", fmt.Errorf("marshal canonical state-v8 for fingerprint: %w", err)
	}
	fingerprint, err := IntGenISISStateV8Fingerprint(wire, ctx)
	if err != nil {
		return "", fmt.Errorf("fingerprint canonical state-v8: %w", err)
	}
	return fingerprint, nil
}

func deriveIntGenISISUsageBindingsV3(st IntGenISISState, ctx IntGenISISStateCodecContext) (intGenISISUsageBindingsV3, error) {
	preset, _, width, err := validateIntGenISISStateV8Context(ctx)
	if err != nil {
		return intGenISISUsageBindingsV3{}, err
	}
	publicBinding, keyBinding, err := intGenISISStateV8Bindings(ctx.Public, ctx.VerifierKey, width)
	if err != nil {
		return intGenISISUsageBindingsV3{}, err
	}
	fingerprint, err := IntGenISISCredentialFingerprintV3(st, ctx)
	if err != nil {
		return intGenISISUsageBindingsV3{}, err
	}
	return intGenISISUsageBindingsV3{
		presetManifestDigest:  IntGenISISPresetManifestDigest(preset),
		publicBinding:         hex.EncodeToString(publicBinding),
		verifierKeyBinding:    hex.EncodeToString(keyBinding),
		credentialFingerprint: fingerprint,
		bindingWidth:          width,
	}, nil
}

func deriveIntGenISISVerifierBindingsV3(ctx IntGenISISPresentationCodecContext) (intGenISISUsageBindingsV3, error) {
	preset, _, width, err := validateIntGenISISPresentationV3Context(ctx)
	if err != nil {
		return intGenISISUsageBindingsV3{}, err
	}
	publicBinding, keyBinding, err := intGenISISStateV8Bindings(ctx.Public, ctx.VerifierKey, width)
	if err != nil {
		return intGenISISUsageBindingsV3{}, err
	}
	return intGenISISUsageBindingsV3{
		presetManifestDigest: IntGenISISPresetManifestDigest(preset),
		publicBinding:        hex.EncodeToString(publicBinding),
		verifierKeyBinding:   hex.EncodeToString(keyBinding),
		bindingWidth:         width,
	}, nil
}

func validateConfiguredDigestHex(name, value string, width int) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != width || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("%s must be canonical lowercase %d-byte hex", name, width)
	}
	return nil
}

func newIntGenISISHolderUsageStateV3(bindings intGenISISUsageBindingsV3) IntGenISISHolderUsageStateV3 {
	return IntGenISISHolderUsageStateV3{
		Version:               IntGenISISHolderUsageStateVersionV3,
		PresetManifestDigest:  bindings.presetManifestDigest,
		PublicBinding:         bindings.publicBinding,
		VerifierKeyBinding:    bindings.verifierKeyBinding,
		CredentialFingerprint: bindings.credentialFingerprint,
		NextSlotByContext:     make(map[string]uint8),
	}
}

func (st *IntGenISISHolderUsageStateV3) validateAgainst(bindings intGenISISUsageBindingsV3) error {
	if st.Version != IntGenISISHolderUsageStateVersionV3 {
		return noMigrationSchemaError("IntGenISIS holder-usage-state", st.Version, IntGenISISHolderUsageStateVersionV3)
	}
	if err := validateDigestHex("holder-v3 preset manifest digest", st.PresetManifestDigest); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"holder-v3 public binding":         st.PublicBinding,
		"holder-v3 verifier-key binding":   st.VerifierKeyBinding,
		"holder-v3 credential fingerprint": st.CredentialFingerprint,
	} {
		if err := validateConfiguredDigestHex(name, value, bindings.bindingWidth); err != nil {
			return err
		}
	}
	if st.PresetManifestDigest != bindings.presetManifestDigest ||
		st.PublicBinding != bindings.publicBinding ||
		st.VerifierKeyBinding != bindings.verifierKeyBinding ||
		st.CredentialFingerprint != bindings.credentialFingerprint {
		return fmt.Errorf("holder usage state-v3 credential binding mismatch")
	}
	if st.NextSlotByContext == nil {
		return fmt.Errorf("holder usage state-v3 missing context map")
	}
	for context, next := range st.NextSlotByContext {
		if err := validateConfiguredDigestHex("holder-v3 context identifier", context, bindings.bindingWidth); err != nil {
			return err
		}
		if uint32(next) > IntGenISISQuotaSlots {
			return fmt.Errorf("holder-v3 next slot %d exceeds quota %d", next, IntGenISISQuotaSlots)
		}
	}
	return nil
}

func loadIntGenISISHolderUsageStateV3(path string, bindings intGenISISUsageBindingsV3) (IntGenISISHolderUsageStateV3, error) {
	var st IntGenISISHolderUsageStateV3
	data, err := os.ReadFile(path)
	if err != nil {
		return st, fmt.Errorf("read IntGenISIS holder usage state-v3: %w", err)
	}
	if err := decodeStrictVersionedJSON(data, &st, "IntGenISIS holder-usage-state", IntGenISISHolderUsageStateVersionV3); err != nil {
		return st, fmt.Errorf("decode IntGenISIS holder usage state-v3: %w", err)
	}
	if err := st.validateAgainst(bindings); err != nil {
		return st, err
	}
	return st, nil
}

// LoadIntGenISISHolderUsageStateV3 strictly loads a ledger bound to the exact
// target credential.  A legacy v2 ledger at path is rejected, never migrated.
func LoadIntGenISISHolderUsageStateV3(path string, credential IntGenISISState, ctx IntGenISISStateCodecContext) (IntGenISISHolderUsageStateV3, error) {
	bindings, err := deriveIntGenISISUsageBindingsV3(credential, ctx)
	if err != nil {
		return IntGenISISHolderUsageStateV3{}, err
	}
	return loadIntGenISISHolderUsageStateV3(path, bindings)
}

func saveIntGenISISHolderUsageStateV3(path string, st IntGenISISHolderUsageStateV3, bindings intGenISISUsageBindingsV3) error {
	if err := st.validateAgainst(bindings); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS holder usage state-v3: %w", err)
	}
	return atomicWriteFile(path, append(encoded, '\n'), 0o600)
}

// SaveIntGenISISHolderUsageStateV3 writes a credential-bound ledger with
// mode 0600.  It is primarily useful for explicit state inspection; normal
// callers should reserve through ReserveIntGenISISSlotV3.
func SaveIntGenISISHolderUsageStateV3(path string, usage IntGenISISHolderUsageStateV3, credential IntGenISISState, ctx IntGenISISStateCodecContext) error {
	bindings, err := deriveIntGenISISUsageBindingsV3(credential, ctx)
	if err != nil {
		return err
	}
	return saveIntGenISISHolderUsageStateV3(path, usage, bindings)
}

func canonicalUsageIdentifierV3(domain string, values []int64, modulus uint64, bindings intGenISISUsageBindingsV3, extra []byte) (string, error) {
	packed, err := packCanonicalFq20(values, modulus)
	if err != nil {
		return "", err
	}
	presetDigest, err := hex.DecodeString(bindings.presetManifestDigest)
	if err != nil {
		return "", fmt.Errorf("decode v3 preset digest: %w", err)
	}
	publicBinding, _ := hex.DecodeString(bindings.publicBinding)
	keyBinding, _ := hex.DecodeString(bindings.verifierKeyBinding)
	payload := make([]byte, 0, len(presetDigest)+len(publicBinding)+len(keyBinding)+len(extra)+8+len(packed))
	for _, framed := range [][]byte{presetDigest, publicBinding, keyBinding, extra, packed} {
		var size [8]byte
		binary.LittleEndian.PutUint64(size[:], uint64(len(framed)))
		payload = append(payload, size[:]...)
		payload = append(payload, framed...)
	}
	digest, err := shakeConfiguredBinding(domain, payload, bindings.bindingWidth)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

// ReserveIntGenISISSlotV3 burns and durably persists a target hidden slot
// before proving.  context is the independently derived public field-lane
// binding; it is converted to a configured-width local identifier.
func ReserveIntGenISISSlotV3(path string, credential IntGenISISState, ctx IntGenISISStateCodecContext, context PresentationContextBinding) (uint8, error) {
	bindings, err := deriveIntGenISISUsageBindingsV3(credential, ctx)
	if err != nil {
		return 0, err
	}
	if err := context.Validate(ctx.Public.Modulus); err != nil {
		return 0, fmt.Errorf("validate holder-v3 context: %w", err)
	}
	contextDigest, err := hex.DecodeString(context.Digest)
	if err != nil {
		return 0, fmt.Errorf("decode holder-v3 context digest: %w", err)
	}
	contextID, err := canonicalUsageIdentifierV3(holderUsageV3ContextDomain, context.Lanes, ctx.Public.Modulus, bindings, contextDigest)
	if err != nil {
		return 0, fmt.Errorf("derive holder-v3 context identifier: %w", err)
	}
	var reserved uint8
	err = withExclusiveFileLock(path, func() error {
		st := newIntGenISISHolderUsageStateV3(bindings)
		loaded, loadErr := loadIntGenISISHolderUsageStateV3(path, bindings)
		if loadErr == nil {
			st = loaded
		} else if !errors.Is(loadErr, os.ErrNotExist) {
			return loadErr
		}
		next := st.NextSlotByContext[contextID]
		if uint32(next) >= IntGenISISQuotaSlots {
			return fmt.Errorf("presentation quota exhausted for context: %d slots already reserved", IntGenISISQuotaSlots)
		}
		reserved = next
		st.NextSlotByContext[contextID] = next + 1
		return saveIntGenISISHolderUsageStateV3(path, st, bindings)
	})
	return reserved, err
}

func newIntGenISISVerifierStateV3(bindings intGenISISUsageBindingsV3) IntGenISISVerifierStateV3 {
	return IntGenISISVerifierStateV3{
		Version:              IntGenISISVerifierStateVersionV3,
		PresetManifestDigest: bindings.presetManifestDigest,
		PublicBinding:        bindings.publicBinding,
		VerifierKeyBinding:   bindings.verifierKeyBinding,
		Seen:                 make(map[string]map[string]bool),
	}
}

func (st *IntGenISISVerifierStateV3) validateAgainst(bindings intGenISISUsageBindingsV3) error {
	if st.Version != IntGenISISVerifierStateVersionV3 {
		return noMigrationSchemaError("IntGenISIS verifier-state", st.Version, IntGenISISVerifierStateVersionV3)
	}
	if err := validateDigestHex("verifier-v3 preset manifest digest", st.PresetManifestDigest); err != nil {
		return err
	}
	if err := validateConfiguredDigestHex("verifier-v3 public binding", st.PublicBinding, bindings.bindingWidth); err != nil {
		return err
	}
	if err := validateConfiguredDigestHex("verifier-v3 verifier-key binding", st.VerifierKeyBinding, bindings.bindingWidth); err != nil {
		return err
	}
	if st.PresetManifestDigest != bindings.presetManifestDigest || st.PublicBinding != bindings.publicBinding || st.VerifierKeyBinding != bindings.verifierKeyBinding {
		return fmt.Errorf("verifier state-v3 public/verifier-key binding mismatch")
	}
	if st.Seen == nil {
		return fmt.Errorf("verifier state-v3 missing seen map")
	}
	for namespace, tags := range st.Seen {
		if err := validateConfiguredDigestHex("verifier-v3 context identifier", namespace, bindings.bindingWidth); err != nil {
			return err
		}
		if tags == nil {
			return fmt.Errorf("verifier state-v3 context namespace %q has nil tag set", namespace)
		}
		for tag, seen := range tags {
			if err := validateConfiguredDigestHex("verifier-v3 tag identifier", tag, bindings.bindingWidth); err != nil {
				return err
			}
			if !seen {
				return fmt.Errorf("verifier state-v3 tag identifier %q has false membership", tag)
			}
		}
	}
	return nil
}

func loadIntGenISISVerifierStateV3(path string, bindings intGenISISUsageBindingsV3) (IntGenISISVerifierStateV3, error) {
	var st IntGenISISVerifierStateV3
	data, err := os.ReadFile(path)
	if err != nil {
		return st, fmt.Errorf("read IntGenISIS verifier state-v3: %w", err)
	}
	if err := decodeStrictVersionedJSON(data, &st, "IntGenISIS verifier-state", IntGenISISVerifierStateVersionV3); err != nil {
		return st, fmt.Errorf("decode IntGenISIS verifier state-v3: %w", err)
	}
	if err := st.validateAgainst(bindings); err != nil {
		return st, err
	}
	return st, nil
}

// LoadIntGenISISVerifierStateV3 strictly loads target replay state using the
// externally supplied public/key/context codec binding.
func LoadIntGenISISVerifierStateV3(path string, ctx IntGenISISPresentationCodecContext) (IntGenISISVerifierStateV3, error) {
	bindings, err := deriveIntGenISISVerifierBindingsV3(ctx)
	if err != nil {
		return IntGenISISVerifierStateV3{}, err
	}
	return loadIntGenISISVerifierStateV3(path, bindings)
}

func saveIntGenISISVerifierStateV3(path string, st IntGenISISVerifierStateV3, bindings intGenISISUsageBindingsV3) error {
	if err := st.validateAgainst(bindings); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS verifier state-v3: %w", err)
	}
	return atomicWriteFile(path, append(encoded, '\n'), 0o600)
}

// CheckAndMarkIntGenISISPresentationV3 atomically inserts the tag into the
// replay set derived from ctx.  Callers must cryptographically verify the
// canonical proof with the same ctx before invoking this transition.
func CheckAndMarkIntGenISISPresentationV3(path string, pres IntGenISISPresentationV3, ctx IntGenISISPresentationCodecContext) error {
	if _, err := MarshalIntGenISISPresentationV3(pres, ctx); err != nil {
		return fmt.Errorf("validate presentation-v3 before replay transition: %w", err)
	}
	bindings, err := deriveIntGenISISVerifierBindingsV3(ctx)
	if err != nil {
		return err
	}
	contextID, err := canonicalUsageIdentifierV3(verifierV3ContextDomain, ctx.Context, ctx.Public.Modulus, bindings, nil)
	if err != nil {
		return fmt.Errorf("derive verifier-v3 context identifier: %w", err)
	}
	tagID, err := canonicalUsageIdentifierV3(verifierV3TagDomain, pres.Tag, ctx.Public.Modulus, bindings, nil)
	if err != nil {
		return fmt.Errorf("derive verifier-v3 tag identifier: %w", err)
	}
	return withExclusiveFileLock(path, func() error {
		st := newIntGenISISVerifierStateV3(bindings)
		loaded, loadErr := loadIntGenISISVerifierStateV3(path, bindings)
		if loadErr == nil {
			st = loaded
		} else if !errors.Is(loadErr, os.ErrNotExist) {
			return loadErr
		}
		if st.Seen[contextID] == nil {
			st.Seen[contextID] = make(map[string]bool)
		}
		if st.Seen[contextID][tagID] {
			return fmt.Errorf("replayed IntGenISIS tag in presentation context")
		}
		st.Seen[contextID][tagID] = true
		return saveIntGenISISVerifierStateV3(path, st, bindings)
	})
}
