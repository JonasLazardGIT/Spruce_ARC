package credential

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

const IntGenISISStateVersion = 7

// IntGenISISState is the live credential witness/state for the committed-message
// protocol. It intentionally does not include c, T, r0/r1, holder/issuer split
// randomness, or LHL metadata.
type IntGenISISState struct {
	Version              int       `json:"version"`
	Profile              string    `json:"profile"`
	PresetID             string    `json:"preset_id"`
	PresetVersion        int       `json:"preset_version"`
	PrimitiveProfileID   string    `json:"primitive_profile_id"`
	PRFProfile           string    `json:"prf_profile"`
	TranscriptMode       string    `json:"transcript_mode"`
	PresetManifestDigest string    `json:"preset_manifest_digest"`
	M                    [][]int64 `json:"M"`
	MAttr                [][]int64 `json:"m"`
	K                    [][]int64 `json:"k"`
	S                    [][]int64 `json:"s"`
	E                    [][]int64 `json:"e"`
	MuSig                [][]int64 `json:"mu_sig"`
	X0                   [][]int64 `json:"x0"`
	X1                   [][]int64 `json:"x1"`
	SigS1                []int64   `json:"sig_s1"`
	SigS2                []int64   `json:"sig_s2"`
	RingDegree           int       `json:"ring_degree"`
	PackedNCols          int       `json:"packed_ncols"`
	CredentialPublicPath string    `json:"credential_public_path"`
	HashRelation         string    `json:"hash_relation"`
	BPath                string    `json:"b_path"`
	PRFParamsPath        string    `json:"prf_params_path"`
	NTRUPublic           [][]int64 `json:"ntru_public"`
	SignatureBound       int64     `json:"signature_bound"`
}

func SaveIntGenISISState(path string, st IntGenISISState) error {
	if err := st.Validate(); err != nil {
		return err
	}
	if err := rejectTargetLegacyIntGenISISStateIO(st); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IntGenISIS state: %w", err)
	}
	if err := atomicWriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write IntGenISIS state: %w", err)
	}
	return nil
}

func LoadIntGenISISState(path string) (IntGenISISState, error) {
	var st IntGenISISState
	data, err := os.ReadFile(path)
	if err != nil {
		return st, fmt.Errorf("read IntGenISIS state: %w", err)
	}
	if err := decodeStrictVersionedJSON(data, &st, "IntGenISIS credential-state", IntGenISISStateVersion); err != nil {
		return st, fmt.Errorf("decode IntGenISIS state: %w", err)
	}
	if err := st.Validate(); err != nil {
		return st, fmt.Errorf("validate IntGenISIS state %s: %w", path, err)
	}
	if err := rejectTargetLegacyIntGenISISStateIO(st); err != nil {
		return st, fmt.Errorf("validate IntGenISIS state %s: %w", path, err)
	}
	return st, nil
}

// rejectTargetLegacyIntGenISISStateIO keeps the exported JSON helpers from
// becoming an implicit migration or fallback path for strict-v3 credentials.
// State-v8 deliberately decodes into the existing in-memory IntGenISISState
// type, so this guard belongs at the legacy I/O boundary rather than Validate.
func rejectTargetLegacyIntGenISISStateIO(st IntGenISISState) error {
	preset, ok := LookupIntGenISISPreset(st.PresetID)
	if !ok {
		return fmt.Errorf("unknown state preset_id %q", st.PresetID)
	}
	if preset.StateFormatVersion == IntGenISISStateFormatVersionV8 {
		return fmt.Errorf("preset %q rejects legacy JSON credential-state I/O; use the canonical state-v8 codec (no automatic migration)", preset.CanonicalID)
	}
	return nil
}

func (st IntGenISISState) Validate() error {
	if st.Version != IntGenISISStateVersion {
		return noMigrationSchemaError("IntGenISIS credential-state", st.Version, IntGenISISStateVersion)
	}
	profile, ok := LookupIntGenISISProfile(st.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", st.Profile)
	}
	if st.RingDegree != profile.N {
		return fmt.Errorf("ring_degree=%d want %d", st.RingDegree, profile.N)
	}
	if st.PresetID == "" || st.PresetVersion <= 0 || st.PrimitiveProfileID == "" || st.PRFProfile == "" || st.TranscriptMode == "" || st.PresetManifestDigest == "" {
		return fmt.Errorf("incomplete IntGenISIS state preset binding")
	}
	preset, ok := LookupIntGenISISPreset(st.PresetID)
	if !ok {
		return fmt.Errorf("unknown state preset_id %q", st.PresetID)
	}
	if st.PresetID != preset.CanonicalID || st.Profile != preset.Profile || st.PrimitiveProfileID != preset.PrimitiveProfileID || st.PRFProfile != preset.PRFProfile || st.TranscriptMode != preset.Showing.TranscriptMode || st.PresetVersion != preset.PresetVersion || st.PresetManifestDigest != IntGenISISPresetManifestDigest(preset) {
		return fmt.Errorf("IntGenISIS state preset manifest mismatch")
	}
	if st.PRFParamsPath != preset.PRFParamsPath {
		return fmt.Errorf("state prf_params_path=%q does not match preset path %q", st.PRFParamsPath, preset.PRFParamsPath)
	}
	if st.PackedNCols != preset.Showing.NCols {
		return fmt.Errorf("state packed_ncols=%d does not match preset showing ncols=%d", st.PackedNCols, preset.Showing.NCols)
	}
	if st.CredentialPublicPath == "" {
		return fmt.Errorf("missing credential_public_path")
	}
	if err := ValidateHashRelation(st.HashRelation); err != nil {
		return err
	}
	if st.BPath == "" {
		return fmt.Errorf("missing b_path")
	}
	if len(st.M) != profile.EllM {
		return fmt.Errorf("m rows=%d want ell_M=%d", len(st.M), profile.EllM)
	}
	if len(st.MAttr) != profile.EllM {
		return fmt.Errorf("m rows=%d want ell_M=%d", len(st.MAttr), profile.EllM)
	}
	if len(st.K) != profile.EllM {
		return fmt.Errorf("k rows=%d want ell_M=%d", len(st.K), profile.EllM)
	}
	if len(st.S) != profile.KS {
		return fmt.Errorf("s rows=%d want k_s=%d", len(st.S), profile.KS)
	}
	if len(st.E) != profile.NC {
		return fmt.Errorf("e rows=%d want n_c=%d", len(st.E), profile.NC)
	}
	if len(st.MuSig) != profile.EllMuSig {
		return fmt.Errorf("mu_sig rows=%d want %d", len(st.MuSig), profile.EllMuSig)
	}
	if len(st.X0) != profile.EllX0 {
		return fmt.Errorf("x0 rows=%d want %d", len(st.X0), profile.EllX0)
	}
	if len(st.X1) != profile.EllX1 {
		return fmt.Errorf("x1 rows=%d want %d", len(st.X1), profile.EllX1)
	}
	for name, rows := range map[string][][]int64{
		"M":      st.M,
		"m":      st.MAttr,
		"k":      st.K,
		"s":      st.S,
		"e":      st.E,
		"mu_sig": st.MuSig,
		"x0":     st.X0,
		"x1":     st.X1,
	} {
		for i := range rows {
			if len(rows[i]) != profile.N {
				return fmt.Errorf("%s[%d] coefficient length=%d want %d", name, i, len(rows[i]), profile.N)
			}
		}
	}
	layout, err := DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		return err
	}
	if err := ValidateSemanticMessage(layout, SemanticMessage{M: st.M, MAttr: st.MAttr, K: st.K}); err != nil {
		return fmt.Errorf("semantic message: %w", err)
	}
	if err := validateBoundedIntGenISISRows("s", st.S, IntGenISISLiveBound); err != nil {
		return err
	}
	if err := validateBoundedIntGenISISRows("e", st.E, IntGenISISLiveBound); err != nil {
		return err
	}
	for name, rows := range map[string][][]int64{
		"mu_sig": st.MuSig,
		"x0":     st.X0,
		"x1":     st.X1,
	} {
		if err := validateBoundedIntGenISISRows(name, rows, profile.HashInputBound); err != nil {
			return err
		}
	}
	if len(st.SigS1) != profile.N {
		return fmt.Errorf("sig_s1 coefficient length=%d want %d", len(st.SigS1), profile.N)
	}
	if len(st.SigS2) != profile.N {
		return fmt.Errorf("sig_s2 coefficient length=%d want %d", len(st.SigS2), profile.N)
	}
	if st.SignatureBound <= 0 {
		return fmt.Errorf("signature_bound=%d must be positive", st.SignatureBound)
	}
	if err := validateBoundedIntGenISISRows("signature", [][]int64{st.SigS1, st.SigS2}, st.SignatureBound); err != nil {
		return err
	}
	if len(st.NTRUPublic) != 1 || len(st.NTRUPublic[0]) != profile.N {
		return fmt.Errorf("ntru_public dimensions=%dx? want 1x%d", len(st.NTRUPublic), profile.N)
	}
	return nil
}

func (st IntGenISISState) HasPresetBinding() bool {
	return st.PresetID != "" || st.PresetVersion != 0 || st.PrimitiveProfileID != "" || st.PRFProfile != "" || st.TranscriptMode != "" || st.PresetManifestDigest != ""
}

func (st IntGenISISState) ValidateIntGenISISPreset(public PublicParams, preset IntGenISISPreset) error {
	if err := st.Validate(); err != nil {
		return err
	}
	if err := (&public).Validate(); err != nil {
		return err
	}
	if err := public.ValidateIntGenISISPreset(preset); err != nil {
		return err
	}
	if st.Profile != public.Profile || st.PresetID != public.PresetID || st.PresetVersion != public.PresetVersion || st.PrimitiveProfileID != public.PrimitiveProfileID || st.PRFProfile != public.PRFProfile || st.TranscriptMode != public.TranscriptMode || st.PresetManifestDigest != public.PresetManifestDigest {
		return fmt.Errorf("credential state and public parameter preset bindings differ")
	}
	if st.RingDegree != public.RingDegree || st.HashRelation != public.HashRelation || st.BPath != public.BPath {
		return fmt.Errorf("credential state and public parameter primitive bindings differ")
	}
	return nil
}

// ValidateAgainst verifies the complete persisted credential/public/verifier
// key identity. It must be called before the state is used for showing.
func (st IntGenISISState) ValidateAgainst(public PublicParams, key IntGenISISVerifierKey) error {
	preset, ok := LookupIntGenISISPreset(public.PresetID)
	if !ok {
		return fmt.Errorf("unknown public parameter preset_id %q", public.PresetID)
	}
	if err := st.ValidateIntGenISISPreset(public, preset); err != nil {
		return err
	}
	if err := key.ValidateAgainst(public); err != nil {
		return err
	}
	if st.SignatureBound != key.SignatureBound || len(st.NTRUPublic) != len(key.NTRUPublic) {
		return fmt.Errorf("credential state and verifier key signature bindings differ")
	}
	for i := range st.NTRUPublic {
		if !slices.Equal(st.NTRUPublic[i], key.NTRUPublic[i]) {
			return fmt.Errorf("credential state and verifier key NTRU public keys differ")
		}
	}
	return nil
}

func validateBoundedIntGenISISRows(name string, rows [][]int64, bound int64) error {
	if bound <= 0 {
		return fmt.Errorf("invalid %s bound %d", name, bound)
	}
	for i := range rows {
		for j, v := range rows[i] {
			if v < -bound || v > bound {
				return fmt.Errorf("%s[%d][%d]=%d outside [-%d,%d]", name, i, j, v, bound, bound)
			}
		}
	}
	return nil
}
