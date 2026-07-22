package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

type PresetLifecycle string

const (
	PresetInternal   PresetLifecycle = "internal"
	PresetArtifact   PresetLifecycle = "artifact"
	PresetPoC        PresetLifecycle = "poc"
	PresetCandidate  PresetLifecycle = "candidate"
	PresetResearch   PresetLifecycle = "research"
	PresetComplete   PresetLifecycle = "complete"
	PresetDeprecated PresetLifecycle = "deprecated"
)

type ClaimScope string

const (
	ClaimNone           ClaimScope = "none"
	ClaimProofOnly      ClaimScope = "proof_only"
	ClaimCompleteSystem ClaimScope = "complete_system"
)

type ROQueryCapScope string

const (
	// ROQueryCapPerPhaseGlobal means each cap bounds all adversarial oracle
	// queries made against one proof-system phase. Cross-phase composition adds
	// the issuance and showing caps in the log domain.
	ROQueryCapPerPhaseGlobal ROQueryCapScope = "per_phase_global"
)

type ProofVolumeScope string

const (
	ProofVolumeHonestTranscripts ProofVolumeScope = "honest_transcripts"
)

const (
	IntGenISISPresetPoCN512SC96V1            = "poc-n512-sc96-v1"
	IntGenISISPresetArtifactN1024SC96V1      = "artifact-n1024-sc96-v1"
	IntGenISISPresetArtifactN1024SC125V1     = "artifact-n1024-sc125-v1"
	IntGenISISPresetPilotN1024BQ32R96V1      = "pilot-n1024-bq32-r96-v1"
	IntGenISISPresetSystemN1024WF128CROMV1   = "system-n1024-wf128-crom-v1"
	IntGenISISPresetResearchN1024BQ32R128V1  = "research-n1024-bq32-r128-v1"
	IntGenISISPresetResearchN1024BQ128R128V1 = "research-n1024-bq128-r128-v1"
)

// PresetThreatModel records the resource scope to which a preset's security
// statement applies. Counts are represented as base-two logarithms so profiles
// beyond uint64, including BQ128, are represented exactly.
type PresetThreatModel struct {
	ROM                       ROMModel         `json:"rom"`
	SecurityMode              SecurityMode     `json:"security_mode"`
	TargetSingleCandidateBits float64          `json:"target_single_candidate_bits,omitempty"`
	TargetWorkFactorBits      float64          `json:"target_work_factor_bits,omitempty"`
	TargetResidualBits        float64          `json:"target_residual_bits,omitempty"`
	ROQueryCapLog2            [5]float64       `json:"ro_query_cap_log2"`
	ROQueryCapScope           ROQueryCapScope  `json:"ro_query_cap_scope"`
	MaxProofsLog2             float64          `json:"max_proofs_log2"`
	MaxIssuanceProofsLog2     float64          `json:"max_issuance_proofs_log2"`
	MaxShowingProofsLog2      float64          `json:"max_showing_proofs_log2"`
	MaxTagsPerContextLog2     float64          `json:"max_tags_per_context_log2"`
	MaxUsersLog2              float64          `json:"max_users_log2"`
	MaxContextsLog2           float64          `json:"max_contexts_log2"`
	DomainSeparatedContexts   bool             `json:"domain_separated_contexts"`
	ProofVolumeScope          ProofVolumeScope `json:"proof_volume_scope"`
	AcceptedIssuance          int              `json:"accepted_issuance"`
	AcceptedShowing           int              `json:"accepted_showing"`
}

type IntGenISISPresetPortfolioEntry struct {
	CanonicalID       string            `json:"canonical_id"`
	LegacySelector    string            `json:"legacy_selector,omitempty"`
	Purpose           string            `json:"purpose"`
	Lifecycle         PresetLifecycle   `json:"lifecycle"`
	ClaimScope        ClaimScope        `json:"claim_scope"`
	Status            string            `json:"status"`
	Available         bool              `json:"available"`
	SecurityProfile   string            `json:"security_profile,omitempty"`
	SecurityStatement string            `json:"security_statement"`
	ThreatModel       PresetThreatModel `json:"threat_model"`
	Blockers          []string          `json:"blockers,omitempty"`
}

type intGenISISPresetMetadata struct {
	canonicalID      string
	purpose          string
	lifecycle        PresetLifecycle
	claimScope       ClaimScope
	visibleByDefault bool
	proofsLog2       float64
	issuanceLog2     float64
	showingLog2      float64
	tagsLog2         float64
}

func intGenISISPresetMetadataRegistry() map[string]intGenISISPresetMetadata {
	return map[string]intGenISISPresetMetadata{
		IntGenISISPresetN512Compact96: {
			canonicalID: IntGenISISPresetPoCN512SC96V1, purpose: "demonstration",
			lifecycle: PresetPoC, claimScope: ClaimProofOnly, visibleByDefault: true,
		},
		IntGenISISPresetN1024Compact96: {
			canonicalID: IntGenISISPresetArtifactN1024SC96V1, purpose: "reproduction",
			lifecycle: PresetArtifact, claimScope: ClaimProofOnly, visibleByDefault: true,
		},
		IntGenISISPresetN1024Compact125: {
			canonicalID: IntGenISISPresetArtifactN1024SC125V1, purpose: "reproduction",
			lifecycle: PresetArtifact, claimScope: ClaimProofOnly, visibleByDefault: true,
		},
		IntGenISISPresetN1024Q10_96: {
			canonicalID: "artifact-n1024-bq10-r96-historical-v1", purpose: "historical reproduction",
			lifecycle: PresetArtifact, claimScope: ClaimProofOnly,
		},
		IntGenISISPresetN1024Q16_96: {
			canonicalID: "artifact-n1024-bq16-r96-historical-v1", purpose: "historical reproduction",
			lifecycle: PresetArtifact, claimScope: ClaimProofOnly,
		},
		IntGenISISPresetN1024Q32_96: {
			canonicalID: "artifact-n1024-bq32-r96-historical-v1", purpose: "historical reproduction",
			lifecycle: PresetDeprecated, claimScope: ClaimProofOnly,
		},
		IntGenISISPresetN1024Q10_128: {
			canonicalID: "artifact-n1024-bq10-r128-historical-v1", purpose: "historical reproduction",
			lifecycle: PresetArtifact, claimScope: ClaimProofOnly,
		},
		IntGenISISPresetN1024Q16_128: {
			canonicalID: "artifact-n1024-bq16-r128-historical-v1", purpose: "historical reproduction",
			lifecycle: PresetArtifact, claimScope: ClaimProofOnly,
		},
		IntGenISISPresetN1024Q32_128: {
			canonicalID: IntGenISISPresetResearchN1024BQ32R128V1, purpose: "strong bounded-query experiment",
			lifecycle: PresetResearch, claimScope: ClaimProofOnly,
		},
		IntGenISISPresetN1024BQ32_96: {
			canonicalID: IntGenISISPresetPilotN1024BQ32R96V1, purpose: "controlled pilot",
			lifecycle: PresetCandidate, claimScope: ClaimCompleteSystem, visibleByDefault: true,
			proofsLog2: 32, issuanceLog2: 31, showingLog2: 31, tagsLog2: 32,
		},
		IntGenISISPresetN1024BQ64_96Theta11: {
			canonicalID: "internal-n1024-bq64-r96-theta11-v1", purpose: "theorem trail",
			lifecycle: PresetInternal, claimScope: ClaimNone,
		},
		IntGenISISPresetN1024BQ64_128Theta13H256: {
			canonicalID: "internal-n1024-bq64-r128-theta13-h256-v1", purpose: "theorem trail",
			lifecycle: PresetInternal, claimScope: ClaimNone,
		},
		IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512: {
			canonicalID: IntGenISISPresetResearchN1024BQ128R128V1, purpose: "extreme proof-layer experiment",
			lifecycle: PresetResearch, claimScope: ClaimProofOnly,
		},
	}
}

func intGenISISPresetAliases() map[string]string {
	metadata := intGenISISPresetMetadataRegistry()
	legacySelectors := make(map[string]string, len(metadata))
	for legacy := range metadata {
		legacySelectors[normalizeIntGenISISPresetName(legacy)] = legacy
	}
	aliases := make(map[string]string)
	for legacy, presetMetadata := range metadata {
		canonical := normalizeIntGenISISPresetName(presetMetadata.canonicalID)
		if collidingLegacy, exists := legacySelectors[canonical]; exists && collidingLegacy != legacy {
			panic(fmt.Sprintf("canonical IntGenISIS preset ID %q collides with legacy selector %q", presetMetadata.canonicalID, collidingLegacy))
		}
		if existing, exists := aliases[canonical]; exists && existing != legacy {
			panic(fmt.Sprintf("duplicate canonical IntGenISIS preset ID %q", presetMetadata.canonicalID))
		}
		aliases[canonical] = legacy
	}
	return aliases
}

func intGenISISPresetApplyMetadata(reg map[string]IntGenISISPreset) {
	metadata := intGenISISPresetMetadataRegistry()
	for name, preset := range reg {
		meta, ok := metadata[name]
		if !ok {
			panic("missing lifecycle metadata for IntGenISIS preset " + name)
		}
		preset.CanonicalID = meta.canonicalID
		preset.PresetVersion = 1
		preset.Purpose = meta.purpose
		preset.Lifecycle = meta.lifecycle
		preset.ClaimScope = meta.claimScope
		preset.VisibleByDefault = meta.visibleByDefault
		preset.PrimitiveProfileID = preset.Profile
		preset.ThreatModel = intGenISISPresetThreatModel(preset, meta)
		if err := ValidatePresetThreatModel(preset.ThreatModel); err != nil {
			panic(fmt.Sprintf("invalid threat model for IntGenISIS preset %s: %v", name, err))
		}
		if err := ValidateIntGenISISPresetManifest(preset); err != nil {
			panic(fmt.Sprintf("invalid IntGenISIS preset manifest %s: %v", name, err))
		}
		reg[name] = preset
	}
}

func ValidateIntGenISISPresetManifest(preset IntGenISISPreset) error {
	if preset.Name == "" || preset.CanonicalID == "" || preset.PresetVersion <= 0 {
		return fmt.Errorf("missing selector, canonical ID, or version")
	}
	if preset.Profile == "" || preset.PrimitiveProfileID != preset.Profile {
		return fmt.Errorf("primitive profile ID does not match executable profile")
	}
	spec, ok := LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok || preset.SecurityMode != string(spec.Mode) || preset.ThreatModel.SecurityMode != spec.Mode || preset.ThreatModel.ROM != spec.ROM {
		return fmt.Errorf("security profile, mode, and threat model are inconsistent")
	}
	if err := ValidatePresetThreatModel(preset.ThreatModel); err != nil {
		return fmt.Errorf("invalid threat model: %w", err)
	}
	if !presetThreatTargetMatchesProfile(preset.ThreatModel, spec) {
		return fmt.Errorf("threat-model target does not match security profile target")
	}
	issuanceCaps := intGenISISTuningROQueryCapLog2(preset.Issuance)
	showingCaps := intGenISISTuningROQueryCapLog2(preset.Showing)
	if !equalLog2Vectors(issuanceCaps, showingCaps) || !equalLog2Vectors(showingCaps, preset.ThreatModel.ROQueryCapLog2) {
		return fmt.Errorf("issuance, showing, and threat-model query caps differ")
	}
	if spec.Mode == SecurityModeResidualAtBudget {
		var requiredCaps [5]float64
		copy(requiredCaps[:], spec.ROQueryCapBits)
		if !equalLog2Vectors(preset.ThreatModel.ROQueryCapLog2, requiredCaps) {
			return fmt.Errorf("threat-model query caps do not match security profile")
		}
	}
	if preset.PRFProfile == "" || preset.PRFParamsPath == "" || preset.PRFParamsDigest == "" {
		return fmt.Errorf("missing executable PRF binding")
	}
	if _, ok := IntGenISISPRFProfileTagElements(preset.PRFProfile); !ok {
		return fmt.Errorf("unknown executable PRF profile %q", preset.PRFProfile)
	}
	expectedPRFDigest, ok := IntGenISISPRFProfileParamsDigest(preset.PRFProfile)
	if !ok || preset.PRFParamsDigest != expectedPRFDigest {
		return fmt.Errorf("PRF parameter digest does not match executable profile")
	}
	if preset.Issuance.PRFProfile != preset.PRFProfile || preset.Showing.PRFProfile != preset.PRFProfile || preset.Issuance.PRFParamsPath != preset.PRFParamsPath || preset.Showing.PRFParamsPath != preset.PRFParamsPath {
		return fmt.Errorf("phase PRF metadata does not match preset binding")
	}
	if preset.Issuance.TranscriptMode == "" || preset.Issuance.TranscriptMode != preset.Showing.TranscriptMode {
		return fmt.Errorf("issuance and showing transcript modes differ")
	}
	switch preset.Lifecycle {
	case PresetInternal, PresetArtifact, PresetPoC, PresetCandidate, PresetResearch, PresetComplete, PresetDeprecated:
	default:
		return fmt.Errorf("unsupported lifecycle %q", preset.Lifecycle)
	}
	switch preset.ClaimScope {
	case ClaimNone, ClaimProofOnly, ClaimCompleteSystem:
	default:
		return fmt.Errorf("unsupported claim scope %q", preset.ClaimScope)
	}
	if preset.CompleteSystemClaim && (preset.Lifecycle != PresetComplete || preset.ClaimScope != ClaimCompleteSystem || spec.Status != SecurityProfileCompleteLive) {
		return fmt.Errorf("complete-system claim lacks complete lifecycle/profile status")
	}
	if preset.TargetTheoremBits <= 0 || preset.MaxNLeaves <= 0 {
		return fmt.Errorf("invalid theorem target or degree-enforcing domain cap")
	}
	return nil
}

func presetThreatTargetMatchesProfile(model PresetThreatModel, spec IntGenISISSecurityProfileSpec) bool {
	var target float64
	switch spec.Mode {
	case SecurityModeSingleCandidate:
		target = model.TargetSingleCandidateBits
	case SecurityModeQueryWorkFactor:
		target = model.TargetWorkFactorBits
	case SecurityModeResidualAtBudget:
		target = model.TargetResidualBits
	default:
		return false
	}
	return math.Abs(target-spec.TargetBits) <= 1e-9
}

func equalLog2Vectors(left, right [5]float64) bool {
	for i := range left {
		if math.IsNaN(left[i]) || math.IsNaN(right[i]) || math.IsInf(left[i], 0) || math.IsInf(right[i], 0) || math.Abs(left[i]-right[i]) > 1e-9 {
			return false
		}
	}
	return true
}

func intGenISISPresetThreatModel(preset IntGenISISPreset, meta intGenISISPresetMetadata) PresetThreatModel {
	spec, ok := LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		panic(fmt.Sprintf("missing security profile %q for IntGenISIS preset %s", preset.SecurityProfile, preset.Name))
	}
	model := PresetThreatModel{
		ROM:                     spec.ROM,
		SecurityMode:            spec.Mode,
		ROQueryCapLog2:          intGenISISTuningROQueryCapLog2(preset.Showing),
		ROQueryCapScope:         ROQueryCapPerPhaseGlobal,
		MaxProofsLog2:           meta.proofsLog2,
		MaxIssuanceProofsLog2:   meta.issuanceLog2,
		MaxShowingProofsLog2:    meta.showingLog2,
		MaxTagsPerContextLog2:   meta.tagsLog2,
		DomainSeparatedContexts: true,
		ProofVolumeScope:        ProofVolumeHonestTranscripts,
		AcceptedIssuance:        1,
		AcceptedShowing:         1,
	}
	if meta.proofsLog2 == 0 {
		// Artifact and proof-only manifests cover one issuance and one showing.
		model.MaxProofsLog2 = 1
		model.MaxIssuanceProofsLog2 = 0
		model.MaxShowingProofsLog2 = 0
	}
	switch spec.Mode {
	case SecurityModeSingleCandidate:
		model.TargetSingleCandidateBits = spec.TargetBits
	case SecurityModeQueryWorkFactor:
		model.TargetWorkFactorBits = spec.TargetBits
	case SecurityModeResidualAtBudget:
		model.TargetResidualBits = spec.TargetBits
	}
	return model
}

func intGenISISTuningROQueryCapLog2(tuning IntGenISISTuningPreset) [5]float64 {
	if tuning.ROQueryCapBitsSet {
		return tuning.ROQueryCapBits
	}
	var out [5]float64
	if tuning.ROQueryCapsSet {
		for i, cap := range tuning.ROQueryCaps {
			if cap > 0 {
				out[i] = math.Log2(float64(cap))
			}
		}
	}
	return out
}

func ValidatePresetThreatModel(model PresetThreatModel) error {
	if model.ROM == "" || model.SecurityMode == "" {
		return fmt.Errorf("threat model is missing ROM or security mode")
	}
	if model.ROQueryCapScope != ROQueryCapPerPhaseGlobal {
		return fmt.Errorf("unsupported RO query-cap scope %q", model.ROQueryCapScope)
	}
	if model.ProofVolumeScope != ProofVolumeHonestTranscripts {
		return fmt.Errorf("unsupported proof volume scope %q", model.ProofVolumeScope)
	}
	switch model.SecurityMode {
	case SecurityModeSingleCandidate:
		if !finitePositive(model.TargetSingleCandidateBits) || model.TargetWorkFactorBits != 0 || model.TargetResidualBits != 0 {
			return fmt.Errorf("single-candidate threat model has inconsistent targets")
		}
	case SecurityModeQueryWorkFactor:
		if !finitePositive(model.TargetWorkFactorBits) || model.TargetSingleCandidateBits != 0 || model.TargetResidualBits != 0 {
			return fmt.Errorf("work-factor threat model has inconsistent targets")
		}
	case SecurityModeResidualAtBudget:
		if !finitePositive(model.TargetResidualBits) || model.TargetSingleCandidateBits != 0 || model.TargetWorkFactorBits != 0 {
			return fmt.Errorf("residual-budget threat model has inconsistent targets")
		}
	default:
		return fmt.Errorf("unsupported security mode %q", model.SecurityMode)
	}
	if model.AcceptedIssuance < 0 || model.AcceptedShowing < 0 || model.AcceptedIssuance+model.AcceptedShowing == 0 {
		return fmt.Errorf("invalid accepted-proof composition issuance=%d showing=%d", model.AcceptedIssuance, model.AcceptedShowing)
	}
	for i, value := range model.ROQueryCapLog2 {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("invalid logarithmic query cap %d=%v", i, value)
		}
	}
	volumes := []struct {
		name  string
		value float64
	}{
		{"proofs", model.MaxProofsLog2},
		{"issuance proofs", model.MaxIssuanceProofsLog2},
		{"showing proofs", model.MaxShowingProofsLog2},
		{"tags per context", model.MaxTagsPerContextLog2},
		{"users", model.MaxUsersLog2},
		{"contexts", model.MaxContextsLog2},
	}
	for _, volume := range volumes {
		if volume.value < 0 || math.IsNaN(volume.value) || math.IsInf(volume.value, 0) {
			return fmt.Errorf("invalid %s logarithmic volume %v", volume.name, volume.value)
		}
	}
	phaseTotal := log2SumCounts(model.MaxIssuanceProofsLog2, model.MaxShowingProofsLog2)
	if phaseTotal > model.MaxProofsLog2+1e-9 {
		return fmt.Errorf("issuance/showing proof volumes total 2^%.2f above global 2^%.2f", phaseTotal, model.MaxProofsLog2)
	}
	return nil
}

func log2SumCounts(a, b float64) float64 {
	max := math.Max(a, b)
	return max + math.Log2(math.Exp2(a-max)+math.Exp2(b-max))
}

func IntGenISISDefaultPresetNames() []string {
	entries := IntGenISISPresetPortfolio(false, false)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.CanonicalID)
	}
	return names
}

func IntGenISISPresetPortfolio(includeResearch, includeAll bool) []IntGenISISPresetPortfolioEntry {
	reg := intGenISISPresetRegistry()
	ordered := []string{
		IntGenISISPresetN512Compact96,
		IntGenISISPresetN1024Compact96,
		IntGenISISPresetN1024Compact125,
		IntGenISISPresetN1024BQ32_96,
	}
	entries := make([]IntGenISISPresetPortfolioEntry, 0, len(reg)+1)
	seen := make(map[string]bool)
	for _, name := range ordered {
		preset := reg[name]
		if !preset.VisibleByDefault {
			continue
		}
		entry := intGenISISPortfolioEntryFromPreset(preset)
		entries = append(entries, entry)
		seen[name] = true
	}
	entries = append(entries, intGenISISUnavailableWF128Entry())
	if includeResearch || includeAll {
		for _, name := range []string{IntGenISISPresetN1024Q32_128, IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512} {
			entries = append(entries, intGenISISPortfolioEntryFromPreset(reg[name]))
			seen[name] = true
		}
	}
	if includeAll {
		names := make([]string, 0, len(reg))
		for name := range reg {
			if !seen[name] {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			entries = append(entries, intGenISISPortfolioEntryFromPreset(reg[name]))
		}
	}
	return entries
}

func LookupIntGenISISPresetPortfolioEntry(selector string) (IntGenISISPresetPortfolioEntry, bool) {
	normalized := normalizeIntGenISISPresetName(selector)
	for _, entry := range IntGenISISPresetPortfolio(true, true) {
		if normalized == normalizeIntGenISISPresetName(entry.CanonicalID) || normalized == normalizeIntGenISISPresetName(entry.LegacySelector) {
			return entry, true
		}
	}
	return IntGenISISPresetPortfolioEntry{}, false
}

func intGenISISPortfolioEntryFromPreset(preset IntGenISISPreset) IntGenISISPresetPortfolioEntry {
	status := "available"
	blockers := []string(nil)
	if preset.Lifecycle == PresetCandidate {
		status = "candidate"
		blockers = []string{"complete security ledger has not passed", "full-game simultaneous extraction remains report-only"}
	} else if preset.Lifecycle == PresetResearch || preset.Lifecycle == PresetInternal {
		status = "research"
	}
	statement := preset.SecurityProfile + " proof-system profile"
	switch preset.CanonicalID {
	case IntGenISISPresetPoCN512SC96V1:
		statement = "approximately 96 one-candidate SmallWood bits; no full-game claim"
	case IntGenISISPresetArtifactN1024SC96V1:
		statement = "SC-96 proof-only paper reproduction"
	case IntGenISISPresetArtifactN1024SC125V1:
		statement = "SC-125 proof-only paper reproduction"
	case IntGenISISPresetPilotN1024BQ32R96V1:
		statement = "candidate for at least 96 residual bits under raw 2^32 CROM caps and the declared pilot volume"
	case IntGenISISPresetResearchN1024BQ32R128V1:
		statement = "proof-only bounded-query experiment; complete use requires a stronger primitive and PRF family"
	case IntGenISISPresetResearchN1024BQ128R128V1:
		statement = "128 residual proof-system bits after raw 2^128 CROM queries; complete use requires a 256-bit redesign"
	}
	return IntGenISISPresetPortfolioEntry{
		CanonicalID:       preset.CanonicalID,
		LegacySelector:    preset.Name,
		Purpose:           preset.Purpose,
		Lifecycle:         preset.Lifecycle,
		ClaimScope:        preset.ClaimScope,
		Status:            status,
		Available:         true,
		SecurityProfile:   preset.SecurityProfile,
		SecurityStatement: statement,
		ThreatModel:       preset.ThreatModel,
		Blockers:          blockers,
	}
}

func intGenISISUnavailableWF128Entry() IntGenISISPresetPortfolioEntry {
	model := PresetThreatModel{
		ROM:                     ROMModelCROM,
		SecurityMode:            SecurityModeQueryWorkFactor,
		TargetWorkFactorBits:    128,
		ROQueryCapScope:         ROQueryCapPerPhaseGlobal,
		MaxProofsLog2:           1,
		DomainSeparatedContexts: true,
		ProofVolumeScope:        ProofVolumeHonestTranscripts,
		AcceptedIssuance:        1,
		AcceptedShowing:         1,
	}
	if err := ValidatePresetThreatModel(model); err != nil {
		panic("invalid unavailable WF-128 threat model: " + err.Error())
	}
	return IntGenISISPresetPortfolioEntry{
		CanonicalID:       IntGenISISPresetSystemN1024WF128CROMV1,
		Purpose:           "deployment",
		Lifecycle:         PresetCandidate,
		ClaimScope:        ClaimCompleteSystem,
		Status:            "unavailable",
		Available:         false,
		SecurityProfile:   "WF-128",
		SecurityStatement: "128-bit complete-system CROM work factor once every measured, theorem, and primitive gate passes",
		ThreatModel:       model,
		Blockers: []string{
			"no executable tag-13 or tag-14 PRF parameter family",
			"full-game simultaneous extraction remains report-only",
			"complete-system composition and estimator provenance are not approved",
		},
	}
}

type intGenISISCanonicalManifest struct {
	Schema             string                 `json:"schema"`
	CanonicalID        string                 `json:"canonical_id"`
	PresetVersion      int                    `json:"preset_version"`
	PrimitiveProfileID string                 `json:"primitive_profile_id"`
	SecurityProfile    string                 `json:"security_profile"`
	SecurityMode       string                 `json:"security_mode"`
	Lifecycle          PresetLifecycle        `json:"lifecycle"`
	ClaimScope         ClaimScope             `json:"claim_scope"`
	PRFProfile         string                 `json:"prf_profile"`
	PRFParamsDigest    string                 `json:"prf_params_digest"`
	NTRUBeta           uint64                 `json:"ntru_beta"`
	MaxNLeaves         int                    `json:"max_nleaves"`
	Issuance           IntGenISISTuningPreset `json:"issuance"`
	Showing            IntGenISISTuningPreset `json:"showing"`
	ThreatModel        PresetThreatModel      `json:"threat_model"`
}

func IntGenISISPresetManifestDigest(preset IntGenISISPreset) string {
	issuance := preset.Issuance
	showing := preset.Showing
	// Parameter-file locations are operational configuration. The digest and
	// profile IDs bind file contents independently of where they are installed.
	issuance.PRFParamsPath = ""
	showing.PRFParamsPath = ""
	manifest := intGenISISCanonicalManifest{
		Schema:             "spruce.intgenisis.preset.v1",
		CanonicalID:        preset.CanonicalID,
		PresetVersion:      preset.PresetVersion,
		PrimitiveProfileID: preset.PrimitiveProfileID,
		SecurityProfile:    preset.SecurityProfile,
		SecurityMode:       preset.SecurityMode,
		Lifecycle:          preset.Lifecycle,
		ClaimScope:         preset.ClaimScope,
		PRFProfile:         preset.PRFProfile,
		PRFParamsDigest:    preset.PRFParamsDigest,
		NTRUBeta:           preset.NTRUBeta,
		MaxNLeaves:         preset.MaxNLeaves,
		Issuance:           issuance,
		Showing:            showing,
		ThreatModel:        preset.ThreatModel,
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		panic("marshal IntGenISIS preset manifest: " + err.Error())
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
