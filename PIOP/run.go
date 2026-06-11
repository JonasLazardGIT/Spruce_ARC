package PIOP

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	CoeffNativeSigModelLiteralPackedAggregatedV3 = "literal_packed_aggregated_v3"
	TranscriptProtocolSmallField2025V1           = "smallfield_2025_1085_v1"
	TranscriptVersionSmallWood2025               = "smallwood_2025_1085_v1"
)

const (
	ShowingPresetInlineTargetReplayCompactResearch = "aggregate_inline_target_replay_compact_research"
)

type ShowingReplayMode string

const (
	ShowingReplayModeReduced ShowingReplayMode = "reduced"
	ShowingReplayModeFull    ShowingReplayMode = "full"
)

type ShowingStatementClass string

const (
	ShowingStatementClassReducedEngineeringReplay           ShowingStatementClass = "reduced_engineering_replay"
	ShowingStatementClassTheoremCleanFullReplay             ShowingStatementClass = "theorem_clean_full_replay"
	ShowingStatementClassTheoremCleanDirectTargetFullReplay ShowingStatementClass = "theorem_clean_direct_target_full_replay"
	ShowingStatementClassCustom                             ShowingStatementClass = "custom_replay_surface"
)

const (
	SigShortnessModeNone             = "none"
	SigShortnessModeReplayCompactV18 = "sig_shortness_inline_target_replay_compact_hiding"
)

const (
	aggregateInlineTargetReplayCompactLVCSNCols  = 84
	aggregateInlineTargetReplayCompactEll        = 16
	aggregateInlineTargetReplayCompactEta        = 41
	aggregateInlineTargetReplayCompactEllPrime   = 2
	aggregateInlineTargetReplayCompactTheta      = 3
	aggregateInlineTargetReplayCompactRho        = 2
	aggregateInlineTargetReplayCompactNLeaves    = 5760
	aggregateInlineTargetReplayCompactNCols      = 16
	aggregateInlineTargetReplayCompactGroupSize  = 1
	aggregateInlineTargetReplayCompactSigProfile = SigShortnessProfileR11L4Production
)

var (
	aggregateInlineTargetReplayCompactKappa = [4]int{10, 0, 0, 6}
)

func normalizeShowingReplayMode(mode ShowingReplayMode) ShowingReplayMode {
	switch mode {
	case ShowingReplayModeReduced, ShowingReplayModeFull:
		return mode
	case "":
		return ShowingReplayModeReduced
	default:
		return ShowingReplayModeReduced
	}
}

func normalizeTranscriptProtocolMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case "":
		return ""
	case TranscriptProtocolSmallField2025V1, "smallfield-2025-1085-v1", "smallfield_2025", "smallfield-2025":
		return TranscriptProtocolSmallField2025V1
	default:
		return strings.TrimSpace(mode)
	}
}

func normalizeTranscriptVersion(version string) string {
	switch strings.TrimSpace(version) {
	case "", "legacy":
		return ""
	case TranscriptVersionSmallWood2025, "smallwood-2025-1085-v1", "2025-1085", "paper":
		return TranscriptVersionSmallWood2025
	default:
		return strings.TrimSpace(version)
	}
}

func proofUsesPaperQPayloadOnly(proof *Proof) bool {
	return proof != nil && normalizeTranscriptVersion(proof.TranscriptVersion) == TranscriptVersionSmallWood2025
}

func proofHasLegacyQDECS(proof *Proof) bool {
	if proof == nil {
		return false
	}
	return proof.QRoot != ([16]byte{}) ||
		len(proof.QRootHash) > 0 ||
		len(proof.QR) > 0 ||
		len(proof.QRBits) > 0 ||
		proof.QRRows != 0 ||
		proof.QRCols != 0 ||
		proof.QRBitWidth != 0 ||
		proof.QOpening != nil
}

func proofQRowsExpected(proof *Proof) int {
	if proof == nil {
		return 0
	}
	if proof.Theta > 1 && len(proof.GammaPrimeK) > 0 {
		return len(proof.GammaPrimeK) * proof.Theta
	}
	if len(proof.GammaPrime) > 0 {
		return len(proof.GammaPrime)
	}
	if proof.QOpening != nil {
		return proof.QOpening.R
	}
	if rows := proof.QPayloadMatrix(); len(rows) > 0 {
		return len(rows)
	}
	return 0
}

func ResolveShowingStatementClass(proof *Proof, opts SimOpts) string {
	mode := normalizeShowingReplayMode(opts.ShowingReplayMode)
	if proof == nil {
		switch mode {
		case ShowingReplayModeReduced:
			return string(ShowingStatementClassReducedEngineeringReplay)
		case ShowingReplayModeFull:
			return string(ShowingStatementClassCustom)
		default:
			return string(ShowingStatementClassCustom)
		}
	}
	if showingLayoutIsTheoremCleanDirectTargetFullReplay(proof.RowLayout, mode) ||
		(proof.SigShortness != nil && proof.SigShortness.Version == sigShortnessProofVersionV18 && showingLayoutIsInlineTargetFullReplayCore(proof.RowLayout, mode)) {
		return string(ShowingStatementClassTheoremCleanDirectTargetFullReplay)
	}
	if showingLayoutIsTheoremCleanFullReplay(proof.RowLayout, mode) {
		return string(ShowingStatementClassTheoremCleanFullReplay)
	}
	if mode == ShowingReplayModeReduced {
		return string(ShowingStatementClassReducedEngineeringReplay)
	}
	return string(ShowingStatementClassCustom)
}

func showingLayoutIsTheoremCleanFullReplay(layout RowLayout, mode ShowingReplayMode) bool {
	if normalizeShowingReplayMode(mode) != ShowingReplayModeFull {
		return false
	}
	replayBlocks := rowLayoutReplayBlockCount(layout)
	if replayBlocks <= 0 {
		return false
	}
	if rowLayoutReplayTHatCount(layout) != replayBlocks {
		return false
	}
	if layout.SigBlocks > 0 && layout.SigBlocks != replayBlocks {
		return false
	}
	x0Len := rowLayoutX0Len(layout)
	if x0Len <= 0 {
		return false
	}
	for block := 0; block < replayBlocks; block++ {
		if rowLayoutPostSignTHatIndex(layout, block) < 0 ||
			rowLayoutPostSignMHatSigmaIndex(layout, block) < 0 ||
			rowLayoutPostSignRHat1Index(layout, block) < 0 ||
			rowLayoutPostSignZHatIndex(layout, block) < 0 {
			return false
		}
		if rowLayoutPostSignR0B2HatIndex(layout, block) < 0 {
			for component := 0; component < x0Len; component++ {
				if rowLayoutPostSignRHat0ComponentIndex(layout, block, component) < 0 {
					return false
				}
			}
		}
	}
	return true
}

func showingLayoutIsTheoremCleanDirectTargetFullReplay(layout RowLayout, mode ShowingReplayMode) bool {
	if !showingLayoutIsDirectTargetFullReplayCore(layout, mode) {
		return false
	}
	if layout.PackedSigChainBase < 0 || layout.PackedSigChainGroupCount <= 0 || layout.PackedSigChainRowsPerGroup <= 0 {
		return false
	}
	return true
}

func showingLayoutIsDirectTargetFullReplayCore(layout RowLayout, mode ShowingReplayMode) bool {
	if normalizeShowingReplayMode(mode) != ShowingReplayModeFull {
		return false
	}
	replayBlocks := rowLayoutReplayBlockCount(layout)
	if replayBlocks <= 0 {
		return false
	}
	if rowLayoutReplayTHatCount(layout) != 0 {
		return false
	}
	if layout.SigBlocks > 0 && layout.SigBlocks != replayBlocks {
		return false
	}
	for block := 0; block < replayBlocks; block++ {
		if rowLayoutPostSignTargetMR0HatIndex(layout, block) < 0 ||
			rowLayoutPostSignRHat1Index(layout, block) < 0 ||
			rowLayoutPostSignZHatIndex(layout, block) < 0 {
			return false
		}
	}
	return true
}

func showingLayoutIsInlineTargetFullReplayCore(layout RowLayout, mode ShowingReplayMode) bool {
	if normalizeShowingReplayMode(mode) != ShowingReplayModeFull {
		return false
	}
	replayBlocks := rowLayoutReplayBlockCount(layout)
	if replayBlocks <= 0 {
		return false
	}
	if rowLayoutReplayTHatCount(layout) != 0 || len(rowLayoutPostSignTargetMR0HatRows(layout)) != 0 {
		return false
	}
	if layout.SigBlocks > 0 && layout.SigBlocks != replayBlocks {
		return false
	}
	if layout.PackedSigChainBase < 0 || layout.PackedSigChainGroupCount <= 0 || layout.PackedSigChainRowsPerGroup <= 0 {
		return false
	}
	for block := 0; block < replayBlocks; block++ {
		if rowLayoutPostSignRHat1Index(layout, block) < 0 ||
			rowLayoutPostSignZHatIndex(layout, block) < 0 {
			return false
		}
	}
	return true
}

func ResolveSigShortnessMode(proof *Proof) string {
	if proof == nil || proof.SigShortness == nil {
		return SigShortnessModeNone
	}
	switch proof.SigShortness.Version {
	case sigShortnessProofVersionV18:
		return SigShortnessModeReplayCompactV18
	default:
		return fmt.Sprintf("sig_shortness_v%d_unsupported", proof.SigShortness.Version)
	}
}

func sigShortnessV18EnabledForOpts(opts SimOpts) bool {
	resolved := opts
	resolved.applyDefaults()
	if normalizeShowingPreset(resolved.ShowingPreset) != ShowingPresetInlineTargetReplayCompactResearch {
		return false
	}
	if normalizeShowingReplayMode(resolved.ShowingReplayMode) != ShowingReplayModeFull || !resolved.AggregateR0Replay {
		return false
	}
	if resolved.PackedSigChainGroupSize != aggregateInlineTargetReplayCompactGroupSize {
		return false
	}
	if sigLookupShadowR121L2EnabledForOpts(resolved) {
		return resolved.SigShortnessRadix == sigLookupShadowR121L2Radix &&
			resolved.SigShortnessL == sigLookupShadowR121L2Digits &&
			resolved.NCols == aggregateInlineTargetReplayCompactNCols
	}
	if sigShortnessRawOverrideActive(resolved) {
		return resolved.RingDegree == 512 &&
			resolved.NCols == aggregateInlineTargetReplayCompactNCols
	}
	return ResolveSignatureShortnessProfileLabelForOpts(resolved) == aggregateInlineTargetReplayCompactSigProfile &&
		resolved.NCols == aggregateInlineTargetReplayCompactNCols
}

func sigShortnessInlinedTargetHidingEnabledForOpts(opts SimOpts) bool {
	return sigShortnessV18EnabledForOpts(opts)
}

type PRFCompanionMode string

const (
	PRFCompanionModeDirectFull PRFCompanionMode = "direct_full"
)

const (
	SigLookupShadowR121L2None  = ""
	SigLookupShadowR121L2Free  = "free"
	SigLookupShadowR121L2SameQ = "same_q"
)

const (
	sigLookupShadowR121L2Radix        = 121
	sigLookupShadowR121L2Digits       = 2
	sigLookupShadowR121L2TableLo      = -60
	sigLookupShadowR121L2TableHi      = 60
	sigLookupShadowR121L2TableSize    = 121
	sigLookupShadowR121L2TargetBudget = 35500
)

func normalizePRFCompanionMode(mode PRFCompanionMode) PRFCompanionMode {
	switch mode {
	case "", PRFCompanionModeDirectFull:
		return PRFCompanionModeDirectFull
	default:
		return mode
	}
}

func NormalizeSigLookupShadowR121L2Mode(mode string) string {
	switch strings.TrimSpace(mode) {
	case SigLookupShadowR121L2None:
		return SigLookupShadowR121L2None
	case SigLookupShadowR121L2Free:
		return SigLookupShadowR121L2Free
	case SigLookupShadowR121L2SameQ:
		return SigLookupShadowR121L2SameQ
	default:
		return SigLookupShadowR121L2None
	}
}

func sigLookupShadowR121L2EnabledForOpts(opts SimOpts) bool {
	return NormalizeSigLookupShadowR121L2Mode(opts.UnsafeSigLookupShadowR121L2) != SigLookupShadowR121L2None
}

func sigLookupShadowR121L2FreeForOpts(opts SimOpts) bool {
	return NormalizeSigLookupShadowR121L2Mode(opts.UnsafeSigLookupShadowR121L2) == SigLookupShadowR121L2Free
}

func normalizeShowingPreset(preset string) string {
	switch strings.TrimSpace(preset) {
	case ShowingPresetInlineTargetReplayCompactResearch:
		return ShowingPresetInlineTargetReplayCompactResearch
	default:
		return ""
	}
}

func ResolveShowingPresetLabelForOpts(opts SimOpts) string {
	if !opts.Credential || resolveCoeffNativeSigModel(opts) != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return ""
	}
	if sigShortnessRawOverrideActive(opts) {
		return ""
	}
	resolved := opts
	resolved.applyDefaults()
	requested := normalizeShowingPreset(opts.ShowingPreset)
	if requested == ShowingPresetInlineTargetReplayCompactResearch && showingOptsMatchInlineTargetReplayCompactShape(resolved) {
		return requested
	}
	return ""
}

func showingOptsMatchInlineTargetReplayCompactShape(resolved SimOpts) bool {
	groupSize := resolved.PackedSigChainGroupSize
	if groupSize <= 0 {
		groupSize = aggregateInlineTargetReplayCompactGroupSize
	}
	return normalizeShowingReplayMode(resolved.ShowingReplayMode) == ShowingReplayModeFull &&
		resolved.AggregateR0Replay &&
		resolved.NCols == aggregateInlineTargetReplayCompactNCols &&
		groupSize == aggregateInlineTargetReplayCompactGroupSize &&
		resolved.SigShortnessProfile == aggregateInlineTargetReplayCompactSigProfile
}

// SimOpts carries the proving and reporting knobs used by the retained
// issuance and showing flows.
type SimOpts struct {
	Rho      int
	EllPrime int
	Ell      int
	Eta      int
	NLeaves  int
	Theta    int
	// RingDegree selects the ring dimension for opt-in research runs. Zero
	// keeps the repository default from internal/source_data/Parameters.json.
	RingDegree int
	Kappa      [4]int
	// ROQueryCaps records the assumed Random Oracle query counts (Q0..Q4) used
	// for the theorem-level ROM soundness bound.
	ROQueryCaps       [5]int
	ROQueryCapsSet    bool `json:"-"`
	DECSCollisionBits int
	NCols             int
	PCSNCols          int
	LVCSNCols         int
	PostSignLVCSNCols int
	PostSignNLeaves   int
	PRFLVCSNCols      int
	PRFNLeaves        int
	DQOverride        int
	Lambda            int
	ChainW            int
	ChainL            int
	// SigShortnessL overrides the default signature shortness digit count.
	SigShortnessL int
	// SigShortnessRadix overrides the balanced signature shortness radix.
	SigShortnessRadix int
	// SigShortnessProfile selects the production shortness profile for the
	// literal-packed coeff-native showing path.
	SigShortnessProfile string
	// ShowingPreset selects a coherent showing-time transcript preset for the
	// retained credential flow.
	ShowingPreset string
	// ShowingReplayMode selects the active showing replay surface.
	ShowingReplayMode ShowingReplayMode
	// CoeffNativeSigModel selects the coeff-native post-sign model.
	CoeffNativeSigModel string
	CoeffPacking        bool
	// Only explicit public-domain mode is supported.
	DomainMode DomainMode
	// PRFGroupRounds controls grouped PRF checkpointing in showing mode.
	PRFGroupRounds int
	// PRFCompanionMode selects the live one-root PRF companion route.
	PRFCompanionMode PRFCompanionMode
	// PRFCheckpointSamples controls the number of transcript-selected checkpoint
	// audits in output-audit and direct-auth modes.
	PRFCheckpointSamples int
	// MuWitnessPackWidth compresses full-capacity showing-time mu carrier
	// blocks. Width 1 is the singleton carrier; width 2 packs matching columns
	// from adjacent logical mu blocks into one carrier value. Width 4 is an
	// internal high-degree experiment and is not selected by public presets.
	MuWitnessPackWidth int
	// EnablePackedPRFWitnessRows gates the experimental row-major PRF packing
	// path. The retained verifier model still uses the unpacked layout by
	// default.
	EnablePackedPRFWitnessRows bool
	// EnablePRFCompanion emits and verifies the Phase-2 authenticated packed
	// coordinate bridge for packed PRF witness rows.
	EnablePRFCompanion bool
	// AggregateR0Replay replaces per-component R0 replay hats with one
	// block-local B2*r0 aggregate row in full direct bb_tran showing proofs.
	AggregateR0Replay bool
	// PackedSigChainGroupSize is fixed by the selected optimized V18 profile.
	PackedSigChainGroupSize int
	// SigShortnessNCols is reserved for future single-root signature packing
	// research. The removed V12/V13 two-oracle paths are no longer live.
	SigShortnessNCols int
	// IntGenISISMSECompression selects the legacy IntGenISIS ternary carrier
	// compression level for showing-time M/s/e coefficient rows. Level 0 keeps
	// the uncompressed rows; bounded-range B>1 profiles reject level k>0.
	IntGenISISMSECompression int
	// IntGenISISReplayProjection selects the IntGenISIS showing replay
	// projection mode. Empty and "none" keep the explicit hat-row relation;
	// experimental source-linear modes are sound-gated by layout validation.
	IntGenISISReplayProjection string
	// UnsafeSigLookupShadowR121L2 enables an explicitly unsound measurement
	// mode for the R121/L2 fixed-table lookup idea. "free" omits interval
	// membership from Q; "same_q" keeps the degree-121 membership in Q.
	UnsafeSigLookupShadowR121L2 string
	// TranscriptCodec selects exact serialization codecs that do not change the
	// algebraic relation. Empty keeps the historical transcript encoding.
	TranscriptCodec string
	// TranscriptProtocolMode selects transcript-shape protocol changes. Empty
	// keeps the historical dense replay protocol.
	TranscriptProtocolMode string
	// TranscriptVersion selects the Fiat-Shamir/proof-message transcript shape.
	// Empty preserves the legacy implementation. The SmallWood 2025 version is
	// introduced incrementally and requires an explicit PACS Q payload.
	TranscriptVersion string
	// FixedTranscriptSize selects fixed-width DECS openings for stable maintained
	// proof-size reporting. It does not change the algebraic statement.
	FixedTranscriptSize bool
	PhaseRecorder       *PhaseRecorder                                                                               `json:"-"`
	Mutate              func(r *ring.Ring, omega []uint64, ell int, w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly) `json:"-"`
	Credential          bool
}

func defaultSimOpts() SimOpts {
	return SimOpts{
		Rho:                  7,
		EllPrime:             10,
		Ell:                  26,
		Eta:                  7,
		NLeaves:              0,
		Theta:                1,
		Kappa:                [4]int{0, 0, 0, 0},
		ROQueryCaps:          [5]int{1, 1, 1, 1, 1},
		DECSCollisionBits:    144,
		NCols:                8,
		PCSNCols:             0,
		LVCSNCols:            0,
		DQOverride:           0,
		Lambda:               256,
		ChainW:               4,
		ChainL:               0,
		SigShortnessL:        0,
		SigShortnessRadix:    0,
		SigShortnessProfile:  "",
		ShowingPreset:        "",
		ShowingReplayMode:    ShowingReplayModeReduced,
		CoeffPacking:         false,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       1,
		PRFCheckpointSamples: 8,
		MuWitnessPackWidth:   1,
	}
}

func (o *SimOpts) applyDefaults() {
	def := defaultSimOpts()
	if o.NLeaves < 0 {
		o.NLeaves = 0
	}
	if o.RingDegree < 0 {
		o.RingDegree = 0
	}
	if o.PostSignNLeaves < 0 {
		o.PostSignNLeaves = 0
	}
	if o.PRFNLeaves < 0 {
		o.PRFNLeaves = 0
	}
	if o.PCSNCols < 0 {
		o.PCSNCols = 0
	}
	if o.LVCSNCols < 0 {
		o.LVCSNCols = 0
	}
	if o.PostSignLVCSNCols < 0 {
		o.PostSignLVCSNCols = 0
	}
	if o.PRFLVCSNCols < 0 {
		o.PRFLVCSNCols = 0
	}
	if o.DQOverride < 0 {
		o.DQOverride = 0
	}
	if o.ChainL < 0 {
		o.ChainL = 0
	}
	if o.SigShortnessL < 0 {
		o.SigShortnessL = 0
	}
	if o.SigShortnessRadix < 0 {
		o.SigShortnessRadix = 0
	}
	if o.PackedSigChainGroupSize < 0 {
		o.PackedSigChainGroupSize = 0
	}
	if o.SigShortnessNCols < 0 {
		o.SigShortnessNCols = 0
	}
	if o.IntGenISISMSECompression < 0 {
		o.IntGenISISMSECompression = 0
	}
	o.IntGenISISReplayProjection = normalizeIntGenISISReplayProjection(o.IntGenISISReplayProjection)
	o.UnsafeSigLookupShadowR121L2 = NormalizeSigLookupShadowR121L2Mode(o.UnsafeSigLookupShadowR121L2)
	if sigLookupShadowR121L2EnabledForOpts(*o) {
		o.SigShortnessRadix = sigLookupShadowR121L2Radix
		o.SigShortnessL = sigLookupShadowR121L2Digits
	}
	if o.Credential && resolveCoeffNativeSigModel(*o) == CoeffNativeSigModelLiteralPackedAggregatedV3 {
		o.ShowingPreset = normalizeShowingPreset(o.ShowingPreset)
		if o.ShowingPreset == ShowingPresetInlineTargetReplayCompactResearch {
			o.ShowingReplayMode = ShowingReplayModeFull
			o.AggregateR0Replay = true
			if o.NCols <= 0 {
				o.NCols = aggregateInlineTargetReplayCompactNCols
			}
			if o.PackedSigChainGroupSize <= 0 {
				o.PackedSigChainGroupSize = aggregateInlineTargetReplayCompactGroupSize
			}
			if o.MuWitnessPackWidth <= 0 {
				o.MuWitnessPackWidth = 2
			}
			if !sigShortnessRawOverrideActive(*o) && o.SigShortnessProfile == "" {
				o.SigShortnessProfile = aggregateInlineTargetReplayCompactSigProfile
			}
			if o.Theta <= 0 {
				o.Theta = aggregateInlineTargetReplayCompactTheta
			}
			if o.Rho <= 0 {
				o.Rho = aggregateInlineTargetReplayCompactRho
			}
			if o.EllPrime <= 0 {
				o.EllPrime = aggregateInlineTargetReplayCompactEllPrime
			}
			if o.Ell <= 0 {
				o.Ell = aggregateInlineTargetReplayCompactEll
			}
			if o.Eta <= 0 {
				o.Eta = aggregateInlineTargetReplayCompactEta
			}
			if o.NLeaves <= 0 {
				o.NLeaves = aggregateInlineTargetReplayCompactNLeaves
			}
			if o.PostSignNLeaves <= 0 {
				o.PostSignNLeaves = aggregateInlineTargetReplayCompactNLeaves
			}
			if o.PRFNLeaves <= 0 {
				o.PRFNLeaves = aggregateInlineTargetReplayCompactNLeaves
			}
			if o.LVCSNCols <= 0 {
				o.LVCSNCols = aggregateInlineTargetReplayCompactLVCSNCols
			}
			if o.PostSignLVCSNCols <= 0 {
				o.PostSignLVCSNCols = aggregateInlineTargetReplayCompactLVCSNCols
			}
			if o.PRFLVCSNCols <= 0 {
				o.PRFLVCSNCols = aggregateInlineTargetReplayCompactLVCSNCols
			}
			if o.Kappa == [4]int{} {
				o.Kappa = aggregateInlineTargetReplayCompactKappa
			}
		}
	}
	if o.Rho <= 0 {
		o.Rho = def.Rho
	}
	if o.EllPrime <= 0 {
		o.EllPrime = def.EllPrime
	}
	if o.Ell <= 0 {
		o.Ell = def.Ell
	}
	if o.Eta <= 0 {
		o.Eta = def.Eta
	}
	if o.Theta <= 0 {
		o.Theta = def.Theta
	}
	for i := 0; i < len(o.Kappa); i++ {
		if o.Kappa[i] <= 0 {
			o.Kappa[i] = def.Kappa[i]
		}
	}
	for i := 0; i < len(o.ROQueryCaps); i++ {
		if o.ROQueryCapsSet {
			if o.ROQueryCaps[i] < 0 {
				o.ROQueryCaps[i] = 0
			}
		} else if o.ROQueryCaps[i] <= 0 {
			o.ROQueryCaps[i] = def.ROQueryCaps[i]
		}
	}
	if o.DECSCollisionBits <= 0 {
		o.DECSCollisionBits = def.DECSCollisionBits
	}
	if o.NCols <= 0 {
		o.NCols = def.NCols
	}
	if o.Lambda <= 0 {
		o.Lambda = def.Lambda
	}
	if o.ChainW <= 0 {
		o.ChainW = def.ChainW
	}
	o.ShowingPreset = normalizeShowingPreset(o.ShowingPreset)
	o.SigShortnessProfile = normalizeSigShortnessProfile(o.SigShortnessProfile)
	if o.PRFGroupRounds <= 0 {
		o.PRFGroupRounds = def.PRFGroupRounds
	}
	if o.PRFCheckpointSamples <= 0 {
		o.PRFCheckpointSamples = def.PRFCheckpointSamples
	}
	if o.MuWitnessPackWidth <= 0 {
		o.MuWitnessPackWidth = def.MuWitnessPackWidth
	}
	o.PRFCompanionMode = normalizePRFCompanionMode(o.PRFCompanionMode)
	o.ShowingReplayMode = normalizeShowingReplayMode(o.ShowingReplayMode)
	o.TranscriptProtocolMode = normalizeTranscriptProtocolMode(o.TranscriptProtocolMode)
	o.TranscriptVersion = normalizeTranscriptVersion(o.TranscriptVersion)
	if o.DomainMode != DomainModeExplicit {
		o.DomainMode = DomainModeExplicit
	}
}

// ResolveSimOptsDefaults returns a copy of opts with the internal default and
// preset resolution applied. This is intended for reporting/CLI callers that
// need the resolved view without mutating the original struct in-place.
func ResolveSimOptsDefaults(opts SimOpts) SimOpts {
	opts.applyDefaults()
	return opts
}

// CoeffNativeSigLayout captures the coeff-native post-sign witness partition
// used by the retained showing layouts.
type CoeffNativeSigLayout struct {
	Enabled bool
	Model   string

	// Signature witness rows for the active coeff-native post-sign model.
	SigBase   int
	SigCount  int
	SigBlocks int
	SigUCount int
	// Literal packed metadata for packed-row coeff-native models.
	PackedSigBase       int
	PackedSigCount      int
	PackedSigBlocks     int
	PackedSigComponents int
	PackedSigBlockWidth int
	// ScalarBundle rows pack independent scalar witness values into the Ω slots
	// of one or more committed rows. Legacy layouts used these for U/X0/X1.
	ScalarBundleBase  int
	ScalarBundleCount int
	USlots            []PRFSlot
	X0Slots           []PRFSlot
	X1Slot            PRFSlot
	// Replay-facing projection rows for the legacy compressed non-sign scalar path.
	PostSignMsgSumRow int
	PostSignRndSumRow int
	PostSignX1Row     int
	// Signed-digit certificate rows for the legacy compressed non-sign scalar path.
	UScalarCertBase         int
	UScalarCertCount        int
	X0ScalarCertBase        int
	X0ScalarCertCount       int
	X1ScalarCertBase        int
	X1ScalarCertCount       int
	NonSigCertRowsPerScalar int
	NonSigCertRadix         int
	NonSigCertDigits        int
	// Signature component metadata for scalar signature rows.
	SigComponentCount int
	SigCoeffCount     int
	OutputBlocks      int
	OutputBlockWidth  int

	// Retained row-count metadata used by the current witness geometry and
	// replay-accounting helpers.
	W1SigBase      int
	W1SigCount     int
	W1MsgBase      int
	W1MsgCount     int
	W1MsgRowsPer   int
	W1RndBase      int
	W1RndCount     int
	W1RndRowsPer   int
	W2Base         int
	W2Count        int
	W2RowsPerBlock int
	W3RowsPerBlock int
}

type RowLayout struct {
	RingDegree int
	SigCount   int
	MsgCount   int
	RndCount   int
	// IntGenISISPreSign records the committed-message pre-sign witness row
	// inventory. The rows are raw ring-polynomial witnesses in the order
	// M || s || e; no legacy r0/r1/challenge rows are present.
	IntGenISISPreSign *IntGenISISPreSignRowLayout
	// IntGenISISShowing records the committed-message showing witness inventory.
	// The rows are raw ring-polynomial witnesses before PRF auxiliary rows.
	IntGenISISShowing *IntGenISISShowingRowLayout
	// Explicit base indices for post-sign witness rows.
	// When false, the standard issuance row order is used.
	HasExplicitBaseIdx     bool
	X0Len                  int
	IdxMu                  int
	IdxM1                  int
	IdxM2                  int
	IdxRU0                 int
	IdxRU1                 int
	IdxR                   int
	IdxR0                  int
	IdxR1                  int
	IdxK0                  int
	IdxK1                  int
	IdxZ                   int
	IdxMSigmaR1            int
	IdxR0R1                int
	IdxMSigmaR1Alias       int
	IdxR0R1Alias           int
	IdxCarrierM            int
	CarrierMuBlockRows     []int
	AliasMuBlockRows       []int
	MuCarrierPackWidth     int
	MuVirtualBlockCount    int
	IdxCarrierPreRU        int
	IdxCarrierRU1          int
	IdxCarrierPreR         int
	IdxCarrierCtr          int
	IdxCarrierR1           int
	IdxCarrierK            int
	IdxCarrierK1           int
	CarrierRU0Rows         []int
	CarrierR0Rows          []int
	CarrierK0Rows          []int
	AliasRU0Rows           []int
	AliasR0Rows            []int
	AliasK0Rows            []int
	IdxTSource             int
	IdxSigHatBase          int
	SigHatExtraBase        int
	IdxTHatBase            int
	ReplayTHatRows         []int
	ReplayTHatCount        int
	ReplayBlockCount       int
	IdxMHatSigma           int
	ReplayMHatSigmaRows    []int
	IdxMHat1               int
	IdxMHat2               int
	IdxRHat0               int
	ReplayRHat0Rows        []int
	IdxR0B2Hat             int
	ReplayR0B2HatRows      []int
	IdxTargetMR0Hat        int
	ReplayTargetMR0HatRows []int
	IdxRHat1               int
	ReplayRHat1Rows        []int
	IdxZHat                int
	ReplayZHatRows         []int
	IdxMSigmaR1Hat         int
	ReplayMSigmaR1HatRows  []int
	IdxR0R1Hat             int
	ReplayR0R1HatRows      []int
	ChainBase              int
	ChainRowsPerSig        int
	PackedSigChainBase     int
	// Packed signature shortness metadata for modes that use one shortness row
	// per digit lane and coefficient group instead of per coefficient.
	PackedSigChainGroupCount       int
	PackedSigChainGroupSize        int
	PackedSigChainRowsPerGroup     int
	PackedSigChainBlockWidth       int
	PackedSigChainEffectiveBlocks  int
	PackedSigChainSourceBlockWidth int
	PairLookupExtractBase          int
	PairLookupExtractGroupCount    int
	PairLookupExtractRowsPerLane   int
	PairLookupRangeLoWidth         int
	PairLookupRangeHiWidth         int
	PairLookupBase                 int
	CoeffLookupBase                int
	CoeffLookupRowCount            int
	CoeffLookupComponents          int
	CoeffLookupBlocks              int
	CoeffLookupBlockWidth          int
	CoeffLookupBeta                int
	CoeffLookupTableSize           int
	SigSignedChain                 bool
	SigShortnessV9RandBase         int
	SigShortnessV9RandCount        int
	SigShortnessV9RandBound        int
	MsgChainBase                   int
	RndChainBase                   int
	X1ChainBase                    int
	MsgRangeBase                   int
	RndRangeBase                   int
	X1RangeBase                    int
	NonSigBoundRowsPer             int
	// Experimental v3 logical-slice accounting for the single-root coeff-native
	// showing path.
	SigPrimaryLimbRows            int
	ScalarBundleRows              int
	SigBoundSliceRows             int
	PostSignScalarProjectionRows  int
	PostSignScalarCertificateRows int
	PRFScalarBundleRows           int
	PRFGroupedNonlinearRows       int
	// Signature packing metadata for showing.
	SigBlocks    int
	SigUCount    int
	SigCoeffBase int
	// Non-signature coefficient-bound metadata for showing.
	NonSigBlocks    int
	MsgCompCount    int
	MsgExtraNTTBase int
	MsgCoeffBase    int
	RndCompCount    int
	RndExtraNTTBase int
	RndCoeffBase    int
	X1CompCount     int
	X1ExtraNTTBase  int
	X1CoeffBase     int

	// Coeff-native showing signature path.
	CoeffNativeSig CoeffNativeSigLayout
}

// KPolySnapshot serialises a K[X] polynomial by degree and limb coefficients.
type KPolySnapshot struct {
	Degree int
	Limbs  [][]uint64
}

// Proof captures the transcript material emitted by the prover following the
// nine-round SmallWood–ARK flow.
type Proof struct {
	Root                   [16]byte
	RootHash               []byte `json:"root_hash,omitempty"`
	RingDegree             int
	HashRelation           string
	TranscriptVersion      string
	TranscriptProtocolMode string
	FixedTranscriptSize    bool
	Salt                   []byte
	Ctr                    [4]uint64
	Digests                [4][]byte
	LabelsDigest           []byte
	Lambda                 int
	Kappa                  [4]int
	Theta                  int
	Chi                    []uint64
	Zeta                   []uint64
	Tail                   []int
	VTargets               [][]uint64
	VTargetsBits           []byte
	VTargetsRows           int
	VTargetsCols           int
	VTargetsBitWidth       uint8
	VTargetsWidthCodec     bool `json:"-"`
	SmallField2025         *SmallField2025LVCSProof
	BarSets                [][]uint64
	BarSetsBits            []byte
	BarSetsRows            int
	BarSetsCols            int
	BarSetsBitWidth        uint8
	CoeffMatrix            [][]uint64
	KPoint                 [][]uint64
	GammaPrimeK            [][][]KScalar
	GammaAggK              [][]KScalar
	GammaPrime             [][][]uint64
	GammaAgg               [][]uint64
	R                      [][]uint64
	// Q material. Legacy proofs carry a redundant Q DECS commitment/opening here;
	// smallwood_2025_1085_v1 proofs carry the paper-shaped QPayload only.
	QRoot            [16]byte
	QRootHash        []byte `json:"q_root_hash,omitempty"`
	QR               [][]uint64
	QRBits           []byte
	QRRows           int
	QRCols           int
	QRBitWidth       uint8
	QPayload         [][]uint64
	QPayloadBits     []byte
	QPayloadRows     int
	QPayloadCols     int
	QPayloadBitWidth uint8
	QDegreeBound     int
	QOpening         *decs.DECSOpening
	// These coefficient snapshots are retained so verifier-side constraint
	// replay can reconstruct explicit-domain residual families after the proof
	// crosses a JSON boundary.
	QCoeffDebug    [][]uint64 `json:"q_coeff_debug,omitempty"`
	MaskCoeffDebug [][]uint64 `json:"mask_coeff_debug,omitempty"`
	FparCoeffDebug [][]uint64 `json:"fpar_coeff_debug,omitempty"`
	FaggCoeffDebug [][]uint64 `json:"fagg_coeff_debug,omitempty"`
	MKData         []KPolySnapshot
	QKData         []KPolySnapshot
	RowLayout      RowLayout
	MaskRowOffset  int
	MaskRowCount   int
	// RowDegreeBound records the DECS/LVCS degree used for the committed row
	// oracle. This can exceed the Q/mask degree bound when explicit-domain row
	// interpolation over LVCSNCols imposes a larger floor.
	RowDegreeBound  int
	MaskDegreeBound int
	TailTranscript  []byte
	Gamma           [][]uint64
	GammaK          [][]KScalar
	RoundCounters   [4]uint64

	PCSGeometry   PCSGeometry
	PCSOpening    *decs.DECSOpening
	RowOpening    *decs.DECSOpening
	NColsUsed     int
	PCSNColsUsed  int
	LVCSNColsUsed int
	DomainMode    DomainMode
	NLeavesUsed   int
	EvalPoints    []uint64 // |E'|
	PvalsEvalBits []byte   // packed field-width matrix: |E'| x RowCount
	MvalsEvalBits []byte   // packed field-width matrix: |E'| x Eta
	MaskEvalBits  []byte   // packed field-width matrix: |E'| x rho (PACS masks)
	PvalsEvalRows int
	PvalsEvalCols int
	MvalsEvalRows int
	MvalsEvalCols int
	MaskEvalRows  int
	MaskEvalCols  int
	// Optional PRF layout metadata for showing proofs.
	PRFLayout *PRFLayout
	// Optional Phase-2 PRF companion proof metadata.
	PRFCompanion *PRFCompanionProof
	// Optional same-root source-product bridge for theorem-clean full replay.
	SourceProductBridge *SourceProductBridge
	// Optional signature shortness proof for retained packed-signature showing.
	SigShortness *SigShortnessProof
}

// SigShortnessProof carries the versioned signature shortness argument used by
// the retained packed-signature showing path.
type SigShortnessProof struct {
	Version      int
	SupportSlots []int
	Opening      *decs.DECSOpening
	V18          *SigShortnessProofV18
}

type SigShortnessProofV18 struct {
	Mode                uint8
	RingDegree          int
	Radix               int
	Digits              int
	GroupSize           int
	BlockWidth          int
	LayoutDigest        []byte
	ReplayCompactDigest []byte
	PRFCompactDigest    []byte
}

type IntervalLookupProof struct {
	Version       int
	Backend       string
	Status        string
	FailureReason string
}

type fsRoundResult struct {
	Seed []byte
	RNG  *fsRNG
}

func fsRound(fs *FS, proof *Proof, round int, label string, material ...[]byte) fsRoundResult {
	if fs == nil {
		panic("fsRound: nil FS state")
	}
	if proof == nil {
		panic("fsRound: nil proof")
	}
	h, ctr, seed := fs.GrindAndDerive(round, material, func(h []byte) []byte { return h })
	proof.Ctr[round] = ctr
	proof.RoundCounters[round] = ctr
	proof.Digests[round] = append([]byte(nil), h...)
	return fsRoundResult{
		Seed: append([]byte(nil), seed...),
		RNG:  newFSRNG(label, seed),
	}
}

func (p *Proof) setBarSets(mat [][]uint64) {
	if len(mat) == 0 {
		p.BarSets = nil
		p.BarSetsBits = nil
		p.BarSetsRows = 0
		p.BarSetsCols = 0
		p.BarSetsBitWidth = 0
		return
	}
	bits, rows, cols, width := decs.PackUintMatrix(mat)
	p.BarSetsBits = bits
	p.BarSetsRows = rows
	p.BarSetsCols = cols
	p.BarSetsBitWidth = uint8(width)
	p.BarSets = nil
}

func (p *Proof) setQR(mat [][]uint64) {
	if len(mat) == 0 {
		p.QR = nil
		p.QRBits = nil
		p.QRRows = 0
		p.QRCols = 0
		p.QRBitWidth = 0
		return
	}
	bits, rows, cols, width := decs.PackUintMatrix(mat)
	p.QRBits = bits
	p.QRRows = rows
	p.QRCols = cols
	p.QRBitWidth = uint8(width)
	p.QR = copyMatrix(mat)
}

func (p *Proof) ensureQRPacked() {
	if len(p.QRBits) == 0 && len(p.QR) > 0 {
		p.setQR(p.QR)
	}
}

func (p *Proof) QRMatrix() [][]uint64 {
	if len(p.QR) > 0 {
		return p.QR
	}
	if len(p.QRBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := decs.UnpackUintMatrix(p.QRBits)
	if err != nil {
		return nil
	}
	p.QR = mat
	p.QRRows = rows
	p.QRCols = cols
	p.QRBitWidth = uint8(width)
	return mat
}

func (p *Proof) QRBytes() []byte {
	p.ensureQRPacked()
	return p.QRBits
}

func (p *Proof) setQPayload(mat [][]uint64) {
	if len(mat) == 0 {
		p.QPayload = nil
		p.QPayloadBits = nil
		p.QPayloadRows = 0
		p.QPayloadCols = 0
		p.QPayloadBitWidth = 0
		return
	}
	bits, rows, cols, width := decs.PackUintMatrix(mat)
	p.QPayloadBits = bits
	p.QPayloadRows = rows
	p.QPayloadCols = cols
	p.QPayloadBitWidth = uint8(width)
	p.QPayload = copyMatrix(mat)
}

func (p *Proof) ensureQPayloadPacked() {
	if len(p.QPayloadBits) == 0 && len(p.QPayload) > 0 {
		p.setQPayload(p.QPayload)
	}
}

func (p *Proof) QPayloadMatrix() [][]uint64 {
	if len(p.QPayload) > 0 {
		return p.QPayload
	}
	if len(p.QPayloadBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := decs.UnpackUintMatrix(p.QPayloadBits)
	if err != nil {
		return nil
	}
	p.QPayload = mat
	p.QPayloadRows = rows
	p.QPayloadCols = cols
	p.QPayloadBitWidth = uint8(width)
	return mat
}

func (p *Proof) QPayloadBytes() []byte {
	p.ensureQPayloadPacked()
	return p.QPayloadBits
}

func (p *Proof) ensureBarSetsPacked() {
	if len(p.BarSetsBits) == 0 && len(p.BarSets) > 0 {
		p.setBarSets(p.BarSets)
	}
}

func (p *Proof) BarSetsMatrix() [][]uint64 {
	if len(p.BarSets) > 0 {
		return p.BarSets
	}
	if len(p.BarSetsBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := decs.UnpackUintMatrix(p.BarSetsBits)
	if err != nil {
		return nil
	}
	p.BarSets = mat
	p.BarSetsRows = rows
	p.BarSetsCols = cols
	p.BarSetsBitWidth = uint8(width)
	return mat
}

// SoundnessBudget captures the four Eq. (8) error components together with the
// theorem-level ROM aggregation from Theorem 9 and the Eq. (10) size counters.
type SoundnessBudget struct {
	Eps                 [4]float64
	RawBits             [4]float64
	Bits                [4]float64
	Clamped             [4]bool
	Grinding            [4]float64
	GrindingBits        [4]float64
	TheoremTerms        [4]float64
	TheoremBits         [4]float64
	AlgebraicTerms      [4]float64
	AlgebraicBits       [4]float64
	AlgebraicTotal      float64
	AlgebraicTotalBits  float64
	Eq8Total            float64
	Eq8TotalBits        float64
	Collision           float64
	CollisionBits       float64
	Total               float64
	TotalBits           float64
	OneProofTotal       float64
	OneProofTotalBits   float64
	DQ                  int
	DDECS               int
	WitnessSupportCols  int
	CommittedCols       int
	FSLambdaBits        int
	DECSHashBits        int
	DECSTapeBits        int
	EffectiveLambdaBits int
	CollisionSpaceBits  int
	QueryCaps           [5]int
	NRows               int
	M                   int
}

func maxDegreeFromCoeffs(poly []uint64) int {
	for i := len(poly) - 1; i >= 0; i-- {
		if poly[i] != 0 {
			return i
		}
	}
	return -1
}

// computeDQFromConstraintDegrees implements paper Eq.(3):
//
//	dQ = max( d·(ℓ+s−1)+s−1, d′·(ℓ+s−1) )
//
// where d and d′ are algebraic degrees of the parallel/aggregated constraint
// polynomials in the witness variables, s=|Ω|, and ℓ is the number of blinding
// points per committed row polynomial (so deg(P_i) ≤ ℓ+s−1).
func computeDQFromConstraintDegrees(d, dPrime, s, ell int) int {
	if s <= 0 {
		s = 1
	}
	if ell <= 0 {
		ell = 1
	}
	span := ell + s - 1
	c1 := d*span + (s - 1)
	c2 := dPrime * span
	if c1 >= c2 {
		return c1
	}
	return c2
}

func computeVTargets(mod uint64, rows [][]uint64, C [][]uint64) [][]uint64 {
	if len(rows) == 0 {
		return nil
	}
	ncols := len(rows[0])
	m := len(C)
	res := make([][]uint64, m)
	for k := 0; k < m; k++ {
		res[k] = make([]uint64, ncols)
		for i := 0; i < ncols; i++ {
			sum := uint64(0)
			for j := 0; j < len(rows); j++ {
				sum = lvcs.MulAddMod64(sum, C[k][j], rows[j][i], mod)
			}
			res[k][i] = sum
		}
	}
	return res
}

func copyMatrix(src [][]uint64) [][]uint64 {
	if src == nil {
		return nil
	}
	out := make([][]uint64, len(src))
	for i := range src {
		out[i] = append([]uint64(nil), src[i]...)
	}
	return out
}

func copyTensor3(src [][][]uint64) [][][]uint64 {
	if src == nil {
		return nil
	}
	out := make([][][]uint64, len(src))
	for i := range src {
		if src[i] == nil {
			continue
		}
		out[i] = make([][]uint64, len(src[i]))
		for j := range src[i] {
			out[i][j] = append([]uint64(nil), src[i][j]...)
		}
	}
	return out
}

func matrixEqual(a, b [][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

func tensor3Equal(a, b [][][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if len(a[i][j]) != len(b[i][j]) {
				return false
			}
			for k := range a[i][j] {
				if a[i][j][k] != b[i][j][k] {
					return false
				}
			}
		}
	}
	return true
}

func kTensor3Equal(a, b [][][]KScalar) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if len(a[i][j]) != len(b[i][j]) {
				return false
			}
			for k := range a[i][j] {
				if len(a[i][j][k]) != len(b[i][j][k]) {
					return false
				}
				for t := range a[i][j][k] {
					if a[i][j][k][t] != b[i][j][k][t] {
						return false
					}
				}
			}
		}
	}
	return true
}

func copyKMatrix(src [][]KScalar) [][]KScalar {
	if src == nil {
		return nil
	}
	out := make([][]KScalar, len(src))
	for i := range src {
		if src[i] == nil {
			continue
		}
		row := make([]KScalar, len(src[i]))
		for j := range src[i] {
			if src[i][j] == nil {
				continue
			}
			scalar := make(KScalar, len(src[i][j]))
			copy(scalar, src[i][j])
			row[j] = scalar
		}
		out[i] = row
	}
	return out
}

func copyKTensor3(src [][][]KScalar) [][][]KScalar {
	if src == nil {
		return nil
	}
	out := make([][][]KScalar, len(src))
	for i := range src {
		if src[i] == nil {
			continue
		}
		out[i] = make([][]KScalar, len(src[i]))
		for j := range src[i] {
			poly := src[i][j]
			if poly == nil {
				continue
			}
			coeffs := make([]KScalar, len(poly))
			for k := range poly {
				if poly[k] == nil {
					continue
				}
				limbs := make(KScalar, len(poly[k]))
				copy(limbs, poly[k])
				coeffs[k] = limbs
			}
			out[i][j] = coeffs
		}
	}
	return out
}

func snapshotKPolys(polys []*KPoly) []KPolySnapshot {
	if polys == nil {
		return nil
	}
	out := make([]KPolySnapshot, len(polys))
	for i, kp := range polys {
		if kp == nil {
			continue
		}
		limbs := make([][]uint64, len(kp.Limbs))
		for j := range kp.Limbs {
			limbs[j] = append([]uint64(nil), kp.Limbs[j]...)
		}
		out[i] = KPolySnapshot{Degree: kp.Degree, Limbs: limbs}
	}
	return out
}

func restoreKPolys(data []KPolySnapshot) []*KPoly {
	if data == nil {
		return nil
	}
	out := make([]*KPoly, len(data))
	for i := range data {
		kp := &KPoly{Degree: data[i].Degree}
		if len(data[i].Limbs) > 0 {
			kp.Limbs = make([][]uint64, len(data[i].Limbs))
			for j := range data[i].Limbs {
				kp.Limbs[j] = append([]uint64(nil), data[i].Limbs[j]...)
			}
		}
		out[i] = kp
	}
	return out
}

func kMatrixFirstLimb(mat [][]KScalar) [][]uint64 {
	if mat == nil {
		return nil
	}
	out := make([][]uint64, len(mat))
	for i := range mat {
		row := make([]uint64, len(mat[i]))
		for j := range mat[i] {
			scalar := mat[i][j]
			if len(scalar) > 0 {
				row[j] = scalar[0]
			}
		}
		out[i] = row
	}
	return out
}

func trimCoeffsCopy(src []uint64, q uint64) []uint64 {
	if len(src) == 0 {
		return []uint64{0}
	}
	out := make([]uint64, len(src))
	for i := range src {
		out[i] = src[i] % q
	}
	last := len(out) - 1
	for last > 0 && out[last] == 0 {
		last--
	}
	return out[:last+1]
}

func encodeUint64Slice(vals []uint64) []byte {
	if len(vals) == 0 {
		return nil
	}
	out := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(out[i*8:], v)
	}
	return out
}

func cloneDECSOpening(op *decs.DECSOpening) *decs.DECSOpening {
	if op == nil {
		return nil
	}
	clone := &decs.DECSOpening{
		FormatVersion:  op.FormatVersion,
		PColsEncoded:   op.PColsEncoded,
		POmitCols:      append([]int(nil), op.POmitCols...),
		MFormatVersion: op.MFormatVersion,
		MColsEncoded:   op.MColsEncoded,
		MOmitCols:      append([]int(nil), op.MOmitCols...),
		MaskBase:       op.MaskBase,
		MaskCount:      op.MaskCount,
		Indices:        append([]int(nil), op.Indices...),
	}
	clone.TailCount = op.TailCount
	clone.IndexBitWidth = op.IndexBitWidth
	if len(op.IndexBits) > 0 {
		clone.IndexBits = append([]byte(nil), op.IndexBits...)
	}
	// copy metadata and packed buffers if present
	clone.R = op.R
	clone.Eta = op.Eta
	clone.NonceBytes = op.NonceBytes
	if len(op.NonceSeed) > 0 {
		clone.NonceSeed = append([]byte(nil), op.NonceSeed...)
	}
	if op.PvalsBits != nil {
		clone.PvalsBits = append([]byte(nil), op.PvalsBits...)
	}
	clone.PvalsBitWidth = op.PvalsBitWidth
	if len(op.PvalsColumnWidths) > 0 {
		clone.PvalsColumnWidths = append([]uint8(nil), op.PvalsColumnWidths...)
	}
	if op.MvalsBits != nil {
		clone.MvalsBits = append([]byte(nil), op.MvalsBits...)
	}
	clone.MvalsBitWidth = op.MvalsBitWidth
	if len(op.MvalsColumnWidths) > 0 {
		clone.MvalsColumnWidths = append([]uint8(nil), op.MvalsColumnWidths...)
	}
	if len(op.Pvals) > 0 {
		clone.Pvals = make([][]uint64, len(op.Pvals))
		for i := range op.Pvals {
			clone.Pvals[i] = append([]uint64(nil), op.Pvals[i]...)
		}
	}
	if len(op.Mvals) > 0 {
		clone.Mvals = make([][]uint64, len(op.Mvals))
		for i := range op.Mvals {
			clone.Mvals[i] = append([]uint64(nil), op.Mvals[i]...)
		}
	}
	if len(op.Nodes) > 0 {
		clone.Nodes = make([][]byte, len(op.Nodes))
		for i := range op.Nodes {
			clone.Nodes[i] = append([]byte(nil), op.Nodes[i]...)
		}
	}
	if len(op.PathIndex) > 0 {
		clone.PathIndex = make([][]int, len(op.PathIndex))
		for i := range op.PathIndex {
			clone.PathIndex[i] = append([]int(nil), op.PathIndex[i]...)
		}
	}
	if len(op.PathBits) > 0 {
		clone.PathBits = append([]byte(nil), op.PathBits...)
	}
	clone.PathBitWidth = op.PathBitWidth
	clone.PathDepth = op.PathDepth
	if len(op.Nonces) > 0 {
		clone.Nonces = make([][]byte, len(op.Nonces))
		for i := range op.Nonces {
			clone.Nonces[i] = append([]byte(nil), op.Nonces[i]...)
		}
	}
	return clone
}

func maybeCompressRowOpeningPvals(open *decs.DECSOpening, coeffMatrix [][]uint64, mod uint64) {
	if open == nil || open.R <= 0 || len(open.Pvals) == 0 || len(coeffMatrix) == 0 {
		return
	}
	omitCols, ok := compressionPivotCols(coeffMatrix, open.R, mod)
	if !ok || len(omitCols) == 0 || len(omitCols) >= open.R {
		return
	}
	keepCols := compressionKeepCols(open.R, omitCols)
	if len(keepCols) == 0 {
		return
	}
	compressed := make([][]uint64, len(open.Pvals))
	for i := range open.Pvals {
		if len(open.Pvals[i]) != open.R {
			return
		}
		row := make([]uint64, len(keepCols))
		for j, col := range keepCols {
			row[j] = open.Pvals[i][col] % mod
		}
		compressed[i] = row
	}
	open.FormatVersion = 1
	open.PColsEncoded = len(keepCols)
	open.POmitCols = append([]int(nil), omitCols...)
	open.Pvals = compressed
}

func omitAllRowOpeningMvals(open *decs.DECSOpening) {
	if open == nil {
		return
	}
	eta := open.Eta
	if eta <= 0 && len(open.Mvals) > 0 {
		eta = len(open.Mvals[0])
	}
	if eta <= 0 {
		return
	}
	omit := make([]int, eta)
	for i := range omit {
		omit[i] = i
	}
	open.MFormatVersion = 1
	open.MColsEncoded = 0
	open.MOmitCols = omit
	open.Mvals = nil
	open.MvalsBits = nil
	open.MvalsBitWidth = 0
}

func maybeCompressQOpeningPvals(open *decs.DECSOpening, gammaQ [][]uint64, mod uint64) (eqRows []int, compressed bool) {
	if open == nil || open.R <= 1 || len(open.Pvals) == 0 || len(gammaQ) == 0 {
		return nil, false
	}
	omitCols, eqRows, ok := qCompressionPOmitPlan(gammaQ, open.R, mod)
	if !ok || len(omitCols) == 0 || len(omitCols) >= open.R {
		return nil, false
	}
	keepCols := compressionKeepCols(open.R, omitCols)
	if len(keepCols) == 0 {
		return nil, false
	}
	encodedRows := make([][]uint64, len(open.Pvals))
	for i := range open.Pvals {
		if len(open.Pvals[i]) != open.R {
			return nil, false
		}
		row := make([]uint64, len(keepCols))
		for j, col := range keepCols {
			row[j] = open.Pvals[i][col] % mod
		}
		encodedRows[i] = row
	}
	open.FormatVersion = 1
	open.PColsEncoded = len(keepCols)
	open.POmitCols = append([]int(nil), omitCols...)
	open.Pvals = encodedRows
	return append([]int(nil), eqRows...), true
}

func maybeCompressQOpeningMvals(open *decs.DECSOpening, keepCols []int) {
	if open == nil || open.Eta <= 0 || len(open.Mvals) == 0 {
		return
	}
	keepSet := make(map[int]struct{}, len(keepCols))
	for _, col := range keepCols {
		if col < 0 || col >= open.Eta {
			return
		}
		keepSet[col] = struct{}{}
	}
	keep := make([]int, 0, len(keepSet))
	for col := 0; col < open.Eta; col++ {
		if _, ok := keepSet[col]; ok {
			keep = append(keep, col)
		}
	}
	omit := make([]int, 0, open.Eta-len(keep))
	for col := 0; col < open.Eta; col++ {
		if _, ok := keepSet[col]; !ok {
			omit = append(omit, col)
		}
	}
	if len(omit) == 0 {
		return
	}
	encoded := make([][]uint64, len(open.Mvals))
	for i := range encoded {
		if len(open.Mvals[i]) != open.Eta {
			return
		}
		row := make([]uint64, len(keep))
		for j, col := range keep {
			row[j] = open.Mvals[i][col]
		}
		encoded[i] = row
	}
	open.MFormatVersion = 1
	open.MColsEncoded = len(keep)
	open.MOmitCols = append([]int(nil), omit...)
	open.Mvals = encoded
}

func maybeCompressQOpening(open *decs.DECSOpening, gammaQ [][]uint64, mod uint64, compressM bool) {
	eqRows, pCompressed := maybeCompressQOpeningPvals(open, gammaQ, mod)
	if compressM && pCompressed {
		maybeCompressQOpeningMvals(open, eqRows)
	}
}

func qCompressionPOmitPlan(gammaQ [][]uint64, rho int, mod uint64) (omitCols []int, eqRows []int, ok bool) {
	if rho <= 1 || len(gammaQ) == 0 {
		return nil, nil, false
	}
	maxOmit := rho - 1 // keep at least one encoded P column
	if maxOmit > len(gammaQ) {
		maxOmit = len(gammaQ)
	}
	for target := maxOmit; target >= 1; target-- {
		sub := make([][]uint64, target)
		eq := make([]int, target)
		for i := 0; i < target; i++ {
			if len(gammaQ[i]) < rho {
				return nil, nil, false
			}
			sub[i] = append([]uint64(nil), gammaQ[i][:rho]...)
			eq[i] = i
		}
		pivots, fullRank := compressionPivotCols(sub, rho, mod)
		if !fullRank || len(pivots) != target {
			continue
		}
		return pivots, eq, true
	}
	return nil, nil, false
}

func compressionKeepCols(total int, omit []int) []int {
	if total <= 0 {
		return nil
	}
	omitSet := make(map[int]struct{}, len(omit))
	for _, col := range omit {
		if col >= 0 && col < total {
			omitSet[col] = struct{}{}
		}
	}
	out := make([]int, 0, total-len(omitSet))
	for col := 0; col < total; col++ {
		if _, drop := omitSet[col]; drop {
			continue
		}
		out = append(out, col)
	}
	return out
}

func compressionPivotCols(coeff [][]uint64, colCount int, mod uint64) ([]int, bool) {
	rows := len(coeff)
	if rows == 0 || colCount <= 0 {
		return nil, false
	}
	a := make([][]uint64, rows)
	for i := 0; i < rows; i++ {
		if len(coeff[i]) < colCount {
			return nil, false
		}
		a[i] = make([]uint64, colCount)
		for j := 0; j < colCount; j++ {
			a[i][j] = coeff[i][j] % mod
		}
	}
	pivots := make([]int, 0, rows)
	row := 0
	for col := 0; col < colCount && row < rows; col++ {
		pivot := -1
		for r := row; r < rows; r++ {
			if a[r][col]%mod != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			continue
		}
		if pivot != row {
			a[row], a[pivot] = a[pivot], a[row]
		}
		invPivot := ring.ModExp(a[row][col]%mod, mod-2, mod)
		for c := col; c < colCount; c++ {
			a[row][c] = lvcs.MulMod64(a[row][c], invPivot, mod)
		}
		for r := row + 1; r < rows; r++ {
			factor := a[r][col] % mod
			if factor == 0 {
				continue
			}
			for c := col; c < colCount; c++ {
				term := lvcs.MulMod64(factor, a[row][c], mod)
				a[r][c] = compressionSubMod(a[r][c], term, mod)
			}
		}
		pivots = append(pivots, col)
		row++
	}
	return pivots, row == rows
}

func compressionSubMod(a, b, mod uint64) uint64 {
	if a >= mod {
		a %= mod
	}
	if b >= mod {
		b %= mod
	}
	if a >= b {
		return a - b
	}
	return a + mod - b
}

func bytesFromUint64Matrix(mat [][]uint64) []byte {
	return bytesU64Mat(mat)
}

// unpackUint64Matrix reconstructs a matrix from a flat little-endian byte slice.
// rows/cols must be provided; returns nil if lengths are inconsistent.
func unpackUint64Matrix(data []byte, rows, cols int) [][]uint64 {
	if rows <= 0 || cols <= 0 {
		return nil
	}
	need := rows * cols * 8
	if len(data) != need {
		return nil
	}
	out := make([][]uint64, rows)
	for r := 0; r < rows; r++ {
		row := make([]uint64, cols)
		for c := 0; c < cols; c++ {
			row[c] = binary.LittleEndian.Uint64(data[(r*cols+c)*8:])
		}
		out[r] = row
	}
	return out
}

func sampleDistinctFieldElemsAvoid(count int, q uint64, rng *fsRNG, forbid []uint64) []uint64 {
	res := make([]uint64, 0, count)
	seen := make(map[uint64]struct{}, count+len(forbid))
	for _, w := range forbid {
		seen[w%q] = struct{}{}
	}
	for len(res) < count {
		candidate := rng.nextU64() % q
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		res = append(res, candidate)
	}
	return res
}

func sampleDistinctIndices(start, length, count int, rng *fsRNG) []int {
	if count > length {
		panic("sampleDistinctIndices: count exceeds range")
	}
	res := make([]int, 0, count)
	seen := make(map[int]struct{}, count)
	for len(res) < count {
		candidate := int(rng.nextU64()%uint64(length)) + start
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		res = append(res, candidate)
	}
	return res
}

func ceilDiv(a, b int) int {
	if b == 0 {
		return 0
	}
	return (a + b - 1) / b
}

func logComb2(n float64, k int) float64 {
	if k < 0 || n <= 0 {
		return math.Inf(-1)
	}
	if float64(k) > n {
		return math.Inf(-1)
	}
	if k == 0 || n == 0 {
		return 0
	}
	// symmetry: C(n,k) == C(n,n-k)
	if float64(k) > n/2 {
		k = int(n) - k
	}
	if k <= 32 {
		var sum float64
		nf := n
		for i := 0; i < k; i++ {
			sum += math.Log2(nf - float64(i))
			sum -= math.Log2(float64(i + 1))
		}
		return sum
	}
	nPlus, _ := math.Lgamma(n + 1)
	kPlus, _ := math.Lgamma(float64(k) + 1)
	nMinusKPlus, _ := math.Lgamma(n - float64(k) + 1)
	return (nPlus - kPlus - nMinusKPlus) / math.Ln2
}

func clampBitsToProbability(rawBits float64) (float64, float64) {
	bits := rawBits
	if math.IsInf(bits, -1) || bits < 0 {
		bits = 0
	}
	if math.IsInf(bits, 1) {
		return bits, 0
	}
	return bits, math.Pow(2, -bits)
}

func theoremTerm(queryCap int, eps float64, kappa int) (float64, float64) {
	if queryCap <= 0 || eps <= 0 {
		return 0, math.Inf(1)
	}
	term := float64(queryCap) * eps * math.Pow(2, -float64(kappa))
	if term <= 0 {
		return 0, math.Inf(1)
	}
	if term >= 1 {
		return 1, 0
	}
	return term, -math.Log2(term)
}

func computeSoundnessBudget(
	o SimOpts,
	q uint64,
	fieldSize float64,
	collisionSpaceBits int,
	decsHashBits int,
	decsTapeBits int,
	dQ int,
	sWitness int,
	ncolsLVCS int,
	ell int,
	ellPrime int,
	eta int,
	nLeaves int,
	witnessRows int,
) SoundnessBudget {
	o.applyDefaults()
	sb := SoundnessBudget{DQ: dQ}
	if sWitness <= 0 {
		sWitness = 1
	}
	if ncolsLVCS <= 0 {
		ncolsLVCS = sWitness
	}
	if nLeaves <= 0 {
		nLeaves = sWitness
	}
	if collisionSpaceBits <= 0 {
		collisionSpaceBits = fsCollisionSpaceBits(o.Lambda, 0)
	}
	if decsHashBits <= 0 {
		decsHashBits = decs.DefaultHashBytes * 8
	}
	if decsTapeBits <= 0 {
		decsTapeBits = decs.DefaultHashBytes * 8
	}
	effectiveLambdaBits := o.Lambda
	if effectiveLambdaBits <= 0 {
		effectiveLambdaBits = defaultSimOpts().Lambda
	}
	if decsHashBits < effectiveLambdaBits {
		effectiveLambdaBits = decsHashBits
	}
	if decsTapeBits < effectiveLambdaBits {
		effectiveLambdaBits = decsTapeBits
	}
	if effectiveLambdaBits < collisionSpaceBits {
		collisionSpaceBits = effectiveLambdaBits
	}
	qf := float64(q)
	ddecs := ncolsLVCS + ell - 1
	sb.DDECS = ddecs
	sb.WitnessSupportCols = sWitness
	sb.CommittedCols = ncolsLVCS
	sb.FSLambdaBits = o.Lambda
	sb.DECSHashBits = decsHashBits
	sb.DECSTapeBits = decsTapeBits
	sb.EffectiveLambdaBits = effectiveLambdaBits
	sb.CollisionSpaceBits = collisionSpaceBits
	sb.QueryCaps = o.ROQueryCaps

	rawBits1 := float64(eta)*math.Log2(qf) - logComb2Stable(float64(nLeaves), ddecs+2)
	sb.RawBits[0] = rawBits1
	sb.Bits[0], sb.Eps[0] = clampBitsToProbability(rawBits1)
	sb.Clamped[0] = rawBits1 < 0

	rhoEff := o.Rho
	if rhoEff < 1 {
		rhoEff = 1
	}
	var rawBits2 float64
	if o.Theta > 1 {
		rawBits2 = float64(o.Theta*rhoEff) * math.Log2(qf)
	} else {
		rawBits2 = float64(rhoEff) * math.Log2(qf)
	}
	sb.RawBits[1] = rawBits2
	sb.Bits[1], sb.Eps[1] = clampBitsToProbability(rawBits2)
	sb.Clamped[1] = rawBits2 < 0

	if ellPrime < 1 {
		ellPrime = 1
	}
	if fieldSize <= 0 {
		fieldSize = qf
	}
	// The PACS opening term uses Theorem 7 over S = K \ Ω in the small-field
	// variant, so the denominator is |S| = q^θ - s with s = |Ω| = NCols on this
	// branch, not the ring degree.
	Ssize := fieldSize - float64(sWitness)
	if Ssize < 1 {
		Ssize = 1
	}
	var rawBits3 float64
	if dQ < ellPrime {
		rawBits3 = math.Inf(1)
	} else {
		rawBits3 = logComb2Stable(Ssize, ellPrime) - logComb2Stable(float64(dQ), ellPrime)
		if math.IsInf(rawBits3, -1) {
			rawBits3 = math.Inf(1)
		}
	}
	sb.RawBits[2] = rawBits3
	sb.Bits[2], sb.Eps[2] = clampBitsToProbability(rawBits3)
	sb.Clamped[2] = rawBits3 < 0

	logCombCols := logComb2Stable(float64(ncolsLVCS+ell-1), ell)
	logCombLeaves := logComb2Stable(float64(nLeaves), ell)
	rawBits4 := logCombLeaves - logCombCols
	sb.RawBits[3] = rawBits4
	sb.Bits[3], sb.Eps[3] = clampBitsToProbability(rawBits4)
	sb.Clamped[3] = rawBits4 < 0

	sb.Eq8Total = sb.Eps[0] + sb.Eps[1] + sb.Eps[2] + sb.Eps[3]
	if sb.Eq8Total <= 0 {
		sb.Eq8Total = math.SmallestNonzeroFloat64
	}
	if sb.Eq8Total > 1 {
		sb.Eq8Total = 1
	}
	sb.Eq8TotalBits = -math.Log2(sb.Eq8Total)

	for i := 0; i < 4; i++ {
		kappa := o.Kappa[i]
		sb.GrindingBits[i] = float64(kappa)
		sb.Grinding[i] = math.Pow(2, -float64(kappa))
		sb.TheoremTerms[i], sb.TheoremBits[i] = theoremTerm(o.ROQueryCaps[i+1], sb.Eps[i], kappa)
		sb.AlgebraicTerms[i] = sb.TheoremTerms[i]
		sb.AlgebraicBits[i] = sb.TheoremBits[i]
		sb.AlgebraicTotal += sb.AlgebraicTerms[i]
	}
	if sb.AlgebraicTotal <= 0 {
		sb.AlgebraicTotalBits = math.Inf(1)
	} else {
		if sb.AlgebraicTotal > 1 {
			sb.AlgebraicTotal = 1
		}
		sb.AlgebraicTotalBits = -math.Log2(sb.AlgebraicTotal)
	}

	querySquares := 0.0
	for _, cap := range o.ROQueryCaps {
		if cap > 0 {
			querySquares += float64(cap) * float64(cap)
		}
	}
	if querySquares > 0 {
		sb.Collision = querySquares * math.Pow(2, -float64(collisionSpaceBits))
		if sb.Collision > 1 {
			sb.Collision = 1
		}
		sb.CollisionBits = -math.Log2(sb.Collision)
	} else {
		sb.CollisionBits = math.Inf(1)
	}

	sb.Total = sb.Collision
	for _, term := range sb.TheoremTerms {
		sb.Total += term
	}
	if sb.Total <= 0 {
		sb.Total = math.SmallestNonzeroFloat64
	}
	if sb.Total > 1 {
		sb.Total = 1
	}
	sb.TotalBits = -math.Log2(sb.Total)
	sb.OneProofTotal = sb.Total
	sb.OneProofTotalBits = sb.TotalBits

	rowsBlock := ceilDiv(witnessRows, ncolsLVCS)
	sb.NRows = rowsBlock * (sWitness + o.Theta)
	if o.Theta > 1 {
		// smallfield_matrix_v1 commits:
		// - rowsBlock witness blocks of size (s + theta),
		// - rho masks, each chunked into floor(dQ/ncols)+1 coefficient blocks,
		// - ell' coefficient matrices of size rowsBlock*theta for K-point replay.
		maskChunks := dQ/ncolsLVCS + 1
		sb.NRows += maskChunks * o.Theta * rhoEff
		sb.M = rowsBlock * o.Theta * ellPrime
	} else {
		sb.M = rowsBlock * ellPrime
	}
	return sb
}

func sizeUint64Matrix(mat [][]uint64) int {
	sum := 0
	for _, row := range mat {
		sum += len(row) * 8
	}
	return sum
}

func sizePackedUintMatrix(mat [][]uint64) int {
	bits, _, _, _ := decs.PackUintMatrix(mat)
	return len(bits)
}

func varintSize(x int) int {
	if x < 0 {
		x = -x
	}
	ux := uint64(x)
	size := 1
	for ux >= 0x80 {
		size++
		ux >>= 7
	}
	return size
}

func sizeDECSOpening(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	sum := 0
	if open.FormatVersion != 0 {
		sum += 1
	}
	if open.PColsEncoded > 0 {
		sum += varintSize(open.PColsEncoded)
	}
	for _, col := range open.POmitCols {
		sum += varintSize(col)
	}
	if open.MFormatVersion != 0 {
		sum += 1
	}
	if open.MColsEncoded > 0 {
		sum += varintSize(open.MColsEncoded)
	}
	for _, col := range open.MOmitCols {
		sum += varintSize(col)
	}
	if open.MaskCount > 0 {
		sum += varintSize(open.MaskBase)
		sum += varintSize(open.MaskCount)
	}
	if len(open.IndexBits) > 0 && open.TailCount > 0 && len(open.Indices) == 0 {
		sum += len(open.IndexBits)
		if open.IndexBitWidth > 0 {
			sum += 1
		}
		sum += varintSize(open.TailCount)
	} else {
		for _, idx := range open.Indices {
			sum += varintSize(idx)
		}
	}
	if open.PvalsBits != nil {
		if open.PvalsBitWidth != 0 {
			sum += 1
		}
		sum += len(open.PvalsColumnWidths)
		sum += len(open.PvalsBits)
	} else {
		sum += sizeUint64Matrix(open.Pvals)
	}
	if open.MvalsBits != nil {
		if open.MvalsBitWidth != 0 {
			sum += 1
		}
		sum += len(open.MvalsColumnWidths)
		sum += len(open.MvalsBits)
	} else {
		sum += sizeUint64Matrix(open.Mvals)
	}
	// Nodes bytes (unique siblings)
	for _, node := range open.Nodes {
		sum += len(node)
	}
	// PathIndex encoding (either packed bits or explicit ints)
	if len(open.PathBits) > 0 && open.PathDepth > 0 && open.PathBitWidth > 0 && len(open.PathIndex) == 0 {
		sum += len(open.PathBits)
		sum += 1 // bit width
		sum += varintSize(open.PathDepth)
	} else if open.PathDepth > 0 && len(open.PathIndex) == 0 && len(open.PathBits) == 0 && len(open.Nodes) == open.EntryCount()*open.PathDepth {
		sum += varintSize(open.PathDepth)
	} else {
		for _, pi := range open.PathIndex {
			sum += len(pi) * 4
		}
	}
	if len(open.Nonces) > 0 {
		for _, nonce := range open.Nonces {
			sum += len(nonce)
		}
	} else if len(open.NonceSeed) > 0 {
		sum += len(open.NonceSeed)
	}
	if open.NonceBytes > 0 {
		sum += varintSize(open.NonceBytes)
	}
	return sum
}

// proofSizeBreakdown computes a per-component size accounting for the retained
// proof serialization.
func proofSizeBreakdown(proof *Proof) (map[string]int, int) {
	if proof == nil {
		return map[string]int{}, 0
	}
	proof.syncPCSCompat()
	proof.ensureQPayloadPacked()
	if !proofUsesPaperQPayloadOnly(proof) {
		proof.ensureQRPacked()
	}
	proof.ensureVTargetsPacked()
	proof.ensureBarSetsPacked()
	sizes := make(map[string]int)
	sizes["Salt"] = len(proof.Salt)
	sizes["RingDegree"] = varintSize(proof.RingDegree)
	sizes["Root"] = proofRootSerializedSize(proof)
	sizes["Ctr"] = len(proof.Ctr) * 8
	digSum := 0
	for _, d := range proof.Digests {
		digSum += len(d)
	}
	sizes["Digests"] = digSum
	sizes["EvalPoints"] = len(proof.EvalPoints) * 8
	sizes["PvalsEvalBits"] = len(proof.PvalsEvalBits)
	sizes["MvalsEvalBits"] = len(proof.MvalsEvalBits)
	sizes["MaskEvalBits"] = len(proof.MaskEvalBits)
	sizes["Chi"] = len(proof.Chi) * 8
	sizes["Zeta"] = len(proof.Zeta) * 8
	sizes["TailIndices"] = len(proof.Tail) * 4
	sizes["R"] = sizePackedUintMatrix(proof.R)
	sizes["QRoot"] = 0
	sizes["QR"] = 0
	if !proofUsesPaperQPayloadOnly(proof) {
		sizes["QRoot"] = proofQRootSerializedSize(proof)
		sizes["QR"] = len(proof.QRBits)
	}
	sizes["QPayload"] = len(proof.QPayloadBits)
	// C re-derived on verifier
	sizes["VTargets"] = len(proof.VTargetsBits)
	sizes["BarSets"] = len(proof.BarSetsBits)
	sizes["RowOpening"] = sizeDECSOpening(resolveProofPCSOpening(proof))
	sizes["QOpening"] = 0
	if !proofUsesPaperQPayloadOnly(proof) {
		sizes["QOpening"] = sizeDECSOpening(proof.QOpening)
	}
	sizes["PRFCompanion"] = sizePRFCompanionProof(proof.PRFCompanion)
	sizes["SourceProductBridge"] = sizeSourceProductBridge(proof.SourceProductBridge)
	sizes["SigShortness"] = sizeSigShortnessProof(proof.SigShortness)
	sizes["SmallField2025"] = sizeSmallField2025Proof(proof.SmallField2025)
	total := 0
	for _, v := range sizes {
		total += v
	}
	return sizes, total
}

func sizeSigShortnessProof(sig *SigShortnessProof) int {
	if sig == nil {
		return 0
	}
	if sig.Version == sigShortnessProofVersionV18 && sig.V18 != nil {
		size := 0
		if sig.V18.Mode != 0 {
			size++
		}
		size += varintSize(sig.V18.Radix)
		size += varintSize(sig.V18.RingDegree)
		size += varintSize(sig.V18.Digits)
		size += varintSize(sig.V18.GroupSize)
		size += varintSize(sig.V18.BlockWidth)
		size += len(sig.V18.LayoutDigest)
		size += len(sig.V18.ReplayCompactDigest)
		size += len(sig.V18.PRFCompactDigest)
		return size
	}
	return 0
}

func sizePRFCompanionOpening(open PRFCompanionOpening) int {
	return len(open.Masked)*8 + len(open.Mask)*8
}

func sizePRFCompanionProof(companion *PRFCompanionProof) int {
	if companion == nil {
		return 0
	}
	size := 0
	if companion.Mode != "" {
		size += len(companion.Mode)
	}
	size += varintSize(companion.CheckpointSamples)
	size += 1 // BridgeInQ
	size += sizeUint64Matrix(companion.BridgeChecks)
	size += len(companion.BridgeChecksBits)
	size += len(companion.CoordDigest)
	for i := range companion.CheckpointAudits {
		size += sizePRFCompanionOpening(companion.CheckpointAudits[i].Z)
		size += sizePRFCompanionOpening(companion.CheckpointAudits[i].Wire)
	}
	size += sizePRFCompanionOpening(companion.TagFinal)
	size += sizePRFCompanionOpening(companion.KeyTrunc)
	if companion.Bridge != nil {
		size += varintSize(companion.Bridge.Version)
		size += len(companion.Bridge.RowIndices) * 4
		size += len(companion.Bridge.PhysicalRows) * 4
		size += len(companion.Bridge.SupportSlots) * 4
		size += sizeDECSOpening(companion.Bridge.RowsOpening)
		size += len(companion.Bridge.PackedDigest)
		size += len(companion.Bridge.CoordDigest)
		size += len(companion.Bridge.GeometryDigest)
		size += len(companion.Bridge.BridgeDigest)
	}
	return size
}

func sizeSourceProductBridge(bridge *SourceProductBridge) int {
	if bridge == nil {
		return 0
	}
	size := varintSize(bridge.Version)
	size += len(bridge.RowIndices) * 4
	size += len(bridge.PhysicalRows) * 4
	size += len(bridge.SupportSlots) * 4
	size += sizeDECSOpening(bridge.RowsOpening)
	size += len(bridge.PackedDigest)
	size += len(bridge.GeometryDigest)
	size += len(bridge.BridgeDigest)
	return size
}

// ProofSizeReport summarises the byte footprint of a proof as consumed by the verifier.
type ProofSizeReport struct {
	Total int
	Parts map[string]int
}

// MeasureProofSize returns a copy of the breakdown used by VerifyNIZK to reconstruct the proof.
func MeasureProofSize(proof *Proof) ProofSizeReport {
	parts, total := proofSizeBreakdown(proof)
	copyParts := make(map[string]int, len(parts))
	for k, v := range parts {
		copyParts[k] = v
	}
	return ProofSizeReport{Total: total, Parts: copyParts}
}

func combineOpenings(mask, tail *decs.DECSOpening) *decs.DECSOpening {
	combined := &decs.DECSOpening{}
	nodeMap := make(map[string]int)
	addNode := func(b []byte) int {
		key := string(b)
		if id, ok := nodeMap[key]; ok {
			return id
		}
		id := len(combined.Nodes)
		combined.Nodes = append(combined.Nodes, append([]byte(nil), b...))
		nodeMap[key] = id
		return id
	}
	// helper to append per-entry data and remap path indices
	appendOpen := func(src *decs.DECSOpening, storeIndices bool) {
		if src == nil {
			return
		}
		for _, b := range src.Nodes {
			_ = addNode(b)
		}
		for _, row := range src.Pvals {
			combined.Pvals = append(combined.Pvals, append([]uint64(nil), row...))
		}
		for _, row := range src.Mvals {
			combined.Mvals = append(combined.Mvals, append([]uint64(nil), row...))
		}
		for _, pi := range src.PathIndex {
			mapped := make([]int, len(pi))
			for i, id := range pi {
				if id < 0 || id >= len(src.Nodes) {
					mapped[i] = -1
					continue
				}
				mapped[i] = addNode(src.Nodes[id])
			}
			combined.PathIndex = append(combined.PathIndex, mapped)
		}
		if storeIndices {
			combined.Indices = append(combined.Indices, src.AllIndices()...)
		}
	}

	if mask != nil {
		maskIndices := mask.AllIndices()
		if len(maskIndices) > 0 {
			base := maskIndices[0]
			for i := 1; i < len(maskIndices); i++ {
				if maskIndices[i] != base+i {
					panic("mask indices not contiguous")
				}
			}
			combined.MaskBase = base
			combined.MaskCount = len(maskIndices)
		}
		combined.R = mask.R
		combined.Eta = mask.Eta
		if len(combined.NonceSeed) == 0 && len(mask.NonceSeed) > 0 {
			combined.NonceSeed = append([]byte(nil), mask.NonceSeed...)
			combined.NonceBytes = mask.NonceBytes
		}
		appendOpen(mask, false)
	}
	if tail != nil {
		if combined.R == 0 {
			combined.R = tail.R
		}
		if combined.Eta == 0 {
			combined.Eta = tail.Eta
		}
		if len(tail.NonceSeed) > 0 {
			if len(combined.NonceSeed) == 0 {
				combined.NonceSeed = append([]byte(nil), tail.NonceSeed...)
				combined.NonceBytes = tail.NonceBytes
			} else if !bytes.Equal(combined.NonceSeed, tail.NonceSeed) {
				panic("tail opening nonce seed mismatch")
			}
		}
		appendOpen(tail, true)
	}
	if len(combined.PathIndex) > 0 && len(combined.PathIndex[0]) > 0 {
		combined.PathDepth = len(combined.PathIndex[0])
	}
	return combined
}

func buildKPointCoeffMatrix(
	r *ring.Ring, K *kf.Field, omega []uint64, rows [][]uint64, e kf.Elem, omegaS1 kf.Elem, muDenomInv kf.Elem,
	replayWitnessRows, maskRowOffset, maskRowCount int,
) [][]uint64 {
	if K == nil {
		panic("buildKPointCoeffMatrix: nil field")
	}
	q := r.Modulus[0]
	s := len(omega)
	theta := K.Theta
	layerSize := s + theta
	if layerSize == 0 {
		return nil
	}
	totalRows := len(rows)
	witnessRowCount := replayWitnessRows
	if witnessRowCount <= 0 {
		witnessRowCount = totalRows
		if maskRowCount > 0 {
			witnessRowCount = maskRowOffset
		}
	}
	if maskRowCount > 0 {
		if maskRowOffset < 0 || maskRowOffset > totalRows {
			panic(fmt.Sprintf("buildKPointCoeffMatrix: mask offset %d out of bounds (total=%d)", maskRowOffset, totalRows))
		}
		if maskRowOffset+maskRowCount != totalRows {
			panic(fmt.Sprintf("buildKPointCoeffMatrix: mask segment [%d,%d) inconsistent with total rows %d", maskRowOffset, maskRowOffset+maskRowCount, totalRows))
		}
		if witnessRowCount > maskRowOffset {
			panic(fmt.Sprintf("buildKPointCoeffMatrix: replay witness rows %d exceed witness segment %d", witnessRowCount, maskRowOffset))
		}
	}
	if witnessRowCount < 0 || witnessRowCount > totalRows {
		panic(fmt.Sprintf("buildKPointCoeffMatrix: invalid replay witness row count %d (total=%d)", witnessRowCount, totalRows))
	}
	if witnessRowCount%layerSize != 0 {
		panic(fmt.Sprintf("buildKPointCoeffMatrix: inconsistent row count %d (layer size %d)", witnessRowCount, layerSize))
	}
	layerCount := witnessRowCount / layerSize

	lagNum := make([][]uint64, s)
	lagDenInv := make([]uint64, s)
	for k := 0; k < s; k++ {
		lagNum[k] = lagrangeBasisNumerator(omega, k, q)
		den := uint64(1)
		for j := 0; j < s; j++ {
			if j == k {
				continue
			}
			den = modMul(den, modSub(omega[k]%q, omega[j]%q, q), q)
		}
		lagDenInv[k] = modInv(den, q)
	}

	lambdas := make([]kf.Elem, s)
	lambdaAtOmegaS1 := make([]kf.Elem, s)
	for k := 0; k < s; k++ {
		numK := K.EvalFPolyAtK(lagNum[k], e)
		lambdas[k] = K.Mul(numK, K.EmbedF(lagDenInv[k]))
		numOmegaS1 := K.EvalFPolyAtK(lagNum[k], omegaS1)
		lambdaAtOmegaS1[k] = K.Mul(numOmegaS1, K.EmbedF(lagDenInv[k]))
	}

	prod := K.One()
	for _, w := range omega {
		diff := K.Sub(e, K.EmbedF(w%q))
		prod = K.Mul(prod, diff)
	}
	mu := K.Mul(prod, muDenomInv)
	Mmu := K.MulMatrix(mu)

	coeffs := make([][]uint64, layerCount*theta)
	for layer := 0; layer < layerCount; layer++ {
		base := layer * layerSize
		for k := 0; k < s; k++ {
			coeffK := K.Sub(lambdas[k], K.Mul(mu, lambdaAtOmegaS1[k]))
			for coord := 0; coord < theta; coord++ {
				rowIdx := layer*theta + coord
				if coeffs[rowIdx] == nil {
					coeffs[rowIdx] = make([]uint64, totalRows)
				}
				coeffs[rowIdx][base+k] = coeffK.Limb[coord] % q
			}
		}
		for coord := 0; coord < theta; coord++ {
			for rowIdx := 0; rowIdx < theta; rowIdx++ {
				coeffs[layer*theta+coord][base+s+rowIdx] = Mmu[coord][rowIdx] % q
			}
		}
	}

	return coeffs
}

func elemEqual(f *kf.Field, a, b kf.Elem) bool {
	if len(a.Limb) != len(b.Limb) {
		return false
	}
	for i := range a.Limb {
		if a.Limb[i]%f.Q != b.Limb[i]%f.Q {
			return false
		}
	}
	return true
}

func logComb2Stable(n float64, k int) float64 {
	if k < 0 || float64(k) > n {
		return -1e18
	}
	if k == 0 || float64(k) == n {
		return 0
	}
	if k <= 64 {
		sum := 0.0
		for i := 0; i < k; i++ {
			sum += math.Log2(n-float64(i)) - math.Log2(float64(i+1))
		}
		return sum
	}
	return logComb2(n, k)
}

func flattenBytes(parts [][]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func equalByteSlices(a, b []byte) bool {
	return bytes.Equal(a, b)
}
