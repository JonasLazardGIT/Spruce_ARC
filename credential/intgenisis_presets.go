package credential

import (
	"fmt"
	"sort"
	"strings"
)

const (
	IntGenISISPresetN512Compact96                              = "n512-compact96"
	IntGenISISPresetN1024Compact96                             = "n1024-compact96"
	IntGenISISPresetN1024Compact125                            = "n1024-compact125"
	IntGenISISPresetN1024BQ32_96                               = "n1024-bq32-96"
	IntGenISISPresetN1024BQ64_96Theta11                        = "n1024-bq64-96-theta11"
	IntGenISISPresetN1024BQ64_128Theta13H256                   = "n1024-bq64-128-theta13-h256"
	IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512 = "n1024-bq128-128-raw128-residual128-theta13-lvcs48-h512"
	IntGenISISPresetN1024Q10_128                               = "n1024-q10-128"
	IntGenISISPresetN1024Q16_128                               = "n1024-q16-128"
	IntGenISISPresetN1024Q32_128                               = "n1024-q32-128"
	IntGenISISPresetN1024Q10_96                                = "n1024-q10-96"
	IntGenISISPresetN1024Q16_96                                = "n1024-q16-96"
	IntGenISISPresetN1024Q32_96                                = "n1024-q32-96"

	IntGenISISPRFProfileDefault      = "poseidon2-t20-tag7"
	IntGenISISPRFProfileTag9         = "poseidon2-t20-tag9"
	IntGenISISPRFProfileTag13        = "poseidon2-t20-tag13"
	IntGenISISPRFParamsDefault       = "prf/prf_params.json"
	IntGenISISPRFParamsTag9          = "prf/prf_params_tag9.json"
	IntGenISISPRFParamsTag13         = "prf/prf_params_tag13.json"
	IntGenISISPRFParamsDefaultDigest = "1b4258504c486507dc067ce0c6d6649820ab3b55bb3edeaf40afa8d2ea68de94"
	IntGenISISPRFParamsTag9Digest    = "552f38ceaddf0ba0ddfc919602fcd7abfd85430f808bd1b1cf731bcd95ba438f"
	IntGenISISPRFParamsTag13Digest   = "94462038554d296342ed088fcbbecd03165a8f1705fdf64346551a4eabe6b5dd"
)

func IntGenISISPRFProfileTagElements(profile string) (int, bool) {
	switch strings.TrimSpace(strings.ToLower(profile)) {
	case IntGenISISPRFProfileDefault:
		return 7, true
	case IntGenISISPRFProfileTag9:
		return 9, true
	case IntGenISISPRFProfileTag13:
		return 13, true
	default:
		return 0, false
	}
}

func IntGenISISPRFProfileParamsDigest(profile string) (string, bool) {
	switch strings.TrimSpace(strings.ToLower(profile)) {
	case IntGenISISPRFProfileDefault:
		return IntGenISISPRFParamsDefaultDigest, true
	case IntGenISISPRFProfileTag9:
		return IntGenISISPRFParamsTag9Digest, true
	case IntGenISISPRFProfileTag13:
		return IntGenISISPRFParamsTag13Digest, true
	default:
		return "", false
	}
}

// IntGenISISTuningPreset is the CLI-stable, package-neutral representation of
// the SmallWood knobs used by maintained IntGenISIS issuance and showing presets.
type IntGenISISTuningPreset struct {
	NCols               int        `json:"ncols"`
	LVCSNCols           int        `json:"lvcs_ncols"`
	NLeaves             int        `json:"nleaves"`
	Eta                 int        `json:"eta"`
	Theta               int        `json:"theta"`
	Rho                 int        `json:"rho"`
	Ell                 int        `json:"ell"`
	EllPrime            int        `json:"ell_prime"`
	Kappa               [4]int     `json:"kappa"`
	ROQueryCaps         [5]int     `json:"ro_query_caps,omitempty"`
	ROQueryCapsSet      bool       `json:"ro_query_caps_set,omitempty"`
	ROQueryCapBits      [5]float64 `json:"ro_query_cap_bits,omitempty"`
	ROQueryCapBitsSet   bool       `json:"ro_query_cap_bits_set,omitempty"`
	DECSCollisionBits   int        `json:"decs_collision_bits,omitempty"`
	DECSHashBits        int        `json:"decs_hash_bits,omitempty"`
	DECSTapeBits        int        `json:"decs_tape_bits,omitempty"`
	FSCollisionBits     int        `json:"fs_collision_bits,omitempty"`
	SaltBits            int        `json:"salt_bits,omitempty"`
	PRFProfile          string     `json:"prf_profile,omitempty"`
	PRFParamsPath       string     `json:"prf_params_path,omitempty"`
	PRFCompanionMode    string     `json:"prf_companion_mode,omitempty"`
	PRFGroupRounds      int        `json:"prf_group_rounds,omitempty"`
	CheckpointSamples   int        `json:"prf_checkpoint_samples,omitempty"`
	SigShortnessRadix   int        `json:"sig_shortness_radix,omitempty"`
	SigShortnessDigits  int        `json:"sig_shortness_digits,omitempty"`
	CompressedRows      int        `json:"compressed_rows,omitempty"`
	ReplayProjection    string     `json:"replay_projection,omitempty"`
	TranscriptMode      string     `json:"transcript_mode,omitempty"`
	FixedTranscriptSize bool       `json:"fixed_transcript_size,omitempty"`
	TargetEq8Bits       float64    `json:"target_eq8_bits,omitempty"`
	TargetTheoremBits   float64    `json:"target_theorem_bits,omitempty"`
	SoundnessGate       string     `json:"soundness_gate,omitempty"`
}

// IntGenISISPreset describes a maintained issuance/showing parameter set.
type IntGenISISPreset struct {
	Name                string                 `json:"name"`
	CanonicalID         string                 `json:"canonical_id"`
	PresetVersion       int                    `json:"preset_version"`
	Description         string                 `json:"description"`
	Purpose             string                 `json:"purpose"`
	Lifecycle           PresetLifecycle        `json:"lifecycle"`
	ClaimScope          ClaimScope             `json:"claim_scope"`
	Profile             string                 `json:"profile"`
	PrimitiveProfileID  string                 `json:"primitive_profile_id"`
	SecurityProfile     string                 `json:"security_profile,omitempty"`
	SecurityMode        string                 `json:"security_mode,omitempty"`
	CoreBitsRequired    float64                `json:"core_bits_required,omitempty"`
	CompleteSystemClaim bool                   `json:"complete_system_claim,omitempty"`
	PRFProfile          string                 `json:"prf_profile,omitempty"`
	PRFParamsPath       string                 `json:"prf_params_path,omitempty"`
	PRFParamsDigest     string                 `json:"prf_params_digest,omitempty"`
	TargetEq8Bits       float64                `json:"target_eq8_bits"`
	TargetTheoremBits   float64                `json:"target_theorem_bits,omitempty"`
	SoundnessGate       string                 `json:"soundness_gate,omitempty"`
	NTRUBeta            uint64                 `json:"ntru_beta,omitempty"`
	LVCSNCols           int                    `json:"lvcs_ncols"`
	MaxNLeaves          int                    `json:"max_nleaves,omitempty"`
	Issuance            IntGenISISTuningPreset `json:"issuance"`
	Showing             IntGenISISTuningPreset `json:"showing"`
	ThreatModel         PresetThreatModel      `json:"threat_model"`
	Notes               []string               `json:"notes,omitempty"`
}

func LookupIntGenISISPreset(name string) (IntGenISISPreset, bool) {
	selector := normalizeIntGenISISPresetName(name)
	if target, ok := intGenISISPresetAliases()[selector]; ok {
		selector = target
	}
	p, ok := intGenISISPresetRegistry()[selector]
	return p, ok
}

func MustLookupIntGenISISPreset(name string) (IntGenISISPreset, error) {
	p, ok := LookupIntGenISISPreset(name)
	if !ok {
		return IntGenISISPreset{}, fmt.Errorf("unknown IntGenISIS preset %q (available: %s)", name, strings.Join(IntGenISISDefaultPresetNames(), ", "))
	}
	return p, nil
}

func ResolveIntGenISISPresetSelector(name string, use96Bit bool) (string, error) {
	if use96Bit {
		return "", fmt.Errorf("-96bit was removed; use -preset %s or -preset %s", IntGenISISPresetN512Compact96, IntGenISISPresetN1024Compact96)
	}
	return normalizeIntGenISISPresetName(name), nil
}

func IntGenISISPresetNames() []string {
	reg := intGenISISPresetRegistry()
	names := make([]string, 0, len(reg))
	for name := range reg {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func normalizeIntGenISISPresetName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func intGenISISPresetRegistry() map[string]IntGenISISPreset {
	n512Show96 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           36,
		NLeaves:             262144,
		Eta:                 36,
		Theta:               5,
		Rho:                 1,
		Ell:                 7,
		EllPrime:            1,
		Kappa:               [4]int{0, 0, 6, 8},
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		ReplayProjection:    "project_u_digits_and_y_view_v3",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   96,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n512Issuance96 := intGenISISIssuanceTuning(n512Show96)

	n1024Show96 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           43,
		NLeaves:             230208,
		Eta:                 40,
		Theta:               5,
		Rho:                 1,
		Ell:                 7,
		EllPrime:            1,
		Kappa:               [4]int{0, 0, 6, 11},
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   96,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n1024Issuance96 := intGenISISIssuanceTuning(n1024Show96)

	n1024Show125 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           46,
		NLeaves:             608192,
		Eta:                 48,
		Theta:               7,
		Rho:                 1,
		Ell:                 9,
		EllPrime:            1,
		Kappa:               [4]int{0, 0, 0, 5},
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   11,
		SigShortnessDigits:  4,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   125,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n1024Issuance125 := intGenISISIssuanceTuning(n1024Show125)

	n1024Q10Show128 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           36,
		NLeaves:             983040,
		Eta:                 44,
		Theta:               7,
		Rho:                 1,
		Ell:                 9,
		EllPrime:            1,
		Kappa:               [4]int{0, 4, 9, 9},
		ROQueryCaps:         intGenISISROQueryCaps(intGenISISPow2QueryCap(10)),
		ROQueryCapsSet:      true,
		DECSCollisionBits:   152,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   11,
		SigShortnessDigits:  4,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   128,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n1024Q10Issuance128 := intGenISISIssuanceTuning(n1024Q10Show128)
	n1024WF128Show := n1024Q10Show128
	n1024WF128Show.LVCSNCols = 43
	n1024WF128Show.NLeaves = 524288
	n1024WF128Show.Eta = 46
	n1024WF128Show.Kappa = [4]int{0, 0, 4, 13}
	n1024WF128Show.ROQueryCaps = [5]int{}
	n1024WF128Show.ROQueryCapsSet = false
	n1024WF128Show.ROQueryCapBits = [5]float64{}
	n1024WF128Show.ROQueryCapBitsSet = false
	n1024WF128Show.DECSCollisionBits = 264
	n1024WF128Show.DECSHashBits = 264
	n1024WF128Show.DECSTapeBits = 128
	n1024WF128Show.FSCollisionBits = 264
	n1024WF128Show.SaltBits = 256
	n1024WF128Show.PRFProfile = IntGenISISPRFProfileTag13
	n1024WF128Show.PRFParamsPath = IntGenISISPRFParamsTag13
	n1024WF128Issuance := intGenISISIssuanceTuning(n1024WF128Show)

	n1024Q16Show128 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           37,
		NLeaves:             524288,
		Eta:                 43,
		Theta:               8,
		Rho:                 1,
		Ell:                 10,
		EllPrime:            1,
		Kappa:               [4]int{0, 0, 0, 8},
		ROQueryCaps:         intGenISISROQueryCaps(intGenISISPow2QueryCap(16)),
		ROQueryCapsSet:      true,
		DECSCollisionBits:   168,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   128,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n1024Q16Issuance128 := intGenISISIssuanceTuning(n1024Q16Show128)

	n1024Q32Show128 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           37,
		NLeaves:             655360,
		Eta:                 45,
		Theta:               9,
		Rho:                 1,
		Ell:                 11,
		EllPrime:            1,
		Kappa:               [4]int{1, 0, 0, 8},
		ROQueryCaps:         intGenISISROQueryCaps(intGenISISPow2QueryCap(32)),
		ROQueryCapsSet:      true,
		DECSCollisionBits:   200,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   128,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n1024Q32Issuance128 := intGenISISIssuanceTuning(n1024Q32Show128)

	n1024Q10Show96 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           37,
		NLeaves:             720896,
		Eta:                 40,
		Theta:               6,
		Rho:                 1,
		Ell:                 7,
		EllPrime:            1,
		Kappa:               [4]int{0, 0, 0, 8},
		ROQueryCaps:         intGenISISROQueryCaps(intGenISISPow2QueryCap(10)),
		ROQueryCapsSet:      true,
		DECSCollisionBits:   128,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   96,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n1024Q10Issuance96 := intGenISISIssuanceTuning(n1024Q10Show96)

	n1024Q16Show96 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           38,
		NLeaves:             393216,
		Eta:                 40,
		Theta:               6,
		Rho:                 1,
		Ell:                 8,
		EllPrime:            1,
		Kappa:               [4]int{0, 0, 3, 7},
		ROQueryCaps:         intGenISISROQueryCaps(intGenISISPow2QueryCap(16)),
		ROQueryCapsSet:      true,
		DECSCollisionBits:   136,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   11,
		SigShortnessDigits:  4,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   96,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n1024Q16Issuance96 := intGenISISIssuanceTuning(n1024Q16Show96)

	n1024Q32Show96 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           37,
		NLeaves:             458752,
		Eta:                 44,
		Theta:               7,
		Rho:                 1,
		Ell:                 9,
		EllPrime:            1,
		Kappa:               [4]int{0, 0, 2, 7},
		ROQueryCaps:         intGenISISROQueryCaps(intGenISISPow2QueryCap(32)),
		ROQueryCapsSet:      true,
		DECSCollisionBits:   168,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   96,
		SoundnessGate:       "smallwood_2025_1085_live",
	}
	n1024Q32Issuance96 := intGenISISIssuanceTuning(n1024Q32Show96)
	n1024BQ32Show96 := n1024Q32Show96
	n1024BQ32Show96.LVCSNCols = 40
	n1024BQ32Show96.NLeaves = 786432
	n1024BQ32Show96.Eta = 46
	n1024BQ32Show96.Ell = 9
	n1024BQ32Show96.DECSHashBits = 168
	n1024BQ32Show96.DECSTapeBits = 136
	n1024BQ32Show96.FSCollisionBits = 168
	n1024BQ32Show96.SaltBits = 168
	n1024BQ32Show96.TargetTheoremBits = 99.5
	n1024BQ32Show96.PRFProfile = IntGenISISPRFProfileTag9
	n1024BQ32Show96.PRFParamsPath = IntGenISISPRFParamsTag9
	n1024BQ32Issuance96 := intGenISISIssuanceTuning(n1024BQ32Show96)

	n1024BQ64Show96Theta11 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           43,
		NLeaves:             983040,
		Eta:                 58,
		Theta:               11,
		Rho:                 1,
		Ell:                 16,
		EllPrime:            1,
		Kappa:               [4]int{0, 11, 13, 2},
		ROQueryCapBits:      intGenISISROQueryCapBits(64),
		ROQueryCapBitsSet:   true,
		DECSHashBits:        232,
		DECSTapeBits:        160,
		FSCollisionBits:     232,
		SaltBits:            224,
		PRFProfile:          IntGenISISPRFProfileTag9,
		PRFParamsPath:       IntGenISISPRFParamsTag9,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   164,
		SoundnessGate:       "smallwood_2025_1085_theorem_trail",
	}
	n1024BQ64Issuance96Theta11 := intGenISISIssuanceTuning(n1024BQ64Show96Theta11)

	n1024BQ64Show128Theta13H256 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           48,
		NLeaves:             983040,
		Eta:                 65,
		Theta:               13,
		Rho:                 1,
		Ell:                 18,
		EllPrime:            1,
		Kappa:               [4]int{0, 7, 13, 13},
		ROQueryCapBits:      intGenISISROQueryCapBits(64),
		ROQueryCapBitsSet:   true,
		DECSHashBits:        256,
		DECSTapeBits:        192,
		FSCollisionBits:     256,
		SaltBits:            256,
		PRFProfile:          IntGenISISPRFProfileTag9,
		PRFParamsPath:       IntGenISISPRFParamsTag9,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   200,
		SoundnessGate:       "smallwood_2025_1085_theorem_trail",
	}
	n1024BQ64Issuance128Theta13H256 := intGenISISIssuanceTuning(n1024BQ64Show128Theta13H256)

	n1024BQ128Show128RawResidualTheta13LVCS48H512 := IntGenISISTuningPreset{
		NCols:               32,
		LVCSNCols:           48,
		NLeaves:             983040,
		Eta:                 65,
		Theta:               13,
		Rho:                 1,
		Ell:                 18,
		EllPrime:            1,
		Kappa:               [4]int{0, 0, 8, 5},
		ROQueryCapBits:      intGenISISROQueryCapBits(128),
		ROQueryCapBitsSet:   true,
		DECSCollisionBits:   512,
		DECSHashBits:        512,
		DECSTapeBits:        256,
		FSCollisionBits:     512,
		SaltBits:            384,
		PRFProfile:          IntGenISISPRFProfileTag9,
		PRFParamsPath:       IntGenISISPRFParamsTag9,
		PRFCompanionMode:    "direct_full",
		PRFGroupRounds:      2,
		CheckpointSamples:   1,
		SigShortnessRadix:   7,
		SigShortnessDigits:  5,
		CompressedRows:      1,
		ReplayProjection:    "project_u_digits_y_w_residual_v5",
		TranscriptMode:      "smallfield_2025_1085_v1",
		FixedTranscriptSize: true,
		TargetTheoremBits:   128,
		SoundnessGate:       "smallwood_2025_1085_nizk_q128_live",
	}
	n1024BQ128Issuance128RawResidualTheta13LVCS48H512 := intGenISISIssuanceTuning(n1024BQ128Show128RawResidualTheta13LVCS48H512)

	reg := map[string]IntGenISISPreset{
		IntGenISISPresetN512Compact96: {
			Name:              IntGenISISPresetN512Compact96,
			Description:       "profile-B N=512 compact 96-bit engineering preset",
			Profile:           ProfileIntGenISISB,
			TargetTheoremBits: 96,
			SoundnessGate:     n512Show96.SoundnessGate,
			NTRUBeta:          IntGenISISN512SignatureBeta,
			LVCSNCols:         n512Show96.LVCSNCols,
			MaxNLeaves:        n512Show96.NLeaves,
			Issuance:          n512Issuance96,
			Showing:           n512Show96,
			Notes: []string{
				"N=512 is maintained only as the compact 96-bit engineering preset.",
				"NTRU beta is calibrated to 6002 for the R7/L5 top-digit-capped signature shortness proof.",
			},
		},
		IntGenISISPresetN1024Compact96: {
			Name:              IntGenISISPresetN1024Compact96,
			Description:       "profile-C N=1024 compact 96-bit strict-smallfield preset",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 96,
			SoundnessGate:     n1024Show96.SoundnessGate,
			LVCSNCols:         n1024Show96.LVCSNCols,
			MaxNLeaves:        n1024Show96.NLeaves,
			Issuance:          n1024Issuance96,
			Showing:           n1024Show96,
			Notes: []string{
				"Maintained degree-1024 compact 96-bit preset.",
				"Uses smallfield_2025_1085_v1 for issuance and showing while sharing the security tuple.",
			},
		},
		IntGenISISPresetN1024Compact125: {
			Name:              IntGenISISPresetN1024Compact125,
			Description:       "profile-C N=1024 compact 125+ strict-smallfield preset",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 125,
			SoundnessGate:     n1024Show125.SoundnessGate,
			LVCSNCols:         n1024Show125.LVCSNCols,
			MaxNLeaves:        n1024Show125.NLeaves,
			Issuance:          n1024Issuance125,
			Showing:           n1024Show125,
			Notes: []string{
				"Maintained high-security preset.",
				"This is a 125+ live preset optimized for execution time with less than 6 grinding bits per round; it is not a 128-bit live preset.",
			},
		},
		IntGenISISPresetSystemN1024WF128CROMV1: {
			Name:              IntGenISISPresetSystemN1024WF128CROMV1,
			Description:       "profile-C N=1024 executable WF-128 CROM PoC with tag-13 PRF",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 128,
			SoundnessGate:     n1024WF128Show.SoundnessGate,
			LVCSNCols:         n1024WF128Show.LVCSNCols,
			MaxNLeaves:        n1024WF128Show.NLeaves,
			Issuance:          n1024WF128Issuance,
			Showing:           n1024WF128Show,
			Notes: []string{
				"Experimental PoC shape for the 128-bit CROM work-factor profile; not a complete-system deployment claim.",
				"Uses a measured R11/L4 SmallWood retune without bounded-query caps, 264-bit hash/Fiat-Shamir output, 128-bit tape, 256-bit salt, and tag-13 PRF parameters.",
				"Three repeated runs report 133.44/133.35 issuance/showing theorem bits and 26758/38092 paper transcript bytes.",
				"Primitive and complete-game ledger terms remain diagnostic under the repository-wide PoC assumption.",
			},
		},
		IntGenISISPresetN1024BQ32_96: {
			Name:              IntGenISISPresetN1024BQ32_96,
			Description:       "profile-C N=1024 BQ32-96 candidate with split DECS widths and tag-9 PRF",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 99.5,
			SoundnessGate:     n1024BQ32Show96.SoundnessGate,
			LVCSNCols:         n1024BQ32Show96.LVCSNCols,
			MaxNLeaves:        n1024BQ32Show96.NLeaves,
			Issuance:          n1024BQ32Issuance96,
			Showing:           n1024BQ32Show96,
			Notes: []string{
				"BQ32-96 candidate preset for equal ROQueryCaps=[2^32]*5.",
				"The retuned n=786432, eta=46 shape measures 99.98 one-proof theorem bits and 98.59 bits after the current one-issuance/one-showing global-collision composition.",
				"Uses 168-bit hash/Fiat-Shamir output, 136-bit tapes, 168-bit salts, and actual tag-9 PRF params; complete-system promotion remains gated by the security ledger.",
			},
		},
		IntGenISISPresetN1024BQ64_96Theta11: {
			Name:              IntGenISISPresetN1024BQ64_96Theta11,
			Description:       "profile-C N=1024 BQ64-96 theta11 theorem-trail preset",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 164,
			SoundnessGate:     n1024BQ64Show96Theta11.SoundnessGate,
			LVCSNCols:         n1024BQ64Show96Theta11.LVCSNCols,
			MaxNLeaves:        n1024BQ64Show96Theta11.NLeaves,
			Issuance:          n1024BQ64Issuance96Theta11,
			Showing:           n1024BQ64Show96Theta11,
			Notes: []string{
				"Research-only BQ64-96 theta11 trail with RO query caps represented as log2 caps [64]*5.",
				"The theta11 shape requires an external valid-prefix/similar theorem argument before it can be used as current-theorem security.",
				"Profile remains requires_new_primitives: BQ64-96 needs a 160-bit primitive family and tag-12 PRF lane; tag-9 is only the current executable plumbing.",
			},
		},
		IntGenISISPresetN1024BQ64_128Theta13H256: {
			Name:              IntGenISISPresetN1024BQ64_128Theta13H256,
			Description:       "profile-C N=1024 BQ64-128 theta13 h256 theorem-trail preset",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 200,
			SoundnessGate:     n1024BQ64Show128Theta13H256.SoundnessGate,
			LVCSNCols:         n1024BQ64Show128Theta13H256.LVCSNCols,
			MaxNLeaves:        n1024BQ64Show128Theta13H256.NLeaves,
			Issuance:          n1024BQ64Issuance128Theta13H256,
			Showing:           n1024BQ64Show128Theta13H256,
			Notes: []string{
				"Research-only BQ64-128 theta13+h256 trail with RO query caps represented as log2 caps [64]*5.",
				"The theta13+h256 shape is justified only by an external theorem/accounting argument that reduces the effective algebraic round-prefix cap while raw collision/programming accounting remains at 2^64.",
				"Profile remains requires_new_primitives: BQ64-128 needs a 192-bit primitive family and tag-13 PRF lane; tag-9 is only the current executable plumbing.",
			},
		},
		IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512: {
			Name:              IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512,
			Description:       "profile-C N=1024 SmallWood NIZK Q128/epsilon128 raw-residual preset",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 128,
			SoundnessGate:     n1024BQ128Show128RawResidualTheta13LVCS48H512.SoundnessGate,
			LVCSNCols:         n1024BQ128Show128RawResidualTheta13LVCS48H512.LVCSNCols,
			MaxNLeaves:        n1024BQ128Show128RawResidualTheta13LVCS48H512.NLeaves,
			Issuance:          n1024BQ128Issuance128RawResidualTheta13LVCS48H512,
			Showing:           n1024BQ128Show128RawResidualTheta13LVCS48H512,
			Notes: []string{
				"SmallWood NIZK-only Q128/epsilon128 preset: proof soundness and zero knowledge target about 128 bits for an adversary making up to 2^128 ROM/Fiat-Shamir queries against the proof system.",
				"Uses raw log RO caps [128]*5 with no valid-prefix discount, h512 Fiat-Shamir/collision accounting, 256-bit tape, 384-bit salt, theta13, ell18, LVCS48, and measured 89950 paper transcript bytes.",
				"Not a complete IntGenISIS credential-system claim: the BQ128-128 system profile still requires a 256-bit primitive redesign, and tag-9 remains executable plumbing rather than the claimed primitive lane.",
			},
		},
		IntGenISISPresetN1024Q10_128: {
			Name:              IntGenISISPresetN1024Q10_128,
			Description:       "historical profile-C N=1024 proof-theorem artifact for 2^10 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 128,
			SoundnessGate:     n1024Q10Show128.SoundnessGate,
			LVCSNCols:         n1024Q10Show128.LVCSNCols,
			MaxNLeaves:        n1024Q10Show128.NLeaves,
			Issuance:          n1024Q10Issuance128,
			Showing:           n1024Q10Show128,
			Notes: []string{
				"Hidden historical artifact for ROQueryCaps=[2^10]*5; not a complete-system claim.",
				"The executable tag-7 primitive does not meet the BQ10-128 profile requirement.",
			},
		},
		IntGenISISPresetN1024Q16_128: {
			Name:              IntGenISISPresetN1024Q16_128,
			Description:       "historical profile-C N=1024 proof-theorem artifact for 2^16 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 128,
			SoundnessGate:     n1024Q16Show128.SoundnessGate,
			LVCSNCols:         n1024Q16Show128.LVCSNCols,
			MaxNLeaves:        n1024Q16Show128.NLeaves,
			Issuance:          n1024Q16Issuance128,
			Showing:           n1024Q16Show128,
			Notes: []string{
				"Hidden historical artifact for ROQueryCaps=[2^16]*5; not a complete-system claim.",
				"The executable tag-7 primitive does not meet the BQ16-128 profile requirement.",
			},
		},
		IntGenISISPresetN1024Q32_128: {
			Name:              IntGenISISPresetN1024Q32_128,
			Description:       "profile-C N=1024 BQ32-128 proof-theorem research point",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 128,
			SoundnessGate:     n1024Q32Show128.SoundnessGate,
			LVCSNCols:         n1024Q32Show128.LVCSNCols,
			MaxNLeaves:        n1024Q32Show128.NLeaves,
			Issuance:          n1024Q32Issuance128,
			Showing:           n1024Q32Show128,
			Notes: []string{
				"Proof-only research point for ROQueryCaps=[2^32]*5; not a complete-system claim.",
				"The executable tag-7 primitive does not meet the required tag-10 and 160-bit primitive lane.",
			},
		},
		IntGenISISPresetN1024Q10_96: {
			Name:              IntGenISISPresetN1024Q10_96,
			Description:       "historical profile-C N=1024 proof artifact for 2^10 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 96,
			SoundnessGate:     n1024Q10Show96.SoundnessGate,
			LVCSNCols:         n1024Q10Show96.LVCSNCols,
			MaxNLeaves:        n1024Q10Show96.NLeaves,
			Issuance:          n1024Q10Issuance96,
			Showing:           n1024Q10Show96,
			Notes: []string{
				"Hidden historical artifact for ROQueryCaps=[2^10]*5; retained for byte reproduction.",
			},
		},
		IntGenISISPresetN1024Q16_96: {
			Name:              IntGenISISPresetN1024Q16_96,
			Description:       "historical profile-C N=1024 proof artifact for 2^16 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 96,
			SoundnessGate:     n1024Q16Show96.SoundnessGate,
			LVCSNCols:         n1024Q16Show96.LVCSNCols,
			MaxNLeaves:        n1024Q16Show96.NLeaves,
			Issuance:          n1024Q16Issuance96,
			Showing:           n1024Q16Show96,
			Notes: []string{
				"Hidden historical artifact for ROQueryCaps=[2^16]*5; retained for byte reproduction.",
			},
		},
		IntGenISISPresetN1024Q32_96: {
			Name:              IntGenISISPresetN1024Q32_96,
			Description:       "superseded profile-C N=1024 proof artifact for 2^32 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 96,
			SoundnessGate:     n1024Q32Show96.SoundnessGate,
			LVCSNCols:         n1024Q32Show96.LVCSNCols,
			MaxNLeaves:        n1024Q32Show96.NLeaves,
			Issuance:          n1024Q32Issuance96,
			Showing:           n1024Q32Show96,
			Notes: []string{
				"Historical byte artifact for ROQueryCaps=[2^32]*5; superseded by the actual tag-9 BQ32 pilot candidate.",
			},
		},
	}
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN512Compact96, "SC-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Compact96, "SC-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Compact125, "SC-125")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetSystemN1024WF128CROMV1, "WF-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024BQ32_96, "BQ32-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024BQ64_96Theta11, "BQ64-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024BQ64_128Theta13H256, "BQ64-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512, "BQ128-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q10_128, "BQ10-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q16_128, "BQ16-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q32_128, "BQ32-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q10_96, "BQ10-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q16_96, "BQ16-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q32_96, "BQ32-96")
	intGenISISPresetApplyDefaultPRF(reg)
	intGenISISPresetApplyPRF(reg, IntGenISISPresetN1024BQ32_96, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
	intGenISISPresetApplyPRF(reg, IntGenISISPresetN1024BQ64_96Theta11, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
	intGenISISPresetApplyPRF(reg, IntGenISISPresetN1024BQ64_128Theta13H256, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
	intGenISISPresetApplyPRF(reg, IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
	intGenISISPresetApplyPRF(reg, IntGenISISPresetSystemN1024WF128CROMV1, IntGenISISPRFProfileTag13, IntGenISISPRFParamsTag13)
	intGenISISPresetApplyMetadata(reg)
	return reg
}

func intGenISISPresetApplySecurityProfile(reg map[string]IntGenISISPreset, name, label string) {
	preset, ok := reg[name]
	if !ok {
		panic(fmt.Sprintf("missing IntGenISIS preset %s for security profile %q", name, label))
	}
	profile, ok := LookupIntGenISISSecurityProfile(label)
	if !ok {
		panic(fmt.Sprintf("unknown IntGenISIS security profile %q for preset %s", label, name))
	}
	preset.SecurityProfile = profile.Label
	preset.SecurityMode = string(profile.Mode)
	preset.CoreBitsRequired = profile.CoreBitsRequired
	preset.CompleteSystemClaim = profile.Status == SecurityProfileCompleteLive
	reg[name] = preset
}

func intGenISISPresetApplyDefaultPRF(reg map[string]IntGenISISPreset) {
	for name := range reg {
		intGenISISPresetApplyPRF(reg, name, IntGenISISPRFProfileDefault, IntGenISISPRFParamsDefault)
	}
}

func intGenISISPresetApplyPRF(reg map[string]IntGenISISPreset, name, profile, paramsPath string) {
	preset, ok := reg[name]
	if !ok {
		panic(fmt.Sprintf("missing IntGenISIS preset %s for PRF profile %q", name, profile))
	}
	digest, ok := IntGenISISPRFProfileParamsDigest(profile)
	if !ok {
		panic(fmt.Sprintf("unknown IntGenISIS PRF profile %q", profile))
	}
	preset.PRFProfile = profile
	preset.PRFParamsPath = paramsPath
	preset.PRFParamsDigest = digest
	preset.Issuance.PRFProfile = profile
	preset.Issuance.PRFParamsPath = paramsPath
	preset.Showing.PRFProfile = profile
	preset.Showing.PRFParamsPath = paramsPath
	reg[name] = preset
}

func intGenISISIssuanceTuning(showing IntGenISISTuningPreset) IntGenISISTuningPreset {
	issuance := showing
	issuance.PRFCompanionMode = ""
	issuance.PRFGroupRounds = 0
	issuance.CheckpointSamples = 0
	issuance.SigShortnessRadix = 0
	issuance.SigShortnessDigits = 0
	issuance.CompressedRows = 0
	issuance.ReplayProjection = ""
	return issuance
}

func intGenISISPow2QueryCap(exp uint) int {
	return int(uint64(1) << exp)
}

func intGenISISROQueryCaps(cap int) [5]int {
	return [5]int{cap, cap, cap, cap, cap}
}

func intGenISISROQueryCapBits(bits float64) [5]float64 {
	return [5]float64{bits, bits, bits, bits, bits}
}
