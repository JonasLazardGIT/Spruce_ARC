package credential

import (
	"fmt"
	"sort"
	"strings"
)

const (
	IntGenISISPresetN512Compact96            = "n512-compact96"
	IntGenISISPresetN1024Compact96           = "n1024-compact96"
	IntGenISISPresetN1024Compact125          = "n1024-compact125"
	IntGenISISPresetN1024BQ32_96             = "n1024-bq32-96"
	IntGenISISPresetN1024BQ64_96Theta11      = "n1024-bq64-96-theta11"
	IntGenISISPresetN1024BQ64_128Theta13H256 = "n1024-bq64-128-theta13-h256"
	IntGenISISPresetN1024Q10_128             = "n1024-q10-128"
	IntGenISISPresetN1024Q16_128             = "n1024-q16-128"
	IntGenISISPresetN1024Q32_128             = "n1024-q32-128"
	IntGenISISPresetN1024Q10_96              = "n1024-q10-96"
	IntGenISISPresetN1024Q16_96              = "n1024-q16-96"
	IntGenISISPresetN1024Q32_96              = "n1024-q32-96"

	IntGenISISPRFProfileDefault = "poseidon2-t20-tag7"
	IntGenISISPRFProfileTag9    = "poseidon2-t20-tag9"
	IntGenISISPRFParamsDefault  = "prf/prf_params.json"
	IntGenISISPRFParamsTag9     = "prf/prf_params_tag9.json"
)

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
	Description         string                 `json:"description"`
	Profile             string                 `json:"profile"`
	SecurityProfile     string                 `json:"security_profile,omitempty"`
	SecurityMode        string                 `json:"security_mode,omitempty"`
	CoreBitsRequired    float64                `json:"core_bits_required,omitempty"`
	CompleteSystemClaim bool                   `json:"complete_system_claim,omitempty"`
	PRFProfile          string                 `json:"prf_profile,omitempty"`
	PRFParamsPath       string                 `json:"prf_params_path,omitempty"`
	TargetEq8Bits       float64                `json:"target_eq8_bits"`
	TargetTheoremBits   float64                `json:"target_theorem_bits,omitempty"`
	SoundnessGate       string                 `json:"soundness_gate,omitempty"`
	NTRUBeta            uint64                 `json:"ntru_beta,omitempty"`
	LVCSNCols           int                    `json:"lvcs_ncols"`
	MaxNLeaves          int                    `json:"max_nleaves,omitempty"`
	Issuance            IntGenISISTuningPreset `json:"issuance"`
	Showing             IntGenISISTuningPreset `json:"showing"`
	Notes               []string               `json:"notes,omitempty"`
}

func LookupIntGenISISPreset(name string) (IntGenISISPreset, bool) {
	p, ok := intGenISISPresetRegistry()[normalizeIntGenISISPresetName(name)]
	return p, ok
}

func MustLookupIntGenISISPreset(name string) (IntGenISISPreset, error) {
	p, ok := LookupIntGenISISPreset(name)
	if !ok {
		return IntGenISISPreset{}, fmt.Errorf("unknown IntGenISIS preset %q (supported: %s)", name, strings.Join(IntGenISISPresetNames(), ", "))
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
	n1024BQ32Show96.NLeaves = 557056
	n1024BQ32Show96.Eta = 44
	n1024BQ32Show96.Ell = 9
	n1024BQ32Show96.DECSHashBits = 168
	n1024BQ32Show96.DECSTapeBits = 128
	n1024BQ32Show96.FSCollisionBits = 168
	n1024BQ32Show96.SaltBits = 128
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
		IntGenISISPresetN1024BQ32_96: {
			Name:              IntGenISISPresetN1024BQ32_96,
			Description:       "profile-C N=1024 BQ32-96 candidate with split DECS widths and tag-9 PRF",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 96,
			SoundnessGate:     n1024BQ32Show96.SoundnessGate,
			LVCSNCols:         n1024BQ32Show96.LVCSNCols,
			MaxNLeaves:        n1024BQ32Show96.NLeaves,
			Issuance:          n1024BQ32Issuance96,
			Showing:           n1024BQ32Show96,
			Notes: []string{
				"BQ32-96 candidate preset for equal ROQueryCaps=[2^32]*5.",
				"Uses split DECS hash/tape metadata and tag-9 PRF params; complete-system promotion remains gated by the security ledger.",
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
		IntGenISISPresetN1024Q10_128: {
			Name:              IntGenISISPresetN1024Q10_128,
			Description:       "profile-C N=1024 128-bit showing preset for 2^10 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 128,
			SoundnessGate:     n1024Q10Show128.SoundnessGate,
			LVCSNCols:         n1024Q10Show128.LVCSNCols,
			MaxNLeaves:        n1024Q10Show128.NLeaves,
			Issuance:          n1024Q10Issuance128,
			Showing:           n1024Q10Show128,
			Notes: []string{
				"Query-budget-specific 128-bit live preset for ROQueryCaps=[2^10]*5.",
				"Updated from repeat-confirmed sweetspot live run on 2026-06-12.",
			},
		},
		IntGenISISPresetN1024Q16_128: {
			Name:              IntGenISISPresetN1024Q16_128,
			Description:       "profile-C N=1024 128-bit showing preset for 2^16 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 128,
			SoundnessGate:     n1024Q16Show128.SoundnessGate,
			LVCSNCols:         n1024Q16Show128.LVCSNCols,
			MaxNLeaves:        n1024Q16Show128.NLeaves,
			Issuance:          n1024Q16Issuance128,
			Showing:           n1024Q16Show128,
			Notes: []string{
				"Query-budget-specific 128-bit live preset for ROQueryCaps=[2^16]*5.",
				"Updated from repeat-confirmed sweetspot live run on 2026-06-12.",
			},
		},
		IntGenISISPresetN1024Q32_128: {
			Name:              IntGenISISPresetN1024Q32_128,
			Description:       "profile-C N=1024 128-bit showing preset for 2^32 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 128,
			SoundnessGate:     n1024Q32Show128.SoundnessGate,
			LVCSNCols:         n1024Q32Show128.LVCSNCols,
			MaxNLeaves:        n1024Q32Show128.NLeaves,
			Issuance:          n1024Q32Issuance128,
			Showing:           n1024Q32Show128,
			Notes: []string{
				"Query-budget-specific 128-bit live preset for ROQueryCaps=[2^32]*5.",
				"Updated from repeat-confirmed sweetspot live run on 2026-06-12.",
			},
		},
		IntGenISISPresetN1024Q10_96: {
			Name:              IntGenISISPresetN1024Q10_96,
			Description:       "profile-C N=1024 96-bit showing preset for 2^10 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 96,
			SoundnessGate:     n1024Q10Show96.SoundnessGate,
			LVCSNCols:         n1024Q10Show96.LVCSNCols,
			MaxNLeaves:        n1024Q10Show96.NLeaves,
			Issuance:          n1024Q10Issuance96,
			Showing:           n1024Q10Show96,
			Notes: []string{
				"Query-budget-specific 96-bit live preset for ROQueryCaps=[2^10]*5.",
				"Promoted from repeat-confirmed sweetspot96 live run on 2026-06-12.",
			},
		},
		IntGenISISPresetN1024Q16_96: {
			Name:              IntGenISISPresetN1024Q16_96,
			Description:       "profile-C N=1024 96-bit showing preset for 2^16 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 96,
			SoundnessGate:     n1024Q16Show96.SoundnessGate,
			LVCSNCols:         n1024Q16Show96.LVCSNCols,
			MaxNLeaves:        n1024Q16Show96.NLeaves,
			Issuance:          n1024Q16Issuance96,
			Showing:           n1024Q16Show96,
			Notes: []string{
				"Query-budget-specific 96-bit live preset for ROQueryCaps=[2^16]*5.",
				"Promoted from repeat-confirmed sweetspot96 live run on 2026-06-12.",
			},
		},
		IntGenISISPresetN1024Q32_96: {
			Name:              IntGenISISPresetN1024Q32_96,
			Description:       "profile-C N=1024 96-bit showing preset for 2^32 ROM query budgets",
			Profile:           ProfileIntGenISISC,
			TargetTheoremBits: 96,
			SoundnessGate:     n1024Q32Show96.SoundnessGate,
			LVCSNCols:         n1024Q32Show96.LVCSNCols,
			MaxNLeaves:        n1024Q32Show96.NLeaves,
			Issuance:          n1024Q32Issuance96,
			Showing:           n1024Q32Show96,
			Notes: []string{
				"Query-budget-specific 96-bit live preset for ROQueryCaps=[2^32]*5.",
				"Promoted from repeat-confirmed sweetspot96 live run on 2026-06-12.",
			},
		},
	}
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN512Compact96, "SC-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Compact96, "SC-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Compact125, "SC-125")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024BQ32_96, "BQ32-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024BQ64_96Theta11, "BQ64-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024BQ64_128Theta13H256, "BQ64-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q10_128, "BQ32-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q16_128, "BQ32-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q32_128, "BQ32-128")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q10_96, "BQ32-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q16_96, "BQ32-96")
	intGenISISPresetApplySecurityProfile(reg, IntGenISISPresetN1024Q32_96, "BQ32-96")
	intGenISISPresetApplyDefaultPRF(reg)
	intGenISISPresetApplyPRF(reg, IntGenISISPresetN1024BQ32_96, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
	intGenISISPresetApplyPRF(reg, IntGenISISPresetN1024BQ64_96Theta11, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
	intGenISISPresetApplyPRF(reg, IntGenISISPresetN1024BQ64_128Theta13H256, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
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
	preset.PRFProfile = profile
	preset.PRFParamsPath = paramsPath
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
