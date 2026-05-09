package credential

import (
	"fmt"
	"sort"
	"strings"
)

const (
	IntGenISISPreset96Bit        = "96bit"
	IntGenISISPreset120BitSF     = "120bitsf"
	IntGenISISPresetFast96       = "fast96"
	IntGenISISPresetFastLocal    = "fast-local"
	IntGenISISPresetSW96LVCS32   = "sw96-lvcs32"
	IntGenISISPresetSW96LVCS64   = "sw96-lvcs64"
	IntGenISISPresetSW96LVCS128  = "sw96-lvcs128"
	IntGenISISPresetSW128LVCS32  = "sw128-lvcs32"
	IntGenISISPresetSW128LVCS64  = "sw128-lvcs64"
	IntGenISISPresetSW128LVCS128 = "sw128-lvcs128"
	IntGenISISPresetN256SW96     = "n256-sw96"
	IntGenISISPresetN256SW128    = "n256-sw128"
	IntGenISISPresetN1024SW90SF  = "n1024-sw90-smallfield"
	IntGenISISPresetN1024SW96    = "n1024-sw96"
	IntGenISISPresetN1024SW115SF = "n1024-sw115-smallfield"
	IntGenISISPresetN1024SW120SF = "n1024-sw120-smallfield"
	IntGenISISPresetN1024SW128   = "n1024-sw128"
)

// IntGenISISTuningPreset is the CLI-stable, package-neutral representation of
// the SmallWood knobs used by IntGenISIS issuance and showing presets.
type IntGenISISTuningPreset struct {
	NCols              int     `json:"ncols"`
	LVCSNCols          int     `json:"lvcs_ncols"`
	NLeaves            int     `json:"nleaves"`
	Eta                int     `json:"eta"`
	Theta              int     `json:"theta"`
	Rho                int     `json:"rho"`
	Ell                int     `json:"ell"`
	EllPrime           int     `json:"ell_prime"`
	Kappa              [4]int  `json:"kappa"`
	PRFCompanionMode   string  `json:"prf_companion_mode,omitempty"`
	PRFGroupRounds     int     `json:"prf_group_rounds,omitempty"`
	CheckpointSamples  int     `json:"prf_checkpoint_samples,omitempty"`
	SigShortnessRadix  int     `json:"sig_shortness_radix,omitempty"`
	SigShortnessDigits int     `json:"sig_shortness_digits,omitempty"`
	CompressedRows     int     `json:"compressed_rows,omitempty"`
	ReplayProjection   string  `json:"replay_projection,omitempty"`
	TranscriptMode     string  `json:"transcript_mode,omitempty"`
	TargetEq8Bits      float64 `json:"target_eq8_bits,omitempty"`
	TargetTheoremBits  float64 `json:"target_theorem_bits,omitempty"`
	SoundnessGate      string  `json:"soundness_gate,omitempty"`
}

// IntGenISISPreset describes a named issuance/showing parameter set. The
// secure entries are maintained as practical seeds; preset sweeps can emit
// measured replacements as JSON before promotion into this registry.
type IntGenISISPreset struct {
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Profile             string                 `json:"profile"`
	TargetEq8Bits       float64                `json:"target_eq8_bits"`
	TargetTheoremBits   float64                `json:"target_theorem_bits,omitempty"`
	SoundnessGate       string                 `json:"soundness_gate,omitempty"`
	LVCSNCols           int                    `json:"lvcs_ncols"`
	MaxNLeaves          int                    `json:"max_nleaves,omitempty"`
	ResearchLargeDomain bool                   `json:"research_large_domain,omitempty"`
	Issuance            IntGenISISTuningPreset `json:"issuance"`
	Showing             IntGenISISTuningPreset `json:"showing"`
	Notes               []string               `json:"notes,omitempty"`
}

func LookupIntGenISISPreset(name string) (IntGenISISPreset, bool) {
	key := normalizeIntGenISISPresetName(name)
	p, ok := intGenISISPresetRegistry()[key]
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
	name = normalizeIntGenISISPresetName(name)
	if !use96Bit {
		return name, nil
	}
	if name != "" && name != IntGenISISPreset96Bit {
		return "", fmt.Errorf("-96bit cannot be combined with -preset %s", name)
	}
	return IntGenISISPreset96Bit, nil
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
	key := strings.ToLower(strings.TrimSpace(name))
	switch key {
	case "96", "96-bit", "96_bit", "sw96":
		return IntGenISISPreset96Bit
	case "120", "120-bit-sf", "120_bit_sf", "120sf":
		return IntGenISISPreset120BitSF
	case "fast-96", "fast_96", "runtime96", "runtime-96", "runtime_96", "n256-fast96", "n256-fast-96":
		return IntGenISISPresetFast96
	case "n1024-96", "n1024_96", "n1024-sw-96", "n1024-ternary-sw96", "n1024-b1-sw96", "ternary1024-sw96":
		return IntGenISISPresetN1024SW96
	case "n1024-90", "n1024_90", "n1024-sw90", "n1024-sw-90", "n1024-ternary-sw90", "n1024-b1-sw90", "ternary1024-sw90", "n1024-sw90-sf", "n1024-90-smallfield":
		return IntGenISISPresetN1024SW90SF
	case "n1024-115", "n1024_115", "n1024-sw115", "n1024-sw-115", "n1024-ternary-sw115", "n1024-b1-sw115", "ternary1024-sw115", "n1024-sw115-sf", "n1024-115-smallfield":
		return IntGenISISPresetN1024SW115SF
	case "n1024-120", "n1024_120", "n1024-sw120", "n1024-sw-120", "n1024-ternary-sw120", "n1024-b1-sw120", "ternary1024-sw120", "n1024-sw120-sf", "n1024-120-smallfield":
		return IntGenISISPresetN1024SW120SF
	case "n1024-128", "n1024_128", "n1024-sw-128", "n1024-ternary-sw128", "n1024-b1-sw128", "ternary1024-sw128":
		return IntGenISISPresetN1024SW128
	default:
		return key
	}
}

func intGenISISPresetRegistry() map[string]IntGenISISPreset {
	fast := IntGenISISTuningPreset{
		NCols:             16,
		LVCSNCols:         32,
		NLeaves:           4096,
		Eta:               8,
		Theta:             1,
		Rho:               1,
		Ell:               4,
		EllPrime:          4,
		PRFCompanionMode:  "output_audit",
		PRFGroupRounds:    2,
		CheckpointSamples: 8,
	}
	show96LVCS32 := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          32,
		NLeaves:            32448,
		Eta:                29,
		Theta:              6,
		Rho:                1,
		Ell:                10,
		EllPrime:           1,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     0,
		TargetEq8Bits:      96,
	}
	show96LVCS64 := show96LVCS32
	show96LVCS64.LVCSNCols = 64
	show96LVCS64.NLeaves = 61056
	show96LVCS64.Eta = 47
	show96LVCS64Issuance := show96LVCS64
	show96LVCS64Issuance.PRFCompanionMode = ""
	show96LVCS64Issuance.PRFGroupRounds = 0
	show96LVCS64Issuance.CheckpointSamples = 0
	show96LVCS64Issuance.SigShortnessRadix = 0
	show96LVCS64Issuance.SigShortnessDigits = 0
	show96LVCS64Issuance.CompressedRows = 0
	show96LVCS64Issuance.TargetEq8Bits = 96
	show96LVCS64Issuance.SoundnessGate = "raw_eq8"
	show96LVCS64 = IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          70,
		NLeaves:            42000,
		Eta:                47,
		Theta:              3,
		Rho:                2,
		Ell:                10,
		EllPrime:           2,
		Kappa:              [4]int{0, 0, 0, 6},
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  11,
		SigShortnessDigits: 4,
		CompressedRows:     0,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
		TargetTheoremBits:  96,
		SoundnessGate:      "theorem9_grinding",
	}
	show96LVCS128 := show96LVCS32
	show96LVCS128.LVCSNCols = 128
	show96LVCS128.NLeaves = 64512
	show96LVCS128.Eta = 77
	show96LVCS128.Ell = 11

	show128LVCS32 := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          32,
		NLeaves:            41088,
		Eta:                33,
		Theta:              7,
		Rho:                1,
		Ell:                13,
		EllPrime:           1,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     0,
		TargetEq8Bits:      128,
	}
	show128LVCS64 := show128LVCS32
	show128LVCS64 = IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          70,
		NLeaves:            262144,
		Eta:                59,
		Theta:              7,
		Rho:                1,
		Ell:                10,
		EllPrime:           1,
		Kappa:              [4]int{6, 0, 0, 11},
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  11,
		SigShortnessDigits: 4,
		CompressedRows:     0,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
		TargetTheoremBits:  128,
		SoundnessGate:      "theorem9_grinding",
	}
	show128LVCS64Issuance := show128LVCS64
	show128LVCS64Issuance.PRFCompanionMode = ""
	show128LVCS64Issuance.PRFGroupRounds = 0
	show128LVCS64Issuance.CheckpointSamples = 0
	show128LVCS64Issuance.SigShortnessRadix = 0
	show128LVCS64Issuance.SigShortnessDigits = 0
	show128LVCS64Issuance.CompressedRows = 0
	show128LVCS64Issuance.ReplayProjection = ""
	show128LVCS128 := show128LVCS32
	show128LVCS128.LVCSNCols = 128
	show128LVCS128.NLeaves = 57344
	show128LVCS128.Eta = 79
	show128LVCS128.Ell = 15

	n256Show96 := IntGenISISTuningPreset{
		NCols:              16,
		LVCSNCols:          48,
		NLeaves:            262144,
		Eta:                44,
		Theta:              2,
		Rho:                3,
		Ell:                8,
		EllPrime:           3,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     0,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
	}
	n256Show96.TargetTheoremBits = 96
	n256Show96.TargetEq8Bits = 0
	n256Show96.SoundnessGate = "theorem9_measured"
	n256Issuance96 := n256Show96
	n256Issuance96.PRFCompanionMode = ""
	n256Issuance96.PRFGroupRounds = 0
	n256Issuance96.CheckpointSamples = 0
	n256Issuance96.SigShortnessRadix = 0
	n256Issuance96.SigShortnessDigits = 0
	n256Issuance96.CompressedRows = 0
	n256Issuance96.ReplayProjection = ""

	n256Show120SF := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          36,
		NLeaves:            618048,
		Eta:                42,
		Theta:              2,
		Rho:                3,
		Ell:                9,
		EllPrime:           4,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		CompressedRows:     0,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
	}
	n256Show120SF.TargetTheoremBits = 120
	n256Show120SF.TargetEq8Bits = 0
	n256Show120SF.SoundnessGate = "theorem9_measured"
	n256Issuance120SF := n256Show120SF
	n256Issuance120SF.PRFCompanionMode = ""
	n256Issuance120SF.PRFGroupRounds = 0
	n256Issuance120SF.CheckpointSamples = 0
	n256Issuance120SF.SigShortnessRadix = 0
	n256Issuance120SF.SigShortnessDigits = 0
	n256Issuance120SF.CompressedRows = 0
	n256Issuance120SF.ReplayProjection = ""

	n256Fast96 := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          52,
		NLeaves:            11546,
		Eta:                35,
		Theta:              2,
		Rho:                3,
		Ell:                13,
		EllPrime:           3,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		CompressedRows:     0,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
	}
	n256Fast96.TargetTheoremBits = 96
	n256Fast96.TargetEq8Bits = 0
	n256Fast96.SoundnessGate = "theorem9_measured"
	n256Fast96Issuance := n256Fast96
	n256Fast96Issuance.PRFCompanionMode = ""
	n256Fast96Issuance.PRFGroupRounds = 0
	n256Fast96Issuance.CheckpointSamples = 0
	n256Fast96Issuance.SigShortnessRadix = 0
	n256Fast96Issuance.SigShortnessDigits = 0
	n256Fast96Issuance.CompressedRows = 0
	n256Fast96Issuance.ReplayProjection = ""

	n256Show128 := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          32,
		NLeaves:            917504,
		Eta:                40,
		Theta:              1,
		Rho:                7,
		Ell:                9,
		EllPrime:           11,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		CompressedRows:     0,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
	}
	n256Show128.TargetTheoremBits = 128
	n256Show128.TargetEq8Bits = 0
	n256Show128.SoundnessGate = "theorem9_measured"
	n256Issuance128 := n256Show128
	n256Issuance128.PRFCompanionMode = ""
	n256Issuance128.PRFGroupRounds = 0
	n256Issuance128.CheckpointSamples = 0
	n256Issuance128.SigShortnessRadix = 0
	n256Issuance128.SigShortnessDigits = 0
	n256Issuance128.CompressedRows = 0
	n256Issuance128.ReplayProjection = ""

	n1024Show96 := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          96,
		NLeaves:            262144,
		Eta:                44,
		Theta:              2,
		Rho:                3,
		Ell:                8,
		EllPrime:           3,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     0,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
	}
	n1024Show96.TargetTheoremBits = 96
	n1024Show96.TargetEq8Bits = 0
	n1024Show96.SoundnessGate = "theorem9_seed"
	n1024Issuance96 := n1024Show96
	n1024Issuance96.PRFCompanionMode = ""
	n1024Issuance96.PRFGroupRounds = 0
	n1024Issuance96.CheckpointSamples = 0
	n1024Issuance96.SigShortnessRadix = 0
	n1024Issuance96.SigShortnessDigits = 0
	n1024Issuance96.CompressedRows = 0
	n1024Issuance96.ReplayProjection = ""

	n1024Show90SF := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          43,
		NLeaves:            230208,
		Eta:                40,
		Theta:              5,
		Rho:                1,
		Ell:                7,
		EllPrime:           1,
		Kappa:              [4]int{0, 0, 6, 11},
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  1,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     1,
		ReplayProjection:   "project_u_digits_y_w_residual_v5",
		TranscriptMode:     "smallfield_2025_1085_v1",
		TargetTheoremBits:  96,
		SoundnessGate:      "smallwood_2025_1085_live",
	}
	n1024Issuance90SF := n1024Show90SF
	n1024Issuance90SF.PRFCompanionMode = ""
	n1024Issuance90SF.PRFGroupRounds = 0
	n1024Issuance90SF.CheckpointSamples = 0
	n1024Issuance90SF.SigShortnessRadix = 0
	n1024Issuance90SF.SigShortnessDigits = 0
	n1024Issuance90SF.CompressedRows = 0
	n1024Issuance90SF.ReplayProjection = ""
	n1024Issuance90SF.TranscriptMode = ""

	n1024Show115SF := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          42,
		NLeaves:            354816,
		Eta:                43,
		Theta:              7,
		Rho:                1,
		Ell:                9,
		EllPrime:           1,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  1,
		SigShortnessRadix:  11,
		SigShortnessDigits: 4,
		CompressedRows:     1,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
		TranscriptMode:     "smallfield_2025_1085_v1",
		TargetTheoremBits:  115,
		SoundnessGate:      "smallwood_2025_1085_live",
	}
	n1024Issuance115SF := IntGenISISTuningPreset{
		NCols:             32,
		LVCSNCols:         36,
		NLeaves:           839680,
		Eta:               41,
		Theta:             7,
		Rho:               1,
		Ell:               8,
		EllPrime:          1,
		TargetTheoremBits: 115,
		SoundnessGate:     "smallwood_2025_1085_live",
	}

	n1024Show120SF := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          52,
		NLeaves:            594752,
		Eta:                52,
		Theta:              7,
		Rho:                1,
		Ell:                9,
		EllPrime:           1,
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  1,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     0,
		ReplayProjection:   "project_u_y_hat_and_y_view_v2",
		TranscriptMode:     "smallfield_2025_1085_v1",
		TargetTheoremBits:  120,
		SoundnessGate:      "smallwood_2025_1085_live",
	}
	n1024Issuance120SF := n1024Show120SF
	n1024Issuance120SF.PRFCompanionMode = ""
	n1024Issuance120SF.PRFGroupRounds = 0
	n1024Issuance120SF.CheckpointSamples = 0
	n1024Issuance120SF.SigShortnessRadix = 0
	n1024Issuance120SF.SigShortnessDigits = 0
	n1024Issuance120SF.CompressedRows = 0
	n1024Issuance120SF.ReplayProjection = ""
	n1024Issuance120SF.TranscriptMode = ""

	n1024Show128 := IntGenISISTuningPreset{
		NCols:              32,
		LVCSNCols:          44,
		NLeaves:            524288,
		Eta:                46,
		Theta:              7,
		Rho:                1,
		Ell:                9,
		EllPrime:           1,
		Kappa:              [4]int{0, 0, 0, 8},
		PRFCompanionMode:   "direct_auth",
		PRFGroupRounds:     2,
		CheckpointSamples:  1,
		SigShortnessRadix:  11,
		SigShortnessDigits: 4,
		CompressedRows:     1,
		ReplayProjection:   "project_u_digits_and_y_view_v3",
		TranscriptMode:     "smallfield_2025_1085_v1",
	}
	n1024Show128.TargetTheoremBits = 128
	n1024Show128.TargetEq8Bits = 0
	n1024Show128.SoundnessGate = "smallwood_2025_1085_collision256_candidate"
	n1024Issuance128 := n1024Show128
	n1024Issuance128.PRFCompanionMode = ""
	n1024Issuance128.PRFGroupRounds = 0
	n1024Issuance128.CheckpointSamples = 0
	n1024Issuance128.SigShortnessRadix = 0
	n1024Issuance128.SigShortnessDigits = 0
	n1024Issuance128.CompressedRows = 0
	n1024Issuance128.ReplayProjection = ""
	n1024Issuance128.TranscriptMode = ""

	mk := func(name, desc string, target float64, lvcs, maxLeaves int, showing IntGenISISTuningPreset) IntGenISISPreset {
		issuance := showing
		if issuance.NCols < 16 {
			issuance.NCols = 16
		}
		issuance.PRFCompanionMode = ""
		issuance.PRFGroupRounds = 0
		issuance.CheckpointSamples = 0
		issuance.SigShortnessRadix = 0
		issuance.SigShortnessDigits = 0
		issuance.CompressedRows = 0
		issuance.TranscriptMode = ""
		issuance.TargetEq8Bits = target
		return IntGenISISPreset{
			Name:          name,
			Description:   desc,
			Profile:       ProfileIntGenISISB,
			TargetEq8Bits: target,
			SoundnessGate: "raw_eq8",
			LVCSNCols:     lvcs,
			MaxNLeaves:    maxLeaves,
			Issuance:      issuance,
			Showing:       showing,
			Notes: []string{
				"Static preset values were promoted from the measured sweep-intgenisis-presets frontier.",
				"Raw Eq. (8) bits, not kappa-assisted theorem bits, are the pass criterion for secure presets.",
			},
		}
	}
	reg := map[string]IntGenISISPreset{
		IntGenISISPreset96Bit: {
			Name:                IntGenISISPreset96Bit,
			Description:         "general IntGenISIS 96-bit preset from measured viable frontier est_000514",
			Profile:             ProfileIntGenISISA,
			TargetEq8Bits:       0,
			TargetTheoremBits:   96,
			SoundnessGate:       n256Show96.SoundnessGate,
			LVCSNCols:           n256Show96.LVCSNCols,
			MaxNLeaves:          n256Show96.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n256Issuance96,
			Showing:             n256Show96,
			Notes: []string{
				"Promoted from measured viable-frontier candidate est_000514 after dimension-faithful transcript estimation.",
				"B=4 remeasurement showing snapshot: paper_transcript_bytes=23444, proof_bytes=44637, dQ=222, theorem_total_bits=96.33, raw Eq. (8)=96.33.",
				"B=4 remeasurement issuance snapshot: paper_transcript_bytes=16531, committed_cols=48, theorem_total_bits=96.33.",
				"B=4 measured combined paper transcript bytes: 39975.",
			},
		},
		IntGenISISPreset120BitSF: {
			Name:                IntGenISISPreset120BitSF,
			Description:         "profile-A N=256 120-bit small-field measured preset",
			Profile:             ProfileIntGenISISA,
			TargetEq8Bits:       0,
			TargetTheoremBits:   120,
			SoundnessGate:       n256Show120SF.SoundnessGate,
			LVCSNCols:           n256Show120SF.LVCSNCols,
			MaxNLeaves:          n256Show120SF.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n256Issuance120SF,
			Showing:             n256Show120SF,
			Notes: []string{
				"Promoted from measured focused-sweep candidate est_1246730 as the 120-bit small-field baseline.",
				"B=4 remeasurement showing snapshot: paper_transcript_bytes=28750, proof_bytes=68022, dQ=391, theorem_total_bits=119.98, raw Eq. (8)=119.98.",
				"B=4 remeasurement issuance snapshot: paper_transcript_bytes=20075, committed_cols=36, theorem_total_bits=119.98.",
				"B=4 measured combined paper transcript bytes: 48825.",
			},
		},
		IntGenISISPresetFastLocal: {
			Name:          IntGenISISPresetFastLocal,
			Description:   "fast local IntGenISIS profile-B debugging parameters; not a secure Eq. (8) preset",
			Profile:       ProfileIntGenISISB,
			TargetEq8Bits: 0,
			LVCSNCols:     fast.LVCSNCols,
			MaxNLeaves:    4096,
			Issuance:      fast,
			Showing:       fast,
			Notes:         []string{"Use only for local correctness and profiling; soundness is intentionally low."},
		},
		IntGenISISPresetFast96: {
			Name:              IntGenISISPresetFast96,
			Description:       "profile-A N=256 runtime-focused measured preset; B=4 remeasurement falls below 96 bits",
			Profile:           ProfileIntGenISISA,
			TargetEq8Bits:     0,
			TargetTheoremBits: 96,
			SoundnessGate:     n256Fast96.SoundnessGate,
			LVCSNCols:         n256Fast96.LVCSNCols,
			MaxNLeaves:        n256Fast96.NLeaves,
			Issuance:          n256Fast96Issuance,
			Showing:           n256Fast96,
			Notes: []string{
				"Promoted from the transcript-focused runtime96-deep search with max showing transcript bytes 25000.",
				"B=4 remeasurement showing snapshot: paper_transcript_bytes=29039, proof_bytes=62859, dQ=427, theorem_total_bits=93.81, proving_ms≈2569, verification_ms≈798.",
				"B=4 remeasurement issuance snapshot: paper_transcript_bytes=23157, theorem_total_bits=93.81.",
				"Targeted low-leaf check accepted nleaves=11546 and rejected all candidates under nleaves=11545 in the narrowed 25 KiB grid.",
			},
		},
		IntGenISISPresetSW96LVCS32: mk(IntGenISISPresetSW96LVCS32, "profile-B 96-bit Eq. (8) seed with lvcs_ncols=32", 96, 32, 65536, show96LVCS32),
		IntGenISISPresetSW96LVCS64: {
			Name:              IntGenISISPresetSW96LVCS64,
			Description:       "profile-B compact 96-bit Theorem 9 default with V2 projection and R11/L4 shortness",
			Profile:           ProfileIntGenISISB,
			TargetEq8Bits:     0,
			TargetTheoremBits: 96,
			SoundnessGate:     "theorem9_grinding",
			LVCSNCols:         show96LVCS64.LVCSNCols,
			MaxNLeaves:        65536,
			Issuance:          show96LVCS64Issuance,
			Showing:           show96LVCS64,
			Notes: []string{
				"Promoted as the compact default after V2 projection and R11/L4 retuning.",
				"Pass criterion is SmallWood Theorem 9 with kappa4=6; raw Eq. (8) showing bits are intentionally below 96.",
				"B=4 remeasurement showing snapshot: paper_transcript_bytes=34006, proof_bytes=83350, dQ=482, theorem_total_bits=96.50, raw Eq. (8)=91.38.",
			},
		},
		IntGenISISPresetSW96LVCS128: mk(IntGenISISPresetSW96LVCS128, "profile-B 96-bit Eq. (8) seed with lvcs_ncols=128", 96, 128, 65536, show96LVCS128),
		IntGenISISPresetSW128LVCS32: mk(IntGenISISPresetSW128LVCS32, "profile-B 128-bit Eq. (8) seed with lvcs_ncols=32", 128, 32, 65536, show128LVCS32),
		IntGenISISPresetSW128LVCS64: {
			Name:              IntGenISISPresetSW128LVCS64,
			Description:       "profile-B compact 128-bit Theorem 9 default with V2 projection and R11/L4 shortness",
			Profile:           ProfileIntGenISISB,
			TargetEq8Bits:     0,
			TargetTheoremBits: 128,
			SoundnessGate:     "theorem9_grinding",
			LVCSNCols:         show128LVCS64.LVCSNCols,
			MaxNLeaves:        262144,
			Issuance:          show128LVCS64Issuance,
			Showing:           show128LVCS64,
			Notes: []string{
				"Promoted from the projected 128-bit tuning frontier after V2 projection and R11/L4 retuning.",
				"Pass criterion is SmallWood Theorem 9 with kappa={6,0,0,11}; raw Eq. (8) showing bits are intentionally below 128.",
				"B=4 remeasurement showing snapshot: paper_transcript_bytes=40042, proof_bytes=102015, dQ=482, theorem_total_bits=128.01, raw Eq. (8)=117.79.",
				"A smaller 36694-byte research variant used nleaves=180000, eta=58, kappa4=16, but had substantially higher proving time.",
			},
		},
		IntGenISISPresetSW128LVCS128: mk(IntGenISISPresetSW128LVCS128, "profile-B 128-bit Eq. (8) seed with lvcs_ncols=128", 128, 128, 65536, show128LVCS128),
		IntGenISISPresetN256SW96: {
			Name:                IntGenISISPresetN256SW96,
			Description:         "profile-A N=256 96-bit measured viable-frontier preset",
			Profile:             ProfileIntGenISISA,
			TargetEq8Bits:       0,
			TargetTheoremBits:   96,
			SoundnessGate:       n256Show96.SoundnessGate,
			LVCSNCols:           n256Show96.LVCSNCols,
			MaxNLeaves:          n256Show96.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n256Issuance96,
			Showing:             n256Show96,
			Notes: []string{
				"N=256 preset promoted from measured viable-frontier candidate est_000514.",
				"B=4 remeasurement showing snapshot: paper_transcript_bytes=23427, proof_bytes=44623, dQ=222, theorem_total_bits=96.33, raw Eq. (8)=96.33.",
				"B=4 remeasurement issuance snapshot: paper_transcript_bytes=16377, committed_cols=48, theorem_total_bits=96.33.",
				"Uses the same ring-tail-key bounded-range B=4 semantic layout as N=512: m in [0,N-8), key in [N-8,N).",
			},
		},
		IntGenISISPresetN256SW128: {
			Name:                IntGenISISPresetN256SW128,
			Description:         "profile-A N=256 128-bit measured zero-kappa preset",
			Profile:             ProfileIntGenISISA,
			TargetEq8Bits:       0,
			TargetTheoremBits:   128,
			SoundnessGate:       n256Show128.SoundnessGate,
			LVCSNCols:           n256Show128.LVCSNCols,
			MaxNLeaves:          n256Show128.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n256Issuance128,
			Showing:             n256Show128,
			Notes: []string{
				"N=256 128-bit preset promoted from measured focused-sweep candidate est_490949.",
				"B=4 remeasurement showing snapshot: paper_transcript_bytes=26001, proof_bytes=63126, dQ=391, theorem_total_bits=125.56, raw Eq. (8)=125.56.",
				"B=4 remeasurement issuance snapshot: paper_transcript_bytes=19673, committed_cols=32, theorem_total_bits=125.56.",
				"B=4 measured combined paper transcript bytes: 45674.",
				"Uses the same ring-tail-key bounded-range B=4 semantic layout as N=512: m in [0,N-8), key in [N-8,N).",
			},
		},
		IntGenISISPresetN1024SW96: {
			Name:                IntGenISISPresetN1024SW96,
			Description:         "profile-C N=1024 ternary 96-bit sweep seed",
			Profile:             ProfileIntGenISISC,
			TargetEq8Bits:       0,
			TargetTheoremBits:   96,
			SoundnessGate:       n1024Show96.SoundnessGate,
			LVCSNCols:           n1024Show96.LVCSNCols,
			MaxNLeaves:          n1024Show96.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n1024Issuance96,
			Showing:             n1024Show96,
			Notes: []string{
				"N=1024 ternary seed uses profile-C B=1 and degree-3 live membership.",
				"Seed geometry is intentionally conservative; run sweep-intgenisis-n1024-ternary-deep before promoting a measured transcript frontier.",
			},
		},
		IntGenISISPresetN1024SW90SF: {
			Name:                IntGenISISPresetN1024SW90SF,
			Description:         "profile-C N=1024 ternary >96-bit strict small-field transcript preset",
			Profile:             ProfileIntGenISISC,
			TargetEq8Bits:       0,
			TargetTheoremBits:   96,
			SoundnessGate:       n1024Show90SF.SoundnessGate,
			LVCSNCols:           n1024Show90SF.LVCSNCols,
			MaxNLeaves:          n1024Show90SF.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n1024Issuance90SF,
			Showing:             n1024Show90SF,
			Notes: []string{
				"Promoted from the N=1024 profile-C strict small-field rho=1 ell'=1 transcript sweep as the compact >96-bit live preset while retaining the sw90 preset alias.",
				"W-residual showing is promoted as the default projection: project_u_digits_y_w_residual_v5 keeps digit-only U and replaces committed mu_sig/x0 hats by one committed W residual.",
				"Live snapshot: paper_transcript_bytes=26419, theorem_total_bits=96.15, rows=471, rows_block=11, eta=40, kappa={0,0,6,11}, dQ=373, DDECS=49.",
				"Live buckets: q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=4640/4302/7207/0/1830/0/6783/1113.",
				"M/s/e pack2 is promoted only for profile-C ternary B=1; bounded-range B>1 compression remains rejected.",
				"Strict smallfield live mode opens DECS rows only at sampled tail points; VBar carries mask-coordinate LVCS targets.",
				"Uses smallfield_2025_1085_v1 only for showing; issuance remains dense-compatible while sharing the security tuple.",
			},
		},
		IntGenISISPresetN1024SW115SF: {
			Name:                IntGenISISPresetN1024SW115SF,
			Description:         "profile-C N=1024 ternary >115-bit strict small-field transcript preset",
			Profile:             ProfileIntGenISISC,
			TargetEq8Bits:       0,
			TargetTheoremBits:   115,
			SoundnessGate:       n1024Show115SF.SoundnessGate,
			LVCSNCols:           n1024Show115SF.LVCSNCols,
			MaxNLeaves:          n1024Show115SF.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n1024Issuance115SF,
			Showing:             n1024Show115SF,
			Notes: []string{
				"Promoted from the zero-grinding strict small-field rho=1 ell'=1 architecture sweep as the balanced-fast >115-bit showing preset.",
				"Live showing snapshot: paper_transcript_bytes=38693, theorem_total_bits=116.24, prove_ms=3844.77, verify_ms=445.99, rows=503, rows_block=12, eta=43, kappa={0,0,0,0}, dQ=471, DDECS=50.",
				"Live showing buckets: q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=8211/4517/10896/0/2322/0/10043/2160.",
				"Previous compact zero-grinding point lvcs=36, eta=41, ell=8, nleaves=839680 was about 37842 bytes but substantially slower; this preset trades roughly +851 bytes for much lower showing time and leaf count.",
				"Issuance remains on the prior validated 115-bit baseline tuple; the balanced-fast retune applies to showing only.",
				"Strict smallfield live mode opens DECS rows only at sampled tail points; VBar carries mask-coordinate LVCS targets.",
				"This preset intentionally targets 115 theorem bits and must not replace n1024-sw120-smallfield.",
			},
		},
		IntGenISISPresetN1024SW120SF: {
			Name:                IntGenISISPresetN1024SW120SF,
			Description:         "profile-C N=1024 ternary >120-bit strict small-field transcript preset",
			Profile:             ProfileIntGenISISC,
			TargetEq8Bits:       0,
			TargetTheoremBits:   120,
			SoundnessGate:       n1024Show120SF.SoundnessGate,
			LVCSNCols:           n1024Show120SF.LVCSNCols,
			MaxNLeaves:          n1024Show120SF.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n1024Issuance120SF,
			Showing:             n1024Show120SF,
			Notes: []string{
				"Promoted from the N=1024 profile-C strict small-field rho=1 ell'=1 transcript sweep as the compact >120-bit preset.",
				"Estimator snapshot: showing_bytes=37450, theorem_total_bits=120.35, dQ=311, DDECS=60, q/r/pdecs/mdecs/auth/tapes/vtargets/barsets=5410/6763/9432/1171/691/144/11678/2049.",
				"Strict smallfield live mode opens DECS rows only at sampled tail points; VBar carries mask-coordinate LVCS targets.",
				"Uses smallfield_2025_1085_v1 only for showing; issuance remains dense-compatible while sharing the security tuple.",
				"The smaller compression=1 research row is not promoted because live M/s/e compression is still rejected by the bounded-range showing surface.",
			},
		},
		IntGenISISPresetN1024SW128: {
			Name:                IntGenISISPresetN1024SW128,
			Description:         "profile-C N=1024 strict smallfield compact 128-bit candidate",
			Profile:             ProfileIntGenISISC,
			TargetEq8Bits:       0,
			TargetTheoremBits:   128,
			SoundnessGate:       n1024Show128.SoundnessGate,
			LVCSNCols:           n1024Show128.LVCSNCols,
			MaxNLeaves:          n1024Show128.NLeaves,
			ResearchLargeDomain: true,
			Issuance:            n1024Issuance128,
			Showing:             n1024Show128,
			Notes: []string{
				"Promoted from the strict smallfield N=1024 profile-C route sweep as the compact moderate-grinding candidate.",
				"Strict smallfield live shape: rho=1, ell'=1, smallfield_2025_1085_v1, digit-only U projection, R11/L4, M/s/e compression level 1.",
				"Live showing snapshot: paper_transcript_bytes=35991, prove_ms≈4625, verify_ms≈540, theorem_total_bits≈125.47 under the current 16-byte DECS collision cap.",
				"With 256-bit collision-space accounting, the same round terms give about 128.33 theorem bits; do not claim full 128-bit live theorem security until collision accounting/protocol material is updated.",
			},
		},
	}
	return reg
}
