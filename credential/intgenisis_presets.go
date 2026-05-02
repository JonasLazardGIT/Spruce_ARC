package credential

import (
	"fmt"
	"sort"
	"strings"
)

const (
	IntGenISISPreset96Bit        = "96bit"
	IntGenISISPreset120BitSF     = "120bitsf"
	IntGenISISPresetFastLocal    = "fast-local"
	IntGenISISPresetSW96LVCS32   = "sw96-lvcs32"
	IntGenISISPresetSW96LVCS64   = "sw96-lvcs64"
	IntGenISISPresetSW96LVCS128  = "sw96-lvcs128"
	IntGenISISPresetSW128LVCS32  = "sw128-lvcs32"
	IntGenISISPresetSW128LVCS64  = "sw128-lvcs64"
	IntGenISISPresetSW128LVCS128 = "sw128-lvcs128"
	IntGenISISPresetN256SW96     = "n256-sw96"
	IntGenISISPresetN256SW128    = "n256-sw128"
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
		CompressedRows:     1,
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
		CompressedRows:     1,
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
		CompressedRows:     1,
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
		CompressedRows:     1,
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
		CompressedRows:     1,
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
				"Measured profile-A showing snapshot: paper_transcript_bytes=22116, dQ=222, theorem_total_bits=96.33, raw Eq. (8)=96.33.",
				"Measured profile-A issuance snapshot: paper_transcript_bytes=13652, committed_cols=48, theorem_total_bits=98.27.",
				"Measured combined paper transcript bytes: 35768.",
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
				"Measured showing snapshot: paper_transcript_bytes=25232, dQ=231, theorem_total_bits=120.01, raw Eq. (8)=120.01.",
				"Measured issuance snapshot: paper_transcript_bytes=14822, committed_cols=36, theorem_total_bits=120.01.",
				"Measured combined paper transcript bytes: 40054.",
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
				"Measured showing snapshot: paper_transcript_bytes=31232, dQ=482, VTargets=4420, Pdecs=8323, Q=7189, R=8229, theorem_total_bits=96.50.",
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
				"Measured showing snapshot: paper_transcript_bytes=36938, dQ=482, VTargets=5155, Pdecs=9325, Q=8404, R=10330, theorem_total_bits=128.01.",
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
				"Measured showing snapshot: paper_transcript_bytes=22116, dQ=222, theorem_total_bits=96.33, raw Eq. (8)=96.33.",
				"Measured issuance snapshot: paper_transcript_bytes=13652, committed_cols=48, theorem_total_bits=98.27.",
				"Uses the same ring-tail-key ternary semantic layout as N=512: m in [0,N-8), key in [N-8,N).",
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
				"Measured showing snapshot: paper_transcript_bytes=23100, dQ=231, theorem_total_bits=131.49, raw Eq. (8)=131.49.",
				"Measured issuance snapshot: paper_transcript_bytes=15438, committed_cols=32, theorem_total_bits=131.75.",
				"Measured combined paper transcript bytes: 38538.",
				"Uses the same ring-tail-key ternary semantic layout as N=512: m in [0,N-8), key in [N-8,N).",
			},
		},
	}
	return reg
}
