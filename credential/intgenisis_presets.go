package credential

import (
	"fmt"
	"sort"
	"strings"
)

const (
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

	n256Show96 := show96LVCS64
	n256Show96.NCols = 32
	n256Show96.LVCSNCols = 70
	n256Show96.NLeaves = 42000
	n256Show96.Eta = 47
	n256Show96.Theta = 3
	n256Show96.Rho = 2
	n256Show96.Ell = 10
	n256Show96.EllPrime = 2
	n256Show96.Kappa = [4]int{0, 0, 0, 6}
	n256Show96.SigShortnessRadix = 11
	n256Show96.SigShortnessDigits = 4
	n256Show96.CompressedRows = 1
	n256Show96.ReplayProjection = "project_u_y_hat_and_y_view_v2"
	n256Show96.TargetTheoremBits = 96
	n256Show96.TargetEq8Bits = 0
	n256Show96.SoundnessGate = "theorem9_grinding"
	n256Issuance96 := n256Show96
	n256Issuance96.PRFCompanionMode = ""
	n256Issuance96.CheckpointSamples = 0
	n256Issuance96.SigShortnessRadix = 0
	n256Issuance96.SigShortnessDigits = 0
	n256Issuance96.CompressedRows = 0
	n256Issuance96.ReplayProjection = ""

	n256Show128 := show128LVCS64
	n256Show128.NCols = 32
	n256Show128.LVCSNCols = 70
	n256Show128.NLeaves = 262144
	n256Show128.Eta = 59
	n256Show128.Theta = 7
	n256Show128.Rho = 1
	n256Show128.Ell = 10
	n256Show128.EllPrime = 1
	n256Show128.Kappa = [4]int{6, 0, 0, 11}
	n256Show128.SigShortnessRadix = 11
	n256Show128.SigShortnessDigits = 4
	n256Show128.CompressedRows = 1
	n256Show128.ReplayProjection = "project_u_y_hat_and_y_view_v2"
	n256Show128.TargetTheoremBits = 128
	n256Show128.TargetEq8Bits = 0
	n256Show128.SoundnessGate = "theorem9_grinding"
	n256Issuance128 := n256Show128
	n256Issuance128.PRFCompanionMode = ""
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
			Name:              IntGenISISPresetN256SW96,
			Description:       "profile-A N=256 96-bit candidate with V2 projection and R11/L4 shortness",
			Profile:           ProfileIntGenISISA,
			TargetEq8Bits:     0,
			TargetTheoremBits: 96,
			SoundnessGate:     "theorem9_grinding",
			LVCSNCols:         n256Show96.LVCSNCols,
			MaxNLeaves:        65536,
			Issuance:          n256Issuance96,
			Showing:           n256Show96,
			Notes: []string{
				"N=256 candidate seed; promote only after parameter_search/run_intgenisis_degree256.sage and measured e2e verification pass.",
				"Uses the same ring-tail-key ternary semantic layout as N=512: m in [0,N-8), key in [N-8,N).",
			},
		},
		IntGenISISPresetN256SW128: {
			Name:                IntGenISISPresetN256SW128,
			Description:         "profile-A N=256 128-bit candidate with V2 projection and R11/L4 shortness",
			Profile:             ProfileIntGenISISA,
			TargetEq8Bits:       0,
			TargetTheoremBits:   128,
			SoundnessGate:       "theorem9_grinding",
			LVCSNCols:           n256Show128.LVCSNCols,
			MaxNLeaves:          262144,
			ResearchLargeDomain: true,
			Issuance:            n256Issuance128,
			Showing:             n256Show128,
			Notes: []string{
				"N=256 128-bit candidate seed; not promoted as final until parameter search and measured e2e pass.",
				"Uses the same ring-tail-key ternary semantic layout as N=512: m in [0,N-8), key in [N-8,N).",
			},
		},
	}
	return reg
}
