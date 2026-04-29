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
	TargetEq8Bits      float64 `json:"target_eq8_bits,omitempty"`
}

// IntGenISISPreset describes a named issuance/showing parameter set. The
// secure entries are maintained as practical seeds; preset sweeps can emit
// measured replacements as JSON before promotion into this registry.
type IntGenISISPreset struct {
	Name                string                 `json:"name"`
	Description         string                 `json:"description"`
	Profile             string                 `json:"profile"`
	TargetEq8Bits       float64                `json:"target_eq8_bits"`
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
	show128LVCS64.LVCSNCols = 64
	show128LVCS64.NLeaves = 48384
	show128LVCS64.Eta = 49
	show128LVCS64.Ell = 14
	show128LVCS128 := show128LVCS32
	show128LVCS128.LVCSNCols = 128
	show128LVCS128.NLeaves = 57344
	show128LVCS128.Eta = 79
	show128LVCS128.Ell = 15

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
		IntGenISISPresetSW96LVCS32:   mk(IntGenISISPresetSW96LVCS32, "profile-B 96-bit Eq. (8) seed with lvcs_ncols=32", 96, 32, 65536, show96LVCS32),
		IntGenISISPresetSW96LVCS64:   mk(IntGenISISPresetSW96LVCS64, "profile-B 96-bit Eq. (8) seed with lvcs_ncols=64", 96, 64, 65536, show96LVCS64),
		IntGenISISPresetSW96LVCS128:  mk(IntGenISISPresetSW96LVCS128, "profile-B 96-bit Eq. (8) seed with lvcs_ncols=128", 96, 128, 65536, show96LVCS128),
		IntGenISISPresetSW128LVCS32:  mk(IntGenISISPresetSW128LVCS32, "profile-B 128-bit Eq. (8) seed with lvcs_ncols=32", 128, 32, 65536, show128LVCS32),
		IntGenISISPresetSW128LVCS64:  mk(IntGenISISPresetSW128LVCS64, "profile-B 128-bit Eq. (8) seed with lvcs_ncols=64", 128, 64, 65536, show128LVCS64),
		IntGenISISPresetSW128LVCS128: mk(IntGenISISPresetSW128LVCS128, "profile-B 128-bit Eq. (8) seed with lvcs_ncols=128", 128, 128, 65536, show128LVCS128),
	}
	return reg
}
