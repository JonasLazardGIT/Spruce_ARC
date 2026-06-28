package main

import (
	"math"
	"testing"

	"vSIS-Signature/credential"
)

type securityProfileSmallWoodSearchSeed struct {
	SecurityProfile string   `json:"security_profile"`
	TargetBits      float64  `json:"target_bits"`
	Eta             int      `json:"eta"`
	Kappa           [4]int   `json:"kappa"`
	LVCSNCols       int      `json:"lvcs_ncols"`
	NLeaves         int      `json:"nleaves"`
	Theta           int      `json:"theta"`
	Ell             int      `json:"ell"`
	LVCSWindow      []int    `json:"lvcs_window,omitempty"`
	EtaWindow       []int    `json:"eta_window,omitempty"`
	ThetaWindow     []int    `json:"theta_window,omitempty"`
	EllWindow       []int    `json:"ell_window,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

func deriveSecurityProfileSmallWoodSearchSeed(spec credential.IntGenISISSecurityProfileSpec, relation benchmarkIntGenISISRelationReport, base intGenISISTuning) securityProfileSmallWoodSearchSeed {
	etaFloor := int(math.Ceil(spec.TargetBits / math.Log2(float64(credential.IntGenISISSharedModulusQ))))
	if etaFloor < 1 {
		etaFloor = 1
	}
	eta := maxIntLocal(base.Eta, etaFloor)
	theta := maxIntLocal(base.Theta, 1)
	ell := maxIntLocal(base.Ell, 1)
	lvcs := base.LVCSNCols
	if lvcs <= 0 {
		lvcs = base.NCols
	}
	if lvcs <= 0 {
		lvcs = 1
	}
	if relation.LogicalRows > 0 && relation.DQ > 0 && base.NCols > 0 {
		continuous := math.Sqrt(float64(ell) * (float64(relation.LogicalRows*(base.NCols+theta)) + float64(relation.DQ*theta)) / float64(eta+theta))
		if continuous > 1 {
			lvcs = int(math.Round(continuous))
		}
	}
	nleaves := base.NLeaves
	if nleaves <= 0 {
		nleaves = 1
	}
	return securityProfileSmallWoodSearchSeed{
		SecurityProfile: spec.Label,
		TargetBits:      spec.TargetBits,
		Eta:             eta,
		Kappa:           base.Kappa,
		LVCSNCols:       lvcs,
		NLeaves:         nleaves,
		Theta:           theta,
		Ell:             ell,
		LVCSWindow:      positiveWindow(lvcs, 2),
		EtaWindow:       positiveWindow(eta, 1),
		ThetaWindow:     positiveWindow(theta, 1),
		EllWindow:       positiveWindow(ell, 1),
		Notes: []string{
			"internal search seed only; does not alter maintained preset knobs",
			"eta floor uses target/log2(q) before exact SmallWood verification",
		},
	}
}

func TestDeriveSecurityProfileSmallWoodSearchSeedKeepsPresetKnobsAsFloor(t *testing.T) {
	spec, ok := credential.LookupIntGenISISSecurityProfile("BQ32-96")
	if !ok {
		t.Fatal("missing BQ32-96 profile")
	}
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	base := intGenISISTuningFromPresetSpec(preset.Showing)
	seed := deriveSecurityProfileSmallWoodSearchSeed(spec, benchmarkIntGenISISRelationReport{
		LogicalRows:      2048,
		ParallelDegree:   11,
		AggregatedDegree: 2,
		DQ:               1200,
	}, base)
	if seed.SecurityProfile != "BQ32-96" {
		t.Fatalf("seed profile=%q", seed.SecurityProfile)
	}
	if seed.Eta < base.Eta || seed.Theta < 1 || seed.Ell < 1 || seed.LVCSNCols <= 0 || seed.NLeaves <= 0 {
		t.Fatalf("bad seed: %+v base=%+v", seed, base)
	}
	if len(seed.LVCSWindow) == 0 || len(seed.EtaWindow) == 0 {
		t.Fatalf("missing search windows: %+v", seed)
	}
}

func positiveWindow(center, radius int) []int {
	out := make([]int, 0, 2*radius+1)
	for v := center - radius; v <= center+radius; v++ {
		if v > 0 {
			out = append(out, v)
		}
	}
	return out
}

func maxIntLocal(a, b int) int {
	if a > b {
		return a
	}
	return b
}
