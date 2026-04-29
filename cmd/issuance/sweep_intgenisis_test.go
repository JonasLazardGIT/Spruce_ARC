package main

import (
	"strings"
	"testing"

	"vSIS-Signature/credential"
)

func TestSweepIntGenISISPackingGrids(t *testing.T) {
	tests := map[string][]int{
		"pack64":   {64},
		"pack128":  {128},
		"pack256":  {256},
		"packwide": {64, 128, 256},
	}
	for name, wantNCols := range tests {
		t.Run(name, func(t *testing.T) {
			g, err := sweepIntGenISISGridFor(name)
			if err != nil {
				t.Fatalf("grid %s: %v", name, err)
			}
			if g.Name != name {
				t.Fatalf("grid name=%q want %q", g.Name, name)
			}
			if !sameInts(g.NCols, wantNCols) {
				t.Fatalf("ncols=%v want %v", g.NCols, wantNCols)
			}
			if g.EtaSlack != 4 {
				t.Fatalf("eta slack=%d want deep-style 4", g.EtaSlack)
			}
			if g.MaxEta != 128 {
				t.Fatalf("max eta=%d want deep-style 128", g.MaxEta)
			}
			if len(g.Families) <= 21 {
				t.Fatalf("families=%d, packing grids should inherit deep families", len(g.Families))
			}
			if len(g.Ell) == 0 || g.Ell[len(g.Ell)-1] != 32 {
				t.Fatalf("ell coverage=%v, want deep coverage through 32", g.Ell)
			}
			for _, ncols := range g.NCols {
				if 512%ncols != 0 {
					t.Fatalf("ncols=%d must divide profile-B ring degree 512", ncols)
				}
				hasLVCS := false
				for _, lvcs := range g.LVCSNCols {
					if lvcs >= ncols {
						hasLVCS = true
						break
					}
				}
				if !hasLVCS {
					t.Fatalf("grid %s has no lvcs_ncols >= ncols=%d", name, ncols)
				}
			}
		})
	}
}

func TestSweepIntGenISISRejectsUnsupportedPack96(t *testing.T) {
	_, err := sweepIntGenISISGridFor("pack96")
	if err == nil {
		t.Fatal("pack96 unexpectedly succeeded")
	}
	msg := err.Error()
	for _, want := range []string{"96", "512", "not divisible"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("pack96 error %q missing %q", msg, want)
		}
	}
}

func TestSweepIntGenISISAnalyticDQUsesTernaryAndShortnessDegree(t *testing.T) {
	issuance := intGenISISTuning{NCols: 32, Ell: 10}
	if got, want := sweepAnalyticDQ(issuance, "issuance"), sweepComputeDQFromDegrees(3, 1, 32, 10); got != want {
		t.Fatalf("issuance dQ=%d want %d", got, want)
	}
	showing := intGenISISTuning{NCols: 32, Ell: 10, SigShortnessRadix: 11, SigShortnessDigits: 4}
	if got, want := sweepAnalyticDQ(showing, "showing"), sweepComputeDQFromDegrees(11, 2, 32, 10); got != want {
		t.Fatalf("showing R11/L4 dQ=%d want %d", got, want)
	}
	showing.SigShortnessRadix = 5
	showing.SigShortnessDigits = 6
	if got, want := sweepAnalyticDQ(showing, "showing"), sweepComputeDQFromDegrees(5, 2, 32, 10); got != want {
		t.Fatalf("showing R5/L6 dQ=%d want %d", got, want)
	}
}

func TestSweepIntGenISISPresetGridsFixLVCSAndValidNCols(t *testing.T) {
	tests := []struct {
		target    float64
		lvcs      int
		wantNCols []int
	}{
		{target: 96, lvcs: 32, wantNCols: []int{16, 32}},
		{target: 96, lvcs: 64, wantNCols: []int{32, 64}},
		{target: 128, lvcs: 128, wantNCols: []int{32, 64, 128}},
	}
	for _, tt := range tests {
		t.Run(intGenISISPresetTrackID(tt.target, tt.lvcs), func(t *testing.T) {
			g, err := sweepIntGenISISPresetGrid(tt.target, tt.lvcs)
			if err != nil {
				t.Fatalf("preset grid: %v", err)
			}
			if !sameInts(g.NCols, tt.wantNCols) {
				t.Fatalf("ncols=%v want %v", g.NCols, tt.wantNCols)
			}
			if !sameInts(g.LVCSNCols, []int{tt.lvcs}) {
				t.Fatalf("lvcs_ncols=%v want [%d]", g.LVCSNCols, tt.lvcs)
			}
			for _, ncols := range g.NCols {
				if 512%ncols != 0 {
					t.Fatalf("generated invalid ncols=%d", ncols)
				}
				if ncols > tt.lvcs {
					t.Fatalf("ncols=%d exceeds fixed lvcs=%d", ncols, tt.lvcs)
				}
			}
			for _, mode := range g.PRFModes {
				if mode != "direct_auth" {
					t.Fatalf("preset grid PRF modes=%v want direct_auth only", g.PRFModes)
				}
			}
		})
	}
}

func TestSweepIntGenISISPresetAnalyticSmoke(t *testing.T) {
	profile := credential.PrimaryIntGenISISProfile()
	grid, err := sweepIntGenISISPresetGrid(96, 32)
	if err != nil {
		t.Fatalf("preset grid: %v", err)
	}
	cands := sweepIntGenISISGenerateCandidates(profile, 98, grid, 4, 65536)
	if len(cands) == 0 {
		t.Fatal("preset analytic smoke found no 96-bit lvcs32 candidates")
	}
	sweepPopulateAnalyticBudgets(profile, cands)
	for _, cand := range cands {
		if cand.Showing.LVCSNCols != 32 || cand.Issuance.LVCSNCols != 32 {
			t.Fatalf("candidate escaped fixed lvcs=32: issuance=%d showing=%d", cand.Issuance.LVCSNCols, cand.Showing.LVCSNCols)
		}
		if cand.Issuance.NCols == 96 || cand.Showing.NCols == 96 {
			t.Fatalf("candidate used unsupported ncols=96: %+v", cand)
		}
		if cand.AnalyticIssuance.Eq8TotalBits < 98 || cand.AnalyticShowing.Eq8TotalBits < 98 {
			t.Fatalf("candidate below threshold: issuance=%.2f showing=%.2f", cand.AnalyticIssuance.Eq8TotalBits, cand.AnalyticShowing.Eq8TotalBits)
		}
	}
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
