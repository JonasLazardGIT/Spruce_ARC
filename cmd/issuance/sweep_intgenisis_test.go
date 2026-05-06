package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
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

func TestSweepIntGenISISAnalyticDQUsesB4RangeAndShortnessDegree(t *testing.T) {
	issuance := intGenISISTuning{NCols: 32, Ell: 10}
	if got, want := sweepAnalyticDQ(issuance, "issuance"), sweepComputeDQFromDegrees(9, 1, 32, 10); got != want {
		t.Fatalf("issuance dQ=%d want %d", got, want)
	}
	if got, want := sweepAnalyticDQForBound(issuance, "issuance", 1), sweepComputeDQFromDegrees(3, 1, 32, 10); got != want {
		t.Fatalf("ternary issuance dQ=%d want %d", got, want)
	}
	showing := intGenISISTuning{NCols: 32, Ell: 10, SigShortnessRadix: 11, SigShortnessDigits: 4}
	if got, want := sweepAnalyticDQ(showing, "showing"), sweepComputeDQFromDegrees(11, 2, 32, 10); got != want {
		t.Fatalf("showing R11/L4 dQ=%d want %d", got, want)
	}
	showing.SigShortnessRadix = 5
	showing.SigShortnessDigits = 6
	if got, want := sweepAnalyticDQ(showing, "showing"), sweepComputeDQFromDegrees(9, 2, 32, 10); got != want {
		t.Fatalf("showing R5/L6 dQ=%d want %d", got, want)
	}
	if got, want := sweepAnalyticDQForBound(showing, "showing", 1), sweepComputeDQFromDegrees(5, 2, 32, 10); got != want {
		t.Fatalf("ternary showing R5/L6 dQ=%d want %d", got, want)
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

func TestSweepIntGenISISEstimateValidNColsByProfile(t *testing.T) {
	a, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISA)
	if !ok {
		t.Fatal("missing profile A")
	}
	b := credential.PrimaryIntGenISISProfile()
	for _, tc := range []struct {
		profile credential.IntGenISISProfile
		ncols   int
		valid   bool
	}{
		{a, 8, true},
		{a, 256, true},
		{a, 512, false},
		{a, 96, false},
		{b, 8, true},
		{b, 512, true},
		{b, 96, false},
	} {
		t.Run(fmt.Sprintf("%s/%d", tc.profile.Name, tc.ncols), func(t *testing.T) {
			tuning := intGenISISTuning{
				NCols:              tc.ncols,
				LVCSNCols:          maxIntMain(tc.ncols, 32),
				NLeaves:            4096,
				Eta:                8,
				Theta:              1,
				Rho:                1,
				Ell:                4,
				EllPrime:           4,
				SigShortnessRadix:  11,
				SigShortnessDigits: 4,
				ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
			}
			_, err := estimateIntGenISISGeometry(tc.profile, tuning, "showing")
			if tc.valid && err != nil {
				t.Fatalf("valid ncols rejected: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("invalid ncols=%d accepted for N=%d", tc.ncols, tc.profile.N)
			}
		})
	}
}

func TestSweepIntGenISISEstimateDefaultGridIsPrePruned(t *testing.T) {
	g, err := sweepIntGenISISEstimateGridFor("estimate-deep")
	if err != nil {
		t.Fatalf("estimate grid: %v", err)
	}
	if !sameInts(g.NCols, []int{8, 16, 32, 64, 128}) {
		t.Fatalf("ncols=%v want tight divisor set through 128", g.NCols)
	}
	if containsIntTest(g.NCols, 96) || containsIntTest(g.NCols, 256) || containsIntTest(g.NCols, 512) {
		t.Fatalf("default estimate grid includes dominated or invalid ncols: %v", g.NCols)
	}
	if maxIntTest(g.LVCSNCols) > 256 {
		t.Fatalf("lvcs_ncols max=%d want <=256", maxIntTest(g.LVCSNCols))
	}
	if maxIntTest(g.Ell) > 32 {
		t.Fatalf("ell max=%d want <=32", maxIntTest(g.Ell))
	}
	if maxIntTest(g.NLeavesBase) > 262144 {
		t.Fatalf("nleaves base max=%d want <=262144", maxIntTest(g.NLeavesBase))
	}
	if !sameInts(g.Compression, []int{0}) {
		t.Fatalf("compression levels=%v want [0]", g.Compression)
	}
	for _, fam := range g.Families {
		if fam.Theta <= 0 || fam.Rho <= 0 || fam.EllPrime <= 0 {
			t.Fatalf("invalid family %+v", fam)
		}
		if fam.Theta > 1 && fam.Theta*fam.Rho < 5 {
			t.Fatalf("round-2-impossible theta>1 family survived pruning: %+v", fam)
		}
		if fam.Theta > 9 {
			t.Fatalf("high-theta dominated family survived pruning: %+v", fam)
		}
		if fam.Theta == 1 && (fam.Rho < 5 || fam.Rho > 7 || fam.EllPrime < 9 || fam.EllPrime > 13) {
			t.Fatalf("theta=1 family outside retained baseline window: %+v", fam)
		}
	}
	for _, fam := range []sweepIntGenISISFamily{
		{Theta: 7, Rho: 1, EllPrime: 1},
		{Theta: 2, Rho: 4, EllPrime: 4},
		{Theta: 3, Rho: 2, EllPrime: 3},
		{Theta: 1, Rho: 7, EllPrime: 13},
	} {
		if !containsFamilyTest(g.Families, fam) {
			t.Fatalf("default grid lost retained edge family %+v", fam)
		}
	}
}

func TestSweepIntGenISISEstimateRuntime96GridAndObjective(t *testing.T) {
	g, err := sweepIntGenISISEstimateGridFor("runtime96")
	if err != nil {
		t.Fatalf("runtime96 grid: %v", err)
	}
	if g.Name != sweepEstimateRuntime96Grid {
		t.Fatalf("grid name=%q want %q", g.Name, sweepEstimateRuntime96Grid)
	}
	if !containsIntTest(g.NLeavesBase, 2048) || !containsIntTest(g.NLeavesBase, 4096) {
		t.Fatalf("runtime grid missing low nleaves bases: %v", g.NLeavesBase)
	}
	if !containsIntTest(g.Ell, 48) || !containsIntTest(g.Ell, 64) {
		t.Fatalf("runtime grid missing high ell values for low-leaf round-4 security: %v", g.Ell)
	}
	if !sameInts(g.PRFGroups, []int{2}) || !sameInts(g.Checkpoints, []int{2}) {
		t.Fatalf("runtime grid PRF geometry groups=%v checkpoints=%v", g.PRFGroups, g.Checkpoints)
	}
	objective, err := normalizeSweepEstimateObjective("runtime-96")
	if err != nil {
		t.Fatalf("normalize objective: %v", err)
	}
	if objective != sweepEstimateObjectiveRuntime {
		t.Fatalf("objective=%q want %q", objective, sweepEstimateObjectiveRuntime)
	}
	score, logLeaves := sweepRuntimeScore(1000, 4096)
	if score != 12000 || logLeaves != 12 {
		t.Fatalf("runtime score/log=(%.2f,%.2f) want (12000,12)", score, logLeaves)
	}
}

func TestSweepIntGenISISEstimateTranscriptObjectiveSortsOnlyByBytes(t *testing.T) {
	objective, err := normalizeSweepEstimateObjective("transcript-only")
	if err != nil {
		t.Fatalf("normalize transcript objective: %v", err)
	}
	if objective != sweepEstimateObjectiveTranscript {
		t.Fatalf("objective=%q want %q", objective, sweepEstimateObjectiveTranscript)
	}
	smallerTranscript := sweepIntGenISISEstimateCandidate{
		ID:                     "small-transcript",
		CandidateTheoremBits:   96,
		ShowingTranscriptBytes: 1000,
		TotalTranscriptBytes:   5000,
		Showing:                intGenISISTuning{NLeaves: 65536},
	}
	largerTranscript := sweepIntGenISISEstimateCandidate{
		ID:                     "large-transcript",
		CandidateTheoremBits:   160,
		ShowingTranscriptBytes: 1200,
		TotalTranscriptBytes:   2000,
		Showing:                intGenISISTuning{NLeaves: 64},
	}
	selected := selectEstimateCandidates([]sweepIntGenISISEstimateCandidate{largerTranscript, smallerTranscript}, 1, objective)
	if len(selected) != 1 || selected[0].ID != "small-transcript" {
		t.Fatalf("transcript objective selected=%v want smallest showing transcript", selected)
	}
	if score := sweepEstimateObjectiveScore(objective, selected[0]); score != 1000 {
		t.Fatalf("transcript objective score=%.0f want showing bytes", score)
	}
}

func TestSweepIntGenISISEstimateRuntime96DeepGridBroadensAxes(t *testing.T) {
	base, err := sweepIntGenISISEstimateGridFor("runtime96")
	if err != nil {
		t.Fatalf("runtime96 grid: %v", err)
	}
	deep, err := sweepIntGenISISEstimateGridFor("runtime96-deep")
	if err != nil {
		t.Fatalf("runtime96-deep grid: %v", err)
	}
	if deep.Name != sweepEstimateRuntime96DeepGrid {
		t.Fatalf("deep grid name=%q want %q", deep.Name, sweepEstimateRuntime96DeepGrid)
	}
	if len(deep.Families) <= len(base.Families) || len(deep.LVCSNCols) <= len(base.LVCSNCols) || len(deep.Ell) <= len(base.Ell) || len(deep.NLeavesBase) <= len(base.NLeavesBase) {
		t.Fatalf("deep grid should broaden base axes: families %d/%d lvcs %d/%d ell %d/%d leaves %d/%d",
			len(deep.Families), len(base.Families), len(deep.LVCSNCols), len(base.LVCSNCols), len(deep.Ell), len(base.Ell), len(deep.NLeavesBase), len(base.NLeavesBase))
	}
	for _, want := range []int{768, 896} {
		if !containsIntTest(deep.NLeavesBase, want) {
			t.Fatalf("deep grid missing low nleaves base %d: %v", want, deep.NLeavesBase)
		}
	}
	if !containsIntTest(deep.Ell, 80) || !containsIntTest(deep.LVCSNCols, 160) {
		t.Fatalf("deep grid missing high ell/lvcs extensions: ell=%v lvcs=%v", deep.Ell, deep.LVCSNCols)
	}
	if !containsFamilyTest(deep.Families, sweepIntGenISISFamily{Theta: 1, Rho: 9, EllPrime: 15}) ||
		!containsFamilyTest(deep.Families, sweepIntGenISISFamily{Theta: 2, Rho: 5, EllPrime: 5}) {
		t.Fatalf("deep grid missing widened family coverage: %+v", deep.Families)
	}
	if !containsShortnessTest(deep.Shortness, sweepIntGenISISShortness{Radix: 9, Digits: 5}) {
		t.Fatalf("deep grid missing R9/L5 shortness: %+v", deep.Shortness)
	}
	if !sameInts(deep.Checkpoints, []int{2, 4}) {
		t.Fatalf("deep grid checkpoints=%v want [2 4]", deep.Checkpoints)
	}
	if deep.EtaSlack <= base.EtaSlack || deep.MaxEta <= base.MaxEta {
		t.Fatalf("deep grid eta window should exceed base: deep slack/max=%d/%d base=%d/%d", deep.EtaSlack, deep.MaxEta, base.EtaSlack, base.MaxEta)
	}
}

func TestSweepIntGenISISEstimateN1024TernaryDeepGrid(t *testing.T) {
	g, err := sweepIntGenISISEstimateGridFor("n1024-ternary-deep")
	if err != nil {
		t.Fatalf("n1024 ternary grid: %v", err)
	}
	if g.Name != sweepEstimateN1024TernaryDeepGrid {
		t.Fatalf("grid name=%q want %q", g.Name, sweepEstimateN1024TernaryDeepGrid)
	}
	for _, want := range []int{16, 32, 64, 128, 256, 1024} {
		if !containsIntTest(g.NCols, want) {
			t.Fatalf("n1024 grid missing ncols=%d: %v", want, g.NCols)
		}
	}
	if !containsIntTest(g.LVCSNCols, 1024) || !containsIntTest(g.NLeavesBase, 64) || !containsIntTest(g.NLeavesBase, 1054720) || !containsIntTest(g.Ell, 160) {
		t.Fatalf("n1024 grid missing broad transcript axes: lvcs=%v leaves=%v ell=%v", g.LVCSNCols, g.NLeavesBase, g.Ell)
	}
	if !containsIntTest(g.LVCSNCols, 57) || !containsIntTest(g.NLeavesBase, 950272) || !containsIntTest(g.Ell, 7) {
		t.Fatalf("n1024 grid missing refined transcript basin: lvcs=%v leaves=%v ell=%v", g.LVCSNCols, g.NLeavesBase, g.Ell)
	}
	if g.ExhaustiveNLeaves {
		t.Fatalf("n1024 transcript grid should not exhaust high nleaves bases by default")
	}
	if !sameInts(g.Compression, []int{0, 1, 2, 3, 4}) {
		t.Fatalf("n1024 ternary grid compression=%v want [0 1 2 3 4]", g.Compression)
	}
	if !sameInts(g.PRFGroups, []int{2, 5}) || !sameInts(g.Checkpoints, []int{1, 8}) {
		t.Fatalf("n1024 grid prf groups/checkpoints=%v/%v", g.PRFGroups, g.Checkpoints)
	}
	if !sameStrings(g.Projection, []string{PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2}) ||
		len(g.PRFModes) != 1 || g.PRFModes[0] != PIOP.PRFCompanionModeDirectAuth {
		t.Fatalf("n1024 grid projection/prf modes=%v/%v want coarse first-pass defaults", g.Projection, g.PRFModes)
	}
	if !containsFamilyTest(g.Families, sweepIntGenISISFamily{Theta: 1, Rho: 10, EllPrime: 18}) ||
		!containsFamilyTest(g.Families, sweepIntGenISISFamily{Theta: 2, Rho: 3, EllPrime: 4}) ||
		!containsFamilyTest(g.Families, sweepIntGenISISFamily{Theta: 12, Rho: 2, EllPrime: 3}) ||
		!containsFamilyTest(g.Families, sweepIntGenISISFamily{Theta: 24, Rho: 2, EllPrime: 3}) {
		t.Fatalf("n1024 grid missing widened family coverage")
	}
	if !containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 111, Digits: 2}) ||
		!containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 25, Digits: 3}) ||
		!containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 7, Digits: 5}) {
		t.Fatalf("n1024 grid missing expected shortness shapes: %+v", g.Shortness)
	}
	if len(g.Families) > 41 || len(g.NLeavesBase) > 17 || len(g.Ell) > 16 || len(g.LVCSNCols) > 24 {
		t.Fatalf("n1024 grid should stay bounded after refinement: families=%d leaves=%d ell=%d lvcs=%d", len(g.Families), len(g.NLeavesBase), len(g.Ell), len(g.LVCSNCols))
	}
}

func TestSweepIntGenISISEstimateN1024StrictSmallFieldGrid(t *testing.T) {
	g, err := sweepIntGenISISEstimateGridFor("n1024-strict-smallfield-deep")
	if err != nil {
		t.Fatalf("n1024 strict smallfield grid: %v", err)
	}
	if g.Name != sweepEstimateN1024StrictSmallFieldGrid {
		t.Fatalf("grid name=%q want %q", g.Name, sweepEstimateN1024StrictSmallFieldGrid)
	}
	if len(g.Families) == 0 {
		t.Fatal("strict smallfield grid has no families")
	}
	for _, fam := range g.Families {
		if fam.Theta <= 1 || fam.Rho != 1 || fam.EllPrime != 1 {
			t.Fatalf("strict smallfield family escaped canonical shape: %+v", fam)
		}
	}
	for _, want := range []sweepIntGenISISFamily{
		{Theta: 5, Rho: 1, EllPrime: 1},
		{Theta: 7, Rho: 1, EllPrime: 1},
		{Theta: 12, Rho: 1, EllPrime: 1},
		{Theta: 16, Rho: 1, EllPrime: 1},
	} {
		if !containsFamilyTest(g.Families, want) {
			t.Fatalf("strict smallfield grid missing family %+v", want)
		}
	}
	for _, want := range []int{32, 44, 52, 64, 128, 1024} {
		if !containsIntTest(g.LVCSNCols, want) {
			t.Fatalf("strict smallfield grid missing lvcs=%d: %v", want, g.LVCSNCols)
		}
	}
	if !containsIntTest(g.NLeavesBase, 116864) || !containsIntTest(g.NLeavesBase, 1054720) {
		t.Fatalf("strict smallfield grid missing known/high leaf probes: %v", g.NLeavesBase)
	}
	if !containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 7, Digits: 5}) ||
		!containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 25, Digits: 3}) ||
		!containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 3, Digits: 9}) {
		t.Fatalf("strict smallfield grid missing shortness probes: %+v", g.Shortness)
	}
	if !sameInts(g.Compression, []int{0, 1, 2}) {
		t.Fatalf("strict smallfield compression=%v want [0 1 2]", g.Compression)
	}
	if !sameStrings(g.Projection, []string{PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2}) ||
		len(g.PRFModes) != 1 || g.PRFModes[0] != PIOP.PRFCompanionModeDirectAuth {
		t.Fatalf("strict smallfield grid projection/prf modes=%v/%v", g.Projection, g.PRFModes)
	}
}

func TestSweepIntGenISISEstimateN1024TranscriptLeavesStayNearMinimum(t *testing.T) {
	g, err := sweepIntGenISISEstimateGridFor("n1024-ternary-deep")
	if err != nil {
		t.Fatalf("n1024 ternary grid: %v", err)
	}
	profile := credential.Ternary1024IntGenISISProfile()
	vals := sweepCachedNLeavesCandidates(profile, g, 16, 4, 1, 0, newSweepAnalyticCache())
	if !containsIntTest(vals, 64) {
		t.Fatalf("transcript nleaves=%v missing low 64", vals)
	}
	if containsIntTest(vals, int(profile.Q)-1) {
		t.Fatalf("transcript nleaves=%v should not include high q-1=%d unless required by the lower-bound search", vals, int(profile.Q)-1)
	}
	if got := sweepMaxNLeaves(profile, 0); got != int(profile.Q)-1 {
		t.Fatalf("uncapped max leaves=%d want q-1=%d", got, int(profile.Q)-1)
	}
}

func TestSweepIntGenISISEstimateN1024TernaryLowLeavesGrid(t *testing.T) {
	g, err := sweepIntGenISISEstimateGridFor("n1024-ternary-lowleaves")
	if err != nil {
		t.Fatalf("n1024 low-leaves grid: %v", err)
	}
	if g.Name != sweepEstimateN1024TernaryLowLeavesGrid {
		t.Fatalf("grid name=%q want %q", g.Name, sweepEstimateN1024TernaryLowLeavesGrid)
	}
	if !g.ExhaustiveNLeaves {
		t.Fatalf("low-leaves grid should preserve explicit low leaf probes")
	}
	for _, want := range []int{64, 1024, 262144, 393216} {
		if !containsIntTest(g.NLeavesBase, want) {
			t.Fatalf("low-leaves grid missing nleaves=%d: %v", want, g.NLeavesBase)
		}
	}
	if !containsIntTest(g.Ell, 256) || !containsIntTest(g.LVCSNCols, 512) || !containsIntTest(g.NCols, 512) {
		t.Fatalf("low-leaves grid missing high ell/lvcs probes: ell=%v lvcs=%v", g.Ell, g.LVCSNCols)
	}
	if !containsFamilyTest(g.Families, sweepIntGenISISFamily{Theta: 1, Rho: 6, EllPrime: 8}) ||
		!containsFamilyTest(g.Families, sweepIntGenISISFamily{Theta: 3, Rho: 3, EllPrime: 4}) ||
		!containsFamilyTest(g.Families, sweepIntGenISISFamily{Theta: 8, Rho: 4, EllPrime: 6}) ||
		!containsFamilyTest(g.Families, sweepIntGenISISFamily{Theta: 12, Rho: 3, EllPrime: 5}) {
		t.Fatalf("low-leaves grid missing family probes: %+v", g.Families)
	}
	if !containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 111, Digits: 2}) ||
		!containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 13, Digits: 4}) ||
		!containsShortnessTest(g.Shortness, sweepIntGenISISShortness{Radix: 3, Digits: 9}) {
		t.Fatalf("low-leaves grid missing decomposition probes: %+v", g.Shortness)
	}
	if !sameInts(g.Compression, []int{0, 1, 2, 3, 4}) {
		t.Fatalf("low-leaves compression levels=%v want [0 1 2 3 4]", g.Compression)
	}
	if !sameInts(g.PRFGroups, []int{2, 3, 5, 8}) || !sameInts(g.Checkpoints, []int{1, 2, 4, 8}) {
		t.Fatalf("low-leaves PRF axes groups/checkpoints=%v/%v", g.PRFGroups, g.Checkpoints)
	}
	for _, group := range g.PRFGroups {
		if group < 2 {
			t.Fatalf("low-leaves grid includes invalid live PRF group rounds=%d", group)
		}
	}
	if g.EtaSlack != 8 || g.MaxEta != 640 {
		t.Fatalf("low-leaves eta window=%d/%d want 8/640", g.EtaSlack, g.MaxEta)
	}
	if objective, err := normalizeSweepEstimateObjective("low-leaves"); err != nil || objective != sweepEstimateObjectiveRuntime {
		t.Fatalf("low-leaves objective normalized to %q err=%v", objective, err)
	}
}

func TestSweepIntGenISISN1024CommandUsesTranscriptObjective(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "n1024")
	err := run([]string{
		"sweep-intgenisis-n1024-ternary-deep",
		"-force",
		"-progress=false",
		"-checkpoint-interval", "0",
		"-out-dir", outDir,
		"-soundness-min", "1",
		"-soundness-max", "200",
		"-max-showing-bytes", "200000",
		"-top-k", "5",
		"-ncols", "16",
		"-lvcs-ncols", "16",
		"-ell", "4",
		"-nleaves", "64,1054720",
		"-theta", "2",
		"-rho", "3",
		"-ell-prime", "3",
		"-shortness", "11/4",
		"-compression-levels", "0",
		"-projection-modes", PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
		"-prf-companion-modes", string(PIOP.PRFCompanionModeDirectAuth),
		"-prf-group-rounds", "2",
		"-prf-checkpoint-samples", "2",
	})
	if err != nil {
		t.Fatalf("n1024 transcript sweep: %v", err)
	}
	summary, err := os.ReadFile(filepath.Join(outDir, "summary.json"))
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	if !strings.Contains(string(summary), `"objective": "transcript"`) {
		t.Fatalf("summary missing transcript objective: %s", string(summary))
	}
	if _, err := os.Stat(filepath.Join(outDir, "frontier_runtime96.json")); !os.IsNotExist(err) {
		t.Fatalf("transcript objective should not write runtime frontier, stat err=%v", err)
	}
}

func TestSweepIntGenISISN1024StrictSmallFieldZeroCommand(t *testing.T) {
	args90 := sweepIntGenISISN1024StrictSmallFieldZeroArgs(90)
	joined90 := strings.Join(args90, " ")
	for _, want := range []string{
		"-profiles " + credential.ProfileIntGenISISC,
		"-grid " + sweepEstimateN1024StrictSmallFieldGrid,
		"-soundness-min 90",
		"-transcript-modes " + sweepTranscriptModeSmallField2025,
		"-kappa-tuples 0/0/0/0",
		"-max-kappa-per-round 0",
	} {
		if !strings.Contains(joined90, want) {
			t.Fatalf("strict smallfield 90 defaults missing %q in %s", want, joined90)
		}
	}
	args115 := sweepIntGenISISN1024StrictSmallFieldZeroArgs(115)
	if !strings.Contains(strings.Join(args115, " "), "-soundness-min 115") {
		t.Fatalf("strict smallfield 115 defaults missing target: %v", args115)
	}

	outDir := filepath.Join(t.TempDir(), "smallfield90")
	err := run([]string{
		"sweep-intgenisis-n1024-smallfield90-zero",
		"-force",
		"-progress=false",
		"-checkpoint-interval", "0",
		"-out-dir", outDir,
		"-soundness-min", "1",
		"-soundness-max", "200",
		"-max-showing-bytes", "100000",
		"-top-k", "2",
		"-ncols", "32",
		"-lvcs-ncols", "44",
		"-ell", "7",
		"-nleaves", "1024",
		"-theta", "5",
		"-shortness", "7/5",
		"-compression-levels", "1",
		"-prf-group-rounds", "2",
		"-prf-checkpoint-samples", "1",
	})
	if err != nil {
		t.Fatalf("strict smallfield zero command: %v", err)
	}
	gridConfig, err := os.ReadFile(filepath.Join(outDir, "grid_config.json"))
	if err != nil {
		t.Fatalf("read grid_config.json: %v", err)
	}
	for _, want := range []string{
		`"name": "n1024-strict-smallfield-deep"`,
		`"theta": 5`,
		`"rho": 1`,
		`"ell_prime": 1`,
		`"transcript_modes"`,
		sweepTranscriptModeSmallField2025,
		`"kappa_selection": "zero_grinding_only_v1"`,
		`"0/0/0/0"`,
	} {
		if !strings.Contains(string(gridConfig), want) {
			t.Fatalf("grid_config missing %s: %s", want, string(gridConfig))
		}
	}
	frontier, err := os.ReadFile(filepath.Join(outDir, "frontier_all.csv"))
	if err != nil {
		t.Fatalf("read frontier_all.csv: %v", err)
	}
	for _, want := range []string{sweepTranscriptModeSmallField2025, ",5,1,7,1,"} {
		if !strings.Contains(string(frontier), want) {
			t.Fatalf("frontier_all.csv missing %s: %s", want, string(frontier))
		}
	}
}

func TestSweepIntGenISISEstimateRuntimeSortPreservesSmallLeafCandidate(t *testing.T) {
	largeLeaf := sweepIntGenISISEstimateCandidate{
		ID:                     "large",
		CandidateTheoremBits:   100,
		ShowingTranscriptBytes: 1000,
		TotalTranscriptBytes:   1400,
		Showing:                intGenISISTuning{NLeaves: 65536},
	}
	largeLeaf.RuntimeScore, largeLeaf.RuntimeLog2NLeaves = sweepRuntimeScore(largeLeaf.ShowingTranscriptBytes, largeLeaf.Showing.NLeaves)
	smallLeaf := sweepIntGenISISEstimateCandidate{
		ID:                     "small",
		CandidateTheoremBits:   100,
		ShowingTranscriptBytes: 1200,
		TotalTranscriptBytes:   1800,
		Showing:                intGenISISTuning{NLeaves: 4096},
	}
	smallLeaf.RuntimeScore, smallLeaf.RuntimeLog2NLeaves = sweepRuntimeScore(smallLeaf.ShowingTranscriptBytes, smallLeaf.Showing.NLeaves)
	if !(smallLeaf.RuntimeScore < largeLeaf.RuntimeScore) {
		t.Fatalf("test setup invalid: small score %.2f large %.2f", smallLeaf.RuntimeScore, largeLeaf.RuntimeScore)
	}
	frontier := estimateRuntimeTargetFrontier([]sweepIntGenISISEstimateCandidate{largeLeaf, smallLeaf}, 96, 1)
	if len(frontier) != 1 || frontier[0].ID != "small" {
		t.Fatalf("runtime frontier=%v want small-leaf candidate", frontier)
	}
	if math.Abs(frontier[0].RuntimeScore-14400) > 1e-9 {
		t.Fatalf("runtime score=%.2f want 14400", frontier[0].RuntimeScore)
	}
}

func TestSweepIntGenISISEstimateDefaultKappasAreZeroGrindingOnly(t *testing.T) {
	kappas := defaultSweepEstimateKappas()
	if len(kappas) != 1 || kappas[0] != [4]int{} {
		t.Fatalf("default kappas=%v want only 0/0/0/0", kappaTupleStrings(kappas))
	}
	if err := validateSweepKappas(kappas, sweepEstimateDefaultMaxKappaPerRound); err != nil {
		t.Fatalf("default kappas failed zero cap validation: %v", err)
	}
	if err := validateSweepKappas([][4]int{{0, 0, 0, 1}}, sweepEstimateDefaultMaxKappaPerRound); err == nil {
		t.Fatal("expected kappa cap validation failure")
	}
}

func TestSweepIntGenISISEstimateGeneratedKappasUseK1K4Only(t *testing.T) {
	kappas := generatedSweepEstimateKappas(2)
	if len(kappas) != 9 {
		t.Fatalf("generated kappas=%v want 9 tuples", kappaTupleStrings(kappas))
	}
	for _, want := range [][4]int{
		{0, 0, 0, 0},
		{1, 0, 0, 0},
		{0, 0, 0, 1},
		{2, 0, 0, 2},
	} {
		if !containsKappaTest(kappas, want) {
			t.Fatalf("generated kappas missing %s in %v", kappaTupleString(want), kappaTupleStrings(kappas))
		}
	}
	for _, k := range kappas {
		if k[1] != 0 || k[2] != 0 {
			t.Fatalf("generated tuple %s uses k2/k3", kappaTupleString(k))
		}
	}
	if err := validateSweepKappas(kappas, 2); err != nil {
		t.Fatalf("generated kappas failed cap validation: %v", err)
	}
	if got := sweepEstimateKappaSelectionLabel(sweepIntGenISISEstimateConfig{MaxKappaPerRound: 2}); got != "bounded_grinding_k1_k4_v1" {
		t.Fatalf("kappa selection label=%q", got)
	}
	if got := sweepEstimateKappaSelectionLabel(sweepIntGenISISEstimateConfig{}); got != "zero_grinding_only_v1" {
		t.Fatalf("zero kappa selection label=%q", got)
	}
}

func TestSweepIntGenISISEstimateCommandAllowsBoundedKappaCap(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "estimate-kappa")
	err := run([]string{
		"sweep-intgenisis-estimate",
		"-profiles", credential.ProfileIntGenISISC,
		"-grid", "n1024-ternary-deep",
		"-out-dir", outDir,
		"-force",
		"-ncols", "32",
		"-lvcs-ncols", "44",
		"-ell", "7",
		"-nleaves", "1024",
		"-theta", "5",
		"-rho", "1",
		"-ell-prime", "1",
		"-compression-levels", "1",
		"-shortness", "7/5",
		"-transcript-modes", sweepTranscriptModeSmallField2025,
		"-projection-modes", PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
		"-prf-companion-modes", string(PIOP.PRFCompanionModeDirectAuth),
		"-prf-group-rounds", "2",
		"-prf-checkpoint-samples", "1",
		"-max-kappa-per-round", "2",
		"-soundness-min", "1",
		"-soundness-max", "200",
		"-max-showing-bytes", "100000",
		"-top-k", "2",
		"-progress=false",
	})
	if err != nil {
		t.Fatalf("bounded kappa estimate command: %v", err)
	}
	gridConfig, err := os.ReadFile(filepath.Join(outDir, "grid_config.json"))
	if err != nil {
		t.Fatalf("read grid_config.json: %v", err)
	}
	for _, want := range []string{`"kappa_selection": "bounded_grinding_k1_k4_v1"`, `"2/0/0/2"`} {
		if !strings.Contains(string(gridConfig), want) {
			t.Fatalf("grid_config missing %s: %s", want, string(gridConfig))
		}
	}
}

func TestSweepIntGenISISEstimateSelectsMinimalKappaTopup(t *testing.T) {
	issuance := benchmarkIntGenISISMetrics{
		TheoremBits:      [4]float64{120, 120, 120, 120},
		TheoremTotalBits: 118,
		SoundnessEq8Bits: 118,
		CollisionBits:    500,
	}
	showing := benchmarkIntGenISISMetrics{
		TheoremBits:      [4]float64{120, 120, 120, 91.5},
		TheoremTotalBits: 91.4,
		SoundnessEq8Bits: 91.4,
		CollisionBits:    500,
	}
	kappas := [][4]int{
		{0, 0, 0, 0},
		{0, 0, 0, 2},
		{0, 0, 0, 3},
		{0, 0, 0, 6},
	}
	kappa, _, boostedShowing, bits, ok, high := selectSweepKappaTopup(issuance, showing, kappas, 94, 135)
	if !ok || high {
		t.Fatalf("kappa selection failed ok=%v high=%v bits=%.2f", ok, high, bits)
	}
	if kappa != [4]int{0, 0, 0, 3} {
		t.Fatalf("selected kappa=%s want 0/0/0/3", kappaTupleString(kappa))
	}
	if boostedShowing.TheoremBits[3] != 94.5 {
		t.Fatalf("boosted round4=%.2f want 94.50", boostedShowing.TheoremBits[3])
	}
}

func TestSweepIntGenISISEstimateShortnessCapacity(t *testing.T) {
	const beta = int64(6142)
	for _, shape := range []sweepIntGenISISShortness{{Radix: 111, Digits: 2}, {Radix: 25, Digits: 3}, {Radix: 11, Digits: 4}, {Radix: 9, Digits: 5}, {Radix: 7, Digits: 5}, {Radix: 5, Digits: 6}} {
		if !sweepShortnessCoversSignatureBound(shape, beta) {
			t.Fatalf("shape %+v should cover beta=%d", shape, beta)
		}
	}
	for _, shape := range []sweepIntGenISISShortness{{Radix: 109, Digits: 2}, {Radix: 23, Digits: 3}, {Radix: 9, Digits: 4}, {Radix: 5, Digits: 5}} {
		if sweepShortnessCoversSignatureBound(shape, beta) {
			t.Fatalf("shape %+v should not cover beta=%d", shape, beta)
		}
	}
}

func TestParseNonNegativeIntCSVKeepsCompressionZero(t *testing.T) {
	got, err := parseNonNegativeIntCSV("0,1,2,0")
	if err != nil {
		t.Fatalf("parse non-negative CSV: %v", err)
	}
	if !sameInts(got, []int{0, 1, 2}) {
		t.Fatalf("parse non-negative CSV=%v want [0 1 2]", got)
	}
	if _, err := parseNonNegativeIntCSV("-1"); err == nil {
		t.Fatal("parse non-negative CSV accepted a negative value")
	}
}

func TestSweepIntGenISISEstimatePRFRowsUsePackedCompanionGeometry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ncols int
		want  int
	}{
		{name: "ncols16", ncols: 16, want: 12},
		{name: "ncols32", ncols: 32, want: 7},
		{name: "ncols64", ncols: 64, want: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := estimatePRFRows(intGenISISTuning{
				NCols:             tc.ncols,
				PRFCompanionMode:  PIOP.PRFCompanionModeDirectAuth,
				PRFGroupRounds:    2,
				CheckpointSamples: 2,
			})
			if err != nil {
				t.Fatalf("estimate PRF rows: %v", err)
			}
			if got != tc.want {
				t.Fatalf("PRF rows=%d want %d", got, tc.want)
			}
		})
	}
}

func TestSweepIntGenISISEstimateProfileA96BitShowingPRFGeometry(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISA)
	if !ok {
		t.Fatal("missing profile A")
	}
	geom, err := estimateIntGenISISGeometry(profile, intGenISISTuning{
		NCols:              16,
		LVCSNCols:          48,
		NLeaves:            262144,
		Eta:                44,
		Theta:              2,
		Rho:                3,
		Ell:                8,
		EllPrime:           3,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     0,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}, "showing")
	if err != nil {
		t.Fatalf("estimate geometry: %v", err)
	}
	if got, want := geom.PRFRows, 12; got != want {
		t.Fatalf("profile-A 96-bit PRF rows=%d want %d", got, want)
	}
	if got, want := geom.Rows, 380; got != want {
		t.Fatalf("profile-A 96-bit rows=%d want %d", got, want)
	}
	if got, want := geom.SmallFieldReplayRows, 144; got != want {
		t.Fatalf("profile-A 96-bit smallfield replay rows=%d want %d", got, want)
	}
}

func TestSweepIntGenISISEstimatePaperTranscriptUsesPackedBucketShapes(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISA)
	if !ok {
		t.Fatal("missing profile A")
	}
	tuning := intGenISISTuning{
		NCols:              16,
		LVCSNCols:          60,
		NLeaves:            3712,
		Eta:                32,
		Theta:              2,
		Rho:                3,
		Ell:                17,
		EllPrime:           3,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	sm, err := estimateIntGenISISMetrics(profile, tuning, "showing")
	if err != nil {
		t.Fatalf("showing estimate: %v", err)
	}
	if got, want := sm.PdecsBytes, 10755; got != want {
		t.Fatalf("Pdecs bytes=%d want measured row-opening residue shape %d", got, want)
	}
	if got, want := sm.VTargetsBytes, 6625; got != want {
		t.Fatalf("VTargets bytes=%d want packed matrix shape %d", got, want)
	}
	if got, want := sm.BarSetsBytes, 1885; got != want {
		t.Fatalf("BarSets bytes=%d want packed matrix shape %d", got, want)
	}
	if got, measured := sm.PaperTranscriptBytes, 30974; got < measured-200 || got > measured+200 {
		t.Fatalf("paper transcript bytes=%d outside measured neighborhood around %d", got, measured)
	}
}

func TestSweepIntGenISISEstimatePaperTranscriptCurrent96BitPresetShape(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISA)
	if !ok {
		t.Fatal("missing profile A")
	}
	tuning := intGenISISTuning{
		NCols:              16,
		LVCSNCols:          48,
		NLeaves:            262144,
		Eta:                44,
		Theta:              2,
		Rho:                3,
		Ell:                8,
		EllPrime:           3,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     0,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	sm, err := estimateIntGenISISMetrics(profile, tuning, "showing")
	if err != nil {
		t.Fatalf("showing estimate: %v", err)
	}
	if got, want := sm.PdecsBytes, 5347; got != want {
		t.Fatalf("Pdecs bytes=%d want current 96-bit row-opening shape %d", got, want)
	}
	if got, want := sm.VTargetsBytes, 6058; got != want {
		t.Fatalf("VTargets bytes=%d want current 96-bit packed matrix shape %d", got, want)
	}
	if got, want := sm.BarSetsBytes, 1018; got != want {
		t.Fatalf("BarSets bytes=%d want current 96-bit packed matrix shape %d", got, want)
	}
	if got, measured := sm.PaperTranscriptBytes, 23166; got < measured-400 || got > measured+400 {
		t.Fatalf("paper transcript bytes=%d outside measured neighborhood around %d", got, measured)
	}
}

func TestSweepIntGenISISEstimatePaperTranscriptTheta1PResidueShape(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISB)
	if !ok {
		t.Fatal("missing profile B")
	}
	tuning := intGenISISTuning{
		NCols:              128,
		LVCSNCols:          128,
		NLeaves:            4096,
		Eta:                54,
		Theta:              1,
		Rho:                7,
		Ell:                27,
		EllPrime:           13,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	sm, err := estimateIntGenISISMetrics(profile, tuning, "showing")
	if err != nil {
		t.Fatalf("showing estimate: %v", err)
	}
	if got, want := sm.PdecsBytes, 14460; got != want {
		t.Fatalf("theta=1 Pdecs bytes=%d want measured P residue stream shape %d", got, want)
	}
	if got, want := sm.VTargetsBytes, 4378; got != want {
		t.Fatalf("theta=1 VTargets bytes=%d want packed matrix shape %d", got, want)
	}
	if got, want := sm.BarSetsBytes, 932; got != want {
		t.Fatalf("theta=1 BarSets bytes=%d want packed matrix shape %d", got, want)
	}
}

func TestSweepIntGenISISEstimateTheoremAndTranscriptFilters(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISA)
	if !ok {
		t.Fatal("missing profile A")
	}
	tuning := intGenISISTuning{
		NCols:              32,
		LVCSNCols:          70,
		NLeaves:            42000,
		Eta:                47,
		Theta:              3,
		Rho:                2,
		Ell:                10,
		EllPrime:           2,
		Kappa:              [4]int{0, 0, 0, 6},
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  11,
		SigShortnessDigits: 4,
		CompressedRows:     0,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	issuance := tuning
	issuance.PRFCompanionMode = ""
	issuance.CheckpointSamples = 0
	issuance.SigShortnessRadix = 0
	issuance.SigShortnessDigits = 0
	issuance.CompressedRows = 0
	issuance.ReplayProjection = ""
	im, err := estimateIntGenISISMetrics(profile, issuance, "issuance")
	if err != nil {
		t.Fatalf("issuance estimate: %v", err)
	}
	sm, err := estimateIntGenISISMetrics(profile, tuning, "showing")
	if err != nil {
		t.Fatalf("showing estimate: %v", err)
	}
	candidateBits := minFloat64Main(im.TheoremTotalBits, sm.TheoremTotalBits)
	if candidateBits < 90 || candidateBits > 135 {
		t.Fatalf("candidate theorem bits %.2f outside estimate sweep band", candidateBits)
	}
	if sm.PaperTranscriptBytes <= 0 || sm.PaperTranscriptBytes > 50000 {
		t.Fatalf("showing bytes=%d outside cap", sm.PaperTranscriptBytes)
	}
	if sm.DQ != sweepComputeDQFromDegrees(11, 2, 32, 10) {
		t.Fatalf("showing dQ=%d want conservative Eq.(3) dQ", sm.DQ)
	}
}

func TestSweepIntGenISISEstimateUsesProfileTernaryBound(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISC)
	if !ok {
		t.Fatal("missing profile C")
	}
	tuning := intGenISISTuning{
		NCols:              32,
		LVCSNCols:          96,
		NLeaves:            262144,
		Eta:                44,
		Theta:              2,
		Rho:                3,
		Ell:                8,
		EllPrime:           3,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  2,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	im, err := estimateIntGenISISMetrics(profile, tuning, "issuance")
	if err != nil {
		t.Fatalf("issuance estimate: %v", err)
	}
	if im.ParallelAlgDegree != 3 || im.DQ != sweepComputeDQFromDegrees(3, 1, 32, 8) {
		t.Fatalf("ternary issuance degree/dQ=%d/%d", im.ParallelAlgDegree, im.DQ)
	}
	sm, err := estimateIntGenISISMetrics(profile, tuning, "showing")
	if err != nil {
		t.Fatalf("showing estimate: %v", err)
	}
	if sm.ParallelAlgDegree != 5 || sm.DQ != sweepComputeDQFromDegrees(5, 2, 32, 8) || sm.DominantDegreeSource != "shortness" {
		t.Fatalf("ternary showing degree/dQ/source=%d/%d/%s", sm.ParallelAlgDegree, sm.DQ, sm.DominantDegreeSource)
	}
}

func TestSweepIntGenISISEstimateN1024BaselineAttribution(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISC)
	if !ok {
		t.Fatal("missing profile C")
	}
	tuning := intGenISISTuning{
		NCols:              32,
		LVCSNCols:          57,
		NLeaves:            950272,
		Eta:                55,
		Theta:              2,
		Rho:                3,
		Ell:                7,
		EllPrime:           3,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  1,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		CompressedRows:     0,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	sm, err := estimateIntGenISISMetrics(profile, tuning, "showing")
	if err != nil {
		t.Fatalf("showing estimate: %v", err)
	}
	if got, want := sm.PaperTranscriptBytes, 38737; got != want {
		t.Fatalf("paper transcript bytes=%d want current baseline %d", got, want)
	}
	if got, want := sm.RowsBlock, 12; got != want {
		t.Fatalf("rows_block=%d want %d", got, want)
	}
	if got, want := sm.AuditRows, 72; got != want {
		t.Fatalf("audit_rows=%d want %d", got, want)
	}
	if got, want := sm.OpeningCols, 360; got != want {
		t.Fatalf("opening_cols=%d want %d", got, want)
	}
	if got, want := sm.PdecsBytes+sm.VTargetsBytes, 24137; got != want {
		t.Fatalf("pdecs+vtargets=%d want %d", got, want)
	}
}

func TestSweepIntGenISISEstimateResearchModesExposeAccounting(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISC)
	if !ok {
		t.Fatal("missing profile C")
	}
	base := intGenISISTuning{
		NCols:              32,
		LVCSNCols:          57,
		NLeaves:            950272,
		Eta:                55,
		Theta:              2,
		Rho:                3,
		Ell:                7,
		EllPrime:           3,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  1,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		CompressedRows:     0,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	if _, err := estimateIntGenISISMetrics(profile, base, "showing"); err != nil {
		t.Fatalf("baseline estimate: %v", err)
	}
	shortLookup := base
	shortLookup.SigShortnessRadix = 25
	shortLookup.SigShortnessDigits = 3
	shortLookup.TranscriptMode = sweepTranscriptModeShortnessLookup
	shortMetrics, err := estimateIntGenISISMetrics(profile, shortLookup, "showing")
	if err != nil {
		t.Fatalf("shortness lookup estimate: %v", err)
	}
	if shortMetrics.ParallelAlgDegree != 5 || shortMetrics.AggregatedAlgDegree != 2 || shortMetrics.DominantDegreeSource != "shortness_lookup" {
		t.Fatalf("shortness lookup degree/source=%d/%d/%s, want 5/2/shortness_lookup",
			shortMetrics.ParallelAlgDegree, shortMetrics.AggregatedAlgDegree, shortMetrics.DominantDegreeSource)
	}

	mseLookup := base
	mseLookup.CompressedRows = 1
	mseLookup.TranscriptMode = sweepTranscriptModeMSELookupPack2
	mseMetrics, err := estimateIntGenISISMetrics(profile, mseLookup, "showing")
	if err != nil {
		t.Fatalf("mse lookup estimate: %v", err)
	}
	if mseMetrics.ParallelAlgDegree != 5 || mseMetrics.AggregatedAlgDegree != 2 || mseMetrics.DominantDegreeSource != "mse_lookup" {
		t.Fatalf("mse lookup degree/source=%d/%d/%s, want 5/2/mse_lookup",
			mseMetrics.ParallelAlgDegree, mseMetrics.AggregatedAlgDegree, mseMetrics.DominantDegreeSource)
	}
}

func TestSweepIntGenISISEstimateSmallField2025ShapeAccounting(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISC)
	if !ok {
		t.Fatal("missing profile C")
	}
	base := intGenISISTuning{
		NCols:              32,
		LVCSNCols:          57,
		NLeaves:            950272,
		Eta:                55,
		Theta:              2,
		Rho:                3,
		Ell:                7,
		EllPrime:           3,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  1,
		SigShortnessRadix:  5,
		SigShortnessDigits: 6,
		CompressedRows:     0,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	nonCanonical := base
	nonCanonical.TranscriptMode = sweepTranscriptModeSmallField2025
	if sweepTranscriptModeApplies(sweepTranscriptModeSmallField2025, nonCanonical) {
		t.Fatalf("smallfield_2025_1085_v1 must not apply to rho=%d ell'=%d", nonCanonical.Rho, nonCanonical.EllPrime)
	}
	canonical := base
	canonical.Rho = 1
	canonical.EllPrime = 1
	canonical.TranscriptMode = sweepTranscriptModeSmallField2025
	if !sweepTranscriptModeApplies(sweepTranscriptModeSmallField2025, canonical) {
		t.Fatalf("smallfield_2025_1085_v1 should apply to theta>1 rho=1 ell'=1")
	}
	m, err := estimateIntGenISISMetrics(profile, canonical, "showing")
	if err != nil {
		t.Fatalf("smallfield 2025 estimate: %v", err)
	}
	if !m.PaperShapeCanonical {
		t.Fatalf("paper_shape_canonical=false")
	}
	if got, want := m.PaperShapeWitnessLayers, 12; got != want {
		t.Fatalf("paper witness layers=%d want %d", got, want)
	}
	if got, want := m.PaperShapeMaskRows, 8; got != want {
		t.Fatalf("paper mask rows=%d want %d", got, want)
	}
	if got, want := m.PaperShapeNRows, 416; got != want {
		t.Fatalf("paper nrows=%d want %d", got, want)
	}
	if got, want := m.PaperShapeQueries, 26; got != want {
		t.Fatalf("paper queries=%d want %d", got, want)
	}
	if got, want := m.OpeningCols, 390; got != want {
		t.Fatalf("paper opening cols=%d want %d", got, want)
	}
	if got, want := m.PaperShapeOpeningOmitEntries, 182; got != want {
		t.Fatalf("paper omitted opening entries=%d want %d", got, want)
	}
	if m.MdecsBytes <= 0 || m.TapesBytes <= 0 {
		t.Fatalf("smallfield paper estimate did not expose mdecs/tapes: mdecs=%d tapes=%d", m.MdecsBytes, m.TapesBytes)
	}
	if m.TranscriptSecurityStatus != "smallwood_2025_1085_formula_estimate" {
		t.Fatalf("security status=%q", m.TranscriptSecurityStatus)
	}
}

func TestSweepIntGenISISEstimateSmallFieldPack2DropsRowsBlock(t *testing.T) {
	profile, ok := credential.LookupIntGenISISProfile(credential.ProfileIntGenISISC)
	if !ok {
		t.Fatal("missing profile C")
	}
	tuning := intGenISISTuning{
		NCols:              32,
		LVCSNCols:          44,
		NLeaves:            116864,
		Eta:                37,
		Theta:              5,
		Rho:                1,
		Ell:                7,
		EllPrime:           1,
		PRFCompanionMode:   PIOP.PRFCompanionModeDirectAuth,
		PRFGroupRounds:     2,
		CheckpointSamples:  1,
		SigShortnessRadix:  7,
		SigShortnessDigits: 5,
		CompressedRows:     1,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
		TranscriptMode:     sweepTranscriptModeSmallField2025,
	}
	m, err := estimateIntGenISISMetrics(profile, tuning, "showing")
	if err != nil {
		t.Fatalf("pack2 smallfield estimate: %v", err)
	}
	if got, want := m.RowsBlock, 13; got != want {
		t.Fatalf("pack2 rows_block=%d want %d", got, want)
	}
	if got, want := m.BoundRows, 48; got != want {
		t.Fatalf("pack2 bound_rows=%d want %d", got, want)
	}
	if got, want := m.DQ, 373; got != want {
		t.Fatalf("pack2 dQ=%d want honest carrier degree %d", got, want)
	}
	if m.PaperTranscriptBytes >= 29607 {
		t.Fatalf("pack2 estimate bytes=%d should be below current live preset", m.PaperTranscriptBytes)
	}
}

func TestSweepIntGenISISEstimateCommandSmoke(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "estimate")
	err := run([]string{
		"sweep-intgenisis-estimate",
		"-profiles", credential.ProfileIntGenISISA,
		"-out-dir", outDir,
		"-force",
		"-ncols", "32",
		"-lvcs-ncols", "70",
		"-ell", "10",
		"-nleaves", "42000",
		"-theta", "3",
		"-rho", "2",
		"-ell-prime", "2",
		"-compression-levels", "0,1",
		"-shortness", "11/4",
		"-transcript-modes", "baseline,column_widths_v1",
		"-kappa-tuples", "0/0/0/0",
		"-soundness-min", "88",
		"-soundness-max", "135",
		"-max-showing-bytes", "50000",
		"-top-k", "5",
	})
	if err != nil {
		t.Fatalf("estimate command: %v", err)
	}
	for _, name := range []string{"summary.json", "frontier_all.json", "frontier_all.csv", "frontier_96.json", "frontier_128.csv", "rejected_counts.json", "grid_config.json", "progress.json"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "accepted_candidates.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("accepted_candidates.jsonl should not be written, stat err=%v", err)
	}
	gridConfig, err := os.ReadFile(filepath.Join(outDir, "grid_config.json"))
	if err != nil {
		t.Fatalf("read grid_config.json: %v", err)
	}
	if !strings.Contains(string(gridConfig), PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2) {
		t.Fatalf("grid_config missing default V2 projection: %s", string(gridConfig))
	}
	if strings.Contains(string(gridConfig), PIOP.IntGenISISReplayProjectionProjectUYHatV1) ||
		strings.Contains(string(gridConfig), PIOP.IntGenISISReplayProjectionNone) {
		t.Fatalf("default estimate projection modes should be V2-only: %s", string(gridConfig))
	}
	for _, want := range []string{`"prf_companion_modes"`, string(PIOP.PRFCompanionModeDirectAuth), `"prf_group_rounds"`, `"prf_checkpoint_samples"`} {
		if !strings.Contains(string(gridConfig), want) {
			t.Fatalf("grid_config missing %s: %s", want, string(gridConfig))
		}
	}
	for _, want := range []string{`"transcript_modes"`, sweepTranscriptModeBaseline, sweepTranscriptModeColumnWidths} {
		if !strings.Contains(string(gridConfig), want) {
			t.Fatalf("grid_config missing transcript mode %s: %s", want, string(gridConfig))
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

func sameStrings(a, b []string) bool {
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

func containsIntTest(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func maxIntTest(values []int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func containsFamilyTest(values []sweepIntGenISISFamily, want sweepIntGenISISFamily) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsShortnessTest(values []sweepIntGenISISShortness, want sweepIntGenISISShortness) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsKappaTest(values [][4]int, want [4]int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func minFloat64Main(a, b float64) float64 {
	if a <= b {
		return a
	}
	return b
}
