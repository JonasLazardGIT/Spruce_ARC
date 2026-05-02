package main

import (
	"fmt"
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
	if !sameInts(g.Compression, []int{0, 1, 2}) {
		t.Fatalf("compression levels=%v want [0 1 2]", g.Compression)
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

func TestSweepIntGenISISEstimateDefaultKappasAreZeroGrindingOnly(t *testing.T) {
	kappas := defaultSweepEstimateKappas()
	if len(kappas) != 1 || kappas[0] != [4]int{} {
		t.Fatalf("default kappas=%v want only 0/0/0/0", kappaTupleStrings(kappas))
	}
	for _, k := range kappas {
		for round, v := range k {
			if v > sweepEstimateMaxKappaPerRound {
				t.Fatalf("kappa round %d in %s exceeds cap %d", round+1, kappaTupleString(k), sweepEstimateMaxKappaPerRound)
			}
		}
	}
	if err := validateSweepKappas([][4]int{{0, 0, 0, 7}}, sweepEstimateMaxKappaPerRound); err == nil {
		t.Fatal("expected kappa cap validation failure")
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
	for _, shape := range []sweepIntGenISISShortness{{Radix: 11, Digits: 4}, {Radix: 7, Digits: 5}, {Radix: 5, Digits: 6}} {
		if !sweepShortnessCoversSignatureBound(shape, beta) {
			t.Fatalf("shape %+v should cover beta=%d", shape, beta)
		}
	}
	for _, shape := range []sweepIntGenISISShortness{{Radix: 9, Digits: 4}, {Radix: 5, Digits: 5}} {
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
		CompressedRows:     1,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}, "showing")
	if err != nil {
		t.Fatalf("estimate geometry: %v", err)
	}
	if got, want := geom.PRFRows, 12; got != want {
		t.Fatalf("profile-A 96-bit PRF rows=%d want %d", got, want)
	}
	if got, want := geom.Rows, 332; got != want {
		t.Fatalf("profile-A 96-bit rows=%d want %d", got, want)
	}
	if got, want := geom.SmallFieldReplayRows, 126; got != want {
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
	if got, want := sm.PdecsBytes, 9149; got != want {
		t.Fatalf("Pdecs bytes=%d want measured row-opening residue shape %d", got, want)
	}
	if got, want := sm.VTargetsBytes, 6625; got != want {
		t.Fatalf("VTargets bytes=%d want packed matrix shape %d", got, want)
	}
	if got, want := sm.BarSetsBytes, 1885; got != want {
		t.Fatalf("BarSets bytes=%d want packed matrix shape %d", got, want)
	}
	if got, measured := sm.PaperTranscriptBytes, 27569; got < measured-200 || got > measured+200 {
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
		CompressedRows:     1,
		ReplayProjection:   PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
	}
	sm, err := estimateIntGenISISMetrics(profile, tuning, "showing")
	if err != nil {
		t.Fatalf("showing estimate: %v", err)
	}
	if got, want := sm.PdecsBytes, 4833; got != want {
		t.Fatalf("Pdecs bytes=%d want current 96-bit row-opening shape %d", got, want)
	}
	if got, want := sm.VTargetsBytes, 5302; got != want {
		t.Fatalf("VTargets bytes=%d want current 96-bit packed matrix shape %d", got, want)
	}
	if got, want := sm.BarSetsBytes, 892; got != want {
		t.Fatalf("BarSets bytes=%d want current 96-bit packed matrix shape %d", got, want)
	}
	if got, measured := sm.PaperTranscriptBytes, 22116; got < measured-400 || got > measured+400 {
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
		CompressedRows:     1,
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
	if sm.DQ != sweepComputeDQFromDegrees(11, 8, 32, 10) {
		t.Fatalf("showing dQ=%d want conservative Eq.(3) dQ", sm.DQ)
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
