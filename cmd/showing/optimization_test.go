package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/signverify"
)

func stablePaperTranscriptScore(rep PIOP.PaperTranscriptReport) int {
	return rep.Counters.OptimizedBytes +
		rep.SaltRoot.OptimizedBytes +
		rep.ExtraHash.OptimizedBytes +
		rep.R.OptimizedBytes +
		rep.Q.OptimizedBytes +
		rep.VTargets.OptimizedBytes +
		rep.BarSets.OptimizedBytes +
		rep.Pdecs.OptimizedBytes +
		rep.Mdecs.OptimizedBytes +
		rep.Tapes.OptimizedBytes
}

func TestShowingProductionBetaAuditMatchesCalibrationPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)

	par, err := ntrurio.LoadParams(filepath.Join("Parameters", "Parameters.json"), true)
	if err != nil {
		t.Fatalf("load params: %v", err)
	}
	rawParams, err := os.ReadFile(filepath.Join("Parameters", "Parameters.json"))
	if err != nil {
		t.Fatalf("read params json: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(rawParams, &raw); err != nil {
		t.Fatalf("unmarshal params json: %v", err)
	}
	state, err := credential.LoadState(filepath.Join(root, "credential", "keys", "credential_state.json"))
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	calibration, err := signverify.CalibrateMeasuredBeta(signverify.SignPaths{
		ParamsPath:    filepath.Join("Parameters", "Parameters.json"),
		BFile:         filepath.Join("Parameters", "Bmatrix.json"),
		PublicKeyPath: filepath.Join("ntru_keys", "public.json"),
		PrivatePath:   filepath.Join("ntru_keys", "private.json"),
	}, 64, 2048, ntru.SamplerOpts{
		AutoTuneAlpha:       true,
		AutoTuneAlphaMargin: 1.00,
	})
	if err != nil {
		t.Fatalf("calibrate beta: %v", err)
	}
	audit := buildSignatureBoundAuditReport(state, par.Beta, calibration)

	if audit.ProductionBeta == 0 {
		t.Fatalf("production beta is zero")
	}
	if audit.CalibrationBatchMax <= 0 {
		t.Fatalf("calibration batch max=%d", audit.CalibrationBatchMax)
	}
	boundValue, ok := raw["bound"].(float64)
	if !ok {
		t.Fatalf("params bound missing or non-numeric: %#v", raw["bound"])
	}
	if uint64(audit.CalibrationBatchMax) != par.Beta || uint64(boundValue) != par.Beta {
		t.Fatalf("beta/bound mismatch: audit=%d beta=%d bound=%d", audit.CalibrationBatchMax, par.Beta, uint64(boundValue))
	}
	if audit.CalibrationMaxSample < 0 || audit.CalibrationMaxSample >= audit.CalibrationSamples {
		t.Fatalf("calibration max sample=%d outside samples=%d", audit.CalibrationMaxSample, audit.CalibrationSamples)
	}
	if calibration.PerSample[audit.CalibrationMaxSample] != audit.CalibrationBatchMax {
		t.Fatalf("batch max sample mismatch: per_sample[%d]=%d batch_max=%d", audit.CalibrationMaxSample, calibration.PerSample[audit.CalibrationMaxSample], audit.CalibrationBatchMax)
	}
	if audit.StateMaxS1 <= 0 || audit.StateMaxS2 <= 0 || audit.StateMax <= 0 {
		t.Fatalf("unexpected state norm audit: %+v", audit)
	}
	if uint64(audit.StateMax) > audit.ProductionBeta {
		t.Fatalf("state max=%d exceeds beta=%d", audit.StateMax, audit.ProductionBeta)
	}
	if audit.CalibrationBatchMax < audit.StateMax {
		t.Fatalf("calibration batch max=%d below persisted state max=%d", audit.CalibrationBatchMax, audit.StateMax)
	}
	if audit.SlackRatio <= 1 {
		t.Fatalf("slack ratio=%f want >1", audit.SlackRatio)
	}
	t.Logf("beta audit: beta=%d state_max={s1=%d s2=%d max=%d} calibration={samples=%d alpha=%.6f batch_max=%d idx=%d} slack=%.4f",
		audit.ProductionBeta,
		audit.StateMaxS1,
		audit.StateMaxS2,
		audit.StateMax,
		audit.CalibrationSamples,
		audit.CalibrationAlpha,
		audit.CalibrationBatchMax,
		audit.CalibrationMaxSample,
		audit.SlackRatio)
}

type shortnessCandidate struct {
	label   string
	profile string
	radix   int
	digits  int
}

func buildShortnessCandidatesForBeta(t *testing.T) []shortnessCandidate {
	t.Helper()
	const ringQ = uint64(1054721)
	seen := map[string]bool{}
	add := func(out *[]shortnessCandidate, c shortnessCandidate) {
		key := fmt.Sprintf("%s:%s:%d:%d", c.label, c.profile, c.radix, c.digits)
		if seen[key] {
			return
		}
		seen[key] = true
		*out = append(*out, c)
	}

	out := []shortnessCandidate{
		{label: PIOP.SigShortnessProfileR11L4Production, profile: PIOP.SigShortnessProfileR11L4Production},
	}
	for _, digits := range []int{3, 4, 5, 6} {
		base, gotDigits, _, err := PIOP.ResolveSignatureBoundShapeForOpts(ringQ, PIOP.SimOpts{
			CoeffNativeSigModel: PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
			SigShortnessL:       digits,
		})
		if err != nil {
			t.Fatalf("resolve minimal radix for L=%d: %v", digits, err)
		}
		add(&out, shortnessCandidate{
			label:  fmt.Sprintf("minimal_r%d_l%d", base, gotDigits),
			radix:  base,
			digits: gotDigits,
		})
		for delta := 1; delta <= 1; delta++ {
			add(&out, shortnessCandidate{
				label:  fmt.Sprintf("nearby_r%d_l%d", base+delta, gotDigits),
				radix:  base + delta,
				digits: gotDigits,
			})
		}
	}
	return out
}

func TestShowingShortnessSweepKeepsProductionProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	type measured struct {
		shortnessCandidate
		score     int
		total     int
		pdecs     int
		vtargets  int
		barsets   int
		q         int
		soundness float64
	}

	var best *measured
	for _, cand := range buildShortnessCandidatesForBeta(t) {
		_, rep, _, _, _, _ := buildShowingProofForTestConfigWithShortness(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, cand.profile, cand.radix, cand.digits)
		got := measured{
			shortnessCandidate: cand,
			score:              stablePaperTranscriptScore(rep.PaperTranscript),
			total:              rep.PaperTranscript.OptimizedBytes,
			pdecs:              rep.PaperTranscript.Pdecs.OptimizedBytes,
			vtargets:           rep.PaperTranscript.VTargets.OptimizedBytes,
			barsets:            rep.PaperTranscript.BarSets.OptimizedBytes,
			q:                  rep.PaperTranscript.Q.OptimizedBytes,
			soundness:          rep.Soundness.TotalBits,
		}
		if rep.Soundness.TotalBits < 100 {
			t.Logf("shortness candidate %s rejected by theorem floor: %.2f", cand.label, rep.Soundness.TotalBits)
			continue
		}
		t.Logf("shortness candidate %s -> stable=%d total=%d Pdecs=%d VTargets=%d BarSets=%d Q=%d soundness=%.2f",
			cand.label, got.score, got.total, got.pdecs, got.vtargets, got.barsets, got.q, got.soundness)
		if best == nil || got.score < best.score {
			copy := got
			best = &copy
		}
	}
	if best == nil {
		t.Fatalf("no shortness candidates measured")
	}
	if best.profile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("best shortness candidate=%s want production profile %s", best.label, PIOP.SigShortnessProfileR11L4Production)
	}
}

type nizkCandidate struct {
	label  string
	mutate func(*PIOP.SimOpts)
}

func TestShowingNIZKRetuneSelectsTheta3Eta43Preset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	candidates := []nizkCandidate{
		{
			label: "old_soundness_balanced_theta5_eta63",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 96, 96, 96
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4096, 4096, 4096
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 5, 2, 2, 63
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
		{
			label: "rho1_theta5_eta43",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 96, 96, 96
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4096, 4096, 4096
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 5, 1, 2, 43
				opts.Kappa = [4]int{0, 5, 0, 5}
			},
		},
		{
			label: "theta4_eta43",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 96, 96, 96
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4096, 4096, 4096
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 4, 2, 2, 43
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
		{
			label: "theta3_eta43",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 96, 96, 96
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4096, 4096, 4096
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 3, 2, 2, 43
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
		{
			label: "narrow_lvcs80_theta3_eta43",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 80, 80, 80
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 3072, 3072, 3072
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 3, 2, 2, 43
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
		{
			label: "wide_lvcs112_theta3_eta44",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 112, 112, 112
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4608, 4608, 4608
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 3, 2, 2, 44
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
	}

	type measured struct {
		label     string
		score     int
		total     int
		pdecs     int
		vtargets  int
		barsets   int
		q         int
		soundness float64
	}
	var best *measured
	for _, cand := range candidates {
		_, rep, _, _, _, _ := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
			t,
			PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
			false,
			false,
			"",
			8,
			PIOP.ShowingPresetSoundnessBalanced,
			PIOP.SigShortnessProfileR11L4Production,
			0,
			0,
			16,
			0,
			cand.mutate,
		)
		got := measured{
			label:     cand.label,
			score:     stablePaperTranscriptScore(rep.PaperTranscript),
			total:     rep.PaperTranscript.OptimizedBytes,
			pdecs:     rep.PaperTranscript.Pdecs.OptimizedBytes,
			vtargets:  rep.PaperTranscript.VTargets.OptimizedBytes,
			barsets:   rep.PaperTranscript.BarSets.OptimizedBytes,
			q:         rep.PaperTranscript.Q.OptimizedBytes,
			soundness: rep.Soundness.TotalBits,
		}
		t.Logf("nizk candidate %s -> stable=%d total=%d Pdecs=%d VTargets=%d BarSets=%d Q=%d soundness=%.2f",
			got.label, got.score, got.total, got.pdecs, got.vtargets, got.barsets, got.q, got.soundness)
		if got.soundness < 100 {
			continue
		}
		if best == nil || got.score < best.score {
			copy := got
			best = &copy
		}
	}
	if best == nil {
		t.Fatalf("no candidate met the theorem floor")
	}
	if best.label != "theta3_eta43" {
		t.Fatalf("best NIZK candidate=%s want theta3_eta43", best.label)
	}
}
