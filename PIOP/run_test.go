package PIOP

import "testing"

func TestRemovedShowingPresetStringsNormalizeToCustom(t *testing.T) {
	removed := []string{
		"aggregate_v11_direct_target_research",
		"aggregate_v11_pair_lookup_research",
		"aggregate_v15_coeff_lookup_research",
		"aggregate_v16_inline_target_research",
		"aggregate_v17_z_elim_inline_target_research",
		"aggregate_v18_replay_compact_research",
		"aggregate_v18_replay_compact_w84_research",
		"aggregate_v19_inline_r1_research",
		"compact_l3",
		"compact_l2",
		"compact_l1_research",
		"transcript_first",
		"production_balance",
	}
	for _, preset := range removed {
		if got := normalizeShowingPreset(preset); got != ShowingPresetCustom {
			t.Fatalf("removed preset %q normalized to %q, want custom", preset, got)
		}
	}
}

func TestCanonicalShowingPresetStringsRemainLive(t *testing.T) {
	for _, preset := range []string{
		ShowingPresetSoundnessBalanced,
		ShowingPresetAggregateV6Research,
		ShowingPresetInlineTargetReplayCompactResearch,
	} {
		if got := normalizeShowingPreset(preset); got != preset {
			t.Fatalf("live preset %q normalized to %q", preset, got)
		}
	}
}

func TestInlineTargetReplayCompactPresetEnablesOnlyV18(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetInlineTargetReplayCompactResearch,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if !sigShortnessV18EnabledForOpts(opts) {
		t.Fatalf("canonical inline-target preset did not enable V18")
	}
	if sigShortnessV7EnabledForOpts(opts) ||
		sigShortnessV8EnabledForOpts(opts) ||
		sigShortnessV9EnabledForOpts(opts) ||
		sigShortnessV10EnabledForOpts(opts) ||
		sigShortnessV11EnabledForOpts(opts) ||
		sigShortnessV12EnabledForOpts(opts) ||
		sigShortnessV13EnabledForOpts(opts) ||
		sigShortnessV14EnabledForOpts(opts) ||
		sigShortnessV15EnabledForOpts(opts) ||
		sigShortnessV16EnabledForOpts(opts) ||
		sigShortnessV17EnabledForOpts(opts) {
		t.Fatalf("canonical inline-target preset enabled a pruned shortness family")
	}
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetInlineTargetReplayCompactResearch {
		t.Fatalf("resolved preset=%q want %q", got, ShowingPresetInlineTargetReplayCompactResearch)
	}
}

func TestBenchmarkSweepReducedCandidatesPreserveBasePresetLabel(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:              true,
		NCols:                   16,
		Ell:                     18,
		DomainMode:              DomainModeExplicit,
		PRFGroupRounds:          2,
		CoeffPacking:            true,
		CoeffNativeSigModel:     CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:           ShowingPresetSoundnessBalanced,
		ShowingReplayMode:       ShowingReplayModeReduced,
		BenchmarkSweepCandidate: "a1_w96_n4096_e40_ep2_sig_r11_l4_production",
		SigShortnessProfile:     SigShortnessProfileR11L4Production,
		LVCSNCols:               96,
		PostSignLVCSNCols:       96,
		PRFLVCSNCols:            96,
		NLeaves:                 4096,
		PostSignNLeaves:         4096,
		PRFNLeaves:              4096,
		Eta:                     40,
		EllPrime:                2,
		Theta:                   3,
		Rho:                     2,
		Kappa:                   [4]int{0, 0, 0, 5},
		PRFCompanionMode:        PRFCompanionModeOutputAudit,
		PRFCheckpointSamples:    8,
	})
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetSoundnessBalanced {
		t.Fatalf("resolved preset=%q want %q", got, ShowingPresetSoundnessBalanced)
	}
	if got := ResolveBenchmarkSweepCandidateLabelForOpts(opts); got != "a1_w96_n4096_e40_ep2_sig_r11_l4_production" {
		t.Fatalf("resolved benchmark sweep candidate=%q", got)
	}
}
