package PIOP

import "testing"

func TestResolveShowingPresetLabelForOptsPreservesTranscriptFirstRequest(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetTranscriptFirst,
		SigShortnessProfile:  SigShortnessProfileR11L4Production,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetTranscriptFirst {
		t.Fatalf("resolved preset=%q want %q", got, ShowingPresetTranscriptFirst)
	}
}

func TestResolveShowingPresetLabelForOptsPreservesProductionBalanceRequest(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetProductionBalance,
		SigShortnessProfile:  SigShortnessProfileR11L4Production,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetProductionBalance {
		t.Fatalf("resolved preset=%q want %q", got, ShowingPresetProductionBalance)
	}
}

func TestSigShortnessV7DisabledForShippedCompactL1Full(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetCompactL1Research,
		ShowingReplayMode:    ShowingReplayModeFull,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if sigShortnessV7EnabledForOpts(opts) {
		t.Fatalf("compact_l1_research -full should not enable removed V7")
	}
	if got := ResolveSigShortnessMode(&Proof{SigShortness: &SigShortnessProof{Version: sigShortnessProofVersionV6}}); got != SigShortnessModeHiddenV6 {
		t.Fatalf("V6 mode=%q want %q", got, SigShortnessModeHiddenV6)
	}
}

func TestSigShortnessV7DisabledForCompactL1FullRawOverride(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetCompactL1Research,
		ShowingReplayMode:    ShowingReplayModeFull,
		SigShortnessRadix:    11,
		SigShortnessL:        4,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if sigShortnessV7EnabledForOpts(opts) {
		t.Fatalf("compact_l1_research -full with raw override should fall back to V6")
	}
}

func TestSigShortnessV7DisabledForCompactL1FullProfileOverride(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetCompactL1Research,
		ShowingReplayMode:    ShowingReplayModeFull,
		SigShortnessProfile:  SigShortnessProfileR24L3Compact,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if sigShortnessV7EnabledForOpts(opts) {
		t.Fatalf("compact_l1_research -full with profile override should fall back to V6")
	}
}

func TestCompactL1ResearchPresetSplitsProfileByReplayMode(t *testing.T) {
	reduced := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetCompactL1Research,
		ShowingReplayMode:    ShowingReplayModeReduced,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if got := ResolveSignatureShortnessProfileLabelForOpts(reduced); got != SigShortnessProfileR12285L1Research {
		t.Fatalf("compact_l1_research reduced profile=%q want %q", got, SigShortnessProfileR12285L1Research)
	}

	full := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetCompactL1Research,
		ShowingReplayMode:    ShowingReplayModeFull,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if got := ResolveSignatureShortnessProfileLabelForOpts(full); got == "" {
		t.Fatalf("compact_l1_research full profile should remain explicit for V6 fallback")
	}
}

func TestSigShortnessV7DisabledForReducedAndOtherFullPresets(t *testing.T) {
	reduced := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetCompactL1Research,
		ShowingReplayMode:    ShowingReplayModeReduced,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if sigShortnessV7EnabledForOpts(reduced) {
		t.Fatalf("reduced replay should stay on V6")
	}
	transcriptFirstFull := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetTranscriptFirst,
		ShowingReplayMode:    ShowingReplayModeFull,
		SigShortnessProfile:  SigShortnessProfileR11L4Production,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if sigShortnessV7EnabledForOpts(transcriptFirstFull) {
		t.Fatalf("other full presets should stay on V6")
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

func TestCompactFullBenchmarkCustomGeometryFallsOffV7(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetCompactL1Research,
		ShowingReplayMode:    ShowingReplayModeFull,
		LVCSNCols:            48,
		PostSignLVCSNCols:    48,
		PRFLVCSNCols:         48,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetCustom {
		t.Fatalf("custom compact-full override resolved preset=%q want %q", got, ShowingPresetCustom)
	}
	if sigShortnessV7EnabledForOpts(opts) {
		t.Fatalf("custom compact-full geometry override should fall off V7")
	}
}
