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

func TestSigShortnessV7EnabledForShippedCompactL1Full(t *testing.T) {
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
	if !sigShortnessV7EnabledForOpts(opts) {
		t.Fatalf("compact_l1_research -full should enable V7")
	}
	if got := ResolveSignatureShortnessProfileLabelForOpts(opts); got != compactL1ResearchFullV7Profile() {
		t.Fatalf("compact_l1_research -full profile=%q want %q", got, compactL1ResearchFullV7Profile())
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
	if got := ResolveSignatureShortnessProfileLabelForOpts(full); got != compactL1ResearchFullV7Profile() {
		t.Fatalf("compact_l1_research full profile=%q want %q", got, compactL1ResearchFullV7Profile())
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

func TestCompactFullBenchmarkCandidatesResolveAsCompactL1ResearchV7(t *testing.T) {
	for _, candidate := range CompactFullCandidateIDs() {
		t.Run(candidate, func(t *testing.T) {
			opts := ResolveSimOptsDefaults(SimOpts{
				Credential:           true,
				NCols:                16,
				Ell:                  18,
				DomainMode:           DomainModeExplicit,
				NLeaves:              4096,
				PRFGroupRounds:       2,
				CoeffPacking:         true,
				CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
				ShowingPreset:        ShowingPresetCompactL1Research,
				ShowingReplayMode:    ShowingReplayModeFull,
				CompactFullCandidate: candidate,
				PRFCompanionMode:     PRFCompanionModeOutputAudit,
				PRFCheckpointSamples: 8,
			})
			if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetCompactL1Research {
				t.Fatalf("candidate %s resolved preset=%q want %q", candidate, got, ShowingPresetCompactL1Research)
			}
			if got := ResolveCompactFullCandidateLabelForOpts(opts); got != candidate {
				t.Fatalf("candidate %s resolved compact_full_candidate=%q", candidate, got)
			}
			if !sigShortnessV7EnabledForOpts(opts) {
				t.Fatalf("candidate %s should stay on V7", candidate)
			}
		})
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

func TestCompactFullSweepCandidatesResolveAsCompactL1ResearchV7(t *testing.T) {
	candidate := makeCompactFullSweepCandidateID(48, 4096, 24, 2, SigShortnessProfileR24L3Compact, [4]int{0, 0, 0, 2})
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:              true,
		NCols:                   16,
		Ell:                     18,
		DomainMode:              DomainModeExplicit,
		PRFGroupRounds:          2,
		CoeffPacking:            true,
		CoeffNativeSigModel:     CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:           ShowingPresetCompactL1Research,
		ShowingReplayMode:       ShowingReplayModeFull,
		CompactFullCandidate:    candidate,
		BenchmarkSweepCandidate: candidate,
		PRFCompanionMode:        PRFCompanionModeOutputAudit,
		PRFCheckpointSamples:    8,
	})
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetCompactL1Research {
		t.Fatalf("resolved preset=%q want %q", got, ShowingPresetCompactL1Research)
	}
	if got := ResolveCompactFullCandidateLabelForOpts(opts); got != candidate {
		t.Fatalf("resolved compact full candidate=%q want %q", got, candidate)
	}
	if !sigShortnessV7EnabledForOpts(opts) {
		t.Fatalf("compact full sweep candidate should stay on V7")
	}
	if got := ResolveSignatureShortnessProfileLabelForOpts(opts); got != SigShortnessProfileR24L3Compact {
		t.Fatalf("resolved sig profile=%q want %q", got, SigShortnessProfileR24L3Compact)
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
