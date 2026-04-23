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
