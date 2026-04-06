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
