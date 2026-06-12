package PIOP

import "testing"

func TestUnsupportedShowingPresetStringsNormalizeToEmpty(t *testing.T) {
	for _, preset := range []string{
		"",
		"production_balance",
		"compact_l3",
		"aggregate_replay_removed",
	} {
		if got := normalizeShowingPreset(preset); got != "" {
			t.Fatalf("unsupported preset %q normalized to %q, want empty", preset, got)
		}
	}
}

func TestOnlyOptimizedV18ShowingPresetRemainsLive(t *testing.T) {
	if got := normalizeShowingPreset(ShowingPresetInlineTargetReplayCompact); got != ShowingPresetInlineTargetReplayCompact {
		t.Fatalf("live preset normalized to %q", got)
	}
}

func TestInlineTargetReplayCompactPresetEnablesOnlyV18(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  0,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetInlineTargetReplayCompact,
		PRFCompanionMode:     PRFCompanionModeDirectFull,
		PRFCheckpointSamples: 8,
	})
	if !sigShortnessV18EnabledForOpts(opts) {
		t.Fatalf("canonical inline-target preset did not enable V18")
	}
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetInlineTargetReplayCompact {
		t.Fatalf("resolved preset=%q want %q", got, ShowingPresetInlineTargetReplayCompact)
	}
	if opts.MuWitnessPackWidth != 2 {
		t.Fatalf("inline-target mu witness pack width=%d want 2", opts.MuWitnessPackWidth)
	}
}
