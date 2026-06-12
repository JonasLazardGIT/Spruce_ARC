package main

import (
	"bytes"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func TestFormatPaperTranscriptSummaryUsesPaperWording(t *testing.T) {
	line := formatPaperTranscriptSummary(PIOP.ProofReport{
		PaperTranscript: PIOP.PaperTranscriptReport{OptimizedBytes: 12345},
	})
	if !strings.Contains(line, "Paper transcript") {
		t.Fatalf("missing paper transcript wording: %q", line)
	}
	if strings.Contains(line, "Canonical transcript") {
		t.Fatalf("stale canonical wording still present: %q", line)
	}
}

func TestIntGenISISShowingOptsCarriesPresetShortnessAndCompression(t *testing.T) {
	preset, ok := credential.LookupIntGenISISPreset(credential.IntGenISISPresetN1024Compact125)
	if !ok {
		t.Fatal("missing n1024-compact125 preset")
	}
	tuning := preset.Showing
	opts := intGenISISShowingOpts(1024, tuning)
	if opts.NCols != tuning.NCols || opts.LVCSNCols != tuning.LVCSNCols || opts.NLeaves != tuning.NLeaves {
		t.Fatalf("opts did not carry preset geometry: %+v preset=%+v", opts, tuning)
	}
	if opts.PRFCompanionMode != PIOP.PRFCompanionModeDirectFull || opts.PRFCheckpointSamples != tuning.CheckpointSamples {
		t.Fatalf("opts PRF mode/samples=%s/%d", opts.PRFCompanionMode, opts.PRFCheckpointSamples)
	}
	if opts.SigShortnessRadix != 11 || opts.SigShortnessL != 4 {
		t.Fatalf("opts shortness=%d/%d", opts.SigShortnessRadix, opts.SigShortnessL)
	}
	if opts.IntGenISISMSECompression != tuning.CompressedRows {
		t.Fatalf("opts compression=%d want %d", opts.IntGenISISMSECompression, tuning.CompressedRows)
	}
	if opts.IntGenISISReplayProjection != "project_u_digits_y_w_residual_v5" {
		t.Fatalf("opts replay projection=%q", opts.IntGenISISReplayProjection)
	}
}

func TestShowingCLIPropagatesPresetAccounting(t *testing.T) {
	cfg, err := parseShowingCLIArgs([]string{
		"-preset", credential.IntGenISISPresetN1024Q16_128,
	})
	if err != nil {
		t.Fatalf("parse showing query-budget preset: %v", err)
	}
	opts := intGenISISShowingOpts(1024, cfg.Preset.Showing)
	wantCaps := [5]int{65536, 65536, 65536, 65536, 65536}
	if !opts.ROQueryCapsSet || opts.ROQueryCaps != wantCaps {
		t.Fatalf("opts query caps=%v set=%v", opts.ROQueryCaps, opts.ROQueryCapsSet)
	}
	if opts.DECSCollisionBits != 168 {
		t.Fatalf("opts decs collision bits=%d", opts.DECSCollisionBits)
	}
}

func TestShowingVerboseFlagParses(t *testing.T) {
	cfg, err := parseShowingCLIArgs([]string{
		"-preset", credential.IntGenISISPresetN512Compact96,
		"-verbose",
	})
	if err != nil {
		t.Fatalf("parse showing verbose flag: %v", err)
	}
	if !cfg.Verbose {
		t.Fatal("verbose flag was not carried into config")
	}
}

func TestShowingRemovedFlagsAreUnknown(t *testing.T) {
	for _, flagName := range []string{
		"-prf-companion-mode",
		"-intgenisis-replay-projection",
		"-sig-shortness-profile",
		"-fixed-transcript-size",
		"-ro-query-caps",
		"-decs-collision-bits",
		"-decs-collision-bytes",
	} {
		t.Run(flagName, func(t *testing.T) {
			_, err := parseShowingCLIArgs([]string{"-preset", "n512-compact96", flagName, "x"})
			if err == nil {
				t.Fatalf("%s unexpectedly parsed", flagName)
			}
			if !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Fatalf("unexpected error for %s: %v", flagName, err)
			}
		})
	}
}

func TestFormatPaperTranscriptReductionSummaryShowsRSavedAndQSaved(t *testing.T) {
	line := formatPaperTranscriptReductionSummary(PIOP.ProofReport{
		PaperTranscript: PIOP.PaperTranscriptReport{
			R: PIOP.PaperTranscriptBucket{NaiveBits: 100, OptimizedBits: 60},
			Q: PIOP.PaperTranscriptBucket{NaiveBits: 200, OptimizedBits: 160},
		},
	})
	if !strings.Contains(line, "R saved=40b") {
		t.Fatalf("missing R reduction summary: %q", line)
	}
	if !strings.Contains(line, "Q saved=40b") {
		t.Fatalf("missing Q reduction summary: %q", line)
	}
}

func TestFormatTranscriptOptimizationSummaryShowsPackedPRFGeometry(t *testing.T) {
	line := formatTranscriptOptimizationSummary(PIOP.ProofReport{
		TranscriptFocus: PIOP.TranscriptOptimizationReport{
			ShowingPreset:     PIOP.ShowingPresetInlineTargetReplayCompact,
			ReplayMode:        string(PIOP.ShowingReplayModeFull),
			ReplayBlocks:      1,
			LVCSNCols:         128,
			NLeaves:           2048,
			WitnessRows:       859,
			RowsBlock:         7,
			MaskChunks:        2,
			PRFPacked:         true,
			PRFLogicalScalars: 165,
			PRFPackedRows:     11,
			NRows:             560,
			M:                 288,
			PCols:             272,
			OmitP:             288,
			RowOpeningEntries: 36,
		},
	})
	if !strings.Contains(line, "preset=aggregate_inline_target_replay_compact replay=full blocks=1 lvcs=128 nleaves=2048 rowsBlock=7 maskChunks=2 witness=859 nrows=560 m=288 pcols=272 omitP=288") {
		t.Fatalf("missing nrows/m/pcols summary: %q", line)
	}
	if !strings.Contains(line, "prf_scalars=165 prf_rows=11 (packed)") {
		t.Fatalf("missing packed PRF summary: %q", line)
	}
}

func TestFormatTranscriptOptimizationSummaryShowsFactorizedInstanceGeometry(t *testing.T) {
	line := formatTranscriptOptimizationSummary(PIOP.ProofReport{
		TranscriptFocus: PIOP.TranscriptOptimizationReport{
			ShowingPreset:            PIOP.ShowingPresetInlineTargetReplayCompact,
			ReplayMode:               string(PIOP.ShowingReplayModeFull),
			ReplayBlocks:             32,
			LVCSNCols:                32,
			NLeaves:                  4096,
			WitnessRows:              561,
			RowsBlock:                18,
			MaskChunks:               10,
			PRFPacked:                true,
			PRFLogicalScalars:        165,
			PRFPackedRows:            11,
			NRows:                    560,
			M:                        288,
			PCols:                    272,
			OmitP:                    288,
			RowOpeningEntries:        36,
			MainLVCSNCols:            32,
			MainNLeaves:              4096,
			PRFLVCSNCols:             24,
			PRFNLeaves:               1024,
			HiddenShortnessLVCSNCols: 128,
			HiddenShortnessNLeaves:   1024,
		},
	})
	if !strings.Contains(line, "main=32/4096 prf=24/1024 hidden=128/1024") {
		t.Fatalf("missing factorized instance geometry: %q", line)
	}
}

func TestFormatStatementSummaryShowsClassReplayAndShortness(t *testing.T) {
	line := formatStatementSummary(PIOP.ProofReport{
		TranscriptFocus: PIOP.TranscriptOptimizationReport{
			StatementClass: string(PIOP.ShowingStatementClassTheoremCleanFullReplay),
			ReplayMode:     string(PIOP.ShowingReplayModeFull),
			ShortnessMode:  PIOP.SigShortnessModeReplayCompactV18,
		},
		SigShortness: PIOP.SigShortnessReport{
			Enabled: true,
			Mode:    PIOP.SigShortnessModeReplayCompactV18,
		},
	})
	if !strings.Contains(line, "class=theorem_clean_full_replay") {
		t.Fatalf("missing statement class: %q", line)
	}
	if !strings.Contains(line, "replay=full") {
		t.Fatalf("missing replay mode: %q", line)
	}
	if !strings.Contains(line, "shortness=sig_shortness_inline_target_replay_compact_hiding") {
		t.Fatalf("missing shortness mode: %q", line)
	}
}

func TestFormatStatementSummaryDistinguishesReducedAndFull(t *testing.T) {
	reduced := formatStatementSummary(PIOP.ProofReport{
		TranscriptFocus: PIOP.TranscriptOptimizationReport{
			StatementClass: string(PIOP.ShowingStatementClassReducedEngineeringReplay),
			ReplayMode:     string(PIOP.ShowingReplayModeReduced),
		},
		SigShortness: PIOP.SigShortnessReport{
			Enabled: true,
			Mode:    PIOP.SigShortnessModeReplayCompactV18,
		},
	})
	full := formatStatementSummary(PIOP.ProofReport{
		TranscriptFocus: PIOP.TranscriptOptimizationReport{
			StatementClass: string(PIOP.ShowingStatementClassTheoremCleanFullReplay),
			ReplayMode:     string(PIOP.ShowingReplayModeFull),
		},
		SigShortness: PIOP.SigShortnessReport{
			Enabled: true,
			Mode:    PIOP.SigShortnessModeReplayCompactV18,
		},
	})
	if reduced == full {
		t.Fatalf("reduced/full statement summaries unexpectedly identical: %q", reduced)
	}
	if !strings.Contains(reduced, "reduced_engineering_replay") || !strings.Contains(full, "theorem_clean_full_replay") {
		t.Fatalf("unexpected statement summaries: reduced=%q full=%q", reduced, full)
	}
}

func TestFormatReplayFamilyAuditSummaryListsSelectedFamilies(t *testing.T) {
	line := formatReplayFamilyAuditSummary(PIOP.ProofReport{
		ReplayAudit: PIOP.ReplayFamilyAuditReport{
			Selector: PIOP.ReplayActiveRowStats{
				SelectedRows: 16,
				WitnessRows:  22,
				ActiveBlocks: 2,
				FullBlocks:   2,
				ReductionPct: 27.27,
			},
			Families: []PIOP.ReplayFamilyAuditEntry{
				{Family: PIOP.ReplayFamilyTSource, SelectedRowCount: 0},
				{Family: PIOP.ReplayFamilySourceProduct, SelectedRowCount: 2},
				{Family: PIOP.ReplayFamilyCarrier, SelectedRowCount: 2},
				{Family: PIOP.ReplayFamilyPRFCompanion, SelectedRowCount: 12},
			},
		},
	})
	if !strings.Contains(line, "selectedFamilies=source_product, carrier, prf_companion") {
		t.Fatalf("missing selected family summary: %q", line)
	}
	if strings.Contains(line, "top_stage_b") {
		t.Fatalf("stale stage-B wording still present: %q", line)
	}
}

func TestFormatReplaySubfamilyAuditSummaryListsSelectedKinds(t *testing.T) {
	line := formatReplaySubfamilyAuditSummary(PIOP.ReplaySubfamilyAuditReport{
		Entries: []PIOP.ReplaySubfamilyAuditEntry{
			{Kind: PIOP.ReplaySubfamilySourceProductMSigmaR1, SelectedRowCount: 1},
			{Kind: PIOP.ReplaySubfamilySourceProductR0R1, SelectedRowCount: 1},
			{Kind: PIOP.ReplaySubfamilyPRFKeyRows, SelectedRowCount: 1},
			{Kind: PIOP.ReplaySubfamilyPRFCheckpointRows, SelectedRowCount: 10},
			{Kind: PIOP.ReplaySubfamilyPRFFinalTagRows, SelectedRowCount: 2},
			{Kind: PIOP.ReplaySubfamilyPRFHelperRows, SelectedRowCount: 1},
		},
	})
	if !strings.Contains(line, "selectedSubfamilies=source_product_msigmar1, source_product_r0r1, prf_key_rows, prf_checkpoint_rows, prf_final_tag_rows, prf_helper_rows") {
		t.Fatalf("missing selected subfamily summary: %q", line)
	}
	if strings.Contains(line, "top_remaining") {
		t.Fatalf("stale ranked-target wording still present: %q", line)
	}
}

func TestFormatSoundnessComponentShowsClampReason(t *testing.T) {
	line := formatSoundnessComponent("eps1", -336.91, 0)
	if !strings.Contains(line, "eps1=0.00 (clamped from raw -336.91)") {
		t.Fatalf("missing clamp wording: %q", line)
	}
}

func TestFormatSoundnessNotesExplainsRawClampAndGrinding(t *testing.T) {
	line := formatSoundnessNotes(PIOP.ProofReport{
		Soundness: PIOP.SoundnessBudget{
			Clamped: [4]bool{true, false, false, false},
		},
		Kappa: [4]int{128, 0, 0, 58},
	})
	if !strings.Contains(line, "eps1 raw term is negative and is paper-clamped to 0") {
		t.Fatalf("missing raw-clamp explanation: %q", line)
	}
	if !strings.Contains(line, "algebraic round bits already include grinding") {
		t.Fatalf("missing grinding explanation: %q", line)
	}
}

func TestFormatTranscriptBucketFocusSummaryShowsDominantPaperBuckets(t *testing.T) {
	line := formatTranscriptBucketFocusSummary(PIOP.ProofReport{
		TranscriptFocus: PIOP.TranscriptOptimizationReport{
			PdecsBytes:    15000,
			VTargetsBytes: 11800,
			BarSetsBytes:  8900,
			QBytes:        9000,
		},
	})
	if !strings.Contains(line, "Pdecs=15000") || !strings.Contains(line, "VTargets=11800") {
		t.Fatalf("missing dominant bucket summary: %q", line)
	}
	if !strings.Contains(line, "BarSets=8900") || !strings.Contains(line, "Q=9000") {
		t.Fatalf("missing bucket fields: %q", line)
	}
}

func TestOrderedPaperTranscriptRowsSortsByOptimizedBytesAndOmitsZero(t *testing.T) {
	rows := orderedPaperTranscriptRows(PIOP.PaperTranscriptReport{
		OptimizedBytes: 100,
		R:              PIOP.PaperTranscriptBucket{OptimizedBytes: 12, OptimizedBits: 96},
		Q:              PIOP.PaperTranscriptBucket{OptimizedBytes: 20, OptimizedBits: 160},
		Auth:           PIOP.PaperTranscriptBucket{OptimizedBytes: 20, OptimizedBits: 159},
		BarSets:        PIOP.PaperTranscriptBucket{OptimizedBytes: 0, OptimizedBits: 0},
	})
	if len(rows) != 3 {
		t.Fatalf("row count=%d, want 3 non-zero rows", len(rows))
	}
	if rows[0].Label != "Q" || rows[1].Label != "Auth" || rows[2].Label != "R" {
		t.Fatalf("unexpected row order: %+v", rows)
	}
}

func TestStyleMessageAddsAnsiWhenEnabledAndFallsBackPlain(t *testing.T) {
	colored := styleMessage(true, categoryTranscript, "hello")
	if !strings.Contains(colored, "\x1b[35mhello\x1b[0m") {
		t.Fatalf("missing transcript ANSI color: %q", colored)
	}
	plain := styleMessage(false, categoryTranscript, "hello")
	if plain != "hello" {
		t.Fatalf("plain fallback mismatch: %q", plain)
	}
}

func TestPrintPaperTranscriptBreakdownUsesPaperHeaderNotLegacyBreakdown(t *testing.T) {
	var out bytes.Buffer
	var errBuf bytes.Buffer
	old := cli
	cli = cliRenderer{out: &out, err: &errBuf, colorEnabled: false}
	defer func() { cli = old }()

	printPaperTranscriptBreakdown("[showing-cli] ", PIOP.ProofReport{
		PaperTranscript: PIOP.PaperTranscriptReport{
			OptimizedBytes: 100,
			Q:              PIOP.PaperTranscriptBucket{OptimizedBytes: 20, OptimizedBits: 160},
			R:              PIOP.PaperTranscriptBucket{OptimizedBytes: 12, OptimizedBits: 96},
		},
	})

	got := out.String()
	if !strings.Contains(got, "Paper transcript breakdown (optimized, bytes, total=100):") {
		t.Fatalf("missing paper transcript breakdown header: %q", got)
	}
	if strings.Contains(got, "Current verifier-consumed size breakdown") {
		t.Fatalf("legacy live-size breakdown still present: %q", got)
	}
	if !strings.Contains(got, "Q                20") || !strings.Contains(got, "R                12") {
		t.Fatalf("missing paper bucket lines: %q", got)
	}
}

func TestPrintSigShortnessShowsSupportSlots(t *testing.T) {
	var out bytes.Buffer
	var errBuf bytes.Buffer
	old := cli
	cli = cliRenderer{out: &out, err: &errBuf, colorEnabled: false}
	defer func() { cli = old }()

	printSigShortness("[showing-cli] ", PIOP.ProofReport{
		SigShortness: PIOP.SigShortnessReport{
			Enabled:          true,
			Mode:             PIOP.SigShortnessModeReplayCompactV18,
			Version:          18,
			SupportSlotCount: 16,
			OpenedBlockCount: 13,
			OpeningBytes:     14469,
			ProofBytes:       23370,
		},
	})

	got := out.String()
	if !strings.Contains(got, "slots=16") || !strings.Contains(got, "blocks=13") {
		t.Fatalf("missing shortness slot summary: %q", got)
	}
}

func TestPrintConciseProofReportOmitsDetailedBreakdown(t *testing.T) {
	var out bytes.Buffer
	var errBuf bytes.Buffer
	old := cli
	cli = cliRenderer{out: &out, err: &errBuf, colorEnabled: false}
	defer func() { cli = old }()

	printConciseProofReport("[showing-cli] ", PIOP.ProofReport{
		PaperTranscript: PIOP.PaperTranscriptReport{OptimizedBytes: 22008},
		Soundness:       PIOP.SoundnessBudget{TotalBits: 96.5},
	}, 2, 3)

	got := out.String()
	for _, want := range []string{"paper_transcript_bytes=22008", "paper_transcript_kb=21.49", "theorem_total_bits=96.50", "timing prove=2ns verify=3ns"} {
		if !strings.Contains(got, want) {
			t.Fatalf("concise proof report missing %q: %s", want, got)
		}
	}
	for _, stale := range []string{"Paper transcript breakdown", "Current verifier payload", "Table row", "Bucket focus"} {
		if strings.Contains(got, stale) {
			t.Fatalf("concise proof report retained detailed field %q: %s", stale, got)
		}
	}
}

func TestFormatWitnessGeometrySummaryIsCompact(t *testing.T) {
	line := formatWitnessGeometrySummary(PIOP.WitnessGeometrySnapshot{
		ActualWitnessPolys:         561,
		ActualPostSignWitnessPolys: 395,
		ActualPRFWitnessPolys:      166,
		WitnessRowsCommitted:       528,
		MaskRowsCommitted:          228,
		PCSBlockCount:              24,
		RowsPerBlock:               22,
		FinalBlockSlack:            15,
		PostSignPrefixSlack:        13,
		OccupancyPct:               97.4,
		ReplayToWitnessExpansion:   1.0,
		ReplayPostSignRows:         395,
		ReplayPRFRows:              166,
	})
	if !strings.Contains(line, "Geometry: witness=561 (post=395 prf=166)") {
		t.Fatalf("missing grouped witness summary: %q", line)
	}
	if !strings.Contains(line, "committed=528 mask=228 blocks=24x22 occupancy=97.4%") {
		t.Fatalf("missing compact committed/block summary: %q", line)
	}
	if !strings.Contains(line, "slack=15/13") || !strings.Contains(line, "prf_replay=1.00x") {
		t.Fatalf("missing compact trailing metrics: %q", line)
	}
	if strings.Contains(line, "witness_polys=") || strings.Contains(line, "replay_post=") || strings.Contains(line, "rows_per_block=") {
		t.Fatalf("old unreadable field dump still present: %q", line)
	}
}
