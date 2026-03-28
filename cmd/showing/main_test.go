package main

import (
	"bytes"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
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
			ShowingPreset:     PIOP.ShowingPresetTranscriptFirst,
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
	if !strings.Contains(line, "preset=transcript_first lvcs=128 nleaves=2048 rowsBlock=7 maskChunks=2 witness=859 nrows=560 m=288 pcols=272 omitP=288") {
		t.Fatalf("missing nrows/m/pcols summary: %q", line)
	}
	if !strings.Contains(line, "prf_scalars=165 prf_rows=11 (packed)") {
		t.Fatalf("missing packed PRF summary: %q", line)
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
	if !strings.Contains(line, "Thm.9 round bits already include grinding") {
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
