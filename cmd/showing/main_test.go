package main

import (
	"bytes"
	"path/filepath"
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

func TestDefaultShowingProfileIsN512X0Len70_100(t *testing.T) {
	profile, ok := lookupShowingProfile(defaultShowingProfile)
	if !ok {
		t.Fatalf("default showing profile %q is not registered", defaultShowingProfile)
	}
	if profile.Name != showingProfileN512X0Len70_100 {
		t.Fatalf("default showing profile=%q want %q", profile.Name, showingProfileN512X0Len70_100)
	}
	if profile.RingDegree != 512 || profile.X0Len != 70 || profile.SoundnessTarget != 100 {
		t.Fatalf("default profile tuple ring=%d x0=%d target=%.0f", profile.RingDegree, profile.X0Len, profile.SoundnessTarget)
	}
	if profile.StatePath != filepath.Join("credential", "keys", "credential_state.n512_x0len70.json") {
		t.Fatalf("default profile state path=%q", profile.StatePath)
	}
}

func TestMaintainedShowingProfilesAreExactlyX0Len70(t *testing.T) {
	names := showingProfileNames()
	if len(names) != 3 {
		t.Fatalf("maintained showing profile count=%d names=%v", len(names), names)
	}
	for _, name := range names {
		profile, ok := lookupShowingProfile(name)
		if !ok {
			t.Fatalf("profile %q not registered", name)
		}
		if profile.X0Len != 70 {
			t.Fatalf("profile %s x0_len=%d want 70", profile.Name, profile.X0Len)
		}
		if profile.RingDegree != 512 && profile.RingDegree != 1024 {
			t.Fatalf("profile %s ring_degree=%d", profile.Name, profile.RingDegree)
		}
	}
	legacy := strings.Join([]string{"soundness", "balanced"}, "_")
	if _, ok := lookupShowingProfile(legacy); ok {
		t.Fatalf("legacy preset %q registered as maintained profile", legacy)
	}
}

func TestIntGenISISShowingOptsCarriesPresetShortnessAndCompression(t *testing.T) {
	preset, ok := credential.LookupIntGenISISPreset(credential.IntGenISISPresetSW128LVCS64)
	if !ok {
		t.Fatal("missing sw128-lvcs64 preset")
	}
	tuning := preset.Showing
	opts := intGenISISShowingOpts(512, tuning.NCols, tuning.LVCSNCols, tuning.NLeaves, tuning.Eta, tuning.Theta, tuning.Rho, tuning.Ell, tuning.EllPrime, tuning.Kappa, PIOP.PRFCompanionMode(tuning.PRFCompanionMode), tuning.CheckpointSamples, tuning.CompressedRows, tuning.SigShortnessRadix, tuning.SigShortnessDigits, tuning.ReplayProjection)
	if opts.NCols != tuning.NCols || opts.LVCSNCols != tuning.LVCSNCols || opts.NLeaves != tuning.NLeaves {
		t.Fatalf("opts did not carry preset geometry: %+v preset=%+v", opts, tuning)
	}
	if opts.PRFCompanionMode != PIOP.PRFCompanionModeDirectAuth || opts.PRFCheckpointSamples != 2 {
		t.Fatalf("opts PRF mode/samples=%s/%d", opts.PRFCompanionMode, opts.PRFCheckpointSamples)
	}
	if opts.SigShortnessRadix != 11 || opts.SigShortnessL != 4 {
		t.Fatalf("opts shortness=%d/%d", opts.SigShortnessRadix, opts.SigShortnessL)
	}
	if opts.IntGenISISMSECompression != tuning.CompressedRows {
		t.Fatalf("opts compression=%d want %d", opts.IntGenISISMSECompression, tuning.CompressedRows)
	}
	if opts.IntGenISISReplayProjection != "project_u_y_hat_and_y_view_v2" {
		t.Fatalf("opts replay projection=%q", opts.IntGenISISReplayProjection)
	}
}

func TestResearchRingDegree512RejectsDefaultN1024Artifacts(t *testing.T) {
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)
	statePath := filepath.Join("credential", "keys", "credential_state.json")
	state, err := credential.LoadState(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	publicParams, err := loadCredentialPublicParamsFromState(state)
	if err != nil {
		t.Fatalf("load public params: %v", err)
	}
	err = validateArtifactRingDegree(512, statePath, state, publicParams)
	if err == nil {
		t.Fatal("default N=1024 artifacts accepted under research ring_degree=512")
	}
	if !strings.Contains(err.Error(), "fresh N=512 artifacts") {
		t.Fatalf("degree mismatch error did not explain fresh artifacts requirement: %v", err)
	}
}

func TestValidateArtifactRingDegreeRejectsX0Mismatch(t *testing.T) {
	st := credential.State{
		X0Len:      69,
		RingDegree: 512,
		Mu:         [][]int64{make([]int64, 512)},
		R0:         make([][]int64, 69),
		R1:         [][]int64{make([]int64, 512)},
		Z:          [][]int64{make([]int64, 512)},
		SigS1:      make([]int64, 512),
		SigS2:      make([]int64, 512),
	}
	for i := range st.R0 {
		st.R0[i] = make([]int64, 512)
	}
	public := credential.PublicParams{RingDegree: 512, X0Len: 70}
	err := validateArtifactRingDegree(512, "test_state.json", st, public)
	if err == nil {
		t.Fatal("x0_len mismatch accepted")
	}
	if !strings.Contains(err.Error(), "x0_len") {
		t.Fatalf("x0 mismatch error did not mention x0_len: %v", err)
	}
}

func TestDeriveOmegaForOptsUsesRelationAwareWitnessOmega(t *testing.T) {
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	base := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:          true,
		NCols:               16,
		LVCSNCols:           96,
		Ell:                 18,
		NLeaves:             4096,
		DomainMode:          PIOP.DomainModeExplicit,
		CoeffPacking:        true,
		CoeffNativeSigModel: PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
	})
	omega4096, err := deriveOmegaForOpts(ringQ, base, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("deriveOmegaForOpts(4096): %v", err)
	}
	base.NLeaves = 8192
	omega8192, err := deriveOmegaForOpts(ringQ, base, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("deriveOmegaForOpts(8192): %v", err)
	}
	if len(omega4096) != len(omega8192) {
		t.Fatalf("omega length mismatch: 4096=%d 8192=%d", len(omega4096), len(omega8192))
	}
	for i := range omega4096 {
		if omega4096[i] != omega8192[i] {
			t.Fatalf("omega[%d] mismatch: 4096=%d 8192=%d", i, omega4096[i], omega8192[i])
		}
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
			ShowingPreset:     PIOP.ShowingPresetInlineTargetReplayCompactResearch,
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
	if !strings.Contains(line, "preset=aggregate_inline_target_replay_compact_research replay=full blocks=1 lvcs=128 nleaves=2048 rowsBlock=7 maskChunks=2 witness=859 nrows=560 m=288 pcols=272 omitP=288") {
		t.Fatalf("missing nrows/m/pcols summary: %q", line)
	}
	if !strings.Contains(line, "prf_scalars=165 prf_rows=11 (packed)") {
		t.Fatalf("missing packed PRF summary: %q", line)
	}
}

func TestFormatTranscriptOptimizationSummaryShowsFactorizedInstanceGeometry(t *testing.T) {
	line := formatTranscriptOptimizationSummary(PIOP.ProofReport{
		TranscriptFocus: PIOP.TranscriptOptimizationReport{
			ShowingPreset:            PIOP.ShowingPresetInlineTargetReplayCompactResearch,
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
			PRFAuxInstance:           true,
			PRFAuxProofBytes:         4096,
			PRFAuxOpeningBytes:       8192,
		},
	})
	if !strings.Contains(line, "main=32/4096 prf=24/1024 hidden=128/1024") {
		t.Fatalf("missing factorized instance geometry: %q", line)
	}
	if !strings.Contains(line, "prf_aux=on auxProof=4096 auxOpening=8192 bridgeRows=0 bridgeSlots=0 bridgeBlocks=0 bridgePad=0") {
		t.Fatalf("missing aux-instance size summary: %q", line)
	}
}

func TestFormatStatementSummaryShowsClassReplayAndShortness(t *testing.T) {
	line := formatStatementSummary(PIOP.ProofReport{
		TranscriptFocus: PIOP.TranscriptOptimizationReport{
			StatementClass: string(PIOP.ShowingStatementClassTheoremCleanFullReplay),
			ReplayMode:     string(PIOP.ShowingReplayModeFull),
			ShortnessMode:  PIOP.SigShortnessModeHiddenV6,
		},
		SigShortness: PIOP.SigShortnessReport{
			Enabled: true,
			Mode:    PIOP.SigShortnessModeHiddenV6,
		},
	})
	if !strings.Contains(line, "class=theorem_clean_full_replay") {
		t.Fatalf("missing statement class: %q", line)
	}
	if !strings.Contains(line, "replay=full") {
		t.Fatalf("missing replay mode: %q", line)
	}
	if !strings.Contains(line, "shortness=sig_shortness_v6_hidden") {
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
			Mode:    PIOP.SigShortnessModeHiddenV6,
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

func TestPrintSigShortnessShowsSupportSlots(t *testing.T) {
	var out bytes.Buffer
	var errBuf bytes.Buffer
	old := cli
	cli = cliRenderer{out: &out, err: &errBuf, colorEnabled: false}
	defer func() { cli = old }()

	printSigShortness("[showing-cli] ", PIOP.ProofReport{
		SigShortness: PIOP.SigShortnessReport{
			Enabled:          true,
			Mode:             PIOP.SigShortnessModeHiddenV6,
			Version:          6,
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
