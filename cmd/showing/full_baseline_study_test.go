package main

import (
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
)

func buildFullBaselineStudyForCompactL1Research(t *testing.T) (*PIOP.Proof, PIOP.ProofReport, PIOP.FullProofStudyReport, PIOP.SimOpts, PIOP.PublicInputs) {
	t.Helper()
	resolved := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           PIOP.DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        PIOP.ShowingPresetCompactL1Research,
		ShowingReplayMode:    PIOP.ShowingReplayModeFull,
		PRFCompanionMode:     PIOP.PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	proof, rep, _, opts, ringQ, pub := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
		t,
		PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		false,
		false,
		"",
		8,
		PIOP.ShowingPresetCompactL1Research,
		resolved.SigShortnessProfile,
		0,
		0,
		16,
		resolved.PostSignLVCSNCols,
		func(opts *PIOP.SimOpts) {
			opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
		},
	)
	study, err := PIOP.BuildFullProofStudyReport(proof, pub, opts, ringQ)
	if err != nil {
		t.Fatalf("build full proof study: %v", err)
	}
	return proof, rep, study, opts, pub
}

func studyLeverByName(t *testing.T, study PIOP.FullProofStudyReport, name string) PIOP.FullProofStudyLever {
	t.Helper()
	for _, lever := range study.LeverMatrix {
		if lever.Name == name {
			return lever
		}
	}
	t.Fatalf("missing study lever %q", name)
	return PIOP.FullProofStudyLever{}
}

func studyWitnessFamilyByName(t *testing.T, study PIOP.FullProofStudyReport, name string) PIOP.FullProofStudyWitnessFamily {
	t.Helper()
	for _, fam := range study.WitnessFamilies {
		if fam.Name == name {
			return fam
		}
	}
	t.Fatalf("missing witness family %q", name)
	return PIOP.FullProofStudyWitnessFamily{}
}

func TestShowingFullBaselineStudyCompactL1ResearchFullPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, study, _, _ := buildFullBaselineStudyForCompactL1Research(t)
	if rep.TranscriptFocus.StatementClass != string(PIOP.ShowingStatementClassTheoremCleanFullReplay) {
		t.Fatalf("statement class=%q want %q", rep.TranscriptFocus.StatementClass, PIOP.ShowingStatementClassTheoremCleanFullReplay)
	}
	if proof.SourceProductBridge != nil {
		t.Fatal("compact full baseline unexpectedly emitted a source-product bridge")
	}
	if study.BaselineSnapshot.StatementClass != rep.TranscriptFocus.StatementClass {
		t.Fatalf("study statement class=%q want %q", study.BaselineSnapshot.StatementClass, rep.TranscriptFocus.StatementClass)
	}
	if study.BaselineSnapshot.OptimizedBytes < compactL1ResearchFullOptimizedBytesMin || study.BaselineSnapshot.OptimizedBytes > compactL1ResearchFullOptimizedBytesMax {
		t.Fatalf("study optimized bytes=%d want in [%d,%d] around control %d", study.BaselineSnapshot.OptimizedBytes, compactL1ResearchFullOptimizedBytesMin, compactL1ResearchFullOptimizedBytesMax, compactL1ResearchFullControlOptimizedBytes)
	}
	if study.BaselineSnapshot.OptimizedBytes != rep.PaperTranscript.OptimizedBytes {
		t.Fatalf("study optimized bytes=%d want %d", study.BaselineSnapshot.OptimizedBytes, rep.PaperTranscript.OptimizedBytes)
	}
	if study.BaselineSnapshot.SigShortnessBytes != rep.PaperTranscript.SigShortness.OptimizedBytes {
		t.Fatalf("study sig shortness bytes=%d want %d", study.BaselineSnapshot.SigShortnessBytes, rep.PaperTranscript.SigShortness.OptimizedBytes)
	}
	if study.BaselineSnapshot.PdecsBytes != rep.PaperTranscript.Pdecs.OptimizedBytes {
		t.Fatalf("study Pdecs bytes=%d want %d", study.BaselineSnapshot.PdecsBytes, rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if study.BaselineSnapshot.VTargetsBytes != rep.PaperTranscript.VTargets.OptimizedBytes {
		t.Fatalf("study VTargets bytes=%d want %d", study.BaselineSnapshot.VTargetsBytes, rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if study.BaselineSnapshot.BarSetsBytes != rep.PaperTranscript.BarSets.OptimizedBytes {
		t.Fatalf("study BarSets bytes=%d want %d", study.BaselineSnapshot.BarSetsBytes, rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if study.BaselineSnapshot.QBytes != rep.PaperTranscript.Q.OptimizedBytes {
		t.Fatalf("study Q bytes=%d want %d", study.BaselineSnapshot.QBytes, rep.PaperTranscript.Q.OptimizedBytes)
	}
	if study.BaselineSnapshot.SelectorSelectedRows != rep.ReplayAudit.Selector.SelectedRows ||
		study.BaselineSnapshot.SelectorWitnessRows != rep.ReplayAudit.Selector.WitnessRows ||
		study.BaselineSnapshot.SelectorActiveBlocks != rep.ReplayAudit.Selector.ActiveBlocks {
		t.Fatalf("study selector mismatch: %+v audit=%+v", study.BaselineSnapshot, rep.ReplayAudit.Selector)
	}
	if study.BaselineSnapshot.HiddenShortnessProofBytes != rep.SigShortness.HiddenProofBytes {
		t.Fatalf("study hidden shortness proof bytes=%d want %d", study.BaselineSnapshot.HiddenShortnessProofBytes, rep.SigShortness.HiddenProofBytes)
	}
	if study.HiddenShortness.HiddenProofBytes != rep.SigShortness.HiddenProofBytes {
		t.Fatalf("hidden study proof bytes=%d want %d", study.HiddenShortness.HiddenProofBytes, rep.SigShortness.HiddenProofBytes)
	}
	if study.HiddenShortness.OpeningBytes != rep.SigShortness.OpeningBytes {
		t.Fatalf("hidden study opening bytes=%d want %d", study.HiddenShortness.OpeningBytes, rep.SigShortness.OpeningBytes)
	}
	if study.HiddenShortness.OpeningBytes < compactL1ResearchFullOuterShortnessOpeningMin || study.HiddenShortness.OpeningBytes > compactL1ResearchFullOuterShortnessOpeningMax {
		t.Fatalf("hidden study opening bytes=%d want in [%d,%d] around control %d", study.HiddenShortness.OpeningBytes, compactL1ResearchFullOuterShortnessOpeningMin, compactL1ResearchFullOuterShortnessOpeningMax, compactL1ResearchFullControlOuterShortnessOpeningB)
	}
	if study.HiddenShortness.OuterSupportSlotCount != rep.SigShortness.SupportSlotCount {
		t.Fatalf("hidden study support slots=%d want %d", study.HiddenShortness.OuterSupportSlotCount, rep.SigShortness.SupportSlotCount)
	}
	if rep.SigShortness.SupportSlotCount != 6 {
		t.Fatalf("full replay shortness support slots=%d want 6", rep.SigShortness.SupportSlotCount)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != compactL1ResearchFullControlQBytes || study.BaselineSnapshot.QBytes != compactL1ResearchFullControlQBytes {
		t.Fatalf("compact full baseline Q changed: report=%d study=%d want %d", rep.PaperTranscript.Q.OptimizedBytes, study.BaselineSnapshot.QBytes, compactL1ResearchFullControlQBytes)
	}
	if rep.ReplayAudit.Selector.SelectedRows != 16 || rep.ReplayAudit.Selector.ActiveBlocks != 3 {
		t.Fatalf("full replay selector changed unexpectedly: %+v", rep.ReplayAudit.Selector)
	}
	if study.Recommendations.NextBaselineDoable == "" || study.Recommendations.NextBridgeRequired == "" || study.Recommendations.NextArchitectureRequired == "" {
		t.Fatalf("incomplete recommendations: %+v", study.Recommendations)
	}
}

func TestShowingFullBaselineStudyLeverMatrixCompactL1ResearchFullPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, _, study, _, _ := buildFullBaselineStudyForCompactL1Research(t)
	for _, lever := range study.LeverMatrix {
		if len(lever.WitnessFamilies) == 0 {
			t.Fatalf("lever %q missing witness families", lever.Name)
		}
		if len(lever.ConstraintFamilies) == 0 {
			t.Fatalf("lever %q missing constraint families", lever.Name)
		}
		if len(lever.AuthenticatedSurfaces) == 0 {
			t.Fatalf("lever %q missing authenticated surfaces", lever.Name)
		}
		if lever.Status != PIOP.FullProofStudyLeverAlreadyDerivedNow && lever.Status != PIOP.FullProofStudyLeverDoableWithCurrentOpenings && strings.TrimSpace(lever.Rationale) == "" {
			t.Fatalf("lever %q with status %q missing rationale", lever.Name, lever.Status)
		}
	}

	tSource := studyLeverByName(t, study, "t_source_derivation")
	if tSource.Status != PIOP.FullProofStudyLeverAlreadyDerivedNow {
		t.Fatalf("t_source lever status=%q want %q", tSource.Status, PIOP.FullProofStudyLeverAlreadyDerivedNow)
	}
	sourceProduct := studyLeverByName(t, study, "source_product_extraction")
	if sourceProduct.Status != PIOP.FullProofStudyLeverNeedsSameRootSubsetBridge {
		t.Fatalf("source_product lever status=%q want %q", sourceProduct.Status, PIOP.FullProofStudyLeverNeedsSameRootSubsetBridge)
	}
	if strings.Contains(sourceProduct.Rationale, "doable") {
		t.Fatalf("source_product rationale should not classify current openings as sufficient: %q", sourceProduct.Rationale)
	}
	prfMaster := studyLeverByName(t, study, "prf_packed_rows_master_root_bridge")
	if prfMaster.Status != PIOP.FullProofStudyLeverNeedsSeparateOracleOrMasterRoot {
		t.Fatalf("prf master-root lever status=%q want %q", prfMaster.Status, PIOP.FullProofStudyLeverNeedsSeparateOracleOrMasterRoot)
	}
	hidden := studyLeverByName(t, study, "hidden_sig_shortness_geometry_tuning")
	if hidden.Status != PIOP.FullProofStudyLeverDoableWithCurrentOpenings {
		t.Fatalf("hidden shortness geometry status=%q want %q", hidden.Status, PIOP.FullProofStudyLeverDoableWithCurrentOpenings)
	}
	if !study.HiddenShortness.Enabled {
		t.Fatalf("hidden shortness study unexpectedly disabled")
	}
	if study.Recommendations.NextBaselineDoable != "hidden_sig_shortness_geometry_tuning" {
		t.Fatalf("next baseline-doable=%q want hidden_sig_shortness_geometry_tuning", study.Recommendations.NextBaselineDoable)
	}
	if study.Recommendations.NextBridgeRequired != "hidden_sig_shortness_outer_t_hat_opening" {
		t.Fatalf("next bridge-required=%q want hidden_sig_shortness_outer_t_hat_opening", study.Recommendations.NextBridgeRequired)
	}
	if study.Recommendations.NextArchitectureRequired != "prf_packed_rows_master_root_bridge" {
		t.Fatalf("next architecture-required=%q want prf_packed_rows_master_root_bridge", study.Recommendations.NextArchitectureRequired)
	}
}

func TestShowingFullBaselineStudyWitnessInventoryCompactL1ResearchFullPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, study, _, _ := buildFullBaselineStudyForCompactL1Research(t)
	if proof.RowLayout.IdxTSource >= 0 {
		t.Fatalf("full theorem-clean baseline should not commit T-source rows")
	}
	tSource := studyWitnessFamilyByName(t, study, "t_source")
	if tSource.CommittedRowCount != 0 || tSource.SelectedRowCount != 0 {
		t.Fatalf("t_source family rows=%d selected=%d want 0/0", tSource.CommittedRowCount, tSource.SelectedRowCount)
	}
	msigmaR1Source := studyWitnessFamilyByName(t, study, "msigmar1_source")
	if msigmaR1Source.CommittedRowCount != 1 || msigmaR1Source.SelectedRowCount != 1 {
		t.Fatalf("msigmar1_source rows=%d selected=%d want 1/1", msigmaR1Source.CommittedRowCount, msigmaR1Source.SelectedRowCount)
	}
	r0r1Source := studyWitnessFamilyByName(t, study, "r0r1_source")
	if r0r1Source.CommittedRowCount != 1 || r0r1Source.SelectedRowCount != 1 {
		t.Fatalf("r0r1_source rows=%d selected=%d want 1/1", r0r1Source.CommittedRowCount, r0r1Source.SelectedRowCount)
	}
	if len(proof.RowLayout.ReplayMSigmaR1HatRows) != proof.RowLayout.ReplayBlockCount {
		t.Fatalf("ReplayMSigmaR1HatRows=%d want replay blocks=%d", len(proof.RowLayout.ReplayMSigmaR1HatRows), proof.RowLayout.ReplayBlockCount)
	}
	if len(proof.RowLayout.ReplayR0R1HatRows) != proof.RowLayout.ReplayBlockCount {
		t.Fatalf("ReplayR0R1HatRows=%d want replay blocks=%d", len(proof.RowLayout.ReplayR0R1HatRows), proof.RowLayout.ReplayBlockCount)
	}
	if proof.PRFCompanion == nil || proof.PRFCompanion.Layout == nil {
		t.Fatalf("missing PRF companion layout")
	}
	if proof.PRFCompanion.Layout.StartRow != 388 {
		t.Fatalf("PRF companion start row=%d want 388", proof.PRFCompanion.Layout.StartRow)
	}
	var foundSourceProduct bool
	for _, entry := range rep.ReplayAudit.Subfamilies.Entries {
		if entry.Kind == PIOP.ReplaySubfamilySourceProductMSigmaR1 || entry.Kind == PIOP.ReplaySubfamilySourceProductR0R1 {
			foundSourceProduct = true
			if entry.SelectedRowCount != 1 {
				t.Fatalf("source-product subfamily %q selected rows=%d want 1", entry.Kind, entry.SelectedRowCount)
			}
		}
	}
	if !foundSourceProduct {
		t.Fatalf("missing source-product replay subfamilies in baseline audit")
	}
}

func TestShowingFullBaselineStudyRenderCompactL1ResearchFullPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, _, study, _, _ := buildFullBaselineStudyForCompactL1Research(t)
	md := PIOP.RenderFullProofStudyMarkdown(study)
	for _, want := range []string{
		"# Full Baseline Proof Study",
		"## Baseline Snapshot",
		"## Main Witness Families",
		"## Hidden Sig Shortness",
		"## Constraint Families",
		"## Authenticated Surfaces",
		"## Lever Matrix",
		"## Recommendations",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("rendered study markdown missing section %q", want)
		}
	}
	t.Log("\n" + md)
}
