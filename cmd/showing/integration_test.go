package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func showingTestRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func chdirForShowingTest(t *testing.T, dir string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

func buildShowingProofForTestConfigWithResearchKnobs(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, showingPreset string, sigShortnessProfile string, sigShortnessRadix int, sigShortnessDigits int, ncols int, lvcsNCols int) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithResearchKnobsAndMutator(t, model, packedPRF, companion, companionMode, checkpointSamples, showingPreset, sigShortnessProfile, sigShortnessRadix, sigShortnessDigits, ncols, lvcsNCols, nil)
}

func buildShowingProofForTestConfigWithResearchKnobsAndMutator(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, showingPreset string, sigShortnessProfile string, sigShortnessRadix int, sigShortnessDigits int, ncols int, lvcsNCols int, mutateOpts func(*PIOP.SimOpts)) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	state, err := credential.LoadState(filepath.Join(root, "credential", "keys", "credential_state.json"))
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	params, err := loadPRFParamsFromState(state)
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	if ncols <= 0 {
		ncols = 16
	}
	postLVCS := 0
	postNLeaves := 0
	prfLVCS := 0
	prfNLeaves := 0
	if lvcsNCols > 0 {
		postLVCS = lvcsNCols
		prfLVCS = lvcsNCols
	}
	opts := PIOP.SimOpts{
		Credential:                 true,
		Theta:                      0,
		EllPrime:                   0,
		Rho:                        0,
		NCols:                      ncols,
		LVCSNCols:                  postLVCS,
		Ell:                        18,
		Eta:                        0,
		DomainMode:                 PIOP.DomainModeExplicit,
		NLeaves:                    postNLeaves,
		PRFGroupRounds:             2,
		EnablePackedPRFWitnessRows: packedPRF,
		EnablePRFCompanion:         companion,
		PRFCheckpointSamples:       checkpointSamples,
		CoeffPacking:               true,
		CoeffNativeSigModel:        model,
		ShowingPreset:              showingPreset,
		SigShortnessProfile:        sigShortnessProfile,
		SigShortnessRadix:          sigShortnessRadix,
		SigShortnessL:              sigShortnessDigits,
		PostSignLVCSNCols:          postLVCS,
		PostSignNLeaves:            postNLeaves,
		PRFLVCSNCols:               prfLVCS,
		PRFNLeaves:                 prfNLeaves,
	}
	if companion {
		opts.PRFCompanionMode = companionMode
		if opts.PRFCompanionMode == "" {
			opts.PRFCompanionMode = PIOP.PRFCompanionModeOutputAudit
		}
		if opts.PRFCheckpointSamples <= 0 {
			opts.PRFCheckpointSamples = 8
		}
	}
	if mutateOpts != nil {
		mutateOpts(&opts)
	}

	wit, err := buildWitnessFromState(ringQ, state)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}
	A, err := buildSignatureMatrix(ringQ, state, showingSignatureComponentCount(wit))
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	B, err := loadBFromState(ringQ, state)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	key, err := prfKeyFromSignedWitness(ringQ, wit.CoeffNativeShowing, params.LenKey)
	if err != nil {
		t.Fatalf("prf key: %v", err)
	}
	nonce, noncePublic := sampleNonce(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	tagPublic := lanesFromElems(tag, opts.NCols)
	if !companion {
		x0, err := prf.ConcatKeyNonce(key, nonce, params)
		if err != nil {
			t.Fatalf("concat key/nonce: %v", err)
		}
		sboxes, _, err := prf.TraceSBoxOutputsGrouped(x0, params, opts.PRFGroupRounds)
		if err != nil {
			t.Fatalf("trace grouped sboxes: %v", err)
		}
		if wit.Extras == nil {
			wit.Extras = map[string]interface{}{}
		}
		wit.Extras["prf_sbox"] = elemsToPolys(ringQ, sboxes)
	}

	pub := PIOP.PublicInputs{
		A:      A,
		B:      B,
		T:      append([]int64(nil), state.T...),
		Tag:    tagPublic,
		Nonce:  noncePublic,
		BoundB: 8,
	}
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		t.Fatalf("build showing: %v", err)
	}
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify showing returned ok=false")
	}
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		t.Fatalf("proof report: %v", err)
	}
	return proof, rep, wit, opts, ringQ, pub
}

func buildShowingProofForTestConfigWithPresetAndShortness(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, showingPreset string, sigShortnessProfile string, sigShortnessRadix int, sigShortnessDigits int) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithResearchKnobs(t, model, packedPRF, companion, companionMode, checkpointSamples, showingPreset, sigShortnessProfile, sigShortnessRadix, sigShortnessDigits, 16, 0)
}

func buildShowingProofForTestConfigWithShortness(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, sigShortnessProfile string, sigShortnessRadix int, sigShortnessDigits int) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithPresetAndShortness(t, model, packedPRF, companion, companionMode, checkpointSamples, PIOP.ShowingPresetSoundnessBalanced, sigShortnessProfile, sigShortnessRadix, sigShortnessDigits)
}

func buildShowingProofForTestConfigWithShortnessProfile(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, sigShortnessProfile string) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithShortness(t, model, packedPRF, companion, companionMode, checkpointSamples, sigShortnessProfile, 0, 0)
}

func buildShowingProofForTestConfigWithProductionBalanceShortnessProfile(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, sigShortnessProfile string) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithPresetAndShortness(t, model, packedPRF, companion, companionMode, checkpointSamples, PIOP.ShowingPresetProductionBalance, sigShortnessProfile, 0, 0)
}

func buildShowingProofForTestConfig(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithPresetAndShortness(t, model, packedPRF, companion, companionMode, checkpointSamples, PIOP.ShowingPresetSoundnessBalanced, "", 0, 0)
}

func buildShowingProofForProductionBalanceConfig(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithPresetAndShortness(t, model, packedPRF, companion, companionMode, checkpointSamples, PIOP.ShowingPresetProductionBalance, "", 0, 0)
}

func buildShowingProofForTestWithFlags(t *testing.T, model string, packedPRF bool, companion bool) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfig(t, model, packedPRF, companion, "", 8)
}

func buildShowingProofForTestConfigWithLVCSAndShortnessProfile(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, sigShortnessProfile string, lvcsNCols int) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithResearchKnobs(t, model, packedPRF, companion, companionMode, checkpointSamples, PIOP.ShowingPresetTranscriptFirst, sigShortnessProfile, 0, 0, 16, lvcsNCols)
}

func buildShowingProofForTestConfigWithLVCSAndRawShortness(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, sigShortnessRadix int, sigShortnessDigits int, lvcsNCols int) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithResearchKnobs(t, model, packedPRF, companion, companionMode, checkpointSamples, PIOP.ShowingPresetTranscriptFirst, "", sigShortnessRadix, sigShortnessDigits, 16, lvcsNCols)
}

func buildShowingProofForTest(t *testing.T, model string) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring) {
	t.Helper()
	proof, rep, wit, opts, ringQ, _ := buildShowingProofForTestWithFlags(t, model, false, false)
	return proof, rep, wit, opts, ringQ
}

func TestShowingV3TranscriptRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, _, _, _ := buildShowingProofForTest(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3)
	if proof.PRFCompanion == nil || proof.PRFCompanion.Layout == nil {
		t.Fatalf("missing PRF companion layout")
	}
	if len(proof.PRFCompanion.Layout.KeySlots) != 0 {
		t.Fatalf("expected no packed key slots in live output-audit mode")
	}
	if len(proof.PRFCompanion.Layout.CheckpointInputSlots) != 0 {
		t.Fatalf("expected no committed checkpoint-input slots in live output-audit mode")
	}
	wantPRFLogicalScalars := 166
	if proof.PRFCompanion.Layout.PackedLogicalCount != wantPRFLogicalScalars {
		t.Fatalf("prf logical scalars=%d want %d", proof.PRFCompanion.Layout.PackedLogicalCount, wantPRFLogicalScalars)
	}
	if rep.TranscriptFocus.PRFLogicalScalars != wantPRFLogicalScalars {
		t.Fatalf("reported prf logical scalars=%d want %d", rep.TranscriptFocus.PRFLogicalScalars, wantPRFLogicalScalars)
	}
	if rep.TranscriptFocus.PRFPackedRows != proof.PRFCompanion.Layout.PackedRows {
		t.Fatalf("reported prf rows=%d want %d", rep.TranscriptFocus.PRFPackedRows, proof.PRFCompanion.Layout.PackedRows)
	}
	if rep.TranscriptFocus.PRFPackedRows != 11 {
		t.Fatalf("reported prf packed rows=%d want 11", rep.TranscriptFocus.PRFPackedRows)
	}
	if rep.TranscriptFocus.PRFMode != string(PIOP.PRFCompanionModeOutputAudit) {
		t.Fatalf("reported prf mode=%q want %q", rep.TranscriptFocus.PRFMode, PIOP.PRFCompanionModeOutputAudit)
	}
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetSoundnessBalanced {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetSoundnessBalanced)
	}
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR11L4Production)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 11 || rep.TranscriptFocus.SigShortnessDigits != 4 || rep.TranscriptFocus.SigShortnessDegree != 11 {
		t.Fatalf("unexpected sig shortness metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if rep.TranscriptFocus.PRFAuditSamples != 8 {
		t.Fatalf("reported prf audit samples=%d want 8", rep.TranscriptFocus.PRFAuditSamples)
	}
	if !rep.TranscriptFocus.PRFBridgeInQ {
		t.Fatalf("expected output_audit to keep PRF bridge inside Q")
	}
	if proof.PRFCompanion.Layout.SignedKeyMapping.M2Row < 0 {
		t.Fatalf("missing signed M2 row binding in companion layout")
	}
	if proof.RowLayout.IdxM2 < 0 || proof.RowLayout.IdxT < 0 {
		t.Fatalf("missing signed base rows in showing layout: %+v", proof.RowLayout)
	}
	if rep.LVCSNCols != 96 {
		t.Fatalf("LVCSNCols=%d want 96", rep.LVCSNCols)
	}
	if rep.TranscriptFocus.LVCSNCols != 96 {
		t.Fatalf("reported LVCSNCols=%d want 96", rep.TranscriptFocus.LVCSNCols)
	}
	if rep.TranscriptFocus.WitnessRows != 859 {
		t.Fatalf("reported witness rows=%d want 859", rep.TranscriptFocus.WitnessRows)
	}
	if rep.TranscriptFocus.RowsBlock != 9 {
		t.Fatalf("reported rowsBlock=%d want 9", rep.TranscriptFocus.RowsBlock)
	}
	if rep.TranscriptFocus.MaskChunks != 4 {
		t.Fatalf("reported maskChunks=%d want 4", rep.TranscriptFocus.MaskChunks)
	}
	if rep.DQ != 378 {
		t.Fatalf("dQ=%d want 378", rep.DQ)
	}
	if rep.TranscriptFocus.NRows != rep.Soundness.NRows || rep.TranscriptFocus.M != rep.Soundness.M {
		t.Fatalf("transcript focus row geometry mismatch: %+v soundness=%+v", rep.TranscriptFocus, rep.Soundness)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("pcols=%d nrows-m=%d", rep.TranscriptFocus.PCols, rep.TranscriptFocus.NRows-rep.TranscriptFocus.M)
	}
	if rep.Geometry.PCSBlockCount != 9 {
		t.Fatalf("pcs block count=%d want 9", rep.Geometry.PCSBlockCount)
	}
	if rep.Geometry.ActualWitnessPolys != 859 || rep.Geometry.ActualPostSignWitnessPolys != 848 || rep.Geometry.ActualPRFWitnessPolys != 11 {
		t.Fatalf("unexpected witness geometry: %+v", rep.Geometry)
	}
	if proof.RowLayout.MsgChainBase < 0 || proof.RowLayout.RndChainBase < 0 || proof.RowLayout.NonSigBoundRowsPer != 3 {
		t.Fatalf("expected live semantic-rewrite non-sign chain rows, got MsgChainBase=%d RndChainBase=%d RowsPer=%d", proof.RowLayout.MsgChainBase, proof.RowLayout.RndChainBase, proof.RowLayout.NonSigBoundRowsPer)
	}
	if proof.RowLayout.IdxUBase != proof.RowLayout.CoeffNativeSig.PackedSigBase+proof.RowLayout.CoeffNativeSig.PackedSigCount {
		t.Fatalf("phase-2 investigation regression: IdxUBase=%d packedSigEnd=%d", proof.RowLayout.IdxUBase, proof.RowLayout.CoeffNativeSig.PackedSigBase+proof.RowLayout.CoeffNativeSig.PackedSigCount)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 13618 {
		t.Fatalf("VTargets=%d want 13618", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 2562 {
		t.Fatalf("BarSets=%d want 2562", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 13395 {
		t.Fatalf("Pdecs=%d want 13395", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 5628 {
		t.Fatalf("Q=%d want 5628", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 195 {
		t.Fatalf("nrows=%d want 195", rep.TranscriptFocus.NRows)
	}
	if rep.TranscriptFocus.M != 54 {
		t.Fatalf("m=%d want 54", rep.TranscriptFocus.M)
	}
	if rep.TranscriptFocus.PCols != 141 {
		t.Fatalf("pcols=%d want 141", rep.TranscriptFocus.PCols)
	}
	t.Logf("v3 transcript: total=%d dQ=%d Pdecs=%d Auth=%d Q=%d R=%d nrows=%d m=%d pcols=%d",
		rep.PaperTranscript.OptimizedBytes,
		rep.DQ,
		rep.PaperTranscript.Pdecs.OptimizedBytes,
		rep.PaperTranscript.Auth.OptimizedBytes,
		rep.PaperTranscript.Q.OptimizedBytes,
		rep.PaperTranscript.R.OptimizedBytes,
		rep.TranscriptFocus.NRows,
		rep.TranscriptFocus.M,
		rep.TranscriptFocus.PCols,
	)
	if rep.PaperTranscript.OptimizedBytes >= 116000 {
		t.Fatalf("paper transcript=%d bytes exceeds semantic-rewrite baseline guardrail", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes >= 50000 {
		t.Fatalf("Pdecs=%d bytes exceeds semantic-rewrite baseline bound", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.Soundness.TotalBits < 100 {
		t.Fatalf("unexpected soundness-balanced theorem floor: total=%.2f bits=%v theorem=%v", rep.Soundness.TotalBits, rep.Soundness.Bits, rep.Soundness.TheoremBits)
	}
}

func TestShowingPRFCompanionEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, _, _, opts, _, pub := buildShowingProofForTestWithFlags(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true)
	if proof.PRFCompanion == nil {
		t.Fatalf("missing PRF companion proof")
	}
	if proof.PRFCompanion.Layout == nil {
		t.Fatalf("missing PRF companion layout")
	}
	if proof.PRFLayout != nil {
		t.Fatalf("companion route should retire the live legacy PRF layout")
	}
	if proof.PRFCompanion.Layout.PackedRows <= 0 {
		t.Fatalf("missing packed companion rows")
	}
	companionWitnessRows := proof.RowLayout.SigCount
	if companionWitnessRows <= 0 {
		companionWitnessRows = proof.MaskRowOffset
	}
	if err := PIOP.ValidatePRFCompanionLayout(proof.PRFCompanion.Layout, companionWitnessRows); err != nil {
		t.Fatalf("validate companion layout: %v", err)
	}
	ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout, PRFCompanionLayout: proof.PRFCompanion.Layout}, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify companion showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify companion showing returned ok=false")
	}
}

func TestShowingPRFCompanionDirectAuthEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, _, opts, _, pub := buildShowingProofForTestConfig(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true, PIOP.PRFCompanionModeDirectAuth, 8)
	if proof.PRFCompanion == nil || proof.PRFCompanion.Layout == nil {
		t.Fatalf("missing PRF companion proof")
	}
	if rep.TranscriptFocus.PRFMode != string(PIOP.PRFCompanionModeDirectAuth) {
		t.Fatalf("reported prf mode=%q want %q", rep.TranscriptFocus.PRFMode, PIOP.PRFCompanionModeDirectAuth)
	}
	if !proof.PRFCompanion.BridgeInQ || !rep.TranscriptFocus.PRFBridgeInQ {
		t.Fatalf("direct_auth research fallback should currently keep PRF bridge inside Q")
	}
	if rep.DQ != 378 {
		t.Fatalf("direct_auth dQ=%d want 378", rep.DQ)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 5628 {
		t.Fatalf("direct_auth Q=%d want 5628", rep.PaperTranscript.Q.OptimizedBytes)
	}
	ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout, PRFCompanionLayout: proof.PRFCompanion.Layout}, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify direct_auth showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify direct_auth showing returned ok=false")
	}
}

func TestShowingV3ProductionBalancePreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForProductionBalanceConfig(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetProductionBalance {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetProductionBalance)
	}
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR11L4Production)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 11 || rep.TranscriptFocus.SigShortnessDigits != 4 || rep.TranscriptFocus.SigShortnessDegree != 11 {
		t.Fatalf("unexpected production-balance sig shortness metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if rep.TranscriptFocus.LVCSNCols != 28 || rep.TranscriptFocus.WitnessRows != 859 || rep.TranscriptFocus.RowsBlock != 31 || rep.TranscriptFocus.MaskChunks != 14 {
		t.Fatalf("unexpected production-balance geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.DQ != 378 {
		t.Fatalf("production-balance dQ=%d want 378", rep.DQ)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 45847 {
		t.Fatalf("production-balance Pdecs=%d want 45847", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 27352 {
		t.Fatalf("production-balance VTargets=%d want 27352", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 17587 {
		t.Fatalf("production-balance BarSets=%d want 17587", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 11255 {
		t.Fatalf("production-balance Q=%d want 11255", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 850 || rep.TranscriptFocus.M != 372 || rep.TranscriptFocus.PCols != 478 {
		t.Fatalf("unexpected production-balance transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
}

func TestShowingV3TranscriptFirstProductionShortnessPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForTestConfigWithPresetAndShortness(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, PIOP.ShowingPresetTranscriptFirst, PIOP.SigShortnessProfileR11L4Production, 0, 0)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetTranscriptFirst {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetTranscriptFirst)
	}
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR11L4Production)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 11 || rep.TranscriptFocus.SigShortnessDigits != 4 || rep.TranscriptFocus.SigShortnessDegree != 11 {
		t.Fatalf("unexpected transcript-first sig shortness metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if rep.DQ != 378 {
		t.Fatalf("transcript-first dQ=%d want 378", rep.DQ)
	}
	if rep.Geometry.ActualWitnessPolys != 859 || rep.Geometry.ActualPostSignWitnessPolys != 848 || rep.Geometry.ActualPRFWitnessPolys != 11 {
		t.Fatalf("unexpected transcript-first witness geometry: %+v", rep.Geometry)
	}
	if rep.Geometry.PCSBlockCount != 7 {
		t.Fatalf("transcript-first pcs block count=%d want 7", rep.Geometry.PCSBlockCount)
	}
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows != 859 || rep.TranscriptFocus.RowsBlock != 7 || rep.TranscriptFocus.MaskChunks != 3 {
		t.Fatalf("unexpected transcript-first lvcs geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 10116 {
		t.Fatalf("transcript-first Pdecs=%d want 10116", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 28234 {
		t.Fatalf("transcript-first VTargets=%d want 28234", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 3979 {
		t.Fatalf("transcript-first BarSets=%d want 3979", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 11255 {
		t.Fatalf("transcript-first Q=%d want 11255", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 190 || rep.TranscriptFocus.M != 84 || rep.TranscriptFocus.PCols != 106 {
		t.Fatalf("unexpected transcript-first transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
}

func TestShowingV3CustomBalancedRawShortnessProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForTestConfigWithShortness(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, "", 7, 5)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetCustom {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetCustom)
	}
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileCustomBalanced {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileCustomBalanced)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 7 || rep.TranscriptFocus.SigShortnessDigits != 5 || rep.TranscriptFocus.SigShortnessDegree != 7 {
		t.Fatalf("unexpected custom sig shortness metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if rep.DQ != 246 {
		t.Fatalf("custom dQ=%d want 246", rep.DQ)
	}
	if rep.Geometry.ActualWitnessPolys != 987 || rep.Geometry.ActualPostSignWitnessPolys != 976 || rep.Geometry.ActualPRFWitnessPolys != 11 {
		t.Fatalf("unexpected custom witness geometry: %+v", rep.Geometry)
	}
	if rep.Geometry.PCSBlockCount != 11 {
		t.Fatalf("custom pcs block count=%d want 11", rep.Geometry.PCSBlockCount)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 15309 {
		t.Fatalf("custom Pdecs=%d want 15309", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 16642 {
		t.Fatalf("custom VTargets=%d want 16642", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 3129 {
		t.Fatalf("custom BarSets=%d want 3129", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 3647 {
		t.Fatalf("custom Q=%d want 3647", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 227 || rep.TranscriptFocus.M != 66 || rep.TranscriptFocus.PCols != 161 {
		t.Fatalf("unexpected custom transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
}

func TestShowingV3ProductionShortnessWideLVCS96ResearchBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForTestConfigWithLVCSAndShortnessProfile(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, PIOP.SigShortnessProfileR11L4Production, 96)
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR11L4Production)
	}
	if rep.TranscriptFocus.LVCSNCols != 96 || rep.TranscriptFocus.WitnessRows != 859 || rep.TranscriptFocus.RowsBlock != 9 || rep.TranscriptFocus.MaskChunks != 4 {
		t.Fatalf("unexpected lvcs96 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 9 {
		t.Fatalf("production lvcs96 pcs block count=%d want 9", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ != 378 {
		t.Fatalf("production lvcs96 dQ=%d want 378", rep.DQ)
	}
}

func TestShowingV3ProductionShortnessWideLVCS128ResearchBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForTestConfigWithLVCSAndShortnessProfile(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, PIOP.SigShortnessProfileR11L4Production, 128)
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR11L4Production)
	}
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows != 859 || rep.TranscriptFocus.RowsBlock != 7 || rep.TranscriptFocus.MaskChunks != 3 {
		t.Fatalf("unexpected lvcs128 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 7 {
		t.Fatalf("production lvcs128 pcs block count=%d want 7", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ != 378 {
		t.Fatalf("production lvcs128 dQ=%d want 378", rep.DQ)
	}
}

func TestShowingV3CustomBalancedRawShortnessWideLVCS128Probe(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForTestConfigWithLVCSAndRawShortness(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, 7, 5, 128)
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileCustomBalanced {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileCustomBalanced)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 7 || rep.TranscriptFocus.SigShortnessDigits != 5 || rep.TranscriptFocus.SigShortnessDegree != 7 {
		t.Fatalf("unexpected custom lvcs128 sig metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows != 987 || rep.TranscriptFocus.RowsBlock != 8 || rep.TranscriptFocus.MaskChunks != 2 {
		t.Fatalf("unexpected custom lvcs128 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 8 {
		t.Fatalf("custom lvcs128 pcs block count=%d want 8", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ != 246 {
		t.Fatalf("custom lvcs128 dQ=%d want 246", rep.DQ)
	}
}

func TestShowingV3ProductionShortnessWideLVCS128DirectAuthMatchesOutputAuditGeometry(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, repOutput, _, _, _, _ := buildShowingProofForTestConfigWithLVCSAndShortnessProfile(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true, PIOP.PRFCompanionModeOutputAudit, 8, PIOP.SigShortnessProfileR11L4Production, 128)
	_, repDirect, _, _, _, _ := buildShowingProofForTestConfigWithLVCSAndShortnessProfile(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true, PIOP.PRFCompanionModeDirectAuth, 8, PIOP.SigShortnessProfileR11L4Production, 128)
	if !repOutput.TranscriptFocus.PRFBridgeInQ || !repDirect.TranscriptFocus.PRFBridgeInQ {
		t.Fatalf("wide lvcs direct_auth/output_audit should both keep PRF bridge inside Q")
	}
	if repOutput.TranscriptFocus.LVCSNCols != 128 || repDirect.TranscriptFocus.LVCSNCols != 128 {
		t.Fatalf("unexpected wide lvcs focus: output=%d direct=%d", repOutput.TranscriptFocus.LVCSNCols, repDirect.TranscriptFocus.LVCSNCols)
	}
	if repDirect.DQ != repOutput.DQ || repDirect.PaperTranscript.Q.OptimizedBytes != repOutput.PaperTranscript.Q.OptimizedBytes {
		t.Fatalf("wide lvcs direct_auth mismatch: dQ=%d/%d Q=%d/%d", repDirect.DQ, repOutput.DQ, repDirect.PaperTranscript.Q.OptimizedBytes, repOutput.PaperTranscript.Q.OptimizedBytes)
	}
	if repDirect.TranscriptFocus.NRows != repOutput.TranscriptFocus.NRows || repDirect.TranscriptFocus.M != repOutput.TranscriptFocus.M || repDirect.TranscriptFocus.PCols != repOutput.TranscriptFocus.PCols {
		t.Fatalf("wide lvcs direct_auth geometry mismatch: direct=(%d,%d,%d) output=(%d,%d,%d)", repDirect.TranscriptFocus.NRows, repDirect.TranscriptFocus.M, repDirect.TranscriptFocus.PCols, repOutput.TranscriptFocus.NRows, repOutput.TranscriptFocus.M, repOutput.TranscriptFocus.PCols)
	}
}

func TestShowingPRFCompanionDirectAuthNoQReductionYet(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, repOutput, _, _, _, _ := buildShowingProofForTestConfig(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true, PIOP.PRFCompanionModeOutputAudit, 8)
	_, repDirect, _, _, _, _ := buildShowingProofForTestConfig(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true, PIOP.PRFCompanionModeDirectAuth, 8)
	if !repOutput.TranscriptFocus.PRFBridgeInQ || !repDirect.TranscriptFocus.PRFBridgeInQ {
		t.Fatalf("both output_audit and direct_auth should currently keep PRF bridge inside Q")
	}
	if repDirect.DQ != repOutput.DQ {
		t.Fatalf("direct_auth dQ=%d want output_audit dQ=%d", repDirect.DQ, repOutput.DQ)
	}
	if repDirect.PaperTranscript.Q.OptimizedBytes != repOutput.PaperTranscript.Q.OptimizedBytes {
		t.Fatalf("direct_auth Q=%d want output_audit Q=%d", repDirect.PaperTranscript.Q.OptimizedBytes, repOutput.PaperTranscript.Q.OptimizedBytes)
	}
	if repDirect.TranscriptFocus.NRows != repOutput.TranscriptFocus.NRows {
		t.Fatalf("direct_auth nrows=%d want output_audit nrows=%d", repDirect.TranscriptFocus.NRows, repOutput.TranscriptFocus.NRows)
	}
	if repDirect.TranscriptFocus.M != repOutput.TranscriptFocus.M {
		t.Fatalf("direct_auth m=%d want output_audit m=%d", repDirect.TranscriptFocus.M, repOutput.TranscriptFocus.M)
	}
	if repDirect.TranscriptFocus.PCols != repOutput.TranscriptFocus.PCols {
		t.Fatalf("direct_auth pcols=%d want output_audit pcols=%d", repDirect.TranscriptFocus.PCols, repOutput.TranscriptFocus.PCols)
	}
}

func TestShowingPRFCompanionCurrentRegressionMode(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, _, _, opts, _, pub := buildShowingProofForTestConfig(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true, PIOP.PRFCompanionModeCurrent, 8)
	if proof.PRFCompanion == nil || proof.PRFCompanion.Layout == nil {
		t.Fatalf("missing PRF companion proof")
	}
	if proof.PRFCompanion.Mode != PIOP.PRFCompanionModeCurrent {
		t.Fatalf("proof prf mode=%q want current", proof.PRFCompanion.Mode)
	}
	if !proof.PRFCompanion.BridgeInQ {
		t.Fatalf("current mode should keep PRF bridge inside Q")
	}
	if len(proof.PRFCompanion.Layout.KeySlots) == 0 {
		t.Fatalf("current mode should retain packed key slots")
	}
	if len(proof.PRFCompanion.Layout.CheckpointInputSlots) == 0 {
		t.Fatalf("current mode should retain packed checkpoint-input slots")
	}
	ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout, PRFCompanionLayout: proof.PRFCompanion.Layout}, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify current-mode showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify current-mode showing returned ok=false")
	}
}

func TestShowingPRFCompanionTamperRejects(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, _, _, opts, _, pub := buildShowingProofForTestWithFlags(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true)
	if proof.PRFCompanion == nil {
		t.Fatalf("missing PRF companion proof")
	}

	tamperedDigest := *proof
	tamperedDigest.PRFCompanion = PIOP.ClonePRFCompanionProofForTest(proof.PRFCompanion)
	if len(tamperedDigest.PRFCompanion.CoordDigest) == 0 {
		t.Fatalf("missing companion digest")
	}
	tamperedDigest.PRFCompanion.CoordDigest[0] ^= 0x01
	ok, err := PIOP.VerifyWithConstraints(&tamperedDigest, PIOP.ConstraintSet{PRFLayout: tamperedDigest.PRFLayout, PRFCompanionLayout: tamperedDigest.PRFCompanion.Layout}, pub, opts, PIOP.FSModeCredential)
	if err == nil && ok {
		t.Fatalf("tampered companion digest unexpectedly verified")
	}

	tamperedBridge := *proof
	tamperedBridge.PRFCompanion = PIOP.ClonePRFCompanionProofForTest(proof.PRFCompanion)
	if len(tamperedBridge.PRFCompanion.BridgeChecks) == 0 || len(tamperedBridge.PRFCompanion.BridgeChecks[0]) == 0 {
		t.Fatalf("missing companion bridge checks")
	}
	tamperedBridge.PRFCompanion.BridgeChecks[0][0]++
	ok, err = PIOP.VerifyWithConstraints(&tamperedBridge, PIOP.ConstraintSet{PRFLayout: tamperedBridge.PRFLayout, PRFCompanionLayout: tamperedBridge.PRFCompanion.Layout}, pub, opts, PIOP.FSModeCredential)
	if err == nil && ok {
		t.Fatalf("tampered companion bridge unexpectedly verified")
	}

	tamperedOpening := *proof
	tamperedOpening.PRFCompanion = PIOP.ClonePRFCompanionProofForTest(proof.PRFCompanion)
	if len(tamperedOpening.PRFCompanion.CheckpointAudits) == 0 || len(tamperedOpening.PRFCompanion.CheckpointAudits[0].Z.Masked) == 0 {
		t.Fatalf("missing companion checkpoint audit opening")
	}
	tamperedOpening.PRFCompanion.CheckpointAudits[0].Z.Masked[0]++
	ok, err = PIOP.VerifyWithConstraints(&tamperedOpening, PIOP.ConstraintSet{PRFLayout: tamperedOpening.PRFLayout, PRFCompanionLayout: tamperedOpening.PRFCompanion.Layout}, pub, opts, PIOP.FSModeCredential)
	if err == nil && ok {
		t.Fatalf("tampered companion opening unexpectedly verified")
	}

	tamperedMask := *proof
	tamperedMask.PRFCompanion = PIOP.ClonePRFCompanionProofForTest(proof.PRFCompanion)
	if len(tamperedMask.PRFCompanion.CheckpointAudits) == 0 || len(tamperedMask.PRFCompanion.CheckpointAudits[0].Z.Mask) == 0 {
		t.Fatalf("missing companion checkpoint audit opening mask")
	}
	tamperedMask.PRFCompanion.CheckpointAudits[0].Z.Mask[0]++
	ok, err = PIOP.VerifyWithConstraints(&tamperedMask, PIOP.ConstraintSet{PRFLayout: tamperedMask.PRFLayout, PRFCompanionLayout: tamperedMask.PRFCompanion.Layout}, pub, opts, PIOP.FSModeCredential)
	if err == nil && ok {
		t.Fatalf("tampered companion opening mask unexpectedly verified")
	}
}
