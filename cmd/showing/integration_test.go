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

func maxAbsFromRows(rows [][]int64) int64 {
	var max int64
	for _, row := range rows {
		for _, v := range row {
			if v < 0 {
				v = -v
			}
			if v > max {
				max = v
			}
		}
	}
	return max
}

func maxAbsFromHeadRows(r *ring.Ring, rows [][]int64, omega []uint64, ncols int) int64 {
	if r == nil {
		return 0
	}
	q := int64(r.Modulus[0])
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	if len(omega) == 0 {
		return 0
	}
	if ncols > len(omega) {
		ncols = len(omega)
	}
	var max int64
	for _, row := range rows {
		coeffs := make([]uint64, len(row))
		for i := 0; i < len(row); i++ {
			v := row[i] % q
			if v < 0 {
				v += q
			}
			coeffs[i] = uint64(v)
		}
		for i := 0; i < ncols; i++ {
			v := int64(PIOP.EvalPoly(coeffs, omega[i]%uint64(q), uint64(q)))
			if v > q/2 {
				v -= q
			}
			if v < 0 {
				v = -v
			}
			if v > max {
				max = v
			}
		}
	}
	return max
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
	if lvcsNCols <= 0 {
		lvcsNCols = ncols
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
	opts = PIOP.ResolveSimOptsDefaults(opts)

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
	nonce, noncePublic := sampleNonceForTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
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

	publicParams, err := loadCredentialPublicParamsFromState(state)
	if err != nil {
		t.Fatalf("load credential public params: %v", err)
	}

	pub := PIOP.PublicInputs{
		A:      A,
		B:      B,
		Tag:    tagPublic,
		Nonce:  noncePublic,
		BoundB: publicParams.BoundB,
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

func sampleNonceForTest(lennonce, ncols int, q uint64) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lennonce)
	public := make([][]int64, lennonce)
	if q == 0 {
		return nonce, public
	}
	for i := 0; i < lennonce; i++ {
		v := uint64(i+1) % q
		nonce[i] = prf.Elem(v)
		public[i] = buildConstLane(ncols, int64(v))
	}
	return nonce, public
}

func buildShowingProofForTestConfigWithPresetAndShortness(t *testing.T, model string, packedPRF bool, companion bool, companionMode PIOP.PRFCompanionMode, checkpointSamples int, showingPreset string, sigShortnessProfile string, sigShortnessRadix int, sigShortnessDigits int) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	return buildShowingProofForTestConfigWithResearchKnobs(t, model, packedPRF, companion, companionMode, checkpointSamples, showingPreset, sigShortnessProfile, sigShortnessRadix, sigShortnessDigits, 16, 0)
}

func buildShowingProofForShippedPresetDefault(t *testing.T, showingPreset string) (*PIOP.Proof, PIOP.ProofReport, PIOP.WitnessInputs, PIOP.SimOpts, *ring.Ring, PIOP.PublicInputs) {
	t.Helper()
	resolved := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           PIOP.DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        showingPreset,
		SigShortnessProfile:  PIOP.SigShortnessProfileR11L4Production,
		PRFCompanionMode:     PIOP.PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	return buildShowingProofForTestConfigWithResearchKnobs(
		t,
		PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		false,
		false,
		"",
		8,
		showingPreset,
		PIOP.SigShortnessProfileR11L4Production,
		0,
		0,
		16,
		resolved.PostSignLVCSNCols,
	)
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
	if len(proof.PRFCompanion.Layout.KeySlots) != proof.PRFCompanion.Layout.KeyCount {
		t.Fatalf("packed key slots=%d want key count=%d", len(proof.PRFCompanion.Layout.KeySlots), proof.PRFCompanion.Layout.KeyCount)
	}
	wantPRFLogicalScalars := 174
	if proof.PRFCompanion.Layout.PackedLogicalCount != wantPRFLogicalScalars {
		t.Fatalf("prf logical scalars=%d want %d", proof.PRFCompanion.Layout.PackedLogicalCount, wantPRFLogicalScalars)
	}
	if rep.TranscriptFocus.PRFLogicalScalars != wantPRFLogicalScalars {
		t.Fatalf("reported prf logical scalars=%d want %d", rep.TranscriptFocus.PRFLogicalScalars, wantPRFLogicalScalars)
	}
	if rep.TranscriptFocus.PRFPackedRows != proof.PRFCompanion.Layout.PackedRows {
		t.Fatalf("reported prf rows=%d want %d", rep.TranscriptFocus.PRFPackedRows, proof.PRFCompanion.Layout.PackedRows)
	}
	if rep.TranscriptFocus.PRFPackedRows != 12 {
		t.Fatalf("reported prf packed rows=%d want 12", rep.TranscriptFocus.PRFPackedRows)
	}
	if rep.TranscriptFocus.PRFMode != string(PIOP.PRFCompanionModeOutputAudit) {
		t.Fatalf("reported prf mode=%q want %q", rep.TranscriptFocus.PRFMode, PIOP.PRFCompanionModeOutputAudit)
	}
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetCustom {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetCustom)
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
	if proof.PRFCompanion.Layout.KeySource != PIOP.KeySourceIndependentWitness {
		t.Fatalf("companion key source=%d want independent witness", proof.PRFCompanion.Layout.KeySource)
	}
	if proof.RowLayout.IdxCarrierM < 0 || proof.RowLayout.IdxCarrierCtr < 0 || proof.RowLayout.IdxTSource < 0 {
		t.Fatalf("missing showing source rows in layout: %+v", proof.RowLayout)
	}
	if proof.RowLayout.IdxMHatSigma < 0 || proof.RowLayout.IdxTHatBase < 0 {
		t.Fatalf("missing transform-domain replay rows in showing layout: %+v", proof.RowLayout)
	}
	if proof.RowLayout.IdxSigHatBase >= 0 || proof.RowLayout.CoeffNativeSig.PackedSigCount != 0 || proof.RowLayout.CoeffNativeSig.PackedSigBase >= 0 {
		t.Fatalf("expected final reduced showing layout with no committed packed source or sig hats: %+v", proof.RowLayout)
	}
	if rep.LVCSNCols != 16 {
		t.Fatalf("LVCSNCols=%d want 16", rep.LVCSNCols)
	}
	if rep.TranscriptFocus.LVCSNCols != 16 {
		t.Fatalf("reported LVCSNCols=%d want 16", rep.TranscriptFocus.LVCSNCols)
	}
	if rep.TranscriptFocus.WitnessRows != 594 {
		t.Fatalf("reported witness rows=%d want 594", rep.TranscriptFocus.WitnessRows)
	}
	if rep.TranscriptFocus.RowsBlock != 38 {
		t.Fatalf("reported rowsBlock=%d want 38", rep.TranscriptFocus.RowsBlock)
	}
	if rep.TranscriptFocus.MaskChunks != 24 {
		t.Fatalf("reported maskChunks=%d want 24", rep.TranscriptFocus.MaskChunks)
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
	if rep.Geometry.PCSBlockCount != 38 {
		t.Fatalf("pcs block count=%d want 38", rep.Geometry.PCSBlockCount)
	}
	if rep.Geometry.ActualWitnessPolys != 594 || rep.Geometry.ActualPostSignWitnessPolys != 582 || rep.Geometry.ActualPRFWitnessPolys != 12 {
		t.Fatalf("unexpected witness geometry: %+v", rep.Geometry)
	}
	if proof.RowLayout.MsgChainBase >= 0 || proof.RowLayout.RndChainBase >= 0 || proof.RowLayout.NonSigBoundRowsPer != 0 {
		t.Fatalf("expected compressed carriers (no non-sig chain rows), got MsgChainBase=%d RndChainBase=%d RowsPer=%d", proof.RowLayout.MsgChainBase, proof.RowLayout.RndChainBase, proof.RowLayout.NonSigBoundRowsPer)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 9586 {
		t.Fatalf("VTargets=%d want 9586", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 10783 {
		t.Fatalf("BarSets=%d want 10783", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 60709 {
		t.Fatalf("Pdecs=%d want 60709", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 5628 {
		t.Fatalf("Q=%d want 5628", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 866 {
		t.Fatalf("nrows=%d want 866", rep.TranscriptFocus.NRows)
	}
	if rep.TranscriptFocus.M != 228 {
		t.Fatalf("m=%d want 228", rep.TranscriptFocus.M)
	}
	if rep.TranscriptFocus.PCols != 638 {
		t.Fatalf("pcols=%d want 638", rep.TranscriptFocus.PCols)
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
	if rep.PaperTranscript.OptimizedBytes >= 100000 {
		t.Fatalf("paper transcript=%d bytes exceeds transform-bridge baseline guardrail", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes >= 65000 {
		t.Fatalf("Pdecs=%d bytes exceeds transform-bridge baseline bound", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.Soundness.TotalBits < 100 {
		t.Fatalf("unexpected soundness-balanced theorem floor: total=%.2f bits=%v theorem=%v", rep.Soundness.TotalBits, rep.Soundness.Bits, rep.Soundness.TheoremBits)
	}
}

func TestShowingV3SoundnessBalancedPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetSoundnessBalanced)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetSoundnessBalanced {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetSoundnessBalanced)
	}
	if rep.TranscriptFocus.LVCSNCols != 96 || rep.TranscriptFocus.WitnessRows != 594 || rep.TranscriptFocus.RowsBlock != 7 || rep.TranscriptFocus.MaskChunks != 4 {
		t.Fatalf("unexpected soundness-balanced geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.PaperTranscript.OptimizedBytes >= 47000 {
		t.Fatalf("soundness-balanced total=%d want <47000", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 10913 {
		t.Fatalf("soundness-balanced Pdecs=%d want 10913", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 10594 {
		t.Fatalf("soundness-balanced VTargets=%d want 10594", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 1995 {
		t.Fatalf("soundness-balanced BarSets=%d want 1995", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 5628 {
		t.Fatalf("soundness-balanced Q=%d want 5628", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 157 || rep.TranscriptFocus.M != 42 || rep.TranscriptFocus.PCols != 115 {
		t.Fatalf("unexpected soundness-balanced transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
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
	_, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetProductionBalance)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetProductionBalance {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetProductionBalance)
	}
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR11L4Production)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 11 || rep.TranscriptFocus.SigShortnessDigits != 4 || rep.TranscriptFocus.SigShortnessDegree != 11 {
		t.Fatalf("unexpected production-balance sig shortness metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if rep.TranscriptFocus.LVCSNCols != 32 || rep.TranscriptFocus.WitnessRows != 594 || rep.TranscriptFocus.RowsBlock != 19 || rep.TranscriptFocus.MaskChunks != 12 {
		t.Fatalf("unexpected production-balance geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.DQ != 378 {
		t.Fatalf("production-balance dQ=%d want 378", rep.DQ)
	}
	if rep.PaperTranscript.OptimizedBytes >= 82000 {
		t.Fatalf("production-balance total=%d want <82000", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 31951 {
		t.Fatalf("production-balance Pdecs=%d want 31951", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 19162 {
		t.Fatalf("production-balance VTargets=%d want 19162", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 10783 {
		t.Fatalf("production-balance BarSets=%d want 10783", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 11255 {
		t.Fatalf("production-balance Q=%d want 11255", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 562 || rep.TranscriptFocus.M != 228 || rep.TranscriptFocus.PCols != 334 {
		t.Fatalf("unexpected production-balance transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
}

func TestShowingV3TranscriptFirstProductionShortnessPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetTranscriptFirst)
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
	if rep.Geometry.ActualWitnessPolys != 594 || rep.Geometry.ActualPostSignWitnessPolys != 582 || rep.Geometry.ActualPRFWitnessPolys != 12 {
		t.Fatalf("unexpected transcript-first witness geometry: %+v", rep.Geometry)
	}
	if rep.Geometry.PCSBlockCount != 19 {
		t.Fatalf("transcript-first pcs block count=%d want 19", rep.Geometry.PCSBlockCount)
	}
	if rep.TranscriptFocus.LVCSNCols != 32 || rep.TranscriptFocus.WitnessRows != 594 || rep.TranscriptFocus.RowsBlock != 19 || rep.TranscriptFocus.MaskChunks != 12 {
		t.Fatalf("unexpected transcript-first lvcs geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.PaperTranscript.OptimizedBytes >= 82000 {
		t.Fatalf("transcript-first total=%d want <82000", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 31951 {
		t.Fatalf("transcript-first Pdecs=%d want 31951", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 19162 {
		t.Fatalf("transcript-first VTargets=%d want 19162", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 10783 {
		t.Fatalf("transcript-first BarSets=%d want 10783", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 11255 {
		t.Fatalf("transcript-first Q=%d want 11255", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 562 || rep.TranscriptFocus.M != 228 || rep.TranscriptFocus.PCols != 334 {
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
	if rep.DQ != 312 {
		t.Fatalf("custom dQ=%d want 312", rep.DQ)
	}
	if rep.Geometry.ActualWitnessPolys != 722 || rep.Geometry.ActualPostSignWitnessPolys != 710 || rep.Geometry.ActualPRFWitnessPolys != 12 {
		t.Fatalf("unexpected custom witness geometry: %+v", rep.Geometry)
	}
	if rep.Geometry.PCSBlockCount != 46 {
		t.Fatalf("custom pcs block count=%d want 46", rep.Geometry.PCSBlockCount)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 63403 {
		t.Fatalf("custom Pdecs=%d want 63403", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes != 10594 {
		t.Fatalf("custom VTargets=%d want 10594", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 11917 {
		t.Fatalf("custom BarSets=%d want 11917", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 4637 {
		t.Fatalf("custom Q=%d want 4637", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 918 || rep.TranscriptFocus.M != 252 || rep.TranscriptFocus.PCols != 666 {
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
	if rep.TranscriptFocus.LVCSNCols != 96 || rep.TranscriptFocus.WitnessRows != 594 || rep.TranscriptFocus.RowsBlock != 7 || rep.TranscriptFocus.MaskChunks != 4 {
		t.Fatalf("unexpected lvcs96 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 7 {
		t.Fatalf("production lvcs96 pcs block count=%d want 7", rep.Geometry.PCSBlockCount)
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
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows != 594 || rep.TranscriptFocus.RowsBlock != 5 || rep.TranscriptFocus.MaskChunks != 3 {
		t.Fatalf("unexpected lvcs128 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 5 {
		t.Fatalf("production lvcs128 pcs block count=%d want 5", rep.Geometry.PCSBlockCount)
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
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows != 722 || rep.TranscriptFocus.RowsBlock != 6 || rep.TranscriptFocus.MaskChunks != 3 {
		t.Fatalf("unexpected custom lvcs128 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 6 {
		t.Fatalf("custom lvcs128 pcs block count=%d want 6", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ != 312 {
		t.Fatalf("custom lvcs128 dQ=%d want 312", rep.DQ)
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
