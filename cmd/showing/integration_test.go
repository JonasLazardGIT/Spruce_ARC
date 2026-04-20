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
	B, err := loadBForShowing(ringQ, state, publicParams)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}

	pub := PIOP.PublicInputs{
		A:            A,
		B:            B,
		Tag:          tagPublic,
		Nonce:        noncePublic,
		BoundB:       publicParams.BoundB,
		HashRelation: publicParams.HashRelation,
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
		resolved.SigShortnessProfile,
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
	if proof.RowLayout.IdxCarrierM < 0 || proof.RowLayout.IdxCarrierCtr < 0 {
		t.Fatalf("missing showing carrier rows in layout: %+v", proof.RowLayout)
	}
	if proof.RowLayout.IdxTSource >= 0 {
		t.Fatalf("reduced replay should omit committed T source rows: %+v", proof.RowLayout)
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
	if rep.TranscriptFocus.WitnessRows != 22 {
		t.Fatalf("reported witness rows=%d want 22", rep.TranscriptFocus.WitnessRows)
	}
	if rep.TranscriptFocus.RowsBlock != 2 {
		t.Fatalf("reported rowsBlock=%d want 2", rep.TranscriptFocus.RowsBlock)
	}
	if rep.TranscriptFocus.MaskChunks != 20 {
		t.Fatalf("reported maskChunks=%d want 20", rep.TranscriptFocus.MaskChunks)
	}
	if rep.DQ != 312 {
		t.Fatalf("dQ=%d want 312", rep.DQ)
	}
	if rep.TranscriptFocus.NRows != rep.Soundness.NRows || rep.TranscriptFocus.M != rep.Soundness.M {
		t.Fatalf("transcript focus row geometry mismatch: %+v soundness=%+v", rep.TranscriptFocus, rep.Soundness)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("pcols=%d nrows-m=%d", rep.TranscriptFocus.PCols, rep.TranscriptFocus.NRows-rep.TranscriptFocus.M)
	}
	if rep.Geometry.PCSBlockCount != 2 {
		t.Fatalf("pcs block count=%d want 2", rep.Geometry.PCSBlockCount)
	}
	if rep.Geometry.ActualWitnessPolys != 22 || rep.Geometry.ActualPostSignWitnessPolys != 10 || rep.Geometry.ActualPRFWitnessPolys != 12 {
		t.Fatalf("unexpected witness geometry: %+v", rep.Geometry)
	}
	if proof.RowLayout.MsgChainBase >= 0 || proof.RowLayout.RndChainBase >= 0 || proof.RowLayout.NonSigBoundRowsPer != 0 {
		t.Fatalf("expected compressed carriers (no non-sig chain rows), got MsgChainBase=%d RndChainBase=%d RowsPer=%d", proof.RowLayout.MsgChainBase, proof.RowLayout.RndChainBase, proof.RowLayout.NonSigBoundRowsPer)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 4637 {
		t.Fatalf("Q=%d want 4637", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows >= 790 {
		t.Fatalf("nrows=%d want < 790 after packed-source removal", rep.TranscriptFocus.NRows)
	}
	if rep.TranscriptFocus.M != 12 {
		t.Fatalf("m=%d want 12", rep.TranscriptFocus.M)
	}
	if rep.TranscriptFocus.PCols != 146 {
		t.Fatalf("pcols=%d want 146 after packed-source removal", rep.TranscriptFocus.PCols)
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
	if rep.PaperTranscript.OptimizedBytes < 29500 || rep.PaperTranscript.OptimizedBytes > 30500 {
		t.Fatalf("paper transcript=%d want in [29500,30500]", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 13813 {
		t.Fatalf("Pdecs=%d want 13813", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.Soundness.TotalBits < 100 {
		t.Fatalf("unexpected soundness-balanced theorem floor: total=%.2f bits=%v theorem=%v", rep.Soundness.TotalBits, rep.Soundness.Bits, rep.Soundness.TheoremBits)
	}
}

func TestShowingV3SoundnessBalancedPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetSoundnessBalanced)
	t.Logf("soundness-balanced shipped default: total=%d Pdecs=%d VTargets=%d BarSets=%d Mdecs=%d Auth=%d Q=%d lvcs=%d rowsBlock=%d maskChunks=%d soundness=%.2f",
		rep.PaperTranscript.OptimizedBytes,
		rep.PaperTranscript.Pdecs.OptimizedBytes,
		rep.PaperTranscript.VTargets.OptimizedBytes,
		rep.PaperTranscript.BarSets.OptimizedBytes,
		rep.PaperTranscript.Mdecs.OptimizedBytes,
		rep.PaperTranscript.Auth.OptimizedBytes,
		rep.PaperTranscript.Q.OptimizedBytes,
		rep.TranscriptFocus.LVCSNCols,
		rep.TranscriptFocus.RowsBlock,
		rep.TranscriptFocus.MaskChunks,
		rep.Soundness.TotalBits,
	)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetSoundnessBalanced {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetSoundnessBalanced)
	}
	if proof.PCSGeometry.ShortnessTailRows != 0 {
		t.Fatalf("shortness tail rows=%d want 0", proof.PCSGeometry.ShortnessTailRows)
	}
	if !rep.SigShortness.Enabled || rep.SigShortness.Version != 6 || rep.SigShortness.SupportSlotCount != 1 || rep.SigShortness.OpenedBlockCount != 1 {
		t.Fatalf("unexpected sig shortness report: %+v", rep.SigShortness)
	}
	if rep.SigShortness.ProofBytes >= 12000 {
		t.Fatalf("soundness-balanced sig shortness bytes=%d want < 12000", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols != 89 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 4 {
		t.Fatalf("unexpected soundness-balanced geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.PaperTranscript.OptimizedBytes < 30500 || rep.PaperTranscript.OptimizedBytes > 32500 {
		t.Fatalf("soundness-balanced total=%d want in [30500,32500]", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 3506 {
		t.Fatalf("soundness-balanced Pdecs=%d want 3506", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes > 1412 {
		t.Fatalf("soundness-balanced VTargets=%d want <= 1412", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes > 294 {
		t.Fatalf("soundness-balanced BarSets=%d want <= 294", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 4637 {
		t.Fatalf("soundness-balanced Q=%d want 4637", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 43 || rep.TranscriptFocus.M != 6 || rep.TranscriptFocus.PCols != 37 {
		t.Fatalf("unexpected soundness-balanced transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
}

func TestShowingV3CompactL3Preset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetCompactL3)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetCompactL3 {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetCompactL3)
	}
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR24L3Compact {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR24L3Compact)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 24 || rep.TranscriptFocus.SigShortnessDigits != 3 || rep.TranscriptFocus.SigShortnessDegree != 24 {
		t.Fatalf("unexpected compact-l3 sig metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if !rep.SigShortness.Enabled || rep.SigShortness.Version != 6 || rep.SigShortness.SupportSlotCount != 1 || rep.SigShortness.OpenedBlockCount != 1 {
		t.Fatalf("unexpected compact-l3 sig shortness report: %+v", rep.SigShortness)
	}
	if rep.SigShortness.ProofBytes >= 12000 {
		t.Fatalf("compact-l3 sig shortness bytes=%d want < 12000", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols != 68 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 5 {
		t.Fatalf("unexpected compact-l3 geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.PaperTranscript.OptimizedBytes < 27500 || rep.PaperTranscript.OptimizedBytes > 29000 {
		t.Fatalf("compact-l3 total=%d want in [27500,29000]", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 4073 {
		t.Fatalf("compact-l3 Pdecs=%d want 4073", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes > 1081 {
		t.Fatalf("compact-l3 VTargets=%d want <= 1081", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes > 294 {
		t.Fatalf("compact-l3 BarSets=%d want <= 294", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 4637 {
		t.Fatalf("compact-l3 Q=%d want 4637", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 49 || rep.TranscriptFocus.M != 6 || rep.TranscriptFocus.PCols != 43 {
		t.Fatalf("unexpected compact-l3 transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
	if rep.Soundness.TotalBits < 103 {
		t.Fatalf("unexpected compact-l3 theorem floor: total=%.2f", rep.Soundness.TotalBits)
	}
}

func TestShowingV3CompactL2Preset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetCompactL2)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetCompactL2 {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetCompactL2)
	}
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR111L2Compact {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR111L2Compact)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 111 || rep.TranscriptFocus.SigShortnessDigits != 2 || rep.TranscriptFocus.SigShortnessDegree != 111 {
		t.Fatalf("unexpected compact-l2 sig metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if !rep.SigShortness.Enabled || rep.SigShortness.Version != 6 || rep.SigShortness.SupportSlotCount != 1 || rep.SigShortness.OpenedBlockCount != 1 {
		t.Fatalf("unexpected compact-l2 sig shortness report: %+v", rep.SigShortness)
	}
	if rep.SigShortness.ProofBytes >= 12000 {
		t.Fatalf("compact-l2 sig shortness bytes=%d want < 12000", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols != 70 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 5 {
		t.Fatalf("unexpected compact-l2 geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.PaperTranscript.OptimizedBytes < 27800 || rep.PaperTranscript.OptimizedBytes > 29200 {
		t.Fatalf("compact-l2 total=%d want in [27800,29200]", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 4073 {
		t.Fatalf("compact-l2 Pdecs=%d want 4073", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes > 1113 {
		t.Fatalf("compact-l2 VTargets=%d want <= 1113", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes > 294 {
		t.Fatalf("compact-l2 BarSets=%d want <= 294", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 4637 {
		t.Fatalf("compact-l2 Q=%d want 4637", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 49 || rep.TranscriptFocus.M != 6 || rep.TranscriptFocus.PCols != 43 {
		t.Fatalf("unexpected compact-l2 transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
	if rep.Soundness.TotalBits < 103 {
		t.Fatalf("unexpected compact-l2 theorem floor: total=%.2f", rep.Soundness.TotalBits)
	}
}

func TestShowingV3CompactL1ResearchPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetCompactL1Research)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetCompactL1Research {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetCompactL1Research)
	}
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR12285L1Research {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR12285L1Research)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 12285 || rep.TranscriptFocus.SigShortnessDigits != 1 || rep.TranscriptFocus.SigShortnessDegree != 12285 {
		t.Fatalf("unexpected compact-l1 sig metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if !rep.SigShortness.Enabled || rep.SigShortness.Version != 6 || rep.SigShortness.SupportSlotCount != 1 || rep.SigShortness.OpenedBlockCount != 1 {
		t.Fatalf("unexpected compact-l1 sig shortness report: %+v", rep.SigShortness)
	}
	if rep.SigShortness.ProofBytes >= 12000 {
		t.Fatalf("compact-l1 sig shortness bytes=%d want < 12000", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols != 50 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 7 {
		t.Fatalf("unexpected compact-l1 geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.PaperTranscript.OptimizedBytes < 26200 || rep.PaperTranscript.OptimizedBytes > 27200 {
		t.Fatalf("compact-l1 total=%d want in [26200,27200]", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 5207 {
		t.Fatalf("compact-l1 Pdecs=%d want 5207", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes > 798 {
		t.Fatalf("compact-l1 VTargets=%d want <= 798", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes > 294 {
		t.Fatalf("compact-l1 BarSets=%d want <= 294", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 4637 {
		t.Fatalf("compact-l1 Q=%d want 4637", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 61 || rep.TranscriptFocus.M != 6 || rep.TranscriptFocus.PCols != 55 {
		t.Fatalf("unexpected compact-l1 transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
	if rep.Soundness.TotalBits < 103.4 {
		t.Fatalf("unexpected compact-l1 theorem floor: total=%.2f", rep.Soundness.TotalBits)
	}
}

func TestShowingReplayDependencyClosureShippedDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, _, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetSoundnessBalanced)
	var companion *PIOP.PRFCompanionLayout
	if proof.PRFCompanion != nil {
		companion = proof.PRFCompanion.Layout
	}
	selector := PIOP.BuildShowingReplayActiveRowSelector(proof.RowLayout, companion)
	stats := PIOP.BuildShowingReplayActiveRowStats(proof)
	if len(selector) == 0 {
		t.Fatalf("empty replay selector")
	}
	for i := range selector {
		if selector[i] < 0 || selector[i] >= proof.RowLayout.SigCount {
			t.Fatalf("selector[%d]=%d out of range for witness rows=%d", i, selector[i], proof.RowLayout.SigCount)
		}
		if i > 0 && selector[i] <= selector[i-1] {
			t.Fatalf("selector not strictly increasing at %d: %v", i, selector)
		}
	}
	if len(selector) >= proof.RowLayout.SigCount {
		t.Fatalf("selector rows=%d want < witness rows=%d", len(selector), proof.RowLayout.SigCount)
	}
	if stats.ActiveBlocks != stats.FullBlocks {
		t.Fatalf("unexpected replay block shrink: active=%d full=%d", stats.ActiveBlocks, stats.FullBlocks)
	}
	if len(selector)*100 > proof.RowLayout.SigCount*85 {
		t.Fatalf("replay selector reduction too small after packed-source removal: selected=%d witness=%d reduction=%.2f%%", len(selector), proof.RowLayout.SigCount, stats.ReductionPct)
	}
	t.Logf("showing replay selector: selected=%d witness=%d reduction=%.2f%% activeBlocks=%d/%d layerSize=%d",
		stats.SelectedRows,
		stats.WitnessRows,
		stats.ReductionPct,
		stats.ActiveBlocks,
		stats.FullBlocks,
		stats.LayerSize,
	)
}

func TestShowingReplayFamilyAuditShippedDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetSoundnessBalanced)
	audit := rep.ReplayAudit
	if len(audit.Families) != 6 {
		t.Fatalf("replay audit family count=%d want 6", len(audit.Families))
	}
	if audit.Selector.SelectedRows != 16 || audit.Selector.WitnessRows != 22 {
		t.Fatalf("unexpected replay selector baseline: selected=%d witness=%d", audit.Selector.SelectedRows, audit.Selector.WitnessRows)
	}
	if audit.Selector.ActiveBlocks != audit.Selector.FullBlocks {
		t.Fatalf("expected shipped replay audit to remain block-dense: active=%d full=%d", audit.Selector.ActiveBlocks, audit.Selector.FullBlocks)
	}
	wantTargets := []PIOP.ReplayFamilyKind{
		PIOP.ReplayFamilyPRFCompanion,
		PIOP.ReplayFamilySourceProduct,
		PIOP.ReplayFamilyCarrier,
	}
	if len(audit.StageBTargets) != len(wantTargets) {
		t.Fatalf("stage B target count=%d want %d (%v)", len(audit.StageBTargets), len(wantTargets), audit.StageBTargets)
	}
	for i := range wantTargets {
		if audit.StageBTargets[i] != wantTargets[i] {
			t.Fatalf("stage B target[%d]=%q want %q (full order=%v)", i, audit.StageBTargets[i], wantTargets[i], audit.StageBTargets)
		}
	}
	entries := make(map[PIOP.ReplayFamilyKind]PIOP.ReplayFamilyAuditEntry, len(audit.Families))
	for _, entry := range audit.Families {
		entries[entry.Family] = entry
	}
	top := entries[audit.StageBTargets[0]]
	if top.Derivability == PIOP.ReplayFamilyAlreadyDerivedNow {
		t.Fatalf("top Stage B target %q should not already be derived", top.Family)
	}
	coveredBlocks := make(map[int]struct{})
	for _, family := range audit.StageBTargets[:3] {
		entry := entries[family]
		for _, idx := range entry.SelectedRows {
			coveredBlocks[idx/audit.Selector.LayerSize] = struct{}{}
		}
	}
	if len(coveredBlocks) != audit.Selector.FullBlocks {
		t.Fatalf("top three Stage B targets should jointly cover all active blocks: covered=%d full=%d", len(coveredBlocks), audit.Selector.FullBlocks)
	}
	if entries[PIOP.ReplayFamilyPRFCompanion].ActiveBlockCount != 2 || entries[PIOP.ReplayFamilyTSource].ActiveBlockCount != 0 {
		t.Fatalf("unexpected shipped block split: prf_companion=%d t_source=%d", entries[PIOP.ReplayFamilyPRFCompanion].ActiveBlockCount, entries[PIOP.ReplayFamilyTSource].ActiveBlockCount)
	}
	if proof.RowLayout.SigCount != audit.Selector.WitnessRows {
		t.Fatalf("proof witness rows=%d audit witness rows=%d mismatch", proof.RowLayout.SigCount, audit.Selector.WitnessRows)
	}
	if entries[PIOP.ReplayFamilyTransformAlias].ReductionEffect != PIOP.ReplayFamilyAlreadyExcludedFromSelector {
		t.Fatalf("transform alias reduction effect=%q want %q", entries[PIOP.ReplayFamilyTransformAlias].ReductionEffect, PIOP.ReplayFamilyAlreadyExcludedFromSelector)
	}
	if entries[PIOP.ReplayFamilyReplayImage].ReductionEffect != PIOP.ReplayFamilyAlreadyExcludedFromSelector {
		t.Fatalf("replay image reduction effect=%q want %q", entries[PIOP.ReplayFamilyReplayImage].ReductionEffect, PIOP.ReplayFamilyAlreadyExcludedFromSelector)
	}
}

func TestShowingReplaySubfamilyAuditShippedDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	_, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetSoundnessBalanced)
	sub := rep.ReplayAudit.Subfamilies
	if len(sub.Entries) == 0 {
		t.Fatalf("missing replay subfamily audit")
	}
	byKind := make(map[PIOP.ReplaySubfamilyKind]PIOP.ReplaySubfamilyAuditEntry, len(sub.Entries))
	for _, entry := range sub.Entries {
		byKind[entry.Kind] = entry
	}
	for _, kind := range []PIOP.ReplaySubfamilyKind{
		PIOP.ReplaySubfamilySourceProductMSigmaR1,
		PIOP.ReplaySubfamilySourceProductR0R1,
		PIOP.ReplaySubfamilyPRFKeyRows,
		PIOP.ReplaySubfamilyPRFCheckpointRows,
		PIOP.ReplaySubfamilyPRFFinalTagRows,
		PIOP.ReplaySubfamilyPRFHelperRows,
	} {
		if _, ok := byKind[kind]; !ok {
			t.Fatalf("missing replay subfamily %q", kind)
		}
	}
	if got := byKind[PIOP.ReplaySubfamilyPRFFinalTagRows].Consumption; got != PIOP.ReplaySubfamilyMixed {
		t.Fatalf("prf final-tag rows consumption=%q want %q", got, PIOP.ReplaySubfamilyMixed)
	}
	if sub.PRFBridgeBlocker == "" {
		t.Fatalf("missing prf bridge blocker summary")
	}
	if sub.SigBasisBlocker != "" {
		t.Fatalf("unexpected sig basis blocker summary=%q", sub.SigBasisBlocker)
	}
	wantPRF := []PIOP.ReplaySubfamilyKind{
		PIOP.ReplaySubfamilyPRFCheckpointRows,
		PIOP.ReplaySubfamilyPRFFinalTagRows,
		PIOP.ReplaySubfamilyPRFHelperRows,
	}
	if len(sub.PRFBridgeTargets) < len(wantPRF) {
		t.Fatalf("prf bridge target count=%d want at least %d", len(sub.PRFBridgeTargets), len(wantPRF))
	}
	for i := range wantPRF {
		if sub.PRFBridgeTargets[i] != wantPRF[i] {
			t.Fatalf("prf bridge target[%d]=%q want %q (full order=%v)", i, sub.PRFBridgeTargets[i], wantPRF[i], sub.PRFBridgeTargets)
		}
	}
	if len(sub.SigBasisTargets) != 0 {
		t.Fatalf("unexpected sig basis targets=%v", sub.SigBasisTargets)
	}
	if got := byKind[PIOP.ReplaySubfamilySourceProductMSigmaR1].SelectedRowCount; got != 1 {
		t.Fatalf("source_product_msigmar1 selected=%d want 1", got)
	}
	if got := byKind[PIOP.ReplaySubfamilySourceProductR0R1].SelectedRowCount; got != 1 {
		t.Fatalf("source_product_r0r1 selected=%d want 1", got)
	}
	wantTop := []PIOP.ReplaySubfamilyKind{
		PIOP.ReplaySubfamilySourceProductMSigmaR1,
		PIOP.ReplaySubfamilySourceProductR0R1,
		PIOP.ReplaySubfamilyPRFCheckpointRows,
		PIOP.ReplaySubfamilyPRFFinalTagRows,
	}
	if len(sub.StageBTargets) < len(wantTop) {
		t.Fatalf("subfamily target count=%d want at least %d", len(sub.StageBTargets), len(wantTop))
	}
	for i := range wantTop {
		if sub.StageBTargets[i] != wantTop[i] {
			t.Fatalf("subfamily target[%d]=%q want %q (full order=%v)", i, sub.StageBTargets[i], wantTop[i], sub.StageBTargets)
		}
	}
}

func TestShowingRowOpeningReconstructsOmittedMvals(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, _, _, opts, _, pub := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetSoundnessBalanced)
	if proof.PCSOpening == nil {
		t.Fatalf("missing row opening")
	}
	if proof.PCSOpening.MFormatVersion != 1 {
		t.Fatalf("row opening MFormatVersion=%d want 1", proof.PCSOpening.MFormatVersion)
	}
	if proof.PCSOpening.MColsEncoded != 0 {
		t.Fatalf("row opening MColsEncoded=%d want 0", proof.PCSOpening.MColsEncoded)
	}
	if got, want := len(proof.PCSOpening.MOmitCols), proof.PCSOpening.Eta; got != want {
		t.Fatalf("row opening omitted M cols=%d want %d", got, want)
	}
	ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify row-opening-reconstructed showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify row-opening-reconstructed showing returned ok=false")
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
	if rep.DQ != 312 {
		t.Fatalf("direct_auth dQ=%d want 312", rep.DQ)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 4637 {
		t.Fatalf("direct_auth Q=%d want 4637", rep.PaperTranscript.Q.OptimizedBytes)
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
	if rep.TranscriptFocus.LVCSNCols != 32 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 10 {
		t.Fatalf("unexpected production-balance geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.DQ != 312 {
		t.Fatalf("production-balance dQ=%d want 312", rep.DQ)
	}
	if rep.PaperTranscript.OptimizedBytes < 33500 || rep.PaperTranscript.OptimizedBytes > 34250 {
		t.Fatalf("production-balance total=%d want in [33500,34250]", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 12301 {
		t.Fatalf("production-balance Pdecs=%d want 12301", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes > 1018 {
		t.Fatalf("production-balance VTargets=%d want <= 1018", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 577 {
		t.Fatalf("production-balance BarSets=%d want 577", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 9274 {
		t.Fatalf("production-balance Q=%d want 9274", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 142 {
		t.Fatalf("unexpected production-balance nrows=%d want 142", rep.TranscriptFocus.NRows)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("unexpected production-balance pcols=%d nrows-m=%d", rep.TranscriptFocus.PCols, rep.TranscriptFocus.NRows-rep.TranscriptFocus.M)
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
	if rep.DQ != 312 {
		t.Fatalf("transcript-first dQ=%d want 312", rep.DQ)
	}
	if rep.Geometry.ActualWitnessPolys != 22 || rep.Geometry.ActualPostSignWitnessPolys != 10 || rep.Geometry.ActualPRFWitnessPolys != 12 {
		t.Fatalf("unexpected transcript-first witness geometry: %+v", rep.Geometry)
	}
	if rep.Geometry.PCSBlockCount != 1 {
		t.Fatalf("transcript-first pcs block count=%d want 1", rep.Geometry.PCSBlockCount)
	}
	if rep.TranscriptFocus.LVCSNCols != 32 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 10 {
		t.Fatalf("unexpected transcript-first lvcs geometry: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.PaperTranscript.OptimizedBytes < 33700 || rep.PaperTranscript.OptimizedBytes > 34500 {
		t.Fatalf("transcript-first total=%d want in [33700,34500]", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 12301 {
		t.Fatalf("transcript-first Pdecs=%d want 12301", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes > 1018 {
		t.Fatalf("transcript-first VTargets=%d want <= 1018", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 577 {
		t.Fatalf("transcript-first BarSets=%d want 577", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 9274 {
		t.Fatalf("transcript-first Q=%d want 9274", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 142 {
		t.Fatalf("unexpected transcript-first nrows=%d want 142", rep.TranscriptFocus.NRows)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("unexpected transcript-first pcols=%d nrows-m=%d", rep.TranscriptFocus.PCols, rep.TranscriptFocus.NRows-rep.TranscriptFocus.M)
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
	if rep.Geometry.ActualWitnessPolys != 22 || rep.Geometry.ActualPostSignWitnessPolys != 10 || rep.Geometry.ActualPRFWitnessPolys != 12 {
		t.Fatalf("unexpected custom witness geometry: %+v", rep.Geometry)
	}
	if rep.Geometry.PCSBlockCount != 2 {
		t.Fatalf("custom pcs block count=%d want 2", rep.Geometry.PCSBlockCount)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes != 13813 {
		t.Fatalf("custom Pdecs=%d want 13813", rep.PaperTranscript.Pdecs.OptimizedBytes)
	}
	if rep.PaperTranscript.VTargets.OptimizedBytes > 514 {
		t.Fatalf("custom VTargets=%d want <= 514", rep.PaperTranscript.VTargets.OptimizedBytes)
	}
	if rep.PaperTranscript.BarSets.OptimizedBytes != 577 {
		t.Fatalf("custom BarSets=%d want 577", rep.PaperTranscript.BarSets.OptimizedBytes)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != 4637 {
		t.Fatalf("custom Q=%d want 4637", rep.PaperTranscript.Q.OptimizedBytes)
	}
	if rep.TranscriptFocus.NRows != 158 || rep.TranscriptFocus.M != 12 || rep.TranscriptFocus.PCols != 146 {
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
	if rep.TranscriptFocus.LVCSNCols != 96 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 4 {
		t.Fatalf("unexpected lvcs96 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 1 {
		t.Fatalf("production lvcs96 pcs block count=%d want 1", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ != 312 {
		t.Fatalf("production lvcs96 dQ=%d want 312", rep.DQ)
	}
}

func TestShowingV3ProductionShortnessWideLVCS128ResearchBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, _, _, _, _ := buildShowingProofForTestConfigWithLVCSAndShortnessProfile(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, PIOP.SigShortnessProfileR11L4Production, 128)
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR11L4Production)
	}
	if proof.PCSGeometry.ShortnessTailRows != 0 {
		t.Fatalf("shortness tail rows=%d want 0", proof.PCSGeometry.ShortnessTailRows)
	}
	if !rep.SigShortness.Enabled || rep.SigShortness.Version != 6 || rep.SigShortness.SupportSlotCount != 1 || rep.SigShortness.OpenedBlockCount != 1 {
		t.Fatalf("unexpected wide lvcs128 sig shortness report: %+v", rep.SigShortness)
	}
	if rep.SigShortness.ProofBytes >= 12000 {
		t.Fatalf("wide lvcs128 sig shortness bytes=%d want < 12000", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 3 {
		t.Fatalf("unexpected lvcs128 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 1 {
		t.Fatalf("production lvcs128 pcs block count=%d want 1", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ != 312 {
		t.Fatalf("production lvcs128 dQ=%d want 312", rep.DQ)
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
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows != 22 || rep.TranscriptFocus.RowsBlock != 1 || rep.TranscriptFocus.MaskChunks != 3 {
		t.Fatalf("unexpected custom lvcs128 geometry focus: lvcs=%d witness=%d rowsBlock=%d maskChunks=%d", rep.TranscriptFocus.LVCSNCols, rep.TranscriptFocus.WitnessRows, rep.TranscriptFocus.RowsBlock, rep.TranscriptFocus.MaskChunks)
	}
	if rep.Geometry.PCSBlockCount != 1 {
		t.Fatalf("custom lvcs128 pcs block count=%d want 1", rep.Geometry.PCSBlockCount)
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
