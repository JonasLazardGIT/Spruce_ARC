package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	compactL1ResearchFullControlQBytes            = 5613
	compactL1ResearchFullSelectedRows             = 14
	compactL1ResearchFullPreV7WitnessRowsBaseline = 402
	compactL1ResearchFullActiveReplayBlocks       = 2
	compactL1ResearchFullMinSoundnessBits         = 118
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

	publicParams, err := loadCredentialPublicParamsFromState(state)
	if err != nil {
		t.Fatalf("load credential public params: %v", err)
	}
	B, err := loadBForShowing(ringQ, state, publicParams)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	wit, err := buildWitnessFromState(ringQ, state, B)
	if err != nil {
		t.Fatalf("build witness: %v", err)
	}
	A, err := buildSignatureMatrix(ringQ, state, showingSignatureComponentCount(wit))
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	nonce, noncePublic := sampleNonceForTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	omega, err := deriveOmegaForOpts(ringQ, opts, publicParams.HashRelation)
	if err != nil {
		t.Fatalf("derive omega: %v", err)
	}
	key, err := prfKeyFromWitnessOnOmega(ringQ, wit, omega, params.LenKey)
	if err != nil {
		t.Fatalf("prf key: %v", err)
	}
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
		A:                  A,
		B:                  B,
		Tag:                tagPublic,
		Nonce:              noncePublic,
		BoundB:             publicParams.BoundB,
		X0Len:              publicParams.X0Len,
		X0CoeffBound:       publicParams.X0CoeffBound,
		TargetDim:          publicParams.TargetDim,
		TargetHidingLambda: publicParams.TargetHidingLambda,
		HashRelation:       publicParams.HashRelation,
	}
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		t.Fatalf("build showing: %v", err)
	}
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	t.Logf("debug showing proof fields: qCoeff=%d evalPoints=%d ncols=%d qr=%d qopening=%v m1=%d m2=%d r1=%d carrierM=%d carrierR1=%d carrierR0=%v aliasR0=%v",
		len(proof.QCoeffDebug), len(proof.EvalPoints), proof.NColsUsed, len(proof.QR), proof.QOpening != nil,
		proof.RowLayout.IdxM1, proof.RowLayout.IdxM2, proof.RowLayout.IdxR1,
		proof.RowLayout.IdxCarrierM, proof.RowLayout.IdxCarrierR1,
		proof.RowLayout.CarrierR0Rows, proof.RowLayout.AliasR0Rows,
	)
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		if len(proof.QCoeffDebug) > 0 && len(proof.EvalPoints) > 0 && proof.NColsUsed > 0 {
			q := ringQ.Modulus[0]
			limit := 4
			if limit > len(proof.QCoeffDebug) {
				limit = len(proof.QCoeffDebug)
			}
			for rowIdx := 0; rowIdx < limit; rowIdx++ {
				sum := uint64(0)
				for i := 0; i < proof.NColsUsed && i < len(proof.EvalPoints); i++ {
					sum = (sum + PIOP.EvalPoly(proof.QCoeffDebug[rowIdx], proof.EvalPoints[i]%q, q)) % q
				}
				t.Logf("debug showing q row %d sigma=%d deg=%d", rowIdx, sum, len(proof.QCoeffDebug[rowIdx])-1)
			}
		}
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
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.LVCSNCols <= 0 || rep.TranscriptFocus.LVCSNCols <= 0 {
		t.Fatalf("missing LVCS geometry in transcript report: %+v", rep.TranscriptFocus)
	}
	if rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("invalid witness geometry: %+v", rep.TranscriptFocus)
	}
	if rep.DQ <= 0 {
		t.Fatalf("expected positive dQ, got %d", rep.DQ)
	}
	if rep.TranscriptFocus.NRows != rep.Soundness.NRows || rep.TranscriptFocus.M != rep.Soundness.M {
		t.Fatalf("transcript focus row geometry mismatch: %+v soundness=%+v", rep.TranscriptFocus, rep.Soundness)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("pcols=%d nrows-m=%d", rep.TranscriptFocus.PCols, rep.TranscriptFocus.NRows-rep.TranscriptFocus.M)
	}
	if rep.Geometry.PCSBlockCount <= 0 {
		t.Fatalf("pcs block count=%d want > 0", rep.Geometry.PCSBlockCount)
	}
	if rep.Geometry.ActualWitnessPolys <= 0 || rep.Geometry.ActualPostSignWitnessPolys <= 0 || rep.Geometry.ActualPRFWitnessPolys <= 0 {
		t.Fatalf("unexpected witness geometry: %+v", rep.Geometry)
	}
	if proof.RowLayout.MsgChainBase >= 0 || proof.RowLayout.RndChainBase >= 0 || proof.RowLayout.NonSigBoundRowsPer != 0 {
		t.Fatalf("expected compressed carriers (no non-sig chain rows), got MsgChainBase=%d RndChainBase=%d RowsPer=%d", proof.RowLayout.MsgChainBase, proof.RowLayout.RndChainBase, proof.RowLayout.NonSigBoundRowsPer)
	}
	if rep.PaperTranscript.Q.OptimizedBytes <= 0 || rep.PaperTranscript.Pdecs.OptimizedBytes <= 0 {
		t.Fatalf("missing transcript sizes: %+v", rep.PaperTranscript)
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
	if rep.PaperTranscript.OptimizedBytes <= 0 {
		t.Fatalf("paper transcript bytes=%d want > 0", rep.PaperTranscript.OptimizedBytes)
	}
	if rep.Soundness.TotalBits < 100 {
		t.Fatalf("unexpected soundness-balanced theorem floor: total=%.2f bits=%v theorem=%v", rep.Soundness.TotalBits, rep.Soundness.Bits, rep.Soundness.TheoremBits)
	}
}

func TestShowingV3SoundnessBalancedPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.SigShortness.ProofBytes <= 0 {
		t.Fatalf("soundness-balanced sig shortness bytes=%d want > 0", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols <= 0 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected soundness-balanced geometry: %+v", rep.TranscriptFocus)
	}
	if rep.PaperTranscript.OptimizedBytes <= 0 || rep.PaperTranscript.Pdecs.OptimizedBytes <= 0 || rep.PaperTranscript.Q.OptimizedBytes <= 0 {
		t.Fatalf("missing soundness-balanced transcript sizes: %+v", rep.PaperTranscript)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("unexpected soundness-balanced transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
}

func TestShowingV3CompactL3Preset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.SigShortness.ProofBytes <= 0 {
		t.Fatalf("compact-l3 sig shortness bytes=%d want > 0", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols <= 0 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected compact-l3 geometry: %+v", rep.TranscriptFocus)
	}
	if rep.PaperTranscript.OptimizedBytes <= 0 || rep.PaperTranscript.Pdecs.OptimizedBytes <= 0 || rep.PaperTranscript.Q.OptimizedBytes <= 0 {
		t.Fatalf("missing compact-l3 transcript sizes: %+v", rep.PaperTranscript)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
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
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.SigShortness.ProofBytes <= 0 {
		t.Fatalf("compact-l2 sig shortness bytes=%d want > 0", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols <= 0 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected compact-l2 geometry: %+v", rep.TranscriptFocus)
	}
	if rep.PaperTranscript.OptimizedBytes <= 0 || rep.PaperTranscript.Pdecs.OptimizedBytes <= 0 || rep.PaperTranscript.Q.OptimizedBytes <= 0 {
		t.Fatalf("missing compact-l2 transcript sizes: %+v", rep.PaperTranscript)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
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
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.TranscriptFocus.StatementClass != string(PIOP.ShowingStatementClassReducedEngineeringReplay) {
		t.Fatalf("compact-l1 statement class=%q want %q", rep.TranscriptFocus.StatementClass, PIOP.ShowingStatementClassReducedEngineeringReplay)
	}
	if rep.TranscriptFocus.ShortnessMode != PIOP.SigShortnessModeHiddenV6 || rep.SigShortness.Mode != PIOP.SigShortnessModeHiddenV6 {
		t.Fatalf("compact-l1 shortness mode mismatch: focus=%q report=%q", rep.TranscriptFocus.ShortnessMode, rep.SigShortness.Mode)
	}
	if !rep.SigShortness.Enabled || rep.SigShortness.Version != 6 || rep.SigShortness.SupportSlotCount != 1 || rep.SigShortness.OpenedBlockCount != 1 {
		t.Fatalf("unexpected compact-l1 sig shortness report: %+v", rep.SigShortness)
	}
	if rep.SigShortness.ProofBytes <= 0 {
		t.Fatalf("compact-l1 sig shortness bytes=%d want > 0", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols <= 0 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected compact-l1 geometry: %+v", rep.TranscriptFocus)
	}
	if rep.Kappa != [4]int{0, 11, 0, 11} {
		t.Fatalf("compact-l1 kappa=%v want [0 11 0 11]", rep.Kappa)
	}
	if rep.PaperTranscript.OptimizedBytes <= 0 || rep.PaperTranscript.Pdecs.OptimizedBytes <= 0 || rep.PaperTranscript.Q.OptimizedBytes <= 0 {
		t.Fatalf("missing compact-l1 transcript sizes: %+v", rep.PaperTranscript)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("unexpected compact-l1 transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
	if rep.Soundness.TotalBits < 128 {
		t.Fatalf("unexpected compact-l1 theorem floor: total=%.2f", rep.Soundness.TotalBits)
	}
}

func TestShowingV3CompactL1ResearchFullReplayPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if os.Getenv("SPRUCE_RUN_SLOW_V7_FULL") == "" {
		t.Skip("V7 compact full proving is currently runtime-heavy; set SPRUCE_RUN_SLOW_V7_FULL=1 to run this end-to-end check")
	}
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
	proof, rep, _, _, _, _ := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
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
	if rep.TranscriptFocus.ReplayMode != string(PIOP.ShowingReplayModeFull) {
		t.Fatalf("reported full compact-l1 replay mode=%q want %q", rep.TranscriptFocus.ReplayMode, PIOP.ShowingReplayModeFull)
	}
	if rep.Kappa != [4]int{} {
		t.Fatalf("full compact-l1 kappa=%v want [0 0 0 0]", rep.Kappa)
	}
	if rep.TranscriptFocus.StatementClass != string(PIOP.ShowingStatementClassCustom) {
		t.Fatalf("reported full compact-l1 statement class=%q want %q", rep.TranscriptFocus.StatementClass, PIOP.ShowingStatementClassCustom)
	}
	if rep.TranscriptFocus.ShortnessMode != PIOP.SigShortnessModeHiddenV7 || rep.SigShortness.Mode != PIOP.SigShortnessModeHiddenV7 {
		t.Fatalf("reported full compact-l1 shortness mode mismatch: focus=%q report=%q", rep.TranscriptFocus.ShortnessMode, rep.SigShortness.Mode)
	}
	if proof.RowLayout.IdxTSource >= 0 {
		t.Fatalf("full compact-l1 replay should derive T source rows locally")
	}
	if got, want := proof.RowLayout.ReplayBlockCount, proof.RowLayout.SigBlocks; got != want {
		t.Fatalf("full compact-l1 replay blocks=%d want sig blocks=%d", got, want)
	}
	if got, want := proof.RowLayout.ReplayTHatCount, proof.RowLayout.SigBlocks; got != want {
		t.Fatalf("full compact-l1 replay T-hat count=%d want sig blocks=%d", got, want)
	}
	if proof.PCSNColsUsed != resolved.PostSignLVCSNCols || proof.LVCSNColsUsed != resolved.PostSignLVCSNCols {
		t.Fatalf("full compact-l1 pcs width=%d/%d want %d", proof.PCSNColsUsed, proof.LVCSNColsUsed, resolved.PostSignLVCSNCols)
	}
	if !rep.SigShortness.Enabled || rep.SigShortness.Version != 7 || proof.SigShortness == nil || proof.SigShortness.V7 == nil {
		t.Fatalf("unexpected full compact-l1 sig shortness report: %+v", rep.SigShortness)
	}
	if proof.SigShortness.V5 != nil || proof.SigShortness.V6 != nil || proof.SigShortness.Opening != nil || len(proof.SigShortness.SupportSlots) != 0 {
		t.Fatalf("full compact-l1 V7 payload still carries legacy shortness state: %+v", proof.SigShortness)
	}
	if rep.SigShortness.SupportSlotCount != 0 || rep.SigShortness.OpenedBlockCount != 0 || rep.SigShortness.OpeningBytes != 0 || rep.SigShortness.HiddenProofBytes != 0 {
		t.Fatalf("full compact-l1 V7 shortness should have no dedicated opening: %+v", rep.SigShortness)
	}
	if rep.TranscriptFocus.SigShortnessSupportSlots != 0 {
		t.Fatalf("full compact-l1 transcript focus still reports shortness support slots=%d", rep.TranscriptFocus.SigShortnessSupportSlots)
	}
	if proof.RowLayout.PackedSigChainBase < 0 || proof.RowLayout.PackedSigChainGroupCount <= 0 || proof.RowLayout.PackedSigChainRowsPerGroup <= 0 {
		t.Fatalf("full compact-l1 V7 missing packed shortness witness rows: %+v", proof.RowLayout)
	}
	if proof.SourceProductBridge != nil {
		t.Fatalf("full compact-l1 should not carry source-product bridge: %+v", proof.SourceProductBridge)
	}
	if rep.TranscriptFocus.SourceProductBridgeBytes != 0 {
		t.Fatalf("full compact-l1 source-product bridge bytes=%d want 0", rep.TranscriptFocus.SourceProductBridgeBytes)
	}
	if rep.TranscriptFocus.SourceProductBridgeSupportSlots != 0 || rep.TranscriptFocus.SourceProductBridgeOpenedBlocks != 0 {
		t.Fatalf("full compact-l1 source-product bridge geometry changed: slots=%d blocks=%d", rep.TranscriptFocus.SourceProductBridgeSupportSlots, rep.TranscriptFocus.SourceProductBridgeOpenedBlocks)
	}
	if rep.TranscriptFocus.SourceProductSelectedRows != 0 {
		t.Fatalf("full compact-l1 source-product rows still selected=%d", rep.TranscriptFocus.SourceProductSelectedRows)
	}
	if rep.ReplayAudit.Selector.SelectedRows != compactL1ResearchFullSelectedRows {
		t.Fatalf("full compact-l1 selected rows=%d want %d", rep.ReplayAudit.Selector.SelectedRows, compactL1ResearchFullSelectedRows)
	}
	if rep.ReplayAudit.Selector.WitnessRows <= compactL1ResearchFullPreV7WitnessRowsBaseline {
		t.Fatalf("full compact-l1 witness rows=%d want > pre-V7 baseline %d", rep.ReplayAudit.Selector.WitnessRows, compactL1ResearchFullPreV7WitnessRowsBaseline)
	}
	if rep.ReplayAudit.Selector.ActiveBlocks != compactL1ResearchFullActiveReplayBlocks {
		t.Fatalf("full compact-l1 active replay blocks=%d want %d", rep.ReplayAudit.Selector.ActiveBlocks, compactL1ResearchFullActiveReplayBlocks)
	}
	if rep.PaperTranscript.Q.OptimizedBytes != compactL1ResearchFullControlQBytes {
		t.Fatalf("full compact-l1 Q=%d want %d", rep.PaperTranscript.Q.OptimizedBytes, compactL1ResearchFullControlQBytes)
	}
	if rep.Soundness.TotalBits < compactL1ResearchFullMinSoundnessBits {
		t.Fatalf("unexpected full compact-l1 theorem floor: total=%.2f", rep.Soundness.TotalBits)
	}
}

func TestShowingV3CompactL1ResearchFullReplayRawOverrideFallsBackToV6(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("research-only compact_l1 full-replay fallback is not maintained under vector x0; shipped reduced-path benchmark-x0 covers the live protocol")
	proof, rep, _, _, _, _ := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
		t,
		PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		false,
		false,
		"",
		8,
		PIOP.ShowingPresetCompactL1Research,
		"",
		11,
		4,
		16,
		0,
		func(opts *PIOP.SimOpts) {
			opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
		},
	)
	if rep.TranscriptFocus.ShortnessMode != PIOP.SigShortnessModeHiddenV6 || rep.SigShortness.Mode != PIOP.SigShortnessModeHiddenV6 {
		t.Fatalf("raw override full compact-l1 should fall back to V6: focus=%q report=%q", rep.TranscriptFocus.ShortnessMode, rep.SigShortness.Mode)
	}
	if proof.SigShortness == nil || proof.SigShortness.Version != 6 || proof.SigShortness.V6 == nil || proof.SigShortness.V6.THatOpening == nil || proof.SigShortness.V6.HiddenProof == nil {
		t.Fatalf("raw override full compact-l1 missing V6 payload: %+v", proof.SigShortness)
	}
}

func TestShowingV3CompactL1ResearchFullReplayProfileOverrideFallsBackToV6(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("research-only compact_l1 full-replay fallback is not maintained under vector x0; shipped reduced-path benchmark-x0 covers the live protocol")
	proof, rep, _, _, _, _ := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
		t,
		PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		false,
		false,
		"",
		8,
		PIOP.ShowingPresetCompactL1Research,
		PIOP.SigShortnessProfileR11L4Production,
		0,
		0,
		16,
		0,
		func(opts *PIOP.SimOpts) {
			opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
		},
	)
	if rep.TranscriptFocus.ShortnessMode != PIOP.SigShortnessModeHiddenV6 || rep.SigShortness.Mode != PIOP.SigShortnessModeHiddenV6 {
		t.Fatalf("profile override full compact-l1 should fall back to V6: focus=%q report=%q", rep.TranscriptFocus.ShortnessMode, rep.SigShortness.Mode)
	}
	if proof.SigShortness == nil || proof.SigShortness.Version != 6 || proof.SigShortness.V6 == nil || proof.SigShortness.V6.THatOpening == nil || proof.SigShortness.V6.HiddenProof == nil {
		t.Fatalf("profile override full compact-l1 missing V6 payload: %+v", proof.SigShortness)
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
	selector := PIOP.BuildShowingReplayActiveRowSelector(proof.RowLayout, companion, proof.PRFCompanion.Mode)
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
	if audit.Selector.SelectedRows <= 0 || audit.Selector.WitnessRows <= audit.Selector.SelectedRows {
		t.Fatalf("unexpected replay selector geometry: selected=%d witness=%d", audit.Selector.SelectedRows, audit.Selector.WitnessRows)
	}
	if audit.Selector.SelectedRows*100 > audit.Selector.WitnessRows*70 {
		t.Fatalf("replay selector reduction too small for shipped default: selected=%d witness=%d", audit.Selector.SelectedRows, audit.Selector.WitnessRows)
	}
	if audit.Selector.ActiveBlocks != audit.Selector.FullBlocks {
		t.Fatalf("expected shipped replay audit to remain block-dense: active=%d full=%d", audit.Selector.ActiveBlocks, audit.Selector.FullBlocks)
	}
	entries := make(map[PIOP.ReplayFamilyKind]PIOP.ReplayFamilyAuditEntry, len(audit.Families))
	selectedFamilies := make([]PIOP.ReplayFamilyKind, 0, len(audit.Families))
	for _, entry := range audit.Families {
		entries[entry.Family] = entry
		if entry.SelectedRowCount > 0 {
			selectedFamilies = append(selectedFamilies, entry.Family)
		}
	}
	wantSelectedFamilies := []PIOP.ReplayFamilyKind{
		PIOP.ReplayFamilyCarrier,
		PIOP.ReplayFamilyPRFCompanion,
	}
	if len(selectedFamilies) != len(wantSelectedFamilies) {
		t.Fatalf("selected family count=%d want %d (%v)", len(selectedFamilies), len(wantSelectedFamilies), selectedFamilies)
	}
	for i := range wantSelectedFamilies {
		if selectedFamilies[i] != wantSelectedFamilies[i] {
			t.Fatalf("selected family[%d]=%q want %q (full order=%v)", i, selectedFamilies[i], wantSelectedFamilies[i], selectedFamilies)
		}
	}
	coveredBlocks := make(map[int]struct{})
	for _, family := range selectedFamilies {
		entry := entries[family]
		for _, idx := range entry.SelectedRows {
			coveredBlocks[idx/audit.Selector.LayerSize] = struct{}{}
		}
	}
	if len(coveredBlocks) != audit.Selector.FullBlocks {
		t.Fatalf("selected families should jointly cover all active blocks: covered=%d full=%d", len(coveredBlocks), audit.Selector.FullBlocks)
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
	if got := byKind[PIOP.ReplaySubfamilySourceProductMSigmaR1].SelectedRowCount; got != 0 {
		t.Fatalf("source_product_msigmar1 selected=%d want 0", got)
	}
	if got := byKind[PIOP.ReplaySubfamilySourceProductR0R1].SelectedRowCount; got != 0 {
		t.Fatalf("source_product_r0r1 selected=%d want 0", got)
	}
	selectedKinds := make([]PIOP.ReplaySubfamilyKind, 0, len(sub.Entries))
	for _, entry := range sub.Entries {
		if entry.SelectedRowCount == 0 {
			continue
		}
		selectedKinds = append(selectedKinds, entry.Kind)
	}
	wantSelectedKinds := []PIOP.ReplaySubfamilyKind{
		PIOP.ReplaySubfamilyPRFKeyRows,
		PIOP.ReplaySubfamilyPRFCheckpointRows,
		PIOP.ReplaySubfamilyPRFFinalTagRows,
		PIOP.ReplaySubfamilyPRFHelperRows,
	}
	if len(selectedKinds) != len(wantSelectedKinds) {
		t.Fatalf("selected subfamily count=%d want %d (%v)", len(selectedKinds), len(wantSelectedKinds), selectedKinds)
	}
	for i := range wantSelectedKinds {
		if selectedKinds[i] != wantSelectedKinds[i] {
			t.Fatalf("selected subfamily[%d]=%q want %q (full order=%v)", i, selectedKinds[i], wantSelectedKinds[i], selectedKinds)
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

func TestShowingFullReplayOperatorModes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	cases := []struct {
		name string
		mode PIOP.PRFCompanionMode
	}{
		{name: "output_audit", mode: PIOP.PRFCompanionModeOutputAudit},
		{name: "direct_auth", mode: PIOP.PRFCompanionModeDirectAuth},
		{name: "aux_instance", mode: PIOP.PRFCompanionModeAuxInstance},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, rep, _, _, _, _ := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
				t,
				PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
				true,
				true,
				tc.mode,
				8,
				PIOP.ShowingPresetSoundnessBalanced,
				"",
				0,
				0,
				16,
				0,
				func(opts *PIOP.SimOpts) {
					opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
				},
			)
			if rep.TranscriptFocus.ReplayMode != string(PIOP.ShowingReplayModeFull) {
				t.Fatalf("reported replay mode=%q want %q", rep.TranscriptFocus.ReplayMode, PIOP.ShowingReplayModeFull)
			}
			if rep.TranscriptFocus.PRFMode != string(tc.mode) {
				t.Fatalf("reported prf mode=%q want %q", rep.TranscriptFocus.PRFMode, tc.mode)
			}
		})
	}
}

func TestShowingCompactL1ResearchFullReplayBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, _, opts, _, pub := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
		t,
		PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		true,
		true,
		PIOP.PRFCompanionModeOutputAudit,
		8,
		PIOP.ShowingPresetCompactL1Research,
		"",
		0,
		0,
		16,
		0,
		func(opts *PIOP.SimOpts) {
			opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
		},
	)
	if rep.TranscriptFocus.ReplayMode != string(PIOP.ShowingReplayModeFull) {
		t.Fatalf("reported replay mode=%q want %q", rep.TranscriptFocus.ReplayMode, PIOP.ShowingReplayModeFull)
	}
	if rep.TranscriptFocus.ShowingPreset == "" {
		t.Fatalf("missing reported showing preset")
	}
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify compact-l1 full replay showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify compact-l1 full replay showing returned ok=false")
	}
}

func TestShowingCompactFullCandidateW48E24EP2Verifies(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, _, opts, _, pub := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
		t,
		PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		true,
		true,
		PIOP.PRFCompanionModeOutputAudit,
		8,
		PIOP.ShowingPresetCompactL1Research,
		"",
		0,
		0,
		16,
		48,
		func(opts *PIOP.SimOpts) {
			opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
			opts.CompactFullCandidate = PIOP.CompactFullCandidateW48E24EP2
		},
	)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetCompactL1Research {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetCompactL1Research)
	}
	if rep.TranscriptFocus.CompactFullCandidate != PIOP.CompactFullCandidateW48E24EP2 {
		t.Fatalf("reported compact full candidate=%q want %q", rep.TranscriptFocus.CompactFullCandidate, PIOP.CompactFullCandidateW48E24EP2)
	}
	if rep.TranscriptFocus.ShortnessMode != PIOP.SigShortnessModeHiddenV7 {
		t.Fatalf("reported shortness mode=%q want %q", rep.TranscriptFocus.ShortnessMode, PIOP.SigShortnessModeHiddenV7)
	}
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify compact-full candidate showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify compact-full candidate showing returned ok=false")
	}
}

func TestShowingCompactFullSweepCandidateVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	candidate := "sweep:w48:n4096:e24:ep2:sigr11_l4_production:k0-0-0-0"
	proof, rep, _, opts, _, pub := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
		t,
		PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		true,
		true,
		PIOP.PRFCompanionModeOutputAudit,
		8,
		PIOP.ShowingPresetCompactL1Research,
		"",
		0,
		0,
		16,
		0,
		func(opts *PIOP.SimOpts) {
			opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
			opts.CompactFullCandidate = candidate
			opts.BenchmarkSweepCandidate = candidate
		},
	)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetCompactL1Research {
		t.Fatalf("reported showing preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetCompactL1Research)
	}
	if rep.TranscriptFocus.CompactFullCandidate != candidate {
		t.Fatalf("reported compact full candidate=%q want %q", rep.TranscriptFocus.CompactFullCandidate, candidate)
	}
	if rep.TranscriptFocus.BenchmarkSweepCandidate != candidate {
		t.Fatalf("reported benchmark sweep candidate=%q want %q", rep.TranscriptFocus.BenchmarkSweepCandidate, candidate)
	}
	if rep.TranscriptFocus.ShortnessMode != PIOP.SigShortnessModeHiddenV7 {
		t.Fatalf("reported shortness mode=%q want %q", rep.TranscriptFocus.ShortnessMode, PIOP.SigShortnessModeHiddenV7)
	}
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify compact-full sweep candidate showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify compact-full sweep candidate showing returned ok=false")
	}
}

func TestShowingCompactFullBenchmarkSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)
	out := filepath.Join(t.TempDir(), "compact_full_benchmark.json")
	if err := runBenchmarkCompactFull([]string{
		"-candidates", PIOP.CompactFullCandidateCurrent,
		"-controls", compactFullBenchmarkControlBalancedFull + "," + compactFullBenchmarkControlCompactReduced,
		"-runs", "1",
		"-json-out", out,
	}); err != nil {
		t.Fatalf("benchmark-compact-full: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read benchmark json: %v", err)
	}
	var report benchmarkCompactFullReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal benchmark json: %v", err)
	}
	if report.Version != benchmarkCompactFullVersion {
		t.Fatalf("report version=%d want %d", report.Version, benchmarkCompactFullVersion)
	}
	if len(report.Entries) < 3 {
		t.Fatalf("entries len=%d want at least 3", len(report.Entries))
	}
	seen := make(map[string]benchmarkCompactFullEntry, len(report.Entries))
	for _, entry := range report.Entries {
		seen[entry.ID] = entry
		if entry.TranscriptBytes <= 0 || entry.ProofBytes <= 0 {
			t.Fatalf("entry %s missing size metrics: %+v", entry.ID, entry)
		}
		if entry.PaperBuckets.TotalBytes != entry.TranscriptBytes {
			t.Fatalf("entry %s bucket total=%d want transcript=%d", entry.ID, entry.PaperBuckets.TotalBytes, entry.TranscriptBytes)
		}
		if entry.Focus.DQ <= 0 || entry.Focus.LVCSNCols <= 0 || entry.Focus.WitnessRows <= 0 {
			t.Fatalf("entry %s missing focus geometry: %+v", entry.ID, entry.Focus)
		}
	}
	entry, ok := seen[PIOP.CompactFullCandidateCurrent]
	if !ok {
		t.Fatalf("missing candidate entry %q", PIOP.CompactFullCandidateCurrent)
	}
	if entry.ShortnessMode != PIOP.SigShortnessModeHiddenV7 {
		t.Fatalf("candidate %s shortness mode=%q want %q", PIOP.CompactFullCandidateCurrent, entry.ShortnessMode, PIOP.SigShortnessModeHiddenV7)
	}
}

func TestShowingTranscriptSweepSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)
	out := filepath.Join(t.TempDir(), "transcript_sweep.json")
	if err := runBenchmarkTranscriptSweep([]string{
		"-tracks", strings.Join([]string{
			transcriptSweepTrackReduced,
			transcriptSweepTrackCompactFullV7,
			transcriptSweepTrackPRFReduced,
			transcriptSweepTrackPRFFull96,
		}, ","),
		"-controls-only",
		"-runs", "1",
		"-json-out", out,
	}); err != nil {
		t.Fatalf("benchmark-transcript-sweep: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read benchmark json: %v", err)
	}
	var report transcriptSweepReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal benchmark json: %v", err)
	}
	if report.Version != benchmarkTranscriptSweepVersion {
		t.Fatalf("report version=%d want %d", report.Version, benchmarkTranscriptSweepVersion)
	}
	if len(report.Entries) == 0 {
		t.Fatal("expected transcript sweep entries")
	}
	if len(report.TrackSummaries) == 0 {
		t.Fatal("expected transcript sweep track summaries")
	}
	for _, entry := range report.Entries {
		if entry.Track == "" || entry.CandidateID == "" {
			t.Fatalf("entry missing track/id: %+v", entry)
		}
		if entry.PRFMode == "" || entry.PRFGroupRounds <= 0 {
			t.Fatalf("entry missing prf controls: %+v", entry)
		}
		if entry.Geometry.LVCSNCols <= 0 || entry.Geometry.NLeaves <= 0 {
			t.Fatalf("entry missing geometry: %+v", entry.Geometry)
		}
		if entry.Soundness.Eq8TotalBits <= 0 || entry.Soundness.Thm9TotalBits <= 0 {
			t.Fatalf("entry missing soundness: %+v", entry.Soundness)
		}
		if entry.PaperTranscriptBytes > 0 {
			total := entry.PaperBuckets.QBytes + entry.PaperBuckets.PdecsBytes + entry.PaperBuckets.RBytes +
				entry.PaperBuckets.SigShortnessBytes + entry.PaperBuckets.AuthBytes + entry.PaperBuckets.VTargetsBytes + entry.PaperBuckets.BarSetsBytes
			if total <= 0 {
				t.Fatalf("entry missing transcript buckets: %+v", entry.PaperBuckets)
			}
		}
		if !entry.Verified && entry.RejectReason == "" {
			t.Fatalf("rejected entry missing reject_reason: %+v", entry)
		}
	}
}

func TestShowingPRFCompanionDirectAuthEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("direct_auth remains research-only and is not a maintained acceptance target under vector x0")
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

func TestShowingPRFCompanionAuxInstanceFullReplayEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("aux_instance full-replay remains research-only and is not a maintained acceptance target under vector x0")
	proof, rep, _, opts, _, pub := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
		t,
		PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		true,
		true,
		PIOP.PRFCompanionModeAuxInstance,
		8,
		PIOP.ShowingPresetCompactL1Research,
		PIOP.SigShortnessProfileR12285L1Research,
		0,
		0,
		16,
		0,
		func(opts *PIOP.SimOpts) {
			opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
		},
	)
	if proof.PRFCompanion == nil || proof.PRFCompanion.Layout == nil {
		t.Fatalf("missing PRF companion proof/layout")
	}
	if proof.PRFCompanion.Bridge == nil {
		t.Fatalf("missing PRF witness omega bridge")
	}
	if proof.PRFCompanion.AuxInstance == nil || proof.PRFCompanion.AuxInstance.Proof == nil {
		t.Fatalf("missing PRF aux instance proof")
	}
	if proof.PRFCompanion.BridgeInQ || rep.TranscriptFocus.PRFBridgeInQ {
		t.Fatalf("aux_instance should keep PRF bridge out of Q")
	}
	if !rep.TranscriptFocus.PRFAuxInstance || rep.TranscriptFocus.PRFAuxProofBytes <= 0 || rep.TranscriptFocus.PRFAuxOpeningBytes <= 0 {
		t.Fatalf("missing aux-instance transcript accounting: %+v", rep.TranscriptFocus)
	}
	if rep.TranscriptFocus.PRFBridgeOpeningBytes != rep.TranscriptFocus.PRFAuxOpeningBytes {
		t.Fatalf("bridge opening bytes=%d want aux opening bytes=%d", rep.TranscriptFocus.PRFBridgeOpeningBytes, rep.TranscriptFocus.PRFAuxOpeningBytes)
	}
	if rep.TranscriptFocus.PRFBridgeSupportSlots <= 0 || rep.TranscriptFocus.PRFBridgeOpenedBlocks <= 0 || rep.TranscriptFocus.PRFBridgeRowCount <= 0 {
		t.Fatalf("missing bridge stripe accounting: %+v", rep.TranscriptFocus)
	}
	if proof.PRFCompanion.Layout.BridgeStripe == nil {
		t.Fatalf("missing prf bridge stripe layout")
	}
	if len(proof.PRFCompanion.Layout.BridgeStripe.SourceRows) != rep.TranscriptFocus.PRFBridgeRowCount {
		t.Fatalf("bridge row count=%d want %d", rep.TranscriptFocus.PRFBridgeRowCount, len(proof.PRFCompanion.Layout.BridgeStripe.SourceRows))
	}
	if rep.TranscriptFocus.StatementClass != string(PIOP.ShowingStatementClassCustom) {
		t.Fatalf("statement class=%q want %q", rep.TranscriptFocus.StatementClass, PIOP.ShowingStatementClassCustom)
	}
	if rep.TranscriptFocus.ReplayMode != string(PIOP.ShowingReplayModeFull) {
		t.Fatalf("replay mode=%q want %q", rep.TranscriptFocus.ReplayMode, PIOP.ShowingReplayModeFull)
	}
	if rep.TranscriptFocus.PRFLVCSNCols != opts.PRFLVCSNCols || rep.TranscriptFocus.PRFNLeaves != opts.PRFNLeaves {
		t.Fatalf("unexpected aux PRF geometry in report: lvcs=%d/%d nleaves=%d/%d", rep.TranscriptFocus.PRFLVCSNCols, opts.PRFLVCSNCols, rep.TranscriptFocus.PRFNLeaves, opts.PRFNLeaves)
	}
	if rep.TranscriptFocus.MainLVCSNCols != opts.LVCSNCols || rep.TranscriptFocus.MainNLeaves != opts.NLeaves {
		t.Fatalf("unexpected main geometry in report: lvcs=%d/%d nleaves=%d/%d", rep.TranscriptFocus.MainLVCSNCols, opts.LVCSNCols, rep.TranscriptFocus.MainNLeaves, opts.NLeaves)
	}
	if rep.TranscriptFocus.HiddenShortnessLVCSNCols <= 0 || rep.TranscriptFocus.HiddenShortnessNLeaves <= 0 {
		t.Fatalf("missing hidden shortness geometry in report: %+v", rep.TranscriptFocus)
	}

	subfamilyCounts := map[PIOP.ReplaySubfamilyKind]int{}
	for _, entry := range rep.ReplayAudit.Subfamilies.Entries {
		subfamilyCounts[entry.Kind] = entry.SelectedRowCount
	}
	if subfamilyCounts[PIOP.ReplaySubfamilyPRFCheckpointRows] != 0 {
		t.Fatalf("checkpoint rows still selected under aux_instance: %d", subfamilyCounts[PIOP.ReplaySubfamilyPRFCheckpointRows])
	}
	if subfamilyCounts[PIOP.ReplaySubfamilyPRFFinalTagRows] != 0 {
		t.Fatalf("final-tag rows still selected under aux_instance: %d", subfamilyCounts[PIOP.ReplaySubfamilyPRFFinalTagRows])
	}
	if subfamilyCounts[PIOP.ReplaySubfamilyPRFHelperRows] != 0 {
		t.Fatalf("helper rows still selected under aux_instance: %d", subfamilyCounts[PIOP.ReplaySubfamilyPRFHelperRows])
	}
	if subfamilyCounts[PIOP.ReplaySubfamilyPRFKeyRows] <= 0 {
		t.Fatalf("key rows unexpectedly dropped under aux_instance")
	}

	ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout, PRFCompanionLayout: proof.PRFCompanion.Layout}, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify aux_instance full replay showing: %v", err)
	}
	if !ok {
		t.Fatalf("verify aux_instance full replay showing returned ok=false")
	}
}

func TestShowingV3ProductionBalancePreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.TranscriptFocus.LVCSNCols <= 0 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected production-balance geometry: %+v", rep.TranscriptFocus)
	}
	if rep.DQ <= 0 {
		t.Fatalf("production-balance dQ=%d want > 0", rep.DQ)
	}
	if rep.PaperTranscript.OptimizedBytes <= 0 || rep.PaperTranscript.Pdecs.OptimizedBytes <= 0 || rep.PaperTranscript.Q.OptimizedBytes <= 0 {
		t.Fatalf("missing production-balance transcript sizes: %+v", rep.PaperTranscript)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("unexpected production-balance pcols=%d nrows-m=%d", rep.TranscriptFocus.PCols, rep.TranscriptFocus.NRows-rep.TranscriptFocus.M)
	}
}

func TestShowingV3TranscriptFirstProductionShortnessPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.DQ <= 0 {
		t.Fatalf("transcript-first dQ=%d want > 0", rep.DQ)
	}
	if rep.Geometry.ActualWitnessPolys <= 0 || rep.Geometry.ActualPostSignWitnessPolys <= 0 || rep.Geometry.ActualPRFWitnessPolys <= 0 {
		t.Fatalf("unexpected transcript-first witness geometry: %+v", rep.Geometry)
	}
	if rep.Geometry.PCSBlockCount <= 0 {
		t.Fatalf("transcript-first pcs block count=%d want > 0", rep.Geometry.PCSBlockCount)
	}
	if rep.TranscriptFocus.LVCSNCols <= 0 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected transcript-first lvcs geometry: %+v", rep.TranscriptFocus)
	}
	if rep.PaperTranscript.OptimizedBytes <= 0 || rep.PaperTranscript.Pdecs.OptimizedBytes <= 0 || rep.PaperTranscript.Q.OptimizedBytes <= 0 {
		t.Fatalf("missing transcript-first transcript sizes: %+v", rep.PaperTranscript)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("unexpected transcript-first pcols=%d nrows-m=%d", rep.TranscriptFocus.PCols, rep.TranscriptFocus.NRows-rep.TranscriptFocus.M)
	}
}

func TestShowingV3CustomBalancedRawShortnessProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.DQ <= 0 {
		t.Fatalf("custom dQ=%d want > 0", rep.DQ)
	}
	if rep.Geometry.ActualWitnessPolys <= 0 || rep.Geometry.ActualPostSignWitnessPolys <= 0 || rep.Geometry.ActualPRFWitnessPolys <= 0 {
		t.Fatalf("unexpected custom witness geometry: %+v", rep.Geometry)
	}
	if rep.Geometry.PCSBlockCount <= 0 {
		t.Fatalf("custom pcs block count=%d want > 0", rep.Geometry.PCSBlockCount)
	}
	if rep.PaperTranscript.Pdecs.OptimizedBytes <= 0 || rep.PaperTranscript.Q.OptimizedBytes <= 0 {
		t.Fatalf("missing custom transcript sizes: %+v", rep.PaperTranscript)
	}
	if rep.TranscriptFocus.PCols != rep.TranscriptFocus.NRows-rep.TranscriptFocus.M {
		t.Fatalf("unexpected custom transcript geometry: nrows=%d m=%d pcols=%d", rep.TranscriptFocus.NRows, rep.TranscriptFocus.M, rep.TranscriptFocus.PCols)
	}
}

func TestShowingV3ProductionShortnessWideLVCS96ResearchBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
	_, rep, _, _, _, _ := buildShowingProofForTestConfigWithLVCSAndShortnessProfile(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, PIOP.SigShortnessProfileR11L4Production, 96)
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileR11L4Production {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileR11L4Production)
	}
	if rep.TranscriptFocus.LVCSNCols != 96 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected lvcs96 geometry focus: %+v", rep.TranscriptFocus)
	}
	if rep.Geometry.PCSBlockCount <= 0 {
		t.Fatalf("production lvcs96 pcs block count=%d want > 0", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ <= 0 {
		t.Fatalf("production lvcs96 dQ=%d want > 0", rep.DQ)
	}
}

func TestShowingV3ProductionShortnessWideLVCS128ResearchBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
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
	if rep.SigShortness.ProofBytes <= 0 {
		t.Fatalf("wide lvcs128 sig shortness bytes=%d want > 0", rep.SigShortness.ProofBytes)
	}
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected lvcs128 geometry focus: %+v", rep.TranscriptFocus)
	}
	if rep.Geometry.PCSBlockCount <= 0 {
		t.Fatalf("production lvcs128 pcs block count=%d want > 0", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ <= 0 {
		t.Fatalf("production lvcs128 dQ=%d want > 0", rep.DQ)
	}
}

func TestShowingV3CustomBalancedRawShortnessWideLVCS128Probe(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("stale transcript-size baseline under vector x0; benchmark-x0 supersedes preset byte-count regression checks")
	_, rep, _, _, _, _ := buildShowingProofForTestConfigWithLVCSAndRawShortness(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, false, false, "", 8, 7, 5, 128)
	if rep.TranscriptFocus.SigShortnessProfile != PIOP.SigShortnessProfileCustomBalanced {
		t.Fatalf("reported sig shortness profile=%q want %q", rep.TranscriptFocus.SigShortnessProfile, PIOP.SigShortnessProfileCustomBalanced)
	}
	if rep.TranscriptFocus.SigShortnessRadix != 7 || rep.TranscriptFocus.SigShortnessDigits != 5 || rep.TranscriptFocus.SigShortnessDegree != 7 {
		t.Fatalf("unexpected custom lvcs128 sig metrics: profile=%q radix=%d digits=%d degree=%d", rep.TranscriptFocus.SigShortnessProfile, rep.TranscriptFocus.SigShortnessRadix, rep.TranscriptFocus.SigShortnessDigits, rep.TranscriptFocus.SigShortnessDegree)
	}
	if rep.TranscriptFocus.LVCSNCols != 128 || rep.TranscriptFocus.WitnessRows <= 0 || rep.TranscriptFocus.RowsBlock <= 0 || rep.TranscriptFocus.MaskChunks <= 0 {
		t.Fatalf("unexpected custom lvcs128 geometry focus: %+v", rep.TranscriptFocus)
	}
	if rep.Geometry.PCSBlockCount <= 0 {
		t.Fatalf("custom lvcs128 pcs block count=%d want > 0", rep.Geometry.PCSBlockCount)
	}
	if rep.DQ <= 0 {
		t.Fatalf("custom lvcs128 dQ=%d want > 0", rep.DQ)
	}
}

func TestShowingV3ProductionShortnessWideLVCS128DirectAuthMatchesOutputAuditGeometry(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	t.Skip("wide-LVCS direct_auth comparison is a research-only geometry probe and is not maintained under vector x0")
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
