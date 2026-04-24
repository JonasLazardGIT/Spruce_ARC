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

func TestShowingAggregateV11DirectTargetResearchPreset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, rep, _, _, _, _ := buildShowingProofForShippedPresetDefault(t, PIOP.ShowingPresetAggregateV11DirectTargetResearch)
	if rep.TranscriptFocus.ShowingPreset != PIOP.ShowingPresetAggregateV11DirectTargetResearch {
		t.Fatalf("reported preset=%q want %q", rep.TranscriptFocus.ShowingPreset, PIOP.ShowingPresetAggregateV11DirectTargetResearch)
	}
	if rep.TranscriptFocus.StatementClass != string(PIOP.ShowingStatementClassTheoremCleanDirectTargetFullReplay) {
		t.Fatalf("aggregate V11 statement class=%q", rep.TranscriptFocus.StatementClass)
	}
	if rep.TranscriptFocus.ReplayMode != string(PIOP.ShowingReplayModeFull) {
		t.Fatalf("aggregate V11 replay mode=%q want full", rep.TranscriptFocus.ReplayMode)
	}
	if !rep.TranscriptFocus.AggregateR0Replay {
		t.Fatal("aggregate V11 report did not enable aggregate replay")
	}
	if rep.TranscriptFocus.ShortnessMode != PIOP.SigShortnessModeDirectTargetV11 || rep.SigShortness.Mode != PIOP.SigShortnessModeDirectTargetV11 {
		t.Fatalf("aggregate V11 shortness mismatch: focus=%q report=%q", rep.TranscriptFocus.ShortnessMode, rep.SigShortness.Mode)
	}
	if proof.SigShortness == nil || proof.SigShortness.Version != 11 || proof.SigShortness.V11 == nil {
		t.Fatalf("aggregate V11 proof missing V11 payload: %+v", proof.SigShortness)
	}
	if proof.SigShortness.V6 != nil || proof.SigShortness.V7 != nil || proof.SigShortness.V8 != nil || proof.SigShortness.V9 != nil || proof.SigShortness.V10 != nil || proof.SigShortness.Opening != nil || len(proof.SigShortness.SupportSlots) != 0 {
		t.Fatalf("aggregate V11 proof populated legacy shortness fields: %+v", proof.SigShortness)
	}
	if proof.SigShortness.V11.Radix != 24 || proof.SigShortness.V11.Digits != 3 {
		t.Fatalf("aggregate V11 shortness shape R=%d L=%d want R=24 L=3", proof.SigShortness.V11.Radix, proof.SigShortness.V11.Digits)
	}
	if len(proof.RowLayout.ReplayTHatRows) != 0 || proof.RowLayout.ReplayTHatCount != 0 || proof.RowLayout.IdxTHatBase >= 0 {
		t.Fatalf("aggregate V11 should not materialize T-hat rows: %+v", proof.RowLayout.ReplayTHatRows)
	}
	if rep.TranscriptFocus.ReplayTargetMR0HatRows != 64 || rep.TranscriptFocus.ReplayMHatSigmaRows != 0 || rep.TranscriptFocus.ReplayR0B2HatRows != 0 {
		t.Fatalf("aggregate V11 replay rows target_mr0=%d mhat=%d r0b2=%d",
			rep.TranscriptFocus.ReplayTargetMR0HatRows,
			rep.TranscriptFocus.ReplayMHatSigmaRows,
			rep.TranscriptFocus.ReplayR0B2HatRows,
		)
	}
	if rep.TranscriptFocus.ReplayRHat1Rows != 64 || rep.TranscriptFocus.ReplayZHatRows != 64 || rep.TranscriptFocus.ReplayTHatRows != 0 {
		t.Fatalf("aggregate V11 direct replay rows rhat1=%d zhat=%d that=%d",
			rep.TranscriptFocus.ReplayRHat1Rows,
			rep.TranscriptFocus.ReplayZHatRows,
			rep.TranscriptFocus.ReplayTHatRows,
		)
	}
	if rep.TranscriptFocus.V11ShortnessRows != 384 || rep.TranscriptFocus.V11PackedSigChainGroupSize != 1 || rep.TranscriptFocus.V11PackedSigBlockWidth != 16 || rep.TranscriptFocus.V11EffectiveSigBlocks != 64 {
		t.Fatalf("aggregate V11 geometry rows=%d group=%d width=%d blocks=%d",
			rep.TranscriptFocus.V11ShortnessRows,
			rep.TranscriptFocus.V11PackedSigChainGroupSize,
			rep.TranscriptFocus.V11PackedSigBlockWidth,
			rep.TranscriptFocus.V11EffectiveSigBlocks,
		)
	}
	if rep.SigShortness.OpeningBytes != 0 || rep.SigShortness.SupportSlotCount != 0 || rep.SigShortness.OpenedBlockCount != 0 {
		t.Fatalf("aggregate V11 should report no opening: %+v", rep.SigShortness)
	}
	if rep.SigShortness.HiddenProofBytes != 0 || rep.SigShortness.BindingBytes == 0 {
		t.Fatalf("aggregate V11 should report metadata binding only: %+v", rep.SigShortness)
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
			transcriptSweepTrackFullV6,
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
	sawAggregateR0 := false
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
		if entry.AggregateR0Replay {
			sawAggregateR0 = true
			if entry.Geometry.ReplayR0B2HatRows+entry.Geometry.ReplayTargetMR0HatRows <= 0 || entry.Geometry.ReplayRHat0Rows != 0 {
				t.Fatalf("aggregate R0 entry missing aggregate row geometry: %+v", entry.Geometry)
			}
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
	if !sawAggregateR0 {
		t.Fatal("expected transcript sweep to include aggregate R0 control")
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

func TestShowingCredentialQOpeningCompressedAndVerifies(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	proof, _, _, _, _, _ := buildShowingProofForTestConfig(t, PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3, true, true, PIOP.PRFCompanionModeOutputAudit, 8)
	if proof.QOpening == nil {
		t.Fatal("missing Q opening")
	}
	if proof.QOpening.FormatVersion != 1 {
		t.Fatalf("Q opening P format=%d want compressed format 1", proof.QOpening.FormatVersion)
	}
	if len(proof.QOpening.POmitCols) == 0 || proof.QOpening.PColsEncoded <= 0 {
		t.Fatalf("Q opening missing compressed P metadata: cols=%d omit=%v", proof.QOpening.PColsEncoded, proof.QOpening.POmitCols)
	}
	if proof.QOpening.MFormatVersion != 1 {
		t.Fatalf("Q opening M format=%d want compressed format 1", proof.QOpening.MFormatVersion)
	}
	if len(proof.QOpening.MOmitCols) == 0 || proof.QOpening.MColsEncoded <= 0 {
		t.Fatalf("Q opening missing compressed M metadata: cols=%d omit=%v", proof.QOpening.MColsEncoded, proof.QOpening.MOmitCols)
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
