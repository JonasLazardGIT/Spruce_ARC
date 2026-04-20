package PIOP

import (
	"strings"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func hiddenSigShortnessOptsForTest(proof *Proof, v6 *SigShortnessProofV6) SimOpts {
	opts := SimOpts{
		Credential:          true,
		DomainMode:          proof.DomainMode,
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		NCols:               proof.NColsUsed,
		PCSNCols:            proof.PCSNColsUsed,
		LVCSNCols:           proof.LVCSNColsUsed,
		Theta:               proof.Theta,
		Rho:                 proof.QOpening.R,
		Ell:                 len(proof.Tail),
		EllPrime:            len(proof.BarSetsMatrix()),
		Eta:                 proof.QOpening.Eta,
		NLeaves:             proof.NLeavesUsed,
		SigShortnessRadix:   v6.Radix,
		SigShortnessL:       v6.Digits,
	}
	opts.Kappa = proof.Kappa
	opts.applyDefaults()
	return opts
}

func buildSigShortnessV6FixtureProof(t *testing.T, profile string) (transformBridgeFixture, *Proof, ConstraintSet) {
	t.Helper()
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, profile)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	set := ConstraintSet{
		FparInt:            append([]*ring.Poly{}, postSet.FparInt...),
		FparIntCoeffs:      append([][]uint64{}, postSet.FparIntCoeffs...),
		FparNorm:           postSet.FparNorm,
		FparNormCoeffs:     postSet.FparNormCoeffs,
		FaggInt:            postSet.FaggInt,
		FaggIntCoeffs:      postSet.FaggIntCoeffs,
		FaggNorm:           postSet.FaggNorm,
		FaggNormCoeffs:     postSet.FaggNormCoeffs,
		ParallelAlgDeg:     postSet.ParallelAlgDeg,
		AggregatedAlgDeg:   postSet.AggregatedAlgDeg,
		PRFLayout:          fx.prfLayout,
		PRFCompanionLayout: fx.prfCompanion,
	}
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	return fx, proof, set
}

func TestSigShortnessProofV6RoundTripAndDigestBinding(t *testing.T) {
	fx, proof, set := buildSigShortnessV6FixtureProof(t, SigShortnessProfileR11L4Production)
	if proof.SigShortness == nil || proof.SigShortness.Version != sigShortnessProofVersionV6 {
		t.Fatalf("sig shortness version=%v want V6", proof.SigShortness)
	}
	if proof.SigShortness.V6 == nil || proof.SigShortness.V6.THatOpening == nil || proof.SigShortness.V6.HiddenProof == nil {
		t.Fatalf("missing sig shortness V6 payload: %+v", proof.SigShortness)
	}
	if proof.SigShortness.V5 != nil {
		t.Fatalf("unexpected legacy V5 payload")
	}
	if len(proof.SigShortness.V6.HiddenProof.FparCoeffDebug) != 0 || len(proof.SigShortness.V6.HiddenProof.FaggCoeffDebug) != 0 {
		t.Fatalf("hidden shortness proof still carries explicit constraint debug coefficients")
	}
	ok, err := VerifyWithConstraints(proof, set, fx.pub, fx.opts, FSModeCredential)
	if err != nil {
		t.Fatalf("verify with constraints: %v", err)
	}
	if !ok {
		t.Fatalf("verify with constraints returned false")
	}
	if err := VerifySigShortnessProof(proof, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err != nil {
		t.Fatalf("verify sig shortness V6: %v", err)
	}
	hiddenOpts := hiddenSigShortnessOptsForTest(proof.SigShortness.V6.HiddenProof, proof.SigShortness.V6)
	hiddenRep, err := BuildProofReport(proof.SigShortness.V6.HiddenProof, hiddenOpts, fx.ringQ)
	if err != nil {
		t.Fatalf("build hidden sig shortness report: %v", err)
	}
	if hiddenRep.PaperTranscript.OptimizedBytes >= 12000 {
		t.Fatalf("hidden sig shortness paper transcript=%d want < 12000", hiddenRep.PaperTranscript.OptimizedBytes)
	}

	tampered := cloneProofWithSigShortnessForTest(proof)
	tampered.SigShortness.V6.HiddenProof.Digests[0][0] ^= 1
	ok, err = VerifyWithConstraints(tampered, set, fx.pub, fx.opts, FSModeCredential)
	if err == nil || !strings.Contains(err.Error(), "FS round 0") {
		t.Fatalf("tampered V6 digest error=%v want FS round 0 rejection", err)
	}
	if ok {
		t.Fatalf("tampered V6 digest unexpectedly verified")
	}
}

func TestSigShortnessProofV6RejectsTHatAndHiddenLabelsTamper(t *testing.T) {
	fx, proof, _ := buildSigShortnessV6FixtureProof(t, SigShortnessProfileR11L4Production)

	t.Run("t_hat_opening", func(t *testing.T) {
		tampered := cloneProofWithSigShortnessForTest(proof)
		opening := expandPackedOpening(tampered.SigShortness.V6.THatOpening)
		opening.Pvals[0][0] = modAdd(opening.Pvals[0][0], 1, fx.ringQ.Modulus[0])
		tampered.SigShortness.V6.THatOpening = opening
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("tampered V6 T-hat opening unexpectedly verified")
		}
	})

	t.Run("hidden_labels", func(t *testing.T) {
		tampered := cloneProofWithSigShortnessForTest(proof)
		tampered.SigShortness.V6.HiddenProof.LabelsDigest[0] ^= 1
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("tampered hidden labels digest unexpectedly verified")
		}
	})
}

func TestSigShortnessProofV6DigestMatchesVerifierRound0Material(t *testing.T) {
	_, proof, _ := buildSigShortnessV6FixtureProof(t, SigShortnessProfileR11L4Production)
	digest, err := buildSigShortnessBindingDigest(proof.SigShortness, proof.RowLayout, proof.NColsUsed)
	if err != nil {
		t.Fatalf("build V6 digest: %v", err)
	}
	if len(digest) == 0 {
		t.Fatal("missing V6 binding digest")
	}
	material0 := [][]byte{append([]byte(nil), proof.Root[:]...), proof.LabelsDigest, digest}
	fs := NewFS(NewShake256XOF(fsDigestBytes), proof.Salt, FSParams{Lambda: proof.Lambda, Kappa: proof.Kappa})
	if _, err := verifyRoundDigest(fs, 0, proof.Ctr[0], material0, proof.Digests[0], proof.Kappa[0]); err != nil {
		t.Fatalf("verify round-0 digest with V6 material: %v", err)
	}
}

func TestSigShortnessV6HiddenMembershipConstraintsVanishOnWitnessOmega(t *testing.T) {
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, SigShortnessProfileR11L4Production)
	packedWitness, hiddenOpts, spec, err := chooseSigShortnessHiddenProfile(fx.ringQ, fx.wit.CoeffNativeShowing, fx.omegaWitness, fx.opts.NCols, fx.opts)
	if err != nil {
		t.Fatalf("choose hidden profile: %v", err)
	}
	hiddenLayout := buildSigShortnessHiddenLayout(fx.layout, spec, fx.opts.NCols)
	hiddenRowsNTT, err := flattenSigShortnessHiddenWitnessRows(hiddenLayout, packedWitness, spec)
	if err != nil {
		t.Fatalf("flatten hidden rows: %v", err)
	}
	set, err := buildLiteralPackedSignatureShortnessConstraintSet(fx.ringQ, hiddenLayout, hiddenRowsNTT, SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: hiddenOpts.SigShortnessProfile,
		SigShortnessRadix:   hiddenOpts.SigShortnessRadix,
		SigShortnessL:       hiddenOpts.SigShortnessL,
	})
	if err != nil {
		t.Fatalf("build hidden shortness set: %v", err)
	}
	if len(set.FparNorm) == 0 {
		t.Fatal("hidden shortness set missing FparNorm")
	}
	for i, poly := range set.FparNorm {
		vals, err := evalPolyOnOmegaTest(fx.ringQ, fx.omegaWitness, poly)
		if err != nil {
			t.Fatalf("eval hidden FparNorm[%d]: %v", i, err)
		}
		for j, v := range vals {
			if v%fx.ringQ.Modulus[0] != 0 {
				t.Fatalf("hidden FparNorm[%d](omega[%d])=%d for profile=%s radix=%d digits=%d", i, j, v, hiddenOpts.SigShortnessProfile, spec.R, spec.L)
			}
		}
	}
}

func TestSigShortnessV6HiddenBridgeReplayMatchesFormalCoeffs(t *testing.T) {
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, SigShortnessProfileR11L4Production)
	_, hiddenOpts, spec, err := chooseSigShortnessHiddenProfile(fx.ringQ, fx.wit.CoeffNativeShowing, fx.omegaWitness, fx.opts.NCols, fx.opts)
	if err != nil {
		t.Fatalf("choose hidden profile: %v", err)
	}
	hiddenLVCSNCols := resolvePCSNCols(hiddenOpts, fx.opts.NCols)
	hiddenOmegaWitness, err := deriveRelationWitnessOmega(
		fx.ringQ.Modulus[0],
		hiddenOpts.NLeaves,
		fx.opts.NCols,
		hiddenLVCSNCols,
		hiddenOpts.Ell,
		fx.pub.HashRelation,
	)
	if err != nil {
		t.Fatalf("derive hidden witness omega: %v", err)
	}
	packedWitness, err := buildLiteralPackedPolyWitness(
		fx.ringQ,
		fx.wit.CoeffNativeShowing,
		hiddenOmegaWitness,
		fx.opts.NCols,
		CoeffNativeSigModelLiteralPackedAggregatedV3,
		hiddenOpts,
	)
	if err != nil {
		t.Fatalf("build hidden witness: %v", err)
	}
	packedSigHeads := reconstructPackedSigHeadsFromLimbHeads(packedWitness.SigLimbHeads, spec, fx.ringQ.Modulus[0])
	sigHatHeads, err := buildSigHatHeadsFromPackedSigHeads(fx.ringQ, packedSigHeads, fx.opts.NCols)
	if err != nil {
		t.Fatalf("build sig hats: %v", err)
	}
	tHatHeads, err := buildTHatHeadsFromSigHatHeads(
		fx.ringQ,
		fx.pub,
		hiddenOmegaWitness,
		sigHatHeads,
		rowLayoutReplayTHatCount(fx.layout),
		fx.layout.CoeffNativeSig.PackedSigBlocks,
	)
	if err != nil {
		t.Fatalf("build T-hat heads: %v", err)
	}
	hiddenLayout := buildSigShortnessHiddenLayout(fx.layout, spec, fx.opts.NCols)
	hiddenRowsNTT, err := flattenSigShortnessHiddenWitnessRows(hiddenLayout, packedWitness, spec)
	if err != nil {
		t.Fatalf("flatten hidden rows: %v", err)
	}
	_, faggCoeffs, err := buildSigShortnessHiddenTHatBridgeFormalCoeffs(fx.ringQ, hiddenLayout, fx.pub, hiddenOmegaWitness, hiddenRowsNTT, tHatHeads, spec)
	if err != nil {
		t.Fatalf("build hidden bridge coeffs: %v", err)
	}
	replay, err := buildSigShortnessHiddenReplay(fx.ringQ, &Proof{
		RowLayout:    hiddenLayout,
		PCSGeometry:  PCSGeometry{LogicalWitnessPolys: len(hiddenRowsNTT)},
		NColsUsed:    fx.opts.NCols,
		PCSNColsUsed: hiddenLVCSNCols,
		NLeavesUsed:  hiddenOpts.NLeaves,
		Tail:         make([]int, hiddenOpts.Ell),
		HashRelation: fx.pub.HashRelation,
	}, fx.pub, hiddenOmegaWitness, tHatHeads, spec)
	if err != nil {
		t.Fatalf("build hidden replay: %v", err)
	}
	if replay == nil || replay.Eval == nil {
		t.Fatal("missing hidden replay evaluator")
	}
	xIdx := hiddenLVCSNCols + hiddenOpts.Ell
	_, domainPoints, err := deriveExplicitDomainForRelation(
		fx.ringQ.Modulus[0],
		hiddenOpts.NLeaves,
		fx.opts.NCols,
		hiddenLVCSNCols,
		hiddenOpts.Ell,
		fx.pub.HashRelation,
	)
	if err != nil {
		t.Fatalf("derive hidden domain: %v", err)
	}
	x := domainPoints[xIdx]
	rowVals := make([]uint64, len(hiddenRowsNTT))
	for i, row := range hiddenRowsNTT {
		coeff, err := coeffFromNTTPoly(fx.ringQ, row)
		if err != nil {
			t.Fatalf("row %d coeffs: %v", i, err)
		}
		rowVals[i] = EvalPoly(coeff, x, fx.ringQ.Modulus[0]) % fx.ringQ.Modulus[0]
	}
	_, fagg, err := replay.Eval(uint64(xIdx), rowVals)
	if err != nil {
		t.Fatalf("replay eval: %v", err)
	}
	if len(fagg) != len(faggCoeffs) {
		t.Fatalf("hidden fagg len=%d want %d", len(fagg), len(faggCoeffs))
	}
	for i := range fagg {
		want := EvalPoly(faggCoeffs[i], x, fx.ringQ.Modulus[0]) % fx.ringQ.Modulus[0]
		if fagg[i] != want {
			t.Fatalf("hidden fagg[%d]=%d want %d at xIdx=%d", i, fagg[i], want, xIdx)
		}
	}
}
