package PIOP

import (
	"strings"
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildSigShortnessV5FixtureProof(t *testing.T, profile string) (transformBridgeFixture, *Proof, ConstraintSet) {
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

func repackSigShortnessExactHeadsForTest(t *testing.T, proof *Proof, heads [][][]uint64) {
	t.Helper()
	packed, err := packSigShortnessV5ExactHeads(heads)
	if err != nil {
		t.Fatalf("pack exact heads: %v", err)
	}
	proof.SigShortness.V5.ExactHeads = packed
}

func mutateSigShortnessExactHeadsForTest(t *testing.T, proof *Proof, mutate func([][][]uint64)) *Proof {
	t.Helper()
	tampered := cloneProofWithSigShortnessForTest(proof)
	if tampered == nil || tampered.SigShortness == nil || tampered.SigShortness.V5 == nil {
		t.Fatalf("missing sig shortness V5 proof to tamper")
	}
	heads, err := unpackSigShortnessV5ExactHeads(tampered.RowLayout, tampered.SigShortness.V5.ExactHeads)
	if err != nil {
		t.Fatalf("unpack exact heads: %v", err)
	}
	mutate(heads)
	repackSigShortnessExactHeadsForTest(t, tampered, heads)
	return tampered
}

func firstValidExactHeadMutationForTest(t *testing.T, q uint64, spec LinfSpec, value uint64) uint64 {
	t.Helper()
	for delta := int64(1); delta < 32; delta++ {
		candidate := modAdd(value, uint64(delta), q)
		if _, err := decomposeLinfDigitsSigned(centeredLift(candidate, q), spec); err == nil {
			return candidate
		}
	}
	t.Fatalf("could not find valid exact-head mutation from %d", value)
	return 0
}

func TestSigShortnessProofV5RoundTripAndDigestBinding(t *testing.T) {
	fx, proof, set := buildSigShortnessV5FixtureProof(t, SigShortnessProfileR11L4Production)
	if proof.SigShortness == nil || proof.SigShortness.Version != sigShortnessProofVersionV5 {
		t.Fatalf("sig shortness version=%v want V5", proof.SigShortness)
	}
	if proof.SigShortness.V5 == nil || proof.SigShortness.V5.THatOpening == nil {
		t.Fatalf("missing sig shortness V5 payload: %+v", proof.SigShortness)
	}
	if proof.RowLayout.PackedSigChainBase >= 0 || proof.RowLayout.PackedSigChainRowsPerGroup != 0 {
		t.Fatalf("raw shortness rows still present in layout: %+v", proof.RowLayout)
	}
	ok, err := VerifyWithConstraints(proof, set, fx.pub, fx.opts, FSModeCredential)
	if err != nil {
		t.Fatalf("verify with constraints: %v", err)
	}
	if !ok {
		t.Fatalf("verify with constraints returned false")
	}
	if err := VerifySigShortnessProof(proof, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err != nil {
		t.Fatalf("verify sig shortness V5: %v", err)
	}

	tampered := cloneProofWithSigShortnessForTest(proof)
	tampered.SigShortness.V5.ExactHeads.Bits[0] ^= 1
	ok, err = VerifyWithConstraints(tampered, set, fx.pub, fx.opts, FSModeCredential)
	if err == nil || !strings.Contains(err.Error(), "FS round 0") {
		t.Fatalf("tampered V5 digest error=%v want FS round 0 rejection", err)
	}
	if ok {
		t.Fatalf("tampered V5 digest unexpectedly verified")
	}
}

func TestSigShortnessProofV5RejectsBoundAndTHatTamper(t *testing.T) {
	fx, proof, _ := buildSigShortnessV5FixtureProof(t, SigShortnessProfileR11L4Production)
	spec, err := signatureChainSpecForLayoutAndOpts(fx.ringQ.Modulus[0], proof.RowLayout, fx.opts)
	if err != nil {
		t.Fatalf("signature chain spec: %v", err)
	}

	t.Run("bound", func(t *testing.T) {
		tampered := mutateSigShortnessExactHeadsForTest(t, proof, func(heads [][][]uint64) {
			heads[0][0][0] = liftToField(fx.ringQ.Modulus[0], int64(spec.MaxAbs)+1)
		})
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("tampered exact head unexpectedly satisfied V5 bound")
		}
	})

	t.Run("t_hat_opening", func(t *testing.T) {
		tampered := cloneProofWithSigShortnessForTest(proof)
		opening := expandPackedOpening(tampered.SigShortness.V5.THatOpening)
		opening.Pvals[0][0] = modAdd(opening.Pvals[0][0], 1, fx.ringQ.Modulus[0])
		tampered.SigShortness.V5.THatOpening = opening
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("tampered V5 T-hat opening unexpectedly verified")
		}
	})
}

func TestSigShortnessProofV5RejectsCrossBindingMismatch(t *testing.T) {
	fx, proof, _ := buildSigShortnessV5FixtureProof(t, SigShortnessProfileR11L4Production)
	spec, err := signatureChainSpecForLayoutAndOpts(fx.ringQ.Modulus[0], proof.RowLayout, fx.opts)
	if err != nil {
		t.Fatalf("signature chain spec: %v", err)
	}
	tampered := mutateSigShortnessExactHeadsForTest(t, proof, func(heads [][][]uint64) {
		heads[0][0][0] = firstValidExactHeadMutationForTest(t, fx.ringQ.Modulus[0], spec, heads[0][0][0])
	})
	if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
		t.Fatalf("tampered exact heads unexpectedly verified")
	}
}

func TestSigShortnessProofV5DigestMatchesVerifierRound0Material(t *testing.T) {
	_, proof, _ := buildSigShortnessV5FixtureProof(t, SigShortnessProfileR11L4Production)
	digest, err := buildSigShortnessV5BindingDigest(proof.SigShortness, proof.RowLayout, proof.NColsUsed)
	if err != nil {
		t.Fatalf("build V5 digest: %v", err)
	}
	if len(digest) == 0 {
		t.Fatal("missing V5 binding digest")
	}
	material0 := [][]byte{append([]byte(nil), proof.Root[:]...), proof.LabelsDigest, digest}
	fs := NewFS(NewShake256XOF(fsDigestBytes), proof.Salt, FSParams{Lambda: proof.Lambda, Kappa: proof.Kappa})
	if _, err := verifyRoundDigest(fs, 0, proof.Ctr[0], material0, proof.Digests[0], proof.Kappa[0]); err != nil {
		t.Fatalf("verify round-0 digest with V5 material: %v", err)
	}
}

func TestSigShortnessProofV5PackedMatrixRoundTrip(t *testing.T) {
	mat := [][][]uint64{
		{{1, 2, 3}, {4, 5, 6}},
		{{7, 8, 9}, {10, 11, 12}},
	}
	packed, err := packSigShortnessV5ExactHeads(mat)
	if err != nil {
		t.Fatalf("pack exact heads: %v", err)
	}
	layout := RowLayout{
		CoeffNativeSig: CoeffNativeSigLayout{
			Enabled:             true,
			Model:               CoeffNativeSigModelLiteralPackedAggregatedV3,
			PackedSigComponents: 2,
			PackedSigBlocks:     2,
			PackedSigBlockWidth: 3,
		},
	}
	got, err := unpackSigShortnessV5ExactHeads(layout, packed)
	if err != nil {
		t.Fatalf("unpack exact heads: %v", err)
	}
	bits, rows, cols, width := decs.PackUintMatrix([][]uint64{{1}})
	if rows != 1 || cols != 1 || width == 0 || len(bits) == 0 {
		t.Fatalf("pack uint matrix sanity failed")
	}
	if len(got) != len(mat) || len(got[0]) != len(mat[0]) || got[1][1][2] != mat[1][1][2] {
		t.Fatalf("round-trip exact heads mismatch: got=%v want=%v", got, mat)
	}
}
