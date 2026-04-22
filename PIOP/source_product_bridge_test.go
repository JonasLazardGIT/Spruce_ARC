package PIOP

import (
	"testing"

	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
)

func bridgeTestRowInputs(inputs []decsRowInput) []lvcs.RowInput {
	out := make([]lvcs.RowInput, len(inputs))
	for i := range inputs {
		out[i] = lvcs.RowInput{
			Head:       append([]uint64(nil), inputs[i].Head...),
			Tail:       append([]uint64(nil), inputs[i].Tail...),
			Poly:       inputs[i].Poly,
			PolyCoeffs: append([]uint64(nil), inputs[i].PolyCoeffs...),
		}
	}
	return out
}

func TestSourceProductBridgeCurrentPhysicalRowsDoNotRoundTripThroughSameRootOpening(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	fx := buildTransformBridgeFullFixture(t)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}

	rowInputs := bridgeTestRowInputs(fx.rowInputs)
	_, pk, _, err := commitRows(fx.ringQ, rowInputs, fx.opts.Ell, fx.decsParams, fx.witnessCount, fx.maskRowOff, fx.maskRowCount, fx.domainPoints)
	if err != nil {
		t.Fatalf("commit rows for source-product bridge probe: %v", err)
	}

	pcsNCols := resolveProofPCSNCols(proof, len(fx.omegaWitness))
	if pcsNCols <= 0 {
		t.Fatalf("missing pcs ncols in proof")
	}
	physicalRows := []int{fx.layout.IdxMSigmaR1, fx.layout.IdxR0R1}
	slots, opening, err := buildSourceProductBridgeRowsOpening(pk, physicalRows, pcsNCols)
	if err != nil {
		t.Fatalf("build source-product bridge opening: %v", err)
	}
	if got, want := slots, []int{2, 3}; !equalIntSlices(got, want) {
		t.Fatalf("source-product bridge slots=%v want %v", got, want)
	}

	heads, err := extractSourceProductHeadsFromWitnessOpening(proof.PCSGeometry, len(fx.omegaWitness), physicalRows, opening, slots, fx.ringQ.Modulus[0])
	if err != nil {
		t.Fatalf("extract source-product bridge heads: %v", err)
	}

	wantMSigmaR1, err := rowHeadOnOmega(fx.ringQ, fx.omegaWitness, fx.rows[fx.layout.IdxMSigmaR1], len(fx.omegaWitness))
	if err != nil {
		t.Fatalf("msigmar1 head on omega: %v", err)
	}
	wantR0R1, err := rowHeadOnOmega(fx.ringQ, fx.omegaWitness, fx.rows[fx.layout.IdxR0R1], len(fx.omegaWitness))
	if err != nil {
		t.Fatalf("r0r1 head on omega: %v", err)
	}
	if equalU64SliceTrimmed(heads[0], wantMSigmaR1) && equalU64SliceTrimmed(heads[1], wantR0R1) {
		t.Fatalf("current source-product physical rows unexpectedly round-trip through the same-root opening; revisit bridge gating")
	}
}

func TestSourceProductBridgeCurrentPhysicalRowsDoNotMatchCommittedKValues(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	fx := buildTransformBridgeFullFixture(t)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	if proof.Theta <= 1 || len(proof.Chi) == 0 || len(proof.Zeta) == 0 {
		t.Fatalf("proof missing small-field parameters")
	}
	if len(proof.KPoint) == 0 {
		t.Fatalf("proof missing K points")
	}

	rowInputs := bridgeTestRowInputs(fx.rowInputs)
	_, pk, _, err := commitRows(fx.ringQ, rowInputs, fx.opts.Ell, fx.decsParams, fx.witnessCount, fx.maskRowOff, fx.maskRowCount, fx.domainPoints)
	if err != nil {
		t.Fatalf("commit rows for source-product bridge probe: %v", err)
	}

	pcsNCols := resolveProofPCSNCols(proof, len(fx.omegaWitness))
	physicalRows := []int{fx.layout.IdxMSigmaR1, fx.layout.IdxR0R1}
	slots, opening, err := buildSourceProductBridgeRowsOpening(pk, physicalRows, pcsNCols)
	if err != nil {
		t.Fatalf("build source-product bridge opening: %v", err)
	}
	heads, err := extractSourceProductHeadsFromWitnessOpening(proof.PCSGeometry, len(fx.omegaWitness), physicalRows, opening, slots, fx.ringQ.Modulus[0])
	if err != nil {
		t.Fatalf("extract source-product bridge heads: %v", err)
	}
	omegaS1Limbs, err := extractSourceProductOmegaS1LimbsFromWitnessOpening(proof.PCSGeometry, len(fx.omegaWitness), physicalRows, opening, slots, fx.ringQ.Modulus[0])
	if err != nil {
		t.Fatalf("extract source-product bridge omega_s+1 limbs: %v", err)
	}

	K, err := kf.New(fx.ringQ.Modulus[0], proof.Theta, proof.Chi)
	if err != nil {
		t.Fatalf("build K field: %v", err)
	}
	omegaS1 := kf.Elem{Limb: append([]uint64(nil), proof.Zeta...)}
	vTargets := proof.VTargetsMatrix()
	witnessCount := proof.RowLayout.SigCount
	if witnessCount <= 0 {
		witnessCount = proof.PCSGeometry.LogicalWitnessPolys
	}
	if witnessCount <= 0 {
		t.Fatalf("missing witness row count")
	}

	mismatchFound := false
	for kpIdx, limbs := range proof.KPoint {
		rowVals, err := buildRowValsFromVTargets(K, vTargets, kpIdx, len(proof.KPoint), witnessCount)
		if err != nil {
			t.Fatalf("build row vals from vtargets: %v", err)
		}
		e := K.Phi(limbs)

		gotMSigmaR1, err := evalSourceProductBridgeValueAtK(K, fx.omegaWitness, omegaS1, heads[0], omegaS1Limbs[0], e)
		if err != nil {
			t.Fatalf("eval source-product bridge msigmar1 at kp=%d: %v", kpIdx, err)
		}
		gotR0R1, err := evalSourceProductBridgeValueAtK(K, fx.omegaWitness, omegaS1, heads[1], omegaS1Limbs[1], e)
		if err != nil {
			t.Fatalf("eval source-product bridge r0r1 at kp=%d: %v", kpIdx, err)
		}

		wantMSigmaR1 := rowVals[fx.layout.IdxMSigmaR1]
		wantR0R1 := rowVals[fx.layout.IdxR0R1]
		if !elemEqual(K, gotMSigmaR1, wantMSigmaR1) || !elemEqual(K, gotR0R1, wantR0R1) {
			mismatchFound = true
			break
		}
	}
	if !mismatchFound {
		t.Fatalf("current source-product physical rows unexpectedly match committed K-values through the same-root opening; revisit bridge gating")
	}
}

func TestSourceProductBridgeRemainsDisabledOnLiveFullReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	fx := buildTransformBridgeFullFixture(t)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	if sourceProductBridgeEnabled(fx.pub, fx.opts, fx.layout) {
		t.Fatal("source-product bridge unexpectedly enabled on live full replay")
	}
	if proof.SourceProductBridge != nil {
		t.Fatal("live full replay unexpectedly emitted a source-product bridge")
	}
}
