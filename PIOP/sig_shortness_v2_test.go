package PIOP

import (
	"testing"

	decs "vSIS-Signature/DECS"
)

func cloneSigShortnessProofForTest(src *SigShortnessProof) *SigShortnessProof {
	if src == nil {
		return nil
	}
	return &SigShortnessProof{
		Version:      src.Version,
		SupportSlots: append([]int(nil), src.SupportSlots...),
		Opening:      cloneDECSOpening(src.Opening),
	}
}

func cloneProofWithSigShortnessForTest(src *Proof) *Proof {
	if src == nil {
		return nil
	}
	clone := *src
	clone.SigShortness = cloneSigShortnessProofForTest(src.SigShortness)
	return &clone
}

func sigShortnessSupportSlotPosForTest(t *testing.T, slots []int, want int) int {
	t.Helper()
	for i, slot := range slots {
		if slot == want {
			return i
		}
	}
	t.Fatalf("missing support slot %d in %v", want, slots)
	return -1
}

func tamperSigShortnessWitnessValueForTest(t *testing.T, proof *Proof, witnessPolyIdx, omegaRow int, q uint64) *Proof {
	t.Helper()
	tampered := cloneProofWithSigShortnessForTest(proof)
	if tampered == nil || tampered.SigShortness == nil {
		t.Fatalf("missing sig shortness proof to tamper")
	}
	pcsNCols := resolveProofPCSNCols(tampered, 0)
	if pcsNCols <= 0 {
		t.Fatalf("missing pcs ncols")
	}
	witnessNCols := tampered.NColsUsed
	if witnessNCols <= 0 {
		t.Fatalf("missing witness ncols")
	}
	theta := tampered.Theta
	if theta <= 1 {
		theta = tampered.PCSGeometry.Theta
	}
	rowsPerBlock := witnessNCols + theta
	block := witnessPolyIdx / pcsNCols
	slot := witnessPolyIdx % pcsNCols
	pos := sigShortnessSupportSlotPosForTest(t, tampered.SigShortness.SupportSlots, slot)
	rowIdx := block*rowsPerBlock + omegaRow
	opening := expandPackedOpening(tampered.SigShortness.Opening)
	if rowIdx < 0 || rowIdx >= len(opening.Pvals[pos]) {
		t.Fatalf("row idx=%d out of range for slot pos=%d", rowIdx, pos)
	}
	opening.Pvals[pos][rowIdx] = modAdd(opening.Pvals[pos][rowIdx], 1, q)
	tampered.SigShortness.Opening = opening
	return tampered
}

func TestSigShortnessSupportSlotMappingByVersion(t *testing.T) {
	layout := RowLayout{
		HasExplicitBaseIdx: true,
		IdxTHatBase:        9,
		ReplayTHatCount:    1,
		CoeffNativeSig: CoeffNativeSigLayout{
			Enabled:             true,
			Model:               CoeffNativeSigModelLiteralPackedAggregatedV3,
			PackedSigBase:       10,
			PackedSigCount:      6,
			PackedSigComponents: 2,
			PackedSigBlocks:     3,
		},
		PackedSigChainBase:         20,
		PackedSigChainGroupCount:   6,
		PackedSigChainRowsPerGroup: 4,
	}
	rowsV2 := buildSigShortnessWitnessPolyIndicesForVersion(layout, sigShortnessProofVersionV2)
	if len(rowsV2) != 30 {
		t.Fatalf("V2 shortness witness row count=%d want 30", len(rowsV2))
	}
	rowsV3 := buildSigShortnessWitnessPolyIndicesForVersion(layout, sigShortnessProofVersionV3)
	if len(rowsV3) != 31 {
		t.Fatalf("V3 shortness witness row count=%d want 31", len(rowsV3))
	}
	if rowsV3[0] != layout.IdxTHatBase {
		t.Fatalf("V3 shortness rows should include T-hat row first, got %v", rowsV3[:3])
	}
	rowsV4 := buildSigShortnessWitnessPolyIndicesForVersion(layout, sigShortnessProofVersionV4)
	if len(rowsV4) != 25 {
		t.Fatalf("V4 shortness witness row count=%d want 25", len(rowsV4))
	}
	if rowsV4[0] != layout.IdxTHatBase {
		t.Fatalf("V4 shortness rows should include T-hat row first, got %v", rowsV4[:3])
	}
	for _, row := range rowsV4 {
		if row >= layout.CoeffNativeSig.PackedSigBase && row < layout.CoeffNativeSig.PackedSigBase+layout.CoeffNativeSig.PackedSigCount {
			t.Fatalf("V4 shortness rows should exclude packed source rows, got %v", rowsV4)
		}
	}
	slotsV2, err := buildSigShortnessSupportSlotsForVersion(layout, 8, sigShortnessProofVersionV2)
	if err != nil {
		t.Fatalf("build V2 support slots: %v", err)
	}
	slotsV3, err := buildSigShortnessSupportSlotsForVersion(layout, 8, sigShortnessProofVersionV3)
	if err != nil {
		t.Fatalf("build V3 support slots: %v", err)
	}
	slotsV4, err := buildSigShortnessSupportSlotsForVersion(layout, 8, sigShortnessProofVersionV4)
	if err != nil {
		t.Fatalf("build V4 support slots: %v", err)
	}
	want := []int{0, 1, 2, 3, 4, 5, 6, 7}
	if !equalIntSlices(slotsV2, want) {
		t.Fatalf("V2 support slots=%v want %v", slotsV2, want)
	}
	if !equalIntSlices(slotsV3, want) {
		t.Fatalf("V3 support slots=%v want %v", slotsV3, want)
	}
	if !equalIntSlices(slotsV4, want) {
		t.Fatalf("V4 support slots=%v want %v", slotsV4, want)
	}
}

func TestSigShortnessSupportValuesV2AcceptAndReject(t *testing.T) {
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, SigShortnessProfileR11L4Production)
	ringQ := fx.ringQ
	opts := SimOpts{
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: SigShortnessProfileR11L4Production,
	}
	spec, err := signatureChainSpecForOpts(ringQ.Modulus[0], opts)
	if err != nil {
		t.Fatalf("signature spec: %v", err)
	}
	layout := RowLayout{
		CoeffNativeSig: CoeffNativeSigLayout{
			Enabled:             true,
			Model:               CoeffNativeSigModelLiteralPackedAggregatedV3,
			PackedSigBase:       0,
			PackedSigCount:      1,
			PackedSigComponents: 1,
			PackedSigBlocks:     1,
		},
		PackedSigChainBase:         1,
		PackedSigChainGroupCount:   1,
		PackedSigChainGroupSize:    2,
		PackedSigChainRowsPerGroup: spec.L,
	}
	proof := &Proof{
		RowLayout: layout,
		Theta:     2,
		NColsUsed: 2,
		PCSGeometry: PCSGeometry{
			Kind:              PCSGeometryKindSmallFieldMatrixV1,
			ReplayWitnessRows: 4,
		},
	}
	supportSlots := []int{0, 1, 2, 3, 4}
	opening := &decs.DECSOpening{
		Indices: supportSlots,
		Pvals: [][]uint64{
			{liftToField(ringQ.Modulus[0], 23), liftToField(ringQ.Modulus[0], 10), 0, 0},
			{liftToField(ringQ.Modulus[0], 1), liftToField(ringQ.Modulus[0], -1), 0, 0},
			{liftToField(ringQ.Modulus[0], 2), liftToField(ringQ.Modulus[0], 1), 0, 0},
			{0, 0, 0, 0},
			{0, 0, 0, 0},
		},
		R: 4,
	}
	view, err := newSigShortnessSupportView(proof, opening, supportSlots, 2, 8, 2, ringQ.Modulus[0])
	if err != nil {
		t.Fatalf("new support view: %v", err)
	}
	if _, err := verifySigShortnessSupportValues(proof, view, spec); err != nil {
		t.Fatalf("verify valid support values: %v", err)
	}

	mutatedDigit := cloneDECSOpening(opening)
	mutatedDigit.Pvals[1][0] = liftToField(ringQ.Modulus[0], 6)
	viewDigit, err := newSigShortnessSupportView(proof, mutatedDigit, supportSlots, 2, 8, 2, ringQ.Modulus[0])
	if err != nil {
		t.Fatalf("new mutated-digit support view: %v", err)
	}
	if _, err := verifySigShortnessSupportValues(proof, viewDigit, spec); err == nil {
		t.Fatalf("expected mutated digit value to be rejected")
	}

	mutatedSource := cloneDECSOpening(opening)
	mutatedSource.Pvals[0][0] = liftToField(ringQ.Modulus[0], 24)
	viewSource, err := newSigShortnessSupportView(proof, mutatedSource, supportSlots, 2, 8, 2, ringQ.Modulus[0])
	if err != nil {
		t.Fatalf("new mutated-source support view: %v", err)
	}
	if _, err := verifySigShortnessSupportValues(proof, viewSource, spec); err == nil {
		t.Fatalf("expected mutated source value to be rejected")
	}
}

func TestSigShortnessV4SupportSlotsStaySaturatedOnShippedDefault(t *testing.T) {
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, SigShortnessProfileR11L4Production)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing proof: %v", err)
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		t.Fatalf("missing pcs ncols")
	}
	slots, err := buildSigShortnessSupportSlotsForVersion(proof.RowLayout, pcsNCols, sigShortnessProofVersionV4)
	if err != nil {
		t.Fatalf("build V4 support slots: %v", err)
	}
	if len(slots) != 96 {
		t.Fatalf("V4 support slots=%d want 96", len(slots))
	}
	if !equalIntSlices(slots, proof.SigShortness.SupportSlots) {
		t.Fatalf("proof support slots=%v want %v", proof.SigShortness.SupportSlots, slots)
	}
}

func TestSigShortnessProofV4OpeningAndValueTamperRejects(t *testing.T) {
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, SigShortnessProfileR11L4Production)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing proof: %v", err)
	}
	if proof.SigShortness == nil {
		t.Fatalf("missing sig shortness proof")
	}
	if proof.SigShortness.Version != sigShortnessProofVersionV4 {
		t.Fatalf("sig shortness version=%d want %d", proof.SigShortness.Version, sigShortnessProofVersionV4)
	}
	if proof.PCSGeometry.ShortnessTailRows != 0 {
		t.Fatalf("shortness tail rows=%d want 0", proof.PCSGeometry.ShortnessTailRows)
	}
	rep, err := BuildProofReport(proof, fx.opts, fx.ringQ)
	if err != nil {
		t.Fatalf("build proof report: %v", err)
	}
	if !rep.SigShortness.Enabled || rep.SigShortness.SupportSlotCount <= 0 {
		t.Fatalf("missing shortness report payload: %+v", rep.SigShortness)
	}
	if rep.SigShortness.ProofBytes >= 55000 {
		t.Fatalf("sig shortness proof bytes=%d want < 55000", rep.SigShortness.ProofBytes)
	}

	t.Run("wrong slot set", func(t *testing.T) {
		tampered := cloneProofWithSigShortnessForTest(proof)
		tampered.SigShortness.SupportSlots[0] = tampered.SigShortness.SupportSlots[len(tampered.SigShortness.SupportSlots)-1] + 1
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("expected wrong support slot set to be rejected")
		}
	})

	t.Run("duplicate slot", func(t *testing.T) {
		tampered := cloneProofWithSigShortnessForTest(proof)
		tampered.SigShortness.SupportSlots[1] = tampered.SigShortness.SupportSlots[0]
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("expected duplicate support slot to be rejected")
		}
	})

	t.Run("wrong opening", func(t *testing.T) {
		tampered := cloneProofWithSigShortnessForTest(proof)
		tampered.SigShortness.Opening = expandPackedOpening(tampered.SigShortness.Opening)
		tampered.SigShortness.Opening.Indices[0] = tampered.SigShortness.Opening.Indices[1]
		tampered.SigShortness.Opening.MaskBase = 0
		tampered.SigShortness.Opening.MaskCount = 0
		tampered.SigShortness.Opening.IndexBits = nil
		tampered.SigShortness.Opening.TailCount = len(tampered.SigShortness.Opening.Indices)
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("expected wrong shortness opening to be rejected")
		}
	})

	t.Run("tampered digit value", func(t *testing.T) {
		digitRow := rowLayoutCoeffNativePackedSigLimbIndex(proof.RowLayout, 0, 0, 0)
		if digitRow < 0 {
			t.Fatalf("missing packed digit row")
		}
		tampered := tamperSigShortnessWitnessValueForTest(t, proof, digitRow, 0, fx.ringQ.Modulus[0])
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("expected tampered digit value to be rejected")
		}
	})

	t.Run("tampered T-hat value", func(t *testing.T) {
		tHatRow := rowLayoutPostSignTHatIndex(proof.RowLayout, 0)
		if tHatRow < 0 {
			t.Fatalf("missing T-hat row")
		}
		tampered := tamperSigShortnessWitnessValueForTest(t, proof, tHatRow, 0, fx.ringQ.Modulus[0])
		if err := VerifySigShortnessProof(tampered, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err == nil {
			t.Fatalf("expected tampered T-hat value to be rejected")
		}
	})
}

func TestSigShortnessProofVersionCompatibilityVerifierAcceptsLegacyVersions(t *testing.T) {
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, SigShortnessProfileR11L4Production)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing proof: %v", err)
	}
	for _, version := range []int{sigShortnessProofVersionV2, sigShortnessProofVersionV3} {
		legacy := cloneProofWithSigShortnessForTest(proof)
		legacy.SigShortness.Version = version
		if err := VerifySigShortnessProof(legacy, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err != nil {
			t.Fatalf("verify V%d compatibility path: %v", version, err)
		}
	}
}

func TestSigShortnessProofOmitsMvalsAndVerifies(t *testing.T) {
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, SigShortnessProfileR11L4Production)
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing proof: %v", err)
	}
	if proof.SigShortness == nil || proof.SigShortness.Opening == nil {
		t.Fatalf("missing sig shortness opening")
	}
	open := proof.SigShortness.Opening
	if open.MFormatVersion != 1 {
		t.Fatalf("sig shortness opening MFormatVersion=%d want 1", open.MFormatVersion)
	}
	if open.MColsEncoded != 0 {
		t.Fatalf("sig shortness opening MColsEncoded=%d want 0", open.MColsEncoded)
	}
	if got, want := len(open.MOmitCols), open.Eta; got != want {
		t.Fatalf("sig shortness opening omitted M cols=%d want %d", got, want)
	}
	if len(open.Mvals) != 0 || len(open.MvalsBits) != 0 {
		t.Fatalf("sig shortness opening should omit serialized M values")
	}
	if err := VerifySigShortnessProof(proof, fx.ringQ, fx.omegaWitness, fx.pub, fx.opts); err != nil {
		t.Fatalf("verify sig shortness proof with omitted Mvals: %v", err)
	}
}
