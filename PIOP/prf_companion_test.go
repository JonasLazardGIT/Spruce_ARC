package PIOP

import (
	"bytes"
	"path/filepath"
	"reflect"
	"testing"

	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type prfCompanionFixture struct {
	base         transformBridgeFixture
	params       *prf.Params
	opts         SimOpts
	rows         []*ring.Poly
	rowsNTT      []*ring.Poly
	rowInputs    []lvcs.RowInput
	layout       RowLayout
	prfLayout    *PRFLayout
	companion    *PRFCompanionLayout
	witnessCount int
}

func buildPRFCompanionFixture(t *testing.T) prfCompanionFixture {
	t.Helper()
	base := buildTransformBridgeFixture(t)
	params, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	opts := base.opts
	opts.EnablePackedPRFWitnessRows = true
	opts.EnablePRFCompanion = true
	opts.PRFCompanionMode = PRFCompanionModeOutputAudit
	opts.PRFCheckpointSamples = 8
	rows, rowInputs, layout, prfLayout, companion, _, _, _, witnessCount, _, _, err := BuildCredentialRowsShowing(
		base.ringQ,
		base.pub,
		base.wit,
		params.LenKey,
		params.LenNonce,
		params.RF,
		params.RP,
		opts.PRFGroupRounds,
		opts,
	)
	if err != nil {
		t.Fatalf("build companion showing rows: %v", err)
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = base.ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		base.ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	return prfCompanionFixture{
		base:         base,
		params:       params,
		opts:         opts,
		rows:         rows,
		rowsNTT:      rowsNTT,
		rowInputs:    rowInputs,
		layout:       layout,
		prfLayout:    prfLayout,
		companion:    companion,
		witnessCount: witnessCount,
	}
}

func fixedSeed2Test() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func fixedSeed3Test() []byte {
	return bytes.Repeat([]byte{0x24}, 32)
}

func TestPRFCompanionLayoutEmission(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	if fx.companion == nil {
		t.Fatal("missing companion layout")
	}
	if err := ValidatePRFCompanionLayout(fx.companion, fx.witnessCount); err != nil {
		t.Fatalf("validate companion layout: %v", err)
	}
	if fx.prfLayout != nil {
		t.Fatal("expected companion route to retire the live legacy PRF layout")
	}
	if fx.companion.PackedRows <= 0 {
		t.Fatal("expected packed companion rows when companion is enabled")
	}
	if fx.companion.PackWidth != fx.opts.NCols {
		t.Fatalf("pack width=%d want %d", fx.companion.PackWidth, fx.opts.NCols)
	}
	if fx.companion.KeySource != KeySourceIndependentWitness {
		t.Fatalf("key source=%d want independent witness", fx.companion.KeySource)
	}
	if len(fx.companion.KeySlots) != fx.params.LenKey {
		t.Fatalf("key slots=%d want %d", len(fx.companion.KeySlots), fx.params.LenKey)
	}
	wantCheckpoints := groupedPRFSBoxCount(fx.params.LenKey, fx.params.LenNonce, fx.params.RF, fx.params.RP, fx.opts.PRFGroupRounds)
	if len(fx.companion.CheckpointSlots) != wantCheckpoints {
		t.Fatalf("checkpoint slots=%d want %d", len(fx.companion.CheckpointSlots), wantCheckpoints)
	}
	if len(fx.companion.FinalTagSlots) != fx.params.LenTag {
		t.Fatalf("final tag slots=%d want %d", len(fx.companion.FinalTagSlots), fx.params.LenTag)
	}
	wantLogical := len(fx.companion.KeySlots) + len(fx.companion.CheckpointSlots) + len(fx.companion.FinalTagSlots)
	if fx.companion.PackedLogicalCount != wantLogical {
		t.Fatalf("packed logical count=%d want %d", fx.companion.PackedLogicalCount, wantLogical)
	}
	if fx.companion.PackedRows != ceilDiv(wantLogical, fx.opts.NCols) {
		t.Fatalf("packed rows=%d want %d", fx.companion.PackedRows, ceilDiv(wantLogical, fx.opts.NCols))
	}
	if fx.companion.DataRows != ceilDiv(len(fx.companion.KeySlots)+len(fx.companion.CheckpointSlots), fx.opts.NCols) {
		t.Fatalf("data rows=%d want %d", fx.companion.DataRows, ceilDiv(len(fx.companion.KeySlots)+len(fx.companion.CheckpointSlots), fx.opts.NCols))
	}
	if fx.companion.HelperRows != fx.companion.PackedRows-fx.companion.DataRows {
		t.Fatalf("helper rows=%d want %d", fx.companion.HelperRows, fx.companion.PackedRows-fx.companion.DataRows)
	}
	for i, sem := range fx.companion.RowSemantics {
		if sem != CoeffPackedRow {
			t.Fatalf("row semantics[%d]=%d want coeff-packed", i, sem)
		}
	}
}

func TestPRFCompanionKeyAlignment(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	if fx.companion == nil {
		t.Fatal("missing companion layout")
	}
	if fx.layout.IdxCarrierM < 0 {
		t.Fatalf("missing carrier M row for key binding")
	}
	if len(fx.companion.KeySlots) == 0 {
		t.Fatalf("missing key slots in companion layout")
	}
	keyScalars, err := ExtractSignedPRFKeyScalarsFromCarrierOnOmega(
		fx.base.ringQ,
		fx.rows[fx.layout.IdxCarrierM],
		fx.base.omegaWitness,
		fx.companion.PackWidth,
		fx.params.LenKey,
		fx.base.pub.BoundB,
	)
	if err != nil {
		t.Fatalf("extract signed prf key from carrier: %v", err)
	}
	if len(keyScalars) != len(fx.companion.KeySlots) {
		t.Fatalf("key lengths differ: extracted=%d slots=%d", len(keyScalars), len(fx.companion.KeySlots))
	}
	q := fx.base.ringQ.Modulus[0]
	for i, slot := range fx.companion.KeySlots {
		head, err := rowHeadOnOmega(fx.base.ringQ, fx.base.omegaWitness, fx.rows[slot.Row], fx.companion.PackWidth)
		if err != nil {
			t.Fatalf("extract key head row %d: %v", slot.Row, err)
		}
		got := head[slot.Coeff] % q
		want := liftToField(q, keyScalars[i]) % q
		if got != want {
			t.Fatalf("key lane %d mismatch: got=%d want=%d", i, got, want)
		}
	}
}

func TestPRFCompanionBridgeDeterminism(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	seedA := fixedSeed2Test()
	bridgeA, err := buildPRFCompanionBridgeFamiliesFormal(fx.base.ringQ, fx.base.omegaWitness, fx.companion, fx.rowInputs, fx.rows[:fx.witnessCount], seedA, prfCompanionBridgeChecks, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples)
	if err != nil {
		t.Fatalf("build bridge A: %v", err)
	}
	bridgeB, err := buildPRFCompanionBridgeFamiliesFormal(fx.base.ringQ, fx.base.omegaWitness, fx.companion, fx.rowInputs, fx.rows[:fx.witnessCount], seedA, prfCompanionBridgeChecks, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples)
	if err != nil {
		t.Fatalf("build bridge B: %v", err)
	}
	if !bytes.Equal(bridgeA.CoordDigest, bridgeB.CoordDigest) {
		t.Fatal("same seed/layout produced different companion digest")
	}
	if !matrixEqual(bridgeA.BridgeChecks, bridgeB.BridgeChecks) {
		t.Fatal("same seed/layout produced different bridge checks")
	}
	seedB := bytes.Repeat([]byte{0x43}, 32)
	bridgeC, err := buildPRFCompanionBridgeFamiliesFormal(fx.base.ringQ, fx.base.omegaWitness, fx.companion, fx.rowInputs, fx.rows[:fx.witnessCount], seedB, prfCompanionBridgeChecks, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples)
	if err != nil {
		t.Fatalf("build bridge C: %v", err)
	}
	if bytes.Equal(bridgeA.CoordDigest, bridgeC.CoordDigest) {
		t.Fatal("different seed2 produced same companion digest")
	}
}

func TestPRFCompanionBridgeFamiliesOnOmega(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	bridge, err := buildPRFCompanionBridgeFamiliesFormal(fx.base.ringQ, fx.base.omegaWitness, fx.companion, fx.rowInputs, fx.rows[:fx.witnessCount], fixedSeed2Test(), prfCompanionBridgeChecks, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples)
	if err != nil {
		t.Fatalf("build bridge: %v", err)
	}
	if bridge == nil {
		t.Fatal("missing bridge build")
	}
	if len(bridge.Families) != prfCompanionBridgeChecks {
		t.Fatalf("bridge family count=%d want %d", len(bridge.Families), prfCompanionBridgeChecks)
	}
	for i := range bridge.Coeffs {
		valsCoeff := evalCoeffOnOmegaTest(bridge.Coeffs[i], fx.base.omegaWitness, fx.base.ringQ.Modulus[0])
		for j, v := range valsCoeff {
			if v != 0 {
				t.Fatalf("bridge coeff family[%d] nonzero on omega[%d]=%d", i, j, v)
			}
		}
		if bridge.Families[i] == nil {
			continue
		}
		valsPoly, err := evalPolyOnOmegaTest(fx.base.ringQ, fx.base.omegaWitness, bridge.Families[i])
		if err != nil {
			t.Fatalf("eval bridge family[%d]: %v", i, err)
		}
		if len(valsPoly) != len(valsCoeff) {
			t.Fatalf("bridge family[%d] omega len=%d want %d", i, len(valsPoly), len(valsCoeff))
		}
		for j := range valsPoly {
			if valsPoly[j] != valsCoeff[j] {
				t.Fatalf("bridge family[%d] poly/coeff mismatch at omega[%d]: poly=%d coeff=%d", i, j, valsPoly[j], valsCoeff[j])
			}
		}
	}
}

func TestPRFCompanionQContributionZero(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	bridge, err := buildPRFCompanionBridgeFamiliesFormal(fx.base.ringQ, fx.base.omegaWitness, fx.companion, fx.rowInputs, fx.rows[:fx.witnessCount], fixedSeed2Test(), prfCompanionBridgeChecks, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples)
	if err != nil {
		t.Fatalf("build bridge: %v", err)
	}
	faggNorm := bridge.Families
	faggNormCoeffs := bridge.Coeffs
	gammaPrime := make([][][]uint64, 1)
	gammaPrime[0] = nil
	gammaAgg := make([][]uint64, 1)
	gammaAgg[0] = make([]uint64, len(faggNorm))
	for i := range gammaAgg[0] {
		gammaAgg[0][i] = 1
	}
	qCoeffs, err := BuildQCoeffsChecked(
		fx.base.ringQ,
		BuildQLayout{MaskPolys: []*ring.Poly{fx.base.ringQ.NewPoly()}},
		nil,
		nil,
		nil,
		faggNorm,
		nil,
		nil,
		nil,
		faggNormCoeffs,
		gammaPrime,
		gammaAgg,
	)
	if err != nil {
		t.Fatalf("build Q coeffs: %v", err)
	}
	if len(qCoeffs) != 1 {
		t.Fatalf("Q row count=%d want 1", len(qCoeffs))
	}
	vals := evalCoeffOnOmegaTest(qCoeffs[0], fx.base.omegaWitness, fx.base.ringQ.Modulus[0])
	for i, v := range vals {
		if v != 0 {
			t.Fatalf("Q omega[%d]=%d want 0", i, v)
		}
	}
}

func TestPRFCompanionKEvaluatorMatchesCoeffs(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	bridge, err := buildPRFCompanionBridgeFamiliesFormal(fx.base.ringQ, fx.base.omegaWitness, fx.companion, fx.rowInputs, fx.rows[:fx.witnessCount], fixedSeed2Test(), prfCompanionBridgeChecks, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples)
	if err != nil {
		t.Fatalf("build bridge: %v", err)
	}
	sf, err := deriveSmallFieldParamsNoRows(fx.base.ringQ, fx.base.omegaWitness, fx.opts.Theta)
	if err != nil {
		t.Fatalf("derive small field: %v", err)
	}
	cfg := PRFCompanionBridgeConfig{
		Ring:         fx.base.ringQ,
		Layout:       fx.companion,
		OmegaWitness: fx.base.omegaWitness,
		Seed2:        fixedSeed2Test(),
		BridgeChecks: bridge.BridgeChecks,
	}
	ek, err := cfg.KEvaluator(sf.K)
	if err != nil {
		t.Fatalf("companion K evaluator: %v", err)
	}
	limbs := []uint64{2, 3, 5, 7, 11, 13}
	if len(limbs) > fx.opts.Theta {
		limbs = limbs[:fx.opts.Theta]
	}
	for len(limbs) < fx.opts.Theta {
		limbs = append(limbs, uint64(len(limbs)+17))
	}
	point := sf.K.Phi(limbs)
	rowsK := make([]kf.Elem, fx.companion.StartRow+fx.companion.PackedRows)
	for r := 0; r < fx.companion.PackedRows; r++ {
		rowIdx := fx.companion.StartRow + r
		rowsK[rowIdx] = sf.K.EvalFPolyAtK(fx.rows[rowIdx].Coeffs[0], point)
	}
	_, fagg, err := ek(point, rowsK)
	if err != nil {
		t.Fatalf("evaluate K bridge: %v", err)
	}
	if len(fagg) != len(bridge.Coeffs) {
		t.Fatalf("fagg len=%d want %d", len(fagg), len(bridge.Coeffs))
	}
	for i := range fagg {
		want := sf.K.EvalFPolyAtK(bridge.Coeffs[i], point)
		if !elemEqual(sf.K, fagg[i], want) {
			t.Fatalf("K evaluator mismatch at family %d", i)
		}
	}
}

func TestPRFCompanionKReplayRowsMatchWitnessPolys(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	sf, err := deriveSmallFieldParamsNoRows(fx.base.ringQ, fx.base.omegaWitness, fx.opts.Theta)
	if err != nil {
		t.Fatalf("derive small field: %v", err)
	}
	pcsRows, err := buildSmallFieldPCSRows(
		fx.base.ringQ,
		fx.base.omegaWitness,
		fx.base.opts.LVCSNCols,
		fx.base.opts.Ell,
		sf.K,
		sf.OmegaS1,
		fx.rows[:fx.witnessCount],
		SampleIndependentMaskPolynomialsK(fx.base.ringQ, sf.K, fx.base.opts.Rho, fx.base.opts.Ell, fx.base.omegaWitness),
		fx.base.opts.Ell,
	)
	if err != nil {
		t.Fatalf("build small-field pcs rows: %v", err)
	}
	rows := make([][]uint64, len(pcsRows.RowInputs))
	for i := range pcsRows.RowInputs {
		rows[i] = append([]uint64(nil), pcsRows.RowInputs[i].Head...)
	}
	limbs := []uint64{2, 3, 5, 7, 11, 13}
	if len(limbs) > fx.opts.Theta {
		limbs = limbs[:fx.opts.Theta]
	}
	for len(limbs) < fx.opts.Theta {
		limbs = append(limbs, uint64(len(limbs)+17))
	}
	point := sf.K.Phi(limbs)
	coeffBlock := buildKPointCoeffMatrix(
		fx.base.ringQ,
		sf.K,
		fx.base.omegaWitness,
		rows,
		point,
		sf.OmegaS1,
		sf.MuInv,
		pcsRows.MaskRowOffset,
		pcsRows.MaskRowCount,
	)
	vTargets := computeVTargets(fx.base.ringQ.Modulus[0], rows, coeffBlock)
	rowVals, err := buildRowValsFromVTargets(sf.K, vTargets, 0, 1, fx.witnessCount)
	if err != nil {
		t.Fatalf("build row vals from VTargets: %v", err)
	}
	for r := 0; r < fx.companion.PackedRows; r++ {
		rowIdx := fx.companion.StartRow + r
		want := sf.K.EvalFPolyAtK(fx.rows[rowIdx].Coeffs[0], point)
		if !elemEqual(sf.K, rowVals[rowIdx], want) {
			t.Fatalf("row replay mismatch at companion row %d", rowIdx)
		}
	}
}

func TestPRFCompanionLiveProofKEvaluatorMatchesCoeffs(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	proof, err := BuildShowingCombined(fx.base.pub, fx.base.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing proof: %v", err)
	}
	if proof.PRFCompanion == nil {
		t.Fatal("missing prf companion proof")
	}
	if len(proof.KPoint) == 0 {
		t.Fatal("missing K points")
	}
	field, err := kf.New(fx.base.ringQ.Modulus[0], proof.Theta, proof.Chi)
	if err != nil {
		t.Fatalf("build K field: %v", err)
	}
	bridge, err := buildPRFCompanionBridgeFamiliesFormal(
		fx.base.ringQ,
		fx.base.omegaWitness,
		fx.companion,
		fx.rowInputs,
		fx.rows[:fx.witnessCount],
		proof.Digests[1],
		len(proof.PRFCompanion.BridgeChecks),
		proof.PRFCompanion.Mode,
		proof.PRFCompanion.CheckpointSamples,
	)
	if err != nil {
		t.Fatalf("rebuild bridge families: %v", err)
	}
	if !matrixEqual(bridge.BridgeChecks, proof.PRFCompanion.BridgeChecks) {
		t.Fatal("live proof bridge checks differ from rebuilt bridge checks")
	}
	cfg := PRFCompanionBridgeConfig{
		Ring:         fx.base.ringQ,
		Layout:       fx.companion,
		OmegaWitness: fx.base.omegaWitness,
		Seed2:        append([]byte(nil), proof.Digests[1]...),
		BridgeChecks: copyMatrix(proof.PRFCompanion.BridgeChecks),
	}
	ek, err := cfg.KEvaluator(field)
	if err != nil {
		t.Fatalf("companion K evaluator: %v", err)
	}
	rowVals, err := buildRowValsFromVTargets(field, proof.VTargetsMatrix(), 0, len(proof.KPoint), proof.RowLayout.SigCount)
	if err != nil {
		t.Fatalf("row vals from vtargets: %v", err)
	}
	point := field.Phi(proof.KPoint[0])
	for r := 0; r < fx.companion.PackedRows; r++ {
		rowIdx := fx.companion.StartRow + r
		wantRow := field.EvalFPolyAtK(fx.rows[rowIdx].Coeffs[0], point)
		if !elemEqual(field, rowVals[rowIdx], wantRow) {
			t.Fatalf("live proof row replay mismatch at companion row %d", rowIdx)
		}
	}
	_, fagg, err := ek(point, rowVals)
	if err != nil {
		t.Fatalf("evaluate K bridge: %v", err)
	}
	if len(fagg) != len(bridge.Coeffs) {
		t.Fatalf("fagg len=%d want %d", len(fagg), len(bridge.Coeffs))
	}
	for i := range fagg {
		want := field.EvalFPolyAtK(bridge.Coeffs[i], point)
		if !elemEqual(field, fagg[i], want) {
			cache, cerr := buildPRFCompanionBridgeCache(fx.base.ringQ, fx.base.omegaWitness, fx.companion, proof.Digests[1], len(proof.PRFCompanion.BridgeChecks))
			if cerr != nil {
				t.Fatalf("build cache: %v", cerr)
			}
			q := fx.base.ringQ.Modulus[0]
			mix := field.Zero()
			mixHead := make([]uint64, fx.companion.PackWidth)
			for r := 0; r < fx.companion.PackedRows; r++ {
				rowIdx := fx.companion.StartRow + r
				field.AddMulBaseInto(&mix, rowVals[rowIdx], cache.alpha[i][r]%q)
				head := fx.rowInputs[rowIdx].Head[:fx.companion.PackWidth]
				for col := 0; col < fx.companion.PackWidth; col++ {
					mixHead[col] = modAdd(mixHead[col], modMul(cache.alpha[i][r]%q, head[col]%q, q), q)
				}
			}
			mixCoeff := trimPoly(Interpolate(fx.base.omegaWitness, mixHead, q), q)
			betaSel := field.EvalFPolyAtK(cache.betaSelCoeff[i], point)
			hCoeff := trimPoly(Interpolate(fx.base.omegaWitness, proof.PRFCompanion.BridgeChecks[i], q), q)
			hVal := field.EvalFPolyAtK(hCoeff, point)
			wantMix := field.EvalFPolyAtK(mixCoeff, point)
			t.Fatalf("live proof K evaluator mismatch at family %d: got=%v want=%v mix=%v wantMix=%v betaSel=%v hVal=%v", i, fagg[i].Limb, want.Limb, mix.Limb, wantMix.Limb, betaSel.Limb, hVal.Limb)
		}
	}
}

func TestPRFCompanionOpeningPlanDeterminism(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	bridge, err := buildPRFCompanionBridgeFamiliesFormal(
		fx.base.ringQ,
		fx.base.omegaWitness,
		fx.companion,
		fx.rowInputs,
		fx.rows[:fx.witnessCount],
		fixedSeed2Test(),
		prfCompanionBridgeChecks,
		fx.opts.PRFCompanionMode,
		fx.opts.PRFCheckpointSamples,
	)
	if err != nil {
		t.Fatalf("build bridge: %v", err)
	}
	planA, err := buildPRFCompanionOpeningPlan(fx.companion, fx.params, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples, fixedSeed3Test(), bridge.CoordDigest, fx.base.pub.Tag, fx.base.pub.Nonce)
	if err != nil {
		t.Fatalf("build opening plan A: %v", err)
	}
	planB, err := buildPRFCompanionOpeningPlan(fx.companion, fx.params, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples, fixedSeed3Test(), bridge.CoordDigest, fx.base.pub.Tag, fx.base.pub.Nonce)
	if err != nil {
		t.Fatalf("build opening plan B: %v", err)
	}
	if !reflect.DeepEqual(planA, planB) {
		t.Fatal("same seed3/layout produced different opening plan")
	}
	planC, err := buildPRFCompanionOpeningPlan(fx.companion, fx.params, fx.opts.PRFCompanionMode, fx.opts.PRFCheckpointSamples, bytes.Repeat([]byte{0x25}, 32), bridge.CoordDigest, fx.base.pub.Tag, fx.base.pub.Nonce)
	if err != nil {
		t.Fatalf("build opening plan C: %v", err)
	}
	if reflect.DeepEqual(planA.Descriptors, planC.Descriptors) && reflect.DeepEqual(planA.Masks, planC.Masks) {
		t.Fatal("different seed3 produced identical opening plan")
	}
}

func TestPRFCompanionOpeningPayloadRoundTrip(t *testing.T) {
	fx := buildPRFCompanionFixture(t)
	bridge, err := buildPRFCompanionBridgeFamiliesFormal(
		fx.base.ringQ,
		fx.base.omegaWitness,
		fx.companion,
		fx.rowInputs,
		fx.rows[:fx.witnessCount],
		fixedSeed2Test(),
		prfCompanionBridgeChecks,
		fx.opts.PRFCompanionMode,
		fx.opts.PRFCheckpointSamples,
	)
	if err != nil {
		t.Fatalf("build bridge: %v", err)
	}
	payload, _, err := buildPRFCompanionOpeningPayload(
		fx.companion,
		fx.opts.PRFCompanionMode,
		fx.opts.PRFCheckpointSamples,
		fx.rows[:fx.witnessCount],
		fx.base.ringQ,
		fx.base.omegaWitness,
		fx.params,
		fixedSeed3Test(),
		bridge.CoordDigest,
		fx.base.pub.Tag,
		fx.base.pub.Nonce,
	)
	if err != nil {
		t.Fatalf("build opening payload: %v", err)
	}
	proof := &Proof{
		Digests: [4][]byte{nil, nil, append([]byte(nil), fixedSeed3Test()...), nil},
		PRFCompanion: &PRFCompanionProof{
			Mode:              fx.opts.PRFCompanionMode,
			CheckpointSamples: fx.opts.PRFCheckpointSamples,
			BridgeInQ:         true,
			Layout:            clonePRFCompanionLayout(fx.companion),
			BridgeChecks:      copyMatrix(bridge.BridgeChecks),
			CoordDigest:       append([]byte(nil), bridge.CoordDigest...),
		},
	}
	proof.PRFCompanion.CheckpointAudits = clonePRFCheckpointAuditOpenings(payload.CheckpointAudits)
	proof.PRFCompanion.TagFinal = clonePRFCompanionOpening(payload.TagFinal)
	proof.PRFCompanion.KeyTrunc = clonePRFCompanionOpening(payload.KeyTrunc)
	if err := verifyPRFCompanionOpenings(fx.companion, proof, fx.params, fx.base.pub.Tag, fx.base.pub.Nonce); err != nil {
		t.Fatalf("verify opening payload: %v", err)
	}
	proof.PRFCompanion.CheckpointAudits[0].Z.Masked[0]++
	if err := verifyPRFCompanionOpenings(fx.companion, proof, fx.params, fx.base.pub.Tag, fx.base.pub.Nonce); err == nil {
		t.Fatal("tampered masked opening unexpectedly verified")
	}
	proof.PRFCompanion.CheckpointAudits = clonePRFCheckpointAuditOpenings(payload.CheckpointAudits)
	proof.PRFCompanion.CheckpointAudits[0].Z.Mask[0]++
	if err := verifyPRFCompanionOpenings(fx.companion, proof, fx.params, fx.base.pub.Tag, fx.base.pub.Nonce); err == nil {
		t.Fatal("tampered opening mask unexpectedly verified")
	}
}
