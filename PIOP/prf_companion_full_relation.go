package PIOP

import (
	"fmt"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildPRFCompanionDirectFullFormalCoeffs(
	ringQ *ring.Ring,
	prfParams *prf.Params,
	rowsNTT []*ring.Poly,
	rowCache *intGenISISRowCoeffCache,
	layout *PRFCompanionLayout,
	tagPublic [][]int64,
	noncePublic [][]int64,
	omega []uint64,
	groupRounds int,
) ([]*ring.Poly, [][]uint64, int, error) {
	if layout == nil || layout.RelationVersion != 1 {
		return nil, nil, 0, nil
	}
	if ringQ == nil {
		return nil, nil, 0, fmt.Errorf("nil ring")
	}
	if prfParams == nil {
		return nil, nil, 0, fmt.Errorf("nil prf params")
	}
	if err := prfParams.Validate(); err != nil {
		return nil, nil, 0, fmt.Errorf("prf params invalid: %w", err)
	}
	if rowCache == nil {
		return nil, nil, 0, fmt.Errorf("nil row cache")
	}
	if len(omega) == 0 {
		return nil, nil, 0, fmt.Errorf("missing omega")
	}
	if len(omega) != layout.PackWidth {
		return nil, nil, 0, fmt.Errorf("omega width=%d want companion pack width=%d", len(omega), layout.PackWidth)
	}
	if len(layout.KeySlots) != prfParams.LenKey {
		return nil, nil, 0, fmt.Errorf("direct_full key slots=%d want %d", len(layout.KeySlots), prfParams.LenKey)
	}
	if len(layout.FinalRoundOutputSlots) != prfParams.T() {
		return nil, nil, 0, fmt.Errorf("direct_full final-round output slots=%d want %d", len(layout.FinalRoundOutputSlots), prfParams.T())
	}
	if len(layout.FinalTagSlots) != prfParams.LenTag {
		return nil, nil, 0, fmt.Errorf("direct_full final tag slots=%d want %d", len(layout.FinalTagSlots), prfParams.LenTag)
	}
	if groupRounds <= 0 {
		groupRounds = prfCompanionOpeningGroupRounds
	}
	checkpointCount, err := prf.SBoxOutputCountGrouped(prfParams, groupRounds)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("grouped checkpoint count: %w", err)
	}
	if len(layout.CheckpointSlots) != checkpointCount {
		return nil, nil, 0, fmt.Errorf("direct_full checkpoint slots=%d want %d", len(layout.CheckpointSlots), checkpointCount)
	}
	lastRound := prfParams.RF + prfParams.RP - 1
	if prf.ShouldCheckpointRound(prfParams, lastRound, groupRounds) {
		return nil, nil, 0, fmt.Errorf("direct_full expects an uncheckpointed terminal full round")
	}
	if len(tagPublic) != prfParams.LenTag {
		return nil, nil, 0, fmt.Errorf("tag lanes=%d want %d", len(tagPublic), prfParams.LenTag)
	}
	if len(noncePublic) != prfParams.LenNonce {
		return nil, nil, 0, fmt.Errorf("nonce lanes=%d want %d", len(noncePublic), prfParams.LenNonce)
	}

	q := ringQ.Modulus[0]
	_, selectorCoeff, err := buildOmegaDeltaSelectors(ringQ, omega)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("direct_full selectors: %w", err)
	}
	tagTheta, tagCoeff, err := buildPRFThetaPolys(ringQ, tagPublic, omega)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("tag theta: %w", err)
	}
	_ = tagTheta
	nonceElems, err := publicNonceElems(noncePublic, q)
	if err != nil {
		return nil, nil, 0, err
	}
	zeroKey := make([]prf.Elem, prfParams.LenKey)
	grouped, err := prf.TraceGroupedWitness(zeroKey, nonceElems, prfParams, groupRounds)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("trace direct_full symbolic PRF: %w", err)
	}
	if len(grouped.Checkpoints) != checkpointCount {
		return nil, nil, 0, fmt.Errorf("symbolic checkpoint count=%d want %d", len(grouped.Checkpoints), checkpointCount)
	}
	if len(grouped.FinalRoundInputs) != prfParams.T() {
		return nil, nil, 0, fmt.Errorf("symbolic final round inputs=%d want %d", len(grouped.FinalRoundInputs), prfParams.T())
	}

	slotRowCoeff := func(kind string, slot CoeffSlot) ([]uint64, error) {
		if slot.Row < 0 || slot.Row >= len(rowsNTT) {
			return nil, fmt.Errorf("%s row %d out of range (rows=%d)", kind, slot.Row, len(rowsNTT))
		}
		if slot.Coeff < 0 || slot.Coeff >= len(selectorCoeff) {
			return nil, fmt.Errorf("%s coeff %d out of range", kind, slot.Coeff)
		}
		rowCoeff, err := rowCache.Row(slot.Row)
		if err != nil {
			return nil, fmt.Errorf("%s row coeff: %w", kind, err)
		}
		return rowCoeff, nil
	}
	slotScalar := func(kind string, slot CoeffSlot) (uint64, error) {
		rowCoeff, err := slotRowCoeff(kind, slot)
		if err != nil {
			return 0, err
		}
		return EvalPoly(rowCoeff, omega[slot.Coeff]%q, q) % q, nil
	}
	selectedSlotCoeff := func(kind string, slot CoeffSlot) ([]uint64, error) {
		rowCoeff, err := slotRowCoeff(kind, slot)
		if err != nil {
			return nil, err
		}
		return trimPoly(polyMul(rowCoeff, selectorCoeff[slot.Coeff], q), q), nil
	}
	placeScalarAt := func(slot CoeffSlot, scalar uint64) []uint64 {
		return trimPoly(scalePoly(selectorCoeff[slot.Coeff], scalar%q, q), q)
	}
	linearFormScalar := func(form prf.LinearForm) (uint64, error) {
		acc := uint64(form.Const) % q
		for i, coeff := range form.KeyCoeffs {
			if coeff == 0 {
				continue
			}
			if i >= len(layout.KeySlots) {
				return 0, fmt.Errorf("linear form key coeff %d exceeds key slots", i)
			}
			v, err := slotScalar("key", layout.KeySlots[i])
			if err != nil {
				return 0, err
			}
			acc = modAdd(acc, modMul(uint64(coeff)%q, v, q), q)
		}
		for i, coeff := range form.CheckpointCoeffs {
			if coeff == 0 {
				continue
			}
			if i >= len(layout.CheckpointSlots) {
				return 0, fmt.Errorf("linear form checkpoint coeff %d exceeds checkpoint slots", i)
			}
			v, err := slotScalar("checkpoint", layout.CheckpointSlots[i])
			if err != nil {
				return 0, err
			}
			acc = modAdd(acc, modMul(uint64(coeff)%q, v, q), q)
		}
		return acc, nil
	}
	appendSlotResidual := func(polys *[]*ring.Poly, coeffs *[][]uint64, slot CoeffSlot, coeff []uint64) {
		trimmed := trimPoly(coeff, q)
		*coeffs = append(*coeffs, trimmed)
		*polys = append(*polys, nttPolyFromFormalCoeffsIfFits(ringQ, trimmed))
	}

	residuals := make([]*ring.Poly, 0, checkpointCount+prfParams.T()+2*prfParams.LenTag)
	residualCoeffs := make([][]uint64, 0, checkpointCount+prfParams.T()+2*prfParams.LenTag)
	for i, cp := range grouped.Checkpoints {
		zSlot := layout.CheckpointSlots[i]
		zCoeff, err := selectedSlotCoeff("checkpoint", zSlot)
		if err != nil {
			return nil, nil, 0, err
		}
		wire, err := linearFormScalar(cp.Wire)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("checkpoint wire %d: %w", i, err)
		}
		rhs := placeScalarAt(zSlot, powMod(wire, prfParams.D, q))
		appendSlotResidual(&residuals, &residualCoeffs, zSlot, polySub(zCoeff, rhs, q))
	}
	for i, form := range grouped.FinalRoundInputs {
		zSlot := layout.FinalRoundOutputSlots[i]
		zCoeff, err := selectedSlotCoeff("final_round_output", zSlot)
		if err != nil {
			return nil, nil, 0, err
		}
		wire, err := linearFormScalar(form)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("final round wire %d: %w", i, err)
		}
		rhs := placeScalarAt(zSlot, powMod(wire, prfParams.D, q))
		appendSlotResidual(&residuals, &residualCoeffs, zSlot, polySub(zCoeff, rhs, q))
	}
	for j := 0; j < prfParams.LenTag; j++ {
		ySlot := layout.FinalTagSlots[j]
		yCoeff, err := selectedSlotCoeff("final_tag", ySlot)
		if err != nil {
			return nil, nil, 0, err
		}
		linearFinal := uint64(0)
		for i, weight := range prfParams.ME[j] {
			if i >= len(layout.FinalRoundOutputSlots) {
				return nil, nil, 0, fmt.Errorf("final output slot %d missing", i)
			}
			z, err := slotScalar("final_round_output", layout.FinalRoundOutputSlots[i])
			if err != nil {
				return nil, nil, 0, err
			}
			linearFinal = modAdd(linearFinal, modMul(weight%q, z, q), q)
		}
		appendSlotResidual(&residuals, &residualCoeffs, ySlot, polySub(yCoeff, placeScalarAt(ySlot, linearFinal), q))

		var x0 uint64
		if j < prfParams.LenKey {
			x0, err = slotScalar("key", layout.KeySlots[j])
			if err != nil {
				return nil, nil, 0, err
			}
		} else {
			x0 = uint64(nonceElems[j-prfParams.LenKey]) % q
		}
		tagAtSlot := EvalPoly(tagCoeff[j], omega[ySlot.Coeff]%q, q) % q
		lhs := selectedSlotCoeffNoErr(yCoeff, placeScalarAt(ySlot, x0), q)
		appendSlotResidual(&residuals, &residualCoeffs, ySlot, polySub(lhs, placeScalarAt(ySlot, tagAtSlot), q))
	}
	if len(residuals) != len(residualCoeffs) {
		return nil, nil, 0, fmt.Errorf("direct_full residual count mismatch: polys=%d coeffs=%d", len(residuals), len(residualCoeffs))
	}
	if prfParams.D > uint64(^uint(0)>>1) {
		return nil, nil, 0, fmt.Errorf("prf degree overflows int: %d", prfParams.D)
	}
	return residuals, residualCoeffs, int(prfParams.D), nil
}

func selectedSlotCoeffNoErr(a, b []uint64, q uint64) []uint64 {
	return polyAdd(a, b, q)
}
