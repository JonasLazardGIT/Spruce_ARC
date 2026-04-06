package PIOP

import (
	"fmt"

	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func reducePolyModXN1(coeffs []uint64, n int, q uint64) []uint64 {
	if n <= 0 || len(coeffs) <= n {
		return trimPoly(coeffs, q)
	}
	out := make([]uint64, n)
	copy(out, coeffs[:n])
	for i := n; i < len(coeffs); i++ {
		j := i % n
		if ((i / n) % 2) == 1 {
			out[j] = modSub(out[j], coeffs[i]%q, q)
		} else {
			out[j] = modAdd(out[j], coeffs[i]%q, q)
		}
	}
	return trimPoly(out, q)
}

func buildCredentialConstraintSetPostCoeffNativeTransformBridge(
	ringQ *ring.Ring,
	bound int64,
	pub PublicInputs,
	layout RowLayout,
	rowsNTT []*ring.Poly,
	omega []uint64,
	domainMode DomainMode,
	opts SimOpts,
	prfLayout *PRFLayout,
	prfCompanionLayout *PRFCompanionLayout,
) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	if domainMode != DomainModeExplicit {
		return ConstraintSet{}, fmt.Errorf("transform-bridge showing requires explicit domain mode")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return ConstraintSet{}, fmt.Errorf("direct T-hat bridge expects one public A row, got %d", len(pub.A))
	}
	if len(pub.B) < 4 {
		return ConstraintSet{}, fmt.Errorf("missing B for hash constraint")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	q := ringQ.Modulus[0]
	if bound <= 0 {
		return ConstraintSet{}, fmt.Errorf("transform-bridge requires positive bound")
	}
	sourceBlocks := layout.SigBlocks
	if sourceBlocks <= 0 {
		sourceBlocks = 1
	}
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	if replayTHatCount <= 0 {
		replayTHatCount = 1
	}
	cfg := layout.CoeffNativeSig
	componentCount := cfg.SigComponentCount
	if componentCount <= 0 {
		componentCount = len(pub.A[0])
	}
	if componentCount != len(pub.A[0]) {
		return ConstraintSet{}, fmt.Errorf("signature component mismatch: layout=%d want %d", componentCount, len(pub.A[0]))
	}

	carrierMIdx := rowLayoutPostSignCarrierM(layout)
	carrierCtrIdx := rowLayoutPostSignCarrierCtr(layout)
	if carrierMIdx < 0 || carrierCtrIdx < 0 {
		return ConstraintSet{}, fmt.Errorf("missing carrier rows (M=%d ctr=%d)", carrierMIdx, carrierCtrIdx)
	}
	if carrierMIdx >= len(rowsNTT) || carrierCtrIdx >= len(rowsNTT) {
		return ConstraintSet{}, fmt.Errorf("carrier row index out of range (rows=%d)", len(rowsNTT))
	}
	if layout.IdxMHatSigma < 0 || layout.IdxRHat0 < 0 || layout.IdxRHat1 < 0 || layout.IdxTHatBase < 0 {
		return ConstraintSet{}, fmt.Errorf("missing transform-domain replay rows")
	}

	specSig, err := signatureChainSpecForLayoutAndOpts(q, layout, opts)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("signature chain spec: %w", err)
	}

	thetaB := make([][]uint64, len(pub.B))
	for i := range pub.B {
		theta, terr := thetaPolyFromNTT(ringQ, pub.B[i], omega)
		if terr != nil {
			return ConstraintSet{}, fmt.Errorf("theta B[%d]: %w", i, terr)
		}
		coeff, cerr := coeffFromNTTPoly(ringQ, theta)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("theta B[%d] coeffs: %w", i, cerr)
		}
		thetaB[i] = trimPoly(coeff, q)
	}
	aHeads := make([][][]uint64, replayTHatCount)
	for b := 0; b < replayTHatCount; b++ {
		aHeads[b] = make([][]uint64, componentCount)
		for comp := 0; comp < componentCount; comp++ {
			head, herr := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omega, b, sourceBlocks)
			if herr != nil {
				return ConstraintSet{}, fmt.Errorf("theta A head block %d comp %d: %w", b, comp, herr)
			}
			aHeads[b][comp] = head
		}
	}

	msgDecode1, msgDecode2, err := buildPackedMessageCarrierDecodePolys(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("message carrier decode polys: %w", err)
	}
	ctrDecode1, ctrDecode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier decode polys: %w", err)
	}
	msgMembershipPoly, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("message carrier membership poly: %w", err)
	}
	ctrMembershipPoly, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier membership poly: %w", err)
	}
	getRowCoeff := func(idx int) ([]uint64, error) {
		if idx < 0 || idx >= len(rowsNTT) {
			return nil, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[idx])
		if err != nil {
			return nil, err
		}
		return trimPoly(coeff, q), nil
	}

	carrierMCoeff, err := getRowCoeff(carrierMIdx)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier M coeffs: %w", err)
	}
	carrierCtrCoeff, err := getRowCoeff(carrierCtrIdx)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier ctr coeffs: %w", err)
	}
	msgDecode1Poly := fpoly.New(q, msgDecode1)
	msgDecode2Poly := fpoly.New(q, msgDecode2)
	ctrDecode1Poly := fpoly.New(q, ctrDecode1)
	ctrDecode2Poly := fpoly.New(q, ctrDecode2)
	carrierMPoly := fpoly.New(q, carrierMCoeff)
	carrierCtrPoly := fpoly.New(q, carrierCtrCoeff)
	m1CompCoeffs := trimPoly(msgDecode1Poly.Compose(carrierMPoly).Coeffs, q)
	m2CompCoeffs := trimPoly(msgDecode2Poly.Compose(carrierMPoly).Coeffs, q)
	r0CompCoeffs := trimPoly(ctrDecode1Poly.Compose(carrierCtrPoly).Coeffs, q)
	r1CompCoeffs := trimPoly(ctrDecode2Poly.Compose(carrierCtrPoly).Coeffs, q)
	mSigmaCompCoeffs := polyAdd(m1CompCoeffs, m2CompCoeffs, q)
	msgMembership := fpoly.New(q, msgMembershipPoly)
	ctrMembership := fpoly.New(q, ctrMembershipPoly)
	memMCoeffs := trimPoly(msgMembership.Compose(carrierMPoly).Coeffs, q)
	memCtrCoeffs := trimPoly(ctrMembership.Compose(carrierCtrPoly).Coeffs, q)

	packSelCoeff, err := buildPackingSelectorCoeff(ringQ, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("packing selector coeffs: %w", err)
	}
	oneMinusSelCoeff := polySub([]uint64{1}, packSelCoeff, q)
	m1PackCoeff := polyMul(packSelCoeff, m1CompCoeffs, q)
	m2PackCoeff := polyMul(oneMinusSelCoeff, m2CompCoeffs, q)
	m1Pack := nttPolyFromFormalCoeffsIfFits(ringQ, m1PackCoeff)
	m2Pack := nttPolyFromFormalCoeffsIfFits(ringQ, m2PackCoeff)
	carrierMemM := nttPolyFromFormalCoeffsIfFits(ringQ, memMCoeffs)
	carrierMemCtr := nttPolyFromFormalCoeffsIfFits(ringQ, memCtrCoeffs)

	mSigmaHatCoeff, err := getRowCoeff(layout.IdxMHatSigma)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("m-hat-sigma coeffs: %w", err)
	}
	r0HatCoeff, err := getRowCoeff(layout.IdxRHat0)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("rhat0 coeffs: %w", err)
	}
	r1HatCoeff, err := getRowCoeff(layout.IdxRHat1)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("rhat1 coeffs: %w", err)
	}
	tHat0Coeff, err := getRowCoeff(layout.IdxTHatBase)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("t-hat coeffs: %w", err)
	}
	hashResCoeff := buildTransformHashResidualCombinedCoeffs(q, thetaB, mSigmaHatCoeff, r0HatCoeff, r1HatCoeff, tHat0Coeff)
	hashRes := nttPolyFromFormalCoeffsIfFits(ringQ, hashResCoeff)

	var keyBindRes []*ring.Poly
	var keyBindCoeffs [][]uint64
	if prfCompanionLayout != nil {
		_, selectorCoeff, err := buildOmegaDeltaSelectors(ringQ, omega)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("delta selectors: %w", err)
		}
		half := ncols / 2
		keyCount := prfCompanionLayout.KeyCount
		keySlots := append([]CoeffSlot(nil), prfCompanionLayout.KeySlots...)
		if keyCount > 0 {
			if half < keyCount {
				return ConstraintSet{}, fmt.Errorf("key binding requires ncols/2 >= lenkey; got ncols=%d lenkey=%d", ncols, keyCount)
			}
			for i := 0; i < keyCount; i++ {
				col := half + i
				if col < 0 || col >= len(selectorCoeff) {
					return ConstraintSet{}, fmt.Errorf("key binding selector col=%d out of range", col)
				}
				if i >= len(keySlots) {
					return ConstraintSet{}, fmt.Errorf("key slot %d out of range (%d)", i, len(keySlots))
				}
				slot := keySlots[i]
				if slot.Coeff != col {
					return ConstraintSet{}, fmt.Errorf("key slot col %d mismatch for key %d (want %d)", slot.Coeff, i, col)
				}
				keyCoeff, err := getRowCoeff(slot.Row)
				if err != nil {
					return ConstraintSet{}, fmt.Errorf("key row coeffs: %w", err)
				}
				selCoeff := selectorCoeff[col]
				keyExtract := polyMul(selCoeff, keyCoeff, q)
				m2Extract := polyMul(selCoeff, m2CompCoeffs, q)
				resCoeff := polySub(keyExtract, m2Extract, q)
				keyBindCoeffs = append(keyBindCoeffs, resCoeff)
				keyBindRes = append(keyBindRes, nttPolyFromFormalCoeffsIfFits(ringQ, resCoeff))
			}
		}
	}

	fparInt := []*ring.Poly{hashRes, m1Pack, m2Pack, carrierMemM, carrierMemCtr}
	fparInt = append(fparInt, keyBindRes...)
	fparIntCoeffs := [][]uint64{hashResCoeff, m1PackCoeff, m2PackCoeff, memMCoeffs, memCtrCoeffs}
	fparIntCoeffs = append(fparIntCoeffs, keyBindCoeffs...)
	if len(fparIntCoeffs) != len(fparInt) {
		return ConstraintSet{}, fmt.Errorf("transform-bridge formal coeff mismatch: coeffs=%d polys=%d", len(fparIntCoeffs), len(fparInt))
	}

	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omega, replayTHatCount*ncols, sourceBlocks)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("transform-bridge basis: %w", err)
	}
	faggNorm := make([]*ring.Poly, 0, replayTHatCount*ncols+3*ncols)
	faggNormCoeffs := make([][]uint64, 0, replayTHatCount*ncols+3*ncols)
	for b := 0; b < replayTHatCount; b++ {
		tCoeff, err := getRowCoeff(layout.IdxTHatBase + b)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("t-hat block %d coeffs: %w", b, err)
		}
		for j := 0; j < ncols; j++ {
			t := b*ncols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < componentCount; comp++ {
				aScale := aHeads[b][comp][j] % q
				if aScale == 0 {
					continue
				}
				for bSrc := 0; bSrc < sourceBlocks; bSrc++ {
					blockScale := bridgeBasis.BlockFactors[t][bSrc] % q
					for lane := 0; lane < specSig.L; lane++ {
						limbIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, bSrc, lane)
						if limbIdx < 0 {
							return ConstraintSet{}, fmt.Errorf("missing limb row for comp=%d block=%d lane=%d", comp, bSrc, lane)
						}
						limbCoeff, err := getRowCoeff(limbIdx)
						if err != nil {
							return ConstraintSet{}, fmt.Errorf("limb coeffs (comp=%d block=%d lane=%d): %w", comp, bSrc, lane, err)
						}
						scale := modMul(aScale, modMul(blockScale, specSig.RPows[lane]%q, q), q)
						term := polyMul(bridgeBasis.TransformH[t], limbCoeff, q)
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						leftCoeff = polyAdd(leftCoeff, term, q)
					}
				}
			}
			rightCoeff := polyMul(bridgeBasis.LagrangeBasis[j], tCoeff, q)
			bridgeCoeff := polySub(leftCoeff, rightCoeff, q)
			faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
			faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
		}
	}
	for _, pair := range []struct {
		srcCoeff []uint64
		hatIdx   int
	}{
		{srcCoeff: mSigmaCompCoeffs, hatIdx: layout.IdxMHatSigma},
		{srcCoeff: r0CompCoeffs, hatIdx: layout.IdxRHat0},
		{srcCoeff: r1CompCoeffs, hatIdx: layout.IdxRHat1},
	} {
		hatCoeff, err := getRowCoeff(pair.hatIdx)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("non-sign hat coeffs: %w", err)
		}
		for j := 0; j < ncols; j++ {
			bridgeCoeff := buildTransformBridgeResidualCoeff(q, bridgeBasis.TransformHEval[j], bridgeBasis.LagrangeBasis[j], pair.srcCoeff, hatCoeff)
			faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
			faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
		}
	}
	_ = prfLayout

	parallelDeg := 2
	if deg := maxDegreeFromCoeffs(msgDecode1); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(ctrDecode1); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(msgMembershipPoly); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(ctrMembershipPoly); deg > parallelDeg {
		parallelDeg = deg
	}
	aggDeg := 1
	if deg := maxDegreeFromCoeffs(msgDecode1); deg > aggDeg {
		aggDeg = deg
	}
	if deg := maxDegreeFromCoeffs(ctrDecode1); deg > aggDeg {
		aggDeg = deg
	}

	return ConstraintSet{
		FparInt:          fparInt,
		FparIntCoeffs:    fparIntCoeffs,
		FparNorm:         nil,
		FparNormCoeffs:   nil,
		FaggNorm:         faggNorm,
		FaggNormCoeffs:   faggNormCoeffs,
		ParallelAlgDeg:   parallelDeg,
		AggregatedAlgDeg: aggDeg,
	}, nil
}
