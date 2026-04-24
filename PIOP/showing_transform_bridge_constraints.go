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
	directTargetReplay := sigShortnessV11EnabledForOpts(opts) || rowLayoutPostSignTargetMR0HatIndex(layout, 0) >= 0
	if replayTHatCount <= 0 && !directTargetReplay {
		replayTHatCount = 1
	}
	replayBlockCount := rowLayoutReplayBlockCount(layout)
	if replayBlockCount <= 0 {
		replayBlockCount = replayTHatCount
	}
	useBBTran := publicUsesBBTran(pub)
	if !directTargetReplay && replayTHatCount != replayBlockCount {
		return ConstraintSet{}, fmt.Errorf("replay family mismatch: T-hat count=%d replay blocks=%d", replayTHatCount, replayBlockCount)
	}
	if replayBlockCount > sourceBlocks {
		return ConstraintSet{}, fmt.Errorf("replay blocks=%d exceed source blocks=%d", replayBlockCount, sourceBlocks)
	}

	x0Len := pub.X0Len
	if x0Len <= 0 {
		x0Len = rowLayoutX0Len(layout)
	}
	carrierMIdx := rowLayoutPostSignCarrierM(layout)
	carrierR0Idxs := rowLayoutPostSignCarrierR0Rows(layout)
	carrierR1Idx := rowLayoutPostSignCarrierR1(layout)
	if carrierMIdx < 0 || carrierR1Idx < 0 || len(carrierR0Idxs) != x0Len {
		return ConstraintSet{}, fmt.Errorf("missing carrier rows (M=%d R0=%d R1=%d want x0Len=%d)", carrierMIdx, len(carrierR0Idxs), carrierR1Idx, x0Len)
	}
	if carrierMIdx >= len(rowsNTT) || carrierR1Idx >= len(rowsNTT) {
		return ConstraintSet{}, fmt.Errorf("showing source row index out of range (rows=%d)", len(rowsNTT))
	}
	for _, idx := range carrierR0Idxs {
		if idx >= len(rowsNTT) {
			return ConstraintSet{}, fmt.Errorf("showing R0 carrier row index %d out of range (rows=%d)", idx, len(rowsNTT))
		}
	}
	if directTargetReplay {
		if rowLayoutPostSignTargetMR0HatIndex(layout, 0) < 0 || rowLayoutPostSignRHat1Index(layout, 0) < 0 {
			return ConstraintSet{}, fmt.Errorf("missing direct-target transform-domain replay rows")
		}
	} else {
		if rowLayoutPostSignMHatSigmaIndex(layout, 0) < 0 || rowLayoutPostSignRHat1Index(layout, 0) < 0 || rowLayoutPostSignTHatIndex(layout, 0) < 0 {
			return ConstraintSet{}, fmt.Errorf("missing transform-domain replay rows")
		}
		if rowLayoutPostSignR0B2HatIndex(layout, 0) < 0 && rowLayoutPostSignRHat0ComponentIndex(layout, 0, 0) < 0 {
			return ConstraintSet{}, fmt.Errorf("missing transform-domain RHat0 or aggregate R0-B2 rows")
		}
	}
	if useBBTran && rowLayoutPostSignZHatIndex(layout, 0) < 0 {
		return ConstraintSet{}, fmt.Errorf("bb_tran showing requires replay Z hats")
	}

	thetaBBlocks := make([][][]uint64, replayBlockCount)
	for b := 0; b < replayBlockCount; b++ {
		thetaBBlocks[b] = make([][]uint64, len(pub.B))
		for i := range pub.B {
			var theta *ring.Poly
			var terr error
			if replayBlockCount == 1 {
				theta, terr = thetaPolyFromNTT(ringQ, pub.B[i], omega)
			} else {
				theta, terr = thetaPolyFromNTTBlock(ringQ, pub.B[i], omega, b, sourceBlocks)
			}
			if terr != nil {
				return ConstraintSet{}, fmt.Errorf("theta B[%d] block %d: %w", i, b, terr)
			}
			coeff, cerr := coeffFromNTTPoly(ringQ, theta)
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("theta B[%d] block %d coeffs: %w", i, b, cerr)
			}
			thetaBBlocks[b][i] = trimPoly(coeff, q)
		}
	}
	msgDecode1, msgDecode2, err := buildPackedMessageCarrierDecodePolys(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("message carrier decode polys: %w", err)
	}
	x0Decode1, err := buildSingletonCarrierDecodePoly(pub.X0CoeffBound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("x0 carrier decode polys: %w", err)
	}
	scalarDecode1, _, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("scalar carrier decode polys: %w", err)
	}
	msgMembershipPoly, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("message carrier membership poly: %w", err)
	}
	x0MembershipPoly, err := buildSingletonCarrierMembershipPoly(pub.X0CoeffBound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("x0 carrier membership poly: %w", err)
	}
	scalarMembershipPoly, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("scalar carrier membership poly: %w", err)
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
	carrierR1Coeff, err := getRowCoeff(carrierR1Idx)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier R1 coeffs: %w", err)
	}
	carrierR0Coeffs := make([][]uint64, x0Len)
	for i := range carrierR0Idxs {
		carrierR0Coeffs[i], err = getRowCoeff(carrierR0Idxs[i])
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("carrier R0[%d] coeffs: %w", i, err)
		}
	}
	composeLeft := func(carrierCoeff []uint64, decodeCoeff []uint64) []uint64 {
		if domainMode == DomainModeExplicit {
			head := make([]uint64, ncols)
			for i, w := range omega {
				code := EvalPoly(carrierCoeff, w%q, q) % q
				head[i] = EvalPoly(decodeCoeff, code, q) % q
			}
			return trimPoly(Interpolate(omega, head, q), q)
		}
		return trimPoly(fpoly.New(q, decodeCoeff).Compose(fpoly.New(q, carrierCoeff)).Coeffs, q)
	}
	m1CompCoeffs := composeLeft(carrierMCoeff, msgDecode1)
	m2CompCoeffs := composeLeft(carrierMCoeff, msgDecode2)
	r0CompCoeffs := make([][]uint64, x0Len)
	for i := range carrierR0Coeffs {
		r0CompCoeffs[i] = composeLeft(carrierR0Coeffs[i], x0Decode1)
	}
	r1CompCoeffs := composeLeft(carrierR1Coeff, scalarDecode1)
	mSigmaCompCoeffs := polyAdd(m1CompCoeffs, m2CompCoeffs, q)
	memMCoeffs := composeLeft(carrierMCoeff, msgMembershipPoly)
	memR0Coeffs := make([][]uint64, x0Len)
	for i := range carrierR0Coeffs {
		memR0Coeffs[i] = composeLeft(carrierR0Coeffs[i], x0MembershipPoly)
	}
	memR1Coeffs := composeLeft(carrierR1Coeff, scalarMembershipPoly)

	packSelCoeff, err := buildPackingSelectorCoeff(ringQ, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("packing selector coeffs: %w", err)
	}
	oneMinusSelCoeff := polySub([]uint64{1}, packSelCoeff, q)
	m1PackCoeff := polyMul(packSelCoeff, m1CompCoeffs, q)
	m2PackCoeff := polyMul(oneMinusSelCoeff, m2CompCoeffs, q)
	m1PackCoeff = reducePolyModXN1(m1PackCoeff, int(ringQ.N), q)
	m2PackCoeff = reducePolyModXN1(m2PackCoeff, int(ringQ.N), q)
	m1Pack := nttPolyFromFormalCoeffsIfFits(ringQ, m1PackCoeff)
	m2Pack := nttPolyFromFormalCoeffsIfFits(ringQ, m2PackCoeff)
	carrierMemM := nttPolyFromFormalCoeffsIfFits(ringQ, memMCoeffs)
	carrierMemR0 := make([]*ring.Poly, x0Len)
	for i := range memR0Coeffs {
		carrierMemR0[i] = nttPolyFromFormalCoeffsIfFits(ringQ, memR0Coeffs[i])
	}
	carrierMemR1 := nttPolyFromFormalCoeffsIfFits(ringQ, memR1Coeffs)

	mSigmaHatCoeffs := make([][]uint64, replayBlockCount)
	r0HatCoeffs := make([][][]uint64, replayBlockCount)
	r0B2HatCoeffs := make([][]uint64, replayBlockCount)
	targetMR0HatCoeffs := make([][]uint64, replayBlockCount)
	r1HatCoeffs := make([][]uint64, replayBlockCount)
	var zHatCoeffs [][]uint64
	if useBBTran {
		zHatCoeffs = make([][]uint64, replayBlockCount)
	}
	aggregateR0Replay := rowLayoutPostSignR0B2HatIndex(layout, 0) >= 0
	for b := 0; b < replayBlockCount; b++ {
		r1HatCoeff, err := getRowCoeff(rowLayoutPostSignRHat1Index(layout, b))
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("rhat1 coeffs block %d: %w", b, err)
		}
		if directTargetReplay {
			targetMR0HatCoeff, err := getRowCoeff(rowLayoutPostSignTargetMR0HatIndex(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("target-MR0-hat coeffs block %d: %w", b, err)
			}
			targetMR0HatCoeffs[b] = targetMR0HatCoeff
		} else {
			mSigmaHatCoeff, err := getRowCoeff(rowLayoutPostSignMHatSigmaIndex(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("m-hat-sigma coeffs block %d: %w", b, err)
			}
			mSigmaHatCoeffs[b] = mSigmaHatCoeff
			if aggregateR0Replay {
				r0B2HatCoeff, err := getRowCoeff(rowLayoutPostSignR0B2HatIndex(layout, b))
				if err != nil {
					return ConstraintSet{}, fmt.Errorf("r0-b2-hat coeffs block %d: %w", b, err)
				}
				r0B2HatCoeffs[b] = r0B2HatCoeff
			} else {
				r0HatCoeffs[b] = make([][]uint64, x0Len)
				for i := 0; i < x0Len; i++ {
					r0HatCoeffs[b][i], err = getRowCoeff(rowLayoutPostSignRHat0ComponentIndex(layout, b, i))
					if err != nil {
						return ConstraintSet{}, fmt.Errorf("rhat0[%d] coeffs block %d: %w", i, b, err)
					}
				}
			}
		}
		r1HatCoeffs[b] = r1HatCoeff
		if useBBTran {
			zHatCoeff, err := getRowCoeff(rowLayoutPostSignZHatIndex(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("z hat coeffs block %d: %w", b, err)
			}
			zHatCoeffs[b] = zHatCoeff
		}
	}
	var tHatCoeffs [][]uint64
	if !directTargetReplay {
		tHatCoeffs = make([][]uint64, replayTHatCount)
		for b := 0; b < replayTHatCount; b++ {
			tHatCoeff, err := getRowCoeff(rowLayoutPostSignTHatIndex(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("t-hat coeffs block %d: %w", b, err)
			}
			tHatCoeffs[b] = tHatCoeff
		}
	}

	hashResCoeffs := make([][]uint64, 0, 2*replayBlockCount)
	hashResPolys := make([]*ring.Poly, 0, 2*replayBlockCount)
	for b := 0; b < replayBlockCount; b++ {
		inverseResCoeff := reducePolyModXN1(buildTransformInverseResidualCoeffs(q, pub.HashRelation, thetaBBlocks[b], r1HatCoeffs[b], coeffOrZero(zHatCoeffs, b)), int(ringQ.N), q)
		if directTargetReplay {
			hashResCoeffs = append(hashResCoeffs, inverseResCoeff)
			hashResPolys = append(hashResPolys, nttPolyFromFormalCoeffsIfFits(ringQ, inverseResCoeff))
			continue
		}
		var targetResCoeff []uint64
		if aggregateR0Replay {
			targetResCoeff = reducePolyModXN1(buildTransformTargetResidualCombinedCoeffsAggregate(q, pub.HashRelation, thetaBBlocks[b], mSigmaHatCoeffs[b], r0B2HatCoeffs[b], coeffOrZero(zHatCoeffs, b), tHatCoeffs[b]), int(ringQ.N), q)
		} else {
			targetResCoeff = reducePolyModXN1(buildTransformTargetResidualCombinedCoeffsVector(q, pub.HashRelation, thetaBBlocks[b], mSigmaHatCoeffs[b], r0HatCoeffs[b], coeffOrZero(zHatCoeffs, b), tHatCoeffs[b]), int(ringQ.N), q)
		}
		hashResCoeffs = append(hashResCoeffs, targetResCoeff, inverseResCoeff)
		hashResPolys = append(hashResPolys, nttPolyFromFormalCoeffsIfFits(ringQ, targetResCoeff), nttPolyFromFormalCoeffsIfFits(ringQ, inverseResCoeff))
	}

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
				resCoeff := reducePolyModXN1(polySub(keyExtract, m2Extract, q), int(ringQ.N), q)
				keyBindCoeffs = append(keyBindCoeffs, resCoeff)
				keyBindRes = append(keyBindRes, nttPolyFromFormalCoeffsIfFits(ringQ, resCoeff))
			}
		}
	}

	fparInt := append([]*ring.Poly{}, hashResPolys...)
	fparInt = append(fparInt, m1Pack, m2Pack, carrierMemM)
	fparInt = append(fparInt, carrierMemR0...)
	fparInt = append(fparInt, carrierMemR1)
	fparInt = append(fparInt, keyBindRes...)
	fparIntCoeffs := append([][]uint64{}, hashResCoeffs...)
	fparIntCoeffs = append(fparIntCoeffs, m1PackCoeff, m2PackCoeff, memMCoeffs)
	fparIntCoeffs = append(fparIntCoeffs, memR0Coeffs...)
	fparIntCoeffs = append(fparIntCoeffs, memR1Coeffs)
	fparIntCoeffs = append(fparIntCoeffs, keyBindCoeffs...)
	if len(fparIntCoeffs) != len(fparInt) {
		return ConstraintSet{}, fmt.Errorf("transform-bridge formal coeff mismatch: coeffs=%d polys=%d", len(fparIntCoeffs), len(fparInt))
	}

	outputBlocks := replayTHatCount
	if directTargetReplay {
		outputBlocks = replayBlockCount
	}
	bridgeBasis, err := newRowTransformBridgeBasisCache(ringQ, omega, outputBlocks*ncols)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("transform-bridge basis: %w", err)
	}
	r0BridgeFamilies := x0Len
	if aggregateR0Replay {
		r0BridgeFamilies = 1
	}
	if directTargetReplay {
		r0BridgeFamilies = 1
	}
	faggNorm := make([]*ring.Poly, 0, (r0BridgeFamilies+2)*replayBlockCount*ncols)
	faggNormCoeffs := make([][]uint64, 0, (r0BridgeFamilies+2)*replayBlockCount*ncols)
	bridgePairs := []struct {
		srcCoeff []uint64
		name     string
		hatAt    func(int) ([]uint64, error)
	}{
		{srcCoeff: r1CompCoeffs, name: "r1", hatAt: func(block int) ([]uint64, error) { return getRowCoeff(rowLayoutPostSignRHat1Index(layout, block)) }},
	}
	if !directTargetReplay {
		bridgePairs = append([]struct {
			srcCoeff []uint64
			name     string
			hatAt    func(int) ([]uint64, error)
		}{
			{srcCoeff: mSigmaCompCoeffs, name: "m-sigma", hatAt: func(block int) ([]uint64, error) { return getRowCoeff(rowLayoutPostSignMHatSigmaIndex(layout, block)) }},
		}, bridgePairs...)
	}
	for _, pair := range bridgePairs {
		for b := 0; b < replayBlockCount; b++ {
			hatCoeff, err := pair.hatAt(b)
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("non-sign hat coeffs %s block %d: %w", pair.name, b, err)
			}
			for j := 0; j < ncols; j++ {
				t := b*ncols + j
				bridgeCoeff := reducePolyModXN1(buildTransformBridgeResidualCoeff(q, bridgeBasis.TransformH[t], bridgeBasis.LagrangeBasis[j], pair.srcCoeff, hatCoeff), int(ringQ.N), q)
				faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
				faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
			}
		}
	}
	if directTargetReplay {
		for b := 0; b < replayBlockCount; b++ {
			hatCoeff, err := getRowCoeff(rowLayoutPostSignTargetMR0HatIndex(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("non-sign hat coeffs target-MR0 block %d: %w", b, err)
			}
			for j := 0; j < ncols; j++ {
				t := b*ncols + j
				b1Scale := EvalPoly(thetaBBlocks[b][1], omega[j]%q, q) % q
				leftCoeff := reducePolyModXN1(polyMul(bridgeBasis.TransformH[t], mSigmaCompCoeffs, q), int(ringQ.N), q)
				if b1Scale != 1 {
					leftCoeff = scalePoly(leftCoeff, b1Scale, q)
				}
				for i := 0; i < x0Len; i++ {
					scale := EvalPoly(thetaBBlocks[b][2+i], omega[j]%q, q) % q
					term := reducePolyModXN1(polyMul(bridgeBasis.TransformH[t], r0CompCoeffs[i], q), int(ringQ.N), q)
					if scale != 1 {
						term = scalePoly(term, scale, q)
					}
					leftCoeff = polyAdd(leftCoeff, term, q)
				}
				rightCoeff := reducePolyModXN1(polyMul(bridgeBasis.LagrangeBasis[j], hatCoeff, q), int(ringQ.N), q)
				bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
				faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
				faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
			}
		}
	} else if aggregateR0Replay {
		for b := 0; b < replayBlockCount; b++ {
			hatCoeff, err := getRowCoeff(rowLayoutPostSignR0B2HatIndex(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("non-sign hat coeffs r0-b2 block %d: %w", b, err)
			}
			for j := 0; j < ncols; j++ {
				t := b*ncols + j
				leftCoeff := []uint64{0}
				for i := 0; i < x0Len; i++ {
					scale := EvalPoly(thetaBBlocks[b][2+i], omega[j]%q, q) % q
					term := reducePolyModXN1(polyMul(bridgeBasis.TransformH[t], r0CompCoeffs[i], q), int(ringQ.N), q)
					if scale != 1 {
						term = scalePoly(term, scale, q)
					}
					leftCoeff = polyAdd(leftCoeff, term, q)
				}
				rightCoeff := reducePolyModXN1(polyMul(bridgeBasis.LagrangeBasis[j], hatCoeff, q), int(ringQ.N), q)
				bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
				faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
				faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
			}
		}
	} else {
		for i := 0; i < x0Len; i++ {
			for b := 0; b < replayBlockCount; b++ {
				hatCoeff, err := getRowCoeff(rowLayoutPostSignRHat0ComponentIndex(layout, b, i))
				if err != nil {
					return ConstraintSet{}, fmt.Errorf("non-sign hat coeffs r0[%d] block %d: %w", i, b, err)
				}
				for j := 0; j < ncols; j++ {
					t := b*ncols + j
					bridgeCoeff := reducePolyModXN1(buildTransformBridgeResidualCoeff(q, bridgeBasis.TransformH[t], bridgeBasis.LagrangeBasis[j], r0CompCoeffs[i], hatCoeff), int(ringQ.N), q)
					faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
					faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
				}
			}
		}
	}
	_ = prfLayout

	parallelDeg := 2
	if deg := maxDegreeFromCoeffs(msgDecode1); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(x0Decode1); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(msgMembershipPoly); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(x0MembershipPoly); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(scalarMembershipPoly); deg > parallelDeg {
		parallelDeg = deg
	}
	aggDeg := 1
	if deg := maxDegreeFromCoeffs(msgDecode1); deg > aggDeg {
		aggDeg = deg
	}
	if deg := maxDegreeFromCoeffs(x0Decode1); deg > aggDeg {
		aggDeg = deg
	}
	if deg := maxDegreeFromCoeffs(scalarDecode1); deg > aggDeg {
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
