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
	replayBlockCount := rowLayoutReplayBlockCount(layout)
	if replayBlockCount <= 0 {
		replayBlockCount = replayTHatCount
	}
	useBBTran := publicUsesBBTran(pub)
	useSourceProductBridge := useBBTran && sourceProductBridgeEnabled(pub, opts, layout)
	if replayTHatCount != replayBlockCount {
		return ConstraintSet{}, fmt.Errorf("replay family mismatch: T-hat count=%d replay blocks=%d", replayTHatCount, replayBlockCount)
	}
	if replayBlockCount > sourceBlocks {
		return ConstraintSet{}, fmt.Errorf("replay blocks=%d exceed source blocks=%d", replayBlockCount, sourceBlocks)
	}

	carrierMIdx := rowLayoutPostSignCarrierM(layout)
	carrierCtrIdx := rowLayoutPostSignCarrierCtr(layout)
	if carrierMIdx < 0 || carrierCtrIdx < 0 {
		return ConstraintSet{}, fmt.Errorf("missing carrier rows (M=%d ctr=%d)", carrierMIdx, carrierCtrIdx)
	}
	if carrierMIdx >= len(rowsNTT) || carrierCtrIdx >= len(rowsNTT) {
		return ConstraintSet{}, fmt.Errorf("showing source row index out of range (rows=%d)", len(rowsNTT))
	}
	if rowLayoutPostSignMHatSigmaIndex(layout, 0) < 0 || rowLayoutPostSignRHat0Index(layout, 0) < 0 || rowLayoutPostSignRHat1Index(layout, 0) < 0 || rowLayoutPostSignTHatIndex(layout, 0) < 0 {
		return ConstraintSet{}, fmt.Errorf("missing transform-domain replay rows")
	}
	if useBBTran && (rowLayoutPostSignMSigmaR1HatIndex(layout, 0) < 0 || rowLayoutPostSignR0R1HatIndex(layout, 0) < 0) {
		return ConstraintSet{}, fmt.Errorf("bb_tran showing requires replay product hats")
	}
	if useBBTran && (layout.IdxMSigmaR1 < 0 || layout.IdxR0R1 < 0) {
		return ConstraintSet{}, fmt.Errorf("bb_tran showing requires committed product rows")
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
	var mSigmaR1CompCoeffs, r0R1CompCoeffs []uint64
	if useBBTran {
		mSigmaR1CompCoeffs, r0R1CompCoeffs, err = buildBBTranProductInterpCoeffs(q, omega, m1CompCoeffs, m2CompCoeffs, r0CompCoeffs, r1CompCoeffs)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("bb_tran source product interpolants: %w", err)
		}
	}
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

	mSigmaHatCoeffs := make([][]uint64, replayBlockCount)
	r0HatCoeffs := make([][]uint64, replayBlockCount)
	r1HatCoeffs := make([][]uint64, replayBlockCount)
	var mSigmaR1HatCoeffs, r0R1HatCoeffs [][]uint64
	if useBBTran {
		mSigmaR1HatCoeffs = make([][]uint64, replayBlockCount)
		r0R1HatCoeffs = make([][]uint64, replayBlockCount)
	}
	for b := 0; b < replayBlockCount; b++ {
		mSigmaHatCoeff, err := getRowCoeff(rowLayoutPostSignMHatSigmaIndex(layout, b))
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("m-hat-sigma coeffs block %d: %w", b, err)
		}
		r0HatCoeff, err := getRowCoeff(rowLayoutPostSignRHat0Index(layout, b))
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("rhat0 coeffs block %d: %w", b, err)
		}
		r1HatCoeff, err := getRowCoeff(rowLayoutPostSignRHat1Index(layout, b))
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("rhat1 coeffs block %d: %w", b, err)
		}
		mSigmaHatCoeffs[b] = mSigmaHatCoeff
		r0HatCoeffs[b] = r0HatCoeff
		r1HatCoeffs[b] = r1HatCoeff
		if useBBTran {
			mSigmaR1HatCoeff, err := getRowCoeff(rowLayoutPostSignMSigmaR1HatIndex(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("mSigmaR1 hat coeffs block %d: %w", b, err)
			}
			r0R1HatCoeff, err := getRowCoeff(rowLayoutPostSignR0R1HatIndex(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("r0R1 hat coeffs block %d: %w", b, err)
			}
			mSigmaR1HatCoeffs[b] = mSigmaR1HatCoeff
			r0R1HatCoeffs[b] = r0R1HatCoeff
		}
	}
	var mSigmaR1SourceCoeff, r0R1SourceCoeff []uint64
	var productSourceRes []*ring.Poly
	var productSourceResCoeffs [][]uint64
	if useBBTran {
		mSigmaR1SourceCoeff, err = getRowCoeff(layout.IdxMSigmaR1)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("bb_tran source MSigmaR1 coeffs: %w", err)
		}
		r0R1SourceCoeff, err = getRowCoeff(layout.IdxR0R1)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("bb_tran source R0R1 coeffs: %w", err)
		}
		for _, pair := range []struct {
			got  []uint64
			want []uint64
			name string
		}{
			{got: mSigmaR1SourceCoeff, want: mSigmaR1CompCoeffs, name: "bb_tran source MSigmaR1"},
			{got: r0R1SourceCoeff, want: r0R1CompCoeffs, name: "bb_tran source R0R1"},
		} {
			resCoeff := polySub(pair.got, pair.want, q)
			productSourceResCoeffs = append(productSourceResCoeffs, resCoeff)
			productSourceRes = append(productSourceRes, nttPolyFromFormalCoeffsIfFits(ringQ, resCoeff))
		}
	}
	tHatCoeffs := make([][]uint64, replayTHatCount)
	for b := 0; b < replayTHatCount; b++ {
		tHatCoeff, err := getRowCoeff(rowLayoutPostSignTHatIndex(layout, b))
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("t-hat coeffs block %d: %w", b, err)
		}
		tHatCoeffs[b] = tHatCoeff
	}

	hashResCoeffs := make([][]uint64, replayBlockCount)
	hashResPolys := make([]*ring.Poly, replayBlockCount)
	for b := 0; b < replayBlockCount; b++ {
		hashResCoeff := buildTransformHashResidualCombinedCoeffs(q, pub.HashRelation, thetaBBlocks[b], mSigmaHatCoeffs[b], r0HatCoeffs[b], r1HatCoeffs[b], tHatCoeffs[b], coeffOrZero(mSigmaR1HatCoeffs, b), coeffOrZero(r0R1HatCoeffs, b))
		hashResCoeffs[b] = hashResCoeff
		hashResPolys[b] = nttPolyFromFormalCoeffsIfFits(ringQ, hashResCoeff)
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
				resCoeff := polySub(keyExtract, m2Extract, q)
				keyBindCoeffs = append(keyBindCoeffs, resCoeff)
				keyBindRes = append(keyBindRes, nttPolyFromFormalCoeffsIfFits(ringQ, resCoeff))
			}
		}
	}

	fparInt := append([]*ring.Poly{}, hashResPolys...)
	fparInt = append(fparInt, productSourceRes...)
	fparInt = append(fparInt, m1Pack, m2Pack, carrierMemM, carrierMemCtr)
	fparInt = append(fparInt, keyBindRes...)
	fparIntCoeffs := append([][]uint64{}, hashResCoeffs...)
	fparIntCoeffs = append(fparIntCoeffs, productSourceResCoeffs...)
	fparIntCoeffs = append(fparIntCoeffs, m1PackCoeff, m2PackCoeff, memMCoeffs, memCtrCoeffs)
	fparIntCoeffs = append(fparIntCoeffs, keyBindCoeffs...)
	if len(fparIntCoeffs) != len(fparInt) {
		return ConstraintSet{}, fmt.Errorf("transform-bridge formal coeff mismatch: coeffs=%d polys=%d", len(fparIntCoeffs), len(fparInt))
	}

	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omega, replayTHatCount*ncols, sourceBlocks)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("transform-bridge basis: %w", err)
	}
	faggNorm := make([]*ring.Poly, 0, (1+3+2)*replayBlockCount*ncols)
	faggNormCoeffs := make([][]uint64, 0, (1+3+2)*replayBlockCount*ncols)
	for _, pair := range []struct {
		srcCoeff []uint64
		idxAt    func(RowLayout, int) int
		name     string
	}{
		{srcCoeff: mSigmaCompCoeffs, idxAt: rowLayoutPostSignMHatSigmaIndex, name: "m-sigma"},
		{srcCoeff: r0CompCoeffs, idxAt: rowLayoutPostSignRHat0Index, name: "r0"},
		{srcCoeff: r1CompCoeffs, idxAt: rowLayoutPostSignRHat1Index, name: "r1"},
	} {
		for b := 0; b < replayBlockCount; b++ {
			hatCoeff, err := getRowCoeff(pair.idxAt(layout, b))
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("non-sign hat coeffs %s block %d: %w", pair.name, b, err)
			}
			for j := 0; j < ncols; j++ {
				t := b*ncols + j
				bridgeCoeff := buildTransformBridgeResidualCoeff(q, bridgeBasis.TransformH[t], bridgeBasis.LagrangeBasis[j], pair.srcCoeff, hatCoeff)
				faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
				faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
			}
		}
	}
	if useBBTran && !useSourceProductBridge {
		for _, pair := range []struct {
			srcCoeff []uint64
			idxAt    func(RowLayout, int) int
			name     string
		}{
			{srcCoeff: mSigmaR1CompCoeffs, idxAt: rowLayoutPostSignMSigmaR1HatIndex, name: "mSigmaR1"},
			{srcCoeff: r0R1CompCoeffs, idxAt: rowLayoutPostSignR0R1HatIndex, name: "r0R1"},
		} {
			for b := 0; b < replayBlockCount; b++ {
				hatCoeff, err := getRowCoeff(pair.idxAt(layout, b))
				if err != nil {
					return ConstraintSet{}, fmt.Errorf("bb_tran hat coeffs %s block %d: %w", pair.name, b, err)
				}
				for j := 0; j < ncols; j++ {
					t := b*ncols + j
					bridgeCoeff := buildTransformBridgeResidualCoeff(q, bridgeBasis.TransformH[t], bridgeBasis.LagrangeBasis[j], pair.srcCoeff, hatCoeff)
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
