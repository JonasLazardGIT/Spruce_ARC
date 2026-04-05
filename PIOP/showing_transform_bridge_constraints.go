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
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	if len(pub.A) == 0 || len(pub.A[0]) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing A for signature constraint")
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
	blocks := layout.SigBlocks
	if blocks <= 0 {
		blocks = 1
	}
	uCount := len(pub.A[0])
	if uCount <= 0 {
		return ConstraintSet{}, fmt.Errorf("empty A columns")
	}
	if layout.SigUCount != 0 && layout.SigUCount != uCount {
		return ConstraintSet{}, fmt.Errorf("signature component mismatch: SigUCount=%d want %d", layout.SigUCount, uCount)
	}
	carrierMIdx := rowLayoutPostSignCarrierM(layout)
	carrierCtrIdx := rowLayoutPostSignCarrierCtr(layout)
	if carrierMIdx < 0 || carrierCtrIdx < 0 {
		return ConstraintSet{}, fmt.Errorf("missing carrier rows (M=%d ctr=%d)", carrierMIdx, carrierCtrIdx)
	}
	if carrierMIdx >= len(rowsNTT) || carrierCtrIdx >= len(rowsNTT) {
		return ConstraintSet{}, fmt.Errorf("carrier row index out of range (rows=%d)", len(rowsNTT))
	}
	if layout.IdxSigHatBase < 0 || layout.IdxTHatBase < 0 {
		return ConstraintSet{}, fmt.Errorf("missing transform-domain signature aliases")
	}
	if layout.IdxMHat1 < 0 || layout.IdxMHat2 < 0 || layout.IdxRHat0 < 0 || layout.IdxRHat1 < 0 {
		return ConstraintSet{}, fmt.Errorf("missing transform-domain non-sign aliases")
	}
	cfg := layout.CoeffNativeSig
	if cfg.PackedSigBase < 0 || cfg.PackedSigCount <= 0 {
		return ConstraintSet{}, fmt.Errorf("missing packed signature rows")
	}

	thetaABlocks := make([][][]*ring.Poly, blocks)
	for b := 0; b < blocks; b++ {
		thetaABlocks[b] = make([][]*ring.Poly, len(pub.A))
		for i := range pub.A {
			thetaABlocks[b][i] = make([]*ring.Poly, len(pub.A[i]))
			for j := range pub.A[i] {
				theta, terr := thetaPolyFromNTTBlock(ringQ, pub.A[i][j], omega, b, blocks)
				if terr != nil {
					return ConstraintSet{}, fmt.Errorf("theta A[%d][%d] block %d: %w", i, j, b, terr)
				}
				thetaABlocks[b][i][j] = theta
			}
		}
	}
	thetaB := make([]*ring.Poly, len(pub.B))
	for i := range pub.B {
		theta, terr := thetaPolyFromNTT(ringQ, pub.B[i], omega)
		if terr != nil {
			return ConstraintSet{}, fmt.Errorf("theta B[%d]: %w", i, terr)
		}
		thetaB[i] = theta
	}

	decode1, decode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier decode polys: %w", err)
	}
	membershipPoly, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier membership poly: %w", err)
	}
	carrierMCoeff, err := coeffFromNTTPoly(ringQ, rowsNTT[carrierMIdx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier M coeffs: %w", err)
	}
	carrierCtrCoeff, err := coeffFromNTTPoly(ringQ, rowsNTT[carrierCtrIdx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier ctr coeffs: %w", err)
	}
	carrierMCoeff = trimPoly(carrierMCoeff, q)
	carrierCtrCoeff = trimPoly(carrierCtrCoeff, q)
	decode1Poly := fpoly.New(q, decode1)
	decode2Poly := fpoly.New(q, decode2)
	carrierMPoly := fpoly.New(q, carrierMCoeff)
	carrierCtrPoly := fpoly.New(q, carrierCtrCoeff)
	m1Comp := decode1Poly.Compose(carrierMPoly)
	m2Comp := decode2Poly.Compose(carrierMPoly)
	r0Comp := decode1Poly.Compose(carrierCtrPoly)
	r1Comp := decode2Poly.Compose(carrierCtrPoly)
	m1CompCoeffs := trimPoly(m1Comp.Coeffs, q)
	m2CompCoeffs := trimPoly(m2Comp.Coeffs, q)
	r0CompCoeffs := trimPoly(r0Comp.Coeffs, q)
	r1CompCoeffs := trimPoly(r1Comp.Coeffs, q)
	membership := fpoly.New(q, membershipPoly)
	memMComp := membership.Compose(carrierMPoly)
	memCtrComp := membership.Compose(carrierCtrPoly)
	memMCoeffs := trimPoly(memMComp.Coeffs, q)
	memCtrCoeffs := trimPoly(memCtrComp.Coeffs, q)
	if domainMode != DomainModeExplicit {
		m1CompCoeffs = reducePolyModXN1(m1CompCoeffs, int(ringQ.N), q)
		m2CompCoeffs = reducePolyModXN1(m2CompCoeffs, int(ringQ.N), q)
		r0CompCoeffs = reducePolyModXN1(r0CompCoeffs, int(ringQ.N), q)
		r1CompCoeffs = reducePolyModXN1(r1CompCoeffs, int(ringQ.N), q)
		memMCoeffs = reducePolyModXN1(memMCoeffs, int(ringQ.N), q)
		memCtrCoeffs = reducePolyModXN1(memCtrCoeffs, int(ringQ.N), q)
	}
	m1NTTCoeffs := m1CompCoeffs
	if domainMode == DomainModeExplicit {
		m1NTTCoeffs = reducePolyModXN1(append([]uint64(nil), m1CompCoeffs...), int(ringQ.N), q)
	}
	m1NTT := nttPolyFromFormalCoeffsIfFits(ringQ, m1NTTCoeffs)
	if m1NTT == nil {
		m1NTT = ringQ.NewPoly()
		copy(m1NTT.Coeffs[0], m1NTTCoeffs)
		ringQ.NTT(m1NTT, m1NTT)
	}
	m2NTTCoeffs := m2CompCoeffs
	if domainMode == DomainModeExplicit {
		m2NTTCoeffs = reducePolyModXN1(append([]uint64(nil), m2CompCoeffs...), int(ringQ.N), q)
	}
	m2NTT := nttPolyFromFormalCoeffsIfFits(ringQ, m2NTTCoeffs)
	if m2NTT == nil {
		m2NTT = ringQ.NewPoly()
		copy(m2NTT.Coeffs[0], m2NTTCoeffs)
		ringQ.NTT(m2NTT, m2NTT)
	}
	r0NTTCoeffs := r0CompCoeffs
	if domainMode == DomainModeExplicit {
		r0NTTCoeffs = reducePolyModXN1(append([]uint64(nil), r0CompCoeffs...), int(ringQ.N), q)
	}
	r0NTT := nttPolyFromFormalCoeffsIfFits(ringQ, r0NTTCoeffs)
	if r0NTT == nil {
		r0NTT = ringQ.NewPoly()
		copy(r0NTT.Coeffs[0], r0NTTCoeffs)
		ringQ.NTT(r0NTT, r0NTT)
	}
	r1NTTCoeffs := r1CompCoeffs
	if domainMode == DomainModeExplicit {
		r1NTTCoeffs = reducePolyModXN1(append([]uint64(nil), r1CompCoeffs...), int(ringQ.N), q)
	}
	r1NTT := nttPolyFromFormalCoeffsIfFits(ringQ, r1NTTCoeffs)
	if r1NTT == nil {
		r1NTT = ringQ.NewPoly()
		copy(r1NTT.Coeffs[0], r1NTTCoeffs)
		ringQ.NTT(r1NTT, r1NTT)
	}

	sigHatRow := func(block, comp int) (int, error) {
		if block < 0 || block >= blocks {
			return -1, fmt.Errorf("invalid signature block %d", block)
		}
		if comp < 0 || comp >= uCount {
			return -1, fmt.Errorf("invalid signature component %d", comp)
		}
		if block == 0 {
			return layout.IdxSigHatBase + comp, nil
		}
		if layout.SigHatExtraBase < 0 {
			return -1, fmt.Errorf("missing SigHatExtraBase for block %d", block)
		}
		return layout.SigHatExtraBase + (block-1)*uCount + comp, nil
	}
	sigSourceRow := func(block, comp int) (int, error) {
		if block < 0 || block >= blocks {
			return -1, fmt.Errorf("invalid signature block %d", block)
		}
		if comp < 0 || comp >= uCount {
			return -1, fmt.Errorf("invalid signature component %d", comp)
		}
		idx := cfg.PackedSigBase + block*cfg.PackedSigComponents + comp
		return idx, nil
	}

	toFormalCoeffs := func(p *ring.Poly) ([]uint64, error) {
		coeff, cerr := coeffFromNTTPoly(ringQ, p)
		if cerr != nil {
			return nil, cerr
		}
		if len(coeff) == 0 {
			return []uint64{0}, nil
		}
		return trimPoly(coeff, q), nil
	}
	polyAdd := func(a, b []uint64) []uint64 {
		n := len(a)
		if len(b) > n {
			n = len(b)
		}
		if n == 0 {
			return []uint64{0}
		}
		out := make([]uint64, n)
		for i := 0; i < n; i++ {
			av := uint64(0)
			if i < len(a) {
				av = a[i] % q
			}
			bv := uint64(0)
			if i < len(b) {
				bv = b[i] % q
			}
			out[i] = modAdd(av, bv, q)
		}
		return trimPoly(out, q)
	}
	polySub := func(a, b []uint64) []uint64 {
		n := len(a)
		if len(b) > n {
			n = len(b)
		}
		if n == 0 {
			return []uint64{0}
		}
		out := make([]uint64, n)
		for i := 0; i < n; i++ {
			av := uint64(0)
			if i < len(a) {
				av = a[i] % q
			}
			bv := uint64(0)
			if i < len(b) {
				bv = b[i] % q
			}
			out[i] = modSub(av, bv, q)
		}
		return trimPoly(out, q)
	}
	var getRowCoeff func(idx int) ([]uint64, error)
	if domainMode == DomainModeExplicit {
		coeffCache := map[int][]uint64{}
		getRowCoeff = func(idx int) ([]uint64, error) {
			if coeff, ok := coeffCache[idx]; ok {
				return coeff, nil
			}
			if idx < 0 || idx >= len(rowsNTT) {
				return nil, fmt.Errorf("row coeff idx %d out of range (rows=%d)", idx, len(rowsNTT))
			}
			coeff, err := toFormalCoeffs(rowsNTT[idx])
			if err != nil {
				return nil, err
			}
			coeffCache[idx] = coeff
			return coeff, nil
		}
	}

	var sigRes []*ring.Poly
	var sigResCoeffs [][]uint64

	for b := 0; b < blocks; b++ {
		uBlock := make([]*ring.Poly, uCount)
		for j := 0; j < uCount; j++ {
			idx, err := sigHatRow(b, j)
			if err != nil {
				return ConstraintSet{}, err
			}
			if idx < 0 || idx >= len(rowsNTT) {
				return ConstraintSet{}, fmt.Errorf("sig hat row %d out of range", idx)
			}
			uBlock[j] = rowsNTT[idx]
		}
		tRow := layout.IdxTHatBase + b
		if tRow < 0 || tRow >= len(rowsNTT) {
			return ConstraintSet{}, fmt.Errorf("T-hat row %d out of range", tRow)
		}
		tBlock := rowsNTT[tRow]
		if domainMode == DomainModeExplicit {
			if getRowCoeff == nil {
				return ConstraintSet{}, fmt.Errorf("missing explicit coeff cache for signature residuals")
			}
			tCoeff, terr := getRowCoeff(tRow)
			if terr != nil {
				return ConstraintSet{}, fmt.Errorf("signature block %d T coeffs: %w", b, terr)
			}
			for i := 0; i < len(thetaABlocks[b]); i++ {
				acc := []uint64{0}
				for j := 0; j < uCount; j++ {
					uIdx, err := sigHatRow(b, j)
					if err != nil {
						return ConstraintSet{}, err
					}
					aCoeff, aerr := toFormalCoeffs(thetaABlocks[b][i][j])
					if aerr != nil {
						return ConstraintSet{}, fmt.Errorf("signature block %d A[%d][%d] coeffs: %w", b, i, j, aerr)
					}
					uCoeff, uerr := getRowCoeff(uIdx)
					if uerr != nil {
						return ConstraintSet{}, fmt.Errorf("signature block %d U[%d] coeffs: %w", b, j, uerr)
					}
					acc = polyAdd(acc, polyMul(aCoeff, uCoeff, q))
				}
				resCoeff := polySub(acc, tCoeff)
				sigResCoeffs = append(sigResCoeffs, resCoeff)
				sigRes = append(sigRes, nttPolyFromFormalCoeffsIfFits(ringQ, resCoeff))
			}
		} else {
			res, err := BuildSignatureConstraintNTT(ringQ, thetaABlocks[b], uBlock, tBlock)
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("signature residuals block %d: %w", b, err)
			}
			sigRes = append(sigRes, res...)
		}
	}

	mHat1 := rowsNTT[layout.IdxMHat1]
	mHat2 := rowsNTT[layout.IdxMHat2]
	rHat0 := rowsNTT[layout.IdxRHat0]
	rHat1 := rowsNTT[layout.IdxRHat1]
	tHat0 := rowsNTT[layout.IdxTHatBase]
	var hashRes []*ring.Poly
	var hashResCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		if getRowCoeff == nil {
			return ConstraintSet{}, fmt.Errorf("missing explicit coeff cache for hash residuals")
		}
		if len(thetaB) != 4 {
			return ConstraintSet{}, fmt.Errorf("theta B length=%d want 4", len(thetaB))
		}
		bCoeff := make([][]uint64, 4)
		for i := 0; i < 4; i++ {
			coeff, cerr := toFormalCoeffs(thetaB[i])
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("hash B[%d] coeffs: %w", i, cerr)
			}
			bCoeff[i] = coeff
		}
		m1Coeff, m1Err := getRowCoeff(layout.IdxMHat1)
		if m1Err != nil {
			return ConstraintSet{}, fmt.Errorf("mhat1 coeffs: %w", m1Err)
		}
		m2Coeff, m2Err := getRowCoeff(layout.IdxMHat2)
		if m2Err != nil {
			return ConstraintSet{}, fmt.Errorf("mhat2 coeffs: %w", m2Err)
		}
		r0Coeff, r0Err := getRowCoeff(layout.IdxRHat0)
		if r0Err != nil {
			return ConstraintSet{}, fmt.Errorf("rhat0 coeffs: %w", r0Err)
		}
		r1Coeff, r1Err := getRowCoeff(layout.IdxRHat1)
		if r1Err != nil {
			return ConstraintSet{}, fmt.Errorf("rhat1 coeffs: %w", r1Err)
		}
		tCoeff, tErr := getRowCoeff(layout.IdxTHatBase)
		if tErr != nil {
			return ConstraintSet{}, fmt.Errorf("t-hat coeffs: %w", tErr)
		}
		mCombined := polyAdd(m1Coeff, m2Coeff)
		num := polyAdd(bCoeff[0], polyMul(bCoeff[1], mCombined, q))
		num = polyAdd(num, polyMul(bCoeff[2], r0Coeff, q))
		den := polySub(bCoeff[3], r1Coeff)
		resCoeff := polySub(polyMul(den, tCoeff, q), num)
		hashResCoeffs = [][]uint64{resCoeff}
		hashRes = []*ring.Poly{nttPolyFromFormalCoeffsIfFits(ringQ, resCoeff)}
	} else {
		var err error
		hashRes, err = BuildHashConstraintsNTT(ringQ, thetaB, mHat1, mHat2, rHat0, rHat1, tHat0)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("hash residuals: %w", err)
		}
	}

	selNTT, oneMinusSel, err := buildPackingSelectorNTT(ringQ, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("packing selector: %w", err)
	}
	m1Pack := ringQ.NewPoly()
	m2Pack := ringQ.NewPoly()
	ringQ.MulCoeffs(selNTT, m1NTT, m1Pack)
	ringQ.MulCoeffs(oneMinusSel, m2NTT, m2Pack)
	var m1PackCoeff, m2PackCoeff []uint64
	if domainMode == DomainModeExplicit {
		selCoeff, serr := buildPackingSelectorCoeff(ringQ, omega)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("packing selector coeffs: %w", serr)
		}
		oneMinusSelCoeff := polySub([]uint64{1}, selCoeff)
		m1PackCoeff = polyMul(selCoeff, m1CompCoeffs, q)
		m2PackCoeff = polyMul(oneMinusSelCoeff, m2CompCoeffs, q)
		m1Pack = nttPolyFromFormalCoeffsIfFits(ringQ, m1PackCoeff)
		m2Pack = nttPolyFromFormalCoeffsIfFits(ringQ, m2PackCoeff)
	}

	carrierMemM := nttPolyFromFormalCoeffsIfFits(ringQ, memMCoeffs)
	if carrierMemM == nil && domainMode != DomainModeExplicit {
		carrierMemM, err = evalPolyOnNTT(ringQ, membershipPoly, rowsNTT[carrierMIdx])
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("carrier membership M: %w", err)
		}
	}
	carrierMemCtr := nttPolyFromFormalCoeffsIfFits(ringQ, memCtrCoeffs)
	if carrierMemCtr == nil && domainMode != DomainModeExplicit {
		carrierMemCtr, err = evalPolyOnNTT(ringQ, membershipPoly, rowsNTT[carrierCtrIdx])
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("carrier membership ctr: %w", err)
		}
	}

	var keyBindRes []*ring.Poly
	var keyBindCoeffs [][]uint64
	if prfCompanionLayout != nil {
		selectorTheta, selectorCoeff, err := buildOmegaDeltaSelectors(ringQ, omega)
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
			if domainMode == DomainModeExplicit {
				if getRowCoeff == nil {
					return ConstraintSet{}, fmt.Errorf("missing explicit coeff cache for key binding")
				}
				for i := 0; i < keyCount; i++ {
					col := half + i
					if col < 0 || col >= len(selectorCoeff) {
						return ConstraintSet{}, fmt.Errorf("key binding selector col=%d out of range", col)
					}
					selCoeff := selectorCoeff[col]
					if i >= len(keySlots) {
						return ConstraintSet{}, fmt.Errorf("key slot %d out of range (%d)", i, len(keySlots))
					}
					slot := keySlots[i]
					if slot.Row < 0 || slot.Row >= len(rowsNTT) {
						return ConstraintSet{}, fmt.Errorf("key slot row %d out of range", slot.Row)
					}
					if slot.Coeff < 0 || slot.Coeff >= len(selectorCoeff) {
						return ConstraintSet{}, fmt.Errorf("key slot col %d out of range", slot.Coeff)
					}
					if slot.Coeff != col {
						return ConstraintSet{}, fmt.Errorf("key slot col %d mismatch for key %d (want %d)", slot.Coeff, i, col)
					}
					keyCoeff, err := getRowCoeff(slot.Row)
					if err != nil {
						return ConstraintSet{}, fmt.Errorf("key row coeffs: %w", err)
					}
					keyExtract := polyMul(selCoeff, keyCoeff, q)
					m2Extract := polyMul(selCoeff, m2CompCoeffs, q)
					resCoeff := polySub(keyExtract, m2Extract)
					keyBindCoeffs = append(keyBindCoeffs, resCoeff)
					keyBindRes = append(keyBindRes, nttPolyFromFormalCoeffsIfFits(ringQ, resCoeff))
				}
			} else {
				for i := 0; i < keyCount; i++ {
					col := half + i
					if col < 0 || col >= len(selectorTheta) {
						return ConstraintSet{}, fmt.Errorf("key binding selector col=%d out of range", col)
					}
					if i >= len(keySlots) {
						return ConstraintSet{}, fmt.Errorf("key slot %d out of range (%d)", i, len(keySlots))
					}
					slot := keySlots[i]
					if slot.Row < 0 || slot.Row >= len(rowsNTT) {
						return ConstraintSet{}, fmt.Errorf("key slot row %d out of range", slot.Row)
					}
					if slot.Coeff < 0 || slot.Coeff >= len(selectorTheta) {
						return ConstraintSet{}, fmt.Errorf("key slot col %d out of range", slot.Coeff)
					}
					if slot.Coeff != col {
						return ConstraintSet{}, fmt.Errorf("key slot col %d mismatch for key %d (want %d)", slot.Coeff, i, col)
					}
					keyRow := ringQ.NewPoly()
					ringQ.MulCoeffs(rowsNTT[slot.Row], selectorTheta[slot.Coeff], keyRow)
					m2Extract := ringQ.NewPoly()
					ringQ.MulCoeffs(selectorTheta[col], m2NTT, m2Extract)
					res := ringQ.NewPoly()
					ringQ.Sub(keyRow, m2Extract, res)
					keyBindRes = append(keyBindRes, res)
				}
			}
		}
	}

	fparInt := append(sigRes, hashRes...)
	fparInt = append(fparInt, m1Pack, m2Pack)
	fparInt = append(fparInt, carrierMemM, carrierMemCtr)
	fparInt = append(fparInt, keyBindRes...)
	var fparIntCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		fparIntCoeffs = append(fparIntCoeffs, sigResCoeffs...)
		fparIntCoeffs = append(fparIntCoeffs, hashResCoeffs...)
		fparIntCoeffs = append(fparIntCoeffs, m1PackCoeff, m2PackCoeff)
		fparIntCoeffs = append(fparIntCoeffs, memMCoeffs, memCtrCoeffs)
		fparIntCoeffs = append(fparIntCoeffs, keyBindCoeffs...)
		if len(fparIntCoeffs) != len(fparInt) {
			return ConstraintSet{}, fmt.Errorf("transform-bridge formal coeff mismatch: coeffs=%d polys=%d", len(fparIntCoeffs), len(fparInt))
		}
	}

	// Aggregated transform-bridge constraints.
	lagrangeBasis, err := buildLagrangeBasisCoeffs(omega, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("lagrange basis: %w", err)
	}
	required := blocks * ncols
	transformHCoeff, blockFactors, err := buildTransformBridgeHFromNTTMatrix(ringQ, omega, required)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("transform H matrix: %w", err)
	}
	if len(blockFactors) < required {
		return ConstraintSet{}, fmt.Errorf("block factors len=%d < required=%d", len(blockFactors), required)
	}
	transformHEval := transformHCoeff
	if len(transformHEval) > ncols {
		transformHEval = transformHEval[:ncols]
	}
	hThetaCoeff := make([]*ring.Poly, len(transformHCoeff))
	for j := range transformHCoeff {
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], transformHCoeff[j])
		ringQ.NTT(p, p)
		hThetaCoeff[j] = p
	}
	hThetaEval := make([]*ring.Poly, len(transformHEval))
	for j := range transformHEval {
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], transformHEval[j])
		ringQ.NTT(p, p)
		hThetaEval[j] = p
	}
	lagrangeTheta := make([]*ring.Poly, len(lagrangeBasis))
	for j := range lagrangeBasis {
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], lagrangeBasis[j])
		ringQ.NTT(p, p)
		lagrangeTheta[j] = p
	}

	var faggNorm []*ring.Poly
	var faggNormCoeffs [][]uint64
	for b := 0; b < blocks; b++ {
		for comp := 0; comp < uCount; comp++ {
			hatIdx, err := sigHatRow(b, comp)
			if err != nil {
				return ConstraintSet{}, err
			}
			for j := 0; j < ncols; j++ {
				t := b*ncols + j
				if t < 0 || t >= len(hThetaCoeff) {
					return ConstraintSet{}, fmt.Errorf("signature bridge index t=%d out of range (len=%d)", t, len(hThetaCoeff))
				}
				left := ringQ.NewPoly()
				factor := uint64(1)
				for bSrc := 0; bSrc < blocks; bSrc++ {
					srcIdx, err := sigSourceRow(bSrc, comp)
					if err != nil {
						return ConstraintSet{}, err
					}
					if srcIdx < 0 || srcIdx >= len(rowsNTT) {
						return ConstraintSet{}, fmt.Errorf("signature bridge row out of range (src=%d)", srcIdx)
					}
					tmp := ringQ.NewPoly()
					ringQ.MulCoeffs(rowsNTT[srcIdx], hThetaCoeff[t], tmp)
					factor = blockFactors[t][bSrc]
					if factor != 1 {
						ringQ.MulScalar(tmp, factor, tmp)
					}
					ringQ.Add(left, tmp, left)
				}
				right := ringQ.NewPoly()
				ringQ.MulCoeffs(rowsNTT[hatIdx], lagrangeTheta[j], right)
				ringQ.Sub(left, right, left)
				if domainMode == DomainModeExplicit {
					if getRowCoeff == nil {
						return ConstraintSet{}, fmt.Errorf("missing explicit coeff cache for signature bridge")
					}
					hatCoeff, err := getRowCoeff(hatIdx)
					if err != nil {
						return ConstraintSet{}, fmt.Errorf("sig bridge hat coeffs: %w", err)
					}
					leftCoeff := []uint64{0}
					for bSrc := 0; bSrc < blocks; bSrc++ {
						srcIdx, err := sigSourceRow(bSrc, comp)
						if err != nil {
							return ConstraintSet{}, err
						}
						srcCoeff, err := getRowCoeff(srcIdx)
						if err != nil {
							return ConstraintSet{}, fmt.Errorf("sig bridge src coeffs: %w", err)
						}
						term := polyMul(transformHCoeff[t], srcCoeff, q)
						factorCoeff := blockFactors[t][bSrc]
						if factorCoeff != 1 {
							term = scalePoly(term, factorCoeff, q)
						}
						leftCoeff = polyAdd(leftCoeff, term)
					}
					rightCoeff := polyMul(lagrangeBasis[j], hatCoeff, q)
					bridgeCoeff := polySub(leftCoeff, rightCoeff)
					faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
					faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
				} else {
					faggNorm = append(faggNorm, left)
				}
			}
		}
	}
	// Non-sign transform bridges: decoded rows -> hats.
	nonSigPairs := []struct {
		src *ring.Poly
		hat *ring.Poly
	}{
		{src: m1NTT, hat: mHat1},
		{src: m2NTT, hat: mHat2},
		{src: r0NTT, hat: rHat0},
		{src: r1NTT, hat: rHat1},
	}
	for _, pair := range nonSigPairs {
		for j := 0; j < ncols; j++ {
			left := ringQ.NewPoly()
			ringQ.MulCoeffs(pair.src, hThetaEval[j], left)
			right := ringQ.NewPoly()
			ringQ.MulCoeffs(pair.hat, lagrangeTheta[j], right)
			ringQ.Sub(left, right, left)
			if domainMode == DomainModeExplicit {
				if getRowCoeff == nil {
					return ConstraintSet{}, fmt.Errorf("missing explicit coeff cache for non-sign bridge")
				}
				var srcCoeff []uint64
				hatIdx := -1
				switch pair.hat {
				case mHat1:
					srcCoeff = m1CompCoeffs
					hatIdx = layout.IdxMHat1
				case mHat2:
					srcCoeff = m2CompCoeffs
					hatIdx = layout.IdxMHat2
				case rHat0:
					srcCoeff = r0CompCoeffs
					hatIdx = layout.IdxRHat0
				case rHat1:
					srcCoeff = r1CompCoeffs
					hatIdx = layout.IdxRHat1
				default:
					srcCoeff = []uint64{0}
				}
				if hatIdx < 0 {
					return ConstraintSet{}, fmt.Errorf("non-sig hat row missing for coeffs")
				}
				hatCoeff, err := getRowCoeff(hatIdx)
				if err != nil {
					return ConstraintSet{}, fmt.Errorf("non-sig hat coeffs: %w", err)
				}
				leftCoeff := polyMul(transformHEval[j], srcCoeff, q)
				rightCoeff := polyMul(lagrangeBasis[j], hatCoeff, q)
				bridgeCoeff := polySub(leftCoeff, rightCoeff)
				faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
				faggNorm = append(faggNorm, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
			} else {
				faggNorm = append(faggNorm, left)
			}
		}
	}
	_ = prfLayout

	parallelDeg := 2
	if deg := maxDegreeFromCoeffs(decode1); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(membershipPoly); deg > parallelDeg {
		parallelDeg = deg
	}
	aggDeg := 1
	if deg := maxDegreeFromCoeffs(decode1); deg > aggDeg {
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
