package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/fpoly"
)

func sumB2MulNTT(ringQ *ring.Ring, b2 []*ring.Poly, rows []*ring.Poly) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(b2) == 0 || len(rows) == 0 {
		return nil, fmt.Errorf("empty b2/rows")
	}
	if len(b2) != len(rows) {
		return nil, fmt.Errorf("b2 length=%d mismatches rows=%d", len(b2), len(rows))
	}
	acc := ringQ.NewPoly()
	tmp := ringQ.NewPoly()
	for i := range b2 {
		if b2[i] == nil || rows[i] == nil {
			return nil, fmt.Errorf("nil b2/row at index %d", i)
		}
		ringQ.MulCoeffs(b2[i], rows[i], tmp)
		ringQ.Add(acc, tmp, acc)
	}
	return acc, nil
}

func buildPackingSelectorNTT(ringQ *ring.Ring, omega []uint64) (*ring.Poly, *ring.Poly, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	if ncols <= 0 {
		return nil, nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	if ncols%2 != 0 {
		return nil, nil, fmt.Errorf("ncols %d not even for packing selector", ncols)
	}
	selCoeffs, err := buildPackingSelectorCoeff(ringQ, omega)
	if err != nil {
		return nil, nil, fmt.Errorf("interpolate selector: %w", err)
	}
	selCoeff := ringQ.NewPoly()
	copy(selCoeff.Coeffs[0], selCoeffs)
	selNTT := ringQ.NewPoly()
	ring.Copy(selCoeff, selNTT)
	ringQ.NTT(selNTT, selNTT)
	one := ringQ.NewPoly()
	one.Coeffs[0][0] = 1 % ringQ.Modulus[0]
	ringQ.NTT(one, one)
	oneMinus := ringQ.NewPoly()
	ringQ.Sub(one, selNTT, oneMinus)
	return selNTT, oneMinus, nil
}

func BuildTargetConstraintsRelationNTT(ringQ *ring.Ring, relation string, B []*ring.Poly, m1NTT, m2NTT *ring.Poly, r0NTT []*ring.Poly, zNTT, tNTT *ring.Poly) ([]*ring.Poly, error) {
	switch normalizePublicHashRelation(PublicInputs{HashRelation: relation}) {
	case credential.HashRelationBBTran:
		if ringQ == nil {
			return nil, fmt.Errorf("nil ring")
		}
		if m1NTT == nil || m2NTT == nil || len(r0NTT) == 0 || zNTT == nil || tNTT == nil {
			return nil, fmt.Errorf("nil bb_tran target input poly")
		}
		b0, b1, b2, _, err := credential.SplitBBTranB(B, len(r0NTT), 1)
		if err != nil {
			return nil, err
		}
		mCombined := ringQ.NewPoly()
		ring.Copy(m1NTT, mCombined)
		ringQ.Add(mCombined, m2NTT, mCombined)
		target := ringQ.NewPoly()
		tmp := ringQ.NewPoly()
		ring.Copy(b0, target)
		ringQ.MulCoeffs(b1, mCombined, tmp)
		ringQ.Add(target, tmp, target)
		r0Lin, err := sumB2MulNTT(ringQ, b2, r0NTT)
		if err != nil {
			return nil, err
		}
		ringQ.Add(target, r0Lin, target)
		ringQ.Add(target, zNTT, target)
		res := ringQ.NewPoly()
		ringQ.Sub(tNTT, target, res)
		return []*ring.Poly{res}, nil
	default:
		return nil, fmt.Errorf("unsupported target relation %q", relation)
	}
}

func BuildInverseConstraintsRelationNTT(ringQ *ring.Ring, relation string, B []*ring.Poly, r1NTT, zNTT *ring.Poly) ([]*ring.Poly, error) {
	switch normalizePublicHashRelation(PublicInputs{HashRelation: relation}) {
	case credential.HashRelationBBTran:
		if ringQ == nil {
			return nil, fmt.Errorf("nil ring")
		}
		if r1NTT == nil || zNTT == nil {
			return nil, fmt.Errorf("nil bb_tran inverse input poly")
		}
		x0Len := len(B) - 3
		_, _, _, b3, err := credential.SplitBBTranB(B, x0Len, 1)
		if err != nil {
			return nil, err
		}
		den := ringQ.NewPoly()
		ringQ.Sub(b3, r1NTT, den)
		res := ringQ.NewPoly()
		ringQ.MulCoeffs(den, zNTT, res)
		one := ringQ.NewPoly()
		one.Coeffs[0][0] = 1 % ringQ.Modulus[0]
		ringQ.NTT(one, one)
		ringQ.Sub(res, one, res)
		return []*ring.Poly{res}, nil
	default:
		return nil, fmt.Errorf("unsupported inverse relation %q", relation)
	}
}

// buildCredentialConstraintSetPreFromRows builds the pre-sign constraint set
// directly from the committed row polynomials (NTT domain). This ensures the
// constraint polynomials include the LVCS tails, matching the paper definition
// F_j(X) = f_j(P(X), Theta(X)) on the full polynomial P.
func buildCredentialConstraintSetPreFromRows(ringQ *ring.Ring, bound int64, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, domainMode DomainMode) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	q := ringQ.Modulus[0]
	if len(pub.Ac) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Ac")
	}
	if len(pub.Com) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Com")
	}
	if len(pub.RI0) == 0 || len(pub.RI1) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing RI0/RI1")
	}
	if len(pub.B) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing B for hash constraint")
	}
	if len(pub.T) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing public T coeffs for hash constraint")
	}

	useBBTran := publicUsesBBTran(pub)
	x0Len := pub.X0Len
	if x0Len <= 0 {
		x0Len = rowLayoutX0Len(layout)
	}
	if x0Len <= 0 {
		return ConstraintSet{}, fmt.Errorf("invalid x0 length %d", x0Len)
	}
	muMode := rowLayoutUsesMu(layout)
	fullMuMode := rowLayoutUsesFullMu(layout)
	carrierMuIdxs := rowLayoutCarrierMuBlockRows(layout)
	aliasMuIdxs := rowLayoutAliasMuBlockRows(layout)
	carrierRU0Idxs := rowLayoutPreSignCarrierRU0Rows(layout)
	carrierR0Idxs := rowLayoutPostSignCarrierR0Rows(layout)
	carrierK0Idxs := rowLayoutPreSignCarrierK0Rows(layout)
	ru0Idxs := rowLayoutPreSignRU0Rows(layout)
	r0Idxs := rowLayoutPostSignR0Rows(layout)
	k0Idxs := rowLayoutPreSignK0Rows(layout)
	rHat0Idxs := rowLayoutPostSignRHat0Rows(layout)
	if len(carrierRU0Idxs) != x0Len || len(carrierR0Idxs) != x0Len || len(carrierK0Idxs) != x0Len || len(ru0Idxs) != x0Len || len(r0Idxs) != x0Len || len(k0Idxs) != x0Len || len(rHat0Idxs) != x0Len {
		return ConstraintSet{}, fmt.Errorf("x0 row-layout mismatch: carrierRU0=%d carrierR0=%d carrierK0=%d aliasRU0=%d aliasR0=%d aliasK0=%d rHat0=%d want %d", len(carrierRU0Idxs), len(carrierR0Idxs), len(carrierK0Idxs), len(ru0Idxs), len(r0Idxs), len(k0Idxs), len(rHat0Idxs), x0Len)
	}
	required := []int{
		rowLayoutPostSignCarrierM(layout),
		rowLayoutPreSignCarrierRU1(layout),
		rowLayoutPreSignCarrierR(layout),
		rowLayoutPostSignCarrierR1(layout),
		rowLayoutPreSignCarrierK1(layout),
		rowLayoutPostSignM1(layout),
		rowLayoutPostSignM2(layout),
		rowLayoutPreSignRU1(layout),
		rowLayoutPostSignR(layout),
		rowLayoutPostSignR1(layout),
		rowLayoutPreSignK1(layout),
		rowLayoutPostSignMHat1(layout),
		rowLayoutPostSignMHat2(layout),
		rowLayoutPostSignRHat1(layout),
	}
	required = append(required, carrierRU0Idxs...)
	required = append(required, carrierMuIdxs...)
	required = append(required, aliasMuIdxs...)
	required = append(required, carrierR0Idxs...)
	required = append(required, carrierK0Idxs...)
	required = append(required, ru0Idxs...)
	required = append(required, r0Idxs...)
	required = append(required, k0Idxs...)
	required = append(required, rHat0Idxs...)
	if useBBTran {
		required = append(required, rowLayoutPostSignZHat(layout))
	}
	maxIdx := -1
	for _, idx := range required {
		if idx < 0 {
			return ConstraintSet{}, fmt.Errorf("invalid pre-sign row index %d", idx)
		}
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	if maxIdx >= len(rowsNTT) {
		return ConstraintSet{}, fmt.Errorf("rows length %d <= required pre-sign max index %d", len(rowsNTT), maxIdx)
	}

	var err error
	var msgDecode1, msgDecode2 []uint64
	if muMode {
		msgDecode1, err = buildSingletonCarrierDecodePoly(bound, q)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("mu carrier decode poly: %w", err)
		}
		msgDecode2 = []uint64{0}
	} else {
		msgDecode1, msgDecode2, err = buildPackedMessageCarrierDecodePolys(bound, q)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("message carrier decode polys: %w", err)
		}
	}
	x0Decode1, err := buildSingletonCarrierDecodePoly(pub.X0CoeffBound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("x0 carrier decode polys: %w", err)
	}
	scalarDecode1, _, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("scalar carrier decode polys: %w", err)
	}
	x0CarryDecode, err := buildSingletonCarrierDecodePoly(1, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("x0 carry decode polys: %w", err)
	}
	decode1K, _, err := buildCarrierDecodePolys(1, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier decode polys (K): %w", err)
	}
	var memMsg []uint64
	if muMode {
		memMsg, err = buildSingletonCarrierMembershipPoly(bound, q)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("mu carrier membership poly: %w", err)
		}
	} else {
		memMsg, err = buildPackedMessageCarrierMembershipPoly(bound, q)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("message carrier membership poly: %w", err)
		}
	}
	memX0, err := buildSingletonCarrierMembershipPoly(pub.X0CoeffBound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("x0 carrier membership poly: %w", err)
	}
	memScalar, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("scalar carrier membership poly: %w", err)
	}
	memX0Carry, err := buildSingletonCarrierMembershipPoly(1, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("x0 carry membership poly: %w", err)
	}
	memCarry, err := buildCarrierMembershipPoly(1, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier membership poly (K): %w", err)
	}

	rowCoeff := func(idx int, name string) ([]uint64, error) {
		coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[idx])
		if err != nil {
			return nil, fmt.Errorf("%s coeffs: %w", name, err)
		}
		return trimPoly(coeff, q), nil
	}
	rowCoeffSlice := func(indices []int, name string) ([][]uint64, error) {
		out := make([][]uint64, len(indices))
		for i, idx := range indices {
			coeff, err := rowCoeff(idx, fmt.Sprintf("%s[%d]", name, i))
			if err != nil {
				return nil, err
			}
			out[i] = coeff
		}
		return out, nil
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
		out := trimPoly(fpoly.New(q, decodeCoeff).Compose(fpoly.New(q, carrierCoeff)).Coeffs, q)
		return reducePolyModXN1(out, int(ringQ.N), q)
	}
	thetaFromCoeffs := func(coeffs []uint64, name string) (*ring.Poly, []uint64, error) {
		trimmed := trimPoly(coeffs, q)
		if domainMode == DomainModeExplicit {
			trimmed = reducePolyModXN1(trimmed, int(ringQ.N), q)
		}
		p := nttPolyFromFormalCoeffsIfFits(ringQ, trimmed)
		if p == nil {
			return nil, nil, fmt.Errorf("%s degree=%d exceeds ring dimension %d", name, len(trimmed)-1, ringQ.N)
		}
		return p, trimmed, nil
	}

	carrierMCoeff, err := rowCoeff(rowLayoutPostSignCarrierM(layout), "carrier M")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierMuCoeffs := [][]uint64{carrierMCoeff}
	if fullMuMode {
		carrierMuCoeffs, err = rowCoeffSlice(carrierMuIdxs, "carrier Mu")
		if err != nil {
			return ConstraintSet{}, err
		}
	}
	carrierRU1Coeff, err := rowCoeff(rowLayoutPreSignCarrierRU1(layout), "carrier RU1")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierRCoeff, err := rowCoeff(rowLayoutPreSignCarrierR(layout), "carrier R")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierR1Coeff, err := rowCoeff(rowLayoutPostSignCarrierR1(layout), "carrier R1")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierK1Coeff, err := rowCoeff(rowLayoutPreSignCarrierK1(layout), "carrier K1")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierRU0Coeffs, err := rowCoeffSlice(carrierRU0Idxs, "carrier RU0")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierR0Coeffs, err := rowCoeffSlice(carrierR0Idxs, "carrier R0")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierK0Coeffs, err := rowCoeffSlice(carrierK0Idxs, "carrier K0")
	if err != nil {
		return ConstraintSet{}, err
	}

	m1AliasCoeffs, err := rowCoeff(rowLayoutPostSignM1(layout), "alias M1")
	if err != nil {
		return ConstraintSet{}, err
	}
	aliasMuCoeffs := [][]uint64{m1AliasCoeffs}
	if fullMuMode {
		aliasMuCoeffs, err = rowCoeffSlice(aliasMuIdxs, "alias Mu")
		if err != nil {
			return ConstraintSet{}, err
		}
	}
	m2AliasCoeffs, err := rowCoeff(rowLayoutPostSignM2(layout), "alias M2")
	if err != nil {
		return ConstraintSet{}, err
	}
	ru1AliasCoeffs, err := rowCoeff(rowLayoutPreSignRU1(layout), "alias RU1")
	if err != nil {
		return ConstraintSet{}, err
	}
	rAliasCoeffs, err := rowCoeff(rowLayoutPostSignR(layout), "alias R")
	if err != nil {
		return ConstraintSet{}, err
	}
	r1AliasCoeffs, err := rowCoeff(rowLayoutPostSignR1(layout), "alias R1")
	if err != nil {
		return ConstraintSet{}, err
	}
	k1AliasCoeffs, err := rowCoeff(rowLayoutPreSignK1(layout), "alias K1")
	if err != nil {
		return ConstraintSet{}, err
	}
	ru0AliasCoeffs, err := rowCoeffSlice(ru0Idxs, "alias RU0")
	if err != nil {
		return ConstraintSet{}, err
	}
	r0AliasCoeffs, err := rowCoeffSlice(r0Idxs, "alias R0")
	if err != nil {
		return ConstraintSet{}, err
	}
	k0AliasCoeffs, err := rowCoeffSlice(k0Idxs, "alias K0")
	if err != nil {
		return ConstraintSet{}, err
	}
	mHat1Coeffs, err := rowCoeff(rowLayoutPostSignMHat1(layout), "hat M1")
	if err != nil {
		return ConstraintSet{}, err
	}
	mHat2Coeffs, err := rowCoeff(rowLayoutPostSignMHat2(layout), "hat M2")
	if err != nil {
		return ConstraintSet{}, err
	}
	rHat1Coeffs, err := rowCoeff(rowLayoutPostSignRHat1(layout), "hat R1")
	if err != nil {
		return ConstraintSet{}, err
	}
	rHat0Coeffs, err := rowCoeffSlice(rHat0Idxs, "hat R0")
	if err != nil {
		return ConstraintSet{}, err
	}
	var zHatCoeffs []uint64
	if useBBTran {
		zHatCoeffs, err = rowCoeff(rowLayoutPostSignZHat(layout), "bb_tran hat Z")
		if err != nil {
			return ConstraintSet{}, err
		}
	}

	m1CompCoeffs := composeLeft(carrierMCoeff, msgDecode1)
	muCompCoeffs := [][]uint64{m1CompCoeffs}
	if fullMuMode {
		muCompCoeffs = make([][]uint64, len(carrierMuCoeffs))
		for i := range carrierMuCoeffs {
			muCompCoeffs[i] = composeLeft(carrierMuCoeffs[i], msgDecode1)
		}
	}
	m2CompCoeffs := composeLeft(carrierMCoeff, msgDecode2)
	ru1CompCoeffs := composeLeft(carrierRU1Coeff, scalarDecode1)
	rCompCoeffs := composeLeft(carrierRCoeff, scalarDecode1)
	r1CompCoeffs := composeLeft(carrierR1Coeff, scalarDecode1)
	k1CompCoeffs := composeLeft(carrierK1Coeff, decode1K)
	ru0CompCoeffs := make([][]uint64, x0Len)
	r0CompCoeffs := make([][]uint64, x0Len)
	k0CompCoeffs := make([][]uint64, x0Len)
	for i := 0; i < x0Len; i++ {
		ru0CompCoeffs[i] = composeLeft(carrierRU0Coeffs[i], x0Decode1)
		r0CompCoeffs[i] = composeLeft(carrierR0Coeffs[i], x0Decode1)
		k0CompCoeffs[i] = composeLeft(carrierK0Coeffs[i], x0CarryDecode)
	}
	memMCoeffs := composeLeft(carrierMCoeff, memMsg)
	memMuCoeffs := [][]uint64{memMCoeffs}
	if fullMuMode {
		memMuCoeffs = make([][]uint64, len(carrierMuCoeffs))
		for i := range carrierMuCoeffs {
			memMuCoeffs[i] = composeLeft(carrierMuCoeffs[i], memMsg)
		}
	}
	memRU1Coeffs := composeLeft(carrierRU1Coeff, memScalar)
	memRCoeffs := composeLeft(carrierRCoeff, memScalar)
	memR1Coeffs := composeLeft(carrierR1Coeff, memScalar)
	memK1Coeffs := composeLeft(carrierK1Coeff, memCarry)
	memRU0Coeffs := make([][]uint64, x0Len)
	memR0Coeffs := make([][]uint64, x0Len)
	memK0Coeffs := make([][]uint64, x0Len)
	for i := 0; i < x0Len; i++ {
		memRU0Coeffs[i] = composeLeft(carrierRU0Coeffs[i], memX0)
		memR0Coeffs[i] = composeLeft(carrierR0Coeffs[i], memX0)
		memK0Coeffs[i] = composeLeft(carrierK0Coeffs[i], memX0Carry)
	}

	var bridgeMu []*ring.Poly
	if fullMuMode {
		bridgeMu = make([]*ring.Poly, len(aliasMuCoeffs))
		for i := range aliasMuCoeffs {
			bridgeMu[i], _, err = thetaFromCoeffs(fpoly.New(q, aliasMuCoeffs[i]).Sub(fpoly.New(q, muCompCoeffs[i])).Coeffs, fmt.Sprintf("bridge Mu[%d]", i))
			if err != nil {
				return ConstraintSet{}, err
			}
		}
	} else {
		var bridgeM1 *ring.Poly
		bridgeM1, _, err = thetaFromCoeffs(fpoly.New(q, m1AliasCoeffs).Sub(fpoly.New(q, m1CompCoeffs)).Coeffs, "bridge M1")
		if err != nil {
			return ConstraintSet{}, err
		}
		bridgeMu = []*ring.Poly{bridgeM1}
	}
	bridgeM2, _, err := thetaFromCoeffs(fpoly.New(q, m2AliasCoeffs).Sub(fpoly.New(q, m2CompCoeffs)).Coeffs, "bridge M2")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeRU1, _, err := thetaFromCoeffs(fpoly.New(q, ru1AliasCoeffs).Sub(fpoly.New(q, ru1CompCoeffs)).Coeffs, "bridge RU1")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeR, _, err := thetaFromCoeffs(fpoly.New(q, rAliasCoeffs).Sub(fpoly.New(q, rCompCoeffs)).Coeffs, "bridge R")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeR1, _, err := thetaFromCoeffs(fpoly.New(q, r1AliasCoeffs).Sub(fpoly.New(q, r1CompCoeffs)).Coeffs, "bridge R1")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeK1, _, err := thetaFromCoeffs(fpoly.New(q, k1AliasCoeffs).Sub(fpoly.New(q, k1CompCoeffs)).Coeffs, "bridge K1")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeRU0 := make([]*ring.Poly, x0Len)
	bridgeR0 := make([]*ring.Poly, x0Len)
	bridgeK0 := make([]*ring.Poly, x0Len)
	for i := 0; i < x0Len; i++ {
		bridgeRU0[i], _, err = thetaFromCoeffs(fpoly.New(q, ru0AliasCoeffs[i]).Sub(fpoly.New(q, ru0CompCoeffs[i])).Coeffs, fmt.Sprintf("bridge RU0[%d]", i))
		if err != nil {
			return ConstraintSet{}, err
		}
		bridgeR0[i], _, err = thetaFromCoeffs(fpoly.New(q, r0AliasCoeffs[i]).Sub(fpoly.New(q, r0CompCoeffs[i])).Coeffs, fmt.Sprintf("bridge R0[%d]", i))
		if err != nil {
			return ConstraintSet{}, err
		}
		bridgeK0[i], _, err = thetaFromCoeffs(fpoly.New(q, k0AliasCoeffs[i]).Sub(fpoly.New(q, k0CompCoeffs[i])).Coeffs, fmt.Sprintf("bridge K0[%d]", i))
		if err != nil {
			return ConstraintSet{}, err
		}
	}

	m1NTT := rowsNTT[rowLayoutPostSignM1(layout)]
	m2NTT := rowsNTT[rowLayoutPostSignM2(layout)]
	ru1NTT := rowsNTT[rowLayoutPreSignRU1(layout)]
	rNTT := rowsNTT[rowLayoutPostSignR(layout)]
	r1NTT := rowsNTT[rowLayoutPostSignR1(layout)]
	k1NTT := rowsNTT[rowLayoutPreSignK1(layout)]
	mHat1NTT := rowsNTT[rowLayoutPostSignMHat1(layout)]
	mHat2NTT := rowsNTT[rowLayoutPostSignMHat2(layout)]
	rHat1NTT := rowsNTT[rowLayoutPostSignRHat1(layout)]
	ru0NTTs := make([]*ring.Poly, x0Len)
	r0NTTs := make([]*ring.Poly, x0Len)
	k0NTTs := make([]*ring.Poly, x0Len)
	rHat0NTTs := make([]*ring.Poly, x0Len)
	for i := 0; i < x0Len; i++ {
		ru0NTTs[i] = rowsNTT[ru0Idxs[i]]
		r0NTTs[i] = rowsNTT[r0Idxs[i]]
		k0NTTs[i] = rowsNTT[k0Idxs[i]]
		rHat0NTTs[i] = rowsNTT[rHat0Idxs[i]]
	}
	var zHatNTT *ring.Poly
	if useBBTran {
		zHatNTT = rowsNTT[rowLayoutPostSignZHat(layout)]
	}
	mSourceCoeffs := m1AliasCoeffs
	if fullMuMode {
		mSourceCoeffs, err = assembleFullCoeffFromAliasBlocks(aliasMuCoeffs, omega, int(ringQ.N), q)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("assemble full mu coeffs: %w", err)
		}
	}
	mSourceNTT := m1NTT
	if fullMuMode {
		mSourceNTT = nttPolyFromFormalCoeffsIfFits(ringQ, mSourceCoeffs)
		if mSourceNTT == nil {
			return ConstraintSet{}, fmt.Errorf("full mu source degree=%d exceeds ring dimension %d", len(mSourceCoeffs)-1, ringQ.N)
		}
	}

	thetaAc := make([][]*ring.Poly, len(pub.Ac))
	for i := range pub.Ac {
		thetaAc[i] = make([]*ring.Poly, len(pub.Ac[i]))
		for j := range pub.Ac[i] {
			theta, terr := thetaPolyFromNTT(ringQ, pub.Ac[i][j], omega)
			if terr != nil {
				return ConstraintSet{}, fmt.Errorf("theta Ac[%d][%d]: %w", i, j, terr)
			}
			thetaAc[i][j] = theta
		}
	}
	thetaCom := make([]*ring.Poly, len(pub.Com))
	for i := range pub.Com {
		theta, terr := thetaPolyFromNTT(ringQ, pub.Com[i], omega)
		if terr != nil {
			return ConstraintSet{}, fmt.Errorf("theta Com[%d]: %w", i, terr)
		}
		thetaCom[i] = theta
	}
	thetaRI0 := make([]*ring.Poly, x0Len)
	for i := 0; i < x0Len; i++ {
		theta, err := thetaPolyFromNTT(ringQ, pub.RI0[i], omega)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("theta RI0[%d]: %w", i, err)
		}
		thetaRI0[i] = theta
	}
	thetaRI1, err := thetaPolyFromNTT(ringQ, pub.RI1[0], omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("theta RI1: %w", err)
	}
	thetaB := make([]*ring.Poly, len(pub.B))
	for i := range pub.B {
		theta, terr := thetaPolyFromNTT(ringQ, pub.B[i], omega)
		if terr != nil {
			return ConstraintSet{}, fmt.Errorf("theta B[%d]: %w", i, terr)
		}
		thetaB[i] = theta
	}
	publicTTheta, err := thetaPolyFromCoeff(ringQ, pub.T, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("theta public T: %w", err)
	}

	commitWitness := []*ring.Poly{mSourceNTT}
	if !muMode {
		commitWitness = append(commitWitness, m2NTT)
	}
	commitWitness = append(commitWitness, ru0NTTs...)
	commitWitness = append(commitWitness, ru1NTT, rNTT)
	commitAc := thetaAc
	commitCom := thetaCom
	if fullMuMode {
		commitAc = pub.Ac
		commitCom = pub.Com
	}
	comRes, err := BuildCommitConstraints(ringQ, commitAc, commitWitness, commitCom)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("commit residuals: %w", err)
	}

	centerWrapResidual := func(ru, ri, rVal, kVal *ring.Poly, delta uint64) (*ring.Poly, error) {
		if ru == nil || ri == nil || rVal == nil || kVal == nil {
			return nil, fmt.Errorf("nil center-wrap input poly")
		}
		res := ringQ.NewPoly()
		ringQ.Add(ru, ri, res)
		ringQ.Sub(res, rVal, res)
		tmp := ringQ.NewPoly()
		scalePolyNTT(ringQ, kVal, delta, tmp)
		ringQ.Sub(res, tmp, res)
		return res, nil
	}
	centerRes := make([]*ring.Poly, 0, x0Len+1)
	for i := 0; i < x0Len; i++ {
		res, err := centerWrapResidual(ru0NTTs[i], thetaRI0[i], r0NTTs[i], k0NTTs[i], uint64(2*pub.X0CoeffBound+1))
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("center wrap residual x0[%d]: %w", i, err)
		}
		centerRes = append(centerRes, res)
	}
	res1, err := centerWrapResidual(ru1NTT, thetaRI1, r1NTT, k1NTT, uint64(2*bound+1))
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 1: %w", err)
	}
	centerRes = append(centerRes, res1)

	if ncols%2 != 0 {
		return ConstraintSet{}, fmt.Errorf("ncols %d is not even for packing", ncols)
	}
	var m1Pack, m2Pack *ring.Poly
	if !muMode {
		selNTT, oneMinusSel, err := buildPackingSelectorNTT(ringQ, omega)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("packing selector: %w", err)
		}
		m1Pack = ringQ.NewPoly()
		m2Pack = ringQ.NewPoly()
		ringQ.MulCoeffs(selNTT, m1NTT, m1Pack)
		ringQ.MulCoeffs(oneMinusSel, m2NTT, m2Pack)
	}

	var hashRes []*ring.Poly
	if domainMode == DomainModeExplicit {
		thetaBCoeffs := make([][]uint64, len(thetaB))
		for i := range thetaB {
			coeff, cerr := coeffFromNTTPoly(ringQ, thetaB[i])
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("theta B[%d] coeffs: %w", i, cerr)
			}
			thetaBCoeffs[i] = trimPoly(coeff, q)
		}
		tThetaCoeff, cerr := coeffFromNTTPoly(ringQ, publicTTheta)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("theta public T coeffs: %w", cerr)
		}
		tThetaTrimmed := trimPoly(tThetaCoeff, q)
		targetHead := make([]uint64, len(omega))
		for i, x := range omega {
			x %= q
			mCombinedVal := EvalPoly(mSourceCoeffs, x, q) % q
			if fullMuMode {
				mCombinedVal = EvalPoly(mHat1Coeffs, x, q) % q
			}
			if !muMode {
				mCombinedVal = modAdd(mCombinedVal, EvalPoly(mHat2Coeffs, x, q)%q, q)
			}
			r0Vals := make([]uint64, len(rHat0Coeffs))
			for j := range rHat0Coeffs {
				r0Vals[j] = EvalPoly(rHat0Coeffs[j], x, q) % q
			}
			zVal := EvalPoly(zHatCoeffs, x, q) % q
			tVal := EvalPoly(tThetaTrimmed, x, q) % q
			targetHead[i] = transformTargetResidualCombinedEvalVector(q, x, pub.HashRelation, thetaBCoeffs, mCombinedVal, r0Vals, zVal, tVal)
		}
		targetCoeff := trimPoly(Interpolate(omega, targetHead, q), q)
		pTarget := nttPolyFromFormalCoeffsIfFits(ringQ, targetCoeff)
		if pTarget == nil {
			return ConstraintSet{}, fmt.Errorf("pre-sign explicit target degree=%d exceeds ring dimension %d", len(targetCoeff)-1, ringQ.N)
		}
		hashRes = append(hashRes, pTarget)
		if useBBTran {
			inverseHead := make([]uint64, len(omega))
			for i, x := range omega {
				x %= q
				b3 := EvalPoly(thetaBCoeffs[len(thetaBCoeffs)-1], x, q) % q
				r1v := EvalPoly(rHat1Coeffs, x, q) % q
				zv := EvalPoly(zHatCoeffs, x, q) % q
				res := modSub(b3, r1v, q)
				res = modMul(res, zv, q)
				inverseHead[i] = modSub(res, 1, q)
			}
			inverseCoeff := trimPoly(Interpolate(omega, inverseHead, q), q)
			pInverse := nttPolyFromFormalCoeffsIfFits(ringQ, inverseCoeff)
			if pInverse == nil {
				return ConstraintSet{}, fmt.Errorf("pre-sign explicit inverse degree=%d exceeds ring dimension %d", len(inverseCoeff)-1, ringQ.N)
			}
			hashRes = append(hashRes, pInverse)
		}
	} else {
		targetRes, err := BuildTargetConstraintsRelationNTT(ringQ, pub.HashRelation, thetaB, m1NTT, m2NTT, r0NTTs, zHatNTT, publicTTheta)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("target residuals: %w", err)
		}
		hashRes = append(hashRes, targetRes...)
		if useBBTran {
			inverseRes, err := BuildInverseConstraintsRelationNTT(ringQ, pub.HashRelation, thetaB, r1NTT, zHatNTT)
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("inverse residuals: %w", err)
			}
			hashRes = append(hashRes, inverseRes...)
		}
	}

	fparBounds := make([]*ring.Poly, 0, 4+3*x0Len)
	addBoundPoly := func(coeffs []uint64, name string) error {
		p, _, err := thetaFromCoeffs(coeffs, name)
		if err != nil {
			return err
		}
		fparBounds = append(fparBounds, p)
		return nil
	}
	for i := range memMuCoeffs {
		if err := addBoundPoly(memMuCoeffs[i], fmt.Sprintf("membership Mu[%d]", i)); err != nil {
			return ConstraintSet{}, err
		}
	}
	if err := addBoundPoly(memRU1Coeffs, "membership RU1"); err != nil {
		return ConstraintSet{}, err
	}
	if err := addBoundPoly(memRCoeffs, "membership R"); err != nil {
		return ConstraintSet{}, err
	}
	if err := addBoundPoly(memR1Coeffs, "membership R1"); err != nil {
		return ConstraintSet{}, err
	}
	for i := 0; i < x0Len; i++ {
		if err := addBoundPoly(memRU0Coeffs[i], fmt.Sprintf("membership RU0[%d]", i)); err != nil {
			return ConstraintSet{}, err
		}
		if err := addBoundPoly(memR0Coeffs[i], fmt.Sprintf("membership R0[%d]", i)); err != nil {
			return ConstraintSet{}, err
		}
	}
	for i := 0; i < x0Len; i++ {
		if err := addBoundPoly(memK0Coeffs[i], fmt.Sprintf("membership K0[%d]", i)); err != nil {
			return ConstraintSet{}, err
		}
	}
	if err := addBoundPoly(memK1Coeffs, "membership K1"); err != nil {
		return ConstraintSet{}, err
	}
	fparBoundsCoeffs := make([][]uint64, 0, len(fparBounds))
	for i, p := range fparBounds {
		coeff, cerr := coeffFromNTTPoly(ringQ, p)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("pre-sign norm coeffs[%d]: %w", i, cerr)
		}
		fparBoundsCoeffs = append(fparBoundsCoeffs, trimPoly(coeff, q))
	}

	parallelDeg := 2
	for _, coeffs := range [][]uint64{x0Decode1, scalarDecode1, decode1K, memX0, memScalar, memCarry} {
		if deg := maxDegreeFromCoeffs(coeffs); deg > parallelDeg {
			parallelDeg = deg
		}
	}

	fparInt := append([]*ring.Poly{}, bridgeMu...)
	if !muMode {
		fparInt = append(fparInt, bridgeM2)
	}
	fparInt = append(fparInt, bridgeRU0...)
	fparInt = append(fparInt, bridgeRU1, bridgeR)
	fparInt = append(fparInt, bridgeR0...)
	fparInt = append(fparInt, bridgeR1)
	fparInt = append(fparInt, bridgeK0...)
	fparInt = append(fparInt, bridgeK1)
	fparInt = append(fparInt, comRes...)
	fparInt = append(fparInt, centerRes...)
	fparInt = append(fparInt, hashRes...)
	if !muMode {
		fparInt = append(fparInt, m1Pack, m2Pack)
	}
	fparIntCoeffs := make([][]uint64, 0, len(fparInt))
	for i, p := range fparInt {
		coeff, cerr := coeffFromNTTPoly(ringQ, p)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("pre-sign int coeffs[%d]: %w", i, cerr)
		}
		fparIntCoeffs = append(fparIntCoeffs, trimPoly(coeff, q))
	}

	lagrangeBasis, err := buildLagrangeBasisCoeffs(omega, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("pre-sign lagrange basis: %w", err)
	}
	bridgeBasis, err := newRowTransformBridgeBasisCache(ringQ, omega, ncols)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("pre-sign transform H: %w", err)
	}
	var fullMuBridgeBasis *transformBridgeBasisCache
	if fullMuMode {
		fullMuBridgeBasis, err = newTransformBridgeBasisCache(ringQ, omega, ncols, len(aliasMuCoeffs))
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("pre-sign full mu transform H: %w", err)
		}
	}
	transformHCoeff := bridgeBasis.TransformH
	hThetaEval := make([]*ring.Poly, ncols)
	lagrangeTheta := make([]*ring.Poly, ncols)
	for j := 0; j < ncols; j++ {
		hp := ringQ.NewPoly()
		copy(hp.Coeffs[0], transformHCoeff[j])
		ringQ.NTT(hp, hp)
		hThetaEval[j] = hp
		lp := ringQ.NewPoly()
		copy(lp.Coeffs[0], lagrangeBasis[j])
		ringQ.NTT(lp, lp)
		lagrangeTheta[j] = lp
	}
	type bridgePair struct {
		srcNTT   *ring.Poly
		hatNTT   *ring.Poly
		srcCoeff []uint64
		hatCoeff []uint64
	}
	faggNorm := make([]*ring.Poly, 0, (x0Len+3)*ncols)
	faggNormCoeffs := make([][]uint64, 0, (x0Len+3)*ncols)
	if fullMuMode {
		for j := 0; j < ncols; j++ {
			leftCoeff := []uint64{0}
			for block := range aliasMuCoeffs {
				term := reducePolyModXN1(polyMul(fullMuBridgeBasis.TransformH[j], aliasMuCoeffs[block], q), int(ringQ.N), q)
				scale := fullMuBridgeBasis.BlockFactors[j][block] % q
				if scale != 1 {
					term = scalePoly(term, scale, q)
				}
				leftCoeff = polyAdd(leftCoeff, term, q)
			}
			rightCoeff := reducePolyModXN1(polyMul(fullMuBridgeBasis.LagrangeBasis[j], mHat1Coeffs, q), int(ringQ.N), q)
			bridgeCoeff := reducePolyModXN1(polySub(leftCoeff, rightCoeff, q), int(ringQ.N), q)
			p := nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff)
			if p == nil {
				return ConstraintSet{}, fmt.Errorf("pre-sign full mu transform bridge degree=%d exceeds ring dimension %d", len(bridgeCoeff)-1, ringQ.N)
			}
			faggNorm = append(faggNorm, p)
			faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
		}
	}
	bridgePairs := []bridgePair{
		{srcNTT: r1NTT, hatNTT: rHat1NTT, srcCoeff: r1AliasCoeffs, hatCoeff: rHat1Coeffs},
	}
	if !muMode {
		bridgePairs = append([]bridgePair{
			{srcNTT: m1NTT, hatNTT: mHat1NTT, srcCoeff: m1AliasCoeffs, hatCoeff: mHat1Coeffs},
			{srcNTT: m2NTT, hatNTT: mHat2NTT, srcCoeff: m2AliasCoeffs, hatCoeff: mHat2Coeffs},
		}, bridgePair{srcNTT: r1NTT, hatNTT: rHat1NTT, srcCoeff: r1AliasCoeffs, hatCoeff: rHat1Coeffs})
	} else if !fullMuMode {
		bridgePairs = append([]bridgePair{
			{srcNTT: m1NTT, hatNTT: mHat1NTT, srcCoeff: m1AliasCoeffs, hatCoeff: mHat1Coeffs},
		}, bridgePairs...)
	}
	for i := 0; i < x0Len; i++ {
		bridgePairs = append(bridgePairs, bridgePair{srcNTT: r0NTTs[i], hatNTT: rHat0NTTs[i], srcCoeff: r0AliasCoeffs[i], hatCoeff: rHat0Coeffs[i]})
	}
	for _, pair := range bridgePairs {
		for j := 0; j < ncols; j++ {
			if domainMode == DomainModeExplicit {
				bridgeCoeff := reducePolyModXN1(buildTransformBridgeResidualCoeff(q, transformHCoeff[j], lagrangeBasis[j], pair.srcCoeff, pair.hatCoeff), int(ringQ.N), q)
				p := nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff)
				if p == nil {
					return ConstraintSet{}, fmt.Errorf("pre-sign transform bridge degree=%d exceeds ring dimension %d", len(bridgeCoeff)-1, ringQ.N)
				}
				faggNorm = append(faggNorm, p)
				faggNormCoeffs = append(faggNormCoeffs, bridgeCoeff)
				continue
			}
			left := ringQ.NewPoly()
			ringQ.MulCoeffs(pair.srcNTT, hThetaEval[j], left)
			right := ringQ.NewPoly()
			ringQ.MulCoeffs(pair.hatNTT, lagrangeTheta[j], right)
			ringQ.Sub(left, right, left)
			faggNorm = append(faggNorm, left)
		}
	}
	return ConstraintSet{
		FparInt:          fparInt,
		FparIntCoeffs:    fparIntCoeffs,
		FparNorm:         fparBounds,
		FparNormCoeffs:   fparBoundsCoeffs,
		FaggNorm:         faggNorm,
		FaggNormCoeffs:   faggNormCoeffs,
		ParallelAlgDeg:   parallelDeg,
		AggregatedAlgDeg: 1,
	}, nil
}

// buildCredentialConstraintSetPostFromRows builds the post-sign constraint set
// (signature, hash, packing, bounds) directly from committed row polynomials
// in NTT form. Row order is assumed to be:
// M1,M2,RU0,RU1,R,R0,R1,K0,K1,T,U...
func buildCredentialConstraintSetPostFromRows(ringQ *ring.Ring, bound int64, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, domainMode DomainMode, opts SimOpts, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	if rowLayoutHasCoeffNativeSig(layout) {
		return buildCredentialConstraintSetPostCoeffNative(ringQ, bound, pub, layout, rowsNTT, omega, domainMode, opts, prfLayout, prfCompanionLayout)
	}
	return ConstraintSet{}, fmt.Errorf("only coeff-native showing layouts are supported")
}
