package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/internal/fpoly"
	"vSIS-Signature/prf"
)

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

// buildDeltaSelectorNTT returns the Ω selector polynomial Sel_col(X) in NTT form,
// where Sel_col(ω_k)=1 iff k==col and 0 otherwise (for k in [0..ncols-1]).
// Sel_col is a public Θ polynomial of degree < ncols.
func buildDeltaSelectorNTT(ringQ *ring.Ring, omega []uint64, col int) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	if col < 0 || col >= ncols {
		return nil, fmt.Errorf("invalid selector col=%d for ncols=%d", col, ncols)
	}
	q := ringQ.Modulus[0]
	vals := make([]uint64, ncols)
	vals[col] = 1 % q
	coeffs := Interpolate(omega, vals, q)
	out := ringQ.NewPoly()
	copy(out.Coeffs[0], coeffs)
	ringQ.NTT(out, out)
	return out, nil
}

// BuildHashConstraints (pre-sign, paper form) enforces the cleared-denominator
// BBS equation with public T:
//
//	(B3 - R1) ⊙ T  -  (B0 + B1·(M1+M2) + B2·R0) = 0
//
// Inputs B must be in NTT; witness polys are in coeff domain; T is provided as
// coeff slice. Returns a single residual poly in NTT.
func BuildHashConstraints(ringQ *ring.Ring, B []*ring.Poly, m1, m2, r0, r1 *ring.Poly, tCoeff []int64) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(B) != 4 {
		return nil, fmt.Errorf("b must have 4 polys, got %d", len(B))
	}
	if m1 == nil || m2 == nil || r0 == nil || r1 == nil {
		return nil, fmt.Errorf("nil hash input poly")
	}
	if len(tCoeff) != ringQ.N {
		return nil, fmt.Errorf("t length mismatch: got %d want %d", len(tCoeff), ringQ.N)
	}
	qMod := ringQ.Modulus[0]
	q := int64(qMod)
	// Build T in NTT.
	tPoly := ringQ.NewPoly()
	for i := 0; i < ringQ.N; i++ {
		v := tCoeff[i]
		if v < 0 {
			v += q
		}
		tPoly.Coeffs[0][i] = uint64(v % q)
	}
	ringQ.NTT(tPoly, tPoly)
	// mCombined = m1 + m2 (coeff), then NTT.
	mCombined := ringQ.NewPoly()
	ring.Copy(m1, mCombined)
	ringQ.Add(mCombined, m2, mCombined)
	ringQ.NTT(mCombined, mCombined)
	r0NTT := ringQ.NewPoly()
	r1NTT := ringQ.NewPoly()
	ring.Copy(r0, r0NTT)
	ring.Copy(r1, r1NTT)
	ringQ.NTT(r0NTT, r0NTT)
	ringQ.NTT(r1NTT, r1NTT)
	// num = B0 + B1*(m1+m2) + B2*r0
	num := ringQ.NewPoly()
	tmp := ringQ.NewPoly()
	ring.Copy(B[0], num)
	ringQ.MulCoeffs(B[1], mCombined, tmp)
	ringQ.Add(num, tmp, num)
	ringQ.MulCoeffs(B[2], r0NTT, tmp)
	ringQ.Add(num, tmp, num)
	// den = B3 - r1
	den := ringQ.NewPoly()
	ringQ.Sub(B[3], r1NTT, den)
	// res = den ⊙ T - num
	res := ringQ.NewPoly()
	ringQ.MulCoeffs(den, tPoly, res)
	ringQ.Sub(res, num, res)
	return []*ring.Poly{res}, nil
}

// BuildHashConstraintsNTT enforces the cleared-denominator BBS equation using
// all inputs in the evaluation domain (NTT). This is used for post-signature
// proofs where T is a witness row.
func BuildHashConstraintsNTT(ringQ *ring.Ring, B []*ring.Poly, m1NTT, m2NTT, r0NTT, r1NTT, tNTT *ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(B) != 4 {
		return nil, fmt.Errorf("b must have 4 polys, got %d", len(B))
	}
	if m1NTT == nil || m2NTT == nil || r0NTT == nil || r1NTT == nil || tNTT == nil {
		return nil, fmt.Errorf("nil hash input poly")
	}
	// mCombined = m1 + m2 (NTT).
	mCombined := ringQ.NewPoly()
	ring.Copy(m1NTT, mCombined)
	ringQ.Add(mCombined, m2NTT, mCombined)
	// num = B0 + B1*(m1+m2) + B2*r0
	num := ringQ.NewPoly()
	tmp := ringQ.NewPoly()
	ring.Copy(B[0], num)
	ringQ.MulCoeffs(B[1], mCombined, tmp)
	ringQ.Add(num, tmp, num)
	ringQ.MulCoeffs(B[2], r0NTT, tmp)
	ringQ.Add(num, tmp, num)
	// den = B3 - r1
	den := ringQ.NewPoly()
	ringQ.Sub(B[3], r1NTT, den)
	// res = den ⊙ T - num
	res := ringQ.NewPoly()
	ringQ.MulCoeffs(den, tNTT, res)
	ringQ.Sub(res, num, res)
	return []*ring.Poly{res}, nil
}

// BuildSignatureConstraintNTT builds residual polys for A·U - T with all
// inputs in the evaluation domain (NTT).
func BuildSignatureConstraintNTT(ringQ *ring.Ring, A [][]*ring.Poly, U []*ring.Poly, tNTT *ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(A) == 0 || len(U) == 0 {
		return nil, fmt.Errorf("empty A or U")
	}
	if tNTT == nil {
		return nil, fmt.Errorf("nil T")
	}
	rows := len(A)
	cols := len(A[0])
	if len(U) != cols {
		return nil, fmt.Errorf("u length mismatch: got %d want %d", len(U), cols)
	}
	residuals := make([]*ring.Poly, rows)
	tmp := ringQ.NewPoly()
	for i := 0; i < rows; i++ {
		acc := ringQ.NewPoly()
		for j := 0; j < cols; j++ {
			ringQ.MulCoeffs(A[i][j], U[j], tmp)
			ringQ.Add(acc, tmp, acc)
		}
		ringQ.Sub(acc, tNTT, acc)
		residuals[i] = acc
	}
	return residuals, nil
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
	// Row order defaults to: M1,M2,RU0,RU1,R,R0,R1,K0,K1,(optional T/U...).
	m1Idx := rowLayoutPostSignM1(layout)
	m2Idx := rowLayoutPostSignM2(layout)
	ru0Idx := rowLayoutPreSignRU0(layout)
	ru1Idx := rowLayoutPreSignRU1(layout)
	rIdx := rowLayoutPostSignR(layout)
	r0Idx := rowLayoutPostSignR0(layout)
	r1Idx := rowLayoutPostSignR1(layout)
	k0Idx := rowLayoutPreSignK0(layout)
	k1Idx := rowLayoutPreSignK1(layout)
	rowIdxs := []int{m1Idx, m2Idx, ru0Idx, ru1Idx, rIdx, r0Idx, r1Idx, k0Idx, k1Idx}
	maxIdx := -1
	for _, idx := range rowIdxs {
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

	m1NTT := rowsNTT[m1Idx]
	m2NTT := rowsNTT[m2Idx]
	ru0NTT := rowsNTT[ru0Idx]
	ru1NTT := rowsNTT[ru1Idx]
	rNTT := rowsNTT[rIdx]
	r0NTT := rowsNTT[r0Idx]
	r1NTT := rowsNTT[r1Idx]
	k0NTT := rowsNTT[k0Idx]
	k1NTT := rowsNTT[k1Idx]

	// Interpolate public polynomials over Ω so constraint evaluation at K-points
	// uses Θ(X) (degree < ncols), not full ring polynomials.
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
	thetaRI0, err := thetaPolyFromNTT(ringQ, pub.RI0[0], omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("theta RI0: %w", err)
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

	// Commit residuals: Ac·[M1||M2||RU0||RU1||R] - Com.
	vec := []*ring.Poly{m1NTT, m2NTT, ru0NTT, ru1NTT, rNTT}
	comRes, err := BuildCommitConstraints(ringQ, thetaAc, vec, thetaCom)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("commit residuals: %w", err)
	}
	toFormalCoeffs := func(p *ring.Poly) ([]uint64, error) {
		coeff, err := coeffFromNTTPoly(ringQ, p)
		if err != nil {
			return nil, err
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
		copy(out, a)
		for i := 0; i < len(b); i++ {
			out[i] = modAdd(out[i], b[i]%q, q)
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
		copy(out, a)
		for i := 0; i < len(b); i++ {
			out[i] = modSub(out[i], b[i]%q, q)
		}
		return trimPoly(out, q)
	}
	var comResCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		comResCoeffs = make([][]uint64, len(thetaAc))
		vecCoeffs := make([][]uint64, len(vec))
		for j := 0; j < len(vec); j++ {
			coeff, cerr := toFormalCoeffs(vec[j])
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("commit vec coeffs[%d]: %w", j, cerr)
			}
			vecCoeffs[j] = coeff
		}
		for i := 0; i < len(thetaAc); i++ {
			acc := []uint64{0}
			for j := 0; j < len(thetaAc[i]); j++ {
				aCoeff, cerr := toFormalCoeffs(thetaAc[i][j])
				if cerr != nil {
					return ConstraintSet{}, fmt.Errorf("commit theta Ac[%d][%d] coeffs: %w", i, j, cerr)
				}
				acc = polyAdd(acc, polyMul(aCoeff, vecCoeffs[j], q))
			}
			comCoeff, cerr := toFormalCoeffs(thetaCom[i])
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("commit theta Com[%d] coeffs: %w", i, cerr)
			}
			comResCoeffs[i] = polySub(acc, comCoeff)
		}
	}

	centerWrapResidual := func(ru, ri, rVal, kVal *ring.Poly) (*ring.Poly, error) {
		if ru == nil || ri == nil || rVal == nil || kVal == nil {
			return nil, fmt.Errorf("nil center-wrap input poly")
		}
		if bound <= 0 {
			return nil, fmt.Errorf("invalid bound %d", bound)
		}
		q := ringQ.Modulus[0]
		delta := uint64((2*bound + 1) % int64(q))
		// res = RU + RI - R - delta*K   (all in NTT / evaluation domain)
		res := ringQ.NewPoly()
		ringQ.Add(ru, ri, res)
		ringQ.Sub(res, rVal, res)
		tmp := ringQ.NewPoly()
		scalePolyNTT(ringQ, kVal, delta, tmp)
		ringQ.Sub(res, tmp, res)
		return res, nil
	}

	// Center residuals.
	centerRes0, err := centerWrapResidual(ru0NTT, thetaRI0, r0NTT, k0NTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 0: %w", err)
	}
	centerRes1, err := centerWrapResidual(ru1NTT, thetaRI1, r1NTT, k1NTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 1: %w", err)
	}
	centerRes := []*ring.Poly{centerRes0, centerRes1}
	var centerResCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		ru0Coeff, cerr := toFormalCoeffs(ru0NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("center RU0 coeffs: %w", cerr)
		}
		ri0Coeff, cerr := toFormalCoeffs(thetaRI0)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("center RI0 coeffs: %w", cerr)
		}
		r0Coeff, cerr := toFormalCoeffs(r0NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("center R0 coeffs: %w", cerr)
		}
		k0Coeff, cerr := toFormalCoeffs(k0NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("center K0 coeffs: %w", cerr)
		}
		ru1Coeff, cerr := toFormalCoeffs(ru1NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("center RU1 coeffs: %w", cerr)
		}
		ri1Coeff, cerr := toFormalCoeffs(thetaRI1)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("center RI1 coeffs: %w", cerr)
		}
		r1Coeff, cerr := toFormalCoeffs(r1NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("center R1 coeffs: %w", cerr)
		}
		k1Coeff, cerr := toFormalCoeffs(k1NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("center K1 coeffs: %w", cerr)
		}
		delta := uint64((2*bound + 1) % int64(q))
		res0 := polySub(polySub(polyAdd(ru0Coeff, ri0Coeff), r0Coeff), scalePoly(k0Coeff, delta, q))
		res1 := polySub(polySub(polyAdd(ru1Coeff, ri1Coeff), r1Coeff), scalePoly(k1Coeff, delta, q))
		centerResCoeffs = [][]uint64{res0, res1}
	}

	// Packing constraints (evaluation-domain): enforce m1 occupies lower half,
	// m2 upper half over Ω of length ncols.
	if ncols%2 != 0 {
		return ConstraintSet{}, fmt.Errorf("ncols %d is not even for packing", ncols)
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
		m1Coeff, cerr := toFormalCoeffs(m1NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("m1 coeffs: %w", cerr)
		}
		m2Coeff, cerr := toFormalCoeffs(m2NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("m2 coeffs: %w", cerr)
		}
		selCoeff, serr := buildPackingSelectorCoeff(ringQ, omega)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("packing selector coeffs: %w", serr)
		}
		oneMinusSelCoeff := []uint64{1 % q}
		oneMinusSelCoeff = polySub(oneMinusSelCoeff, selCoeff)
		m1PackCoeff = trimPoly(polyMul(selCoeff, m1Coeff, q), q)
		m2PackCoeff = trimPoly(polyMul(oneMinusSelCoeff, m2Coeff, q), q)
	}

	// Hash constraint: T = HashMessage(B, M1, M2, R0, R1).
	toCoeff := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		ringQ.InvNTT(cp, cp)
		return cp
	}
	// Interpolate public T over Ω to get Θ_T (degree < ncols), then pass
	// its coefficients to the hash gadget.
	tNTT := ringQ.NewPoly()
	q64 := int64(ringQ.Modulus[0])
	for i := 0; i < ringQ.N && i < len(pub.T); i++ {
		v := pub.T[i]
		if v < 0 {
			v += q64
		}
		tNTT.Coeffs[0][i] = uint64(v % q64)
	}
	ringQ.NTT(tNTT, tNTT)
	tThetaCoeff, err := thetaCoeffFromNTT(ringQ, tNTT, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("theta T: %w", err)
	}
	tThetaInt := make([]int64, len(tThetaCoeff))
	for i := range tThetaCoeff {
		tThetaInt[i] = int64(tThetaCoeff[i])
	}
	hashRes, err := BuildHashConstraints(
		ringQ,
		thetaB,
		toCoeff(m1NTT),
		toCoeff(m2NTT),
		toCoeff(r0NTT),
		toCoeff(r1NTT),
		tThetaInt,
	)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("hash residuals: %w", err)
	}
	var hashResCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
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
		m1Coeff, cerr := toFormalCoeffs(m1NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("hash M1 coeffs: %w", cerr)
		}
		m2Coeff, cerr := toFormalCoeffs(m2NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("hash M2 coeffs: %w", cerr)
		}
		r0Coeff, cerr := toFormalCoeffs(r0NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("hash R0 coeffs: %w", cerr)
		}
		r1Coeff, cerr := toFormalCoeffs(r1NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("hash R1 coeffs: %w", cerr)
		}
		tThetaTrim := trimPoly(append([]uint64(nil), tThetaCoeff...), q)
		mCombined := polyAdd(m1Coeff, m2Coeff)
		num := polyAdd(bCoeff[0], polyMul(bCoeff[1], mCombined, q))
		num = polyAdd(num, polyMul(bCoeff[2], r0Coeff, q))
		den := polySub(bCoeff[3], r1Coeff)
		hashResCoeffs = [][]uint64{polySub(polyMul(den, tThetaTrim, q), num)}
	}

	// Bounds (evaluation-domain composition): enforce membership in [-B,B] for
	// configured value rows and [-1,1] for configured carry rows.
	boundIdxs := preSignBoundRowIndices(layout)
	carryIdxs := preSignCarryRowIndices(layout)
	boundedRows := make([]*ring.Poly, 0, len(boundIdxs))
	for _, idx := range boundIdxs {
		if idx < 0 || idx >= len(rowsNTT) {
			return ConstraintSet{}, fmt.Errorf("pre-sign bound row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		boundedRows = append(boundedRows, rowsNTT[idx])
	}
	carryRows := make([]*ring.Poly, 0, len(carryIdxs))
	for _, idx := range carryIdxs {
		if idx < 0 || idx >= len(rowsNTT) {
			return ConstraintSet{}, fmt.Errorf("pre-sign carry row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		carryRows = append(carryRows, rowsNTT[idx])
	}
	if bound > int64(^uint(0)>>1) {
		return ConstraintSet{}, fmt.Errorf("bound too large for membership spec: %d", bound)
	}
	specVal := NewRangeMembershipSpec(q, int(bound))
	fparBounds := buildFparRangeMembershipCompose(ringQ, boundedRows, specVal)
	specCarry := NewRangeMembershipSpec(q, 1)
	fparCarry := buildFparRangeMembershipCompose(ringQ, carryRows, specCarry)
	fparBounds = append(fparBounds, fparCarry...)
	var fparBoundsCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		membershipVal := fpoly.New(q, specVal.Coeffs)
		membershipCarry := fpoly.New(q, specCarry.Coeffs)
		fparBoundsCoeffs = make([][]uint64, len(fparBounds))
		for i := 0; i < len(boundedRows); i++ {
			rowCoeff, cerr := toFormalCoeffs(boundedRows[i])
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("bound row %d coeffs: %w", i, cerr)
			}
			composed := membershipVal.Compose(fpoly.New(q, rowCoeff))
			fparBoundsCoeffs[i] = append([]uint64(nil), composed.Coeffs...)
		}
		for i := 0; i < len(carryRows); i++ {
			rowCoeff, cerr := toFormalCoeffs(carryRows[i])
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("carry row %d coeffs: %w", i, cerr)
			}
			composed := membershipCarry.Compose(fpoly.New(q, rowCoeff))
			fparBoundsCoeffs[len(boundedRows)+i] = append([]uint64(nil), composed.Coeffs...)
		}
	}

	parallelDeg := 2
	if deg := maxDegreeFromCoeffs(specVal.Coeffs); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(specCarry.Coeffs); deg > parallelDeg {
		parallelDeg = deg
	}
	fparInt := append(append(append(comRes, centerRes...), hashRes...), m1Pack, m2Pack)
	var fparIntCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		fparIntCoeffs = append(fparIntCoeffs, comResCoeffs...)
		fparIntCoeffs = append(fparIntCoeffs, centerResCoeffs...)
		fparIntCoeffs = append(fparIntCoeffs, hashResCoeffs...)
		fparIntCoeffs = append(fparIntCoeffs, m1PackCoeff, m2PackCoeff)
		if len(fparIntCoeffs) != len(fparInt) {
			return ConstraintSet{}, fmt.Errorf("pre-sign formal coeff mismatch: coeffs=%d polys=%d", len(fparIntCoeffs), len(fparInt))
		}
	}
	return ConstraintSet{
		FparInt:          fparInt,
		FparIntCoeffs:    fparIntCoeffs,
		FparNorm:         fparBounds,
		FparNormCoeffs:   fparBoundsCoeffs,
		ParallelAlgDeg:   parallelDeg,
		AggregatedAlgDeg: 1,
	}, nil
}

// buildCredentialConstraintSetPostFromRows builds the post-sign constraint set
// (signature, hash, packing, bounds) directly from committed row polynomials
// in NTT form. Row order is assumed to be:
// M1,M2,RU0,RU1,R,R0,R1,K0,K1,T,U...
func buildCredentialConstraintSetPostFromRows(ringQ *ring.Ring, bound int64, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, domainMode DomainMode, opts SimOpts) (ConstraintSet, error) {
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
	q := ringQ.Modulus[0]
	if rowLayoutHasCoeffNativeSig(layout) {
		return buildCredentialConstraintSetPostCoeffNative(ringQ, bound, pub, layout, rowsNTT, omega, domainMode, opts)
	}
	if len(pub.A) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing A for signature constraint")
	}
	if len(pub.B) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing B for hash constraint")
	}
	uCount := len(pub.A[0])
	if uCount == 0 {
		return ConstraintSet{}, fmt.Errorf("empty A columns")
	}
	m1Idx := rowLayoutPostSignM1(layout)
	m2Idx := rowLayoutPostSignM2(layout)
	r0Idx := rowLayoutPostSignR0(layout)
	r1Idx := rowLayoutPostSignR1(layout)
	tIdx := rowLayoutPostSignT(layout)
	uStart := rowLayoutPostSignUBase(layout)
	for _, idx := range []int{m1Idx, m2Idx, r0Idx, r1Idx, tIdx, uStart} {
		if idx < 0 {
			return ConstraintSet{}, fmt.Errorf("invalid post-sign row index %d", idx)
		}
	}
	if len(rowsNTT) < uStart+uCount {
		return ConstraintSet{}, fmt.Errorf("rows length %d < %d for U rows", len(rowsNTT), uStart+uCount)
	}

	m1NTT := rowsNTT[m1Idx]
	m2NTT := rowsNTT[m2Idx]
	r0NTT := rowsNTT[r0Idx]
	r1NTT := rowsNTT[r1Idx]
	tNTT := rowsNTT[tIdx]
	uRows := rowsNTT[uStart : uStart+uCount]

	// If the showing witness packs the full signature into blocks, rebuild the
	// signature constraints per block (so A·U=T holds across all ring slots).
	blocks := 1
	if layout.SigBlocks > 0 {
		blocks = layout.SigBlocks
	}
	if blocks <= 0 {
		blocks = 1
	}
	if blocks > 1 {
		if layout.SigUCount != 0 && layout.SigUCount != uCount {
			return ConstraintSet{}, fmt.Errorf("signature block layout mismatch: SigUCount=%d want %d", layout.SigUCount, uCount)
		}
		if layout.SigExtraUBase < 0 || (!layout.SigDerivedT && layout.SigExtraTBase < 0) {
			return ConstraintSet{}, fmt.Errorf("signature block layout missing extra U/T bases (uBase=%d tBase=%d derived=%t)", layout.SigExtraUBase, layout.SigExtraTBase, layout.SigDerivedT)
		}
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
	var thetaTBlocks []*ring.Poly
	if blocks > 1 && layout.SigDerivedT {
		if len(pub.T) < blocks*ncols {
			return ConstraintSet{}, fmt.Errorf("public T length %d too small for %d signature blocks of size %d", len(pub.T), blocks, ncols)
		}
		thetaTBlocks = make([]*ring.Poly, blocks)
		for b := 0; b < blocks; b++ {
			start := b * ncols
			end := start + ncols
			vals := make([]int64, ncols)
			copy(vals, pub.T[start:end])
			theta, terr := thetaPolyFromValues(ringQ, vals, omega)
			if terr != nil {
				return ConstraintSet{}, fmt.Errorf("theta T block %d: %w", b, terr)
			}
			thetaTBlocks[b] = theta
		}
	}

	var sigRes []*ring.Poly
	var sigResCoeffs [][]uint64
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
		copy(out, a)
		for i := 0; i < len(b); i++ {
			out[i] = modAdd(out[i], b[i]%q, q)
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
		copy(out, a)
		for i := 0; i < len(b); i++ {
			out[i] = modSub(out[i], b[i]%q, q)
		}
		return trimPoly(out, q)
	}
	for b := 0; b < blocks; b++ {
		uBlock := uRows
		tBlock := tNTT
		if rowLayoutCoeffNativeUsesSemanticRewrite(layout) && layout.SigExtraTBase >= 0 {
			tPos := layout.SigExtraTBase + b
			if tPos < 0 || tPos >= len(rowsNTT) {
				return ConstraintSet{}, fmt.Errorf("signature T block %d row %d out of range (rows=%d)", b, tPos, len(rowsNTT))
			}
			tBlock = rowsNTT[tPos]
		}
		if b > 0 {
			uBase := layout.SigExtraUBase + (b-1)*uCount
			uEnd := uBase + uCount
			if uBase < 0 || uEnd > len(rowsNTT) {
				return ConstraintSet{}, fmt.Errorf("signature U block %d rows [%d,%d) out of range (rows=%d)", b, uBase, uEnd, len(rowsNTT))
			}
			uBlock = rowsNTT[uBase:uEnd]
			if rowLayoutCoeffNativeUsesSemanticRewrite(layout) && layout.SigExtraTBase >= 0 {
				// semantic-rewrite T blocks are already wired above
			} else if layout.SigDerivedT {
				if b >= len(thetaTBlocks) || thetaTBlocks[b] == nil {
					return ConstraintSet{}, fmt.Errorf("missing derived public T block %d", b)
				}
				tBlock = thetaTBlocks[b]
			} else {
				tPos := layout.SigExtraTBase + (b - 1)
				if tPos < 0 || tPos >= len(rowsNTT) {
					return ConstraintSet{}, fmt.Errorf("signature T block %d row %d out of range (rows=%d)", b, tPos, len(rowsNTT))
				}
				tBlock = rowsNTT[tPos]
			}
		}
		res, err := BuildSignatureConstraintNTT(ringQ, thetaABlocks[b], uBlock, tBlock)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("signature residuals block %d: %w", b, err)
		}
		if domainMode == DomainModeExplicit {
			tCoeff, terr := toFormalCoeffs(tBlock)
			if terr != nil {
				return ConstraintSet{}, fmt.Errorf("signature block %d T coeffs: %w", b, terr)
			}
			for i := 0; i < len(thetaABlocks[b]); i++ {
				acc := []uint64{0}
				for j := 0; j < len(thetaABlocks[b][i]); j++ {
					aCoeff, aerr := toFormalCoeffs(thetaABlocks[b][i][j])
					if aerr != nil {
						return ConstraintSet{}, fmt.Errorf("signature block %d A[%d][%d] coeffs: %w", b, i, j, aerr)
					}
					uCoeff, uerr := toFormalCoeffs(uBlock[j])
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
			sigRes = append(sigRes, res...)
		}
	}
	hashRes, err := BuildHashConstraintsNTT(ringQ, thetaB, m1NTT, m2NTT, r0NTT, r1NTT, tNTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("hash residuals: %w", err)
	}
	var hashResCoeffs [][]uint64
	m1Coeff, m1CoeffErr := toFormalCoeffs(m1NTT)
	if m1CoeffErr != nil {
		return ConstraintSet{}, fmt.Errorf("m1 coeffs: %w", m1CoeffErr)
	}
	m2Coeff, m2CoeffErr := toFormalCoeffs(m2NTT)
	if m2CoeffErr != nil {
		return ConstraintSet{}, fmt.Errorf("m2 coeffs: %w", m2CoeffErr)
	}
	if domainMode == DomainModeExplicit {
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
		r0Coeff, r0Err := toFormalCoeffs(r0NTT)
		if r0Err != nil {
			return ConstraintSet{}, fmt.Errorf("r0 coeffs: %w", r0Err)
		}
		r1Coeff, r1Err := toFormalCoeffs(r1NTT)
		if r1Err != nil {
			return ConstraintSet{}, fmt.Errorf("r1 coeffs: %w", r1Err)
		}
		tCoeff, tErr := toFormalCoeffs(tNTT)
		if tErr != nil {
			return ConstraintSet{}, fmt.Errorf("T coeffs: %w", tErr)
		}
		mCombined := polyAdd(m1Coeff, m2Coeff)
		num := polyAdd(bCoeff[0], polyMul(bCoeff[1], mCombined, q))
		num = polyAdd(num, polyMul(bCoeff[2], r0Coeff, q))
		den := polySub(bCoeff[3], r1Coeff)
		hashResCoeffs = [][]uint64{polySub(polyMul(den, tCoeff, q), num)}
		hashRes = []*ring.Poly{nttPolyFromFormalCoeffsIfFits(ringQ, hashResCoeffs[0])}
	}

	if ncols%2 != 0 {
		return ConstraintSet{}, fmt.Errorf("ncols %d is not even for packing", ncols)
	}
	selNTT, oneMinusSel, err := buildPackingSelectorNTT(ringQ, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("packing selector: %w", err)
	}
	m1Pack := ringQ.NewPoly()
	m2Pack := ringQ.NewPoly()
	ringQ.MulCoeffs(selNTT, m1NTT, m1Pack)
	ringQ.MulCoeffs(oneMinusSel, m2NTT, m2Pack)

	parallelDeg := 2
	var fparBounds []*ring.Poly
	var fparBoundsCoeffs [][]uint64

	// Low-degree non-signature bound chain (preferred when chain rows are present).
	//
	// Layout contract:
	//   - message rows [0,1] use chain rows starting at MsgChainBase
	//   - randomness rows [5,6] use chain rows starting at RndChainBase
	// Each constrained row consumes (1+L) rows: M, D0..D_{L-1}.
	if layout.MsgChainBase >= 0 && layout.RndChainBase >= 0 {
		specBound, serr := nonSigBoundLinfSpec(q, bound)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("post-sign bound chain spec: %w", serr)
		}
		rowsPer := nonSigChainRowsPer(specBound)
		if rowsPer <= 1 {
			return ConstraintSet{}, fmt.Errorf("invalid post-sign bound chain rowsPer=%d", rowsPer)
		}
		P := make([]*ring.Poly, 0, 4)
		cd := ChainDecomp{
			M: make([]*ring.Poly, 0, 4),
			D: make([][]*ring.Poly, 0, 4),
		}
		appendBoundFamily := func(base int, srcRows []int, label string) error {
			for t, srcIdx := range srcRows {
				if srcIdx < 0 || srcIdx >= len(rowsNTT) {
					return fmt.Errorf("%s source row idx %d out of range (rows=%d)", label, srcIdx, len(rowsNTT))
				}
				chainBase := base + t*rowsPer
				if chainBase < 0 || chainBase+rowsPer > len(rowsNTT) {
					return fmt.Errorf("%s chain rows [%d,%d) out of range (rows=%d)", label, chainBase, chainBase+rowsPer, len(rowsNTT))
				}
				P = append(P, rowsNTT[srcIdx])
				cd.M = append(cd.M, rowsNTT[chainBase])
				digits := make([]*ring.Poly, specBound.L)
				for i := 0; i < specBound.L; i++ {
					digits[i] = rowsNTT[chainBase+1+i]
				}
				cd.D = append(cd.D, digits)
			}
			return nil
		}
		msgBoundRows := []int{rowLayoutPostSignM1(layout), rowLayoutPostSignM2(layout)}
		if err := appendBoundFamily(layout.MsgChainBase, msgBoundRows, "post-sign msg bound chain"); err != nil {
			return ConstraintSet{}, err
		}
		rndBoundRows := []int{rowLayoutPostSignR0(layout), rowLayoutPostSignR1(layout)}
		if err := appendBoundFamily(layout.RndChainBase, rndBoundRows, "post-sign rnd bound chain"); err != nil {
			return ConstraintSet{}, err
		}
		if len(P) == 0 {
			return ConstraintSet{}, fmt.Errorf("empty bounded row set for post-sign constraints")
		}
		if domainMode == DomainModeExplicit {
			fparBounds, fparBoundsCoeffs = buildFparLinfChainComposeFormalCoeffs(ringQ, P, cd, specBound)
		} else {
			fparBounds = buildFparLinfChainCompose(ringQ, P, cd, specBound)
			fparBoundsCoeffs = make([][]uint64, len(fparBounds))
		}
		for i := 0; i < specBound.L; i++ {
			if deg := maxDegreeFromCoeffs(specBound.PDi[i]); deg > parallelDeg {
				parallelDeg = deg
			}
		}
	} else {
		// Fallback high-degree range-membership composition.
		specVal := NewRangeMembershipSpec(q, int(bound))
		boundIdxs := postSignBoundRowIndices(layout)
		boundedRows := make([]*ring.Poly, 0, len(boundIdxs))
		for _, idx := range boundIdxs {
			if idx < 0 || idx >= len(rowsNTT) {
				return ConstraintSet{}, fmt.Errorf("bound row idx %d out of range (rows=%d)", idx, len(rowsNTT))
			}
			boundedRows = append(boundedRows, rowsNTT[idx])
		}
		if len(boundedRows) == 0 {
			return ConstraintSet{}, fmt.Errorf("empty bounded row set for post-sign constraints")
		}
		fparBounds = buildFparRangeMembershipCompose(ringQ, boundedRows, specVal)
		fparBoundsCoeffs = make([][]uint64, len(fparBounds))
		if domainMode == DomainModeExplicit {
			membership := fpoly.New(q, specVal.Coeffs)
			for i := 0; i < len(boundedRows); i++ {
				rowCoeff, cerr := toFormalCoeffs(boundedRows[i])
				if cerr != nil {
					return ConstraintSet{}, fmt.Errorf("bound row %d coeffs: %w", i, cerr)
				}
				composed := membership.Compose(fpoly.New(q, rowCoeff))
				fparBoundsCoeffs[i] = append([]uint64(nil), composed.Coeffs...)
			}
		}
		if deg := maxDegreeFromCoeffs(specVal.Coeffs); deg > parallelDeg {
			parallelDeg = deg
		}
	}

	// Showing-time signature coefficient bounds (ℓ∞, coefficient domain).
	//
	// When the showing witness includes coefficient-packed signature rows and
	// chain rows, append the replayable membership-chain constraints.
	if layout.SigCoeffBase >= 0 && layout.ChainBase >= 0 && layout.ChainRowsPerSig > 0 {
		return ConstraintSet{}, fmt.Errorf("scalar signature shortness requires the retained literal-packed coeff-native showing protocol")
	}

	fparInt := append(sigRes, hashRes...)
	fparInt = append(fparInt, m1Pack, m2Pack)
	var fparIntCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		selCoeff, selErr := toFormalCoeffs(selNTT)
		if selErr != nil {
			return ConstraintSet{}, fmt.Errorf("selector coeffs: %w", selErr)
		}
		oneMinusSelCoeff, oneSelErr := toFormalCoeffs(oneMinusSel)
		if oneSelErr != nil {
			return ConstraintSet{}, fmt.Errorf("selector complement coeffs: %w", oneSelErr)
		}
		m1PackCoeff := trimPoly(polyMul(selCoeff, m1Coeff, q), q)
		m2PackCoeff := trimPoly(polyMul(oneMinusSelCoeff, m2Coeff, q), q)
		m1Pack = nttPolyFromFormalCoeffsIfFits(ringQ, m1PackCoeff)
		m2Pack = nttPolyFromFormalCoeffsIfFits(ringQ, m2PackCoeff)
		fparIntCoeffs = append(fparIntCoeffs, sigResCoeffs...)
		fparIntCoeffs = append(fparIntCoeffs, hashResCoeffs...)
		fparIntCoeffs = append(fparIntCoeffs, m1PackCoeff, m2PackCoeff)
		if len(fparIntCoeffs) != len(fparInt) {
			return ConstraintSet{}, fmt.Errorf("post-sign formal coeff mismatch: coeffs=%d polys=%d", len(fparIntCoeffs), len(fparInt))
		}
	}
	aggDeg := 1
	// Signature NTT↔coeff bridge constraints are appended in credential mode when
	// the packed coefficient layout is present; its algebraic degree is 2.
	if layout.SigCoeffBase >= 0 || hasPostSignNonSigFamilies(layout) {
		aggDeg = 2
	}
	return ConstraintSet{
		FparInt:          fparInt,
		FparIntCoeffs:    fparIntCoeffs,
		FparNorm:         fparBounds,
		FparNormCoeffs:   fparBoundsCoeffs,
		ParallelAlgDeg:   parallelDeg,
		AggregatedAlgDeg: aggDeg,
	}, nil
}

// BuildCredentialConstraintSetPre builds the constraint set for the pre-signature
// credential proof (Com/center/hash/bounds).
func BuildCredentialConstraintSetPre(ringQ *ring.Ring, bound int64, pub PublicInputs, wit WitnessInputs, omega []uint64) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("credential constraint config: missing omega")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	if len(pub.Ac) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Ac")
	}
	if len(pub.Com) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Com")
	}
	if len(pub.RI0) == 0 || len(pub.RI1) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing RI0/RI1")
	}
	// Witness presence checks.
	require := func(vec []*ring.Poly, name string) error {
		if len(vec) == 0 {
			return fmt.Errorf("missing witness %s", name)
		}
		return nil
	}
	if err := require(wit.M1, "M1"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.M2, "M2"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.RU0, "RU0"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.RU1, "RU1"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.R, "R"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.R0, "R0"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.R1, "R1"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.K0, "K0"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.K1, "K1"); err != nil {
		return ConstraintSet{}, err
	}
	ensureNTT := func(p *ring.Poly) *ring.Poly {
		if p == nil {
			return nil
		}
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		ringQ.NTT(cp, cp)
		return cp
	}

	// Basic bound sanity on witness row heads used by constraint composition.
	// These pre-sign constraints are built over the packed row-head encoding, so
	// we enforce bounds on the first |Ω| NTT slots of each witness row.
	allWits := []*ring.Poly{wit.M1[0], wit.M2[0], wit.RU0[0], wit.RU1[0], wit.R[0], wit.R0[0], wit.R1[0], wit.K0[0], wit.K1[0]}
	nttWits := make([]*ring.Poly, len(allWits))
	for i := range allWits {
		nttWits[i] = ensureNTT(allWits[i])
	}
	q := ringQ.Modulus[0]
	qInt := int64(q)
	half := qInt / 2
	for idx, pNTT := range nttWits {
		if pNTT == nil {
			return ConstraintSet{}, fmt.Errorf("nil witness poly %d", idx)
		}
		for j := 0; j < len(omega); j++ {
			cv := int64(pNTT.Coeffs[0][j] % q)
			if cv > half {
				cv -= qInt
			}
			if cv < -half {
				cv += qInt
			}
			if cv > bound || cv < -bound {
				return ConstraintSet{}, fmt.Errorf("bound check failed: witness poly %d out of range on Ω (slot %d)", idx, j)
			}
		}
	}
	for idx, p := range nttWits {
		if p == nil {
			return ConstraintSet{}, fmt.Errorf("nil witness poly %d", idx)
		}
	}

	rowsNTT := []*ring.Poly{
		nttWits[0],
		nttWits[1],
		nttWits[2],
		nttWits[3],
		nttWits[4],
		nttWits[5],
		nttWits[6],
		nttWits[7],
		nttWits[8],
	}
	// Use the same row-based builder (without LVCS tails).
	return buildCredentialConstraintSetPreFromRows(ringQ, bound, pub, RowLayout{}, rowsNTT, omega, DomainModeExplicit)
}

// BuildPRFConstraintSet constructs the parallel constraints for tag = F(m2, nonce)
// using the Poseidon2-like params in prfParams. This follows the degree-5
// arithmetization (no quadraticization), introducing degree-5 constraints for
// each round/lanes transition and linear constraints for the feed-forward/tag.
//
// Inputs:
//   - ringQ: PCS ring
//   - prfParams: PRF Params (ME/MI/cExt/cInt/d/RF/RP/lentag)
//   - rows: flattened witness rows containing the PRF trace (row polynomials).
//     Rows are expected in NTT (evaluation-domain) form.
//     The slice must contain (R+1)*t consecutive rows starting at startIdx,
//     where R = RF+RP and t = LenKey+LenNonce.
//   - startIdx: index into rows where x^(0)_0 is stored; row order is
//     x^(r)_j = rows[startIdx + r*t + j].
//   - tagPublic: public tag values on Ω (len= lentag, each length ≥ ncols)
//   - noncePublic: optional nonce values on Ω (lenNonce lanes), each length ≥ ncols.
//   - omega: evaluation set Ω values.
//
// Output: ConstraintSet with FparInt populated; no bounds or agg constraints.
func BuildPRFConstraintSet(ringQ *ring.Ring, prfParams *prf.Params, rows []*ring.Poly, startIdx int, tagPublic [][]int64, noncePublic [][]int64, omega []uint64) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if prfParams == nil {
		return ConstraintSet{}, fmt.Errorf("nil prf params")
	}
	if err := prfParams.Validate(); err != nil {
		return ConstraintSet{}, fmt.Errorf("prf params invalid: %w", err)
	}
	ncols := len(omega)
	if ncols == 0 {
		return ConstraintSet{}, fmt.Errorf("prf constraint config: missing omega")
	}
	if ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("invalid ncols %d", ncols)
	}
	R := prfParams.RF + prfParams.RP
	t := prfParams.T()
	need := startIdx + (R+1)*t
	if startIdx < 0 || need > len(rows) {
		return ConstraintSet{}, fmt.Errorf("rows len=%d too small for PRF trace (need %d from %d)", len(rows), (R+1)*t, startIdx)
	}
	if len(tagPublic) != prfParams.LenTag {
		return ConstraintSet{}, fmt.Errorf("tag lanes=%d want %d", len(tagPublic), prfParams.LenTag)
	}
	for i := range tagPublic {
		if len(tagPublic[i]) < ncols {
			return ConstraintSet{}, fmt.Errorf("tag lane %d len=%d < ncols=%d", i, len(tagPublic[i]), ncols)
		}
	}
	if noncePublic != nil && len(noncePublic) != prfParams.LenNonce {
		return ConstraintSet{}, fmt.Errorf("nonce lanes=%d want %d", len(noncePublic), prfParams.LenNonce)
	}
	if noncePublic != nil {
		for i := range noncePublic {
			if len(noncePublic[i]) < ncols {
				return ConstraintSet{}, fmt.Errorf("nonce lane %d len=%d < ncols=%d", i, len(noncePublic[i]), ncols)
			}
		}
	}
	q := int64(ringQ.Modulus[0])

	getState := func(r, j int) *ring.Poly {
		return rows[startIdx+r*t+j]
	}
	powNTT := func(p *ring.Poly, c uint64, d uint64) *ring.Poly {
		out := ringQ.NewPoly()
		for i := 0; i < ringQ.N; i++ {
			v := (p.Coeffs[0][i] + c) % uint64(q)
			res := uint64(1)
			base := v
			exp := d
			for exp > 0 {
				if exp&1 == 1 {
					res = (res * base) % uint64(q)
				}
				base = (base * base) % uint64(q)
				exp >>= 1
			}
			out.Coeffs[0][i] = res
		}
		return out
	}
	scaleNTT := func(p *ring.Poly, scalar uint64) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		for i := 0; i < ringQ.N; i++ {
			cp.Coeffs[0][i] = (cp.Coeffs[0][i] * scalar) % uint64(q)
		}
		return cp
	}

	// Interpolate public Tag/Nonce over Ω for Θ(X).
	tagTheta, _, err := buildPRFThetaPolys(ringQ, tagPublic, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("tag theta: %w", err)
	}
	var nonceTheta []*ring.Poly
	if noncePublic != nil {
		nonceTheta, _, err = buildPRFThetaPolys(ringQ, noncePublic, omega)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("nonce theta: %w", err)
		}
	}

	residuals := make([]*ring.Poly, 0, (prfParams.RF+prfParams.RP)*t+prfParams.LenTag)

	rIdx := 0
	// External rounds (first half)
	for r := 0; r < prfParams.RF/2; r++ {
		lanePow := make([]*ring.Poly, t)
		for i := 0; i < t; i++ {
			lanePow[i] = powNTT(getState(rIdx, i), prfParams.CExt[r][i]%uint64(q), prfParams.D)
		}
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			for i := 0; i < t; i++ {
				term := scaleNTT(lanePow[i], prfParams.ME[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			ringQ.Sub(res, getState(rIdx+1, j), res)
			residuals = append(residuals, res)
		}
		rIdx++
	}
	// Internal rounds
	for ir := 0; ir < prfParams.RP; ir++ {
		u1Pow := powNTT(getState(rIdx, 0), prfParams.CInt[ir]%uint64(q), prfParams.D)
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			term0 := scaleNTT(u1Pow, prfParams.MI[j][0]%uint64(q))
			ringQ.Add(acc, term0, acc)
			for i := 1; i < t; i++ {
				term := scaleNTT(getState(rIdx, i), prfParams.MI[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			ringQ.Sub(res, getState(rIdx+1, j), res)
			residuals = append(residuals, res)
		}
		rIdx++
	}
	// External rounds (second half)
	for r := prfParams.RF / 2; r < prfParams.RF; r++ {
		lanePow := make([]*ring.Poly, t)
		for i := 0; i < t; i++ {
			lanePow[i] = powNTT(getState(rIdx, i), prfParams.CExt[r][i]%uint64(q), prfParams.D)
		}
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			for i := 0; i < t; i++ {
				term := scaleNTT(lanePow[i], prfParams.ME[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			ringQ.Sub(res, getState(rIdx+1, j), res)
			residuals = append(residuals, res)
		}
		rIdx++
	}

	// Tag binding: x^(R)_j + x^(0)_j - tag_j^public = 0 for j<lentag.
	finalStateIdx := R
	for j := 0; j < prfParams.LenTag; j++ {
		res := ringQ.NewPoly()
		ringQ.Add(getState(finalStateIdx, j), getState(0, j), res)
		ringQ.Sub(res, tagTheta[j], res)
		residuals = append(residuals, res)
	}

	// Nonce binding (public): x^(0)_{lenkey + j} - nonce_j = 0.
	if noncePublic != nil {
		for j := 0; j < prfParams.LenNonce; j++ {
			res := ringQ.NewPoly()
			ringQ.Sub(getState(0, prfParams.LenKey+j), nonceTheta[j], res)
			residuals = append(residuals, res)
		}
	}

	return ConstraintSet{FparInt: residuals, ParallelAlgDeg: int(prfParams.D), AggregatedAlgDeg: 1}, nil
}

// BuildPRFConstraintSetSBox constructs the PRF constraints in "System A" form:
// the witness carries only the PRF key lanes and a subset of S-box outputs.
//
// Witness layout (starting at startIdx):
//   - Key lanes: rows[startIdx + i] for i=0..LenKey-1
//   - S-box outputs Zα in strict execution order, but only at checkpoint rounds defined by groupRounds:
//   - internal rounds are always checkpointed,
//   - for groupRounds>1, external rounds are checkpointed except the final full round
//     (degree-stable grouped mode).
//     stored as rows[sboxStart + α], where sboxStart = startIdx + LenKey.
//
// Nonce and tag are public (Θ-polynomials built from tagPublic/noncePublic).
//
// Constraint ordering in FparInt:
//   - All S-box constraints in execution order:  U^d - Z = 0
//   - Tag binding constraints (LenTag): y[j] + x0[j] - tag[j] = 0
//   - Optional key-binding constraints (LenKey), when enabled:
//     Sel_{half+i}(X)·(Key_i(X) - M2(X)) = 0
//     where Sel_k is the Ω selector polynomial for column k and half = ncols/2.
//
// This keeps PRF constraints fully parallel (no Fagg). Under the current grouped
// schedule, the maximum algebraic degree remains D in witness variables.
func BuildPRFConstraintSetSBox(ringQ *ring.Ring, prfParams *prf.Params, rows []*ring.Poly, layout *PRFLayout, tagPublic [][]int64, noncePublic [][]int64, omega []uint64) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if prfParams == nil {
		return ConstraintSet{}, fmt.Errorf("nil prf params")
	}
	if layout == nil {
		return ConstraintSet{}, fmt.Errorf("nil prf layout")
	}
	if err := prfParams.Validate(); err != nil {
		return ConstraintSet{}, fmt.Errorf("prf params invalid: %w", err)
	}
	if layout.LenKey != prfParams.LenKey || layout.LenNonce != prfParams.LenNonce || layout.RF != prfParams.RF || layout.RP != prfParams.RP || layout.LenTag != prfParams.LenTag {
		return ConstraintSet{}, fmt.Errorf("prf layout mismatch with params")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("prf constraint config: missing omega")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	if len(tagPublic) != prfParams.LenTag {
		return ConstraintSet{}, fmt.Errorf("tag lanes=%d want %d", len(tagPublic), prfParams.LenTag)
	}
	for i := range tagPublic {
		if len(tagPublic[i]) < ncols {
			return ConstraintSet{}, fmt.Errorf("tag lane %d len=%d < ncols=%d", i, len(tagPublic[i]), ncols)
		}
	}
	if noncePublic != nil && len(noncePublic) != prfParams.LenNonce {
		return ConstraintSet{}, fmt.Errorf("nonce lanes=%d want %d", len(noncePublic), prfParams.LenNonce)
	}
	if noncePublic != nil {
		for i := range noncePublic {
			if len(noncePublic[i]) < ncols {
				return ConstraintSet{}, fmt.Errorf("nonce lane %d len=%d < ncols=%d", i, len(noncePublic[i]), ncols)
			}
		}
	}

	t := prfParams.T()
	startIdx := layout.StartIdx
	groupRounds := layout.GroupRounds
	if groupRounds <= 0 {
		groupRounds = 1
	}
	sboxCount, err := prf.SBoxOutputCountGrouped(prfParams, groupRounds)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("sbox count grouped: %w", err)
	}
	keyCount := prfParams.LenKey
	if keyCount <= 0 {
		return ConstraintSet{}, fmt.Errorf("invalid lenkey %d", keyCount)
	}
	keyBind := layout.KeyBind
	m2RowIdx := layout.M2RowIdx
	if keyBind {
		if m2RowIdx < 0 || m2RowIdx >= len(rows) {
			return ConstraintSet{}, fmt.Errorf("keyBind enabled but invalid m2RowIdx=%d (rows=%d)", m2RowIdx, len(rows))
		}
		if ncols%2 != 0 {
			return ConstraintSet{}, fmt.Errorf("keyBind requires even ncols, got %d", ncols)
		}
		if ncols/2 < keyCount {
			return ConstraintSet{}, fmt.Errorf("keyBind requires ncols/2 >= lenkey; got ncols=%d lenkey=%d", ncols, keyCount)
		}
	}
	sboxStart := startIdx + keyCount
	need := sboxStart + sboxCount
	if !layout.PackedRows && (startIdx < 0 || need > len(rows)) {
		return ConstraintSet{}, fmt.Errorf("rows len=%d too small for PRF key+sbox witness (need %d from %d)", len(rows), keyCount+sboxCount, startIdx)
	}

	qMod := ringQ.Modulus[0]
	q := int64(qMod)
	mulNTTPoly := func(a, b *ring.Poly) *ring.Poly {
		out := ringQ.NewPoly()
		for i := 0; i < ringQ.N; i++ {
			out.Coeffs[0][i] = lvcs.MulMod64(a.Coeffs[0][i]%qMod, b.Coeffs[0][i]%qMod, qMod)
		}
		return out
	}
	var selectorTheta []*ring.Poly
	var selectorCoeff [][]uint64
	if layout.PackedRows || keyBind {
		selectorTheta, selectorCoeff, err = buildOmegaDeltaSelectors(ringQ, omega)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("delta selectors: %w", err)
		}
	}

	// Public Θ polynomials for tag/nonce.
	tagTheta, tagCoeff, err := buildPRFThetaPolys(ringQ, tagPublic, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("tag theta: %w", err)
	}
	var nonceTheta []*ring.Poly
	var nonceCoeff [][]uint64
	if noncePublic != nil {
		nonceTheta, nonceCoeff, err = buildPRFThetaPolys(ringQ, noncePublic, omega)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("nonce theta: %w", err)
		}
	}

	rowCoeffCache := map[int][]uint64{}
	nonceLane := func(j int) *ring.Poly {
		if nonceTheta == nil || j < 0 || j >= len(nonceTheta) {
			return nil
		}
		return nonceTheta[j]
	}

	powNTT := func(p *ring.Poly, c uint64, d uint64) *ring.Poly {
		out := ringQ.NewPoly()
		for i := 0; i < ringQ.N; i++ {
			v := (p.Coeffs[0][i] + c) % uint64(q)
			res := uint64(1)
			base := v
			exp := d
			for exp > 0 {
				if exp&1 == 1 {
					res = (res * base) % uint64(q)
				}
				base = (base * base) % uint64(q)
				exp >>= 1
			}
			out.Coeffs[0][i] = res
		}
		return out
	}
	scaleNTT := func(p *ring.Poly, scalar uint64) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		for i := 0; i < ringQ.N; i++ {
			cp.Coeffs[0][i] = (cp.Coeffs[0][i] * scalar) % uint64(q)
		}
		return cp
	}
	mdsApply := func(state []*ring.Poly, mds [][]uint64) []*ring.Poly {
		out := make([]*ring.Poly, len(state))
		for j := 0; j < len(state); j++ {
			acc := ringQ.NewPoly()
			for i := 0; i < len(state); i++ {
				term := scaleNTT(state[i], mds[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			out[j] = acc
		}
		return out
	}

	toFormalCoeffs := func(p *ring.Poly) ([]uint64, error) {
		coeff, err := coeffFromNTTPoly(ringQ, p)
		if err != nil {
			return nil, err
		}
		if len(coeff) == 0 {
			return []uint64{0}, nil
		}
		return trimPoly(coeff, qMod), nil
	}
	polyAddFormal := func(a, b []uint64) []uint64 {
		n := len(a)
		if len(b) > n {
			n = len(b)
		}
		if n == 0 {
			return []uint64{0}
		}
		out := make([]uint64, n)
		copy(out, a)
		for i := 0; i < len(b); i++ {
			out[i] = modAdd(out[i], b[i]%qMod, qMod)
		}
		return trimPoly(out, qMod)
	}
	polySubFormal := func(a, b []uint64) []uint64 {
		n := len(a)
		if len(b) > n {
			n = len(b)
		}
		if n == 0 {
			return []uint64{0}
		}
		out := make([]uint64, n)
		copy(out, a)
		for i := 0; i < len(b); i++ {
			out[i] = modSub(out[i], b[i]%qMod, qMod)
		}
		return trimPoly(out, qMod)
	}
	powCoeff := func(base []uint64, c uint64, d uint64) []uint64 {
		shifted := append([]uint64(nil), base...)
		if len(shifted) == 0 {
			shifted = []uint64{0}
		}
		shifted[0] = modAdd(shifted[0], c%qMod, qMod)
		if d == 0 {
			return []uint64{1}
		}
		res := []uint64{1}
		exp := d
		powBase := shifted
		for exp > 0 {
			if exp&1 == 1 {
				res = trimPoly(polyMul(res, powBase, qMod), qMod)
			}
			exp >>= 1
			if exp > 0 {
				powBase = trimPoly(polyMul(powBase, powBase, qMod), qMod)
			}
		}
		return trimPoly(res, qMod)
	}
	mdsApplyCoeff := func(state [][]uint64, mds [][]uint64) [][]uint64 {
		out := make([][]uint64, len(state))
		for j := 0; j < len(state); j++ {
			acc := []uint64{0}
			for i := 0; i < len(state); i++ {
				term := scalePoly(state[i], mds[j][i]%qMod, qMod)
				addIntoUint(&acc, term, qMod)
			}
			out[j] = trimPoly(acc, qMod)
		}
		return out
	}
	getRowCoeff := func(idx int) ([]uint64, error) {
		if coeff, ok := rowCoeffCache[idx]; ok {
			return coeff, nil
		}
		if idx < 0 || idx >= len(rows) {
			return nil, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
		}
		coeff, err := toFormalCoeffs(rows[idx])
		if err != nil {
			return nil, err
		}
		rowCoeffCache[idx] = coeff
		return coeff, nil
	}
	getCoeff := func(p *ring.Poly) ([]uint64, error) {
		if p == nil {
			return nil, fmt.Errorf("nil polynomial in PRF formal replay")
		}
		return toFormalCoeffs(p)
	}
	getKey := func(i int) (*ring.Poly, []uint64, error) {
		if layout.PackedRows {
			if i < 0 || i >= len(layout.KeySlots) {
				return nil, nil, fmt.Errorf("packed key slot %d out of range (%d)", i, len(layout.KeySlots))
			}
			slot := layout.KeySlots[i]
			if slot.Row < 0 || slot.Row >= len(rows) {
				return nil, nil, fmt.Errorf("packed key row %d out of range (rows=%d)", slot.Row, len(rows))
			}
			if slot.Col < 0 || slot.Col >= len(selectorTheta) {
				return nil, nil, fmt.Errorf("packed key col %d out of range", slot.Col)
			}
			coeff, err := getRowCoeff(slot.Row)
			if err != nil {
				return nil, nil, err
			}
			return mulNTTPoly(rows[slot.Row], selectorTheta[slot.Col]), trimPoly(polyMul(coeff, selectorCoeff[slot.Col], qMod), qMod), nil
		}
		idx := startIdx + i
		coeff, err := getRowCoeff(idx)
		if err != nil {
			return nil, nil, err
		}
		return rows[idx], coeff, nil
	}
	getZ := func(alpha int) (*ring.Poly, []uint64, error) {
		if layout.PackedRows {
			if alpha < 0 || alpha >= len(layout.SBoxSlots) {
				return nil, nil, fmt.Errorf("packed sbox slot %d out of range (%d)", alpha, len(layout.SBoxSlots))
			}
			slot := layout.SBoxSlots[alpha]
			if slot.Row < 0 || slot.Row >= len(rows) {
				return nil, nil, fmt.Errorf("packed sbox row %d out of range (rows=%d)", slot.Row, len(rows))
			}
			if slot.Col < 0 || slot.Col >= len(selectorTheta) {
				return nil, nil, fmt.Errorf("packed sbox col %d out of range", slot.Col)
			}
			coeff, err := getRowCoeff(slot.Row)
			if err != nil {
				return nil, nil, err
			}
			return mulNTTPoly(rows[slot.Row], selectorTheta[slot.Col]), trimPoly(polyMul(coeff, selectorCoeff[slot.Col], qMod), qMod), nil
		}
		idx := sboxStart + alpha
		coeff, err := getRowCoeff(idx)
		if err != nil {
			return nil, nil, err
		}
		return rows[idx], coeff, nil
	}

	// Build initial state as polys in NTT: key lanes are witness rows; nonce lanes are public Θ.
	state := make([]*ring.Poly, t)
	stateCoeff := make([][]uint64, t)
	for i := 0; i < t; i++ {
		switch {
		case i < prfParams.LenKey:
			row, coeff, cerr := getKey(i)
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("key lane coeff %d: %w", i, cerr)
			}
			state[i] = row
			stateCoeff[i] = coeff
		default:
			if nonceTheta == nil {
				return ConstraintSet{}, fmt.Errorf("nonce is required (public) for lane %d", i)
			}
			state[i] = nonceLane(i - prfParams.LenKey)
			if i-prfParams.LenKey >= len(nonceCoeff) {
				return ConstraintSet{}, fmt.Errorf("nonce coeff lane %d out of range", i-prfParams.LenKey)
			}
			stateCoeff[i] = trimPoly(append([]uint64(nil), nonceCoeff[i-prfParams.LenKey]...), qMod)
		}
		if state[i] == nil {
			return ConstraintSet{}, fmt.Errorf("nil initial state lane %d", i)
		}
	}

	residuals := make([]*ring.Poly, 0, sboxCount+prfParams.LenTag)
	residualCoeffs := make([][]uint64, 0, sboxCount+prfParams.LenTag)
	alpha := 0

	// External rounds (first half): global rounds 0..RF/2-1.
	for r := 0; r < prfParams.RF/2; r++ {
		globalRound := r
		checkpoint := prf.ShouldCheckpointRound(prfParams, globalRound, groupRounds)
		for lane := 0; lane < t; lane++ {
			pow := powNTT(state[lane], prfParams.CExt[r][lane]%uint64(q), prfParams.D)
			powC := powCoeff(stateCoeff[lane], prfParams.CExt[r][lane]%qMod, prfParams.D)
			if checkpoint {
				zRow, zCoeff, zErr := getZ(alpha)
				if zErr != nil {
					return ConstraintSet{}, fmt.Errorf("sbox lane %d: %w", alpha, zErr)
				}
				res := ringQ.NewPoly()
				ring.Copy(pow, res)
				ringQ.Sub(res, zRow, res) // U^d - Z
				residuals = append(residuals, res)
				residualCoeffs = append(residualCoeffs, polySubFormal(powC, zCoeff))
				state[lane] = zRow
				stateCoeff[lane] = zCoeff
				alpha++
			} else {
				state[lane] = pow
				stateCoeff[lane] = powC
			}
		}
		state = mdsApply(state, prfParams.ME)
		stateCoeff = mdsApplyCoeff(stateCoeff, prfParams.ME)
	}
	// Internal rounds: global rounds RF/2..RF/2+RP-1.
	for ir := 0; ir < prfParams.RP; ir++ {
		globalRound := prfParams.RF/2 + ir
		checkpoint := prf.ShouldCheckpointRound(prfParams, globalRound, groupRounds)
		pow := powNTT(state[0], prfParams.CInt[ir]%uint64(q), prfParams.D)
		powC := powCoeff(stateCoeff[0], prfParams.CInt[ir]%qMod, prfParams.D)
		if checkpoint {
			zRow, zCoeff, zErr := getZ(alpha)
			if zErr != nil {
				return ConstraintSet{}, fmt.Errorf("sbox lane %d: %w", alpha, zErr)
			}
			res := ringQ.NewPoly()
			ring.Copy(pow, res)
			ringQ.Sub(res, zRow, res)
			residuals = append(residuals, res)
			residualCoeffs = append(residualCoeffs, polySubFormal(powC, zCoeff))
			state[0] = zRow
			stateCoeff[0] = zCoeff
			alpha++
		} else {
			state[0] = pow
			stateCoeff[0] = powC
		}
		state = mdsApply(state, prfParams.MI)
		stateCoeff = mdsApplyCoeff(stateCoeff, prfParams.MI)
	}
	// External rounds (second half): global rounds RF/2+RP..RF+RP-1.
	for r := prfParams.RF / 2; r < prfParams.RF; r++ {
		globalRound := r + prfParams.RP
		checkpoint := prf.ShouldCheckpointRound(prfParams, globalRound, groupRounds)
		for lane := 0; lane < t; lane++ {
			pow := powNTT(state[lane], prfParams.CExt[r][lane]%uint64(q), prfParams.D)
			powC := powCoeff(stateCoeff[lane], prfParams.CExt[r][lane]%qMod, prfParams.D)
			if checkpoint {
				zRow, zCoeff, zErr := getZ(alpha)
				if zErr != nil {
					return ConstraintSet{}, fmt.Errorf("sbox lane %d: %w", alpha, zErr)
				}
				res := ringQ.NewPoly()
				ring.Copy(pow, res)
				ringQ.Sub(res, zRow, res)
				residuals = append(residuals, res)
				residualCoeffs = append(residualCoeffs, polySubFormal(powC, zCoeff))
				state[lane] = zRow
				stateCoeff[lane] = zCoeff
				alpha++
			} else {
				state[lane] = pow
				stateCoeff[lane] = powC
			}
		}
		state = mdsApply(state, prfParams.ME)
		stateCoeff = mdsApplyCoeff(stateCoeff, prfParams.ME)
	}
	if alpha != sboxCount {
		return ConstraintSet{}, fmt.Errorf("sbox count mismatch: built %d want %d", alpha, sboxCount)
	}

	// Tag binding: y[j] + x0[j] - tag[j] = 0 for j<lentag.
	for j := 0; j < prfParams.LenTag; j++ {
		x0j := (*ring.Poly)(nil)
		var x0Coeff []uint64
		if j < prfParams.LenKey {
			row, coeff, cerr := getKey(j)
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("x0 coeff lane %d: %w", j, cerr)
			}
			x0j = row
			x0Coeff = coeff
		} else {
			if nonceTheta == nil {
				return ConstraintSet{}, fmt.Errorf("missing nonce theta for x0 lane %d", j)
			}
			x0j = nonceLane(j - prfParams.LenKey)
			if j-prfParams.LenKey >= len(nonceCoeff) {
				return ConstraintSet{}, fmt.Errorf("missing nonce coeff for x0 lane %d", j)
			}
			x0Coeff = nonceCoeff[j-prfParams.LenKey]
		}
		res := ringQ.NewPoly()
		ringQ.Add(state[j], x0j, res)
		ringQ.Sub(res, tagTheta[j], res)
		residuals = append(residuals, res)
		if j >= len(tagCoeff) {
			return ConstraintSet{}, fmt.Errorf("missing tag coeff lane %d", j)
		}
		tagBind := polySubFormal(polyAddFormal(stateCoeff[j], x0Coeff), tagCoeff[j])
		residualCoeffs = append(residualCoeffs, tagBind)
	}

	// Key binding: enforce Key_i matches the signed credential M2 encoding at ω_{half+i}.
	if keyBind {
		half := ncols / 2
		m2NTT := rows[m2RowIdx]
		m2Coeff, cerr := getCoeff(m2NTT)
		if cerr != nil {
			return ConstraintSet{}, fmt.Errorf("m2 coeff for keyBind: %w", cerr)
		}
		for i := 0; i < prfParams.LenKey; i++ {
			col := half + i
			selNTT, err := buildDeltaSelectorNTT(ringQ, omega, col)
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("keyBind selector col=%d: %w", col, err)
			}
			keyRow, keyCoeff, kerr := getKey(i)
			if kerr != nil {
				return ConstraintSet{}, fmt.Errorf("key coeff %d: %w", i, kerr)
			}
			m2Extract := ringQ.NewPoly()
			ringQ.MulCoeffs(selNTT, m2NTT, m2Extract)
			res := ringQ.NewPoly()
			if layout.PackedRows {
				ringQ.Sub(keyRow, m2Extract, res)
				residuals = append(residuals, res)
				m2ExtractCoeff := trimPoly(polyMul(m2Coeff, selectorCoeff[col], qMod), qMod)
				residualCoeffs = append(residualCoeffs, polySubFormal(keyCoeff, m2ExtractCoeff))
				continue
			}
			diff := ringQ.NewPoly()
			ringQ.Sub(keyRow, m2NTT, diff)
			ringQ.MulCoeffs(selNTT, diff, res)
			residuals = append(residuals, res)
			selCoeff, serr := toFormalCoeffs(selNTT)
			if serr != nil {
				return ConstraintSet{}, fmt.Errorf("selector coeff col=%d: %w", col, serr)
			}
			diffCoeff := polySubFormal(keyCoeff, m2Coeff)
			residualCoeffs = append(residualCoeffs, trimPoly(polyMul(selCoeff, diffCoeff, qMod), qMod))
		}
	}
	if len(residualCoeffs) != len(residuals) {
		return ConstraintSet{}, fmt.Errorf("prf formal coeff count mismatch: coeffs=%d polys=%d", len(residualCoeffs), len(residuals))
	}

	parallelDeg, derr := prf.MaxConstraintDegreeGrouped(prfParams, groupRounds)
	if derr != nil {
		return ConstraintSet{}, fmt.Errorf("prf grouped degree: %w", derr)
	}
	if parallelDeg > uint64(^uint(0)>>1) {
		return ConstraintSet{}, fmt.Errorf("PRF parallel algebraic degree overflows int: %d", parallelDeg)
	}
	return ConstraintSet{
		FparInt:          residuals,
		FparIntCoeffs:    residualCoeffs,
		ParallelAlgDeg:   int(parallelDeg),
		AggregatedAlgDeg: 1,
	}, nil
}
