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

// BuildCredentialConstraintSetPre builds the pre-sign constraint set directly
// from the provided witness polynomials (coeff domain).
func BuildCredentialConstraintSetPre(ringQ *ring.Ring, bound int64, pub PublicInputs, wit WitnessInputs, omega []uint64) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	if len(wit.M1) == 0 || len(wit.M2) == 0 || len(wit.RU0) == 0 || len(wit.RU1) == 0 || len(wit.R) == 0 || len(wit.R0) == 0 || len(wit.R1) == 0 || len(wit.K0) == 0 || len(wit.K1) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing pre-sign witness rows")
	}
	rows := []*ring.Poly{
		wit.M1[0],
		wit.M2[0],
		wit.RU0[0],
		wit.RU1[0],
		wit.R[0],
		wit.R0[0],
		wit.R1[0],
		wit.K0[0],
		wit.K1[0],
	}
	if len(wit.T) > 0 {
		tPoly := ringQ.NewPoly()
		if len(wit.T) > len(tPoly.Coeffs[0]) {
			return ConstraintSet{}, fmt.Errorf("t length %d exceeds ring dimension %d", len(wit.T), len(tPoly.Coeffs[0]))
		}
		q := int64(ringQ.Modulus[0])
		for i := range wit.T {
			v := wit.T[i] % q
			if v < 0 {
				v += q
			}
			tPoly.Coeffs[0][i] = uint64(v)
		}
		rows = append(rows, tPoly)
	}
	if len(wit.U) > 0 {
		rows = append(rows, wit.U...)
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	domainMode := DomainModeExplicit
	return buildCredentialConstraintSetPreFromRows(ringQ, bound, pub, RowLayout{}, rowsNTT, omega, domainMode)
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
	headThetaNTT := func(p *ring.Poly) (*ring.Poly, error) {
		if p == nil {
			return nil, fmt.Errorf("nil row poly")
		}
		if domainMode != DomainModeExplicit {
			return p, nil
		}
		coeffs, err := coeffFromNTTPoly(ringQ, p)
		if err != nil {
			return nil, err
		}
		q := ringQ.Modulus[0]
		head := make([]uint64, ncols)
		for i := 0; i < ncols; i++ {
			head[i] = EvalPoly(coeffs, omega[i]%q, q)
		}
		return BuildThetaPrime(ringQ, head, omega), nil
	}

	m1NTT, err := headThetaNTT(rowsNTT[m1Idx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("m1 theta row: %w", err)
	}
	m2NTT, err := headThetaNTT(rowsNTT[m2Idx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("m2 theta row: %w", err)
	}
	ru0NTT, err := headThetaNTT(rowsNTT[ru0Idx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("ru0 theta row: %w", err)
	}
	ru1NTT, err := headThetaNTT(rowsNTT[ru1Idx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("ru1 theta row: %w", err)
	}
	rNTT, err := headThetaNTT(rowsNTT[rIdx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("r theta row: %w", err)
	}
	r0NTT, err := headThetaNTT(rowsNTT[r0Idx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("r0 theta row: %w", err)
	}
	r1NTT, err := headThetaNTT(rowsNTT[r1Idx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("r1 theta row: %w", err)
	}
	k0NTT, err := headThetaNTT(rowsNTT[k0Idx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("k0 theta row: %w", err)
	}
	k1NTT, err := headThetaNTT(rowsNTT[k1Idx])
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("k1 theta row: %w", err)
	}

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
		for i, coeffs := range comResCoeffs {
			if p := nttPolyFromFormalCoeffsIfFits(ringQ, coeffs); p != nil {
				comRes[i] = p
			}
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
		for i, coeffs := range centerResCoeffs {
			if p := nttPolyFromFormalCoeffsIfFits(ringQ, coeffs); p != nil {
				centerRes[i] = p
			}
		}
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
		if p := nttPolyFromFormalCoeffsIfFits(ringQ, m1PackCoeff); p != nil {
			m1Pack = p
		}
		if p := nttPolyFromFormalCoeffsIfFits(ringQ, m2PackCoeff); p != nil {
			m2Pack = p
		}
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
		for i, coeffs := range hashResCoeffs {
			if p := nttPolyFromFormalCoeffsIfFits(ringQ, coeffs); p != nil {
				hashRes[i] = p
			}
		}
	}

	if domainMode == DomainModeExplicit {
		headFromNTT := func(p *ring.Poly) ([]uint64, error) {
			if p == nil {
				return nil, fmt.Errorf("nil row poly")
			}
			coeffs, err := coeffFromNTTPoly(ringQ, p)
			if err != nil {
				return nil, err
			}
			head := make([]uint64, ncols)
			for i := 0; i < ncols; i++ {
				head[i] = EvalPoly(coeffs, omega[i]%q, q)
			}
			return head, nil
		}
		thetaFromHead := func(head []uint64) (*ring.Poly, []uint64) {
			coeffs := Interpolate(omega, head, q)
			out := ringQ.NewPoly()
			copy(out.Coeffs[0], coeffs)
			ringQ.NTT(out, out)
			return out, trimPoly(coeffs, q)
		}

		m1Head, err := headFromNTT(m1NTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("m1 head: %w", err)
		}
		m2Head, err := headFromNTT(m2NTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("m2 head: %w", err)
		}
		ru0Head, err := headFromNTT(ru0NTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("ru0 head: %w", err)
		}
		ru1Head, err := headFromNTT(ru1NTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("ru1 head: %w", err)
		}
		rHead, err := headFromNTT(rNTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("r head: %w", err)
		}
		r0Head, err := headFromNTT(r0NTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("r0 head: %w", err)
		}
		r1Head, err := headFromNTT(r1NTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("r1 head: %w", err)
		}
		k0Head, err := headFromNTT(k0NTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("k0 head: %w", err)
		}
		k1Head, err := headFromNTT(k1NTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("k1 head: %w", err)
		}

		// Commitment residual heads.
		comResHeads := make([][]uint64, len(pub.Com))
		vecHeads := [][]uint64{m1Head, m2Head, ru0Head, ru1Head, rHead}
		for i := range pub.Com {
			if len(pub.Ac[i]) != len(vecHeads) {
				return ConstraintSet{}, fmt.Errorf("Ac row %d length=%d want %d", i, len(pub.Ac[i]), len(vecHeads))
			}
			head := make([]uint64, ncols)
			for k := 0; k < ncols; k++ {
				acc := uint64(0)
				for j := 0; j < len(vecHeads); j++ {
					acc = lvcs.MulAddMod64(acc, pub.Ac[i][j].Coeffs[0][k]%q, vecHeads[j][k]%q, q)
				}
				comVal := pub.Com[i].Coeffs[0][k] % q
				head[k] = modSub(acc, comVal, q)
			}
			comResHeads[i] = head
		}

		// Centering residual heads.
		centerResHeads := make([][]uint64, 2)
		delta := uint64((2*bound + 1) % int64(q))
		res0 := make([]uint64, ncols)
		res1 := make([]uint64, ncols)
		for k := 0; k < ncols; k++ {
			ri0 := pub.RI0[0].Coeffs[0][k] % q
			ri1 := pub.RI1[0].Coeffs[0][k] % q
			acc0 := modAdd(ru0Head[k]%q, ri0, q)
			acc0 = modSub(acc0, r0Head[k]%q, q)
			acc0 = modSub(acc0, modMul(delta, k0Head[k]%q, q), q)
			res0[k] = acc0
			acc1 := modAdd(ru1Head[k]%q, ri1, q)
			acc1 = modSub(acc1, r1Head[k]%q, q)
			acc1 = modSub(acc1, modMul(delta, k1Head[k]%q, q), q)
			res1[k] = acc1
		}
		centerResHeads[0] = res0
		centerResHeads[1] = res1

		// Packing residual heads.
		half := ncols / 2
		m1PackHead := make([]uint64, ncols)
		m2PackHead := make([]uint64, ncols)
		for k := 0; k < ncols; k++ {
			if k >= half {
				m1PackHead[k] = m1Head[k] % q
			} else {
				m2PackHead[k] = m2Head[k] % q
			}
		}

		// Hash residual heads.
		tCoeff := make([]uint64, ringQ.N)
		for i := 0; i < ringQ.N && i < len(pub.T); i++ {
			v := pub.T[i] % int64(q)
			if v < 0 {
				v += int64(q)
			}
			tCoeff[i] = uint64(v)
		}
		tHead := make([]uint64, ncols)
		for i := 0; i < ncols; i++ {
			tHead[i] = EvalPoly(tCoeff, omega[i]%q, q) % q
		}
		hashHead := make([]uint64, ncols)
		for k := 0; k < ncols; k++ {
			b0 := pub.B[0].Coeffs[0][k] % q
			b1 := pub.B[1].Coeffs[0][k] % q
			b2 := pub.B[2].Coeffs[0][k] % q
			b3 := pub.B[3].Coeffs[0][k] % q
			mCombined := modAdd(m1Head[k]%q, m2Head[k]%q, q)
			num := modAdd(b0, modMul(b1, mCombined, q), q)
			num = modAdd(num, modMul(b2, r0Head[k]%q, q), q)
			den := modSub(b3, r1Head[k]%q, q)
			hashHead[k] = modSub(modMul(den, tHead[k]%q, q), num, q)
		}

		// Override residual polynomials + coeffs from explicit heads.
		for i := range comResHeads {
			p, coeffs := thetaFromHead(comResHeads[i])
			comRes[i] = p
			comResCoeffs[i] = coeffs
		}
		for i := range centerResHeads {
			p, coeffs := thetaFromHead(centerResHeads[i])
			centerRes[i] = p
			centerResCoeffs[i] = coeffs
		}
		p, coeffs := thetaFromHead(hashHead)
		hashRes[0] = p
		hashResCoeffs = [][]uint64{coeffs}
		p, coeffs = thetaFromHead(m1PackHead)
		m1Pack = p
		m1PackCoeff = coeffs
		p, coeffs = thetaFromHead(m2PackHead)
		m2Pack = p
		m2PackCoeff = coeffs
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
		row, rerr := headThetaNTT(rowsNTT[idx])
		if rerr != nil {
			return ConstraintSet{}, fmt.Errorf("bound theta row %d: %w", idx, rerr)
		}
		boundedRows = append(boundedRows, row)
	}
	carryRows := make([]*ring.Poly, 0, len(carryIdxs))
	for _, idx := range carryIdxs {
		if idx < 0 || idx >= len(rowsNTT) {
			return ConstraintSet{}, fmt.Errorf("pre-sign carry row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		row, rerr := headThetaNTT(rowsNTT[idx])
		if rerr != nil {
			return ConstraintSet{}, fmt.Errorf("carry theta row %d: %w", idx, rerr)
		}
		carryRows = append(carryRows, row)
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

// BuildPRFConstraintSet constructs the parallel constraints for tag = F(m2, nonce)
// using the Poseidon2-like params in prfParams. This follows the native
// x^d arithmetization selected by the shipped PRF parameters, introducing
// degree-d constraints for each round/lanes transition and linear constraints
// for the feed-forward/tag.
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
