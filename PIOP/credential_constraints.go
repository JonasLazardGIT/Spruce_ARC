package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/fpoly"
	"vSIS-Signature/prf"
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

func BuildHashConstraintsRelationNTT(ringQ *ring.Ring, relation string, B []*ring.Poly, m1NTT, m2NTT, r0NTT, r1NTT, tNTT, mSigmaR1NTT, r0R1NTT *ring.Poly) ([]*ring.Poly, error) {
	switch normalizePublicHashRelation(PublicInputs{HashRelation: relation}) {
	case "":
		return nil, fmt.Errorf("missing or invalid hash relation %q", relation)
	case "bbs":
		return BuildHashConstraintsNTT(ringQ, B, m1NTT, m2NTT, r0NTT, r1NTT, tNTT)
	case "bb_tran":
		if ringQ == nil {
			return nil, fmt.Errorf("nil ring")
		}
		if len(B) != 4 {
			return nil, fmt.Errorf("b must have 4 polys, got %d", len(B))
		}
		if m1NTT == nil || m2NTT == nil || r0NTT == nil || r1NTT == nil || tNTT == nil || mSigmaR1NTT == nil || r0R1NTT == nil {
			return nil, fmt.Errorf("nil bb_tran hash input poly")
		}
		mCombined := ringQ.NewPoly()
		ring.Copy(m1NTT, mCombined)
		ringQ.Add(mCombined, m2NTT, mCombined)
		b3b1 := ringQ.NewPoly()
		b3b2 := ringQ.NewPoly()
		ringQ.MulCoeffs(B[3], B[1], b3b1)
		ringQ.MulCoeffs(B[3], B[2], b3b2)
		res := ringQ.NewPoly()
		tmp := ringQ.NewPoly()
		ringQ.MulCoeffs(B[3], tNTT, res)
		ringQ.MulCoeffs(tNTT, r1NTT, tmp)
		ringQ.Sub(res, tmp, res)
		ringQ.MulCoeffs(b3b1, mCombined, tmp)
		ringQ.Sub(res, tmp, res)
		ringQ.MulCoeffs(b3b2, r0NTT, tmp)
		ringQ.Sub(res, tmp, res)
		ringQ.MulCoeffs(B[1], mSigmaR1NTT, tmp)
		ringQ.Add(res, tmp, res)
		ringQ.MulCoeffs(B[2], r0R1NTT, tmp)
		ringQ.Add(res, tmp, res)
		one := ringQ.NewPoly()
		one.Coeffs[0][0] = 1 % ringQ.Modulus[0]
		ringQ.NTT(one, one)
		ringQ.Sub(res, one, res)
		return []*ring.Poly{res}, nil
	default:
		return nil, fmt.Errorf("unsupported hash relation %q", relation)
	}
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
func BuildCredentialConstraintSetPre(ringQ *ring.Ring, bound int64, pub PublicInputs, wit WitnessInputs, omega []uint64, opts SimOpts) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	if len(wit.M1) == 0 || len(wit.M2) == 0 || len(wit.RU0) == 0 || len(wit.RU1) == 0 || len(wit.R) == 0 || len(wit.R0) == 0 || len(wit.R1) == 0 || len(wit.K0) == 0 || len(wit.K1) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing pre-sign witness rows")
	}
	if publicUsesBBTran(pub) && len(wit.Z) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Z witness rows")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	if bound <= 0 {
		return ConstraintSet{}, fmt.Errorf("invalid bound %d for carrier encoding", bound)
	}
	opts.applyDefaults()
	rowOpts := opts
	rowOpts.NCols = len(omega)
	rows, _, layout, _, _, _, _, _, err := buildCredentialRows(ringQ, pub.HashRelation, wit, rowOpts, bound, pub.X0CoeffBound)
	if err != nil {
		return ConstraintSet{}, err
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	return buildCredentialConstraintSetPreFromRows(ringQ, bound, pub, layout, rowsNTT, omega, opts.DomainMode)
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
	x0CarryDecode, err := buildSingletonCarrierDecodePoly(1, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("x0 carry decode polys: %w", err)
	}
	decode1K, _, err := buildCarrierDecodePolys(1, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier decode polys (K): %w", err)
	}
	memMsg, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("message carrier membership poly: %w", err)
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

	bridgeM1, _, err := thetaFromCoeffs(fpoly.New(q, m1AliasCoeffs).Sub(fpoly.New(q, m1CompCoeffs)).Coeffs, "bridge M1")
	if err != nil {
		return ConstraintSet{}, err
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

	commitWitness := []*ring.Poly{m1NTT, m2NTT}
	commitWitness = append(commitWitness, ru0NTTs...)
	commitWitness = append(commitWitness, ru1NTT, rNTT)
	comRes, err := BuildCommitConstraints(ringQ, thetaAc, commitWitness, thetaCom)
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
	selNTT, oneMinusSel, err := buildPackingSelectorNTT(ringQ, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("packing selector: %w", err)
	}
	m1Pack := ringQ.NewPoly()
	m2Pack := ringQ.NewPoly()
	ringQ.MulCoeffs(selNTT, m1NTT, m1Pack)
	ringQ.MulCoeffs(oneMinusSel, m2NTT, m2Pack)

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
			mCombinedVal := modAdd(EvalPoly(mHat1Coeffs, x, q)%q, EvalPoly(mHat2Coeffs, x, q)%q, q)
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
	if err := addBoundPoly(memMCoeffs, "membership M"); err != nil {
		return ConstraintSet{}, err
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

	fparInt := []*ring.Poly{bridgeM1, bridgeM2}
	fparInt = append(fparInt, bridgeRU0...)
	fparInt = append(fparInt, bridgeRU1, bridgeR)
	fparInt = append(fparInt, bridgeR0...)
	fparInt = append(fparInt, bridgeR1)
	fparInt = append(fparInt, bridgeK0...)
	fparInt = append(fparInt, bridgeK1)
	fparInt = append(fparInt, comRes...)
	fparInt = append(fparInt, centerRes...)
	fparInt = append(fparInt, hashRes...)
	fparInt = append(fparInt, m1Pack, m2Pack)
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
	bridgePairs := []bridgePair{
		{srcNTT: m1NTT, hatNTT: mHat1NTT, srcCoeff: m1AliasCoeffs, hatCoeff: mHat1Coeffs},
		{srcNTT: m2NTT, hatNTT: mHat2NTT, srcCoeff: m2AliasCoeffs, hatCoeff: mHat2Coeffs},
		{srcNTT: r1NTT, hatNTT: rHat1NTT, srcCoeff: r1AliasCoeffs, hatCoeff: rHat1Coeffs},
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
