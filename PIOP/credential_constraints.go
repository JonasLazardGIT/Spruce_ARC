package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/credential"
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

func BuildTargetConstraintsRelationNTT(ringQ *ring.Ring, relation string, B []*ring.Poly, m1NTT, m2NTT, r0NTT, zNTT, tNTT *ring.Poly) ([]*ring.Poly, error) {
	switch normalizePublicHashRelation(PublicInputs{HashRelation: relation}) {
	case credential.HashRelationBBTran:
		if ringQ == nil {
			return nil, fmt.Errorf("nil ring")
		}
		if len(B) != 4 {
			return nil, fmt.Errorf("b must have 4 polys, got %d", len(B))
		}
		if m1NTT == nil || m2NTT == nil || r0NTT == nil || zNTT == nil || tNTT == nil {
			return nil, fmt.Errorf("nil bb_tran target input poly")
		}
		mCombined := ringQ.NewPoly()
		ring.Copy(m1NTT, mCombined)
		ringQ.Add(mCombined, m2NTT, mCombined)
		target := ringQ.NewPoly()
		tmp := ringQ.NewPoly()
		ring.Copy(B[0], target)
		ringQ.MulCoeffs(B[1], mCombined, tmp)
		ringQ.Add(target, tmp, target)
		ringQ.MulCoeffs(B[2], r0NTT, tmp)
		ringQ.Add(target, tmp, target)
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
		if len(B) != 4 {
			return nil, fmt.Errorf("b must have 4 polys, got %d", len(B))
		}
		if r1NTT == nil || zNTT == nil {
			return nil, fmt.Errorf("nil bb_tran inverse input poly")
		}
		den := ringQ.NewPoly()
		ringQ.Sub(B[3], r1NTT, den)
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
	rows, _, layout, _, _, _, _, _, err := buildCredentialRows(ringQ, pub.HashRelation, wit, rowOpts, bound)
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

	carrierMIdx := rowLayoutPostSignCarrierM(layout)
	carrierRUIdx := rowLayoutPreSignCarrierRU(layout)
	carrierRIdx := rowLayoutPreSignCarrierR(layout)
	carrierCtrIdx := rowLayoutPostSignCarrierCtr(layout)
	carrierKIdx := rowLayoutPreSignCarrierK(layout)
	m1Idx := rowLayoutPostSignM1(layout)
	m2Idx := rowLayoutPostSignM2(layout)
	ru0Idx := rowLayoutPreSignRU0(layout)
	ru1Idx := rowLayoutPreSignRU1(layout)
	rIdx := rowLayoutPostSignR(layout)
	r0Idx := rowLayoutPostSignR0(layout)
	r1Idx := rowLayoutPostSignR1(layout)
	k0Idx := rowLayoutPreSignK0(layout)
	k1Idx := rowLayoutPreSignK1(layout)
	mHat1Idx := rowLayoutPostSignMHat1(layout)
	mHat2Idx := rowLayoutPostSignMHat2(layout)
	rHat0Idx := rowLayoutPostSignRHat0(layout)
	rHat1Idx := rowLayoutPostSignRHat1(layout)
	zHatIdx := rowLayoutPostSignZHat(layout)
	useBBTran := publicUsesBBTran(pub)
	rowIdxs := []int{carrierMIdx, carrierRUIdx, carrierRIdx, carrierCtrIdx, carrierKIdx, m1Idx, m2Idx, ru0Idx, ru1Idx, rIdx, r0Idx, r1Idx, k0Idx, k1Idx, mHat1Idx, mHat2Idx, rHat0Idx, rHat1Idx}
	if useBBTran {
		rowIdxs = append(rowIdxs, zHatIdx)
	}
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

	msgDecode1, msgDecode2, err := buildPackedMessageCarrierDecodePolys(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("message carrier decode polys: %w", err)
	}
	decode1, decode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier decode polys: %w", err)
	}
	decode1K, decode2K, err := buildCarrierDecodePolys(1, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier decode polys (K): %w", err)
	}
	memMsg, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("message carrier membership poly: %w", err)
	}
	memBound, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("carrier membership poly: %w", err)
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

	carrierMCoeff, err := rowCoeff(carrierMIdx, "carrier M")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierRUCoeff, err := rowCoeff(carrierRUIdx, "carrier RU")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierRCoeff, err := rowCoeff(carrierRIdx, "carrier R")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierCtrCoeff, err := rowCoeff(carrierCtrIdx, "carrier ctr")
	if err != nil {
		return ConstraintSet{}, err
	}
	carrierKCoeff, err := rowCoeff(carrierKIdx, "carrier K")
	if err != nil {
		return ConstraintSet{}, err
	}

	m1AliasCoeffs, err := rowCoeff(m1Idx, "alias M1")
	if err != nil {
		return ConstraintSet{}, err
	}
	m2AliasCoeffs, err := rowCoeff(m2Idx, "alias M2")
	if err != nil {
		return ConstraintSet{}, err
	}
	ru0AliasCoeffs, err := rowCoeff(ru0Idx, "alias RU0")
	if err != nil {
		return ConstraintSet{}, err
	}
	ru1AliasCoeffs, err := rowCoeff(ru1Idx, "alias RU1")
	if err != nil {
		return ConstraintSet{}, err
	}
	rAliasCoeffs, err := rowCoeff(rIdx, "alias R")
	if err != nil {
		return ConstraintSet{}, err
	}
	r0AliasCoeffs, err := rowCoeff(r0Idx, "alias R0")
	if err != nil {
		return ConstraintSet{}, err
	}
	r1AliasCoeffs, err := rowCoeff(r1Idx, "alias R1")
	if err != nil {
		return ConstraintSet{}, err
	}
	k0AliasCoeffs, err := rowCoeff(k0Idx, "alias K0")
	if err != nil {
		return ConstraintSet{}, err
	}
	k1AliasCoeffs, err := rowCoeff(k1Idx, "alias K1")
	if err != nil {
		return ConstraintSet{}, err
	}
	mHat1Coeffs, err := rowCoeff(mHat1Idx, "hat M1")
	if err != nil {
		return ConstraintSet{}, err
	}
	mHat2Coeffs, err := rowCoeff(mHat2Idx, "hat M2")
	if err != nil {
		return ConstraintSet{}, err
	}
	rHat0Coeffs, err := rowCoeff(rHat0Idx, "hat R0")
	if err != nil {
		return ConstraintSet{}, err
	}
	rHat1Coeffs, err := rowCoeff(rHat1Idx, "hat R1")
	if err != nil {
		return ConstraintSet{}, err
	}
	var zHatCoeffs []uint64
	if useBBTran {
		zHatCoeffs, err = rowCoeff(zHatIdx, "bb_tran hat Z")
		if err != nil {
			return ConstraintSet{}, err
		}
	}

	msgDecode1Poly := fpoly.New(q, msgDecode1)
	msgDecode2Poly := fpoly.New(q, msgDecode2)
	decode1Poly := fpoly.New(q, decode1)
	decode2Poly := fpoly.New(q, decode2)
	decode1KPoly := fpoly.New(q, decode1K)
	decode2KPoly := fpoly.New(q, decode2K)
	carrierMPoly := fpoly.New(q, carrierMCoeff)
	carrierRUPoly := fpoly.New(q, carrierRUCoeff)
	carrierRPoly := fpoly.New(q, carrierRCoeff)
	carrierCtrPoly := fpoly.New(q, carrierCtrCoeff)
	carrierKPoly := fpoly.New(q, carrierKCoeff)

	m1CompCoeffs := trimPoly(msgDecode1Poly.Compose(carrierMPoly).Coeffs, q)
	m2CompCoeffs := trimPoly(msgDecode2Poly.Compose(carrierMPoly).Coeffs, q)
	ru0CompCoeffs := trimPoly(decode1Poly.Compose(carrierRUPoly).Coeffs, q)
	ru1CompCoeffs := trimPoly(decode2Poly.Compose(carrierRUPoly).Coeffs, q)
	rCompCoeffs := trimPoly(decode1Poly.Compose(carrierRPoly).Coeffs, q)
	r0CompCoeffs := trimPoly(decode1Poly.Compose(carrierCtrPoly).Coeffs, q)
	r1CompCoeffs := trimPoly(decode2Poly.Compose(carrierCtrPoly).Coeffs, q)
	k0CompCoeffs := trimPoly(decode1KPoly.Compose(carrierKPoly).Coeffs, q)
	k1CompCoeffs := trimPoly(decode2KPoly.Compose(carrierKPoly).Coeffs, q)

	membershipMsg := fpoly.New(q, memMsg)
	membershipBound := fpoly.New(q, memBound)
	membershipCarry := fpoly.New(q, memCarry)
	memMCoeffs := trimPoly(membershipMsg.Compose(carrierMPoly).Coeffs, q)
	memRUCoeffs := trimPoly(membershipBound.Compose(carrierRUPoly).Coeffs, q)
	memRCoeffs := trimPoly(membershipBound.Compose(carrierRPoly).Coeffs, q)
	memCtrCoeffs := trimPoly(membershipBound.Compose(carrierCtrPoly).Coeffs, q)
	memKCoeffs := trimPoly(membershipCarry.Compose(carrierKPoly).Coeffs, q)

	if domainMode != DomainModeExplicit {
		m1CompCoeffs = reducePolyModXN1(m1CompCoeffs, int(ringQ.N), q)
		m2CompCoeffs = reducePolyModXN1(m2CompCoeffs, int(ringQ.N), q)
		ru0CompCoeffs = reducePolyModXN1(ru0CompCoeffs, int(ringQ.N), q)
		ru1CompCoeffs = reducePolyModXN1(ru1CompCoeffs, int(ringQ.N), q)
		rCompCoeffs = reducePolyModXN1(rCompCoeffs, int(ringQ.N), q)
		r0CompCoeffs = reducePolyModXN1(r0CompCoeffs, int(ringQ.N), q)
		r1CompCoeffs = reducePolyModXN1(r1CompCoeffs, int(ringQ.N), q)
		k0CompCoeffs = reducePolyModXN1(k0CompCoeffs, int(ringQ.N), q)
		k1CompCoeffs = reducePolyModXN1(k1CompCoeffs, int(ringQ.N), q)
		memMCoeffs = reducePolyModXN1(memMCoeffs, int(ringQ.N), q)
		memRUCoeffs = reducePolyModXN1(memRUCoeffs, int(ringQ.N), q)
		memRCoeffs = reducePolyModXN1(memRCoeffs, int(ringQ.N), q)
		memCtrCoeffs = reducePolyModXN1(memCtrCoeffs, int(ringQ.N), q)
		memKCoeffs = reducePolyModXN1(memKCoeffs, int(ringQ.N), q)
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

	bridgeM1, bridgeM1Coeffs, err := thetaFromCoeffs(fpoly.New(q, m1AliasCoeffs).Sub(fpoly.New(q, m1CompCoeffs)).Coeffs, "bridge M1")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeM2, bridgeM2Coeffs, err := thetaFromCoeffs(fpoly.New(q, m2AliasCoeffs).Sub(fpoly.New(q, m2CompCoeffs)).Coeffs, "bridge M2")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeRU0, bridgeRU0Coeffs, err := thetaFromCoeffs(fpoly.New(q, ru0AliasCoeffs).Sub(fpoly.New(q, ru0CompCoeffs)).Coeffs, "bridge RU0")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeRU1, bridgeRU1Coeffs, err := thetaFromCoeffs(fpoly.New(q, ru1AliasCoeffs).Sub(fpoly.New(q, ru1CompCoeffs)).Coeffs, "bridge RU1")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeR, bridgeRCoeffs, err := thetaFromCoeffs(fpoly.New(q, rAliasCoeffs).Sub(fpoly.New(q, rCompCoeffs)).Coeffs, "bridge R")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeR0, bridgeR0Coeffs, err := thetaFromCoeffs(fpoly.New(q, r0AliasCoeffs).Sub(fpoly.New(q, r0CompCoeffs)).Coeffs, "bridge R0")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeR1, bridgeR1Coeffs, err := thetaFromCoeffs(fpoly.New(q, r1AliasCoeffs).Sub(fpoly.New(q, r1CompCoeffs)).Coeffs, "bridge R1")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeK0, bridgeK0Coeffs, err := thetaFromCoeffs(fpoly.New(q, k0AliasCoeffs).Sub(fpoly.New(q, k0CompCoeffs)).Coeffs, "bridge K0")
	if err != nil {
		return ConstraintSet{}, err
	}
	bridgeK1, bridgeK1Coeffs, err := thetaFromCoeffs(fpoly.New(q, k1AliasCoeffs).Sub(fpoly.New(q, k1CompCoeffs)).Coeffs, "bridge K1")
	if err != nil {
		return ConstraintSet{}, err
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
	mHat1NTT := rowsNTT[mHat1Idx]
	mHat2NTT := rowsNTT[mHat2Idx]
	rHat0NTT := rowsNTT[rHat0Idx]
	rHat1NTT := rowsNTT[rHat1Idx]
	var zHatNTT *ring.Poly
	if useBBTran {
		zHatNTT = rowsNTT[zHatIdx]
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
	publicTTheta, err := thetaPolyFromCoeff(ringQ, pub.T, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("theta public T: %w", err)
	}

	comRes, err := BuildCommitConstraints(ringQ, thetaAc, []*ring.Poly{m1NTT, m2NTT, ru0NTT, ru1NTT, rNTT}, thetaCom)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("commit residuals: %w", err)
	}

	centerWrapResidual := func(ru, ri, rVal, kVal *ring.Poly) (*ring.Poly, error) {
		if ru == nil || ri == nil || rVal == nil || kVal == nil {
			return nil, fmt.Errorf("nil center-wrap input poly")
		}
		delta := uint64((2*bound + 1) % int64(q))
		res := ringQ.NewPoly()
		ringQ.Add(ru, ri, res)
		ringQ.Sub(res, rVal, res)
		tmp := ringQ.NewPoly()
		scalePolyNTT(ringQ, kVal, delta, tmp)
		ringQ.Sub(res, tmp, res)
		return res, nil
	}
	centerRes0, err := centerWrapResidual(ru0NTT, thetaRI0, r0NTT, k0NTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 0: %w", err)
	}
	centerRes1, err := centerWrapResidual(ru1NTT, thetaRI1, r1NTT, k1NTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 1: %w", err)
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

	var hashResCoeffsExplicit [][]uint64
	var hashRes []*ring.Poly
	if domainMode == DomainModeExplicit {
		thetaBCoeffs := make([][]uint64, 4)
		for i := 0; i < 4; i++ {
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
		if useBBTran {
			targetResCoeffsExplicit := reducePolyModXN1(buildTransformTargetResidualCoeffs(
				q,
				pub.HashRelation,
				thetaBCoeffs,
				mHat1Coeffs,
				mHat2Coeffs,
				rHat0Coeffs,
				zHatCoeffs,
				tThetaTrimmed,
			), int(ringQ.N), q)
			inverseResCoeffsExplicit := reducePolyModXN1(buildTransformInverseResidualCoeffs(
				q,
				pub.HashRelation,
				thetaBCoeffs,
				rHat1Coeffs,
				zHatCoeffs,
			), int(ringQ.N), q)
			pTarget := nttPolyFromFormalCoeffsIfFits(ringQ, targetResCoeffsExplicit)
			if pTarget == nil {
				return ConstraintSet{}, fmt.Errorf("pre-sign explicit target degree=%d exceeds ring dimension %d", len(targetResCoeffsExplicit)-1, ringQ.N)
			}
			pInverse := nttPolyFromFormalCoeffsIfFits(ringQ, inverseResCoeffsExplicit)
			if pInverse == nil {
				return ConstraintSet{}, fmt.Errorf("pre-sign explicit inverse degree=%d exceeds ring dimension %d", len(inverseResCoeffsExplicit)-1, ringQ.N)
			}
			hashResCoeffsExplicit = [][]uint64{targetResCoeffsExplicit, inverseResCoeffsExplicit}
			hashRes = []*ring.Poly{pTarget, pInverse}
		} else {
			hashCoeff := reducePolyModXN1(buildTransformHashResidualCoeffs(
				q,
				pub.HashRelation,
				thetaBCoeffs,
				mHat1Coeffs,
				mHat2Coeffs,
				rHat0Coeffs,
				rHat1Coeffs,
				tThetaTrimmed,
				nil,
				nil,
			), int(ringQ.N), q)
			pHash := nttPolyFromFormalCoeffsIfFits(ringQ, hashCoeff)
			if pHash == nil {
				return ConstraintSet{}, fmt.Errorf("pre-sign explicit hash degree=%d exceeds ring dimension %d", len(hashCoeff)-1, ringQ.N)
			}
			hashResCoeffsExplicit = [][]uint64{hashCoeff}
			hashRes = []*ring.Poly{pHash}
		}
	} else {
		targetRes, err := BuildTargetConstraintsRelationNTT(ringQ, pub.HashRelation, thetaB, mHat1NTT, mHat2NTT, rHat0NTT, zHatNTT, publicTTheta)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("target residuals: %w", err)
		}
		inverseRes, err := BuildInverseConstraintsRelationNTT(ringQ, pub.HashRelation, thetaB, rHat1NTT, zHatNTT)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("inverse residuals: %w", err)
		}
		hashRes = append(targetRes, inverseRes...)
	}

	memMNTT, _, err := thetaFromCoeffs(memMCoeffs, "membership M")
	if err != nil {
		return ConstraintSet{}, err
	}
	memRUNTT, _, err := thetaFromCoeffs(memRUCoeffs, "membership RU")
	if err != nil {
		return ConstraintSet{}, err
	}
	memRNTT, _, err := thetaFromCoeffs(memRCoeffs, "membership R")
	if err != nil {
		return ConstraintSet{}, err
	}
	memCtrNTT, _, err := thetaFromCoeffs(memCtrCoeffs, "membership ctr")
	if err != nil {
		return ConstraintSet{}, err
	}
	memKNTT, _, err := thetaFromCoeffs(memKCoeffs, "membership K")
	if err != nil {
		return ConstraintSet{}, err
	}
	fparBounds := []*ring.Poly{memMNTT, memRUNTT, memRNTT, memCtrNTT, memKNTT}
	var fparBoundsCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		for i, p := range fparBounds {
			coeff, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("pre-sign norm coeffs[%d]: %w", i, cerr)
			}
			fparBoundsCoeffs = append(fparBoundsCoeffs, trimPoly(coeff, q))
		}
	}

	parallelDeg := 2
	if deg := maxDegreeFromCoeffs(decode1); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(decode1K); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(memBound); deg > parallelDeg {
		parallelDeg = deg
	}
	if deg := maxDegreeFromCoeffs(memCarry); deg > parallelDeg {
		parallelDeg = deg
	}

	fparInt := []*ring.Poly{bridgeM1, bridgeM2, bridgeRU0, bridgeRU1, bridgeR, bridgeR0, bridgeR1, bridgeK0, bridgeK1}
	fparInt = append(fparInt, comRes...)
	fparInt = append(fparInt, centerRes0, centerRes1)
	fparInt = append(fparInt, hashRes...)
	fparInt = append(fparInt, m1Pack, m2Pack)

	var fparIntCoeffs [][]uint64
	if domainMode == DomainModeExplicit {
		coeffPoly := func(coeffs []uint64) fpoly.Poly { return fpoly.New(q, coeffs) }
		m1P := coeffPoly(m1AliasCoeffs)
		m2P := coeffPoly(m2AliasCoeffs)
		ru0P := coeffPoly(ru0AliasCoeffs)
		ru1P := coeffPoly(ru1AliasCoeffs)
		rP := coeffPoly(rAliasCoeffs)
		r0P := coeffPoly(r0AliasCoeffs)
		r1P := coeffPoly(r1AliasCoeffs)
		k0P := coeffPoly(k0AliasCoeffs)
		k1P := coeffPoly(k1AliasCoeffs)
		thetaCoeff := func(p *ring.Poly) (fpoly.Poly, error) {
			coeff, err := coeffFromNTTPoly(ringQ, p)
			if err != nil {
				return fpoly.Poly{}, err
			}
			return coeffPoly(coeff), nil
		}

		acCoeff := make([][]fpoly.Poly, len(thetaAc))
		for i := range thetaAc {
			acCoeff[i] = make([]fpoly.Poly, len(thetaAc[i]))
			for j := range thetaAc[i] {
				c, err := thetaCoeff(thetaAc[i][j])
				if err != nil {
					return ConstraintSet{}, fmt.Errorf("theta Ac[%d][%d] coeffs: %w", i, j, err)
				}
				acCoeff[i][j] = c
			}
		}
		comCoeff := make([]fpoly.Poly, len(thetaCom))
		for i := range thetaCom {
			c, err := thetaCoeff(thetaCom[i])
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("theta Com[%d] coeffs: %w", i, err)
			}
			comCoeff[i] = c
		}
		ri0Coeff, err := thetaCoeff(thetaRI0)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("theta RI0 coeffs: %w", err)
		}
		ri1Coeff, err := thetaCoeff(thetaRI1)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("theta RI1 coeffs: %w", err)
		}
		selCoeff, err := buildPackingSelectorCoeff(ringQ, omega)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("packing selector coeffs: %w", err)
		}
		selP := coeffPoly(selCoeff)
		oneMinusSelP := fpoly.Const(q, 1).Sub(selP)

		explicitFparCoeffs := [][]uint64{
			bridgeM1Coeffs,
			bridgeM2Coeffs,
			bridgeRU0Coeffs,
			bridgeRU1Coeffs,
			bridgeRCoeffs,
			bridgeR0Coeffs,
			bridgeR1Coeffs,
			bridgeK0Coeffs,
			bridgeK1Coeffs,
		}
		for i := range acCoeff {
			sum := fpoly.Zero(q)
			if i < len(comCoeff) {
				sum = sum.Sub(comCoeff[i])
			}
			for j := 0; j < len(acCoeff[i]); j++ {
				var term fpoly.Poly
				switch j {
				case 0:
					term = acCoeff[i][j].Mul(m1P)
				case 1:
					term = acCoeff[i][j].Mul(m2P)
				case 2:
					term = acCoeff[i][j].Mul(ru0P)
				case 3:
					term = acCoeff[i][j].Mul(ru1P)
				case 4:
					term = acCoeff[i][j].Mul(rP)
				default:
					term = fpoly.Zero(q)
				}
				sum = sum.Add(term)
			}
			explicitFparCoeffs = append(explicitFparCoeffs, sum.Coeffs)
		}
		delta := uint64(2*bound + 1)
		res0 := ru0P.Add(ri0Coeff).Sub(r0P).Sub(k0P.Scale(delta))
		res1 := ru1P.Add(ri1Coeff).Sub(r1P).Sub(k1P.Scale(delta))
		explicitFparCoeffs = append(explicitFparCoeffs, res0.Coeffs, res1.Coeffs)
		explicitFparCoeffs = append(explicitFparCoeffs, hashResCoeffsExplicit...)
		explicitFparCoeffs = append(explicitFparCoeffs, selP.Mul(m1P).Coeffs, oneMinusSelP.Mul(m2P).Coeffs)

		fparInt = make([]*ring.Poly, len(explicitFparCoeffs))
		fparIntCoeffs = make([][]uint64, len(explicitFparCoeffs))
		for i, coeffs := range explicitFparCoeffs {
			reduced := reducePolyModXN1(coeffs, int(ringQ.N), q)
			p := nttPolyFromFormalCoeffsIfFits(ringQ, reduced)
			if p == nil {
				return ConstraintSet{}, fmt.Errorf("pre-sign explicit family %d degree=%d exceeds ring dimension %d", i, len(trimPoly(reduced, q))-1, ringQ.N)
			}
			fparInt[i] = p
			fparIntCoeffs[i] = trimPoly(reduced, q)
		}
	} else {
		for i, p := range fparInt {
			coeff, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				return ConstraintSet{}, fmt.Errorf("pre-sign int coeffs[%d]: %w", i, cerr)
			}
			fparIntCoeffs = append(fparIntCoeffs, trimPoly(coeff, q))
		}
	}

	lagrangeBasis, err := buildLagrangeBasisCoeffs(omega, q)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("pre-sign lagrange basis: %w", err)
	}
	transformHCoeff, _, err := buildTransformBridgeHFromNTTMatrix(ringQ, omega, ncols, 1)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("pre-sign transform H: %w", err)
	}
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
	faggNorm := make([]*ring.Poly, 0, 4*ncols)
	faggNormCoeffs := make([][]uint64, 0, 4*ncols)
	for _, pair := range []bridgePair{
		{srcNTT: m1NTT, hatNTT: mHat1NTT, srcCoeff: m1AliasCoeffs, hatCoeff: mHat1Coeffs},
		{srcNTT: m2NTT, hatNTT: mHat2NTT, srcCoeff: m2AliasCoeffs, hatCoeff: mHat2Coeffs},
		{srcNTT: r0NTT, hatNTT: rHat0NTT, srcCoeff: r0AliasCoeffs, hatCoeff: rHat0Coeffs},
		{srcNTT: r1NTT, hatNTT: rHat1NTT, srcCoeff: r1AliasCoeffs, hatCoeff: rHat1Coeffs},
	} {
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
