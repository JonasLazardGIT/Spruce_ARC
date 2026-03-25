package PIOP

import (
	"fmt"

	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildFparRangeMembership adds one parallel constraint row per input row:
// for each row P, it appends the true composition P_B(P(X)).
func buildFparRangeMembership(
	r *ring.Ring,
	rows []*ring.Poly,
	spec RangeMembershipSpec,
) (Fpar []*ring.Poly) {
	q := r.Modulus[0]
	for _, row := range rows {
		coeff := r.NewPoly()
		r.InvNTT(row, coeff)
		out := r.NewPoly()
		for i, c := range coeff.Coeffs[0] {
			out.Coeffs[0][i] = EvalPoly(spec.Coeffs, c%q, q)
		}
		r.NTT(out, out)
		Fpar = append(Fpar, out)
	}
	return
}

// buildFparRangeMembershipCompose builds parallel constraints as the true
// polynomial composition P_B(P_i(X)). This is required for θ>1 K-point replay,
// because the verifier evaluates F_j at random points outside Ω.
// Inputs are expected in NTT domain; output polys are in NTT domain.
func buildFparRangeMembershipCompose(
	r *ring.Ring,
	rows []*ring.Poly,
	spec RangeMembershipSpec,
) (Fpar []*ring.Poly) {
	q := r.Modulus[0]
	if len(spec.Coeffs) == 0 {
		return nil
	}
	for _, row := range rows {
		if row == nil {
			Fpar = append(Fpar, nil)
			continue
		}
		// Horner composition in coefficient domain: res = P_B(P(X)).
		resCoeff := r.NewPoly()
		tmpNTT := r.NewPoly()
		for i := len(spec.Coeffs) - 1; i >= 0; i-- {
			// res = res * row (polynomial multiplication).
			r.NTT(resCoeff, tmpNTT)
			r.MulCoeffs(tmpNTT, row, tmpNTT)
			r.InvNTT(tmpNTT, resCoeff)
			c := spec.Coeffs[i] % q
			if c != 0 {
				resCoeff.Coeffs[0][0] = (resCoeff.Coeffs[0][0] + c) % q
			}
		}
		resNTT := r.NewPoly()
		r.NTT(resCoeff, resNTT)
		Fpar = append(Fpar, resNTT)
	}
	return
}

// buildFparRangeMembershipComposeFormalCoeffs returns replayable membership
// constraints as formal coefficient vectors, together with ring-polynomial
// materialisations when the resulting degree fits ringQ.N.
func buildFparRangeMembershipComposeFormalCoeffs(
	r *ring.Ring,
	rows []*ring.Poly,
	spec RangeMembershipSpec,
) (Fpar []*ring.Poly, coeffs [][]uint64, err error) {
	if r == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(spec.Coeffs) == 0 {
		return []*ring.Poly{}, [][]uint64{}, nil
	}
	q := r.Modulus[0]
	memberPoly := fpoly.New(q, spec.Coeffs)

	toFormal := func(row *ring.Poly) (fpoly.Poly, error) {
		if row == nil {
			return fpoly.Zero(q), fmt.Errorf("nil row")
		}
		coeff, cerr := coeffFromNTTPoly(r, row)
		if cerr != nil {
			return fpoly.Zero(q), cerr
		}
		return fpoly.New(q, coeff), nil
	}
	toNTTIfFits := func(c []uint64) *ring.Poly {
		if len(c) == 0 {
			c = []uint64{0}
		}
		if len(c) > int(r.N) {
			return nil
		}
		out := r.NewPoly()
		copy(out.Coeffs[0], c)
		r.NTT(out, out)
		return out
	}

	Fpar = make([]*ring.Poly, len(rows))
	coeffs = make([][]uint64, len(rows))
	for i := range rows {
		rowFormal, ferr := toFormal(rows[i])
		if ferr != nil {
			return nil, nil, fmt.Errorf("row %d: %w", i, ferr)
		}
		composed := memberPoly.Compose(rowFormal)
		coeffCopy := append([]uint64(nil), composed.Coeffs...)
		coeffs[i] = coeffCopy
		Fpar[i] = toNTTIfFits(coeffCopy)
	}
	return Fpar, coeffs, nil
}
