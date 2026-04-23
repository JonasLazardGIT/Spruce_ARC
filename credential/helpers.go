package credential

import (
	"fmt"

	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func CenterWithCarry(v, bound int64) (centered int64, carry int64, err error) {
	if bound <= 0 {
		return 0, 0, fmt.Errorf("invalid bound %d", bound)
	}
	delta := 2*bound + 1
	centered = CenterBounded(v, bound)
	diff := v - centered
	if diff%delta != 0 {
		return 0, 0, fmt.Errorf("center carry mismatch: v=%d centered=%d delta=%d", v, centered, delta)
	}
	carry = diff / delta
	return centered, carry, nil
}

func CenterBounded(v, bound int64) int64 {
	mod := 2*bound + 1
	w := (v + bound) % mod
	if w < 0 {
		w += mod
	}
	return w - bound
}

func clonePoly(ringQ *ring.Ring, p *ring.Poly) *ring.Poly {
	cp := ringQ.NewPoly()
	ring.Copy(p, cp)
	return cp
}

func coeffPolyToInt64(ringQ *ring.Ring, p *ring.Poly) []int64 {
	out := make([]int64, ringQ.N)
	q := int64(ringQ.Modulus[0])
	half := q / 2
	for i, c := range p.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		out[i] = v
	}
	return out
}

func polyFromCenteredInt64(ringQ *ring.Ring, coeffs []int64) *ring.Poly {
	p := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i := 0; i < len(coeffs) && i < ringQ.N; i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func combineMessageRows(ringQ *ring.Ring, m, k *ring.Poly) *ring.Poly {
	combined := clonePoly(ringQ, m)
	ringQ.Add(combined, k, combined)
	return combined
}

func SplitBBTranB(B []*ring.Poly, x0Len int, targetDim int) (*ring.Poly, *ring.Poly, []*ring.Poly, *ring.Poly, error) {
	if targetDim != 1 {
		return nil, nil, nil, nil, fmt.Errorf("unsupported TargetDim=%d", targetDim)
	}
	if x0Len <= 0 {
		return nil, nil, nil, nil, fmt.Errorf("invalid X0Len=%d", x0Len)
	}
	if want := 3 + x0Len; len(B) != want {
		return nil, nil, nil, nil, fmt.Errorf("b must contain %d polynomials for X0Len=%d, got %d", want, x0Len, len(B))
	}
	return B[0], B[1], B[2 : 2+x0Len], B[len(B)-1], nil
}

func computeB2LinearTermNTT(ringQ *ring.Ring, b2 []*ring.Poly, r0 []*ring.Poly) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(b2) == 0 || len(r0) == 0 {
		return nil, fmt.Errorf("empty b2/r0")
	}
	if len(b2) != len(r0) {
		return nil, fmt.Errorf("b2 length=%d mismatches r0 length=%d", len(b2), len(r0))
	}
	acc := ringQ.NewPoly()
	tmp := ringQ.NewPoly()
	for i := range b2 {
		if b2[i] == nil || r0[i] == nil {
			return nil, fmt.Errorf("nil b2/r0 poly at index %d", i)
		}
		r0NTT := clonePoly(ringQ, r0[i])
		ringQ.NTT(r0NTT, r0NTT)
		ringQ.MulCoeffs(b2[i], r0NTT, tmp)
		ringQ.Add(acc, tmp, acc)
	}
	return acc, nil
}

func IsAdmissible(
	ringQ *ring.Ring,
	B []*ring.Poly,
	r1 *ring.Poly,
) (bool, error) {
	if ringQ == nil {
		return false, fmt.Errorf("nil ring")
	}
	if len(B) < 4 {
		return false, fmt.Errorf("b must contain at least 4 polynomials, got %d", len(B))
	}
	if r1 == nil {
		return false, fmt.Errorf("nil r1 polynomial")
	}
	b3 := B[len(B)-1]
	return vsishash.IsInvertibleDenominator(ringQ, b3, clonePoly(ringQ, r1)), nil
}

func ComputeInverseWitness(
	ringQ *ring.Ring,
	B []*ring.Poly,
	r1 *ring.Poly,
) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(B) < 4 {
		return nil, fmt.Errorf("b must contain at least 4 polynomials, got %d", len(B))
	}
	if r1 == nil {
		return nil, fmt.Errorf("nil r1 polynomial")
	}
	zNTT, err := vsishash.ComputeBBTranInverse(ringQ, B[len(B)-1], clonePoly(ringQ, r1))
	if err != nil {
		return nil, err
	}
	zCoeff := ringQ.NewPoly()
	ringQ.InvNTT(zNTT, zCoeff)
	return zCoeff, nil
}

func ComputeTargetPolysVector(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m,
	k *ring.Poly,
	r0 []*ring.Poly,
	r1 *ring.Poly,
) (*ring.Poly, *ring.Poly, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	b0, b1, b2, b3, err := SplitBBTranB(B, len(r0), DefaultTargetDim)
	if err != nil {
		return nil, nil, err
	}
	if m == nil || k == nil || len(r0) == 0 || r1 == nil {
		return nil, nil, fmt.Errorf("nil input polynomial")
	}
	mu := combineMessageRows(ringQ, m, k)
	zNTT, tNTT, err := vsishash.ComputeBBTranTargetVector(ringQ, b0, b1, b2, b3, clonePoly(ringQ, mu), clonePolySlice(ringQ, r0), clonePoly(ringQ, r1))
	if err != nil {
		return nil, nil, err
	}
	zCoeff := ringQ.NewPoly()
	tCoeff := ringQ.NewPoly()
	ringQ.InvNTT(zNTT, zCoeff)
	ringQ.InvNTT(tNTT, tCoeff)
	return zCoeff, tCoeff, nil
}

func clonePolySlice(ringQ *ring.Ring, polys []*ring.Poly) []*ring.Poly {
	out := make([]*ring.Poly, len(polys))
	for i := range polys {
		out[i] = clonePoly(ringQ, polys[i])
	}
	return out
}

func ComputeTargetPolys(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m,
	k,
	r0,
	r1 *ring.Poly,
) (*ring.Poly, *ring.Poly, error) {
	return ComputeTargetPolysVector(ringQ, B, m, k, []*ring.Poly{r0}, r1)
}

func ComputeTargetVector(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m,
	k *ring.Poly,
	r0 []*ring.Poly,
	r1 *ring.Poly,
) (*ring.Poly, []int64, error) {
	zCoeff, tCoeff, err := ComputeTargetPolysVector(ringQ, B, m, k, r0, r1)
	if err != nil {
		return nil, nil, err
	}
	return zCoeff, coeffPolyToInt64(ringQ, tCoeff), nil
}

func ComputeTarget(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m,
	k,
	r0,
	r1 *ring.Poly,
) (*ring.Poly, []int64, error) {
	return ComputeTargetVector(ringQ, B, m, k, []*ring.Poly{r0}, r1)
}

func VerifyTargetRelationVector(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m,
	k *ring.Poly,
	r0 []*ring.Poly,
	r1,
	z,
	t *ring.Poly,
) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	b0, b1, b2, b3, err := SplitBBTranB(B, len(r0), DefaultTargetDim)
	if err != nil {
		return err
	}
	if m == nil || k == nil || len(r0) == 0 || r1 == nil || z == nil || t == nil {
		return fmt.Errorf("nil input polynomial")
	}
	muNTT := combineMessageRows(ringQ, clonePoly(ringQ, m), clonePoly(ringQ, k))
	ringQ.NTT(muNTT, muNTT)
	r1NTT := clonePoly(ringQ, r1)
	zNTT := clonePoly(ringQ, z)
	tNTT := clonePoly(ringQ, t)
	ringQ.NTT(r1NTT, r1NTT)
	ringQ.NTT(zNTT, zNTT)
	ringQ.NTT(tNTT, tNTT)
	r0TermNTT, err := computeB2LinearTermNTT(ringQ, b2, r0)
	if err != nil {
		return err
	}

	den := ringQ.NewPoly()
	ringQ.Sub(b3, r1NTT, den)
	inverseResidual := ringQ.NewPoly()
	ringQ.MulCoeffs(den, zNTT, inverseResidual)
	one := ringQ.NewPoly()
	one.Coeffs[0][0] = 1 % ringQ.Modulus[0]
	ringQ.NTT(one, one)
	ringQ.Sub(inverseResidual, one, inverseResidual)

	targetResidual := ringQ.NewPoly()
	ring.Copy(b0, targetResidual)
	tmp := ringQ.NewPoly()
	ringQ.MulCoeffs(b1, muNTT, tmp)
	ringQ.Add(targetResidual, tmp, targetResidual)
	ringQ.Add(targetResidual, r0TermNTT, targetResidual)
	ringQ.Add(targetResidual, zNTT, targetResidual)
	ringQ.Sub(targetResidual, tNTT, targetResidual)

	for _, p := range []*ring.Poly{inverseResidual, targetResidual} {
		for _, c := range p.Coeffs[0] {
			if c%ringQ.Modulus[0] != 0 {
				return fmt.Errorf("target relation does not hold")
			}
		}
	}
	return nil
}

func VerifyTargetRelation(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m,
	k,
	r0,
	r1,
	z,
	t *ring.Poly,
) error {
	return VerifyTargetRelationVector(ringQ, B, m, k, []*ring.Poly{r0}, r1, z, t)
}

func HashMessage(
	ringQ *ring.Ring,
	B []*ring.Poly,
	relation string,
	m1, m2, r0, r1 *ring.Poly,
) ([]int64, error) {
	return HashMessageVector(ringQ, B, relation, m1, m2, []*ring.Poly{r0}, r1)
}

func HashMessageVector(
	ringQ *ring.Ring,
	B []*ring.Poly,
	relation string,
	m1, m2 *ring.Poly,
	r0 []*ring.Poly,
	r1 *ring.Poly,
) ([]int64, error) {
	relation = NormalizeHashRelation(relation)
	switch relation {
	case HashRelationBBTran:
		_, tCoeff, err := ComputeTargetVector(ringQ, B, m1, m2, r0, r1)
		return tCoeff, err
	case HashRelationBBS:
		if len(r0) != 1 {
			return nil, fmt.Errorf("bbs only supports scalar r0, got %d rows", len(r0))
		}
		tNTT, err := vsishash.ComputeBBSHash(ringQ, B, clonePoly(ringQ, combineMessageRows(ringQ, m1, m2)), clonePoly(ringQ, r0[0]), clonePoly(ringQ, r1))
		if err != nil {
			return nil, err
		}
		tCoeff := ringQ.NewPoly()
		ringQ.InvNTT(tNTT, tCoeff)
		return coeffPolyToInt64(ringQ, tCoeff), nil
	default:
		return nil, fmt.Errorf("invalid hash relation %q", relation)
	}
}
