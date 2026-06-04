// Exact-ring implementation of the vSIS-BBS hash in the NTT domain.
package hash

import (
	"errors"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// GenerateBWithX0Len samples [B0, B1, B2[0], ..., B2[x0Len-1], B3] in the
// coefficient domain for the live BB-tran relation.
func GenerateBWithX0Len(ringQ *ring.Ring, prng utils.PRNG, x0Len int) ([]*ring.Poly, error) {
	if x0Len <= 0 {
		return nil, errors.New("invalid x0 length")
	}
	uni := ring.NewUniformSampler(prng, ringQ)
	B := make([]*ring.Poly, 3+x0Len)
	for i := 0; i < len(B); i++ {
		p := ringQ.NewPoly()
		if i != 0 {
			uni.Read(p)
		}
		B[i] = p
	}
	return B, nil
}

func polyInverseNTT(r *ring.Ring, a *ring.Poly) (*ring.Poly, bool) {
	q := r.Modulus[0]

	invScalar := func(x uint64) uint64 {
		var t, newT int64 = 0, 1
		var r0, newR int64 = int64(q), int64(x)
		for newR != 0 {
			quot := r0 / newR
			t, newT = newT, t-quot*newT
			r0, newR = newR, r0-quot*newR
		}
		if r0 != 1 {
			return 0
		}
		if t < 0 {
			t += int64(q)
		}
		return uint64(t)
	}

	out := r.NewPoly()
	for i, coeff := range a.Coeffs[0] {
		if coeff == 0 {
			return nil, false
		}
		out.Coeffs[0][i] = invScalar(coeff)
	}
	return out, true
}

func ComputeBBTranInverse(
	ringQ *ring.Ring,
	b3, x1 *ring.Poly,
) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, errors.New("nil ring")
	}
	if b3 == nil || x1 == nil {
		return nil, errors.New("nil denominator input")
	}
	ringQ.NTT(x1, x1)
	d := ringQ.NewPoly()
	ringQ.Sub(b3, x1, d)
	dInv, ok := polyInverseNTT(ringQ, d)
	if !ok {
		return nil, errors.New("denominator not invertible")
	}
	return dInv, nil
}

// ComputeBBSHash evaluates the BBS hash and returns the result in the NTT domain.
func ComputeBBSHash(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m, x0, x1 *ring.Poly,
) (*ring.Poly, error) {
	if len(B) != 4 {
		return nil, errors.New("need four B polynomials")
	}

	ringQ.NTT(m, m)
	ringQ.NTT(x0, x0)
	ringQ.NTT(x1, x1)

	tmp := ringQ.NewPoly()
	r := ringQ.NewPoly()

	ring.Copy(B[0], r)

	ringQ.MulCoeffs(B[1], m, tmp)
	ringQ.Add(r, tmp, r)

	ringQ.MulCoeffs(B[2], x0, tmp)
	ringQ.Add(r, tmp, r)

	d := ringQ.NewPoly()
	ringQ.Sub(B[3], x1, d)

	dInv, ok := polyInverseNTT(ringQ, d)
	if !ok {
		return nil, errors.New("denominator not invertible")
	}

	t := ringQ.NewPoly()
	ringQ.MulCoeffs(r, dInv, t)

	return t, nil
}

// ComputeBBTranHash evaluates the BB-tran target and returns it in the NTT
// domain.
func ComputeBBTranHash(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m, x0, x1 *ring.Poly,
) (*ring.Poly, error) {
	_, t, err := ComputeBBTranTarget(ringQ, B, m, x0, x1)
	return t, err
}

// ComputeBBTranTarget evaluates the live BB-tran target and returns both the
// inverse witness Z=(B3-x1)^(-1) and T=B0+B1*m+B2*x0+Z in the NTT domain.
func ComputeBBTranTarget(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m, x0, x1 *ring.Poly,
) (*ring.Poly, *ring.Poly, error) {
	return ComputeBBTranTargetVector(ringQ, B[0], B[1], []*ring.Poly{B[2]}, B[3], m, []*ring.Poly{x0}, x1)
}

func ComputeBBTranTargetVector(
	ringQ *ring.Ring,
	b0, b1 *ring.Poly,
	b2 []*ring.Poly,
	b3 *ring.Poly,
	m *ring.Poly,
	x0 []*ring.Poly,
	x1 *ring.Poly,
) (*ring.Poly, *ring.Poly, error) {
	if ringQ == nil {
		return nil, nil, errors.New("nil ring")
	}
	if b0 == nil || b1 == nil || b3 == nil {
		return nil, nil, errors.New("nil B polynomial")
	}
	if len(b2) == 0 || len(x0) == 0 || len(b2) != len(x0) {
		return nil, nil, errors.New("invalid b2/x0 length")
	}
	if m == nil {
		return nil, nil, errors.New("nil message polynomial")
	}
	ringQ.NTT(m, m)
	z, err := ComputeBBTranInverse(ringQ, b3, x1)
	if err != nil {
		return nil, nil, err
	}

	tmp := ringQ.NewPoly()
	t := ringQ.NewPoly()
	ring.Copy(b0, t)
	ringQ.MulCoeffs(b1, m, tmp)
	ringQ.Add(t, tmp, t)
	for i := range x0 {
		ringQ.NTT(x0[i], x0[i])
		ringQ.MulCoeffs(b2[i], x0[i], tmp)
		ringQ.Add(t, tmp, t)
	}
	ringQ.Add(t, z, t)
	return z, t, nil
}
