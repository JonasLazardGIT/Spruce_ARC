// Exact-ring implementation of the vSIS-BBS hash in the NTT domain.
package vsishash

import (
	"errors"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// GenerateB samples B in the coefficient domain.
func GenerateB(ringQ *ring.Ring, prng utils.PRNG) ([]*ring.Poly, error) {
	uni := ring.NewUniformSampler(prng, ringQ)
	B := make([]*ring.Poly, 4)
	for i := 0; i < 4; i++ {
		p := ringQ.NewPoly()
		uni.Read(p)
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

func IsInvertibleDenominator(ringQ *ring.Ring, b3, x1 *ring.Poly) bool {
	if ringQ == nil || b3 == nil || x1 == nil {
		return false
	}
	d := ringQ.NewPoly()
	ringQ.Sub(b3, x1, d)
	_, ok := polyInverseNTT(ringQ, d)
	return ok
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
	if len(B) != 4 {
		return nil, nil, errors.New("need four B polynomials")
	}

	ringQ.NTT(m, m)
	ringQ.NTT(x0, x0)
	z, err := ComputeBBTranInverse(ringQ, B[3], x1)
	if err != nil {
		return nil, nil, err
	}

	tmp := ringQ.NewPoly()
	t := ringQ.NewPoly()
	ring.Copy(B[0], t)
	ringQ.MulCoeffs(B[1], m, tmp)
	ringQ.Add(t, tmp, t)
	ringQ.MulCoeffs(B[2], x0, tmp)
	ringQ.Add(t, tmp, t)
	ringQ.Add(t, z, t)
	return z, t, nil
}

func TestPolyInverseNTT(t *testing.T) {
	const N = 8
	const q = 8380417

	ringQ, _ := ring.NewRing(N, []uint64{q})
	uni, _ := utils.NewPRNG()
	us := ring.NewUniformSampler(uni, ringQ)

	a := ringQ.NewPoly()
	us.Read(a)
	ringQ.NTT(a, a) // lift ← this is what polyInverseNTT expects

	ainv, ok := polyInverseNTT(ringQ, a)
	if !ok {
		t.Fatal("poly not invertible (rare event)")
	}

	// verify Hadamard(a,ainv)==1
	prod := ringQ.NewPoly()
	ringQ.MulCoeffs(a, ainv, prod)

	for i, c := range prod.Coeffs[0] {
		if c != 1 {
			t.Fatalf("slot %d : a*ainv=%d ≠ 1", i, c)
		}
	}
}
