package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// coeffFromNTTPoly returns the coefficient vector of a polynomial given in NTT form.
func coeffFromNTTPoly(ringQ *ring.Ring, pNTT *ring.Poly) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if pNTT == nil {
		return nil, nil
	}
	q := ringQ.Modulus[0]
	tmp := ringQ.NewPoly()
	ringQ.InvNTT(pNTT, tmp)
	out := append([]uint64(nil), tmp.Coeffs[0]...)
	for i := range out {
		out[i] %= q
	}
	return out, nil
}

// thetaPolyFromNTT interpolates a public Θ polynomial from its values on Ω.
func thetaPolyFromNTT(ringQ *ring.Ring, pNTT *ring.Poly, omega []uint64) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if pNTT == nil {
		return nil, nil
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if len(omega) > int(ringQ.N) {
		return nil, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", len(omega), ringQ.N)
	}
	q := ringQ.Modulus[0]
	ncols := len(omega)
	head := append([]uint64(nil), pNTT.Coeffs[0][:ncols]...)
	for i := range head {
		head[i] %= q
	}
	coeffs := Interpolate(omega, head, q)
	out := ringQ.NewPoly()
	copy(out.Coeffs[0], coeffs)
	ringQ.NTT(out, out)
	return out, nil
}

// thetaCoeffFromNTT interpolates a public Θ polynomial and returns its coefficients.
func thetaCoeffFromNTT(ringQ *ring.Ring, pNTT *ring.Poly, omega []uint64) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if pNTT == nil {
		return nil, nil
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if len(omega) > int(ringQ.N) {
		return nil, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", len(omega), ringQ.N)
	}
	q := ringQ.Modulus[0]
	ncols := len(omega)
	head := append([]uint64(nil), pNTT.Coeffs[0][:ncols]...)
	for i := range head {
		head[i] %= q
	}
	coeffs := Interpolate(omega, head, q)
	out := make([]uint64, ringQ.N)
	copy(out, coeffs)
	for i := range out {
		out[i] %= q
	}
	return out, nil
}

func thetaPolyFromValues(ringQ *ring.Ring, vals []int64, omega []uint64) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if len(vals) < len(omega) {
		return nil, fmt.Errorf("values len=%d < |omega|=%d", len(vals), len(omega))
	}
	q := int64(ringQ.Modulus[0])
	head := make([]uint64, len(omega))
	for i := range head {
		v := vals[i] % q
		if v < 0 {
			v += q
		}
		head[i] = uint64(v)
	}
	coeffs := Interpolate(omega, head, ringQ.Modulus[0])
	out := ringQ.NewPoly()
	copy(out.Coeffs[0], coeffs)
	ringQ.NTT(out, out)
	return out, nil
}
