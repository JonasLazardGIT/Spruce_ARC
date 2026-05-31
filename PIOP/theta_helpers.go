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

// thetaPolyFromCoeff lifts a public coefficient-domain polynomial to its
// explicit-domain Θ polynomial by taking the first |Ω| slots of its NTT image
// and interpolating those public values. This is the public surface consumed by
// the transform-bridge replay relations.
func thetaPolyFromCoeff(ringQ *ring.Ring, coeffs []int64, omega []uint64) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(coeffs) == 0 {
		return nil, fmt.Errorf("empty coefficient slice")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	pCoeff := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	limit := len(coeffs)
	if limit > len(pCoeff.Coeffs[0]) {
		limit = len(pCoeff.Coeffs[0])
	}
	for i := 0; i < limit; i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		pCoeff.Coeffs[0][i] = uint64(v)
	}
	q64 := ringQ.Modulus[0]
	pNTT := ringQ.NewPoly()
	ring.Copy(pCoeff, pNTT)
	ringQ.NTT(pNTT, pNTT)
	head := make([]uint64, len(omega))
	copy(head, pNTT.Coeffs[0][:len(omega)])
	for i := range head {
		head[i] %= q64
	}
	out := ringQ.NewPoly()
	copy(out.Coeffs[0], Interpolate(omega, head, q64))
	ringQ.NTT(out, out)
	return out, nil
}

// thetaPolyFromNTTBlock interpolates the block-th public Θ polynomial from a
// flattened NTT-head representation whose first blocks*|Ω| entries encode the
// explicit-domain values block by block.
func thetaPolyFromNTTBlock(ringQ *ring.Ring, pNTT *ring.Poly, omega []uint64, block, blocks int) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if pNTT == nil {
		return nil, nil
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if blocks <= 0 {
		return nil, fmt.Errorf("invalid blocks=%d", blocks)
	}
	if block < 0 || block >= blocks {
		return nil, fmt.Errorf("invalid block index %d (blocks=%d)", block, blocks)
	}
	ncols := len(omega)
	start := block * ncols
	end := start + ncols
	if len(pNTT.Coeffs) == 0 || len(pNTT.Coeffs[0]) < end {
		return nil, fmt.Errorf("public poly too short for block slice [%d,%d)", start, end)
	}
	q := ringQ.Modulus[0]
	head := append([]uint64(nil), pNTT.Coeffs[0][start:end]...)
	for i := range head {
		head[i] %= q
	}
	coeffs := Interpolate(omega, head, q)
	out := ringQ.NewPoly()
	copy(out.Coeffs[0], coeffs)
	ringQ.NTT(out, out)
	return out, nil
}

// thetaCoeffFromNTTBlock interpolates the block-th public Θ polynomial and
// returns its coefficient representation directly.
func thetaCoeffFromNTTBlock(ringQ *ring.Ring, pNTT *ring.Poly, omega []uint64, block, blocks int) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if pNTT == nil {
		return nil, nil
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if blocks <= 0 {
		return nil, fmt.Errorf("invalid blocks=%d", blocks)
	}
	if block < 0 || block >= blocks {
		return nil, fmt.Errorf("invalid block index %d (blocks=%d)", block, blocks)
	}
	ncols := len(omega)
	start := block * ncols
	end := start + ncols
	if len(pNTT.Coeffs) == 0 || len(pNTT.Coeffs[0]) < end {
		return nil, fmt.Errorf("public poly too short for block slice [%d,%d)", start, end)
	}
	q := ringQ.Modulus[0]
	head := append([]uint64(nil), pNTT.Coeffs[0][start:end]...)
	for i := range head {
		head[i] %= q
	}
	return trimPoly(Interpolate(omega, head, q), q), nil
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

func nttPolyFromFormalCoeffsIfFits(ringQ *ring.Ring, coeffs []uint64) *ring.Poly {
	if ringQ == nil {
		return nil
	}
	q := ringQ.Modulus[0]
	trimmed := trimPoly(append([]uint64(nil), coeffs...), q)
	if len(trimmed) == 0 {
		trimmed = []uint64{0}
	}
	if len(trimmed) > int(ringQ.N) {
		return nil
	}
	out := ringQ.NewPoly()
	copy(out.Coeffs[0], trimmed)
	ringQ.NTT(out, out)
	return out
}
