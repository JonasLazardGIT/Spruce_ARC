package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildTransformBridgeHFromCoeffs(omega, nttPoints []uint64, q uint64) ([][]uint64, error) {
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if len(nttPoints) < len(omega) {
		return nil, fmt.Errorf("nttPoints len=%d < omega len=%d", len(nttPoints), len(omega))
	}
	out := make([][]uint64, len(nttPoints))
	for j := range nttPoints {
		w := nttPoints[j] % q
		vals := make([]uint64, len(omega))
		pow := uint64(1)
		for k := 0; k < len(omega); k++ {
			vals[k] = pow
			pow = modMul(pow, w, q)
		}
		out[j] = Interpolate(omega, vals, q)
	}
	return out, nil
}

func buildTransformBridgeHFromEvals(omega, nttPoints []uint64, q uint64) ([][]uint64, error) {
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if len(nttPoints) < len(omega) {
		return nil, fmt.Errorf("nttPoints len=%d < omega len=%d", len(nttPoints), len(omega))
	}
	lagrangeBasis, err := buildLagrangeBasisCoeffs(omega, q)
	if err != nil {
		return nil, err
	}
	out := make([][]uint64, len(nttPoints))
	for j := range nttPoints {
		w := nttPoints[j] % q
		vals := make([]uint64, len(omega))
		for k := 0; k < len(omega); k++ {
			vals[k] = EvalPoly(lagrangeBasis[k], w, q)
		}
		out[j] = Interpolate(omega, vals, q)
	}
	return out, nil
}

func nttDomainPoints(ringQ *ring.Ring) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if ringQ.N <= 0 {
		return nil, fmt.Errorf("invalid ring dimension %d", ringQ.N)
	}
	p := ringQ.NewPoly()
	p.Coeffs[0][1] = 1
	pts := ringQ.NewPoly()
	ringQ.NTT(p, pts)
	return append([]uint64(nil), pts.Coeffs[0]...), nil
}

// thetaHeadFromNTTBlock returns the Θ values on Ω for a block of a public NTT-head
// polynomial. This avoids evaluating an NTT-form Θ polynomial via coeff-domain
// routines when the head is already the Θ-values on Ω.
func thetaHeadFromNTTBlock(ringQ *ring.Ring, pNTT *ring.Poly, omega []uint64, block, blocks int) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if pNTT == nil {
		return nil, fmt.Errorf("nil poly")
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
	head := make([]uint64, ncols)
	copy(head, pNTT.Coeffs[0][start:end])
	for i := range head {
		head[i] %= q
	}
	return head, nil
}

func evalPolyOnNTT(ringQ *ring.Ring, coeffs []uint64, rowNTT *ring.Poly) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if rowNTT == nil {
		return nil, fmt.Errorf("nil row")
	}
	q := ringQ.Modulus[0]
	out := ringQ.NewPoly()
	for i := 0; i < len(rowNTT.Coeffs[0]); i++ {
		out.Coeffs[0][i] = EvalPoly(coeffs, rowNTT.Coeffs[0][i]%q, q)
	}
	return out, nil
}
