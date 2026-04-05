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

// buildTransformBridgeHFromNTTMatrix builds the transform-bridge H rows by
// computing the NTT matrix entries directly from basis vectors. For each
// NTT output index t and coefficient index k (0 <= k < |Ω|), it sets:
//   H_{t,k} = NTT(e_k)[t]
// and interpolates H_t(X) over Ω so that H_t(ω_k) = H_{t,k}.
//
// It also returns blockFactors[t][b] = NTT(e_{b*|Ω|})[t] / NTT(e_0)[t],
// which scales the block-b source rows to account for the full NTT matrix.
func buildTransformBridgeHFromNTTMatrix(ringQ *ring.Ring, omega []uint64, count int) ([][]uint64, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	if count <= 0 {
		return nil, nil, fmt.Errorf("invalid H row count=%d", count)
	}
	if count > int(ringQ.N) {
		return nil, nil, fmt.Errorf("H row count=%d exceeds ring dimension %d", count, ringQ.N)
	}
	ncols := len(omega)
	q := ringQ.Modulus[0]
	if count%ncols != 0 {
		return nil, nil, fmt.Errorf("H row count=%d not divisible by ncols=%d", count, ncols)
	}
	blocks := count / ncols

	// weights[t][k] = NTT(e_k)[t] for 0<=k<ncols, 0<=t<count
	weights := make([][]uint64, count)
	for t := 0; t < count; t++ {
		weights[t] = make([]uint64, ncols)
	}
	for k := 0; k < ncols; k++ {
		basis := ringQ.NewPoly()
		basis.Coeffs[0][k] = 1
		ntt := ringQ.NewPoly()
		ringQ.NTT(basis, ntt)
		for t := 0; t < count; t++ {
			weights[t][k] = ntt.Coeffs[0][t] % q
		}
	}

	hCoeffs := make([][]uint64, count)
	blockFactors := make([][]uint64, count)
	// Precompute NTT(e_{b*ncols}) for block scaling.
	blockWeights := make([][]uint64, blocks)
	for b := 0; b < blocks; b++ {
		basis := ringQ.NewPoly()
		basis.Coeffs[0][b*ncols] = 1
		ntt := ringQ.NewPoly()
		ringQ.NTT(basis, ntt)
		vec := make([]uint64, count)
		for t := 0; t < count; t++ {
			vec[t] = ntt.Coeffs[0][t] % q
		}
		blockWeights[b] = vec
	}
	for t := 0; t < count; t++ {
		hCoeffs[t] = Interpolate(omega, weights[t], q)
		w0 := weights[t][0] % q
		if w0 == 0 {
			return nil, nil, fmt.Errorf("ntt matrix weight zero at t=%d,k=0", t)
		}
		blockFactors[t] = make([]uint64, blocks)
		for b := 0; b < blocks; b++ {
			wb := blockWeights[b][t] % q
			blockFactors[t][b] = modMul(wb, modInv(w0, q), q)
		}
	}
	return hCoeffs, blockFactors, nil
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
