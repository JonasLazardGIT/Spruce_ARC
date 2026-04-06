package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// transformBridgeBasisCache holds the public linear-map data used by both the
// showing and pre-sign transform-bridge replay paths.
type transformBridgeBasisCache struct {
	LagrangeBasis  [][]uint64
	TransformH     [][]uint64
	TransformHEval [][]uint64
	BlockFactors   [][]uint64
}

// newTransformBridgeBasisCache derives the fixed public basis used by the
// transform bridges:
// - the Lagrange basis on Ω,
// - the exact NTT-matrix H rows,
// - the evaluation-form H rows used by non-sign bridges,
// - and the per-block scaling factors used by signature bridges.
func newTransformBridgeBasisCache(ringQ *ring.Ring, omega []uint64, outputCount int, sourceBlocks int) (*transformBridgeBasisCache, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if outputCount <= 0 {
		return nil, fmt.Errorf("invalid H row count=%d", outputCount)
	}
	if outputCount > int(ringQ.N) {
		return nil, fmt.Errorf("H row count=%d exceeds ring dimension %d", outputCount, ringQ.N)
	}
	if sourceBlocks <= 0 {
		return nil, fmt.Errorf("invalid source blocks=%d", sourceBlocks)
	}
	ncols := len(omega)
	lagrangeBasis, err := buildLagrangeBasisCoeffs(omega, ringQ.Modulus[0])
	if err != nil {
		return nil, fmt.Errorf("lagrange basis: %w", err)
	}
	transformH, blockFactors, err := buildTransformBridgeHFromNTTMatrix(ringQ, omega, outputCount, sourceBlocks)
	if err != nil {
		return nil, err
	}
	transformHEval := transformH
	if len(transformHEval) > ncols {
		transformHEval = transformHEval[:ncols]
	}
	return &transformBridgeBasisCache{
		LagrangeBasis:  lagrangeBasis,
		TransformH:     transformH,
		TransformHEval: transformHEval,
		BlockFactors:   blockFactors,
	}, nil
}

// buildTransformBridgeHFromNTTMatrix builds H rows directly from the NTT
// matrix entries H_{t,k} = NTT(e_k)[t] for k in [0,|Ω|). This maps the
// coefficient-slot surface used by the explicit-domain rows to the exact NTT
// outputs consumed by the replay equations.
func buildTransformBridgeHFromNTTMatrix(ringQ *ring.Ring, omega []uint64, outputCount int, sourceBlocks int) ([][]uint64, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	if outputCount <= 0 {
		return nil, nil, fmt.Errorf("invalid H row count=%d", outputCount)
	}
	if outputCount > int(ringQ.N) {
		return nil, nil, fmt.Errorf("H row count=%d exceeds ring dimension %d", outputCount, ringQ.N)
	}
	ncols := len(omega)
	q := ringQ.Modulus[0]
	if outputCount%ncols != 0 {
		return nil, nil, fmt.Errorf("H row count=%d not divisible by ncols=%d", outputCount, ncols)
	}
	if sourceBlocks <= 0 || sourceBlocks*ncols > int(ringQ.N) {
		return nil, nil, fmt.Errorf("invalid source blocks=%d for ncols=%d ringN=%d", sourceBlocks, ncols, ringQ.N)
	}
	weights := make([][]uint64, outputCount)
	for t := 0; t < outputCount; t++ {
		weights[t] = make([]uint64, ncols)
	}
	for k := 0; k < ncols; k++ {
		basis := ringQ.NewPoly()
		basis.Coeffs[0][k] = 1
		ntt := ringQ.NewPoly()
		ringQ.NTT(basis, ntt)
		for t := 0; t < outputCount; t++ {
			weights[t][k] = ntt.Coeffs[0][t] % q
		}
	}

	hCoeffs := make([][]uint64, outputCount)
	blockFactors := make([][]uint64, outputCount)
	blockWeights := make([][]uint64, sourceBlocks)
	for b := 0; b < sourceBlocks; b++ {
		basis := ringQ.NewPoly()
		basis.Coeffs[0][b*ncols] = 1
		ntt := ringQ.NewPoly()
		ringQ.NTT(basis, ntt)
		vec := make([]uint64, outputCount)
		for t := 0; t < outputCount; t++ {
			vec[t] = ntt.Coeffs[0][t] % q
		}
		blockWeights[b] = vec
	}
	for t := 0; t < outputCount; t++ {
		hCoeffs[t] = Interpolate(omega, weights[t], q)
		w0 := weights[t][0] % q
		if w0 == 0 {
			return nil, nil, fmt.Errorf("ntt matrix weight zero at t=%d,k=0", t)
		}
		blockFactors[t] = make([]uint64, sourceBlocks)
		for b := 0; b < sourceBlocks; b++ {
			wb := blockWeights[b][t] % q
			blockFactors[t][b] = modMul(wb, modInv(w0, q), q)
		}
	}
	return hCoeffs, blockFactors, nil
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

func buildTransformHashResidualCoeffs(q uint64, bCoeff [][]uint64, m1Coeff, m2Coeff, r0Coeff, r1Coeff, tCoeff []uint64) []uint64 {
	mCombined := polyAdd(m1Coeff, m2Coeff, q)
	return buildTransformHashResidualCombinedCoeffs(q, bCoeff, mCombined, r0Coeff, r1Coeff, tCoeff)
}

func buildTransformHashResidualCombinedCoeffs(q uint64, bCoeff [][]uint64, mCombinedCoeff, r0Coeff, r1Coeff, tCoeff []uint64) []uint64 {
	num := polyAdd(bCoeff[0], polyMul(bCoeff[1], mCombinedCoeff, q), q)
	num = polyAdd(num, polyMul(bCoeff[2], r0Coeff, q), q)
	den := polySub(bCoeff[3], r1Coeff, q)
	return trimPoly(polySub(polyMul(den, tCoeff, q), num, q), q)
}

func buildTransformBridgeResidualCoeff(q uint64, transformHCoeff, lagrangeCoeff, srcCoeff, hatCoeff []uint64) []uint64 {
	leftCoeff := polyMul(transformHCoeff, srcCoeff, q)
	rightCoeff := polyMul(lagrangeCoeff, hatCoeff, q)
	return trimPoly(polySub(leftCoeff, rightCoeff, q), q)
}

func transformHashResidualEval(q, x uint64, thetaB [][]uint64, mHat1, mHat2, rHat0, rHat1, tTheta uint64) uint64 {
	return transformHashResidualCombinedEval(q, x, thetaB, modAdd(mHat1, mHat2, q), rHat0, rHat1, tTheta)
}

func transformHashResidualCombinedEval(q, x uint64, thetaB [][]uint64, mCombined, rHat0, rHat1, tTheta uint64) uint64 {
	b0 := EvalPoly(thetaB[0], x, q) % q
	b1 := EvalPoly(thetaB[1], x, q) % q
	b2 := EvalPoly(thetaB[2], x, q) % q
	b3 := EvalPoly(thetaB[3], x, q) % q
	hashNum := modAdd(b0, modMul(b1, mCombined, q), q)
	hashNum = modAdd(hashNum, modMul(b2, rHat0, q), q)
	hashDen := modSub(b3, rHat1, q)
	return modSub(modMul(hashDen, tTheta, q), hashNum, q)
}

func transformHashResidualKEval(K *kf.Field, e kf.Elem, thetaB [][]uint64, mHat1, mHat2, rHat0, rHat1, tTheta kf.Elem) kf.Elem {
	return transformHashResidualCombinedKEval(K, e, thetaB, K.Add(mHat1, mHat2), rHat0, rHat1, tTheta)
}

func transformHashResidualCombinedKEval(K *kf.Field, e kf.Elem, thetaB [][]uint64, mCombined, rHat0, rHat1, tTheta kf.Elem) kf.Elem {
	b0 := K.EvalFPolyAtK(thetaB[0], e)
	b1 := K.EvalFPolyAtK(thetaB[1], e)
	b2 := K.EvalFPolyAtK(thetaB[2], e)
	b3 := K.EvalFPolyAtK(thetaB[3], e)
	hashNum := K.Add(b0, K.Mul(b1, mCombined))
	hashNum = K.Add(hashNum, K.Mul(b2, rHat0))
	hashDen := K.Sub(b3, rHat1)
	return K.Sub(K.Mul(hashDen, tTheta), hashNum)
}
