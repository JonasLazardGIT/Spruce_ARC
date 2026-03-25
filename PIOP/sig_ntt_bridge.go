package PIOP

import (
	"fmt"

	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildSignatureNTTBridgeConstraints builds the aggregated bridge between the
// signature NTT blocks and the coefficient-packed blocks.
func buildSignatureNTTBridgeConstraints(
	ringQ *ring.Ring,
	rowsNTT []*ring.Poly,
	omega []uint64,
	layout RowLayout,
	root [16]byte,
	checks int,
) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if checks <= 0 {
		return nil, fmt.Errorf("invalid bridge check count %d", checks)
	}
	if layout.SigBlocks <= 0 || layout.SigUCount <= 0 || layout.SigCoeffBase < 0 {
		return nil, nil
	}
	if layout.SigBlocks*len(omega) != int(ringQ.N) {
		return nil, fmt.Errorf("signature bridge expects SigBlocks*|Ω|==ringN (%d*%d != %d)", layout.SigBlocks, len(omega), ringQ.N)
	}
	if layout.SigExtraUBase < 0 {
		return nil, fmt.Errorf("signature bridge missing extra U base (uBase=%d)", layout.SigExtraUBase)
	}

	q := ringQ.Modulus[0]
	ncols := len(omega)
	blocks := layout.SigBlocks
	uCount := layout.SigUCount

	uRowIdx := func(block, j int) (int, error) {
		if block < 0 || block >= blocks {
			return 0, fmt.Errorf("invalid block %d (blocks=%d)", block, blocks)
		}
		if j < 0 || j >= uCount {
			return 0, fmt.Errorf("invalid u component %d (uCount=%d)", j, uCount)
		}
		if block == 0 {
			return rowLayoutPostSignUBase(layout) + j, nil
		}
		base := layout.SigExtraUBase + (block-1)*uCount
		return base + j, nil
	}
	uCoefIdx := func(block, j int) (int, error) {
		if block < 0 || block >= blocks {
			return 0, fmt.Errorf("invalid block %d (blocks=%d)", block, blocks)
		}
		if j < 0 || j >= uCount {
			return 0, fmt.Errorf("invalid u component %d (uCount=%d)", j, uCount)
		}
		base := layout.SigCoeffBase + block*uCount
		return base + j, nil
	}

	rng := newFSRNG("SigNTTBridge", root[:], bytesU64Vec([]uint64{uint64(ncols), uint64(blocks), uint64(uCount)}))

	buildThetaPrime := func(vals []uint64) (*ring.Poly, error) {
		if len(vals) != ncols {
			return nil, fmt.Errorf("theta values length %d want %d", len(vals), ncols)
		}
		coeffs := Interpolate(omega, vals, q)
		out := ringQ.NewPoly()
		for i := range out.Coeffs[0] {
			out.Coeffs[0][i] = 0
		}
		copy(out.Coeffs[0], coeffs)
		ringQ.NTT(out, out)
		return out, nil
	}

	rowValsOnOmega := make(map[int][]uint64, len(rowsNTT))
	coeffTmp := ringQ.NewPoly()
	evalRow := func(idx int) ([]uint64, error) {
		if vals, ok := rowValsOnOmega[idx]; ok {
			return vals, nil
		}
		if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
			return nil, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		ringQ.InvNTT(rowsNTT[idx], coeffTmp)
		vals := make([]uint64, ncols)
		for k, w := range omega {
			vals[k] = EvalPoly(coeffTmp.Coeffs[0], w%q, q)
		}
		rowValsOnOmega[idx] = vals
		return vals, nil
	}

	linCombVals := func(idxs []int, alpha []uint64) ([]uint64, error) {
		if len(idxs) != len(alpha) {
			return nil, fmt.Errorf("linComb: idxs len=%d alpha len=%d", len(idxs), len(alpha))
		}
		out := make([]uint64, ncols)
		for j, idx := range idxs {
			rowVals, err := evalRow(idx)
			if err != nil {
				return nil, err
			}
			a := alpha[j] % q
			if a == 0 {
				continue
			}
			for k := 0; k < ncols; k++ {
				out[k] = modAdd(out[k], modMul(a, rowVals[k], q), q)
			}
		}
		return out, nil
	}

	sampleVector := func() []uint64 {
		v := make([]uint64, ringQ.N)
		for i := 0; i < int(ringQ.N); i++ {
			v[i] = rng.nextU64() % q
		}
		return v
	}

	out := make([]*ring.Poly, 0, checks)
	for t := 0; t < checks; t++ {
		alpha := make([]uint64, uCount)
		for j := 0; j < uCount; j++ {
			alpha[j] = rng.nextU64() % q
		}
		rVec := sampleVector()
		sVec, err := TransposeNTTVector(ringQ, rVec)
		if err != nil {
			return nil, fmt.Errorf("transpose NTT: %w", err)
		}

		acc := ringQ.NewPoly()
		for b := 0; b < blocks; b++ {
			start := b * ncols

			uIdxs := make([]int, uCount)
			uCoefIdxs := make([]int, uCount)
			for j := 0; j < uCount; j++ {
				idx, err := uRowIdx(b, j)
				if err != nil {
					return nil, err
				}
				uIdxs[j] = idx
				cidx, err := uCoefIdx(b, j)
				if err != nil {
					return nil, err
				}
				uCoefIdxs[j] = cidx
			}
			mixNTTVals, err := linCombVals(uIdxs, alpha)
			if err != nil {
				return nil, fmt.Errorf("bridge U mix block %d: %w", b, err)
			}
			mixCoefVals, err := linCombVals(uCoefIdxs, alpha)
			if err != nil {
				return nil, fmt.Errorf("bridge Ucoef mix block %d: %w", b, err)
			}

			term := make([]uint64, ncols)
			for k := 0; k < ncols; k++ {
				rw := rVec[start+k] % q
				sw := sVec[start+k] % q
				left := modMul(rw, mixNTTVals[k], q)
				right := modMul(sw, mixCoefVals[k], q)
				term[k] = modSub(left, right, q)
			}
			termTheta, err := buildThetaPrime(term)
			if err != nil {
				return nil, fmt.Errorf("bridge term theta block %d: %w", b, err)
			}
			ringQ.Add(acc, termTheta, acc)
		}
		out = append(out, acc)
	}
	return out, nil
}

// buildSignatureNTTBridgeConstraintsFormal returns the same bridge together
// with formal coefficient vectors for each aggregated constraint polynomial:
//
//	F_t(X) = Σ_b (R_{t,b}(X)·Ũ_b^NTT(X) - S_{t,b}(X)·Ũ_b^coef(X))
//
// where Ũ_b are alpha-mixed witness rows. In explicit-domain mode these
// coefficient vectors are used to avoid ring-dimension truncation in BuildQ/BuildQK.
func buildSignatureNTTBridgeConstraintsFormal(
	ringQ *ring.Ring,
	rowsNTT []*ring.Poly,
	omega []uint64,
	layout RowLayout,
	root [16]byte,
	checks int,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	if checks <= 0 {
		return nil, nil, fmt.Errorf("invalid bridge check count %d", checks)
	}
	if layout.SigBlocks <= 0 || layout.SigUCount <= 0 || layout.SigCoeffBase < 0 {
		return nil, nil, nil
	}
	if layout.SigBlocks*len(omega) != int(ringQ.N) {
		return nil, nil, fmt.Errorf("signature bridge expects SigBlocks*|Ω|==ringN (%d*%d != %d)", layout.SigBlocks, len(omega), ringQ.N)
	}
	if layout.SigExtraUBase < 0 {
		return nil, nil, fmt.Errorf("signature bridge missing extra U base (uBase=%d)", layout.SigExtraUBase)
	}

	q := ringQ.Modulus[0]
	ncols := len(omega)
	blocks := layout.SigBlocks
	uCount := layout.SigUCount

	uRowIdx := func(block, j int) (int, error) {
		if block < 0 || block >= blocks {
			return 0, fmt.Errorf("invalid block %d (blocks=%d)", block, blocks)
		}
		if j < 0 || j >= uCount {
			return 0, fmt.Errorf("invalid u component %d (uCount=%d)", j, uCount)
		}
		if block == 0 {
			return rowLayoutPostSignUBase(layout) + j, nil
		}
		base := layout.SigExtraUBase + (block-1)*uCount
		return base + j, nil
	}
	uCoefIdx := func(block, j int) (int, error) {
		if block < 0 || block >= blocks {
			return 0, fmt.Errorf("invalid block %d (blocks=%d)", block, blocks)
		}
		if j < 0 || j >= uCount {
			return 0, fmt.Errorf("invalid u component %d (uCount=%d)", j, uCount)
		}
		base := layout.SigCoeffBase + block*uCount
		return base + j, nil
	}

	rng := newFSRNG("SigNTTBridge", root[:], bytesU64Vec([]uint64{uint64(ncols), uint64(blocks), uint64(uCount)}))

	sampleVector := func() []uint64 {
		v := make([]uint64, ringQ.N)
		for i := 0; i < int(ringQ.N); i++ {
			v[i] = rng.nextU64() % q
		}
		return v
	}

	rowCoeffCache := make(map[int]fpoly.Poly, len(rowsNTT))
	rowPoly := func(idx int) (fpoly.Poly, error) {
		if p, ok := rowCoeffCache[idx]; ok {
			return p, nil
		}
		if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
			return fpoly.Zero(q), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(rowsNTT[idx], coeff)
		fp := fpoly.New(q, coeff.Coeffs[0])
		rowCoeffCache[idx] = fp
		return fp, nil
	}

	linCombPoly := func(idxs []int, alpha []uint64) (fpoly.Poly, error) {
		if len(idxs) != len(alpha) {
			return fpoly.Zero(q), fmt.Errorf("linComb: idx len=%d alpha len=%d", len(idxs), len(alpha))
		}
		acc := fpoly.Zero(q)
		for j, idx := range idxs {
			p, err := rowPoly(idx)
			if err != nil {
				return fpoly.Zero(q), err
			}
			a := alpha[j] % q
			if a == 0 {
				continue
			}
			acc = acc.Add(p.Scale(a))
		}
		return acc, nil
	}

	toNTTIfFits := func(c []uint64) *ring.Poly {
		if len(c) == 0 {
			c = []uint64{0}
		}
		if len(c) > int(ringQ.N) {
			return nil
		}
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], c)
		ringQ.NTT(p, p)
		return p
	}

	out := make([]*ring.Poly, 0, checks)
	outCoeffs := make([][]uint64, 0, checks)
	for t := 0; t < checks; t++ {
		alpha := make([]uint64, uCount)
		for j := 0; j < uCount; j++ {
			alpha[j] = rng.nextU64() % q
		}
		rVec := sampleVector()
		sVec, err := TransposeNTTVector(ringQ, rVec)
		if err != nil {
			return nil, nil, fmt.Errorf("transpose NTT: %w", err)
		}

		acc := fpoly.Zero(q)
		for b := 0; b < blocks; b++ {
			start := b * ncols
			uIdxs := make([]int, uCount)
			uCoefIdxs := make([]int, uCount)
			for j := 0; j < uCount; j++ {
				idx, err := uRowIdx(b, j)
				if err != nil {
					return nil, nil, err
				}
				uIdxs[j] = idx
				cidx, err := uCoefIdx(b, j)
				if err != nil {
					return nil, nil, err
				}
				uCoefIdxs[j] = cidx
			}
			mixNTT, err := linCombPoly(uIdxs, alpha)
			if err != nil {
				return nil, nil, fmt.Errorf("bridge U mix block %d: %w", b, err)
			}
			mixCoef, err := linCombPoly(uCoefIdxs, alpha)
			if err != nil {
				return nil, nil, fmt.Errorf("bridge Ucoef mix block %d: %w", b, err)
			}

			rCoeff := Interpolate(omega, rVec[start:start+ncols], q)
			sCoeff := Interpolate(omega, sVec[start:start+ncols], q)
			rPoly := fpoly.New(q, rCoeff)
			sPoly := fpoly.New(q, sCoeff)

			term := rPoly.Mul(mixNTT).Sub(sPoly.Mul(mixCoef))
			acc = acc.Add(term)
		}

		outCoeffs = append(outCoeffs, append([]uint64(nil), acc.Coeffs...))
		out = append(out, toNTTIfFits(acc.Coeffs))
	}
	return out, outCoeffs, nil
}

// buildRowSetNTTCoeffBridgeConstraintsFormal builds replayable aggregated bridge
// constraints linking one or more NTT-row families to coefficient-row families.
//
// Inputs are arranged by component and block:
//   - nttRows[c][b] is the row holding NTT slot block b for component c,
//   - coefRows[c][b] is the row holding coefficient block b for component c.
//
// The helper samples random row-mixing and projection vectors and emits checks:
//
//	F_t(X) = Σ_b (R_{t,b}(X)·Ũ_b^NTT(X) - S_{t,b}(X)·Ũ_b^coef(X)),
//
// where Ũ_b are alpha-mixed component rows for block b.
func buildRowSetNTTCoeffBridgeConstraintsFormal(
	ringQ *ring.Ring,
	omega []uint64,
	root [16]byte,
	checks int,
	nttRows [][]*ring.Poly,
	coefRows [][]*ring.Poly,
	label string,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	if checks <= 0 {
		return nil, nil, fmt.Errorf("invalid bridge check count %d", checks)
	}
	if len(nttRows) == 0 || len(coefRows) == 0 || len(nttRows) != len(coefRows) {
		return nil, nil, fmt.Errorf("invalid bridge component sets: ntt=%d coef=%d", len(nttRows), len(coefRows))
	}
	componentCount := len(nttRows)
	blocks := len(nttRows[0])
	if blocks <= 0 {
		return nil, nil, fmt.Errorf("invalid bridge block count %d", blocks)
	}
	for i := 0; i < componentCount; i++ {
		if len(nttRows[i]) != blocks || len(coefRows[i]) != blocks {
			return nil, nil, fmt.Errorf("component %d block mismatch: ntt=%d coef=%d want=%d", i, len(nttRows[i]), len(coefRows[i]), blocks)
		}
	}
	ncols := len(omega)
	if blocks*ncols != int(ringQ.N) {
		return nil, nil, fmt.Errorf("bridge expects blocks*|Ω|==ringN (%d*%d != %d)", blocks, ncols, ringQ.N)
	}
	if label == "" {
		label = "RowSetNTTBridge"
	}

	q := ringQ.Modulus[0]
	rng := newFSRNG(label, root[:], bytesU64Vec([]uint64{uint64(ncols), uint64(blocks), uint64(componentCount)}))

	rowCoeffCache := make(map[*ring.Poly][]uint64, componentCount*blocks*2)
	evalRowCoeff := func(row *ring.Poly) ([]uint64, error) {
		if row == nil {
			return nil, fmt.Errorf("nil row polynomial in bridge")
		}
		if coeff, ok := rowCoeffCache[row]; ok {
			return coeff, nil
		}
		coeff, err := coeffFromNTTPoly(ringQ, row)
		if err != nil {
			return nil, err
		}
		coeff = trimPoly(coeff, q)
		rowCoeffCache[row] = coeff
		return coeff, nil
	}
	toNTTIfFits := func(coeffs []uint64) *ring.Poly {
		if len(coeffs) == 0 {
			coeffs = []uint64{0}
		}
		if len(coeffs) > int(ringQ.N) {
			// Eq.(7) only depends on evaluations over Ω; project back to a degree-<|Ω|
			// representative so ring-path checks can consume this helper output.
			vals := make([]uint64, len(omega))
			for idx, w := range omega {
				vals[idx] = EvalPoly(coeffs, w%q, q)
			}
			coeffs = Interpolate(omega, vals, q)
		}
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], coeffs)
		ringQ.NTT(p, p)
		return p
	}
	sampleVector := func() []uint64 {
		v := make([]uint64, ringQ.N)
		for i := 0; i < int(ringQ.N); i++ {
			v[i] = rng.nextU64() % q
		}
		return v
	}

	out := make([]*ring.Poly, 0, checks)
	outCoeffs := make([][]uint64, 0, checks)
	for t := 0; t < checks; t++ {
		alpha := make([]uint64, componentCount)
		for c := 0; c < componentCount; c++ {
			alpha[c] = rng.nextU64() % q
		}
		rVec := sampleVector()
		sVec, err := TransposeNTTVector(ringQ, rVec)
		if err != nil {
			return nil, nil, fmt.Errorf("transpose NTT: %w", err)
		}

		acc := fpoly.Zero(q)
		for b := 0; b < blocks; b++ {
			mixNTT := fpoly.Zero(q)
			mixCoef := fpoly.Zero(q)
			for c := 0; c < componentCount; c++ {
				a := alpha[c] % q
				if a == 0 {
					continue
				}
				nttCoeff, nErr := evalRowCoeff(nttRows[c][b])
				if nErr != nil {
					return nil, nil, fmt.Errorf("ntt row coeff c=%d b=%d: %w", c, b, nErr)
				}
				coefCoeff, cErr := evalRowCoeff(coefRows[c][b])
				if cErr != nil {
					return nil, nil, fmt.Errorf("coef row coeff c=%d b=%d: %w", c, b, cErr)
				}
				mixNTT = mixNTT.Add(fpoly.New(q, nttCoeff).Scale(a))
				mixCoef = mixCoef.Add(fpoly.New(q, coefCoeff).Scale(a))
			}
			start := b * ncols
			rCoeff := Interpolate(omega, rVec[start:start+ncols], q)
			sCoeff := Interpolate(omega, sVec[start:start+ncols], q)
			term := fpoly.New(q, rCoeff).Mul(mixNTT).Sub(fpoly.New(q, sCoeff).Mul(mixCoef))
			acc = acc.Add(term)
		}
		coeffCopy := append([]uint64(nil), acc.Coeffs...)
		outCoeffs = append(outCoeffs, coeffCopy)
		out = append(out, toNTTIfFits(coeffCopy))
	}
	return out, outCoeffs, nil
}
