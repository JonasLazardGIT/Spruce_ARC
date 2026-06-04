package PIOP

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// transformBridgeBasisCache holds the public linear-map data used by both the
// showing and pre-sign transform-bridge replay paths.
type transformBridgeBasisCache struct {
	LagrangeBasis     [][]uint64
	TransformH        [][]uint64
	TransformHEval    [][]uint64
	TransformHAtOmega [][]uint64
	BlockFactors      [][]uint64
}

type transformBridgeBasisGlobalEntry struct {
	key   [32]byte
	value *transformBridgeBasisCache
	ok    bool
}

var transformBridgeBasisGlobalCache = struct {
	sync.Mutex
	next    int
	entries [4]transformBridgeBasisGlobalEntry
}{}

func coeffOrZero(coeffs [][]uint64, idx int) []uint64 {
	if idx < 0 || idx >= len(coeffs) || coeffs[idx] == nil {
		return []uint64{0}
	}
	return coeffs[idx]
}

func transformBridgeBasisCacheKey(ringQ *ring.Ring, omega []uint64, outputCount, sourceBlocks int) [32]byte {
	h := sha256.New()
	var buf [8]byte
	writeU64 := func(v uint64) {
		binary.LittleEndian.PutUint64(buf[:], v)
		_, _ = h.Write(buf[:])
	}
	writeInt := func(v int) {
		writeU64(uint64(v))
	}
	writeU64(ringQ.Modulus[0])
	writeInt(int(ringQ.N))
	writeInt(outputCount)
	writeInt(sourceBlocks)
	writeInt(len(omega))
	for _, v := range omega {
		writeU64(v)
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

func loadTransformBridgeBasisGlobalCache(key [32]byte) (*transformBridgeBasisCache, bool) {
	transformBridgeBasisGlobalCache.Lock()
	defer transformBridgeBasisGlobalCache.Unlock()
	for i := range transformBridgeBasisGlobalCache.entries {
		entry := &transformBridgeBasisGlobalCache.entries[i]
		if entry.ok && entry.key == key {
			return entry.value, true
		}
	}
	return nil, false
}

func storeTransformBridgeBasisGlobalCache(key [32]byte, value *transformBridgeBasisCache) {
	if value == nil {
		return
	}
	transformBridgeBasisGlobalCache.Lock()
	defer transformBridgeBasisGlobalCache.Unlock()
	idx := transformBridgeBasisGlobalCache.next % len(transformBridgeBasisGlobalCache.entries)
	transformBridgeBasisGlobalCache.entries[idx] = transformBridgeBasisGlobalEntry{
		key:   key,
		value: value,
		ok:    true,
	}
	transformBridgeBasisGlobalCache.next = (idx + 1) % len(transformBridgeBasisGlobalCache.entries)
}

func buildTransformHAtOmega(transformH [][]uint64, omega []uint64, q uint64) [][]uint64 {
	out := make([][]uint64, len(transformH))
	for i := range transformH {
		row := make([]uint64, len(omega))
		for j, x := range omega {
			row[j] = EvalPoly(transformH[i], x%q, q) % q
		}
		out[i] = row
	}
	return out
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
		return nil, fmt.Errorf("h row count=%d exceeds ring dimension %d", outputCount, ringQ.N)
	}
	if sourceBlocks <= 0 {
		return nil, fmt.Errorf("invalid source blocks=%d", sourceBlocks)
	}
	key := transformBridgeBasisCacheKey(ringQ, omega, outputCount, sourceBlocks)
	if cached, ok := loadTransformBridgeBasisGlobalCache(key); ok {
		return cached, nil
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
	out := &transformBridgeBasisCache{
		LagrangeBasis:     lagrangeBasis,
		TransformH:        transformH,
		TransformHEval:    transformHEval,
		TransformHAtOmega: buildTransformHAtOmega(transformH, omega, ringQ.Modulus[0]),
		BlockFactors:      blockFactors,
	}
	storeTransformBridgeBasisGlobalCache(key, out)
	return out, nil
}

// newRowTransformBridgeBasisCache derives the transform basis for explicit-domain
// source rows represented by their evaluations on Ω. In this setting the source
// row is expanded in the Lagrange basis on Ω, so the replay transform must map
// those Lagrange coordinates to the desired NTT outputs.
func newRowTransformBridgeBasisCache(ringQ *ring.Ring, omega []uint64, outputCount int) (*transformBridgeBasisCache, error) {
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
		return nil, fmt.Errorf("h row count=%d exceeds ring dimension %d", outputCount, ringQ.N)
	}
	lagrangeBasis, err := buildLagrangeBasisCoeffs(omega, ringQ.Modulus[0])
	if err != nil {
		return nil, fmt.Errorf("lagrange basis: %w", err)
	}
	transformH, err := buildTransformBridgeHFromLagrangeBasis(ringQ, omega, lagrangeBasis, outputCount)
	if err != nil {
		return nil, err
	}
	transformHEval := transformH
	if len(transformHEval) > len(omega) {
		transformHEval = transformHEval[:len(omega)]
	}
	blockFactors := make([][]uint64, outputCount)
	for t := range blockFactors {
		blockFactors[t] = []uint64{1}
	}
	return &transformBridgeBasisCache{
		LagrangeBasis:     lagrangeBasis,
		TransformH:        transformH,
		TransformHEval:    transformHEval,
		TransformHAtOmega: buildTransformHAtOmega(transformH, omega, ringQ.Modulus[0]),
		BlockFactors:      blockFactors,
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
		return nil, nil, fmt.Errorf("h row count=%d exceeds ring dimension %d", outputCount, ringQ.N)
	}
	ncols := len(omega)
	q := ringQ.Modulus[0]
	if outputCount%ncols != 0 {
		return nil, nil, fmt.Errorf("h row count=%d not divisible by ncols=%d", outputCount, ncols)
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

func buildTransformBridgeHFromLagrangeBasis(ringQ *ring.Ring, omega []uint64, lagrangeBasis [][]uint64, outputCount int) ([][]uint64, error) {
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
		return nil, fmt.Errorf("h row count=%d exceeds ring dimension %d", outputCount, ringQ.N)
	}
	ncols := len(omega)
	if len(lagrangeBasis) != ncols {
		return nil, fmt.Errorf("lagrange basis count=%d want ncols=%d", len(lagrangeBasis), ncols)
	}
	q := ringQ.Modulus[0]
	weights := make([][]uint64, outputCount)
	for t := 0; t < outputCount; t++ {
		weights[t] = make([]uint64, ncols)
	}
	for k := 0; k < ncols; k++ {
		basis := ringQ.NewPoly()
		copy(basis.Coeffs[0], lagrangeBasis[k])
		ntt := ringQ.NewPoly()
		ringQ.NTT(basis, ntt)
		for t := 0; t < outputCount; t++ {
			weights[t][k] = ntt.Coeffs[0][t] % q
		}
	}
	hCoeffs := make([][]uint64, outputCount)
	for t := 0; t < outputCount; t++ {
		hCoeffs[t] = Interpolate(omega, weights[t], q)
	}
	return hCoeffs, nil
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

func buildTransformB2LinearCoeffs(q uint64, bCoeff [][]uint64, r0Coeffs [][]uint64) ([]uint64, error) {
	if len(r0Coeffs) == 0 {
		return nil, fmt.Errorf("missing r0 coefficients")
	}
	if len(bCoeff) != 3+len(r0Coeffs) {
		return nil, fmt.Errorf("b coeff length=%d mismatches x0Len=%d", len(bCoeff), len(r0Coeffs))
	}
	acc := []uint64{0}
	for i := range r0Coeffs {
		acc = polyAdd(acc, polyMul(bCoeff[2+i], r0Coeffs[i], q), q)
	}
	return acc, nil
}

func buildTransformTargetResidualCombinedCoeffsVector(q uint64, relation string, bCoeff [][]uint64, mCombinedCoeff []uint64, r0Coeffs [][]uint64, zCoeff, tCoeff []uint64) []uint64 {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		lin, err := buildTransformB2LinearCoeffs(q, bCoeff, r0Coeffs)
		if err != nil {
			return []uint64{1}
		}
		res := polyAdd(bCoeff[0], polyMul(bCoeff[1], mCombinedCoeff, q), q)
		res = polyAdd(res, lin, q)
		res = polyAdd(res, zCoeff, q)
		return trimPoly(polySub(tCoeff, res, q), q)
	default:
		return []uint64{0}
	}
}

func buildTransformTargetResidualCombinedCoeffsAggregate(q uint64, relation string, bCoeff [][]uint64, mCombinedCoeff, r0B2Coeff, zCoeff, tCoeff []uint64) []uint64 {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		if len(bCoeff) < 3 {
			return []uint64{1}
		}
		res := polyAdd(bCoeff[0], polyMul(bCoeff[1], mCombinedCoeff, q), q)
		res = polyAdd(res, r0B2Coeff, q)
		res = polyAdd(res, zCoeff, q)
		return trimPoly(polySub(tCoeff, res, q), q)
	default:
		return []uint64{0}
	}
}

func buildTransformInverseResidualCoeffs(q uint64, relation string, bCoeff [][]uint64, r1Coeff, zCoeff []uint64) []uint64 {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		if len(bCoeff) < 4 {
			return []uint64{1}
		}
		den := polySub(bCoeff[len(bCoeff)-1], r1Coeff, q)
		return trimPoly(polySub(polyMul(den, zCoeff, q), []uint64{1}, q), q)
	default:
		return []uint64{0}
	}
}

func buildTransformBridgeResidualCoeff(q uint64, transformHCoeff, lagrangeCoeff, srcCoeff, hatCoeff []uint64) []uint64 {
	leftCoeff := polyMul(transformHCoeff, srcCoeff, q)
	rightCoeff := polyMul(lagrangeCoeff, hatCoeff, q)
	return trimPoly(polySub(leftCoeff, rightCoeff, q), q)
}

func transformHashResidualCombinedEval(q, x uint64, relation string, thetaB [][]uint64, mCombined, rHat0, rHat1, tTheta, mSigmaR1Hat, r0R1Hat uint64) uint64 {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBS:
		return transformHashResidualCombinedEvalBBS(q, x, thetaB, mCombined, rHat0, rHat1, tTheta)
	case credential.HashRelationBBTran:
		return transformHashResidualCombinedEvalBBTran(q, x, thetaB, mCombined, rHat0, rHat1, tTheta, mSigmaR1Hat, r0R1Hat)
	default:
		return 1 % q
	}
}

func transformHashResidualCombinedEvalBBS(q, x uint64, thetaB [][]uint64, mCombined, rHat0, rHat1, tTheta uint64) uint64 {
	b0 := EvalPoly(thetaB[0], x, q) % q
	b1 := EvalPoly(thetaB[1], x, q) % q
	b2 := EvalPoly(thetaB[2], x, q) % q
	b3 := EvalPoly(thetaB[3], x, q) % q
	hashNum := modAdd(b0, modMul(b1, mCombined, q), q)
	hashNum = modAdd(hashNum, modMul(b2, rHat0, q), q)
	hashDen := modSub(b3, rHat1, q)
	return modSub(modMul(hashDen, tTheta, q), hashNum, q)
}

func transformHashResidualCombinedEvalBBTran(q, x uint64, thetaB [][]uint64, mCombined, rHat0, rHat1, tTheta, mSigmaR1Hat, r0R1Hat uint64) uint64 {
	_ = mSigmaR1Hat
	_ = r0R1Hat
	b1 := EvalPoly(thetaB[1], x, q) % q
	b2 := EvalPoly(thetaB[2], x, q) % q
	b3 := EvalPoly(thetaB[3], x, q) % q
	res := modMul(b3, tTheta, q)
	res = modSub(res, modMul(tTheta, rHat1, q), q)
	res = modSub(res, modMul(modMul(b3, b1, q), mCombined, q), q)
	res = modSub(res, modMul(modMul(b3, b2, q), rHat0, q), q)
	res = modAdd(res, modMul(b1, modMul(mCombined, rHat1, q), q), q)
	res = modAdd(res, modMul(b2, modMul(rHat0, rHat1, q), q), q)
	return modSub(res, 1, q)
}

func transformTargetResidualCombinedEvalVector(q, x uint64, relation string, thetaB [][]uint64, mCombined uint64, rHat0 []uint64, zHat, tTheta uint64) uint64 {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		if len(thetaB) != 3+len(rHat0) {
			return 1
		}
		b0 := EvalPoly(thetaB[0], x, q) % q
		b1 := EvalPoly(thetaB[1], x, q) % q
		target := modAdd(b0, modMul(b1, mCombined, q), q)
		for i := range rHat0 {
			target = modAdd(target, modMul(EvalPoly(thetaB[2+i], x, q)%q, rHat0[i], q), q)
		}
		target = modAdd(target, zHat, q)
		return modSub(tTheta, target, q)
	default:
		return 0
	}
}

func transformTargetResidualCombinedEvalAggregate(q, x uint64, relation string, thetaB [][]uint64, mCombined, r0B2Hat, zHat, tTheta uint64) uint64 {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		if len(thetaB) < 3 {
			return 1
		}
		b0 := EvalPoly(thetaB[0], x, q) % q
		b1 := EvalPoly(thetaB[1], x, q) % q
		target := modAdd(b0, modMul(b1, mCombined, q), q)
		target = modAdd(target, r0B2Hat, q)
		target = modAdd(target, zHat, q)
		return modSub(tTheta, target, q)
	default:
		return 0
	}
}

func transformInverseResidualEval(q, x uint64, relation string, thetaB [][]uint64, rHat1, zHat uint64) uint64 {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		if len(thetaB) < 4 {
			return 1 % q
		}
		b3 := EvalPoly(thetaB[len(thetaB)-1], x, q) % q
		return modSub(modMul(modSub(b3, rHat1, q), zHat, q), 1, q)
	default:
		return 0
	}
}

func transformHashResidualCombinedKEval(K *kf.Field, e kf.Elem, relation string, thetaB [][]uint64, mCombined, rHat0, rHat1, tTheta, mSigmaR1Hat, r0R1Hat kf.Elem) kf.Elem {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBS:
		return transformHashResidualCombinedKEvalBBS(K, e, thetaB, mCombined, rHat0, rHat1, tTheta)
	case credential.HashRelationBBTran:
		return transformHashResidualCombinedKEvalBBTran(K, e, thetaB, mCombined, rHat0, rHat1, tTheta, mSigmaR1Hat, r0R1Hat)
	default:
		return K.One()
	}
}

func transformHashResidualCombinedKEvalBBS(K *kf.Field, e kf.Elem, thetaB [][]uint64, mCombined, rHat0, rHat1, tTheta kf.Elem) kf.Elem {
	b0 := K.EvalFPolyAtK(thetaB[0], e)
	b1 := K.EvalFPolyAtK(thetaB[1], e)
	b2 := K.EvalFPolyAtK(thetaB[2], e)
	b3 := K.EvalFPolyAtK(thetaB[3], e)
	hashNum := K.Add(b0, K.Mul(b1, mCombined))
	hashNum = K.Add(hashNum, K.Mul(b2, rHat0))
	hashDen := K.Sub(b3, rHat1)
	return K.Sub(K.Mul(hashDen, tTheta), hashNum)
}

func transformHashResidualCombinedKEvalBBTran(K *kf.Field, e kf.Elem, thetaB [][]uint64, mCombined, rHat0, rHat1, tTheta, mSigmaR1Hat, r0R1Hat kf.Elem) kf.Elem {
	_ = mSigmaR1Hat
	_ = r0R1Hat
	b1 := K.EvalFPolyAtK(thetaB[1], e)
	b2 := K.EvalFPolyAtK(thetaB[2], e)
	b3 := K.EvalFPolyAtK(thetaB[3], e)
	res := K.Mul(b3, tTheta)
	res = K.Sub(res, K.Mul(tTheta, rHat1))
	res = K.Sub(res, K.Mul(K.Mul(b3, b1), mCombined))
	res = K.Sub(res, K.Mul(K.Mul(b3, b2), rHat0))
	res = K.Add(res, K.Mul(b1, K.Mul(mCombined, rHat1)))
	res = K.Add(res, K.Mul(b2, K.Mul(rHat0, rHat1)))
	return K.Sub(res, K.One())
}

func transformTargetResidualCombinedKEvalVector(K *kf.Field, e kf.Elem, relation string, thetaB [][]uint64, mCombined kf.Elem, rHat0 []kf.Elem, zHat, tTheta kf.Elem) kf.Elem {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		if len(thetaB) != 3+len(rHat0) {
			return K.One()
		}
		b0 := K.EvalFPolyAtK(thetaB[0], e)
		b1 := K.EvalFPolyAtK(thetaB[1], e)
		target := K.Add(b0, K.Mul(b1, mCombined))
		for i := range rHat0 {
			target = K.Add(target, K.Mul(K.EvalFPolyAtK(thetaB[2+i], e), rHat0[i]))
		}
		target = K.Add(target, zHat)
		return K.Sub(tTheta, target)
	default:
		return K.Zero()
	}
}

func transformTargetResidualCombinedKEvalAggregate(K *kf.Field, e kf.Elem, relation string, thetaB [][]uint64, mCombined, r0B2Hat, zHat, tTheta kf.Elem) kf.Elem {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		if len(thetaB) < 3 {
			return K.One()
		}
		b0 := K.EvalFPolyAtK(thetaB[0], e)
		b1 := K.EvalFPolyAtK(thetaB[1], e)
		target := K.Add(b0, K.Mul(b1, mCombined))
		target = K.Add(target, r0B2Hat)
		target = K.Add(target, zHat)
		return K.Sub(tTheta, target)
	default:
		return K.Zero()
	}
}

func transformInverseResidualKEval(K *kf.Field, e kf.Elem, relation string, thetaB [][]uint64, rHat1, zHat kf.Elem) kf.Elem {
	switch credential.NormalizeHashRelation(relation) {
	case credential.HashRelationBBTran:
		if len(thetaB) < 4 {
			return K.One()
		}
		b3 := K.EvalFPolyAtK(thetaB[len(thetaB)-1], e)
		return K.Sub(K.Mul(K.Sub(b3, rHat1), zHat), K.One())
	default:
		return K.Zero()
	}
}
