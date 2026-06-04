package PIOP

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildReplayHeadsFromSourceHeads(ringQ *ring.Ring, srcHeads [][]uint64, omega []uint64, replayBlockCount int, name string) ([][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(srcHeads) == 0 {
		return nil, fmt.Errorf("missing source heads for %s", name)
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega for %s", name)
	}
	if replayBlockCount <= 0 {
		return nil, fmt.Errorf("invalid replay block count=%d", replayBlockCount)
	}
	ncols := len(omega)
	for i := range srcHeads {
		if len(srcHeads[i]) != ncols {
			return nil, fmt.Errorf("source head %s[%d] len=%d want %d", name, i, len(srcHeads[i]), ncols)
		}
	}
	basis, err := newTransformBridgeBasisCache(ringQ, omega, replayBlockCount*ncols, len(srcHeads))
	if err != nil {
		return nil, fmt.Errorf("transform basis for %s: %w", name, err)
	}
	q := ringQ.Modulus[0]
	out := make([][]uint64, replayBlockCount)
	useAtOmega := len(basis.TransformHAtOmega) >= replayBlockCount*ncols
	computeBlock := func(block int) {
		head := make([]uint64, ncols)
		for j := 0; j < ncols; j++ {
			t := block*ncols + j
			acc := uint64(0)
			for srcBlock := range srcHeads {
				blockScale := basis.BlockFactors[t][srcBlock] % q
				if blockScale == 0 {
					continue
				}
				inner := uint64(0)
				if useAtOmega && len(basis.TransformHAtOmega[t]) >= ncols {
					weights := basis.TransformHAtOmega[t]
					for k := 0; k < ncols; k++ {
						inner = modAdd(inner, modMul(weights[k]%q, srcHeads[srcBlock][k]%q, q), q)
					}
				} else {
					for k := 0; k < ncols; k++ {
						weight := EvalPoly(basis.TransformH[t], omega[k]%q, q) % q
						inner = modAdd(inner, modMul(weight, srcHeads[srcBlock][k]%q, q), q)
					}
				}
				acc = modAdd(acc, modMul(blockScale, inner, q), q)
			}
			head[j] = acc
		}
		out[block] = head
	}
	workers := minInt(runtime.GOMAXPROCS(0), replayBlockCount)
	if workers <= 1 || replayBlockCount < 4 {
		for block := 0; block < replayBlockCount; block++ {
			computeBlock(block)
		}
		return out, nil
	}
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		start := worker * replayBlockCount / workers
		end := (worker + 1) * replayBlockCount / workers
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for block := start; block < end; block++ {
				computeBlock(block)
			}
		}(start, end)
	}
	wg.Wait()
	return out, nil
}

func centeredLift(v, q uint64) int64 {
	out := int64(v % q)
	if out > int64(q)/2 {
		out -= int64(q)
	}
	return out
}

func polyAddMod(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	if n == 0 {
		return []uint64{0}
	}
	out := make([]uint64, n)
	copy(out, a)
	for i := 0; i < len(b); i++ {
		out[i] = modAdd(out[i], b[i]%q, q)
	}
	return trimPoly(out, q)
}

func polyScale(a []uint64, c uint64, q uint64) []uint64 {
	if len(a) == 0 || c%q == 0 {
		return []uint64{0}
	}
	out := make([]uint64, len(a))
	for i := range a {
		out[i] = modMul(a[i]%q, c%q, q)
	}
	return trimPoly(out, q)
}

func polySubMod(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	if n == 0 {
		return []uint64{0}
	}
	out := make([]uint64, n)
	copy(out, a)
	for i := 0; i < len(b); i++ {
		out[i] = modSub(out[i], b[i]%q, q)
	}
	return trimPoly(out, q)
}

func coeffsToNTTIfFits(ringQ *ring.Ring, coeffs []uint64) *ring.Poly {
	if ringQ == nil {
		return nil
	}
	if len(coeffs) == 0 {
		coeffs = []uint64{0}
	}
	if len(coeffs) > int(ringQ.N) {
		return nil
	}
	p := ringQ.NewPoly()
	copy(p.Coeffs[0], coeffs)
	ringQ.NTT(p, p)
	return p
}

func literalPackedPostSignReplayRowCount(layout RowLayout) int {
	if layout.SigCount > 0 {
		return layout.SigCount
	}
	cfg := layout.CoeffNativeSig
	rowCount := 0
	componentCount := cfg.SigComponentCount
	if idx := rowLayoutPostSignSigHatBase(layout); idx >= 0 && layout.SigBlocks > 0 && componentCount > 0 {
		if end := idx + layout.SigBlocks*componentCount; end > rowCount {
			rowCount = end
		}
	}
	if idx := rowLayoutPostSignCarrierM(layout); idx >= 0 && idx+1 > rowCount {
		rowCount = idx + 1
	}
	if idx := rowLayoutPostSignCarrierCtr(layout); idx >= 0 && idx+1 > rowCount {
		rowCount = idx + 1
	}
	if idx := rowLayoutPostSignCarrierR1(layout); idx >= 0 && idx+1 > rowCount {
		rowCount = idx + 1
	}
	for _, idx := range rowLayoutPostSignCarrierR0Rows(layout) {
		if idx >= 0 && idx+1 > rowCount {
			rowCount = idx + 1
		}
	}
	if idx := rowLayoutPostSignTSource(layout); idx >= 0 && rowLayoutPostSignTSourceCount(layout) > 0 {
		if end := idx + rowLayoutPostSignTSourceCount(layout); end > rowCount {
			rowCount = end
		}
	}
	for _, idx := range []int{rowLayoutMSigmaR1(layout), rowLayoutR0R1(layout)} {
		if idx >= 0 && idx+1 > rowCount {
			rowCount = idx + 1
		}
	}
	for _, idx := range rowLayoutSourceProductAliasRows(layout) {
		if idx >= 0 && idx+1 > rowCount {
			rowCount = idx + 1
		}
	}
	replayBlocks := rowLayoutReplayBlockCount(layout)
	if replayBlocks <= 0 {
		replayBlocks = 1
	}
	for _, idx := range []int{
		rowLayoutPostSignMHatSigma(layout),
		rowLayoutPostSignRHat0(layout),
		rowLayoutPostSignR0B2Hat(layout),
		rowLayoutPostSignTargetMR0Hat(layout),
		rowLayoutPostSignRHat1(layout),
		rowLayoutPostSignZHat(layout),
		rowLayoutPostSignMSigmaR1Hat(layout),
		rowLayoutPostSignR0R1Hat(layout),
	} {
		if idx >= 0 && idx+replayBlocks > rowCount {
			rowCount = idx + replayBlocks
		}
	}
	for _, idx := range rowLayoutPostSignTHatRows(layout) {
		if idx >= 0 && idx+1 > rowCount {
			rowCount = idx + 1
		}
	}
	for _, rows := range [][]int{
		rowLayoutPostSignMHatSigmaRows(layout),
		rowLayoutPostSignRHat0Rows(layout),
		rowLayoutPostSignR0B2HatRows(layout),
		rowLayoutPostSignTargetMR0HatRows(layout),
		rowLayoutPostSignRHat1Rows(layout),
		rowLayoutPostSignZHatRows(layout),
		rowLayoutPostSignMSigmaR1HatRows(layout),
		rowLayoutPostSignR0R1HatRows(layout),
	} {
		for _, idx := range rows {
			if idx >= 0 && idx+1 > rowCount {
				rowCount = idx + 1
			}
		}
	}
	if layout.PackedSigChainBase >= 0 && layout.PackedSigChainRowsPerGroup > 0 {
		if end := layout.PackedSigChainBase + layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup; end > rowCount {
			rowCount = end
		}
	}
	if layout.PairLookupExtractBase >= 0 {
		if end := layout.PairLookupExtractBase + rowLayoutPairLookupExtractRowCount(layout); end > rowCount {
			rowCount = end
		}
	}
	return rowCount
}

func buildCredentialConstraintSetPostCoeffNativeLiteralPacked(ringQ *ring.Ring, bound int64, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, domainMode DomainMode, opts SimOpts, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout) (ConstraintSet, error) {
	opts.applyDefaults()
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return ConstraintSet{}, fmt.Errorf("literal packed coeff-native compiler requires literal packed layout")
	}
	if domainMode != DomainModeExplicit {
		return ConstraintSet{}, fmt.Errorf("literal packed aggregated mode requires explicit domain mode")
	}
	if prfCompanionLayout != nil && prfCompanionLayout.RelationVersion == 1 {
		return ConstraintSet{}, fmt.Errorf("direct_full PRF companion is only implemented for IntGenISIS showing constraints")
	}
	var baseSet ConstraintSet
	if rowLayoutCoeffNativeUsesTransformBridge(layout) {
		var err error
		baseSet, err = buildCredentialConstraintSetPostCoeffNativeTransformBridge(ringQ, bound, pub, layout, rowsNTT, omega, domainMode, opts, prfLayout, prfCompanionLayout)
		if err != nil {
			return ConstraintSet{}, err
		}
	} else {
		return ConstraintSet{}, fmt.Errorf("literal packed coeff-native showing requires transform-bridge layout")
	}
	q := ringQ.Modulus[0]
	if cfg.Model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return ConstraintSet{}, fmt.Errorf("unsupported literal packed coeff-native model %q", cfg.Model)
	}
	_ = q
	shortSet, err := buildSigShortnessV18ConstraintSet(ringQ, layout, pub, omega, rowsNTT, opts)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("sig shortness V7 constraints: %w", err)
	}
	baseSet.FparNorm = append(baseSet.FparNorm, shortSet.FparNorm...)
	baseSet.FparNormCoeffs = append(baseSet.FparNormCoeffs, shortSet.FparNormCoeffs...)
	baseSet.FaggNorm = append(baseSet.FaggNorm, shortSet.FaggNorm...)
	baseSet.FaggNormCoeffs = append(baseSet.FaggNormCoeffs, shortSet.FaggNormCoeffs...)
	if shortSet.ParallelAlgDeg > baseSet.ParallelAlgDeg {
		baseSet.ParallelAlgDeg = shortSet.ParallelAlgDeg
	}
	if shortSet.AggregatedAlgDeg > baseSet.AggregatedAlgDeg {
		baseSet.AggregatedAlgDeg = shortSet.AggregatedAlgDeg
	}
	return baseSet, nil
}

func buildLiteralPackedSignatureShortnessConstraintSet(ringQ *ring.Ring, layout RowLayout, rowsNTT []*ring.Poly, opts SimOpts) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	cfg := layout.CoeffNativeSig
	if cfg.Model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return ConstraintSet{}, fmt.Errorf("unsupported literal packed coeff-native model %q", cfg.Model)
	}
	if layout.PackedSigChainBase < 0 || layout.PackedSigChainRowsPerGroup <= 0 {
		return ConstraintSet{}, nil
	}
	q := ringQ.Modulus[0]
	specSig, err := signatureChainSpecForLayoutAndOpts(q, layout, opts)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("signature chain spec: %w", err)
	}
	wantRowsPer, err := signaturePackedChainRowsPerGroupForOpts(specSig, opts, layout.PackedSigChainGroupSize)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("signature shortness rows-per-group: %w", err)
	}
	if layout.PackedSigChainRowsPerGroup != wantRowsPer {
		return ConstraintSet{}, fmt.Errorf("signature shortness rows/group=%d want %d", layout.PackedSigChainRowsPerGroup, wantRowsPer)
	}
	wantBlocks := rowLayoutPackedSigChainEffectiveBlocks(layout)
	if wantBlocks <= 0 {
		wantBlocks = cfg.PackedSigBlocks
	}
	wantGroupCount := cfg.PackedSigComponents * wantBlocks
	if layout.PackedSigChainGroupCount != wantGroupCount {
		return ConstraintSet{}, fmt.Errorf("signature shortness group count=%d want %d", layout.PackedSigChainGroupCount, wantGroupCount)
	}
	if layout.PackedSigChainBase+layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup > len(rowsNTT) {
		return ConstraintSet{}, fmt.Errorf("signature shortness rows [%d,%d) out of range (rows=%d)", layout.PackedSigChainBase, layout.PackedSigChainBase+layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup, len(rowsNTT))
	}
	packedRows := make([][]*ring.Poly, layout.PackedSigChainGroupCount)
	for g := 0; g < layout.PackedSigChainGroupCount; g++ {
		packedRows[g] = make([]*ring.Poly, layout.PackedSigChainRowsPerGroup)
		for i := 0; i < layout.PackedSigChainRowsPerGroup; i++ {
			packedRows[g][i] = rowsNTT[layout.PackedSigChainBase+g*layout.PackedSigChainRowsPerGroup+i]
		}
	}
	var (
		chainPolys  []*ring.Poly
		chainCoeffs [][]uint64
	)
	if cfg.PackedSigCount > 0 && cfg.PackedSigBase >= 0 {
		if cfg.PackedSigBase+cfg.PackedSigCount > len(rowsNTT) {
			return ConstraintSet{}, fmt.Errorf("packed signature source rows [%d,%d) out of range (rows=%d)", cfg.PackedSigBase, cfg.PackedSigBase+cfg.PackedSigCount, len(rowsNTT))
		}
		packedSourceRows := make([]*ring.Poly, layout.PackedSigChainGroupCount)
		for g := 0; g < layout.PackedSigChainGroupCount; g++ {
			packedSourceRows[g] = rowsNTT[cfg.PackedSigBase+g]
		}
		if sigLookupShadowR121L2FreeForOpts(opts) {
			chainPolys, chainCoeffs, err = buildSigShortnessPackedRecompositionFormalCoeffs(ringQ, packedSourceRows, packedRows, specSig)
		} else {
			chainPolys, chainCoeffs, err = buildSigShortnessPackedMembershipFormalCoeffs(ringQ, packedSourceRows, packedRows, specSig)
		}
	} else {
		if sigLookupShadowR121L2FreeForOpts(opts) {
			chainPolys = nil
			chainCoeffs = nil
		} else {
			chainPolys, chainCoeffs, err = buildSigShortnessPackedMembershipFormalCoeffs(ringQ, nil, packedRows, specSig)
		}
	}
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("literal packed signature shortness: %w", err)
	}
	deg := 1
	if !sigLookupShadowR121L2FreeForOpts(opts) {
		deg, err = signatureShortnessMaxDegree(specSig, opts)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("signature shortness degree: %w", err)
		}
	}
	return ConstraintSet{
		FparNorm:       append([]*ring.Poly{}, chainPolys...),
		FparNormCoeffs: append([][]uint64{}, chainCoeffs...),
		ParallelAlgDeg: deg,
	}, nil
}
