package PIOP

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type literalPackedPolyWitness struct {
	Sig          [][]*ring.Poly
	SigHeads     [][][]uint64
	SigLimbs     [][][]*ring.Poly
	SigLimbHeads [][][][]uint64
}

func resolveFullReplayTHatStripeSlots(startRow, replayRows, pcsNCols, tHatCount int) ([]int, error) {
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols %d", pcsNCols)
	}
	if replayRows < 0 {
		return nil, fmt.Errorf("invalid replay window row count %d", replayRows)
	}
	if tHatCount < 0 || tHatCount > replayRows {
		return nil, fmt.Errorf("invalid T-hat row count %d for replay window rows %d", tHatCount, replayRows)
	}
	if tHatCount == 0 {
		return nil, nil
	}
	type slotCapacity struct {
		slot  int
		count int
	}
	capacities := make([]slotCapacity, pcsNCols)
	for slot := 0; slot < pcsNCols; slot++ {
		capacities[slot] = slotCapacity{slot: slot}
	}
	for row := startRow; row < startRow+replayRows; row++ {
		capacities[row%pcsNCols].count++
	}
	sort.Slice(capacities, func(i, j int) bool {
		if capacities[i].count != capacities[j].count {
			return capacities[i].count > capacities[j].count
		}
		return capacities[i].slot < capacities[j].slot
	})
	slots := make([]int, 0, pcsNCols)
	capacity := 0
	for _, candidate := range capacities {
		if candidate.count == 0 {
			break
		}
		slots = append(slots, candidate.slot)
		capacity += candidate.count
		if capacity >= tHatCount {
			sort.Ints(slots)
			return slots, nil
		}
	}
	return nil, fmt.Errorf("full replay T-hat planner capacity=%d need %d for replayRows=%d pcsNCols=%d", capacity, tHatCount, replayRows, pcsNCols)
}

func planFullReplayTHatRows(startRow, replayRows, pcsNCols, tHatCount int) ([]int, []int, error) {
	if startRow < 0 {
		return nil, nil, fmt.Errorf("invalid replay window start row %d", startRow)
	}
	if replayRows < 0 {
		return nil, nil, fmt.Errorf("invalid replay window row count %d", replayRows)
	}
	if pcsNCols <= 0 {
		return nil, nil, fmt.Errorf("invalid pcs ncols %d", pcsNCols)
	}
	if tHatCount < 0 || tHatCount > replayRows {
		return nil, nil, fmt.Errorf("invalid T-hat row count %d for replay window rows %d", tHatCount, replayRows)
	}
	stripeSlots, err := resolveFullReplayTHatStripeSlots(startRow, replayRows, pcsNCols, tHatCount)
	if err != nil {
		return nil, nil, err
	}
	stripe := make(map[int]struct{}, len(stripeSlots))
	for _, slot := range stripeSlots {
		stripe[slot] = struct{}{}
	}
	tHatRows := make([]int, 0, tHatCount)
	otherRows := make([]int, 0, replayRows-tHatCount)
	for row := startRow; row < startRow+replayRows; row++ {
		if _, ok := stripe[row%pcsNCols]; ok && len(tHatRows) < tHatCount {
			tHatRows = append(tHatRows, row)
			continue
		}
		otherRows = append(otherRows, row)
	}
	if len(tHatRows) != tHatCount {
		return nil, nil, fmt.Errorf("full replay T-hat stripe reserved %d rows, need %d", len(tHatRows), tHatCount)
	}
	if len(otherRows) != replayRows-tHatCount {
		return nil, nil, fmt.Errorf("full replay replay-window non-T-hat rows=%d want %d", len(otherRows), replayRows-tHatCount)
	}
	return tHatRows, otherRows, nil
}

func buildLiteralPackedPolyWitness(ringQ *ring.Ring, cn *CoeffNativeShowingWitness, omega []uint64, ncols int, model string, opts SimOpts) (*literalPackedPolyWitness, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if cn == nil {
		return nil, fmt.Errorf("nil coeff-native showing witness")
	}
	if ncols <= 0 || int(ringQ.N)%ncols != 0 {
		return nil, fmt.Errorf("invalid ncols=%d for ringN=%d", ncols, ringQ.N)
	}
	if len(omega) != ncols {
		return nil, fmt.Errorf("omega len=%d want ncols=%d", len(omega), ncols)
	}
	if model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return nil, fmt.Errorf("unsupported coeff-native showing model %q", model)
	}
	q := ringQ.Modulus[0]
	blocks := int(ringQ.N) / ncols
	out := &literalPackedPolyWitness{
		Sig:          make([][]*ring.Poly, len(cn.Sig)),
		SigHeads:     make([][][]uint64, len(cn.Sig)),
		SigLimbs:     make([][][]*ring.Poly, len(cn.Sig)),
		SigLimbHeads: make([][][][]uint64, len(cn.Sig)),
	}
	opts.CoeffNativeSigModel = model
	spec, err := signatureChainSpecForOpts(q, opts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	for comp := range cn.Sig {
		if cn.Sig[comp] == nil || len(cn.Sig[comp].Coeffs) == 0 || len(cn.Sig[comp].Coeffs[0]) < int(ringQ.N) {
			return nil, fmt.Errorf("signature component %d width=%d want ringN=%d", comp, len(cn.Sig[comp].Coeffs[0]), ringQ.N)
		}
		out.Sig[comp] = make([]*ring.Poly, blocks)
		out.SigHeads[comp] = make([][]uint64, blocks)
		out.SigLimbs[comp] = make([][]*ring.Poly, blocks)
		out.SigLimbHeads[comp] = make([][][]uint64, blocks)
		for block := 0; block < blocks; block++ {
			start := block * ncols
			end := start + ncols
			sigHead := append([]uint64(nil), cn.Sig[comp].Coeffs[0][start:end]...)
			for i := range sigHead {
				sigHead[i] %= q
			}
			out.SigHeads[comp][block] = append([]uint64(nil), sigHead...)
			out.Sig[comp][block] = BuildThetaPrime(ringQ, sigHead, omega)
			out.SigLimbs[comp][block] = make([]*ring.Poly, spec.L)
			out.SigLimbHeads[comp][block] = make([][]uint64, spec.L)
			limbHeads := make([][]uint64, spec.L)
			for lane := 0; lane < spec.L; lane++ {
				limbHeads[lane] = make([]uint64, ncols)
			}
			for i := range sigHead {
				av := centeredLift(sigHead[i], q)
				digits, derr := decomposeLinfDigitsSigned(av, spec)
				if derr != nil {
					return nil, fmt.Errorf("v3 signature limb decomposition (comp=%d block=%d col=%d): %w", comp, block, i, derr)
				}
				for lane := 0; lane < spec.L; lane++ {
					limbHeads[lane][i] = liftToField(q, digits[lane])
				}
			}
			for lane := 0; lane < spec.L; lane++ {
				out.SigLimbHeads[comp][block][lane] = append([]uint64(nil), limbHeads[lane]...)
				out.SigLimbs[comp][block][lane] = BuildThetaPrime(ringQ, limbHeads[lane], omega)
			}
		}
	}
	return out, nil
}

func reconstructPackedSigHeadsFromLimbHeads(sigLimbHeads [][][][]uint64, spec LinfSpec, q uint64) [][][]uint64 {
	if len(sigLimbHeads) == 0 {
		return nil
	}
	out := make([][][]uint64, len(sigLimbHeads))
	for comp := range sigLimbHeads {
		out[comp] = make([][]uint64, len(sigLimbHeads[comp]))
		for block := range sigLimbHeads[comp] {
			ncols := 0
			if len(sigLimbHeads[comp][block]) > 0 {
				ncols = len(sigLimbHeads[comp][block][0])
			}
			head := make([]uint64, ncols)
			for lane := 0; lane < len(sigLimbHeads[comp][block]) && lane < len(spec.RPows); lane++ {
				for col := 0; col < ncols; col++ {
					head[col] = modAdd(head[col], modMul(spec.RPows[lane]%q, sigLimbHeads[comp][block][lane][col]%q, q), q)
				}
			}
			out[comp][block] = head
		}
	}
	return out
}

func buildSigHatHeadsFromPackedSigHeads(ringQ *ring.Ring, sigHeads [][][]uint64, ncols int) ([][][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if ncols <= 0 || int(ringQ.N)%ncols != 0 {
		return nil, fmt.Errorf("invalid ncols=%d for ringN=%d", ncols, ringQ.N)
	}
	if len(sigHeads) == 0 {
		return nil, fmt.Errorf("empty signature heads")
	}
	blocks := int(ringQ.N) / ncols
	q := ringQ.Modulus[0]
	out := make([][][]uint64, blocks)
	for block := 0; block < blocks; block++ {
		out[block] = make([][]uint64, len(sigHeads))
	}
	for comp := range sigHeads {
		if len(sigHeads[comp]) != blocks {
			return nil, fmt.Errorf("signature head block count=%d want %d", len(sigHeads[comp]), blocks)
		}
		coeff := ringQ.NewPoly()
		for block := 0; block < blocks; block++ {
			if len(sigHeads[comp][block]) != ncols {
				return nil, fmt.Errorf("signature head width=%d want %d", len(sigHeads[comp][block]), ncols)
			}
			start := block * ncols
			for col := 0; col < ncols; col++ {
				coeff.Coeffs[0][start+col] = sigHeads[comp][block][col] % q
			}
		}
		coeffNTT := ringQ.NewPoly()
		ringQ.NTT(coeff, coeffNTT)
		for block := 0; block < blocks; block++ {
			start := block * ncols
			end := start + ncols
			out[block][comp] = append([]uint64(nil), coeffNTT.Coeffs[0][start:end]...)
		}
	}
	return out, nil
}

func buildTHatHeadsFromSigHatHeads(ringQ *ring.Ring, pub PublicInputs, omega []uint64, sigHatHeads [][][]uint64, replayTHatCount int, sourceBlocks int) ([][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return nil, fmt.Errorf("direct T-hat expects one public A row, got %d", len(pub.A))
	}
	if replayTHatCount <= 0 {
		return nil, fmt.Errorf("invalid replay T-hat count=%d", replayTHatCount)
	}
	if sourceBlocks <= 0 {
		return nil, fmt.Errorf("invalid source blocks=%d", sourceBlocks)
	}
	ncols := len(omega)
	q := ringQ.Modulus[0]
	out := make([][]uint64, replayTHatCount)
	for block := 0; block < replayTHatCount; block++ {
		tHead := make([]uint64, ncols)
		for comp := 0; comp < len(pub.A[0]); comp++ {
			aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omega, block, sourceBlocks)
			if err != nil {
				return nil, fmt.Errorf("theta A head block %d comp %d: %w", block, comp, err)
			}
			for k := 0; k < ncols; k++ {
				tHead[k] = modAdd(tHead[k], modMul(aHead[k]%q, sigHatHeads[block][comp][k]%q, q), q)
			}
		}
		out[block] = tHead
	}
	return out, nil
}

func buildReplayHeadsFromSourcePoly(ringQ *ring.Ring, sourcePoly *ring.Poly, omega []uint64, replayBlockCount int, name string) ([][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if sourcePoly == nil {
		return nil, fmt.Errorf("nil %s", name)
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega for %s", name)
	}
	if replayBlockCount <= 0 {
		return nil, fmt.Errorf("invalid replay block count=%d", replayBlockCount)
	}
	ncols := len(omega)
	if ncols <= 0 || ncols > int(ringQ.N) {
		return nil, fmt.Errorf("invalid ncols=%d for ringN=%d", ncols, ringQ.N)
	}
	return buildReplayHeadsFromCoeffPolyNTT(ringQ, sourcePoly, replayBlockCount, ncols, name)
}

func buildReplayHeadsFromCoeffPolyNTT(ringQ *ring.Ring, sourcePoly *ring.Poly, replayBlockCount, ncols int, name string) ([][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if sourcePoly == nil {
		return nil, fmt.Errorf("nil %s", name)
	}
	if replayBlockCount <= 0 {
		return nil, fmt.Errorf("invalid replay block count=%d", replayBlockCount)
	}
	if ncols <= 0 || replayBlockCount*ncols > int(ringQ.N) {
		return nil, fmt.Errorf("invalid replay geometry blocks=%d ncols=%d ringN=%d", replayBlockCount, ncols, ringQ.N)
	}
	pNTT := ringQ.NewPoly()
	ring.Copy(sourcePoly, pNTT)
	ringQ.NTT(pNTT, pNTT)
	q := ringQ.Modulus[0]
	out := make([][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
		start := block * ncols
		end := start + ncols
		head := append([]uint64(nil), pNTT.Coeffs[0][start:end]...)
		for i := range head {
			head[i] %= q
		}
		out[block] = head
	}
	return out, nil
}

func buildReplayHeadsFromSourceRows(ringQ *ring.Ring, sourceRows []*ring.Poly, omega []uint64, replayBlockCount int, name string) ([][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(sourceRows) == 0 {
		return nil, fmt.Errorf("missing source rows for %s", name)
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega for %s", name)
	}
	if replayBlockCount <= 0 {
		return nil, fmt.Errorf("invalid replay block count=%d", replayBlockCount)
	}
	ncols := len(omega)
	srcHeads := make([][]uint64, len(sourceRows))
	for i := range sourceRows {
		head, herr := rowHeadOnOmega(ringQ, omega, sourceRows[i], ncols)
		if herr != nil {
			return nil, fmt.Errorf("source head %s[%d]: %w", name, i, herr)
		}
		srcHeads[i] = head
	}
	return buildReplayHeadsFromSourceHeads(ringQ, srcHeads, omega, replayBlockCount, name)
}

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

func repeatFieldValue(v uint64, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func validateSparseSupportTailZero(p *ring.Poly, ncols int, q uint64, name string) error {
	if p == nil {
		return fmt.Errorf("nil %s", name)
	}
	if ncols < 0 || ncols > len(p.Coeffs[0]) {
		return fmt.Errorf("invalid sparse support width=%d for %s", ncols, name)
	}
	for i := ncols; i < len(p.Coeffs[0]); i++ {
		if p.Coeffs[0][i]%q != 0 {
			return fmt.Errorf("%s has nonzero coefficient outside sparse support at idx=%d", name, i)
		}
	}
	return nil
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

func buildCredentialRowsShowingCoeffNativeLiteralPacked(
	ringQ *ring.Ring,
	pub PublicInputs,
	wit WitnessInputs,
	prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds int,
	opts SimOpts,
) (rows []*ring.Poly, rowInputs []lvcs.RowInput, layout RowLayout, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols int, err error) {
	if ringQ == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	if opts.DomainMode != DomainModeExplicit {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed aggregated mode requires explicit domain mode")
	}
	if opts.NCols <= 0 {
		opts.NCols = int(ringQ.N)
	}
	ncols = opts.NCols
	if ncols <= 0 || ringQ.N%ncols != 0 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires ringN %% ncols == 0 (ringN=%d ncols=%d)", ringQ.N, ncols)
	}
	if wit.CoeffNativeShowing == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires WitnessInputs.CoeffNativeShowing")
	}
	model := resolveCoeffNativeSigModel(opts)
	if !coeffNativeSigModelUsesLiteralPacked(model) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("unsupported literal packed coeff-native model %q", model)
	}
	cn := wit.CoeffNativeShowing
	if err := cn.Validate(int(ringQ.N)); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("invalid coeff-native witness: %w", err)
	}
	if len(pub.A) == 0 || len(pub.A[0]) == 0 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires non-empty A")
	}
	if len(cn.Sig) != len(pub.A[0]) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed signature witness rows=%d want %d", len(cn.Sig), len(pub.A[0]))
	}
	blocks := int(ringQ.N) / ncols
	replayBlockCount := 1
	if opts.ShowingReplayMode == ShowingReplayModeFull {
		replayBlockCount = blocks
	}
	var explicitOmega []uint64
	if opts.DomainMode == DomainModeExplicit {
		nLeaves := opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		derivedOmega, derr := deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, ncols, opts.LVCSNCols, opts.Ell, pub.HashRelation)
		if derr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed explicit omega: %w", derr)
		}
		explicitOmega = derivedOmega
	}
	makeRowFromHead := func(head []uint64) *ring.Poly {
		if opts.DomainMode == DomainModeExplicit {
			pNTT := BuildThetaPrime(ringQ, head, explicitOmega)
			coeff := ringQ.NewPoly()
			ringQ.InvNTT(pNTT, coeff)
			return coeff
		}
		pNTT := ringQ.NewPoly()
		q := ringQ.Modulus[0]
		for i := 0; i < ncols && i < len(head); i++ {
			pNTT.Coeffs[0][i] = head[i] % q
		}
		out := ringQ.NewPoly()
		ringQ.InvNTT(pNTT, out)
		return out
	}
	packedWitness, err := buildLiteralPackedPolyWitness(ringQ, cn, explicitOmega, ncols, model, opts)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed witness: %w", err)
	}
	if model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("unsupported literal packed coeff-native model %q", model)
	}

	spec, serr := signatureChainSpecForOpts(ringQ.Modulus[0], opts)
	if serr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature chain spec: %w", serr)
	}
	if !signatureSpecNoWrapOK(spec) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature chain spec violates no-wrap bound: maxAbs=%d q=%d", spec.MaxAbs, spec.Q)
	}
	useV18Shortness := sigShortnessV18EnabledForOpts(opts)
	useInlinedShortness := useV18Shortness
	useDirectTargetReplay := useV18Shortness
	useTargetMR0HatReplay := false
	useRHat1Replay := true
	muPackWidth := resolveMuWitnessPackWidth(opts)
	if err := validateMuWitnessPackWidth(muPackWidth); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if muPackWidth > 1 && !useV18Shortness {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("packed mu witness width=%d is only supported by the V18 optimized showing path", muPackWidth)
	}
	if useInlinedShortness && spec.UsesAbsRow {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("inlined sig shortness does not support abs-row packed chains")
	}
	if useV18Shortness {
		sourceNCols := cn.PackedNCols
		if sourceNCols <= 0 {
			sourceNCols = ncols
		}
		groupSize := opts.PackedSigChainGroupSize
		if groupSize <= 0 {
			groupSize = aggregateInlineTargetReplayCompactGroupSize
		}
		if groupSize <= 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("inlined sig shortness requires positive group size, got %d", groupSize)
		}
		if groupSize != aggregateInlineTargetReplayCompactGroupSize {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("sig shortness V18 group_size=%d want %d", groupSize, aggregateInlineTargetReplayCompactGroupSize)
		}
		if ncols != sourceNCols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("inlined sig shortness ncols=%d want source_ncols=%d", ncols, sourceNCols)
		}
		if int(ringQ.N)%ncols != 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("inlined sig shortness invalid block geometry N=%d ncols=%d", ringQ.N, ncols)
		}
	} else if cn.PackedNCols != ncols {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native packed ncols=%d want %d", cn.PackedNCols, ncols)
	}
	nttHead := func(src *ring.Poly) ([]uint64, error) {
		if src == nil {
			return nil, fmt.Errorf("nil NTT source row")
		}
		fullNTT := ringQ.NewPoly()
		ring.Copy(src, fullNTT)
		ringQ.NTT(fullNTT, fullNTT)
		if ncols > len(fullNTT.Coeffs[0]) {
			return nil, fmt.Errorf("NTT source row ncols=%d exceeds row width=%d", ncols, len(fullNTT.Coeffs[0]))
		}
		head0 := append([]uint64(nil), fullNTT.Coeffs[0][:ncols]...)
		return head0, nil
	}

	if pub.BoundB <= 0 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("transform-bridge showing requires positive BoundB")
	}
	q := ringQ.Modulus[0]
	if opts.ShowingReplayMode == ShowingReplayModeFull {
		sparseSupportRows := []struct {
			poly *ring.Poly
			name string
		}{
			{poly: cn.R1, name: "R1"},
		}
		for i, r0 := range cn.R0 {
			sparseSupportRows = append(sparseSupportRows, struct {
				poly *ring.Poly
				name string
			}{poly: r0, name: fmt.Sprintf("R0[%d]", i)})
		}
		for _, pair := range sparseSupportRows {
			if err := validateSparseSupportTailZero(pair.poly, ncols, q, pair.name); err != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
			}
		}
	}
	var berr error
	if cn.Mu == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native showing witness missing Mu row")
	}
	muHeads, berr := coeffBlockHeadsFromPoly(ringQ, cn.Mu, ncols, "Mu")
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native Mu blocks: %w", berr)
	}
	r0Heads := make([][]uint64, len(cn.R0))
	for i := range cn.R0 {
		if opts.DomainMode == DomainModeExplicit {
			r0Heads[i], berr = rowHeadOnOmega(ringQ, explicitOmega, cn.R0[i], ncols)
		} else {
			r0Heads[i], berr = nttHead(cn.R0[i])
		}
		if berr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0[%d] head: %w", i, berr)
		}
	}
	var r1Head []uint64
	if opts.DomainMode == DomainModeExplicit {
		r1Head, berr = rowHeadOnOmega(ringQ, explicitOmega, cn.R1, ncols)
	} else {
		r1Head, berr = nttHead(cn.R1)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R1 head: %w", berr)
	}
	carrierMHeads, cerr := buildPackedMuCarrierHeads(muHeads, q, pub.BoundB, muPackWidth)
	if cerr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
	}
	carrierR0Heads := make([][]uint64, len(r0Heads))
	for i := range carrierR0Heads {
		carrierR0Heads[i] = make([]uint64, ncols)
	}
	carrierR1Head := make([]uint64, ncols)
	for col := 0; col < ncols; col++ {
		for i := range r0Heads {
			code, err := encodeSingletonCarrier(centeredLift(r0Heads[i][col], q), pub.X0CoeffBound)
			if err != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("encode carrier R0[%d] col=%d: %w", i, col, err)
			}
			carrierR0Heads[i][col] = liftToField(q, int64(code))
		}
		code, err := encodeCarrierPair(centeredLift(r1Head[col], q), 0, pub.BoundB)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("encode carrier R1 col=%d: %w", col, err)
		}
		carrierR1Head[col] = liftToField(q, int64(code))
	}
	carrierMuBlockRows := make([]int, len(carrierMHeads))
	for i := range carrierMHeads {
		carrierMuBlockRows[i] = len(rows)
		rows = append(rows, makeRowFromHead(carrierMHeads[i]))
	}
	idxCarrierM := firstIndex(carrierMuBlockRows)
	carrierR0Rows := make([]int, len(carrierR0Heads))
	for i := range carrierR0Heads {
		carrierR0Rows[i] = len(rows)
		rows = append(rows, makeRowFromHead(carrierR0Heads[i]))
	}
	idxCarrierR1 := len(rows)
	rows = append(rows, makeRowFromHead(carrierR1Head))

	companionMode := normalizePRFCompanionMode(opts.PRFCompanionMode)
	keySourceBlock := -1
	keySourcePackedRow := -1
	keySourceLane := 0
	keySourceColStart := -1
	appendPRFCompanionRows := func(denseKeyPacking bool) error {
		if prfGroupRounds <= 0 {
			prfGroupRounds = 1
		}
		var keyScalars []int64
		var kerr error
		keyStart := fullCapacityMuKeyStart(int(ringQ.N))
		keySourceBlock = keyStart / ncols
		keySourceColStart = keyStart % ncols
		keySourcePackedRow = keySourceBlock / muPackWidth
		keySourceLane = keySourceBlock % muPackWidth
		if keySourceBlock < 0 || keySourcePackedRow < 0 || keySourcePackedRow >= len(carrierMuBlockRows) || keySourceColStart+prfParamsLenKey > ncols {
			return fmt.Errorf("full-capacity mu key window block=%d packed_row=%d col=%d len=%d outside ncols=%d carrier_rows=%d", keySourceBlock, keySourcePackedRow, keySourceColStart, prfParamsLenKey, ncols, len(carrierMuBlockRows))
		}
		keyCarrierRow := rows[carrierMuBlockRows[keySourcePackedRow]]
		if opts.DomainMode == DomainModeExplicit {
			if len(explicitOmega) == 0 {
				return fmt.Errorf("explicit omega missing for semantic key extraction")
			}
			if muPackWidth == 1 {
				keyScalars, kerr = ExtractSignedPRFKeyScalarsFromSingletonCarrierWindowOnOmega(ringQ, keyCarrierRow, explicitOmega, keySourceColStart, prfParamsLenKey, pub.BoundB)
			} else {
				keyScalars, kerr = ExtractSignedPRFKeyScalarsFromPackedMuCarrierWindowOnOmega(ringQ, keyCarrierRow, explicitOmega, keySourceColStart, prfParamsLenKey, pub.BoundB, muPackWidth, keySourceLane)
			}
		} else {
			if muPackWidth == 1 {
				keyScalars, kerr = ExtractSignedPRFKeyScalarsFromSingletonCarrierWindow(ringQ, keyCarrierRow, keySourceColStart, prfParamsLenKey, pub.BoundB)
			} else {
				keyScalars, kerr = ExtractSignedPRFKeyScalarsFromPackedMuCarrierWindow(ringQ, keyCarrierRow, keySourceColStart, prfParamsLenKey, pub.BoundB, muPackWidth, keySourceLane)
			}
		}
		if kerr != nil {
			return fmt.Errorf("extract signed prf key: %w", kerr)
		}
		if companionMode == "" {
			return fmt.Errorf("showing requires PRF companion mode")
		}
		companionStart := len(rows)
		if startIdx <= 0 {
			startIdx = companionStart
		}
		keyElems := make([]prf.Elem, len(keyScalars))
		for i := range keyScalars {
			keyElems[i] = prf.Elem(liftToField(ringQ.Modulus[0], keyScalars[i]))
		}
		nonceElems := make([]prf.Elem, len(pub.Nonce))
		for i := range pub.Nonce {
			if len(pub.Nonce[i]) == 0 {
				return fmt.Errorf("public nonce lane %d is empty", i)
			}
			nonceElems[i] = prf.Elem(liftToField(ringQ.Modulus[0], pub.Nonce[i][0]))
		}
		params, perr := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
		if perr != nil {
			return fmt.Errorf("load prf params for companion witness: %w", perr)
		}
		groupedWitness, gwerr := prf.TraceGroupedWitness(keyElems, nonceElems, params, prfGroupRounds)
		if gwerr != nil {
			return fmt.Errorf("trace grouped prf witness: %w", gwerr)
		}
		packed, perr := packPRFCompanionWitnessRows(ringQ, ncols, companionStart, companionMode, denseKeyPacking, keyElems, groupedWitness, makeRowFromHead)
		if perr != nil {
			return fmt.Errorf("pack prf companion rows: %w", perr)
		}
		rows = append(rows, packed.Rows...)
		if len(packed.KeySlots) == 0 {
			return fmt.Errorf("prf companion missing key slots for independent-key showing")
		}
		rowSemantics := make([]RowSemantics, len(packed.Rows))
		for i := range rowSemantics {
			rowSemantics[i] = CoeffPackedRow
		}
		dataSlotRows := append([]CoeffSlot(nil), packed.KeySlots...)
		dataSlotRows = append(dataSlotRows, packed.CheckpointSlots...)
		dataSlotRows = append(dataSlotRows, packed.FinalRoundOutputSlots...)
		dataRows := len(uniqueRowsFromCoeffSlots(dataSlotRows))
		helperRows := maxInt(len(packed.Rows)-dataRows, 0)
		helperFamilies := []string{"final_tag_state"}
		if denseKeyPacking && helperRows == 0 {
			helperFamilies = nil
		}
		prfCompanionLayout = &PRFCompanionLayout{
			StartRow:              companionStart,
			PackWidth:             ncols,
			GroupRounds:           prfGroupRounds,
			KeySource:             KeySourceIndependentWitness,
			KeySlots:              packed.KeySlots,
			KeySourceSlots:        nil,
			CheckpointSlots:       packed.CheckpointSlots,
			FinalRoundOutputSlots: packed.FinalRoundOutputSlots,
			FinalTagSlots:         packed.FinalTagSlots,
			HelperFamilies:        helperFamilies,
			ReplayRows:            len(packed.Rows),
			PackedRows:            len(packed.Rows),
			PackedLogicalCount:    packed.TotalLogicalScalars,
			HelperRowCount:        helperRows,
			DataRows:              dataRows,
			HelperRows:            helperRows,
			KeyCount:              len(packed.KeySlots),
			CheckpointCount:       len(packed.CheckpointSlots),
			FinalRoundOutputCount: len(packed.FinalRoundOutputSlots),
			TagCount:              len(pub.Tag),
			RelationVersion:       prfCompanionRelationVersion(companionMode),
			RowSemantics:          rowSemantics,
		}
		if companionMode == PRFCompanionModeAuxInstance {
			pcsNCols := resolvePCSNCols(opts, ncols)
			var aerr error
			rows, aerr = appendPRFBridgeStripeRows(ringQ, rows, prfCompanionLayout, pcsNCols)
			if aerr != nil {
				return fmt.Errorf("append prf bridge stripe rows: %w", aerr)
			}
		}
		return nil
	}
	if useV18Shortness {
		if err := appendPRFCompanionRows(true); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}

	rawRowsForAlias := PreSignRawRows{
		R0: cn.R0,
		R1: cn.R1,
	}
	if muPackWidth == 1 {
		rawRowsForAlias.Mu = cn.Mu
	}
	rawAliasSurface, derr := DerivePreSignCarrierAndAliasRows(
		ringQ,
		pub.BoundB,
		pub.X0CoeffBound,
		explicitOmega,
		DomainModeExplicit,
		rawRowsForAlias,
	)
	if derr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("derive showing raw alias surface: %w", derr)
	}

	var aliasMuBlockRows []int
	if muPackWidth == 1 {
		aliasMuBlockRows = make([]int, len(rawAliasSurface.AliasMuRows))
		for i := range rawAliasSurface.AliasMuRows {
			aliasMuBlockRows[i] = len(rows)
			rows = append(rows, rawAliasSurface.AliasMuRows[i])
		}
	}
	idxM1 := firstIndex(aliasMuBlockRows)
	idxM2 := -1
	if muPackWidth == 1 {
		idxM2 = len(rows)
		rows = append(rows, rawAliasSurface.AliasM2)
	}
	if prfCompanionLayout != nil && keySourceBlock >= 0 {
		prfCompanionLayout.KeySourceSlots = make([]CoeffSlot, prfParamsLenKey)
		prfCompanionLayout.KeySourceDecodeLanes = nil
		for i := 0; i < prfParamsLenKey; i++ {
			if muPackWidth == 1 {
				if keySourceBlock >= len(aliasMuBlockRows) {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("key source block=%d outside alias mu blocks=%d", keySourceBlock, len(aliasMuBlockRows))
				}
				prfCompanionLayout.KeySourceSlots[i] = CoeffSlot{Row: aliasMuBlockRows[keySourceBlock], Coeff: keySourceColStart + i}
			} else {
				prfCompanionLayout.KeySourceSlots[i] = CoeffSlot{Row: carrierMuBlockRows[keySourcePackedRow], Coeff: keySourceColStart + i}
			}
		}
		if muPackWidth > 1 {
			prfCompanionLayout.KeySourceDecodeLanes = make([]int, prfParamsLenKey)
			for i := range prfCompanionLayout.KeySourceDecodeLanes {
				prfCompanionLayout.KeySourceDecodeLanes[i] = keySourceLane
			}
		}
	}
	aliasR0Rows := make([]int, len(rawAliasSurface.AliasR0Rows))
	for i := range rawAliasSurface.AliasR0Rows {
		aliasR0Rows[i] = len(rows)
		rows = append(rows, rawAliasSurface.AliasR0Rows[i])
	}
	idxR1 := len(rows)
	rows = append(rows, rawAliasSurface.AliasR1)

	useBBTran := publicUsesBBTran(pub)
	useZHatReplay := useBBTran
	idxZ := -1
	var zSourcePoly *ring.Poly
	if useBBTran {
		zSourcePoly = cn.Z
	}

	mHat1Heads, berr := buildReplayHeadsFromSourcePoly(ringQ, cn.Mu, explicitOmega, replayBlockCount, "Mu hat")
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native Mu hat: %w", berr)
	}
	mSigmaHatHeads := make([][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
		mSigmaHatHeads[block] = make([]uint64, ncols)
		for col := 0; col < ncols; col++ {
			mSigmaHatHeads[block][col] = mHat1Heads[block][col] % q
		}
	}
	r0HatHeads := make([][][]uint64, len(rawAliasSurface.AliasR0Rows))
	for i := range rawAliasSurface.AliasR0Rows {
		r0HatHeads[i], berr = buildReplayHeadsFromSourcePoly(ringQ, rawAliasSurface.AliasR0Rows[i], explicitOmega, replayBlockCount, fmt.Sprintf("R0[%d]", i))
		if berr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0[%d] hats: %w", i, berr)
		}
	}
	aggregateR0Replay := opts.AggregateR0Replay
	if aggregateR0Replay {
		if opts.ShowingReplayMode != ShowingReplayModeFull {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("aggregate R0 replay requires full replay mode")
		}
		if !useBBTran {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("aggregate R0 replay requires bb_tran relation")
		}
		if len(r0HatHeads) == 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("aggregate R0 replay requires R0 hats")
		}
		if len(pub.B) != 3+len(r0HatHeads) {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("aggregate R0 replay B rows=%d want %d", len(pub.B), 3+len(r0HatHeads))
		}
	}
	var r0B2HatHeads [][]uint64
	if aggregateR0Replay {
		r0B2HatHeads = make([][]uint64, replayBlockCount)
		for block := 0; block < replayBlockCount; block++ {
			head := make([]uint64, ncols)
			for i := range r0HatHeads {
				b2Head, err := thetaHeadFromNTTBlock(ringQ, pub.B[2+i], explicitOmega, block, blocks)
				if err != nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("aggregate R0 theta B2[%d] block %d: %w", i, block, err)
				}
				for col := 0; col < ncols; col++ {
					head[col] = modAdd(head[col], modMul(b2Head[col]%q, r0HatHeads[i][block][col]%q, q), q)
				}
			}
			r0B2HatHeads[block] = head
		}
	}
	var targetMR0HatHeads [][]uint64
	if useTargetMR0HatReplay {
		if !aggregateR0Replay {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("direct-target replay requires aggregate R0 replay")
		}
		if !useBBTran {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("direct-target replay requires bb_tran relation")
		}
		targetMR0HatHeads = make([][]uint64, replayBlockCount)
		for block := 0; block < replayBlockCount; block++ {
			b1Head, err := thetaHeadFromNTTBlock(ringQ, pub.B[1], explicitOmega, block, blocks)
			if err != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("direct-target theta B1 block %d: %w", block, err)
			}
			head := make([]uint64, ncols)
			for col := 0; col < ncols; col++ {
				head[col] = modAdd(modMul(b1Head[col]%q, mSigmaHatHeads[block][col]%q, q), r0B2HatHeads[block][col]%q, q)
			}
			targetMR0HatHeads[block] = head
		}
	}
	var r1HatHeads [][]uint64
	if useRHat1Replay {
		r1HatHeads, berr = buildReplayHeadsFromSourcePoly(ringQ, rawAliasSurface.AliasR1, explicitOmega, replayBlockCount, "R1")
		if berr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R1 hats: %w", berr)
		}
	}
	var zHatHeads [][]uint64
	if useZHatReplay {
		zHatHeads, derr = buildReplayHeadsFromCoeffPolyNTT(ringQ, zSourcePoly, replayBlockCount, ncols, "Z")
		if derr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native Z hats: %w", derr)
		}
	}

	replayTHatCount := replayBlockCount
	if useDirectTargetReplay {
		replayTHatCount = 0
	}
	packedSigHeadsForReplay := packedWitness.SigHeads
	if useInlinedShortness {
		packedSigHeadsForReplay = reconstructPackedSigHeadsFromLimbHeads(packedWitness.SigLimbHeads, spec, q)
	}
	sigHatHeads, terr := buildSigHatHeadsFromPackedSigHeads(ringQ, packedSigHeadsForReplay, ncols)
	if terr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("build sig hats from packed heads: %w", terr)
	}
	var tHatHeads [][]uint64
	if !useDirectTargetReplay {
		tHatHeads, terr = buildTHatHeadsFromSigHatHeads(ringQ, pub, explicitOmega, sigHatHeads, replayTHatCount, blocks)
		if terr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("build T replay heads from signature hats: %w", terr)
		}
	}
	replayMHatSigmaRows := make([]int, replayBlockCount)
	replayRHat0Rows := make([]int, 0, replayBlockCount*len(r0HatHeads))
	replayR0B2HatRows := make([]int, 0, replayBlockCount)
	replayTargetMR0HatRows := make([]int, 0, replayBlockCount)
	var replayRHat1Rows []int
	if useRHat1Replay {
		replayRHat1Rows = make([]int, replayBlockCount)
	}
	var replayZHatRows []int
	if useZHatReplay {
		replayZHatRows = make([]int, replayBlockCount)
	}
	replayTHatRows := make([]int, replayTHatCount)
	packedFullReplay := false
	if opts.ShowingReplayMode == ShowingReplayModeFull && replayBlockCount > 1 && !useDirectTargetReplay {
		r0ReplayRowsPerBlock := len(r0HatHeads)
		if aggregateR0Replay {
			r0ReplayRowsPerBlock = 1
		}
		nonTHatRowsPerBlock := 2 + r0ReplayRowsPerBlock
		if useBBTran {
			nonTHatRowsPerBlock++
		}
		totalReplayRowsPerBlock := nonTHatRowsPerBlock + 1
		replayWindowStart := len(rows)
		replayWindowRows := replayBlockCount * totalReplayRowsPerBlock
		pcsNCols := opts.PostSignLVCSNCols
		if pcsNCols <= 0 {
			pcsNCols = resolvePCSNCols(opts, ncols)
		}
		tHatPlanRows, otherPlanRows, planErr := planFullReplayTHatRows(replayWindowStart, replayWindowRows, pcsNCols, replayTHatCount)
		if planErr == nil {
			if len(otherPlanRows) != replayBlockCount*nonTHatRowsPerBlock {
				planErr = fmt.Errorf("packed full replay non-T-hat rows=%d want %d", len(otherPlanRows), replayBlockCount*nonTHatRowsPerBlock)
			}
		}
		if planErr == nil {
			replayRowsPacked := make([]*ring.Poly, replayWindowRows)
			assignReplayRow := func(row int, poly *ring.Poly) error {
				if row < replayWindowStart || row >= replayWindowStart+replayWindowRows {
					return fmt.Errorf("replay row %d outside packed window [%d,%d)", row, replayWindowStart, replayWindowStart+replayWindowRows)
				}
				idx := row - replayWindowStart
				if replayRowsPacked[idx] != nil {
					return fmt.Errorf("replay row %d assigned twice", row)
				}
				replayRowsPacked[idx] = poly
				return nil
			}
			otherPos := 0
			assignOther := func(poly *ring.Poly) (int, error) {
				if otherPos >= len(otherPlanRows) {
					return -1, fmt.Errorf("replay row planner exhausted non-T-hat positions")
				}
				row := otherPlanRows[otherPos]
				otherPos++
				if err := assignReplayRow(row, poly); err != nil {
					return -1, err
				}
				return row, nil
			}
			for block := 0; block < replayBlockCount; block++ {
				row, err := assignOther(makeRowFromHead(mSigmaHatHeads[block]))
				if err != nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay M-hat-sigma block %d: %w", block, err)
				}
				replayMHatSigmaRows[block] = row
				if aggregateR0Replay {
					row, err = assignOther(makeRowFromHead(r0B2HatHeads[block]))
					if err != nil {
						return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay R0-B2-hat block %d: %w", block, err)
					}
					replayR0B2HatRows = append(replayR0B2HatRows, row)
				} else {
					for i := range r0HatHeads {
						row, err = assignOther(makeRowFromHead(r0HatHeads[i][block]))
						if err != nil {
							return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay R-hat0[%d] block %d: %w", i, block, err)
						}
						replayRHat0Rows = append(replayRHat0Rows, row)
					}
				}
				row, err = assignOther(makeRowFromHead(r1HatHeads[block]))
				if err != nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay R-hat1 block %d: %w", block, err)
				}
				replayRHat1Rows[block] = row
				if useBBTran {
					row, err = assignOther(makeRowFromHead(zHatHeads[block]))
					if err != nil {
						return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay Z-hat block %d: %w", block, err)
					}
					replayZHatRows[block] = row
				}
				replayTHatRows[block] = tHatPlanRows[block]
				if err := assignReplayRow(replayTHatRows[block], makeRowFromHead(tHatHeads[block])); err != nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay T-hat block %d: %w", block, err)
				}
			}
			if otherPos != len(otherPlanRows) {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("packed %d non-T-hat replay rows want %d", otherPos, len(otherPlanRows))
			}
			for i, row := range replayRowsPacked {
				if row == nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("missing packed replay row at window offset %d", i)
				}
			}
			rows = append(rows, replayRowsPacked...)
			packedFullReplay = true
		}
	}
	if !packedFullReplay {
		for block := 0; block < replayBlockCount; block++ {
			if useDirectTargetReplay {
				replayTargetMR0HatRows = append(replayTargetMR0HatRows, len(rows))
				if useTargetMR0HatReplay {
					rows = append(rows, makeRowFromHead(targetMR0HatHeads[block]))
				} else {
					replayTargetMR0HatRows = replayTargetMR0HatRows[:len(replayTargetMR0HatRows)-1]
				}
				if useRHat1Replay {
					replayRHat1Rows[block] = len(rows)
					rows = append(rows, makeRowFromHead(r1HatHeads[block]))
				}
				if useZHatReplay {
					replayZHatRows[block] = len(rows)
					rows = append(rows, makeRowFromHead(zHatHeads[block]))
				}
				continue
			}
			replayMHatSigmaRows[block] = len(rows)
			rows = append(rows, makeRowFromHead(mSigmaHatHeads[block]))
			if aggregateR0Replay {
				replayR0B2HatRows = append(replayR0B2HatRows, len(rows))
				rows = append(rows, makeRowFromHead(r0B2HatHeads[block]))
			} else {
				for i := range r0HatHeads {
					replayRHat0Rows = append(replayRHat0Rows, len(rows))
					rows = append(rows, makeRowFromHead(r0HatHeads[i][block]))
				}
			}
			if useRHat1Replay {
				replayRHat1Rows[block] = len(rows)
				rows = append(rows, makeRowFromHead(r1HatHeads[block]))
			}
			if useZHatReplay {
				replayZHatRows[block] = len(rows)
				rows = append(rows, makeRowFromHead(zHatHeads[block]))
			}
			replayTHatRows[block] = len(rows)
			rows = append(rows, makeRowFromHead(tHatHeads[block]))
		}
	}

	packedSigBase := -1
	packedSigCount := 0

	packedSigChainBase := -1
	packedSigChainGroupCount := 0
	packedSigChainGroupSize := 0
	packedSigChainRowsPerGroup := 0
	packedSigChainBlockWidth := 0
	packedSigChainEffectiveBlocks := 0
	packedSigChainSourceBlockWidth := ncols
	pairLookupExtractBase := -1
	pairLookupExtractGroupCount := 0
	pairLookupExtractRowsPerLane := 0
	pairLookupRangeLoWidth := 0
	pairLookupRangeHiWidth := 0
	pairLookupBase := 0
	coeffLookupBase := -1
	coeffLookupRowCount := 0
	coeffLookupComponents := 0
	coeffLookupBlocks := 0
	coeffLookupBlockWidth := 0
	coeffLookupBeta := 0
	coeffLookupTableSize := 0
	sigSignedChain := false
	if useInlinedShortness {
		groupSize := opts.PackedSigChainGroupSize
		if groupSize <= 0 {
			groupSize = aggregateInlineTargetReplayCompactGroupSize
		}
		rowsPerGroup, err := signaturePackedChainRowsPerGroupForOpts(spec, opts, groupSize)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature shortness rows/group: %w", err)
		}
		packedSigChainBase = len(rows)
		effectiveBlocks := blocks
		sigBlockWidth := ncols
		packedSigChainGroupCount = len(cn.Sig) * effectiveBlocks
		packedSigChainGroupSize = groupSize
		packedSigChainRowsPerGroup = rowsPerGroup
		packedSigChainBlockWidth = sigBlockWidth
		packedSigChainEffectiveBlocks = effectiveBlocks
		packedSigChainSourceBlockWidth = ncols
		sigSignedChain = spec.UsesAbsRow
		for groupBlock := 0; groupBlock < effectiveBlocks; groupBlock++ {
			for comp := 0; comp < len(cn.Sig); comp++ {
				for lane := 0; lane < spec.L; lane++ {
					groupedHead := make([]uint64, sigBlockWidth)
					for sub := 0; sub < groupSize; sub++ {
						block := groupBlock*groupSize + sub
						if comp >= len(packedWitness.SigLimbs) || block >= len(packedWitness.SigLimbs[comp]) {
							return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("missing packed shortness limbs for comp=%d block=%d", comp, block)
						}
						if len(packedWitness.SigLimbs[comp][block]) != spec.L {
							return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("packed shortness limb rows=%d want %d for comp=%d block=%d", len(packedWitness.SigLimbs[comp][block]), spec.L, comp, block)
						}
						if packedWitness.SigLimbs[comp][block][lane] == nil {
							return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("nil packed shortness limb for comp=%d block=%d lane=%d", comp, block, lane)
						}
						if comp >= len(packedWitness.SigLimbHeads) || block >= len(packedWitness.SigLimbHeads[comp]) || lane >= len(packedWitness.SigLimbHeads[comp][block]) {
							return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("missing packed shortness limb heads for comp=%d block=%d lane=%d", comp, block, lane)
						}
						head := packedWitness.SigLimbHeads[comp][block][lane]
						if len(head) != ncols {
							return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("packed shortness limb head width=%d want %d for comp=%d block=%d lane=%d", len(head), ncols, comp, block, lane)
						}
						copy(groupedHead[sub*ncols:(sub+1)*ncols], head)
					}
					rows = append(rows, makeRowFromHead(groupedHead))
				}
			}
		}
	}

	if !useV18Shortness {
		startIdx = len(rows)
		if err := appendPRFCompanionRows(false); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}
	if prfCompanionLayout != nil && len(prfCompanionLayout.KeySourceSlots) == 0 && keySourceBlock >= 0 {
		prfCompanionLayout.KeySourceSlots = make([]CoeffSlot, prfParamsLenKey)
		for i := 0; i < prfParamsLenKey; i++ {
			if muPackWidth == 1 {
				if keySourceBlock >= len(aliasMuBlockRows) {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("key source block=%d outside alias mu blocks=%d", keySourceBlock, len(aliasMuBlockRows))
				}
				prfCompanionLayout.KeySourceSlots[i] = CoeffSlot{Row: aliasMuBlockRows[keySourceBlock], Coeff: keySourceColStart + i}
			} else {
				prfCompanionLayout.KeySourceSlots[i] = CoeffSlot{Row: carrierMuBlockRows[keySourcePackedRow], Coeff: keySourceColStart + i}
			}
		}
		if muPackWidth > 1 {
			prfCompanionLayout.KeySourceDecodeLanes = make([]int, prfParamsLenKey)
			for i := range prfCompanionLayout.KeySourceDecodeLanes {
				prfCompanionLayout.KeySourceDecodeLanes[i] = keySourceLane
			}
		}
	}

	layout.HasExplicitBaseIdx = true
	layout.RingDegree = int(ringQ.N)
	layout.X0Len = len(cn.R0)
	if muPackWidth > 1 {
		layout.IdxMu = idxCarrierM
	} else {
		layout.IdxMu = idxM1
	}
	layout.IdxM1 = idxM1
	layout.IdxM2 = idxM2
	layout.IdxRU0 = -1
	layout.IdxRU1 = -1
	layout.IdxR = -1
	layout.IdxR0 = firstIndex(aliasR0Rows)
	layout.IdxR1 = idxR1
	layout.IdxK0 = -1
	layout.IdxK1 = -1
	layout.IdxZ = idxZ
	layout.IdxCarrierM = idxCarrierM
	layout.CarrierMuBlockRows = append([]int(nil), carrierMuBlockRows...)
	layout.AliasMuBlockRows = append([]int(nil), aliasMuBlockRows...)
	layout.MuCarrierPackWidth = muPackWidth
	layout.MuVirtualBlockCount = len(muHeads)
	layout.IdxCarrierCtr = firstIndex(carrierR0Rows)
	layout.IdxCarrierR1 = idxCarrierR1
	layout.CarrierR0Rows = append([]int(nil), carrierR0Rows...)
	layout.AliasR0Rows = append([]int(nil), aliasR0Rows...)
	layout.IdxTSource = -1
	layout.IdxSigHatBase = -1
	layout.SigHatExtraBase = -1
	layout.IdxTargetMR0Hat = -1
	layout.ReplayTargetMR0HatRows = nil
	if useDirectTargetReplay {
		layout.IdxTHatBase = -1
		layout.ReplayTHatRows = nil
		if useTargetMR0HatReplay {
			layout.IdxTargetMR0Hat = firstIndex(replayTargetMR0HatRows)
			layout.ReplayTargetMR0HatRows = append([]int(nil), replayTargetMR0HatRows...)
		}
	} else {
		layout.IdxTHatBase = replayTHatRows[0]
		layout.ReplayTHatRows = append([]int(nil), replayTHatRows...)
	}
	layout.ReplayTHatCount = replayTHatCount
	layout.ReplayBlockCount = replayBlockCount
	if useDirectTargetReplay {
		layout.IdxMHatSigma = -1
		layout.ReplayMHatSigmaRows = nil
	} else {
		layout.IdxMHatSigma = replayMHatSigmaRows[0]
		layout.ReplayMHatSigmaRows = append([]int(nil), replayMHatSigmaRows...)
	}
	layout.IdxMHat1 = -1
	layout.IdxMHat2 = -1
	if useDirectTargetReplay {
		layout.IdxRHat0 = -1
		layout.ReplayRHat0Rows = nil
		layout.IdxR0B2Hat = -1
		layout.ReplayR0B2HatRows = nil
	} else if aggregateR0Replay {
		layout.IdxRHat0 = -1
		layout.ReplayRHat0Rows = nil
		layout.IdxR0B2Hat = firstIndex(replayR0B2HatRows)
		layout.ReplayR0B2HatRows = append([]int(nil), replayR0B2HatRows...)
	} else {
		layout.IdxRHat0 = firstIndex(replayRHat0Rows)
		layout.ReplayRHat0Rows = append([]int(nil), replayRHat0Rows...)
		layout.IdxR0B2Hat = -1
		layout.ReplayR0B2HatRows = nil
	}
	if useRHat1Replay {
		layout.IdxRHat1 = replayRHat1Rows[0]
		layout.ReplayRHat1Rows = append([]int(nil), replayRHat1Rows...)
	} else {
		layout.IdxRHat1 = -1
		layout.ReplayRHat1Rows = nil
	}
	layout.IdxMSigmaR1 = -1
	layout.IdxR0R1 = -1
	layout.IdxMSigmaR1Alias = -1
	layout.IdxR0R1Alias = -1
	if useZHatReplay {
		layout.IdxZHat = replayZHatRows[0]
		layout.ReplayZHatRows = append([]int(nil), replayZHatRows...)
		layout.IdxMSigmaR1Hat = -1
		layout.IdxR0R1Hat = -1
	} else {
		layout.IdxZHat = -1
		layout.IdxMSigmaR1Hat = -1
		layout.IdxR0R1Hat = -1
	}
	layout.SigBlocks = blocks
	layout.SigUCount = 0
	layout.SigCoeffBase = -1
	layout.ChainBase = -1
	layout.ChainRowsPerSig = 0
	layout.PackedSigChainBase = packedSigChainBase
	layout.PackedSigChainGroupCount = packedSigChainGroupCount
	layout.PackedSigChainGroupSize = packedSigChainGroupSize
	layout.PackedSigChainRowsPerGroup = packedSigChainRowsPerGroup
	layout.PackedSigChainBlockWidth = packedSigChainBlockWidth
	layout.PackedSigChainEffectiveBlocks = packedSigChainEffectiveBlocks
	layout.PackedSigChainSourceBlockWidth = packedSigChainSourceBlockWidth
	layout.PairLookupExtractBase = pairLookupExtractBase
	layout.PairLookupExtractGroupCount = pairLookupExtractGroupCount
	layout.PairLookupExtractRowsPerLane = pairLookupExtractRowsPerLane
	layout.PairLookupRangeLoWidth = pairLookupRangeLoWidth
	layout.PairLookupRangeHiWidth = pairLookupRangeHiWidth
	layout.PairLookupBase = pairLookupBase
	layout.CoeffLookupBase = coeffLookupBase
	layout.CoeffLookupRowCount = coeffLookupRowCount
	layout.CoeffLookupComponents = coeffLookupComponents
	layout.CoeffLookupBlocks = coeffLookupBlocks
	layout.CoeffLookupBlockWidth = coeffLookupBlockWidth
	layout.CoeffLookupBeta = coeffLookupBeta
	layout.CoeffLookupTableSize = coeffLookupTableSize
	layout.SigSignedChain = sigSignedChain
	layout.SigShortnessV9RandBase = -1
	layout.SigShortnessV9RandCount = 0
	layout.SigShortnessV9RandBound = 0
	layout.MsgChainBase = -1
	layout.RndChainBase = -1
	layout.MsgRangeBase = -1
	layout.RndRangeBase = -1
	layout.X1RangeBase = -1
	layout.NonSigBoundRowsPer = 0
	layout.SigPrimaryLimbRows = packedSigChainGroupCount * packedSigChainRowsPerGroup
	layout.ScalarBundleRows = 0
	layout.SigBoundSliceRows = packedSigChainGroupCount * packedSigChainRowsPerGroup
	layout.PostSignScalarProjectionRows = 0
	layout.PostSignScalarCertificateRows = 0
	layout.PRFScalarBundleRows = len(rows) - startIdx
	layout.PRFGroupedNonlinearRows = 0
	layout.SigCount = len(rows)
	layout.NonSigBlocks = blocks
	layout.MsgCompCount = 0
	layout.MsgExtraNTTBase = -1
	layout.MsgCoeffBase = -1
	layout.RndCompCount = 0
	layout.RndExtraNTTBase = -1
	layout.RndCoeffBase = -1
	layout.X1CompCount = 0
	layout.X1ExtraNTTBase = -1
	layout.X1CoeffBase = -1
	layout.CoeffNativeSig = CoeffNativeSigLayout{
		Enabled:             true,
		Model:               model,
		SigBase:             -1,
		SigCount:            0,
		SigBlocks:           blocks,
		SigUCount:           0,
		SigComponentCount:   len(cn.Sig),
		SigCoeffCount:       int(ringQ.N),
		OutputBlocks:        blocks,
		OutputBlockWidth:    ncols,
		W1SigBase:           -1,
		W1SigCount:          0,
		PackedSigBase:       packedSigBase,
		PackedSigCount:      packedSigCount,
		PackedSigBlocks:     blocks,
		PackedSigComponents: len(cn.Sig),
		PackedSigBlockWidth: ncols,
		ScalarBundleBase:    -1,
		ScalarBundleCount:   0,
	}
	if prfCompanionLayout == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("missing PRF companion layout")
	}
	prfScalarBundleRows := prfCompanionLayout.PackedRows
	layout.PRFScalarBundleRows = prfScalarBundleRows
	layout.SigCount = len(rows)

	if !useInlinedShortness {
		layout.PackedSigChainBase = -1
		layout.PackedSigChainGroupCount = 0
		layout.PackedSigChainGroupSize = 0
		layout.PackedSigChainRowsPerGroup = 0
		layout.PackedSigChainBlockWidth = 0
		layout.PackedSigChainEffectiveBlocks = 0
		layout.PackedSigChainSourceBlockWidth = 0
		layout.PairLookupExtractBase = -1
		layout.PairLookupExtractGroupCount = 0
		layout.PairLookupExtractRowsPerLane = 0
		layout.PairLookupRangeLoWidth = 0
		layout.PairLookupRangeHiWidth = 0
		layout.PairLookupBase = 0
		layout.SigSignedChain = false
		layout.SigPrimaryLimbRows = 0
		layout.SigBoundSliceRows = 0
	}

	witnessCount = len(rows)
	if opts.DomainMode == DomainModeExplicit {
		if len(explicitOmega) == 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("explicit omega missing for row inputs")
		}
		var rerr error
		rowInputs, rerr = buildRowInputsExplicit(ringQ, rows, explicitOmega, ncols)
		if rerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, rerr
		}
	} else {
		rowInputs = buildRowInputs(ringQ, rows, ncols)
	}
	maskRowOffset = len(rows)
	maskRowCount = opts.Rho
	if maskRowCount > 0 {
		zeroHead := make([]uint64, ncols)
		for i := 0; i < maskRowCount; i++ {
			rows = append(rows, ringQ.NewPoly())
			rowInputs = append(rowInputs, lvcs.RowInput{Head: zeroHead})
		}
	}
	maxDegree := opts.DQOverride
	if maxDegree <= 0 {
		maxDegree = ncols + opts.Ell - 1
	}
	decsParams = decs.Params{Degree: maxDegree, Eta: opts.Eta, NonceBytes: 16}
	return rows, rowInputs, layout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols, nil
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
	shortSet, err := buildSigShortnessV7ConstraintSet(ringQ, layout, pub, omega, rowsNTT, opts)
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
	if normalizePRFCompanionMode(opts.PRFCompanionMode) == PRFCompanionModeAuxInstance && prfCompanionLayout != nil && prfCompanionLayout.BridgeStripe != nil {
		eqFamilies, eqCoeffs, err := buildPRFBridgeStripeEqualityConstraints(ringQ, rowsNTT, prfCompanionLayout)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("prf bridge stripe equality constraints: %w", err)
		}
		baseSet.FparNorm = append(baseSet.FparNorm, eqFamilies...)
		baseSet.FparNormCoeffs = append(baseSet.FparNormCoeffs, eqCoeffs...)
		if len(eqFamilies) > 0 && baseSet.ParallelAlgDeg < 1 {
			baseSet.ParallelAlgDeg = 1
		}
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
