package PIOP

import (
	"fmt"
	"path/filepath"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/internal/fpoly"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type literalPackedPolyWitness struct {
	Sig          [][]*ring.Poly
	SigHeads     [][][]uint64
	SigLimbs     [][][]*ring.Poly
	SigLimbHeads [][][][]uint64
}

var fullReplayTHatStripeSlots = []int{26, 27, 28, 29, 30, 31}

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
	stripe := make(map[int]struct{}, len(fullReplayTHatStripeSlots))
	for _, slot := range fullReplayTHatStripeSlots {
		if slot < 0 || slot >= pcsNCols {
			return nil, nil, fmt.Errorf("T-hat stripe slot %d out of range for pcs ncols %d", slot, pcsNCols)
		}
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
	basis, err := newTransformBridgeBasisCache(ringQ, omega, replayBlockCount*ncols, 1)
	if err != nil {
		return nil, fmt.Errorf("transform basis for %s: %w", name, err)
	}
	srcHead, err := rowHeadOnOmega(ringQ, omega, sourcePoly, ncols)
	if err != nil {
		return nil, fmt.Errorf("source head for %s: %w", name, err)
	}
	q := ringQ.Modulus[0]
	out := make([][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
		head := make([]uint64, ncols)
		for j := 0; j < ncols; j++ {
			t := block*ncols + j
			acc := uint64(0)
			for k := 0; k < ncols; k++ {
				weight := EvalPoly(basis.TransformH[t], omega[k]%q, q) % q
				acc = modAdd(acc, modMul(weight, srcHead[k]%q, q), q)
			}
			head[j] = acc
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
	basis, err := newTransformBridgeBasisCache(ringQ, omega, replayBlockCount*ncols, len(sourceRows))
	if err != nil {
		return nil, fmt.Errorf("transform basis for %s: %w", name, err)
	}
	srcHeads := make([][]uint64, len(sourceRows))
	for i := range sourceRows {
		head, herr := rowHeadOnOmega(ringQ, omega, sourceRows[i], ncols)
		if herr != nil {
			return nil, fmt.Errorf("source head %s[%d]: %w", name, i, herr)
		}
		srcHeads[i] = head
	}
	q := ringQ.Modulus[0]
	out := make([][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
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
				for k := 0; k < ncols; k++ {
					weight := EvalPoly(basis.TransformH[t], omega[k]%q, q) % q
					inner = modAdd(inner, modMul(weight, srcHeads[srcBlock][k]%q, q), q)
				}
				acc = modAdd(acc, modMul(blockScale, inner, q), q)
			}
			head[j] = acc
		}
		out[block] = head
	}
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
	replayBlocks := rowLayoutReplayBlockCount(layout)
	if replayBlocks <= 0 {
		replayBlocks = 1
	}
	for _, idx := range []int{
		rowLayoutPostSignMHatSigma(layout),
		rowLayoutPostSignRHat0(layout),
		rowLayoutPostSignRHat1(layout),
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
		rowLayoutPostSignRHat1Rows(layout),
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
	if cn.PackedNCols != ncols {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native packed ncols=%d want %d", cn.PackedNCols, ncols)
	}

	spec, serr := signatureChainSpecForOpts(ringQ.Modulus[0], opts)
	if serr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature chain spec: %w", serr)
	}
	if !signatureSpecNoWrapOK(spec) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature chain spec violates no-wrap bound: maxAbs=%d q=%d", spec.MaxAbs, spec.Q)
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
		for _, pair := range []struct {
			poly *ring.Poly
			name string
		}{
			{poly: cn.M1, name: "M1"},
			{poly: cn.M2, name: "M2"},
			{poly: cn.R0, name: "R0"},
			{poly: cn.R1, name: "R1"},
		} {
			if err := validateSparseSupportTailZero(pair.poly, ncols, q, pair.name); err != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
			}
		}
	}
	var m1Head []uint64
	var berr error
	if opts.DomainMode == DomainModeExplicit {
		if len(cn.M1.Coeffs) == 0 || len(cn.M1.Coeffs[0]) < ncols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M1 head width=%d want >=%d", len(cn.M1.Coeffs[0]), ncols)
		}
		m1Head = append([]uint64(nil), cn.M1.Coeffs[0][:ncols]...)
		for i := range m1Head {
			m1Head[i] %= q
		}
	} else {
		m1Head, berr = nttHead(cn.M1)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M1 head: %w", berr)
	}
	var m2Head []uint64
	if opts.DomainMode == DomainModeExplicit {
		if len(cn.M2.Coeffs) == 0 || len(cn.M2.Coeffs[0]) < ncols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M2 head width=%d want >=%d", len(cn.M2.Coeffs[0]), ncols)
		}
		m2Head = append([]uint64(nil), cn.M2.Coeffs[0][:ncols]...)
		for i := range m2Head {
			m2Head[i] %= q
		}
	} else {
		m2Head, berr = nttHead(cn.M2)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M2 head: %w", berr)
	}
	var r0Head []uint64
	if opts.DomainMode == DomainModeExplicit {
		if len(cn.R0.Coeffs) == 0 || len(cn.R0.Coeffs[0]) < ncols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0 head width=%d want >=%d", len(cn.R0.Coeffs[0]), ncols)
		}
		r0Head = append([]uint64(nil), cn.R0.Coeffs[0][:ncols]...)
		for i := range r0Head {
			r0Head[i] %= q
		}
	} else {
		r0Head, berr = nttHead(cn.R0)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0 head: %w", berr)
	}
	var r1Head []uint64
	if opts.DomainMode == DomainModeExplicit {
		if len(cn.R1.Coeffs) == 0 || len(cn.R1.Coeffs[0]) < ncols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R1 head width=%d want >=%d", len(cn.R1.Coeffs[0]), ncols)
		}
		r1Head = append([]uint64(nil), cn.R1.Coeffs[0][:ncols]...)
		for i := range r1Head {
			r1Head[i] %= q
		}
	} else {
		r1Head, berr = nttHead(cn.R1)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R1 head: %w", berr)
	}
	carrierMHead := make([]uint64, ncols)
	carrierCtrHead := make([]uint64, ncols)
	for col := 0; col < ncols; col++ {
		m1 := centeredLift(m1Head[col], q)
		m2 := centeredLift(m2Head[col], q)
		code, err := encodePackedMessageCarrier(m1, m2, pub.BoundB)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("encode carrier M col=%d: %w", col, err)
		}
		carrierMHead[col] = liftToField(q, int64(code))
		r0 := centeredLift(r0Head[col], q)
		r1 := centeredLift(r1Head[col], q)
		code, err = encodeCarrierPair(r0, r1, pub.BoundB)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("encode carrier ctr col=%d: %w", col, err)
		}
		carrierCtrHead[col] = liftToField(q, int64(code))
	}
	idxCarrierM := len(rows)
	rows = append(rows, makeRowFromHead(carrierMHead))
	idxCarrierCtr := len(rows)
	rows = append(rows, makeRowFromHead(carrierCtrHead))

	msgDecode1, msgDecode2, derr := buildPackedMessageCarrierDecodePolys(pub.BoundB, q)
	if derr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("message carrier decode polys: %w", derr)
	}
	ctrDecode1, ctrDecode2, derr := buildCarrierDecodePolys(pub.BoundB, q)
	if derr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("carrier decode polys: %w", derr)
	}
	carrierMPoly := fpoly.New(q, trimPoly(append([]uint64(nil), rows[idxCarrierM].Coeffs[0]...), q))
	carrierCtrPoly := fpoly.New(q, trimPoly(append([]uint64(nil), rows[idxCarrierCtr].Coeffs[0]...), q))
	m1CanonCoeff := trimPoly(fpoly.New(q, msgDecode1).Compose(carrierMPoly).Coeffs, q)
	m2CanonCoeff := trimPoly(fpoly.New(q, msgDecode2).Compose(carrierMPoly).Coeffs, q)
	r0CanonCoeff := trimPoly(fpoly.New(q, ctrDecode1).Compose(carrierCtrPoly).Coeffs, q)
	r1CanonCoeff := trimPoly(fpoly.New(q, ctrDecode2).Compose(carrierCtrPoly).Coeffs, q)
	rawAliasSurface, derr := DerivePreSignCarrierAndAliasRows(
		ringQ,
		pub.BoundB,
		explicitOmega,
		DomainModeExplicit,
		PreSignRawRows{
			M1: cn.M1,
			M2: cn.M2,
			R0: cn.R0,
			R1: cn.R1,
		},
	)
	if derr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("derive showing raw alias surface: %w", derr)
	}

	useBBTran := publicUsesBBTran(pub)
	idxMSigmaR1 := -1
	idxR0R1 := -1
	var mSigmaR1SourcePoly, r0R1SourcePoly *ring.Poly
	if useBBTran {
		mSigmaR1Coeff, r0R1Coeff, derr := buildBBTranProductInterpCoeffs(q, explicitOmega, m1CanonCoeff, m2CanonCoeff, r0CanonCoeff, r1CanonCoeff)
		if derr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, derr
		}
		mSigmaR1SourcePoly, derr = coeffPolyFromFormalCoeffs(ringQ, mSigmaR1Coeff, "showing canonical MSigmaR1")
		if derr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, derr
		}
		r0R1SourcePoly, derr = coeffPolyFromFormalCoeffs(ringQ, r0R1Coeff, "showing canonical R0R1")
		if derr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, derr
		}
		idxMSigmaR1 = len(rows)
		rows = append(rows, mSigmaR1SourcePoly)
		idxR0R1 = len(rows)
		rows = append(rows, r0R1SourcePoly)
	}

	mHat1Heads, berr := buildReplayHeadsFromSourcePoly(ringQ, rawAliasSurface.AliasRows[PreSignAliasM1], explicitOmega, replayBlockCount, "M hat 1")
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M hat1: %w", berr)
	}
	mHat2Heads, berr := buildReplayHeadsFromSourcePoly(ringQ, rawAliasSurface.AliasRows[PreSignAliasM2], explicitOmega, replayBlockCount, "M hat 2")
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M hat2: %w", berr)
	}
	mSigmaHatHeads := make([][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
		mSigmaHatHeads[block] = make([]uint64, ncols)
		for col := 0; col < ncols; col++ {
			mSigmaHatHeads[block][col] = modAdd(mHat1Heads[block][col]%q, mHat2Heads[block][col]%q, q)
		}
	}
	r0HatHeads, berr := buildReplayHeadsFromSourcePoly(ringQ, rawAliasSurface.AliasRows[PreSignAliasR0], explicitOmega, replayBlockCount, "R0")
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0 hats: %w", berr)
	}
	r1HatHeads, berr := buildReplayHeadsFromSourcePoly(ringQ, rawAliasSurface.AliasRows[PreSignAliasR1], explicitOmega, replayBlockCount, "R1")
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R1 hats: %w", berr)
	}
	var mSigmaR1HatHeads, r0R1HatHeads [][]uint64
	if useBBTran {
		mSigmaR1HatHeads, derr = buildReplayHeadsFromSourcePoly(ringQ, mSigmaR1SourcePoly, explicitOmega, replayBlockCount, "MSigmaR1")
		if derr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native MSigmaR1 hats: %w", derr)
		}
		r0R1HatHeads, derr = buildReplayHeadsFromSourcePoly(ringQ, r0R1SourcePoly, explicitOmega, replayBlockCount, "R0R1")
		if derr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0R1 hats: %w", derr)
		}
	}

	replayTHatCount := replayBlockCount
	sigHatHeads, terr := buildSigHatHeadsFromPackedSigHeads(ringQ, packedWitness.SigHeads, ncols)
	if terr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("build sig hats from packed heads: %w", terr)
	}
	tHatHeads, terr := buildTHatHeadsFromSigHatHeads(ringQ, pub, explicitOmega, sigHatHeads, replayTHatCount, blocks)
	if terr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("build T replay heads from signature hats: %w", terr)
	}
	replayMHatSigmaRows := make([]int, replayBlockCount)
	replayRHat0Rows := make([]int, replayBlockCount)
	replayRHat1Rows := make([]int, replayBlockCount)
	replayMSigmaR1HatRows := make([]int, replayBlockCount)
	replayR0R1HatRows := make([]int, replayBlockCount)
	replayTHatRows := make([]int, replayTHatCount)
	packedFullReplay := false
	if opts.ShowingReplayMode == ShowingReplayModeFull && replayBlockCount > 1 {
		replayRowsPerBlock := 4
		if useBBTran {
			replayRowsPerBlock += 2
		}
		replayWindowStart := len(rows)
		replayWindowRows := replayBlockCount * replayRowsPerBlock
		pcsNCols := opts.PostSignLVCSNCols
		if pcsNCols <= 0 {
			pcsNCols = resolvePCSNCols(opts, ncols)
		}
		tHatPlanRows, otherPlanRows, planErr := planFullReplayTHatRows(replayWindowStart, replayWindowRows, pcsNCols, replayTHatCount)
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
				row, err = assignOther(makeRowFromHead(r0HatHeads[block]))
				if err != nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay R-hat0 block %d: %w", block, err)
				}
				replayRHat0Rows[block] = row
				row, err = assignOther(makeRowFromHead(r1HatHeads[block]))
				if err != nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay R-hat1 block %d: %w", block, err)
				}
				replayRHat1Rows[block] = row
				if useBBTran {
					row, err = assignOther(makeRowFromHead(mSigmaR1HatHeads[block]))
					if err != nil {
						return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay MSigmaR1-hat block %d: %w", block, err)
					}
					replayMSigmaR1HatRows[block] = row
					row, err = assignOther(makeRowFromHead(r0R1HatHeads[block]))
					if err != nil {
						return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack full replay R0R1-hat block %d: %w", block, err)
					}
					replayR0R1HatRows[block] = row
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
			replayMHatSigmaRows[block] = len(rows)
			rows = append(rows, makeRowFromHead(mSigmaHatHeads[block]))
			replayRHat0Rows[block] = len(rows)
			rows = append(rows, makeRowFromHead(r0HatHeads[block]))
			replayRHat1Rows[block] = len(rows)
			rows = append(rows, makeRowFromHead(r1HatHeads[block]))
			if useBBTran {
				replayMSigmaR1HatRows[block] = len(rows)
				rows = append(rows, makeRowFromHead(mSigmaR1HatHeads[block]))
				replayR0R1HatRows[block] = len(rows)
				rows = append(rows, makeRowFromHead(r0R1HatHeads[block]))
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
	sigSignedChain := false

	if prfGroupRounds <= 0 {
		prfGroupRounds = 1
	}
	var keyScalars []int64
	if opts.DomainMode == DomainModeExplicit {
		if len(explicitOmega) == 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("explicit omega missing for carrier key extraction")
		}
		keyScalars, err = ExtractSignedPRFKeyScalarsFromCarrierOnOmega(ringQ, rows[idxCarrierM], explicitOmega, cn.PackedNCols, prfParamsLenKey, pub.BoundB)
	} else {
		keyScalars, err = ExtractSignedPRFKeyScalarsFromCarrier(ringQ, rows[idxCarrierM], cn.PackedNCols, prfParamsLenKey, pub.BoundB)
	}
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("extract signed prf key: %w", err)
	}
	startIdx = len(rows)
	companionMode := normalizePRFCompanionMode(opts.PRFCompanionMode)
	if companionMode == "" {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("showing requires PRF companion mode")
	}

	layout.HasExplicitBaseIdx = true
	layout.IdxM1 = -1
	layout.IdxM2 = -1
	layout.IdxRU0 = -1
	layout.IdxRU1 = -1
	layout.IdxR = -1
	layout.IdxR0 = -1
	layout.IdxR1 = -1
	layout.IdxK0 = -1
	layout.IdxK1 = -1
	layout.IdxCarrierM = idxCarrierM
	layout.IdxCarrierCtr = idxCarrierCtr
	layout.IdxTSource = -1
	layout.IdxSigHatBase = -1
	layout.SigHatExtraBase = -1
	layout.IdxTHatBase = replayTHatRows[0]
	layout.ReplayTHatRows = append([]int(nil), replayTHatRows...)
	layout.ReplayTHatCount = replayTHatCount
	layout.ReplayBlockCount = replayBlockCount
	layout.IdxMHatSigma = replayMHatSigmaRows[0]
	layout.ReplayMHatSigmaRows = append([]int(nil), replayMHatSigmaRows...)
	layout.IdxMHat1 = -1
	layout.IdxMHat2 = -1
	layout.IdxRHat0 = replayRHat0Rows[0]
	layout.ReplayRHat0Rows = append([]int(nil), replayRHat0Rows...)
	layout.IdxRHat1 = replayRHat1Rows[0]
	layout.ReplayRHat1Rows = append([]int(nil), replayRHat1Rows...)
	layout.IdxMSigmaR1 = idxMSigmaR1
	layout.IdxR0R1 = idxR0R1
	if useBBTran {
		layout.IdxMSigmaR1Hat = replayMSigmaR1HatRows[0]
		layout.ReplayMSigmaR1HatRows = append([]int(nil), replayMSigmaR1HatRows...)
		layout.IdxR0R1Hat = replayR0R1HatRows[0]
		layout.ReplayR0R1HatRows = append([]int(nil), replayR0R1HatRows...)
	} else {
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
	layout.SigSignedChain = sigSignedChain
	layout.MsgChainBase = -1
	layout.RndChainBase = -1
	layout.MsgRangeBase = -1
	layout.RndRangeBase = -1
	layout.X1RangeBase = -1
	layout.NonSigBoundRowsPer = 0
	layout.SigPrimaryLimbRows = 0
	layout.ScalarBundleRows = 0
	layout.SigBoundSliceRows = 0
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
	if companionMode != "" {
		companionStart := len(rows)
		keyElems := make([]prf.Elem, len(keyScalars))
		for i := range keyScalars {
			keyElems[i] = prf.Elem(liftToField(ringQ.Modulus[0], keyScalars[i]))
		}
		nonceElems := make([]prf.Elem, len(pub.Nonce))
		for i := range pub.Nonce {
			if len(pub.Nonce[i]) == 0 {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("public nonce lane %d is empty", i)
			}
			nonceElems[i] = prf.Elem(liftToField(ringQ.Modulus[0], pub.Nonce[i][0]))
		}
		params, perr := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("load prf params for companion witness: %w", perr)
		}
		groupedWitness, gwerr := prf.TraceGroupedWitness(keyElems, nonceElems, params, prfGroupRounds)
		if gwerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("trace grouped prf witness: %w", gwerr)
		}
		packed, perr := packPRFCompanionWitnessRows(ringQ, ncols, companionStart, companionMode, keyElems, groupedWitness, makeRowFromHead)
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack prf companion rows: %w", perr)
		}
		rows = append(rows, packed.Rows...)
		if len(packed.KeySlots) == 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("prf companion missing key slots for independent-key showing")
		}
		rowSemantics := make([]RowSemantics, len(packed.Rows))
		for i := range rowSemantics {
			rowSemantics[i] = CoeffPackedRow
		}
		dataRows := ceilDiv(len(packed.KeySlots)+len(packed.CheckpointSlots), ncols)
		helperRows := maxInt(len(packed.Rows)-dataRows, 0)
		helperFamilies := []string{"final_tag_state"}
		prfCompanionLayout = &PRFCompanionLayout{
			StartRow:           companionStart,
			PackWidth:          ncols,
			KeySource:          KeySourceIndependentWitness,
			KeySlots:           packed.KeySlots,
			CheckpointSlots:    packed.CheckpointSlots,
			FinalTagSlots:      packed.FinalTagSlots,
			HelperFamilies:     helperFamilies,
			ReplayRows:         len(packed.Rows),
			PackedRows:         len(packed.Rows),
			PackedLogicalCount: packed.TotalLogicalScalars,
			HelperRowCount:     helperRows,
			DataRows:           dataRows,
			HelperRows:         helperRows,
			KeyCount:           len(packed.KeySlots),
			CheckpointCount:    len(packed.CheckpointSlots),
			TagCount:           len(pub.Tag),
			RowSemantics:       rowSemantics,
		}
		if companionMode == PRFCompanionModeAuxInstance {
			pcsNCols := resolvePCSNCols(opts, ncols)
			rows, err = appendPRFBridgeStripeRows(ringQ, rows, prfCompanionLayout, pcsNCols)
			if err != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("append prf bridge stripe rows: %w", err)
			}
		}
	}
	layout.PRFScalarBundleRows = len(rows) - startIdx
	layout.SigCount = len(rows)

	layout.PackedSigChainBase = -1
	layout.PackedSigChainGroupCount = 0
	layout.PackedSigChainGroupSize = 0
	layout.PackedSigChainRowsPerGroup = 0
	layout.SigSignedChain = false
	layout.SigBoundSliceRows = 0

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
	wantGroupCount := cfg.PackedSigComponents * cfg.PackedSigBlocks
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
		chainPolys, chainCoeffs, err = buildSigShortnessPackedMembershipFormalCoeffs(ringQ, packedSourceRows, packedRows, specSig)
	} else {
		chainPolys, chainCoeffs, err = buildSigShortnessPackedMembershipFormalCoeffs(ringQ, nil, packedRows, specSig)
	}
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("literal packed signature shortness: %w", err)
	}
	deg, err := signatureShortnessMaxDegree(specSig, opts)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("signature shortness degree: %w", err)
	}
	return ConstraintSet{
		FparNorm:       append([]*ring.Poly{}, chainPolys...),
		FparNormCoeffs: append([][]uint64{}, chainCoeffs...),
		ParallelAlgDeg: deg,
	}, nil
}
