package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/internal/fpoly"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type literalPackedPolyWitness struct {
	Sig           [][]*ring.Poly
	SigLimbs      [][][]*ring.Poly
	U             []*ring.Poly
	USum          *ring.Poly
	X0            []*ring.Poly
	X0Sum         *ring.Poly
	X1            *ring.Poly
	ScalarBundles []*ring.Poly
}

type literalPackedCompileContext struct {
	cfg               LiteralPackedPostSignConfig
	omega             []uint64
	sigCoeff          [][][]uint64
	sigLimbCoeff      [][][][]uint64
	uCoeff            [][]uint64
	uSumCoeff         []uint64
	x0Coeff           [][]uint64
	x0SumCoeff        []uint64
	x1Coeff           []uint64
	scalarBundleCoeff [][]uint64
	x1Slot            PRFSlot
}

type LiteralPackedPostSignConfig struct {
	Ring          *ring.Ring
	Layout        RowLayout
	SigSpec       LinfSpec
	Tables        *ShowingCoeffNativeTables
	B0ConstBlocks [][]uint64
	B0MsgBlocks   [][]uint64
	B0RndBlocks   [][]uint64
	LagrangeBasis [][]uint64
	OmegaPlan     *interpolationPlan
	DomainPoints  []uint64
}

func buildLiteralPackedPolyWitness(ringQ *ring.Ring, cn *CoeffNativeShowingWitness, omega []uint64, ncols int, model string) (*literalPackedPolyWitness, error) {
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
	sumScalars := func(vals []int64) uint64 {
		sum := int64(0)
		for _, v := range vals {
			sum += v
		}
		return liftToField(q, sum)
	}
	out := &literalPackedPolyWitness{
		Sig:      make([][]*ring.Poly, len(cn.Sig)),
		SigLimbs: make([][][]*ring.Poly, len(cn.Sig)),
	}
	spec, err := signatureChainSpecForOpts(q, SimOpts{CoeffNativeSigModel: model})
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	for comp := range cn.Sig {
		if cn.Sig[comp] == nil || len(cn.Sig[comp].Coeffs) == 0 || len(cn.Sig[comp].Coeffs[0]) < int(ringQ.N) {
			return nil, fmt.Errorf("signature component %d width=%d want ringN=%d", comp, len(cn.Sig[comp].Coeffs[0]), ringQ.N)
		}
		out.Sig[comp] = make([]*ring.Poly, blocks)
		out.SigLimbs[comp] = make([][]*ring.Poly, blocks)
		for block := 0; block < blocks; block++ {
			start := block * ncols
			end := start + ncols
			sigHead := append([]uint64(nil), cn.Sig[comp].Coeffs[0][start:end]...)
			for i := range sigHead {
				sigHead[i] %= q
			}
			out.SigLimbs[comp][block] = make([]*ring.Poly, spec.L)
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
				out.SigLimbs[comp][block][lane] = BuildThetaPrime(ringQ, limbHeads[lane], omega)
			}
		}
	}
	for _, v := range cn.U {
		out.U = append(out.U, BuildThetaPrime(ringQ, repeatFieldValue(liftToField(q, v), ncols), omega))
	}
	out.USum = BuildThetaPrime(ringQ, repeatFieldValue(sumScalars(cn.U), ncols), omega)
	for _, v := range cn.X0 {
		out.X0 = append(out.X0, BuildThetaPrime(ringQ, repeatFieldValue(liftToField(q, v), ncols), omega))
	}
	out.X0Sum = BuildThetaPrime(ringQ, repeatFieldValue(sumScalars(cn.X0), ncols), omega)
	out.X1 = BuildThetaPrime(ringQ, repeatFieldValue(liftToField(q, cn.X1), ncols), omega)
	return out, nil
}

func repeatFieldValue(v uint64, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func centeredLift(v, q uint64) int64 {
	out := int64(v % q)
	if out > int64(q)/2 {
		out -= int64(q)
	}
	return out
}

func evalHeadWithLagrange(head []uint64, lambdas []uint64, q uint64) uint64 {
	if len(head) == 0 || len(lambdas) == 0 {
		return 0
	}
	n := len(head)
	if len(lambdas) < n {
		n = len(lambdas)
	}
	acc := uint64(0)
	for i := 0; i < n; i++ {
		acc = modAdd(acc, modMul(head[i]%q, lambdas[i]%q, q), q)
	}
	return acc
}

func evalHeadWithLagrangeK(K *kf.Field, head []uint64, lambdas []kf.Elem) kf.Elem {
	if K == nil || len(head) == 0 || len(lambdas) == 0 {
		if K == nil {
			var zero kf.Elem
			return zero
		}
		return K.Zero()
	}
	n := len(head)
	if len(lambdas) < n {
		n = len(lambdas)
	}
	acc := K.Zero()
	q := K.Q
	for i := 0; i < n; i++ {
		addScaledBaseKElem(&acc, lambdas[i], head[i], q)
	}
	return acc
}

func addScaledBaseKElem(acc *kf.Elem, src kf.Elem, scalar, q uint64) {
	if acc == nil || q == 0 {
		return
	}
	scalar %= q
	if scalar == 0 {
		return
	}
	for i := range acc.Limb {
		acc.Limb[i] = modAdd(acc.Limb[i]%q, modMul(src.Limb[i]%q, scalar, q), q)
	}
}

func scaleKElemByBase(K *kf.Field, src kf.Elem, scalar uint64) kf.Elem {
	if K == nil {
		var zero kf.Elem
		return zero
	}
	out := K.Zero()
	K.MulBaseInto(&out, src, scalar)
	return out
}

func buildLiteralPackedCompileContext(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, wit *literalPackedPolyWitness, omega []uint64) (*literalPackedCompileContext, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if wit == nil {
		return nil, fmt.Errorf("nil literal packed witness")
	}
	cfg, err := buildLiteralPackedPostSignConfig(ringQ, pub, layout, omega, nil)
	if err != nil {
		return nil, err
	}
	q := ringQ.Modulus[0]
	toCoeff := func(p *ring.Poly) ([]uint64, error) {
		c, err := coeffFromNTTPoly(ringQ, p)
		if err != nil {
			return nil, err
		}
		return trimPoly(c, q), nil
	}
	ctx := &literalPackedCompileContext{
		cfg:          cfg,
		omega:        append([]uint64(nil), omega...),
		sigCoeff:     make([][][]uint64, len(wit.Sig)),
		sigLimbCoeff: make([][][][]uint64, len(wit.SigLimbs)),
		uCoeff:       make([][]uint64, len(wit.U)),
		x0Coeff:      make([][]uint64, len(wit.X0)),
		x1Slot:       layout.CoeffNativeSig.X1Slot,
	}
	for comp := range wit.Sig {
		ctx.sigCoeff[comp] = make([][]uint64, len(wit.Sig[comp]))
		for block := range wit.Sig[comp] {
			coeff, err := toCoeff(wit.Sig[comp][block])
			if err != nil {
				return nil, err
			}
			ctx.sigCoeff[comp][block] = coeff
		}
	}
	for comp := range wit.SigLimbs {
		if len(wit.SigLimbs[comp]) == 0 {
			continue
		}
		ctx.sigLimbCoeff[comp] = make([][][]uint64, len(wit.SigLimbs[comp]))
		for block := range wit.SigLimbs[comp] {
			ctx.sigLimbCoeff[comp][block] = make([][]uint64, len(wit.SigLimbs[comp][block]))
			for lane := range wit.SigLimbs[comp][block] {
				coeff, err := toCoeff(wit.SigLimbs[comp][block][lane])
				if err != nil {
					return nil, err
				}
				ctx.sigLimbCoeff[comp][block][lane] = coeff
			}
		}
	}
	for i := range wit.U {
		coeff, err := toCoeff(wit.U[i])
		if err != nil {
			return nil, err
		}
		ctx.uCoeff[i] = coeff
	}
	for i := range wit.X0 {
		coeff, err := toCoeff(wit.X0[i])
		if err != nil {
			return nil, err
		}
		ctx.x0Coeff[i] = coeff
	}
	if wit.USum != nil {
		coeff, err := toCoeff(wit.USum)
		if err != nil {
			return nil, err
		}
		ctx.uSumCoeff = coeff
	}
	if wit.X0Sum != nil {
		coeff, err := toCoeff(wit.X0Sum)
		if err != nil {
			return nil, err
		}
		ctx.x0SumCoeff = coeff
	}
	for i := range wit.ScalarBundles {
		coeff, err := toCoeff(wit.ScalarBundles[i])
		if err != nil {
			return nil, err
		}
		ctx.scalarBundleCoeff = append(ctx.scalarBundleCoeff, coeff)
	}
	if wit.X1 != nil {
		x1Coeff, err := toCoeff(wit.X1)
		if err != nil {
			return nil, err
		}
		ctx.x1Coeff = x1Coeff
	}
	return ctx, nil
}

func (ctx *literalPackedCompileContext) packedSigCoeff(comp, block int) ([]uint64, error) {
	if ctx == nil || ctx.cfg.Ring == nil {
		return nil, fmt.Errorf("nil literal packed compile context")
	}
	if comp < 0 || block < 0 {
		return nil, fmt.Errorf("negative packed sig index")
	}
	if comp < len(ctx.sigCoeff) && block < len(ctx.sigCoeff[comp]) && len(ctx.sigCoeff[comp][block]) > 0 {
		return ctx.sigCoeff[comp][block], nil
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(ctx.cfg.Layout) {
		return nil, fmt.Errorf("missing packed signature coeffs for comp=%d block=%d", comp, block)
	}
	if comp >= len(ctx.sigLimbCoeff) || block >= len(ctx.sigLimbCoeff[comp]) {
		return nil, fmt.Errorf("missing v3 signature limb coeffs for comp=%d block=%d", comp, block)
	}
	acc := []uint64{0}
	for lane := 0; lane < len(ctx.sigLimbCoeff[comp][block]); lane++ {
		acc = polyAddMod(acc, polyScale(ctx.sigLimbCoeff[comp][block][lane], ctx.cfg.SigSpec.RPows[lane]%ctx.cfg.Ring.Modulus[0], ctx.cfg.Ring.Modulus[0]), ctx.cfg.Ring.Modulus[0])
	}
	acc = trimPoly(acc, ctx.cfg.Ring.Modulus[0])
	if comp < len(ctx.sigCoeff) && block < len(ctx.sigCoeff[comp]) {
		ctx.sigCoeff[comp][block] = acc
	}
	return acc, nil
}

func (ctx *literalPackedCompileContext) scalarBundleSlotCoeff(slot PRFSlot) ([]uint64, error) {
	if ctx == nil || ctx.cfg.Ring == nil {
		return nil, fmt.Errorf("nil literal packed compile context")
	}
	if slot.Row < 0 || slot.Col < 0 {
		return nil, fmt.Errorf("invalid scalar bundle slot (%d,%d)", slot.Row, slot.Col)
	}
	cfg := ctx.cfg.Layout.CoeffNativeSig
	if cfg.ScalarBundleBase < 0 {
		return nil, fmt.Errorf("missing scalar bundle base")
	}
	rowIdx := slot.Row - cfg.ScalarBundleBase
	if rowIdx < 0 || rowIdx >= len(ctx.scalarBundleCoeff) {
		return nil, fmt.Errorf("scalar bundle row idx %d out of range (base=%d count=%d)", slot.Row, cfg.ScalarBundleBase, len(ctx.scalarBundleCoeff))
	}
	if slot.Col >= len(ctx.cfg.LagrangeBasis) {
		return nil, fmt.Errorf("scalar bundle slot col %d out of range", slot.Col)
	}
	return trimPoly(polyMul(ctx.scalarBundleCoeff[rowIdx], ctx.cfg.LagrangeBasis[slot.Col], ctx.cfg.Ring.Modulus[0]), ctx.cfg.Ring.Modulus[0]), nil
}

func buildLiteralPackedAggregatedConstraintFormalCoeffsV3(ctx *literalPackedCompileContext, outRow, outBlock, outCoord int) ([]uint64, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil literal packed compile context")
	}
	if ctx.cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	ringQ := ctx.cfg.Ring
	tables := ctx.cfg.Tables
	if tables == nil {
		return nil, fmt.Errorf("missing literal packed tables")
	}
	if outRow < 0 || outRow >= tables.OutputRows || outBlock < 0 || outBlock >= tables.Blocks || outCoord < 0 || outCoord >= tables.NCols {
		return nil, fmt.Errorf("aggregated literal packed row out of range")
	}
	q := ringQ.Modulus[0]
	x1Coeff := ctx.x1Coeff
	if ctx.x1Slot.Row >= 0 {
		var err error
		x1Coeff, err = ctx.scalarBundleSlotCoeff(ctx.x1Slot)
		if err != nil {
			return nil, err
		}
	}
	acc := []uint64{0}
	for comp := 0; comp < ctx.cfg.Layout.CoeffNativeSig.PackedSigComponents; comp++ {
		for inBlock := 0; inBlock < ctx.cfg.Layout.CoeffNativeSig.PackedSigBlocks; inBlock++ {
			sigCoeff, err := ctx.packedSigCoeff(comp, inBlock)
			if err != nil {
				return nil, err
			}
			b1aTheta := trimPoly(ctx.cfg.OmegaPlan.interpolate(tables.B1ARoutes[outRow][comp].Weights[outBlock][inBlock][outCoord]), q)
			aTheta := trimPoly(ctx.cfg.OmegaPlan.interpolate(tables.ARoutes[outRow][comp].Weights[outBlock][inBlock][outCoord]), q)
			acc = polyAddMod(acc, polyMul(b1aTheta, sigCoeff, q), q)
			acc = polySubMod(acc, polyMul(aTheta, polyMul(sigCoeff, x1Coeff, q), q), q)
		}
	}
	selector := ctx.cfg.LagrangeBasis[outCoord]
	acc = polySubMod(acc, polyScale(selector, ctx.cfg.B0ConstBlocks[outBlock][outCoord], q), q)
	msgTheta := polyScale(selector, ctx.cfg.B0MsgBlocks[outBlock][outCoord], q)
	if len(ctx.uSumCoeff) > 0 {
		acc = polySubMod(acc, polyMul(msgTheta, ctx.uSumCoeff, q), q)
	} else {
		for i := range ctx.uCoeff {
			acc = polySubMod(acc, polyMul(msgTheta, ctx.uCoeff[i], q), q)
		}
	}
	rndTheta := polyScale(selector, ctx.cfg.B0RndBlocks[outBlock][outCoord], q)
	if len(ctx.x0SumCoeff) > 0 {
		acc = polySubMod(acc, polyMul(rndTheta, ctx.x0SumCoeff, q), q)
	} else {
		for i := range ctx.x0Coeff {
			acc = polySubMod(acc, polyMul(rndTheta, ctx.x0Coeff[i], q), q)
		}
	}
	return trimPoly(acc, q), nil
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
	cfg := layout.CoeffNativeSig
	rowCount := 0
	if cfg.PackedSigBase >= 0 {
		if end := cfg.PackedSigBase + cfg.PackedSigCount; end > rowCount {
			rowCount = end
		}
	}
	if cfg.ScalarBundleBase >= 0 {
		if end := cfg.ScalarBundleBase + cfg.ScalarBundleCount; end > rowCount {
			rowCount = end
		}
	}
	if cfg.UBase >= 0 {
		if end := cfg.UBase + cfg.UCount; end > rowCount {
			rowCount = end
		}
	}
	if cfg.X0Base >= 0 {
		if end := cfg.X0Base + cfg.X0Count; end > rowCount {
			rowCount = end
		}
	}
	if cfg.X1Row >= 0 && cfg.X1Row+1 > rowCount {
		rowCount = cfg.X1Row + 1
	}
	if cfg.X1Slot.Row+1 > rowCount {
		rowCount = cfg.X1Slot.Row + 1
	}
	if cfg.PostSignMsgSumRow >= 0 && cfg.PostSignMsgSumRow+1 > rowCount {
		rowCount = cfg.PostSignMsgSumRow + 1
	}
	if cfg.PostSignRndSumRow >= 0 && cfg.PostSignRndSumRow+1 > rowCount {
		rowCount = cfg.PostSignRndSumRow + 1
	}
	if cfg.PostSignX1Row >= 0 && cfg.PostSignX1Row+1 > rowCount {
		rowCount = cfg.PostSignX1Row + 1
	}
	if layout.PackedSigChainBase >= 0 && layout.PackedSigChainRowsPerGroup > 0 {
		if end := layout.PackedSigChainBase + layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup; end > rowCount {
			rowCount = end
		}
	}
	if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		if end := cfg.UScalarCertBase + cfg.UScalarCertCount*cfg.NonSigCertRowsPerScalar; cfg.UScalarCertBase >= 0 && end > rowCount {
			rowCount = end
		}
		if end := cfg.X0ScalarCertBase + cfg.X0ScalarCertCount*cfg.NonSigCertRowsPerScalar; cfg.X0ScalarCertBase >= 0 && end > rowCount {
			rowCount = end
		}
		if end := cfg.X1ScalarCertBase + cfg.X1ScalarCertCount*cfg.NonSigCertRowsPerScalar; cfg.X1ScalarCertBase >= 0 && end > rowCount {
			rowCount = end
		}
		return rowCount
	}
	if rowsPer := inferNonSigBoundRowsPer(layout); rowsPer > 0 {
		if end := layout.MsgRangeBase + cfg.UCount*rowsPer; end > rowCount {
			rowCount = end
		}
		if end := layout.RndRangeBase + cfg.X0Count*rowsPer; end > rowCount {
			rowCount = end
		}
		if end := layout.X1RangeBase + rowsPer; end > rowCount {
			rowCount = end
		}
	}
	return rowCount
}

func buildLiteralPackedPostSignConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64) (LiteralPackedPostSignConfig, error) {
	if ringQ == nil {
		return LiteralPackedPostSignConfig{}, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return LiteralPackedPostSignConfig{}, fmt.Errorf("literal packed post-sign config requires literal packed coeff-native layout")
	}
	cfg := layout.CoeffNativeSig
	sigSpec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], layout, SimOpts{})
	if err != nil {
		return LiteralPackedPostSignConfig{}, fmt.Errorf("signature chain spec: %w", err)
	}
	tables, err := BuildShowingCoeffNativeTables(ringQ, pub, cfg.PackedSigBlockWidth)
	if err != nil {
		return LiteralPackedPostSignConfig{}, err
	}
	b0ConstBlocks, err := buildShowingCoeffNativeConstBlocks(ringQ, pub.B[0], cfg.PackedSigBlockWidth)
	if err != nil {
		return LiteralPackedPostSignConfig{}, fmt.Errorf("B0Const blocks: %w", err)
	}
	b0MsgBlocks, err := buildShowingCoeffNativeConstBlocks(ringQ, pub.B[1], cfg.PackedSigBlockWidth)
	if err != nil {
		return LiteralPackedPostSignConfig{}, fmt.Errorf("B0Msg blocks: %w", err)
	}
	b0RndBlocks, err := buildShowingCoeffNativeConstBlocks(ringQ, pub.B[2], cfg.PackedSigBlockWidth)
	if err != nil {
		return LiteralPackedPostSignConfig{}, fmt.Errorf("B0Rnd blocks: %w", err)
	}
	lagrangeBasis, err := buildLagrangeBasisCoeffs(omegaWitness, ringQ.Modulus[0])
	if err != nil {
		return LiteralPackedPostSignConfig{}, fmt.Errorf("literal packed lagrange basis: %w", err)
	}
	omegaPlan, err := buildInterpolationPlan(omegaWitness, ringQ.Modulus[0])
	if err != nil {
		return LiteralPackedPostSignConfig{}, fmt.Errorf("literal packed interpolation plan: %w", err)
	}
	return LiteralPackedPostSignConfig{
		Ring:          ringQ,
		Layout:        layout,
		SigSpec:       sigSpec,
		Tables:        tables,
		B0ConstBlocks: b0ConstBlocks,
		B0MsgBlocks:   b0MsgBlocks,
		B0RndBlocks:   b0RndBlocks,
		LagrangeBasis: lagrangeBasis,
		OmegaPlan:     omegaPlan,
		DomainPoints:  append([]uint64(nil), domainPoints...),
	}, nil
}

func (cfg LiteralPackedPostSignConfig) evalPoint(evalIdx uint64) (uint64, error) {
	q := cfg.Ring.Modulus[0]
	ptIdx := int(evalIdx)
	if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
		return 0, fmt.Errorf("literal packed eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
	}
	return cfg.DomainPoints[ptIdx] % q, nil
}

func (cfg LiteralPackedPostSignConfig) evalLagrangeWeightsAt(x uint64) ([]uint64, error) {
	if len(cfg.LagrangeBasis) == 0 {
		return nil, fmt.Errorf("missing literal packed lagrange basis")
	}
	q := cfg.Ring.Modulus[0]
	out := make([]uint64, len(cfg.LagrangeBasis))
	for i := range cfg.LagrangeBasis {
		out[i] = EvalPoly(cfg.LagrangeBasis[i], x%q, q) % q
	}
	return out, nil
}

func (cfg LiteralPackedPostSignConfig) evalLagrangeWeightsAtK(K *kf.Field, e kf.Elem) ([]kf.Elem, error) {
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if len(cfg.LagrangeBasis) == 0 {
		return nil, fmt.Errorf("missing literal packed lagrange basis")
	}
	out := make([]kf.Elem, len(cfg.LagrangeBasis))
	for i := range cfg.LagrangeBasis {
		out[i] = K.EvalFPolyAtK(cfg.LagrangeBasis[i], e)
	}
	return out, nil
}

func (cfg LiteralPackedPostSignConfig) LiteralPackedPostSignEvaluator() ConstraintEvaluator {
	switch cfg.Layout.CoeffNativeSig.Model {
	case CoeffNativeSigModelLiteralPackedAggregatedV3:
		return cfg.literalPackedPostSignEvaluatorV3()
	default:
		return func(_ uint64, _ []uint64) ([]uint64, []uint64, error) {
			return nil, nil, fmt.Errorf("unsupported literal packed coeff-native model %q", cfg.Layout.CoeffNativeSig.Model)
		}
	}
}

func (cfg LiteralPackedPostSignConfig) LiteralPackedPostSignKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	switch cfg.Layout.CoeffNativeSig.Model {
	case CoeffNativeSigModelLiteralPackedAggregatedV3:
		return cfg.literalPackedPostSignKEvaluatorV3(K)
	default:
		return nil, fmt.Errorf("unsupported literal packed coeff-native model %q", cfg.Layout.CoeffNativeSig.Model)
	}
}

func literalPackedSlotValue(rows []uint64, slot PRFSlot, lambdas []uint64, q uint64) (uint64, error) {
	if slot.Row < 0 || slot.Row >= len(rows) {
		return 0, fmt.Errorf("slot row %d out of range (rows=%d)", slot.Row, len(rows))
	}
	if slot.Col < 0 || slot.Col >= len(lambdas) {
		return 0, fmt.Errorf("slot col %d out of range (lambdas=%d)", slot.Col, len(lambdas))
	}
	return modMul(rows[slot.Row]%q, lambdas[slot.Col]%q, q), nil
}

func literalPackedSlotValueK(K *kf.Field, rows []kf.Elem, slot PRFSlot, lambdas []kf.Elem) (kf.Elem, error) {
	if slot.Row < 0 || slot.Row >= len(rows) {
		return K.Zero(), fmt.Errorf("slot row %d out of range (rows=%d)", slot.Row, len(rows))
	}
	if slot.Col < 0 || slot.Col >= len(lambdas) {
		return K.Zero(), fmt.Errorf("slot col %d out of range (lambdas=%d)", slot.Col, len(lambdas))
	}
	return K.Mul(rows[slot.Row], lambdas[slot.Col]), nil
}

func literalPackedDerivedSigValue(rows []uint64, layout RowLayout, spec LinfSpec, comp, block int, q uint64) (uint64, error) {
	acc := uint64(0)
	for lane := 0; lane < spec.L; lane++ {
		idx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
		if idx < 0 || idx >= len(rows) {
			return 0, fmt.Errorf("derived sig limb row %d out of range (rows=%d)", idx, len(rows))
		}
		acc = lvcs.MulAddMod64(acc, spec.RPows[lane]%q, rows[idx]%q, q)
	}
	return acc, nil
}

func literalPackedDerivedSigValueK(K *kf.Field, rows []kf.Elem, layout RowLayout, spec LinfSpec, comp, block int) (kf.Elem, error) {
	acc := K.Zero()
	q := K.Q
	for lane := 0; lane < spec.L; lane++ {
		idx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
		if idx < 0 || idx >= len(rows) {
			return K.Zero(), fmt.Errorf("derived sig limb row %d out of range (rows=%d)", idx, len(rows))
		}
		addScaledBaseKElem(&acc, rows[idx], spec.RPows[lane]%q, q)
	}
	return acc, nil
}

func literalPackedDerivedSigValues(rows []uint64, layout RowLayout, spec LinfSpec, q uint64) ([][]uint64, error) {
	cfg := layout.CoeffNativeSig
	out := make([][]uint64, cfg.PackedSigComponents)
	for comp := 0; comp < cfg.PackedSigComponents; comp++ {
		out[comp] = make([]uint64, cfg.PackedSigBlocks)
		for block := 0; block < cfg.PackedSigBlocks; block++ {
			val, err := literalPackedDerivedSigValue(rows, layout, spec, comp, block, q)
			if err != nil {
				return nil, err
			}
			out[comp][block] = val
		}
	}
	return out, nil
}

func literalPackedDerivedSigValuesK(K *kf.Field, rows []kf.Elem, layout RowLayout, spec LinfSpec) ([][]kf.Elem, error) {
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	cfg := layout.CoeffNativeSig
	out := make([][]kf.Elem, cfg.PackedSigComponents)
	for comp := 0; comp < cfg.PackedSigComponents; comp++ {
		out[comp] = make([]kf.Elem, cfg.PackedSigBlocks)
		for block := 0; block < cfg.PackedSigBlocks; block++ {
			val, err := literalPackedDerivedSigValueK(K, rows, layout, spec, comp, block)
			if err != nil {
				return nil, err
			}
			out[comp][block] = val
		}
	}
	return out, nil
}

func (cfg LiteralPackedPostSignConfig) literalPackedPostSignEvaluatorV3() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil ring")
		}
		if cfg.Tables == nil {
			return nil, nil, fmt.Errorf("missing literal packed tables")
		}
		if !rowLayoutCoeffNativeUsesLiteralPackedV3(cfg.Layout) {
			return nil, nil, fmt.Errorf("literal packed v3 evaluator requires v3 coeff-native layout")
		}
		layout := cfg.Layout.CoeffNativeSig
		q := cfg.Ring.Modulus[0]
		x, err := cfg.evalPoint(evalIdx)
		if err != nil {
			return nil, nil, err
		}
		lambdas, err := cfg.evalLagrangeWeightsAt(x)
		if err != nil {
			return nil, nil, err
		}
		sigVals, err := literalPackedDerivedSigValues(rows, cfg.Layout, cfg.SigSpec, q)
		if err != nil {
			return nil, nil, err
		}
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		var x1Val uint64
		if rowLayoutCoeffNativeUsesCompressedNonSigScalars(cfg.Layout) {
			x1Val, err = getRow(rowLayoutCoeffNativePostSignX1Index(cfg.Layout))
			if err != nil {
				return nil, nil, err
			}
		} else if layout.X1Slot.Row >= 0 {
			x1Val, err = literalPackedSlotValue(rows, layout.X1Slot, lambdas, q)
			if err != nil {
				return nil, nil, err
			}
		} else {
			x1Val, err = getRow(rowLayoutCoeffNativeX1Index(cfg.Layout))
			if err != nil {
				return nil, nil, err
			}
		}
		fagg := make([]uint64, 0, cfg.Tables.OutputRows*cfg.Tables.Blocks*cfg.Tables.NCols)
		for outRow := 0; outRow < cfg.Tables.OutputRows; outRow++ {
			for outBlock := 0; outBlock < cfg.Tables.Blocks; outBlock++ {
				for outCoord := 0; outCoord < cfg.Tables.NCols; outCoord++ {
					selectorVal := uint64(0)
					if outCoord < len(lambdas) {
						selectorVal = lambdas[outCoord] % q
					}
					left := uint64(0)
					for comp := 0; comp < layout.PackedSigComponents; comp++ {
						for inBlock := 0; inBlock < layout.PackedSigBlocks; inBlock++ {
							sigVal := sigVals[comp][inBlock]
							b1aVal := evalHeadWithLagrange(cfg.Tables.B1ARoutes[outRow][comp].Weights[outBlock][inBlock][outCoord], lambdas, q)
							aVal := evalHeadWithLagrange(cfg.Tables.ARoutes[outRow][comp].Weights[outBlock][inBlock][outCoord], lambdas, q)
							left = modAdd(left, modMul(b1aVal, sigVal, q), q)
							left = modSub(left, modMul(aVal, modMul(sigVal, x1Val, q), q), q)
						}
					}
					right := modMul(selectorVal, cfg.B0ConstBlocks[outBlock][outCoord]%q, q)
					if rowLayoutCoeffNativeUsesCompressedNonSigScalars(cfg.Layout) {
						uVal, err := getRow(rowLayoutCoeffNativePostSignMsgSumIndex(cfg.Layout))
						if err != nil {
							return nil, nil, err
						}
						thetaVal := modMul(selectorVal, cfg.B0MsgBlocks[outBlock][outCoord]%q, q)
						right = modAdd(right, modMul(thetaVal, uVal, q), q)
					} else if len(layout.USlots) > 0 {
						for i := range layout.USlots {
							uVal, err := literalPackedSlotValue(rows, layout.USlots[i], lambdas, q)
							if err != nil {
								return nil, nil, err
							}
							thetaVal := modMul(selectorVal, cfg.B0MsgBlocks[outBlock][outCoord]%q, q)
							right = modAdd(right, modMul(thetaVal, uVal, q), q)
						}
					} else {
						for i := 0; i < layout.UCount; i++ {
							uVal, err := getRow(rowLayoutCoeffNativeUIndex(cfg.Layout, i))
							if err != nil {
								return nil, nil, err
							}
							thetaVal := modMul(selectorVal, cfg.B0MsgBlocks[outBlock][outCoord]%q, q)
							right = modAdd(right, modMul(thetaVal, uVal, q), q)
						}
					}
					if rowLayoutCoeffNativeUsesCompressedNonSigScalars(cfg.Layout) {
						x0Val, err := getRow(rowLayoutCoeffNativePostSignRndSumIndex(cfg.Layout))
						if err != nil {
							return nil, nil, err
						}
						thetaVal := modMul(selectorVal, cfg.B0RndBlocks[outBlock][outCoord]%q, q)
						right = modAdd(right, modMul(thetaVal, x0Val, q), q)
					} else if len(layout.X0Slots) > 0 {
						for i := range layout.X0Slots {
							x0Val, err := literalPackedSlotValue(rows, layout.X0Slots[i], lambdas, q)
							if err != nil {
								return nil, nil, err
							}
							thetaVal := modMul(selectorVal, cfg.B0RndBlocks[outBlock][outCoord]%q, q)
							right = modAdd(right, modMul(thetaVal, x0Val, q), q)
						}
					} else {
						for i := 0; i < layout.X0Count; i++ {
							x0Val, err := getRow(rowLayoutCoeffNativeX0Index(cfg.Layout, i))
							if err != nil {
								return nil, nil, err
							}
							thetaVal := modMul(selectorVal, cfg.B0RndBlocks[outBlock][outCoord]%q, q)
							right = modAdd(right, modMul(thetaVal, x0Val, q), q)
						}
					}
					fagg = append(fagg, modSub(left, right, q))
				}
			}
		}
		return []uint64{}, fagg, nil
	}
}

func (cfg LiteralPackedPostSignConfig) literalPackedPostSignKEvaluatorV3(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(cfg.Layout) {
		return nil, fmt.Errorf("literal packed v3 K evaluator requires v3 coeff-native layout")
	}
	layout := cfg.Layout.CoeffNativeSig
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		lambdas, err := cfg.evalLagrangeWeightsAtK(K, e)
		if err != nil {
			return nil, nil, err
		}
		sigVals, err := literalPackedDerivedSigValuesK(K, rows, cfg.Layout, cfg.SigSpec)
		if err != nil {
			return nil, nil, err
		}
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		var x1Val kf.Elem
		if rowLayoutCoeffNativeUsesCompressedNonSigScalars(cfg.Layout) {
			x1Val, err = getRow(rowLayoutCoeffNativePostSignX1Index(cfg.Layout))
			if err != nil {
				return nil, nil, err
			}
		} else if layout.X1Slot.Row >= 0 {
			x1Val, err = literalPackedSlotValueK(K, rows, layout.X1Slot, lambdas)
			if err != nil {
				return nil, nil, err
			}
		} else {
			x1Val, err = getRow(rowLayoutCoeffNativeX1Index(cfg.Layout))
			if err != nil {
				return nil, nil, err
			}
		}
		fagg := make([]kf.Elem, 0, cfg.Tables.OutputRows*cfg.Tables.Blocks*cfg.Tables.NCols)
		sigTimesX1 := K.Zero()
		thetaVal := K.Zero()
		for outRow := 0; outRow < cfg.Tables.OutputRows; outRow++ {
			for outBlock := 0; outBlock < cfg.Tables.Blocks; outBlock++ {
				for outCoord := 0; outCoord < cfg.Tables.NCols; outCoord++ {
					selectorVal := K.Zero()
					if outCoord < len(lambdas) {
						selectorVal = lambdas[outCoord]
					}
					left := K.Zero()
					for comp := 0; comp < layout.PackedSigComponents; comp++ {
						for inBlock := 0; inBlock < layout.PackedSigBlocks; inBlock++ {
							sigVal := sigVals[comp][inBlock]
							b1aVal := evalHeadWithLagrangeK(K, cfg.Tables.B1ARoutes[outRow][comp].Weights[outBlock][inBlock][outCoord], lambdas)
							aVal := evalHeadWithLagrangeK(K, cfg.Tables.ARoutes[outRow][comp].Weights[outBlock][inBlock][outCoord], lambdas)
							K.AddMulInto(&left, b1aVal, sigVal)
							K.MulInto(&sigTimesX1, sigVal, x1Val)
							K.SubMulInto(&left, aVal, sigTimesX1)
						}
					}
					right := scaleKElemByBase(K, selectorVal, cfg.B0ConstBlocks[outBlock][outCoord]%cfg.Ring.Modulus[0])
					if rowLayoutCoeffNativeUsesCompressedNonSigScalars(cfg.Layout) {
						uVal, err := getRow(rowLayoutCoeffNativePostSignMsgSumIndex(cfg.Layout))
						if err != nil {
							return nil, nil, err
						}
						K.MulBaseInto(&thetaVal, selectorVal, cfg.B0MsgBlocks[outBlock][outCoord]%cfg.Ring.Modulus[0])
						K.AddMulInto(&right, thetaVal, uVal)
					} else if len(layout.USlots) > 0 {
						for i := range layout.USlots {
							uVal, err := literalPackedSlotValueK(K, rows, layout.USlots[i], lambdas)
							if err != nil {
								return nil, nil, err
							}
							K.MulBaseInto(&thetaVal, selectorVal, cfg.B0MsgBlocks[outBlock][outCoord]%cfg.Ring.Modulus[0])
							K.AddMulInto(&right, thetaVal, uVal)
						}
					} else {
						for i := 0; i < layout.UCount; i++ {
							uVal, err := getRow(rowLayoutCoeffNativeUIndex(cfg.Layout, i))
							if err != nil {
								return nil, nil, err
							}
							K.MulBaseInto(&thetaVal, selectorVal, cfg.B0MsgBlocks[outBlock][outCoord]%cfg.Ring.Modulus[0])
							K.AddMulInto(&right, thetaVal, uVal)
						}
					}
					if rowLayoutCoeffNativeUsesCompressedNonSigScalars(cfg.Layout) {
						x0Val, err := getRow(rowLayoutCoeffNativePostSignRndSumIndex(cfg.Layout))
						if err != nil {
							return nil, nil, err
						}
						K.MulBaseInto(&thetaVal, selectorVal, cfg.B0RndBlocks[outBlock][outCoord]%cfg.Ring.Modulus[0])
						K.AddMulInto(&right, thetaVal, x0Val)
					} else if len(layout.X0Slots) > 0 {
						for i := range layout.X0Slots {
							x0Val, err := literalPackedSlotValueK(K, rows, layout.X0Slots[i], lambdas)
							if err != nil {
								return nil, nil, err
							}
							K.MulBaseInto(&thetaVal, selectorVal, cfg.B0RndBlocks[outBlock][outCoord]%cfg.Ring.Modulus[0])
							K.AddMulInto(&right, thetaVal, x0Val)
						}
					} else {
						for i := 0; i < layout.X0Count; i++ {
							x0Val, err := getRow(rowLayoutCoeffNativeX0Index(cfg.Layout, i))
							if err != nil {
								return nil, nil, err
							}
							K.MulBaseInto(&thetaVal, selectorVal, cfg.B0RndBlocks[outBlock][outCoord]%cfg.Ring.Modulus[0])
							K.AddMulInto(&right, thetaVal, x0Val)
						}
					}
					fagg = append(fagg, K.Sub(left, right))
				}
			}
		}
		return []kf.Elem{}, fagg, nil
	}, nil
}

func literalPackedWitnessFromRowsNTT(layout RowLayout, rowsNTT []*ring.Poly) (*literalPackedPolyWitness, error) {
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return nil, fmt.Errorf("literal packed witness extraction requires literal packed coeff-native layout")
	}
	getPoly := func(idx int) (*ring.Poly, error) {
		if idx < 0 || idx >= len(rowsNTT) {
			return nil, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		return rowsNTT[idx], nil
	}
	out := &literalPackedPolyWitness{
		Sig: make([][]*ring.Poly, cfg.PackedSigComponents),
		U:   make([]*ring.Poly, cfg.UCount),
		X0:  make([]*ring.Poly, cfg.X0Count),
	}
	if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		out.U = nil
		out.X0 = nil
	}
	if rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		out.SigLimbs = make([][][]*ring.Poly, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			out.SigLimbs[comp] = make([][]*ring.Poly, cfg.PackedSigBlocks)
			for block := 0; block < cfg.PackedSigBlocks; block++ {
				out.SigLimbs[comp][block] = make([]*ring.Poly, layout.PackedSigChainRowsPerGroup)
				for lane := 0; lane < layout.PackedSigChainRowsPerGroup; lane++ {
					p, err := getPoly(rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane))
					if err != nil {
						return nil, err
					}
					out.SigLimbs[comp][block][lane] = p
				}
			}
		}
		if cfg.ScalarBundleCount > 0 {
			out.ScalarBundles = make([]*ring.Poly, cfg.ScalarBundleCount)
			for i := 0; i < cfg.ScalarBundleCount; i++ {
				p, err := getPoly(rowLayoutCoeffNativeScalarBundleIndex(layout, i))
				if err != nil {
					return nil, err
				}
				out.ScalarBundles[i] = p
			}
		}
	} else {
		return nil, fmt.Errorf("unsupported literal packed coeff-native model %q", cfg.Model)
	}
	if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		p, err := getPoly(rowLayoutCoeffNativePostSignMsgSumIndex(layout))
		if err != nil {
			return nil, err
		}
		out.USum = p
		p, err = getPoly(rowLayoutCoeffNativePostSignRndSumIndex(layout))
		if err != nil {
			return nil, err
		}
		out.X0Sum = p
	} else {
		for i := 0; i < cfg.UCount; i++ {
			p, err := getPoly(rowLayoutCoeffNativeUIndex(layout, i))
			if err != nil {
				return nil, err
			}
			out.U[i] = p
		}
		for i := 0; i < cfg.X0Count; i++ {
			p, err := getPoly(rowLayoutCoeffNativeX0Index(layout, i))
			if err != nil {
				return nil, err
			}
			out.X0[i] = p
		}
	}
	x1, err := getPoly(rowLayoutCoeffNativeX1Index(layout))
	if err != nil {
		return nil, err
	}
	out.X1 = x1
	return out, nil
}

func buildSigShortnessPackedMembershipFormalCoeffs(r *ring.Ring, packedRows [][]*ring.Poly, spec LinfSpec) ([]*ring.Poly, [][]uint64, error) {
	if r == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(packedRows) == 0 {
		return nil, nil, fmt.Errorf("missing packed signature limb rows")
	}
	toFormal := func(pNTT *ring.Poly) fpoly.Poly {
		if pNTT == nil {
			return fpoly.Zero(spec.Q)
		}
		coeff := r.NewPoly()
		r.InvNTT(pNTT, coeff)
		return fpoly.New(spec.Q, coeff.Coeffs[0])
	}
	toNTTIfFits := func(c []uint64) *ring.Poly {
		if len(c) == 0 {
			c = []uint64{0}
		}
		if len(c) > int(r.N) {
			return nil
		}
		p := r.NewPoly()
		copy(p.Coeffs[0], c)
		r.NTT(p, p)
		return p
	}
	outPolys := make([]*ring.Poly, 0, len(packedRows)*spec.L)
	outCoeffs := make([][]uint64, 0, len(packedRows)*spec.L)
	for g := 0; g < len(packedRows); g++ {
		if len(packedRows[g]) != spec.L {
			return nil, nil, fmt.Errorf("packed limb group %d row count=%d want %d", g, len(packedRows[g]), spec.L)
		}
		for i := 0; i < spec.L; i++ {
			cMem := fpoly.New(spec.Q, spec.PDi[i]).Compose(toFormal(packedRows[g][i]))
			outCoeffs = append(outCoeffs, append([]uint64(nil), cMem.Coeffs...))
			outPolys = append(outPolys, toNTTIfFits(cMem.Coeffs))
		}
	}
	return outPolys, outCoeffs, nil
}

func buildCredentialRowsShowingCoeffNativeLiteralPacked(
	ringQ *ring.Ring,
	pub PublicInputs,
	wit WitnessInputs,
	prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds int,
	opts SimOpts,
) (rows []*ring.Poly, rowInputs []lvcs.RowInput, layout RowLayout, prfLayout *PRFLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols int, err error) {
	if ringQ == nil {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	if opts.DomainMode != DomainModeExplicit {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed aggregated mode requires explicit domain mode")
	}
	if opts.NCols <= 0 {
		opts.NCols = int(ringQ.N)
	}
	ncols = opts.NCols
	if ncols <= 0 || ringQ.N%ncols != 0 {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires ringN %% ncols == 0 (ringN=%d ncols=%d)", ringQ.N, ncols)
	}
	if wit.CoeffNativeShowing == nil {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires WitnessInputs.CoeffNativeShowing")
	}
	model := resolveCoeffNativeSigModel(opts)
	if !coeffNativeSigModelUsesLiteralPacked(model) {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("unsupported literal packed coeff-native model %q", model)
	}
	cn := wit.CoeffNativeShowing
	if err := cn.Validate(int(ringQ.N)); err != nil {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("invalid coeff-native semantic witness: %w", err)
	}
	if len(pub.A) == 0 || len(pub.A[0]) == 0 {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires non-empty A")
	}
	if len(cn.Sig) != len(pub.A[0]) {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed signature witness rows=%d want %d", len(cn.Sig), len(pub.A[0]))
	}
	blocks := int(ringQ.N) / ncols
	var explicitOmega []uint64
	if opts.DomainMode == DomainModeExplicit {
		nLeaves := opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		derivedOmega, derr := deriveExplicitWitnessOmega(ringQ.Modulus[0], nLeaves, ncols, opts.LVCSNCols, opts.Ell)
		if derr != nil {
			return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed explicit omega: %w", derr)
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
	constantHead := func(v int64) []uint64 {
		head := make([]uint64, ncols)
		fv := liftToField(ringQ.Modulus[0], v)
		for i := range head {
			head[i] = fv
		}
		return head
	}
	appendBoundChainFromValues := func(values []uint64, spec LinfSpec) (int, error) {
		if len(values) == 0 {
			return -1, nil
		}
		R := int64(spec.R)
		q := ringQ.Modulus[0]
		base := len(rows)
		for _, value := range values {
			mHead := make([]uint64, ncols)
			dHeads := make([][]uint64, spec.L)
			for i := 0; i < spec.L; i++ {
				dHeads[i] = make([]uint64, ncols)
			}
			av := centeredLift(value, q)
			absA := av
			if absA < 0 {
				absA = -absA
			}
			remaining := absA
			digits := make([]int64, spec.L)
			for i := 0; i < spec.L; i++ {
				if i == spec.L-1 {
					digits[i] = remaining
					remaining = 0
					continue
				}
				digit := remaining % R
				remaining /= R
				if i == 0 {
					lo := int64(spec.LSDLo)
					hi := int64(spec.LSDHi)
					for digit > hi {
						digit -= R
						remaining++
					}
					for digit < lo {
						digit += R
						remaining--
					}
				}
				digits[i] = digit
			}
			for j := 0; j < ncols; j++ {
				mHead[j] = liftToField(q, absA)
				for i := 0; i < spec.L; i++ {
					dHeads[i][j] = liftToField(q, digits[i])
				}
			}
			rows = append(rows, makeRowFromHead(mHead))
			for i := 0; i < spec.L; i++ {
				rows = append(rows, makeRowFromHead(dHeads[i]))
			}
		}
		return base, nil
	}
	appendSignedScalarCertRows := func(values []int64, spec LinfSpec) (int, error) {
		if len(values) == 0 {
			return -1, nil
		}
		base := len(rows)
		for _, value := range values {
			digits, err := decomposeLinfDigitsSigned(value, spec)
			if err != nil {
				return -1, err
			}
			for digit := 0; digit < spec.L; digit++ {
				rows = append(rows, makeRowFromHead(constantHead(digits[digit])))
			}
		}
		return base, nil
	}

	packedWitness, err := buildLiteralPackedPolyWitness(ringQ, cn, explicitOmega, ncols, model)
	if err != nil {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed witness: %w", err)
	}
	packedSigBase, packedSigCount := -1, 0
	uBase, x0Base, x1Row := -1, -1, -1
	postSignMsgSumRow, postSignRndSumRow, postSignX1Row := -1, -1, -1
	uScalarCertBase, x0ScalarCertBase, x1ScalarCertBase := -1, -1, -1
	uScalarCertCount, x0ScalarCertCount, x1ScalarCertCount := 0, 0, 0
	nonSigCertRowsPerScalar, nonSigCertRadix, nonSigCertDigits := 0, 0, 0
	uCount := len(cn.U)
	x0Count := len(cn.X0)
	scalarBundleBase, scalarBundleCount := -1, 0
	var uSlots, x0Slots []PRFSlot
	x1Slot := PRFSlot{Row: -1, Col: -1}
	compressedNonSigV3 := model == CoeffNativeSigModelLiteralPackedAggregatedV3 && v3NonSigScalarCertEnabled(pub.BoundB)
	if model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("unsupported literal packed coeff-native model %q", model)
	}
	// V3 commits only the primary shortness limbs; semantic S is derived
	// inside the post-sign compiler/evaluator.
	if compressedNonSigV3 {
		msgSum := int64(0)
		for _, v := range cn.U {
			msgSum += v
		}
		postSignMsgSumRow = len(rows)
		rows = append(rows, makeRowFromHead(constantHead(msgSum)))
		rndSum := int64(0)
		for _, v := range cn.X0 {
			rndSum += v
		}
		postSignRndSumRow = len(rows)
		rows = append(rows, makeRowFromHead(constantHead(rndSum)))
		postSignX1Row = len(rows)
		x1Row = postSignX1Row
		rows = append(rows, makeRowFromHead(constantHead(cn.X1)))
	} else {
		uBase = len(rows)
		for _, v := range cn.U {
			rows = append(rows, makeRowFromHead(constantHead(v)))
		}
		x0Base = len(rows)
		for _, v := range cn.X0 {
			rows = append(rows, makeRowFromHead(constantHead(v)))
		}
		x1Row = len(rows)
		rows = append(rows, makeRowFromHead(constantHead(cn.X1)))
	}

	packedSigChainBase := -1
	packedSigChainGroupCount := 0
	packedSigChainGroupSize := 0
	packedSigChainRowsPerGroup := 0
	sigSignedChain := false
	spec, serr := signatureChainSpecForOpts(ringQ.Modulus[0], opts)
	if serr != nil {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature chain spec: %w", serr)
	}
	if !signatureSpecNoWrapOK(spec) {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature chain spec violates no-wrap bound: maxAbs=%d q=%d", spec.MaxAbs, spec.Q)
	}
	packedSigChainBase = len(rows)
	for comp := 0; comp < len(packedWitness.SigLimbs); comp++ {
		for block := 0; block < len(packedWitness.SigLimbs[comp]); block++ {
			for lane := 0; lane < len(packedWitness.SigLimbs[comp][block]); lane++ {
				coeff := ringQ.NewPoly()
				ringQ.InvNTT(packedWitness.SigLimbs[comp][block][lane], coeff)
				rows = append(rows, coeff)
			}
		}
	}
	packedSigChainGroupCount = len(cn.Sig) * blocks
	packedSigChainGroupSize = ncols
	packedSigChainRowsPerGroup = spec.L
	sigSignedChain = true

	msgChainBase, rndChainBase := -1, -1
	msgRangeBase, rndRangeBase, x1RangeBase := -1, -1, -1
	nonSigBoundRowsPer := 0
	if compressedNonSigV3 {
		specCert, serr := v3NonSigScalarCertSpec(ringQ.Modulus[0], pub.BoundB)
		if serr != nil {
			return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("v3 non-sign scalar cert spec: %w", serr)
		}
		uScalarCertBase, err = appendSignedScalarCertRows(cn.U, specCert)
		if err != nil {
			return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("append v3 U scalar cert rows: %w", err)
		}
		x0ScalarCertBase, err = appendSignedScalarCertRows(cn.X0, specCert)
		if err != nil {
			return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("append v3 X0 scalar cert rows: %w", err)
		}
		x1ScalarCertBase, err = appendSignedScalarCertRows([]int64{cn.X1}, specCert)
		if err != nil {
			return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("append v3 X1 scalar cert rows: %w", err)
		}
		uScalarCertCount = len(cn.U)
		x0ScalarCertCount = len(cn.X0)
		x1ScalarCertCount = 1
		nonSigCertRowsPerScalar = specCert.L
		nonSigCertRadix = int(specCert.R)
		nonSigCertDigits = specCert.L
	} else if pub.BoundB > 0 {
		specBound, serr := nonSigBoundLinfSpec(ringQ.Modulus[0], pub.BoundB)
		if serr != nil {
			return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("bound chain spec: %w", serr)
		}
		nonSigBoundRowsPer = nonSigChainRowsPer(specBound)
		if uCount > 0 {
			uVals := make([]uint64, uCount)
			for i, v := range cn.U {
				uVals[i] = liftToField(ringQ.Modulus[0], v)
			}
			msgRangeBase, err = appendBoundChainFromValues(uVals, specBound)
			if err != nil {
				return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, err
			}
			msgChainBase = msgRangeBase
		}
		if x0Count > 0 {
			x0Vals := make([]uint64, x0Count)
			for i, v := range cn.X0 {
				x0Vals[i] = liftToField(ringQ.Modulus[0], v)
			}
			rndRangeBase, err = appendBoundChainFromValues(x0Vals, specBound)
			if err != nil {
				return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, err
			}
			rndChainBase = rndRangeBase
		}
		x1RangeBase, err = appendBoundChainFromValues([]uint64{liftToField(ringQ.Modulus[0], cn.X1)}, specBound)
		if err != nil {
			return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}

	inputLen := prfParamsLenKey + prfParamsLenNonce
	R := prfRF + prfRP
	if prfGroupRounds <= 0 {
		prfGroupRounds = 1
	}
	if len(cn.PRFKey) != prfParamsLenKey {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native semantic prf key len=%d want %d", len(cn.PRFKey), prfParamsLenKey)
	}
	if len(wit.Extras) == 0 {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("missing PRF witness in Extras (need prf_sbox)")
	}
	sboxAny, ok := wit.Extras["prf_sbox"]
	if !ok {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("missing prf_sbox in witness Extras")
	}
	sboxPolys, ok := sboxAny.([]*ring.Poly)
	if !ok {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("prf_sbox has wrong type")
	}
	sboxNeeded := 0
	scheduleParams := &prf.Params{RF: prfRF, RP: prfRP}
	for round := 0; round < R; round++ {
		if !prf.ShouldCheckpointRound(scheduleParams, round, prfGroupRounds) {
			continue
		}
		full := round < prfRF/2 || round >= prfRF/2+prfRP
		if full {
			sboxNeeded += inputLen
		} else {
			sboxNeeded++
		}
	}
	if len(sboxPolys) != sboxNeeded {
		return nil, nil, RowLayout{}, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("prf_sbox len=%d want %d", len(sboxPolys), sboxNeeded)
	}
	startIdx = len(rows)
	prfPackedRows := false
	var prfKeySlots, prfSBoxSlots []PRFSlot
	for _, v := range cn.PRFKey {
		rows = append(rows, makeRowFromHead(constantHead(v)))
	}
	rows = append(rows, sboxPolys...)

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
	layout.IdxT = -1
	layout.IdxUBase = -1
	layout.SigBlocks = blocks
	layout.SigUCount = len(cn.Sig)
	layout.SigExtraUBase = -1
	layout.SigExtraTBase = -1
	layout.SigDerivedT = true
	layout.SigCoeffBase = -1
	layout.ChainBase = -1
	layout.ChainRowsPerSig = 0
	layout.PackedSigChainBase = packedSigChainBase
	layout.PackedSigChainGroupCount = packedSigChainGroupCount
	layout.PackedSigChainGroupSize = packedSigChainGroupSize
	layout.PackedSigChainRowsPerGroup = packedSigChainRowsPerGroup
	layout.SigSignedChain = sigSignedChain
	layout.MsgChainBase = msgChainBase
	layout.RndChainBase = rndChainBase
	layout.MsgRangeBase = msgRangeBase
	layout.RndRangeBase = rndRangeBase
	layout.X1RangeBase = x1RangeBase
	layout.NonSigBoundRowsPer = nonSigBoundRowsPer
	layout.SigPrimaryLimbRows = 0
	layout.ScalarBundleRows = 0
	layout.SigBoundSliceRows = 0
	layout.PostSignScalarProjectionRows = 0
	layout.PostSignScalarCertificateRows = 0
	layout.PRFScalarBundleRows = 0
	layout.PRFGroupedNonlinearRows = 0
	layout.SigCount = len(rows)
	layout.CoeffNativeSig = CoeffNativeSigLayout{
		Enabled:                 true,
		Model:                   model,
		SigBase:                 packedSigBase,
		SigCount:                packedSigCount,
		SigBlocks:               blocks,
		SigUCount:               len(cn.Sig),
		SigComponentCount:       len(cn.Sig),
		SigCoeffCount:           int(ringQ.N),
		OutputBlocks:            blocks,
		OutputBlockWidth:        ncols,
		UBase:                   uBase,
		UCount:                  uCount,
		X0Base:                  x0Base,
		X0Count:                 x0Count,
		X1Row:                   x1Row,
		W1SigBase:               packedSigBase,
		W1SigCount:              packedSigCount,
		PackedSigBase:           packedSigBase,
		PackedSigCount:          packedSigCount,
		PackedSigBlocks:         blocks,
		PackedSigComponents:     len(cn.Sig),
		PackedSigBlockWidth:     ncols,
		ScalarBundleBase:        scalarBundleBase,
		ScalarBundleCount:       scalarBundleCount,
		USlots:                  clonePRFSlots(uSlots),
		X0Slots:                 clonePRFSlots(x0Slots),
		X1Slot:                  x1Slot,
		PostSignMsgSumRow:       postSignMsgSumRow,
		PostSignRndSumRow:       postSignRndSumRow,
		PostSignX1Row:           postSignX1Row,
		UScalarCertBase:         uScalarCertBase,
		UScalarCertCount:        uScalarCertCount,
		X0ScalarCertBase:        x0ScalarCertBase,
		X0ScalarCertCount:       x0ScalarCertCount,
		X1ScalarCertBase:        x1ScalarCertBase,
		X1ScalarCertCount:       x1ScalarCertCount,
		NonSigCertRowsPerScalar: nonSigCertRowsPerScalar,
		NonSigCertRadix:         nonSigCertRadix,
		NonSigCertDigits:        nonSigCertDigits,
	}
	if model == CoeffNativeSigModelLiteralPackedAggregatedV3 {
		layout.SigPrimaryLimbRows = packedSigChainGroupCount * packedSigChainRowsPerGroup
		if compressedNonSigV3 {
			layout.PostSignScalarProjectionRows = 3
			layout.PostSignScalarCertificateRows = nonSigCertRowsPerScalar * (uCount + x0Count + 1)
			layout.SigBoundSliceRows = layout.PostSignScalarCertificateRows
		} else {
			layout.PostSignScalarProjectionRows = 0
			layout.PostSignScalarCertificateRows = 0
			layout.ScalarBundleRows = scalarBundleCount
			layout.SigBoundSliceRows = layout.SigPrimaryLimbRows
			if rowsPer := nonSigBoundRowsPer; rowsPer > 0 {
				layout.SigBoundSliceRows += rowsPer * (uCount + x0Count + 1)
			}
		}
	}

	prfLayout = &PRFLayout{
		Mode:        PRFLayoutModeSBox,
		StartIdx:    startIdx,
		LenKey:      prfParamsLenKey,
		LenNonce:    prfParamsLenNonce,
		RF:          prfRF,
		RP:          prfRP,
		LenTag:      len(pub.Tag),
		GroupRounds: prfGroupRounds,
		PackedRows:  prfPackedRows,
		KeySlots:    clonePRFSlots(prfKeySlots),
		SBoxSlots:   clonePRFSlots(prfSBoxSlots),
		WitnessRows: len(cn.PRFKey) + len(sboxPolys),
		KeyBind:     false,
		M2RowIdx:    -1,
	}

	witnessCount = len(rows)
	rowInputs = buildRowInputs(ringQ, rows, ncols)
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
	return rows, rowInputs, layout, prfLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols, nil
}

func buildCredentialConstraintSetPostCoeffNativeLiteralPacked(ringQ *ring.Ring, bound int64, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, domainMode DomainMode, opts SimOpts) (ConstraintSet, error) {
	opts.applyDefaults()
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return ConstraintSet{}, fmt.Errorf("literal packed coeff-native compiler requires literal packed layout")
	}
	if domainMode != DomainModeExplicit {
		return ConstraintSet{}, fmt.Errorf("literal packed aggregated mode requires explicit domain mode")
	}
	q := ringQ.Modulus[0]
	wit, err := literalPackedWitnessFromRowsNTT(layout, rowsNTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("literal packed witness from rows: %w", err)
	}
	compileCtx, err := buildLiteralPackedCompileContext(ringQ, pub, layout, wit, omega)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("literal packed compile context: %w", err)
	}
	if cfg.Model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return ConstraintSet{}, fmt.Errorf("unsupported literal packed coeff-native model %q", cfg.Model)
	}
	fparInt := []*ring.Poly{}
	fparIntCoeffs := [][]uint64{}
	faggInt := make([]*ring.Poly, 0, cfg.OutputBlocks*len(pub.A)*cfg.OutputBlockWidth)
	faggIntCoeffs := make([][]uint64, 0, cfg.OutputBlocks*len(pub.A)*cfg.OutputBlockWidth)
	for outRow := 0; outRow < len(pub.A); outRow++ {
		for outBlock := 0; outBlock < cfg.PackedSigBlocks; outBlock++ {
			for outCoord := 0; outCoord < cfg.PackedSigBlockWidth; outCoord++ {
				var (
					coeffs []uint64
					aerr   error
				)
				coeffs, aerr = buildLiteralPackedAggregatedConstraintFormalCoeffsV3(compileCtx, outRow, outBlock, outCoord)
				if aerr != nil {
					return ConstraintSet{}, fmt.Errorf("literal packed aggregated row (%d,%d,%d): %w", outRow, outBlock, outCoord, aerr)
				}
				faggInt = append(faggInt, coeffsToNTTIfFits(ringQ, coeffs))
				faggIntCoeffs = append(faggIntCoeffs, coeffs)
			}
		}
	}
	parallelDeg := 1
	var fparBounds []*ring.Poly
	var fparBoundsCoeffs [][]uint64
	if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		specCert, serr := v3NonSigScalarCertSpec(q, bound)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("v3 non-sign scalar cert spec: %w", serr)
		}
		cfgCert := PostSignScalarCertConfig{
			Ring:              ringQ,
			Spec:              specCert,
			MsgSumRow:         cfg.PostSignMsgSumRow,
			RndSumRow:         cfg.PostSignRndSumRow,
			X1Row:             cfg.PostSignX1Row,
			UScalarCertBase:   cfg.UScalarCertBase,
			UScalarCertCount:  cfg.UScalarCertCount,
			X0ScalarCertBase:  cfg.X0ScalarCertBase,
			X0ScalarCertCount: cfg.X0ScalarCertCount,
			X1ScalarCertBase:  cfg.X1ScalarCertBase,
			X1ScalarCertCount: cfg.X1ScalarCertCount,
			RowsPerScalar:     cfg.NonSigCertRowsPerScalar,
		}
		certPolys, certCoeffs, err := buildPostSignScalarCertFormalCoeffs(ringQ, rowsNTT, cfgCert)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("v3 post-sign scalar cert: %w", err)
		}
		fparBounds = append(fparBounds, certPolys...)
		fparBoundsCoeffs = append(fparBoundsCoeffs, certCoeffs...)
		for i := 0; i < specCert.L; i++ {
			if deg := maxDegreeFromCoeffs(specCert.PDi[i]); deg > parallelDeg {
				parallelDeg = deg
			}
		}
	} else if rowsPer := inferNonSigBoundRowsPer(layout); rowsPer > 0 {
		specBound, serr := nonSigBoundLinfSpec(q, bound)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("post-sign bound chain spec: %w", serr)
		}
		P := make([]*ring.Poly, 0, cfg.UCount+cfg.X0Count+1)
		cd := ChainDecomp{M: make([]*ring.Poly, 0, cfg.UCount+cfg.X0Count+1), D: make([][]*ring.Poly, 0, cfg.UCount+cfg.X0Count+1)}
		mulNTTPoly := func(a, b *ring.Poly) *ring.Poly {
			out := ringQ.NewPoly()
			for i := 0; i < ringQ.N; i++ {
				out.Coeffs[0][i] = lvcs.MulMod64(a.Coeffs[0][i]%q, b.Coeffs[0][i]%q, q)
			}
			return out
		}
		appendBoundFamily := func(base int, srcRows []int, label string) error {
			for t, srcIdx := range srcRows {
				if srcIdx < 0 || srcIdx >= len(rowsNTT) {
					return fmt.Errorf("%s source row idx %d out of range (rows=%d)", label, srcIdx, len(rowsNTT))
				}
				chainBase := base + t*rowsPer
				if chainBase < 0 || chainBase+rowsPer > len(rowsNTT) {
					return fmt.Errorf("%s chain rows [%d,%d) out of range (rows=%d)", label, chainBase, chainBase+rowsPer, len(rowsNTT))
				}
				P = append(P, rowsNTT[srcIdx])
				cd.M = append(cd.M, rowsNTT[chainBase])
				digits := make([]*ring.Poly, specBound.L)
				for i := 0; i < specBound.L; i++ {
					digits[i] = rowsNTT[chainBase+1+i]
				}
				cd.D = append(cd.D, digits)
			}
			return nil
		}
		if rowLayoutCoeffNativeUsesLiteralPackedV3(layout) && cfg.ScalarBundleCount > 0 {
			selectorTheta, selectorCoeff, err := buildOmegaDeltaSelectors(ringQ, omega)
			if err != nil {
				return ConstraintSet{}, fmt.Errorf("v3 bound selectors: %w", err)
			}
			appendSlotBoundFamily := func(base int, slots []PRFSlot, label string) error {
				for t, slot := range slots {
					if slot.Row < 0 || slot.Row >= len(rowsNTT) {
						return fmt.Errorf("%s slot row %d out of range (rows=%d)", label, slot.Row, len(rowsNTT))
					}
					if slot.Col < 0 || slot.Col >= len(selectorTheta) {
						return fmt.Errorf("%s slot col %d out of range", label, slot.Col)
					}
					chainBase := base + t*rowsPer
					if chainBase < 0 || chainBase+rowsPer > len(rowsNTT) {
						return fmt.Errorf("%s chain rows [%d,%d) out of range (rows=%d)", label, chainBase, chainBase+rowsPer, len(rowsNTT))
					}
					P = append(P, mulNTTPoly(rowsNTT[slot.Row], selectorTheta[slot.Col]))
					cd.M = append(cd.M, rowsNTT[chainBase])
					digits := make([]*ring.Poly, specBound.L)
					for i := 0; i < specBound.L; i++ {
						digits[i] = rowsNTT[chainBase+1+i]
					}
					cd.D = append(cd.D, digits)
					_ = selectorCoeff
				}
				return nil
			}
			if err := appendSlotBoundFamily(layout.MsgRangeBase, cfg.USlots, "literal packed v3 msg bound chain"); err != nil {
				return ConstraintSet{}, err
			}
			if err := appendSlotBoundFamily(layout.RndRangeBase, cfg.X0Slots, "literal packed v3 rnd bound chain"); err != nil {
				return ConstraintSet{}, err
			}
			if err := appendSlotBoundFamily(layout.X1RangeBase, []PRFSlot{cfg.X1Slot}, "literal packed v3 x1 bound chain"); err != nil {
				return ConstraintSet{}, err
			}
		} else {
			uRows := make([]int, cfg.UCount)
			for i := range uRows {
				uRows[i] = rowLayoutCoeffNativeUIndex(layout, i)
			}
			if err := appendBoundFamily(layout.MsgRangeBase, uRows, "literal packed msg bound chain"); err != nil {
				return ConstraintSet{}, err
			}
			x0Rows := make([]int, cfg.X0Count)
			for i := range x0Rows {
				x0Rows[i] = rowLayoutCoeffNativeX0Index(layout, i)
			}
			if err := appendBoundFamily(layout.RndRangeBase, x0Rows, "literal packed rnd bound chain"); err != nil {
				return ConstraintSet{}, err
			}
			if err := appendBoundFamily(layout.X1RangeBase, []int{rowLayoutCoeffNativeX1Index(layout)}, "literal packed x1 bound chain"); err != nil {
				return ConstraintSet{}, err
			}
		}
		boundPolys, boundCoeffs := buildFparLinfChainComposeFormalCoeffs(ringQ, P, cd, specBound)
		fparBounds = append(fparBounds, boundPolys...)
		fparBoundsCoeffs = append(fparBoundsCoeffs, boundCoeffs...)
		for i := 0; i < specBound.L; i++ {
			if deg := maxDegreeFromCoeffs(specBound.PDi[i]); deg > parallelDeg {
				parallelDeg = deg
			}
		}
	}
	if layout.PackedSigChainBase >= 0 && layout.PackedSigChainRowsPerGroup > 0 {
		specSig, serr := signatureChainSpecForLayoutAndOpts(q, layout, opts)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("signature chain spec: %w", serr)
		}
		wantRowsPer, serr := signaturePackedChainRowsPerGroupForOpts(specSig, opts, layout.PackedSigChainGroupSize)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("signature shortness rows-per-group: %w", serr)
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
		chainPolys, chainCoeffs, err := buildSigShortnessPackedMembershipFormalCoeffs(ringQ, packedRows, specSig)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("literal packed signature shortness: %w", err)
		}
		fparBounds = append(fparBounds, chainPolys...)
		fparBoundsCoeffs = append(fparBoundsCoeffs, chainCoeffs...)
		deg, derr := signatureShortnessMaxDegree(specSig, opts)
		if derr != nil {
			return ConstraintSet{}, fmt.Errorf("signature shortness degree: %w", derr)
		}
		if deg > parallelDeg {
			parallelDeg = deg
		}
	}
	return ConstraintSet{
		FparInt:          fparInt,
		FparNorm:         fparBounds,
		FaggInt:          faggInt,
		FparIntCoeffs:    fparIntCoeffs,
		FparNormCoeffs:   fparBoundsCoeffs,
		FaggIntCoeffs:    faggIntCoeffs,
		ParallelAlgDeg:   parallelDeg,
		AggregatedAlgDeg: 2,
	}, nil
}
