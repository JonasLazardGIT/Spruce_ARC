package PIOP

import (
	"fmt"
	"sync"
	"time"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// semanticQBuildV3Input contains only committed-row geometry, public
// challenges, and the shared semantic relation evaluator.  In particular it
// has no formal/debug coefficient families: strict v3 builds Q by replaying
// Eq. (4) at fixed points and interpolating the resulting K values.
type semanticQBuildV3Input struct {
	Ring                *ring.Ring
	K                   *kf.Field
	OmegaWitness        []uint64
	OmegaExtra          kf.Elem
	MuInv               kf.Elem
	PhysicalRows        [][]uint64
	ReplayWitnessRows   int
	LogicalWitnessCount int
	MaskRowOffset       int
	MaskRowCount        int
	MaskDegreeBound     int
	DegreeBound         int
	Eval                KConstraintEvaluator
	EvalParallel        KParallelConstraintEvaluator
	AggregateDot        KAggregateDotFactory
	// The Into evaluators are private strict-v3 accelerators.  Their legacy
	// counterparts above remain authoritative compatibility paths (and are
	// used by the independent general-K audit when an Into evaluator elects
	// to fall back).  Every scratch value returned by NewScratch is owned by a
	// single semantic-Q worker.
	EvalInto          *semanticKConstraintIntoV3
	EvalParallelInto  *semanticKConstraintIntoV3
	AggregateDotInto  semanticKAggregateDotFactoryIntoV3
	AggregateCount    int
	aggregateDots     []KAggregateDotEvaluator
	aggregateDotsInto []*semanticKAggregateDotIntoV3
	GammaPrimeK       [][][]KScalar
	GammaAggK         [][]KScalar
	PhaseRecorder     *PhaseRecorder
	PhasePrefix       string
	ExecutionPolicy   ExecutionPolicy
}

// semanticKConstraintIntoV3 evaluates a fixed semantic relation into caller-
// owned, pre-sized K-element buffers.  It is intentionally private: proof and
// verifier APIs continue to use KConstraintEvaluator, while strict-v3 Q
// interpolation can avoid rebuilding thousands of elements at every point.
type semanticKConstraintIntoV3 struct {
	ParallelCount  int
	AggregateCount int
	NewScratch     func() any
	EvalInto       func(e kf.Elem, rows, fpar, fagg []kf.Elem, scratch any) error
}

type semanticKAggregateDotIntoV3 struct {
	NewScratch func() any
	EvalInto   func(dst *kf.Elem, e kf.Elem, rows []kf.Elem, scratch any) error
}

type semanticKAggregateDotFactoryIntoV3 func(gamma []KScalar) (*semanticKAggregateDotIntoV3, error)

func semanticQPhaseLabelV3(in semanticQBuildV3Input, suffix string) string {
	prefix := in.PhasePrefix
	if prefix == "" {
		prefix = "proof"
	}
	return prefix + ".semantic_q." + suffix
}

func prepareSemanticQAggregateDotsV3(in *semanticQBuildV3Input) error {
	if in == nil {
		return fmt.Errorf("semantic Q v3: nil input")
	}
	direct := in.EvalParallel != nil || in.AggregateDot != nil || in.EvalParallelInto != nil || in.AggregateDotInto != nil || in.AggregateCount != 0
	if !direct {
		return nil
	}
	if in.EvalParallel == nil || in.AggregateDot == nil || in.AggregateCount <= 0 {
		return fmt.Errorf("semantic Q v3: incomplete direct aggregate evaluator")
	}
	if (in.EvalParallelInto == nil) != (in.AggregateDotInto == nil) {
		return fmt.Errorf("semantic Q v3: incomplete direct aggregate Into evaluator")
	}
	if in.EvalParallelInto != nil && (in.EvalParallelInto.EvalInto == nil || in.EvalParallelInto.ParallelCount <= 0 || in.EvalParallelInto.AggregateCount != 0) {
		return fmt.Errorf("semantic Q v3: malformed parallel Into evaluator")
	}
	if len(in.GammaAggK) == 0 {
		return fmt.Errorf("semantic Q v3: direct aggregate evaluator has no gamma rows")
	}
	in.aggregateDots = make([]KAggregateDotEvaluator, len(in.GammaAggK))
	if in.AggregateDotInto != nil {
		in.aggregateDotsInto = make([]*semanticKAggregateDotIntoV3, len(in.GammaAggK))
	}
	for i := range in.GammaAggK {
		if len(in.GammaAggK[i]) != in.AggregateCount {
			return fmt.Errorf("semantic Q v3: aggregate gamma width %d want %d", len(in.GammaAggK[i]), in.AggregateCount)
		}
		var err error
		if in.AggregateDotInto != nil {
			in.aggregateDotsInto[i], err = in.AggregateDotInto(in.GammaAggK[i])
			if err != nil {
				return fmt.Errorf("semantic Q v3: bind direct aggregate Into row %d: %w", i, err)
			}
			if in.aggregateDotsInto[i] == nil || in.aggregateDotsInto[i].EvalInto == nil {
				return fmt.Errorf("semantic Q v3: nil direct aggregate Into row %d", i)
			}
			continue
		}
		in.aggregateDots[i], err = in.AggregateDot(in.GammaAggK[i])
		if err != nil {
			return fmt.Errorf("semantic Q v3: bind direct aggregate row %d: %w", i, err)
		}
	}
	return nil
}

// semanticQDirectPlanV3 is the transcript-independent decoding of the
// committed SmallWood row matrix. It evaluates the same semantic queries as
// buildKPointCoeffMatrix+VTargets, but it never materializes their enormous
// sparse query matrix. That distinction is essential when Eq. (4) is sampled
// at dQ+1 interpolation points.
type semanticQDirectPlanV3 struct {
	K                  *kf.Field
	OmegaWitness       []uint64
	OmegaExtra         kf.Elem
	MuInv              kf.Elem
	NCols              int
	HeadCoeffs         [][]uint64
	ExtraCorrections   []kf.Elem
	BaseAdjustments    []kf.Elem
	MaskShape          smallFieldMaskShapeV3
	MaskColumnByDegree [][]kf.Elem
}

// makeKElementBuffer creates count independently addressable K elements backed
// by one flat limb allocation. The returned elements own references to their
// portions of the backing store, so the store remains live without a separate
// owner field.
func makeKElementBuffer(count, theta int) []kf.Elem {
	if count <= 0 || theta <= 0 {
		return nil
	}
	limbs := make([]uint64, count*theta)
	out := make([]kf.Elem, count)
	for i := range out {
		out[i].Limb = limbs[i*theta : (i+1)*theta]
	}
	return out
}

func makeKElementMatrixBuffer(rows, cols, theta int) [][]kf.Elem {
	if rows <= 0 || cols <= 0 || theta <= 0 {
		return nil
	}
	flat := makeKElementBuffer(rows*cols, theta)
	out := make([][]kf.Elem, rows)
	for row := range out {
		out[row] = flat[row*cols : (row+1)*cols]
	}
	return out
}

func newSemanticQDirectPlanV3(in semanticQBuildV3Input) (*semanticQDirectPlanV3, error) {
	if in.Ring == nil || in.K == nil || len(in.OmegaWitness) == 0 || len(in.PhysicalRows) == 0 || len(in.PhysicalRows[0]) == 0 {
		return nil, fmt.Errorf("semantic Q v3: invalid direct-evaluation input")
	}
	if in.LogicalWitnessCount <= 0 || in.ReplayWitnessRows <= 0 {
		return nil, fmt.Errorf("semantic Q v3: invalid witness geometry")
	}
	ncols := len(in.PhysicalRows[0])
	for i := range in.PhysicalRows {
		if len(in.PhysicalRows[i]) != ncols {
			return nil, fmt.Errorf("semantic Q v3: physical row %d width=%d want %d", i, len(in.PhysicalRows[i]), ncols)
		}
	}
	shape, err := deriveSmallFieldMaskShapeV3(in.MaskDegreeBound, ncols, in.K.Theta)
	if err != nil {
		return nil, err
	}
	if in.MaskRowCount != shape.RowsPerMask || in.MaskRowOffset != in.ReplayWitnessRows || in.MaskRowOffset+in.MaskRowCount != len(in.PhysicalRows) {
		return nil, fmt.Errorf("semantic Q v3: physical mask segment offset/count/total=%d/%d/%d want replay=%d rows=%d", in.MaskRowOffset, in.MaskRowCount, len(in.PhysicalRows), in.ReplayWitnessRows, shape.RowsPerMask)
	}
	s := len(in.OmegaWitness)
	layerSize := s + in.K.Theta
	if in.ReplayWitnessRows%layerSize != 0 {
		return nil, fmt.Errorf("semantic Q v3: replay rows=%d not divisible by layer size=%d", in.ReplayWitnessRows, layerSize)
	}
	if capacity := (in.ReplayWitnessRows / layerSize) * ncols; in.LogicalWitnessCount > capacity {
		return nil, fmt.Errorf("semantic Q v3: logical rows=%d exceed replay capacity=%d", in.LogicalWitnessCount, capacity)
	}
	if len(in.OmegaExtra.Limb) != in.K.Theta || len(in.MuInv.Limb) != in.K.Theta {
		return nil, fmt.Errorf("semantic Q v3: malformed extra point or mu inverse")
	}
	headInterpolation, err := buildInterpolationPlan(in.OmegaWitness, in.K.Q)
	if err != nil {
		return nil, fmt.Errorf("semantic Q v3: witness interpolation plan: %w", err)
	}

	plan := &semanticQDirectPlanV3{
		K:                in.K,
		OmegaWitness:     append([]uint64(nil), in.OmegaWitness...),
		OmegaExtra:       kf.Elem{Limb: append([]uint64(nil), in.OmegaExtra.Limb...)},
		MuInv:            kf.Elem{Limb: append([]uint64(nil), in.MuInv.Limb...)},
		NCols:            ncols,
		HeadCoeffs:       make([][]uint64, in.LogicalWitnessCount),
		ExtraCorrections: makeKElementBuffer(in.LogicalWitnessCount, in.K.Theta),
		BaseAdjustments:  makeKElementBuffer(in.LogicalWitnessCount, in.K.Theta),
		MaskShape:        shape,
	}
	q := in.K.Q
	head := make([]uint64, s)
	rho := kf.Elem{Limb: make([]uint64, in.K.Theta)}
	headAtExtra := kf.Elem{Limb: make([]uint64, in.K.Theta)}
	for logical := 0; logical < in.LogicalWitnessCount; logical++ {
		layer, col := logical/ncols, logical%ncols
		base := layer * layerSize
		for k := 0; k < s; k++ {
			head[k] = in.PhysicalRows[base+k][col] % q
		}
		plan.HeadCoeffs[logical] = headInterpolation.interpolate(head)
		for coord := 0; coord < in.K.Theta; coord++ {
			rho.Limb[coord] = in.PhysicalRows[base+s+coord][col] % q
		}
		in.K.EvalFPolyAtKInto(&headAtExtra, plan.HeadCoeffs[logical], in.OmegaExtra)
		in.K.SubInto(&plan.ExtraCorrections[logical], rho, headAtExtra)
		// At every fixed interpolation point x in F_q,
		// mu(x)=prod_k(x-omega_k)*MuInv. Pre-multiplying the correction
		// by MuInv turns every per-row extension multiplication into a
		// coordinate-wise base-field scale.
		in.K.MulInto(&plan.BaseAdjustments[logical], in.MuInv, plan.ExtraCorrections[logical])
	}

	plan.MaskColumnByDegree = make([][]kf.Elem, shape.Mu+1)
	for degree := 0; degree <= shape.Mu; degree++ {
		plan.MaskColumnByDegree[degree] = makeKElementBuffer(shape.Nu, in.K.Theta)
		for col := 0; col < shape.Nu; col++ {
			for coord := 0; coord < in.K.Theta; coord++ {
				plan.MaskColumnByDegree[degree][col].Limb[coord] = in.PhysicalRows[in.MaskRowOffset+degree*in.K.Theta+coord][col] % q
			}
		}
	}
	return plan, nil
}

type semanticQPointScratchV3 struct {
	rowValues []kf.Elem
	outputs   []kf.Elem
	point     kf.Elem
	mask      kf.Elem
	mu        kf.Elem
	value     kf.Elem
	tmp0      kf.Elem
	tmp1      kf.Elem
	power     kf.Elem
	powerBase kf.Elem
	gamma     kf.Elem
	term      kf.Elem
	dot       kf.Elem
	fpar      []kf.Elem
	fagg      []kf.Elem
	eval      any
	dots      []any
}

func newSemanticQPointScratchV3(plan *semanticQDirectPlanV3, outputCount int) *semanticQPointScratchV3 {
	if plan == nil || plan.K == nil {
		return nil
	}
	temps := makeKElementBuffer(11, plan.K.Theta)
	return &semanticQPointScratchV3{
		rowValues: makeKElementBuffer(len(plan.HeadCoeffs), plan.K.Theta),
		outputs:   makeKElementBuffer(outputCount, plan.K.Theta),
		point:     temps[0],
		mask:      temps[1],
		mu:        temps[2],
		value:     temps[3],
		tmp0:      temps[4],
		tmp1:      temps[5],
		power:     temps[6],
		powerBase: temps[7],
		gamma:     temps[8],
		term:      temps[9],
		dot:       temps[10],
	}
}

func newSemanticQPointScratchForInputV3(plan *semanticQDirectPlanV3, outputCount int, in semanticQBuildV3Input) (*semanticQPointScratchV3, error) {
	scratch := newSemanticQPointScratchV3(plan, outputCount)
	if scratch == nil {
		return nil, fmt.Errorf("semantic Q v3: nil point scratch plan")
	}
	direct := len(in.aggregateDots) > 0
	into := in.EvalInto
	if direct {
		into = in.EvalParallelInto
	}
	if into != nil {
		if into.EvalInto == nil || into.ParallelCount < 0 || into.AggregateCount < 0 {
			return nil, fmt.Errorf("semantic Q v3: malformed Into evaluator")
		}
		scratch.fpar = makeKElementBuffer(into.ParallelCount, plan.K.Theta)
		scratch.fagg = makeKElementBuffer(into.AggregateCount, plan.K.Theta)
		if into.NewScratch != nil {
			scratch.eval = into.NewScratch()
		}
	}
	if direct && len(in.aggregateDotsInto) > 0 {
		if len(in.aggregateDotsInto) != len(in.aggregateDots) {
			return nil, fmt.Errorf("semantic Q v3: aggregate Into rows=%d want %d", len(in.aggregateDotsInto), len(in.aggregateDots))
		}
		scratch.dots = make([]any, len(in.aggregateDotsInto))
		for i, dot := range in.aggregateDotsInto {
			if dot != nil && dot.NewScratch != nil {
				scratch.dots[i] = dot.NewScratch()
			}
		}
	}
	return scratch, nil
}

func powKUintInto(K *kf.Field, dst *kf.Elem, base kf.Elem, exponent int, baseScratch *kf.Elem) {
	K.OneInto(dst)
	K.SetInto(baseScratch, base)
	for exponent > 0 {
		if exponent&1 == 1 {
			K.MulInto(dst, *dst, *baseScratch)
		}
		K.MulInto(baseScratch, *baseScratch, *baseScratch)
		exponent >>= 1
	}
}

func (plan *semanticQDirectPlanV3) vanishingProductInto(dst *kf.Elem, e kf.Elem, scratch *semanticQPointScratchV3) (uint64, bool) {
	if x, embedded := embeddedFqValueV3(plan.K, e); embedded {
		product := uint64(1)
		for _, omega := range plan.OmegaWitness {
			product = modMul(product, modSub(x, omega%plan.K.Q, plan.K.Q), plan.K.Q)
		}
		plan.K.ScaleBaseInto(dst, plan.MuInv, product)
		return product, true
	}
	plan.K.OneInto(dst)
	for _, omega := range plan.OmegaWitness {
		plan.K.EmbedFInto(&scratch.tmp0, omega%plan.K.Q)
		plan.K.SubInto(&scratch.tmp1, e, scratch.tmp0)
		plan.K.MulInto(dst, *dst, scratch.tmp1)
	}
	plan.K.MulInto(dst, *dst, plan.MuInv)
	return 0, false
}

func (plan *semanticQDirectPlanV3) witnessValuesInto(values []kf.Elem, e kf.Elem, scratch *semanticQPointScratchV3) error {
	if plan == nil || plan.K == nil || scratch == nil {
		return fmt.Errorf("semantic Q v3: nil witness evaluation plan or scratch")
	}
	if len(values) != len(plan.HeadCoeffs) {
		return fmt.Errorf("semantic Q v3: witness destination rows=%d want %d", len(values), len(plan.HeadCoeffs))
	}
	baseProduct, embedded := plan.vanishingProductInto(&scratch.mu, e, scratch)
	if x, ok := embeddedFqValueV3(plan.K, e); embedded && ok {
		for i := range values {
			plan.K.ScaleBaseInto(&values[i], plan.BaseAdjustments[i], baseProduct)
			values[i].Limb[0] = modAdd(values[i].Limb[0], EvalPoly(plan.HeadCoeffs[i], x, plan.K.Q), plan.K.Q)
		}
		return nil
	}
	for i := range values {
		plan.K.EvalFPolyAtKInto(&values[i], plan.HeadCoeffs[i], e)
		plan.K.MulInto(&scratch.tmp0, scratch.mu, plan.ExtraCorrections[i])
		plan.K.AddInto(&values[i], values[i], scratch.tmp0)
	}
	return nil
}

func (plan *semanticQDirectPlanV3) witnessValues(e kf.Elem) ([]kf.Elem, error) {
	if plan == nil || plan.K == nil {
		return nil, fmt.Errorf("semantic Q v3: nil witness evaluation plan")
	}
	scratch := newSemanticQPointScratchV3(plan, 0)
	if err := plan.witnessValuesInto(scratch.rowValues, e, scratch); err != nil {
		return nil, err
	}
	return scratch.rowValues, nil
}

func (plan *semanticQDirectPlanV3) maskValueInto(result *kf.Elem, e kf.Elem, scratch *semanticQPointScratchV3) error {
	if plan == nil || plan.K == nil || scratch == nil {
		return fmt.Errorf("semantic Q v3: nil mask evaluation plan or scratch")
	}
	shape := plan.MaskShape
	plan.K.ZeroInto(result)
	if x, embedded := embeddedFqValueV3(plan.K, e); embedded {
		for col := 0; col < shape.Nu; col++ {
			plan.K.ZeroInto(&scratch.value)
			for coord := 0; coord < plan.K.Theta; coord++ {
				acc := uint64(0)
				for degree := shape.Mu; degree >= 0; degree-- {
					acc = modAdd(modMul(acc, x, plan.K.Q), plan.MaskColumnByDegree[degree][col].Limb[coord], plan.K.Q)
				}
				scratch.value.Limb[coord] = acc
			}
			exponent := col * shape.Mu
			if col == shape.Nu-1 {
				exponent -= shape.Delta
			}
			plan.K.AddMulBaseInto(result, scratch.value, powMod(x, uint64(exponent), plan.K.Q))
		}
		return nil
	}
	for col := 0; col < shape.Nu; col++ {
		plan.K.ZeroInto(&scratch.value)
		for degree := shape.Mu; degree >= 0; degree-- {
			plan.K.MulInto(&scratch.tmp0, scratch.value, e)
			plan.K.AddInto(&scratch.value, scratch.tmp0, plan.MaskColumnByDegree[degree][col])
		}
		exponent := col * shape.Mu
		if col == shape.Nu-1 {
			exponent -= shape.Delta
		}
		powKUintInto(plan.K, &scratch.power, e, exponent, &scratch.powerBase)
		plan.K.MulInto(&scratch.tmp0, scratch.power, scratch.value)
		plan.K.AddInto(result, *result, scratch.tmp0)
	}
	return nil
}

func (plan *semanticQDirectPlanV3) maskValue(e kf.Elem) (kf.Elem, error) {
	if plan == nil || plan.K == nil {
		return kf.Elem{}, fmt.Errorf("semantic Q v3: nil mask evaluation plan")
	}
	scratch := newSemanticQPointScratchV3(plan, 0)
	if err := plan.maskValueInto(&scratch.mask, e, scratch); err != nil {
		return kf.Elem{}, err
	}
	return scratch.mask, nil
}

func semanticEq4ValuesWithPlanIntoV3(in semanticQBuildV3Input, plan *semanticQDirectPlanV3, e kf.Elem, scratch *semanticQPointScratchV3) ([]kf.Elem, error) {
	if scratch == nil {
		return nil, fmt.Errorf("semantic Q v3: nil point scratch")
	}
	if err := plan.witnessValuesInto(scratch.rowValues, e, scratch); err != nil {
		return nil, err
	}
	if err := plan.maskValueInto(&scratch.mask, e, scratch); err != nil {
		return nil, err
	}
	var fpar, fagg []kf.Elem
	directAggregate := len(in.aggregateDots) > 0
	if directAggregate && in.EvalParallelInto != nil {
		if err := in.EvalParallelInto.EvalInto(e, scratch.rowValues, scratch.fpar, nil, scratch.eval); err != nil {
			return nil, err
		}
		fpar = scratch.fpar
	} else if directAggregate {
		var err error
		fpar, err = in.EvalParallel(e, scratch.rowValues)
		if err != nil {
			return nil, err
		}
	} else if in.EvalInto != nil {
		if err := in.EvalInto.EvalInto(e, scratch.rowValues, scratch.fpar, scratch.fagg, scratch.eval); err != nil {
			return nil, err
		}
		fpar, fagg = scratch.fpar, scratch.fagg
	} else {
		var err error
		fpar, fagg, err = in.Eval(e, scratch.rowValues)
		if err != nil {
			return nil, err
		}
	}
	rho := len(in.GammaPrimeK)
	if rho == 0 {
		rho = len(in.GammaAggK)
	}
	if rho <= 0 {
		return nil, fmt.Errorf("semantic Q v3: empty gamma rows")
	}
	if len(scratch.outputs) != rho {
		return nil, fmt.Errorf("semantic Q v3: scratch output rows=%d want %d", len(scratch.outputs), rho)
	}
	out := scratch.outputs
	for i := 0; i < rho; i++ {
		value := &out[i]
		in.K.SetInto(value, scratch.mask)
		if i < len(in.GammaPrimeK) {
			for j, residual := range fpar {
				if j >= len(in.GammaPrimeK[i]) {
					return nil, fmt.Errorf("semantic Q v3: parallel gamma width %d < residuals %d", len(in.GammaPrimeK[i]), len(fpar))
				}
				evalKScalarPolyAtKInto(in.K, &scratch.gamma, in.GammaPrimeK[i][j], e)
				in.K.MulInto(&scratch.term, scratch.gamma, residual)
				in.K.AddInto(value, *value, scratch.term)
			}
		}
		if directAggregate {
			if i >= len(in.aggregateDots) {
				return nil, fmt.Errorf("semantic Q v3: missing direct aggregate row %d", i)
			}
			if len(in.aggregateDotsInto) > 0 {
				if err := in.aggregateDotsInto[i].EvalInto(&scratch.dot, e, scratch.rowValues, scratch.dots[i]); err != nil {
					return nil, err
				}
				in.K.AddInto(value, *value, scratch.dot)
			} else {
				dot, dotErr := in.aggregateDots[i](e, scratch.rowValues)
				if dotErr != nil {
					return nil, dotErr
				}
				in.K.AddInto(value, *value, dot)
			}
		} else if i < len(in.GammaAggK) {
			for j, residual := range fagg {
				if j >= len(in.GammaAggK[i]) {
					return nil, fmt.Errorf("semantic Q v3: aggregate gamma width %d < residuals %d", len(in.GammaAggK[i]), len(fagg))
				}
				setKCoords(in.K, &scratch.gamma, in.GammaAggK[i][j])
				in.K.MulInto(&scratch.term, scratch.gamma, residual)
				in.K.AddInto(value, *value, scratch.term)
			}
		}
	}
	return out, nil
}

func semanticEq4ValuesWithPlanV3(in semanticQBuildV3Input, plan *semanticQDirectPlanV3, e kf.Elem) ([]kf.Elem, error) {
	rho := len(in.GammaPrimeK)
	if rho == 0 {
		rho = len(in.GammaAggK)
	}
	scratch, err := newSemanticQPointScratchForInputV3(plan, rho, in)
	if err != nil {
		return nil, err
	}
	return semanticEq4ValuesWithPlanIntoV3(in, plan, e, scratch)
}

func semanticEq4ValuesV3(in semanticQBuildV3Input, e kf.Elem) ([]kf.Elem, error) {
	if in.Ring == nil || in.K == nil || in.Eval == nil {
		return nil, fmt.Errorf("semantic Q v3: missing ring, field, or evaluator")
	}
	plan, err := newSemanticQDirectPlanV3(in)
	if err != nil {
		return nil, err
	}
	aggregatePlanStart := phaseTimingStart(in.PhaseRecorder)
	if err := prepareSemanticQAggregateDotsV3(&in); err != nil {
		return nil, err
	}
	if in.PhaseRecorder != nil {
		in.PhaseRecorder.RecordDuration(semanticQPhaseLabelV3(in, "aggregate_plan"), time.Since(aggregatePlanStart))
	}
	return semanticEq4ValuesWithPlanV3(in, plan, e)
}

func buildSemanticQKV3(in semanticQBuildV3Input) ([]*KPoly, error) {
	planStart := phaseTimingStart(in.PhaseRecorder)
	if in.DegreeBound < 0 || in.K == nil || uint64(in.DegreeBound+2) >= in.K.Q {
		return nil, fmt.Errorf("semantic Q v3: invalid degree bound %d", in.DegreeBound)
	}
	pointCount := in.DegreeBound + 1
	plan, err := newSemanticQDirectPlanV3(in)
	if err != nil {
		return nil, err
	}
	aggregatePlanStart := phaseTimingStart(in.PhaseRecorder)
	if err := prepareSemanticQAggregateDotsV3(&in); err != nil {
		return nil, err
	}
	if in.PhaseRecorder != nil {
		in.PhaseRecorder.RecordDuration(semanticQPhaseLabelV3(in, "aggregate_plan"), time.Since(aggregatePlanStart))
	}
	xs := make([]uint64, pointCount)
	rho := len(in.GammaPrimeK)
	if rho == 0 {
		rho = len(in.GammaAggK)
	}
	for point := range xs {
		xs[point] = uint64(point)
	}
	qInterpolation, err := buildInterpolationPlan(xs, in.K.Q)
	if err != nil {
		return nil, fmt.Errorf("semantic Q v3: Q interpolation plan: %w", err)
	}
	if in.PhaseRecorder != nil {
		in.PhaseRecorder.RecordDuration(semanticQPhaseLabelV3(in, "plan"), time.Since(planStart))
	}
	// Values for one (Q row, K limb) occupy a contiguous point slice. This
	// removes the rho*theta inner allocations while preserving point and limb
	// ordering exactly.
	values := make([]uint64, rho*in.K.Theta*pointCount)
	valueSlice := func(row, limb int) []uint64 {
		start := (row*in.K.Theta + limb) * pointCount
		return values[start : start+pointCount]
	}
	// Each Eq. (4) point is independent and the shared plan/evaluator are
	// immutable. A bounded pool therefore reduces prover latency without
	// changing the sampled points, relation, interpolation, or proof bytes.
	workers := in.ExecutionPolicy.semanticWorkerCount()
	if workers > pointCount {
		workers = pointCount
	}
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan int)
	done := make(chan struct{})
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error
	evaluationStart := phaseTimingStart(in.PhaseRecorder)
	worker := func() {
		defer wg.Done()
		scratch, scratchErr := newSemanticQPointScratchForInputV3(plan, rho, in)
		if scratchErr != nil {
			errOnce.Do(func() {
				firstErr = scratchErr
				close(done)
			})
			return
		}
		for point := range jobs {
			select {
			case <-done:
				return
			default:
			}
			in.K.EmbedFInto(&scratch.point, xs[point])
			qVals, evalErr := semanticEq4ValuesWithPlanIntoV3(in, plan, scratch.point, scratch)
			if evalErr == nil && len(qVals) != rho {
				evalErr = fmt.Errorf("got %d Q values want %d", len(qVals), rho)
			}
			if evalErr != nil {
				errOnce.Do(func() {
					firstErr = fmt.Errorf("semantic Q v3 point %d: %w", point, evalErr)
					close(done)
				})
				return
			}
			for i := 0; i < rho; i++ {
				for limb := 0; limb < in.K.Theta; limb++ {
					valueSlice(i, limb)[point] = qVals[i].Limb[limb] % in.K.Q
				}
			}
		}
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
feedPoints:
	for point := 0; point < pointCount; point++ {
		select {
		case jobs <- point:
		case <-done:
			break feedPoints
		}
	}
	close(jobs)
	wg.Wait()
	if in.PhaseRecorder != nil {
		in.PhaseRecorder.RecordDuration(semanticQPhaseLabelV3(in, "evaluation"), time.Since(evaluationStart))
	}
	if firstErr != nil {
		return nil, firstErr
	}
	interpolationStart := phaseTimingStart(in.PhaseRecorder)
	out := make([]*KPoly, rho)
	for i := 0; i < rho; i++ {
		poly := &KPoly{Limbs: make([][]uint64, in.K.Theta)}
		degree := 0
		for limb := 0; limb < in.K.Theta; limb++ {
			poly.Limbs[limb] = qInterpolation.interpolate(valueSlice(i, limb))
			for d := len(poly.Limbs[limb]) - 1; d >= 0; d-- {
				if poly.Limbs[limb][d]%in.K.Q != 0 {
					if d > degree {
						degree = d
					}
					break
				}
			}
		}
		poly.Degree = degree
		out[i] = poly
	}
	if in.PhaseRecorder != nil {
		in.PhaseRecorder.RecordDuration(semanticQPhaseLabelV3(in, "interpolation"), time.Since(interpolationStart))
	}

	// The compiler supplies the degree lemma. One independent fixed point makes
	// accidental evaluator/layout drift fail closed during proof construction.
	// omegaExtra is outside F_q for the fixed public profiles, so this audit
	// exercises the generic extension-field evaluator independently of the
	// embedded base-field interpolation points.
	auditPoint := in.OmegaExtra
	auditScratch, err := newSemanticQPointScratchForInputV3(plan, rho, in)
	if err != nil {
		return nil, err
	}
	auditStart := phaseTimingStart(in.PhaseRecorder)
	want, err := semanticEq4ValuesWithPlanIntoV3(in, plan, auditPoint, auditScratch)
	if err != nil {
		return nil, fmt.Errorf("semantic Q v3 audit point: %w", err)
	}
	for i := range out {
		var got kf.Elem
		evalKPolyAtKInto(in.K, &got, out[i], auditPoint)
		if !elemEqual(in.K, got, want[i]) {
			return nil, fmt.Errorf("semantic Q v3 degree/evaluator audit failed for row %d", i)
		}
	}
	if in.PhaseRecorder != nil {
		in.PhaseRecorder.RecordDuration(semanticQPhaseLabelV3(in, "audit"), time.Since(auditStart))
	}
	return out, nil
}
