package PIOP

import (
	"fmt"
	"strings"

	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// prfInputTraceV3Relation is the PIOP rendering of prf.InputTraceV3IR.  It is
// intentionally witness independent: the same instance is used to construct
// formal prover polynomials and to replay them in F_q and K.
type prfInputTraceV3Relation struct {
	Q               uint64
	IR              *prf.InputTraceV3IR
	Payload         *PRFInputTraceV3Layout
	KeySourceSlots  []CoeffSlot
	Context         []uint64
	Tag             []uint64
	Lagrange        [][]uint64
	Constraints     []prf.InputTraceV3Constraint
	BooleanBitSlots [4]CoeffSlot
}

func canonicalPRFInputTraceV3Layout(startRow, tagCount int) (*PRFInputTraceV3Layout, error) {
	if startRow < 0 || (tagCount != 9 && tagCount != 10 && tagCount != 13) {
		return nil, fmt.Errorf("invalid canonical PRF input-trace start/tag=%d/%d", startRow, tagCount)
	}
	layout := &PRFInputTraceV3Layout{
		RelationVersion: prf.InputTraceRelationVersionV3,
		StartRow:        startRow,
		PackWidth:       prfInputTraceV3PackWidth,
		BridgeMatrices:  prfInputTraceV3BridgeMatrices,
		SBoxInputSlots:  make([]CoeffSlot, prfInputTraceV3SBoxInputs),
		FinalTagSlots:   make([]CoeffSlot, tagCount-len([4]CoeffSlot{})),
		FinalTagLanes:   make([]int, tagCount-len([4]CoeffSlot{})),
	}
	next := 0
	assign := func() CoeffSlot {
		slot := CoeffSlot{Row: startRow + next/prfInputTraceV3PackWidth, Coeff: next % prfInputTraceV3PackWidth}
		next++
		return slot
	}
	for i := range layout.SBoxInputSlots {
		layout.SBoxInputSlots[i] = assign()
	}
	for i := range layout.HiddenSlotBits {
		layout.HiddenSlotBits[i] = assign()
	}
	for i := range layout.FinalTagSlots {
		layout.FinalTagSlots[i] = assign()
		layout.FinalTagLanes[i] = i + len(layout.HiddenSlotBits)
	}
	layout.LogicalScalars = next
	layout.PackedRows = (next + layout.PackWidth - 1) / layout.PackWidth
	layout.PaddingScalars = layout.PackedRows*layout.PackWidth - next
	if err := validatePRFInputTraceV3Layout(layout, tagCount, startRow+layout.PackedRows); err != nil {
		return nil, err
	}
	return layout, nil
}

func clonePRFInputTraceV3Constraint(src prf.InputTraceV3Constraint) prf.InputTraceV3Constraint {
	out := src
	out.Terms = append([]prf.InputTraceV3Term(nil), src.Terms...)
	return out
}

func mergePRFInputTraceV3Constraints(q uint64, label string, a, b prf.InputTraceV3Constraint) prf.InputTraceV3Constraint {
	out := prf.InputTraceV3Constraint{Label: label, Constant: prf.Elem((uint64(a.Constant) + uint64(b.Constant)) % q)}
	type termKey struct {
		Ref   prf.InputTraceV3Ref
		Power uint8
	}
	terms := make(map[termKey]uint64, len(a.Terms)+len(b.Terms))
	for _, source := range [][]prf.InputTraceV3Term{a.Terms, b.Terms} {
		for _, term := range source {
			key := termKey{Ref: term.Ref, Power: term.Power}
			terms[key] = (terms[key] + uint64(term.Coeff)) % q
		}
	}
	for key, coeff := range terms {
		if coeff != 0 {
			out.Terms = append(out.Terms, prf.InputTraceV3Term{Ref: key.Ref, Power: key.Power, Coeff: prf.Elem(coeff)})
		}
	}
	// Keep construction deterministic without exporting the prf package's
	// internal normalizer.
	for i := 1; i < len(out.Terms); i++ {
		for j := i; j > 0; j-- {
			a, b := out.Terms[j], out.Terms[j-1]
			less := a.Ref.Kind < b.Ref.Kind ||
				(a.Ref.Kind == b.Ref.Kind && (a.Ref.Index < b.Ref.Index ||
					(a.Ref.Index == b.Ref.Index && a.Power < b.Power)))
			if !less {
				break
			}
			out.Terms[j], out.Terms[j-1] = out.Terms[j-1], out.Terms[j]
		}
	}
	return out
}

// inputTraceV3ConstraintsWithoutOmittedFinals substitutes terminal state
// lanes 0..3 out of the paired final-MDS/feed-forward equations.  Adding the
// pair cancels that terminal variable and is algebraically equivalent to the
// existence of its unique value.  Retained lanes keep both equations.
func inputTraceV3ConstraintsWithoutOmittedFinals(ir *prf.InputTraceV3IR) ([]prf.InputTraceV3Constraint, error) {
	if ir == nil || ir.TagCount < 4 {
		return nil, fmt.Errorf("invalid PRF input-trace IR")
	}
	finalMDS := make(map[int]prf.InputTraceV3Constraint, ir.TagCount)
	feedForward := make(map[int]prf.InputTraceV3Constraint, ir.TagCount)
	core := make([]prf.InputTraceV3Constraint, 0, len(ir.Constraints))
	for _, constraint := range ir.Constraints {
		var lane int
		switch {
		case strings.HasPrefix(constraint.Label, "final_mds["):
			if _, err := fmt.Sscanf(constraint.Label, "final_mds[%d]", &lane); err != nil {
				return nil, fmt.Errorf("parse %q: %w", constraint.Label, err)
			}
			finalMDS[lane] = clonePRFInputTraceV3Constraint(constraint)
		case strings.HasPrefix(constraint.Label, "feed_forward_tag["):
			if _, err := fmt.Sscanf(constraint.Label, "feed_forward_tag[%d]", &lane); err != nil {
				return nil, fmt.Errorf("parse %q: %w", constraint.Label, err)
			}
			feedForward[lane] = clonePRFInputTraceV3Constraint(constraint)
		default:
			core = append(core, clonePRFInputTraceV3Constraint(constraint))
		}
	}
	if len(finalMDS) != ir.TagCount || len(feedForward) != ir.TagCount {
		return nil, fmt.Errorf("terminal PRF equations=%d/%d want %d/%d", len(finalMDS), len(feedForward), ir.TagCount, ir.TagCount)
	}
	out := make([]prf.InputTraceV3Constraint, 0, len(core)+4+2*(ir.TagCount-4))
	out = append(out, core...)
	for lane := 0; lane < ir.TagCount; lane++ {
		if lane < 4 {
			out = append(out, mergePRFInputTraceV3Constraints(ir.Q, fmt.Sprintf("terminal_tag_substituted[%d]", lane), finalMDS[lane], feedForward[lane]))
			continue
		}
		out = append(out, finalMDS[lane], feedForward[lane])
	}
	return out, nil
}

func newPRFInputTraceV3Relation(
	q uint64,
	params *prf.Params,
	payload *PRFInputTraceV3Layout,
	keySourceSlots []CoeffSlot,
	contextPublic, tagPublic []int64,
	omega []uint64,
	witnessRows int,
) (*prfInputTraceV3Relation, error) {
	if params == nil {
		return nil, fmt.Errorf("nil PRF params")
	}
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("PRF params: %w", err)
	}
	if params.Q != q {
		return nil, fmt.Errorf("PRF/ring modulus=%d/%d", params.Q, q)
	}
	if len(omega) != prfInputTraceV3PackWidth {
		return nil, fmt.Errorf("PRF input-trace omega width=%d want %d", len(omega), prfInputTraceV3PackWidth)
	}
	if err := validatePRFInputTraceV3Layout(payload, params.LenTag, witnessRows); err != nil {
		return nil, err
	}
	wantKeySources := params.LenKey * credential.IntGenISISPRFSeedDigitsPerLane
	if len(keySourceSlots) != wantKeySources {
		return nil, fmt.Errorf("PRF input-trace seed slots=%d want %d", len(keySourceSlots), wantKeySources)
	}
	for i, slot := range keySourceSlots {
		if slot.Row < 0 || slot.Row >= witnessRows || slot.Coeff < 0 || slot.Coeff >= len(omega) {
			return nil, fmt.Errorf("PRF seed source slot %d=%+v outside rows/width=%d/%d", i, slot, witnessRows, len(omega))
		}
	}
	contextElems, err := publicContextElems(contextPublic, q)
	if err != nil {
		return nil, err
	}
	if len(tagPublic) != params.LenTag {
		return nil, fmt.Errorf("public tag lanes=%d want %d", len(tagPublic), params.LenTag)
	}
	tag := make([]uint64, len(tagPublic))
	for i, value := range tagPublic {
		if value < 0 || uint64(value) >= q {
			return nil, fmt.Errorf("public tag lane %d=%d is not canonical modulo %d", i, value, q)
		}
		tag[i] = uint64(value)
	}
	context := make([]uint64, len(contextElems))
	for i := range contextElems {
		context[i] = uint64(contextElems[i])
	}
	ir, err := prf.BuildInputTraceV3IR(params)
	if err != nil {
		return nil, err
	}
	constraints, err := inputTraceV3ConstraintsWithoutOmittedFinals(ir)
	if err != nil {
		return nil, err
	}
	lagrange, err := buildLagrangeBasisCoeffs(omega, q)
	if err != nil {
		return nil, fmt.Errorf("PRF input-trace selectors: %w", err)
	}
	return &prfInputTraceV3Relation{
		Q:               q,
		IR:              ir,
		Payload:         clonePRFInputTraceV3Layout(payload),
		KeySourceSlots:  cloneCoeffSlots(keySourceSlots),
		Context:         context,
		Tag:             tag,
		Lagrange:        lagrange,
		Constraints:     constraints,
		BooleanBitSlots: payload.HiddenSlotBits,
	}, nil
}

func loadTargetPRFParamsV3(tagCount int) (*prf.Params, error) {
	theta := 0
	switch tagCount {
	case 9:
		params, _, err := prf.LoadEmbeddedTargetParamsV3(credential.IntGenISISPRFParamsTag9)
		if err != nil {
			return nil, err
		}
		if params.LenTag != tagCount {
			return nil, fmt.Errorf("strict v3 embedded PRF tag width=%d want %d", params.LenTag, tagCount)
		}
		return params, nil
	case 10:
		theta = 13
	case 13:
		theta = 7
	default:
		return nil, fmt.Errorf("strict v3 unsupported PRF tag width %d", tagCount)
	}
	params, _, err := loadTargetPRFParamsForOptsV3(SimOpts{Theta: theta})
	if err != nil {
		return nil, err
	}
	return params, nil
}

func newPRFInputTraceV3RelationForShowing(
	ringQ *ring.Ring,
	pub PublicInputs,
	layout *IntGenISISShowingRowLayout,
	omega []uint64,
	params *prf.Params,
	witnessRows int,
) (*prfInputTraceV3Relation, error) {
	if ringQ == nil || layout == nil || layout.LayoutVersion != intGenISISShowingLayoutVersionInputTraceCarrierV3 {
		return nil, fmt.Errorf("missing strict v3 showing layout")
	}
	if params == nil {
		var err error
		params, err = loadTargetPRFParamsV3(layout.PRFInputTraceV3TagCount)
		if err != nil {
			return nil, err
		}
	}
	payload, err := canonicalPRFInputTraceV3Layout(layout.PRFInputTraceV3Start, layout.PRFInputTraceV3TagCount)
	if err != nil {
		return nil, err
	}
	var keySources []CoeffSlot
	if layout.MSECompressionLevel > 0 {
		keySources, err = intGenISISSeedSourceTailViewSlots(layout.MSeedViewStart, len(omega), int(ringQ.N))
	} else {
		keySources, err = intGenISISSeedSourceViewSlots(layout.MViewStart, len(omega), int(ringQ.N))
	}
	if err != nil {
		return nil, fmt.Errorf("strict v3 PRF key sources: %w", err)
	}
	return newPRFInputTraceV3Relation(ringQ.Modulus[0], params, payload, keySources, pub.Context, pub.Tag, omega, witnessRows)
}

func (relation *prfInputTraceV3Relation) selectedFormalCoeff(rowCache *intGenISISRowCoeffCache, slot CoeffSlot, power uint8, ringN int) ([]uint64, error) {
	if relation == nil || rowCache == nil {
		return nil, fmt.Errorf("nil PRF relation/row cache")
	}
	if slot.Coeff < 0 || slot.Coeff >= len(relation.Lagrange) {
		return nil, fmt.Errorf("PRF relation slot coeff=%d out of range", slot.Coeff)
	}
	row, err := rowCache.Row(slot.Row)
	if err != nil {
		return nil, err
	}
	switch power {
	case 1:
		return reducePolyModXN1(polyMul(relation.Lagrange[slot.Coeff], row, relation.Q), ringN, relation.Q), nil
	case 2:
		square := polyMul(row, row, relation.Q)
		return reducePolyModXN1(polyMul(relation.Lagrange[slot.Coeff], square, relation.Q), ringN, relation.Q), nil
	case 3:
		return selectorWeightedCubeFormalCoeffV3(relation.Lagrange[slot.Coeff], row, relation.Q, ringN)
	default:
		return nil, fmt.Errorf("unsupported PRF input-trace power %d", power)
	}
}

func (relation *prfInputTraceV3Relation) addFormalRef(
	acc []uint64,
	rowCache *intGenISISRowCoeffCache,
	ref prf.InputTraceV3Ref,
	power uint8,
	scalar uint64,
	ringN int,
) ([]uint64, error) {
	if power != 1 && ref.Kind != prf.InputTraceV3SBoxInput {
		return nil, fmt.Errorf("nonlinear PRF ref kind=%d power=%d", ref.Kind, power)
	}
	addSelected := func(slot CoeffSlot, selectedPower uint8, weight uint64) error {
		coeff, err := relation.selectedFormalCoeff(rowCache, slot, selectedPower, ringN)
		if err != nil {
			return err
		}
		acc = polyAdd(acc, scalePoly(coeff, modMul(scalar, weight, relation.Q), relation.Q), relation.Q)
		return nil
	}
	addConstant := func(value uint64) {
		acc = polyAdd(acc, scalePoly(relation.Lagrange[0], modMul(scalar, value, relation.Q), relation.Q), relation.Q)
	}
	switch ref.Kind {
	case prf.InputTraceV3Key:
		if ref.Index < 0 || ref.Index >= relation.IR.KeyCount {
			return nil, fmt.Errorf("key ref %d out of range", ref.Index)
		}
		pow := uint64(1)
		constant := uint64(0)
		for digit := 0; digit < credential.IntGenISISPRFSeedDigitsPerLane; digit++ {
			slot := relation.KeySourceSlots[ref.Index*credential.IntGenISISPRFSeedDigitsPerLane+digit]
			if err := addSelected(slot, 1, pow); err != nil {
				return nil, err
			}
			constant = (constant + uint64(credential.IntGenISISPRFSeedBound)*pow) % relation.Q
			pow = modMul(pow, uint64(credential.IntGenISISPRFSeedPackBase), relation.Q)
		}
		addConstant(constant)
	case prf.InputTraceV3Nonce:
		if ref.Index < 0 || ref.Index >= relation.IR.NonceCount {
			return nil, fmt.Errorf("nonce ref %d out of range", ref.Index)
		}
		if ref.Index < len(relation.Context) {
			addConstant(relation.Context[ref.Index])
			break
		}
		if ref.Index != len(relation.Context) {
			return nil, fmt.Errorf("unsupported hidden nonce ref %d", ref.Index)
		}
		for bit, slot := range relation.BooleanBitSlots {
			if err := addSelected(slot, 1, uint64(1<<bit)); err != nil {
				return nil, err
			}
		}
	case prf.InputTraceV3SBoxInput:
		if ref.Index < 0 || ref.Index >= len(relation.Payload.SBoxInputSlots) {
			return nil, fmt.Errorf("S-box input ref %d out of range", ref.Index)
		}
		if err := addSelected(relation.Payload.SBoxInputSlots[ref.Index], power, 1); err != nil {
			return nil, err
		}
	case prf.InputTraceV3FinalTagState:
		if ref.Index < 4 || ref.Index >= relation.IR.TagCount {
			return nil, fmt.Errorf("omitted/invalid terminal state ref %d survived substitution", ref.Index)
		}
		if err := addSelected(relation.Payload.FinalTagSlots[ref.Index-4], 1, 1); err != nil {
			return nil, err
		}
	case prf.InputTraceV3PublicTag:
		if ref.Index < 0 || ref.Index >= len(relation.Tag) {
			return nil, fmt.Errorf("public tag ref %d out of range", ref.Index)
		}
		addConstant(relation.Tag[ref.Index])
	default:
		return nil, fmt.Errorf("unsupported PRF input-trace ref kind %d", ref.Kind)
	}
	return reducePolyModXN1(acc, ringN, relation.Q), nil
}

func (relation *prfInputTraceV3Relation) FormalCoeffs(ringQ *ring.Ring, rowCache *intGenISISRowCoeffCache) ([]*ring.Poly, [][]uint64, int, error) {
	if relation == nil || ringQ == nil || rowCache == nil {
		return nil, nil, 0, fmt.Errorf("nil PRF input-trace formal relation input")
	}
	if ringQ.Modulus[0] != relation.Q {
		return nil, nil, 0, fmt.Errorf("PRF relation/ring modulus mismatch")
	}
	ringN := int(ringQ.N)
	coeffs := make([][]uint64, 0, len(relation.BooleanBitSlots)+len(relation.Constraints))
	for _, slot := range relation.BooleanBitSlots {
		selectedSquare, err := relation.selectedFormalCoeff(rowCache, slot, 2, ringN)
		if err != nil {
			return nil, nil, 0, err
		}
		selectedLinear, err := relation.selectedFormalCoeff(rowCache, slot, 1, ringN)
		if err != nil {
			return nil, nil, 0, err
		}
		coeffs = append(coeffs, reducePolyModXN1(polySub(selectedSquare, selectedLinear, relation.Q), ringN, relation.Q))
	}
	for _, constraint := range relation.Constraints {
		acc := scalePoly(relation.Lagrange[0], uint64(constraint.Constant)%relation.Q, relation.Q)
		var err error
		for _, term := range constraint.Terms {
			acc, err = relation.addFormalRef(acc, rowCache, term.Ref, term.Power, uint64(term.Coeff)%relation.Q, ringN)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("%s: %w", constraint.Label, err)
			}
		}
		coeffs = append(coeffs, trimPoly(reducePolyModXN1(acc, ringN, relation.Q), relation.Q))
	}
	polys := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		polys[i] = nttPolyFromFormalCoeffsIfFits(ringQ, coeffs[i])
	}
	return polys, coeffs, relation.IR.MaxWitnessDegree, nil
}

func powFqV3(value uint64, power uint8, q uint64) (uint64, error) {
	switch power {
	case 1:
		return value % q, nil
	case 2:
		return modMul(value, value, q), nil
	case 3:
		return modMul(modMul(value, value, q), value, q), nil
	default:
		return 0, fmt.Errorf("unsupported PRF power %d", power)
	}
}

func (relation *prfInputTraceV3Relation) evalSelectedF(x uint64, rows []uint64, slot CoeffSlot, power uint8) (uint64, error) {
	if slot.Row < 0 || slot.Row >= len(rows) || slot.Coeff < 0 || slot.Coeff >= len(relation.Lagrange) {
		return 0, fmt.Errorf("PRF slot %+v outside replay rows/width=%d/%d", slot, len(rows), len(relation.Lagrange))
	}
	powered, err := powFqV3(rows[slot.Row], power, relation.Q)
	if err != nil {
		return 0, err
	}
	return modMul(EvalPoly(relation.Lagrange[slot.Coeff], x, relation.Q), powered, relation.Q), nil
}

func (relation *prfInputTraceV3Relation) evalRefF(x uint64, rows []uint64, ref prf.InputTraceV3Ref, power uint8) (uint64, error) {
	selector0 := EvalPoly(relation.Lagrange[0], x, relation.Q)
	switch ref.Kind {
	case prf.InputTraceV3Key:
		if ref.Index < 0 || ref.Index >= relation.IR.KeyCount || power != 1 {
			return 0, fmt.Errorf("invalid key ref/power=%d/%d", ref.Index, power)
		}
		acc, pow := uint64(0), uint64(1)
		constant := uint64(0)
		for digit := 0; digit < credential.IntGenISISPRFSeedDigitsPerLane; digit++ {
			value, err := relation.evalSelectedF(x, rows, relation.KeySourceSlots[ref.Index*credential.IntGenISISPRFSeedDigitsPerLane+digit], 1)
			if err != nil {
				return 0, err
			}
			acc = modAdd(acc, modMul(pow, value, relation.Q), relation.Q)
			constant = modAdd(constant, modMul(uint64(credential.IntGenISISPRFSeedBound), pow, relation.Q), relation.Q)
			pow = modMul(pow, uint64(credential.IntGenISISPRFSeedPackBase), relation.Q)
		}
		return modAdd(acc, modMul(selector0, constant, relation.Q), relation.Q), nil
	case prf.InputTraceV3Nonce:
		if power != 1 || ref.Index < 0 || ref.Index >= relation.IR.NonceCount {
			return 0, fmt.Errorf("invalid nonce ref/power=%d/%d", ref.Index, power)
		}
		if ref.Index < len(relation.Context) {
			return modMul(selector0, relation.Context[ref.Index], relation.Q), nil
		}
		acc := uint64(0)
		for bit, slot := range relation.BooleanBitSlots {
			value, err := relation.evalSelectedF(x, rows, slot, 1)
			if err != nil {
				return 0, err
			}
			acc = modAdd(acc, modMul(uint64(1<<bit), value, relation.Q), relation.Q)
		}
		return acc, nil
	case prf.InputTraceV3SBoxInput:
		if ref.Index < 0 || ref.Index >= len(relation.Payload.SBoxInputSlots) {
			return 0, fmt.Errorf("S-box ref %d out of range", ref.Index)
		}
		return relation.evalSelectedF(x, rows, relation.Payload.SBoxInputSlots[ref.Index], power)
	case prf.InputTraceV3FinalTagState:
		if ref.Index < 4 || ref.Index >= relation.IR.TagCount || power != 1 {
			return 0, fmt.Errorf("invalid retained terminal ref/power=%d/%d", ref.Index, power)
		}
		return relation.evalSelectedF(x, rows, relation.Payload.FinalTagSlots[ref.Index-4], 1)
	case prf.InputTraceV3PublicTag:
		if ref.Index < 0 || ref.Index >= len(relation.Tag) || power != 1 {
			return 0, fmt.Errorf("invalid public tag ref/power=%d/%d", ref.Index, power)
		}
		return modMul(selector0, relation.Tag[ref.Index], relation.Q), nil
	default:
		return 0, fmt.Errorf("unsupported PRF ref kind %d", ref.Kind)
	}
}

func (relation *prfInputTraceV3Relation) Evaluator(domainPoints []uint64) ConstraintEvaluator {
	if relation == nil {
		return nil
	}
	points := append([]uint64(nil), domainPoints...)
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		idx := int(evalIdx)
		if idx < 0 || idx >= len(points) {
			return nil, nil, fmt.Errorf("PRF input-trace eval index %d outside domain=%d", idx, len(points))
		}
		x := points[idx] % relation.Q
		fagg := make([]uint64, 0, len(relation.BooleanBitSlots)+len(relation.Constraints))
		for _, slot := range relation.BooleanBitSlots {
			square, err := relation.evalSelectedF(x, rows, slot, 2)
			if err != nil {
				return nil, nil, err
			}
			linear, err := relation.evalSelectedF(x, rows, slot, 1)
			if err != nil {
				return nil, nil, err
			}
			fagg = append(fagg, modSub(square, linear, relation.Q))
		}
		selector0 := EvalPoly(relation.Lagrange[0], x, relation.Q)
		for _, constraint := range relation.Constraints {
			acc := modMul(selector0, uint64(constraint.Constant), relation.Q)
			for _, term := range constraint.Terms {
				value, err := relation.evalRefF(x, rows, term.Ref, term.Power)
				if err != nil {
					return nil, nil, fmt.Errorf("%s: %w", constraint.Label, err)
				}
				acc = modAdd(acc, modMul(uint64(term.Coeff), value, relation.Q), relation.Q)
			}
			fagg = append(fagg, acc)
		}
		return nil, fagg, nil
	}
}

func powKV3(K *kf.Field, value kf.Elem, power uint8) (kf.Elem, error) {
	switch power {
	case 1:
		return value, nil
	case 2:
		return K.Mul(value, value), nil
	case 3:
		return K.Mul(K.Mul(value, value), value), nil
	default:
		return kf.Elem{}, fmt.Errorf("unsupported PRF K power %d", power)
	}
}

// scaleKElemByFqV3 and addScaledKElemByFqV3 exploit that relation
// coefficients live in F_q. Calling K.Mul(K.EmbedF(c), value) allocates a
// schoolbook extension-field product even though multiplication by c is
// coordinate-wise; semantic-Q evaluates this relation hundreds of times, so
// keeping the base-field operation explicit is material to the proving-time
// gate.
func scaleKElemByFqV3(K *kf.Field, value kf.Elem, scalar uint64) kf.Elem {
	out := K.Zero()
	scalar %= K.Q
	for i := 0; i < K.Theta && i < len(value.Limb); i++ {
		out.Limb[i] = modMul(value.Limb[i]%K.Q, scalar, K.Q)
	}
	return out
}

func addScaledKElemByFqV3(K *kf.Field, dst *kf.Elem, value kf.Elem, scalar uint64) {
	if dst == nil {
		return
	}
	if len(dst.Limb) != K.Theta {
		dst.Limb = make([]uint64, K.Theta)
	}
	scalar %= K.Q
	if scalar == 0 {
		return
	}
	for i := 0; i < K.Theta && i < len(value.Limb); i++ {
		dst.Limb[i] = modAdd(dst.Limb[i], modMul(value.Limb[i]%K.Q, scalar, K.Q), K.Q)
	}
}

func embeddedFqValueV3(K *kf.Field, value kf.Elem) (uint64, bool) {
	if K == nil || len(value.Limb) != K.Theta {
		return 0, false
	}
	for i := 1; i < len(value.Limb); i++ {
		if value.Limb[i]%K.Q != 0 {
			return 0, false
		}
	}
	return value.Limb[0] % K.Q, true
}

func (relation *prfInputTraceV3Relation) evalSelectedK(K *kf.Field, e kf.Elem, rows []kf.Elem, slot CoeffSlot, power uint8) (kf.Elem, error) {
	if slot.Row < 0 || slot.Row >= len(rows) || slot.Coeff < 0 || slot.Coeff >= len(relation.Lagrange) {
		return kf.Elem{}, fmt.Errorf("PRF K slot %+v outside replay rows/width=%d/%d", slot, len(rows), len(relation.Lagrange))
	}
	powered, err := powKV3(K, rows[slot.Row], power)
	if err != nil {
		return kf.Elem{}, err
	}
	return K.Mul(K.EvalFPolyAtK(relation.Lagrange[slot.Coeff], e), powered), nil
}

func (relation *prfInputTraceV3Relation) evalRefK(K *kf.Field, e kf.Elem, rows []kf.Elem, ref prf.InputTraceV3Ref, power uint8) (kf.Elem, error) {
	selector0 := K.EvalFPolyAtK(relation.Lagrange[0], e)
	scale := func(value kf.Elem, scalar uint64) kf.Elem { return K.Mul(K.EmbedF(scalar), value) }
	switch ref.Kind {
	case prf.InputTraceV3Key:
		if ref.Index < 0 || ref.Index >= relation.IR.KeyCount || power != 1 {
			return kf.Elem{}, fmt.Errorf("invalid K key ref/power=%d/%d", ref.Index, power)
		}
		acc, pow := K.Zero(), uint64(1)
		constant := uint64(0)
		for digit := 0; digit < credential.IntGenISISPRFSeedDigitsPerLane; digit++ {
			value, err := relation.evalSelectedK(K, e, rows, relation.KeySourceSlots[ref.Index*credential.IntGenISISPRFSeedDigitsPerLane+digit], 1)
			if err != nil {
				return kf.Elem{}, err
			}
			acc = K.Add(acc, scale(value, pow))
			constant = modAdd(constant, modMul(uint64(credential.IntGenISISPRFSeedBound), pow, relation.Q), relation.Q)
			pow = modMul(pow, uint64(credential.IntGenISISPRFSeedPackBase), relation.Q)
		}
		return K.Add(acc, scale(selector0, constant)), nil
	case prf.InputTraceV3Nonce:
		if power != 1 || ref.Index < 0 || ref.Index >= relation.IR.NonceCount {
			return kf.Elem{}, fmt.Errorf("invalid K nonce ref/power=%d/%d", ref.Index, power)
		}
		if ref.Index < len(relation.Context) {
			return scale(selector0, relation.Context[ref.Index]), nil
		}
		acc := K.Zero()
		for bit, slot := range relation.BooleanBitSlots {
			value, err := relation.evalSelectedK(K, e, rows, slot, 1)
			if err != nil {
				return kf.Elem{}, err
			}
			acc = K.Add(acc, scale(value, uint64(1<<bit)))
		}
		return acc, nil
	case prf.InputTraceV3SBoxInput:
		if ref.Index < 0 || ref.Index >= len(relation.Payload.SBoxInputSlots) {
			return kf.Elem{}, fmt.Errorf("K S-box ref %d out of range", ref.Index)
		}
		return relation.evalSelectedK(K, e, rows, relation.Payload.SBoxInputSlots[ref.Index], power)
	case prf.InputTraceV3FinalTagState:
		if ref.Index < 4 || ref.Index >= relation.IR.TagCount || power != 1 {
			return kf.Elem{}, fmt.Errorf("invalid K retained terminal ref/power=%d/%d", ref.Index, power)
		}
		return relation.evalSelectedK(K, e, rows, relation.Payload.FinalTagSlots[ref.Index-4], 1)
	case prf.InputTraceV3PublicTag:
		if ref.Index < 0 || ref.Index >= len(relation.Tag) || power != 1 {
			return kf.Elem{}, fmt.Errorf("invalid K public tag ref/power=%d/%d", ref.Index, power)
		}
		return scale(selector0, relation.Tag[ref.Index]), nil
	default:
		return kf.Elem{}, fmt.Errorf("unsupported PRF K ref kind %d", ref.Kind)
	}
}

func (relation *prfInputTraceV3Relation) KEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if relation == nil || K == nil || K.Q != relation.Q {
		return nil, fmt.Errorf("nil/mismatched PRF input-trace K relation")
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		basePoint, embeddedPoint := embeddedFqValueV3(K, e)
		lagrangeValues := make([]kf.Elem, len(relation.Lagrange))
		for i := range relation.Lagrange {
			if embeddedPoint {
				lagrangeValues[i] = K.EmbedF(EvalPoly(relation.Lagrange[i], basePoint, relation.Q))
			} else {
				lagrangeValues[i] = K.EvalFPolyAtK(relation.Lagrange[i], e)
			}
		}
		type selectedKey struct {
			slot  CoeffSlot
			power uint8
		}
		selectedCache := make(map[selectedKey]kf.Elem, len(relation.Payload.SBoxInputSlots)*2+64)
		selected := func(slot CoeffSlot, power uint8) (kf.Elem, error) {
			key := selectedKey{slot: slot, power: power}
			if value, ok := selectedCache[key]; ok {
				return value, nil
			}
			if slot.Row < 0 || slot.Row >= len(rows) || slot.Coeff < 0 || slot.Coeff >= len(lagrangeValues) {
				return kf.Elem{}, fmt.Errorf("PRF K slot %+v outside replay rows/width=%d/%d", slot, len(rows), len(lagrangeValues))
			}
			powered, err := powKV3(K, rows[slot.Row], power)
			if err != nil {
				return kf.Elem{}, err
			}
			var value kf.Elem
			if embeddedPoint {
				value = scaleKElemByFqV3(K, powered, lagrangeValues[slot.Coeff].Limb[0])
			} else {
				value = K.Mul(lagrangeValues[slot.Coeff], powered)
			}
			selectedCache[key] = value
			return value, nil
		}

		type refKey struct {
			ref   prf.InputTraceV3Ref
			power uint8
		}
		refCache := make(map[refKey]kf.Elem, relation.IR.SBoxCount*2+relation.IR.KeyCount+relation.IR.NonceCount+2*relation.IR.TagCount)
		var resolve func(prf.InputTraceV3Ref, uint8) (kf.Elem, error)
		resolve = func(ref prf.InputTraceV3Ref, power uint8) (kf.Elem, error) {
			key := refKey{ref: ref, power: power}
			if value, ok := refCache[key]; ok {
				return value, nil
			}
			value := K.Zero()
			switch ref.Kind {
			case prf.InputTraceV3Key:
				if ref.Index < 0 || ref.Index >= relation.IR.KeyCount || power != 1 {
					return kf.Elem{}, fmt.Errorf("invalid K key ref/power=%d/%d", ref.Index, power)
				}
				pow, constant := uint64(1), uint64(0)
				for digit := 0; digit < credential.IntGenISISPRFSeedDigitsPerLane; digit++ {
					source, err := selected(relation.KeySourceSlots[ref.Index*credential.IntGenISISPRFSeedDigitsPerLane+digit], 1)
					if err != nil {
						return kf.Elem{}, err
					}
					addScaledKElemByFqV3(K, &value, source, pow)
					constant = modAdd(constant, modMul(uint64(credential.IntGenISISPRFSeedBound), pow, relation.Q), relation.Q)
					pow = modMul(pow, uint64(credential.IntGenISISPRFSeedPackBase), relation.Q)
				}
				addScaledKElemByFqV3(K, &value, lagrangeValues[0], constant)
			case prf.InputTraceV3Nonce:
				if power != 1 || ref.Index < 0 || ref.Index >= relation.IR.NonceCount {
					return kf.Elem{}, fmt.Errorf("invalid K nonce ref/power=%d/%d", ref.Index, power)
				}
				if ref.Index < len(relation.Context) {
					value = scaleKElemByFqV3(K, lagrangeValues[0], relation.Context[ref.Index])
					break
				}
				if ref.Index != len(relation.Context) {
					return kf.Elem{}, fmt.Errorf("unsupported hidden K nonce ref %d", ref.Index)
				}
				for bit, slot := range relation.BooleanBitSlots {
					bitValue, err := selected(slot, 1)
					if err != nil {
						return kf.Elem{}, err
					}
					addScaledKElemByFqV3(K, &value, bitValue, uint64(1<<bit))
				}
			case prf.InputTraceV3SBoxInput:
				if ref.Index < 0 || ref.Index >= len(relation.Payload.SBoxInputSlots) {
					return kf.Elem{}, fmt.Errorf("K S-box ref %d out of range", ref.Index)
				}
				var err error
				value, err = selected(relation.Payload.SBoxInputSlots[ref.Index], power)
				if err != nil {
					return kf.Elem{}, err
				}
			case prf.InputTraceV3FinalTagState:
				if ref.Index < 4 || ref.Index >= relation.IR.TagCount || power != 1 {
					return kf.Elem{}, fmt.Errorf("invalid K retained terminal ref/power=%d/%d", ref.Index, power)
				}
				var err error
				value, err = selected(relation.Payload.FinalTagSlots[ref.Index-4], 1)
				if err != nil {
					return kf.Elem{}, err
				}
			case prf.InputTraceV3PublicTag:
				if ref.Index < 0 || ref.Index >= len(relation.Tag) || power != 1 {
					return kf.Elem{}, fmt.Errorf("invalid K public tag ref/power=%d/%d", ref.Index, power)
				}
				value = scaleKElemByFqV3(K, lagrangeValues[0], relation.Tag[ref.Index])
			default:
				return kf.Elem{}, fmt.Errorf("unsupported PRF K ref kind %d", ref.Kind)
			}
			refCache[key] = value
			return value, nil
		}

		fagg := make([]kf.Elem, 0, len(relation.BooleanBitSlots)+len(relation.Constraints))
		for _, slot := range relation.BooleanBitSlots {
			square, err := selected(slot, 2)
			if err != nil {
				return nil, nil, err
			}
			linear, err := selected(slot, 1)
			if err != nil {
				return nil, nil, err
			}
			fagg = append(fagg, K.Sub(square, linear))
		}
		for _, constraint := range relation.Constraints {
			acc := scaleKElemByFqV3(K, lagrangeValues[0], uint64(constraint.Constant))
			for _, term := range constraint.Terms {
				value, err := resolve(term.Ref, term.Power)
				if err != nil {
					return nil, nil, fmt.Errorf("%s: %w", constraint.Label, err)
				}
				addScaledKElemByFqV3(K, &acc, value, uint64(term.Coeff))
			}
			fagg = append(fagg, acc)
		}
		return nil, fagg, nil
	}, nil
}
