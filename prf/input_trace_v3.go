package prf

import "fmt"

// InputTraceRelationVersionV3 identifies the input-trace relation used by the
// strict SmallWood v3 showing path.  It is deliberately separate from the
// grouped output/checkpoint witness used by the legacy companion relation.
const InputTraceRelationVersionV3 uint8 = 3

// InputTraceSBoxV3 records the input of one executed Poseidon S-box.  Entries
// are ordered by round, then lane.  A full round contributes T entries and an
// internal round contributes the lane-zero entry.
type InputTraceSBoxV3 struct {
	Round int
	Lane  int
	Input Elem
}

// InputTraceV3 contains only the nonlinear inputs plus the pre-feed-forward
// final tag lanes.  The key, nonce/context, hidden slot, and hidden-slot bits
// remain in their already-authenticated source rows and are not duplicated.
type InputTraceV3 struct {
	SBoxInputs    []InputTraceSBoxV3
	FinalTagState []Elem
}

// InputTraceV3RefKind names a scalar source in the semantic relation IR.
type InputTraceV3RefKind uint8

const (
	InputTraceV3Key InputTraceV3RefKind = iota
	InputTraceV3Nonce
	InputTraceV3SBoxInput
	InputTraceV3FinalTagState
	InputTraceV3PublicTag
)

// InputTraceV3Ref identifies one scalar source.  Index is relative to Kind.
type InputTraceV3Ref struct {
	Kind  InputTraceV3RefKind
	Index int
}

// InputTraceV3Term is coeff*source^power.  The v3 IR only permits powers one
// and three; in particular a selector is never cubed with its source.
type InputTraceV3Term struct {
	Ref   InputTraceV3Ref
	Coeff Elem
	Power uint8
}

// InputTraceV3Constraint is a scalar polynomial that must evaluate to zero.
type InputTraceV3Constraint struct {
	Label    string
	Constant Elem
	Terms    []InputTraceV3Term
}

// InputTraceV3IR is the single semantic description consumed by input-trace
// witness tests and intended for both the v3 formal-Q compiler and verifier
// evaluator.  Its witness-variable degree is three.
type InputTraceV3IR struct {
	Q                uint64
	RelationVersion  uint8
	KeyCount         int
	NonceCount       int
	SBoxCount        int
	TagCount         int
	PayloadScalars   int
	MaxWitnessDegree int
	Constraints      []InputTraceV3Constraint
	Schedule         []InputTraceSBoxV3
}

type inputTraceV3Expr struct {
	constant Elem
	terms    map[inputTraceV3ExprKey]Elem
}

type inputTraceV3ExprKey struct {
	ref   InputTraceV3Ref
	power uint8
}

func inputTraceV3RefExpr(ref InputTraceV3Ref, power uint8) inputTraceV3Expr {
	return inputTraceV3Expr{terms: map[inputTraceV3ExprKey]Elem{{ref: ref, power: power}: 1}}
}

func inputTraceV3ConstExpr(c Elem) inputTraceV3Expr {
	return inputTraceV3Expr{constant: c, terms: make(map[inputTraceV3ExprKey]Elem)}
}

func inputTraceV3CloneExpr(src inputTraceV3Expr) inputTraceV3Expr {
	out := inputTraceV3Expr{constant: src.constant, terms: make(map[inputTraceV3ExprKey]Elem, len(src.terms))}
	for key, value := range src.terms {
		out.terms[key] = value
	}
	return out
}

func inputTraceV3AddExpr(f Field, a, b inputTraceV3Expr) inputTraceV3Expr {
	out := inputTraceV3CloneExpr(a)
	out.constant = f.add(out.constant, b.constant)
	for key, value := range b.terms {
		out.terms[key] = f.add(out.terms[key], value)
		if out.terms[key] == 0 {
			delete(out.terms, key)
		}
	}
	return out
}

func inputTraceV3ScaleExpr(f Field, src inputTraceV3Expr, scalar Elem) inputTraceV3Expr {
	out := inputTraceV3Expr{constant: f.mul(src.constant, scalar), terms: make(map[inputTraceV3ExprKey]Elem, len(src.terms))}
	for key, value := range src.terms {
		if scaled := f.mul(value, scalar); scaled != 0 {
			out.terms[key] = scaled
		}
	}
	return out
}

func inputTraceV3Neg(f Field, value Elem) Elem {
	if value == 0 {
		return 0
	}
	return Elem(f.q - uint64(value))
}

func inputTraceV3ConstraintFromExpr(label string, expr inputTraceV3Expr) InputTraceV3Constraint {
	out := InputTraceV3Constraint{Label: label, Constant: expr.constant, Terms: make([]InputTraceV3Term, 0, len(expr.terms))}
	// Map iteration order does not become transcript state: BuildInputTraceV3IR
	// normalizes the terms before returning.
	for key, coeff := range expr.terms {
		out.Terms = append(out.Terms, InputTraceV3Term{Ref: key.ref, Coeff: coeff, Power: key.power})
	}
	return out
}

func inputTraceV3RefLess(a, b InputTraceV3Term) bool {
	if a.Ref.Kind != b.Ref.Kind {
		return a.Ref.Kind < b.Ref.Kind
	}
	if a.Ref.Index != b.Ref.Index {
		return a.Ref.Index < b.Ref.Index
	}
	return a.Power < b.Power
}

func inputTraceV3SortTerms(terms []InputTraceV3Term) {
	for i := 1; i < len(terms); i++ {
		for j := i; j > 0 && inputTraceV3RefLess(terms[j], terms[j-1]); j-- {
			terms[j], terms[j-1] = terms[j-1], terms[j]
		}
	}
}

// SBoxInputCountV3 returns the exact number of S-box inputs committed by the
// input-trace relation: RF*T + RP.  The shipped T=20, RF=8, RP=19 profiles
// therefore commit 179 inputs.
func SBoxInputCountV3(params *Params) (int, error) {
	if params == nil {
		return 0, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return 0, err
	}
	if params.D != 3 {
		return 0, fmt.Errorf("input-trace v3 requires cubic S-box exponent 3, got %d", params.D)
	}
	return params.RF*params.T() + params.RP, nil
}

// InputTraceScheduleV3 returns the canonical round/lane ordering.
func InputTraceScheduleV3(params *Params) ([]InputTraceSBoxV3, error) {
	count, err := SBoxInputCountV3(params)
	if err != nil {
		return nil, err
	}
	out := make([]InputTraceSBoxV3, 0, count)
	for round := 0; round < params.RF+params.RP; round++ {
		if isFullRound(params, round) {
			for lane := 0; lane < params.T(); lane++ {
				out = append(out, InputTraceSBoxV3{Round: round, Lane: lane})
			}
			continue
		}
		out = append(out, InputTraceSBoxV3{Round: round, Lane: 0})
	}
	if len(out) != count {
		return nil, fmt.Errorf("input-trace schedule=%d want %d", len(out), count)
	}
	return out, nil
}

// TraceInputWitnessV3 constructs the canonical nonlinear-input witness.
func TraceInputWitnessV3(key, nonce []Elem, params *Params) (*InputTraceV3, error) {
	if params == nil {
		return nil, fmt.Errorf("nil params")
	}
	if _, err := SBoxInputCountV3(params); err != nil {
		return nil, err
	}
	state, err := ConcatKeyNonce(key, nonce, params)
	if err != nil {
		return nil, err
	}
	for i, value := range state {
		if uint64(value) >= params.Q {
			return nil, fmt.Errorf("initial state lane %d=%d is not canonical modulo %d", i, value, params.Q)
		}
	}
	f := NewField(params.Q)
	tmp := make([]Elem, params.T())
	next := make([]Elem, params.T())
	count, _ := SBoxInputCountV3(params)
	out := &InputTraceV3{SBoxInputs: make([]InputTraceSBoxV3, 0, count)}
	for round := 0; round < params.RF+params.RP; round++ {
		if isFullRound(params, round) {
			extRound, _ := fullRoundIndex(params, round)
			for lane := 0; lane < params.T(); lane++ {
				in := f.add(state[lane], Elem(params.CExt[extRound][lane]%params.Q))
				out.SBoxInputs = append(out.SBoxInputs, InputTraceSBoxV3{Round: round, Lane: lane, Input: in})
				tmp[lane] = f.mul(f.mul(in, in), in)
			}
			matVec(next, params.ME, tmp, f)
			copy(state, next)
			continue
		}
		internalRound := round - params.RF/2
		in := f.add(state[0], Elem(params.CInt[internalRound]%params.Q))
		out.SBoxInputs = append(out.SBoxInputs, InputTraceSBoxV3{Round: round, Lane: 0, Input: in})
		tmp[0] = f.mul(f.mul(in, in), in)
		copy(tmp[1:], state[1:])
		matVec(next, params.MI, tmp, f)
		copy(state, next)
	}
	out.FinalTagState = append([]Elem(nil), state[:params.LenTag]...)
	if len(out.SBoxInputs) != count {
		return nil, fmt.Errorf("input-trace inputs=%d want %d", len(out.SBoxInputs), count)
	}
	return out, nil
}

// TraceInputWitnessContextSlotV3 keeps the presentation API aligned with the
// existing v2 PRF input convention (eleven public context lanes and one hidden
// slot lane).
func TraceInputWitnessContextSlotV3(key, context []Elem, slot Elem, params *Params) (*InputTraceV3, error) {
	if len(context) != ContextLaneCountV2 {
		return nil, fmt.Errorf("context lanes=%d want %d", len(context), ContextLaneCountV2)
	}
	if params == nil || params.LenNonce != ContextLaneCountV2+1 {
		return nil, fmt.Errorf("input-trace v3 PRF requires %d input lanes", ContextLaneCountV2+1)
	}
	nonce := make([]Elem, 0, params.LenNonce)
	nonce = append(nonce, context...)
	nonce = append(nonce, slot)
	return TraceInputWitnessV3(key, nonce, params)
}

// BuildInputTraceV3IR constructs recurrence constraints from one semantic IR.
// Each nonlinear contribution is source^3 with a linear coefficient.  A
// formal renderer must therefore encode L*P^3, never (L*P)^3.
func BuildInputTraceV3IR(params *Params) (*InputTraceV3IR, error) {
	count, err := SBoxInputCountV3(params)
	if err != nil {
		return nil, err
	}
	f := NewField(params.Q)
	state := make([]inputTraceV3Expr, params.T())
	original := make([]InputTraceV3Ref, params.T())
	for lane := 0; lane < params.T(); lane++ {
		ref := InputTraceV3Ref{Kind: InputTraceV3Nonce, Index: lane - params.LenKey}
		if lane < params.LenKey {
			ref = InputTraceV3Ref{Kind: InputTraceV3Key, Index: lane}
		}
		original[lane] = ref
		state[lane] = inputTraceV3RefExpr(ref, 1)
	}
	constraints := make([]InputTraceV3Constraint, 0, count+2*params.LenTag)
	schedule := make([]InputTraceSBoxV3, 0, count)
	nextInput := 0
	for round := 0; round < params.RF+params.RP; round++ {
		var active []int
		var constants []uint64
		var mds [][]uint64
		if isFullRound(params, round) {
			extRound, _ := fullRoundIndex(params, round)
			active = make([]int, params.T())
			constants = make([]uint64, params.T())
			for lane := range active {
				active[lane] = lane
				constants[lane] = params.CExt[extRound][lane]
			}
			mds = params.ME
		} else {
			internalRound := round - params.RF/2
			active = []int{0}
			constants = []uint64{params.CInt[internalRound]}
			mds = params.MI
		}
		preMDS := make([]inputTraceV3Expr, params.T())
		for lane := range state {
			preMDS[lane] = inputTraceV3CloneExpr(state[lane])
		}
		for pos, lane := range active {
			ref := InputTraceV3Ref{Kind: InputTraceV3SBoxInput, Index: nextInput}
			lhs := inputTraceV3RefExpr(ref, 1)
			lhs = inputTraceV3AddExpr(f, lhs, inputTraceV3ScaleExpr(f, state[lane], inputTraceV3Neg(f, 1)))
			lhs = inputTraceV3AddExpr(f, lhs, inputTraceV3ConstExpr(inputTraceV3Neg(f, Elem(constants[pos]%params.Q))))
			constraints = append(constraints, inputTraceV3ConstraintFromExpr(fmt.Sprintf("sbox_input[%d].r%d.l%d", nextInput, round, lane), lhs))
			schedule = append(schedule, InputTraceSBoxV3{Round: round, Lane: lane})
			preMDS[lane] = inputTraceV3RefExpr(ref, 3)
			nextInput++
		}
		nextState := make([]inputTraceV3Expr, params.T())
		for row := 0; row < params.T(); row++ {
			nextState[row] = inputTraceV3ConstExpr(0)
			for col := 0; col < params.T(); col++ {
				nextState[row] = inputTraceV3AddExpr(f, nextState[row], inputTraceV3ScaleExpr(f, preMDS[col], Elem(mds[row][col]%params.Q)))
			}
		}
		state = nextState
	}
	if nextInput != count {
		return nil, fmt.Errorf("input-trace IR inputs=%d want %d", nextInput, count)
	}
	for lane := 0; lane < params.LenTag; lane++ {
		finalRef := InputTraceV3Ref{Kind: InputTraceV3FinalTagState, Index: lane}
		finalRelation := inputTraceV3RefExpr(finalRef, 1)
		finalRelation = inputTraceV3AddExpr(f, finalRelation, inputTraceV3ScaleExpr(f, state[lane], inputTraceV3Neg(f, 1)))
		constraints = append(constraints, inputTraceV3ConstraintFromExpr(fmt.Sprintf("final_mds[%d]", lane), finalRelation))

		publicRelation := inputTraceV3RefExpr(InputTraceV3Ref{Kind: InputTraceV3PublicTag, Index: lane}, 1)
		publicRelation = inputTraceV3AddExpr(f, publicRelation, inputTraceV3ScaleExpr(f, inputTraceV3RefExpr(finalRef, 1), inputTraceV3Neg(f, 1)))
		publicRelation = inputTraceV3AddExpr(f, publicRelation, inputTraceV3ScaleExpr(f, inputTraceV3RefExpr(original[lane], 1), inputTraceV3Neg(f, 1)))
		constraints = append(constraints, inputTraceV3ConstraintFromExpr(fmt.Sprintf("feed_forward_tag[%d]", lane), publicRelation))
	}
	for i := range constraints {
		inputTraceV3SortTerms(constraints[i].Terms)
	}
	return &InputTraceV3IR{
		Q:                params.Q,
		RelationVersion:  InputTraceRelationVersionV3,
		KeyCount:         params.LenKey,
		NonceCount:       params.LenNonce,
		SBoxCount:        count,
		TagCount:         params.LenTag,
		PayloadScalars:   count + params.LenTag,
		MaxWitnessDegree: 3,
		Constraints:      constraints,
		Schedule:         schedule,
	}, nil
}

func inputTraceV3Pow(f Field, value Elem, power uint8) (Elem, error) {
	switch power {
	case 1:
		return value, nil
	case 3:
		return f.mul(f.mul(value, value), value), nil
	default:
		return 0, fmt.Errorf("unsupported input-trace v3 power %d", power)
	}
}

func (ir *InputTraceV3IR) validateWitnessShape(key, nonce []Elem, trace *InputTraceV3, publicTag []Elem) error {
	if ir == nil {
		return fmt.Errorf("nil input-trace v3 IR")
	}
	if trace == nil {
		return fmt.Errorf("nil input-trace v3 witness")
	}
	if len(key) != ir.KeyCount || len(nonce) != ir.NonceCount {
		return fmt.Errorf("input-trace key/nonce widths=(%d,%d) want (%d,%d)", len(key), len(nonce), ir.KeyCount, ir.NonceCount)
	}
	if len(trace.SBoxInputs) != ir.SBoxCount {
		return fmt.Errorf("input-trace S-box inputs=%d want %d", len(trace.SBoxInputs), ir.SBoxCount)
	}
	if len(trace.FinalTagState) != ir.TagCount || len(publicTag) != ir.TagCount {
		return fmt.Errorf("input-trace tag widths=(%d,%d) want %d", len(trace.FinalTagState), len(publicTag), ir.TagCount)
	}
	for i, want := range ir.Schedule {
		got := trace.SBoxInputs[i]
		if got.Round != want.Round || got.Lane != want.Lane {
			return fmt.Errorf("input-trace schedule[%d]=r%d/l%d want r%d/l%d", i, got.Round, got.Lane, want.Round, want.Lane)
		}
	}
	for _, group := range []struct {
		name string
		vals []Elem
	}{{"key", key}, {"nonce", nonce}, {"final_tag_state", trace.FinalTagState}, {"public_tag", publicTag}} {
		for i, value := range group.vals {
			if uint64(value) >= ir.Q {
				return fmt.Errorf("%s[%d]=%d is not canonical modulo %d", group.name, i, value, ir.Q)
			}
		}
	}
	for i, item := range trace.SBoxInputs {
		if uint64(item.Input) >= ir.Q {
			return fmt.Errorf("sbox_input[%d]=%d is not canonical modulo %d", i, item.Input, ir.Q)
		}
	}
	return nil
}

// Evaluate evaluates every semantic constraint.  A valid witness returns an
// all-zero vector.  This method is the reference evaluator for prover/verifier
// relation-replay tests.
func (ir *InputTraceV3IR) Evaluate(key, nonce []Elem, trace *InputTraceV3, publicTag []Elem) ([]Elem, error) {
	if err := ir.validateWitnessShape(key, nonce, trace, publicTag); err != nil {
		return nil, err
	}
	resolve := func(ref InputTraceV3Ref) (Elem, error) {
		var values []Elem
		switch ref.Kind {
		case InputTraceV3Key:
			values = key
		case InputTraceV3Nonce:
			values = nonce
		case InputTraceV3SBoxInput:
			if ref.Index < 0 || ref.Index >= len(trace.SBoxInputs) {
				return 0, fmt.Errorf("S-box input ref %d out of range", ref.Index)
			}
			return trace.SBoxInputs[ref.Index].Input, nil
		case InputTraceV3FinalTagState:
			values = trace.FinalTagState
		case InputTraceV3PublicTag:
			values = publicTag
		default:
			return 0, fmt.Errorf("unsupported input-trace ref kind %d", ref.Kind)
		}
		if ref.Index < 0 || ref.Index >= len(values) {
			return 0, fmt.Errorf("input-trace ref kind=%d index=%d out of range %d", ref.Kind, ref.Index, len(values))
		}
		return values[ref.Index], nil
	}
	f := NewField(ir.Q)
	out := make([]Elem, len(ir.Constraints))
	for i, constraint := range ir.Constraints {
		acc := constraint.Constant
		for _, term := range constraint.Terms {
			value, err := resolve(term.Ref)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", constraint.Label, err)
			}
			powered, err := inputTraceV3Pow(f, value, term.Power)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", constraint.Label, err)
			}
			acc = f.add(acc, f.mul(term.Coeff, powered))
		}
		out[i] = acc
	}
	return out, nil
}

// EvaluateContextSlot also enforces Boolean hidden-slot bits and their
// recomposition before evaluating the input-trace recurrence.
func (ir *InputTraceV3IR) EvaluateContextSlot(key, context []Elem, slot Elem, bits [4]Elem, trace *InputTraceV3, publicTag []Elem) ([]Elem, error) {
	if len(context) != ContextLaneCountV2 {
		return nil, fmt.Errorf("context lanes=%d want %d", len(context), ContextLaneCountV2)
	}
	if uint64(slot) >= ir.Q {
		return nil, fmt.Errorf("hidden slot=%d is not canonical modulo %d", slot, ir.Q)
	}
	f := NewField(ir.Q)
	residuals := make([]Elem, 0, 5+len(ir.Constraints))
	recomposed := Elem(0)
	weight := Elem(1)
	for i, bit := range bits {
		if uint64(bit) >= ir.Q {
			return nil, fmt.Errorf("hidden bit[%d]=%d is not canonical modulo %d", i, bit, ir.Q)
		}
		residuals = append(residuals, f.mul(bit, f.add(bit, inputTraceV3Neg(f, 1))))
		recomposed = f.add(recomposed, f.mul(weight, bit))
		weight = f.add(weight, weight)
	}
	residuals = append(residuals, f.add(slot, inputTraceV3Neg(f, recomposed)))
	nonce := make([]Elem, 0, ContextLaneCountV2+1)
	nonce = append(nonce, context...)
	nonce = append(nonce, slot)
	core, err := ir.Evaluate(key, nonce, trace, publicTag)
	if err != nil {
		return nil, err
	}
	return append(residuals, core...), nil
}
