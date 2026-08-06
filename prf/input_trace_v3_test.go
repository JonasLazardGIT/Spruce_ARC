package prf

import "testing"

func inputTraceV3Fixture(t *testing.T, paramsFile string) (*Params, []Elem, []Elem, Elem, [4]Elem, []Elem, *InputTraceV3, *InputTraceV3IR) {
	t.Helper()
	params, err := LoadBundledParams(paramsFile)
	if err != nil {
		t.Fatalf("load %s: %v", paramsFile, err)
	}
	key := make([]Elem, params.LenKey)
	for i := range key {
		key[i] = Elem((17 + 29*i) % int(params.Q))
	}
	context := make([]Elem, ContextLaneCountV2)
	for i := range context {
		context[i] = Elem((101 + 37*i) % int(params.Q))
	}
	slot := Elem(11)
	bits := [4]Elem{1, 1, 0, 1}
	tag, err := TagContextSlot(key, context, slot, params)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	trace, err := TraceInputWitnessContextSlotV3(key, context, slot, params)
	if err != nil {
		t.Fatalf("input trace: %v", err)
	}
	ir, err := BuildInputTraceV3IR(params)
	if err != nil {
		t.Fatalf("build IR: %v", err)
	}
	return params, key, context, slot, bits, tag, trace, ir
}

func requireAllInputTraceV3ResidualsZero(t *testing.T, residuals []Elem) {
	t.Helper()
	for i, value := range residuals {
		if value != 0 {
			t.Fatalf("residual[%d]=%d want 0", i, value)
		}
	}
}

func requireSomeInputTraceV3ResidualNonzero(t *testing.T, residuals []Elem, label string) {
	t.Helper()
	for _, value := range residuals {
		if value != 0 {
			return
		}
	}
	t.Fatalf("%s tamper left every residual zero", label)
}

func cloneInputTraceV3(src *InputTraceV3) *InputTraceV3 {
	if src == nil {
		return nil
	}
	out := &InputTraceV3{
		SBoxInputs:    append([]InputTraceSBoxV3(nil), src.SBoxInputs...),
		FinalTagState: append([]Elem(nil), src.FinalTagState...),
	}
	return out
}

func TestInputTraceV3GeometryAndOutputTraceEquivalence(t *testing.T) {
	for _, tc := range []struct {
		file        string
		wantTag     int
		wantPayload int
	}{
		{"prf_params_tag10.json", 10, 189},
		{"prf_params_tag13.json", 13, 192},
	} {
		t.Run(tc.file, func(t *testing.T) {
			params, key, context, slot, bits, tag, trace, ir := inputTraceV3Fixture(t, tc.file)
			if got := len(trace.SBoxInputs); got != 179 {
				t.Fatalf("S-box inputs=%d want 179", got)
			}
			if got := len(trace.FinalTagState); got != tc.wantTag {
				t.Fatalf("final tag state=%d want %d", got, tc.wantTag)
			}
			if ir.RelationVersion != InputTraceRelationVersionV3 || ir.SBoxCount != 179 || ir.TagCount != tc.wantTag || ir.PayloadScalars != tc.wantPayload {
				t.Fatalf("IR geometry version/count/tag/payload=%d/%d/%d/%d", ir.RelationVersion, ir.SBoxCount, ir.TagCount, ir.PayloadScalars)
			}
			if got := len(ir.Constraints); got != 179+2*tc.wantTag {
				t.Fatalf("constraints=%d want %d", got, 179+2*tc.wantTag)
			}
			residuals, err := ir.EvaluateContextSlot(key, context, slot, bits, trace, tag)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			requireAllInputTraceV3ResidualsZero(t, residuals)

			grouped, err := TraceGroupedWitnessContextSlot(key, context, slot, params, 2)
			if err != nil {
				t.Fatalf("legacy output trace: %v", err)
			}
			if len(grouped.FinalTagState) != len(trace.FinalTagState) {
				t.Fatalf("legacy/input final tag widths=%d/%d", len(grouped.FinalTagState), len(trace.FinalTagState))
			}
			for i := range trace.FinalTagState {
				if grouped.FinalTagState[i] != trace.FinalTagState[i] {
					t.Fatalf("final state lane %d input/output trace=%d/%d", i, trace.FinalTagState[i], grouped.FinalTagState[i])
				}
			}
		})
	}
}

func TestInputTraceV3FixedPoseidonReferenceVector(t *testing.T) {
	_, _, _, _, _, _, trace, _ := inputTraceV3Fixture(t, "prf_params_tag13.json")
	wantFirst := []InputTraceSBoxV3{
		{Round: 0, Lane: 0, Input: 966547},
		{Round: 0, Lane: 1, Input: 257162},
		{Round: 0, Lane: 2, Input: 423336},
		{Round: 0, Lane: 3, Input: 618756},
		{Round: 0, Lane: 4, Input: 982992},
		{Round: 0, Lane: 5, Input: 937773},
		{Round: 0, Lane: 6, Input: 521999},
		{Round: 0, Lane: 7, Input: 680266},
	}
	wantLast := []InputTraceSBoxV3{
		{Round: 26, Lane: 12, Input: 181280},
		{Round: 26, Lane: 13, Input: 608983},
		{Round: 26, Lane: 14, Input: 952597},
		{Round: 26, Lane: 15, Input: 352629},
		{Round: 26, Lane: 16, Input: 682099},
		{Round: 26, Lane: 17, Input: 367654},
		{Round: 26, Lane: 18, Input: 340624},
		{Round: 26, Lane: 19, Input: 96931},
	}
	wantFinal := []Elem{759741, 176852, 145942, 797732, 962470, 23293, 330373, 308548, 140777, 285746, 606675, 355491, 452699}
	for i := range wantFirst {
		if trace.SBoxInputs[i] != wantFirst[i] {
			t.Fatalf("first reference[%d]=%+v want %+v", i, trace.SBoxInputs[i], wantFirst[i])
		}
	}
	for i := range wantLast {
		got := trace.SBoxInputs[len(trace.SBoxInputs)-len(wantLast)+i]
		if got != wantLast[i] {
			t.Fatalf("last reference[%d]=%+v want %+v", i, got, wantLast[i])
		}
	}
	for i := range wantFinal {
		if trace.FinalTagState[i] != wantFinal[i] {
			t.Fatalf("final reference[%d]=%d want %d", i, trace.FinalTagState[i], wantFinal[i])
		}
	}
}

func TestInputTraceV3BindsEveryReusedSource(t *testing.T) {
	params, key, context, slot, bits, tag, trace, ir := inputTraceV3Fixture(t, "prf_params_tag13.json")
	evaluate := func(k, c []Elem, s Elem, b [4]Elem, tr *InputTraceV3, publicTag []Elem) []Elem {
		residuals, err := ir.EvaluateContextSlot(k, c, s, b, tr, publicTag)
		if err != nil {
			t.Fatalf("evaluate tamper: %v", err)
		}
		return residuals
	}
	for i := range key {
		mutated := append([]Elem(nil), key...)
		mutated[i] = Elem((uint64(mutated[i]) + 1) % params.Q)
		requireSomeInputTraceV3ResidualNonzero(t, evaluate(mutated, context, slot, bits, trace, tag), "key")
	}
	for i := range context {
		mutated := append([]Elem(nil), context...)
		mutated[i] = Elem((uint64(mutated[i]) + 1) % params.Q)
		requireSomeInputTraceV3ResidualNonzero(t, evaluate(key, mutated, slot, bits, trace, tag), "context")
	}
	mutatedSlot := Elem((uint64(slot) + 1) % params.Q)
	requireSomeInputTraceV3ResidualNonzero(t, evaluate(key, context, mutatedSlot, bits, trace, tag), "slot")
	for i := range bits {
		mutated := bits
		mutated[i] ^= 1
		requireSomeInputTraceV3ResidualNonzero(t, evaluate(key, context, slot, mutated, trace, tag), "slot bit")
	}
	for i := range tag {
		mutated := append([]Elem(nil), tag...)
		mutated[i] = Elem((uint64(mutated[i]) + 1) % params.Q)
		requireSomeInputTraceV3ResidualNonzero(t, evaluate(key, context, slot, bits, trace, mutated), "public tag")
	}
}

func TestInputTraceV3BindsEveryCommittedPayloadScalar(t *testing.T) {
	params, key, context, slot, bits, tag, trace, ir := inputTraceV3Fixture(t, "prf_params_tag10.json")
	for i := range trace.SBoxInputs {
		mutated := cloneInputTraceV3(trace)
		mutated.SBoxInputs[i].Input = Elem((uint64(mutated.SBoxInputs[i].Input) + 1) % params.Q)
		residuals, err := ir.EvaluateContextSlot(key, context, slot, bits, mutated, tag)
		if err != nil {
			t.Fatalf("S-box tamper %d: %v", i, err)
		}
		requireSomeInputTraceV3ResidualNonzero(t, residuals, "S-box input")
	}
	for i := range trace.FinalTagState {
		mutated := cloneInputTraceV3(trace)
		mutated.FinalTagState[i] = Elem((uint64(mutated.FinalTagState[i]) + 1) % params.Q)
		residuals, err := ir.EvaluateContextSlot(key, context, slot, bits, mutated, tag)
		if err != nil {
			t.Fatalf("final-tag tamper %d: %v", i, err)
		}
		requireSomeInputTraceV3ResidualNonzero(t, residuals, "final tag state")
	}
}

func TestInputTraceV3DegreeLemma(t *testing.T) {
	params, _, _, _, _, _, _, ir := inputTraceV3Fixture(t, "prf_params_tag13.json")
	if params.D != 3 || ir.MaxWitnessDegree != 3 {
		t.Fatalf("S-box/IR degrees=%d/%d want 3/3", params.D, ir.MaxWitnessDegree)
	}
	sawCube := false
	for _, constraint := range ir.Constraints {
		for _, term := range constraint.Terms {
			switch term.Power {
			case 1:
			case 3:
				sawCube = true
			default:
				t.Fatalf("constraint %q contains unsupported witness power %d", constraint.Label, term.Power)
			}
		}
	}
	if !sawCube {
		t.Fatal("input-trace IR contains no cubic term")
	}
}

func TestInputTraceV3RejectsNonCanonicalScheduleAndFieldValues(t *testing.T) {
	params, key, context, slot, bits, tag, trace, ir := inputTraceV3Fixture(t, "prf_params_tag10.json")
	mutated := cloneInputTraceV3(trace)
	mutated.SBoxInputs[0].Lane++
	if _, err := ir.EvaluateContextSlot(key, context, slot, bits, mutated, tag); err == nil {
		t.Fatal("noncanonical S-box schedule accepted")
	}
	mutated = cloneInputTraceV3(trace)
	mutated.SBoxInputs[0].Input = Elem(params.Q)
	if _, err := ir.EvaluateContextSlot(key, context, slot, bits, mutated, tag); err == nil {
		t.Fatal("noncanonical S-box field value accepted")
	}
}
