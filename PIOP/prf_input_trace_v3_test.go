package PIOP

import (
	"testing"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func inputTraceV3TestRingAndDomain(t *testing.T) (*ring.Ring, []uint64, *omegaInterpolationPlan) {
	t.Helper()
	const q = uint64(1017857)
	ringQ, err := ring.NewRing(1024, []uint64{q})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	omega := make([]uint64, prfInputTraceV3PackWidth)
	for i := range omega {
		omega[i] = uint64(i + 1)
	}
	interp, err := newOmegaInterpolationPlan(omega, q)
	if err != nil {
		t.Fatalf("interpolation plan: %v", err)
	}
	return ringQ, omega, interp
}

func inputTraceV3TestWitness(t *testing.T, paramsFile string) (*prf.Params, *prf.InputTraceV3, [4]prf.Elem) {
	t.Helper()
	params, err := prf.LoadBundledParams(paramsFile)
	if err != nil {
		t.Fatalf("load params: %v", err)
	}
	key := make([]prf.Elem, params.LenKey)
	context := make([]prf.Elem, prf.ContextLaneCountV2)
	for i := range key {
		key[i] = prf.Elem(11 + i)
	}
	for i := range context {
		context[i] = prf.Elem(101 + 3*i)
	}
	trace, err := prf.TraceInputWitnessContextSlotV3(key, context, 7, params)
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	return params, trace, [4]prf.Elem{1, 1, 1, 0}
}

func TestPackPRFInputTraceV3TargetGeometry(t *testing.T) {
	ringQ, omega, interp := inputTraceV3TestRingAndDomain(t)
	for _, tc := range []struct {
		file        string
		wantLogical int
		wantPadding int
	}{
		{"prf_params_tag9.json", 188, 4},
		{"prf_params_tag10.json", 189, 3},
		{"prf_params_tag13.json", 192, 0},
	} {
		t.Run(tc.file, func(t *testing.T) {
			params, trace, bits := inputTraceV3TestWitness(t, tc.file)
			start := 41
			packed, err := packCanonicalPRFInputTraceV3Rows(ringQ, start, trace, bits, func(head []uint64) *ring.Poly {
				return interp.coeffPolyFromHead(ringQ, head)
			})
			if err != nil {
				t.Fatalf("pack: %v", err)
			}
			layout := packed.Layout
			if layout.RelationVersion != 3 || layout.PackedRows != 6 || len(packed.Rows) != 6 || layout.LogicalScalars != tc.wantLogical || layout.PaddingScalars != tc.wantPadding {
				t.Fatalf("layout version/rows/logical/padding=%d/%d/%d/%d", layout.RelationVersion, layout.PackedRows, layout.LogicalScalars, layout.PaddingScalars)
			}
			if layout.BridgeMatrices != 0 {
				t.Fatalf("v3 bridge matrices=%d want 0", layout.BridgeMatrices)
			}
			if err := validatePRFInputTraceV3Layout(layout, params.LenTag, start+len(packed.Rows)); err != nil {
				t.Fatalf("validate layout: %v", err)
			}
			heads := make([][]uint64, len(packed.Rows))
			for i, row := range packed.Rows {
				heads[i], err = rowHeadOnOmega(ringQ, omega, row.Poly, len(omega))
				if err != nil {
					t.Fatalf("row %d head: %v", i, err)
				}
				if len(row.Head) != len(heads[i]) {
					t.Fatalf("row %d retained head width=%d want %d", i, len(row.Head), len(heads[i]))
				}
				for j := range row.Head {
					if row.Head[j] != heads[i][j] {
						t.Fatalf("row %d retained head[%d]=%d want independent polynomial evaluation %d", i, j, row.Head[j], heads[i][j])
					}
				}
			}
			for i, slot := range layout.SBoxInputSlots {
				got := heads[slot.Row-start][slot.Coeff]
				if got != uint64(trace.SBoxInputs[i].Input) {
					t.Fatalf("S-box slot %d=%d want %d", i, got, trace.SBoxInputs[i].Input)
				}
			}
			for i, slot := range layout.HiddenSlotBits {
				got := heads[slot.Row-start][slot.Coeff]
				if got != uint64(bits[i]) {
					t.Fatalf("hidden-bit slot %d=%d want %d", i, got, bits[i])
				}
			}
			for i, slot := range layout.FinalTagSlots {
				got := heads[slot.Row-start][slot.Coeff]
				lane := layout.FinalTagLanes[i]
				if got != uint64(trace.FinalTagState[lane]) {
					t.Fatalf("final-tag slot %d/lane %d=%d want %d", i, lane, got, trace.FinalTagState[lane])
				}
			}
			for i := layout.LogicalScalars; i < layout.PackedRows*layout.PackWidth; i++ {
				if got := heads[i/layout.PackWidth][i%layout.PackWidth]; got != 0 {
					t.Fatalf("padding scalar %d=%d want zero", i, got)
				}
			}
		})
	}
}

func TestPRFInputTraceV3LayoutRejectsDuplicateOrBridgeMetadata(t *testing.T) {
	ringQ, _, interp := inputTraceV3TestRingAndDomain(t)
	params, trace, bits := inputTraceV3TestWitness(t, "prf_params_tag10.json")
	packed, err := packCanonicalPRFInputTraceV3Rows(ringQ, 0, trace, bits, func(head []uint64) *ring.Poly {
		return interp.coeffPolyFromHead(ringQ, head)
	})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	mutated := clonePRFInputTraceV3Layout(packed.Layout)
	mutated.SBoxInputSlots[1] = mutated.SBoxInputSlots[0]
	if err := validatePRFInputTraceV3Layout(mutated, params.LenTag, len(packed.Rows)); err == nil {
		t.Fatal("duplicate input slot accepted")
	}
	mutated = clonePRFInputTraceV3Layout(packed.Layout)
	mutated.BridgeMatrices = 6
	if err := validatePRFInputTraceV3Layout(mutated, params.LenTag, len(packed.Rows)); err == nil {
		t.Fatal("legacy six-matrix bridge metadata accepted")
	}
	mutated = clonePRFInputTraceV3Layout(packed.Layout)
	mutated.HiddenSlotBits[1] = mutated.HiddenSlotBits[0]
	if err := validatePRFInputTraceV3Layout(mutated, params.LenTag, len(packed.Rows)); err == nil {
		t.Fatal("duplicate hidden-bit slot accepted")
	}
	mutated = clonePRFInputTraceV3Layout(packed.Layout)
	mutated.FinalTagLanes[0] = 0
	if err := validatePRFInputTraceV3Layout(mutated, params.LenTag, len(packed.Rows)); err == nil {
		t.Fatal("noncanonical omitted final-tag lane accepted")
	}
}

func TestSelectorWeightedCubeV3UsesLTimesPCubed(t *testing.T) {
	const q = uint64(1017857)
	omega := []uint64{2, 3, 5, 7}
	values := []uint64{9, 13, 21, 34}
	row := Interpolate(omega, values, q)
	selectors := make([][]uint64, len(omega))
	for i := range omega {
		delta := make([]uint64, len(omega))
		delta[i] = 1
		selectors[i] = Interpolate(omega, delta, q)
		got, err := selectorWeightedCubeFormalCoeffV3(selectors[i], row, q, 1024)
		if err != nil {
			t.Fatalf("selector %d: %v", i, err)
		}
		for j, x := range omega {
			want := uint64(0)
			if i == j {
				want = powMod(values[j], 3, q)
			}
			if value := EvalPoly(got, x, q); value != want {
				t.Fatalf("selector=%d point=%d value=%d want %d", i, j, value, want)
			}
		}
	}
	correct, err := selectorWeightedCubeFormalCoeffV3(selectors[0], row, q, 1024)
	if err != nil {
		t.Fatal(err)
	}
	selected := polyMul(selectors[0], row, q)
	wrong := reducePolyModXN1(polyMul(polyMul(selected, selected, q), selected, q), 1024, q)
	differentOffSupport := false
	for x := uint64(8); x < 40; x++ {
		if EvalPoly(correct, x, q) != EvalPoly(wrong, x, q) {
			differentOffSupport = true
			break
		}
	}
	if !differentOffSupport {
		t.Fatal("L*P^3 unexpectedly matched (L*P)^3 away from the support")
	}
}

func TestInputTraceV3CompilerDegreeEnvelopeTargets(t *testing.T) {
	bq := deriveInputTraceV3DegreeEnvelope(9, 8)
	if bq.PRFDegree != 3 || bq.CarrierDegree != 9 || bq.ParallelDegree != 9 || bq.AggregatedDegree != 8 {
		t.Fatalf("BQ degree envelope=%+v want (3,9,9,8)", bq)
	}
	wf := deriveInputTraceV3DegreeEnvelope(11, 8)
	if wf.PRFDegree != 3 || wf.CarrierDegree != 9 || wf.ParallelDegree != 11 || wf.AggregatedDegree != 8 {
		t.Fatalf("WF degree envelope=%+v want (3,9,11,8)", wf)
	}
}

func TestPackTernarySourceRowsV3Reduces96To48(t *testing.T) {
	ringQ, omega, interp := inputTraceV3TestRingAndDomain(t)
	q := ringQ.Modulus[0]
	sources := make([]intGenISISRowMaterial, 96)
	for row := range sources {
		head := make([]uint64, len(omega))
		for col := range head {
			value := int64((row+col)%3) - 1
			head[col] = liftToField(q, value)
		}
		sources[row] = intGenISISRowMaterial{Head: head, Poly: interp.coeffPolyFromHead(ringQ, head)}
	}
	carriers, layout, err := packTernarySourceRowsV3(ringQ, omega, sources, interp, func(head []uint64) *ring.Poly {
		return interp.coeffPolyFromHead(ringQ, head)
	})
	if err != nil {
		t.Fatalf("pack ternary sources: %v", err)
	}
	if layout.SourceRows != 96 || layout.CarrierRows != 48 || len(carriers) != 48 || layout.PackWidth != 2 || layout.DecodeDegree != 8 || layout.MembershipDegree != 9 {
		t.Fatalf("ternary source geometry=%+v rows=%d", layout, len(carriers))
	}
	for carrier := range carriers {
		for col, code := range carriers[carrier].Head {
			a, b, err := decodeTernaryCarrierV3(code)
			if err != nil {
				t.Fatalf("decode carrier=%d col=%d: %v", carrier, col, err)
			}
			wantA := centeredLift(sources[2*carrier].Head[col], q)
			wantB := centeredLift(sources[2*carrier+1].Head[col], q)
			if a != wantA || b != wantB {
				t.Fatalf("carrier=%d col=%d decoded=(%d,%d) want=(%d,%d)", carrier, col, a, b, wantA, wantB)
			}
		}
	}
}
