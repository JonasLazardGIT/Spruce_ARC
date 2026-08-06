package PIOP

import (
	"sync"
	"testing"

	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func semanticQScratchTestPlan(t *testing.T) (semanticQBuildV3Input, *semanticQDirectPlanV3) {
	t.Helper()
	const q = uint64(1017857)
	ringQ, err := ring.NewRing(16, []uint64{q})
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := kf.LookupSmallWoodFieldProfileV3(q, 7)
	if !ok {
		t.Fatal("missing theta=7 test profile")
	}
	omega := []uint64{1, 2}
	K, extra, err := profile.Validate(omega)
	if err != nil {
		t.Fatal(err)
	}
	muInv, err := smallFieldMuDenomInv(K, omega, extra)
	if err != nil {
		t.Fatal(err)
	}
	logical := []lvcs.RowInput{
		{Head: []uint64{2, 3}},
		{Head: []uint64{4, 5}},
		{Head: []uint64{6, 7}},
	}
	mask := newZeroKPoly(K.Theta, 9)
	mask.Degree = 8
	for limb := 0; limb < K.Theta; limb++ {
		for degree := 0; degree <= mask.Degree; degree++ {
			mask.Limbs[limb][degree] = uint64(1 + limb + 3*degree)
		}
	}
	pcs, err := buildSmallFieldPCSRowsFromLiteralInputsV3(ringQ, omega, 4, 2, K, extra, logical, []*KPoly{mask}, 8)
	if err != nil {
		t.Fatal(err)
	}
	physical := make([][]uint64, len(pcs.RowInputs))
	for i := range pcs.RowInputs {
		physical[i] = append([]uint64(nil), pcs.RowInputs[i].Head...)
	}
	one := K.One()
	in := semanticQBuildV3Input{
		Ring:                ringQ,
		K:                   K,
		OmegaWitness:        omega,
		OmegaExtra:          extra,
		MuInv:               muInv,
		PhysicalRows:        physical,
		ReplayWitnessRows:   pcs.PCSGeometry.ReplayWitnessRows,
		LogicalWitnessCount: len(logical),
		MaskRowOffset:       pcs.MaskRowOffset,
		MaskRowCount:        pcs.MaskRowCount,
		MaskDegreeBound:     8,
		DegreeBound:         8,
		Eval: func(_ kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
			return rows[:1], rows[1:2], nil
		},
		GammaPrimeK: [][][]KScalar{{{KScalar(append([]uint64(nil), one.Limb...))}}},
		GammaAggK:   [][]KScalar{{KScalar(append([]uint64(nil), one.Limb...))}},
	}
	plan, err := newSemanticQDirectPlanV3(in)
	if err != nil {
		t.Fatal(err)
	}
	return in, plan
}

// semanticEq4InputsThroughVTargetsV3 is the intentionally expensive reference
// decoder used before semantic-Q v3 switched to direct interpolation. Keeping
// it in tests pins the optimized path to the authenticated-query semantics.
func semanticEq4InputsThroughVTargetsV3(
	t *testing.T,
	in semanticQBuildV3Input,
	e kf.Elem,
) ([]kf.Elem, kf.Elem) {
	t.Helper()
	witnessQueries := buildKPointCoeffMatrix(
		in.Ring,
		in.K,
		in.OmegaWitness,
		in.PhysicalRows,
		e,
		in.OmegaExtra,
		in.MuInv,
		in.ReplayWitnessRows,
		in.MaskRowOffset,
		in.MaskRowCount,
	)
	shape, err := deriveSmallFieldMaskShapeV3(in.MaskDegreeBound, len(in.PhysicalRows[0]), in.K.Theta)
	if err != nil {
		t.Fatal(err)
	}
	maskQueries, err := smallFieldMaskEvalQueryRowsV3(in.K, e, len(in.PhysicalRows), in.MaskRowOffset, shape)
	if err != nil {
		t.Fatal(err)
	}
	queries := make([][]uint64, 0, len(witnessQueries)+len(maskQueries))
	queries = append(queries, witnessQueries...)
	queries = append(queries, maskQueries...)
	vTargets := computeVTargets(in.K.Q, in.PhysicalRows, queries)
	rows, err := buildRowValsFromVTargets(in.K, vTargets, 0, 1, in.LogicalWitnessCount)
	if err != nil {
		t.Fatal(err)
	}
	mask, err := smallFieldMaskEvalFromVTargetsV3(in.K, e, vTargets, len(witnessQueries), shape)
	if err != nil {
		t.Fatal(err)
	}
	return rows, mask
}

func TestBuildSemanticQKV3MatchesRelationAtIndependentKPoint(t *testing.T) {
	const q = uint64(1017857)
	ringQ, err := ring.NewRing(16, []uint64{q})
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := kf.LookupSmallWoodFieldProfileV3(q, 7)
	if !ok {
		t.Fatal("missing theta=7 test profile")
	}
	omega := []uint64{1, 2}
	K, extra, err := profile.Validate(omega)
	if err != nil {
		t.Fatal(err)
	}
	muInv, err := smallFieldMuDenomInv(K, omega, extra)
	if err != nil {
		t.Fatal(err)
	}
	logical := []lvcs.RowInput{
		{Head: []uint64{2, 3}},
		{Head: []uint64{4, 5}},
		{Head: []uint64{6, 7}},
	}
	mask := newZeroKPoly(K.Theta, 9)
	mask.Degree = 8
	for limb := 0; limb < K.Theta; limb++ {
		for d := 0; d <= mask.Degree; d++ {
			mask.Limbs[limb][d] = uint64(1 + limb + 3*d)
		}
	}
	pcs, err := buildSmallFieldPCSRowsFromLiteralInputsV3(
		ringQ, omega, 4, 2, K, extra, logical, []*KPoly{mask}, 8,
	)
	if err != nil {
		t.Fatal(err)
	}
	physical := make([][]uint64, len(pcs.RowInputs))
	for i := range pcs.RowInputs {
		physical[i] = append([]uint64(nil), pcs.RowInputs[i].Head...)
	}
	one := K.One()
	two := K.EmbedF(2)
	eval := func(_ kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		parallel := K.Add(K.Mul(rows[0], rows[1]), rows[2])
		aggregate := K.Mul(rows[1], rows[1])
		return []kf.Elem{parallel}, []kf.Elem{aggregate}, nil
	}
	in := semanticQBuildV3Input{
		Ring:                ringQ,
		K:                   K,
		OmegaWitness:        omega,
		OmegaExtra:          extra,
		MuInv:               muInv,
		PhysicalRows:        physical,
		ReplayWitnessRows:   pcs.PCSGeometry.ReplayWitnessRows,
		LogicalWitnessCount: len(logical),
		MaskRowOffset:       pcs.MaskRowOffset,
		MaskRowCount:        pcs.MaskRowCount,
		MaskDegreeBound:     8,
		DegreeBound:         8,
		Eval:                eval,
		GammaPrimeK: [][][]KScalar{{{
			KScalar(append([]uint64(nil), one.Limb...)),
			KScalar(append([]uint64(nil), two.Limb...)),
		}}},
		GammaAggK: [][]KScalar{{KScalar(append([]uint64(nil), one.Limb...))}},
	}
	plan, err := newSemanticQDirectPlanV3(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, point := range map[string]kf.Elem{
		"embedded-base": K.EmbedF(37),
		"general-K":     K.Phi([]uint64{19, 1, 2, 3, 4, 5, 6}),
	} {
		t.Run("direct-decoding-equals-VTargets/"+name, func(t *testing.T) {
			wantRows, wantMask := semanticEq4InputsThroughVTargetsV3(t, in, point)
			gotRows, err := plan.witnessValues(point)
			if err != nil {
				t.Fatal(err)
			}
			if len(gotRows) != len(wantRows) {
				t.Fatalf("row count=%d want %d", len(gotRows), len(wantRows))
			}
			for i := range gotRows {
				if !elemEqual(K, gotRows[i], wantRows[i]) {
					t.Fatalf("logical row %d differs from VTargets reference", i)
				}
			}
			gotMask, err := plan.maskValue(point)
			if err != nil {
				t.Fatal(err)
			}
			if !elemEqual(K, gotMask, wantMask) {
				t.Fatal("mask evaluation differs from VTargets reference")
			}
		})
	}
	qPolys, err := buildSemanticQKV3(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(qPolys) != 1 || qPolys[0].Degree > in.DegreeBound {
		t.Fatalf("unexpected Q geometry: %#v", qPolys)
	}
	point := K.Phi([]uint64{19, 1, 2, 3, 4, 5, 6})
	want, err := semanticEq4ValuesV3(in, point)
	if err != nil {
		t.Fatal(err)
	}
	var got kf.Elem
	evalKPolyAtKInto(K, &got, qPolys[0], point)
	if !elemEqual(K, got, want[0]) {
		t.Fatal("semantic Q disagrees with relation at independent K point")
	}

	tampered := in
	tampered.PhysicalRows = copyMatrix(in.PhysicalRows)
	tampered.PhysicalRows[pcs.MaskRowOffset][0] = (tampered.PhysicalRows[pcs.MaskRowOffset][0] + 1) % q
	changed, err := semanticEq4ValuesV3(tampered, point)
	if err != nil {
		t.Fatal(err)
	}
	if elemEqual(K, changed[0], want[0]) {
		t.Fatal("mask-row tampering did not change semantic Eq. (4)")
	}
}

func TestSemanticQEmbeddedPointScratchDoesNotAllocate(t *testing.T) {
	in, plan := semanticQScratchTestPlan(t)
	scratch := newSemanticQPointScratchV3(plan, 1)
	in.K.EmbedFInto(&scratch.point, 37)

	if allocs := testing.AllocsPerRun(1000, func() {
		if err := plan.witnessValuesInto(scratch.rowValues, scratch.point, scratch); err != nil {
			panic(err)
		}
		if err := plan.maskValueInto(&scratch.mask, scratch.point, scratch); err != nil {
			panic(err)
		}
	}); allocs != 0 {
		t.Fatalf("direct embedded witness/mask evaluation allocates %.2f objects/run", allocs)
	}

	want, err := semanticEq4ValuesWithPlanV3(in, plan, scratch.point)
	if err != nil {
		t.Fatal(err)
	}
	got, err := semanticEq4ValuesWithPlanIntoV3(in, plan, scratch.point, scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || !elemEqual(in.K, got[0], want[0]) {
		t.Fatal("scratch Eq. (4) output differs from allocating wrapper")
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		if _, evalErr := semanticEq4ValuesWithPlanIntoV3(in, plan, scratch.point, scratch); evalErr != nil {
			panic(evalErr)
		}
	}); allocs != 0 {
		t.Fatalf("scratch Eq. (4) shell allocates %.2f objects/run", allocs)
	}
}

func TestSemanticQPointScratchIsWorkerLocal(t *testing.T) {
	in, plan := semanticQScratchTestPlan(t)
	const workers = 8
	want := make([]kf.Elem, workers)
	for i := 0; i < workers; i++ {
		values, err := semanticEq4ValuesWithPlanV3(in, plan, in.K.EmbedF(uint64(17+i)))
		if err != nil {
			t.Fatal(err)
		}
		want[i] = in.K.Normalize(values[0])
	}

	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			scratch := newSemanticQPointScratchV3(plan, 1)
			for iteration := 0; iteration < 20; iteration++ {
				in.K.EmbedFInto(&scratch.point, uint64(17+worker))
				got, err := semanticEq4ValuesWithPlanIntoV3(in, plan, scratch.point, scratch)
				if err != nil {
					t.Errorf("worker %d: %v", worker, err)
					return
				}
				if !elemEqual(in.K, got[0], want[worker]) {
					t.Errorf("worker %d iteration %d: scratch result differs", worker, iteration)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestSemanticQPhaseRecorderSplitsPlanEvaluationInterpolationAndAudit(t *testing.T) {
	in, _ := semanticQScratchTestPlan(t)
	in.PhaseRecorder = NewPhaseRecorder()
	in.PhasePrefix = "showing"
	if _, err := buildSemanticQKV3(in); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"showing.semantic_q.plan":          false,
		"showing.semantic_q.evaluation":    false,
		"showing.semantic_q.interpolation": false,
		"showing.semantic_q.audit":         false,
	}
	for _, timing := range in.PhaseRecorder.Snapshot() {
		if _, ok := want[timing.Label]; ok {
			if timing.Milliseconds <= 0 {
				t.Fatalf("phase %s duration=%f", timing.Label, timing.Milliseconds)
			}
			want[timing.Label] = true
		}
	}
	for label, seen := range want {
		if !seen {
			t.Fatalf("missing semantic-Q phase %s", label)
		}
	}
}

func TestShowingBridgeKFactoringPreservesGeneralAndEmbeddedSemantics(t *testing.T) {
	const q = uint64(1017857)
	profile, ok := kf.LookupSmallWoodFieldProfileV3(q, 7)
	if !ok {
		t.Fatal("missing theta=7 test profile")
	}
	K, _, err := profile.Validate([]uint64{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	transform := []uint64{3, 5, 7, 11}
	lagrange := []uint64{13, 17, 19}
	factors := []uint64{23, 29, 31}
	sources := []kf.Elem{
		K.Phi([]uint64{2, 3, 5, 7, 11, 13, 17}),
		K.Phi([]uint64{19, 23, 29, 31, 37, 41, 43}),
		K.Phi([]uint64{47, 53, 59, 61, 67, 71, 73}),
	}
	hat := K.Phi([]uint64{79, 83, 89, 97, 101, 103, 107})
	for name, point := range map[string]kf.Elem{
		"embedded-base": K.EmbedF(37),
		"general-K":     K.Phi([]uint64{109, 1, 2, 3, 4, 5, 6}),
	} {
		t.Run(name, func(t *testing.T) {
			h := K.EvalFPolyAtK(transform, point)
			oldLeft := K.Zero()
			for i := range sources {
				oldLeft = K.Add(oldLeft, K.Mul(K.EmbedF(factors[i]), K.Mul(h, sources[i])))
			}
			oldRight := K.Mul(K.EvalFPolyAtK(lagrange, point), hat)
			oldResidual := K.Sub(oldLeft, oldRight)

			weighted := K.Zero()
			for i := range sources {
				K.AddMulBaseInto(&weighted, sources[i], factors[i])
			}
			var newLeft, newRight kf.Elem
			if x, embedded := embeddedFqValueV3(K, point); embedded {
				newLeft = scaleKElemByFqV3(K, weighted, EvalPoly(transform, x, q))
				newRight = scaleKElemByFqV3(K, hat, EvalPoly(lagrange, x, q))
			} else {
				newLeft = K.Mul(h, weighted)
				newRight = K.Mul(K.EvalFPolyAtK(lagrange, point), hat)
			}
			if !elemEqual(K, oldResidual, K.Sub(newLeft, newRight)) {
				t.Fatal("factored bridge equation differs from the unfactored relation")
			}
		})
	}
}
