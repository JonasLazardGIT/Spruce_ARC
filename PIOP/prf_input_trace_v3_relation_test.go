package PIOP

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type inputTraceV3RelationFixture struct {
	ringQ      *ring.Ring
	omega      []uint64
	interp     *omegaInterpolationPlan
	params     *prf.Params
	context    []int64
	tag        []int64
	rows       []*ring.Poly
	rowsNTT    []*ring.Poly
	layout     *PRFInputTraceV3Layout
	keySources []CoeffSlot
	relation   *prfInputTraceV3Relation
}

func buildInputTraceV3RelationFixture(t *testing.T, paramsFile string) inputTraceV3RelationFixture {
	t.Helper()
	ringQ, omega, interp := inputTraceV3TestRingAndDomain(t)
	params, err := prf.LoadBundledParams(paramsFile)
	if err != nil {
		t.Fatal(err)
	}
	q := ringQ.Modulus[0]
	keySources := make([]CoeffSlot, params.LenKey*credential.IntGenISISPRFSeedDigitsPerLane)
	seedHeads := make([][]uint64, 2)
	for i := range seedHeads {
		seedHeads[i] = make([]uint64, len(omega))
	}
	key := make([]prf.Elem, params.LenKey)
	for lane := 0; lane < params.LenKey; lane++ {
		pow := uint64(1)
		value := uint64(0)
		for digit := 0; digit < credential.IntGenISISPRFSeedDigitsPerLane; digit++ {
			idx := lane*credential.IntGenISISPRFSeedDigitsPerLane + digit
			centered := int64((idx*5)%9) - credential.IntGenISISPRFSeedBound
			slot := CoeffSlot{Row: idx / len(omega), Coeff: idx % len(omega)}
			keySources[idx] = slot
			seedHeads[slot.Row][slot.Coeff] = liftToField(q, centered)
			value = modAdd(value, modMul(uint64(centered+credential.IntGenISISPRFSeedBound), pow, q), q)
			pow = modMul(pow, uint64(credential.IntGenISISPRFSeedPackBase), q)
		}
		key[lane] = prf.Elem(value)
	}
	contextElems := make([]prf.Elem, prf.ContextLaneCountV2)
	context := make([]int64, len(contextElems))
	for i := range contextElems {
		contextElems[i] = prf.Elem(101 + 17*i)
		context[i] = int64(contextElems[i])
	}
	slot := prf.Elem(11)
	bits := [4]prf.Elem{1, 1, 0, 1}
	trace, err := prf.TraceInputWitnessContextSlotV3(key, contextElems, slot, params)
	if err != nil {
		t.Fatal(err)
	}
	tagElems, err := prf.TagContextSlot(key, contextElems, slot, params)
	if err != nil {
		t.Fatal(err)
	}
	tag := make([]int64, len(tagElems))
	for i := range tagElems {
		tag[i] = int64(tagElems[i])
	}
	rows := make([]*ring.Poly, len(seedHeads))
	for i := range seedHeads {
		rows[i] = interp.coeffPolyFromHead(ringQ, seedHeads[i])
	}
	packed, err := packCanonicalPRFInputTraceV3Rows(ringQ, len(rows), trace, bits, func(head []uint64) *ring.Poly {
		return interp.coeffPolyFromHead(ringQ, head)
	})
	if err != nil {
		t.Fatal(err)
	}
	rows = append(rows, intGenISISRowMaterialPolys(packed.Rows)...)
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ringQ.NTT(rows[i], rowsNTT[i])
	}
	relation, err := newPRFInputTraceV3Relation(q, params, packed.Layout, keySources, context, tag, omega, len(rows))
	if err != nil {
		t.Fatal(err)
	}
	return inputTraceV3RelationFixture{ringQ, omega, interp, params, context, tag, rows, rowsNTT, packed.Layout, keySources, relation}
}

func inputTraceV3FormalForFixture(t *testing.T, fixture inputTraceV3RelationFixture) [][]uint64 {
	t.Helper()
	cache, err := newIntGenISISRowCoeffCache(fixture.ringQ, fixture.rowsNTT)
	if err != nil {
		t.Fatal(err)
	}
	_, coeffs, degree, err := fixture.relation.FormalCoeffs(fixture.ringQ, cache)
	if err != nil {
		t.Fatal(err)
	}
	if degree != 3 {
		t.Fatalf("PRF input-trace degree=%d want 3", degree)
	}
	return coeffs
}

func requireInputTraceV3OmegaSums(t *testing.T, fixture inputTraceV3RelationFixture, coeffs [][]uint64, wantNonzero bool) {
	t.Helper()
	q := fixture.ringQ.Modulus[0]
	nonzero := false
	for _, coeff := range coeffs {
		sum := uint64(0)
		for _, x := range fixture.omega {
			sum = modAdd(sum, EvalPoly(coeff, x, q), q)
		}
		if sum != 0 {
			nonzero = true
			break
		}
	}
	if nonzero != wantNonzero {
		t.Fatalf("PRF input-trace aggregate nonzero=%v want %v", nonzero, wantNonzero)
	}
}

func TestPRFInputTraceV3FormalSemanticReplayEquality(t *testing.T) {
	for _, tc := range []struct {
		file  string
		theta int
	}{
		{"prf_params_tag9.json", 7},
		{"prf_params_tag10.json", 13},
		{"prf_params_tag13.json", 7},
	} {
		t.Run(tc.file, func(t *testing.T) {
			fixture := buildInputTraceV3RelationFixture(t, tc.file)
			coeffs := inputTraceV3FormalForFixture(t, fixture)
			if got, want := len(coeffs), 4+179+4+2*(fixture.params.LenTag-4); got != want {
				t.Fatalf("relation families=%d want %d", got, want)
			}
			requireInputTraceV3OmegaSums(t, fixture, coeffs, false)

			domain := []uint64{37, 41, 43, 47}
			eval := fixture.relation.Evaluator(domain)
			q := fixture.ringQ.Modulus[0]
			rowCoeffs := make([][]uint64, len(fixture.rows))
			for i, row := range fixture.rows {
				rowCoeffs[i] = trimPoly(append([]uint64(nil), row.Coeffs[0]...), q)
			}
			for idx, x := range domain {
				rowVals := make([]uint64, len(rowCoeffs))
				for i := range rowCoeffs {
					rowVals[i] = EvalPoly(rowCoeffs[i], x, q)
				}
				_, got, err := eval(uint64(idx), rowVals)
				if err != nil {
					t.Fatal(err)
				}
				for i := range coeffs {
					if want := EvalPoly(coeffs[i], x, q); got[i] != want {
						t.Fatalf("F replay point/family=%d/%d got=%d want=%d", idx, i, got[i], want)
					}
				}
			}

			K, err := kf.NewUnchecked(q, 1, []uint64{1, 1})
			if err != nil {
				t.Fatal(err)
			}
			keval, err := fixture.relation.KEvaluator(K)
			if err != nil {
				t.Fatal(err)
			}
			e := K.EmbedF(53)
			rowValsK := make([]kf.Elem, len(rowCoeffs))
			for i := range rowCoeffs {
				rowValsK[i] = K.EvalFPolyAtK(rowCoeffs[i], e)
			}
			_, gotK, err := keval(e, rowValsK)
			if err != nil {
				t.Fatal(err)
			}
			for i := range coeffs {
				want := K.EvalFPolyAtK(coeffs[i], e)
				if len(gotK[i].Limb) != 1 || gotK[i].Limb[0] != want.Limb[0] {
					t.Fatalf("K replay family=%d got=%v want=%v", i, gotK[i], want)
				}
			}

			// Repeat the equality at the vetted target extension-field point used
			// by the live BQ128/WF128 Q construction, not merely in an embedded
			// degree-one test field.
			targetField, err := deriveSmallFieldParamsNoRowsV3(fixture.ringQ, fixture.omega, tc.theta)
			if err != nil {
				t.Fatal(err)
			}
			targetEval, err := fixture.relation.KEvaluator(targetField.K)
			if err != nil {
				t.Fatal(err)
			}
			rowValsTarget := make([]kf.Elem, len(rowCoeffs))
			for i := range rowCoeffs {
				rowValsTarget[i] = targetField.K.EvalFPolyAtK(rowCoeffs[i], targetField.OmegaS1)
			}
			_, gotTarget, err := targetEval(targetField.OmegaS1, rowValsTarget)
			if err != nil {
				t.Fatal(err)
			}
			for i := range coeffs {
				want := targetField.K.EvalFPolyAtK(coeffs[i], targetField.OmegaS1)
				if !elemEqual(targetField.K, gotTarget[i], want) {
					t.Fatalf("target K(theta=%d) replay family=%d got=%v want=%v", tc.theta, i, gotTarget[i], want)
				}
			}
		})
	}
}

func mutateInputTraceV3FixtureSlot(t *testing.T, fixture inputTraceV3RelationFixture, slot CoeffSlot) inputTraceV3RelationFixture {
	t.Helper()
	q := fixture.ringQ.Modulus[0]
	heads := make([][]uint64, len(fixture.rows))
	rows := make([]*ring.Poly, len(fixture.rows))
	rowsNTT := make([]*ring.Poly, len(fixture.rows))
	for i, row := range fixture.rows {
		var err error
		heads[i], err = rowHeadOnOmega(fixture.ringQ, fixture.omega, row, len(fixture.omega))
		if err != nil {
			t.Fatal(err)
		}
	}
	heads[slot.Row][slot.Coeff] = (heads[slot.Row][slot.Coeff] + 1) % q
	for i := range rows {
		rows[i] = fixture.interp.coeffPolyFromHead(fixture.ringQ, heads[i])
		rowsNTT[i] = fixture.ringQ.NewPoly()
		fixture.ringQ.NTT(rows[i], rowsNTT[i])
	}
	fixture.rows, fixture.rowsNTT = rows, rowsNTT
	return fixture
}

func TestPRFInputTraceV3BindsBitsAndSubstitutedTerminalLanes(t *testing.T) {
	fixture := buildInputTraceV3RelationFixture(t, "prf_params_tag13.json")
	for i, slot := range fixture.layout.HiddenSlotBits {
		mutated := mutateInputTraceV3FixtureSlot(t, fixture, slot)
		requireInputTraceV3OmegaSums(t, mutated, inputTraceV3FormalForFixture(t, mutated), true)
		_ = i
	}
	// The omitted terminal lanes have no witness slots.  Their composed MDS +
	// feed-forward equations must nevertheless bind each public lane directly.
	for lane := 0; lane < 4; lane++ {
		mutated := fixture
		mutated.tag = append([]int64(nil), fixture.tag...)
		mutated.tag[lane] = int64((uint64(mutated.tag[lane]) + 1) % fixture.ringQ.Modulus[0])
		var err error
		mutated.relation, err = newPRFInputTraceV3Relation(fixture.ringQ.Modulus[0], fixture.params, fixture.layout, fixture.keySources, fixture.context, mutated.tag, fixture.omega, len(fixture.rows))
		if err != nil {
			t.Fatal(err)
		}
		requireInputTraceV3OmegaSums(t, mutated, inputTraceV3FormalForFixture(t, mutated), true)
	}
	// The terminal MDS state is derived from the final full-round S-box inputs;
	// mutating any of its four corresponding lanes must break the substituted
	// equations even though no terminal-state scalar is committed for them.
	for lane := 0; lane < 4; lane++ {
		idx := len(fixture.layout.SBoxInputSlots) - fixture.params.T() + lane
		mutated := mutateInputTraceV3FixtureSlot(t, fixture, fixture.layout.SBoxInputSlots[idx])
		requireInputTraceV3OmegaSums(t, mutated, inputTraceV3FormalForFixture(t, mutated), true)
	}
}

func strictV3TargetOptsForRelationTest(t *testing.T, preset credential.IntGenISISPreset) SimOpts {
	t.Helper()
	protocol, version, err := credential.ResolveIntGenISISTranscript(preset.Showing.TranscriptMode)
	if err != nil {
		t.Fatal(err)
	}
	tuning := preset.Showing
	return ResolveSimOptsDefaults(SimOpts{
		Credential:                 true,
		CoeffPacking:               true,
		RingDegree:                 1024,
		NCols:                      tuning.NCols,
		LVCSNCols:                  tuning.LVCSNCols,
		NLeaves:                    tuning.NLeaves,
		Ell:                        tuning.Ell,
		EllPrime:                   tuning.EllPrime,
		Eta:                        tuning.Eta,
		Rho:                        tuning.Rho,
		Theta:                      tuning.Theta,
		Kappa:                      tuning.Kappa,
		ROQueryCaps:                tuning.ROQueryCaps,
		ROQueryCapsSet:             tuning.ROQueryCapsSet,
		ROQueryCapBits:             tuning.ROQueryCapBits,
		ROQueryCapBitsSet:          tuning.ROQueryCapBitsSet,
		DECSCollisionBits:          tuning.DECSCollisionBits,
		DECSHashBits:               tuning.DECSHashBits,
		DECSTapeBits:               tuning.DECSTapeBits,
		FSCollisionBits:            tuning.FSCollisionBits,
		SaltBits:                   tuning.SaltBits,
		DomainMode:                 DomainModeExplicit,
		PRFParamsPath:              tuning.PRFParamsPath,
		PRFGroupRounds:             tuning.PRFGroupRounds,
		PRFCompanionMode:           PRFCompanionMode(tuning.PRFCompanionMode),
		IntGenISISMSECompression:   tuning.CompressedRows,
		IntGenISISReplayProjection: tuning.ReplayProjection,
		SigShortnessRadix:          tuning.SigShortnessRadix,
		SigShortnessL:              tuning.SigShortnessDigits,
		FixedTranscriptSize:        tuning.FixedTranscriptSize,
		TranscriptOmissionMode:     tuning.TranscriptOmissionMode,
		TranscriptProtocolMode:     protocol,
		TranscriptVersion:          version,
	})
}

func targetShowingPublicShapeForRelationTest(ringQ *ring.Ring, tagCount int) PublicInputs {
	zero := func() *ring.Poly { return ringQ.NewPoly() }
	return PublicInputs{
		A:              [][]*ring.Poly{{zero(), zero()}},
		B:              []*ring.Poly{zero(), zero(), zero(), zero()},
		CM:             [][]*ring.Poly{{zero()}},
		AS:             [][]*ring.Poly{{zero()}},
		Tag:            make([]int64, tagCount),
		Context:        make([]int64, prf.ContextLaneCountV2),
		ContextDigest:  make([]byte, 32),
		BoundB:         credential.IntGenISISLiveBound,
		HashInputBound: credential.IntGenISISHashInputBound,
		X0Len:          1,
		RingDegree:     1024,
		HashRelation:   credential.HashRelationBBTran,
		IntGenISIS:     true,
		Extras:         map[string]interface{}{"IntGenISIS.signature_bound_value": int64(6142)},
	}
}

func TestStrictV3TargetGeometryAndDegreeContracts(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	ringQ, err := credential.LoadRingWithDegree(1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		presetName   string
		tagCount     int
		wantRows     int
		wantParallel int
		wantDQ       int
		wantLayers   int
		wantReplay   int
		wantPhysical int
		wantQueries  int
		wantOpening  int
		wantV2Rows   int
		wantPRFPad   int
	}{
		{credential.IntGenISISPresetPoCN1024BQ128R128V3, 10, 423, 11, 570, 10, 450, 645, 143, 502, 600, 3},
		{credential.IntGenISISPresetSystemN1024WF128CROMV2, 13, 423, 11, 471, 11, 429, 520, 84, 436, 536, 0},
	} {
		t.Run(tc.presetName, func(t *testing.T) {
			preset, ok := credential.LookupIntGenISISPreset(tc.presetName)
			if !ok {
				t.Fatalf("missing target preset")
			}
			opts := strictV3TargetOptsForRelationTest(t, preset)
			pub := targetShowingPublicShapeForRelationTest(ringQ, tc.tagCount)
			layout, companion, err := expectedIntGenISISShowingLayoutsV2(ringQ, pub, opts)
			if err != nil {
				t.Fatal(err)
			}
			if layout.SigCount != tc.wantRows {
				t.Fatalf("strict v3 logical rows=%d want %d", layout.SigCount, tc.wantRows)
			}
			if companion != nil {
				t.Fatal("strict v3 verifier reconstructed a legacy PRF companion")
			}
			l := layout.IntGenISISShowing
			if got := intGenISISLinearHatSourceMode(l); got != intGenISISLinearHatSourceMuX0AggregateFused {
				t.Fatalf("strict v3 linear-hat source mode=%q want %q", got, intGenISISLinearHatSourceMuX0AggregateFused)
			}
			if l.MuSigHatStart != -1 || l.MuSigHatCount != 0 || l.X0HatStart != -1 || l.X0HatCount != 0 {
				t.Fatalf("strict v3 retained fused mu/x0 hats: mu=(%d,%d) x0=(%d,%d)", l.MuSigHatStart, l.MuSigHatCount, l.X0HatStart, l.X0HatCount)
			}
			if l.X1HatStart < 0 || l.X1HatCount != l.ViewRowsPerPoly || l.ZHatStart < 0 || l.ZHatCount != l.ViewRowsPerPoly {
				t.Fatalf("strict v3 lost nonlinear x1/Z hats: x1=(%d,%d) Z=(%d,%d)", l.X1HatStart, l.X1HatCount, l.ZHatStart, l.ZHatCount)
			}
			if !l.HashSourceCarrierV3 || l.MuSigCarrierCount+l.X0CarrierCount+l.X1CarrierCount != 48 || l.PRFInputTraceV3Rows != 6 ||
				l.PRFInputTraceV3Logical != 179+tc.tagCount || l.PRFInputTraceV3Padding != tc.wantPRFPad {
				t.Fatalf("strict v3 carrier/PRF geometry=%+v", l)
			}
			if l.MuSigViewStart != -1 || l.X0ViewStart != -1 || l.X1ViewStart != -1 {
				t.Fatalf("strict v3 retained duplicate raw source rows mu/x0/x1=%d/%d/%d", l.MuSigViewStart, l.X0ViewStart, l.X1ViewStart)
			}
			if l.X0CarrierStart != l.MuSigCarrierStart+l.MuSigCarrierCount || l.X1CarrierStart != l.X0CarrierStart+l.X0CarrierCount {
				t.Fatalf("strict v3 carrier rows are not canonical and contiguous")
			}
			meta, err := intGenISISDegreeMetadataForLayout(ringQ, pub, layout, opts)
			if err != nil {
				t.Fatal(err)
			}
			if meta.ParallelAlgDegree != tc.wantParallel || meta.AggregatedAlgDegree != 8 || meta.PRFDegree != 3 || meta.PaperConservativeDQ != tc.wantDQ {
				t.Fatalf("strict v3 degrees=(%d,%d) prf=%d dQ=%d want=(%d,8) prf=3 dQ=%d", meta.ParallelAlgDegree, meta.AggregatedAlgDegree, meta.PRFDegree, meta.PaperConservativeDQ, tc.wantParallel, tc.wantDQ)
			}
			layers := ceilDiv(layout.SigCount, opts.LVCSNCols)
			replay := layers * (opts.NCols + opts.Theta)
			shape, err := deriveSmallFieldMaskShapeV3(tc.wantDQ, opts.LVCSNCols, opts.Theta)
			if err != nil {
				t.Fatal(err)
			}
			physical := replay + opts.Rho*shape.RowsPerMask
			queries := (layers + 1) * opts.Theta
			opening := physical - queries
			if layers != tc.wantLayers || replay != tc.wantReplay || physical != tc.wantPhysical || queries != tc.wantQueries || opening != tc.wantOpening {
				t.Fatalf("strict v3 fused geometry layers/replay/physical/queries/opening=%d/%d/%d/%d/%d want %d/%d/%d/%d/%d", layers, replay, physical, queries, opening, tc.wantLayers, tc.wantReplay, tc.wantPhysical, tc.wantQueries, tc.wantOpening)
			}
			covered := make([]bool, layout.SigCount)
			mark := func(name string, start, count int) {
				t.Helper()
				if start < 0 || count <= 0 || start+count > len(covered) {
					t.Fatalf("invalid %s coverage range [%d,%d) for rows=%d", name, start, start+count, len(covered))
				}
				for row := start; row < start+count; row++ {
					if covered[row] {
						t.Fatalf("row %d is multiply owned while marking %s", row, name)
					}
					covered[row] = true
				}
			}
			mark("u shortness", l.UShortnessStart, l.UShortnessGroupCount*l.UShortnessRowsPerGroup)
			mark("bounded/carrier sources", l.BoundViewStart, l.BoundViewCount)
			mark("x1 hats", l.X1HatStart, l.X1HatCount)
			mark("Z hats", l.ZHatStart, l.ZHatCount)
			mark("PRF input trace", l.PRFInputTraceV3Start, l.PRFInputTraceV3Rows)
			for row, ok := range covered {
				if !ok {
					t.Fatalf("strict v3 fused layout leaves committed row %d orphaned", row)
				}
			}

			// The v2 branch remains the historical 600/536-row, seven-row
			// companion geometry for the same non-transcript parameters.
			v2opts := opts
			v2opts.TranscriptVersion = TranscriptVersionSmallWood2025V2
			v2opts.TranscriptProtocolMode = TranscriptProtocolSmallField2025V2
			v2opts.TranscriptOmissionMode = credential.IntGenISISTranscriptOmissionModeV2
			// The strict-v3 manifest deliberately carries no retired companion
			// metadata. Reconstruct the historical v2 fixture explicitly for this
			// regression branch instead of treating it as target configuration.
			v2opts.PRFCompanionMode = PRFCompanionModeDirectFull
			v2opts.PRFGroupRounds = 2
			if tc.presetName == credential.IntGenISISPresetPoCN1024BQ128R128V3 {
				// Preserve the historical v2 regression fixture: the target v3
				// preset now uses the smaller R11/L4 formulation.
				v2opts.SigShortnessRadix = 7
				v2opts.SigShortnessL = 5
			}
			v2layout, v2companion, err := expectedIntGenISISShowingLayoutsV2(ringQ, pub, v2opts)
			if err != nil {
				t.Fatal(err)
			}
			if v2layout.SigCount != tc.wantV2Rows || v2companion == nil || v2companion.PackedRows != 7 || v2companion.RelationVersion != 2 {
				t.Fatalf("v2 regression rows/companion=%d/%+v want %d/seven-row-v2", v2layout.SigCount, v2companion, tc.wantV2Rows)
			}
		})
	}
}

func TestStrictV3VerifierRejectsPreFusionLayoutAndStatement(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	ringQ, err := credential.LoadRingWithDegree(1024)
	if err != nil {
		t.Fatal(err)
	}
	preset, ok := credential.LookupIntGenISISPreset(credential.IntGenISISPresetPoCN1024BQ128R128V3)
	if !ok {
		t.Fatal("missing BQ128 target preset")
	}
	opts := strictV3TargetOptsForRelationTest(t, preset)
	pub := targetShowingPublicShapeForRelationTest(ringQ, 10)
	pub.Extras = map[string]interface{}{"IntGenISIS.signature_bound_value": []byte("6142")}
	expected, companion, err := expectedIntGenISISShowingLayoutsV2(ringQ, pub, opts)
	if err != nil {
		t.Fatal(err)
	}
	if companion != nil {
		t.Fatal("strict v3 reconstructed a companion")
	}
	legacy := expected
	legacyShowing := *expected.IntGenISISShowing
	legacy.IntGenISISShowing = &legacyShowing
	legacyShowing.LinearHatSourceMode = intGenISISLinearHatSourceMaterialized

	currentStatement, err := canonicalPublicStatementWithLayoutBytesV3(pub, expected)
	if err != nil {
		t.Fatal(err)
	}
	legacyStatement, err := canonicalPublicStatementWithLayoutBytesV3(pub, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(currentStatement, legacyStatement) {
		t.Fatal("pre-fusion and fused layouts share a Fiat-Shamir public statement")
	}

	proof := &Proof{
		SchemaVersion:          ProofSchemaVersionV3,
		RingDegree:             pub.RingDegree,
		HashRelation:           pub.HashRelation,
		TranscriptVersion:      opts.TranscriptVersion,
		TranscriptProtocolMode: opts.TranscriptProtocolMode,
		FixedTranscriptSize:    opts.FixedTranscriptSize,
		Salt:                   make([]byte, fsSaltBytesForOpts(opts)),
		Lambda:                 opts.Lambda,
		Kappa:                  opts.Kappa,
		Theta:                  opts.Theta,
		Tail:                   make([]int, opts.Ell),
		NColsUsed:              opts.NCols,
		PCSNColsUsed:           opts.LVCSNCols,
		LVCSNColsUsed:          opts.LVCSNCols,
		NLeavesUsed:            opts.NLeaves,
		DomainMode:             opts.DomainMode,
		RowDegreeBound:         opts.LVCSNCols + opts.Ell - 1,
		RowLayout:              legacy,
	}
	err = validateIntGenISISProofEnvelopeV2(proof, expected, nil, pub, opts)
	if err == nil || !strings.Contains(err.Error(), "row layout") {
		t.Fatalf("strict v3 verifier did not reject pre-fusion layout at the layout gate: %v", err)
	}
}

func buildStrictV3TargetRowsForTest(t *testing.T, preset credential.IntGenISISPreset) (*ring.Ring, PublicInputs, WitnessInputs, SimOpts, []*ring.Poly, RowLayout, ConstraintSet) {
	t.Helper()
	profile := credential.Ternary1024IntGenISISProfile()
	ringQ, err := credential.LoadRingWithDegree(profile.N)
	if err != nil {
		t.Fatal(err)
	}
	opts := strictV3TargetOptsForRelationTest(t, preset)
	params, err := loadPRFParamsForOpts(opts)
	if err != nil {
		t.Fatal(err)
	}
	semanticLayout, err := credential.DefaultSemanticMessageLayout(profile, params.LenKey)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := credential.EncodeSemanticMessage(semanticLayout, credential.ZeroSemanticAttributes(semanticLayout), intGenISISTestPRFSeed())
	if err != nil {
		t.Fatal(err)
	}
	mRows := polysFromInt64ForIntGenISISTest(ringQ, msg.M)
	mAttrRows := polysFromInt64ForIntGenISISTest(ringQ, msg.MAttr)
	kRows := polysFromInt64ForIntGenISISTest(ringQ, msg.K)
	key, err := extractIntGenISISPRFKeyElemsFromSemanticM(ringQ, profile.B, mRows)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := fixedNonceTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	context := append([]prf.Elem(nil), nonce[:prf.ContextLaneCountV2]...)
	tag, err := prf.TagContextSlot(key, context, 0, params)
	if err != nil {
		t.Fatal(err)
	}
	zero := ringQ.NewPoly()
	one := intGenISISTestCoeffConst(ringQ, 1)
	mNTT := intGenISISTestNTT(ringQ, mRows[0])
	oneNTT := intGenISISTestNTT(ringQ, one)
	cmNTT := intGenISISTestPublicBinomialNTT(ringQ, 1, 1)
	u0NTT := ringQ.NewPoly()
	ringQ.MulCoeffs(cmNTT, mNTT, u0NTT)
	ringQ.Add(u0NTT, oneNTT, u0NTT)
	u0 := ringQ.NewPoly()
	ringQ.InvNTT(u0NTT, u0)
	cn := &CoeffNativeShowingWitness{
		Sig:         []*ring.Poly{u0, zero.CopyNew()},
		M:           mRows[0],
		MAttr:       mAttrRows[0],
		K:           kRows[0],
		S:           []*ring.Poly{zero.CopyNew()},
		E:           []*ring.Poly{zero.CopyNew()},
		MuSig:       []*ring.Poly{zero.CopyNew()},
		X0:          []*ring.Poly{zero.CopyNew()},
		X1:          zero.CopyNew(),
		Z:           one,
		HiddenSlot:  0,
		HiddenBits:  [4]uint64{},
		PackedNCols: opts.NCols,
	}
	pub := PublicInputs{
		A: [][]*ring.Poly{{
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 0),
		}},
		B: []*ring.Poly{
			intGenISISTestPublicConstNTT(ringQ, 0),
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 1),
		},
		CM:             [][]*ring.Poly{{cmNTT}},
		AS:             [][]*ring.Poly{{intGenISISTestPublicConstNTT(ringQ, 0)}},
		Tag:            elemsToInt64Test(tag),
		Context:        elemsToInt64Test(context),
		ContextDigest:  make([]byte, 32),
		BoundB:         profile.B,
		HashInputBound: profile.HashInputBound,
		X0Len:          profile.EllX0,
		RingDegree:     profile.N,
		HashRelation:   credential.HashRelationBBTran,
		IntGenISIS:     true,
		Extras:         map[string]interface{}{"IntGenISIS.signature_bound": []byte("6142")},
	}
	boundPublic := credential.PublicParams{
		Profile:              preset.Profile,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PrimitiveProfileID:   preset.PrimitiveProfileID,
		PRFProfile:           preset.PRFProfile,
		TranscriptMode:       preset.Showing.TranscriptMode,
		PresetManifestDigest: credential.IntGenISISPresetManifestDigest(preset),
		RateLimitPolicy:      preset.RateLimitPolicy,
		Modulus:              ringQ.Modulus[0],
	}
	pub.Extras = boundPublic.PresetTranscriptExtras(pub.Extras)
	pub, err = bindIntGenISISPublicExtrasWithOpts(pub, profile.N, opts)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, layout, _, companion, _, _, _, witnessCount, _, builtNCols, err := BuildCredentialRowsShowingIntGenISIS(
		ringQ, pub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, opts.PRFGroupRounds, opts,
	)
	if err != nil {
		t.Fatal(err)
	}
	if companion != nil {
		t.Fatal("strict v3 row builder returned a legacy PRF companion")
	}
	if witnessCount != layout.SigCount || witnessCount > len(rows) {
		t.Fatalf("strict v3 witness geometry rows/layout/physical=%d/%d/%d", witnessCount, layout.SigCount, len(rows))
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ringQ.NTT(rows[i], rowsNTT[i])
	}
	omega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], opts.NLeaves, opts.NCols, opts.LVCSNCols, opts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatal(err)
	}
	set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, pub, layout, rowsNTT, omega[:builtNCols], nil, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	return ringQ, pub, WitnessInputs{CoeffNativeShowing: cn}, opts, rows, layout, set
}

func TestStrictV3DirectRowBuilderRejectsAlteredPRFProfile(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	preset, ok := credential.LookupIntGenISISPreset(credential.IntGenISISPresetSystemN1024WF128CROMV2)
	if !ok {
		t.Fatal("missing WF128 target preset")
	}
	ringQ, pub, wit, opts, _, _, _ := buildStrictV3TargetRowsForTest(t, preset)
	params, _, err := prf.LoadEmbeddedTargetParamsV3(preset.PRFParamsPath)
	if err != nil {
		t.Fatal(err)
	}
	params.CInt[0] = (params.CInt[0] + 1) % params.Q
	altered, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "altered-wf128-prf.json")
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	opts.PRFParamsPath = path
	_, _, _, _, _, _, _, _, _, _, _, err = BuildCredentialRowsShowingIntGenISIS(
		ringQ, pub, wit, params.LenKey, params.LenNonce, params.RF, params.RP, opts.PRFGroupRounds, opts,
	)
	if err == nil || !strings.Contains(err.Error(), "do not match fixed profile") {
		t.Fatalf("direct strict-v3 row builder accepted altered PRF relation: %v", err)
	}
}

func TestStrictV3LiveRowCompilerTargets(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	for _, tc := range []struct {
		presetName   string
		wantRows     int
		wantParallel int
	}{
		{credential.IntGenISISPresetPoCN1024BQ128R128V3, 423, 11},
		{credential.IntGenISISPresetSystemN1024WF128CROMV2, 423, 11},
	} {
		t.Run(tc.presetName, func(t *testing.T) {
			preset, ok := credential.LookupIntGenISISPreset(tc.presetName)
			if !ok {
				t.Fatal("missing target preset")
			}
			ringQ, pub, wit, opts, rows, layout, set := buildStrictV3TargetRowsForTest(t, preset)
			if layout.SigCount != tc.wantRows || set.ParallelAlgDeg != tc.wantParallel || set.AggregatedAlgDeg != 8 {
				t.Fatalf("live strict v3 rows/degrees=%d/(%d,%d) want %d/(%d,8)", layout.SigCount, set.ParallelAlgDeg, set.AggregatedAlgDeg, tc.wantRows, tc.wantParallel)
			}
			if set.PRFCompanionLayout != nil {
				t.Fatal("live strict v3 constraint set retained PRF companion metadata")
			}
			l := layout.IntGenISISShowing
			if l == nil || l.MuSigViewStart != -1 || l.X0ViewStart != -1 || l.X1ViewStart != -1 ||
				l.MuSigCarrierCount+l.X0CarrierCount+l.X1CarrierCount != 48 || l.PRFInputTraceV3Rows != 6 {
				t.Fatalf("live strict v3 row builder retained duplicate/legacy source geometry: %+v", l)
			}
			if intGenISISLinearHatSourceMode(l) != intGenISISLinearHatSourceMuX0AggregateFused ||
				l.MuSigHatStart != -1 || l.MuSigHatCount != 0 || l.X0HatStart != -1 || l.X0HatCount != 0 ||
				l.X1HatStart < 0 || l.X1HatCount != l.ViewRowsPerPoly {
				t.Fatalf("live strict v3 fused/materialized hat contract mismatch: %+v", l)
			}

			// The production v3 compiler keeps semantic family arities only. Pin
			// those arities, degrees, and values to the retired formal compiler so
			// skipping coefficient materialization cannot drop or reorder a check.
			rowsNTT := make([]*ring.Poly, len(rows))
			for i := range rows {
				rowsNTT[i] = ringQ.NewPoly()
				ringQ.NTT(rows[i], rowsNTT[i])
			}
			omega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], opts.NLeaves, opts.NCols, opts.LVCSNCols, opts.Ell, pub.HashRelation)
			if err != nil {
				t.Fatal(err)
			}
			params, err := loadPRFParamsForOpts(opts)
			if err != nil {
				t.Fatal(err)
			}
			clearedOpts := opts
			clearedOpts.EnablePRFCompanion = false
			clearedOpts.PRFCompanionMode = ""
			clearedOpts.PRFGroupRounds = 0
			clearedOpts.PRFCheckpointSamples = 0
			callerPublic, err := clonePublicInputsOwned(pub)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := PrepareIntGenISISShowingContext(callerPublic, clearedOpts)
			if err != nil {
				t.Fatal(err)
			}
			// The reusable context owns the complete statement. Mutating the
			// caller's slices, polynomial storage, or Extras after preparation
			// must neither change the cached statement nor validate as a reuse.
			callerPublic.ContextDigest[0] ^= 1
			callerPublic.CM[0][0].Coeffs[0][0] ^= 1
			for key, value := range callerPublic.Extras {
				if raw, ok := value.([]byte); ok && len(raw) > 0 {
					raw[0] ^= 1
					callerPublic.Extras[key] = raw
					break
				}
			}
			cachedBinding, err := canonicalPublicInputsBytesV3(prepared.pub)
			if err != nil || !bytes.Equal(cachedBinding, prepared.publicBinding) {
				t.Fatalf("caller mutation changed prepared public statement: err=%v", err)
			}
			if err := validateIntGenISISShowingPreparedReuse(prepared, callerPublic, clearedOpts); err == nil {
				t.Fatal("prepared reuse accepted mutated caller public inputs")
			}
			if err := validateIntGenISISShowingPreparedReuse(prepared, pub, clearedOpts); err != nil {
				t.Fatalf("prepared reuse rejected original public inputs: %v", err)
			}
			for key, value := range prepared.pub.Extras {
				raw, ok := value.([]byte)
				if !ok || len(raw) == 0 {
					continue
				}
				raw[0] ^= 1
				if err := validateIntGenISISShowingPreparedReuse(prepared, pub, clearedOpts); err == nil || !strings.Contains(err.Error(), "cached public inputs changed") {
					t.Fatalf("prepared reuse did not detect cached statement mutation: %v", err)
				}
				raw[0] ^= 1
				prepared.pub.Extras[key] = raw
				break
			}
			if prepared.opts.EnablePRFCompanion || prepared.opts.PRFCompanionMode != "" || prepared.opts.PRFGroupRounds != 0 || prepared.opts.PRFCheckpointSamples != 0 {
				t.Fatalf("strict v3 preparation revived companion metadata: mode=%q rounds=%d samples=%d enabled=%v", prepared.opts.PRFCompanionMode, prepared.opts.PRFGroupRounds, prepared.opts.PRFCheckpointSamples, prepared.opts.EnablePRFCompanion)
			}
			_, _, clearedLayout, _, clearedCompanion, _, _, _, _, _, _, err := BuildCredentialRowsShowingIntGenISIS(
				ringQ, pub, wit, params.LenKey, params.LenNonce, params.RF, params.RP, clearedOpts.PRFGroupRounds, clearedOpts,
			)
			if err != nil {
				t.Fatal(err)
			}
			if clearedCompanion != nil || clearedLayout.SigCount != layout.SigCount {
				t.Fatalf("strict v3 cleared companion metadata changed rows or produced layout: rows=%d want=%d companion=%v", clearedLayout.SigCount, layout.SigCount, clearedCompanion)
			}
			formalSet, err := buildIntGenISISShowingConstraintSetFromRowsPreparedMode(
				ringQ, pub, layout, rowsNTT, omega[:opts.NCols], nil, nil,
				&IntGenISISShowingPreparedContext{prfParams: params}, true,
			)
			if err != nil {
				t.Fatal(err)
			}
			semanticPar := len(set.FparInt) + len(set.FparNorm)
			semanticAgg := len(set.FaggInt) + len(set.FaggNorm)
			formalPar := len(formalSet.FparInt) + len(formalSet.FparNorm)
			formalAgg := len(formalSet.FaggInt) + len(formalSet.FaggNorm)
			if semanticPar != formalPar || semanticAgg != formalAgg ||
				set.ParallelAlgDeg != formalSet.ParallelAlgDeg || set.AggregatedAlgDeg != formalSet.AggregatedAlgDeg {
				t.Fatalf("semantic/formal compiler geometry=(%d,%d,%d,%d) want (%d,%d,%d,%d)", semanticPar, semanticAgg, set.ParallelAlgDeg, set.AggregatedAlgDeg, formalPar, formalAgg, formalSet.ParallelAlgDeg, formalSet.AggregatedAlgDeg)
			}

			x := uint64(73)
			rowValues := make([]uint64, len(rows))
			for i := range rows {
				rowValues[i] = EvalPoly(rows[i].Coeffs[0], x, ringQ.Modulus[0])
			}
			replayCfg, err := newIntGenISISShowingReplayConfig(ringQ, pub, layout, omega[:opts.NCols], []uint64{x}, nil)
			if err != nil {
				t.Fatal(err)
			}
			gotPar, gotAgg, err := replayCfg.CoreEvaluator()(0, rowValues)
			if err != nil {
				t.Fatal(err)
			}
			shapePar, shapeAgg, err := replayCfg.semanticConstraintShapeV3()
			if err != nil {
				t.Fatal(err)
			}
			if shapePar != len(gotPar) || shapeAgg != len(gotAgg) || shapePar != semanticPar || shapeAgg != semanticAgg {
				t.Fatalf("structural/replayed/metadata constraint shape=(%d,%d)/(%d,%d)/(%d,%d)", shapePar, shapeAgg, len(gotPar), len(gotAgg), semanticPar, semanticAgg)
			}
			formalParCoeffs := append(append([][]uint64{}, formalSet.FparIntCoeffs...), formalSet.FparNormCoeffs...)
			formalAggCoeffs := append(append([][]uint64{}, formalSet.FaggIntCoeffs...), formalSet.FaggNormCoeffs...)
			if len(gotPar) != len(formalParCoeffs) || len(gotAgg) != len(formalAggCoeffs) {
				t.Fatalf("semantic/formal value counts=(%d,%d) want (%d,%d)", len(gotPar), len(gotAgg), len(formalParCoeffs), len(formalAggCoeffs))
			}
			for i := range gotPar {
				if gotPar[i] != EvalPoly(formalParCoeffs[i], x, ringQ.Modulus[0]) {
					t.Fatalf("parallel semantic/formal residual %d differs", i)
				}
			}
			for i := range gotAgg {
				if gotAgg[i] != EvalPoly(formalAggCoeffs[i], x, ringQ.Modulus[0]) {
					t.Fatalf("aggregate semantic/formal residual %d differs", i)
				}
			}

			// Q interpolation uses embedded F_q points. Keep the optimized K
			// evaluator pinned to the independent base-field evaluator so a
			// scalar specialization cannot change a residual or its ordering.
			fieldProfile, ok := kf.LookupSmallWoodFieldProfileV3(ringQ.Modulus[0], opts.Theta)
			if !ok {
				t.Fatalf("missing strict v3 field profile q=%d theta=%d", ringQ.Modulus[0], opts.Theta)
			}
			K, _, err := fieldProfile.Validate(omega[:opts.NCols])
			if err != nil {
				t.Fatal(err)
			}
			kRows := make([]kf.Elem, len(rowValues))
			for i := range rowValues {
				kRows[i] = K.EmbedF(rowValues[i])
			}
			kEval, err := replayCfg.CoreKEvaluator(K)
			if err != nil {
				t.Fatal(err)
			}
			kPar, kAgg, err := kEval(K.EmbedF(x), kRows)
			if err != nil {
				t.Fatal(err)
			}
			assertEmbedded := func(label string, want []uint64, got []kf.Elem) {
				t.Helper()
				if len(got) != len(want) {
					t.Fatalf("%s K/F residual count=%d want %d", label, len(got), len(want))
				}
				for i := range got {
					if len(got[i].Limb) != K.Theta || got[i].Limb[0]%K.Q != want[i]%K.Q {
						t.Fatalf("%s K/F residual %d differs", label, i)
					}
					for limb := 1; limb < K.Theta; limb++ {
						if got[i].Limb[limb]%K.Q != 0 {
							t.Fatalf("%s residual %d escaped embedded F_q at limb %d", label, i, limb)
						}
					}
				}
			}
			assertEmbedded("parallel", gotPar, kPar)
			assertEmbedded("aggregate", gotAgg, kAgg)

			into, err := replayCfg.CoreKIntoEvaluator(K)
			if err != nil {
				t.Fatal(err)
			}
			intoPar := makeKElementBuffer(into.ParallelCount, K.Theta)
			intoAgg := makeKElementBuffer(into.AggregateCount, K.Theta)
			intoScratch := into.NewScratch()
			if err := into.EvalInto(K.EmbedF(x), kRows, intoPar, intoAgg, intoScratch); err != nil {
				t.Fatal(err)
			}
			for i := range kPar {
				if !elemEqual(K, kPar[i], intoPar[i]) {
					t.Fatalf("parallel Into residual %d differs", i)
				}
			}
			for i := range kAgg {
				if !elemEqual(K, kAgg[i], intoAgg[i]) {
					t.Fatalf("aggregate Into residual %d differs", i)
				}
			}
			if err := into.EvalInto(K.EmbedF(x), kRows, intoPar, intoAgg, intoScratch); err != nil {
				t.Fatalf("reuse prepared Into scratch: %v", err)
			}
			otherPar := makeKElementBuffer(into.ParallelCount, K.Theta)
			otherAgg := makeKElementBuffer(into.AggregateCount, K.Theta)
			if err := into.EvalInto(K.EmbedF(x), kRows, otherPar, otherAgg, intoScratch); err == nil {
				t.Fatal("expected Into scratch/output rebinding rejection")
			}

			// Also compare the shared semantic evaluator and the formal compiler
			// at a genuinely non-embedded K point.  This pins the fused H-weighted
			// carrier substitution itself, not only its specialization on F_q.
			generalPointLimbs := make([]uint64, K.Theta)
			for i := range generalPointLimbs {
				generalPointLimbs[i] = uint64(19 + 2*i)
			}
			if K.Theta > 1 {
				generalPointLimbs[1] = 1
			}
			generalPoint := K.Phi(generalPointLimbs)
			generalRows := make([]kf.Elem, len(rows))
			for i := range rows {
				generalRows[i] = K.EvalFPolyAtK(rows[i].Coeffs[0], generalPoint)
			}
			generalPar, generalAgg, err := kEval(generalPoint, generalRows)
			if err != nil {
				t.Fatal(err)
			}
			assertFormalK := func(label string, coeffs [][]uint64, got []kf.Elem) {
				t.Helper()
				if len(got) != len(coeffs) {
					t.Fatalf("%s general-K residual count=%d want %d", label, len(got), len(coeffs))
				}
				for i := range got {
					want := K.EvalFPolyAtK(coeffs[i], generalPoint)
					if !elemEqual(K, got[i], want) {
						t.Fatalf("%s general-K semantic/formal residual %d differs", label, i)
					}
				}
			}
			assertFormalK("parallel", formalParCoeffs, generalPar)
			assertFormalK("aggregate", formalAggCoeffs, generalAgg)
		})
	}
}

func TestStrictV3MuX0FusionTamperingAndRetainedNonlinearHats(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	preset, ok := credential.LookupIntGenISISPreset(credential.IntGenISISPresetPoCN1024BQ128R128V3)
	if !ok {
		t.Fatal("missing BQ128 target preset")
	}
	ringQ, pub, _, opts, rows, layout, _ := buildStrictV3TargetRowsForTest(t, preset)
	l := layout.IntGenISISShowing
	if l == nil {
		t.Fatal("missing strict-v3 showing layout")
	}
	omega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], opts.NLeaves, opts.NCols, opts.LVCSNCols, opts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatal(err)
	}
	params, err := loadPRFParamsForOpts(opts)
	if err != nil {
		t.Fatal(err)
	}
	compileFormal := func(coeffRows []*ring.Poly) ConstraintSet {
		t.Helper()
		rowsNTT := make([]*ring.Poly, len(coeffRows))
		for i := range coeffRows {
			rowsNTT[i] = ringQ.NewPoly()
			ringQ.NTT(coeffRows[i], rowsNTT[i])
		}
		set, err := buildIntGenISISShowingConstraintSetFromRowsPreparedMode(
			ringQ, pub, layout, rowsNTT, omega[:opts.NCols], nil, nil,
			&IntGenISISShowingPreparedContext{prfParams: params}, true,
		)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	baseline := compileFormal(rows)
	if nonZero, err := bucketHasNonZeroOmegaValue(ringQ, omega[:opts.NCols], append(append([]*ring.Poly{}, baseline.FparInt...), baseline.FparNorm...), append(append([][]uint64{}, baseline.FparIntCoeffs...), baseline.FparNormCoeffs...)); err != nil || nonZero {
		t.Fatalf("valid fused witness has nonzero parallel relation=%v err=%v", nonZero, err)
	}
	if nonZero, err := bucketHasNonZeroOmegaSum(ringQ, omega[:opts.NCols], append(append([]*ring.Poly{}, baseline.FaggInt...), baseline.FaggNorm...), append(append([][]uint64{}, baseline.FaggIntCoeffs...), baseline.FaggNormCoeffs...)); err != nil || nonZero {
		t.Fatalf("valid fused witness has nonzero aggregate relation=%v err=%v", nonZero, err)
	}

	for _, tc := range []struct {
		name string
		row  int
	}{
		{"mu_sig carrier", l.MuSigCarrierStart},
		{"x0 carrier", l.X0CarrierStart},
		{"x1 carrier", l.X1CarrierStart},
		{"x1 materialized hat", l.X1HatStart},
		{"Z materialized hat", l.ZHatStart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.row < 0 || tc.row >= layout.SigCount {
				t.Fatalf("tamper row=%d outside logical witness rows=%d", tc.row, layout.SigCount)
			}
			mutated := clonePolySliceForIntGenISISTest(ringQ, rows)
			mutated[tc.row].Coeffs[0][0] = (mutated[tc.row].Coeffs[0][0] + 1) % ringQ.Modulus[0]
			set := compileFormal(mutated)
			parallel, err := bucketHasNonZeroOmegaValue(ringQ, omega[:opts.NCols], append(append([]*ring.Poly{}, set.FparInt...), set.FparNorm...), append(append([][]uint64{}, set.FparIntCoeffs...), set.FparNormCoeffs...))
			if err != nil {
				t.Fatal(err)
			}
			aggregate, err := bucketHasNonZeroOmegaSum(ringQ, omega[:opts.NCols], append(append([]*ring.Poly{}, set.FaggInt...), set.FaggNorm...), append(append([][]uint64{}, set.FaggIntCoeffs...), set.FaggNormCoeffs...))
			if err != nil {
				t.Fatal(err)
			}
			if !parallel && !aggregate {
				t.Fatal("tampering left every parallel and aggregate constraint satisfied")
			}
		})
	}
}

// Exact target proofs are deliberately opt-in because they exercise the full
// DECS commitment/opening path. Evidence runs enable this test explicitly;
// ordinary package tests retain the fast live compiler coverage above.
func TestStrictV3LiveProofTargets(t *testing.T) {
	if os.Getenv("SPRUCE_RUN_STRICT_V3_TARGET_E2E") != "1" {
		t.Skip("set SPRUCE_RUN_STRICT_V3_TARGET_E2E=1 for exact BQ128/WF128 proof runs")
	}
	chdirForPIOPIntGenISISTest(t)
	for _, tc := range []struct {
		presetName string
		wantRows   int
	}{
		{credential.IntGenISISPresetPoCN1024BQ128R128V3, 423},
		{credential.IntGenISISPresetSystemN1024WF128CROMV2, 423},
	} {
		t.Run(tc.presetName, func(t *testing.T) {
			preset, ok := credential.LookupIntGenISISPreset(tc.presetName)
			if !ok {
				t.Fatal("missing target preset")
			}
			ringQ, pub, wit, opts, _, _, _ := buildStrictV3TargetRowsForTest(t, preset)
			opts.EnablePRFCompanion = false
			opts.PRFCompanionMode = ""
			opts.PRFGroupRounds = 0
			opts.PRFCheckpointSamples = 0
			opts.PhaseRecorder = NewPhaseRecorder()
			started := time.Now()
			proof, err := BuildIntGenISISShowingCombined(pub, wit, opts)
			if err != nil {
				t.Fatalf("build strict v3 showing proof: %v", err)
			}
			t.Logf("strict v3 build: %s", time.Since(started))
			t.Logf("strict v3 build phases: %+v", opts.PhaseRecorder.Snapshot())
			if proof.SchemaVersion != ProofSchemaVersionV3 || proof.RowLayout.SigCount != tc.wantRows {
				t.Fatalf("strict v3 proof schema/rows=%d/%d want %d/%d", proof.SchemaVersion, proof.RowLayout.SigCount, ProofSchemaVersionV3, tc.wantRows)
			}
			if proof.PRFCompanion != nil || proof.SourceProductBridge != nil {
				t.Fatal("strict v3 proof carried a legacy PRF/source auxiliary opening")
			}
			report, err := BuildProofReport(proof, opts, ringQ)
			if err != nil {
				t.Fatalf("build strict v3 showing report: %v", err)
			}
			wantPaperBytes, wantVBytes := 0, 0
			switch tc.presetName {
			case credential.IntGenISISPresetPoCN1024BQ128R128V3:
				wantPaperBytes, wantVBytes = 90494, 15080
			case credential.IntGenISISPresetSystemN1024WF128CROMV2:
				wantPaperBytes, wantVBytes = 39837, 8103
			}
			if report.PaperTranscript.OptimizedBytes != wantPaperBytes || report.PaperTranscript.VTargets.OptimizedBytes != wantVBytes {
				t.Fatalf("strict v3 showing paper/VTargets bytes=%d/%d want %d/%d", report.PaperTranscript.OptimizedBytes, report.PaperTranscript.VTargets.OptimizedBytes, wantPaperBytes, wantVBytes)
			}
			t.Logf("strict v3 showing paper transcript: total=%d VTargets=%d", report.PaperTranscript.OptimizedBytes, report.PaperTranscript.VTargets.OptimizedBytes)
			started = time.Now()
			verified, verifyErr := VerifyIntGenISISShowing(pub, proof, opts)
			if verifyErr != nil || !verified {
				t.Fatalf("verify strict v3 showing proof: ok=%v err=%v", verified, verifyErr)
			}
			t.Logf("strict v3 verify: %s", time.Since(started))
			canonicalCtx := CanonicalProofContext{Kind: CanonicalProofShowing, Public: pub, Options: opts}
			started = time.Now()
			wire, err := MarshalCanonicalProof(proof, canonicalCtx)
			if err != nil {
				t.Fatalf("marshal strict v3 showing proof: %v", err)
			}
			geometry, err := deriveCanonicalProofGeometryV3(canonicalCtx)
			if err != nil {
				t.Fatalf("derive strict v3 canonical geometry: %v", err)
			}
			counterBytes := 0
			for _, counter := range proof.Ctr {
				counterBytes += len(appendCanonicalUvarint(nil, counter))
			}
			matrixBytes := func(rows, cols int) int {
				width, widthErr := canonicalRadixQMatrixByteLenV5(rows, cols, geometry.q)
				if widthErr != nil {
					t.Fatalf("derive radix-q matrix bytes: %v", widthErr)
				}
				return width
			}
			openingWire, err := marshalCanonicalOpeningV6(resolveProofPCSOpening(proof), proof.Tail, geometry)
			if err != nil {
				t.Fatalf("marshal strict v3 opening for component report: %v", err)
			}
			headerBytes := len(canonicalProofMagicV6) + 2
			rBytes := matrixBytes(geometry.rRows, geometry.rCols)
			qBytes := matrixBytes(geometry.qRows, geometry.qWireCols)
			vBytes, err := canonicalRadixQElementsByteLenV5(geometry.vWireElements, geometry.q)
			if err != nil {
				t.Fatalf("derive radix-q VTarget bytes: %v", err)
			}
			barBytes := matrixBytes(geometry.barRows, geometry.barCols)
			componentTotal := headerBytes + geometry.hashBytes + geometry.saltBytes + counterBytes + rBytes + qBytes + vBytes + barBytes + len(openingWire)
			if componentTotal != len(wire) {
				t.Fatalf("canonical component total=%d want wire=%d", componentTotal, len(wire))
			}
			t.Logf("strict v3 canonical components: header=%d root=%d salt=%d counters=%d R=%d QPayload=%d VTargets=%d BarSets=%d opening=%d total=%d", headerBytes, geometry.hashBytes, geometry.saltBytes, counterBytes, rBytes, qBytes, vBytes, barBytes, len(openingWire), len(wire))
			decoded, err := UnmarshalCanonicalProof(wire, canonicalCtx)
			if err != nil {
				t.Fatalf("unmarshal strict v3 showing proof: %v", err)
			}
			t.Logf("strict v3 canonical round trip (%d bytes): %s", len(wire), time.Since(started))
			started = time.Now()
			verified, verifyErr = VerifyIntGenISISShowing(pub, decoded, opts)
			if verifyErr != nil || !verified {
				t.Fatalf("verify decoded strict v3 showing proof: ok=%v err=%v", verified, verifyErr)
			}
			t.Logf("strict v3 decoded verify: %s", time.Since(started))
		})
	}
}
