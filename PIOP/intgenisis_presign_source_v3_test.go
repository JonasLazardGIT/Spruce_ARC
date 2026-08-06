package PIOP

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type intGenISISPreSignSourceV3Fixture struct {
	ringQ        *ring.Ring
	pub          PublicInputs
	wit          WitnessInputs
	opts         SimOpts
	rows         []*ring.Poly
	rowsNTT      []*ring.Poly
	rowInputs    []lvcs.RowInput
	layout       RowLayout
	omega        []uint64
	domainPoints []uint64
	set          ConstraintSet
	cfg          *intGenISISPreSignSourceOnlyReplayConfig
}

func newIntGenISISPreSignSourceV3Fixture(t *testing.T) intGenISISPreSignSourceV3Fixture {
	return newIntGenISISPreSignSourceV3FixtureTheta(t, 7)
}

func newIntGenISISPreSignSourceV3FixtureTheta(t *testing.T, theta int) intGenISISPreSignSourceV3Fixture {
	t.Helper()
	ctx := canonicalPreSignContextForTest(t, theta)
	ringQ, err := credential.LoadRingWithDegree(1024)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := credential.DefaultSemanticMessageLayout(credential.Ternary1024IntGenISISProfile(), intGenISISPRFKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	message, err := credential.EncodeSemanticMessage(semantic, credential.ZeroSemanticAttributes(semantic), intGenISISTestPRFSeed())
	if err != nil {
		t.Fatal(err)
	}
	sWitness := ringQ.NewPoly()
	eWitness := ringQ.NewPoly()
	q := ringQ.Modulus[0]
	for i := 0; i < int(ringQ.N); i++ {
		if i%7 == 0 {
			sWitness.Coeffs[0][i] = 1
		} else if i%11 == 0 {
			sWitness.Coeffs[0][i] = q - 1
		}
		if i%5 == 0 {
			eWitness.Coeffs[0][i] = q - 1
		} else if i%13 == 0 {
			eWitness.Coeffs[0][i] = 1
		}
	}
	wit := WitnessInputs{
		M:     polysFromInt64ForIntGenISISTest(ringQ, message.M),
		MAttr: polysFromInt64ForIntGenISISTest(ringQ, message.MAttr),
		K:     polysFromInt64ForIntGenISISTest(ringQ, message.K),
		S:     []*ring.Poly{sWitness},
		E:     []*ring.Poly{eWitness},
	}
	// Use C_M=2, A_s=3 and Com=2M+3s+e. Distinct non-unit matrices exercise
	// source ordering and coefficient scaling in addition to all 1,024 output
	// coordinates; all three source families remain nonzero.
	cm := ringQ.NewPoly()
	cm.Coeffs[0][0] = 2
	ringQ.NTT(cm, cm)
	as := ringQ.NewPoly()
	as.Coeffs[0][0] = 3
	ringQ.NTT(as, as)
	com := ringQ.NewPoly()
	ringQ.MulScalar(wit.M[0], 2, com)
	scaledS := ringQ.NewPoly()
	ringQ.MulScalar(sWitness, 3, scaledS)
	ringQ.Add(com, scaledS, com)
	ringQ.Add(com, eWitness, com)
	ringQ.NTT(com, com)
	pub := ctx.Public
	pub.CM = [][]*ring.Poly{{cm}}
	pub.AS = [][]*ring.Poly{{as}}
	pub.Com = []*ring.Poly{com}
	bound, err := bindIntGenISISPublicExtrasWithOpts(pub, 1024, ctx.Options)
	if err != nil {
		t.Fatal(err)
	}
	pub = bound
	rows, rowInputs, layout, _, omega, domainPoints, _, err := buildIntGenISISPreSignSourceOnlyRowsV3(ringQ, pub, wit, ctx.Options, pub.X0Len)
	if err != nil {
		t.Fatal(err)
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	set, err := buildIntGenISISPreSignSourceOnlyConstraintSetV3(ringQ, pub, layout, rowsNTT, omega)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := newIntGenISISPreSignSourceOnlyReplayConfigV3(ringQ, pub, layout, omega, domainPoints)
	if err != nil {
		t.Fatal(err)
	}
	return intGenISISPreSignSourceV3Fixture{
		ringQ: ringQ, pub: pub, wit: wit, opts: ctx.Options, rows: rows, rowsNTT: rowsNTT,
		rowInputs: rowInputs, layout: layout, omega: omega, domainPoints: domainPoints, set: set, cfg: cfg,
	}
}

func intGenISISPreSignSourceV3FormalBuckets(set ConstraintSet) (fpar, fagg [][]uint64) {
	fpar = append(fpar, set.FparIntCoeffs...)
	fpar = append(fpar, set.FparNormCoeffs...)
	fagg = append(fagg, set.FaggIntCoeffs...)
	fagg = append(fagg, set.FaggNormCoeffs...)
	return fpar, fagg
}

func intGenISISPreSignSourceV3RowsAtF(f intGenISISPreSignSourceV3Fixture, x uint64) []uint64 {
	out := make([]uint64, len(f.rows))
	for i := range f.rows {
		out[i] = EvalPoly(f.rows[i].Coeffs[0], x, f.ringQ.Modulus[0])
	}
	return out
}

func TestIntGenISISPreSignSourceV3FormalSemanticEquality(t *testing.T) {
	f := newIntGenISISPreSignSourceV3Fixture(t)
	if got := f.layout.IntGenISISPreSign.WitnessRows(); got != 49 || f.layout.SigCount != 49 {
		t.Fatalf("source-only logical rows=(%d,%d) want 49", got, f.layout.SigCount)
	}
	meta, err := intGenISISDegreeMetadataForLayout(f.ringQ, f.pub, f.layout, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ParallelAlgDegree != 9 || meta.AggregatedAlgDegree != 8 || meta.PaperConservativeDQ != 391 {
		t.Fatalf("source-only degree metadata=%+v", meta)
	}
	shape, err := buildIntGenISISPreSignSourceOnlyConstraintShapeV3(f.ringQ, f.pub, f.layout, f.omega)
	if err != nil {
		t.Fatal(err)
	}
	if len(shape.FparInt) != len(f.set.FparInt) || len(shape.FparNorm) != len(f.set.FparNorm) ||
		len(shape.FaggInt) != len(f.set.FaggInt) || len(shape.FaggNorm) != len(f.set.FaggNorm) ||
		shape.ParallelAlgDeg != f.set.ParallelAlgDeg || shape.AggregatedAlgDeg != f.set.AggregatedAlgDeg {
		t.Fatalf("count-only production shape differs from formal oracle: shape=(%d,%d,%d,%d;%d,%d) formal=(%d,%d,%d,%d;%d,%d)",
			len(shape.FparInt), len(shape.FparNorm), len(shape.FaggInt), len(shape.FaggNorm), shape.ParallelAlgDeg, shape.AggregatedAlgDeg,
			len(f.set.FparInt), len(f.set.FparNorm), len(f.set.FaggInt), len(f.set.FaggNorm), f.set.ParallelAlgDeg, f.set.AggregatedAlgDeg)
	}
	if _, err := buildIntGenISISPreSignConstraintSetFromRows(f.ringQ, f.pub, f.layout, f.rowsNTT, f.omega); err == nil {
		t.Fatal("strict-v3 production rebuild accepted the audit-only formal constraint builder")
	}
	formalFpar, formalFagg := intGenISISPreSignSourceV3FormalBuckets(f.set)
	eval := f.cfg.CoreEvaluator()
	for _, evalIdx := range []int{0, 17, len(f.domainPoints) - 1} {
		x := f.domainPoints[evalIdx] % f.ringQ.Modulus[0]
		gotFpar, gotFagg, err := eval(uint64(evalIdx), intGenISISPreSignSourceV3RowsAtF(f, x))
		if err != nil {
			t.Fatalf("base replay at %d: %v", evalIdx, err)
		}
		if len(gotFpar) != len(formalFpar) || len(gotFagg) != len(formalFagg) {
			t.Fatalf("base replay lengths=(%d,%d) want (%d,%d)", len(gotFpar), len(gotFagg), len(formalFpar), len(formalFagg))
		}
		for i := range formalFpar {
			if want := EvalPoly(formalFpar[i], x, f.ringQ.Modulus[0]); gotFpar[i] != want {
				t.Fatalf("base Fpar[%d] at eval %d=%d want %d", i, evalIdx, gotFpar[i], want)
			}
		}
		for i := range formalFagg {
			if want := EvalPoly(formalFagg[i], x, f.ringQ.Modulus[0]); gotFagg[i] != want {
				t.Fatalf("base Fagg[%d] at eval %d=%d want %d", i, evalIdx, gotFagg[i], want)
			}
		}
	}

	field, err := deriveSmallFieldParamsNoRowsV3(f.ringQ, f.omega, f.opts.Theta)
	if err != nil {
		t.Fatal(err)
	}
	e := field.OmegaS1
	rowsK := make([]kf.Elem, len(f.rows))
	for i := range f.rows {
		rowsK[i] = field.K.EvalFPolyAtK(f.rows[i].Coeffs[0], e)
	}
	evalK, err := f.cfg.CoreKEvaluator(field.K)
	if err != nil {
		t.Fatal(err)
	}
	gotFparK, gotFaggK, err := evalK(e, rowsK)
	if err != nil {
		t.Fatal(err)
	}
	for i := range formalFpar {
		want := field.K.EvalFPolyAtK(formalFpar[i], e)
		if !elemEqual(field.K, gotFparK[i], want) {
			t.Fatalf("K Fpar[%d] differs from formal relation", i)
		}
	}
	for i := range formalFagg {
		want := field.K.EvalFPolyAtK(formalFagg[i], e)
		if !elemEqual(field.K, gotFaggK[i], want) {
			t.Fatalf("K Fagg[%d] differs from formal relation", i)
		}
	}
}

func TestIntGenISISPreSignSourceV3AggregateDotEquivalence(t *testing.T) {
	for _, theta := range []int{7, 13} {
		t.Run(fmt.Sprintf("theta-%d", theta), func(t *testing.T) {
			testIntGenISISPreSignSourceV3AggregateDotEquivalence(t, theta)
		})
	}
}

func testIntGenISISPreSignSourceV3AggregateDotEquivalence(t *testing.T, theta int) {
	f := newIntGenISISPreSignSourceV3FixtureTheta(t, theta)
	field, err := deriveSmallFieldParamsNoRowsV3(f.ringQ, f.omega, f.opts.Theta)
	if err != nil {
		t.Fatal(err)
	}
	full, err := f.cfg.CoreKEvaluator(field.K)
	if err != nil {
		t.Fatal(err)
	}
	directFactory, err := f.cfg.AggregateDotFactoryK(field.K)
	if err != nil {
		t.Fatal(err)
	}
	parallelFactory, err := f.cfg.AggregateDotFactoryK(field.K, ExecutionPolicy{WorkerBudget: 15, IssuancePlanWorkers: 15})
	if err != nil {
		t.Fatal(err)
	}
	count := f.cfg.AggregateConstraintCount()
	if count != 1024 {
		t.Fatalf("aggregate constraint count=%d want 1024", count)
	}
	gammas := sampleFSVectorK(3, count, field.K.Theta, field.K.Q,
		newFSRNGForTranscript(TranscriptVersionSmallWood2025V3, "PreSignSourceAggregateDotTest", []byte("deterministic-random-gamma")))
	for _, index := range []int{0, 31, 32, 1023} {
		oneHot := make([]KScalar, count)
		for j := range oneHot {
			oneHot[j] = make(KScalar, field.K.Theta)
		}
		oneHot[index][index%field.K.Theta] = 1
		gammas = append(gammas, oneHot)
	}
	points := []kf.Elem{
		field.K.EmbedF(0),
		field.K.EmbedF(17),
		field.K.EmbedF(uint64(f.opts.Theta*31 + 1)),
		field.OmegaS1,
	}
	for gammaIndex, gamma := range gammas {
		direct, err := directFactory(gamma)
		if err != nil {
			t.Fatalf("bind gamma %d: %v", gammaIndex, err)
		}
		parallel, err := parallelFactory(gamma)
		if err != nil {
			t.Fatalf("bind parallel gamma %d: %v", gammaIndex, err)
		}
		for pointIndex, e := range points {
			rows := make([]kf.Elem, len(f.rows))
			for i := range f.rows {
				rows[i] = field.K.EvalFPolyAtK(f.rows[i].Coeffs[0], e)
			}
			_, explicitResiduals, err := full(e, rows)
			if err != nil {
				t.Fatalf("full gamma=%d point=%d: %v", gammaIndex, pointIndex, err)
			}
			if len(explicitResiduals) != count {
				t.Fatalf("full aggregate residuals=%d want %d", len(explicitResiduals), count)
			}
			want := field.K.Zero()
			gammaElem := field.K.Zero()
			term := field.K.Zero()
			for j := range explicitResiduals {
				setKCoords(field.K, &gammaElem, gamma[j])
				field.K.MulInto(&term, gammaElem, explicitResiduals[j])
				field.K.AddInto(&want, want, term)
			}
			got, err := direct(e, rows)
			if err != nil {
				t.Fatalf("direct gamma=%d point=%d: %v", gammaIndex, pointIndex, err)
			}
			gotParallel, err := parallel(e, rows)
			if err != nil {
				t.Fatalf("parallel gamma=%d point=%d: %v", gammaIndex, pointIndex, err)
			}
			if !elemEqual(field.K, gotParallel, got) {
				t.Fatalf("parallel aggregate plan differs gamma=%d point=%d", gammaIndex, pointIndex)
			}
			if !elemEqual(field.K, got, want) {
				t.Fatalf("aggregate dot differs for gamma=%d point=%d", gammaIndex, pointIndex)
			}
		}
	}
	if _, err := directFactory(gammas[0][:count-1]); err == nil {
		t.Fatal("direct aggregate accepted a truncated gamma family")
	}
	if _, err := directFactory(append(append([]KScalar(nil), gammas[0]...), make(KScalar, field.K.Theta))); err == nil {
		t.Fatal("direct aggregate accepted an appended aggregate family")
	}
}

// TestIntGenISISPreSignSourceV3CompleteQBitExact is the end-to-end audit gate
// for the production aggregate fast path. It builds the complete SmallWood Q
// at both maintained extension widths over the same randomized committed PCS rows and the same
// full-limb Fiat--Shamir challenges: once with the independent 1,024-residual
// evaluator and once with the challenge-bound weighted evaluator. Equality is
// deliberately structural, including every coefficient limb and Degree field,
// rather than equality at a sampled subset of points.
func TestIntGenISISPreSignSourceV3CompleteQBitExact(t *testing.T) {
	for _, tc := range []struct {
		name    string
		theta   int
		degreeQ int
	}{
		{name: "WF128", theta: 7, degreeQ: 391},
		{name: "BQ128", theta: 13, degreeQ: 472},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testIntGenISISPreSignSourceV3CompleteQBitExact(t, tc.theta, tc.degreeQ)
		})
	}
}

func testIntGenISISPreSignSourceV3CompleteQBitExact(t *testing.T, theta, expectedDQ int) {
	f := newIntGenISISPreSignSourceV3FixtureTheta(t, theta)
	field, err := deriveSmallFieldParamsNoRowsV3(f.ringQ, f.omega, f.opts.Theta)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := intGenISISDegreeMetadataForLayout(f.ringQ, f.pub, f.layout, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	dQ := meta.PaperConservativeDQ
	if dQ != expectedDQ {
		t.Fatalf("theta=%d issuance dQ=%d want %d", theta, dQ, expectedDQ)
	}
	pcsNCols := resolvePCSNCols(f.opts, len(f.omega))
	pcs, err := buildSmallFieldPCSRowsFromLiteralInputsV3(
		f.ringQ,
		f.omega,
		pcsNCols,
		f.opts.Ell,
		field.K,
		field.OmegaS1,
		f.rowInputs,
		[]*KPoly{newZeroKPoly(field.K.Theta, dQ+1)},
		dQ,
	)
	if err != nil {
		t.Fatal(err)
	}
	physical := make([][]uint64, len(pcs.RowInputs))
	for i := range pcs.RowInputs {
		physical[i] = append([]uint64(nil), pcs.RowInputs[i].Head...)
	}

	formalFpar, formalFagg := intGenISISPreSignSourceV3FormalBuckets(f.set)
	if len(formalFagg) != f.cfg.AggregateConstraintCount() {
		t.Fatalf("formal aggregate count=%d want %d", len(formalFagg), f.cfg.AggregateConstraintCount())
	}
	gammaPrime := sampleFSPolyTensorK(
		1,
		len(formalFpar),
		len(f.omega),
		field.K.Theta,
		field.K.Q,
		newFSRNGForTranscript(TranscriptVersionSmallWood2025V3, "PreSignSourceCompleteQGammaPrime", []byte("complete-q-bit-exact")),
	)
	gammaAgg := sampleFSVectorK(
		1,
		len(formalFagg),
		field.K.Theta,
		field.K.Q,
		newFSRNGForTranscript(TranscriptVersionSmallWood2025V3, "PreSignSourceCompleteQGammaAgg", []byte("complete-q-bit-exact")),
	)
	full, err := f.cfg.CoreKEvaluator(field.K)
	if err != nil {
		t.Fatal(err)
	}
	common := semanticQBuildV3Input{
		Ring:                f.ringQ,
		K:                   field.K,
		OmegaWitness:        f.omega,
		OmegaExtra:          field.OmegaS1,
		MuInv:               field.MuInv,
		PhysicalRows:        physical,
		ReplayWitnessRows:   pcs.PCSGeometry.ReplayWitnessRows,
		LogicalWitnessCount: pcs.PCSGeometry.LogicalWitnessPolys,
		MaskRowOffset:       pcs.MaskRowOffset,
		MaskRowCount:        pcs.MaskRowCount,
		MaskDegreeBound:     dQ,
		DegreeBound:         dQ,
		Eval:                full,
		GammaPrimeK:         gammaPrime,
		GammaAggK:           gammaAgg,
	}
	formalQ, err := buildSemanticQKV3(common)
	if err != nil {
		t.Fatalf("formal complete Q: %v", err)
	}

	parallel, err := f.cfg.ParallelKEvaluator(field.K)
	if err != nil {
		t.Fatal(err)
	}
	directFactory, err := f.cfg.AggregateDotFactoryK(field.K)
	if err != nil {
		t.Fatal(err)
	}
	optimized := common
	optimized.EvalParallel = parallel
	optimized.AggregateDot = directFactory
	optimized.AggregateCount = f.cfg.AggregateConstraintCount()
	optimizedQ, err := buildSemanticQKV3(optimized)
	if err != nil {
		t.Fatalf("optimized complete Q: %v", err)
	}
	if !reflect.DeepEqual(optimizedQ, formalQ) {
		t.Fatal("optimized complete Q is not bit-exact with the 1,024-residual formal evaluator")
	}
}

func intGenISISPreSignSourceV3BucketValidOnOmega(q uint64, omega []uint64, fpar, fagg [][]uint64) (bool, bool) {
	parallelOK := true
	for _, coeff := range fpar {
		for _, x := range omega {
			if EvalPoly(coeff, x, q) != 0 {
				parallelOK = false
			}
		}
	}
	aggregateOK := true
	for _, coeff := range fagg {
		sum := uint64(0)
		for _, x := range omega {
			sum = modAdd(sum, EvalPoly(coeff, x, q), q)
		}
		if sum != 0 {
			aggregateOK = false
		}
	}
	return parallelOK, aggregateOK
}

func cloneIntGenISISPreSignSourceV3NTTRows(ringQ *ring.Ring, rows []*ring.Poly) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	for i := range rows {
		out[i] = ringQ.NewPoly()
		ring.Copy(rows[i], out[i])
	}
	return out
}

func tamperIntGenISISPreSignSourceV3Head(t *testing.T, f intGenISISPreSignSourceV3Fixture, rowsNTT []*ring.Poly, row, lane int, delta uint64) {
	t.Helper()
	coeff, err := sourceOnlyRowCoeffV3(f.ringQ, rowsNTT, row)
	if err != nil {
		t.Fatal(err)
	}
	change := scalePoly(f.cfg.Basis.LagrangeBasis[lane], delta, f.ringQ.Modulus[0])
	coeff = polyAdd(coeff, change, f.ringQ.Modulus[0])
	updated := f.ringQ.NewPoly()
	copy(updated.Coeffs[0], coeff)
	f.ringQ.NTT(updated, updated)
	rowsNTT[row] = updated
}

func TestIntGenISISPreSignSourceV3FullTransformAndTailTampering(t *testing.T) {
	f := newIntGenISISPreSignSourceV3Fixture(t)
	q := f.ringQ.Modulus[0]
	baseFpar, baseFagg := intGenISISPreSignSourceV3FormalBuckets(f.set)
	if parOK, aggOK := intGenISISPreSignSourceV3BucketValidOnOmega(q, f.omega, baseFpar, baseFagg); !parOK || !aggOK {
		t.Fatalf("honest source-only relation invalid: parallel=%v aggregate=%v", parOK, aggOK)
	}

	// Carrier 10 contains semantic coefficient blocks 20 and 21. Changing its
	// first lane from code 4 to code 5 is another valid base-9 carrier value,
	// and changes coefficient 20*32=640, well beyond the old 32-coordinate
	// surface. Membership therefore still passes; the full 1024-coordinate
	// commitment transform must be what rejects it.
	tampered := cloneIntGenISISPreSignSourceV3NTTRows(f.ringQ, f.rowsNTT)
	carrier := f.layout.IntGenISISPreSign.MCarrierStart + 10
	tamperIntGenISISPreSignSourceV3Head(t, f, tampered, carrier, 0, 1)
	tamperedSet, err := buildIntGenISISPreSignSourceOnlyConstraintSetV3(f.ringQ, f.pub, f.layout, tampered, f.omega)
	if err != nil {
		t.Fatal(err)
	}
	tamperedFpar, tamperedFagg := intGenISISPreSignSourceV3FormalBuckets(tamperedSet)
	parOK, aggOK := intGenISISPreSignSourceV3BucketValidOnOmega(q, f.omega, tamperedFpar, tamperedFagg)
	if !parOK {
		t.Fatal("valid carrier tamper was rejected by membership instead of exercising commitment binding")
	}
	if aggOK {
		t.Fatal("full-ring commitment transform accepted a valid-carrier tamper at semantic coefficient 640")
	}
	nonzeroHighCoordinate := false
	for tIndex := intGenISISPreSignSourceNCols; tIndex < len(tamperedFagg); tIndex++ {
		sum := uint64(0)
		for _, x := range f.omega {
			sum = modAdd(sum, EvalPoly(tamperedFagg[tIndex], x, q), q)
		}
		if sum != 0 {
			nonzeroHighCoordinate = true
			break
		}
	}
	if !nonzeroHighCoordinate {
		t.Fatal("tamper beyond coefficient 32 did not reach any high NTT commitment coordinate")
	}

	// The first 16 lanes of the first tail row are reserved zero. A range-valid
	// value 1 must be rejected by the independent reserved-support selector.
	tailTampered := cloneIntGenISISPreSignSourceV3NTTRows(f.ringQ, f.rowsNTT)
	tamperIntGenISISPreSignSourceV3Head(t, f, tailTampered, f.layout.IntGenISISPreSign.MSeedViewStart, 0, 1)
	tailSet, err := buildIntGenISISPreSignSourceOnlyConstraintSetV3(f.ringQ, f.pub, f.layout, tailTampered, f.omega)
	if err != nil {
		t.Fatal(err)
	}
	if EvalPoly(tailSet.FparIntCoeffs[0], f.omega[0], q) == 0 {
		t.Fatal("reserved-zero tail selector accepted a nonzero reserved lane")
	}
}

func TestIntGenISISPreSignSourceV3NonzeroSAndECommitment(t *testing.T) {
	f := newIntGenISISPreSignSourceV3Fixture(t)
	q := f.ringQ.Modulus[0]
	s := f.ringQ.NewPoly()
	e := f.ringQ.NewPoly()
	s.Coeffs[0][333] = 1
	e.Coeffs[0][777] = q - 1
	f.wit.S = []*ring.Poly{s}
	f.wit.E = []*ring.Poly{e}

	commitment := f.ringQ.NewPoly()
	f.ringQ.MulScalar(f.wit.M[0], 2, commitment)
	scaledS := f.ringQ.NewPoly()
	f.ringQ.MulScalar(s, 3, scaledS)
	f.ringQ.Add(commitment, scaledS, commitment)
	f.ringQ.Add(commitment, e, commitment)
	f.ringQ.NTT(commitment, commitment)
	f.pub.Com = []*ring.Poly{commitment}

	rows, _, layout, _, omega, _, _, err := buildIntGenISISPreSignSourceOnlyRowsV3(f.ringQ, f.pub, f.wit, f.opts, f.pub.X0Len)
	if err != nil {
		t.Fatal(err)
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = f.ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		f.ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	set, err := buildIntGenISISPreSignSourceOnlyConstraintSetV3(f.ringQ, f.pub, layout, rowsNTT, omega)
	if err != nil {
		t.Fatal(err)
	}
	fpar, fagg := intGenISISPreSignSourceV3FormalBuckets(set)
	if parallelOK, aggregateOK := intGenISISPreSignSourceV3BucketValidOnOmega(q, omega, fpar, fagg); !parallelOK || !aggregateOK {
		t.Fatalf("nonzero s/e commitment invalid: parallel=%v aggregate=%v", parallelOK, aggregateOK)
	}
}

func TestIntGenISISPreSignSourceV3IdentityBindingAndLegacyRejection(t *testing.T) {
	f := newIntGenISISPreSignSourceV3Fixture(t)
	if got := string(f.pub.Extras["IntGenISIS.issuance_relation"].([]byte)); got != intGenISISPreSignRelationVersionSourceOnlyV3 {
		t.Fatalf("bound issuance relation=%q", got)
	}
	if got := string(f.pub.Extras["IntGenISIS.issuance_layout"].([]byte)); got != intGenISISPreSignLayoutVersionSourceOnlyCarrierV3 {
		t.Fatalf("bound issuance layout=%q", got)
	}
	current, err := canonicalPublicStatementWithLayoutBytesV3(f.pub, f.layout)
	if err != nil {
		t.Fatal(err)
	}
	legacy := f.layout
	legacyPre := *legacy.IntGenISISPreSign
	legacyPre.LayoutVersion = ""
	legacyPre.RelationVersion = ""
	legacy.IntGenISISPreSign = &legacyPre
	oldStatement, err := canonicalPublicStatementWithLayoutBytesV3(f.pub, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(current, oldStatement) {
		t.Fatal("canonical public statement did not bind the source-only relation/layout identity")
	}
	if _, err := newIntGenISISPreSignReplayConfig(f.ringQ, f.pub, legacy, f.omega, f.domainPoints); err == nil {
		t.Fatal("strict-v3 replay accepted a legacy/identity-free issuance layout")
	}
	if reflect.DeepEqual(legacy, f.layout) {
		t.Fatal("test did not construct a distinct legacy layout")
	}
}
