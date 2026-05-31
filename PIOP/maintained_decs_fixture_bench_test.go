package PIOP

import (
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type maintainedShowingDECSFixture struct {
	ringQ     *ring.Ring
	params    decs.Params
	points    []uint64
	pFormal   [][]uint64
	mFormal   [][]uint64
	nonceSeed []byte
}

type maintainedDECSBenchRecorder struct {
	durations map[string]int64
}

func newMaintainedDECSBenchRecorder() *maintainedDECSBenchRecorder {
	return &maintainedDECSBenchRecorder{durations: make(map[string]int64)}
}

func (r *maintainedDECSBenchRecorder) RecordDuration(label string, d time.Duration) {
	r.durations[label] += int64(d)
}

func (r *maintainedDECSBenchRecorder) report(b *testing.B, n int) {
	if r == nil || n <= 0 {
		return
	}
	for _, label := range []string{
		"decs.mask_sampling",
		"decs.eval_hash",
		"decs.formal_evaluation_cpu",
		"decs.leaf_encoding_cpu",
		"decs.nonce_derivation_cpu",
		"decs.leaf_hashing_cpu",
		"decs.merkle",
	} {
		if ns := r.durations[label]; ns > 0 {
			b.ReportMetric(float64(ns)/float64(n)/1e6, label+"_ms/op")
		}
	}
}

func simOptsFromIntGenISISTuningPreset(ringDegree int, t credential.IntGenISISTuningPreset) SimOpts {
	lvcsNCols := t.LVCSNCols
	if lvcsNCols < t.NCols {
		lvcsNCols = t.NCols
	}
	return ResolveSimOptsDefaults(SimOpts{
		Credential:                 true,
		CoeffPacking:               true,
		RingDegree:                 ringDegree,
		NCols:                      t.NCols,
		LVCSNCols:                  lvcsNCols,
		PostSignLVCSNCols:          lvcsNCols,
		PRFLVCSNCols:               lvcsNCols,
		NLeaves:                    t.NLeaves,
		Ell:                        t.Ell,
		EllPrime:                   t.EllPrime,
		Eta:                        t.Eta,
		Rho:                        t.Rho,
		Theta:                      t.Theta,
		Kappa:                      t.Kappa,
		DomainMode:                 DomainModeExplicit,
		PRFGroupRounds:             t.PRFGroupRounds,
		PRFCompanionMode:           PRFCompanionMode(t.PRFCompanionMode),
		PRFCheckpointSamples:       t.CheckpointSamples,
		SigShortnessRadix:          t.SigShortnessRadix,
		SigShortnessL:              t.SigShortnessDigits,
		IntGenISISMSECompression:   t.CompressedRows,
		IntGenISISReplayProjection: t.ReplayProjection,
		TranscriptProtocolMode:     TranscriptProtocolSmallField2025V1,
		TranscriptVersion:          TranscriptVersionSmallWood2025,
	})
}

func buildMaintainedShowingPublicWitnessForBench(tb testing.TB, ringQ *ring.Ring, profile credential.IntGenISISProfile, opts SimOpts) (PublicInputs, WitnessInputs) {
	tb.Helper()
	params, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		tb.Fatalf("load prf params: %v", err)
	}
	layout, err := credential.DefaultSemanticMessageLayout(profile, params.LenKey)
	if err != nil {
		tb.Fatalf("semantic layout: %v", err)
	}
	msg, err := credential.EncodeSemanticMessage(layout, credential.ZeroSemanticAttributes(layout), []int64{1, 0, -1, 1, 0, -1, 1, 0})
	if err != nil {
		tb.Fatalf("encode semantic message: %v", err)
	}
	mRows := polysFromInt64ForIntGenISISTest(ringQ, msg.M)
	mAttrRows := polysFromInt64ForIntGenISISTest(ringQ, msg.MAttr)
	kRows := polysFromInt64ForIntGenISISTest(ringQ, msg.K)
	key, err := extractIntGenISISPRFKeyElemsFromSemanticM(ringQ, profile.B, mRows)
	if err != nil {
		tb.Fatalf("extract key: %v", err)
	}
	nonce, noncePublic := fixedNonceTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		tb.Fatalf("tag: %v", err)
	}

	zeroCoeff := ringQ.NewPoly()
	oneCoeff := intGenISISTestCoeffConst(ringQ, 1)
	mNTT := intGenISISTestNTT(ringQ, mRows[0])
	oneNTT := intGenISISTestNTT(ringQ, oneCoeff)
	cmNTT := intGenISISTestPublicBinomialNTT(ringQ, 1, 1)
	u0NTT := ringQ.NewPoly()
	ringQ.MulCoeffs(cmNTT, mNTT, u0NTT)
	ringQ.Add(u0NTT, oneNTT, u0NTT)
	u0 := ringQ.NewPoly()
	ringQ.InvNTT(u0NTT, u0)

	sigRows := make([]*ring.Poly, profile.SignaturePreimageLen)
	sigRows[0] = u0
	for i := 1; i < len(sigRows); i++ {
		sigRows[i] = zeroCoeff.CopyNew()
	}
	sRows := make([]*ring.Poly, profile.KS)
	for i := range sRows {
		sRows[i] = zeroCoeff.CopyNew()
	}
	x0Rows := make([]*ring.Poly, profile.EllX0)
	for i := range x0Rows {
		x0Rows[i] = zeroCoeff.CopyNew()
	}
	aRows := make([]*ring.Poly, profile.SignaturePreimageLen)
	aRows[0] = intGenISISTestPublicConstNTT(ringQ, 1)
	for i := 1; i < len(aRows); i++ {
		aRows[i] = intGenISISTestPublicConstNTT(ringQ, 0)
	}
	bRows := make([]*ring.Poly, 3+profile.EllX0)
	bRows[0] = intGenISISTestPublicConstNTT(ringQ, 0)
	for i := 1; i < len(bRows); i++ {
		bRows[i] = intGenISISTestPublicConstNTT(ringQ, 1)
	}
	asRow := make([]*ring.Poly, profile.KS)
	for i := range asRow {
		asRow[i] = intGenISISTestPublicConstNTT(ringQ, 0)
	}

	wit := WitnessInputs{CoeffNativeShowing: &CoeffNativeShowingWitness{
		Sig:         sigRows,
		M:           mRows[0],
		MAttr:       mAttrRows[0],
		K:           kRows[0],
		S:           sRows,
		E:           []*ring.Poly{zeroCoeff.CopyNew()},
		MuSig:       []*ring.Poly{zeroCoeff.CopyNew()},
		X0:          x0Rows,
		X1:          zeroCoeff.CopyNew(),
		Z:           oneCoeff,
		PackedNCols: opts.NCols,
	}}
	pub := PublicInputs{
		A:            [][]*ring.Poly{aRows},
		B:            bRows,
		CM:           [][]*ring.Poly{{cmNTT}},
		AS:           [][]*ring.Poly{asRow},
		Tag:          lanesFromElemsTest(tag, opts.NCols),
		Nonce:        noncePublic,
		BoundB:       profile.B,
		X0Len:        profile.EllX0,
		RingDegree:   profile.N,
		HashRelation: credential.HashRelationBBTran,
		IntGenISIS:   true,
		Extras:       map[string]interface{}{"IntGenISIS.signature_bound_value": int64(6142)},
	}
	return pub, wit
}

func deterministicFormalMasks(eta, degree int, q uint64) [][]uint64 {
	rng := rand.New(rand.NewSource(20260531))
	out := make([][]uint64, eta)
	for i := range out {
		out[i] = make([]uint64, degree+1)
		for j := range out[i] {
			out[i][j] = uint64(rng.Int63n(int64(q-1))) + 1
		}
	}
	return out
}

func maintainedFormalMaxDegree(rows [][]uint64) int {
	maxDeg := -1
	for _, row := range rows {
		for d := len(row) - 1; d >= 0; d-- {
			if row[d] != 0 {
				if d > maxDeg {
					maxDeg = d
				}
				break
			}
		}
	}
	if maxDeg < 0 {
		return 0
	}
	return maxDeg
}

func maintainedFormalRowsAtMost(rows [][]uint64, degree int) int {
	count := 0
	for _, row := range rows {
		rowDeg := -1
		for d := len(row) - 1; d >= 0; d-- {
			if row[d] != 0 {
				rowDeg = d
				break
			}
		}
		if rowDeg <= degree {
			count++
		}
	}
	return count
}

func maintainedFormalNonZeroCount(rows [][]uint64) int {
	count := 0
	for _, row := range rows {
		for _, c := range row {
			if c != 0 {
				count++
			}
		}
	}
	return count
}

func maintainedFormalUnitCoeffCount(rows [][]uint64, q uint64) int {
	count := 0
	for _, row := range rows {
		for _, c := range row {
			if c == 1 || (q > 1 && c == q-1) {
				count++
			}
		}
	}
	return count
}

func buildMaintainedShowingDECSFixture(b *testing.B, presetName string) maintainedShowingDECSFixture {
	b.Helper()
	chdirForPIOPIntGenISISTest(b)
	preset, ok := credential.LookupIntGenISISPreset(presetName)
	if !ok {
		b.Fatalf("missing preset %s", presetName)
	}
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		b.Fatalf("missing profile %s", preset.Profile)
	}
	ringQ, err := credential.LoadRingWithDegree(profile.N)
	if err != nil {
		b.Fatalf("load ring: %v", err)
	}
	opts := simOptsFromIntGenISISTuningPreset(profile.N, preset.Showing)
	pub, wit := buildMaintainedShowingPublicWitnessForBench(b, ringQ, profile, opts)
	prepared, err := PrepareIntGenISISShowingContext(pub, opts)
	if err != nil {
		b.Fatalf("prepare showing context: %v", err)
	}
	_, state, err := buildIntGenISISShowingCombinedPreparedWithState(pub, wit, opts, prepared)
	if err != nil {
		b.Fatalf("build showing state: %v", err)
	}
	if state == nil || state.builtPK == nil || state.builtPK.DecsProver == nil {
		b.Fatalf("missing built DECS prover state")
	}
	params := state.builtPK.Params
	nonceSeed := make([]byte, params.NonceBytes)
	for i := range nonceSeed {
		nonceSeed[i] = byte(91 + i)
	}
	return maintainedShowingDECSFixture{
		ringQ:     ringQ,
		params:    params,
		points:    append([]uint64(nil), state.builtPK.Points...),
		pFormal:   copyMatrix(state.builtPK.RowPolyCoeffs),
		mFormal:   deterministicFormalMasks(params.Eta, params.Degree, ringQ.Modulus[0]),
		nonceSeed: nonceSeed,
	}
}

func benchmarkMaintainedShowingDECSFixture(b *testing.B, presetName string) {
	fixture := buildMaintainedShowingDECSFixture(b, presetName)
	recorder := newMaintainedDECSBenchRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pr, err := decs.NewProverWithParamsAndPointsFormalChecked(fixture.ringQ, fixture.pFormal, fixture.params, fixture.points)
		if err != nil {
			b.Fatalf("new prover: %v", err)
		}
		if err := pr.SetFormalCommitmentRandomnessForTesting(fixture.mFormal, fixture.nonceSeed); err != nil {
			b.Fatalf("set commitment randomness: %v", err)
		}
		if _, err := pr.CommitInitWithOptions(decs.CommitOptions{PhaseRecorder: recorder, RecordSubphases: true}); err != nil {
			b.Fatalf("CommitInit: %v", err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(len(fixture.pFormal)), "rows/op")
	b.ReportMetric(float64(fixture.params.Eta), "eta/op")
	b.ReportMetric(float64(fixture.params.Degree), "degree/op")
	b.ReportMetric(float64(maintainedFormalMaxDegree(fixture.pFormal)), "p_max_degree/op")
	b.ReportMetric(float64(maintainedFormalRowsAtMost(fixture.pFormal, 64)), "p_rows_degree_le_64/op")
	b.ReportMetric(float64(maintainedFormalNonZeroCount(fixture.pFormal)), "p_nnz/op")
	b.ReportMetric(float64(maintainedFormalUnitCoeffCount(fixture.pFormal, fixture.ringQ.Modulus[0])), "p_unit_coeffs/op")
	b.ReportMetric(float64(len(fixture.points)), "leaves/op")
	recorder.report(b, b.N)
}

func BenchmarkDECSMaintainedShowingRowsN1024Compact96(b *testing.B) {
	benchmarkMaintainedShowingDECSFixture(b, credential.IntGenISISPresetN1024Compact96)
}

func BenchmarkDECSMaintainedShowingRowsN1024Compact125(b *testing.B) {
	benchmarkMaintainedShowingDECSFixture(b, credential.IntGenISISPresetN1024Compact125)
}
