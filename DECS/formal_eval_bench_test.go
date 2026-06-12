package decs

import (
	"testing"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func decsBenchPoints(n int, q uint64) []uint64 {
	points := make([]uint64, n)
	for i := range points {
		points[i] = uint64(i+1) % q
		if points[i] == 0 {
			points[i] = 1
		}
	}
	return points
}

func benchmarkFormalEvalPlanShape(b *testing.B, rowCount, degree, nLeaves int) {
	const q = uint64(1054721)
	rows := formalRowsForCommitTest(rowCount, degree, q)
	points := decsBenchPoints(nLeaves, q)
	plan := newFormalEvalPlan(rows, q)
	red := newModReducer64(q)
	dst := make([]uint64, rowCount)
	powers := make([]uint64, plan.maxDeg+1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x := points[i%len(points)]
		computeFormalEvalPowers(powers, x, red)
		plan.evalIntoPrepared(dst, x, red, powers)
	}
}

func BenchmarkDECSFormalEvalPlanSW90Shape(b *testing.B) {
	benchmarkFormalEvalPlanShape(b, 567, 50, 8383)
}

func BenchmarkDECSFormalEvalPlanSW115Shape(b *testing.B) {
	benchmarkFormalEvalPlanShape(b, 503, 43, 11176)
}

func benchmarkFormalCommitInitShape(b *testing.B, rowCount, degree, eta, nLeaves int) {
	ringQ, err := ring.NewRing(1024, []uint64{1054721})
	if err != nil {
		b.Fatalf("NewRing: %v", err)
	}
	q := ringQ.Modulus[0]
	points := decsBenchPoints(nLeaves, q)
	pr, err := NewProverWithParamsAndPointsFormalChecked(
		ringQ,
		formalRowsForCommitTest(rowCount, degree, q),
		Params{Degree: degree, Eta: eta, NonceBytes: 16},
		points,
	)
	if err != nil {
		b.Fatalf("NewProverWithParamsAndPointsFormalChecked: %v", err)
	}
	pr.MFormal = maskRowsForCommitTest(eta, degree, q)
	pr.nonceSeed = make([]byte, pr.params.NonceBytes)
	for i := range pr.nonceSeed {
		pr.nonceSeed[i] = byte(31 + i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pr.CommitInitWithOptions(CommitOptions{}); err != nil {
			b.Fatalf("CommitInit: %v", err)
		}
	}
}

func BenchmarkDECSCommitInitFormalSW90Shape(b *testing.B) {
	benchmarkFormalCommitInitShape(b, 567, 50, 36, 8383)
}

func BenchmarkDECSCommitInitFormalSW115Shape(b *testing.B) {
	benchmarkFormalCommitInitShape(b, 503, 43, 41, 11176)
}

type benchPhaseRecorder struct {
	durations map[string]time.Duration
}

func newBenchPhaseRecorder() *benchPhaseRecorder {
	return &benchPhaseRecorder{durations: make(map[string]time.Duration)}
}

func (r *benchPhaseRecorder) RecordDuration(label string, d time.Duration) {
	r.durations[label] += d
}

func (r *benchPhaseRecorder) report(b *testing.B, n int) {
	if r == nil || n <= 0 {
		return
	}
	for _, label := range []string{
		"decs.mask_sampling",
		"decs.eval_hash",
		"decs.merkle",
		"decs.formal_evaluation_cpu",
		"decs.leaf_encoding_cpu",
		"decs.nonce_derivation_cpu",
		"decs.leaf_hashing_cpu",
	} {
		if d := r.durations[label]; d > 0 {
			b.ReportMetric(float64(d.Nanoseconds())/float64(n)/1e6, label+"_ms/op")
		}
	}
}

func benchmarkMaintainedFormalCommitInitShape(b *testing.B, rowCount, degree, eta, nLeaves int, phases bool) {
	benchmarkMaintainedFormalCommitInitShapeWithOptions(b, rowCount, degree, eta, nLeaves, phases, commitInitOptions{forceScalarFormalEval: true})
}

func benchmarkMaintainedFormalCommitInitShapeWithOptions(b *testing.B, rowCount, degree, eta, nLeaves int, phases bool, opts commitInitOptions) {
	ringQ, err := ring.NewRing(1024, []uint64{1017857})
	if err != nil {
		b.Fatalf("NewRing: %v", err)
	}
	q := ringQ.Modulus[0]
	points := decsBenchPoints(nLeaves, q)
	pr, err := NewProverWithParamsAndPointsFormalChecked(
		ringQ,
		formalRowsForCommitTest(rowCount, degree, q),
		Params{Degree: degree, Eta: eta, NonceBytes: 16},
		points,
	)
	if err != nil {
		b.Fatalf("NewProverWithParamsAndPointsFormalChecked: %v", err)
	}
	pr.MFormal = maskRowsForCommitTest(eta, degree, q)
	pr.nonceSeed = make([]byte, pr.params.NonceBytes)
	for i := range pr.nonceSeed {
		pr.nonceSeed[i] = byte(31 + i)
	}
	var recorder *benchPhaseRecorder
	if phases {
		recorder = newBenchPhaseRecorder()
		opts.phaseRecorder = recorder
		opts.workerCount = 1
		opts.recordSubphases = true
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pr.commitInitWithOptions(opts); err != nil {
			b.Fatalf("CommitInit: %v", err)
		}
	}
	b.StopTimer()
	if phases {
		recorder.report(b, b.N)
	}
}

func BenchmarkDECSCommitInitFormalN1024Compact96Showing(b *testing.B) {
	benchmarkMaintainedFormalCommitInitShape(b, 471, 373, 40, 230208, false)
}

func BenchmarkDECSCommitInitFormalN1024Compact96ShowingScalarLegacy(b *testing.B) {
	benchmarkMaintainedFormalCommitInitShapeWithOptions(b, 471, 373, 40, 230208, false, commitInitOptions{forceScalarFormalEval: true})
}

func BenchmarkDECSCommitInitFormalN1024Compact96ShowingCombined(b *testing.B) {
	benchmarkMaintainedFormalCommitInitShapeWithOptions(b, 471, 373, 40, 230208, false, commitInitOptions{})
}

func BenchmarkDECSCommitInitFormalN1024Compact96ShowingTiled8(b *testing.B) {
	benchmarkMaintainedFormalCommitInitShapeWithOptions(b, 471, 373, 40, 230208, false, commitInitOptions{tileSize: 8})
}

func BenchmarkDECSCommitInitFormalN1024Compact96ShowingPhases(b *testing.B) {
	benchmarkMaintainedFormalCommitInitShape(b, 471, 373, 40, 230208, true)
}

func BenchmarkDECSCommitInitFormalN1024Compact125Showing(b *testing.B) {
	benchmarkMaintainedFormalCommitInitShape(b, 407, 471, 48, 608192, false)
}

func BenchmarkDECSCommitInitFormalN1024Compact125ShowingPhases(b *testing.B) {
	benchmarkMaintainedFormalCommitInitShape(b, 407, 471, 48, 608192, true)
}

func benchmarkDECSLeafHashShape(b *testing.B, rowCount, eta int) {
	leafBytes := 4*(rowCount+eta) + 2 + 16
	leaf := make([]byte, leafBytes)
	for i := range leaf {
		leaf[i] = byte(17 + i)
	}
	h := sha3.NewShake256()
	b.SetBytes(int64(leafBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hashLeafWith(h, leaf, DefaultHashBytes)
	}
}

func BenchmarkDECSLeafHashSW90Shape(b *testing.B) {
	benchmarkDECSLeafHashShape(b, 567, 36)
}

func BenchmarkDECSLeafHashSW115Shape(b *testing.B) {
	benchmarkDECSLeafHashShape(b, 503, 41)
}

func benchmarkDECSMerkleFromLeafHashesShape(b *testing.B, nLeaves int) {
	leaves := make([][]byte, nLeaves)
	for i := range leaves {
		leaves[i] = make([]byte, DefaultHashBytes)
		for j := range leaves[i] {
			leaves[i][j] = byte(i + 3*j)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildMerkleTreeFromLeafHashBytes(leaves, DefaultHashBytes)
	}
}

func BenchmarkDECSMerkleFromLeafHashesSW90Shape(b *testing.B) {
	benchmarkDECSMerkleFromLeafHashesShape(b, 8383)
}

func BenchmarkDECSMerkleFromLeafHashesSW115Shape(b *testing.B) {
	benchmarkDECSMerkleFromLeafHashesShape(b, 11176)
}
