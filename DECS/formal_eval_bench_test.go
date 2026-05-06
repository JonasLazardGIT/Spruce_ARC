package decs

import (
	"testing"

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

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan.evalInto(dst, points[i%len(points)], red)
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
		if _, err := pr.CommitInit(); err != nil {
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
