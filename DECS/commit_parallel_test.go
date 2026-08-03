package decs

import (
	"bytes"
	"reflect"
	"runtime"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func formalRowsForCommitTest(rowCount int, degree int, mod uint64) [][]uint64 {
	rows := make([][]uint64, rowCount)
	for i := 0; i < rowCount; i++ {
		row := make([]uint64, degree+1)
		for j := range row {
			row[j] = uint64((i*17 + j*29 + 1) % int(mod))
		}
		rows[i] = row
	}
	return rows
}

func maskRowsForCommitTest(maskCount int, degree int, mod uint64) [][]uint64 {
	rows := make([][]uint64, maskCount)
	for i := 0; i < maskCount; i++ {
		row := make([]uint64, degree+1)
		for j := range row {
			row[j] = uint64((i*13 + j*31 + 7) % int(mod))
		}
		rows[i] = row
	}
	return rows
}

func makeDeterministicFormalProver(t testing.TB) *Prover {
	t.Helper()
	ringQ, err := ring.NewRing(1024, []uint64{1017857})
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	const (
		degree    = 32
		rowCount  = 12
		maskCount = 5
		nLeaves   = 256
	)
	mod := ringQ.Modulus[0]
	points := make([]uint64, nLeaves)
	for i := range points {
		points[i] = uint64(i + 1)
	}
	prover, err := NewProverWithParamsAndPointsFormalChecked(
		ringQ,
		formalRowsForCommitTest(rowCount, degree, mod),
		Params{Degree: degree, Eta: maskCount, TapeBytes: 16, HashBytes: 16},
		points,
	)
	if err != nil {
		t.Fatalf("new prover: %v", err)
	}
	prover.MFormal = maskRowsForCommitTest(maskCount, degree, mod)
	prover.tapes = make([]byte, prover.nLeaves*prover.params.TapeBytes)
	for i := range prover.tapes {
		prover.tapes[i] = byte(17 + i)
	}
	return prover
}

func TestCommitInitDeterministicAcrossParallelism(t *testing.T) {
	old := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(old)

	prSerial := makeDeterministicFormalProver(t)
	runtime.GOMAXPROCS(1)
	ctx := v2TestContext(CommitmentRoleMain, 21)
	rootSerial, err := prSerial.CommitInitV2WithOptions(ctx, CommitOptions{})
	if err != nil {
		t.Fatalf("serial commit init: %v", err)
	}
	openSerial, err := prSerial.EvalOpenV2([]int{3, 17, 42})
	if err != nil {
		t.Fatalf("serial opening: %v", err)
	}

	prParallel := makeDeterministicFormalProver(t)
	parallelProcs := old
	if parallelProcs < 2 {
		parallelProcs = 2
	}
	runtime.GOMAXPROCS(parallelProcs)
	rootParallel, err := prParallel.CommitInitV2WithOptions(ctx, CommitOptions{})
	if err != nil {
		t.Fatalf("parallel commit init: %v", err)
	}
	openParallel, err := prParallel.EvalOpenV2([]int{3, 17, 42})
	if err != nil {
		t.Fatalf("parallel opening: %v", err)
	}

	if !bytes.Equal(rootSerial, rootParallel) {
		t.Fatalf("root mismatch: serial=%x parallel=%x", rootSerial, rootParallel)
	}
	if !reflect.DeepEqual(openSerial, openParallel) {
		t.Fatalf("opening mismatch between serial and parallel commit init")
	}
}

func TestCommitInitV2TiledMatchesScalarRoot(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 22)
	prScalar := makeDeterministicFormalProver(t)
	rootScalar, err := prScalar.CommitInitV2WithOptions(ctx, CommitOptions{
		FormalEvalMode: FormalEvalScalar,
		WorkerCount:    1,
	})
	if err != nil {
		t.Fatalf("scalar commit init: %v", err)
	}
	openScalar, err := prScalar.EvalOpenV2([]int{0, 5, 123, 255})
	if err != nil {
		t.Fatalf("scalar opening: %v", err)
	}

	prOptimized := makeDeterministicFormalProver(t)
	rootOptimized, err := prOptimized.CommitInitV2WithOptions(ctx, CommitOptions{
		FormalEvalMode: FormalEvalCombined,
		WorkerCount:    3,
	})
	if err != nil {
		t.Fatalf("optimized commit init: %v", err)
	}
	openOptimized, err := prOptimized.EvalOpenV2([]int{0, 5, 123, 255})
	if err != nil {
		t.Fatalf("optimized opening: %v", err)
	}

	prTiled := makeDeterministicFormalProver(t)
	rootTiled, err := prTiled.CommitInitV2WithOptions(ctx, CommitOptions{
		FormalEvalMode:     FormalEvalTiled,
		FormalEvalTileSize: 7,
		WorkerCount:        3,
	})
	if err != nil {
		t.Fatalf("tiled commit init: %v", err)
	}
	openTiled, err := prTiled.EvalOpenV2([]int{0, 5, 123, 255})
	if err != nil {
		t.Fatalf("tiled opening: %v", err)
	}

	if !bytes.Equal(rootScalar, rootTiled) {
		t.Fatalf("root mismatch: scalar=%x tiled=%x", rootScalar, rootTiled)
	}
	if !bytes.Equal(rootScalar, rootOptimized) {
		t.Fatalf("root mismatch: scalar=%x optimized=%x", rootScalar, rootOptimized)
	}
	if !reflect.DeepEqual(openScalar, openTiled) {
		t.Fatalf("opening mismatch between scalar and tiled commit init")
	}
	if !reflect.DeepEqual(openScalar, openOptimized) {
		t.Fatalf("opening mismatch between scalar and optimized commit init")
	}
}
