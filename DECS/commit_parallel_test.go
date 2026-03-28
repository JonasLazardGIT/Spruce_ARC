package decs

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"vSIS-Signature/credential"
)

func decsTestRepoRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func chdirForDECSTest(tb testing.TB, dir string) {
	tb.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		tb.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		tb.Fatalf("chdir %s: %v", dir, err)
	}
	tb.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

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
	chdirForDECSTest(t, decsTestRepoRoot(t))
	ringQ, err := credential.LoadDefaultRing()
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
		Params{Degree: degree, Eta: maskCount, NonceBytes: 16},
		points,
	)
	if err != nil {
		t.Fatalf("new prover: %v", err)
	}
	prover.MFormal = maskRowsForCommitTest(maskCount, degree, mod)
	prover.nonceSeed = make([]byte, prover.params.NonceBytes)
	for i := range prover.nonceSeed {
		prover.nonceSeed[i] = byte(17 + i)
	}
	return prover
}

func TestCommitInitDeterministicAcrossParallelism(t *testing.T) {
	old := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(old)

	prSerial := makeDeterministicFormalProver(t)
	runtime.GOMAXPROCS(1)
	rootSerial, err := prSerial.CommitInit()
	if err != nil {
		t.Fatalf("serial commit init: %v", err)
	}
	openSerial := prSerial.EvalOpen([]int{3, 17, 42})

	prParallel := makeDeterministicFormalProver(t)
	parallelProcs := old
	if parallelProcs < 2 {
		parallelProcs = 2
	}
	runtime.GOMAXPROCS(parallelProcs)
	rootParallel, err := prParallel.CommitInit()
	if err != nil {
		t.Fatalf("parallel commit init: %v", err)
	}
	openParallel := prParallel.EvalOpen([]int{3, 17, 42})

	if rootSerial != rootParallel {
		t.Fatalf("root mismatch: serial=%x parallel=%x", rootSerial, rootParallel)
	}
	if !reflect.DeepEqual(openSerial, openParallel) {
		t.Fatalf("opening mismatch between serial and parallel commit init")
	}
}
