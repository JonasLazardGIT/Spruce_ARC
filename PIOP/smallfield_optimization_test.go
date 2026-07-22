package PIOP

import (
	"reflect"
	"runtime"
	"testing"

	lvcs "vSIS-Signature/LVCS"
)

func referenceVTargets(mod uint64, rows, coeffs [][]uint64) [][]uint64 {
	if len(rows) == 0 {
		return nil
	}
	out := make([][]uint64, len(coeffs))
	for k := range coeffs {
		out[k] = make([]uint64, len(rows[0]))
		for i := range out[k] {
			for j := range rows {
				out[k][i] = lvcs.MulAddMod64(out[k][i], coeffs[k][j], rows[j][i], mod)
			}
		}
	}
	return out
}

func TestComputeVTargetsParallelMatchesReference(t *testing.T) {
	const (
		q     = uint64(1017857)
		nrows = 41
		ncols = 2048
		m     = 8
	)
	rows := make([][]uint64, nrows)
	for j := range rows {
		rows[j] = make([]uint64, ncols)
		for i := range rows[j] {
			value := uint64((j*4099 + i*65537 + 29) % int(q))
			if (i+j)%89 == 0 {
				value += 2 * q
			}
			rows[j][i] = value
		}
	}
	coeffs := make([][]uint64, m)
	for k := range coeffs {
		coeffs[k] = make([]uint64, nrows)
		for j := range coeffs[k] {
			value := uint64((k*12289 + j*257 + 5) % int(q))
			if (k+j)%13 == 0 {
				value += q
			}
			coeffs[k][j] = value
		}
	}
	want := referenceVTargets(q, rows, coeffs)
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	serial := computeVTargets(q, rows, coeffs)
	runtime.GOMAXPROCS(4)
	parallel := computeVTargets(q, rows, coeffs)
	if !reflect.DeepEqual(serial, want) {
		t.Fatal("serial computeVTargets differs from reduced reference")
	}
	if !reflect.DeepEqual(parallel, want) {
		t.Fatal("parallel computeVTargets differs from reduced reference")
	}
}

func TestComputeVTargetsWideModulusFallback(t *testing.T) {
	const q = uint64(^uint32(0)) + 16
	rows := [][]uint64{
		{q - 1, q - 2, 2*q + 3},
		{q - 4, q - 5, q - 6},
		{7, 8, 9},
	}
	coeffs := [][]uint64{{q - 1, q - 2, q + 3}, {4, q - 5, 6}}
	if got, want := computeVTargets(q, rows, coeffs), referenceVTargets(q, rows, coeffs); !reflect.DeepEqual(got, want) {
		t.Fatalf("wide-modulus fallback mismatch: got=%v want=%v", got, want)
	}
}

func TestCompressionPivotColsParallelDeterministic(t *testing.T) {
	const (
		q    = uint64(1017857)
		rows = 64
		cols = 1024
	)
	coeff := make([][]uint64, rows)
	for r := range coeff {
		coeff[r] = make([]uint64, cols)
		coeff[r][r] = 1
		for c := rows; c < cols; c++ {
			coeff[r][c] = uint64((r*8191 + c*131 + 7) % int(q))
		}
	}
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	serial, serialFullRank := compressionPivotCols(coeff, cols, q)
	runtime.GOMAXPROCS(4)
	parallel, parallelFullRank := compressionPivotCols(coeff, cols, q)
	if !serialFullRank || !parallelFullRank {
		t.Fatalf("full-rank matrix rejected: serial=%v parallel=%v", serialFullRank, parallelFullRank)
	}
	if !reflect.DeepEqual(serial, parallel) {
		t.Fatalf("pivot columns differ: serial=%v parallel=%v", serial, parallel)
	}
	for i, pivot := range serial {
		if pivot != i {
			t.Fatalf("pivot[%d]=%d want %d", i, pivot, i)
		}
	}
}

func BenchmarkComputeVTargetsArtifactGeometry(b *testing.B) {
	const (
		q     = uint64(1017857)
		nrows = 428
		ncols = 46
		m     = 70
	)
	rows := make([][]uint64, nrows)
	for j := range rows {
		rows[j] = make([]uint64, ncols)
		for i := range rows[j] {
			rows[j][i] = uint64((j*4099 + i*65537 + 29) % int(q))
		}
	}
	coeffs := make([][]uint64, m)
	for k := range coeffs {
		coeffs[k] = make([]uint64, nrows)
		for j := range coeffs[k] {
			coeffs[k][j] = uint64((k*12289 + j*257 + 5) % int(q))
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeVTargets(q, rows, coeffs)
	}
}
