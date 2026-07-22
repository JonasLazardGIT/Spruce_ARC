package lvcs

import (
	"reflect"
	"runtime"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestEvalInitManyParallelMatchesReference(t *testing.T) {
	const (
		q     = uint64(1017857)
		nrows = 41
		m     = 8
		ell   = 2048
	)
	ringQ, err := ring.NewRing(16, []uint64{q})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	rows := make([]RowInput, nrows)
	for j := range rows {
		rows[j].Tail = make([]uint64, ell)
		for i := range rows[j].Tail {
			value := uint64((j*7919 + i*104729 + 17) % int(q))
			if (i+j)%97 == 0 {
				value += 2 * q
			}
			rows[j].Tail[i] = value
		}
	}
	reqs := make([]EvalRequest, m)
	for k := range reqs {
		reqs[k].Coeffs = make([]uint64, nrows)
		for j := range reqs[k].Coeffs {
			value := uint64((k*65537 + j*8191 + 3) % int(q))
			if (k+j)%11 == 0 {
				value += q
			}
			reqs[k].Coeffs[j] = value
		}
	}
	prover := &ProverKey{Rows: rows, TailLen: ell}
	want := make([][]uint64, m)
	for k := range want {
		want[k] = make([]uint64, ell)
		for j := 0; j < nrows; j++ {
			for i := 0; i < ell; i++ {
				want[k][i] = MulAddMod64(want[k][i], reqs[k].Coeffs[j], rows[j].Tail[i], q)
			}
		}
	}

	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	serial, err := EvalInitManyChecked(ringQ, prover, reqs)
	if err != nil {
		t.Fatalf("serial EvalInitManyChecked: %v", err)
	}
	runtime.GOMAXPROCS(4)
	parallel, err := EvalInitManyChecked(ringQ, prover, reqs)
	if err != nil {
		t.Fatalf("parallel EvalInitManyChecked: %v", err)
	}
	if !reflect.DeepEqual(serial, want) {
		t.Fatal("serial EvalInitManyChecked differs from reduced reference")
	}
	if !reflect.DeepEqual(parallel, want) {
		t.Fatal("parallel EvalInitManyChecked differs from reduced reference")
	}
}

func BenchmarkEvalInitManyArtifactGeometry(b *testing.B) {
	const (
		q     = uint64(1017857)
		nrows = 428
		m     = 70
		ell   = 9
	)
	ringQ, err := ring.NewRing(16, []uint64{q})
	if err != nil {
		b.Fatalf("NewRing: %v", err)
	}
	rows := make([]RowInput, nrows)
	for j := range rows {
		rows[j].Tail = make([]uint64, ell)
		for i := range rows[j].Tail {
			rows[j].Tail[i] = uint64((j*7919 + i*104729 + 17) % int(q))
		}
	}
	reqs := make([]EvalRequest, m)
	for k := range reqs {
		reqs[k].Coeffs = make([]uint64, nrows)
		for j := range reqs[k].Coeffs {
			reqs[k].Coeffs[j] = uint64((k*65537 + j*8191 + 3) % int(q))
		}
	}
	prover := &ProverKey{Rows: rows, TailLen: ell}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EvalInitManyChecked(ringQ, prover, reqs); err != nil {
			b.Fatalf("EvalInitManyChecked: %v", err)
		}
	}
}
