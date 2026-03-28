package PIOP

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func piopTestRepoRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func chdirForPIOPTest(tb testing.TB, dir string) {
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

func witnessPolysForSmallFieldTest(ringQ *ring.Ring, count int, degree int) []*ring.Poly {
	out := make([]*ring.Poly, count)
	q := ringQ.Modulus[0]
	for i := 0; i < count; i++ {
		p := ringQ.NewPoly()
		limit := degree + 1
		if limit > len(p.Coeffs[0]) {
			limit = len(p.Coeffs[0])
		}
		for j := 0; j < limit; j++ {
			p.Coeffs[0][j] = uint64((i*19 + j*23 + 5) % int(q))
		}
		out[i] = p
	}
	return out
}

func TestBuildSmallFieldWitnessRowsMatchesReference(t *testing.T) {
	chdirForPIOPTest(t, piopTestRepoRoot(t))
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	omegaWitness := make([]uint64, 16)
	for i := range omegaWitness {
		omegaWitness[i] = uint64(i + 1)
	}
	sf, err := deriveSmallFieldParamsNoRows(ringQ, omegaWitness, 5)
	if err != nil {
		t.Fatalf("small field params: %v", err)
	}
	witnessPolys := witnessPolysForSmallFieldTest(ringQ, 160, 246)
	got, err := buildSmallFieldWitnessRows(ringQ, omegaWitness, 96, sf.K, sf.OmegaS1, witnessPolys)
	if err != nil {
		t.Fatalf("optimized witness rows: %v", err)
	}
	want, err := buildSmallFieldWitnessRowsReference(ringQ, omegaWitness, 96, sf.K, sf.OmegaS1, witnessPolys)
	if err != nil {
		t.Fatalf("reference witness rows: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("small-field witness rows mismatch")
	}
}
