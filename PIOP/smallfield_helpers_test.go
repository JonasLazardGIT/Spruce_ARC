package PIOP

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	lvcs "vSIS-Signature/LVCS"
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

func TestBuildSmallFieldWitnessRowsFromLiteralInputsPreservesOmegaHeads(t *testing.T) {
	chdirForPIOPTest(t, piopTestRepoRoot(t))
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	omegaWitness := make([]uint64, 8)
	for i := range omegaWitness {
		omegaWitness[i] = uint64(i + 2)
	}
	sf, err := deriveSmallFieldParamsNoRows(ringQ, omegaWitness, 3)
	if err != nil {
		t.Fatalf("small field params: %v", err)
	}
	q := ringQ.Modulus[0]
	logical := make([]lvcs.RowInput, 19)
	for row := range logical {
		head := make([]uint64, len(omegaWitness))
		for j := range head {
			head[j] = uint64((row*31 + j*17 + 9) % int(q))
		}
		pNTT := BuildThetaPrime(ringQ, head, omegaWitness)
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(pNTT, coeff)
		logical[row] = lvcs.RowInput{
			Head:       head,
			PolyCoeffs: trimCoeffsCopy(coeff.Coeffs[0], q),
		}
	}
	pcsNCols := 16
	rows, err := buildSmallFieldWitnessRowsFromLiteralInputs(ringQ, omegaWitness, pcsNCols, sf.K, sf.OmegaS1, logical)
	if err != nil {
		t.Fatalf("literal small-field rows: %v", err)
	}
	layerSize := len(omegaWitness) + sf.K.Theta
	wantRows := ceilDiv(len(logical), pcsNCols) * layerSize
	if len(rows) != wantRows {
		t.Fatalf("rows=%d want %d", len(rows), wantRows)
	}
	for block := 0; block < ceilDiv(len(logical), pcsNCols); block++ {
		base := block * layerSize
		for j := range omegaWitness {
			for col := 0; col < pcsNCols; col++ {
				idx := block*pcsNCols + col
				want := uint64(0)
				if idx < len(logical) {
					want = logical[idx].Head[j] % q
				}
				if rows[base+j][col] != want {
					t.Fatalf("block=%d omega=%d col=%d got=%d want=%d", block, j, col, rows[base+j][col], want)
				}
			}
		}
		for col := 0; col < pcsNCols; col++ {
			idx := block*pcsNCols + col
			if idx >= len(logical) {
				continue
			}
			y := sf.K.EvalFPolyAtK(logical[idx].PolyCoeffs, sf.OmegaS1)
			for coord := 0; coord < sf.K.Theta; coord++ {
				got := rows[base+len(omegaWitness)+coord][col]
				want := y.Limb[coord] % q
				if got != want {
					t.Fatalf("omegaS1 limb row=%d coord=%d got=%d want=%d", idx, coord, got, want)
				}
			}
		}
	}
}
