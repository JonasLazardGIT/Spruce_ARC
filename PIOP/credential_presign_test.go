package PIOP

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func samplePackedHalfEvalPreSignTest(r *ring.Ring, bound int64, omega []uint64, rng *rand.Rand, lower bool) *ring.Poly {
	ncols := len(omega)
	mod := int64(2*bound + 1)
	q := int64(r.Modulus[0])
	head := make([]uint64, ncols)
	for i := 0; i < ncols; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			head[i] = uint64(v + q)
		} else {
			head[i] = uint64(v)
		}
	}
	half := ncols / 2
	if lower {
		for i := half; i < ncols; i++ {
			head[i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			head[i] = 0
		}
	}
	p := r.NewPoly()
	copy(p.Coeffs[0], Interpolate(omega, head, uint64(q)))
	return p
}

func sampleBoundedEvalPreSignTest(r *ring.Ring, bound int64, omega []uint64, rng *rand.Rand) *ring.Poly {
	ncols := len(omega)
	mod := int64(2*bound + 1)
	q := int64(r.Modulus[0])
	head := make([]uint64, ncols)
	for i := 0; i < ncols; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			head[i] = uint64(v + q)
		} else {
			head[i] = uint64(v)
		}
	}
	p := r.NewPoly()
	copy(p.Coeffs[0], Interpolate(omega, head, uint64(q)))
	return p
}

func preSignWitnessOmegaForRelationTest(ringQ *ring.Ring, opts SimOpts, relation string) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	lvcsNCols := opts.LVCSNCols
	if lvcsNCols <= 0 {
		lvcsNCols = opts.NCols
	}
	return deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, opts.NCols, lvcsNCols, opts.Ell, relation)
}

func credentialPreSignRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func credentialPreSignChdir(t *testing.T, dir string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

func TestDerivePreSignCarrierAndAliasRowsUsesSingletonX0Codec(t *testing.T) {
	root := credentialPreSignRepoRoot(t)
	credentialPreSignChdir(t, root)
	ringQ, err := credential.LoadRingWithDegree(0)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential: true,
		NCols:      16,
		LVCSNCols:  32,
		Ell:        18,
		NLeaves:    int(ringQ.N),
		DomainMode: DomainModeExplicit,
	})
	omega, err := preSignWitnessOmegaForRelationTest(ringQ, opts, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("derive omega: %v", err)
	}
	rng := rand.New(rand.NewSource(7))
	const (
		boundB  = int64(1)
		x0Bound = int64(5)
	)
	raw := PreSignRawRows{
		M1:  samplePackedHalfEvalPreSignTest(ringQ, boundB, omega, rng, true),
		M2:  samplePackedHalfEvalPreSignTest(ringQ, boundB, omega, rng, false),
		RU0: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, x0Bound, omega, rng), sampleBoundedEvalPreSignTest(ringQ, x0Bound, omega, rng)},
		RU1: sampleBoundedEvalPreSignTest(ringQ, boundB, omega, rng),
		R:   sampleBoundedEvalPreSignTest(ringQ, boundB, omega, rng),
		R0:  []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, x0Bound, omega, rng), sampleBoundedEvalPreSignTest(ringQ, x0Bound, omega, rng)},
		R1:  sampleBoundedEvalPreSignTest(ringQ, boundB, omega, rng),
		K0:  []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, 1, omega, rng), sampleBoundedEvalPreSignTest(ringQ, 1, omega, rng)},
		K1:  sampleBoundedEvalPreSignTest(ringQ, 1, omega, rng),
	}
	surface, err := DerivePreSignCarrierAndAliasRows(ringQ, boundB, x0Bound, omega, DomainModeExplicit, raw)
	if err != nil {
		t.Fatalf("derive surface: %v", err)
	}
	q := ringQ.Modulus[0]
	headOnOmega := func(p *ring.Poly, name string) []uint64 {
		t.Helper()
		head, err := rowHeadOnOmega(ringQ, omega, p, len(omega))
		if err != nil {
			t.Fatalf("%s head on omega: %v", name, err)
		}
		return head
	}
	checkSingletonFamily := func(name string, rawRows, carrierRows, aliasRows []*ring.Poly, bound int64) {
		t.Helper()
		for i := range rawRows {
			rawHead := headOnOmega(rawRows[i], fmt.Sprintf("%s raw[%d]", name, i))
			carrierHead := headOnOmega(carrierRows[i], fmt.Sprintf("%s carrier[%d]", name, i))
			aliasHead := headOnOmega(aliasRows[i], fmt.Sprintf("%s alias[%d]", name, i))
			for col := range rawHead {
				code, err := encodeSingletonCarrier(centeredLift(rawHead[col], q), bound)
				if err != nil {
					t.Fatalf("%s[%d] encode col=%d: %v", name, i, col, err)
				}
				wantCarrier := liftToField(q, int64(code))
				if carrierHead[col] != wantCarrier {
					t.Fatalf("%s[%d] carrier col=%d got=%d want=%d", name, i, col, carrierHead[col], wantCarrier)
				}
				if aliasHead[col]%q != rawHead[col]%q {
					t.Fatalf("%s[%d] alias col=%d got=%d want raw=%d", name, i, col, aliasHead[col]%q, rawHead[col]%q)
				}
			}
		}
	}
	checkScalarPairSingleton := func(name string, rawRow, carrierRow, aliasRow *ring.Poly, bound int64) {
		t.Helper()
		rawHead := headOnOmega(rawRow, name+" raw")
		carrierHead := headOnOmega(carrierRow, name+" carrier")
		aliasHead := headOnOmega(aliasRow, name+" alias")
		for col := range rawHead {
			code, err := encodeCarrierPair(centeredLift(rawHead[col], q), 0, bound)
			if err != nil {
				t.Fatalf("%s encode col=%d: %v", name, col, err)
			}
			wantCarrier := liftToField(q, int64(code))
			if carrierHead[col] != wantCarrier {
				t.Fatalf("%s carrier col=%d got=%d want=%d", name, col, carrierHead[col], wantCarrier)
			}
			if aliasHead[col]%q != rawHead[col]%q {
				t.Fatalf("%s alias col=%d got=%d want raw=%d", name, col, aliasHead[col]%q, rawHead[col]%q)
			}
		}
	}
	checkSingletonFamily("RU0", raw.RU0, surface.CarrierRU0Rows, surface.AliasRU0Rows, x0Bound)
	checkSingletonFamily("R0", raw.R0, surface.CarrierR0Rows, surface.AliasR0Rows, x0Bound)
	checkSingletonFamily("K0", raw.K0, surface.CarrierK0Rows, surface.AliasK0Rows, 1)
	checkScalarPairSingleton("RU1", raw.RU1, surface.CarrierRU1, surface.AliasRU1, boundB)
	checkScalarPairSingleton("R1", raw.R1, surface.CarrierR1, surface.AliasR1, boundB)
	checkScalarPairSingleton("K1", raw.K1, surface.CarrierK1, surface.AliasK1, 1)
}
