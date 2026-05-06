package PIOP

import (
	"math/rand"
	"testing"
)

func TestMulModXN1MatchesPolyMulReduce(t *testing.T) {
	q := uint64(1054721)
	rng := rand.New(rand.NewSource(7))
	for iter := 0; iter < 200; iter++ {
		n := 1 + rng.Intn(48)
		a := randomPolyCoeffs(rng, 1+rng.Intn(2*n+7), q)
		b := randomPolyCoeffs(rng, 1+rng.Intn(2*n+7), q)
		got := make([]uint64, n)
		mulModXN1(got, a, b, q)
		want := reducePolyModXN1(polyMul(a, b, q), n, q)
		assertPaddedPolyEqual(t, got, want, q)
	}
}

func TestAddMulModXN1IntoMatchesPolyMulReduce(t *testing.T) {
	q := uint64(1054721)
	rng := rand.New(rand.NewSource(11))
	for iter := 0; iter < 200; iter++ {
		n := 1 + rng.Intn(48)
		scale := uint64(rng.Int63n(int64(q)))
		a := randomPolyCoeffs(rng, 1+rng.Intn(2*n+7), q)
		b := randomPolyCoeffs(rng, 1+rng.Intn(2*n+7), q)
		base := randomPolyCoeffs(rng, n, q)
		got := append([]uint64(nil), base...)
		addMulModXN1Into(got, a, b, scale, q)

		want := append([]uint64(nil), base...)
		term := scalePoly(reducePolyModXN1(polyMul(a, b, q), n, q), scale, q)
		addScaledInto(want, term, 1, q)
		assertPaddedPolyEqual(t, got, want, q)
	}
}

func TestAddScaledAndSubInto(t *testing.T) {
	q := uint64(1054721)
	rng := rand.New(rand.NewSource(13))
	for iter := 0; iter < 100; iter++ {
		n := 1 + rng.Intn(64)
		scale := uint64(rng.Int63n(int64(q)))
		dst := randomPolyCoeffs(rng, n, q)
		src := randomPolyCoeffs(rng, n+rng.Intn(16), q)
		got := append([]uint64(nil), dst...)
		addScaledInto(got, src, scale, q)
		subInto(got, scalePoly(src, scale, q), q)
		assertPaddedPolyEqual(t, got, dst, q)
	}
}

func randomPolyCoeffs(rng *rand.Rand, n int, q uint64) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = uint64(rng.Int63n(int64(q)))
	}
	return out
}

func assertPaddedPolyEqual(t *testing.T, got, want []uint64, q uint64) {
	t.Helper()
	for i := range got {
		var w uint64
		if i < len(want) {
			w = want[i] % q
		}
		if got[i]%q != w {
			t.Fatalf("coeff[%d] got %d want %d (got len=%d want len=%d)", i, got[i]%q, w, len(got), len(want))
		}
	}
	for i := len(got); i < len(want); i++ {
		if want[i]%q != 0 {
			t.Fatalf("extra coeff[%d] want nonzero %d", i, want[i]%q)
		}
	}
}
