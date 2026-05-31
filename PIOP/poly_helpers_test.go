package PIOP

import (
	"math/rand"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
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

func TestAddMulModXN1Power2IntoMatchesPolyMulReduce(t *testing.T) {
	q := uint64(1054721)
	rng := rand.New(rand.NewSource(19))
	sizes := []int{1, 2, 4, 8, 16, 32, 64}
	for _, n := range sizes {
		for iter := 0; iter < 100; iter++ {
			scale := uint64(rng.Int63n(int64(3 * q)))
			a := randomPolyCoeffs(rng, 1+rng.Intn(n), q)
			b := randomPolyCoeffs(rng, 1+rng.Intn(n), q)
			base := randomPolyCoeffs(rng, n, q)
			got := append([]uint64(nil), base...)
			addMulModXN1Power2Into(got, a, b, scale, q)

			want := append([]uint64(nil), base...)
			term := scalePoly(reducePolyModXN1(polyMul(a, b, q), n, q), scale, q)
			addScaledInto(want, term, 1, q)
			assertPaddedPolyEqual(t, got, want, q)
		}
	}
}

func TestAddMulModXN1NTTIntoMatchesPower2(t *testing.T) {
	q := uint64(1054721)
	ringQ, err := ring.NewRing(1024, []uint64{q})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	rng := rand.New(rand.NewSource(29))
	for iter := 0; iter < 50; iter++ {
		scale := uint64(rng.Int63n(int64(3 * q)))
		aLen := 256 + rng.Intn(769)
		bLen := 256 + rng.Intn(769)
		a := randomPolyCoeffs(rng, aLen, q)
		b := randomPolyCoeffs(rng, bLen, q)
		base := randomPolyCoeffs(rng, int(ringQ.N), q)

		got := append([]uint64(nil), base...)
		if !addMulModXN1NTTInto(ringQ, got, a, b, scale, newNegacyclicProductScratch(ringQ)) {
			t.Fatalf("NTT helper declined dense product a=%d b=%d", len(a), len(b))
		}

		want := append([]uint64(nil), base...)
		addMulModXN1Power2Into(want, a, b, scale, q)
		assertPaddedPolyEqual(t, got, want, q)
	}
}

func TestAddMulModXN1PrecomputedNTTIntoMatchesPower2(t *testing.T) {
	q := uint64(1054721)
	ringQ, err := ring.NewRing(1024, []uint64{q})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	rng := rand.New(rand.NewSource(31))
	for iter := 0; iter < 50; iter++ {
		scale := uint64(rng.Int63n(int64(3 * q)))
		a := randomPolyCoeffs(rng, 32+rng.Intn(224), q)
		b := randomPolyCoeffs(rng, 256+rng.Intn(769), q)
		aNTT, ok := nttPolyFromModXN1Coeffs(ringQ, a)
		if !ok {
			t.Fatalf("precompute NTT failed")
		}
		base := randomPolyCoeffs(rng, int(ringQ.N), q)

		got := append([]uint64(nil), base...)
		if !addMulModXN1PrecomputedNTTInto(ringQ, got, aNTT, b, scale, newNegacyclicProductScratch(ringQ)) {
			t.Fatalf("precomputed NTT helper declined product a=%d b=%d", len(a), len(b))
		}

		want := append([]uint64(nil), base...)
		addMulModXN1Power2Into(want, a, b, scale, q)
		assertPaddedPolyEqual(t, got, want, q)
	}
}

func TestAddMulModXN1PrecomputedBothNTTIntoMatchesPower2(t *testing.T) {
	q := uint64(1054721)
	ringQ, err := ring.NewRing(1024, []uint64{q})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	rng := rand.New(rand.NewSource(32))
	for iter := 0; iter < 50; iter++ {
		scale := uint64(rng.Int63n(int64(3 * q)))
		a := randomPolyCoeffs(rng, 32+rng.Intn(224), q)
		b := randomPolyCoeffs(rng, 256+rng.Intn(769), q)
		aNTT, ok := nttPolyFromModXN1Coeffs(ringQ, a)
		if !ok {
			t.Fatalf("precompute a NTT failed")
		}
		bNTT := ringQ.NewPoly()
		if !coeffsToNTTPolyInto(ringQ, bNTT, b) {
			t.Fatalf("precompute b NTT failed")
		}
		base := randomPolyCoeffs(rng, int(ringQ.N), q)

		got := append([]uint64(nil), base...)
		if !addMulModXN1PrecomputedBothNTTInto(ringQ, got, aNTT, bNTT, scale, newNegacyclicProductScratch(ringQ)) {
			t.Fatalf("both-NTT helper declined product a=%d b=%d", len(a), len(b))
		}

		want := append([]uint64(nil), base...)
		addMulModXN1Power2Into(want, a, b, scale, q)
		assertPaddedPolyEqual(t, got, want, q)
	}
}

func TestAddMulNTTIntoAccumulatorMatchesPower2(t *testing.T) {
	q := uint64(1054721)
	ringQ, err := ring.NewRing(1024, []uint64{q})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	rng := rand.New(rand.NewSource(33))
	for iter := 0; iter < 50; iter++ {
		terms := 2 + rng.Intn(6)
		base := randomPolyCoeffs(rng, int(ringQ.N), q)
		got := append([]uint64(nil), base...)
		want := append([]uint64(nil), base...)
		scratch := newNegacyclicProductScratch(ringQ)
		resetRingPolyCoeffs(scratch.acc)
		for term := 0; term < terms; term++ {
			scale := uint64(rng.Int63n(int64(3 * q)))
			a := randomPolyCoeffs(rng, 32+rng.Intn(224), q)
			b := randomPolyCoeffs(rng, 256+rng.Intn(769), q)
			aNTT, ok := nttPolyFromModXN1Coeffs(ringQ, a)
			if !ok {
				t.Fatalf("precompute a NTT failed")
			}
			bNTT := ringQ.NewPoly()
			if !coeffsToNTTPolyInto(ringQ, bNTT, b) {
				t.Fatalf("precompute b NTT failed")
			}
			if !addMulNTTIntoAccumulator(ringQ, scratch.acc, aNTT, bNTT, scale, scratch) {
				t.Fatalf("accumulator declined product a=%d b=%d", len(a), len(b))
			}
			addMulModXN1Power2Into(want, a, b, scale, q)
		}
		if !flushNTTAccumulatorInto(ringQ, got, scratch.acc, scratch) {
			t.Fatalf("accumulator flush failed")
		}
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

func BenchmarkAddMulModXN1Into(b *testing.B) {
	q := uint64(1054721)
	rng := rand.New(rand.NewSource(17))
	n := 1024
	a := randomPolyCoeffs(rng, n, q)
	c := randomPolyCoeffs(rng, n, q)
	dst := make([]uint64, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range dst {
			dst[j] = 0
		}
		addMulModXN1Into(dst, a, c, 7, q)
	}
}

func BenchmarkAddMulModXN1Power2Into(b *testing.B) {
	q := uint64(1054721)
	rng := rand.New(rand.NewSource(23))
	n := 1024
	a := randomPolyCoeffs(rng, n, q)
	c := randomPolyCoeffs(rng, n, q)
	dst := make([]uint64, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range dst {
			dst[j] = 0
		}
		addMulModXN1Power2Into(dst, a, c, 7, q)
	}
}

func BenchmarkAddMulModXN1NTTInto(b *testing.B) {
	q := uint64(1054721)
	ringQ, err := ring.NewRing(1024, []uint64{q})
	if err != nil {
		b.Fatalf("NewRing: %v", err)
	}
	rng := rand.New(rand.NewSource(37))
	n := 1024
	a := randomPolyCoeffs(rng, n, q)
	c := randomPolyCoeffs(rng, n, q)
	dst := make([]uint64, n)
	scratch := newNegacyclicProductScratch(ringQ)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range dst {
			dst[j] = 0
		}
		if !addMulModXN1NTTInto(ringQ, dst, a, c, 7, scratch) {
			b.Fatalf("NTT helper declined product")
		}
	}
}

func BenchmarkAddMulModXN1PrecomputedNTTInto(b *testing.B) {
	q := uint64(1054721)
	ringQ, err := ring.NewRing(1024, []uint64{q})
	if err != nil {
		b.Fatalf("NewRing: %v", err)
	}
	rng := rand.New(rand.NewSource(41))
	n := 1024
	a := randomPolyCoeffs(rng, 96, q)
	c := randomPolyCoeffs(rng, n, q)
	aNTT, ok := nttPolyFromModXN1Coeffs(ringQ, a)
	if !ok {
		b.Fatalf("precompute NTT failed")
	}
	dst := make([]uint64, n)
	scratch := newNegacyclicProductScratch(ringQ)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range dst {
			dst[j] = 0
		}
		if !addMulModXN1PrecomputedNTTInto(ringQ, dst, aNTT, c, 7, scratch) {
			b.Fatalf("precomputed NTT helper declined product")
		}
	}
}

func BenchmarkIntGenISISRowCoeffCache(b *testing.B) {
	ringQ, err := ring.NewRing(1024, []uint64{1054721})
	if err != nil {
		b.Fatalf("NewRing: %v", err)
	}
	rows := make([]*ring.Poly, 512)
	for i := range rows {
		p := ringQ.NewPoly()
		for j := 0; j < int(ringQ.N); j++ {
			p.Coeffs[0][j] = uint64((i + j) % int(ringQ.Modulus[0]))
		}
		ringQ.NTT(p, p)
		rows[i] = p
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache, err := newIntGenISISRowCoeffCache(ringQ, rows)
		if err != nil {
			b.Fatalf("row coeff cache: %v", err)
		}
		if _, err := cache.Row(i % len(rows)); err != nil {
			b.Fatalf("row coeff: %v", err)
		}
	}
}
