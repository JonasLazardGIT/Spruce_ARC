package kfield

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
)

const testQ = 1017857 // the maintained ~20-bit prover modulus

// refMul independently computes a*b in F_q[X]/(chi) via big.Int, as a check on
// the lazy small-field multiply.
func refMul(q uint64, chi, a, b []uint64) []uint64 {
	theta := len(chi) - 1
	Q := new(big.Int).SetUint64(q)
	res := make([]*big.Int, 2*theta-1)
	for i := range res {
		res[i] = new(big.Int)
	}
	for i := 0; i < theta; i++ {
		ai := new(big.Int).SetUint64(a[i] % q)
		for j := 0; j < theta; j++ {
			t := new(big.Int).Mul(ai, new(big.Int).SetUint64(b[j]%q))
			res[i+j].Add(res[i+j], t)
		}
	}
	// reduce modulo the monic chi: x^theta == -(sum_{j<theta} chi[j] x^j)
	for k := 2*theta - 2; k >= theta; k-- {
		c := new(big.Int).Mod(res[k], Q)
		if c.Sign() == 0 {
			continue
		}
		m := k - theta
		for j := 0; j < theta; j++ {
			t := new(big.Int).Mul(c, new(big.Int).SetUint64(chi[j]%q))
			res[m+j].Sub(res[m+j], t)
		}
		res[k].SetInt64(0)
	}
	out := make([]uint64, theta)
	for i := 0; i < theta; i++ {
		out[i] = new(big.Int).Mod(res[i], Q).Uint64()
	}
	return out
}

func randLimbs(rng *rand.Rand, theta int, q uint64) []uint64 {
	l := make([]uint64, theta)
	for i := range l {
		l[i] = rng.Uint64() % q
	}
	return l
}

func TestMulMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20260713))
	for _, theta := range []int{2, 3, 5, 7, 16, 24} {
		chi, err := FindIrreducible(testQ, theta, rng)
		if err != nil {
			t.Fatalf("theta=%d FindIrreducible: %v", theta, err)
		}
		f, err := New(testQ, theta, chi)
		if err != nil {
			t.Fatalf("theta=%d New: %v", theta, err)
		}
		for iter := 0; iter < 200; iter++ {
			a := Elem{Limb: randLimbs(rng, theta, testQ)}
			b := Elem{Limb: randLimbs(rng, theta, testQ)}
			got := f.Mul(a, b)
			want := refMul(testQ, chi, a.Limb, b.Limb)
			for i := 0; i < theta; i++ {
				if got.Limb[i] != want[i] {
					t.Fatalf("theta=%d iter=%d limb %d: got %d want %d", theta, iter, i, got.Limb[i], want[i])
				}
			}
		}
	}
}

func TestNewUncheckedMatchesNew(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, theta := range []int{2, 7, 16} {
		chi, err := FindIrreducible(testQ, theta, rng)
		if err != nil {
			t.Fatalf("FindIrreducible: %v", err)
		}
		checked, err := New(testQ, theta, chi)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		unchecked, err := NewUnchecked(testQ, theta, chi)
		if err != nil {
			t.Fatalf("NewUnchecked: %v", err)
		}
		for iter := 0; iter < 100; iter++ {
			a := Elem{Limb: randLimbs(rng, theta, testQ)}
			b := Elem{Limb: randLimbs(rng, theta, testQ)}
			g1 := checked.Mul(a, b)
			g2 := unchecked.Mul(a, b)
			for i := 0; i < theta; i++ {
				if g1.Limb[i] != g2.Limb[i] {
					t.Fatalf("theta=%d checked/unchecked mismatch limb %d: %d vs %d", theta, i, g1.Limb[i], g2.Limb[i])
				}
			}
		}
	}
}

// TestInverseRoundTrip exercises Mul + Inv (a * a^-1 == 1).
func TestInverseRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for _, theta := range []int{2, 5, 16} {
		chi, err := FindIrreducible(testQ, theta, rng)
		if err != nil {
			t.Fatalf("FindIrreducible: %v", err)
		}
		f, err := New(testQ, theta, chi)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		one := f.One()
		for iter := 0; iter < 20; iter++ {
			a := Elem{Limb: randLimbs(rng, theta, testQ)}
			if f.IsZero(a) {
				continue
			}
			inv := f.Inv(a)
			prod := f.Mul(a, inv)
			for i := 0; i < theta; i++ {
				if prod.Limb[i] != one.Limb[i] {
					t.Fatalf("theta=%d a*a^-1 != 1 at limb %d: %d", theta, i, prod.Limb[i])
				}
			}
		}
	}
}

func TestMulNormalizesInputLimbs(t *testing.T) {
	rng := rand.New(rand.NewSource(1234))
	chi, err := FindIrreducible(testQ, 5, rng)
	if err != nil {
		t.Fatalf("FindIrreducible: %v", err)
	}
	f, err := New(testQ, 5, chi)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := Elem{Limb: []uint64{testQ + 1, 2*testQ + 3, 4, 5, 3*testQ + 6}}
	b := Elem{Limb: []uint64{2*testQ + 7, 8, testQ + 9, 10, 11}}
	got := f.Mul(a, b)
	want := refMul(testQ, chi, a.Limb, b.Limb)
	for i := range want {
		if got.Limb[i] != want[i] {
			t.Fatalf("limb %d: got %d want %d", i, got.Limb[i], want[i])
		}
	}
}

func TestMulUsesReducedFallbackOutsideLazyBound(t *testing.T) {
	for _, q := range []uint64{uint64(^uint32(0)), uint64(^uint32(0)) + 16} {
		chi := []uint64{1, 1, 1}
		f, err := NewUnchecked(q, 2, chi)
		if err != nil {
			t.Fatalf("q=%d NewUnchecked: %v", q, err)
		}
		if f.lazyMul {
			t.Fatalf("q=%d unexpectedly selected lazy multiplication", q)
		}
		a := Elem{Limb: []uint64{q - 1, q - 2}}
		b := Elem{Limb: []uint64{q - 3, q - 4}}
		got := f.Mul(a, b)
		want := refMul(q, chi, a.Limb, b.Limb)
		for i := range want {
			if got.Limb[i] != want[i] {
				t.Fatalf("q=%d limb=%d got=%d want=%d", q, i, got.Limb[i], want[i])
			}
		}
	}
}

func TestMulHeapScratchMatchesReference(t *testing.T) {
	const theta = stackMulDeg + 1
	chi := make([]uint64, theta+1)
	for i := 0; i < theta; i++ {
		chi[i] = uint64(i + 1)
	}
	chi[theta] = 1
	f, err := NewUnchecked(testQ, theta, chi)
	if err != nil {
		t.Fatalf("NewUnchecked: %v", err)
	}
	if !f.lazyMul {
		t.Fatal("maintained modulus unexpectedly disabled lazy multiplication")
	}
	rng := rand.New(rand.NewSource(5678))
	a := Elem{Limb: randLimbs(rng, theta, testQ)}
	b := Elem{Limb: randLimbs(rng, theta, testQ)}
	got := f.Mul(a, b)
	want := refMul(testQ, chi, a.Limb, b.Limb)
	for i := range want {
		if got.Limb[i] != want[i] {
			t.Fatalf("limb=%d got=%d want=%d", i, got.Limb[i], want[i])
		}
	}
}

func TestNewUncheckedTrustBoundary(t *testing.T) {
	reducible := []uint64{0, 0, 1}
	if _, err := New(testQ, 2, reducible); err == nil {
		t.Fatal("New accepted a reducible polynomial")
	}
	if _, err := NewUnchecked(testQ, 2, reducible); err != nil {
		t.Fatalf("NewUnchecked rejected structurally valid trusted input: %v", err)
	}
}

func BenchmarkMul(b *testing.B) {
	for _, theta := range []int{7, 16} {
		b.Run(fmt.Sprintf("theta%d", theta), func(b *testing.B) {
			rng := rand.New(rand.NewSource(int64(theta)))
			chi, err := FindIrreducible(testQ, theta, rng)
			if err != nil {
				b.Fatalf("FindIrreducible: %v", err)
			}
			field, err := New(testQ, theta, chi)
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			a := Elem{Limb: randLimbs(rng, theta, testQ)}
			c := Elem{Limb: randLimbs(rng, theta, testQ)}
			out := field.Zero()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				field.MulInto(&out, a, c)
			}
		})
	}
}
