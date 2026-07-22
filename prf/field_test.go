package prf

import (
	"math/bits"
	"math/rand"
	"testing"
)

func TestFieldMulMatchesWideReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20260722))
	for _, q := range []uint64{17, 1017857, uint64(^uint32(0)), uint64(^uint32(0)) + 16} {
		field := NewField(q)
		for i := 0; i < 10000; i++ {
			a := rng.Uint64() % q
			b := rng.Uint64() % q
			hi, lo := bits.Mul64(a, b)
			_, want := bits.Div64(hi, lo, q)
			if got := uint64(field.mul(Elem(a), Elem(b))); got != want {
				t.Fatalf("q=%d a=%d b=%d got=%d want=%d", q, a, b, got, want)
			}
		}
	}
}
