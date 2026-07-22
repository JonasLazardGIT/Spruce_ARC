package lvcs

import (
	"math/big"
	"math/bits"
	"testing"
)

func TestReducer64MatchesDivision(t *testing.T) {
	mods := []uint64{2, 17, 65537, 1017857, uint64(^uint32(0)), uint64(^uint32(0)) + 16}
	values := []uint64{0, 1, 2, 16, 1 << 20, 1 << 32, 1 << 48, ^uint64(0)}
	for _, mod := range mods {
		red := NewReducer64(mod)
		for _, value := range values {
			if got, want := red.Reduce(value), value%mod; got != want {
				t.Fatalf("Reduce mod=%d value=%d got=%d want=%d", mod, value, got, want)
			}
		}
		factors := []uint64{0, 1, 2, mod / 2, mod - 2, mod - 1}
		for _, a := range factors {
			for _, b := range factors {
				hi, lo := bits.Mul64(a, b)
				_, want := bits.Div64(hi, lo, mod)
				if got := red.MulReduce(a, b); got != want {
					t.Fatalf("MulReduce mod=%d a=%d b=%d got=%d want=%d", mod, a, b, got, want)
				}
			}
		}
	}
}

func TestReducer64LazyAccumulationBound(t *testing.T) {
	max := new(big.Int).SetUint64(^uint64(0))
	for _, mod := range []uint64{2, 17, 65537, 1017857, uint64(^uint32(0))} {
		limit := NewReducer64(mod).MaxLazyAccumulationTerms()
		if limit == 0 {
			t.Fatalf("mod=%d unexpectedly has no lazy accumulation capacity", mod)
		}
		product := new(big.Int).SetUint64((mod - 1) * (mod - 1))
		carried := new(big.Int).SetUint64(mod - 1)
		atLimit := new(big.Int).Mul(new(big.Int).SetUint64(limit), product)
		atLimit.Add(atLimit, carried)
		if atLimit.Cmp(max) > 0 {
			t.Fatalf("mod=%d limit=%d overflows", mod, limit)
		}
		overLimit := new(big.Int).Add(new(big.Int).Set(atLimit), product)
		if overLimit.Cmp(max) <= 0 {
			t.Fatalf("mod=%d limit=%d is not maximal", mod, limit)
		}
	}
	if got := NewReducer64(uint64(^uint32(0)) + 16).MaxLazyAccumulationTerms(); got != 0 {
		t.Fatalf("wide modulus returned lazy limit %d", got)
	}
}
