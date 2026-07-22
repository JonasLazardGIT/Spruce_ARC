package lvcs

import "math/bits"

// Reducer64 is a Barrett-style single-multiply modular reducer for moduli that
// fit in 32 bits. It lets callers accumulate many products in raw uint64 words
// and reduce once, avoiding a hardware division per multiply.
type Reducer64 struct {
	mod   uint64
	recip uint64
	fast  bool
}

// NewReducer64 precomputes the reciprocal floor(2^64/mod) used by the fast path.
func NewReducer64(mod uint64) Reducer64 {
	r := Reducer64{mod: mod}
	if mod > 1 && mod <= uint64(^uint32(0)) {
		r.recip, _ = bits.Div64(1, 0, mod)
		r.fast = true
	}
	return r
}

// Reduce returns v mod r.mod for any v < 2^64. The Barrett estimate never
// overestimates the quotient, so the correction loop only ever subtracts a
// small bounded number of times.
func (r Reducer64) Reduce(v uint64) uint64 {
	if v < r.mod {
		return v
	}
	if r.fast {
		qhat, _ := bits.Mul64(v, r.recip)
		rem := v - qhat*r.mod
		for rem >= r.mod {
			rem -= r.mod
		}
		return rem
	}
	return v % r.mod
}

// MulReduce returns (a*b) mod r.mod for reduced inputs a,b < r.mod. On the
// small-modulus fast path (mod <= 2^32) the product fits in one 64-bit word, so
// it uses the division-free Barrett reduction; otherwise it falls back to a
// 128-bit reduction. The r.fast test is a single, perfectly predicted branch —
// far cheaper than a hardware divide per multiply.
func (r Reducer64) MulReduce(a, b uint64) uint64 {
	if r.fast {
		return r.Reduce(a * b)
	}
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, r.mod)
	return rem
}

func mulMod64Reduced(a, b, mod uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, mod)
	return rem
}

func addMod64Reduced(a, b, mod uint64) uint64 {
	s, c := bits.Add64(a, b, 0)
	if c == 1 || s >= mod {
		s -= mod
	}
	return s
}

// MulAddMod64 returns (sum + a*b) mod mod in constant-time on 64-bit words.
func MulAddMod64(sum, a, b, mod uint64) uint64 {
	if a >= mod {
		a %= mod
	}
	if b >= mod {
		b %= mod
	}
	rem := mulMod64Reduced(a, b, mod)
	if sum >= mod {
		sum %= mod
	}
	return addMod64Reduced(sum, rem, mod)
}

// MulMod64 returns (a*b) mod mod using 128-bit intermediate multiplication.
func MulMod64(a, b, mod uint64) uint64 {
	if a >= mod {
		a %= mod
	}
	if b >= mod {
		b %= mod
	}
	return mulMod64Reduced(a, b, mod)
}

// AddMod64 returns (a+b) mod mod.
func AddMod64(a, b, mod uint64) uint64 {
	if a >= mod {
		a %= mod
	}
	if b >= mod {
		b %= mod
	}
	return addMod64Reduced(a, b, mod)
}
