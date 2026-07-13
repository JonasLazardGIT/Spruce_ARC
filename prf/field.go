package prf

import "math/bits"

// Elem represents a field element modulo q.
type Elem uint64

// Field exposes basic arithmetic modulo q.
type Field struct {
	q     uint64
	recip uint64 // floor(2^64/q), for division-free Barrett reduction
	fast  bool   // q fits in 32 bits, so a*b fits in 64 bits
}

// NewField constructs a Field with modulus q.
func NewField(q uint64) Field {
	f := Field{q: q}
	if q > 1 && q <= uint64(^uint32(0)) {
		f.recip, _ = bits.Div64(1, 0, q)
		f.fast = true
	}
	return f
}

func (f Field) Q() uint64 { return f.q }

func (f Field) add(a, b Elem) Elem {
	v := uint64(a) + uint64(b)
	if v >= f.q {
		v -= f.q
	}
	return Elem(v)
}

func (f Field) sub(a, b Elem) Elem {
	va := uint64(a)
	vb := uint64(b)
	if va >= vb {
		return Elem(va - vb)
	}
	return Elem(va + f.q - vb)
}

func (f Field) mul(a, b Elem) Elem {
	// q < 2^32 so the product fits in one 64-bit word; use a division-free
	// Barrett reduction (the estimate never overestimates, so the correction
	// loop subtracts at most a couple of times).
	if f.fast {
		p := uint64(a) * uint64(b)
		qhat, _ := bits.Mul64(p, f.recip)
		rem := p - qhat*f.q
		for rem >= f.q {
			rem -= f.q
		}
		return Elem(rem)
	}
	return Elem((uint64(a) * uint64(b)) % f.q)
}

// powSmall raises a to the small exponent d (suitable for Poseidon S-box).
func (f Field) powSmall(a Elem, d uint64) Elem {
	// binary exponentiation
	base := a
	var res Elem = 1
	exp := d
	for exp > 0 {
		if exp&1 == 1 {
			res = f.mul(res, base)
		}
		base = f.mul(base, base)
		exp >>= 1
	}
	return res
}
