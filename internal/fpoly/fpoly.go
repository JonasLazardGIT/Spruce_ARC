package fpoly

import "math/bits"

// Poly is a formal polynomial over F_q with variable-length coefficients.
// Coeffs[i] is the coefficient of X^i reduced modulo Q.
type Poly struct {
	Q      uint64
	Coeffs []uint64
}

func (p Poly) isZero() bool {
	if len(p.Coeffs) == 0 {
		return true
	}
	if len(p.Coeffs) == 1 {
		c0 := p.Coeffs[0]
		if c0 >= p.Q {
			c0 %= p.Q
		}
		return c0 == 0
	}
	return false
}

// New constructs a polynomial over F_q from the provided coefficient slice.
func New(q uint64, coeffs []uint64) Poly {
	if q == 0 {
		panic("fpoly: q must be non-zero")
	}
	if len(coeffs) == 0 {
		return Poly{Q: q, Coeffs: []uint64{0}}
	}
	out := make([]uint64, len(coeffs))
	for i := range coeffs {
		out[i] = coeffs[i] % q
	}
	out = trim(out, q)
	return Poly{Q: q, Coeffs: out}
}

// Zero returns the zero polynomial over F_q.
func Zero(q uint64) Poly {
	return Poly{Q: q, Coeffs: []uint64{0}}
}

// Add returns p + rhs.
func (p Poly) Add(rhs Poly) Poly {
	if p.Q != rhs.Q {
		panic("fpoly: mismatched modulus")
	}
	q := p.Q
	n := len(p.Coeffs)
	if len(rhs.Coeffs) > n {
		n = len(rhs.Coeffs)
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		var a uint64
		if i < len(p.Coeffs) {
			a = p.Coeffs[i]
		}
		if a >= q {
			a %= q
		}
		var b uint64
		if i < len(rhs.Coeffs) {
			b = rhs.Coeffs[i]
		}
		if b >= q {
			b %= q
		}
		out[i] = addModReduced(a, b, q)
	}
	return Poly{Q: q, Coeffs: trimReduced(out)}
}

// Sub returns p - rhs.
func (p Poly) Sub(rhs Poly) Poly {
	if p.Q != rhs.Q {
		panic("fpoly: mismatched modulus")
	}
	q := p.Q
	n := len(p.Coeffs)
	if len(rhs.Coeffs) > n {
		n = len(rhs.Coeffs)
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		var a uint64
		if i < len(p.Coeffs) {
			a = p.Coeffs[i]
		}
		if a >= q {
			a %= q
		}
		var b uint64
		if i < len(rhs.Coeffs) {
			b = rhs.Coeffs[i]
		}
		if b >= q {
			b %= q
		}
		out[i] = subModReduced(a, b, q)
	}
	return Poly{Q: q, Coeffs: trimReduced(out)}
}

// Scale returns c * p.
func (p Poly) Scale(c uint64) Poly {
	if c >= p.Q {
		c %= p.Q
	}
	out := make([]uint64, len(p.Coeffs))
	if c == 0 {
		return Poly{Q: p.Q, Coeffs: []uint64{0}}
	}
	for i := range p.Coeffs {
		v := p.Coeffs[i]
		if v >= p.Q {
			v %= p.Q
		}
		out[i] = mulModReduced(c, v, p.Q)
	}
	return Poly{Q: p.Q, Coeffs: trimReduced(out)}
}

// Mul returns p * rhs using formal convolution in F_q[X].
func (p Poly) Mul(rhs Poly) Poly {
	if p.Q != rhs.Q {
		panic("fpoly: mismatched modulus")
	}
	if p.isZero() || rhs.isZero() {
		return Zero(p.Q)
	}
	q := p.Q
	out := make([]uint64, len(p.Coeffs)+len(rhs.Coeffs)-1)
	for i := range p.Coeffs {
		av := p.Coeffs[i]
		if av >= q {
			av %= q
		}
		if av == 0 {
			continue
		}
		for j := range rhs.Coeffs {
			bv := rhs.Coeffs[j]
			if bv >= q {
				bv %= q
			}
			if bv == 0 {
				continue
			}
			out[i+j] = addModReduced(out[i+j], mulModReduced(av, bv, q), q)
		}
	}
	return Poly{Q: q, Coeffs: trimReduced(out)}
}

// Compose returns p(rhs(X)).
func (p Poly) Compose(rhs Poly) Poly {
	if p.Q != rhs.Q {
		panic("fpoly: mismatched modulus")
	}
	if p.isZero() {
		return Zero(p.Q)
	}
	q := p.Q
	acc := Zero(p.Q)
	for i := len(p.Coeffs) - 1; i >= 0; i-- {
		acc = acc.Mul(rhs)
		c := p.Coeffs[i]
		if c >= q {
			c %= q
		}
		acc.Coeffs[0] = addModReduced(acc.Coeffs[0], c, q)
		if i == 0 {
			break
		}
	}
	return acc
}

func trim(coeffs []uint64, q uint64) []uint64 {
	if len(coeffs) == 0 {
		return []uint64{0}
	}
	for i := range coeffs {
		if coeffs[i] >= q {
			coeffs[i] %= q
		}
	}
	return trimReduced(coeffs)
}

func trimReduced(coeffs []uint64) []uint64 {
	if len(coeffs) == 0 {
		return []uint64{0}
	}
	idx := len(coeffs) - 1
	for idx > 0 && coeffs[idx] == 0 {
		idx--
	}
	return coeffs[:idx+1]
}

func addModReduced(a, b, q uint64) uint64 {
	sum, c := bits.Add64(a, b, 0)
	if c == 1 || sum >= q {
		sum -= q
	}
	return sum
}

func subModReduced(a, b, q uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + q - b
}

func mulModReduced(a, b, q uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, q)
	return rem
}
