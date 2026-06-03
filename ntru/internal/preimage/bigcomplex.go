package preimage

import (
	"math"
	"math/big"
	"math/bits"
)

// Domain indicates whether a CyclotomicFieldElem is in coefficient or evaluation domain.
type Domain int

const (
	Coeff Domain = iota
	Eval
)

// BigComplex represents a complex number with arbitrary-precision parts.
type BigComplex struct {
	Real *big.Float
	Imag *big.Float
}

// NewBigComplexFromFloat copies floats into a BigComplex.
func NewBigComplexFromFloat(re, im *big.Float) *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Copy(re),
		Imag: new(big.Float).Copy(im),
	}
}

func (z *BigComplex) Add(w *BigComplex) *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Add(z.Real, w.Real),
		Imag: new(big.Float).Add(z.Imag, w.Imag),
	}
}

func (z *BigComplex) Sub(w *BigComplex) *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Sub(z.Real, w.Real),
		Imag: new(big.Float).Sub(z.Imag, w.Imag),
	}
}

func (z *BigComplex) Mul(w *BigComplex) *BigComplex {
	ac := new(big.Float).Mul(z.Real, w.Real)
	bd := new(big.Float).Mul(z.Imag, w.Imag)
	ad := new(big.Float).Mul(z.Real, w.Imag)
	bc := new(big.Float).Mul(z.Imag, w.Real)
	return &BigComplex{
		Real: new(big.Float).Sub(ac, bd),
		Imag: new(big.Float).Add(ad, bc),
	}
}

func (z *BigComplex) Conj() *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Copy(z.Real),
		Imag: new(big.Float).Neg(z.Imag),
	}
}

func (z *BigComplex) Copy() *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Copy(z.Real),
		Imag: new(big.Float).Copy(z.Imag),
	}
}

// CyclotomicFieldElem is an element in K_{2N}.
type CyclotomicFieldElem struct {
	N      int
	Coeffs []*BigComplex
	Domain Domain
}

// NewFieldElemBig allocates a zero field element in coeff domain.
func NewFieldElemBig(n int, prec uint) *CyclotomicFieldElem {
	coeffs := make([]*BigComplex, n)
	for i := range coeffs {
		coeffs[i] = &BigComplex{
			Real: new(big.Float).SetPrec(prec).SetFloat64(0),
			Imag: new(big.Float).SetPrec(prec).SetFloat64(0),
		}
	}
	return &CyclotomicFieldElem{N: n, Coeffs: coeffs, Domain: Coeff}
}

func FFTBig(coeffs []*BigComplex, prec uint) []*BigComplex {
	n := len(coeffs)
	if n == 0 || (n&(n-1)) != 0 {
		panic("FFTBig: length must be a nonzero power of 2")
	}

	result := make([]*BigComplex, n)
	for i := 0; i < n; i++ {
		result[i] = coeffs[i].Copy()
	}

	logN := bits.Len(uint(n)) - 1
	for i := 0; i < n; i++ {
		j := bitReverseBig(i, logN)
		if i < j {
			result[i], result[j] = result[j], result[i]
		}
	}

	for size := 2; size <= n; size <<= 1 {
		half := size >> 1

		angleF := -2.0 * math.Pi / float64(size)
		cosF := big.NewFloat(0).SetPrec(prec).SetFloat64(math.Cos(angleF))
		sinF := big.NewFloat(0).SetPrec(prec).SetFloat64(math.Sin(angleF))

		wn := &BigComplex{
			Real: new(big.Float).Copy(cosF),
			Imag: new(big.Float).Copy(sinF),
		}

		for start := 0; start < n; start += size {
			w := &BigComplex{
				Real: big.NewFloat(1).SetPrec(prec),
				Imag: big.NewFloat(0).SetPrec(prec),
			}

			for j := 0; j < half; j++ {
				idx1 := start + j
				idx2 := start + j + half

				temp := result[idx2].Mul(w)

				result[idx2] = result[idx1].Sub(temp)
				result[idx1] = result[idx1].Add(temp)
				w = w.Mul(wn)
			}
		}
	}

	return result
}

// isPow2 returns true if n is a power of two.
func isPow2(n int) bool { return n > 0 && (n&(n-1)) == 0 }

// isSmooth23 returns true if n has no prime factors other than 2 or 3.
func isSmooth23(n int) bool {
	if n <= 0 {
		return false
	}
	for n%2 == 0 {
		n /= 2
	}
	for n%3 == 0 {
		n /= 3
	}
	return n == 1
}

func fftAny(a []*BigComplex, prec uint) []*BigComplex {
	L := len(a)
	if isPow2(L) {
		return FFTBig(a, prec)
	}
	if !isSmooth23(L) {
		panic("fftAny: length not 2/3-smooth")
	}
	return fftRec(a, prec)
}

func fftRec(a []*BigComplex, prec uint) []*BigComplex {
	L := len(a)
	out := make([]*BigComplex, L)
	if L == 1 {
		out[0] = a[0].Copy()
		return out
	}
	var r int
	if L%2 == 0 {
		r = 2
	} else {
		r = 3
	}
	m := L / r
	xs := make([][]*BigComplex, r)
	for s := 0; s < r; s++ {
		xs[s] = make([]*BigComplex, m)
		for t := 0; t < m; t++ {
			xs[s][t] = a[r*t+s]
		}
	}
	Ys := make([][]*BigComplex, r)
	for s := 0; s < r; s++ {
		Ys[s] = fftRec(xs[s], prec)
	}
	for k := 0; k < L; k++ {
		k0 := k % m
		theta := -2.0 * math.Pi * float64(k) / float64(L)
		wk := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(math.Cos(theta)), Imag: new(big.Float).SetPrec(prec).SetFloat64(math.Sin(theta))}
		sum := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(0), Imag: new(big.Float).SetPrec(prec).SetFloat64(0)}
		sum = sum.Add(Ys[0][k0])
		if r >= 2 {
			term1 := Ys[1][k0].Mul(wk)
			if r == 2 {
				sum = sum.Add(term1)
			} else {
				omega := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(-0.5), Imag: new(big.Float).SetPrec(prec).SetFloat64(-math.Sqrt(3) / 2)}
				term1 = term1.Mul(omega)
				sum = sum.Add(term1)
				wk2 := wk.Mul(wk)
				term2 := Ys[2][k0].Mul(wk2)
				omega2 := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(-0.5), Imag: new(big.Float).SetPrec(prec).SetFloat64(+math.Sqrt(3) / 2)}
				term2 = term2.Mul(omega2)
				sum = sum.Add(term2)
			}
		}
		out[k] = sum
	}
	return out
}

func ifftAny(A []*BigComplex, prec uint) []*BigComplex {
	L := len(A)
	if isPow2(L) {
		return IFFTBig(A, prec)
	}
	if !isSmooth23(L) {
		panic("ifftAny: length not 2/3-smooth")
	}
	res := ifftRec(A, prec)
	invL := new(big.Float).SetPrec(prec).Quo(big.NewFloat(1).SetPrec(prec), big.NewFloat(float64(L)).SetPrec(prec))
	for i := 0; i < L; i++ {
		res[i].Real = new(big.Float).Mul(res[i].Real, invL)
		res[i].Imag = new(big.Float).Mul(res[i].Imag, invL)
	}
	return res
}

func FFTAnyBig(a []*BigComplex, prec uint) []*BigComplex { return fftAny(a, prec) }

func IFFTAnyBig(A []*BigComplex, prec uint) []*BigComplex { return ifftAny(A, prec) }

func ifftRec(A []*BigComplex, prec uint) []*BigComplex {
	L := len(A)
	out := make([]*BigComplex, L)
	if L == 1 {
		out[0] = A[0].Copy()
		return out
	}
	var r int
	if L%2 == 0 {
		r = 2
	} else {
		r = 3
	}
	m := L / r
	Ys := make([][]*BigComplex, r)
	for s := 0; s < r; s++ {
		Ys[s] = make([]*BigComplex, m)
	}
	for t := 0; t < m; t++ {
		for s := 0; s < r; s++ {
			Ys[s][t] = &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(0), Imag: new(big.Float).SetPrec(prec).SetFloat64(0)}
		}
	}
	for k := 0; k < L; k++ {
		k0 := k % m
		theta := 2.0 * math.Pi * float64(k) / float64(L)
		wk := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(math.Cos(theta)), Imag: new(big.Float).SetPrec(prec).SetFloat64(math.Sin(theta))}
		x0 := A[k]
		Ys[0][k0] = Ys[0][k0].Add(x0)
		if r >= 2 {
			y1 := x0
			omega := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(-0.5), Imag: new(big.Float).SetPrec(prec).SetFloat64(+math.Sqrt(3) / 2)}
			term1 := y1.Mul(omega).Mul(wk)
			if r == 2 {
				Ys[1][k0] = Ys[1][k0].Add(term1)
			} else {
				Ys[1][k0] = Ys[1][k0].Add(term1)
				omega2 := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(-0.5), Imag: new(big.Float).SetPrec(prec).SetFloat64(-math.Sqrt(3) / 2)}
				wk2 := wk.Mul(wk)
				term2 := y1.Mul(omega2).Mul(wk2)
				Ys[2][k0] = Ys[2][k0].Add(term2)
			}
		}
	}
	xs := make([][]*BigComplex, r)
	for s := 0; s < r; s++ {
		xs[s] = ifftRec(Ys[s], prec)
	}
	for s := 0; s < r; s++ {
		for t := 0; t < m; t++ {
			out[r*t+s] = xs[s][t]
		}
	}
	return out
}

func IFFTBig(evals []*BigComplex, prec uint) []*BigComplex {
	n := len(evals)
	if n == 0 || (n&(n-1)) != 0 {
		panic("IFFTBig: length must be a nonzero power of 2")
	}

	result := make([]*BigComplex, n)
	for i := 0; i < n; i++ {
		result[i] = evals[i].Copy()
	}

	logN := bits.Len(uint(n)) - 1
	for i := 0; i < n; i++ {
		j := bitReverseBig(i, logN)
		if i < j {
			result[i], result[j] = result[j], result[i]
		}
	}

	for size := 2; size <= n; size <<= 1 {
		half := size >> 1

		angleF := 2.0 * math.Pi / float64(size)
		cosF := big.NewFloat(0).SetPrec(prec).SetFloat64(math.Cos(angleF))
		sinF := big.NewFloat(0).SetPrec(prec).SetFloat64(math.Sin(angleF))

		wn := &BigComplex{
			Real: new(big.Float).Copy(cosF),
			Imag: new(big.Float).Copy(sinF),
		}

		for start := 0; start < n; start += size {
			w := &BigComplex{
				Real: big.NewFloat(1).SetPrec(prec),
				Imag: big.NewFloat(0).SetPrec(prec),
			}
			for j := 0; j < half; j++ {
				idx1 := start + j
				idx2 := start + j + half

				temp := result[idx2].Mul(w)

				result[idx2] = result[idx1].Sub(temp)
				result[idx1] = result[idx1].Add(temp)

				w = w.Mul(wn)
			}
		}
	}

	bigN := big.NewFloat(0).SetPrec(prec).SetFloat64(float64(n))
	invN := new(big.Float).SetPrec(prec).Quo(big.NewFloat(1).SetPrec(prec), bigN)

	for i := 0; i < n; i++ {
		result[i].Real = result[i].Real.Mul(result[i].Real, invN)
		result[i].Imag = result[i].Imag.Mul(result[i].Imag, invN)
	}

	return result
}

func bitReverseBig(i, logN int) int {
	var rev int
	for b := 0; b < logN; b++ {
		rev = (rev << 1) | ((i >> b) & 1)
	}
	return rev
}

func FieldAddBig(a, b *CyclotomicFieldElem) *CyclotomicFieldElem {
	if a.N != b.N {
		panic("FieldAddBig: dimension mismatch")
	}
	res := NewFieldElemBig(a.N, a.Coeffs[0].Real.Prec())
	for i := 0; i < a.N; i++ {
		res.Coeffs[i] = a.Coeffs[i].Add(b.Coeffs[i])
	}
	return res
}

func FieldSubBig(a, b *CyclotomicFieldElem) *CyclotomicFieldElem {
	if a.N != b.N {
		panic("FieldSubBig: dimension mismatch")
	}
	res := NewFieldElemBig(a.N, a.Coeffs[0].Real.Prec())
	for i := 0; i < a.N; i++ {
		res.Coeffs[i] = a.Coeffs[i].Sub(b.Coeffs[i])
	}
	return res
}

func FieldMulBig(a, b *CyclotomicFieldElem) *CyclotomicFieldElem {
	if a.N != b.N {
		panic("FieldMulBig: dimension mismatch")
	}
	res := NewFieldElemBig(a.N, a.Coeffs[0].Real.Prec())
	for i := 0; i < a.N; i++ {
		res.Coeffs[i] = a.Coeffs[i].Mul(b.Coeffs[i])
	}
	return res
}

func (f *CyclotomicFieldElem) Copy() *CyclotomicFieldElem {
	prec := f.Coeffs[0].Real.Prec()
	out := NewFieldElemBig(f.N, prec)
	out.Domain = f.Domain
	for i := 0; i < f.N; i++ {
		out.Coeffs[i] = f.Coeffs[i].Copy()
	}

	return out
}

func (f *CyclotomicFieldElem) Conj() *CyclotomicFieldElem {
	prec := f.Coeffs[0].Real.Prec()
	out := NewFieldElemBig(f.N, prec)
	out.Domain = f.Domain
	for i := 0; i < f.N; i++ {
		out.Coeffs[i] = f.Coeffs[i].Conj()
	}
	return out
}
