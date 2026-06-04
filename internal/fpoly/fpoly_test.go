package fpoly

import "testing"

func TestNewTrimDegree(t *testing.T) {
	const q = uint64(1038337)
	p := New(q, []uint64{5, 0, 0, q * 2, 0})
	if len(p.Coeffs) != 1 || p.Coeffs[0] != 5 {
		t.Fatalf("trimmed coeffs=%v want [5]", p.Coeffs)
	}
}

func TestAddSubScaleMul(t *testing.T) {
	const q = uint64(1038337)
	p := New(q, []uint64{1, 2, 3})
	r := New(q, []uint64{4, 5})

	sum := p.Add(r)
	if got, want := sum.Coeffs, []uint64{5, 7, 3}; !equalVec(got, want) {
		t.Fatalf("Add coeffs=%v want %v", got, want)
	}

	diff := p.Sub(r)
	if got, want := diff.Coeffs, []uint64{q - 3, q - 3, 3}; !equalVec(got, want) {
		t.Fatalf("Sub coeffs=%v want %v", got, want)
	}

	scaled := p.Scale(7)
	if got, want := scaled.Coeffs, []uint64{7, 14, 21}; !equalVec(got, want) {
		t.Fatalf("Scale coeffs=%v want %v", got, want)
	}

	mul := p.Mul(r) // (1+2x+3x^2)(4+5x)=4+13x+22x^2+15x^3
	if got, want := mul.Coeffs, []uint64{4, 13, 22, 15}; !equalVec(got, want) {
		t.Fatalf("Mul coeffs=%v want %v", got, want)
	}
}

func TestComposeMatchesPointwise(t *testing.T) {
	const q = uint64(1038337)
	outer := New(q, []uint64{3, 9, 4, 7})
	inner := New(q, []uint64{5, 1, 2})
	composed := outer.Compose(inner)

	for _, x := range []uint64{0, 1, 2, 7, 63, 1024} {
		lhs := evalPolyTest(composed, x)
		rhs := evalPolyTest(outer, evalPolyTest(inner, x))
		if lhs != rhs {
			t.Fatalf("compose mismatch at x=%d: got %d want %d", x, lhs, rhs)
		}
	}
}

func evalPolyTest(p Poly, x uint64) uint64 {
	if len(p.Coeffs) == 0 {
		return 0
	}
	mod := p.Q
	val := uint64(0)
	xm := x % mod
	for i := len(p.Coeffs) - 1; i >= 0; i-- {
		val = mulModReduced(val, xm, mod)
		val = addModReduced(val, p.Coeffs[i]%mod, mod)
		if i == 0 {
			break
		}
	}
	return val
}

func equalVec(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
