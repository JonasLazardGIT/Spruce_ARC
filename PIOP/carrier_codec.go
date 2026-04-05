package PIOP

import (
	"fmt"
)

func carrierBase(bound int64) (int64, error) {
	if bound < 0 {
		return 0, fmt.Errorf("invalid carrier bound %d", bound)
	}
	base := 2*bound + 1
	if base <= 0 {
		return 0, fmt.Errorf("invalid carrier base for bound %d", bound)
	}
	return base, nil
}

func carrierAlphabetSize(bound int64) (int64, error) {
	base, err := carrierBase(bound)
	if err != nil {
		return 0, err
	}
	if base > 0 && base > (1<<62) {
		return 0, fmt.Errorf("carrier base %d too large", base)
	}
	if base != 0 && base > (1<<31) && base > (int64(^uint64(0)>>1))/base {
		return 0, fmt.Errorf("carrier alphabet overflows for base %d", base)
	}
	size := base * base
	if size <= 0 {
		return 0, fmt.Errorf("invalid carrier alphabet size for base %d", base)
	}
	return size, nil
}

func encodeCarrierPair(m1, m2, bound int64) (uint64, error) {
	base, err := carrierBase(bound)
	if err != nil {
		return 0, err
	}
	lo := int64(0)
	hi := base - 1
	m1v := m1 + bound
	m2v := m2 + bound
	if m1v < lo || m1v > hi {
		return 0, fmt.Errorf("carrier m1=%d outside [-%d,%d]", m1, bound, bound)
	}
	if m2v < lo || m2v > hi {
		return 0, fmt.Errorf("carrier m2=%d outside [-%d,%d]", m2, bound, bound)
	}
	code := m1v + base*m2v
	if code < 0 {
		return 0, fmt.Errorf("invalid carrier code %d", code)
	}
	return uint64(code), nil
}

func decodeCarrierPair(code uint64, bound int64) (int64, int64, error) {
	size, err := carrierAlphabetSize(bound)
	if err != nil {
		return 0, 0, err
	}
	if int64(code) < 0 || int64(code) >= size {
		return 0, 0, fmt.Errorf("carrier code %d outside [0,%d)", code, size)
	}
	base, _ := carrierBase(bound)
	m1v := int64(code % uint64(base))
	m2v := int64(code/uint64(base))
	return m1v - bound, m2v - bound, nil
}

func buildCarrierDecodePolys(bound int64, q uint64) ([]uint64, []uint64, error) {
	size, err := carrierAlphabetSize(bound)
	if err != nil {
		return nil, nil, err
	}
	if size <= 0 {
		return nil, nil, fmt.Errorf("invalid carrier alphabet size %d", size)
	}
	const maxCarrierAlphabetSize = 1 << 20
	if size > maxCarrierAlphabetSize {
		return nil, nil, fmt.Errorf("carrier alphabet size %d exceeds limit %d", size, maxCarrierAlphabetSize)
	}
	xs := make([]uint64, size)
	ys1 := make([]uint64, size)
	ys2 := make([]uint64, size)
	base, _ := carrierBase(bound)
	for i := int64(0); i < size; i++ {
		xs[i] = uint64(i) % q
		m1 := (i % base) - bound
		m2 := (i / base) - bound
		ys1[i] = liftToField(q, m1)
		ys2[i] = liftToField(q, m2)
	}
	c1 := Interpolate(xs, ys1, q)
	c2 := Interpolate(xs, ys2, q)
	return c1, c2, nil
}

func buildCarrierMembershipPoly(bound int64, q uint64) ([]uint64, error) {
	size, err := carrierAlphabetSize(bound)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("invalid carrier alphabet size %d", size)
	}
	const maxCarrierAlphabetSize = 1 << 20
	if size > maxCarrierAlphabetSize {
		return nil, fmt.Errorf("carrier alphabet size %d exceeds limit %d", size, maxCarrierAlphabetSize)
	}
	// Build ∏_{a=0}^{size-1} (X - a).
	coeffs := make([]uint64, size+1)
	coeffs[0] = 1
	for a := int64(0); a < size; a++ {
		av := uint64(a) % q
		for k := a + 1; k >= 1; k-- {
			coeffs[k] = modSubReduced(coeffs[k-1], modMulReduced(av, coeffs[k], q), q)
		}
		coeffs[0] = modSubReduced(0, modMulReduced(av, coeffs[0], q), q)
	}
	return trimPoly(coeffs, q), nil
}
