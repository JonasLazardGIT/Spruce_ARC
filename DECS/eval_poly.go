package decs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"
)

func mulMod64Reduced(a, b, m uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, m)
	return rem
}

func addMod64Reduced(a, b, m uint64) uint64 {
	if m <= uint64(^uint32(0)) {
		s := a + b
		if s >= m {
			s -= m
		}
		return s
	}
	s, c := bits.Add64(a, b, 0)
	if c == 1 || s >= m {
		s -= m
	}
	return s
}

type modReducer64 struct {
	mod   uint64
	recip uint64
	fast  bool
}

func newModReducer64(mod uint64) modReducer64 {
	red := modReducer64{mod: mod}
	if mod > 1 && mod <= uint64(^uint32(0)) {
		red.recip, _ = bits.Div64(1, 0, mod)
		red.fast = true
	}
	return red
}

func (r modReducer64) mulReduced(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if r.fast && hi == 0 {
		qhat, _ := bits.Mul64(lo, r.recip)
		rem := lo - qhat*r.mod
		for rem >= r.mod {
			rem -= r.mod
		}
		return rem
	}
	_, rem := bits.Div64(hi, lo, r.mod)
	return rem
}

func mulMod64(a, b, m uint64) uint64 {
	if a >= m {
		a %= m
	}
	if b >= m {
		b %= m
	}
	return mulMod64Reduced(a, b, m)
}

func addMod64(a, b, m uint64) uint64 {
	if a >= m {
		a %= m
	}
	if b >= m {
		b %= m
	}
	return addMod64Reduced(a, b, m)
}

func evalPoly(coeffs []uint64, x, q uint64) uint64 {
	if len(coeffs) == 0 {
		return 0
	}
	if x >= q {
		x %= q
	}
	res := coeffs[len(coeffs)-1]
	if res >= q {
		res %= q
	}
	for i := len(coeffs) - 2; i >= 0; i-- {
		res = mulMod64Reduced(res, x, q)
		c := coeffs[i]
		if c >= q {
			c %= q
		}
		res = addMod64Reduced(res, c, q)
	}
	return res
}

func validatePoints(points []uint64, q uint64) error {
	if len(points) == 0 {
		return fmt.Errorf("decs: explicit domain must be non-empty")
	}
	seen := make(map[uint64]struct{}, len(points))
	for i, p := range points {
		if p >= q {
			return fmt.Errorf("decs: points[%d]=%d out of field range (q=%d)", i, p, q)
		}
		if _, ok := seen[p]; ok {
			return fmt.Errorf("decs: explicit domain has duplicate point %d", p)
		}
		seen[p] = struct{}{}
	}
	return nil
}

func randUint64Mod(mod uint64) (uint64, error) {
	if mod == 0 {
		return 0, fmt.Errorf("decs: randUint64Mod with mod=0")
	}
	limit := ^uint64(0) - (^uint64(0) % mod)
	for {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint64(buf[:])
		if v >= limit {
			continue
		}
		return v % mod, nil
	}
}
