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
	s, c := bits.Add64(a, b, 0)
	if c == 1 || s >= m {
		s -= m
	}
	return s
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
