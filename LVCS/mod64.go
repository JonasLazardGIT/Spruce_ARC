package lvcs

import "math/bits"

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
