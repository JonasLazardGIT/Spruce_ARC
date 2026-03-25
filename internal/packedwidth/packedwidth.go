package packedwidth

import "math/bits"

const (
	// Bit cap used by packed small-field proof data.
	LegacyFieldCapBits = 20
)

// ExactForMax returns the minimum non-zero bit width required to encode max.
func ExactForMax(max uint64) int {
	if max == 0 {
		return 1
	}
	return bits.Len64(max)
}

// ModulusCeiling returns ceil(log2(q)) for odd moduli represented as residues in [0,q).
func ModulusCeiling(q uint64) int {
	if q <= 1 {
		return 1
	}
	return bits.Len64(q - 1)
}
