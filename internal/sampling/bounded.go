package sampling

import (
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"math"
	"math/big"
)

// Int64n samples uniformly from [0, n) using rejection sampling over random.
func Int64n(random io.Reader, n int64) (int64, error) {
	if random == nil {
		return 0, fmt.Errorf("nil randomness reader")
	}
	if n <= 0 {
		return 0, fmt.Errorf("non-positive sampling range %d", n)
	}
	value, err := cryptorand.Int(random, big.NewInt(n))
	if err != nil {
		return 0, fmt.Errorf("sample integer in [0,%d): %w", n, err)
	}
	return value.Int64(), nil
}

// CenteredInt64 samples uniformly from the integer interval [-bound, bound].
func CenteredInt64(random io.Reader, bound int64) (int64, error) {
	if bound < 0 {
		return 0, fmt.Errorf("negative centered bound %d", bound)
	}
	if bound > (math.MaxInt64-1)/2 {
		return 0, fmt.Errorf("centered bound %d overflows int64 range", bound)
	}
	value, err := Int64n(random, 2*bound+1)
	if err != nil {
		return 0, err
	}
	return value - bound, nil
}
