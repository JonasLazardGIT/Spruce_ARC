package ntru

import (
	"errors"
	"math/big"
)

type Params struct {
	N  int
	Q  *big.Int
	Qi []uint64
	// C-parity knobs
	M      int  // ANTRAG_M (e.g., 4 or 6)
	LOG3_D bool // parity flag for special conj2 at degree==2
}

func NewParams(N int, Q *big.Int) (Params, error) {
	if N <= 0 || !isSmooth23(N) {
		return Params{}, errors.New("n must be 2/3-smooth (only factors 2 and/or 3)")
	}
	if Q == nil || Q.Sign() <= 0 {
		return Params{}, errors.New("q must be positive")
	}
	p := Params{N: N, Q: new(big.Int).Set(Q)}
	// LOG3_D indicates presence of 3-adic factor in N (used by special conj2 at deg=2)
	if N%3 == 0 {
		p.LOG3_D = true
	}
	return p, nil
}
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
