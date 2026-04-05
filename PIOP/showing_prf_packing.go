package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildOmegaDeltaSelectors(ringQ *ring.Ring, omega []uint64) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return nil, nil, fmt.Errorf("|omega|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	q := ringQ.Modulus[0]
	theta := make([]*ring.Poly, ncols)
	coeff := make([][]uint64, ncols)
	for col := 0; col < ncols; col++ {
		vals := make([]uint64, ncols)
		vals[col] = 1
		c := Interpolate(omega, vals, q)
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], c)
		pNTT := ringQ.NewPoly()
		ring.Copy(p, pNTT)
		ringQ.NTT(pNTT, pNTT)
		theta[col] = pNTT
		full := make([]uint64, ringQ.N)
		copy(full, c)
		for i := range full {
			full[i] %= q
		}
		coeff[col] = trimPoly(full, q)
	}
	return theta, coeff, nil
}
