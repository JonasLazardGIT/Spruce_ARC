package ntru

import (
	"errors"
	"math/big"
)

func CenterModQToInt64(a ModQPoly, par Params) ([]int64, error) {
	if len(a.Coeffs) != par.N {
		return nil, errors.New("dimension mismatch")
	}
	if !par.Q.IsInt64() {
		return nil, errors.New("q does not fit into int64")
	}
	halfUp := new(big.Int).Rsh(par.Q, 1)
	out := make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		ci := new(big.Int).Mod(new(big.Int).Set(a.Coeffs[i]), par.Q)
		if ci.Cmp(halfUp) == 1 {
			ci.Sub(ci, par.Q)
		}
		if !ci.IsInt64() {
			return nil, errors.New("coefficient out of int64 range")
		}
		out[i] = ci.Int64()
	}
	return out, nil
}
