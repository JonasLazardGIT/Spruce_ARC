package ntru

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type BigIntPoly struct {
	Coeffs []*big.Int
}

func PackCRT(limbs []*ring.Poly, p Params) BigIntPoly {
	// If no RNS factorization is provided, fall back to a single modulus Q.
	var moduli []*big.Int
	if len(p.Qi) == 0 {
		moduli = []*big.Int{new(big.Int).Set(p.Q)}
	} else {
		moduli = make([]*big.Int, len(p.Qi))
		for i, qi := range p.Qi {
			moduli[i] = new(big.Int).SetUint64(qi)
		}
	}
	coeffs := make([]*big.Int, p.N)
	for j := 0; j < p.N; j++ {
		residues := make([]*big.Int, len(limbs))
		for i, poly := range limbs {
			residues[i] = new(big.Int).SetUint64(poly.Coeffs[0][j])
		}
		coeffs[j] = Recompose(residues, moduli)
		coeffs[j].Mod(coeffs[j], p.Q)
	}
	return BigIntPoly{Coeffs: coeffs}
}
func Recompose(residues []*big.Int, moduli []*big.Int) *big.Int {
	x := new(big.Int).Set(residues[0])
	M := new(big.Int).Set(moduli[0])
	tmp := new(big.Int)
	for i := 1; i < len(residues); i++ {
		t := new(big.Int).Sub(residues[i], x)
		t.Mod(t, moduli[i])
		inv := new(big.Int).ModInverse(M, moduli[i])
		t.Mul(t, inv)
		t.Mod(t, moduli[i])
		tmp.Mul(M, t)
		x.Add(x, tmp)
		M.Mul(M, moduli[i])
	}
	return x
}
