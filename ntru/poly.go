package ntru

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type IntPoly struct {
	Coeffs []*big.Int
}

type ModQPoly struct {
	Coeffs []*big.Int
	Q      *big.Int
}

func NewIntPoly(N int) IntPoly {
	coeffs := make([]*big.Int, N)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
	}
	return IntPoly{Coeffs: coeffs}
}

func NewModQPoly(N int, Q *big.Int) ModQPoly {
	coeffs := make([]*big.Int, N)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
	}
	return ModQPoly{Coeffs: coeffs, Q: new(big.Int).Set(Q)}
}
func (p ModQPoly) Add(q ModQPoly) ModQPoly {
	r := NewModQPoly(len(p.Coeffs), p.Q)
	for i := range p.Coeffs {
		r.Coeffs[i].Add(p.Coeffs[i], q.Coeffs[i])
		r.Coeffs[i].Mod(r.Coeffs[i], p.Q)
	}
	return r
}

func (p ModQPoly) Sub(q ModQPoly) ModQPoly {
	r := NewModQPoly(len(p.Coeffs), p.Q)
	for i := range p.Coeffs {
		r.Coeffs[i].Sub(p.Coeffs[i], q.Coeffs[i])
		r.Coeffs[i].Mod(r.Coeffs[i], p.Q)
	}
	return r
}

func ToRNS(p ModQPoly, params Params) []*ring.Poly {
	rings, _ := params.BuildRings()
	limbs := make([]*ring.Poly, len(rings))
	for i, r := range rings {
		pl := r.NewPoly()
		var mod *big.Int
		if len(params.Qi) > 0 {
			mod = new(big.Int).SetUint64(params.Qi[i])
		} else {
			// fallback: use ring modulus if no RNS factorization provided
			mod = new(big.Int).SetUint64(r.Modulus[0])
		}
		for j, c := range p.Coeffs {
			pl.Coeffs[0][j] = new(big.Int).Mod(c, mod).Uint64()
		}
		limbs[i] = pl
	}
	return limbs
}

func FromRNS(limbs []*ring.Poly, params Params) ModQPoly {
	bigPoly := PackCRT(limbs, params)
	coeffs := make([]*big.Int, params.N)
	for i, c := range bigPoly.Coeffs {
		coeffs[i] = new(big.Int).Mod(c, params.Q)
	}
	return ModQPoly{Coeffs: coeffs, Q: new(big.Int).Set(params.Q)}
}
