package ntru

import (
	"errors"
	"math/big"
)

func MulNegacyclicZZParam(a, b []int64, log3 bool) ([]int64, error) {
	N := len(a)
	deg := 2*N - 1
	acc := make([]*big.Int, deg)
	for i := 0; i < deg; i++ {
		acc[i] = new(big.Int)
	}
	for i, ai64 := range a {
		if ai64 == 0 {
			continue
		}
		ai := big.NewInt(ai64)
		for j, bj64 := range b {
			if bj64 == 0 {
				continue
			}
			bj := big.NewInt(bj64)
			prod := new(big.Int).Mul(ai, bj)
			acc[i+j].Add(acc[i+j], prod)
		}
	}
	for i := deg - 1; i >= N; i-- {
		acc[i-N].Sub(acc[i-N], acc[i])
		if log3 {
			acc[i-N/2].Add(acc[i-N/2], acc[i])
		}
	}
	res := make([]int64, N)
	for i := 0; i < N; i++ {
		if !acc[i].IsInt64() {
			return nil, errors.New("int64 overflow")
		}
		res[i] = acc[i].Int64()
	}
	return res, nil
}

func CheckNTRUIdentity(f, g, F, G []int64, par Params) bool {
	if len(f) != par.N || len(g) != par.N || len(F) != par.N || len(G) != par.N {
		return false
	}
	q := par.Q.Int64()
	fG, err := MulNegacyclicZZParam(f, G, par.LOG3_D)
	if err != nil {
		return false
	}
	gF, err := MulNegacyclicZZParam(g, F, par.LOG3_D)
	if err != nil {
		return false
	}
	for i := 0; i < par.N; i++ {
		want := int64(0)
		if i == 0 {
			want = q
		}
		if fG[i]-gF[i] != want {
			return false
		}
	}
	return true
}
