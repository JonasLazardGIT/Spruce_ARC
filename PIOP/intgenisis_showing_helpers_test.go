package PIOP

import (
	"fmt"
	"testing"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func constLaneTest(ncols int, v int64) []int64 {
	out := make([]int64, ncols)
	for i := range out {
		out[i] = v
	}
	return out
}

func fixedNonceTest(lenNonce, ncols int, q uint64) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lenNonce)
	public := make([][]int64, lenNonce)
	for i := 0; i < lenNonce; i++ {
		v := uint64(i+1) % q
		nonce[i] = prf.Elem(v)
		public[i] = constLaneTest(ncols, int64(v))
	}
	return nonce, public
}

func lanesFromElemsTest(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = constLaneTest(ncols, int64(v))
	}
	return out
}

func evalPolyOnOmegaTest(ringQ *ring.Ring, omega []uint64, poly *ring.Poly) ([]uint64, error) {
	if poly == nil {
		return nil, nil
	}
	coeffs, err := coeffFromNTTPoly(ringQ, poly)
	if err != nil {
		return nil, err
	}
	return evalCoeffOnOmegaTest(coeffs, omega, ringQ.Modulus[0]), nil
}

func evalCoeffOnOmegaTest(coeffs []uint64, omega []uint64, q uint64) []uint64 {
	if len(coeffs) == 0 {
		return make([]uint64, len(omega))
	}
	out := make([]uint64, len(omega))
	for i, w := range omega {
		out[i] = EvalPoly(coeffs, w%q, q) % q
	}
	return out
}

func assertConstraintBucketVanishesOnOmega(t *testing.T, ringQ *ring.Ring, omega []uint64, bucket string, polys []*ring.Poly, coeffs [][]uint64) {
	t.Helper()
	count := len(polys)
	if len(coeffs) > count {
		count = len(coeffs)
	}
	q := ringQ.Modulus[0]
	for i := 0; i < count; i++ {
		var (
			polyVals  []uint64
			coeffVals []uint64
			err       error
		)
		if i < len(polys) && polys[i] != nil {
			polyVals, err = evalPolyOnOmegaTest(ringQ, omega, polys[i])
			if err != nil {
				t.Fatalf("%s[%d] eval poly: %v", bucket, i, err)
			}
		}
		if i < len(coeffs) && len(coeffs[i]) > 0 {
			coeffVals = evalCoeffOnOmegaTest(coeffs[i], omega, q)
		}
		if len(polyVals) > 0 && len(coeffVals) > 0 {
			if len(polyVals) != len(coeffVals) {
				t.Fatalf("%s[%d] poly/coeff eval length mismatch: %d vs %d", bucket, i, len(polyVals), len(coeffVals))
			}
			for j := range polyVals {
				if polyVals[j] != coeffVals[j] {
					t.Fatalf("%s[%d] poly_coeff_disagree at omega[%d]: poly=%d coeff=%d", bucket, i, j, polyVals[j], coeffVals[j])
				}
			}
		}
		actual := coeffVals
		if len(actual) == 0 {
			actual = polyVals
		}
		for j, v := range actual {
			if v%q != 0 {
				t.Fatalf("%s[%d] nonzero_on_omega at omega[%d]=%d", bucket, i, j, v%q)
			}
		}
	}
}

func bucketHasNonZeroOmegaSum(ringQ *ring.Ring, omega []uint64, polys []*ring.Poly, coeffs [][]uint64) (bool, error) {
	if ringQ == nil {
		return false, fmt.Errorf("nil ring")
	}
	q := ringQ.Modulus[0]
	tmp := ringQ.NewPoly()
	count := len(polys)
	if len(coeffs) > count {
		count = len(coeffs)
	}
	for i := 0; i < count; i++ {
		var coeffVals []uint64
		switch {
		case i < len(coeffs) && len(coeffs[i]) > 0:
			coeffVals = coeffs[i]
		case i < len(polys) && polys[i] != nil:
			ringQ.InvNTT(polys[i], tmp)
			coeffVals = append([]uint64(nil), tmp.Coeffs[0]...)
		default:
			continue
		}
		sum := uint64(0)
		for _, w := range omega {
			sum = modAdd(sum, EvalPoly(coeffVals, w%q, q)%q, q)
		}
		if sum%q != 0 {
			return true, nil
		}
	}
	return false, nil
}
