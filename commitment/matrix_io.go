package commitment

import (
	crand "crypto/rand"
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// CoeffMatrix stores a row-major matrix of coefficient-domain polynomials.
// Each polynomial is represented as a length-N slice of coefficients mod q.
type CoeffMatrix [][][]uint64

// MatrixFromCoeff lifts a coefficient-domain matrix into NTT form.
func MatrixFromCoeff(ringQ *ring.Ring, coeffs CoeffMatrix) (Matrix, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(coeffs) == 0 {
		return nil, fmt.Errorf("empty coeff matrix")
	}
	rows := len(coeffs)
	cols := len(coeffs[0])
	if cols == 0 {
		return nil, fmt.Errorf("empty coeff matrix row")
	}
	out := make(Matrix, rows)
	for i := 0; i < rows; i++ {
		if len(coeffs[i]) != cols {
			return nil, fmt.Errorf("ragged coeff matrix at row %d", i)
		}
		out[i] = make([]*ring.Poly, cols)
		for j := 0; j < cols; j++ {
			if len(coeffs[i][j]) != ringQ.N {
				return nil, fmt.Errorf("coeff poly[%d][%d] len=%d want %d", i, j, len(coeffs[i][j]), ringQ.N)
			}
			p := ringQ.NewPoly()
			for k := 0; k < ringQ.N; k++ {
				p.Coeffs[0][k] = coeffs[i][j][k] % ringQ.Modulus[0]
			}
			ringQ.NTT(p, p)
			out[i][j] = p
		}
	}
	return out, nil
}

// GenerateUniformCoeffMatrix samples a full rectangular coefficient-domain
// matrix with entries uniform mod q.
func GenerateUniformCoeffMatrix(ringQ *ring.Ring, rows, cols int) (CoeffMatrix, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if rows <= 0 || cols <= 0 {
		return nil, fmt.Errorf("invalid matrix dims rows=%d cols=%d", rows, cols)
	}
	modulus := new(big.Int).SetUint64(ringQ.Modulus[0])
	out := make(CoeffMatrix, rows)
	for i := 0; i < rows; i++ {
		out[i] = make([][]uint64, cols)
		for j := 0; j < cols; j++ {
			p := make([]uint64, ringQ.N)
			for k := 0; k < ringQ.N; k++ {
				v, err := crand.Int(crand.Reader, modulus)
				if err != nil {
					return nil, fmt.Errorf("sample coeff[%d][%d][%d]: %w", i, j, k, err)
				}
				p[k] = v.Uint64()
			}
			out[i][j] = p
		}
	}
	return out, nil
}
