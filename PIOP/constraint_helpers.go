package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildCommitConstraints returns residual polynomials for Ac*vec - Com.
func BuildCommitConstraints(ringQ *ring.Ring, Ac [][]*ring.Poly, vec []*ring.Poly, com []*ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(Ac) == 0 {
		return nil, fmt.Errorf("empty Ac")
	}
	rows := len(Ac)
	cols := len(Ac[0])
	if len(vec) != cols {
		return nil, fmt.Errorf("vec length mismatch: got %d want %d", len(vec), cols)
	}
	if len(com) != rows {
		return nil, fmt.Errorf("com length mismatch: got %d want %d", len(com), rows)
	}
	residuals := make([]*ring.Poly, rows)
	tmp := ringQ.NewPoly()
	for i := 0; i < rows; i++ {
		if len(Ac[i]) != cols {
			return nil, fmt.Errorf("ragged Ac row %d", i)
		}
		res := ringQ.NewPoly()
		for j := 0; j < cols; j++ {
			ringQ.MulCoeffs(Ac[i][j], vec[j], tmp)
			ringQ.Add(res, tmp, res)
		}
		ringQ.Sub(res, com[i], res)
		residuals[i] = res
	}
	return residuals, nil
}
