package commitment

import (
	"fmt"
	"math/rand"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// TargetParams describes the IntGenISIS target-shaped MLWE commitment
//
//	c = C_M M + A_s s + e.
//
// C_M and A_s are stored in the NTT domain. Witness polynomials M, s, and e
// are supplied in coefficient form. CommitMessage returns c in the NTT domain,
// matching the protocol transcript representation used by issuance.
type TargetParams struct {
	RingQ *ring.Ring
	CM    Matrix
	AS    Matrix
	EllM  int
	KS    int
	NC    int
	Bound int64
}

func (p TargetParams) Validate() error {
	if p.RingQ == nil {
		return fmt.Errorf("nil ring")
	}
	if p.EllM <= 0 || p.KS <= 0 || p.NC <= 0 {
		return fmt.Errorf("invalid commitment dimensions ell_M=%d k_s=%d n_c=%d", p.EllM, p.KS, p.NC)
	}
	if p.Bound <= 0 {
		return fmt.Errorf("invalid commitment bound %d", p.Bound)
	}
	if err := validateMatrixShape("C_M", p.CM, p.NC, p.EllM); err != nil {
		return err
	}
	if err := validateMatrixShape("A_s", p.AS, p.NC, p.KS); err != nil {
		return err
	}
	return nil
}

func validateMatrixShape(name string, mat Matrix, rows, cols int) error {
	if len(mat) != rows {
		return fmt.Errorf("%s rows=%d want %d", name, len(mat), rows)
	}
	for i := range mat {
		if len(mat[i]) != cols {
			return fmt.Errorf("%s row %d cols=%d want %d", name, i, len(mat[i]), cols)
		}
		for j := range mat[i] {
			if mat[i][j] == nil {
				return fmt.Errorf("%s[%d][%d] is nil", name, i, j)
			}
		}
	}
	return nil
}

// SampleCommitmentRandomness samples s and e coefficient-wise from [-B,B].
func SampleCommitmentRandomness(params TargetParams, rng *rand.Rand) (s []*ring.Poly, e []*ring.Poly, err error) {
	if err := params.Validate(); err != nil {
		return nil, nil, err
	}
	if rng == nil {
		return nil, nil, fmt.Errorf("nil rng")
	}
	s = make([]*ring.Poly, params.KS)
	for i := range s {
		s[i] = sampleBoundedCoeffPoly(params.RingQ, params.Bound, rng)
	}
	e = make([]*ring.Poly, params.NC)
	for i := range e {
		e[i] = sampleBoundedCoeffPoly(params.RingQ, params.Bound, rng)
	}
	return s, e, nil
}

func sampleBoundedCoeffPoly(ringQ *ring.Ring, bound int64, rng *rand.Rand) *ring.Poly {
	p := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	width := 2*bound + 1
	for i := 0; i < ringQ.N; i++ {
		v := rng.Int63n(width) - bound
		if v < 0 {
			p.Coeffs[0][i] = uint64(v + q)
		} else {
			p.Coeffs[0][i] = uint64(v)
		}
	}
	return p
}

// CommitMessage computes c = C_M M + A_s s + e and returns c in the NTT domain.
func CommitMessage(params TargetParams, M, s, e []*ring.Poly) (Vector, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(M) != params.EllM {
		return nil, fmt.Errorf("m length=%d want ell_M=%d", len(M), params.EllM)
	}
	if len(s) != params.KS {
		return nil, fmt.Errorf("s length=%d want k_s=%d", len(s), params.KS)
	}
	if len(e) != params.NC {
		return nil, fmt.Errorf("e length=%d want n_c=%d", len(e), params.NC)
	}
	Mntt, err := coeffVectorToNTT(params.RingQ, M, "M")
	if err != nil {
		return nil, err
	}
	Sntt, err := coeffVectorToNTT(params.RingQ, s, "s")
	if err != nil {
		return nil, err
	}
	Entt, err := coeffVectorToNTT(params.RingQ, e, "e")
	if err != nil {
		return nil, err
	}
	c := make(Vector, params.NC)
	tmp := params.RingQ.NewPoly()
	for row := 0; row < params.NC; row++ {
		acc := params.RingQ.NewPoly()
		for col := 0; col < params.EllM; col++ {
			params.RingQ.MulCoeffs(params.CM[row][col], Mntt[col], tmp)
			params.RingQ.Add(acc, tmp, acc)
		}
		for col := 0; col < params.KS; col++ {
			params.RingQ.MulCoeffs(params.AS[row][col], Sntt[col], tmp)
			params.RingQ.Add(acc, tmp, acc)
		}
		params.RingQ.Add(acc, Entt[row], acc)
		c[row] = acc
	}
	return c, nil
}

func coeffVectorToNTT(ringQ *ring.Ring, vec []*ring.Poly, name string) ([]*ring.Poly, error) {
	out := make([]*ring.Poly, len(vec))
	for i := range vec {
		if vec[i] == nil {
			return nil, fmt.Errorf("nil %s[%d]", name, i)
		}
		if len(vec[i].Coeffs) == 0 || len(vec[i].Coeffs[0]) != ringQ.N {
			return nil, fmt.Errorf("%s[%d] coefficient length mismatch", name, i)
		}
		out[i] = ringQ.NewPoly()
		ring.Copy(vec[i], out[i])
		ringQ.NTT(out[i], out[i])
	}
	return out, nil
}
