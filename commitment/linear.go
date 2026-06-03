package commitment

import "github.com/tuneinsight/lattigo/v4/ring"

// Matrix is a row-major matrix of NTT-domain polynomials.
type Matrix [][]*ring.Poly

// Vector is a helper alias for a slice of polynomials.
type Vector []*ring.Poly
