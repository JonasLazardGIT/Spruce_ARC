package lvcs

import (
	"errors"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func interpolateRowExplicitCoeffs(
	row []uint64,
	mask []uint64,
	ncols int,
	ell int,
	points []uint64, // E (must cover Ω∪Ω′ as a prefix)
	mod uint64,
) ([]uint64, error) {
	if points == nil {
		return nil, errors.New("interpolateRowExplicit: nil points")
	}
	m := ncols + ell
	if len(points) < m {
		return nil, errors.New("interpolateRowExplicit: points length too small")
	}
	return interpolateRowCoeffsWithXs(row, mask, points[:m], ncols, ell, mod)
}

func interpolateRowCoeffsWithXs(
	row []uint64,
	mask []uint64,
	xs []uint64, // length = m, distinct
	ncols int,
	ell int,
	mod uint64,
) ([]uint64, error) {
	m := ncols + ell
	if len(row) != ncols || len(mask) != ell {
		return nil, errors.New("interpolateRow: row/mask length mismatch")
	}
	if len(xs) != m {
		return nil, errors.New("interpolateRow: domain point length mismatch")
	}
	seen := make(map[uint64]struct{}, len(xs))
	xsMod := make([]uint64, len(xs))
	for i, x := range xs {
		if x >= mod {
			x %= mod
		}
		if _, ok := seen[x]; ok {
			return nil, errors.New("interpolateRow: duplicate domain point")
		}
		seen[x] = struct{}{}
		xsMod[i] = x
	}
	subReduced := func(a, b uint64) uint64 {
		if a >= b {
			return a - b
		}
		return a + mod - b
	}

	// 2) Build the combined y-values
	ys := make([]uint64, m)
	copy(ys[:ncols], row)
	copy(ys[ncols:], mask)

	// 3) Compute T(X) = ∏_{j=0..m-1} (X - xs[j]), deg=m
	T := make([]uint64, m+1)
	T[0] = 1
	for _, xj := range xsMod {
		for k := m; k >= 1; k-- {
			// T[k] = T[k-1] - xj*T[k] mod q
			T[k] = subReduced(T[k-1], mulMod64Reduced(xj, T[k], mod))
		}
		// T[0] = - xj * T[0]
		T[0] = subReduced(0, mulMod64Reduced(xj, T[0], mod))
	}

	// 4) Interpolate via sum_i [ y_i * Qi(X) * invDenom_i ]
	Pcoefs := make([]uint64, m)
	tmp := make([]uint64, m)
	for i, xi := range xsMod {
		// 4.1 synthetic‐division: Qi = T/(X - xi)
		tmp[m-1] = T[m]
		for k := m - 2; k >= 0; k-- {
			tmp[k] = addMod64Reduced(T[k+1], mulMod64Reduced(xi, tmp[k+1], mod), mod)
		}
		// 4.2 denom_i = ∏_{j≠i}(xi - xj)
		denom := uint64(1)
		for j, xj := range xsMod {
			if j == i {
				continue
			}
			denom = mulMod64Reduced(denom, subReduced(xi, xj), mod)
		}
		if denom == 0 {
			return nil, errors.New("interpolateRow: denom not invertible")
		}
		// q is prime in the configured rings, so inverse is denom^(q-2).
		invDen := ring.ModExp(denom, mod-2, mod)

		// 4.4 accumulate: Pcoefs += (y_i * invDen) * tmp
		yi := ys[i]
		if yi >= mod {
			yi %= mod
		}
		scale := mulMod64Reduced(yi, invDen, mod)
		for k := 0; k < m; k++ {
			Pcoefs[k] = addMod64Reduced(Pcoefs[k], mulMod64Reduced(tmp[k], scale, mod), mod)
		}
	}

	for len(Pcoefs) > 1 && Pcoefs[len(Pcoefs)-1] == 0 {
		Pcoefs = Pcoefs[:len(Pcoefs)-1]
	}
	return Pcoefs, nil
}
