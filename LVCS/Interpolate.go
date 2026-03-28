package lvcs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type interpolationPlan struct {
	mod   uint64
	ncols int
	ell   int
	xs    []uint64
	basis [][]uint64
}

var interpolationPlanCache sync.Map

func interpolationPlanCacheKey(xs []uint64, mod uint64) string {
	var buf bytes.Buffer
	buf.Grow(8 + len(xs)*8)
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], mod)
	buf.Write(tmp[:])
	for _, x := range xs {
		binary.LittleEndian.PutUint64(tmp[:], x)
		buf.Write(tmp[:])
	}
	return buf.String()
}

func subMod64Reduced(a, b, mod uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + mod - b
}

func buildInterpolationPlan(xs []uint64, ncols int, ell int, mod uint64) (*interpolationPlan, error) {
	m := ncols + ell
	if len(xs) != m {
		return nil, errors.New("interpolation plan: domain point length mismatch")
	}
	seen := make(map[uint64]struct{}, len(xs))
	xsMod := make([]uint64, len(xs))
	for i, x := range xs {
		if x >= mod {
			x %= mod
		}
		if _, ok := seen[x]; ok {
			return nil, errors.New("interpolation plan: duplicate domain point")
		}
		seen[x] = struct{}{}
		xsMod[i] = x
	}

	T := make([]uint64, m+1)
	T[0] = 1
	for _, xj := range xsMod {
		for k := m; k >= 1; k-- {
			T[k] = subMod64Reduced(T[k-1], mulMod64Reduced(xj, T[k], mod), mod)
		}
		T[0] = subMod64Reduced(0, mulMod64Reduced(xj, T[0], mod), mod)
	}

	basis := make([][]uint64, m)
	tmp := make([]uint64, m)
	for i, xi := range xsMod {
		tmp[m-1] = T[m]
		for k := m - 2; k >= 0; k-- {
			tmp[k] = addMod64Reduced(T[k+1], mulMod64Reduced(xi, tmp[k+1], mod), mod)
		}
		denom := uint64(1)
		for j, xj := range xsMod {
			if j == i {
				continue
			}
			denom = mulMod64Reduced(denom, subMod64Reduced(xi, xj, mod), mod)
		}
		if denom == 0 {
			return nil, errors.New("interpolation plan: denom not invertible")
		}
		invDen := ring.ModExp(denom, mod-2, mod)
		rowBasis := make([]uint64, m)
		for k := 0; k < m; k++ {
			rowBasis[k] = mulMod64Reduced(tmp[k], invDen, mod)
		}
		basis[i] = rowBasis
	}

	return &interpolationPlan{
		mod:   mod,
		ncols: ncols,
		ell:   ell,
		xs:    xsMod,
		basis: basis,
	}, nil
}

func getInterpolationPlan(xs []uint64, ncols int, ell int, mod uint64) (*interpolationPlan, error) {
	key := interpolationPlanCacheKey(xs, mod)
	if cached, ok := interpolationPlanCache.Load(key); ok {
		plan, _ := cached.(*interpolationPlan)
		if plan != nil && plan.mod == mod && plan.ncols == ncols && plan.ell == ell {
			return plan, nil
		}
	}
	plan, err := buildInterpolationPlan(xs, ncols, ell, mod)
	if err != nil {
		return nil, err
	}
	actual, _ := interpolationPlanCache.LoadOrStore(key, plan)
	if existing, ok := actual.(*interpolationPlan); ok && existing != nil {
		return existing, nil
	}
	return plan, nil
}

func interpolateRowCoeffsWithPlan(
	row []uint64,
	mask []uint64,
	plan *interpolationPlan,
) ([]uint64, error) {
	if plan == nil {
		return nil, errors.New("interpolateRow: nil interpolation plan")
	}
	ncols := plan.ncols
	ell := plan.ell
	m := ncols + ell
	if len(row) != ncols || len(mask) != ell {
		return nil, errors.New("interpolateRow: row/mask length mismatch")
	}
	ys := make([]uint64, m)
	copy(ys[:ncols], row)
	copy(ys[ncols:], mask)
	Pcoefs := make([]uint64, m)
	for i, yi := range ys {
		if yi >= plan.mod {
			yi %= plan.mod
		}
		if yi == 0 {
			continue
		}
		basis := plan.basis[i]
		for k := 0; k < m; k++ {
			Pcoefs[k] = addMod64Reduced(Pcoefs[k], mulMod64Reduced(basis[k], yi, plan.mod), plan.mod)
		}
	}
	for len(Pcoefs) > 1 && Pcoefs[len(Pcoefs)-1] == 0 {
		Pcoefs = Pcoefs[:len(Pcoefs)-1]
	}
	return Pcoefs, nil
}

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
	plan, err := getInterpolationPlan(points[:m], ncols, ell, mod)
	if err != nil {
		return nil, err
	}
	return interpolateRowCoeffsWithPlan(row, mask, plan)
}

func interpolateRowCoeffsWithXs(
	row []uint64,
	mask []uint64,
	xs []uint64, // length = m, distinct
	ncols int,
	ell int,
	mod uint64,
) ([]uint64, error) {
	plan, err := getInterpolationPlan(xs, ncols, ell, mod)
	if err != nil {
		return nil, err
	}
	return interpolateRowCoeffsWithPlan(row, mask, plan)
}

func interpolateRowCoeffsWithXsReference(
	row []uint64,
	mask []uint64,
	xs []uint64,
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
			T[k] = subMod64Reduced(T[k-1], mulMod64Reduced(xj, T[k], mod), mod)
		}
		// T[0] = - xj * T[0]
		T[0] = subMod64Reduced(0, mulMod64Reduced(xj, T[0], mod), mod)
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
			denom = mulMod64Reduced(denom, subMod64Reduced(xi, xj, mod), mod)
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
