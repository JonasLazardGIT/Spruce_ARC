package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func EvalPoly(coeffs []uint64, x, q uint64) uint64 {
	if len(coeffs) == 0 {
		return 0
	}
	res := coeffs[len(coeffs)-1] % q
	for i := len(coeffs) - 2; i >= 0; i-- {
		res = modMul(res, x, q)
		res = modAdd(res, coeffs[i]%q, q)
	}
	return res
}

func BuildThetaPrime(ringQ *ring.Ring, values, omega []uint64) *ring.Poly {
	if len(values) != len(omega) {
		panic("BuildThetaPrime: length mismatch")
	}
	q := ringQ.Modulus[0]
	coeffs := Interpolate(omega, values, q)
	p := ringQ.NewPoly()
	copy(p.Coeffs[0], coeffs)
	ringQ.NTT(p, p)
	return p
}

type BuildQLayout struct {
	WitnessPolys []*ring.Poly
	MaskPolys    []*ring.Poly
	MaskCoeffs   [][]uint64
}

func BuildQCoeffsChecked(
	ringQ *ring.Ring,
	layout BuildQLayout,
	FparInt []*ring.Poly,
	FparNorm []*ring.Poly,
	FaggInt []*ring.Poly,
	FaggNorm []*ring.Poly,
	FparIntCoeffs [][]uint64,
	FparNormCoeffs [][]uint64,
	FaggIntCoeffs [][]uint64,
	FaggNormCoeffs [][]uint64,
	GammaPrime [][][]uint64,
	gammaPrime [][]uint64,
) ([][]uint64, error) {
	maskPolys := layout.MaskPolys
	maskCoeffs := layout.MaskCoeffs
	if len(maskPolys) == 0 && len(maskCoeffs) == 0 {
		return nil, fmt.Errorf("BuildQ: missing mask polynomials in layout")
	}
	if len(maskPolys) > 0 && len(maskCoeffs) > 0 && len(maskPolys) != len(maskCoeffs) {
		return nil, fmt.Errorf("BuildQ: inconsistent mask layout lengths")
	}

	Fpar := append(append([]*ring.Poly{}, FparInt...), FparNorm...)
	Fagg := append(append([]*ring.Poly{}, FaggInt...), FaggNorm...)
	alignOverrides := func(polys []*ring.Poly, overrides [][]uint64) [][]uint64 {
		if len(polys) == 0 {
			return nil
		}
		out := make([][]uint64, len(polys))
		limit := len(overrides)
		if limit > len(polys) {
			limit = len(polys)
		}
		for i := 0; i < limit; i++ {
			if len(overrides[i]) == 0 {
				continue
			}
			out[i] = append([]uint64(nil), overrides[i]...)
		}
		return out
	}
	FparCoeffOverride := append(alignOverrides(FparInt, FparIntCoeffs), alignOverrides(FparNorm, FparNormCoeffs)...)
	FaggCoeffOverride := append(alignOverrides(FaggInt, FaggIntCoeffs), alignOverrides(FaggNorm, FaggNormCoeffs)...)

	rho := len(maskPolys)
	if len(maskCoeffs) > rho {
		rho = len(maskCoeffs)
	}
	m1 := len(Fpar)
	m2 := len(Fagg)

	FparCoeffs := make([][]uint64, m1)
	FaggCoeffs := make([][]uint64, m2)
	tmp := ringQ.NewPoly()
	q := ringQ.Modulus[0]
	for j := 0; j < m1; j++ {
		if j < len(FparCoeffOverride) && len(FparCoeffOverride[j]) > 0 {
			override := append([]uint64(nil), FparCoeffOverride[j]...)
			for idx := range override {
				override[idx] %= q
			}
			FparCoeffs[j] = trimPoly(override, q)
			continue
		}
		if Fpar[j] == nil {
			continue
		}
		ringQ.InvNTT(Fpar[j], tmp)
		coeffs := append([]uint64(nil), tmp.Coeffs[0]...)
		for idx := range coeffs {
			coeffs[idx] %= q
		}
		deg := maxDegreeFromCoeffs(coeffs)
		if deg < 0 {
			FparCoeffs[j] = []uint64{0}
		} else {
			FparCoeffs[j] = coeffs[:deg+1]
		}
	}
	for j := 0; j < m2; j++ {
		if j < len(FaggCoeffOverride) && len(FaggCoeffOverride[j]) > 0 {
			override := append([]uint64(nil), FaggCoeffOverride[j]...)
			for idx := range override {
				override[idx] %= q
			}
			FaggCoeffs[j] = trimPoly(override, q)
			continue
		}
		if Fagg[j] == nil {
			continue
		}
		ringQ.InvNTT(Fagg[j], tmp)
		coeffs := append([]uint64(nil), tmp.Coeffs[0]...)
		for idx := range coeffs {
			coeffs[idx] %= q
		}
		deg := maxDegreeFromCoeffs(coeffs)
		if deg < 0 {
			FaggCoeffs[j] = []uint64{0}
		} else {
			FaggCoeffs[j] = coeffs[:deg+1]
		}
	}

	Q := make([][]uint64, rho)
	for i := 0; i < rho; i++ {
		var qiCoeffs []uint64
		switch {
		case i < len(maskCoeffs) && maskCoeffs[i] != nil:
			qiCoeffs = append([]uint64(nil), maskCoeffs[i]...)
			for idx := range qiCoeffs {
				qiCoeffs[idx] %= q
			}
			qiCoeffs = trimPoly(qiCoeffs, q)
		case i < len(maskPolys) && maskPolys[i] != nil:
			ringQ.InvNTT(maskPolys[i], tmp)
			qiCoeffs = append([]uint64(nil), tmp.Coeffs[0]...)
			for idx := range qiCoeffs {
				qiCoeffs[idx] %= q
			}
		default:
			return nil, fmt.Errorf("BuildQ: missing mask polynomial for row %d", i)
		}

		for j := 0; j < m1; j++ {
			if j >= len(GammaPrime[i]) || FparCoeffs[j] == nil {
				continue
			}
			gammaCoeffs := GammaPrime[i][j]
			if len(gammaCoeffs) == 0 {
				continue
			}
			prod := polyMul(gammaCoeffs, FparCoeffs[j], q)
			if len(prod) > len(qiCoeffs) {
				resized := make([]uint64, len(prod))
				copy(resized, qiCoeffs)
				qiCoeffs = resized
			}
			for k := range prod {
				qiCoeffs[k] = modAdd(qiCoeffs[k], prod[k], q)
			}
		}
		for j := 0; j < m2; j++ {
			if i >= len(gammaPrime) || j >= len(gammaPrime[i]) || FaggCoeffs[j] == nil {
				continue
			}
			g := gammaPrime[i][j] % q
			if g == 0 {
				continue
			}
			if len(FaggCoeffs[j]) > len(qiCoeffs) {
				resized := make([]uint64, len(FaggCoeffs[j]))
				copy(resized, qiCoeffs)
				qiCoeffs = resized
			}
			for k := range FaggCoeffs[j] {
				qiCoeffs[k] = modAdd(qiCoeffs[k], modMul(g, FaggCoeffs[j][k], q), q)
			}
		}
		Q[i] = trimPoly(qiCoeffs, q)
	}
	return Q, nil
}
