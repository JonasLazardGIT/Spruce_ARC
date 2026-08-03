package ntru

import (
	"fmt"
	"io"
	"math"

	ps "vSIS-Signature/ntru/internal/preimage"
)

// CDT table ported from antrag_opt-main/antrag/samplerZ.c (TABLE_SIZE = 13)
var cdtTable = [...]uint64{
	8562458705743934607,
	14988938141546119862,
	17705984313312429518,
	18353082494776078532,
	18439897061947435901,
	18446457975170112665,
	18446737284374178633,
	18446743982533372247,
	18446744073018029834,
	18446744073706592852,
	18446744073709544480,
	18446744073709551607,
	18446744073709551615,
}

// baseSampler draws z0 per CDT thresholds.
func baseSampler(entropy io.Reader) (int64, error) {
	r, err := entropyUint64(entropy)
	if err != nil {
		return 0, err
	}
	res := int64(0)
	for i := 0; i < len(cdtTable); i++ {
		if r >= cdtTable[i] {
			res++
		}
	}
	return res, nil
}

// sampleZ implements samplerZ(u) from C using Box-Muller acceptance with parameter R.
// u is the real-valued mean (per coefficient), R is the smoothing parameter.
func sampleZ(u, R float64, entropy io.Reader) (int64, error) {
	if math.IsNaN(u) || math.IsInf(u, 0) || math.IsNaN(R) || math.IsInf(R, 0) || R <= 0 {
		return 0, fmt.Errorf("sampleZ: invalid mean/smoothing parameter u=%g R=%g", u, R)
	}
	uf := math.Floor(u)
	for {
		bits, err := entropyByte(entropy)
		if err != nil {
			return 0, err
		}
		for i := 0; i < 8; i++ {
			z0, err := baseSampler(entropy)
			if err != nil {
				return 0, err
			}
			b := (bits >> uint(i)) & 1
			// z = (2*b-1)*z0 + b + uf
			sign := int64(2*int(b) - 1)
			z := float64(sign)*float64(z0) + float64(b) + uf
			x := (float64(z0*z0) - (z-u)*(z-u)) / (2 * R * R)
			p := math.Exp(x)
			// r in [0,1)
			r, err := entropyFloat53(entropy)
			if err != nil {
				return 0, err
			}
			if r < p {
				return RoundAwayFromZero(z), nil
			}
		}
	}
}

// sampleZVec samples an integer vector around coefficient-domain means.
func sampleZVec(xCoeff *ps.CyclotomicFieldElem, R float64, entropy io.Reader) ([]int64, error) {
	if xCoeff.Domain != ps.Coeff {
		return nil, ErrUnsupportedCenterDomain
	}
	n := xCoeff.N
	out := make([]int64, n)
	for i := 0; i < n; i++ {
		mu, _ := xCoeff.Coeffs[i].Real.Float64()
		z, err := sampleZ(mu, R, entropy)
		if err != nil {
			return nil, fmt.Errorf("sampleZVec coefficient %d: %w", i, err)
		}
		out[i] = z
	}
	return out, nil
}

// ErrUnsupportedCenterDomain returned when coefficient centers are not in Coeff domain.
var ErrUnsupportedCenterDomain = fmtError("unsupported center domain for sampleZVec")

type fmtError string

func (e fmtError) Error() string { return string(e) }
