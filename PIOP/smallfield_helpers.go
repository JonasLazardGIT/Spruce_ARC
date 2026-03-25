package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type smallFieldParams struct {
	K       *kf.Field
	Chi     []uint64
	OmegaS1 kf.Elem
	MuInv   kf.Elem
	Rows    [][]uint64
}

// buildSmallFieldWitnessRows projects witness polynomials into theta>1 small-field rows.
func buildSmallFieldWitnessRows(
	ringQ *ring.Ring,
	omega []uint64,
	ncols int,
	K *kf.Field,
	omegaS1 kf.Elem,
	witnessPolys []*ring.Poly,
) ([][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if ncols <= 0 {
		return nil, fmt.Errorf("invalid ncols=%d", ncols)
	}
	s := len(omega)
	if ncols < s {
		return nil, fmt.Errorf("invalid lvcs ncols=%d (must be >= witness ncols=%d)", ncols, s)
	}
	if len(witnessPolys) == 0 {
		return nil, fmt.Errorf("empty witness polynomial set")
	}
	q := ringQ.Modulus[0]
	theta := K.Theta
	blocks := ceilDiv(len(witnessPolys), ncols)
	if blocks <= 0 {
		blocks = 1
	}

	coeffs := make([][]uint64, len(witnessPolys))
	for i, poly := range witnessPolys {
		if poly == nil {
			continue
		}
		coeffs[i] = append([]uint64(nil), poly.Coeffs[0]...)
	}

	yVals := make([]kf.Elem, len(witnessPolys))
	for i := range witnessPolys {
		if coeffs[i] == nil {
			yVals[i] = K.Zero()
			continue
		}
		yVals[i] = K.EvalFPolyAtK(coeffs[i], omegaS1)
	}

	rows := make([][]uint64, 0, blocks*(s+theta))
	for block := 0; block < blocks; block++ {
		for j := 0; j < s; j++ {
			row := make([]uint64, ncols)
			for t := 0; t < ncols; t++ {
				idx := block*ncols + t
				if idx < len(witnessPolys) && coeffs[idx] != nil {
					row[t] = EvalPoly(coeffs[idx], omega[j]%q, q)
				}
			}
			rows = append(rows, row)
		}
		for coord := 0; coord < theta; coord++ {
			row := make([]uint64, ncols)
			for t := 0; t < ncols; t++ {
				idx := block*ncols + t
				if idx < len(yVals) {
					row[t] = yVals[idx].Limb[coord] % q
				}
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}

// deriveSmallFieldParamsNoRows derives theta>1 field data without building rows.
func deriveSmallFieldParamsNoRows(ringQ *ring.Ring, omega []uint64, theta int) (smallFieldParams, error) {
	var out smallFieldParams
	if ringQ == nil {
		return out, fmt.Errorf("nil ring")
	}
	if theta <= 1 {
		return out, fmt.Errorf("theta must be >1")
	}
	if len(omega) == 0 {
		return out, fmt.Errorf("empty omega")
	}
	q := ringQ.Modulus[0]
	chi, chiErr := kf.FindIrreducible(q, theta, nil)
	if chiErr != nil {
		return out, fmt.Errorf("FindIrreducible: %w", chiErr)
	}
	K, kErr := kf.New(q, theta, chi)
	if kErr != nil {
		return out, fmt.Errorf("kfield.New: %w", kErr)
	}
	var omegaS1 kf.Elem
	var muDenomInv kf.Elem
	const maxAttempts = 1 << 12
	for attempt := 0; attempt < maxAttempts; attempt++ {
		candidate, randErr := K.RandomElement(nil)
		if randErr != nil {
			return out, fmt.Errorf("sample omegaS1: %w", randErr)
		}
		conflict := false
		for _, w := range omega {
			if elemEqual(K, candidate, K.EmbedF(w%q)) {
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		denom := K.One()
		zeroDiff := false
		for _, w := range omega {
			diff := K.Sub(candidate, K.EmbedF(w%q))
			if K.IsZero(diff) {
				zeroDiff = true
				break
			}
			denom = K.Mul(denom, diff)
		}
		if zeroDiff || K.IsZero(denom) {
			continue
		}
		muDenomInv = K.Inv(denom)
		omegaS1 = candidate
		break
	}
	if len(muDenomInv.Limb) == 0 {
		return out, fmt.Errorf("failed to sample omegaS1")
	}
	out = smallFieldParams{
		K:       K,
		Chi:     append([]uint64(nil), chi...),
		OmegaS1: omegaS1,
		MuInv:   muDenomInv,
	}
	return out, nil
}

// buildSmallFieldMaskLayerRows expands K-mask polynomials into theta>1 mask rows.
func buildSmallFieldMaskLayerRows(
	K *kf.Field,
	maskPolysK []*KPoly,
	ncols int,
	degreeBound int,
) ([][]uint64, error) {
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if ncols <= 0 {
		return nil, fmt.Errorf("invalid ncols=%d", ncols)
	}
	if degreeBound < 0 {
		return nil, fmt.Errorf("invalid degree bound %d", degreeBound)
	}
	if len(maskPolysK) == 0 {
		return nil, fmt.Errorf("empty K-mask set")
	}
	theta := K.Theta
	if theta <= 0 {
		return nil, fmt.Errorf("invalid theta=%d", theta)
	}
	chunksPerMask := degreeBound/ncols + 1
	if chunksPerMask <= 0 {
		chunksPerMask = 1
	}
	rows := make([][]uint64, 0, len(maskPolysK)*chunksPerMask*theta)
	q := K.Q
	for maskIdx, mask := range maskPolysK {
		if mask == nil {
			return nil, fmt.Errorf("nil K-mask at index %d", maskIdx)
		}
		for chunk := 0; chunk < chunksPerMask; chunk++ {
			baseDeg := chunk * ncols
			for coord := 0; coord < theta; coord++ {
				row := make([]uint64, ncols)
				for col := 0; col < ncols; col++ {
					deg := baseDeg + col
					if coord < len(mask.Limbs) && deg < len(mask.Limbs[coord]) {
						row[col] = mask.Limbs[coord][deg] % q
					}
				}
				rows = append(rows, row)
			}
		}
	}
	return rows, nil
}
