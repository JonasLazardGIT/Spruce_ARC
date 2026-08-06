package PIOP

import (
	"crypto/rand"
	"fmt"
	"io"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type smallFieldMaskShapeV3 struct {
	Degree      int
	NCols       int
	Mu          int
	Nu          int
	Delta       int
	RowsPerMask int
}

func deriveSmallFieldMaskShapeV3(degree, ncols, theta int) (smallFieldMaskShapeV3, error) {
	if degree <= 0 || ncols <= 0 || theta <= 1 {
		return smallFieldMaskShapeV3{}, fmt.Errorf("invalid v3 mask shape d=%d ncols=%d theta=%d", degree, ncols, theta)
	}
	mu := ceilDiv(degree, ncols)
	if mu <= 0 {
		return smallFieldMaskShapeV3{}, fmt.Errorf("invalid v3 mask mu=%d", mu)
	}
	nu := ceilDiv(degree, mu)
	if nu <= 0 || nu > ncols {
		return smallFieldMaskShapeV3{}, fmt.Errorf("invalid v3 mask nu=%d for ncols=%d", nu, ncols)
	}
	delta := mu*nu - degree
	if delta < 0 || delta > mu {
		return smallFieldMaskShapeV3{}, fmt.Errorf("invalid v3 mask delta=%d", delta)
	}
	return smallFieldMaskShapeV3{
		Degree:      degree,
		NCols:       ncols,
		Mu:          mu,
		Nu:          nu,
		Delta:       delta,
		RowsPerMask: (mu + 1) * theta,
	}, nil
}

// buildSmallFieldMaskLayerRowsV3 implements the shifted, randomized mask
// matrix of SmallWood Eq. (2). Rows are ordered first by exponent 0..mu and
// then by the theta power-basis coordinates of K.
func buildSmallFieldMaskLayerRowsV3(
	K *kf.Field,
	maskPolysK []*KPoly,
	ncols int,
	degreeBound int,
	random io.Reader,
) ([][]uint64, smallFieldMaskShapeV3, error) {
	if K == nil {
		return nil, smallFieldMaskShapeV3{}, fmt.Errorf("nil K field")
	}
	shape, err := deriveSmallFieldMaskShapeV3(degreeBound, ncols, K.Theta)
	if err != nil {
		return nil, smallFieldMaskShapeV3{}, err
	}
	if len(maskPolysK) == 0 {
		return nil, smallFieldMaskShapeV3{}, fmt.Errorf("empty K-mask set")
	}
	if random == nil {
		random = rand.Reader
	}
	rows := make([][]uint64, 0, len(maskPolysK)*shape.RowsPerMask)
	q := K.Q
	for maskIdx, mask := range maskPolysK {
		if mask == nil || mask.Degree > degreeBound || len(mask.Limbs) != K.Theta {
			return nil, smallFieldMaskShapeV3{}, fmt.Errorf("invalid K-mask at index %d", maskIdx)
		}
		matrix := make([][]uint64, shape.RowsPerMask)
		for i := range matrix {
			matrix[i] = make([]uint64, ncols)
		}
		setCoeff := func(row, col, degree int) {
			for coord := 0; coord < K.Theta; coord++ {
				if degree >= 0 && coord < len(mask.Limbs) && degree < len(mask.Limbs[coord]) {
					matrix[row*K.Theta+coord][col] = mask.Limbs[coord][degree] % q
				}
			}
		}
		for col := 0; col < shape.Nu-1; col++ {
			for row := 0; row < shape.Mu; row++ {
				setCoeff(row, col, col*shape.Mu+row)
			}
		}
		last := shape.Nu - 1
		for row := shape.Delta; row <= shape.Mu; row++ {
			setCoeff(row, last, last*shape.Mu+row-shape.Delta)
		}
		addElem := func(row, col int, elem kf.Elem, negate bool) {
			for coord := 0; coord < K.Theta; coord++ {
				v := elem.Limb[coord] % q
				if negate && v != 0 {
					v = q - v
				}
				idx := row*K.Theta + coord
				matrix[idx][col] = (matrix[idx][col] + v) % q
			}
		}
		for col := 1; col < shape.Nu; col++ {
			tau, sampleErr := K.RandomElement(random)
			if sampleErr != nil {
				return nil, smallFieldMaskShapeV3{}, fmt.Errorf("sample v3 mask randomizer %d: %w", col, sampleErr)
			}
			// SmallWood Eq. (2): +tau*X^mu in the preceding column
			// cancels -tau in the next column after applying the public
			// column weights. The shifted final column starts at delta.
			addElem(shape.Mu, col-1, tau, false)
			row := 0
			if col == last {
				row = shape.Delta
			}
			addElem(row, col, tau, true)
		}
		rows = append(rows, matrix...)
	}
	return rows, shape, nil
}

func kPowUint(K *kf.Field, base kf.Elem, exponent int) kf.Elem {
	result := K.One()
	for exponent > 0 {
		if exponent&1 == 1 {
			result = K.Mul(result, base)
		}
		base = K.Mul(base, base)
		exponent >>= 1
	}
	return result
}

// smallFieldMaskEvalQueryRowsV3 builds the final theta semantic LVCS queries.
// Their VTargets are the K coordinates of each encoded mask column evaluated
// as a degree-mu polynomial at e.
func smallFieldMaskEvalQueryRowsV3(
	K *kf.Field,
	e kf.Elem,
	totalRows, maskRowOffset int,
	shape smallFieldMaskShapeV3,
) ([][]uint64, error) {
	if K == nil || shape.RowsPerMask != (shape.Mu+1)*K.Theta {
		return nil, fmt.Errorf("invalid v3 mask query shape")
	}
	if maskRowOffset < 0 || maskRowOffset+shape.RowsPerMask > totalRows {
		return nil, fmt.Errorf("v3 mask rows outside committed matrix")
	}
	queries := make([][]uint64, K.Theta)
	power := K.One()
	for row := 0; row <= shape.Mu; row++ {
		mul := K.MulMatrix(power)
		for outCoord := 0; outCoord < K.Theta; outCoord++ {
			if queries[outCoord] == nil {
				queries[outCoord] = make([]uint64, totalRows)
			}
			for inCoord := 0; inCoord < K.Theta; inCoord++ {
				physical := maskRowOffset + row*K.Theta + inCoord
				queries[outCoord][physical] = mul[outCoord][inCoord] % K.Q
			}
		}
		power = K.Mul(power, e)
	}
	return queries, nil
}

// smallFieldMaskEvalFromVTargetsV3 reconstructs M(e) from the final theta
// authenticated VTarget rows produced by smallFieldMaskEvalQueryRowsV3.
func smallFieldMaskEvalFromVTargetsV3(
	K *kf.Field,
	e kf.Elem,
	vTargets [][]uint64,
	witnessQueryRows int,
	shape smallFieldMaskShapeV3,
) (kf.Elem, error) {
	if K == nil || witnessQueryRows < 0 || len(vTargets) != witnessQueryRows+K.Theta {
		return kf.Elem{}, fmt.Errorf("invalid v3 mask VTarget dimensions")
	}
	for coord := 0; coord < K.Theta; coord++ {
		if len(vTargets[witnessQueryRows+coord]) < shape.Nu {
			return kf.Elem{}, fmt.Errorf("short v3 mask VTarget row %d", coord)
		}
	}
	result := K.Zero()
	for col := 0; col < shape.Nu; col++ {
		coords := make([]uint64, K.Theta)
		for coord := 0; coord < K.Theta; coord++ {
			coords[coord] = vTargets[witnessQueryRows+coord][col] % K.Q
		}
		value := K.Phi(coords)
		exponent := col * shape.Mu
		if col == shape.Nu-1 {
			exponent -= shape.Delta
		}
		result = K.Add(result, K.Mul(kPowUint(K, e, exponent), value))
	}
	return result, nil
}

func buildSmallField2025CoeffPlanV3(
	ringQ *ring.Ring,
	K *kf.Field,
	omegaWitness []uint64,
	rows [][]uint64,
	kPoint kf.Elem,
	omegaExtra kf.Elem,
	muDenomInv kf.Elem,
	replayWitnessRows, maskRowOffset, maskRowCount, maskDegreeBound int,
) (smallField2025CoeffPlan, error) {
	if ringQ == nil || K == nil || len(rows) == 0 || len(rows[0]) == 0 {
		return smallField2025CoeffPlan{}, fmt.Errorf("invalid v3 coefficient-plan input")
	}
	q := ringQ.Modulus[0]
	base := buildKPointCoeffMatrix(
		ringQ, K, omegaWitness, rows, kPoint, omegaExtra, muDenomInv,
		replayWitnessRows, maskRowOffset, maskRowCount,
	)
	if len(base) == 0 || len(base)%K.Theta != 0 {
		return smallField2025CoeffPlan{}, fmt.Errorf("invalid v3 witness replay rows=%d theta=%d", len(base), K.Theta)
	}
	shape, err := deriveSmallFieldMaskShapeV3(maskDegreeBound, len(rows[0]), K.Theta)
	if err != nil {
		return smallField2025CoeffPlan{}, err
	}
	if maskRowCount != shape.RowsPerMask {
		return smallField2025CoeffPlan{}, fmt.Errorf("v3 mask rows=%d want=%d", maskRowCount, shape.RowsPerMask)
	}
	maskQueries, err := smallFieldMaskEvalQueryRowsV3(K, kPoint, len(rows), maskRowOffset, shape)
	if err != nil {
		return smallField2025CoeffPlan{}, err
	}
	out := append(copyMatrix(base), maskQueries...)
	omitCols, ok := compressionPivotCols(out, len(rows), q)
	if !ok || len(omitCols) != len(out) {
		return smallField2025CoeffPlan{}, fmt.Errorf("v3 semantic coefficient matrix is not full row rank")
	}
	return smallField2025CoeffPlan{
		C:             out,
		ReplayRows:    len(base),
		WitnessLayers: len(base) / K.Theta,
		QueryCount:    len(out),
		POmitCols:     omitCols,
	}, nil
}
