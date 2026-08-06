package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// PublicInputs holds the public statement values.
type PublicInputs struct {
	Com                []*ring.Poly
	RI0                []*ring.Poly
	RI1                []*ring.Poly
	Ac                 [][]*ring.Poly
	CM                 [][]*ring.Poly
	AS                 [][]*ring.Poly
	A                  [][]*ring.Poly
	B                  []*ring.Poly
	T                  []int64
	Tag                []int64
	Context            []int64
	ContextDigest      []byte
	BoundB             int64
	X0Len              int
	X0CoeffBound       int64
	HashInputBound     int64
	TargetDim          int
	TargetHidingLambda int
	RingDegree         int
	HashRelation       string
	IntGenISIS         bool
	Extras             map[string]interface{}
}

// clonePublicInputsOwned returns an independently owned public statement for
// reusable prepared contexts. PublicInputs is otherwise a shallow value: its
// slices, polynomials, and Extras map can all be mutated by a caller after
// preparation. Prepared strict-v3 paths must never retain those aliases.
func clonePublicInputsOwned(in PublicInputs) (PublicInputs, error) {
	clonePoly := func(poly *ring.Poly) *ring.Poly {
		if poly == nil {
			return nil
		}
		return poly.CopyNew()
	}
	clonePolys := func(polys []*ring.Poly) []*ring.Poly {
		if polys == nil {
			return nil
		}
		out := make([]*ring.Poly, len(polys))
		for i, poly := range polys {
			out[i] = clonePoly(poly)
		}
		return out
	}
	cloneMatrix := func(matrix [][]*ring.Poly) [][]*ring.Poly {
		if matrix == nil {
			return nil
		}
		out := make([][]*ring.Poly, len(matrix))
		for i := range matrix {
			out[i] = clonePolys(matrix[i])
		}
		return out
	}

	out := in
	out.Com = clonePolys(in.Com)
	out.RI0 = clonePolys(in.RI0)
	out.RI1 = clonePolys(in.RI1)
	out.Ac = cloneMatrix(in.Ac)
	out.CM = cloneMatrix(in.CM)
	out.AS = cloneMatrix(in.AS)
	out.A = cloneMatrix(in.A)
	out.B = clonePolys(in.B)
	out.T = append([]int64(nil), in.T...)
	out.Tag = append([]int64(nil), in.Tag...)
	out.Context = append([]int64(nil), in.Context...)
	out.ContextDigest = append([]byte(nil), in.ContextDigest...)
	if in.Extras != nil {
		out.Extras = make(map[string]interface{}, len(in.Extras))
		for key, value := range in.Extras {
			switch typed := value.(type) {
			case nil, string, bool, int, int8, int16, int32, int64,
				uint, uint8, uint16, uint32, uint64, float32, float64:
				out.Extras[key] = typed
			case []byte:
				out.Extras[key] = append([]byte(nil), typed...)
			case []int64:
				out.Extras[key] = append([]int64(nil), typed...)
			case []uint64:
				out.Extras[key] = append([]uint64(nil), typed...)
			default:
				return PublicInputs{}, fmt.Errorf("public input extra %q has mutable or unsupported type %T", key, value)
			}
		}
	}
	return out, nil
}

func publicInputsWithRingDegree(pub PublicInputs, ringDegree int) (PublicInputs, error) {
	if ringDegree <= 0 {
		return pub, nil
	}
	if pub.RingDegree > 0 && pub.RingDegree != ringDegree {
		return pub, fmt.Errorf("public input ring_degree=%d does not match selected ring degree %d", pub.RingDegree, ringDegree)
	}
	pub.RingDegree = ringDegree
	return pub, nil
}

// CoeffNativeShowingWitness holds the retained literal-packed post-sign
// witness. It carries the signed mu row directly so PRF key material can be
// derived from the key slice of mu by construction.
type CoeffNativeShowingWitness struct {
	Sig         []*ring.Poly
	Mu          *ring.Poly
	M           *ring.Poly
	MAttr       *ring.Poly
	K           *ring.Poly
	M1          *ring.Poly
	M2          *ring.Poly
	S           []*ring.Poly
	E           []*ring.Poly
	MuSig       []*ring.Poly
	X0          []*ring.Poly
	X1          *ring.Poly
	R0          []*ring.Poly
	R1          *ring.Poly
	Z           *ring.Poly
	T           *ring.Poly
	HiddenSlot  uint64
	HiddenBits  [4]uint64
	PackedNCols int
}

// WitnessInputs holds the witness vectors for a statement build.
type WitnessInputs struct {
	Mu    []*ring.Poly
	M     []*ring.Poly
	MAttr []*ring.Poly
	K     []*ring.Poly
	S     []*ring.Poly
	E     []*ring.Poly
	MuSig []*ring.Poly
	X0    []*ring.Poly
	X1    []*ring.Poly
	M1    []*ring.Poly
	M2    []*ring.Poly
	RU0   []*ring.Poly
	RU1   []*ring.Poly
	R     []*ring.Poly
	R0    []*ring.Poly
	R1    []*ring.Poly
	// K0/K1 satisfy RU* + RI* = R* + (2B+1)·K*.
	K0 []*ring.Poly
	K1 []*ring.Poly
	Z  []*ring.Poly
	T  []int64
	// CoeffNativeShowing is required when coeff-native showing is enabled.
	CoeffNativeShowing *CoeffNativeShowingWitness
	Extras             map[string]interface{}
}

// ConstraintSet groups the constraint families committed by the prover.
type ConstraintSet struct {
	FparInt  []*ring.Poly
	FparNorm []*ring.Poly
	FaggInt  []*ring.Poly
	FaggNorm []*ring.Poly

	// Formal coefficient overrides are aligned with the corresponding F* slice.
	FparIntCoeffs  [][]uint64
	FparNormCoeffs [][]uint64
	FaggIntCoeffs  [][]uint64
	FaggNormCoeffs [][]uint64

	// These are degrees in witness variables, not in X.
	ParallelAlgDeg   int
	AggregatedAlgDeg int

	PRFLayout          *PRFLayout
	PRFCompanionLayout *PRFCompanionLayout
}

// PRFSlot identifies one logical PRF lane packed into a committed witness row.
type PRFSlot struct {
	Row int
	Col int
}

// PRFLayout locates the grouped PRF witness rows during showing verification.
type PRFLayout struct {
	// Mode names the PRF witness encoding.
	Mode     string
	StartIdx int
	LenKey   int
	LenNonce int
	RF       int
	RP       int
	LenTag   int

	// GroupRounds selects the grouped checkpoint schedule for PRF S-box outputs.
	GroupRounds int

	// PackedRows switches from one-lane-per-row to row-major packed witness rows.
	PackedRows bool
	KeySlots   []PRFSlot
	SBoxSlots  []PRFSlot
	// WitnessRows records the appended PRF witness width before PCS projection.
	WitnessRows int

	// KeyBind ties PRF key lanes to the selected M2 row.
	KeyBind  bool
	M2RowIdx int
}

const PRFLayoutModeSBox = "sbox"
