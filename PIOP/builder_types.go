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
	Tag                [][]int64
	Nonce              [][]int64
	BoundB             int64
	X0Len              int
	X0CoeffBound       int64
	TargetDim          int
	TargetHidingLambda int
	RingDegree         int
	HashRelation       string
	IntGenISIS         bool
	Extras             map[string]interface{}
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
