package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// PublicInputs holds the public statement values.
type PublicInputs struct {
	Com    []*ring.Poly
	RI0    []*ring.Poly
	RI1    []*ring.Poly
	Ac     [][]*ring.Poly
	A      [][]*ring.Poly
	B      []*ring.Poly
	T      []int64
	Tag    [][]int64
	Nonce  [][]int64
	U      []*ring.Poly
	BoundB int64
	HashRelation string
	Extras map[string]interface{}
}

// CoeffNativeShowingWitness holds the retained literal-packed post-sign
// witness. It carries the signed base rows directly so PRF key material can be
// derived from M2 by construction.
type CoeffNativeShowingWitness struct {
	Sig         []*ring.Poly
	M1          *ring.Poly
	M2          *ring.Poly
	R0          *ring.Poly
	R1          *ring.Poly
	T           *ring.Poly
	PackedNCols int
}

// Validate checks the coeff-native showing witness before row packing.
func (wit *CoeffNativeShowingWitness) Validate(ringN int) error {
	if wit == nil {
		return fmt.Errorf("nil coeff-native showing witness")
	}
	if len(wit.Sig) == 0 {
		return fmt.Errorf("missing coeff-native signature witness rows")
	}
	if wit.M1 == nil {
		return fmt.Errorf("missing signed M1 witness row")
	}
	if wit.M2 == nil {
		return fmt.Errorf("missing signed M2 witness row")
	}
	if wit.R0 == nil {
		return fmt.Errorf("missing signed R0 witness row")
	}
	if wit.R1 == nil {
		return fmt.Errorf("missing signed R1 witness row")
	}
	if wit.T == nil {
		return fmt.Errorf("missing signed T witness row")
	}
	if wit.PackedNCols <= 0 {
		return fmt.Errorf("invalid coeff-native packed ncols=%d", wit.PackedNCols)
	}
	rows := []*ring.Poly{wit.M1, wit.M2, wit.R0, wit.R1, wit.T}
	for i, poly := range wit.Sig {
		if poly == nil {
			return fmt.Errorf("nil coeff-native signature row %d", i)
		}
		if ringN > 0 {
			if len(poly.Coeffs) == 0 || len(poly.Coeffs[0]) != ringN {
				return fmt.Errorf("coeff-native signature row %d width=%d want ringN=%d", i, len(poly.Coeffs[0]), ringN)
			}
		}
	}
	for i, poly := range rows {
		if len(poly.Coeffs) == 0 {
			return fmt.Errorf("nil coeff-native base row %d", i)
		}
		if ringN > 0 && len(poly.Coeffs[0]) != ringN {
			return fmt.Errorf("coeff-native base row %d width=%d want ringN=%d", i, len(poly.Coeffs[0]), ringN)
		}
	}
	return nil
}

// WitnessInputs holds the witness vectors for a statement build.
type WitnessInputs struct {
	M1  []*ring.Poly
	M2  []*ring.Poly
	RU0 []*ring.Poly
	RU1 []*ring.Poly
	R   []*ring.Poly
	R0  []*ring.Poly
	R1  []*ring.Poly
	// K0/K1 satisfy RU* + RI* = R* + (2B+1)·K*.
	K0 []*ring.Poly
	K1 []*ring.Poly
	U  []*ring.Poly
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

func clonePRFSlots(src []PRFSlot) []PRFSlot {
	if len(src) == 0 {
		return nil
	}
	out := make([]PRFSlot, len(src))
	copy(out, src)
	return out
}

func clonePRFLayout(src *PRFLayout) *PRFLayout {
	if src == nil {
		return nil
	}
	out := *src
	out.KeySlots = clonePRFSlots(src.KeySlots)
	out.SBoxSlots = clonePRFSlots(src.SBoxSlots)
	return &out
}

// StatementBuilder builds and verifies a statement.
type StatementBuilder interface {
	Build(pub PublicInputs, wit WitnessInputs, cfg MaskConfig) (*Proof, error)
	Verify(pub PublicInputs, proof *Proof) (bool, error)
}
