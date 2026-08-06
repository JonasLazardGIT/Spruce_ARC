package PIOP

import (
	"fmt"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	prfInputTraceV3PackWidth      = 32
	prfInputTraceV3SBoxInputs     = 179
	prfInputTraceV3BridgeMatrices = 0
)

// PRFInputTraceV3Layout is trusted, reconstructible layout data for the strict
// v3 relation. Unlike PRFCompanionLayout v2 it has no duplicated key, hidden
// slot, checkpoint-output, or randomized bridge-matrix slots. Four Boolean
// slot bits replace four uniquely derivable terminal-tag-state lanes.
type PRFInputTraceV3Layout struct {
	RelationVersion uint8
	StartRow        int
	PackWidth       int
	PackedRows      int
	LogicalScalars  int
	PaddingScalars  int
	SBoxInputSlots  []CoeffSlot
	HiddenSlotBits  [4]CoeffSlot
	FinalTagSlots   []CoeffSlot
	FinalTagLanes   []int
	BridgeMatrices  int
}

func clonePRFInputTraceV3Layout(src *PRFInputTraceV3Layout) *PRFInputTraceV3Layout {
	if src == nil {
		return nil
	}
	out := *src
	out.SBoxInputSlots = cloneCoeffSlots(src.SBoxInputSlots)
	out.FinalTagSlots = cloneCoeffSlots(src.FinalTagSlots)
	if len(src.FinalTagLanes) > 0 {
		out.FinalTagLanes = append([]int(nil), src.FinalTagLanes...)
	}
	return &out
}

func validatePRFInputTraceV3Layout(layout *PRFInputTraceV3Layout, tagCount, witnessRows int) error {
	if layout == nil {
		return fmt.Errorf("nil PRF input-trace v3 layout")
	}
	if layout.RelationVersion != prf.InputTraceRelationVersionV3 {
		return fmt.Errorf("PRF input-trace relation version=%d want %d", layout.RelationVersion, prf.InputTraceRelationVersionV3)
	}
	if layout.StartRow < 0 || layout.PackWidth != prfInputTraceV3PackWidth {
		return fmt.Errorf("invalid PRF input-trace row/width=%d/%d", layout.StartRow, layout.PackWidth)
	}
	if len(layout.SBoxInputSlots) != prfInputTraceV3SBoxInputs {
		return fmt.Errorf("PRF input-trace S-box slots=%d want %d", len(layout.SBoxInputSlots), prfInputTraceV3SBoxInputs)
	}
	bitCount := len(layout.HiddenSlotBits)
	if tagCount < bitCount || len(layout.FinalTagSlots) != tagCount-bitCount {
		return fmt.Errorf("PRF input-trace final-tag slots=%d want %d", len(layout.FinalTagSlots), tagCount-bitCount)
	}
	if len(layout.FinalTagLanes) != len(layout.FinalTagSlots) {
		return fmt.Errorf("PRF input-trace final-tag lane map=%d want %d", len(layout.FinalTagLanes), len(layout.FinalTagSlots))
	}
	for i, lane := range layout.FinalTagLanes {
		if want := i + bitCount; lane != want || lane >= tagCount {
			return fmt.Errorf("PRF input-trace final-tag lane[%d]=%d want %d", i, lane, want)
		}
	}
	wantLogical := len(layout.SBoxInputSlots) + bitCount + len(layout.FinalTagSlots)
	wantRows := (wantLogical + layout.PackWidth - 1) / layout.PackWidth
	if layout.LogicalScalars != wantLogical || layout.PackedRows != wantRows {
		return fmt.Errorf("PRF input-trace logical/rows=%d/%d want %d/%d", layout.LogicalScalars, layout.PackedRows, wantLogical, wantRows)
	}
	if layout.PaddingScalars != wantRows*layout.PackWidth-wantLogical {
		return fmt.Errorf("PRF input-trace padding=%d want %d", layout.PaddingScalars, wantRows*layout.PackWidth-wantLogical)
	}
	if layout.BridgeMatrices != prfInputTraceV3BridgeMatrices {
		return fmt.Errorf("PRF input-trace bridge matrices=%d want zero", layout.BridgeMatrices)
	}
	if witnessRows >= 0 && layout.StartRow+layout.PackedRows > witnessRows {
		return fmt.Errorf("PRF input-trace rows [%d,%d) exceed witness rows=%d", layout.StartRow, layout.StartRow+layout.PackedRows, witnessRows)
	}
	seen := make(map[CoeffSlot]struct{}, wantLogical)
	checkSlot := func(kind string, slot CoeffSlot) error {
		if slot.Row < layout.StartRow || slot.Row >= layout.StartRow+layout.PackedRows {
			return fmt.Errorf("%s slot row=%d outside [%d,%d)", kind, slot.Row, layout.StartRow, layout.StartRow+layout.PackedRows)
		}
		if slot.Coeff < 0 || slot.Coeff >= layout.PackWidth {
			return fmt.Errorf("%s slot coeff=%d outside [0,%d)", kind, slot.Coeff, layout.PackWidth)
		}
		if _, ok := seen[slot]; ok {
			return fmt.Errorf("duplicate %s slot %+v", kind, slot)
		}
		seen[slot] = struct{}{}
		return nil
	}
	for _, slot := range layout.SBoxInputSlots {
		if err := checkSlot("S-box input", slot); err != nil {
			return err
		}
	}
	for _, slot := range layout.HiddenSlotBits {
		if err := checkSlot("hidden slot bit", slot); err != nil {
			return err
		}
	}
	for _, slot := range layout.FinalTagSlots {
		if err := checkSlot("final tag", slot); err != nil {
			return err
		}
	}
	return nil
}

type packedPRFInputTraceV3 struct {
	// Rows retain the canonical Omega head next to the interpolated polynomial.
	// The strict showing builder passes this material directly to its RowInput
	// constructor, avoiding a second polynomial evaluation merely to recover the
	// same six heads. Opaque LVCS provenance still independently authenticates
	// every retained head before it can enter the exact-Omega fast path.
	Rows   []intGenISISRowMaterial
	Layout *PRFInputTraceV3Layout
}

// packCanonicalPRFInputTraceV3Rows packs exactly the independently necessary
// v3 PRF payload. Tag-10 gives 179+4+(10-4)=189 scalars and tag-13 gives
// 179+4+(13-4)=192; either occupies six 32-column rows. Terminal state lanes
// 0..3 are substituted directly into feed-forward, freeing exactly the four
// positions needed by the authenticated hidden-slot bits.
//
// Tag-9 gives 179+4+(9-4)=188 scalars and also occupies six 32-column rows.
// The live structural-v3 showing builder and the verifier's trusted layout
// reconstruction both use this exact order.  Keeping it separate from the
// legacy companion packer prevents v2 checkpoints, duplicated keys, or bridge
// matrices from acquiring a representation in the v3 witness layout.
func packCanonicalPRFInputTraceV3Rows(
	ringQ *ring.Ring,
	startRow int,
	trace *prf.InputTraceV3,
	hiddenBits [4]prf.Elem,
	makeRowFromHead func([]uint64) *ring.Poly,
) (*packedPRFInputTraceV3, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if startRow < 0 {
		return nil, fmt.Errorf("invalid PRF input-trace start row %d", startRow)
	}
	if trace == nil {
		return nil, fmt.Errorf("nil PRF input-trace witness")
	}
	if len(trace.SBoxInputs) != prfInputTraceV3SBoxInputs {
		return nil, fmt.Errorf("PRF input-trace S-box inputs=%d want %d", len(trace.SBoxInputs), prfInputTraceV3SBoxInputs)
	}
	if len(trace.FinalTagState) != 9 && len(trace.FinalTagState) != 10 && len(trace.FinalTagState) != 13 {
		return nil, fmt.Errorf("PRF input-trace tag width=%d want target width 9, 10, or 13", len(trace.FinalTagState))
	}
	if makeRowFromHead == nil {
		return nil, fmt.Errorf("nil PRF input-trace row builder")
	}
	q := ringQ.Modulus[0]
	layout := &PRFInputTraceV3Layout{
		RelationVersion: prf.InputTraceRelationVersionV3,
		StartRow:        startRow,
		PackWidth:       prfInputTraceV3PackWidth,
		BridgeMatrices:  prfInputTraceV3BridgeMatrices,
		SBoxInputSlots:  make([]CoeffSlot, 0, len(trace.SBoxInputs)),
		FinalTagSlots:   make([]CoeffSlot, 0, len(trace.FinalTagState)-len(hiddenBits)),
		FinalTagLanes:   make([]int, 0, len(trace.FinalTagState)-len(hiddenBits)),
	}
	rows := make([]intGenISISRowMaterial, 0, 6)
	head := make([]uint64, prfInputTraceV3PackWidth)
	used := 0
	flush := func() {
		if used == 0 {
			return
		}
		canonicalHead := append([]uint64(nil), head...)
		rows = append(rows, intGenISISRowMaterial{
			Poly: makeRowFromHead(append([]uint64(nil), canonicalHead...)),
			Head: canonicalHead,
		})
		for i := range head {
			head[i] = 0
		}
		used = 0
	}
	appendScalar := func(value prf.Elem) (CoeffSlot, error) {
		if uint64(value) >= q {
			return CoeffSlot{}, fmt.Errorf("noncanonical PRF input-trace scalar %d modulo %d", value, q)
		}
		slot := CoeffSlot{Row: startRow + len(rows), Coeff: used}
		head[used] = uint64(value)
		used++
		if used == len(head) {
			flush()
		}
		return slot, nil
	}
	for i := range trace.SBoxInputs {
		slot, err := appendScalar(trace.SBoxInputs[i].Input)
		if err != nil {
			return nil, fmt.Errorf("S-box input %d: %w", i, err)
		}
		layout.SBoxInputSlots = append(layout.SBoxInputSlots, slot)
	}
	for i, bit := range hiddenBits {
		if bit > 1 {
			return nil, fmt.Errorf("hidden slot bit %d=%d is not Boolean", i, bit)
		}
		slot, err := appendScalar(bit)
		if err != nil {
			return nil, fmt.Errorf("hidden slot bit %d: %w", i, err)
		}
		layout.HiddenSlotBits[i] = slot
	}
	for i := len(hiddenBits); i < len(trace.FinalTagState); i++ {
		value := trace.FinalTagState[i]
		slot, err := appendScalar(value)
		if err != nil {
			return nil, fmt.Errorf("final tag lane %d: %w", i, err)
		}
		layout.FinalTagSlots = append(layout.FinalTagSlots, slot)
		layout.FinalTagLanes = append(layout.FinalTagLanes, i)
	}
	flush()
	layout.PackedRows = len(rows)
	layout.LogicalScalars = len(trace.SBoxInputs) + len(hiddenBits) + len(layout.FinalTagSlots)
	layout.PaddingScalars = layout.PackedRows*layout.PackWidth - layout.LogicalScalars
	if err := validatePRFInputTraceV3Layout(layout, len(trace.FinalTagState), startRow+len(rows)); err != nil {
		return nil, err
	}
	return &packedPRFInputTraceV3{Rows: rows, Layout: layout}, nil
}

// selectorWeightedCubeFormalCoeffV3 renders L*P^3.  Cubing L*P would produce
// L^3*P^3 and is not the v3 input-trace relation.
func selectorWeightedCubeFormalCoeffV3(selectorCoeff, rowCoeff []uint64, q uint64, ringN int) ([]uint64, error) {
	if q == 0 || ringN <= 0 {
		return nil, fmt.Errorf("invalid selector-weighted cube field/ring=%d/%d", q, ringN)
	}
	if len(selectorCoeff) == 0 || len(rowCoeff) == 0 {
		return nil, fmt.Errorf("empty selector-weighted cube input")
	}
	cube := polyMul(polyMul(rowCoeff, rowCoeff, q), rowCoeff, q)
	return reducePolyModXN1(polyMul(selectorCoeff, cube, q), ringN, q), nil
}

type inputTraceV3DegreeEnvelope struct {
	PRFDegree        int
	CarrierDegree    int
	ParallelDegree   int
	AggregatedDegree int
}

// deriveInputTraceV3DegreeEnvelope records the local algebraic-equivalence
// lemma in compiler form: input trace contributes degree 3 and the strict
// two-ternary carrier contributes degree 9.  Other relation families may keep
// a larger incumbent degree (11 for WF128); aggregation remains the incumbent
// degree because this reformulation adds no aggregated product.
func deriveInputTraceV3DegreeEnvelope(nonPRFParallel, nonPRFAggregated int) inputTraceV3DegreeEnvelope {
	return inputTraceV3DegreeEnvelope{
		PRFDegree:        3,
		CarrierDegree:    ternaryCarrierV3Alphabet,
		ParallelDegree:   maxInt(nonPRFParallel, ternaryCarrierV3Alphabet),
		AggregatedDegree: nonPRFAggregated,
	}
}

type ternarySourceCarrierV3Layout struct {
	SourceRows       int
	CarrierRows      int
	PackWidth        int
	DecodeDegree     int
	MembershipDegree int
}

// packTernarySourceRowsV3 packs the concatenated mu_sig/x0/x1 source views
// two per carrier and returns no raw duplicate rows.  For the target N=1024,
// NCols=32 layout, 96 source rows become 48 carrier rows.
func packTernarySourceRowsV3(
	ringQ *ring.Ring,
	omega []uint64,
	sourceRows []intGenISISRowMaterial,
	interp *omegaInterpolationPlan,
	makeRowFromHead func([]uint64) *ring.Poly,
) ([]intGenISISRowMaterial, ternarySourceCarrierV3Layout, error) {
	if len(sourceRows) == 0 || len(sourceRows)%ternaryCarrierV3PackWidth != 0 {
		return nil, ternarySourceCarrierV3Layout{}, fmt.Errorf("v3 ternary source rows=%d must be a positive multiple of two", len(sourceRows))
	}
	rows, err := intGenISISBuildTernaryCarrierRowMaterials(ringQ, omega, sourceRows, ternaryCarrierV3PackWidth, interp, makeRowFromHead, "mu_sig/x0/x1 v3")
	if err != nil {
		return nil, ternarySourceCarrierV3Layout{}, err
	}
	layout := ternarySourceCarrierV3Layout{
		SourceRows:       len(sourceRows),
		CarrierRows:      len(rows),
		PackWidth:        ternaryCarrierV3PackWidth,
		DecodeDegree:     ternaryCarrierV3Alphabet - 1,
		MembershipDegree: ternaryCarrierV3Alphabet,
	}
	if layout.CarrierRows*layout.PackWidth != layout.SourceRows {
		return nil, ternarySourceCarrierV3Layout{}, fmt.Errorf("v3 ternary carrier geometry rows/width/source=%d/%d/%d", layout.CarrierRows, layout.PackWidth, layout.SourceRows)
	}
	return rows, layout, nil
}
