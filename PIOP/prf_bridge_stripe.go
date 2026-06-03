package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Research-only same-root PRF bridge stripe support for the non-default
// aux-instance path. The live baseline proof does not use this layout.
const prfBridgeStripeLayoutV1 = 1

func buildPRFBridgeStripeLayout(layout *PRFCompanionLayout, currentWitnessRows int, pcsNCols int) (*PRFBridgeStripeLayout, error) {
	if layout == nil {
		return nil, nil
	}
	if currentWitnessRows < 0 {
		return nil, fmt.Errorf("invalid current witness rows=%d", currentWitnessRows)
	}
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	sourceRows := prfCompanionBridgeStripeSourceRows(layout)
	if len(sourceRows) == 0 {
		return nil, fmt.Errorf("missing prf bridge stripe source rows")
	}
	targetSlots := minInt(4, len(sourceRows))
	if targetSlots <= 0 {
		return nil, fmt.Errorf("invalid bridge stripe target slots=%d", targetSlots)
	}
	baseBlock := ceilDiv(currentWitnessRows, pcsNCols)
	physicalRows := make([]int, len(sourceRows))
	for i := range sourceRows {
		physicalRows[i] = (baseBlock+i/targetSlots)*pcsNCols + (i % targetSlots)
	}
	supportSlots, err := buildSigShortnessSupportSlotsForRows(physicalRows, pcsNCols)
	if err != nil {
		return nil, err
	}
	return &PRFBridgeStripeLayout{
		Version:      prfBridgeStripeLayoutV1,
		SourceRows:   append([]int(nil), sourceRows...),
		PhysicalRows: physicalRows,
		SupportSlots: supportSlots,
		PackWidth:    layout.PackWidth,
	}, nil
}

func appendPRFBridgeStripeRows(ringQ *ring.Ring, rows []*ring.Poly, layout *PRFCompanionLayout, pcsNCols int) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if layout == nil {
		return rows, nil
	}
	stripe, err := buildPRFBridgeStripeLayout(layout, len(rows), pcsNCols)
	if err != nil {
		return nil, err
	}
	for i, sourceRow := range stripe.SourceRows {
		targetRow := stripe.PhysicalRows[i]
		for len(rows) < targetRow {
			rows = append(rows, ringQ.NewPoly())
		}
		if len(rows) != targetRow {
			return nil, fmt.Errorf("bridge stripe target row=%d current rows=%d", targetRow, len(rows))
		}
		if sourceRow < 0 || sourceRow >= len(rows) {
			return nil, fmt.Errorf("bridge stripe source row=%d out of range for rows=%d", sourceRow, len(rows))
		}
		rows = append(rows, rows[sourceRow].CopyNew())
	}
	layout.BridgeStripe = stripe
	return rows, nil
}

func prfBridgeStripePaddingRows(layout *PRFCompanionLayout) int {
	if layout == nil || layout.BridgeStripe == nil || len(layout.BridgeStripe.PhysicalRows) == 0 {
		return 0
	}
	start := layout.StartRow + layout.PackedRows
	last := layout.BridgeStripe.PhysicalRows[len(layout.BridgeStripe.PhysicalRows)-1]
	if last < start {
		return 0
	}
	return maxInt(last-start+1-len(layout.BridgeStripe.PhysicalRows), 0)
}

func buildProjectedPRFBridgeLayout(layout *PRFCompanionLayout) (*PRFCompanionLayout, error) {
	if layout == nil {
		return nil, nil
	}
	sourceRows := prfCompanionBridgeStripeSourceRows(layout)
	if len(sourceRows) == 0 {
		return nil, fmt.Errorf("missing prf bridge source rows")
	}
	rowMap := make(map[int]int, len(sourceRows))
	for rel, row := range sourceRows {
		rowMap[row] = rel
	}
	projectSlots := func(slots []CoeffSlot) []CoeffSlot {
		out := make([]CoeffSlot, 0, len(slots))
		for _, slot := range slots {
			rel, ok := rowMap[slot.Row]
			if !ok {
				continue
			}
			out = append(out, CoeffSlot{Row: rel, Coeff: slot.Coeff})
		}
		return out
	}
	keySlots := projectSlots(layout.KeySlots)
	checkpointSlots := projectSlots(layout.CheckpointSlots)
	finalTagSlots := projectSlots(layout.FinalTagSlots)
	dataSlotRows := append([]CoeffSlot(nil), keySlots...)
	dataSlotRows = append(dataSlotRows, checkpointSlots...)
	dataRows := len(uniqueRowsFromCoeffSlots(dataSlotRows))
	packedRows := len(sourceRows)
	rowSemantics := make([]RowSemantics, packedRows)
	for i := range rowSemantics {
		rowSemantics[i] = CoeffPackedRow
	}
	projected := &PRFCompanionLayout{
		StartRow:           0,
		PackWidth:          layout.PackWidth,
		KeySource:          layout.KeySource,
		KeySlots:           keySlots,
		CheckpointSlots:    checkpointSlots,
		FinalTagSlots:      finalTagSlots,
		HelperFamilies:     append([]string(nil), layout.HelperFamilies...),
		ReplayRows:         packedRows,
		PackedRows:         packedRows,
		PackedLogicalCount: len(keySlots) + len(checkpointSlots) + len(finalTagSlots),
		HelperRowCount:     maxInt(packedRows-dataRows, 0),
		DataRows:           dataRows,
		HelperRows:         maxInt(packedRows-dataRows, 0),
		KeyCount:           len(keySlots),
		CheckpointCount:    len(checkpointSlots),
		TagCount:           layout.TagCount,
		RowSemantics:       rowSemantics,
	}
	if err := ValidatePRFCompanionLayout(projected, packedRows); err != nil {
		return nil, err
	}
	return projected, nil
}

func resolvePRFCompanionBridgeLayout(layout *PRFCompanionLayout, mode PRFCompanionMode) (*PRFCompanionLayout, error) {
	if normalizePRFCompanionMode(mode) == PRFCompanionModeAuxInstance {
		return buildProjectedPRFBridgeLayout(layout)
	}
	return layout, nil
}

func buildPRFBridgeStripeEqualityConstraints(ringQ *ring.Ring, rowsNTT []*ring.Poly, layout *PRFCompanionLayout) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if layout == nil || layout.BridgeStripe == nil {
		return nil, nil, nil
	}
	if len(layout.BridgeStripe.SourceRows) != len(layout.BridgeStripe.PhysicalRows) {
		return nil, nil, fmt.Errorf("bridge stripe source rows=%d want physical rows=%d", len(layout.BridgeStripe.SourceRows), len(layout.BridgeStripe.PhysicalRows))
	}
	q := ringQ.Modulus[0]
	families := make([]*ring.Poly, 0, len(layout.BridgeStripe.SourceRows))
	coeffs := make([][]uint64, 0, len(layout.BridgeStripe.SourceRows))
	for i, sourceRow := range layout.BridgeStripe.SourceRows {
		physicalRow := layout.BridgeStripe.PhysicalRows[i]
		if sourceRow < 0 || sourceRow >= len(rowsNTT) || physicalRow < 0 || physicalRow >= len(rowsNTT) {
			return nil, nil, fmt.Errorf("bridge stripe equality rows source=%d physical=%d out of range (rows=%d)", sourceRow, physicalRow, len(rowsNTT))
		}
		sourceCoeff, err := coeffFromNTTPoly(ringQ, rowsNTT[sourceRow])
		if err != nil {
			return nil, nil, fmt.Errorf("bridge stripe source coeff row %d: %w", sourceRow, err)
		}
		physicalCoeff, err := coeffFromNTTPoly(ringQ, rowsNTT[physicalRow])
		if err != nil {
			return nil, nil, fmt.Errorf("bridge stripe physical coeff row %d: %w", physicalRow, err)
		}
		diff := trimPoly(polySub(sourceCoeff, physicalCoeff, q), q)
		families = append(families, nttPolyFromFormalCoeffsIfFits(ringQ, diff))
		coeffs = append(coeffs, diff)
	}
	return families, coeffs, nil
}

func clonePolysAtIndices(rows []*ring.Poly, rowIndices []int) ([]*ring.Poly, error) {
	if len(rowIndices) == 0 {
		return nil, nil
	}
	out := make([]*ring.Poly, len(rowIndices))
	for i, rowIdx := range rowIndices {
		if rowIdx < 0 || rowIdx >= len(rows) {
			return nil, fmt.Errorf("row idx=%d out of range for rows=%d", rowIdx, len(rows))
		}
		if rows[rowIdx] == nil {
			return nil, fmt.Errorf("nil row polynomial at idx=%d", rowIdx)
		}
		out[i] = rows[rowIdx].CopyNew()
	}
	return out, nil
}
