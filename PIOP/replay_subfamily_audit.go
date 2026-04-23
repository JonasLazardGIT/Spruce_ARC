package PIOP

import (
	"fmt"
	"sort"
)

type ReplaySubfamilyKind string

const (
	ReplaySubfamilySourceProductMSigmaR1 ReplaySubfamilyKind = "source_product_msigmar1"
	ReplaySubfamilySourceProductR0R1     ReplaySubfamilyKind = "source_product_r0r1"
	ReplaySubfamilyPRFKeyRows            ReplaySubfamilyKind = "prf_key_rows"
	ReplaySubfamilyPRFCheckpointRows     ReplaySubfamilyKind = "prf_checkpoint_rows"
	ReplaySubfamilyPRFFinalTagRows       ReplaySubfamilyKind = "prf_final_tag_rows"
	ReplaySubfamilyPRFHelperRows         ReplaySubfamilyKind = "prf_helper_rows"
)

type ReplaySubfamilyConsumption string

const (
	ReplaySubfamilyReplayConsumed ReplaySubfamilyConsumption = "replay_consumed"
	ReplaySubfamilyKeyBindingOnly ReplaySubfamilyConsumption = "key_binding_only"
	ReplaySubfamilyDirectAuthOnly ReplaySubfamilyConsumption = "direct_auth_only"
	ReplaySubfamilyMixed          ReplaySubfamilyConsumption = "mixed"
	ReplaySubfamilyShortnessOnly  ReplaySubfamilyConsumption = "shortness_only"
	ReplaySubfamilyNotSelected    ReplaySubfamilyConsumption = "not_selected"
)

type ReplaySubfamilyAuditEntry struct {
	Kind                 ReplaySubfamilyKind         `json:"kind"`
	Family               ReplayFamilyKind            `json:"family"`
	LogicalRows          []int                       `json:"logical_rows"`
	SelectedRows         []int                       `json:"selected_rows"`
	LogicalRowCount      int                         `json:"logical_row_count"`
	SelectedRowCount     int                         `json:"selected_row_count"`
	ActiveBlockCount     int                         `json:"active_block_count"`
	TotalBlockCount      int                         `json:"total_block_count"`
	SpansAllActiveBlocks bool                        `json:"spans_all_active_blocks"`
	Consumption          ReplaySubfamilyConsumption  `json:"consumption"`
	ReductionEffect      ReplayFamilyReductionEffect `json:"reduction_effect"`
	Consumers            []string                    `json:"consumers,omitempty"`
	Notes                string                      `json:"notes"`
}

type ReplaySubfamilyAuditReport struct {
	SubfamilyOrder []ReplaySubfamilyKind       `json:"subfamily_order"`
	Entries        []ReplaySubfamilyAuditEntry `json:"entries"`
}

type replaySubfamilySpec struct {
	kind        ReplaySubfamilyKind
	family      ReplayFamilyKind
	logicalRows []int
	consumption ReplaySubfamilyConsumption
	consumers   []string
	notes       string
}

func rowLayoutReducedReplayUsesDerivedSourceProducts(layout RowLayout) bool {
	return rowLayoutCoeffNativeUsesTransformBridge(layout) && !rowLayoutUsesCommittedTSourceBridge(layout)
}

func sortedUniqueInts(rows []int) []int {
	if len(rows) == 0 {
		return nil
	}
	out := append([]int(nil), rows...)
	sort.Ints(out)
	w := 1
	for i := 1; i < len(out); i++ {
		if out[i] == out[w-1] {
			continue
		}
		out[w] = out[i]
		w++
	}
	return out[:w]
}

func uniqueRowsFromCoeffSlots(slots []CoeffSlot) []int {
	rows := make([]int, 0, len(slots))
	for _, slot := range slots {
		if slot.Row >= 0 {
			rows = append(rows, slot.Row)
		}
	}
	return sortedUniqueInts(rows)
}

func prfCompanionKeyRowIndices(layout *PRFCompanionLayout) []int {
	if layout == nil {
		return nil
	}
	return uniqueRowsFromCoeffSlots(layout.KeySlots)
}

func prfCompanionCheckpointRowIndices(layout *PRFCompanionLayout) []int {
	if layout == nil {
		return nil
	}
	return uniqueRowsFromCoeffSlots(layout.CheckpointSlots)
}

func prfCompanionFinalTagRowIndices(layout *PRFCompanionLayout) []int {
	if layout == nil {
		return nil
	}
	return uniqueRowsFromCoeffSlots(layout.FinalTagSlots)
}

func prfCompanionHelperRowIndices(layout *PRFCompanionLayout) []int {
	if layout == nil || layout.HelperRows <= 0 {
		return nil
	}
	start := layout.StartRow + layout.DataRows
	rows := make([]int, 0, layout.HelperRows)
	for i := 0; i < layout.HelperRows; i++ {
		rows = append(rows, start+i)
	}
	return rows
}

func prfCompanionDirectAuthRowIndices(layout *PRFCompanionLayout) []int {
	rows := make([]int, 0)
	rows = append(rows, prfCompanionCheckpointRowIndices(layout)...)
	rows = append(rows, prfCompanionFinalTagRowIndices(layout)...)
	rows = append(rows, prfCompanionHelperRowIndices(layout)...)
	return sortedUniqueInts(rows)
}

func prfCompanionReplayConsumedRows(layout *PRFCompanionLayout, mode PRFCompanionMode) []int {
	if layout == nil {
		return nil
	}
	if normalizePRFCompanionMode(mode) == PRFCompanionModeAuxInstance {
		return nil
	}
	rows := layout.ReplayRows
	if rows <= 0 {
		return nil
	}
	out := make([]int, rows)
	for i := 0; i < rows; i++ {
		out[i] = layout.StartRow + i
	}
	return out
}

func prfCompanionSelectedReplayRows(layout *PRFCompanionLayout, mode PRFCompanionMode) []int {
	rows := append([]int(nil), prfCompanionReplayConsumedRows(layout, mode)...)
	rows = append(rows, prfCompanionKeyRowIndices(layout)...)
	return sortedUniqueInts(rows)
}

func buildReplaySubfamilyAuditReport(proof *Proof, selector []int, stats ReplayActiveRowStats) (ReplaySubfamilyAuditReport, error) {
	if proof == nil {
		return ReplaySubfamilyAuditReport{}, fmt.Errorf("nil proof")
	}
	specs := replaySubfamilySpecsForProof(proof)
	report := ReplaySubfamilyAuditReport{
		SubfamilyOrder: make([]ReplaySubfamilyKind, 0, len(specs)),
	}
	for _, spec := range specs {
		report.SubfamilyOrder = append(report.SubfamilyOrder, spec.kind)
		selectedRows := intersectSortedIntSlices(spec.logicalRows, selector)
		entry := ReplaySubfamilyAuditEntry{
			Kind:                 spec.kind,
			Family:               spec.family,
			LogicalRows:          append([]int(nil), spec.logicalRows...),
			SelectedRows:         selectedRows,
			LogicalRowCount:      len(spec.logicalRows),
			SelectedRowCount:     len(selectedRows),
			ActiveBlockCount:     replayActiveBlockCountForRows(selectedRows, stats.WitnessRows, stats.LayerSize),
			TotalBlockCount:      stats.FullBlocks,
			SpansAllActiveBlocks: len(selectedRows) > 0 && stats.FullBlocks > 0 && replayActiveBlockCountForRows(selectedRows, stats.WitnessRows, stats.LayerSize) == stats.FullBlocks,
			Consumption:          spec.consumption,
			ReductionEffect:      replayFamilyReductionEffect(selector, selectedRows, stats),
			Consumers:            append([]string(nil), spec.consumers...),
			Notes:                spec.notes,
		}
		if len(selectedRows) == 0 && entry.Consumption != ReplaySubfamilyShortnessOnly {
			entry.Consumption = ReplaySubfamilyNotSelected
		}
		report.Entries = append(report.Entries, entry)
	}
	return report, nil
}

func replaySubfamilySpecsForProof(proof *Proof) []replaySubfamilySpec {
	layout := proof.RowLayout
	companion := replayCompanionLayoutFromProof(proof)
	mode := proofPRFCompanionMode(proof)
	replayRows := prfCompanionReplayConsumedRows(companion, mode)
	keyRows := prfCompanionKeyRowIndices(companion)
	directAuthRows := prfCompanionDirectAuthRowIndices(companion)
	sourceProductDerivedNow := sourceProductBridgeEnabledForProof(proof) || (layout.IdxMSigmaR1 < 0 && layout.IdxR0R1 < 0)
	nonNegative := func(rows ...int) []int {
		out := make([]int, 0, len(rows))
		for _, row := range rows {
			if row >= 0 {
				out = append(out, row)
			}
		}
		return sortedUniqueInts(out)
	}

	specs := []replaySubfamilySpec{
		{
			kind:        ReplaySubfamilySourceProductMSigmaR1,
			family:      ReplayFamilySourceProduct,
			logicalRows: nonNegative(layout.IdxMSigmaR1),
			consumption: ReplaySubfamilyReplayConsumed,
			consumers:   []string{"transform_bridge_bb_tran"},
			notes:       replaySubfamilySourceProductNote(sourceProductDerivedNow, "MSigmaR1"),
		},
		{
			kind:        ReplaySubfamilySourceProductR0R1,
			family:      ReplayFamilySourceProduct,
			logicalRows: nonNegative(layout.IdxR0R1),
			consumption: ReplaySubfamilyReplayConsumed,
			consumers:   []string{"transform_bridge_bb_tran"},
			notes:       replaySubfamilySourceProductNote(sourceProductDerivedNow, "R0R1"),
		},
	}
	if companion != nil {
		specs = append(specs,
			replayPRFSubfamilySpec(
				ReplaySubfamilyPRFKeyRows,
				prfCompanionKeyRowIndices(companion),
				replayRows,
				keyRows,
				directAuthRows,
				[]string{"prf_bridge", "transform_bridge_key_binding", "prf_direct_auth_key_trunc"},
				"Packed PRF key rows still feed the live bridge and transform key binding.",
			),
			replayPRFSubfamilySpec(
				ReplaySubfamilyPRFCheckpointRows,
				prfCompanionCheckpointRowIndices(companion),
				replayRows,
				keyRows,
				directAuthRows,
				[]string{"prf_bridge", "prf_direct_auth_checkpoint"},
				"Checkpoint rows have authenticated openings, but the live bridge still mixes over their packed rows.",
			),
			replayPRFSubfamilySpec(
				ReplaySubfamilyPRFFinalTagRows,
				prfCompanionFinalTagRowIndices(companion),
				replayRows,
				keyRows,
				directAuthRows,
				[]string{"prf_bridge", "prf_direct_auth_tag_final"},
				"Final-tag rows are directly audited, but remain replay-consumed under the current bridge.",
			),
			replayPRFSubfamilySpec(
				ReplaySubfamilyPRFHelperRows,
				prfCompanionHelperRowIndices(companion),
				replayRows,
				keyRows,
				directAuthRows,
				[]string{"prf_bridge", "prf_helper_tail"},
				"Helper rows capture packed tail occupancy; they only become removable once the bridge stops mixing them.",
			),
		)
	}
	return specs
}

func proofPRFCompanionMode(proof *Proof) PRFCompanionMode {
	if proof == nil || proof.PRFCompanion == nil {
		return PRFCompanionMode("")
	}
	return proof.PRFCompanion.Mode
}

func replaySubfamilySourceProductNote(derivedNow bool, name string) string {
	if derivedNow {
		return fmt.Sprintf("%s is a deprecated zero-row compatibility placeholder on the maintained selector.", name)
	}
	return fmt.Sprintf("%s remains selected only on legacy proofs that still carry committed source-product rows.", name)
}

func replayPRFSubfamilySpec(kind ReplaySubfamilyKind, rows, replayRows, keyRows, directAuthRows []int, consumers []string, notes string) replaySubfamilySpec {
	return replaySubfamilySpec{
		kind:        kind,
		family:      ReplayFamilyPRFCompanion,
		logicalRows: rows,
		consumption: classifyReplaySubfamilyConsumption(rows, replayRows, keyRows, directAuthRows),
		consumers:   consumers,
		notes:       notes,
	}
}

func classifyReplaySubfamilyConsumption(rows, replayRows, keyRows, directAuthRows []int) ReplaySubfamilyConsumption {
	replay := hasIntIntersection(rows, replayRows)
	key := hasIntIntersection(rows, keyRows)
	direct := hasIntIntersection(rows, directAuthRows)
	switch {
	case replay && (key || direct):
		return ReplaySubfamilyMixed
	case replay:
		return ReplaySubfamilyReplayConsumed
	case key:
		return ReplaySubfamilyKeyBindingOnly
	case direct:
		return ReplaySubfamilyDirectAuthOnly
	default:
		return ReplaySubfamilyNotSelected
	}
}

func hasIntIntersection(a, b []int) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			return true
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return false
}
