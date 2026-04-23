package PIOP

import (
	"fmt"
	"sort"
)

type ReplayFamilyKind string

const (
	ReplayFamilySigPackedSource ReplayFamilyKind = "sig_packed_source"
	ReplayFamilyTSource         ReplayFamilyKind = "t_source"
	ReplayFamilySourceProduct   ReplayFamilyKind = "source_product"
	ReplayFamilyCarrier         ReplayFamilyKind = "carrier"
	ReplayFamilyPRFCompanion    ReplayFamilyKind = "prf_companion"
	ReplayFamilyTransformAlias  ReplayFamilyKind = "transform_alias"
	ReplayFamilyReplayImage     ReplayFamilyKind = "replay_image"
)

type ReplayFamilyReductionEffect string

const (
	ReplayFamilyAlreadyExcludedFromSelector ReplayFamilyReductionEffect = "already_excluded_from_selector"
	ReplayFamilyReducesLogicalRowsOnly      ReplayFamilyReductionEffect = "reduces_logical_rows_only"
	ReplayFamilyReducesActiveBlocks         ReplayFamilyReductionEffect = "reduces_active_blocks"
)

type ReplayFamilyAuditEntry struct {
	Family               ReplayFamilyKind            `json:"family"`
	LogicalRows          []int                       `json:"logical_rows"`
	SelectedRows         []int                       `json:"selected_rows"`
	LogicalRowCount      int                         `json:"logical_row_count"`
	SelectedRowCount     int                         `json:"selected_row_count"`
	ActiveBlockCount     int                         `json:"active_block_count"`
	TotalBlockCount      int                         `json:"total_block_count"`
	SpansAllActiveBlocks bool                        `json:"spans_all_active_blocks"`
	ReductionEffect      ReplayFamilyReductionEffect `json:"reduction_effect"`
	Notes                string                      `json:"notes"`
}

type ReplayFamilyAuditReport struct {
	Selector    ReplayActiveRowStats       `json:"selector"`
	FamilyOrder []ReplayFamilyKind         `json:"family_order"`
	Families    []ReplayFamilyAuditEntry   `json:"families"`
	Subfamilies ReplaySubfamilyAuditReport `json:"subfamilies"`
}

var replayFamilyKinds = []ReplayFamilyKind{
	ReplayFamilyTSource,
	ReplayFamilySourceProduct,
	ReplayFamilyCarrier,
	ReplayFamilyPRFCompanion,
	ReplayFamilyTransformAlias,
	ReplayFamilyReplayImage,
}

func replayFamilyKindOrder() []ReplayFamilyKind {
	out := make([]ReplayFamilyKind, len(replayFamilyKinds))
	copy(out, replayFamilyKinds)
	return out
}

func BuildReplayFamilyAuditReport(proof *Proof) (ReplayFamilyAuditReport, error) {
	if proof == nil {
		return ReplayFamilyAuditReport{}, fmt.Errorf("nil proof")
	}
	if !proofSupportsReplayFamilyAudit(proof) {
		return ReplayFamilyAuditReport{}, nil
	}
	stats := BuildShowingReplayActiveRowStats(proof)
	report := ReplayFamilyAuditReport{
		Selector:    stats,
		FamilyOrder: replayFamilyKindOrder(),
	}

	families, err := canonicalReplayFamilyRows(proof)
	if err != nil {
		return ReplayFamilyAuditReport{}, err
	}
	selector := BuildShowingReplayActiveRowSelectorFromProof(proof)
	unionSelected := make([]int, 0, len(selector))
	for _, kind := range replayFamilyKinds {
		logicalRows := append([]int(nil), families[kind]...)
		selectedRows := intersectSortedIntSlices(logicalRows, selector)
		unionSelected = append(unionSelected, selectedRows...)
		entry := ReplayFamilyAuditEntry{
			Family:               kind,
			LogicalRows:          logicalRows,
			SelectedRows:         selectedRows,
			LogicalRowCount:      len(logicalRows),
			SelectedRowCount:     len(selectedRows),
			ActiveBlockCount:     replayActiveBlockCountForRows(selectedRows, stats.WitnessRows, stats.LayerSize),
			TotalBlockCount:      stats.FullBlocks,
			SpansAllActiveBlocks: len(selectedRows) > 0 && stats.FullBlocks > 0 && replayActiveBlockCountForRows(selectedRows, stats.WitnessRows, stats.LayerSize) == stats.FullBlocks,
			Notes:                replayFamilyNotes(kind),
		}
		entry.ReductionEffect = replayFamilyReductionEffect(selector, selectedRows, stats)
		if kind == ReplayFamilySourceProduct {
			entry.Notes = replayFamilySourceProductNotes(len(selectedRows), sourceProductBridgeEnabledForProof(proof))
		}
		report.Families = append(report.Families, entry)
	}
	sort.Ints(unionSelected)
	if !equalIntSlices(unionSelected, selector) {
		return ReplayFamilyAuditReport{}, fmt.Errorf("replay family selected-row union=%v want selector=%v", unionSelected, selector)
	}
	subfamilies, err := buildReplaySubfamilyAuditReport(proof, selector, stats)
	if err != nil {
		return ReplayFamilyAuditReport{}, err
	}
	report.Subfamilies = subfamilies
	return report, nil
}

func proofSupportsReplayFamilyAudit(proof *Proof) bool {
	if proof == nil {
		return false
	}
	if !rowLayoutCoeffNativeUsesTransformBridge(proof.RowLayout) {
		return false
	}
	if proof.RowLayout.SigCount <= 0 && proof.MaskRowOffset <= 0 {
		return false
	}
	if proof.Theta <= 1 {
		return false
	}
	return true
}

func replayCompanionLayoutFromProof(proof *Proof) *PRFCompanionLayout {
	if proof == nil || proof.PRFCompanion == nil {
		return nil
	}
	return proof.PRFCompanion.Layout
}

func canonicalReplayFamilyRows(proof *Proof) (map[ReplayFamilyKind][]int, error) {
	rows := make(map[ReplayFamilyKind][]int, len(replayFamilyKinds))
	for _, kind := range replayFamilyKinds {
		rows[kind] = nil
	}
	if proof == nil {
		return rows, fmt.Errorf("nil proof")
	}
	witnessRows := proof.RowLayout.SigCount
	if witnessRows <= 0 {
		witnessRows = proof.MaskRowOffset
	}
	owner := make(map[int]ReplayFamilyKind)
	add := func(kind ReplayFamilyKind, idx int) error {
		if idx < 0 {
			return nil
		}
		if witnessRows > 0 && idx >= witnessRows {
			return fmt.Errorf("replay family %q row idx=%d out of range for witness rows=%d", kind, idx, witnessRows)
		}
		if prev, ok := owner[idx]; ok && prev != kind {
			return fmt.Errorf("replay family row overlap idx=%d between %q and %q", idx, prev, kind)
		}
		owner[idx] = kind
		rows[kind] = append(rows[kind], idx)
		return nil
	}
	addRange := func(kind ReplayFamilyKind, start, count int) error {
		if start < 0 || count <= 0 {
			return nil
		}
		for i := 0; i < count; i++ {
			if err := add(kind, start+i); err != nil {
				return err
			}
		}
		return nil
	}

	layout := proof.RowLayout
	if err := addRange(ReplayFamilyTSource, layout.IdxTSource, rowLayoutPostSignTSourceCount(layout)); err != nil {
		return nil, err
	}
	for _, idx := range []int{layout.IdxMSigmaR1, layout.IdxR0R1} {
		if err := add(ReplayFamilySourceProduct, idx); err != nil {
			return nil, err
		}
	}
	for _, idx := range []int{layout.IdxCarrierM, rowLayoutPostSignCarrierR1(layout)} {
		if err := add(ReplayFamilyCarrier, idx); err != nil {
			return nil, err
		}
	}
	for _, idx := range rowLayoutPostSignCarrierR0Rows(layout) {
		if err := add(ReplayFamilyCarrier, idx); err != nil {
			return nil, err
		}
	}
	for _, idx := range prfCompanionPackedRowIndices(replayCompanionLayoutFromProof(proof)) {
		if err := add(ReplayFamilyPRFCompanion, idx); err != nil {
			return nil, err
		}
	}
	if err := addRange(ReplayFamilyTransformAlias, rowLayoutPostSignSigHatBase(layout), replaySigTransformAliasCount(layout)); err != nil {
		return nil, err
	}
	for _, replayRows := range [][]int{
		rowLayoutPostSignMHatSigmaRows(layout),
		rowLayoutPostSignRHat0Rows(layout),
		rowLayoutPostSignRHat1Rows(layout),
		rowLayoutPostSignMSigmaR1HatRows(layout),
		rowLayoutPostSignR0R1HatRows(layout),
	} {
		for _, idx := range replayRows {
			if err := add(ReplayFamilyTransformAlias, idx); err != nil {
				return nil, err
			}
		}
	}
	for _, idx := range rowLayoutPostSignTHatRows(layout) {
		if err := add(ReplayFamilyReplayImage, idx); err != nil {
			return nil, err
		}
	}

	for _, kind := range replayFamilyKinds {
		sort.Ints(rows[kind])
		if !isStrictlyIncreasing(rows[kind]) {
			return nil, fmt.Errorf("replay family %q rows not strictly increasing: %v", kind, rows[kind])
		}
	}
	return rows, nil
}

func replaySigTransformAliasCount(layout RowLayout) int {
	if rowLayoutPostSignSigHatBase(layout) < 0 || layout.SigBlocks <= 0 {
		return 0
	}
	componentCount := layout.CoeffNativeSig.SigComponentCount
	if componentCount <= 0 {
		componentCount = layout.CoeffNativeSig.SigUCount
	}
	if componentCount <= 0 {
		return 0
	}
	return layout.SigBlocks * componentCount
}

func replayFamilyNotes(kind ReplayFamilyKind) string {
	switch kind {
	case ReplayFamilyTSource:
		return "Committed T-source rows are absent on theorem-clean full replay and excluded from the active replay selector."
	case ReplayFamilySourceProduct:
		return "Source-product is a deprecated compatibility/reporting bucket. Maintained proofs keep it at zero selected rows."
	case ReplayFamilyCarrier:
		return "Carrier rows remain selected because replay decoding and key binding still consume them directly."
	case ReplayFamilyPRFCompanion:
		return "PRF companion packed rows remain selected because the live proof still authenticates their packed bridge path through Q and key-binding checks."
	case ReplayFamilyTransformAlias:
		return "Transform-hat alias rows are committed but excluded from the active replay selector."
	case ReplayFamilyReplayImage:
		return "THat replay rows are already excluded from the active selector."
	default:
		return ""
	}
}

func replayFamilySourceProductNotes(selectedRows int, bridgeActive bool) string {
	switch {
	case bridgeActive:
		return "Source-product is a deprecated compatibility/reporting bucket. This proof carries the legacy bridge payload, so the active selector cost stays at zero."
	case selectedRows == 0:
		return "Source-product is a deprecated compatibility/reporting bucket. Maintained proofs keep it at zero selected rows."
	default:
		return "Source-product is a deprecated compatibility/reporting bucket. This proof still carries committed source-product rows, so the selector reports their legacy cost."
	}
}

func replayFamilyReductionEffect(selector, selectedRows []int, stats ReplayActiveRowStats) ReplayFamilyReductionEffect {
	if len(selectedRows) == 0 {
		return ReplayFamilyAlreadyExcludedFromSelector
	}
	without := sortedSetDifference(selector, selectedRows)
	if replayActiveBlockCountForRows(without, stats.WitnessRows, stats.LayerSize) < stats.ActiveBlocks {
		return ReplayFamilyReducesActiveBlocks
	}
	return ReplayFamilyReducesLogicalRowsOnly
}

func intersectSortedIntSlices(a, b []int) []int {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make([]int, 0, minInt(len(a), len(b)))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, a[i])
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return out
}

func sortedSetDifference(a, b []int) []int {
	if len(a) == 0 {
		return nil
	}
	if len(b) == 0 {
		out := make([]int, len(a))
		copy(out, a)
		return out
	}
	out := make([]int, 0, len(a))
	i, j := 0, 0
	for i < len(a) {
		if j >= len(b) {
			out = append(out, a[i:]...)
			break
		}
		switch {
		case a[i] == b[j]:
			i++
			j++
		case a[i] < b[j]:
			out = append(out, a[i])
			i++
		default:
			j++
		}
	}
	return out
}

func isStrictlyIncreasing(rows []int) bool {
	for i := 1; i < len(rows); i++ {
		if rows[i] <= rows[i-1] {
			return false
		}
	}
	return true
}

func minInt(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
