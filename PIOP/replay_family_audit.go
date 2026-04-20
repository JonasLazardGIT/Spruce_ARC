package PIOP

import (
	"fmt"
	"sort"
	"strings"
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

type ReplayFamilyDerivability string

const (
	ReplayFamilyAlreadyDerivedNow              ReplayFamilyDerivability = "already_derived_now"
	ReplayFamilyDerivableAfterLocalRefactor    ReplayFamilyDerivability = "derivable_after_local_refactor"
	ReplayFamilyStructurallyRequiredForCurrent ReplayFamilyDerivability = "structurally_required_unless_statement_changes"
)

type ReplayFamilyReductionEffect string

const (
	ReplayFamilyAlreadyExcludedFromSelector ReplayFamilyReductionEffect = "already_excluded_from_selector"
	ReplayFamilyReducesLogicalRowsOnly      ReplayFamilyReductionEffect = "reduces_logical_rows_only"
	ReplayFamilyReducesActiveBlocks         ReplayFamilyReductionEffect = "reduces_active_blocks"
)

type ReplayFamilyChangeClass string

const (
	ReplayFamilyStatementPreserving ReplayFamilyChangeClass = "statement_preserving"
	ReplayFamilyVerifierRefactor    ReplayFamilyChangeClass = "verifier_refactor"
	ReplayFamilyProtocolLevel       ReplayFamilyChangeClass = "protocol_level"
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
	Derivability         ReplayFamilyDerivability    `json:"derivability"`
	ReductionEffect      ReplayFamilyReductionEffect `json:"reduction_effect"`
	ChangeClass          ReplayFamilyChangeClass     `json:"change_class"`
	PriorityRank         int                         `json:"priority_rank"`
	PriorityReason       string                      `json:"priority_reason"`
	Notes                string                      `json:"notes"`
}

type ReplayFamilyAuditReport struct {
	Selector      ReplayActiveRowStats       `json:"selector"`
	FamilyOrder   []ReplayFamilyKind         `json:"family_order"`
	Families      []ReplayFamilyAuditEntry   `json:"families"`
	Subfamilies   ReplaySubfamilyAuditReport `json:"subfamilies"`
	StageBTargets []ReplayFamilyKind         `json:"stage_b_targets"`
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
	selector := BuildShowingReplayActiveRowSelector(proof.RowLayout, replayCompanionLayoutFromProof(proof))

	unionSelected := make([]int, 0, len(selector))
	entryIndexByKind := make(map[ReplayFamilyKind]int, len(replayFamilyKinds))
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
			Derivability:         replayFamilyDerivability(kind),
			ChangeClass:          replayFamilyChangeClass(kind),
			Notes:                replayFamilyNotes(kind),
		}
		entry.ReductionEffect = replayFamilyReductionEffect(selector, selectedRows, stats)
		report.Families = append(report.Families, entry)
		entryIndexByKind[kind] = len(report.Families) - 1
	}
	sort.Ints(unionSelected)
	if !equalIntSlices(unionSelected, selector) {
		return ReplayFamilyAuditReport{}, fmt.Errorf("replay family selected-row union=%v want selector=%v", unionSelected, selector)
	}

	rankedKinds := rankReplayFamiliesForStageB(report.Families)
	for rank, kind := range rankedKinds {
		idx, ok := entryIndexByKind[kind]
		if !ok {
			return ReplayFamilyAuditReport{}, fmt.Errorf("missing replay family entry for %q", kind)
		}
		report.Families[idx].PriorityRank = rank + 1
		report.Families[idx].PriorityReason = replayFamilyPriorityReason(report.Families[idx])
	}
	for _, kind := range rankedKinds {
		idx, ok := entryIndexByKind[kind]
		if !ok {
			return ReplayFamilyAuditReport{}, fmt.Errorf("missing replay family entry for %q", kind)
		}
		entry := report.Families[idx]
		if entry.SelectedRowCount == 0 || entry.Derivability == ReplayFamilyAlreadyDerivedNow {
			continue
		}
		report.StageBTargets = append(report.StageBTargets, kind)
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
	for _, idx := range []int{layout.IdxCarrierM, layout.IdxCarrierCtr} {
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
	replayBlocks := rowLayoutReplayBlockCount(layout)
	for _, idx := range []int{layout.IdxMHatSigma, layout.IdxRHat0, layout.IdxRHat1, layout.IdxMSigmaR1Hat, layout.IdxR0R1Hat} {
		if err := addRange(ReplayFamilyTransformAlias, idx, replayBlocks); err != nil {
			return nil, err
		}
	}
	if err := addRange(ReplayFamilyReplayImage, layout.IdxTHatBase, rowLayoutReplayTHatCount(layout)); err != nil {
		return nil, err
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

func replayFamilyDerivability(kind ReplayFamilyKind) ReplayFamilyDerivability {
	switch kind {
	case ReplayFamilyTransformAlias, ReplayFamilyReplayImage:
		return ReplayFamilyAlreadyDerivedNow
	case ReplayFamilyTSource, ReplayFamilySourceProduct:
		return ReplayFamilyDerivableAfterLocalRefactor
	default:
		return ReplayFamilyStructurallyRequiredForCurrent
	}
}

func replayFamilyChangeClass(kind ReplayFamilyKind) ReplayFamilyChangeClass {
	switch kind {
	case ReplayFamilyTransformAlias, ReplayFamilyReplayImage:
		return ReplayFamilyStatementPreserving
	case ReplayFamilyTSource, ReplayFamilySourceProduct:
		return ReplayFamilyVerifierRefactor
	default:
		return ReplayFamilyProtocolLevel
	}
}

func replayFamilyNotes(kind ReplayFamilyKind) string {
	switch kind {
	case ReplayFamilyTSource:
		return "Reduced replay now derives THat directly; committed T-source rows remain only on paths that still open the full source bridge."
	case ReplayFamilySourceProduct:
		return "MSigmaR1/R0R1 remain live replay inputs; a reduced-only local derivation attempt broke Eq.(4) because the committed rows are omega-interpolated product polynomials."
	case ReplayFamilyCarrier:
		return "Carrier rows remain direct replay inputs for decode and key binding."
	case ReplayFamilyPRFCompanion:
		return "PRF companion rows stay live for grouped nonlinear and key-binding replay."
	case ReplayFamilyTransformAlias:
		return "Transform-hat alias rows are already treated as verifier-derivable."
	case ReplayFamilyReplayImage:
		return "THat replay rows are already excluded from the active selector."
	default:
		return ""
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

func rankReplayFamiliesForStageB(entries []ReplayFamilyAuditEntry) []ReplayFamilyKind {
	ordered := make([]ReplayFamilyAuditEntry, len(entries))
	copy(ordered, entries)
	sort.SliceStable(ordered, func(i, j int) bool {
		a := ordered[i]
		b := ordered[j]
		if a.SpansAllActiveBlocks != b.SpansAllActiveBlocks {
			return a.SpansAllActiveBlocks
		}
		if (a.Derivability != ReplayFamilyAlreadyDerivedNow) != (b.Derivability != ReplayFamilyAlreadyDerivedNow) {
			return a.Derivability != ReplayFamilyAlreadyDerivedNow
		}
		if replayFamilyReductionEffectOrder(a.ReductionEffect) != replayFamilyReductionEffectOrder(b.ReductionEffect) {
			return replayFamilyReductionEffectOrder(a.ReductionEffect) < replayFamilyReductionEffectOrder(b.ReductionEffect)
		}
		if replayFamilyChangeClassOrder(a.ChangeClass) != replayFamilyChangeClassOrder(b.ChangeClass) {
			return replayFamilyChangeClassOrder(a.ChangeClass) < replayFamilyChangeClassOrder(b.ChangeClass)
		}
		if a.SelectedRowCount != b.SelectedRowCount {
			return a.SelectedRowCount > b.SelectedRowCount
		}
		return a.Family < b.Family
	})
	out := make([]ReplayFamilyKind, len(ordered))
	for i := range ordered {
		out[i] = ordered[i].Family
	}
	return out
}

func replayFamilyReductionEffectOrder(effect ReplayFamilyReductionEffect) int {
	switch effect {
	case ReplayFamilyReducesActiveBlocks:
		return 0
	case ReplayFamilyReducesLogicalRowsOnly:
		return 1
	case ReplayFamilyAlreadyExcludedFromSelector:
		return 2
	default:
		return 3
	}
}

func replayFamilyChangeClassOrder(class ReplayFamilyChangeClass) int {
	switch class {
	case ReplayFamilyVerifierRefactor:
		return 0
	case ReplayFamilyProtocolLevel:
		return 1
	case ReplayFamilyStatementPreserving:
		return 2
	default:
		return 3
	}
}

func replayFamilyPriorityReason(entry ReplayFamilyAuditEntry) string {
	parts := make([]string, 0, 4)
	if entry.SpansAllActiveBlocks {
		parts = append(parts, "all_blocks")
	} else if entry.ActiveBlockCount > 0 {
		parts = append(parts, fmt.Sprintf("%d_of_%d_blocks", entry.ActiveBlockCount, entry.TotalBlockCount))
	} else {
		parts = append(parts, "no_selected_blocks")
	}
	parts = append(parts, string(entry.Derivability))
	parts = append(parts, string(entry.ReductionEffect))
	parts = append(parts, string(entry.ChangeClass))
	return strings.Join(parts, "; ")
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
