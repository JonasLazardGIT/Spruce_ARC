package PIOP

import "sort"

// ReplayActiveRowStats captures the current showing replay-basis footprint
// under the live K-point block geometry.
type ReplayActiveRowStats struct {
	SelectedRows int     `json:"selected_rows"`
	WitnessRows  int     `json:"witness_rows"`
	LayerSize    int     `json:"layer_size"`
	ActiveBlocks int     `json:"active_blocks"`
	FullBlocks   int     `json:"full_blocks"`
	ReductionPct float64 `json:"reduction_pct"`
}

type replaySelectorGeometry struct {
	witnessRows int
	layerSize   int
	fullBlocks  int
}

// BuildShowingReplayActiveRowSelector returns the current best-effort showing
// replay basis under the live proof statement. It intentionally excludes rows
// whose values are derivable from selected rows and public coefficients at
// replay time:
//   - non-sign transform aliases
//   - replay-image rows
//
// It retains rows that are still consumed directly by the showing K-replay:
//   - post-sign carriers
//   - committed T-source rows on full replay
//   - PRF companion rows still touched by the live replay bridge / key binding
func BuildShowingReplayActiveRowSelector(layout RowLayout, companion *PRFCompanionLayout) []int {
	acc := map[int]struct{}{}
	add := func(idx int) {
		if idx < 0 {
			return
		}
		acc[idx] = struct{}{}
	}
	addRange := func(start, count int) {
		if start < 0 || count <= 0 {
			return
		}
		for i := 0; i < count; i++ {
			acc[start+i] = struct{}{}
		}
	}

	if rowLayoutCoeffNativeUsesTransformBridge(layout) {
		add(layout.IdxCarrierM)
		add(layout.IdxCarrierCtr)
		if rowLayoutUsesCommittedTSourceBridge(layout) {
			addRange(layout.IdxTSource, rowLayoutPostSignTSourceCount(layout))
		}
		add(layout.IdxMSigmaR1)
		add(layout.IdxR0R1)
	} else {
		deps := BuildShowingRowDependencyMap(layout, nil)
		for _, family := range []string{
			RowFamilyPostSignCore,
			RowFamilyPostSignCarriers,
		} {
			for _, idx := range deps[family] {
				add(idx)
			}
		}
	}
	for _, idx := range prfCompanionSelectedReplayRows(companion) {
		add(idx)
	}

	out := make([]int, 0, len(acc))
	for idx := range acc {
		out = append(out, idx)
	}
	sort.Ints(out)
	return out
}

// BuildShowingReplayActiveRowStats reports how much of the shipped showing
// witness can currently be removed from the K-point replay basis before the
// live block geometry stops shrinking.
func BuildShowingReplayActiveRowStats(proof *Proof) ReplayActiveRowStats {
	if proof == nil {
		return ReplayActiveRowStats{}
	}
	selector := BuildShowingReplayActiveRowSelector(proof.RowLayout, replayCompanionLayoutFromProof(proof))
	geom := buildReplaySelectorGeometryFromProof(proof)
	activeBlocks := replayActiveBlockCountForRows(selector, geom.witnessRows, geom.layerSize)
	reductionPct := 0.0
	if geom.witnessRows > 0 {
		reductionPct = 100.0 * float64(geom.witnessRows-len(selector)) / float64(geom.witnessRows)
	}
	return ReplayActiveRowStats{
		SelectedRows: len(selector),
		WitnessRows:  geom.witnessRows,
		LayerSize:    geom.layerSize,
		ActiveBlocks: activeBlocks,
		FullBlocks:   geom.fullBlocks,
		ReductionPct: reductionPct,
	}
}

func buildReplaySelectorGeometryFromProof(proof *Proof) replaySelectorGeometry {
	if proof == nil {
		return replaySelectorGeometry{}
	}
	witnessRows := proof.RowLayout.SigCount
	if witnessRows <= 0 {
		witnessRows = proof.MaskRowOffset
	}
	ncols := proof.NColsUsed
	if ncols <= 0 {
		ncols = proof.PCSGeometry.WitnessPackingCols
	}
	layerSize := 0
	if proof.Theta > 1 && ncols > 0 {
		layerSize = ncols + proof.Theta
	}
	fullBlocks := 0
	if witnessRows > 0 && layerSize > 0 {
		fullBlocks = ceilDiv(witnessRows, layerSize)
	}
	return replaySelectorGeometry{
		witnessRows: witnessRows,
		layerSize:   layerSize,
		fullBlocks:  fullBlocks,
	}
}

func replayActiveBlockCountForRows(rows []int, witnessRows, layerSize int) int {
	if layerSize <= 0 || witnessRows <= 0 || len(rows) == 0 {
		return 0
	}
	seen := make(map[int]struct{}, len(rows))
	for _, idx := range rows {
		if idx < 0 || idx >= witnessRows {
			continue
		}
		seen[idx/layerSize] = struct{}{}
	}
	return len(seen)
}
