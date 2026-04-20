package PIOP

import (
	"fmt"
	"sort"
)

const (
	RowFamilyPostSignCore         = "post_sign_core"
	RowFamilyPostSignCarriers     = "post_sign_carriers"
	RowFamilySigTransformAlias    = "sig_transform_alias"
	RowFamilyNonSigTransformAlias = "nonsig_transform_alias"
	RowFamilyReplayImage          = "replay_image"
	RowFamilySigPackedSource      = "sig_packed_source"
	RowFamilySigPrimaryLimb       = "sig_primary_limb"
)

// RowDependencyMap records which committed row indices are consumed by each
// showing-time constraint family.
type RowDependencyMap map[string][]int

// BuildShowingRowDependencyMap returns the deterministic row-index footprint
// for the main showing verifier families.
func BuildShowingRowDependencyMap(layout RowLayout, prfLayout *PRFLayout) RowDependencyMap {
	_ = prfLayout
	acc := map[string]map[int]struct{}{
		RowFamilyPostSignCore:         {},
		RowFamilyPostSignCarriers:     {},
		RowFamilySigTransformAlias:    {},
		RowFamilyNonSigTransformAlias: {},
		RowFamilyReplayImage:          {},
		RowFamilySigPackedSource:      {},
		RowFamilySigPrimaryLimb:       {},
	}

	add := func(name string, idx int) {
		if idx < 0 {
			return
		}
		m := acc[name]
		m[idx] = struct{}{}
	}
	addRange := func(name string, start, count int) {
		if count <= 0 || start < 0 {
			return
		}
		for i := 0; i < count; i++ {
			add(name, start+i)
		}
	}
	if rowLayoutHasCoeffNativeSig(layout) {
		if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
			return finalizeRowDependencyMap(acc)
		}
		addCoeffNativeLiteralPackedRows(layout, add, addRange)
		return finalizeRowDependencyMap(acc)
	}
	return finalizeRowDependencyMap(acc)
}

func addCoeffNativeLiteralPackedRows(
	layout RowLayout,
	add func(string, int),
	addRange func(string, int, int),
) {
	if rowLayoutCoeffNativeUsesTransformBridge(layout) {
		if layout.IdxTSource >= 0 && rowLayoutPostSignTSourceCount(layout) > 0 {
			addRange(RowFamilyPostSignCore, layout.IdxTSource, rowLayoutPostSignTSourceCount(layout))
		}
		add(RowFamilyPostSignCarriers, layout.IdxCarrierM)
		add(RowFamilyPostSignCarriers, layout.IdxCarrierCtr)
		if replayBlocks := rowLayoutReplayBlockCount(layout); replayBlocks > 0 {
			addRange(RowFamilyNonSigTransformAlias, layout.IdxMHatSigma, replayBlocks)
			addRange(RowFamilyNonSigTransformAlias, layout.IdxRHat0, replayBlocks)
			addRange(RowFamilyNonSigTransformAlias, layout.IdxRHat1, replayBlocks)
			addRange(RowFamilyNonSigTransformAlias, layout.IdxMSigmaR1Hat, replayBlocks)
			addRange(RowFamilyNonSigTransformAlias, layout.IdxR0R1Hat, replayBlocks)
		}
		add(RowFamilyPostSignCore, layout.IdxMSigmaR1)
		add(RowFamilyPostSignCore, layout.IdxR0R1)
		if layout.IdxTHatBase >= 0 && rowLayoutReplayTHatCount(layout) > 0 {
			addRange(RowFamilyReplayImage, layout.IdxTHatBase, rowLayoutReplayTHatCount(layout))
		}
		return
	}
	addRange(RowFamilySigPackedSource, layout.CoeffNativeSig.PackedSigBase, layout.CoeffNativeSig.PackedSigCount)
	addRange(RowFamilySigPrimaryLimb, layout.PackedSigChainBase, layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup)
}

func finalizeRowDependencyMap(acc map[string]map[int]struct{}) RowDependencyMap {
	out := make(RowDependencyMap, len(acc))
	for family, set := range acc {
		if len(set) == 0 {
			continue
		}
		rows := make([]int, 0, len(set))
		for idx := range set {
			rows = append(rows, idx)
		}
		sort.Ints(rows)
		out[family] = rows
	}
	return out
}

func inferNonSigBoundRowsPer(layout RowLayout) int {
	if layout.NonSigBoundRowsPer > 0 {
		return layout.NonSigBoundRowsPer
	}
	if layout.MsgChainBase < 0 || layout.RndChainBase < 0 {
		return 0
	}
	delta := layout.RndChainBase - layout.MsgChainBase
	if delta <= 0 || delta%2 != 0 {
		return 0
	}
	rowsPer := delta / 2
	if rowsPer <= 0 {
		return 0
	}
	return rowsPer
}

// ValidateRowDependencyClosure ensures every row index consumed by a showing
// verifier family resolves to an existing committed witness row.
func ValidateRowDependencyClosure(layout RowLayout, prfLayout *PRFLayout, witnessRows int) error {
	if witnessRows < 0 {
		return fmt.Errorf("invalid witness row count %d", witnessRows)
	}
	deps := BuildShowingRowDependencyMap(layout, prfLayout)
	for family, rows := range deps {
		prev := -1
		for i := 0; i < len(rows); i++ {
			idx := rows[i]
			if idx < 0 || idx >= witnessRows {
				return fmt.Errorf("row dependency out of range: family=%s idx=%d witnessRows=%d", family, idx, witnessRows)
			}
			if idx <= prev {
				return fmt.Errorf("row dependency not strictly increasing: family=%s rows=%v", family, rows)
			}
			prev = idx
		}
	}
	return nil
}
