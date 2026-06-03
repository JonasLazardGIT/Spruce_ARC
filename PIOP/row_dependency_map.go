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
		if rowLayoutUsesFullMu(layout) {
			for _, idx := range rowLayoutCarrierMuBlockRows(layout) {
				add(RowFamilyPostSignCarriers, idx)
			}
		} else {
			add(RowFamilyPostSignCarriers, layout.IdxCarrierM)
		}
		add(RowFamilyPostSignCarriers, rowLayoutPostSignCarrierR1(layout))
		for _, idx := range rowLayoutPostSignCarrierR0Rows(layout) {
			add(RowFamilyPostSignCarriers, idx)
		}
		for _, rows := range [][]int{
			rowLayoutPostSignMHatSigmaRows(layout),
			rowLayoutPostSignRHat0Rows(layout),
			rowLayoutPostSignR0B2HatRows(layout),
			rowLayoutPostSignTargetMR0HatRows(layout),
			rowLayoutPostSignRHat1Rows(layout),
			rowLayoutPostSignZHatRows(layout),
			rowLayoutPostSignMSigmaR1HatRows(layout),
			rowLayoutPostSignR0R1HatRows(layout),
		} {
			for _, idx := range rows {
				add(RowFamilyNonSigTransformAlias, idx)
			}
		}
		add(RowFamilyPostSignCore, layout.IdxMSigmaR1)
		add(RowFamilyPostSignCore, layout.IdxR0R1)
		for _, idx := range rowLayoutPostSignTHatRows(layout) {
			add(RowFamilyReplayImage, idx)
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
