package PIOP

import (
	"fmt"
	"sort"

	"vSIS-Signature/prf"
)

const (
	RowFamilyPostSignCore              = "post_sign_core"
	RowFamilySigCoeffBounds            = "sig_coeff_bounds_chain"
	RowFamilySigProduct                = "sig_product"
	RowFamilyNonSigBoundChain          = "non_sig_bound_chain"
	RowFamilyPRFGrouped                = "prf_grouped"
	RowFamilySigPrimaryLimb            = "sig_primary_limb"
	RowFamilyPostSignScalarProjection  = "post_sign_scalar_projection"
	RowFamilyPostSignScalarCertificate = "post_sign_scalar_certificate"
	RowFamilyPRFGroupedNonlinear       = "prf_grouped_nonlinear"
)

// RowDependencyMap records which committed row indices are consumed by each
// showing-time constraint family.
type RowDependencyMap map[string][]int

// BuildShowingRowDependencyMap returns the deterministic row-index footprint
// for the main showing verifier families.
func BuildShowingRowDependencyMap(layout RowLayout, prfLayout *PRFLayout) RowDependencyMap {
	acc := map[string]map[int]struct{}{
		RowFamilyPostSignCore:              {},
		RowFamilySigCoeffBounds:            {},
		RowFamilySigProduct:                {},
		RowFamilyNonSigBoundChain:          {},
		RowFamilyPRFGrouped:                {},
		RowFamilySigPrimaryLimb:            {},
		RowFamilyPostSignScalarProjection:  {},
		RowFamilyPostSignScalarCertificate: {},
		RowFamilyPRFGroupedNonlinear:       {},
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
	addPRFFamily := func(prfFamily string) {
		if prfLayout == nil {
			return
		}
		if prfLayout.PackedRows {
			seen := make(map[int]struct{}, len(prfLayout.KeySlots)+len(prfLayout.SBoxSlots))
			for _, slot := range prfLayout.KeySlots {
				if slot.Row >= 0 {
					seen[slot.Row] = struct{}{}
				}
			}
			for _, slot := range prfLayout.SBoxSlots {
				if slot.Row >= 0 {
					seen[slot.Row] = struct{}{}
				}
			}
			for idx := range seen {
				add(prfFamily, idx)
			}
			return
		}
		if prfLayout.StartIdx >= 0 && prfLayout.WitnessRows > 0 {
			addRange(prfFamily, prfLayout.StartIdx, prfLayout.WitnessRows)
			return
		}
		groupRounds := prfLayout.GroupRounds
		if groupRounds <= 0 {
			groupRounds = 1
		}
		t := prfLayout.LenKey + prfLayout.LenNonce
		rounds := prfLayout.RF + prfLayout.RP
		scheduleParams := &prf.Params{RF: prfLayout.RF, RP: prfLayout.RP}
		sboxCount := 0
		for round := 0; round < rounds; round++ {
			if !prf.ShouldCheckpointRound(scheduleParams, round, groupRounds) {
				continue
			}
			full := round < prfLayout.RF/2 || round >= prfLayout.RF/2+prfLayout.RP
			if full {
				sboxCount += t
			} else {
				sboxCount++
			}
		}
		if prfLayout.StartIdx >= 0 {
			addRange(prfFamily, prfLayout.StartIdx, prfLayout.LenKey+sboxCount)
		}
	}
	resolveCoreUCount := func() int {
		if layout.SigUCount > 0 {
			return layout.SigUCount
		}
		uBase := rowLayoutPostSignUBase(layout)
		if uBase < 0 || prfLayout == nil || prfLayout.StartIdx <= uBase {
			return 0
		}
		return prfLayout.StartIdx - uBase
	}

	if layout.ShowingPRFOnly {
		addPRFFamily(RowFamilyPRFGrouped)
		return finalizeRowDependencyMap(acc)
	}

	if rowLayoutHasCoeffNativeSig(layout) {
		if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
			return finalizeRowDependencyMap(acc)
		}
		addCoeffNativeLiteralPackedRows(layout, add, addRange)
		if prfLayout != nil {
			prfFamily := RowFamilyPRFGrouped
			if rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
				prfFamily = RowFamilyPRFGroupedNonlinear
			}
			addPRFFamily(prfFamily)
		}
		return finalizeRowDependencyMap(acc)
	}

	// Post-sign core rows used by signature/hash/packing constraints.
	for _, idx := range rowLayoutPostSignCoreRows(layout) {
		add(RowFamilyPostSignCore, idx)
	}
	if coreUCount := resolveCoreUCount(); coreUCount > 0 {
		addRange(RowFamilyPostSignCore, rowLayoutPostSignUBase(layout), coreUCount)
	}
	if layout.SigBlocks > 1 {
		addRange(RowFamilyPostSignCore, layout.SigExtraUBase, (layout.SigBlocks-1)*layout.SigUCount)
		if !layout.SigDerivedT {
			addRange(RowFamilyPostSignCore, layout.SigExtraTBase, layout.SigBlocks-1)
		}
	}

	// Signature coefficient bounds chain rows.
	coefCount := 0
	if layout.SigBlocks > 0 && layout.SigUCount > 0 {
		coefCount = layout.SigBlocks * layout.SigUCount
	}
	if coefCount > 0 {
		addRange(RowFamilySigCoeffBounds, layout.SigCoeffBase, coefCount)
		if layout.ChainRowsPerSig > 0 {
			addRange(RowFamilySigCoeffBounds, layout.ChainBase, coefCount*layout.ChainRowsPerSig)
		}
	}

	// Non-signature bound chain rows.
	for _, idx := range postSignBoundRowIndices(layout) {
		add(RowFamilyNonSigBoundChain, idx)
	}
	if rowsPer := inferNonSigBoundRowsPer(layout); rowsPer > 0 {
		addRange(RowFamilyNonSigBoundChain, layout.MsgChainBase, 2*rowsPer)
		addRange(RowFamilyNonSigBoundChain, layout.RndChainBase, 2*rowsPer)
	}

	// Grouped PRF witness rows.
	if prfLayout != nil {
		prfFamily := RowFamilyPRFGrouped
		if rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
			prfFamily = RowFamilyPRFGroupedNonlinear
		}
		addPRFFamily(prfFamily)
	}

	return finalizeRowDependencyMap(acc)
}

func addCoeffNativeLiteralPackedRows(
	layout RowLayout,
	add func(string, int),
	addRange func(string, int, int),
) {
	cfg := layout.CoeffNativeSig
	addRange(RowFamilySigPrimaryLimb, layout.PackedSigChainBase, layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup)
	if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		add(RowFamilyPostSignScalarProjection, cfg.PostSignMsgSumRow)
		add(RowFamilyPostSignScalarProjection, cfg.PostSignRndSumRow)
		add(RowFamilyPostSignScalarProjection, cfg.PostSignX1Row)
		if cfg.UScalarCertBase >= 0 && cfg.UScalarCertCount > 0 && cfg.NonSigCertRowsPerScalar > 0 {
			addRange(RowFamilyPostSignScalarCertificate, cfg.UScalarCertBase, cfg.UScalarCertCount*cfg.NonSigCertRowsPerScalar)
		}
		if cfg.X0ScalarCertBase >= 0 && cfg.X0ScalarCertCount > 0 && cfg.NonSigCertRowsPerScalar > 0 {
			addRange(RowFamilyPostSignScalarCertificate, cfg.X0ScalarCertBase, cfg.X0ScalarCertCount*cfg.NonSigCertRowsPerScalar)
		}
		if cfg.X1ScalarCertBase >= 0 && cfg.X1ScalarCertCount > 0 && cfg.NonSigCertRowsPerScalar > 0 {
			addRange(RowFamilyPostSignScalarCertificate, cfg.X1ScalarCertBase, cfg.X1ScalarCertCount*cfg.NonSigCertRowsPerScalar)
		}
	} else if cfg.ScalarBundleCount > 0 {
		addRange(RowFamilyPostSignCore, cfg.ScalarBundleBase, cfg.ScalarBundleCount)
	} else {
		addRange(RowFamilyPostSignCore, cfg.UBase, cfg.UCount)
		addRange(RowFamilyPostSignCore, cfg.X0Base, cfg.X0Count)
		add(RowFamilyPostSignCore, cfg.X1Row)
	}

	if rowsPer := inferNonSigBoundRowsPer(layout); rowsPer > 0 {
		if cfg.ScalarBundleCount > 0 {
			addRange(RowFamilyNonSigBoundChain, cfg.ScalarBundleBase, cfg.ScalarBundleCount)
		} else {
			addRange(RowFamilyNonSigBoundChain, cfg.UBase, cfg.UCount)
			addRange(RowFamilyNonSigBoundChain, cfg.X0Base, cfg.X0Count)
			add(RowFamilyNonSigBoundChain, cfg.X1Row)
		}
		addRange(RowFamilyNonSigBoundChain, layout.MsgRangeBase, cfg.UCount*rowsPer)
		addRange(RowFamilyNonSigBoundChain, layout.RndRangeBase, cfg.X0Count*rowsPer)
		addRange(RowFamilyNonSigBoundChain, layout.X1RangeBase, rowsPer)
	}
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
