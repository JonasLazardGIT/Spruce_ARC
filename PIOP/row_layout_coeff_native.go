package PIOP

func resolveCoeffNativeSigModel(opts SimOpts) string {
	if opts.CoeffNativeSigModel != "" {
		return opts.CoeffNativeSigModel
	}
	return CoeffNativeSigModelLiteralPackedAggregatedV3
}

func coeffNativeSigModelUsesLiteralPacked(model string) bool {
	switch model {
	case CoeffNativeSigModelLiteralPackedAggregatedV3, CoeffNativeSigModelLiteralPackedAggregatedV4SplitPRF:
		return true
	default:
		return false
	}
}

func rowLayoutHasCoeffNativeSig(layout RowLayout) bool {
	return layout.CoeffNativeSig.Enabled
}

func rowLayoutCoeffNativeIsBlocked(layout RowLayout) bool {
	return false
}

func rowLayoutCoeffNativeUsesSemanticRewrite(layout RowLayout) bool {
	return false
}

func rowLayoutCoeffNativeUsesLiteralPacked(layout RowLayout) bool {
	cfg := layout.CoeffNativeSig
	return cfg.Enabled && coeffNativeSigModelUsesLiteralPacked(cfg.Model)
}

func rowLayoutCoeffNativeUsesLiteralPackedV3(layout RowLayout) bool {
	cfg := layout.CoeffNativeSig
	return cfg.Enabled && cfg.Model == CoeffNativeSigModelLiteralPackedAggregatedV3
}

func rowLayoutCoeffNativeSigIndex(layout RowLayout, block, comp int) int {
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) || block < 0 || comp < 0 || comp >= cfg.SigUCount || block >= cfg.SigBlocks {
		return -1
	}
	return cfg.SigBase + block*cfg.SigUCount + comp
}

func rowLayoutCoeffNativeSigScalarIndex(layout RowLayout, comp, coeff int) int {
	return -1
}

func rowLayoutCoeffNativeUIndex(layout RowLayout, ord int) int {
	cfg := layout.CoeffNativeSig
	if !cfg.Enabled || ord < 0 || ord >= cfg.UCount {
		return -1
	}
	if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		return -1
	}
	if rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		if ord < len(cfg.USlots) && cfg.USlots[ord].Row >= 0 {
			return cfg.USlots[ord].Row
		}
	}
	return cfg.UBase + ord
}

func rowLayoutCoeffNativeX0Index(layout RowLayout, ord int) int {
	cfg := layout.CoeffNativeSig
	if !cfg.Enabled || ord < 0 || ord >= cfg.X0Count {
		return -1
	}
	if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		return -1
	}
	if rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		if ord < len(cfg.X0Slots) && cfg.X0Slots[ord].Row >= 0 {
			return cfg.X0Slots[ord].Row
		}
	}
	return cfg.X0Base + ord
}

func rowLayoutCoeffNativeX1Index(layout RowLayout) int {
	cfg := layout.CoeffNativeSig
	if !cfg.Enabled {
		return -1
	}
	if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		return cfg.PostSignX1Row
	}
	if rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		if cfg.X1Slot.Row >= 0 {
			return cfg.X1Slot.Row
		}
	}
	return cfg.X1Row
}

func rowLayoutCoeffNativePackedSigIndex(layout RowLayout, comp, block int) int {
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return -1
	}
	if rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return -1
	}
	if comp < 0 || block < 0 || comp >= cfg.PackedSigComponents || block >= cfg.PackedSigBlocks {
		return -1
	}
	return cfg.PackedSigBase + comp*cfg.PackedSigBlocks + block
}

func rowLayoutCoeffNativeScalarBundleIndex(layout RowLayout, row int) int {
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) || cfg.ScalarBundleBase < 0 || row < 0 || row >= cfg.ScalarBundleCount {
		return -1
	}
	return cfg.ScalarBundleBase + row
}

func rowLayoutCoeffNativeUSlot(layout RowLayout, ord int) PRFSlot {
	cfg := layout.CoeffNativeSig
	if ord < 0 || ord >= len(cfg.USlots) {
		return PRFSlot{Row: -1, Col: -1}
	}
	return cfg.USlots[ord]
}

func rowLayoutCoeffNativeX0Slot(layout RowLayout, ord int) PRFSlot {
	cfg := layout.CoeffNativeSig
	if ord < 0 || ord >= len(cfg.X0Slots) {
		return PRFSlot{Row: -1, Col: -1}
	}
	return cfg.X0Slots[ord]
}

func rowLayoutCoeffNativeX1Slot(layout RowLayout) PRFSlot {
	return layout.CoeffNativeSig.X1Slot
}

func rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout RowLayout) bool {
	cfg := layout.CoeffNativeSig
	return rowLayoutCoeffNativeUsesLiteralPackedV3(layout) &&
		cfg.NonSigCertRowsPerScalar > 0 &&
		cfg.PostSignMsgSumRow >= 0 &&
		cfg.PostSignRndSumRow >= 0 &&
		cfg.PostSignX1Row >= 0
}

func rowLayoutCoeffNativePostSignMsgSumIndex(layout RowLayout) int {
	if !rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		return -1
	}
	return layout.CoeffNativeSig.PostSignMsgSumRow
}

func rowLayoutCoeffNativePostSignRndSumIndex(layout RowLayout) int {
	if !rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		return -1
	}
	return layout.CoeffNativeSig.PostSignRndSumRow
}

func rowLayoutCoeffNativePostSignX1Index(layout RowLayout) int {
	if !rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		return -1
	}
	return layout.CoeffNativeSig.PostSignX1Row
}

func rowLayoutCoeffNativeScalarCertIndex(layout RowLayout, family string, ord, digit int) int {
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
		return -1
	}
	if digit < 0 || digit >= cfg.NonSigCertRowsPerScalar || ord < 0 {
		return -1
	}
	switch family {
	case "u":
		if ord >= cfg.UScalarCertCount || cfg.UScalarCertBase < 0 {
			return -1
		}
		return cfg.UScalarCertBase + ord*cfg.NonSigCertRowsPerScalar + digit
	case "x0":
		if ord >= cfg.X0ScalarCertCount || cfg.X0ScalarCertBase < 0 {
			return -1
		}
		return cfg.X0ScalarCertBase + ord*cfg.NonSigCertRowsPerScalar + digit
	case "x1":
		if ord >= cfg.X1ScalarCertCount || cfg.X1ScalarCertBase < 0 {
			return -1
		}
		return cfg.X1ScalarCertBase + ord*cfg.NonSigCertRowsPerScalar + digit
	default:
		return -1
	}
}

func rowLayoutCoeffNativePackedSigLimbIndex(layout RowLayout, comp, block, lane int) int {
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return -1
	}
	cfg := layout.CoeffNativeSig
	if comp < 0 || comp >= cfg.PackedSigComponents || block < 0 || block >= cfg.PackedSigBlocks {
		return -1
	}
	if layout.PackedSigChainBase < 0 || layout.PackedSigChainRowsPerGroup <= 0 || lane < 0 || lane >= layout.PackedSigChainRowsPerGroup {
		return -1
	}
	group := comp*cfg.PackedSigBlocks + block
	return layout.PackedSigChainBase + group*layout.PackedSigChainRowsPerGroup + lane
}

func rowLayoutCoeffNativeW3ScalarIndex(layout RowLayout, comp, coeff int) int {
	return -1
}

func rowLayoutCoeffNativePackedSigChainIndex(layout RowLayout, group, lane int) int {
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return -1
	}
	if layout.PackedSigChainBase < 0 || layout.PackedSigChainRowsPerGroup <= 0 {
		return -1
	}
	if group < 0 || lane < 0 || group >= layout.PackedSigChainGroupCount || lane >= layout.PackedSigChainRowsPerGroup {
		return -1
	}
	return layout.PackedSigChainBase + group*layout.PackedSigChainRowsPerGroup + lane
}

func rowLayoutCoeffNativeMsgIndex(layout RowLayout, block, ord int) int {
	return -1
}

func rowLayoutCoeffNativeRndIndex(layout RowLayout, block, ord int) int {
	return -1
}

func rowLayoutCoeffNativeW2Index(layout RowLayout, block int) int {
	return -1
}
