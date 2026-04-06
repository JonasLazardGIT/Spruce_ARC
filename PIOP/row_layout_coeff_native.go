package PIOP

func resolveCoeffNativeSigModel(opts SimOpts) string {
	if opts.CoeffNativeSigModel != "" {
		return opts.CoeffNativeSigModel
	}
	return CoeffNativeSigModelLiteralPackedAggregatedV3
}

func coeffNativeSigModelUsesLiteralPacked(model string) bool {
	switch model {
	case CoeffNativeSigModelLiteralPackedAggregatedV3:
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

func rowLayoutCoeffNativeUsesTransformBridge(layout RowLayout) bool {
	cfg := layout.CoeffNativeSig
	return cfg.Enabled && rowLayoutCoeffNativeUsesLiteralPackedV3(layout)
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
	componentCount := cfg.SigUCount
	if componentCount <= 0 {
		componentCount = cfg.SigComponentCount
	}
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) || block < 0 || comp < 0 || comp >= componentCount || block >= cfg.SigBlocks {
		return -1
	}
	return cfg.SigBase + block*componentCount + comp
}

func rowLayoutCoeffNativeSigScalarIndex(layout RowLayout, comp, coeff int) int {
	return -1
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
	group := block*cfg.PackedSigComponents + comp
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
