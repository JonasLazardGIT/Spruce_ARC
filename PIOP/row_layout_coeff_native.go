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

func rowLayoutCoeffLookupIndex(layout RowLayout, comp, block int) int {
	if layout.CoeffLookupBase < 0 || layout.CoeffLookupRowCount <= 0 {
		return -1
	}
	if comp < 0 || block < 0 || comp >= layout.CoeffLookupComponents || block >= layout.CoeffLookupBlocks {
		return -1
	}
	return layout.CoeffLookupBase + comp*layout.CoeffLookupBlocks + block
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
	groupSize := layout.PackedSigChainGroupSize
	if groupSize <= 0 {
		groupSize = 1
	}
	groupBlock := block / groupSize
	group := groupBlock*cfg.PackedSigComponents + comp
	return layout.PackedSigChainBase + group*layout.PackedSigChainRowsPerGroup + lane
}

func rowLayoutPackedSigChainBlockWidth(layout RowLayout) int {
	if layout.PackedSigChainBlockWidth > 0 {
		return layout.PackedSigChainBlockWidth
	}
	return layout.CoeffNativeSig.PackedSigBlockWidth
}

func rowLayoutPackedSigChainEffectiveBlocks(layout RowLayout) int {
	if layout.PackedSigChainEffectiveBlocks > 0 {
		return layout.PackedSigChainEffectiveBlocks
	}
	return layout.CoeffNativeSig.PackedSigBlocks
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

func rowLayoutPairLookupExtractIndex(layout RowLayout, comp, pairGroup, lane, parity, part int) int {
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return -1
	}
	cfg := layout.CoeffNativeSig
	if layout.PairLookupExtractBase < 0 || layout.PairLookupExtractGroupCount <= 0 || layout.PairLookupExtractRowsPerLane <= 0 {
		return -1
	}
	if comp < 0 || comp >= cfg.PackedSigComponents || pairGroup < 0 || pairGroup >= rowLayoutPackedSigChainEffectiveBlocks(layout) {
		return -1
	}
	if lane < 0 || lane >= layout.PackedSigChainRowsPerGroup || parity < 0 || parity >= 2 || part < 0 || part >= 2 {
		return -1
	}
	group := pairGroup*cfg.PackedSigComponents + comp
	if group >= layout.PairLookupExtractGroupCount {
		return -1
	}
	perGroup := layout.PackedSigChainRowsPerGroup * layout.PairLookupExtractRowsPerLane
	offset := group*perGroup + lane*layout.PairLookupExtractRowsPerLane + parity*2 + part
	return layout.PairLookupExtractBase + offset
}

func rowLayoutPairLookupExtractRowCount(layout RowLayout) int {
	if layout.PairLookupExtractBase < 0 || layout.PairLookupExtractGroupCount <= 0 || layout.PairLookupExtractRowsPerLane <= 0 || layout.PackedSigChainRowsPerGroup <= 0 {
		return 0
	}
	return layout.PairLookupExtractGroupCount * layout.PackedSigChainRowsPerGroup * layout.PairLookupExtractRowsPerLane
}
