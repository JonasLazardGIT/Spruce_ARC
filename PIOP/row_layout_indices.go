package PIOP

func resolveRowLayoutIdx(layout RowLayout, explicit int, fallback int) int {
	if layout.HasExplicitBaseIdx {
		return explicit
	}
	return fallback
}

func rowLayoutPostSignM1(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxM1, 0) }
func rowLayoutPostSignM2(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxM2, 1) }
func rowLayoutPreSignRU0(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxRU0, 2) }
func rowLayoutPreSignRU1(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxRU1, 3) }
func rowLayoutPostSignR(layout RowLayout) int  { return resolveRowLayoutIdx(layout, layout.IdxR, 4) }
func rowLayoutPostSignR0(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxR0, 5) }
func rowLayoutPostSignR1(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxR1, 6) }
func rowLayoutPreSignK0(layout RowLayout) int  { return resolveRowLayoutIdx(layout, layout.IdxK0, 7) }
func rowLayoutPreSignK1(layout RowLayout) int  { return resolveRowLayoutIdx(layout, layout.IdxK1, 8) }
func rowLayoutMSigmaR1(layout RowLayout) int   { return resolveRowLayoutIdx(layout, layout.IdxMSigmaR1, -1) }
func rowLayoutR0R1(layout RowLayout) int       { return resolveRowLayoutIdx(layout, layout.IdxR0R1, -1) }
func rowLayoutPostSignCarrierM(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierM, -1)
}
func rowLayoutPreSignCarrierRU(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierPreRU, -1)
}
func rowLayoutPreSignCarrierR(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierPreR, -1)
}
func rowLayoutPostSignCarrierCtr(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierCtr, -1)
}
func rowLayoutPreSignCarrierK(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierK, -1)
}
func rowLayoutPostSignTSource(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxTSource, -1)
}
func rowLayoutPostSignTSourceCount(layout RowLayout) int {
	if rowLayoutPostSignTSource(layout) < 0 {
		return 0
	}
	if layout.SigBlocks > 0 {
		return layout.SigBlocks
	}
	return 1
}
func rowLayoutUsesCommittedTSourceBridge(layout RowLayout) bool {
	return rowLayoutPostSignTSource(layout) >= 0 && rowLayoutPostSignTSourceCount(layout) > 0
}
func rowLayoutPostSignSigHatBase(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxSigHatBase, -1)
}
func rowLayoutPostSignTHatBase(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxTHatBase, -1)
}
func rowLayoutReplayBlockCount(layout RowLayout) int {
	if layout.ReplayBlockCount > 0 {
		return layout.ReplayBlockCount
	}
	if layout.ReplayTHatCount > 0 {
		return layout.ReplayTHatCount
	}
	if layout.SigBlocks > 0 {
		return layout.SigBlocks
	}
	return 0
}
func rowLayoutReplayTHatCount(layout RowLayout) int {
	if layout.ReplayTHatCount > 0 {
		return layout.ReplayTHatCount
	}
	return rowLayoutReplayBlockCount(layout)
}
func rowLayoutPostSignMHatSigma(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxMHatSigma, -1)
}
func rowLayoutPostSignMHat1(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxMHat1, -1)
}
func rowLayoutPostSignMHat2(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxMHat2, -1)
}
func rowLayoutPostSignRHat0(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxRHat0, -1)
}
func rowLayoutPostSignRHat1(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxRHat1, -1)
}
func rowLayoutPostSignMSigmaR1Hat(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxMSigmaR1Hat, -1)
}
func rowLayoutPostSignR0R1Hat(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxR0R1Hat, -1)
}
func rowLayoutPostSignTHatIndex(layout RowLayout, block int) int {
	base := rowLayoutPostSignTHatBase(layout)
	count := rowLayoutReplayTHatCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignMHatSigmaIndex(layout RowLayout, block int) int {
	base := rowLayoutPostSignMHatSigma(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignRHat0Index(layout RowLayout, block int) int {
	base := rowLayoutPostSignRHat0(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignRHat1Index(layout RowLayout, block int) int {
	base := rowLayoutPostSignRHat1(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignMSigmaR1HatIndex(layout RowLayout, block int) int {
	base := rowLayoutPostSignMSigmaR1Hat(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignR0R1HatIndex(layout RowLayout, block int) int {
	base := rowLayoutPostSignR0R1Hat(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}

func rowLayoutPreSignBoundRows(layout RowLayout) []int {
	return uniqueNonNegativeIndices([]int{
		rowLayoutPostSignCarrierM(layout),
		rowLayoutPreSignCarrierRU(layout),
		rowLayoutPreSignCarrierR(layout),
		rowLayoutPostSignCarrierCtr(layout),
	})
}

func rowLayoutPreSignCarryRows(layout RowLayout) []int {
	return uniqueNonNegativeIndices([]int{
		rowLayoutPreSignCarrierK(layout),
	})
}

func uniqueNonNegativeIndices(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	out := make([]int, 0, len(in))
	seen := make(map[int]struct{}, len(in))
	for _, idx := range in {
		if idx < 0 {
			continue
		}
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		out = append(out, idx)
	}
	return out
}
