package PIOP

func resolveRowLayoutIdx(layout RowLayout, explicit int, fallback int) int {
	if layout.HasExplicitBaseIdx {
		return explicit
	}
	return fallback
}

func copyNonNegativeIndices(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	out := make([]int, 0, len(in))
	for _, idx := range in {
		if idx >= 0 {
			out = append(out, idx)
		}
	}
	return out
}

func contiguousRowIndices(base, count int) []int {
	if base < 0 || count <= 0 {
		return nil
	}
	out := make([]int, count)
	for i := range out {
		out[i] = base + i
	}
	return out
}

func resolveReplayRowIndices(explicit []int, base, count int) []int {
	if len(explicit) > 0 {
		return copyNonNegativeIndices(explicit)
	}
	return contiguousRowIndices(base, count)
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
func rowLayoutZ(layout RowLayout) int          { return resolveRowLayoutIdx(layout, layout.IdxZ, -1) }
func rowLayoutMSigmaR1(layout RowLayout) int   { return resolveRowLayoutIdx(layout, layout.IdxMSigmaR1, -1) }
func rowLayoutR0R1(layout RowLayout) int       { return resolveRowLayoutIdx(layout, layout.IdxR0R1, -1) }
func rowLayoutMSigmaR1Alias(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxMSigmaR1Alias, -1)
}
func rowLayoutR0R1Alias(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxR0R1Alias, -1)
}
func rowLayoutSourceProductAliasRows(layout RowLayout) []int {
	return copyNonNegativeIndices([]int{
		rowLayoutMSigmaR1Alias(layout),
		rowLayoutR0R1Alias(layout),
	})
}
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
	if len(layout.ReplayTHatRows) > 0 {
		return len(layout.ReplayTHatRows)
	}
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
func rowLayoutPostSignZHat(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxZHat, -1)
}
func rowLayoutPostSignMSigmaR1Hat(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxMSigmaR1Hat, -1)
}
func rowLayoutPostSignR0R1Hat(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxR0R1Hat, -1)
}
func rowLayoutPostSignTHatIndex(layout RowLayout, block int) int {
	if len(layout.ReplayTHatRows) > 0 {
		if block < 0 || block >= len(layout.ReplayTHatRows) {
			return -1
		}
		return layout.ReplayTHatRows[block]
	}
	base := rowLayoutPostSignTHatBase(layout)
	count := rowLayoutReplayTHatCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignMHatSigmaIndex(layout RowLayout, block int) int {
	if len(layout.ReplayMHatSigmaRows) > 0 {
		if block < 0 || block >= len(layout.ReplayMHatSigmaRows) {
			return -1
		}
		return layout.ReplayMHatSigmaRows[block]
	}
	base := rowLayoutPostSignMHatSigma(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignRHat0Index(layout RowLayout, block int) int {
	if len(layout.ReplayRHat0Rows) > 0 {
		if block < 0 || block >= len(layout.ReplayRHat0Rows) {
			return -1
		}
		return layout.ReplayRHat0Rows[block]
	}
	base := rowLayoutPostSignRHat0(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignRHat1Index(layout RowLayout, block int) int {
	if len(layout.ReplayRHat1Rows) > 0 {
		if block < 0 || block >= len(layout.ReplayRHat1Rows) {
			return -1
		}
		return layout.ReplayRHat1Rows[block]
	}
	base := rowLayoutPostSignRHat1(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignZHatIndex(layout RowLayout, block int) int {
	if len(layout.ReplayZHatRows) > 0 {
		if block < 0 || block >= len(layout.ReplayZHatRows) {
			return -1
		}
		return layout.ReplayZHatRows[block]
	}
	base := rowLayoutPostSignZHat(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignMSigmaR1HatIndex(layout RowLayout, block int) int {
	if len(layout.ReplayMSigmaR1HatRows) > 0 {
		if block < 0 || block >= len(layout.ReplayMSigmaR1HatRows) {
			return -1
		}
		return layout.ReplayMSigmaR1HatRows[block]
	}
	base := rowLayoutPostSignMSigmaR1Hat(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignR0R1HatIndex(layout RowLayout, block int) int {
	if len(layout.ReplayR0R1HatRows) > 0 {
		if block < 0 || block >= len(layout.ReplayR0R1HatRows) {
			return -1
		}
		return layout.ReplayR0R1HatRows[block]
	}
	base := rowLayoutPostSignR0R1Hat(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}

func rowLayoutPostSignTHatRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayTHatRows, rowLayoutPostSignTHatBase(layout), rowLayoutReplayTHatCount(layout))
}

func rowLayoutPostSignMHatSigmaRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayMHatSigmaRows, rowLayoutPostSignMHatSigma(layout), rowLayoutReplayBlockCount(layout))
}

func rowLayoutPostSignRHat0Rows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayRHat0Rows, rowLayoutPostSignRHat0(layout), rowLayoutReplayBlockCount(layout))
}

func rowLayoutPostSignRHat1Rows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayRHat1Rows, rowLayoutPostSignRHat1(layout), rowLayoutReplayBlockCount(layout))
}

func rowLayoutPostSignZHatRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayZHatRows, rowLayoutPostSignZHat(layout), rowLayoutReplayBlockCount(layout))
}

func rowLayoutPostSignMSigmaR1HatRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayMSigmaR1HatRows, rowLayoutPostSignMSigmaR1Hat(layout), rowLayoutReplayBlockCount(layout))
}

func rowLayoutPostSignR0R1HatRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayR0R1HatRows, rowLayoutPostSignR0R1Hat(layout), rowLayoutReplayBlockCount(layout))
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
