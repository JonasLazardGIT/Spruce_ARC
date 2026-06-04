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

func resolveLayoutBlockIndices(explicit []int, scalar int) []int {
	if len(explicit) > 0 {
		return copyNonNegativeIndices(explicit)
	}
	if scalar >= 0 {
		return []int{scalar}
	}
	return nil
}

func rowLayoutX0Len(layout RowLayout) int {
	if layout.X0Len > 0 {
		return layout.X0Len
	}
	for _, n := range []int{
		len(layout.CarrierRU0Rows),
		len(layout.CarrierR0Rows),
		len(layout.CarrierK0Rows),
		len(layout.AliasRU0Rows),
		len(layout.AliasR0Rows),
		len(layout.AliasK0Rows),
	} {
		if n > 0 {
			return n
		}
	}
	if layout.IdxRU0 >= 0 || layout.IdxR0 >= 0 || layout.IdxK0 >= 0 {
		return 1
	}
	return 0
}

func rowLayoutPostSignM1(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxM1, 0) }
func rowLayoutPostSignM2(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxM2, 1) }
func rowLayoutPostSignMu(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxMu, rowLayoutPostSignM1(layout))
}
func rowLayoutUsesMu(layout RowLayout) bool {
	return layout.HasExplicitBaseIdx && layout.IdxMu >= 0 && (layout.IdxMu == layout.IdxM1 || layout.MuCarrierPackWidth > 1)
}
func rowLayoutCarrierMuBlockRows(layout RowLayout) []int {
	return resolveLayoutBlockIndices(layout.CarrierMuBlockRows, rowLayoutPostSignCarrierM(layout))
}
func rowLayoutAliasMuBlockRows(layout RowLayout) []int {
	if layout.MuCarrierPackWidth > 1 && len(layout.AliasMuBlockRows) == 0 {
		return nil
	}
	return resolveLayoutBlockIndices(layout.AliasMuBlockRows, rowLayoutPostSignMu(layout))
}
func rowLayoutMuCarrierPackWidth(layout RowLayout) int {
	if layout.MuCarrierPackWidth > 0 {
		return layout.MuCarrierPackWidth
	}
	return 1
}
func rowLayoutUsesPackedMuCarrier(layout RowLayout) bool {
	return rowLayoutUsesMu(layout) && rowLayoutMuCarrierPackWidth(layout) > 1
}
func rowLayoutMuVirtualBlockCount(layout RowLayout) int {
	if layout.MuVirtualBlockCount > 0 {
		return layout.MuVirtualBlockCount
	}
	if rows := rowLayoutAliasMuBlockRows(layout); len(rows) > 0 {
		return len(rows)
	}
	carrierRows := rowLayoutCarrierMuBlockRows(layout)
	if len(carrierRows) == 0 {
		return 0
	}
	return len(carrierRows) * rowLayoutMuCarrierPackWidth(layout)
}
func rowLayoutUsesFullMu(layout RowLayout) bool {
	return rowLayoutUsesMu(layout) && rowLayoutMuVirtualBlockCount(layout) > 1
}
func rowLayoutPreSignRU0(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxRU0, 2) }
func rowLayoutPreSignRU0Rows(layout RowLayout) []int {
	return resolveLayoutBlockIndices(layout.AliasRU0Rows, rowLayoutPreSignRU0(layout))
}
func rowLayoutPreSignRU1(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxRU1, 3) }
func rowLayoutPostSignR(layout RowLayout) int  { return resolveRowLayoutIdx(layout, layout.IdxR, 4) }
func rowLayoutPostSignR0(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxR0, 5) }
func rowLayoutPostSignR0Rows(layout RowLayout) []int {
	return resolveLayoutBlockIndices(layout.AliasR0Rows, rowLayoutPostSignR0(layout))
}
func rowLayoutPostSignR1(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxR1, 6) }
func rowLayoutPreSignK0(layout RowLayout) int  { return resolveRowLayoutIdx(layout, layout.IdxK0, 7) }
func rowLayoutPreSignK0Rows(layout RowLayout) []int {
	return resolveLayoutBlockIndices(layout.AliasK0Rows, rowLayoutPreSignK0(layout))
}
func rowLayoutPreSignK1(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxK1, 8) }
func rowLayoutMSigmaR1(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxMSigmaR1, -1)
}
func rowLayoutR0R1(layout RowLayout) int { return resolveRowLayoutIdx(layout, layout.IdxR0R1, -1) }
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
func rowLayoutPreSignCarrierRU1(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierRU1, -1)
}
func rowLayoutPreSignCarrierRU0Rows(layout RowLayout) []int {
	return resolveLayoutBlockIndices(layout.CarrierRU0Rows, rowLayoutPreSignCarrierRU(layout))
}
func rowLayoutPreSignCarrierR(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierPreR, -1)
}
func rowLayoutPostSignCarrierCtr(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierCtr, -1)
}
func rowLayoutPostSignCarrierR1(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierR1, -1)
}
func rowLayoutPostSignCarrierR0Rows(layout RowLayout) []int {
	return resolveLayoutBlockIndices(layout.CarrierR0Rows, rowLayoutPostSignCarrierCtr(layout))
}
func rowLayoutPreSignCarrierK(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierK, -1)
}
func rowLayoutPreSignCarrierK1(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxCarrierK1, -1)
}
func rowLayoutPreSignCarrierK0Rows(layout RowLayout) []int {
	return resolveLayoutBlockIndices(layout.CarrierK0Rows, rowLayoutPreSignCarrierK(layout))
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
	if layout.HasExplicitBaseIdx && rowLayoutPostSignTHatBase(layout) < 0 {
		return 0
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
func rowLayoutPostSignR0B2Hat(layout RowLayout) int {
	if layout.HasExplicitBaseIdx && layout.IdxR0B2Hat <= 0 && len(layout.ReplayR0B2HatRows) == 0 {
		return -1
	}
	return resolveRowLayoutIdx(layout, layout.IdxR0B2Hat, -1)
}
func rowLayoutPostSignTargetMR0Hat(layout RowLayout) int {
	if layout.HasExplicitBaseIdx && layout.IdxTargetMR0Hat <= 0 && len(layout.ReplayTargetMR0HatRows) == 0 {
		return -1
	}
	return resolveRowLayoutIdx(layout, layout.IdxTargetMR0Hat, -1)
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

func rowLayoutPostSignRHat0ComponentIndex(layout RowLayout, block, component int) int {
	if component < 0 {
		return -1
	}
	x0Len := rowLayoutX0Len(layout)
	if x0Len <= 0 {
		return -1
	}
	if component >= x0Len {
		return -1
	}
	if len(layout.ReplayRHat0Rows) > 0 {
		idx := block*x0Len + component
		if idx < 0 || idx >= len(layout.ReplayRHat0Rows) {
			return -1
		}
		return layout.ReplayRHat0Rows[idx]
	}
	base := rowLayoutPostSignRHat0(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block*x0Len + component
}
func rowLayoutPostSignR0B2HatIndex(layout RowLayout, block int) int {
	if len(layout.ReplayR0B2HatRows) > 0 {
		if block < 0 || block >= len(layout.ReplayR0B2HatRows) {
			return -1
		}
		return layout.ReplayR0B2HatRows[block]
	}
	base := rowLayoutPostSignR0B2Hat(layout)
	count := rowLayoutReplayBlockCount(layout)
	if base < 0 || block < 0 || block >= count {
		return -1
	}
	return base + block
}
func rowLayoutPostSignTargetMR0HatIndex(layout RowLayout, block int) int {
	if len(layout.ReplayTargetMR0HatRows) > 0 {
		if block < 0 || block >= len(layout.ReplayTargetMR0HatRows) {
			return -1
		}
		return layout.ReplayTargetMR0HatRows[block]
	}
	base := rowLayoutPostSignTargetMR0Hat(layout)
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

func rowLayoutPostSignTHatRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayTHatRows, rowLayoutPostSignTHatBase(layout), rowLayoutReplayTHatCount(layout))
}

func rowLayoutPostSignMHatSigmaRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayMHatSigmaRows, rowLayoutPostSignMHatSigma(layout), rowLayoutReplayBlockCount(layout))
}

func rowLayoutPostSignRHat0Rows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayRHat0Rows, rowLayoutPostSignRHat0(layout), rowLayoutReplayBlockCount(layout))
}

func rowLayoutPostSignR0B2HatRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayR0B2HatRows, rowLayoutPostSignR0B2Hat(layout), rowLayoutReplayBlockCount(layout))
}

func rowLayoutPostSignTargetMR0HatRows(layout RowLayout) []int {
	return resolveReplayRowIndices(layout.ReplayTargetMR0HatRows, rowLayoutPostSignTargetMR0Hat(layout), rowLayoutReplayBlockCount(layout))
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
