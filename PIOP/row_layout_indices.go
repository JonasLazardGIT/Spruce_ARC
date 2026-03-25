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
func rowLayoutPostSignT(layout RowLayout) int  { return resolveRowLayoutIdx(layout, layout.IdxT, 9) }
func rowLayoutPostSignUBase(layout RowLayout) int {
	return resolveRowLayoutIdx(layout, layout.IdxUBase, 10)
}

func rowLayoutPostSignCoreRows(layout RowLayout) []int {
	return uniqueNonNegativeIndices([]int{
		rowLayoutPostSignM1(layout),
		rowLayoutPostSignM2(layout),
		rowLayoutPostSignR(layout),
		rowLayoutPostSignR0(layout),
		rowLayoutPostSignR1(layout),
		rowLayoutPostSignT(layout),
	})
}

func rowLayoutPostSignBoundRows(layout RowLayout) []int {
	return uniqueNonNegativeIndices([]int{
		rowLayoutPostSignM1(layout),
		rowLayoutPostSignM2(layout),
		rowLayoutPostSignR0(layout),
		rowLayoutPostSignR1(layout),
	})
}

func rowLayoutPreSignBoundRows(layout RowLayout) []int {
	return uniqueNonNegativeIndices([]int{
		rowLayoutPostSignM1(layout),
		rowLayoutPostSignM2(layout),
		rowLayoutPreSignRU0(layout),
		rowLayoutPreSignRU1(layout),
		rowLayoutPostSignR(layout),
		rowLayoutPostSignR0(layout),
		rowLayoutPostSignR1(layout),
	})
}

func rowLayoutPreSignCarryRows(layout RowLayout) []int {
	return uniqueNonNegativeIndices([]int{
		rowLayoutPreSignK0(layout),
		rowLayoutPreSignK1(layout),
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
