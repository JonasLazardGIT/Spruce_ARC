package PIOP

func preSignBoundRowIndices(layout RowLayout) []int {
	// BoundB is enforced via carrier membership on the pre-sign carrier rows:
	//   C^M, C^preRU, C^preR, C^ctr
	return rowLayoutPreSignBoundRows(layout)
}

func preSignCarryRowIndices(layout RowLayout) []int {
	// Carry rows are encoded in the pre-sign K carrier.
	return rowLayoutPreSignCarryRows(layout)
}
