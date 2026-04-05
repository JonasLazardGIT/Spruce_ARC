package PIOP

func preSignBoundRowIndices(layout RowLayout) []int {
	// BoundB is enforced on the inner pre-sign fixture rows:
	//   M1,M2,RU0,RU1,R,R0,R1
	return rowLayoutPreSignBoundRows(layout)
}

func preSignCarryRowIndices(layout RowLayout) []int {
	// Carry rows (K0,K1) remain bounded separately in pre-sign.
	return rowLayoutPreSignCarryRows(layout)
}
