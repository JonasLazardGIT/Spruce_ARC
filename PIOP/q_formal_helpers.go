package PIOP

func maxDegreeFromCoeffRows(coeffRows [][]uint64) int {
	maxDegree := -1
	for i := range coeffRows {
		if len(coeffRows[i]) == 0 {
			continue
		}
		deg := len(coeffRows[i]) - 1
		if deg > maxDegree {
			maxDegree = deg
		}
	}
	return maxDegree
}
