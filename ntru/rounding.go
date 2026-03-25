package ntru

import "math"

func RoundAwayFromZero(x float64) int64 {
	if math.IsNaN(x) {
		return 0
	}
	if x >= 0 {
		return int64(math.Floor(x + 0.5))
	}
	return -int64(math.Floor(-x + 0.5))
}
