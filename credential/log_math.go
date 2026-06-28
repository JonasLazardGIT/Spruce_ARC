package credential

import "math"

func Log2Binom(n uint64, k uint64) float64 {
	if k > n {
		return math.Inf(-1)
	}
	if k == 0 || k == n {
		return 0
	}
	if k > n-k {
		k = n - k
	}
	if k == 1 {
		return math.Log2(float64(n))
	}
	if k == 2 {
		return math.Log2(float64(n)) + math.Log2(float64(n-1)) - 1
	}
	lnN, _ := math.Lgamma(float64(n) + 1)
	lnK, _ := math.Lgamma(float64(k) + 1)
	lnNK, _ := math.Lgamma(float64(n-k) + 1)
	return (lnN - lnK - lnNK) / math.Ln2
}

func Log2AddExp(a, b float64) float64 {
	if math.IsInf(a, -1) {
		return b
	}
	if math.IsInf(b, -1) {
		return a
	}
	if b > a {
		a, b = b, a
	}
	return a + math.Log2(1+math.Pow(2, b-a))
}

func Log2SumExp(xs []float64) float64 {
	out := math.Inf(-1)
	for _, x := range xs {
		out = Log2AddExp(out, x)
	}
	return out
}

func BitsFromLog2Prob(logP float64) float64 {
	if math.IsInf(logP, -1) {
		return math.Inf(1)
	}
	if math.IsInf(logP, 1) || math.IsNaN(logP) {
		return 0
	}
	return -logP
}

func minPositiveFloat64(vals ...float64) float64 {
	out := 0.0
	for _, v := range vals {
		if v <= 0 || math.IsInf(v, -1) || math.IsNaN(v) {
			continue
		}
		if out == 0 || v < out {
			out = v
		}
	}
	return out
}
