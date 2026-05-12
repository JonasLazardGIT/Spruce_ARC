package main

import (
	"math"
	"testing"
)

func TestQ12289N512BoundFormulas(t *testing.T) {
	const (
		n     = 512
		q     = 12289
		alpha = 1.25
		slack = 1.042
		r     = 1.32
	)
	aux := computeAuxiliary(n, 8, 4, 4)
	qHalf := float64(q-1) / 2.0
	rawPerCoeff := slack * r * alpha * math.Sqrt(q)
	if got := int64(math.Floor(rawPerCoeff)); got != 190 {
		t.Fatalf("raw-regimen linf ceiling=%d want 190 (scale %.6f)", got, rawPerCoeff)
	}
	if got := linfCeilingForAugmentedLimit(qHalf, aux.ExtraL2Squared, n); got != 191 {
		t.Fatalf("q-half linf ceiling=%d want 191", got)
	}
	c190 := newLInfCase("linf190", "test", 190, n, aux.ExtraL2Squared, qHalf)
	if !c190.BetaAugLessThanQHalf {
		t.Fatalf("linf=190 should be below q/2: beta_aug=%.6f qHalf=%.6f", c190.BetaAugL2, qHalf)
	}
	if math.Abs(c190.BetaAugL2-6101.520466) > 1e-3 {
		t.Fatalf("linf=190 beta_aug=%.6f want about 6101.520466", c190.BetaAugL2)
	}
	c192 := newLInfCase("linf192", "test", 192, n, aux.ExtraL2Squared, qHalf)
	if c192.BetaAugLessThanQHalf {
		t.Fatalf("linf=192 should be above q/2: beta_aug=%.6f qHalf=%.6f", c192.BetaAugL2, qHalf)
	}
}
