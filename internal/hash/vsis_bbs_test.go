package hash

import (
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func TestGenerateBWithX0LenSamplesB0(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{97})
	if err != nil {
		t.Fatalf("new ring: %v", err)
	}
	seed := []byte("bounded-bb-tran-B")
	prng, err := utils.NewKeyedPRNG(seed)
	if err != nil {
		t.Fatalf("new keyed PRNG: %v", err)
	}
	B, err := GenerateBWithX0Len(ringQ, prng, 1)
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}
	if len(B) != 4 {
		t.Fatalf("B length=%d want 4", len(B))
	}
	expectedPRNG, err := utils.NewKeyedPRNG(seed)
	if err != nil {
		t.Fatalf("new expected keyed PRNG: %v", err)
	}
	uniform := ring.NewUniformSampler(expectedPRNG, ringQ)
	for i := range B {
		expected := ringQ.NewPoly()
		uniform.Read(expected)
		for j, coefficient := range B[i].Coeffs[0] {
			if coefficient >= ringQ.Modulus[0] {
				t.Fatalf("B[%d][%d]=%d is not canonical", i, j, coefficient)
			}
			if coefficient != expected.Coeffs[0][j] {
				t.Fatalf("B[%d][%d]=%d want independent uniform draw %d", i, j, coefficient, expected.Coeffs[0][j])
			}
		}
	}
	// This deterministic vector catches a regression that fixes B0 to zero;
	// zero itself remains a valid outcome of uniform sampling.
	for _, coeff := range B[0].Coeffs[0] {
		if coeff != 0 {
			return
		}
	}
	t.Fatal("B0 was left as the zero polynomial")
}

func TestGenerateBWithX0LenRejectsMissingInputs(t *testing.T) {
	if _, err := GenerateBWithX0Len(nil, nil, 1); err == nil {
		t.Fatal("nil ring accepted")
	}
	ringQ, err := ring.NewRing(16, []uint64{97})
	if err != nil {
		t.Fatalf("new ring: %v", err)
	}
	if _, err := GenerateBWithX0Len(ringQ, nil, 1); err == nil {
		t.Fatal("nil PRNG accepted")
	}
}
