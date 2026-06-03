package credential

import (
	"testing"

	vsishash "vSIS-Signature/internal/hash"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func TestComputeTargetVectorAndVerify(t *testing.T) {
	chdirForCredentialTest(t)
	ringQ, err := LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		t.Fatalf("new prng: %v", err)
	}
	B, err := vsishash.GenerateBWithX0Len(ringQ, prng, 6)
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}
	m := ringQ.NewPoly()
	k := ringQ.NewPoly()
	m.Coeffs[0][0] = 1
	k.Coeffs[0][1] = 1
	r0 := make([]*ring.Poly, 6)
	for i := range r0 {
		r0[i] = ringQ.NewPoly()
		r0[i].Coeffs[0][i] = uint64(i + 1)
	}
	r1 := ringQ.NewPoly()
	z, tCoeffs, err := ComputeTargetVector(ringQ, B, m, k, r0, r1)
	if err != nil {
		t.Fatalf("compute target vector: %v", err)
	}
	tPoly := polyFromCenteredInt64(ringQ, tCoeffs)
	if err := VerifyTargetRelationVector(ringQ, B, m, k, r0, r1, z, tPoly); err != nil {
		t.Fatalf("verify target relation: %v", err)
	}
}

func TestComputeTargetVectorRejectsInadmissibleDenominator(t *testing.T) {
	chdirForCredentialTest(t)
	ringQ, err := LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		t.Fatalf("new prng: %v", err)
	}
	B, err := vsishash.GenerateBWithX0Len(ringQ, prng, 5)
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}
	r1 := ringQ.NewPoly()
	ring.Copy(B[len(B)-1], r1)
	ringQ.InvNTT(r1, r1)
	r0 := make([]*ring.Poly, 5)
	for i := range r0 {
		r0[i] = ringQ.NewPoly()
	}
	_, _, err = ComputeTargetVector(ringQ, B, ringQ.NewPoly(), ringQ.NewPoly(), r0, r1)
	if err == nil {
		t.Fatal("expected inadmissible denominator error")
	}
}
