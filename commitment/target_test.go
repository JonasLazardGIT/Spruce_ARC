package commitment

import (
	"math/rand"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func testTargetParams(t *testing.T) TargetParams {
	t.Helper()
	ringQ, err := ring.NewRing(512, []uint64{1054721})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	cmCoeff, err := GenerateUniformCoeffMatrix(ringQ, 1, 1)
	if err != nil {
		t.Fatalf("C_M: %v", err)
	}
	asCoeff, err := GenerateUniformCoeffMatrix(ringQ, 1, 2)
	if err != nil {
		t.Fatalf("A_s: %v", err)
	}
	cm, err := MatrixFromCoeff(ringQ, cmCoeff)
	if err != nil {
		t.Fatalf("lift C_M: %v", err)
	}
	as, err := MatrixFromCoeff(ringQ, asCoeff)
	if err != nil {
		t.Fatalf("lift A_s: %v", err)
	}
	return TargetParams{
		RingQ: ringQ,
		CM:    cm,
		AS:    as,
		EllM:  1,
		KS:    2,
		NC:    1,
		Bound: 8,
	}
}

func TestTargetCommitmentOpeningRoundTrip(t *testing.T) {
	params := testTargetParams(t)
	rng := rand.New(rand.NewSource(7))
	M := []*ring.Poly{sampleBoundedCoeffPoly(params.RingQ, params.Bound, rng)}
	s, e, err := SampleCommitmentRandomness(params, rng)
	if err != nil {
		t.Fatalf("sample randomness: %v", err)
	}
	c, err := CommitMessage(params, M, s, e)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := VerifyCommitmentOpening(params, c, TargetOpening{M: M, S: s, E: e}); err != nil {
		t.Fatalf("verify opening: %v", err)
	}
}

func TestTargetCommitmentRejectsModifiedOpening(t *testing.T) {
	params := testTargetParams(t)
	rng := rand.New(rand.NewSource(11))
	M := []*ring.Poly{sampleBoundedCoeffPoly(params.RingQ, params.Bound, rng)}
	s, e, err := SampleCommitmentRandomness(params, rng)
	if err != nil {
		t.Fatalf("sample randomness: %v", err)
	}
	c, err := CommitMessage(params, M, s, e)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	Mbad := []*ring.Poly{params.RingQ.NewPoly()}
	ring.Copy(M[0], Mbad[0])
	Mbad[0].Coeffs[0][0] = (Mbad[0].Coeffs[0][0] + 1) % params.RingQ.Modulus[0]
	if err := VerifyCommitmentOpening(params, c, TargetOpening{M: Mbad, S: s, E: e}); err == nil {
		t.Fatal("modified M opening accepted")
	}
}

func TestTargetCommitmentRejectsOutOfBoundOpening(t *testing.T) {
	params := testTargetParams(t)
	rng := rand.New(rand.NewSource(13))
	M := []*ring.Poly{sampleBoundedCoeffPoly(params.RingQ, params.Bound, rng)}
	s, e, err := SampleCommitmentRandomness(params, rng)
	if err != nil {
		t.Fatalf("sample randomness: %v", err)
	}
	c, err := CommitMessage(params, M, s, e)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	s[0].Coeffs[0][0] = uint64(params.Bound + 1)
	if err := VerifyCommitmentOpening(params, c, TargetOpening{M: M, S: s, E: e}); err == nil {
		t.Fatal("out-of-bound s opening accepted")
	}
}
