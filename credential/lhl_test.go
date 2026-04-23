package credential

import "testing"

func TestBuildLHLReportProfiles(t *testing.T) {
	chdirForCredentialTest(t)
	ringQ, err := LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}

	makeParams := func(x0Len int, x0Bound int64) *Params {
		return &Params{
			RingQ:              ringQ,
			X0Len:              x0Len,
			X0CoeffBound:       x0Bound,
			TargetDim:          DefaultTargetDim,
			TargetHidingLambda: DefaultTargetHidingLambda,
			X0Distribution:     X0DistributionUniformInterval,
		}
	}

	legacy, err := BuildLHLReport(makeParams(1, 1))
	if err != nil {
		t.Fatalf("legacy report: %v", err)
	}
	if legacy.SatisfiesLHL {
		t.Fatalf("legacy scalar profile unexpectedly satisfied LHL: %+v", legacy)
	}

	def, err := BuildLHLReport(makeParams(6, 5))
	if err != nil {
		t.Fatalf("default report: %v", err)
	}
	if !def.SatisfiesLHL || def.SlackBits <= 0 {
		t.Fatalf("default profile should satisfy LHL with positive slack: %+v", def)
	}

	alt, err := BuildLHLReport(makeParams(5, 8))
	if err != nil {
		t.Fatalf("alt report: %v", err)
	}
	if !alt.SatisfiesLHL || alt.SlackBits <= 0 {
		t.Fatalf("alt profile should satisfy LHL with positive slack: %+v", alt)
	}
}
