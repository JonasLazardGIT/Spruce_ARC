package credential

import (
	"path/filepath"
	"testing"

	"vSIS-Signature/commitment"
)

func TestIntGenISISPublicParamsProfileB(t *testing.T) {
	chdirForCredentialTest(t)
	profile := PrimaryIntGenISISProfile()
	ringQ, err := LoadRingWithDegree(profile.N)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	cm, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.EllM)
	if err != nil {
		t.Fatalf("generate C_M: %v", err)
	}
	as, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.KS)
	if err != nil {
		t.Fatalf("generate A_s: %v", err)
	}
	public := PublicParams{
		Version:              PublicParamsVersion,
		Profile:              profile.Name,
		HashRelation:         HashRelationBBTran,
		BPath:                filepath.Join("Parameters", "Bmatrix.intgenisis_profile_b.json"),
		BoundB:               profile.B,
		CommitmentBound:      profile.B,
		RingDegree:           profile.N,
		CM:                   cm,
		AS:                   as,
		EllM:                 profile.EllM,
		KS:                   profile.KS,
		NC:                   profile.NC,
		EllMuSig:             profile.EllMuSig,
		EllX0:                profile.EllX0,
		EllX1:                profile.EllX1,
		SignaturePreimageLen: profile.SignaturePreimageLen,
		TargetDim:            profile.NC,
	}
	if err := (&public).Validate(); err != nil {
		t.Fatalf("validate public params: %v", err)
	}
	if public.X0Len != profile.EllX0 {
		t.Fatalf("X0Len=%d want ell_x0=%d", public.X0Len, profile.EllX0)
	}
	params, err := public.ToIssuanceParams(ringQ)
	if err != nil {
		t.Fatalf("lift params: %v", err)
	}
	if params.LenR0H != 0 || params.LenR1H != 0 || params.LenRBar != 0 {
		t.Fatalf("IntGenISIS params retained old randomness lengths: %+v", params)
	}
	targetParams, err := public.ToCommitmentParams(ringQ)
	if err != nil {
		t.Fatalf("commitment params: %v", err)
	}
	if targetParams.EllM != 1 || targetParams.KS != 2 || targetParams.NC != 1 || targetParams.Bound != 8 {
		t.Fatalf("unexpected target params: %+v", targetParams)
	}
}
