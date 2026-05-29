package credential

import (
	"path/filepath"
	"testing"

	"vSIS-Signature/commitment"
)

func TestIntGenISISPublicParamsProfileB(t *testing.T) {
	chdirForCredentialTest(t)
	profile := PrimaryIntGenISISProfile()
	if profile.B != 4 {
		t.Fatalf("profile B bound=%d want 4", profile.B)
	}
	if profile.Q != IntGenISISSharedModulusQ {
		t.Fatalf("profile B q=%d want %d", profile.Q, IntGenISISSharedModulusQ)
	}
	ternary1024 := Ternary1024IntGenISISProfile()
	if ternary1024.N != 1024 || ternary1024.B != 1 || ternary1024.KS != 1 || ternary1024.EllX0 != 1 {
		t.Fatalf("profile C tuple N/B/KS/ell_x0=%d/%d/%d/%d want 1024/1/1/1", ternary1024.N, ternary1024.B, ternary1024.KS, ternary1024.EllX0)
	}
	if ternary1024.Q != IntGenISISSharedModulusQ {
		t.Fatalf("profile C q=%d want %d", ternary1024.Q, IntGenISISSharedModulusQ)
	}
	if got, ok := LookupIntGenISISProfileByRingDegree(1024); !ok || got.Name != ProfileIntGenISISC {
		t.Fatalf("ring-degree lookup 1024=(%q,%v), want %q", got.Name, ok, ProfileIntGenISISC)
	}
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
	if targetParams.EllM != 1 || targetParams.KS != 2 || targetParams.NC != 1 || targetParams.Bound != 4 {
		t.Fatalf("unexpected target params: %+v", targetParams)
	}
}
