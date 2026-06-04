package credential

import (
	"math"
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
	if !closeFloat(profile.MLWEHidingBits, 203.816) || !closeFloat(profile.MSISBindingBits, 586.336) {
		t.Fatalf("profile B commitment security hiding/binding=%.3f/%.3f", profile.MLWEHidingBits, profile.MSISBindingBits)
	}
	if profile.CommitmentSecurity.StatisticalHidingSatisfied {
		t.Fatal("profile B must not claim statistical hiding")
	}
	ternary1024 := Ternary1024IntGenISISProfile()
	if ternary1024.N != 1024 || ternary1024.B != 1 || ternary1024.KS != 1 || ternary1024.EllX0 != 1 {
		t.Fatalf("profile C tuple N/B/KS/ell_x0=%d/%d/%d/%d want 1024/1/1/1", ternary1024.N, ternary1024.B, ternary1024.KS, ternary1024.EllX0)
	}
	if ternary1024.Q != IntGenISISSharedModulusQ {
		t.Fatalf("profile C q=%d want %d", ternary1024.Q, IntGenISISSharedModulusQ)
	}
	if !closeFloat(ternary1024.MLWEHidingBits, 131.113) || ternary1024.MSISBindingBits != 0 {
		t.Fatalf("profile C commitment security hiding/binding=%.3f/%.3f", ternary1024.MLWEHidingBits, ternary1024.MSISBindingBits)
	}
	if !ternary1024.CommitmentSecurity.MSISBindingInfinite || ternary1024.CommitmentSecurity.StatisticalHidingSatisfied {
		t.Fatalf("profile C commitment security metadata mismatch: %+v", ternary1024.CommitmentSecurity)
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
		BPath:                filepath.Join("internal", "source_data", "Bmatrix.intgenisis_profile_b.json"),
		BoundB:               IntGenISISLiveBound,
		CommitmentBound:      IntGenISISLiveBound,
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
	if !closeFloat(public.MLWEHidingBits, profile.MLWEHidingBits) || !closeFloat(public.MSISBindingBits, profile.MSISBindingBits) || public.CommitmentSecurity == nil {
		t.Fatalf("public params security not normalized from profile: %+v", public)
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
	if targetParams.EllM != 1 || targetParams.KS != 2 || targetParams.NC != 1 || targetParams.Bound != IntGenISISLiveBound {
		t.Fatalf("unexpected target params: %+v", targetParams)
	}
}

func closeFloat(got, want float64) bool {
	return math.Abs(got-want) < 0.0005
}
