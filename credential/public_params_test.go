package credential

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"vSIS-Signature/commitment"
)

func chdirForCredentialTest(t *testing.T) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir %s: %v", root, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

func TestPublicParamsRoundTripAndLift(t *testing.T) {
	chdirForCredentialTest(t)
	ringQ, err := LoadRingWithDegree(512)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	public := testPublicParamsV2(t, IntGenISISPresetN512Compact96)
	path := filepath.Join(t.TempDir(), "credential_public.json")
	if err := SavePublicParams(path, public); err != nil {
		t.Fatalf("save public params: %v", err)
	}
	loaded, err := LoadPublicParams(path)
	if err != nil {
		t.Fatalf("load public params: %v", err)
	}
	if loaded.BoundB != public.BoundB || loaded.BPath != public.BPath || loaded.X0Len != public.X0Len || loaded.TargetDim != public.TargetDim || loaded.PresetManifestDigest != public.PresetManifestDigest || loaded.RateLimitPolicy != IntGenISISRateLimitPolicyV2() {
		t.Fatalf("loaded public params mismatch: got %+v want %+v", loaded, public)
	}
	params, err := loaded.ToIssuanceParams(ringQ)
	if err != nil {
		t.Fatalf("lift public params: %v", err)
	}
	if len(params.CM) != len(public.CM) || len(params.AS) != len(public.AS) {
		t.Fatalf("lifted commitment matrices dims=%d/%d want %d/%d", len(params.CM), len(params.AS), len(public.CM), len(public.AS))
	}
}

func testPublicParamsV2(t testing.TB, presetName string) PublicParams {
	t.Helper()
	preset, err := MustLookupIntGenISISPreset(presetName)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := LookupIntGenISISProfile(preset.Profile)
	if !ok {
		t.Fatalf("missing profile %q", preset.Profile)
	}
	matrix := func(rows, cols int) commitment.CoeffMatrix {
		out := make(commitment.CoeffMatrix, rows)
		for i := range out {
			out[i] = make([][]uint64, cols)
			for j := range out[i] {
				out[i][j] = make([]uint64, profile.N)
			}
		}
		return out
	}
	public := PublicParams{
		Version:              PublicParamsVersion,
		Profile:              profile.Name,
		Modulus:              profile.Q,
		HashRelation:         HashRelationBBTran,
		BPath:                filepath.Join("internal", "source_data", "Bmatrix."+profile.Name+".json"),
		BoundB:               profile.B,
		CommitmentBound:      profile.B,
		EllM:                 profile.EllM,
		KS:                   profile.KS,
		NC:                   profile.NC,
		EllMuSig:             profile.EllMuSig,
		EllX0:                profile.EllX0,
		EllX1:                profile.EllX1,
		HashInputBound:       profile.HashInputBound,
		SignaturePreimageLen: profile.SignaturePreimageLen,
		MLWEHidingBits:       profile.MLWEHidingBits,
		MSISBindingBits:      profile.MSISBindingBits,
		CommitmentSecurity:   profile.CommitmentSecurity.ClonePtr(),
		X0Len:                profile.EllX0,
		TargetDim:            profile.NC,
		RingDegree:           profile.N,
		CM:                   matrix(profile.NC, profile.EllM),
		AS:                   matrix(profile.NC, profile.KS),
	}
	if err := public.BindIntGenISISPreset(preset); err != nil {
		t.Fatal(err)
	}
	return public
}

func TestGenerateUniformCoeffMatrixNotIdentityLike(t *testing.T) {
	chdirForCredentialTest(t)
	ringQ, err := LoadRingWithDegree(0)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	ac, err := commitment.GenerateUniformCoeffMatrix(ringQ, 3, 3)
	if err != nil {
		t.Fatalf("generate coeff matrix: %v", err)
	}
	identityLike := true
	for i := range ac {
		for j := range ac[i] {
			for k, coeff := range ac[i][j] {
				want := uint64(0)
				if i == j && k == 0 {
					want = 1
				}
				if coeff != want {
					identityLike = false
					break
				}
			}
			if !identityLike {
				break
			}
		}
		if !identityLike {
			break
		}
	}
	if identityLike {
		t.Fatal("generated Ac matched the old identity-like fixture matrix")
	}
}

func TestRepositoryPublicParamsFixturesAreSchemaV8(t *testing.T) {
	chdirForCredentialTest(t)
	for _, tc := range []struct {
		path    string
		profile string
		preset  string
	}{
		{DefaultPublicParamsPath, ProfileIntGenISISB, IntGenISISPresetPoCN512SC96V2},
		{"internal/source_data/credential_public.intgenisis_profile_c.json", ProfileIntGenISISC, IntGenISISPresetArtifactN1024SC125V2},
	} {
		params, err := LoadPublicParams(tc.path)
		if err != nil {
			t.Fatalf("load %s: %v", tc.path, err)
		}
		if params.Version != PublicParamsVersion || params.Profile != tc.profile || params.PresetID != tc.preset || params.RateLimitPolicy != IntGenISISRateLimitPolicyV2() {
			t.Fatalf("fixture %s has inconsistent v2 identity", tc.path)
		}
	}
}
