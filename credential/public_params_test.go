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
	ringQ, err := LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	ac, err := commitment.GenerateUniformCoeffMatrix(ringQ, 2, 3)
	if err != nil {
		t.Fatalf("generate coeff matrix: %v", err)
	}
	public := PublicParams{
		Version:            PublicParamsVersion,
		Ac:                 ac,
		MuLayout:           MuLayoutFullCapacityHalvesV1,
		HashRelation:       HashRelationBBTran,
		BPath:              filepath.Join("Parameters", "Bmatrix.json"),
		BoundB:             1,
		X0Len:              1,
		X0CoeffBound:       1,
		TargetDim:          DefaultTargetDim,
		TargetHidingLambda: DefaultTargetHidingLambda,
		X0Distribution:     X0DistributionUniformInterval,
		LenMu:              1,
		LenR0H:             1,
		LenR1H:             1,
		LenRBar:            1,
	}
	path := filepath.Join(t.TempDir(), "credential_public.json")
	if err := SavePublicParams(path, public); err != nil {
		t.Fatalf("save public params: %v", err)
	}
	loaded, err := LoadPublicParams(path)
	if err != nil {
		t.Fatalf("load public params: %v", err)
	}
	if loaded.BoundB != public.BoundB || loaded.MuLayout != public.MuLayout || loaded.LenMu != public.LenMu || loaded.LenR0H != public.LenR0H || loaded.LenR1H != public.LenR1H || loaded.LenRBar != public.LenRBar || loaded.BPath != public.BPath || loaded.X0Len != public.X0Len || loaded.X0CoeffBound != public.X0CoeffBound || loaded.TargetDim != public.TargetDim || loaded.TargetHidingLambda != public.TargetHidingLambda {
		t.Fatalf("loaded public params mismatch: got %+v want %+v", loaded, public)
	}
	params, err := loaded.ToIssuanceParams(ringQ)
	if err != nil {
		t.Fatalf("lift public params: %v", err)
	}
	if len(params.Ac) != len(ac) || len(params.Ac[0]) != len(ac[0]) {
		t.Fatalf("lifted Ac dims=%dx%d want %dx%d", len(params.Ac), len(params.Ac[0]), len(ac), len(ac[0]))
	}
}

func TestGenerateUniformCoeffMatrixNotIdentityLike(t *testing.T) {
	chdirForCredentialTest(t)
	ringQ, err := LoadDefaultRing()
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
