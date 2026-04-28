package issuance

import (
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func testIntGenISISParams(t *testing.T) (*ring.Ring, *credential.Params) {
	t.Helper()
	chdirForIssuancePackageTest(t)
	profile := credential.PrimaryIntGenISISProfile()
	ringQ, err := credential.LoadRingWithDegree(profile.N)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	cm, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.EllM)
	if err != nil {
		t.Fatalf("C_M: %v", err)
	}
	as, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.KS)
	if err != nil {
		t.Fatalf("A_s: %v", err)
	}
	public := credential.PublicParams{
		Version:              credential.PublicParamsVersion,
		Profile:              profile.Name,
		HashRelation:         credential.HashRelationBBTran,
		BPath:                "Parameters/Bmatrix.intgenisis_profile_b.json",
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
	params, err := public.ToIssuanceParams(ringQ)
	if err != nil {
		t.Fatalf("issuance params: %v", err)
	}
	return ringQ, params
}

func chdirForIssuancePackageTest(t *testing.T) {
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

func TestIntGenISISIssuanceCommitAndTarget(t *testing.T) {
	ringQ, params := testIntGenISISParams(t)
	rng := rand.New(rand.NewSource(21))
	M := []*ring.Poly{boundedTestPoly(ringQ, params.CommitmentBound, rng)}
	s, e, err := SampleIntGenISISCommitmentRandomness(params, rng)
	if err != nil {
		t.Fatalf("sample s/e: %v", err)
	}
	inputs := IntGenISISInputs{M: M, S: s, E: e}
	c, err := PrepareIntGenISISCommit(params, inputs)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := VerifyIntGenISISCommit(params, c, inputs); err != nil {
		t.Fatalf("verify commitment: %v", err)
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		t.Fatalf("prng: %v", err)
	}
	B, err := vsishash.GenerateBWithX0Len(ringQ, prng, params.EllX0)
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}
	for i := range B {
		ringQ.NTT(B[i], B[i])
	}
	data, err := SampleSignatureHashData(ringQ, B, params.EllMuSig, params.EllX0, rng)
	if err != nil {
		t.Fatalf("sample signature hash data: %v", err)
	}
	target, err := ComputeIntGenISISTarget(ringQ, B, c, data)
	if err != nil {
		t.Fatalf("compute target: %v", err)
	}
	if len(target.ZCoeff) != 1 || len(target.TNTT) != 1 || len(target.TCoeff) != int(ringQ.N) {
		t.Fatalf("unexpected target shape z=%d tNTT=%d tCoeff=%d", len(target.ZCoeff), len(target.TNTT), len(target.TCoeff))
	}
	if err := VerifyIntGenISISTarget(ringQ, B, c, data, target.TCoeff); err != nil {
		t.Fatalf("verify target: %v", err)
	}
}

func TestIntGenISISTargetRejectsModifiedCommitment(t *testing.T) {
	ringQ, params := testIntGenISISParams(t)
	rng := rand.New(rand.NewSource(22))
	M := []*ring.Poly{boundedTestPoly(ringQ, params.CommitmentBound, rng)}
	s, e, err := SampleIntGenISISCommitmentRandomness(params, rng)
	if err != nil {
		t.Fatalf("sample s/e: %v", err)
	}
	c, err := PrepareIntGenISISCommit(params, IntGenISISInputs{M: M, S: s, E: e})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		t.Fatalf("prng: %v", err)
	}
	B, err := vsishash.GenerateBWithX0Len(ringQ, prng, params.EllX0)
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}
	for i := range B {
		ringQ.NTT(B[i], B[i])
	}
	data, err := SampleSignatureHashData(ringQ, B, params.EllMuSig, params.EllX0, rng)
	if err != nil {
		t.Fatalf("sample signature hash data: %v", err)
	}
	target, err := ComputeIntGenISISTarget(ringQ, B, c, data)
	if err != nil {
		t.Fatalf("compute target: %v", err)
	}
	c[0].Coeffs[0][0] = (c[0].Coeffs[0][0] + 1) % ringQ.Modulus[0]
	if err := VerifyIntGenISISTarget(ringQ, B, c, data, target.TCoeff); err == nil {
		t.Fatal("modified commitment accepted for target")
	}
}

func boundedTestPoly(ringQ *ring.Ring, bound int64, rng *rand.Rand) *ring.Poly {
	p := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	width := 2*bound + 1
	for i := 0; i < ringQ.N; i++ {
		v := rng.Int63n(width) - bound
		if v < 0 {
			p.Coeffs[0][i] = uint64(v + q)
		} else {
			p.Coeffs[0][i] = uint64(v)
		}
	}
	return p
}
