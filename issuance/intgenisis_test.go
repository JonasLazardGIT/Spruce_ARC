package issuance

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	vsishash "vSIS-Signature/internal/hash"

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
		Modulus:              profile.Q,
		HashRelation:         credential.HashRelationBBTran,
		BPath:                "internal/source_data/Bmatrix.intgenisis_profile_b.json",
		BoundB:               credential.IntGenISISLiveBound,
		CommitmentBound:      credential.IntGenISISLiveBound,
		HashInputBound:       credential.IntGenISISHashInputBound,
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
		X0Len:                profile.EllX0,
		TargetDim:            profile.NC,
		MLWEHidingBits:       profile.MLWEHidingBits,
		MSISBindingBits:      profile.MSISBindingBits,
		CommitmentSecurity:   &profile.CommitmentSecurity,
	}
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN512Compact96)
	if err != nil {
		t.Fatalf("lookup preset: %v", err)
	}
	if err := public.BindIntGenISISPreset(preset); err != nil {
		t.Fatalf("bind preset: %v", err)
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
	assertB4Randomness(t, ringQ, params.CommitmentBound, append(s, e...))
	inputs := IntGenISISInputs{M: M, S: s, E: e}
	c, err := PrepareIntGenISISCommit(params, inputs)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	recomputed, err := PrepareIntGenISISCommit(params, inputs)
	if err != nil {
		t.Fatalf("recompute commitment: %v", err)
	}
	if !equalPolyVec(c, recomputed) {
		t.Fatal("commitment recompute mismatch")
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		t.Fatalf("prng: %v", err)
	}
	B, err := vsishash.GenerateBWithX0Len(ringQ, prng, params.EllX0)
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}
	assertNonzeroPoly(t, B[0], "B0")
	for i := range B {
		ringQ.NTT(B[i], B[i])
	}
	data, err := SampleSignatureHashData(ringQ, B, params.EllMuSig, params.EllX0, rng)
	if err != nil {
		t.Fatalf("sample signature hash data: %v", err)
	}
	assertTernaryPolys(t, ringQ, append(append(append([]*ring.Poly{}, data.MuSig...), data.X0...), data.X1...))
	target, err := ComputeIntGenISISTarget(ringQ, B, c, data)
	if err != nil {
		t.Fatalf("compute target: %v", err)
	}
	if len(target.ZCoeff) != 1 || len(target.TNTT) != 1 || len(target.TCoeff) != int(ringQ.N) {
		t.Fatalf("unexpected target shape z=%d tNTT=%d tCoeff=%d", len(target.ZCoeff), len(target.TNTT), len(target.TCoeff))
	}
	recomputedTarget, err := ComputeIntGenISISTarget(ringQ, B, c, data)
	if err != nil {
		t.Fatalf("recompute target: %v", err)
	}
	if !equalInt64Slices(target.TCoeff, recomputedTarget.TCoeff) {
		t.Fatal("target recompute mismatch")
	}
}

func TestSampleSignatureHashDataPropagatesEntropyFailure(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{97})
	if err != nil {
		t.Fatalf("new ring: %v", err)
	}
	B := make([]*ring.Poly, 4)
	for i := range B {
		B[i] = ringQ.NewPoly()
	}
	B[3].Coeffs[0][0] = 20
	for i := range B {
		ringQ.NTT(B[i], B[i])
	}
	data, err := SampleSignatureHashData(ringQ, B, 1, 1, rand.New(rand.NewSource(23)))
	if err != nil {
		t.Fatalf("sample signature hash data: %v", err)
	}
	assertTernaryPolys(t, ringQ, append(append(append([]*ring.Poly{}, data.MuSig...), data.X0...), data.X1...))
	if _, err := SampleSignatureHashData(ringQ, B, 1, 1, bytes.NewReader(nil)); err == nil {
		t.Fatal("empty entropy reader accepted")
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
	modified, err := ComputeIntGenISISTarget(ringQ, B, c, data)
	if err != nil {
		t.Fatalf("compute modified target: %v", err)
	}
	if equalInt64Slices(target.TCoeff, modified.TCoeff) {
		t.Fatal("modified commitment accepted for target")
	}
}

func TestComputeIntGenISISTargetRejectsOutOfDomainSources(t *testing.T) {
	for _, source := range []string{"mu_sig", "x0", "x1"} {
		t.Run(source, func(t *testing.T) {
			ringQ, B, com, data := smallBoundedBBTranFixture(t)
			switch source {
			case "mu_sig":
				data.MuSig[0].Coeffs[0][0] = 2
			case "x0":
				data.X0[0].Coeffs[0][0] = 2
			case "x1":
				data.X1[0].Coeffs[0][0] = 2
			}
			if _, err := ComputeIntGenISISTarget(ringQ, B, com, data); err == nil || !strings.Contains(err.Error(), "outside canonical ternary domain") {
				t.Fatalf("out-of-domain %s accepted: %v", source, err)
			}
		})
	}
}

func TestComputeIntGenISISTargetRejectsNoncanonicalSource(t *testing.T) {
	ringQ, B, com, data := smallBoundedBBTranFixture(t)
	data.MuSig[0].Coeffs[0][0] = ringQ.Modulus[0] + 1
	if _, err := ComputeIntGenISISTarget(ringQ, B, com, data); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("noncanonical source accepted: %v", err)
	}
}

func TestComputeIntGenISISTargetRejectsNoninvertibleX1(t *testing.T) {
	ringQ, B, com, data := smallBoundedBBTranFixture(t)
	b3 := ringQ.NewPoly()
	b3.Coeffs[0][0] = 1
	ringQ.NTT(b3, b3)
	B[len(B)-1] = b3
	data.X1[0].Coeffs[0][0] = 1
	if _, err := ComputeIntGenISISTarget(ringQ, B, com, data); err == nil || !strings.Contains(err.Error(), "denominator not invertible") {
		t.Fatalf("noninvertible B3-x1 accepted: %v", err)
	}
}

func TestVerifyIntGenISISTargetRelationChecksInverseB0AndCompleteEquation(t *testing.T) {
	ringQ, B, com, data := smallBoundedBBTranFixture(t)
	target, err := ComputeIntGenISISTarget(ringQ, B, com, data)
	if err != nil {
		t.Fatalf("compute target: %v", err)
	}
	if err := VerifyIntGenISISTargetRelation(ringQ, B, com, data, target); err != nil {
		t.Fatalf("valid target relation rejected: %v", err)
	}

	tamperedZ := cloneIntGenISISTarget(ringQ, target)
	tamperedZ.ZCoeff[0].Coeffs[0][0] = (tamperedZ.ZCoeff[0].Coeffs[0][0] + 1) % ringQ.Modulus[0]
	if err := VerifyIntGenISISTargetRelation(ringQ, B, com, data, tamperedZ); err == nil || !strings.Contains(err.Error(), "inverse witness") {
		t.Fatalf("tampered inverse accepted: %v", err)
	}

	tamperedT := cloneIntGenISISTarget(ringQ, target)
	tamperedT.TNTT[0].Coeffs[0][0] = (tamperedT.TNTT[0].Coeffs[0][0] + 1) % ringQ.Modulus[0]
	if err := VerifyIntGenISISTargetRelation(ringQ, B, com, data, tamperedT); err == nil || !strings.Contains(err.Error(), "target equation") {
		t.Fatalf("tampered target accepted: %v", err)
	}

	changedB := clonePolyVec(ringQ, B)
	changedB[0].Coeffs[0][0] = (changedB[0].Coeffs[0][0] + 1) % ringQ.Modulus[0]
	if err := VerifyIntGenISISTargetRelation(ringQ, changedB, com, data, target); err == nil || !strings.Contains(err.Error(), "target equation") {
		t.Fatalf("target that omits changed B0 accepted: %v", err)
	}

	zeroB0 := clonePolyVec(ringQ, B)
	zeroB0[0] = ringQ.NewPoly()
	zeroTarget, err := ComputeIntGenISISTarget(ringQ, zeroB0, com, data)
	if err != nil {
		t.Fatalf("zero-valued uniform outcome for B0 rejected: %v", err)
	}
	if err := VerifyIntGenISISTargetRelation(ringQ, zeroB0, com, data, zeroTarget); err != nil {
		t.Fatalf("target relation imposed a nonzero B0 condition: %v", err)
	}
}

type zeroCountingReader struct {
	bytes int
}

func (r *zeroCountingReader) Read(out []byte) (int, error) {
	for i := range out {
		out[i] = 0
	}
	r.bytes += len(out)
	return len(out), nil
}

func TestSampleSignatureHashDataCapsX1RejectionAtExactly1024(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{97})
	if err != nil {
		t.Fatalf("new ring: %v", err)
	}
	B := make([]*ring.Poly, 4)
	for i := range B {
		B[i] = ringQ.NewPoly()
	}
	// A zero entropy byte samples -1. Make B3 equal that candidate in the
	// NTT domain so every one of the 1,024 attempts is noninvertible.
	for i := range B[3].Coeffs[0] {
		B[3].Coeffs[0][i] = ringQ.Modulus[0] - 1
	}
	ringQ.NTT(B[3], B[3])
	random := &zeroCountingReader{}
	_, err = SampleSignatureHashData(ringQ, B, 1, 1, random)
	if err == nil || !strings.Contains(err.Error(), "after 1024 attempts") {
		t.Fatalf("unexpected rejection exhaustion result: %v", err)
	}
	wantBytes := (1 + 1 + IntGenISISX1RejectionLimit) * ringQ.N
	if random.bytes != wantBytes {
		t.Fatalf("entropy bytes=%d want %d for exactly %d x1 attempts", random.bytes, wantBytes, IntGenISISX1RejectionLimit)
	}
}

func TestSampleSignatureHashDataPropagatesX1EntropyFailure(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{97})
	if err != nil {
		t.Fatalf("new ring: %v", err)
	}
	B := make([]*ring.Poly, 4)
	for i := range B {
		B[i] = ringQ.NewPoly()
	}
	B[3].Coeffs[0][0] = 2
	ringQ.NTT(B[3], B[3])
	// Exactly enough zero bytes for mu_sig and x0; the first x1 draw fails.
	_, err = SampleSignatureHashData(ringQ, B, 1, 1, bytes.NewReader(make([]byte, 2*ringQ.N)))
	if err == nil || !strings.Contains(err.Error(), "sample x1 candidate 1/1024") {
		t.Fatalf("x1 entropy failure was not propagated: %v", err)
	}
}

func smallBoundedBBTranFixture(t *testing.T) (*ring.Ring, []*ring.Poly, commitment.Vector, SignatureHashData) {
	t.Helper()
	ringQ, err := ring.NewRing(16, []uint64{97})
	if err != nil {
		t.Fatalf("new ring: %v", err)
	}
	B := make([]*ring.Poly, 4)
	for i := range B {
		B[i] = ringQ.NewPoly()
	}
	B[0].Coeffs[0][0] = 3
	B[0].Coeffs[0][1] = 7
	B[1].Coeffs[0][0] = 4
	B[2].Coeffs[0][0] = 5
	B[3].Coeffs[0][0] = 2
	for i := range B {
		ringQ.NTT(B[i], B[i])
	}
	commitmentPoly := ringQ.NewPoly()
	commitmentPoly.Coeffs[0][0] = 9
	ringQ.NTT(commitmentPoly, commitmentPoly)
	data := SignatureHashData{
		MuSig: []*ring.Poly{ringQ.NewPoly()},
		X0:    []*ring.Poly{ringQ.NewPoly()},
		X1:    []*ring.Poly{ringQ.NewPoly()},
	}
	return ringQ, B, commitment.Vector{commitmentPoly}, data
}

func cloneIntGenISISTarget(ringQ *ring.Ring, target IntGenISISTarget) IntGenISISTarget {
	return IntGenISISTarget{
		ZCoeff: clonePolyVec(ringQ, target.ZCoeff),
		TNTT:   clonePolyVec(ringQ, target.TNTT),
		TCoeff: append([]int64(nil), target.TCoeff...),
	}
}

func equalPolyVec(a, b []*ring.Poly) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalPoly(a[i], b[i]) {
			return false
		}
	}
	return true
}

func equalPoly(a, b *ring.Poly) bool {
	if a == nil || b == nil || len(a.Coeffs) != len(b.Coeffs) {
		return false
	}
	for level := range a.Coeffs {
		if len(a.Coeffs[level]) != len(b.Coeffs[level]) {
			return false
		}
		for i := range a.Coeffs[level] {
			if a.Coeffs[level][i] != b.Coeffs[level][i] {
				return false
			}
		}
	}
	return true
}

func equalInt64Slices(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

func assertB4Randomness(t *testing.T, ringQ *ring.Ring, bound int64, rows []*ring.Poly) {
	t.Helper()
	q := int64(ringQ.Modulus[0])
	sawNonTernary := false
	for i, row := range rows {
		for j, coeff := range row.Coeffs[0] {
			v := int64(coeff % ringQ.Modulus[0])
			if v > q/2 {
				v -= q
			}
			if v < -bound || v > bound {
				t.Fatalf("row %d coeff %d=%d outside [-%d,%d]", i, j, v, bound, bound)
			}
			if v < -1 || v > 1 {
				sawNonTernary = true
			}
		}
	}
	if bound == 4 && !sawNonTernary {
		t.Fatal("seeded B=4 randomness stayed ternary")
	}
}

func assertTernaryPolys(t *testing.T, ringQ *ring.Ring, rows []*ring.Poly) {
	t.Helper()
	q := ringQ.Modulus[0]
	for i, row := range rows {
		if row == nil {
			t.Fatalf("ternary row %d is nil", i)
		}
		for j, coeff := range row.Coeffs[0] {
			coeff %= q
			if coeff != 0 && coeff != 1 && coeff != q-1 {
				t.Fatalf("ternary row %d coeff %d=%d", i, j, coeff)
			}
		}
	}
}

func assertNonzeroPoly(t *testing.T, p *ring.Poly, name string) {
	t.Helper()
	if p == nil {
		t.Fatalf("%s is nil", name)
	}
	for _, coeff := range p.Coeffs[0] {
		if coeff != 0 {
			return
		}
	}
	t.Fatalf("%s was left as the zero polynomial", name)
}
