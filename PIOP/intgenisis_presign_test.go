package PIOP

import (
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestIntGenISISPreSignProofBuildsAndVerifies(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	profile := credential.PrimaryIntGenISISProfile()
	ringQ, err := credential.LoadRingWithDegree(profile.N)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	cmCoeff, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.EllM)
	if err != nil {
		t.Fatalf("C_M: %v", err)
	}
	asCoeff, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.KS)
	if err != nil {
		t.Fatalf("A_s: %v", err)
	}
	cm, err := commitment.MatrixFromCoeff(ringQ, cmCoeff)
	if err != nil {
		t.Fatalf("lift C_M: %v", err)
	}
	as, err := commitment.MatrixFromCoeff(ringQ, asCoeff)
	if err != nil {
		t.Fatalf("lift A_s: %v", err)
	}
	targetParams := commitment.TargetParams{
		RingQ: ringQ,
		CM:    cm,
		AS:    as,
		EllM:  profile.EllM,
		KS:    profile.KS,
		NC:    profile.NC,
		Bound: profile.B,
	}
	rng := rand.New(rand.NewSource(31))
	M := []*ring.Poly{boundedPIOPPoly(ringQ, profile.B, rng)}
	s, e, err := commitment.SampleCommitmentRandomness(targetParams, rng)
	if err != nil {
		t.Fatalf("sample opening: %v", err)
	}
	c, err := commitment.CommitMessage(targetParams, M, s, e)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	pub := PublicInputs{
		Com:          c,
		CM:           cm,
		AS:           as,
		BoundB:       profile.B,
		X0Len:        profile.EllX0,
		RingDegree:   profile.N,
		HashRelation: credential.HashRelationBBTran,
		IntGenISIS:   true,
	}
	wit := WitnessInputs{M: M, S: s, E: e}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential: true,
		RingDegree: profile.N,
		NCols:      16,
		LVCSNCols:  32,
		Ell:        4,
		Eta:        8,
		Rho:        1,
		Theta:      1,
		DomainMode: DomainModeExplicit,
		NLeaves:    4096,
	})
	proof, err := BuildIntGenISISPreSign(ringQ, pub, wit, opts)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	if proof.RowLayout.SigCount != 4 {
		t.Fatalf("witness row count=%d want 4", proof.RowLayout.SigCount)
	}
	if proof.MaskRowOffset != 4 {
		t.Fatalf("mask offset=%d want 4", proof.MaskRowOffset)
	}
	if string(proof.LabelsDigest) != string(computeLabelsDigest(BuildPublicLabels(pub))) {
		t.Fatal("proof labels do not bind IntGenISIS public statement")
	}
	ok, err := VerifyIntGenISISPreSign(pub, proof, opts)
	if err != nil || !ok {
		t.Fatalf("verify proof: ok=%v err=%v", ok, err)
	}
	tampered := pub
	tampered.Com = clonePolySliceForIntGenISISTest(ringQ, pub.Com)
	tampered.Com[0].Coeffs[0][0] ^= 1
	ok, err = VerifyIntGenISISPreSign(tampered, proof, opts)
	if err == nil && ok {
		t.Fatal("tampered commitment verified")
	}
	tampered = pub
	tampered.CM = clonePolyMatrixForIntGenISISTest(ringQ, pub.CM)
	tampered.CM[0][0].Coeffs[0][0] ^= 1
	ok, err = VerifyIntGenISISPreSign(tampered, proof, opts)
	if err == nil && ok {
		t.Fatal("tampered C_M verified")
	}
	tampered = pub
	tampered.AS = clonePolyMatrixForIntGenISISTest(ringQ, pub.AS)
	tampered.AS[0][0].Coeffs[0][0] ^= 1
	ok, err = VerifyIntGenISISPreSign(tampered, proof, opts)
	if err == nil && ok {
		t.Fatal("tampered A_s verified")
	}
	badLayout := *proof
	if proof.RowLayout.IntGenISISPreSign == nil {
		t.Fatal("missing IntGenISIS pre-sign layout")
	}
	layout := *proof.RowLayout.IntGenISISPreSign
	layout.SCount++
	badLayout.RowLayout.IntGenISISPreSign = &layout
	ok, err = VerifyIntGenISISPreSign(pub, &badLayout, opts)
	if err == nil && ok {
		t.Fatal("tampered row layout verified")
	}
	badProof := *proof
	badProof.Root[0] ^= 1
	ok, err = VerifyIntGenISISPreSign(pub, &badProof, opts)
	if err == nil && ok {
		t.Fatal("tampered proof root verified")
	}
}

func chdirForPIOPIntGenISISTest(t *testing.T) {
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

func boundedPIOPPoly(ringQ *ring.Ring, bound int64, rng *rand.Rand) *ring.Poly {
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

func clonePolySliceForIntGenISISTest(ringQ *ring.Ring, in []*ring.Poly) []*ring.Poly {
	out := make([]*ring.Poly, len(in))
	for i := range in {
		out[i] = ringQ.NewPoly()
		ring.Copy(in[i], out[i])
	}
	return out
}

func clonePolyMatrixForIntGenISISTest(ringQ *ring.Ring, in [][]*ring.Poly) [][]*ring.Poly {
	out := make([][]*ring.Poly, len(in))
	for i := range in {
		out[i] = clonePolySliceForIntGenISISTest(ringQ, in[i])
	}
	return out
}

func truncatePIOPPolysForTest(width int, polys ...*ring.Poly) {
	for _, p := range polys {
		if p == nil || len(p.Coeffs) == 0 {
			continue
		}
		for i := width; i < len(p.Coeffs[0]); i++ {
			p.Coeffs[0][i] = 0
		}
	}
}
