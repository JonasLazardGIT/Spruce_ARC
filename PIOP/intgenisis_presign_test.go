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
	semanticLayout, err := credential.DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		t.Fatalf("semantic layout: %v", err)
	}
	msg, err := credential.EncodeSemanticMessage(semanticLayout, credential.ZeroSemanticAttributes(semanticLayout), []int64{1, 0, -1, 1, 0, -1, 1, 0})
	if err != nil {
		t.Fatalf("encode semantic message: %v", err)
	}
	M := polysFromInt64ForIntGenISISTest(ringQ, msg.M)
	MAttr := polysFromInt64ForIntGenISISTest(ringQ, msg.MAttr)
	K := polysFromInt64ForIntGenISISTest(ringQ, msg.K)
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
	wit := WitnessInputs{M: M, MAttr: MAttr, K: K, S: s, E: e}
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
	if proof.RowLayout.IntGenISISPreSign == nil {
		t.Fatal("missing IntGenISIS pre-sign layout")
	}
	if proof.RowLayout.IntGenISISPreSign.CoreRowCount != 6 {
		t.Fatalf("core witness row count=%d want 6", proof.RowLayout.IntGenISISPreSign.CoreRowCount)
	}
	if proof.RowLayout.IntGenISISPreSign.BoundViewCount == 0 {
		t.Fatal("missing IntGenISIS coefficient-view bound rows")
	}
	if proof.MaskRowOffset != proof.RowLayout.SigCount {
		t.Fatalf("mask offset=%d want committed witness rows=%d", proof.MaskRowOffset, proof.RowLayout.SigCount)
	}
	if got, want := proof.MaskDegreeBound, computeDQFromConstraintDegrees(9, 1, opts.NCols, opts.Ell); got != want || proof.QDegreeBound != want {
		t.Fatalf("paper-conservative degree mismatch mask=%d q=%d want %d", got, proof.QDegreeBound, want)
	}
	pubWithExtras, err := bindIntGenISISPublicExtras(pub, profile.N)
	if err != nil {
		t.Fatalf("bind extras: %v", err)
	}
	if string(proof.LabelsDigest) != string(computeLabelsDigest(BuildPublicLabels(pubWithExtras))) {
		t.Fatal("proof labels do not bind IntGenISIS public statement")
	}
	ok, err := VerifyIntGenISISPreSign(pub, proof, opts)
	if err != nil || !ok {
		t.Fatalf("verify proof: ok=%v err=%v", ok, err)
	}
	if proof.QOpening == nil || proof.QRoot == ([16]byte{}) || len(proof.QRBits) == 0 {
		t.Fatal("legacy proof did not carry Q DECS material")
	}
	thetaOpts := opts
	thetaOpts.Theta = 7
	thetaOpts.Rho = 1
	thetaOpts.EllPrime = 1
	thetaOpts.TranscriptVersion = TranscriptVersionSmallWood2025
	thetaProof, err := BuildIntGenISISPreSign(ringQ, pub, wit, thetaOpts)
	if err != nil {
		t.Fatalf("build theta>1 proof: %v", err)
	}
	if thetaProof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV1 {
		t.Fatalf("theta>1 geometry kind=%q", thetaProof.PCSGeometry.Kind)
	}
	if thetaProof.PCSGeometry.SmallFieldSource != PCSGeometrySmallFieldSourceLiteralRows {
		t.Fatalf("theta>1 source=%q", thetaProof.PCSGeometry.SmallFieldSource)
	}
	if thetaProof.QRoot != ([16]byte{}) || len(thetaProof.QRBits) != 0 || thetaProof.QOpening != nil {
		t.Fatal("strict theta>1 proof carried redundant Q DECS material")
	}
	if len(thetaProof.QPayloadMatrix()) != thetaOpts.Rho*thetaOpts.Theta {
		t.Fatalf("theta>1 Q payload rows mismatch")
	}
	ok, err = VerifyIntGenISISPreSign(pub, thetaProof, thetaOpts)
	if err != nil || !ok {
		t.Fatalf("verify theta>1 proof: ok=%v err=%v", ok, err)
	}
	badQPayload := *thetaProof
	badQPayload.QPayload = copyMatrix(thetaProof.QPayloadMatrix())
	badQPayload.QPayloadBits = nil
	badQPayload.QPayload[0][0] = (badQPayload.QPayload[0][0] + 1) % ringQ.Modulus[0]
	ok, err = VerifyIntGenISISPreSign(pub, &badQPayload, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 proof verified with tampered Q payload")
	}
	missingQPayload := *thetaProof
	missingQPayload.QPayload = nil
	missingQPayload.QPayloadBits = nil
	ok, err = VerifyIntGenISISPreSign(pub, &missingQPayload, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 proof verified without Q payload")
	}
	badQRows := *thetaProof
	badQRows.QPayload = copyMatrix(thetaProof.QPayloadMatrix())
	badQRows.QPayloadBits = nil
	if len(badQRows.QPayload) > 1 {
		badQRows.QPayload = badQRows.QPayload[:len(badQRows.QPayload)-1]
	} else {
		badQRows.QPayload = append(badQRows.QPayload, append([]uint64(nil), badQRows.QPayload[0]...))
	}
	ok, err = VerifyIntGenISISPreSign(pub, &badQRows, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 proof verified with tampered Q payload row count")
	}
	badQDegree := *thetaProof
	badQDegree.QPayload = copyMatrix(thetaProof.QPayloadMatrix())
	badQDegree.QPayloadBits = nil
	overflowCoeff := thetaProof.QDegreeBound + 1
	for len(badQDegree.QPayload[0]) <= overflowCoeff {
		badQDegree.QPayload[0] = append(badQDegree.QPayload[0], 0)
	}
	badQDegree.QPayload[0][overflowCoeff] = 1
	ok, err = VerifyIntGenISISPreSign(pub, &badQDegree, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 proof verified with Q payload degree overflow")
	}
	redundantQ := *thetaProof
	redundantQ.QRoot[0] = 1
	ok, err = VerifyIntGenISISPreSign(pub, &redundantQ, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 proof verified with redundant strict QRoot")
	}
	wideOpts := opts
	wideOpts.NLeaves = 1600
	wideOpts.LVCSNCols = 68
	wideOpts.Ell = 22
	wideOpts.Eta = 30
	wideOpts.Rho = 3
	wideOpts.EllPrime = 3
	wideOpts.Theta = 2
	wideProof, err := BuildIntGenISISPreSign(ringQ, pub, wit, wideOpts)
	if err != nil {
		t.Fatalf("build wide LVCS pre-sign proof: %v", err)
	}
	if got, want := wideProof.NColsUsed, wideOpts.NCols; got != want {
		t.Fatalf("wide pre-sign witness ncols=%d want %d", got, want)
	}
	if got, want := wideProof.PCSNColsUsed, wideOpts.LVCSNCols; got != want {
		t.Fatalf("wide pre-sign pcs ncols=%d want %d", got, want)
	}
	if got, want := wideProof.LVCSNColsUsed, wideOpts.LVCSNCols; got != want {
		t.Fatalf("wide pre-sign lvcs ncols=%d want %d", got, want)
	}
	if got, want := wideProof.PCSGeometry.WitnessPackingCols, wideOpts.NCols; got != want {
		t.Fatalf("wide pre-sign witness packing cols=%d want %d", got, want)
	}
	if got, want := wideProof.PCSGeometry.PCSNCols, wideOpts.LVCSNCols; got != want {
		t.Fatalf("wide pre-sign geometry pcs ncols=%d want %d", got, want)
	}
	wantReplayRows := ceilDiv(wideProof.PCSGeometry.LogicalWitnessPolys, wideOpts.LVCSNCols) * (wideOpts.NCols + wideOpts.Theta)
	if got, want := wideProof.PCSGeometry.ReplayWitnessRows, wantReplayRows; got != want {
		t.Fatalf("wide pre-sign small-field replay rows=%d want %d", got, want)
	}
	ok, err = VerifyIntGenISISPreSign(pub, wideProof, wideOpts)
	if err != nil || !ok {
		t.Fatalf("verify wide LVCS pre-sign proof: ok=%v err=%v", ok, err)
	}
	tamperedTheta := *thetaProof
	tamperedTheta.PCSGeometry.SmallFieldSource = "legacy"
	ok, err = VerifyIntGenISISPreSign(pub, &tamperedTheta, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 proof verified with tampered small-field source")
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
	badDegree := *proof
	badDegree.MaskDegreeBound--
	ok, err = VerifyIntGenISISPreSign(pub, &badDegree, opts)
	if err == nil && ok {
		t.Fatal("tampered mask degree verified")
	}

	policy, err := credential.NewIntGenISISMEqualsPolicy(msg.MAttr)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	policyBytes, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatalf("policy bytes: %v", err)
	}
	pubPolicy := pub
	pubPolicy.Extras = map[string]interface{}{"IntGenISIS.policy": policyBytes}
	policyProof, err := BuildIntGenISISPreSign(ringQ, pubPolicy, wit, opts)
	if err != nil {
		t.Fatalf("build policy proof: %v", err)
	}
	ok, err = VerifyIntGenISISPreSign(pubPolicy, policyProof, opts)
	if err != nil || !ok {
		t.Fatalf("verify policy proof: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyIntGenISISPreSign(pub, policyProof, opts)
	if err == nil && ok {
		t.Fatal("policy proof verified under no-op policy")
	}
	badPolicyRows := credential.ZeroSemanticAttributes(semanticLayout)
	badPolicyRows[0][0] = 1
	badPolicy, err := credential.NewIntGenISISMEqualsPolicy(badPolicyRows)
	if err != nil {
		t.Fatalf("bad policy: %v", err)
	}
	badPolicyBytes, err := badPolicy.CanonicalBytes()
	if err != nil {
		t.Fatalf("bad policy bytes: %v", err)
	}
	pubBadPolicy := pub
	pubBadPolicy.Extras = map[string]interface{}{"IntGenISIS.policy": badPolicyBytes}
	if _, err := BuildIntGenISISPreSign(ringQ, pubBadPolicy, wit, opts); err == nil {
		t.Fatal("mismatched m_eq policy accepted")
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

func polysFromInt64ForIntGenISISTest(ringQ *ring.Ring, rows [][]int64) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	q := int64(ringQ.Modulus[0])
	for i := range rows {
		out[i] = ringQ.NewPoly()
		for j, v := range rows[i] {
			if j >= int(ringQ.N) {
				break
			}
			v %= q
			if v < 0 {
				v += q
			}
			out[i].Coeffs[0][j] = uint64(v)
		}
	}
	return out
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
