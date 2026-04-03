package PIOP

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/credential"
	ntrurio "vSIS-Signature/ntru/io"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func samplePackedHalfEvalPreSignTest(r *ring.Ring, bound int64, ncols int, rng *rand.Rand, lower bool) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	for i := 0; i < r.N; i++ {
		v := rng.Int63n(2*bound+1) - bound
		if v < 0 {
			v += q
		}
		pNTT.Coeffs[0][i] = uint64(v)
	}
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	half := ncols / 2
	if lower {
		for i := half; i < ncols; i++ {
			pNTT.Coeffs[0][i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			pNTT.Coeffs[0][i] = 0
		}
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func sampleBoundedEvalPreSignTest(r *ring.Ring, bound int64, rng *rand.Rand) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	mod := 2*bound + 1
	for i := 0; i < r.N; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			v += q
		}
		pNTT.Coeffs[0][i] = uint64(v)
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func constNTTPolyPreSignTest(r *ring.Ring, v int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	if v < 0 {
		v = (v%q + q) % q
	}
	c := uint64(v % q)
	for i := range p.Coeffs[0] {
		p.Coeffs[0][i] = c
	}
	return p
}

func credentialPreSignRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func credentialPreSignChdir(t *testing.T, dir string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

type preSignChallengeTest struct {
	RI0 []*ring.Poly
	RI1 []*ring.Poly
}

type preSignStateTest struct {
	B  []*ring.Poly
	R0 []*ring.Poly
	R1 []*ring.Poly
	K0 []*ring.Poly
	K1 []*ring.Poly
	T  []int64
}

func sampleChallengePreSignTest(r *ring.Ring, bound int64, rng *rand.Rand) preSignChallengeTest {
	sampleNTT := func() *ring.Poly {
		p := r.NewPoly()
		q := int64(r.Modulus[0])
		for i := 0; i < 16 && i < len(p.Coeffs[0]); i++ {
			v := rng.Int63n(2*bound+1) - bound
			if v < 0 {
				p.Coeffs[0][i] = uint64(v + q)
			} else {
				p.Coeffs[0][i] = uint64(v)
			}
		}
		return p
	}
	return preSignChallengeTest{
		RI0: []*ring.Poly{sampleNTT()},
		RI1: []*ring.Poly{sampleNTT()},
	}
}

func prepareCommitPreSignTest(r *ring.Ring, Ac [][]*ring.Poly, in WitnessInputs, omega []uint64) ([]*ring.Poly, error) {
	if len(omega) == 0 {
		return nil, fmt.Errorf("missing omega")
	}
	ncols := len(omega)
	q := r.Modulus[0]
	vec := make([]*ring.Poly, 0, 5)
	for _, src := range [][]*ring.Poly{in.M1, in.M2, in.RU0, in.RU1, in.R} {
		cp := r.NewPoly()
		ring.Copy(src[0], cp)
		r.NTT(cp, cp)
		vec = append(vec, cp)
	}
	com := make([]*ring.Poly, len(Ac))
	for i := range Ac {
		head := make([]uint64, ncols)
		for j := range Ac[i] {
			for k := 0; k < ncols; k++ {
				head[k] = lvcs.MulAddMod64(head[k], Ac[i][j].Coeffs[0][k]%q, vec[j].Coeffs[0][k]%q, q)
			}
		}
		com[i] = r.NewPoly()
		for k := 0; k < ncols; k++ {
			com[i].Coeffs[0][k] = head[k] % q
		}
	}
	return com, nil
}

func hashMessagePreSignTest(ringQ *ring.Ring, B []*ring.Poly, m1, m2, r0, r1 *ring.Poly) ([]int64, error) {
	if len(B) != 4 {
		return nil, fmt.Errorf("b length=%d want 4", len(B))
	}
	clone := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		return cp
	}
	mCombined := clone(m1)
	ringQ.Add(mCombined, m2, mCombined)
	tNTT, err := vsishash.ComputeBBSHash(ringQ, B, mCombined, clone(r0), clone(r1))
	if err != nil {
		return nil, err
	}
	tCoeff := ringQ.NewPoly()
	ringQ.InvNTT(tNTT, tCoeff)
	q := int64(ringQ.Modulus[0])
	half := q / 2
	out := make([]int64, ringQ.N)
	for i, c := range tCoeff.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		out[i] = v
	}
	return out, nil
}

func modInverseUint64PreSignTest(x, q uint64) (uint64, bool) {
	if x == 0 || q == 0 {
		return 0, false
	}
	var t, newT int64 = 0, 1
	var r0, newR int64 = int64(q), int64(x%q)
	for newR != 0 {
		quot := r0 / newR
		t, newT = newT, t-quot*newT
		r0, newR = newR, r0-quot*newR
	}
	if r0 != 1 {
		return 0, false
	}
	if t < 0 {
		t += int64(q)
	}
	return uint64(t), true
}

func applyChallengePreSignTest(p *credential.Params, in WitnessInputs, ch preSignChallengeTest, omega []uint64) (*preSignStateTest, error) {
	r := p.RingQ
	bound := p.BoundB
	q := int64(r.Modulus[0])
	delta := int64(2*bound + 1)
	headFromCoeff := func(p *ring.Poly, ncols int) []uint64 {
		pNTT := r.NewPoly()
		ring.Copy(p, pNTT)
		r.NTT(pNTT, pNTT)
		head := make([]uint64, ncols)
		copy(head, pNTT.Coeffs[0][:ncols])
		return head
	}
	coeffFromHead := func(head []uint64) *ring.Poly {
		pNTT := r.NewPoly()
		copy(pNTT.Coeffs[0][:len(head)], head)
		out := r.NewPoly()
		r.InvNTT(pNTT, out)
		return out
	}
	centered := func(v uint64) int64 {
		x := int64(v % uint64(q))
		if x > q/2 {
			x -= q
		}
		return x
	}
	sumCarry := func(ruHead, riHead []uint64) (*ring.Poly, *ring.Poly) {
		rHead := make([]uint64, len(ruHead))
		kHead := make([]uint64, len(ruHead))
		for i := range ruHead {
			ruCoeff := centered(ruHead[i])
			riCoeff := centered(riHead[i])
			c := credential.CenterBounded(ruCoeff+riCoeff, bound)
			k := (ruCoeff + riCoeff - c) / delta
			if c < 0 {
				rHead[i] = uint64(c + q)
			} else {
				rHead[i] = uint64(c)
			}
			if k < 0 {
				kHead[i] = uint64(k + q)
			} else {
				kHead[i] = uint64(k)
			}
		}
		return coeffFromHead(rHead), coeffFromHead(kHead)
	}
	ru0Head := headFromCoeff(in.RU0[0], 16)
	ru1Head := headFromCoeff(in.RU1[0], 16)
	r0, k0 := sumCarry(ru0Head, ch.RI0[0].Coeffs[0][:16])
	r1, k1 := sumCarry(ru1Head, ch.RI1[0].Coeffs[0][:16])

	B, err := loadBForPreSignTest(r, p.BPath)
	if err != nil {
		return nil, err
	}
	m1Head := headFromCoeff(in.M1[0], 16)
	m2Head := headFromCoeff(in.M2[0], 16)
	r0Head := headFromCoeff(r0, 16)
	r1Head := headFromCoeff(r1, 16)
	tHead := make([]uint64, len(m1Head))
	for i := range tHead {
		b0 := B[0].Coeffs[0][i] % uint64(q)
		b1 := B[1].Coeffs[0][i] % uint64(q)
		b2 := B[2].Coeffs[0][i] % uint64(q)
		b3 := B[3].Coeffs[0][i] % uint64(q)
		mCombined := (m1Head[i] + m2Head[i]) % uint64(q)
		num := b0
		num = (num + (b1*mCombined)%uint64(q)) % uint64(q)
		num = (num + (b2*r0Head[i])%uint64(q)) % uint64(q)
		den := (b3 + uint64(q) - r1Head[i]%uint64(q)) % uint64(q)
		denInv, ok := modInverseUint64PreSignTest(den, uint64(q))
		if !ok {
			return nil, fmt.Errorf("hash denominator not invertible at omega slot %d", i)
		}
		tHead[i] = (num * denInv) % uint64(q)
	}
	tPoly := coeffFromHead(tHead)
	tCoeff := make([]int64, r.N)
	for i, c := range tPoly.Coeffs[0] {
		tCoeff[i] = centered(c)
	}
	return &preSignStateTest{
		B:  B,
		R0: []*ring.Poly{r0},
		R1: []*ring.Poly{r1},
		K0: []*ring.Poly{k0},
		K1: []*ring.Poly{k1},
		T:  tCoeff,
	}, nil
}

func loadBForPreSignTest(r *ring.Ring, path string) ([]*ring.Poly, error) {
	coeffs, err := ntrurio.LoadBMatrixCoeffs(path)
	if err != nil {
		return nil, err
	}
	out := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		p := r.NewPoly()
		copy(p.Coeffs[0], coeffs[i])
		r.NTT(p, p)
		out[i] = p
	}
	return out, nil
}

func TestCredentialPreSignConstraintFamiliesOnOmega(t *testing.T) {
	credentialPreSignChdir(t, credentialPreSignRepoRoot(t))
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential: true,
		Theta:      4,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		Ell:        25,
		Eta:        19,
		DomainMode: DomainModeExplicit,
		NLeaves:    2048,
	})
	_, omega, _, err := loadParamsAndOmega(opts)
	if err != nil {
		t.Fatalf("load params/omega: %v", err)
	}
	omega = omega[:opts.NCols]
	const bound = int64(8)
	Ac := make([][]*ring.Poly, 5)
	for i := range Ac {
		Ac[i] = make([]*ring.Poly, 5)
		for j := range Ac[i] {
			if i == j {
				Ac[i][j] = constNTTPolyPreSignTest(ringQ, 1)
			} else {
				Ac[i][j] = ringQ.NewPoly()
			}
		}
	}
	params := &credential.Params{
		Ac:     Ac,
		BPath:  "Parameters/Bmatrix.json",
		AcPath: "credential/Ac.json",
		BoundB: bound,
		RingQ:  ringQ,
		LenM1:  1,
		LenM2:  1,
		LenRU0: 1,
		LenRU1: 1,
		LenR:   1,
	}
	rng := rand.New(rand.NewSource(7))
	witBase := WitnessInputs{
		M1:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, opts.NCols, rng, true)},
		M2:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, opts.NCols, rng, false)},
		RU0: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, rng)},
		RU1: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, rng)},
		R:   []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, rng)},
	}
	ch := sampleChallengePreSignTest(ringQ, bound, rng)
	com, err := prepareCommitPreSignTest(ringQ, Ac, witBase, omega)
	if err != nil {
		t.Fatalf("prepare commit: %v", err)
	}
	st, err := applyChallengePreSignTest(params, witBase, ch, omega)
	if err != nil {
		t.Fatalf("apply challenge: %v", err)
	}
	pub := PublicInputs{
		Com:    com,
		RI0:    ch.RI0,
		RI1:    ch.RI1,
		Ac:     params.Ac,
		B:      st.B,
		T:      st.T,
		BoundB: params.BoundB,
	}
	wit := WitnessInputs{
		M1:  witBase.M1,
		M2:  witBase.M2,
		RU0: witBase.RU0,
		RU1: witBase.RU1,
		R:   witBase.R,
		R0:  st.R0,
		R1:  st.R1,
		K0:  st.K0,
		K1:  st.K1,
	}
	cs, err := BuildCredentialConstraintSetPre(ringQ, params.BoundB, pub, wit, omega)
	if err != nil {
		t.Fatalf("build constraint set: %v", err)
	}
	q := ringQ.Modulus[0]
	checkFamily := func(name string, polys []*ring.Poly) {
		t.Helper()
		for i, p := range polys {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("%s[%d] coeffs: %v", name, i, cerr)
			}
			for j, x := range omega {
				v := EvalPoly(coeffs, x, q) % q
				if v != 0 {
					t.Fatalf("%s[%d] nonzero on omega[%d]=%d: %d", name, i, j, x, v)
				}
			}
		}
	}
	checkFamily("FparInt", cs.FparInt)
	checkFamily("FparNorm", cs.FparNorm)
	totalParallel := len(cs.FparInt) + len(cs.FparNorm)
	totalAgg := len(cs.FaggInt) + len(cs.FaggNorm)
	gammaPrime := make([][][]uint64, opts.Rho)
	gammaAgg := make([][]uint64, opts.Rho)
	for i := 0; i < opts.Rho; i++ {
		gammaPrime[i] = make([][]uint64, totalParallel)
		for j := 0; j < totalParallel; j++ {
			gammaPrime[i][j] = []uint64{1}
		}
		gammaAgg[i] = make([]uint64, totalAgg)
		for j := 0; j < totalAgg; j++ {
			gammaAgg[i][j] = 1
		}
	}
	zeroMasks := make([][]uint64, opts.Rho)
	for i := 0; i < opts.Rho; i++ {
		zeroMasks[i] = []uint64{0}
	}
	qCoeffs, err := BuildQCoeffsChecked(
		ringQ,
		BuildQLayout{MaskCoeffs: zeroMasks},
		cs.FparInt,
		cs.FparNorm,
		cs.FaggInt,
		cs.FaggNorm,
		cs.FparIntCoeffs,
		cs.FparNormCoeffs,
		cs.FaggIntCoeffs,
		cs.FaggNormCoeffs,
		gammaPrime,
		gammaAgg,
	)
	if err != nil {
		t.Fatalf("build Q coeffs: %v", err)
	}
	for rowIdx, coeffs := range qCoeffs {
		sum := uint64(0)
		for _, w := range omega {
			sum = modAdd(sum, EvalPoly(coeffs, w%q, q)%q, q)
		}
		if sum != 0 {
			t.Fatalf("Q row %d has non-zero SigmaOmega sum=%d", rowIdx, sum)
		}
	}
	masks := SampleIndependentMaskPolynomials(ringQ, opts.Rho, 32, omega)
	for i, mask := range masks {
		coeffs, err := coeffFromNTTPoly(ringQ, mask)
		if err != nil {
			t.Fatalf("mask %d coeffs: %v", i, err)
		}
		sum := uint64(0)
		for _, w := range omega {
			sum = modAdd(sum, EvalPoly(coeffs, w%q, q)%q, q)
		}
		if sum != 0 {
			t.Fatalf("mask row %d has non-zero SigmaOmega sum=%d", i, sum)
		}
	}
}

func TestCredentialPreSignProofVerifies(t *testing.T) {
	credentialPreSignChdir(t, credentialPreSignRepoRoot(t))
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential: true,
		Theta:      4,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		Ell:        25,
		Eta:        19,
		DomainMode: DomainModeExplicit,
		NLeaves:    2048,
	})
	_, omega, _, err := loadParamsAndOmega(opts)
	if err != nil {
		t.Fatalf("load params/omega: %v", err)
	}
	omega = omega[:opts.NCols]
	const bound = int64(8)
	Ac := make([][]*ring.Poly, 5)
	for i := range Ac {
		Ac[i] = make([]*ring.Poly, 5)
		for j := range Ac[i] {
			if i == j {
				Ac[i][j] = constNTTPolyPreSignTest(ringQ, 1)
			} else {
				Ac[i][j] = ringQ.NewPoly()
			}
		}
	}
	params := &credential.Params{
		Ac:     Ac,
		BPath:  "Parameters/Bmatrix.json",
		AcPath: "credential/Ac.json",
		BoundB: bound,
		RingQ:  ringQ,
		LenM1:  1,
		LenM2:  1,
		LenRU0: 1,
		LenRU1: 1,
		LenR:   1,
	}
	rng := rand.New(rand.NewSource(7))
	witBase := WitnessInputs{
		M1:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, opts.NCols, rng, true)},
		M2:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, opts.NCols, rng, false)},
		RU0: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, rng)},
		RU1: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, rng)},
		R:   []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, rng)},
	}
	ch := sampleChallengePreSignTest(ringQ, bound, rng)
	com, err := prepareCommitPreSignTest(ringQ, Ac, witBase, omega)
	if err != nil {
		t.Fatalf("prepare commit: %v", err)
	}
	st, err := applyChallengePreSignTest(params, witBase, ch, omega)
	if err != nil {
		t.Fatalf("apply challenge: %v", err)
	}
	pub := PublicInputs{
		Com:    com,
		RI0:    ch.RI0,
		RI1:    ch.RI1,
		Ac:     params.Ac,
		B:      st.B,
		T:      st.T,
		BoundB: params.BoundB,
	}
	wit := WitnessInputs{
		M1:  witBase.M1,
		M2:  witBase.M2,
		RU0: witBase.RU0,
		RU1: witBase.RU1,
		R:   witBase.R,
		R0:  st.R0,
		R1:  st.R1,
		K0:  st.K0,
		K1:  st.K1,
	}
	builder := NewCredentialBuilder(opts)
	proof, err := builder.Build(pub, wit, MaskConfig{})
	if err != nil {
		t.Fatalf("prove pre-sign: %v", err)
	}
	ok, err := builder.Verify(pub, proof)
	if err != nil {
		t.Fatalf("verify pre-sign: %v", err)
	}
	if !ok {
		t.Fatal("pre-sign proof did not verify")
	}
}

func equalUint64Slice(a, b []uint64) bool {
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

func equalMatrixUint64(a, b [][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !equalUint64Slice(a[i], b[i]) {
			return false
		}
	}
	return true
}
