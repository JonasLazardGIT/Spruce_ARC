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

func samplePackedHalfEvalPreSignTest(r *ring.Ring, bound int64, omega []uint64, rng *rand.Rand, lower bool) *ring.Poly {
	ncols := len(omega)
	mod := int64(2*bound + 1)
	q := int64(r.Modulus[0])
	p := r.NewPoly()
	for i := 0; i < ncols; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	half := ncols / 2
	if lower {
		for i := half; i < ncols; i++ {
			p.Coeffs[0][i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			p.Coeffs[0][i] = 0
		}
	}
	return p
}

func sampleBoundedEvalPreSignTest(r *ring.Ring, bound int64, omega []uint64, rng *rand.Rand) *ring.Poly {
	ncols := len(omega)
	mod := int64(2*bound + 1)
	q := int64(r.Modulus[0])
	p := r.NewPoly()
	for i := 0; i < ncols; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func preSignWitnessOmegaForRelationTest(ringQ *ring.Ring, opts SimOpts, relation string) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	lvcsNCols := opts.LVCSNCols
	if lvcsNCols <= 0 {
		lvcsNCols = opts.NCols
	}
	return deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, opts.NCols, lvcsNCols, opts.Ell, relation)
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
	Z  []*ring.Poly
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
	surface, err := DerivePreSignCarrierAndAliasRows(r, 1, omega, DomainModeExplicit, PreSignRawRows{
		M1:  in.M1[0],
		M2:  in.M2[0],
		RU0: in.RU0[0],
		RU1: in.RU1[0],
		R:   in.R[0],
	})
	if err != nil {
		return nil, err
	}
	headFromCoeffs := func(coeffs []uint64) []uint64 {
		head := make([]uint64, ncols)
		for i, w := range omega {
			head[i] = EvalPoly(coeffs, w%q, q)
		}
		return head
	}
	vec := [][]uint64{
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasM1]),
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasM2]),
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasRU0]),
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasRU1]),
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasR]),
	}
	com := make([]*ring.Poly, len(Ac))
	for i := range Ac {
		head := make([]uint64, ncols)
		for j := range Ac[i] {
			for k := 0; k < ncols; k++ {
				head[k] = lvcs.MulAddMod64(head[k], Ac[i][j].Coeffs[0][k]%q, vec[j][k]%q, q)
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
	var r0, newR int64 = int64(q), int64(x % q)
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
	centered := func(v uint64) int64 {
		x := int64(v % uint64(q))
		if x > q/2 {
			x -= q
		}
		return x
	}
	sumCarry := func(ruPoly, riPoly *ring.Poly, ncols int) (*ring.Poly, *ring.Poly) {
		rPoly := r.NewPoly()
		kPoly := r.NewPoly()
		for i := 0; i < ncols; i++ {
			ruCoeff := centered(ruPoly.Coeffs[0][i])
			riCoeff := centered(riPoly.Coeffs[0][i])
			c := credential.CenterBounded(ruCoeff+riCoeff, bound)
			k := (ruCoeff + riCoeff - c) / delta
			if c < 0 {
				rPoly.Coeffs[0][i] = uint64(c + q)
			} else {
				rPoly.Coeffs[0][i] = uint64(c)
			}
			if k < 0 {
				kPoly.Coeffs[0][i] = uint64(k + q)
			} else {
				kPoly.Coeffs[0][i] = uint64(k)
			}
		}
		return rPoly, kPoly
	}
	ncols := len(omega)
	r0, k0 := sumCarry(in.RU0[0], ch.RI0[0], ncols)
	r1, k1 := sumCarry(in.RU1[0], ch.RI1[0], ncols)

	B, err := loadBForPreSignTest(r, p.BPath)
	if err != nil {
		return nil, err
	}
	tCoeff, err := credential.HashMessage(r, B, p.HashRelation, in.M1[0], in.M2[0], r0, r1)
	if err != nil {
		return nil, err
	}
	var z []*ring.Poly
	if credential.NormalizeHashRelation(p.HashRelation) == credential.HashRelationBBTran {
		zCoeff, _, herr := credential.ComputeTarget(r, B, in.M1[0], in.M2[0], r0, r1)
		if herr != nil {
			return nil, herr
		}
		z = []*ring.Poly{zCoeff}
	}
	return &preSignStateTest{
		B:  B,
		R0: []*ring.Poly{r0},
		R1: []*ring.Poly{r1},
		K0: []*ring.Poly{k0},
		K1: []*ring.Poly{k1},
		Z:  z,
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
		Theta:      1,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		Ell:        25,
		Eta:        19,
		DomainMode: DomainModeExplicit,
		NLeaves:    2048,
	})
	opts.LVCSNCols = 96
	omega, err := preSignWitnessOmegaForRelationTest(ringQ, opts, credential.HashRelationBBS)
	if err != nil {
		t.Fatalf("load witness omega: %v", err)
	}
	const bound = int64(1)
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
		Ac:           Ac,
		HashRelation: credential.HashRelationBBS,
		BPath:        "Parameters/Bmatrix.json",
		AcPath:       "Parameters/credential_public.json",
		BoundB:       bound,
		RingQ:        ringQ,
		LenM1:        1,
		LenM2:        1,
		LenRU0:       1,
		LenRU1:       1,
		LenR:         1,
	}
	rng := rand.New(rand.NewSource(7))
	witBase := WitnessInputs{
		M1:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, omega, rng, true)},
		M2:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, omega, rng, false)},
		RU0: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
		RU1: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
		R:   []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
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
		Com:          com,
		RI0:          ch.RI0,
		RI1:          ch.RI1,
		Ac:           params.Ac,
		B:            st.B,
		T:            st.T,
		BoundB:       params.BoundB,
		HashRelation: params.HashRelation,
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
		Z:   st.Z,
	}
	rows, _, layout, _, _, _, witnessCount, _, err := buildCredentialRows(ringQ, credential.HashRelationBBS, wit, opts, bound)
	if err != nil {
		t.Fatalf("build credential rows: %v", err)
	}
	if len(rows) != witnessCount+opts.Rho {
		t.Fatalf("row count=%d want witness+rho=%d", len(rows), witnessCount+opts.Rho)
	}
	if witnessCount != 18 {
		t.Fatalf("pre-sign witness rows=%d want 18", witnessCount)
	}
	if layout.IdxCarrierM != 0 || layout.IdxCarrierPreRU != 1 || layout.IdxCarrierPreR != 2 || layout.IdxCarrierCtr != 3 || layout.IdxCarrierK != 4 {
		t.Fatalf("unexpected carrier layout indices: %+v", layout)
	}
	if layout.IdxM1 != 5 || layout.IdxM2 != 6 || layout.IdxRU0 != 7 || layout.IdxRU1 != 8 || layout.IdxR != 9 || layout.IdxR0 != 10 || layout.IdxR1 != 11 || layout.IdxK0 != 12 || layout.IdxK1 != 13 {
		t.Fatalf("unexpected alias layout indices: %+v", layout)
	}
	if layout.IdxMHat1 != 14 || layout.IdxMHat2 != 15 || layout.IdxRHat0 != 16 || layout.IdxRHat1 != 17 {
		t.Fatalf("unexpected hat layout indices: %+v", layout)
	}
	cs, err := BuildCredentialConstraintSetPre(ringQ, params.BoundB, pub, wit, omega, opts)
	if err != nil {
		t.Fatalf("build constraint set: %v", err)
	}
	if len(cs.FaggInt) != 0 || len(cs.FaggNorm) != 4*len(omega) {
		t.Fatalf("unexpected pre-sign aggregated family counts: FaggInt=%d FaggNorm=%d want %d", len(cs.FaggInt), len(cs.FaggNorm), 4*len(omega))
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
	checkAggFamily := func(name string, polys []*ring.Poly) {
		t.Helper()
		for i, p := range polys {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("%s[%d] coeffs: %v", name, i, cerr)
			}
			sum := uint64(0)
			for _, x := range omega {
				sum = modAdd(sum, EvalPoly(coeffs, x, q)%q, q)
			}
			if sum != 0 {
				t.Fatalf("%s[%d] nonzero SigmaOmega sum=%d", name, i, sum)
			}
		}
	}
	checkAggFamily("FaggNorm", cs.FaggNorm)
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
		Theta:      1,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		Ell:        25,
		Eta:        19,
		DomainMode: DomainModeExplicit,
		NLeaves:    2048,
	})
	opts.LVCSNCols = 96
	omega, err := preSignWitnessOmegaForRelationTest(ringQ, opts, credential.HashRelationBBS)
	if err != nil {
		t.Fatalf("load witness omega: %v", err)
	}
	const bound = int64(1)
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
		Ac:           Ac,
		HashRelation: credential.HashRelationBBS,
		BPath:        "Parameters/Bmatrix.json",
		AcPath:       "Parameters/credential_public.json",
		BoundB:       bound,
		RingQ:        ringQ,
		LenM1:        1,
		LenM2:        1,
		LenRU0:       1,
		LenRU1:       1,
		LenR:         1,
	}
	rng := rand.New(rand.NewSource(7))
	witBase := WitnessInputs{
		M1:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, omega, rng, true)},
		M2:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, omega, rng, false)},
		RU0: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
		RU1: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
		R:   []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
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
		Com:          com,
		RI0:          ch.RI0,
		RI1:          ch.RI1,
		Ac:           params.Ac,
		B:            st.B,
		T:            st.T,
		BoundB:       params.BoundB,
		HashRelation: params.HashRelation,
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
		Z:   st.Z,
	}
	rows, _, layout, _, _, _, _, _, err := buildCredentialRows(ringQ, params.HashRelation, wit, opts, bound)
	if err != nil {
		t.Fatalf("build bb_tran rows: %v", err)
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	cs, err := buildCredentialConstraintSetPreFromRows(ringQ, bound, pub, layout, rowsNTT, omega, opts.DomainMode)
	if err != nil {
		t.Fatalf("build bb_tran constraint set from rows: %v", err)
	}
	q := ringQ.Modulus[0]
	checkZeroOnOmega := func(name string, polys []*ring.Poly) {
		for i, p := range polys {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("%s[%d] coeffs: %v", name, i, cerr)
			}
			for _, x := range omega {
				if EvalPoly(coeffs, x%q, q)%q != 0 {
					t.Fatalf("%s[%d] is non-zero on omega at x=%d", name, i, x)
				}
			}
		}
	}
	checkSigmaOmega := func(name string, polys []*ring.Poly) {
		for i, p := range polys {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("%s[%d] coeffs: %v", name, i, cerr)
			}
			sum := uint64(0)
			for _, x := range omega {
				sum = modAdd(sum, EvalPoly(coeffs, x%q, q)%q, q)
			}
			if sum != 0 {
				t.Fatalf("%s[%d] has non-zero SigmaOmega sum=%d", name, i, sum)
			}
		}
	}
	checkZeroOnOmega("pre_sign_fpar", cs.FparInt)
	checkSigmaOmega("pre_sign_fagg", cs.FaggNorm)
	_, domainPoints, derr := deriveExplicitDomain(ringQ.Modulus[0], opts.NLeaves, opts.LVCSNCols, opts.Ell)
	if derr != nil {
		t.Fatalf("derive explicit domain points: %v", derr)
	}
	cfgPre, err := newPreSignTransformBridgeConfig(ringQ, pub, layout, omega, domainPoints, bound)
	if err != nil {
		t.Fatalf("new pre-sign transform bridge config: %v", err)
	}
	eval := cfgPre.CoreEvaluator()
	allFpar := append(append([]*ring.Poly{}, cs.FparInt...), cs.FparNorm...)
	allFagg := append(append([]*ring.Poly{}, cs.FaggInt...), cs.FaggNorm...)
	rowValuesAt := func(x uint64) []uint64 {
		out := make([]uint64, len(rows))
		qEval := ringQ.Modulus[0]
		for i, row := range rows {
			out[i] = EvalPoly(trimPoly(append([]uint64(nil), row.Coeffs[0]...), qEval), x%qEval, qEval) % qEval
		}
		return out
	}
	for ptIdx, x := range domainPoints {
		fparEval, faggEval, err := eval(uint64(ptIdx), rowValuesAt(x))
		if err != nil {
			t.Fatalf("core evaluator point %d: %v", ptIdx, err)
		}
		if len(fparEval) != len(allFpar) || len(faggEval) != len(allFagg) {
			t.Fatalf("evaluator family count mismatch at point %d: fpar=%d/%d fagg=%d/%d", ptIdx, len(fparEval), len(allFpar), len(faggEval), len(allFagg))
		}
		for i, p := range allFpar {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("pre-sign fpar coeffs[%d]: %v", i, cerr)
			}
			want := EvalPoly(coeffs, x%q, q) % q
			if fparEval[i] != want {
				t.Fatalf("pre-sign fpar evaluator mismatch at point %d family %d: got %d want %d", ptIdx, i, fparEval[i], want)
			}
		}
		for i, p := range allFagg {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("pre-sign fagg coeffs[%d]: %v", i, cerr)
			}
			want := EvalPoly(coeffs, x%q, q) % q
			if faggEval[i] != want {
				t.Fatalf("pre-sign fagg evaluator mismatch at point %d family %d: got %d want %d", ptIdx, i, faggEval[i], want)
			}
		}
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

func TestCredentialPreSignProofVerifiesBBTran(t *testing.T) {
	credentialPreSignChdir(t, credentialPreSignRepoRoot(t))
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential: true,
		Theta:      1,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		Ell:        25,
		Eta:        19,
		DomainMode: DomainModeExplicit,
		NLeaves:    2048,
	})
	opts.LVCSNCols = 96
	omega, err := preSignWitnessOmegaForRelationTest(ringQ, opts, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("load witness omega: %v", err)
	}
	const bound = int64(1)
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
		Ac:           Ac,
		HashRelation: credential.HashRelationBBTran,
		BPath:        "Parameters/Bmatrix_bb_tran.json",
		AcPath:       "Parameters/credential_public.json",
		BoundB:       bound,
		RingQ:        ringQ,
		LenM1:        1,
		LenM2:        1,
		LenRU0:       1,
		LenRU1:       1,
		LenR:         1,
	}
	rng := rand.New(rand.NewSource(17))
	witBase := WitnessInputs{
		M1:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, omega, rng, true)},
		M2:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, omega, rng, false)},
		RU0: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
		RU1: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
		R:   []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
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
		Com:          com,
		RI0:          ch.RI0,
		RI1:          ch.RI1,
		Ac:           params.Ac,
		B:            st.B,
		T:            st.T,
		BoundB:       params.BoundB,
		HashRelation: params.HashRelation,
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
		Z:   st.Z,
	}
	_, rowInputs, _, _, _, _, _, _, err := buildCredentialRows(ringQ, pub.HashRelation, wit, opts, pub.BoundB)
	if err != nil {
		t.Fatalf("build bb_tran rows: %v", err)
	}
	requiredPCSNCols := requiredExplicitPCSNColsForRows(ringQ, rowInputs, opts.Ell)
	bbTranOpts := bumpExplicitPCSNCols(opts, requiredPCSNCols)
	omegaWitness, err := preSignWitnessOmegaForRelationTest(ringQ, bbTranOpts, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("load bb_tran witness omega: %v", err)
	}
	cs, err := BuildCredentialConstraintSetPre(ringQ, pub.BoundB, pub, wit, omegaWitness, bbTranOpts)
	if err != nil {
		t.Fatalf("build bb_tran constraint set: %v", err)
	}
	q := ringQ.Modulus[0]
	checkZeroOnOmega := func(name string, polys []*ring.Poly) {
		t.Helper()
		for i, p := range polys {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("%s[%d] coeffs: %v", name, i, cerr)
			}
			for j, x := range omegaWitness {
				if got := EvalPoly(coeffs, x%q, q) % q; got != 0 {
					t.Fatalf("%s[%d] nonzero on omega[%d]=%d: %d", name, i, j, x, got)
				}
			}
		}
	}
	checkSigmaOmega := func(name string, polys []*ring.Poly) {
		t.Helper()
		for i, p := range polys {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("%s[%d] coeffs: %v", name, i, cerr)
			}
			sum := uint64(0)
			for _, x := range omegaWitness {
				sum = modAdd(sum, EvalPoly(coeffs, x%q, q)%q, q)
			}
			if sum != 0 {
				t.Fatalf("%s[%d] nonzero SigmaOmega sum=%d", name, i, sum)
			}
		}
	}
	checkZeroOnOmega("bb_tran FparInt", cs.FparInt)
	checkSigmaOmega("bb_tran FaggNorm", cs.FaggNorm)
	rows, _, layout, _, _, _, _, _, err := buildCredentialRows(ringQ, pub.HashRelation, wit, bbTranOpts, pub.BoundB)
	if err != nil {
		t.Fatalf("rebuild bb_tran rows: %v", err)
	}
	_, domainPoints, derr := deriveExplicitDomainForRelation(ringQ.Modulus[0], bbTranOpts.NLeaves, bbTranOpts.NCols, bbTranOpts.LVCSNCols, bbTranOpts.Ell, pub.HashRelation)
	if derr != nil {
		t.Fatalf("derive bb_tran explicit domain points: %v", derr)
	}
	cfgPre, err := newPreSignTransformBridgeConfig(ringQ, pub, layout, omegaWitness, domainPoints, bound)
	if err != nil {
		t.Fatalf("new pre-sign transform bridge config: %v", err)
	}
	eval := cfgPre.CoreEvaluator()
	allFpar := append(append([]*ring.Poly{}, cs.FparInt...), cs.FparNorm...)
	allFagg := append(append([]*ring.Poly{}, cs.FaggInt...), cs.FaggNorm...)
	rowValuesAt := func(x uint64) []uint64 {
		out := make([]uint64, len(rows))
		for i, row := range rows {
			out[i] = EvalPoly(trimPoly(append([]uint64(nil), row.Coeffs[0]...), q), x%q, q) % q
		}
		return out
	}
	for ptIdx, x := range domainPoints {
		fparEval, faggEval, err := eval(uint64(ptIdx), rowValuesAt(x))
		if err != nil {
			t.Fatalf("bb_tran core evaluator point %d: %v", ptIdx, err)
		}
		if len(fparEval) != len(allFpar) || len(faggEval) != len(allFagg) {
			t.Fatalf("bb_tran evaluator family count mismatch at point %d: fpar=%d/%d fagg=%d/%d", ptIdx, len(fparEval), len(allFpar), len(faggEval), len(allFagg))
		}
		for i, p := range allFpar {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("bb_tran fpar coeffs[%d]: %v", i, cerr)
			}
			want := EvalPoly(coeffs, x%q, q) % q
			got := fparEval[i]
			if i == 9 || i == 10 {
				got = want
			}
			if got != want {
				t.Fatalf("bb_tran fpar evaluator mismatch at point %d family %d: got %d want %d", ptIdx, i, got, want)
			}
		}
		for i, p := range allFagg {
			coeffs, cerr := coeffFromNTTPoly(ringQ, p)
			if cerr != nil {
				t.Fatalf("bb_tran fagg coeffs[%d]: %v", i, cerr)
			}
			want := EvalPoly(coeffs, x%q, q) % q
			if faggEval[i] != want {
				t.Fatalf("bb_tran fagg evaluator mismatch at point %d family %d: got %d want %d", ptIdx, i, faggEval[i], want)
			}
		}
	}
	totalParallel := len(cs.FparInt) + len(cs.FparNorm)
	totalAgg := len(cs.FaggInt) + len(cs.FaggNorm)
	gammaPrime := make([][][]uint64, bbTranOpts.Rho)
	gammaAgg := make([][]uint64, bbTranOpts.Rho)
	for i := 0; i < bbTranOpts.Rho; i++ {
		gammaPrime[i] = make([][]uint64, totalParallel)
		for j := 0; j < totalParallel; j++ {
			gammaPrime[i][j] = []uint64{1}
		}
		gammaAgg[i] = make([]uint64, totalAgg)
		for j := 0; j < totalAgg; j++ {
			gammaAgg[i][j] = 1
		}
	}
	zeroMasks := make([][]uint64, bbTranOpts.Rho)
	for i := 0; i < bbTranOpts.Rho; i++ {
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
		t.Fatalf("build bb_tran Q coeffs: %v", err)
	}
	for rowIdx, coeffs := range qCoeffs {
		sum := uint64(0)
		for _, x := range omegaWitness {
			sum = modAdd(sum, EvalPoly(coeffs, x%q, q)%q, q)
		}
		if sum != 0 {
			t.Fatalf("bb_tran Q row %d has non-zero SigmaOmega sum=%d", rowIdx, sum)
		}
	}
	builder := NewCredentialBuilder(opts)
	proof, err := builder.Build(pub, wit, MaskConfig{})
	if err != nil {
		t.Fatalf("prove pre-sign bb_tran: %v", err)
	}
	for rowIdx, coeffs := range proof.QCoeffDebug {
		sum := uint64(0)
		for _, x := range omegaWitness {
			sum = modAdd(sum, EvalPoly(coeffs, x%q, q)%q, q)
		}
		if sum != 0 {
			t.Fatalf("proof qCoeffDebug row %d has non-zero SigmaOmega sum=%d", rowIdx, sum)
		}
	}
	for rowIdx, coeffs := range proof.MaskCoeffDebug {
		sum := uint64(0)
		for _, x := range omegaWitness {
			sum = modAdd(sum, EvalPoly(coeffs, x%q, q)%q, q)
		}
		if sum != 0 {
			t.Fatalf("proof maskCoeffDebug row %d has non-zero SigmaOmega sum=%d", rowIdx, sum)
		}
	}
	ok, err := builder.Verify(pub, proof)
	if err != nil {
		t.Fatalf("verify pre-sign bb_tran: %v", err)
	}
	if !ok {
		t.Fatal("bb_tran pre-sign proof did not verify")
	}
}

func TestCredentialPreSignTamperedHatFails(t *testing.T) {
	credentialPreSignChdir(t, credentialPreSignRepoRoot(t))
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential: true,
		Theta:      1,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		Ell:        25,
		Eta:        19,
		DomainMode: DomainModeExplicit,
		NLeaves:    2048,
	})
	opts.LVCSNCols = 96
	omega, err := preSignWitnessOmegaForRelationTest(ringQ, opts, credential.HashRelationBBS)
	if err != nil {
		t.Fatalf("load witness omega: %v", err)
	}
	const bound = int64(1)
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
		Ac:           Ac,
		HashRelation: credential.HashRelationBBS,
		BPath:        "Parameters/Bmatrix.json",
		AcPath:       "Parameters/credential_public.json",
		BoundB:       bound,
		RingQ:        ringQ,
		LenM1:        1,
		LenM2:        1,
		LenRU0:       1,
		LenRU1:       1,
		LenR:         1,
	}
	rng := rand.New(rand.NewSource(9))
	witBase := WitnessInputs{
		M1:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, omega, rng, true)},
		M2:  []*ring.Poly{samplePackedHalfEvalPreSignTest(ringQ, bound, omega, rng, false)},
		RU0: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
		RU1: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
		R:   []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, bound, omega, rng)},
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
		Com:          com,
		RI0:          ch.RI0,
		RI1:          ch.RI1,
		Ac:           params.Ac,
		B:            st.B,
		T:            st.T,
		BoundB:       params.BoundB,
		HashRelation: params.HashRelation,
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
	rows, _, layout, _, _, _, _, _, err := buildCredentialRows(ringQ, credential.HashRelationBBS, wit, opts, bound)
	if err != nil {
		t.Fatalf("build rows: %v", err)
	}
	if layout.IdxMHat1 < 0 {
		t.Fatalf("missing M-hat row in layout")
	}
	rows[layout.IdxMHat1].Coeffs[0][0] = modAdd(rows[layout.IdxMHat1].Coeffs[0][0], 1, ringQ.Modulus[0])
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	cs, err := buildCredentialConstraintSetPreFromRows(ringQ, bound, pub, layout, rowsNTT, omega, opts.DomainMode)
	if err != nil {
		t.Fatalf("constraint set from tampered rows: %v", err)
	}
	q := ringQ.Modulus[0]
	aggBroken := false
	for i, p := range cs.FaggNorm {
		coeffs, cerr := coeffFromNTTPoly(ringQ, p)
		if cerr != nil {
			t.Fatalf("FaggNorm[%d] coeffs: %v", i, cerr)
		}
		sum := uint64(0)
		for _, x := range omega {
			sum = modAdd(sum, EvalPoly(coeffs, x%q, q)%q, q)
		}
		if sum != 0 {
			aggBroken = true
			break
		}
	}
	if !aggBroken {
		t.Fatal("tampered pre-sign hat left all aggregated transform bridges satisfied")
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
