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
	vsishash "vSIS-Signature/internal/hash"
	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func samplePackedHalfEvalPreSignTest(r *ring.Ring, bound int64, omega []uint64, rng *rand.Rand, lower bool) *ring.Poly {
	ncols := len(omega)
	mod := int64(2*bound + 1)
	q := int64(r.Modulus[0])
	head := make([]uint64, ncols)
	for i := 0; i < ncols; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			head[i] = uint64(v + q)
		} else {
			head[i] = uint64(v)
		}
	}
	half := ncols / 2
	if lower {
		for i := half; i < ncols; i++ {
			head[i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			head[i] = 0
		}
	}
	p := r.NewPoly()
	copy(p.Coeffs[0], Interpolate(omega, head, uint64(q)))
	return p
}

func sampleBoundedEvalPreSignTest(r *ring.Ring, bound int64, omega []uint64, rng *rand.Rand) *ring.Poly {
	ncols := len(omega)
	mod := int64(2*bound + 1)
	q := int64(r.Modulus[0])
	head := make([]uint64, ncols)
	for i := 0; i < ncols; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			head[i] = uint64(v + q)
		} else {
			head[i] = uint64(v)
		}
	}
	p := r.NewPoly()
	copy(p.Coeffs[0], Interpolate(omega, head, uint64(q)))
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
	return sampleChallengeVectorPreSignTest(r, 1, bound, bound, rng)
}

func sampleChallengeVectorPreSignTest(r *ring.Ring, x0Len int, x0Bound int64, r1Bound int64, rng *rand.Rand) preSignChallengeTest {
	sampleNTT := func(bound int64) *ring.Poly {
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
	ri0 := make([]*ring.Poly, x0Len)
	for i := range ri0 {
		ri0[i] = sampleNTT(x0Bound)
	}
	return preSignChallengeTest{
		RI0: ri0,
		RI1: []*ring.Poly{sampleNTT(r1Bound)},
	}
}

func prepareCommitPreSignTest(r *ring.Ring, Ac [][]*ring.Poly, in WitnessInputs, omega []uint64) ([]*ring.Poly, error) {
	return prepareCommitVectorPreSignTest(r, Ac, in, omega, 1, 1)
}

func TestDerivePreSignCarrierAndAliasRowsUsesSingletonX0Codec(t *testing.T) {
	root := credentialPreSignRepoRoot(t)
	credentialPreSignChdir(t, root)
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential: true,
		NCols:      16,
		LVCSNCols:  32,
		Ell:        18,
		NLeaves:    int(ringQ.N),
		DomainMode: DomainModeExplicit,
	})
	omega, err := preSignWitnessOmegaForRelationTest(ringQ, opts, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("derive omega: %v", err)
	}
	rng := rand.New(rand.NewSource(7))
	const (
		boundB  = int64(1)
		x0Bound = int64(5)
	)
	raw := PreSignRawRows{
		M1:  samplePackedHalfEvalPreSignTest(ringQ, boundB, omega, rng, true),
		M2:  samplePackedHalfEvalPreSignTest(ringQ, boundB, omega, rng, false),
		RU0: []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, x0Bound, omega, rng), sampleBoundedEvalPreSignTest(ringQ, x0Bound, omega, rng)},
		RU1: sampleBoundedEvalPreSignTest(ringQ, boundB, omega, rng),
		R:   sampleBoundedEvalPreSignTest(ringQ, boundB, omega, rng),
		R0:  []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, x0Bound, omega, rng), sampleBoundedEvalPreSignTest(ringQ, x0Bound, omega, rng)},
		R1:  sampleBoundedEvalPreSignTest(ringQ, boundB, omega, rng),
		K0:  []*ring.Poly{sampleBoundedEvalPreSignTest(ringQ, 1, omega, rng), sampleBoundedEvalPreSignTest(ringQ, 1, omega, rng)},
		K1:  sampleBoundedEvalPreSignTest(ringQ, 1, omega, rng),
	}
	surface, err := DerivePreSignCarrierAndAliasRows(ringQ, boundB, x0Bound, omega, DomainModeExplicit, raw)
	if err != nil {
		t.Fatalf("derive surface: %v", err)
	}
	q := ringQ.Modulus[0]
	headOnOmega := func(p *ring.Poly, name string) []uint64 {
		t.Helper()
		head, err := rowHeadOnOmega(ringQ, omega, p, len(omega))
		if err != nil {
			t.Fatalf("%s head on omega: %v", name, err)
		}
		return head
	}
	checkSingletonFamily := func(name string, rawRows, carrierRows, aliasRows []*ring.Poly, bound int64) {
		t.Helper()
		for i := range rawRows {
			rawHead := headOnOmega(rawRows[i], fmt.Sprintf("%s raw[%d]", name, i))
			carrierHead := headOnOmega(carrierRows[i], fmt.Sprintf("%s carrier[%d]", name, i))
			aliasHead := headOnOmega(aliasRows[i], fmt.Sprintf("%s alias[%d]", name, i))
			for col := range rawHead {
				code, err := encodeSingletonCarrier(centeredLift(rawHead[col], q), bound)
				if err != nil {
					t.Fatalf("%s[%d] encode col=%d: %v", name, i, col, err)
				}
				wantCarrier := liftToField(q, int64(code))
				if carrierHead[col] != wantCarrier {
					t.Fatalf("%s[%d] carrier col=%d got=%d want=%d", name, i, col, carrierHead[col], wantCarrier)
				}
				if aliasHead[col]%q != rawHead[col]%q {
					t.Fatalf("%s[%d] alias col=%d got=%d want raw=%d", name, i, col, aliasHead[col]%q, rawHead[col]%q)
				}
			}
		}
	}
	checkScalarPairSingleton := func(name string, rawRow, carrierRow, aliasRow *ring.Poly, bound int64) {
		t.Helper()
		rawHead := headOnOmega(rawRow, name+" raw")
		carrierHead := headOnOmega(carrierRow, name+" carrier")
		aliasHead := headOnOmega(aliasRow, name+" alias")
		for col := range rawHead {
			code, err := encodeCarrierPair(centeredLift(rawHead[col], q), 0, bound)
			if err != nil {
				t.Fatalf("%s encode col=%d: %v", name, col, err)
			}
			wantCarrier := liftToField(q, int64(code))
			if carrierHead[col] != wantCarrier {
				t.Fatalf("%s carrier col=%d got=%d want=%d", name, col, carrierHead[col], wantCarrier)
			}
			if aliasHead[col]%q != rawHead[col]%q {
				t.Fatalf("%s alias col=%d got=%d want raw=%d", name, col, aliasHead[col]%q, rawHead[col]%q)
			}
		}
	}
	checkSingletonFamily("RU0", raw.RU0, surface.CarrierRU0Rows, surface.AliasRU0Rows, x0Bound)
	checkSingletonFamily("R0", raw.R0, surface.CarrierR0Rows, surface.AliasR0Rows, x0Bound)
	checkSingletonFamily("K0", raw.K0, surface.CarrierK0Rows, surface.AliasK0Rows, 1)
	checkScalarPairSingleton("RU1", raw.RU1, surface.CarrierRU1, surface.AliasRU1, boundB)
	checkScalarPairSingleton("R1", raw.R1, surface.CarrierR1, surface.AliasR1, boundB)
	checkScalarPairSingleton("K1", raw.K1, surface.CarrierK1, surface.AliasK1, 1)
}

func prepareCommitVectorPreSignTest(r *ring.Ring, Ac [][]*ring.Poly, in WitnessInputs, omega []uint64, boundB int64, x0Bound int64) ([]*ring.Poly, error) {
	if len(omega) == 0 {
		return nil, fmt.Errorf("missing omega")
	}
	ncols := len(omega)
	q := r.Modulus[0]
	surface, err := DerivePreSignCarrierAndAliasRows(r, boundB, x0Bound, omega, DomainModeExplicit, PreSignRawRows{
		M1:  in.M1[0],
		M2:  in.M2[0],
		RU0: in.RU0,
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
	vec := make([][]uint64, 0, 2+len(surface.AliasRU0Coeffs)+2)
	vec = append(vec,
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasM1]),
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasM2]),
	)
	for i := range surface.AliasRU0Coeffs {
		vec = append(vec, headFromCoeffs(surface.AliasRU0Coeffs[i]))
	}
	vec = append(vec,
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasRU1]),
		headFromCoeffs(surface.AliasCoeffs[PreSignAliasR]),
	)
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
	q := int64(r.Modulus[0])
	centered := func(v uint64) int64 {
		x := int64(v % uint64(q))
		if x > q/2 {
			x -= q
		}
		return x
	}
	sumCarry := func(ruPoly, riPoly *ring.Poly, bound int64, ncols int) (*ring.Poly, *ring.Poly, error) {
		delta := int64(2*bound + 1)
		ruHead, err := rowHeadOnOmega(r, omega, ruPoly, ncols)
		if err != nil {
			return nil, nil, err
		}
		rHead := make([]uint64, ncols)
		kHead := make([]uint64, ncols)
		for i := 0; i < ncols; i++ {
			ruCoeff := centered(ruHead[i])
			riCoeff := centered(riPoly.Coeffs[0][i])
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
		rPoly := r.NewPoly()
		kPoly := r.NewPoly()
		copy(rPoly.Coeffs[0], Interpolate(omega, rHead, uint64(q)))
		copy(kPoly.Coeffs[0], Interpolate(omega, kHead, uint64(q)))
		return rPoly, kPoly, nil
	}
	ncols := len(omega)
	x0Len := p.X0Len
	if x0Len <= 0 {
		x0Len = len(in.RU0)
	}
	r0 := make([]*ring.Poly, x0Len)
	k0 := make([]*ring.Poly, x0Len)
	var err error
	for i := 0; i < x0Len; i++ {
		r0[i], k0[i], err = sumCarry(in.RU0[i], ch.RI0[i], p.X0CoeffBound, ncols)
		if err != nil {
			return nil, err
		}
	}
	r1, k1, err := sumCarry(in.RU1[0], ch.RI1[0], p.BoundB, ncols)
	if err != nil {
		return nil, err
	}

	B, err := loadBForPreSignTest(r, p.BPath)
	if err != nil {
		return nil, err
	}
	tCoeff, err := credential.HashMessageVector(r, B, p.HashRelation, in.M1[0], in.M2[0], r0, r1)
	if err != nil {
		return nil, err
	}
	var z []*ring.Poly
	if credential.NormalizeHashRelation(p.HashRelation) == credential.HashRelationBBTran {
		zCoeff, _, herr := credential.ComputeTargetVector(r, B, in.M1[0], in.M2[0], r0, r1)
		if herr != nil {
			return nil, herr
		}
		z = []*ring.Poly{zCoeff}
	}
	return &preSignStateTest{
		B:  B,
		R0: r0,
		R1: []*ring.Poly{r1},
		K0: k0,
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
