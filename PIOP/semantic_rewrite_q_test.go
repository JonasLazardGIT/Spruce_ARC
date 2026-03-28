package PIOP

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/credential"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type semanticRewriteFixture struct {
	ringQ        *ring.Ring
	pub          PublicInputs
	wit          WitnessInputs
	opts         SimOpts
	omegaWitness []uint64
	domainPoints []uint64
	rows         []*ring.Poly
	rowsNTT      []*ring.Poly
	rowInputs    []decsRowInput
	layout       RowLayout
	prfLayout    *PRFLayout
	decsParams   decs.Params
	maskRowOff   int
	maskRowCount int
	witnessCount int
	root         [16]byte
}

type decsRowInput struct {
	Head       []uint64
	Poly       *ring.Poly
	PolyCoeffs []uint64
}

func semanticRewriteRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func semanticRewriteChdir(t *testing.T, dir string) {
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

func polyFromInt64Test(r *ring.Ring, coeffs []int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	for i := 0; i < len(coeffs) && i < len(p.Coeffs[0]); i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func loadBFromStateTest(r *ring.Ring, st credential.State) ([]*ring.Poly, error) {
	if len(st.B) > 0 {
		out := make([]*ring.Poly, len(st.B))
		for i := range st.B {
			out[i] = polyFromInt64Test(r, st.B[i])
			r.NTT(out[i], out[i])
		}
		return out, nil
	}
	if st.BPath == "" {
		return nil, fmt.Errorf("missing B in state")
	}
	coeffs, err := ntrurio.LoadBMatrixCoeffs(st.BPath)
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

func buildSignatureMatrixTest(r *ring.Ring, st credential.State, uCount int) ([][]*ring.Poly, error) {
	if len(st.NTRUPublic) == 0 {
		pk, err := keys.LoadPublic()
		if err != nil {
			return nil, fmt.Errorf("load public key: %w", err)
		}
		st.NTRUPublic = [][]int64{pk.HCoeffs}
	}
	if uCount <= 1 {
		one := r.NewPoly()
		one.Coeffs[0][0] = 1 % r.Modulus[0]
		r.NTT(one, one)
		return [][]*ring.Poly{{one}}, nil
	}
	hNTT := polyFromInt64Test(r, st.NTRUPublic[0])
	r.NTT(hNTT, hNTT)
	negHNTT := r.NewPoly()
	r.Neg(hNTT, negHNTT)
	one := r.NewPoly()
	one.Coeffs[0][0] = 1 % r.Modulus[0]
	r.NTT(one, one)
	return [][]*ring.Poly{{negHNTT, one}}, nil
}

func buildCoeffNativeShowingWitnessTest(r *ring.Ring, st credential.State) (*CoeffNativeShowingWitness, error) {
	if len(st.SigS1) == 0 || len(st.SigS2) == 0 {
		return nil, fmt.Errorf("missing sig_s1/sig_s2 in credential state")
	}
	if len(st.M1) == 0 || len(st.M2) == 0 || len(st.R0) == 0 || len(st.R1) == 0 || len(st.T) == 0 {
		return nil, fmt.Errorf("missing signed base rows in credential state")
	}
	legacyNCols := 0
	if st.CoeffNativeShowing != nil {
		legacyNCols = st.CoeffNativeShowing.NCols
	}
	packedNCols, err := ResolvePackedNCols(st.PackedNCols, legacyNCols, int(r.N))
	if err != nil {
		return nil, fmt.Errorf("resolve packed ncols: %w", err)
	}
	wit := &CoeffNativeShowingWitness{
		Sig: []*ring.Poly{
			polyFromInt64Test(r, st.SigS1),
			polyFromInt64Test(r, st.SigS2),
		},
		M1:          polyFromInt64Test(r, st.M1[0]),
		M2:          polyFromInt64Test(r, st.M2[0]),
		R0:          polyFromInt64Test(r, st.R0[0]),
		R1:          polyFromInt64Test(r, st.R1[0]),
		T:           polyFromInt64Test(r, st.T),
		PackedNCols: packedNCols,
	}
	if err := wit.Validate(int(r.N)); err != nil {
		return nil, fmt.Errorf("invalid coeff-native showing witness: %w", err)
	}
	return wit, nil
}

func constLaneTest(ncols int, v int64) []int64 {
	out := make([]int64, ncols)
	for i := range out {
		out[i] = v
	}
	return out
}

func fixedNonceTest(lenNonce, ncols int, q uint64) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lenNonce)
	public := make([][]int64, lenNonce)
	for i := 0; i < lenNonce; i++ {
		v := uint64(i+1) % q
		nonce[i] = prf.Elem(v)
		public[i] = constLaneTest(ncols, int64(v))
	}
	return nonce, public
}

func elemsToPolysTest(r *ring.Ring, elems []prf.Elem) []*ring.Poly {
	rows := make([]*ring.Poly, len(elems))
	for i, v := range elems {
		pNTT := r.NewPoly()
		for j := 0; j < r.N; j++ {
			pNTT.Coeffs[0][j] = uint64(v) % r.Modulus[0]
		}
		rows[i] = r.NewPoly()
		r.InvNTT(pNTT, rows[i])
	}
	return rows
}

func lanesFromElemsTest(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = constLaneTest(ncols, int64(v))
	}
	return out
}

func convertRowInputs(inputs []decsRowInput) []decsRowInput {
	out := make([]decsRowInput, len(inputs))
	copy(out, inputs)
	return out
}

func buildSemanticRewriteFixtureWithShortness(t *testing.T, sigShortnessProfile string, sigShortnessRadix int, sigShortnessDigits int) semanticRewriteFixture {
	t.Helper()
	root := semanticRewriteRepoRoot(t)
	semanticRewriteChdir(t, root)

	state, err := credential.LoadState(filepath.Join(root, "credential", "keys", "credential_state.json"))
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	params, err := prf.LoadLocalOrDefaultParams(filepath.Join(root, "prf", "prf_params.json"))
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	opts := SimOpts{
		Credential:          true,
		Theta:               6,
		EllPrime:            2,
		Rho:                 2,
		NCols:               16,
		Ell:                 18,
		Eta:                 31,
		DomainMode:          DomainModeExplicit,
		NLeaves:             2048,
		PRFGroupRounds:      2,
		CoeffPacking:        true,
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:       ShowingPresetTranscriptFirst,
		SigShortnessProfile: sigShortnessProfile,
		SigShortnessRadix:   sigShortnessRadix,
		SigShortnessL:       sigShortnessDigits,
		PostSignNLeaves:     2048,
		PRFNLeaves:          2048,
	}
	opts.applyDefaults()

	omegaLVCS, domainPoints, err := func() ([]uint64, []uint64, error) {
		_, _, ncols, err := loadParamsAndOmega(opts)
		if err != nil {
			return nil, nil, err
		}
		omegaFull, points, derr := deriveExplicitDomain(ringQ.Modulus[0], opts.NLeaves, ncols, opts.Ell)
		if derr != nil {
			return nil, nil, derr
		}
		return omegaFull, points, nil
	}()
	if err != nil {
		t.Fatalf("derive omega/domain: %v", err)
	}
	omegaWitness := append([]uint64(nil), omegaLVCS[:opts.NCols]...)

	cnWit, err := buildCoeffNativeShowingWitnessTest(ringQ, state)
	if err != nil {
		t.Fatalf("build coeff-native witness: %v", err)
	}
	wit := WitnessInputs{CoeffNativeShowing: cnWit}

	A, err := buildSignatureMatrixTest(ringQ, state, len(cnWit.Sig))
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	B, err := loadBFromStateTest(ringQ, state)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	key, err := ExtractSignedPRFKeyElems(ringQ, cnWit.M2, cnWit.PackedNCols, params.LenKey)
	if err != nil {
		t.Fatalf("extract signed PRF key: %v", err)
	}
	nonce, noncePublic := fixedNonceTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		t.Fatalf("compute tag: %v", err)
	}
	tagPublic := lanesFromElemsTest(tag, opts.NCols)
	x0, err := prf.ConcatKeyNonce(key, nonce, params)
	if err != nil {
		t.Fatalf("concat key/nonce: %v", err)
	}
	sboxes, _, err := prf.TraceSBoxOutputsGrouped(x0, params, opts.PRFGroupRounds)
	if err != nil {
		t.Fatalf("trace grouped sboxes: %v", err)
	}
	wit.Extras = map[string]interface{}{
		"prf_sbox": elemsToPolysTest(ringQ, sboxes),
	}

	pub := PublicInputs{
		A:      A,
		B:      B,
		T:      append([]int64(nil), state.T...),
		Tag:    tagPublic,
		Nonce:  noncePublic,
		BoundB: 8,
	}

	rows, rowInputs, layout, prfLayout, _, decsParams, maskRowOffset, maskRowCount, witnessCount, _, _, err := BuildCredentialRowsShowing(
		ringQ,
		pub,
		wit,
		params.LenKey,
		params.LenNonce,
		params.RF,
		params.RP,
		opts.PRFGroupRounds,
		opts,
	)
	if err != nil {
		t.Fatalf("build showing rows: %v", err)
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	rootHash, _, _, err := commitRows(ringQ, rowInputs, opts.Ell, decsParams, witnessCount, maskRowOffset, maskRowCount, domainPoints)
	if err != nil {
		t.Fatalf("commit rows: %v", err)
	}

	outInputs := make([]decsRowInput, len(rowInputs))
	for i := range rowInputs {
		outInputs[i] = decsRowInput{
			Head:       append([]uint64(nil), rowInputs[i].Head...),
			Poly:       rowInputs[i].Poly,
			PolyCoeffs: append([]uint64(nil), rowInputs[i].PolyCoeffs...),
		}
	}

	return semanticRewriteFixture{
		ringQ:        ringQ,
		pub:          pub,
		wit:          wit,
		opts:         opts,
		omegaWitness: omegaWitness,
		domainPoints: domainPoints,
		rows:         rows,
		rowsNTT:      rowsNTT,
		rowInputs:    outInputs,
		layout:       layout,
		prfLayout:    prfLayout,
		decsParams:   decsParams,
		maskRowOff:   maskRowOffset,
		maskRowCount: maskRowCount,
		witnessCount: witnessCount,
		root:         rootHash,
	}
}

func buildSemanticRewriteFixtureWithShortnessProfile(t *testing.T, sigShortnessProfile string) semanticRewriteFixture {
	t.Helper()
	return buildSemanticRewriteFixtureWithShortness(t, sigShortnessProfile, 0, 0)
}

func buildSemanticRewriteFixture(t *testing.T) semanticRewriteFixture {
	t.Helper()
	return buildSemanticRewriteFixtureWithShortnessProfile(t, "")
}

func evalPolyOnOmegaTest(ringQ *ring.Ring, omega []uint64, poly *ring.Poly) ([]uint64, error) {
	if poly == nil {
		return nil, nil
	}
	coeffs, err := coeffFromNTTPoly(ringQ, poly)
	if err != nil {
		return nil, err
	}
	return evalCoeffOnOmegaTest(coeffs, omega, ringQ.Modulus[0]), nil
}

func evalCoeffOnOmegaTest(coeffs []uint64, omega []uint64, q uint64) []uint64 {
	if len(coeffs) == 0 {
		return make([]uint64, len(omega))
	}
	out := make([]uint64, len(omega))
	for i, w := range omega {
		out[i] = EvalPoly(coeffs, w%q, q) % q
	}
	return out
}

func assertConstraintBucketVanishesOnOmega(t *testing.T, ringQ *ring.Ring, omega []uint64, bucket string, polys []*ring.Poly, coeffs [][]uint64) {
	t.Helper()
	count := len(polys)
	if len(coeffs) > count {
		count = len(coeffs)
	}
	q := ringQ.Modulus[0]
	for i := 0; i < count; i++ {
		var (
			polyVals  []uint64
			coeffVals []uint64
			err       error
		)
		if i < len(polys) && polys[i] != nil {
			polyVals, err = evalPolyOnOmegaTest(ringQ, omega, polys[i])
			if err != nil {
				t.Fatalf("%s[%d] eval poly: %v", bucket, i, err)
			}
		}
		if i < len(coeffs) && len(coeffs[i]) > 0 {
			coeffVals = evalCoeffOnOmegaTest(coeffs[i], omega, q)
		}
		if len(polyVals) > 0 && len(coeffVals) > 0 {
			if len(polyVals) != len(coeffVals) {
				t.Fatalf("%s[%d] poly/coeff eval length mismatch: %d vs %d", bucket, i, len(polyVals), len(coeffVals))
			}
			for j := range polyVals {
				if polyVals[j] != coeffVals[j] {
					t.Fatalf("%s[%d] poly_coeff_disagree at omega[%d]: poly=%d coeff=%d", bucket, i, j, polyVals[j], coeffVals[j])
				}
			}
		}
		actual := coeffVals
		if len(actual) == 0 {
			actual = polyVals
		}
		for j, v := range actual {
			if v%q != 0 {
				t.Fatalf("%s[%d] nonzero_on_omega at omega[%d]=%d", bucket, i, j, v%q)
			}
		}
	}
}

func TestSemanticRewriteConstraintFamiliesOnOmega(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildSemanticRewriteFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root)
	if err != nil {
		t.Fatalf("rebuild semantic post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestSemanticRewriteConstraintFamiliesOnOmegaLegacyShortnessProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildSemanticRewriteFixtureWithShortnessProfile(t, SigShortnessProfileR13L3Legacy)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root)
	if err != nil {
		t.Fatalf("rebuild semantic post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestSemanticRewriteConstraintFamiliesOnOmegaExperimentalShortnessProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildSemanticRewriteFixtureWithShortnessProfile(t, SigShortnessProfileR7L4Experimental)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root)
	if err != nil {
		t.Fatalf("rebuild semantic post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestSemanticRewriteConstraintFamiliesOnOmegaCustomBalanced55(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildSemanticRewriteFixtureWithShortness(t, "", 5, 5)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root)
	if err != nil {
		t.Fatalf("rebuild semantic post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestSemanticRewriteQPrefixZero(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildSemanticRewriteFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root)
	if err != nil {
		t.Fatalf("rebuild semantic post-sign set: %v", err)
	}
	totalParallel := len(postSet.FparInt) + len(postSet.FparNorm)
	totalAgg := len(postSet.FaggInt) + len(postSet.FaggNorm)
	gammaPrime := make([][][]uint64, fx.opts.Rho)
	gammaAgg := make([][]uint64, fx.opts.Rho)
	for i := 0; i < fx.opts.Rho; i++ {
		gammaPrime[i] = make([][]uint64, totalParallel)
		for j := 0; j < totalParallel; j++ {
			gammaPrime[i][j] = []uint64{1}
		}
		gammaAgg[i] = make([]uint64, totalAgg)
		for j := 0; j < totalAgg; j++ {
			gammaAgg[i][j] = 1
		}
	}
	zeroMasks := make([][]uint64, fx.opts.Rho)
	for i := 0; i < fx.opts.Rho; i++ {
		zeroMasks[i] = []uint64{0}
	}
	qCoeffs, err := BuildQCoeffsChecked(
		fx.ringQ,
		BuildQLayout{MaskCoeffs: zeroMasks},
		postSet.FparInt,
		postSet.FparNorm,
		postSet.FaggInt,
		postSet.FaggNorm,
		postSet.FparIntCoeffs,
		postSet.FparNormCoeffs,
		postSet.FaggIntCoeffs,
		postSet.FaggNormCoeffs,
		gammaPrime,
		gammaAgg,
	)
	if err != nil {
		t.Fatalf("build Q coeffs: %v", err)
	}
	q := fx.ringQ.Modulus[0]
	for rowIdx, coeffs := range qCoeffs {
		sum := uint64(0)
		for _, w := range fx.omegaWitness {
			sum = modAdd(sum, EvalPoly(coeffs, w%q, q)%q, q)
		}
		if sum != 0 {
			t.Fatalf("Q row %d has non-zero SigmaOmega sum=%d", rowIdx, sum)
		}
	}
}

func TestSemanticRewriteCombinedReplayDebug(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildSemanticRewriteFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root)
	if err != nil {
		t.Fatalf("rebuild semantic post-sign set: %v", err)
	}
	set := ConstraintSet{
		FparInt:          append([]*ring.Poly{}, postSet.FparInt...),
		FparIntCoeffs:    append([][]uint64{}, postSet.FparIntCoeffs...),
		FparNorm:         postSet.FparNorm,
		FparNormCoeffs:   postSet.FparNormCoeffs,
		FaggInt:          postSet.FaggInt,
		FaggIntCoeffs:    postSet.FaggIntCoeffs,
		FaggNorm:         postSet.FaggNorm,
		FaggNormCoeffs:   postSet.FaggNormCoeffs,
		ParallelAlgDeg:   postSet.ParallelAlgDeg,
		AggregatedAlgDeg: postSet.AggregatedAlgDeg,
	}
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	prev := os.Getenv("PIOP_DEBUG_EQ4_K")
	if err := os.Setenv("PIOP_DEBUG_EQ4_K", "1"); err != nil {
		t.Fatalf("set debug env: %v", err)
	}
	defer func() {
		_ = os.Setenv("PIOP_DEBUG_EQ4_K", prev)
	}()
	ok, err := VerifyWithConstraints(proof, set, fx.pub, fx.opts, FSModeCredential)
	if err != nil {
		t.Fatalf("verify with built set: %v", err)
	}
	if !ok {
		t.Fatalf("verify with built set returned false")
	}
}
