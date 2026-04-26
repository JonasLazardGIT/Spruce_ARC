package PIOP

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type transformBridgeFixture struct {
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
	prfCompanion *PRFCompanionLayout
	decsParams   decs.Params
	maskRowOff   int
	maskRowCount int
	witnessCount int
	root         [16]byte
}

type decsRowInput struct {
	Head       []uint64
	Tail       []uint64
	Poly       *ring.Poly
	PolyCoeffs []uint64
}

func transformBridgeRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func transformBridgeChdir(t *testing.T, dir string) {
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

func loadBAsNTTTest(r *ring.Ring, path string) ([]*ring.Poly, error) {
	if path == "" {
		return nil, fmt.Errorf("missing B path")
	}
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

func buildCoeffNativeShowingWitnessTest(r *ring.Ring, st credential.State, B []*ring.Poly, omega []uint64, boundB, x0Bound int64) (*CoeffNativeShowingWitness, error) {
	if len(st.SigS1) == 0 || len(st.SigS2) == 0 {
		return nil, fmt.Errorf("missing sig_s1/sig_s2 in credential state")
	}
	if len(st.Mu) == 0 || len(st.R0) == 0 || len(st.R1) == 0 || len(st.Z) == 0 {
		return nil, fmt.Errorf("missing semantic witness rows in credential state")
	}
	x0Len := st.X0Len
	if x0Len <= 0 {
		x0Len = len(st.R0)
	}
	if x0Len <= 0 {
		x0Len = 1
	}
	if len(st.R0) != x0Len {
		return nil, fmt.Errorf("credential state R0 len=%d want x0Len=%d", len(st.R0), x0Len)
	}
	if len(B) < 3+x0Len {
		return nil, fmt.Errorf("missing B matrix for target reconstruction")
	}
	packedNCols, err := ResolvePackedNCols(st.PackedNCols, 0, int(r.N))
	if err != nil {
		return nil, fmt.Errorf("resolve packed ncols: %w", err)
	}
	muPoly := polyFromInt64Test(r, st.Mu[0])
	targetMu, err := CanonicalMuAliasPoly(r, boundB, x0Bound, omega, muPoly)
	if err != nil {
		return nil, fmt.Errorf("derive canonical mu target row: %w", err)
	}
	r0Polys := make([]*ring.Poly, len(st.R0))
	for i := range st.R0 {
		r0Polys[i] = polyFromInt64Test(r, st.R0[i])
	}
	r1Poly := polyFromInt64Test(r, st.R1[0])
	zPoly := polyFromInt64Test(r, st.Z[0])
	_, tCoeffs, err := credential.ComputeTargetVectorFromMu(r, B, targetMu, r0Polys, r1Poly)
	if err != nil {
		return nil, fmt.Errorf("recompute target from credential state: %w", err)
	}
	tPoly := polyFromInt64Test(r, tCoeffs)
	wit := &CoeffNativeShowingWitness{
		Sig: []*ring.Poly{
			polyFromInt64Test(r, st.SigS1),
			polyFromInt64Test(r, st.SigS2),
		},
		Mu:          muPoly,
		R0:          r0Polys,
		R1:          r1Poly,
		Z:           zPoly,
		T:           tPoly,
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

func maxAbsFromRows(rows [][]int64) int64 {
	var max int64
	for _, row := range rows {
		for _, v := range row {
			if v < 0 {
				v = -v
			}
			if v > max {
				max = v
			}
		}
	}
	return max
}

func maxAbsFromOmegaRows(r *ring.Ring, omega []uint64, rows [][]int64) int64 {
	if r == nil {
		return 0
	}
	q := int64(r.Modulus[0])
	var max int64
	for _, row := range rows {
		p := polyFromInt64Test(r, row)
		head, err := rowHeadOnOmega(r, omega, p, len(omega))
		if err != nil {
			continue
		}
		for _, hv := range head {
			v := int64(hv % uint64(q))
			if v > q/2 {
				v -= q
			}
			if v < 0 {
				v = -v
			}
			if v > max {
				max = v
			}
		}
	}
	return max
}

func convertRowInputs(inputs []decsRowInput) []decsRowInput {
	out := make([]decsRowInput, len(inputs))
	copy(out, inputs)
	return out
}

func buildTransformBridgeFixtureWithReplayModeAndShortness(t *testing.T, replayMode ShowingReplayMode, sigShortnessProfile string, sigShortnessRadix int, sigShortnessDigits int, mutateOpts func(*SimOpts)) transformBridgeFixture {
	t.Helper()
	root := transformBridgeRepoRoot(t)
	transformBridgeChdir(t, root)

	state, err := credential.LoadState(filepath.Join(root, "credential", "keys", "credential_state.json"))
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	publicPath := state.CredentialPublicPath
	if publicPath == "" {
		publicPath = credential.DefaultPublicParamsPath
	}
	publicParams, err := credential.LoadPublicParams(publicPath)
	if err != nil {
		t.Fatalf("load credential public params: %v", err)
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
		NLeaves:             4096,
		PRFGroupRounds:      2,
		CoeffPacking:        true,
		CoeffNativeSigModel: CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:       ShowingPresetCustom,
		ShowingReplayMode:   replayMode,
		SigShortnessProfile: sigShortnessProfile,
		SigShortnessRadix:   sigShortnessRadix,
		SigShortnessL:       sigShortnessDigits,
		PostSignNLeaves:     4096,
		PRFNLeaves:          4096,
	}
	opts.LVCSNCols = 96
	opts.PostSignLVCSNCols = 96
	opts.PRFLVCSNCols = 96
	if mutateOpts != nil {
		mutateOpts(&opts)
	}
	opts.applyDefaults()
	opts.EnablePackedPRFWitnessRows = true
	opts.EnablePRFCompanion = true
	if normalizePRFCompanionMode(opts.PRFCompanionMode) == "" {
		opts.PRFCompanionMode = PRFCompanionModeOutputAudit
	}

	omegaLVCS, domainPoints, err := func() ([]uint64, []uint64, error) {
		_, _, ncols, err := loadParamsAndOmegaForRelation(opts, publicParams.HashRelation)
		if err != nil {
			return nil, nil, err
		}
		omegaFull, points, derr := deriveExplicitDomainForRelation(ringQ.Modulus[0], opts.NLeaves, opts.NCols, ncols, opts.Ell, publicParams.HashRelation)
		if derr != nil {
			return nil, nil, derr
		}
		return omegaFull, points, nil
	}()
	if err != nil {
		t.Fatalf("derive omega/domain: %v", err)
	}
	omegaWitness := append([]uint64(nil), omegaLVCS[:opts.NCols]...)

	B, err := loadBAsNTTTest(ringQ, publicParams.BPath)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	cnWit, err := buildCoeffNativeShowingWitnessTest(ringQ, state, B, omegaWitness, publicParams.BoundB, publicParams.X0CoeffBound)
	if err != nil {
		t.Fatalf("build coeff-native witness: %v", err)
	}
	wit := WitnessInputs{CoeffNativeShowing: cnWit}

	A, err := buildSignatureMatrixTest(ringQ, state, len(cnWit.Sig))
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	nonce, noncePublic := fixedNonceTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])

	dummyTagPublic := lanesFromElemsTest(make([]prf.Elem, params.LenTag), opts.NCols)
	pub := PublicInputs{
		A:                  A,
		B:                  B,
		Tag:                dummyTagPublic,
		Nonce:              noncePublic,
		BoundB:             publicParams.BoundB,
		X0Len:              publicParams.X0Len,
		X0CoeffBound:       publicParams.X0CoeffBound,
		TargetDim:          publicParams.TargetDim,
		TargetHidingLambda: publicParams.TargetHidingLambda,
		HashRelation:       publicParams.HashRelation,
	}

	rows, rowInputs, layout, prfLayout, prfCompanion, decsParams, maskRowOffset, maskRowCount, witnessCount, _, _, err := BuildCredentialRowsShowing(
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
	keyStart := int(ringQ.N) / 2
	keyBlock := keyStart / cnWit.PackedNCols
	keyCol := keyStart % cnWit.PackedNCols
	carrierMuRows := rowLayoutCarrierMuBlockRows(layout)
	if keyBlock < 0 || keyBlock >= len(carrierMuRows) {
		t.Fatalf("key block=%d outside carrier mu blocks=%d", keyBlock, len(carrierMuRows))
	}
	keyScalars, err := ExtractSignedPRFKeyScalarsFromSingletonCarrierWindowOnOmega(ringQ, rows[carrierMuRows[keyBlock]], omegaWitness, keyCol, params.LenKey, publicParams.BoundB)
	if err != nil {
		t.Fatalf("extract signed PRF key from carrier: %v", err)
	}
	key := make([]prf.Elem, len(keyScalars))
	for i := range keyScalars {
		key[i] = prf.Elem(liftToField(ringQ.Modulus[0], keyScalars[i]))
	}
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		t.Fatalf("compute tag: %v", err)
	}
	pub.Tag = lanesFromElemsTest(tag, opts.NCols)
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
			Tail:       append([]uint64(nil), rowInputs[i].Tail...),
			Poly:       rowInputs[i].Poly,
			PolyCoeffs: append([]uint64(nil), rowInputs[i].PolyCoeffs...),
		}
	}

	return transformBridgeFixture{
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
		prfCompanion: prfCompanion,
		decsParams:   decsParams,
		maskRowOff:   maskRowOffset,
		maskRowCount: maskRowCount,
		witnessCount: witnessCount,
		root:         rootHash,
	}
}

func buildTransformBridgeFixtureWithShortness(t *testing.T, sigShortnessProfile string, sigShortnessRadix int, sigShortnessDigits int) transformBridgeFixture {
	t.Helper()
	return buildTransformBridgeFixtureWithReplayModeAndShortness(t, ShowingReplayModeReduced, sigShortnessProfile, sigShortnessRadix, sigShortnessDigits, nil)
}

func buildTransformBridgeFixtureWithShortnessProfile(t *testing.T, sigShortnessProfile string) transformBridgeFixture {
	t.Helper()
	return buildTransformBridgeFixtureWithShortness(t, sigShortnessProfile, 0, 0)
}

func buildTransformBridgeFixture(t *testing.T) transformBridgeFixture {
	t.Helper()
	return buildTransformBridgeFixtureWithShortnessProfile(t, "")
}

func buildTransformBridgeFullFixture(t *testing.T) transformBridgeFixture {
	t.Helper()
	return buildTransformBridgeFixtureWithReplayModeAndShortness(t, ShowingReplayModeFull, "", 0, 0, nil)
}

func buildTransformBridgeFullAggregateR0Fixture(t *testing.T) transformBridgeFixture {
	t.Helper()
	return buildTransformBridgeFixtureWithReplayModeAndShortness(t, ShowingReplayModeFull, "", 0, 0, func(opts *SimOpts) {
		opts.AggregateR0Replay = true
	})
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

func assertConstraintBucketSumsToZeroOnOmega(t *testing.T, ringQ *ring.Ring, omega []uint64, bucket string, polys []*ring.Poly, coeffs [][]uint64) {
	t.Helper()
	if ringQ == nil {
		t.Fatalf("nil ring")
	}
	q := ringQ.Modulus[0]
	tmp := ringQ.NewPoly()
	for i := range polys {
		var coeffVals []uint64
		if i < len(coeffs) && len(coeffs[i]) > 0 {
			coeffVals = coeffs[i]
		} else if polys[i] != nil {
			ringQ.InvNTT(polys[i], tmp)
			coeffVals = append([]uint64(nil), tmp.Coeffs[0]...)
		}
		if len(coeffVals) == 0 {
			continue
		}
		sum := uint64(0)
		for _, w := range omega {
			sum = modAdd(sum, EvalPoly(coeffVals, w%q, q)%q, q)
		}
		if sum%q != 0 {
			t.Fatalf("%s[%d] omega-sum nonzero: %d", bucket, i, sum%q)
		}
	}
}

func bucketHasNonZeroOmegaSum(ringQ *ring.Ring, omega []uint64, polys []*ring.Poly, coeffs [][]uint64) (bool, error) {
	if ringQ == nil {
		return false, fmt.Errorf("nil ring")
	}
	q := ringQ.Modulus[0]
	tmp := ringQ.NewPoly()
	count := len(polys)
	if len(coeffs) > count {
		count = len(coeffs)
	}
	for i := 0; i < count; i++ {
		var coeffVals []uint64
		switch {
		case i < len(coeffs) && len(coeffs[i]) > 0:
			coeffVals = coeffs[i]
		case i < len(polys) && polys[i] != nil:
			ringQ.InvNTT(polys[i], tmp)
			coeffVals = append([]uint64(nil), tmp.Coeffs[0]...)
		default:
			continue
		}
		sum := uint64(0)
		for _, w := range omega {
			sum = modAdd(sum, EvalPoly(coeffVals, w%q, q)%q, q)
		}
		if sum%q != 0 {
			return true, nil
		}
	}
	return false, nil
}

func TestTransformBridgeConstraintFamiliesOnOmega(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestTransformBridgeConstraintFamiliesOnOmegaProductionShortnessProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFixtureWithShortnessProfile(t, SigShortnessProfileR11L4Production)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestTransformBridgeConstraintFamiliesOnOmegaFullReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestTransformBridgeConstraintFamiliesOnOmegaCustomBalanced75(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFixtureWithShortness(t, "", 7, 5)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestTransformBridgeFixtureOmegaVanishing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggInt", postSet.FaggInt, postSet.FaggIntCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestTransformBridgeReplaySurfaceUsesOnlyTHat0(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFixture(t)
	if got := rowLayoutReplayTHatCount(fx.layout); got != 1 {
		t.Fatalf("replay T-hat count=%d want 1", got)
	}
	if fx.layout.IdxTSource >= 0 {
		t.Fatalf("reduced replay should omit committed T source rows, got IdxTSource=%d", fx.layout.IdxTSource)
	}
	if fx.layout.IdxTHatBase < 0 {
		t.Fatalf("missing replay T-hat row")
	}
	if fx.layout.IdxSigHatBase >= 0 || fx.layout.SigHatExtraBase >= 0 {
		t.Fatalf("unexpected committed signature hats in final showing layout: %+v", fx.layout)
	}
}

func TestTransformBridgeTamperedTHat0BreaksHashResidual(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFixture(t)
	tamperedRowsNTT := make([]*ring.Poly, len(fx.rowsNTT))
	for i := range fx.rowsNTT {
		if fx.rowsNTT[i] == nil {
			continue
		}
		tamperedRowsNTT[i] = fx.ringQ.NewPoly()
		ring.Copy(fx.rowsNTT[i], tamperedRowsNTT[i])
	}
	q := fx.ringQ.Modulus[0]
	tamperedRowsNTT[fx.layout.IdxTHatBase].Coeffs[0][0] = modAdd(tamperedRowsNTT[fx.layout.IdxTHatBase].Coeffs[0][0], 1, q)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, tamperedRowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	nonZero, err := bucketHasNonZeroOmegaSum(fx.ringQ, fx.omegaWitness, postSet.FparInt, postSet.FparIntCoeffs)
	if err != nil {
		t.Fatalf("check tampered hash residual: %v", err)
	}
	if !nonZero {
		t.Fatal("tampered THat0 left all parallel hash residual families satisfied")
	}
}

func TestTransformBridgeTamperedFullHiddenTBreaksSourceBridge(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	tamperedRowsNTT := make([]*ring.Poly, len(fx.rowsNTT))
	for i := range fx.rowsNTT {
		if fx.rowsNTT[i] == nil {
			continue
		}
		tamperedRowsNTT[i] = fx.ringQ.NewPoly()
		ring.Copy(fx.rowsNTT[i], tamperedRowsNTT[i])
	}
	q := fx.ringQ.Modulus[0]
	idx := rowLayoutPostSignTHatIndex(fx.layout, 0)
	if idx < 0 {
		t.Fatalf("missing full replay T-hat row 0")
	}
	tamperedRowsNTT[idx].Coeffs[0][0] = modAdd(tamperedRowsNTT[idx].Coeffs[0][0], 1, q)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, tamperedRowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	nonZero, err := bucketHasNonZeroOmegaSum(fx.ringQ, fx.omegaWitness, postSet.FparInt, postSet.FparIntCoeffs)
	if err != nil {
		t.Fatalf("check tampered full T-hat residual: %v", err)
	}
	if !nonZero {
		t.Fatal("tampered hidden T left all parallel replay families satisfied")
	}
}

func TestTransformBridgeFullReplaySurfaceUsesAllBlocks(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	if got, want := rowLayoutReplayBlockCount(fx.layout), fx.layout.SigBlocks; got != want {
		t.Fatalf("replay block count=%d want %d", got, want)
	}
	if got, want := rowLayoutReplayTHatCount(fx.layout), fx.layout.SigBlocks; got != want {
		t.Fatalf("replay T-hat count=%d want %d", got, want)
	}
	if fx.layout.IdxMHatSigma < 0 || fx.layout.IdxRHat0 < 0 || fx.layout.IdxRHat1 < 0 || fx.layout.IdxTHatBase < 0 {
		t.Fatalf("missing full replay family base indices: %+v", fx.layout)
	}
	if fx.layout.IdxTSource >= 0 {
		t.Fatalf("full replay should derive T source rows locally")
	}
}

func TestTransformBridgeFullAggregateR0ReplaySurface(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullAggregateR0Fixture(t)
	if got, want := len(rowLayoutPostSignR0B2HatRows(fx.layout)), rowLayoutReplayBlockCount(fx.layout); got != want {
		t.Fatalf("aggregate R0-B2 rows=%d want replay blocks=%d", got, want)
	}
	if got := len(rowLayoutPostSignRHat0Rows(fx.layout)); got != 0 {
		t.Fatalf("aggregate R0 replay should omit per-component R-hat0 rows, got %d", got)
	}
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild aggregate transform-bridge post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "aggregate FparInt", postSet.FparInt, postSet.FparIntCoeffs)
	assertConstraintBucketSumsToZeroOnOmega(t, fx.ringQ, fx.omegaWitness, "aggregate FaggNorm", postSet.FaggNorm, postSet.FaggNormCoeffs)
}

func TestTransformBridgeTamperedFullRHatBreaksBridge(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	tamperedRowsNTT := make([]*ring.Poly, len(fx.rowsNTT))
	for i := range fx.rowsNTT {
		if fx.rowsNTT[i] == nil {
			continue
		}
		tamperedRowsNTT[i] = fx.ringQ.NewPoly()
		ring.Copy(fx.rowsNTT[i], tamperedRowsNTT[i])
	}
	q := fx.ringQ.Modulus[0]
	idx := rowLayoutPostSignRHat1Index(fx.layout, 1)
	if idx < 0 {
		t.Fatalf("missing replay R1 block 1")
	}
	tamperedRowsNTT[idx].Coeffs[0][0] = modAdd(tamperedRowsNTT[idx].Coeffs[0][0], 1, q)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, tamperedRowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	nonZero, err := bucketHasNonZeroOmegaSum(fx.ringQ, fx.omegaWitness, postSet.FaggNorm, postSet.FaggNormCoeffs)
	if err != nil {
		t.Fatalf("check tampered full replay bridge: %v", err)
	}
	if !nonZero {
		t.Fatal("tampered full replay R1 block left all aggregated bridge families satisfied")
	}
}

func TestTransformBridgeTamperedFullZHatBreaksTargetAndInverse(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	tamperedRowsNTT := make([]*ring.Poly, len(fx.rowsNTT))
	for i := range fx.rowsNTT {
		if fx.rowsNTT[i] == nil {
			continue
		}
		tamperedRowsNTT[i] = fx.ringQ.NewPoly()
		ring.Copy(fx.rowsNTT[i], tamperedRowsNTT[i])
	}
	q := fx.ringQ.Modulus[0]
	idx := rowLayoutPostSignZHatIndex(fx.layout, 1)
	if idx < 0 {
		t.Fatalf("missing replay Z-hat block 1")
	}
	tamperedRowsNTT[idx].Coeffs[0][0] = modAdd(tamperedRowsNTT[idx].Coeffs[0][0], 1, q)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, tamperedRowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	nonZero, err := bucketHasNonZeroOmegaSum(fx.ringQ, fx.omegaWitness, postSet.FparInt, postSet.FparIntCoeffs)
	if err != nil {
		t.Fatalf("check tampered full Z-hat residual: %v", err)
	}
	if !nonZero {
		t.Fatal("tampered full replay Z-hat left all target/inverse families satisfied")
	}
}

func TestTransformBridgeTamperedFullAggregateR0BreaksBridge(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullAggregateR0Fixture(t)
	tamperedRowsNTT := make([]*ring.Poly, len(fx.rowsNTT))
	for i := range fx.rowsNTT {
		if fx.rowsNTT[i] == nil {
			continue
		}
		tamperedRowsNTT[i] = fx.ringQ.NewPoly()
		ring.Copy(fx.rowsNTT[i], tamperedRowsNTT[i])
	}
	q := fx.ringQ.Modulus[0]
	idx := rowLayoutPostSignR0B2HatIndex(fx.layout, 1)
	if idx < 0 {
		t.Fatalf("missing aggregate R0-B2 replay block 1")
	}
	tamperedRowsNTT[idx].Coeffs[0][0] = modAdd(tamperedRowsNTT[idx].Coeffs[0][0], 1, q)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, tamperedRowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild aggregate transform-bridge post-sign set: %v", err)
	}
	nonZero, err := bucketHasNonZeroOmegaSum(fx.ringQ, fx.omegaWitness, postSet.FaggNorm, postSet.FaggNormCoeffs)
	if err != nil {
		t.Fatalf("check tampered aggregate R0-B2 bridge: %v", err)
	}
	if !nonZero {
		t.Fatal("tampered aggregate R0-B2 replay row left all aggregate bridge families satisfied")
	}
}

func cloneCoeffNativeShowingWitnessForTailTest(ringQ *ring.Ring, src *CoeffNativeShowingWitness) *CoeffNativeShowingWitness {
	clonePoly := func(p *ring.Poly) *ring.Poly {
		if p == nil {
			return nil
		}
		out := ringQ.NewPoly()
		ring.Copy(p, out)
		return out
	}
	out := *src
	out.Sig = make([]*ring.Poly, len(src.Sig))
	for i, p := range src.Sig {
		out.Sig[i] = clonePoly(p)
	}
	out.Mu = clonePoly(src.Mu)
	out.M1 = clonePoly(src.M1)
	out.M2 = clonePoly(src.M2)
	out.R0 = make([]*ring.Poly, len(src.R0))
	for i, p := range src.R0 {
		out.R0[i] = clonePoly(p)
	}
	out.R1 = clonePoly(src.R1)
	out.Z = clonePoly(src.Z)
	out.T = clonePoly(src.T)
	return &out
}

func TestTransformBridgeFullReplayRejectsNonSignTailLeakage(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	q := fx.ringQ.Modulus[0]
	tailIdx := len(fx.omegaWitness)
	cases := []struct {
		name   string
		mutate func(*CoeffNativeShowingWitness)
	}{}
	if len(fx.wit.CoeffNativeShowing.R0) > 1 {
		cases = append(cases, struct {
			name   string
			mutate func(*CoeffNativeShowingWitness)
		}{
			name: "R0[1]",
			mutate: func(cn *CoeffNativeShowingWitness) {
				cn.R0[1].Coeffs[0][tailIdx] = 1 % q
			},
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cn := cloneCoeffNativeShowingWitnessForTailTest(fx.ringQ, fx.wit.CoeffNativeShowing)
			tc.mutate(cn)
			wit := fx.wit
			wit.CoeffNativeShowing = cn
			_, _, _, _, _, _, _, _, _, _, _, err := BuildCredentialRowsShowing(
				fx.ringQ,
				fx.pub,
				wit,
				fx.prfCompanion.KeyCount,
				len(fx.pub.Nonce),
				0,
				0,
				fx.opts.PRFGroupRounds,
				fx.opts,
			)
			if err == nil {
				t.Fatal("expected full replay mode to reject non-sign tail leakage")
			}
		})
	}
}

func TestTransformBridgeQPrefixZero(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
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

func TestTransformBridgeCombinedReplayDebug(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	set := ConstraintSet{
		FparInt:            append([]*ring.Poly{}, postSet.FparInt...),
		FparIntCoeffs:      append([][]uint64{}, postSet.FparIntCoeffs...),
		FparNorm:           postSet.FparNorm,
		FparNormCoeffs:     postSet.FparNormCoeffs,
		FaggInt:            postSet.FaggInt,
		FaggIntCoeffs:      postSet.FaggIntCoeffs,
		FaggNorm:           postSet.FaggNorm,
		FaggNormCoeffs:     postSet.FaggNormCoeffs,
		ParallelAlgDeg:     postSet.ParallelAlgDeg,
		AggregatedAlgDeg:   postSet.AggregatedAlgDeg,
		PRFLayout:          fx.prfLayout,
		PRFCompanionLayout: fx.prfCompanion,
	}
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	ok, err := VerifyWithConstraints(proof, set, fx.pub, fx.opts, FSModeCredential)
	if err != nil {
		t.Fatalf("verify with built set: %v", err)
	}
	if !ok {
		t.Fatalf("verify with built set returned false")
	}
}

func TestTransformBridgeCombinedReplayDebugFull(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, fx.ringQ, fx.omegaWitness, "FparNorm", postSet.FparNorm, postSet.FparNormCoeffs)
	set := ConstraintSet{
		FparInt:            append([]*ring.Poly{}, postSet.FparInt...),
		FparIntCoeffs:      append([][]uint64{}, postSet.FparIntCoeffs...),
		FparNorm:           postSet.FparNorm,
		FparNormCoeffs:     postSet.FparNormCoeffs,
		FaggInt:            postSet.FaggInt,
		FaggIntCoeffs:      postSet.FaggIntCoeffs,
		FaggNorm:           postSet.FaggNorm,
		FaggNormCoeffs:     postSet.FaggNormCoeffs,
		ParallelAlgDeg:     postSet.ParallelAlgDeg,
		AggregatedAlgDeg:   postSet.AggregatedAlgDeg,
		PRFLayout:          fx.prfLayout,
		PRFCompanionLayout: fx.prfCompanion,
	}
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	if proof.SourceProductBridge != nil {
		t.Fatalf("full replay proof should not carry source-product bridge: %+v", proof.SourceProductBridge)
	}
	ok, err := VerifyWithConstraints(proof, set, fx.pub, fx.opts, FSModeCredential)
	if err != nil {
		t.Fatalf("verify full replay with rebuilt set: %v", err)
	}
	if !ok {
		t.Fatalf("verify full replay with rebuilt set returned false")
	}
}

func TestTransformBridgeFullReplayKEvaluatorMatchesCoeffs(t *testing.T) {
	if testing.Short() {
		t.Skip("integration-like fixture")
	}
	fx := buildTransformBridgeFullFixture(t)
	postSet, err := rebuildPostSignConstraintSetWithBridges(fx.ringQ, fx.pub, fx.layout, fx.rowsNTT, fx.omegaWitness, fx.opts, fx.root, fx.prfLayout, fx.prfCompanion)
	if err != nil {
		t.Fatalf("rebuild transform-bridge post-sign set: %v", err)
	}
	proof, err := BuildShowingCombined(fx.pub, fx.wit, fx.opts)
	if err != nil {
		t.Fatalf("build showing combined: %v", err)
	}
	cfg, err := newTransformBridgePostSignConfig(fx.ringQ, proof, fx.pub, fx.layout, fx.omegaWitness, fx.domainPoints, fx.pub.BoundB, fx.prfLayout, fx.prfCompanion, fx.opts)
	if err != nil {
		t.Fatalf("build transform-bridge config: %v", err)
	}
	sf, err := deriveSmallFieldParamsNoRows(fx.ringQ, fx.omegaWitness, fx.opts.Theta)
	if err != nil {
		t.Fatalf("derive small field: %v", err)
	}
	ek, err := cfg.CoreKEvaluator(sf.K)
	if err != nil {
		t.Fatalf("transform-bridge K evaluator: %v", err)
	}
	limbs := []uint64{2, 3, 5, 7, 11, 13}
	if len(limbs) > fx.opts.Theta {
		limbs = limbs[:fx.opts.Theta]
	}
	for len(limbs) < fx.opts.Theta {
		limbs = append(limbs, uint64(len(limbs)+17))
	}
	point := sf.K.Phi(limbs)
	rowsK := make([]kf.Elem, len(fx.rows))
	for rowIdx := range fx.rows {
		rowsK[rowIdx] = sf.K.EvalFPolyAtK(fx.rows[rowIdx].Coeffs[0], point)
	}
	_, fagg, err := ek(point, rowsK)
	if err != nil {
		t.Fatalf("evaluate transform-bridge K families: %v", err)
	}
	if len(fagg) != len(postSet.FaggNormCoeffs) {
		t.Fatalf("fagg len=%d want %d", len(fagg), len(postSet.FaggNormCoeffs))
	}
	for i := range fagg {
		want := sf.K.EvalFPolyAtK(postSet.FaggNormCoeffs[i], point)
		if !elemEqual(sf.K, fagg[i], want) {
			t.Fatalf("full replay K evaluator mismatch at family %d", i)
		}
	}
}
