package PIOP

import (
	"path/filepath"
	"strings"
	"testing"

	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestIntGenISISShowingProofBuildsAndVerifies(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	profile := credential.PrimaryIntGenISISProfile()
	ringQ, err := credential.LoadRingWithDegree(profile.N)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	params, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:        true,
		CoeffPacking:      true,
		RingDegree:        profile.N,
		NCols:             16,
		LVCSNCols:         32,
		PostSignLVCSNCols: 32,
		PRFLVCSNCols:      32,
		Ell:               4,
		Eta:               8,
		Rho:               1,
		Theta:             1,
		DomainMode:        DomainModeExplicit,
		NLeaves:           4096,
		PRFGroupRounds:    2,
		PRFCompanionMode:  PRFCompanionModeDirectFull,
	})

	layout, err := credential.DefaultSemanticMessageLayout(profile, params.LenKey)
	if err != nil {
		t.Fatalf("semantic layout: %v", err)
	}
	msg, err := credential.EncodeSemanticMessage(layout, credential.ZeroSemanticAttributes(layout), []int64{1, 0, -1, 1, 0, -1, 1, 0})
	if err != nil {
		t.Fatalf("encode semantic message: %v", err)
	}
	MRows := polysFromInt64ForIntGenISISTest(ringQ, msg.M)
	MAttrRows := polysFromInt64ForIntGenISISTest(ringQ, msg.MAttr)
	KRows := polysFromInt64ForIntGenISISTest(ringQ, msg.K)
	M := MRows[0]
	key, err := extractIntGenISISPRFKeyElemsFromSemanticM(ringQ, profile.B, MRows)
	if err != nil {
		t.Fatalf("extract key: %v", err)
	}
	nonce, noncePublic := fixedNonceTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}

	zeroCoeff := ringQ.NewPoly()
	oneCoeff := intGenISISTestCoeffConst(ringQ, 1)
	MNTT := intGenISISTestNTT(ringQ, M)
	oneNTT := intGenISISTestNTT(ringQ, oneCoeff)
	cmNTT := intGenISISTestPublicBinomialNTT(ringQ, 1, 1)
	u0NTT := ringQ.NewPoly()
	ringQ.MulCoeffs(cmNTT, MNTT, u0NTT)
	ringQ.Add(u0NTT, oneNTT, u0NTT)
	u0 := ringQ.NewPoly()
	ringQ.InvNTT(u0NTT, u0)

	cn := &CoeffNativeShowingWitness{
		Sig:         []*ring.Poly{u0, zeroCoeff.CopyNew()},
		M:           M,
		MAttr:       MAttrRows[0],
		K:           KRows[0],
		S:           []*ring.Poly{zeroCoeff.CopyNew(), zeroCoeff.CopyNew()},
		E:           []*ring.Poly{zeroCoeff.CopyNew()},
		MuSig:       []*ring.Poly{zeroCoeff.CopyNew()},
		X0:          []*ring.Poly{zeroCoeff.CopyNew(), zeroCoeff.CopyNew()},
		X1:          zeroCoeff.CopyNew(),
		Z:           oneCoeff,
		PackedNCols: opts.NCols,
	}
	pub := PublicInputs{
		A: [][]*ring.Poly{{
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 0),
		}},
		B: []*ring.Poly{
			intGenISISTestPublicConstNTT(ringQ, 0),
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 1),
		},
		CM:           [][]*ring.Poly{{cmNTT}},
		AS:           [][]*ring.Poly{{intGenISISTestPublicConstNTT(ringQ, 0), intGenISISTestPublicConstNTT(ringQ, 0)}},
		Tag:          lanesFromElemsTest(tag, opts.NCols),
		Nonce:        noncePublic,
		BoundB:       profile.B,
		X0Len:        profile.EllX0,
		RingDegree:   profile.N,
		HashRelation: credential.HashRelationBBTran,
		IntGenISIS:   true,
		Extras:       map[string]interface{}{"IntGenISIS.signature_bound_value": int64(6142)},
	}
	debugPub, err := bindIntGenISISPublicExtras(pub, int(ringQ.N))
	if err != nil {
		t.Fatalf("bind debug public extras: %v", err)
	}
	rows, _, debugLayout, _, debugCompanion, _, _, _, _, _, builtNCols, err := BuildCredentialRowsShowingIntGenISIS(ringQ, debugPub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, opts.PRFGroupRounds, opts)
	if err != nil {
		t.Fatalf("debug rows: %v", err)
	}
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	debugOmega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], opts.NLeaves, opts.NCols, opts.LVCSNCols, opts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatalf("debug omega: %v", err)
	}
	debugSet, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, debugPub, debugLayout, rowsNTT, debugOmega[:builtNCols], debugCompanion, nil)
	if err != nil {
		t.Fatalf("debug constraints: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, ringQ, debugOmega[:builtNCols], "debug FparInt", debugSet.FparInt, debugSet.FparIntCoeffs)
	if nonZero, err := bucketHasNonZeroOmegaSum(ringQ, debugOmega[:builtNCols], debugSet.FaggNorm, debugSet.FaggNormCoeffs); err != nil || nonZero {
		t.Fatalf("debug FaggNorm nonzero=%v err=%v", nonZero, err)
	}
	debugShowLayout := debugLayout.IntGenISISShowing
	mutatedRowsNTT := func(rowIdx int) []*ring.Poly {
		cp := clonePolySliceForIntGenISISTest(ringQ, rows)
		cp[rowIdx].Coeffs[0][0] = (cp[rowIdx].Coeffs[0][0] + 1) % ringQ.Modulus[0]
		out := make([]*ring.Poly, len(cp))
		for i := range cp {
			out[i] = ringQ.NewPoly()
			ring.Copy(cp[i], out[i])
			ringQ.NTT(out[i], out[i])
		}
		return out
	}
	expectFaggFailure := func(name string, rowIdx int) {
		set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, debugPub, debugLayout, mutatedRowsNTT(rowIdx), debugOmega[:builtNCols], debugCompanion, nil)
		if err != nil {
			t.Fatalf("%s constraints: %v", name, err)
		}
		nonZero, err := bucketHasNonZeroOmegaSum(ringQ, debugOmega[:builtNCols], set.FaggNorm, set.FaggNormCoeffs)
		if err != nil {
			t.Fatalf("%s Fagg check: %v", name, err)
		}
		if !nonZero {
			t.Fatalf("%s did not violate aggregate bridge constraints", name)
		}
	}
	expectFparFailure := func(name string, rowIdx int, fparNorm bool) {
		set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, debugPub, debugLayout, mutatedRowsNTT(rowIdx), debugOmega[:builtNCols], debugCompanion, nil)
		if err != nil {
			t.Fatalf("%s constraints: %v", name, err)
		}
		polys, coeffs := set.FparInt, set.FparIntCoeffs
		if fparNorm {
			polys, coeffs = set.FparNorm, set.FparNormCoeffs
		}
		nonZero, err := bucketHasNonZeroOmegaValue(ringQ, debugOmega[:builtNCols], polys, coeffs)
		if err != nil {
			t.Fatalf("%s Fpar check: %v", name, err)
		}
		if !nonZero {
			t.Fatalf("%s did not violate pointwise constraints", name)
		}
	}
	expectFaggFailure("tampered u coefficient view", debugShowLayout.UViewStart)
	expectFaggFailure("tampered u hat", debugShowLayout.UHatStart)
	expectFparFailure("tampered u shortness digit", debugShowLayout.UShortnessStart, true)
	expectFaggFailure("tampered M coefficient view", debugShowLayout.MViewStart)
	expectFaggFailure("tampered Y coefficient view", debugShowLayout.YViewStart)
	expectFaggFailure("tampered Y hat", debugShowLayout.YHatStart)
	expectFparFailure("tampered mu_sig hat", debugShowLayout.MuSigHatStart, false)
	expectFparFailure("tampered x0 hat", debugShowLayout.X0HatStart, false)
	expectFparFailure("tampered x1 hat", debugShowLayout.X1HatStart, false)
	expectFparFailure("tampered Z hat", debugShowLayout.ZHatStart, false)
	proof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, opts)
	if err != nil {
		t.Fatalf("build showing: %v", err)
	}
	if proof.RowLayout.IntGenISISShowing == nil {
		t.Fatal("missing IntGenISIS showing row layout")
	}
	showLayout := proof.RowLayout.IntGenISISShowing
	if got := showLayout.CoreRowCount; got != 0 {
		t.Fatalf("core showing rows=%d want 0", got)
	}
	if got, want := showLayout.UHatCount, 64; got != want {
		t.Fatalf("u hat rows=%d want %d", got, want)
	}
	if showLayout.MHatStart >= 0 || showLayout.SHatStart >= 0 || showLayout.EHatStart >= 0 || showLayout.MHatCount != 0 || showLayout.SHatCount != 0 || showLayout.EHatCount != 0 {
		t.Fatalf("Y-linear showing retained M/s/e hats: M=(%d,%d) s=(%d,%d) e=(%d,%d)",
			showLayout.MHatStart, showLayout.MHatCount,
			showLayout.SHatStart, showLayout.SHatCount,
			showLayout.EHatStart, showLayout.EHatCount)
	}
	if got, want := showLayout.YViewCount, 32; got != want {
		t.Fatalf("Y coefficient-view rows=%d want %d", got, want)
	}
	if got, want := showLayout.YHatCount, 32; got != want {
		t.Fatalf("Y hat rows=%d want %d", got, want)
	}
	if got, want := showLayout.UShortnessRowsPerGroup, 4; got != want {
		t.Fatalf("u shortness rows/group=%d want %d", got, want)
	}
	if got, want := showLayout.UShortnessRadix, 11; got != want {
		t.Fatalf("u shortness radix=%d want %d", got, want)
	}
	if got, want := showLayout.UShortnessGroupCount*showLayout.UShortnessRowsPerGroup, 256; got != want {
		t.Fatalf("u shortness rows=%d want %d", got, want)
	}
	coeffViewRows := (showLayout.UCount + showLayout.MCount + showLayout.SCount + showLayout.ECount) * showLayout.ViewRowsPerPoly
	if got, want := coeffViewRows, 192; got != want {
		t.Fatalf("coefficient-view row count=%d want %d", got, want)
	}
	if showLayout.MAttrViewStart >= 0 || showLayout.KViewStart >= 0 || showLayout.MuSigViewStart >= 0 || showLayout.X0ViewStart >= 0 || showLayout.X1ViewStart >= 0 || showLayout.ZViewStart >= 0 {
		t.Fatalf("compact/issuer rows should be omitted, got starts m=%d k=%d mu=%d x0=%d x1=%d z=%d", showLayout.MAttrViewStart, showLayout.KViewStart, showLayout.MuSigViewStart, showLayout.X0ViewStart, showLayout.X1ViewStart, showLayout.ZViewStart)
	}
	if showLayout.BoundViewStart <= showLayout.UShortnessStart {
		t.Fatalf("bound views start=%d should follow u shortness start=%d", showLayout.BoundViewStart, showLayout.UShortnessStart)
	}
	if got, want := proof.MaskDegreeBound, computeDQFromConstraintDegrees(11, 2, opts.NCols, opts.Ell); got != want || proof.QDegreeBound != want {
		t.Fatalf("paper-conservative showing degree mismatch mask=%d q=%d want %d", got, proof.QDegreeBound, want)
	}
	if proof.RowDegreeBound <= 0 || proof.RowDegreeBound > proof.MaskDegreeBound {
		t.Fatalf("row degree bound=%d should be positive and no larger than paper-conservative mask degree=%d", proof.RowDegreeBound, proof.MaskDegreeBound)
	}
	ok, err := VerifyIntGenISISShowing(pub, proof, opts)
	if err != nil || !ok {
		t.Fatalf("verify showing: ok=%v err=%v", ok, err)
	}
	preparedCtx, err := PrepareIntGenISISShowingContext(pub, opts)
	if err != nil {
		t.Fatalf("prepare showing context: %v", err)
	}
	preparedProof, err := BuildIntGenISISShowingCombinedPrepared(pub, WitnessInputs{CoeffNativeShowing: cn}, opts, preparedCtx)
	if err != nil {
		t.Fatalf("build prepared showing: %v", err)
	}
	ok, err = VerifyIntGenISISShowing(pub, preparedProof, opts)
	if err != nil || !ok {
		t.Fatalf("verify prepared showing: ok=%v err=%v", ok, err)
	}
	fullOpts := opts
	fullOpts.PRFCompanionMode = PRFCompanionModeDirectFull
	fullDebugPub, err := bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), fullOpts)
	if err != nil {
		t.Fatalf("bind direct_full debug public extras: %v", err)
	}
	fullRows, _, fullDebugLayout, _, fullDebugCompanion, _, _, _, _, _, fullBuiltNCols, err := BuildCredentialRowsShowingIntGenISIS(ringQ, fullDebugPub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, fullOpts.PRFGroupRounds, fullOpts)
	if err != nil {
		t.Fatalf("direct_full debug rows: %v", err)
	}
	fullRowsNTT := make([]*ring.Poly, len(fullRows))
	for i := range fullRows {
		fullRowsNTT[i] = ringQ.NewPoly()
		ring.Copy(fullRows[i], fullRowsNTT[i])
		ringQ.NTT(fullRowsNTT[i], fullRowsNTT[i])
	}
	fullOmega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], fullOpts.NLeaves, fullOpts.NCols, fullOpts.LVCSNCols, fullOpts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatalf("direct_full omega: %v", err)
	}
	fullSet, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, fullDebugPub, fullDebugLayout, fullRowsNTT, fullOmega[:fullBuiltNCols], fullDebugCompanion, nil)
	if err != nil {
		t.Fatalf("direct_full constraints: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, ringQ, fullOmega[:fullBuiltNCols], "direct_full FparInt", fullSet.FparInt, fullSet.FparIntCoeffs)
	if nonZero, err := bucketHasNonZeroOmegaSum(ringQ, fullOmega[:fullBuiltNCols], fullSet.FaggNorm, fullSet.FaggNormCoeffs); err != nil || nonZero {
		for i, coeff := range fullSet.FaggNormCoeffs {
			sum := uint64(0)
			for _, w := range fullOmega[:fullBuiltNCols] {
				sum = modAdd(sum, EvalPoly(coeff, w%ringQ.Modulus[0], ringQ.Modulus[0])%ringQ.Modulus[0], ringQ.Modulus[0])
			}
			if sum != 0 {
				vals := evalCoeffOnOmegaTest(coeff, fullOmega[:fullBuiltNCols], ringQ.Modulus[0])
				bad := make([]uint64, 0, 4)
				for _, v := range vals {
					if v != 0 {
						bad = append(bad, v)
						if len(bad) == 4 {
							break
						}
					}
				}
				t.Fatalf("direct_full FaggNorm first nonzero index=%d sum=%d coeff_len=%d bad=%v", i, sum, len(coeff), bad)
			}
		}
		t.Fatalf("direct_full FaggNorm nonzero=%v err=%v", nonZero, err)
	}
	fullProof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, fullOpts)
	if err != nil {
		t.Fatalf("build direct_full showing: %v", err)
	}
	if fullProof.PRFCompanion == nil || fullProof.PRFCompanion.Layout == nil {
		t.Fatal("direct_full proof missing companion layout")
	}
	fullLayout := fullProof.PRFCompanion.Layout
	if fullProof.PRFCompanion.Mode != PRFCompanionModeDirectFull || fullLayout.RelationVersion != 1 {
		t.Fatalf("direct_full mode/layout=(%s,%d)", fullProof.PRFCompanion.Mode, fullLayout.RelationVersion)
	}
	if got, want := fullLayout.PackedLogicalCount, params.LenKey+groupedPRFSBoxCount(params.LenKey, params.LenNonce, params.RF, params.RP, fullOpts.PRFGroupRounds)+params.T()+params.LenTag; got != want {
		t.Fatalf("direct_full logical count=%d want %d", got, want)
	}
	if got, want := len(fullLayout.FinalRoundOutputSlots), params.T(); got != want {
		t.Fatalf("direct_full final round slots=%d want %d", got, want)
	}
	if len(fullProof.PRFCompanion.CheckpointAudits) != 0 || prfCompanionHasOpeningPayload(fullProof.PRFCompanion) {
		t.Fatal("direct_full proof carried legacy PRF opening payload")
	}
	ok, err = VerifyIntGenISISShowing(pub, fullProof, fullOpts)
	if err != nil || !ok {
		gotAgg := 0
		if len(fullProof.GammaAgg) > 0 {
			gotAgg = len(fullProof.GammaAgg[0])
		}
		t.Fatalf("verify direct_full showing: ok=%v err=%v proofAgg=%d debugAgg=%d fullSetAgg=%d rel=%d", ok, err, gotAgg, len(fullProof.FaggCoeffDebug), len(fullSet.FaggNorm), fullProof.PRFCompanion.Layout.RelationVersion)
	}
	tamperedTagPub := pub
	tamperedTagPub.Tag = make([][]int64, len(pub.Tag))
	for i := range pub.Tag {
		tamperedTagPub.Tag[i] = append([]int64(nil), pub.Tag[i]...)
	}
	tamperedTagPub.Tag[0][0]++
	ok, err = VerifyIntGenISISShowing(tamperedTagPub, fullProof, fullOpts)
	if err == nil && ok {
		t.Fatal("direct_full verifier accepted tampered public tag")
	}
	tamperedNoncePub := pub
	tamperedNoncePub.Nonce = make([][]int64, len(pub.Nonce))
	for i := range pub.Nonce {
		tamperedNoncePub.Nonce[i] = append([]int64(nil), pub.Nonce[i]...)
	}
	tamperedNoncePub.Nonce[0][0]++
	ok, err = VerifyIntGenISISShowing(tamperedNoncePub, fullProof, fullOpts)
	if err == nil && ok {
		t.Fatal("direct_full verifier accepted tampered public nonce")
	}
	if proof.QOpening == nil || proof.QRoot == ([16]byte{}) || len(proof.QRBits) == 0 {
		t.Fatal("showing proof did not carry Q DECS material")
	}
	projectionOpts := opts
	projectionOpts.IntGenISISReplayProjection = IntGenISISReplayProjectionProjectUYHatV1
	projectionDebugPub, err := bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), projectionOpts)
	if err != nil {
		t.Fatalf("bind projection debug public extras: %v", err)
	}
	projectionRows, _, projectionDebugLayout, _, projectionDebugCompanion, _, _, _, _, _, projectionBuiltNCols, err := BuildCredentialRowsShowingIntGenISIS(ringQ, projectionDebugPub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, projectionOpts.PRFGroupRounds, projectionOpts)
	if err != nil {
		t.Fatalf("projection debug rows: %v", err)
	}
	projectionLayout := projectionDebugLayout.IntGenISISShowing
	if projectionLayout.LayoutVersion != intGenISISShowingLayoutVersionProjectionUYHatV1 {
		t.Fatalf("projection layout version=%q", projectionLayout.LayoutVersion)
	}
	if projectionLayout.UHatStart >= 0 || projectionLayout.UHatCount != 0 || projectionLayout.YHatStart >= 0 || projectionLayout.YHatCount != 0 {
		t.Fatalf("projection retained derived hats: u=(%d,%d) Y=(%d,%d)", projectionLayout.UHatStart, projectionLayout.UHatCount, projectionLayout.YHatStart, projectionLayout.YHatCount)
	}
	projectionRowsNTT := make([]*ring.Poly, len(projectionRows))
	for i := range projectionRows {
		projectionRowsNTT[i] = ringQ.NewPoly()
		ring.Copy(projectionRows[i], projectionRowsNTT[i])
		ringQ.NTT(projectionRowsNTT[i], projectionRowsNTT[i])
	}
	projectionOmega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], projectionOpts.NLeaves, projectionOpts.NCols, projectionOpts.LVCSNCols, projectionOpts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatalf("projection debug omega: %v", err)
	}
	projectionSet, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, projectionDebugPub, projectionDebugLayout, projectionRowsNTT, projectionOmega[:projectionBuiltNCols], projectionDebugCompanion, nil)
	if err != nil {
		t.Fatalf("projection constraints: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, ringQ, projectionOmega[:projectionBuiltNCols], "projection FparInt", projectionSet.FparInt, projectionSet.FparIntCoeffs)
	if nonZero, err := bucketHasNonZeroOmegaSum(ringQ, projectionOmega[:projectionBuiltNCols], projectionSet.FaggNorm, projectionSet.FaggNormCoeffs); err != nil || nonZero {
		t.Fatalf("projection FaggNorm nonzero=%v err=%v", nonZero, err)
	}
	projectionMutatedRowsNTT := func(rowIdx int) []*ring.Poly {
		cp := clonePolySliceForIntGenISISTest(ringQ, projectionRows)
		cp[rowIdx].Coeffs[0][0] = (cp[rowIdx].Coeffs[0][0] + 1) % ringQ.Modulus[0]
		out := make([]*ring.Poly, len(cp))
		for i := range cp {
			out[i] = ringQ.NewPoly()
			ring.Copy(cp[i], out[i])
			ringQ.NTT(out[i], out[i])
		}
		return out
	}
	expectProjectionFaggFailure := func(name string, rowIdx int) {
		set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, projectionDebugPub, projectionDebugLayout, projectionMutatedRowsNTT(rowIdx), projectionOmega[:projectionBuiltNCols], projectionDebugCompanion, nil)
		if err != nil {
			t.Fatalf("%s projection constraints: %v", name, err)
		}
		nonZero, err := bucketHasNonZeroOmegaSum(ringQ, projectionOmega[:projectionBuiltNCols], set.FaggNorm, set.FaggNormCoeffs)
		if err != nil {
			t.Fatalf("%s projection Fagg check: %v", name, err)
		}
		if !nonZero {
			t.Fatalf("%s did not violate projected aggregate constraints", name)
		}
	}
	expectProjectionFaggFailure("projection tampered u coefficient view", projectionLayout.UViewStart)
	expectProjectionFaggFailure("projection tampered Y coefficient view", projectionLayout.YViewStart)
	expectProjectionFaggFailure("projection tampered mu_sig hat", projectionLayout.MuSigHatStart)
	projectionProof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, projectionOpts)
	if err != nil {
		t.Fatalf("build projection showing: %v", err)
	}
	if projectionProof.RowLayout.IntGenISISShowing.UHatCount != 0 || projectionProof.RowLayout.IntGenISISShowing.YHatCount != 0 {
		t.Fatalf("projection proof retained U/Y hats")
	}
	ok, err = VerifyIntGenISISShowing(pub, projectionProof, projectionOpts)
	if err != nil || !ok {
		t.Fatalf("verify projection showing: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyIntGenISISShowing(pub, projectionProof, opts)
	if err == nil && ok {
		t.Fatal("default verifier accepted projection proof without matching replay projection option")
	}
	v2Opts := opts
	v2Opts.IntGenISISReplayProjection = IntGenISISReplayProjectionProjectUYHatYViewV2
	v2DebugPub, err := bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), v2Opts)
	if err != nil {
		t.Fatalf("bind projection v2 debug public extras: %v", err)
	}
	v2Rows, _, v2DebugLayout, _, v2DebugCompanion, _, _, _, _, _, v2BuiltNCols, err := BuildCredentialRowsShowingIntGenISIS(ringQ, v2DebugPub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, v2Opts.PRFGroupRounds, v2Opts)
	if err != nil {
		t.Fatalf("projection v2 debug rows: %v", err)
	}
	v2Layout := v2DebugLayout.IntGenISISShowing
	if v2Layout.LayoutVersion != intGenISISShowingLayoutVersionProjectionUYHatYViewV2 {
		t.Fatalf("projection v2 layout version=%q", v2Layout.LayoutVersion)
	}
	if v2Layout.UHatStart >= 0 || v2Layout.UHatCount != 0 || v2Layout.YHatStart >= 0 || v2Layout.YHatCount != 0 || v2Layout.YViewStart >= 0 || v2Layout.YViewCount != 0 {
		t.Fatalf("projection v2 retained derived rows: uhat=(%d,%d) yhat=(%d,%d) yview=(%d,%d)", v2Layout.UHatStart, v2Layout.UHatCount, v2Layout.YHatStart, v2Layout.YHatCount, v2Layout.YViewStart, v2Layout.YViewCount)
	}
	v2RowsNTT := make([]*ring.Poly, len(v2Rows))
	for i := range v2Rows {
		v2RowsNTT[i] = ringQ.NewPoly()
		ring.Copy(v2Rows[i], v2RowsNTT[i])
		ringQ.NTT(v2RowsNTT[i], v2RowsNTT[i])
	}
	v2Omega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], v2Opts.NLeaves, v2Opts.NCols, v2Opts.LVCSNCols, v2Opts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatalf("projection v2 debug omega: %v", err)
	}
	v2Set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, v2DebugPub, v2DebugLayout, v2RowsNTT, v2Omega[:v2BuiltNCols], v2DebugCompanion, nil)
	if err != nil {
		t.Fatalf("projection v2 constraints: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, ringQ, v2Omega[:v2BuiltNCols], "projection v2 FparInt", v2Set.FparInt, v2Set.FparIntCoeffs)
	if nonZero, err := bucketHasNonZeroOmegaSum(ringQ, v2Omega[:v2BuiltNCols], v2Set.FaggNorm, v2Set.FaggNormCoeffs); err != nil || nonZero {
		t.Fatalf("projection v2 FaggNorm nonzero=%v err=%v", nonZero, err)
	}
	v2MutatedRowsNTT := func(rowIdx int) []*ring.Poly {
		cp := clonePolySliceForIntGenISISTest(ringQ, v2Rows)
		cp[rowIdx].Coeffs[0][0] = (cp[rowIdx].Coeffs[0][0] + 1) % ringQ.Modulus[0]
		out := make([]*ring.Poly, len(cp))
		for i := range cp {
			out[i] = ringQ.NewPoly()
			ring.Copy(cp[i], out[i])
			ringQ.NTT(out[i], out[i])
		}
		return out
	}
	expectV2FaggFailure := func(name string, rowIdx int) {
		set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, v2DebugPub, v2DebugLayout, v2MutatedRowsNTT(rowIdx), v2Omega[:v2BuiltNCols], v2DebugCompanion, nil)
		if err != nil {
			t.Fatalf("%s projection v2 constraints: %v", name, err)
		}
		nonZero, err := bucketHasNonZeroOmegaSum(ringQ, v2Omega[:v2BuiltNCols], set.FaggNorm, set.FaggNormCoeffs)
		if err != nil {
			t.Fatalf("%s projection v2 Fagg check: %v", name, err)
		}
		if !nonZero {
			t.Fatalf("%s did not violate projected v2 aggregate constraints", name)
		}
	}
	expectV2FaggFailure("projection v2 tampered u coefficient view", v2Layout.UViewStart)
	expectV2FaggFailure("projection v2 tampered M coefficient view", v2Layout.MViewStart)
	expectV2FaggFailure("projection v2 tampered mu_sig hat", v2Layout.MuSigHatStart)
	v2Proof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, v2Opts)
	if err != nil {
		t.Fatalf("build projection v2 showing: %v", err)
	}
	if v2Proof.RowLayout.IntGenISISShowing.UHatCount != 0 || v2Proof.RowLayout.IntGenISISShowing.YHatCount != 0 || v2Proof.RowLayout.IntGenISISShowing.YViewCount != 0 {
		t.Fatalf("projection v2 proof retained U/Y derived rows")
	}
	ok, err = VerifyIntGenISISShowing(pub, v2Proof, v2Opts)
	if err != nil || !ok {
		t.Fatalf("verify projection v2 showing: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyIntGenISISShowing(pub, v2Proof, projectionOpts)
	if err == nil && ok {
		t.Fatal("projection v1 verifier accepted projection v2 proof")
	}
	v3Opts := opts
	v3Opts.IntGenISISReplayProjection = IntGenISISReplayProjectionProjectUDigitsYViewV3
	v3DebugPub, err := bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), v3Opts)
	if err != nil {
		t.Fatalf("bind projection v3 debug public extras: %v", err)
	}
	v3Rows, _, v3DebugLayout, _, v3DebugCompanion, _, _, _, _, _, v3BuiltNCols, err := BuildCredentialRowsShowingIntGenISIS(ringQ, v3DebugPub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, v3Opts.PRFGroupRounds, v3Opts)
	if err != nil {
		t.Fatalf("projection v3 debug rows: %v", err)
	}
	v3Layout := v3DebugLayout.IntGenISISShowing
	if v3Layout.LayoutVersion != intGenISISShowingLayoutVersionProjectionUDigitsYViewV3 {
		t.Fatalf("projection v3 layout version=%q", v3Layout.LayoutVersion)
	}
	if v3Layout.UViewStart >= 0 || v3Layout.UShortnessSourceViewStart >= 0 || v3Layout.UShortnessSourceViewRows != 0 {
		t.Fatalf("projection v3 committed/reused U views: u=(%d,%d) source=(%d,%d)",
			v3Layout.UViewStart, v3Layout.UCount, v3Layout.UShortnessSourceViewStart, v3Layout.UShortnessSourceViewRows)
	}
	if v3Layout.UHatStart >= 0 || v3Layout.UHatCount != 0 || v3Layout.YHatStart >= 0 || v3Layout.YHatCount != 0 || v3Layout.YViewStart >= 0 || v3Layout.YViewCount != 0 {
		t.Fatalf("projection v3 retained derived rows: uhat=(%d,%d) yhat=(%d,%d) yview=(%d,%d)",
			v3Layout.UHatStart, v3Layout.UHatCount, v3Layout.YHatStart, v3Layout.YHatCount, v3Layout.YViewStart, v3Layout.YViewCount)
	}
	if v3Layout.MuSigViewStart >= 0 || v3Layout.X0ViewStart >= 0 || v3Layout.X1ViewStart >= 0 {
		t.Fatalf("projection v3 unexpectedly committed issuer source views: mu=%d x0=%d x1=%d", v3Layout.MuSigViewStart, v3Layout.X0ViewStart, v3Layout.X1ViewStart)
	}
	if v3Layout.MuSigHatCount == 0 || v3Layout.X0HatCount == 0 || v3Layout.X1HatCount == 0 {
		t.Fatalf("projection v3 must keep issuer hats bound: mu=%d x0=%d x1=%d", v3Layout.MuSigHatCount, v3Layout.X0HatCount, v3Layout.X1HatCount)
	}
	if got, want := v3Layout.UShortnessGroupCount*v3Layout.UShortnessRowsPerGroup, 256; got != want {
		t.Fatalf("projection v3 u shortness rows=%d want %d", got, want)
	}
	v3RowsNTT := make([]*ring.Poly, len(v3Rows))
	for i := range v3Rows {
		v3RowsNTT[i] = ringQ.NewPoly()
		ring.Copy(v3Rows[i], v3RowsNTT[i])
		ringQ.NTT(v3RowsNTT[i], v3RowsNTT[i])
	}
	v3Omega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], v3Opts.NLeaves, v3Opts.NCols, v3Opts.LVCSNCols, v3Opts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatalf("projection v3 debug omega: %v", err)
	}
	v3Set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, v3DebugPub, v3DebugLayout, v3RowsNTT, v3Omega[:v3BuiltNCols], v3DebugCompanion, nil)
	if err != nil {
		t.Fatalf("projection v3 constraints: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, ringQ, v3Omega[:v3BuiltNCols], "projection v3 FparInt", v3Set.FparInt, v3Set.FparIntCoeffs)
	if nonZero, err := bucketHasNonZeroOmegaSum(ringQ, v3Omega[:v3BuiltNCols], v3Set.FaggNorm, v3Set.FaggNormCoeffs); err != nil || nonZero {
		t.Fatalf("projection v3 FaggNorm nonzero=%v err=%v", nonZero, err)
	}
	v3Cache, err := newIntGenISISRowCoeffCache(ringQ, v3RowsNTT)
	if err != nil {
		t.Fatalf("projection v3 row coefficient cache: %v", err)
	}
	v3SigBound, err := intGenISISSignatureBoundFromPublic(pub)
	if err != nil {
		t.Fatalf("projection v3 signature bound: %v", err)
	}
	v3ShortSpec, err := intGenISISUShortnessLayoutSpec(ringQ, v3Layout, v3SigBound)
	if err != nil {
		t.Fatalf("projection v3 shortness spec: %v", err)
	}
	uViewMats, err := intGenISISCoeffViewRowMaterials(ringQ, v3Omega[:v3BuiltNCols], cn.Sig, v3Opts.NCols, nil)
	if err != nil {
		t.Fatalf("projection v3 expected u views: %v", err)
	}
	for comp := 0; comp < v3Layout.UCount; comp++ {
		for block := 0; block < v3Layout.ViewRowsPerPoly; block++ {
			got, err := intGenISISUDigitSourceFormalCoeff(v3Cache, v3Layout, v3ShortSpec.RPows, comp, block, int(ringQ.N), ringQ.Modulus[0])
			if err != nil {
				t.Fatalf("projection v3 reconstructed U[%d,%d]: %v", comp, block, err)
			}
			want := trimCoeffsCopy(uViewMats[comp*v3Layout.ViewRowsPerPoly+block].Poly.Coeffs[0], ringQ.Modulus[0])
			if len(got) != len(want) {
				t.Fatalf("projection v3 reconstructed U[%d,%d] len=%d want %d", comp, block, len(got), len(want))
			}
			for i := range got {
				if got[i]%ringQ.Modulus[0] != want[i]%ringQ.Modulus[0] {
					t.Fatalf("projection v3 reconstructed U[%d,%d][%d]=%d want %d", comp, block, i, got[i]%ringQ.Modulus[0], want[i]%ringQ.Modulus[0])
				}
			}
		}
	}
	v3BadLayout := *v3Layout
	v3BadLayout.UViewStart = 0
	if err := validateIntGenISISShowingPackedLayout(&v3BadLayout, len(v3Rows)); err == nil {
		t.Fatal("projection v3 layout validation accepted committed UView")
	}
	v4Opts := opts
	v4Opts.IntGenISISReplayProjection = IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4
	v4DebugPub, err := bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), v4Opts)
	if err != nil {
		t.Fatalf("bind projection v4 debug public extras: %v", err)
	}
	if _, _, _, _, _, _, _, _, _, _, _, err := BuildCredentialRowsShowingIntGenISIS(ringQ, v4DebugPub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, v4Opts.PRFGroupRounds, v4Opts); err == nil || !strings.Contains(err.Error(), "sound-gated") {
		t.Fatalf("projection v4 build should reject missing committed source provider, err=%v", err)
	}
	v4BadLayout := *v3Layout
	v4BadLayout.LayoutVersion = intGenISISShowingLayoutVersionProjectionUDigitsYSourceLinearV4
	v4BadLayout.ReplayProjection = IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4
	v4BadLayout.MuSigHatStart, v4BadLayout.MuSigHatCount = -1, 0
	v4BadLayout.X0HatStart, v4BadLayout.X0HatCount = -1, 0
	v4BadLayout.X1HatStart, v4BadLayout.X1HatCount = -1, 0
	if err := validateIntGenISISShowingPackedLayout(&v4BadLayout, len(v3Rows)); err == nil || !strings.Contains(err.Error(), "committed source provider") {
		t.Fatalf("projection v4 layout should reject unbound omitted issuer hats, err=%v", err)
	}
	v4NoZ := v4BadLayout
	v4NoZ.ZHatStart, v4NoZ.ZHatCount = -1, 0
	if err := validateIntGenISISShowingPackedLayout(&v4NoZ, len(v3Rows)); err == nil || !strings.Contains(err.Error(), "Z hat") {
		t.Fatalf("projection v4 layout should still require ZHat, err=%v", err)
	}
	v4UnknownSource := v4BadLayout
	v4UnknownSource.LinearHatSourceMode = "uncommitted_witness"
	if err := validateIntGenISISShowingPackedLayout(&v4UnknownSource, len(v3Rows)); err == nil || !strings.Contains(err.Error(), "unsupported IntGenISIS linear hat source mode") {
		t.Fatalf("projection v4 layout should reject unknown source provider, err=%v", err)
	}
	v4SourceView := v4BadLayout
	v4SourceView.LinearHatSourceMode = intGenISISLinearHatSourceView
	if err := validateIntGenISISShowingPackedLayout(&v4SourceView, len(v3Rows)); err == nil || !strings.Contains(err.Error(), "source_view provider is not implemented") {
		t.Fatalf("projection v4 layout should reject unimplemented source_view provider, err=%v", err)
	}
	v5Opts := opts
	v5Opts.IntGenISISReplayProjection = IntGenISISReplayProjectionProjectUDigitsYWResidualV5
	v5DebugPub, err := bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), v5Opts)
	if err != nil {
		t.Fatalf("bind projection v5 debug public extras: %v", err)
	}
	v5Rows, _, v5DebugLayout, _, v5DebugCompanion, _, _, _, _, _, v5BuiltNCols, err := BuildCredentialRowsShowingIntGenISIS(ringQ, v5DebugPub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, v5Opts.PRFGroupRounds, v5Opts)
	if err != nil {
		t.Fatalf("projection v5 debug rows: %v", err)
	}
	v5Layout := v5DebugLayout.IntGenISISShowing
	if v5Layout.LayoutVersion != intGenISISShowingLayoutVersionProjectionUDigitsYWResidualV5 {
		t.Fatalf("projection v5 layout version=%q", v5Layout.LayoutVersion)
	}
	if v5Layout.MuSigHatStart >= 0 || v5Layout.MuSigHatCount != 0 || v5Layout.X0HatStart >= 0 || v5Layout.X0HatCount != 0 {
		t.Fatalf("projection v5 retained mu/x0 hats: mu=(%d,%d) x0=(%d,%d)", v5Layout.MuSigHatStart, v5Layout.MuSigHatCount, v5Layout.X0HatStart, v5Layout.X0HatCount)
	}
	if v5Layout.WHatStart < 0 || v5Layout.WHatCount != v5Layout.ViewRowsPerPoly {
		t.Fatalf("projection v5 W hats=(%d,%d) want rows/poly=%d", v5Layout.WHatStart, v5Layout.WHatCount, v5Layout.ViewRowsPerPoly)
	}
	if v5Layout.X1HatCount != v5Layout.ViewRowsPerPoly || v5Layout.ZHatCount != v5Layout.ViewRowsPerPoly {
		t.Fatalf("projection v5 must keep x1/Z hats: x1=%d Z=%d rows/poly=%d", v5Layout.X1HatCount, v5Layout.ZHatCount, v5Layout.ViewRowsPerPoly)
	}
	if got, want := len(v3Rows)-len(v5Rows), v3Layout.MuSigHatCount+v3Layout.X0HatCount-v5Layout.WHatCount; got != want {
		t.Fatalf("projection v5 row saving=%d want %d", got, want)
	}
	v5RowsNTT := make([]*ring.Poly, len(v5Rows))
	for i := range v5Rows {
		v5RowsNTT[i] = ringQ.NewPoly()
		ring.Copy(v5Rows[i], v5RowsNTT[i])
		ringQ.NTT(v5RowsNTT[i], v5RowsNTT[i])
	}
	v5Omega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], v5Opts.NLeaves, v5Opts.NCols, v5Opts.LVCSNCols, v5Opts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatalf("projection v5 debug omega: %v", err)
	}
	v5Set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, v5DebugPub, v5DebugLayout, v5RowsNTT, v5Omega[:v5BuiltNCols], v5DebugCompanion, nil)
	if err != nil {
		t.Fatalf("projection v5 constraints: %v", err)
	}
	assertConstraintBucketVanishesOnOmega(t, ringQ, v5Omega[:v5BuiltNCols], "projection v5 FparInt", v5Set.FparInt, v5Set.FparIntCoeffs)
	if nonZero, err := bucketHasNonZeroOmegaSum(ringQ, v5Omega[:v5BuiltNCols], v5Set.FaggNorm, v5Set.FaggNormCoeffs); err != nil || nonZero {
		t.Fatalf("projection v5 FaggNorm nonzero=%v err=%v", nonZero, err)
	}
	v5MutatedRowsNTT := func(rowIdx int) []*ring.Poly {
		cp := clonePolySliceForIntGenISISTest(ringQ, v5Rows)
		cp[rowIdx].Coeffs[0][0] = (cp[rowIdx].Coeffs[0][0] + 1) % ringQ.Modulus[0]
		out := make([]*ring.Poly, len(cp))
		for i := range cp {
			out[i] = ringQ.NewPoly()
			ring.Copy(cp[i], out[i])
			ringQ.NTT(out[i], out[i])
		}
		return out
	}
	set, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, v5DebugPub, v5DebugLayout, v5MutatedRowsNTT(v5Layout.WHatStart), v5Omega[:v5BuiltNCols], v5DebugCompanion, nil)
	if err != nil {
		t.Fatalf("projection v5 tampered W constraints: %v", err)
	}
	if nonZero, err := bucketHasNonZeroOmegaSum(ringQ, v5Omega[:v5BuiltNCols], set.FaggNorm, set.FaggNormCoeffs); err != nil || !nonZero {
		t.Fatalf("projection v5 tampered W nonzero=%v err=%v", nonZero, err)
	}
	v5BadLayout := *v5Layout
	v5BadLayout.MuSigHatStart, v5BadLayout.MuSigHatCount = v3Layout.MuSigHatStart, v3Layout.MuSigHatCount
	if err := validateIntGenISISShowingPackedLayout(&v5BadLayout, len(v5Rows)); err == nil || !strings.Contains(err.Error(), "must omit mu_sig/x0 hats") {
		t.Fatalf("projection v5 layout should reject materialized mu hat, err=%v", err)
	}
	badPub := v5DebugPub
	badPub.B = make([]*ring.Poly, len(v5DebugPub.B))
	for i := range v5DebugPub.B {
		badPub.B[i] = ringQ.NewPoly()
		ring.Copy(v5DebugPub.B[i], badPub.B[i])
	}
	for _, idx := range []int{1, 2, 3} {
		badPub.B[idx].Coeffs[0][0] = 0
	}
	if _, _, _, _, _, _, _, _, _, _, _, err := BuildCredentialRowsShowingIntGenISIS(ringQ, badPub, WitnessInputs{CoeffNativeShowing: cn}, params.LenKey, params.LenNonce, params.RF, params.RP, v5Opts.PRFGroupRounds, v5Opts); err == nil || !strings.Contains(err.Error(), "not full-image") {
		t.Fatalf("projection v5 should reject non-full-image B map, err=%v", err)
	}
	v3MutatedRowsNTT := func(rowIdx int) []*ring.Poly {
		cp := clonePolySliceForIntGenISISTest(ringQ, v3Rows)
		cp[rowIdx].Coeffs[0][0] = (cp[rowIdx].Coeffs[0][0] + 1) % ringQ.Modulus[0]
		out := make([]*ring.Poly, len(cp))
		for i := range cp {
			out[i] = ringQ.NewPoly()
			ring.Copy(cp[i], out[i])
			ringQ.NTT(out[i], out[i])
		}
		return out
	}
	set, err = buildIntGenISISShowingConstraintSetFromRows(ringQ, v3DebugPub, v3DebugLayout, v3MutatedRowsNTT(v3Layout.UShortnessStart), v3Omega[:v3BuiltNCols], v3DebugCompanion, nil)
	if err != nil {
		t.Fatalf("projection v3 tampered digit constraints: %v", err)
	}
	nonZero, err := bucketHasNonZeroOmegaSum(ringQ, v3Omega[:v3BuiltNCols], set.FaggNorm, set.FaggNormCoeffs)
	if err != nil {
		t.Fatalf("projection v3 tampered digit Fagg check: %v", err)
	}
	if !nonZero {
		t.Fatal("projection v3 tampered digit did not violate projected signature constraints")
	}
	v3Proof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, v3Opts)
	if err != nil {
		t.Fatalf("build projection v3 showing: %v", err)
	}
	ok, err = VerifyIntGenISISShowing(pub, v3Proof, v3Opts)
	if err != nil || !ok {
		t.Fatalf("verify projection v3 showing: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyIntGenISISShowing(pub, v3Proof, v2Opts)
	if err == nil && ok {
		t.Fatal("projection v2 verifier accepted projection v3 proof")
	}
	v5Proof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, v5Opts)
	if err != nil {
		t.Fatalf("build projection v5 showing: %v", err)
	}
	ok, err = VerifyIntGenISISShowing(pub, v5Proof, v5Opts)
	if err != nil || !ok {
		t.Fatalf("verify projection v5 showing: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyIntGenISISShowing(pub, v5Proof, v3Opts)
	if err == nil && ok {
		t.Fatal("projection v3 verifier accepted projection v5 proof")
	}
	ok, err = VerifyIntGenISISShowing(pub, v3Proof, v5Opts)
	if err == nil && ok {
		t.Fatal("projection v5 verifier accepted projection v3 proof")
	}
	compressedOpts := opts
	compressedOpts.IntGenISISMSECompression = 1
	if _, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, compressedOpts); err == nil {
		t.Fatal("B=4 showing accepted compressed M/s/e proof")
	}
	if _, err := bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), compressedOpts); err == nil {
		t.Fatal("B=4 public extras accepted compressed M/s/e descriptor")
	}
	variantOpts := opts
	variantOpts.SigShortnessRadix = 7
	variantOpts.SigShortnessL = 5
	variantProof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, variantOpts)
	if err != nil {
		t.Fatalf("build R7/L5 showing: %v", err)
	}
	variantLayout := variantProof.RowLayout.IntGenISISShowing
	if got, want := variantLayout.UShortnessRadix, 7; got != want {
		t.Fatalf("variant shortness radix=%d want %d", got, want)
	}
	if got, want := variantLayout.UShortnessGroupCount*variantLayout.UShortnessRowsPerGroup, 320; got != want {
		t.Fatalf("variant shortness rows=%d want %d", got, want)
	}
	ok, err = VerifyIntGenISISShowing(pub, variantProof, variantOpts)
	if err != nil || !ok {
		t.Fatalf("verify R7/L5 showing: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyIntGenISISShowing(pub, variantProof, opts)
	if err == nil && ok {
		t.Fatal("default verifier accepted R7/L5 proof without matching shortness metadata")
	}
	thetaOpts := opts
	thetaOpts.Theta = 7
	thetaOpts.Rho = 1
	thetaOpts.EllPrime = 1
	thetaOpts.LVCSNCols = thetaOpts.NCols
	thetaOpts.PostSignLVCSNCols = thetaOpts.NCols
	thetaOpts.PRFLVCSNCols = thetaOpts.NCols
	thetaOpts.TranscriptVersion = TranscriptVersionSmallWood2025
	thetaOpts.TranscriptProtocolMode = TranscriptProtocolSmallField2025V1
	rawR25Strict := thetaOpts
	rawR25Strict.IntGenISISReplayProjection = IntGenISISReplayProjectionProjectUDigitsYViewV3
	rawR25Strict.SigShortnessRadix = 25
	rawR25Strict.SigShortnessL = 3
	if _, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, rawR25Strict); err == nil || !strings.Contains(err.Error(), "degree-capped") {
		t.Fatalf("strict raw R25/L3 rejection err=%v", err)
	}
	rawPack3Strict := thetaOpts
	rawPack3Strict.IntGenISISMSECompression = 2
	if err := rejectIntGenISISUnsupportedDegreeCappedModes(rawPack3Strict); err == nil || !strings.Contains(err.Error(), "degree-capped") {
		t.Fatalf("strict raw pack3 rejection err=%v", err)
	}
	assertIntGenISISShowingPreparedConstraintsMatchRebuild(t, ringQ, pub, cn, params, thetaOpts)
	thetaProof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, thetaOpts)
	if err != nil {
		t.Fatalf("build theta>1 showing: %v", err)
	}
	if thetaProof.SmallField2025 == nil {
		t.Fatal("strict theta>1 showing missing smallfield2025 metadata")
	}
	if !thetaProof.SmallField2025.ReductionEnabled || thetaProof.SmallField2025.Status != SmallField2025StatusLive {
		t.Fatalf("strict theta>1 showing reduction status=%q enabled=%v", thetaProof.SmallField2025.Status, thetaProof.SmallField2025.ReductionEnabled)
	}
	if got, want := thetaProof.SmallField2025.QueryCount, (thetaProof.SmallField2025.WitnessLayers+1)*thetaOpts.Theta; got != want {
		t.Fatalf("strict theta>1 showing query_count=%d want %d", got, want)
	}
	if thetaProof.PCSOpening == nil || thetaProof.PCSOpening.PColsEncoded != thetaProof.PCSOpening.R-thetaProof.SmallField2025.QueryCount {
		t.Fatalf("strict theta>1 showing opening PColsEncoded=%d R=%d query_count=%d", thetaProof.PCSOpening.PColsEncoded, thetaProof.PCSOpening.R, thetaProof.SmallField2025.QueryCount)
	}
	if thetaProof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV1 {
		t.Fatalf("theta>1 geometry kind=%q", thetaProof.PCSGeometry.Kind)
	}
	if thetaProof.PCSGeometry.SmallFieldSource != PCSGeometrySmallFieldSourceLiteralRows {
		t.Fatalf("theta>1 source=%q", thetaProof.PCSGeometry.SmallFieldSource)
	}
	if thetaProof.QRoot != ([16]byte{}) || len(thetaProof.QRBits) != 0 || thetaProof.QOpening != nil {
		t.Fatal("strict theta>1 showing carried redundant Q DECS material")
	}
	if len(thetaProof.QPayloadMatrix()) != thetaOpts.Rho*thetaOpts.Theta {
		t.Fatalf("theta>1 Q payload rows mismatch")
	}
	ok, err = VerifyIntGenISISShowing(pub, thetaProof, thetaOpts)
	if err != nil || !ok {
		t.Fatalf("verify theta>1 showing: ok=%v err=%v", ok, err)
	}
	badSmallFieldC := *thetaProof
	badSmallFieldC.CoeffMatrix = copyMatrix(thetaProof.CoeffMatrix)
	badSmallFieldC.CoeffMatrix[0][0] = (badSmallFieldC.CoeffMatrix[0][0] + 1) % ringQ.Modulus[0]
	ok, err = VerifyIntGenISISShowing(pub, &badSmallFieldC, thetaOpts)
	if err == nil && ok {
		t.Fatal("smallfield2025 showing verified with tampered coefficient matrix")
	}
	badSmallFieldVHead := *thetaProof
	badSmallFieldVHead.VTargetsBits = append([]byte(nil), thetaProof.VTargetsBits...)
	badSmallFieldVHead.VTargetsBits[len(badSmallFieldVHead.VTargetsBits)-1] ^= 1
	ok, err = VerifyIntGenISISShowing(pub, &badSmallFieldVHead, thetaOpts)
	if err == nil && ok {
		t.Fatal("smallfield2025 showing verified with tampered VHead payload")
	}
	badSmallFieldVBar := *thetaProof
	badSmallFieldVBar.BarSetsBits = append([]byte(nil), thetaProof.BarSetsBits...)
	badSmallFieldVBar.BarSetsBits[len(badSmallFieldVBar.BarSetsBits)-1] ^= 1
	ok, err = VerifyIntGenISISShowing(pub, &badSmallFieldVBar, thetaOpts)
	if err == nil && ok {
		t.Fatal("smallfield2025 showing verified with tampered VBar payload")
	}
	badSmallFieldOmit := *thetaProof
	badSmallFieldMeta := *thetaProof.SmallField2025
	badSmallFieldMeta.POmitCols = make([]int, thetaProof.SmallField2025.QueryCount)
	badSmallFieldOmit.SmallField2025 = &badSmallFieldMeta
	ok, err = VerifyIntGenISISShowing(pub, &badSmallFieldOmit, thetaOpts)
	if err == nil && ok {
		t.Fatal("smallfield2025 showing verified with tampered POmitCols metadata")
	}
	badQPayload := *thetaProof
	badQPayload.QPayload = copyMatrix(thetaProof.QPayloadMatrix())
	badQPayload.QPayloadBits = nil
	badQPayload.QPayload[0][0] = (badQPayload.QPayload[0][0] + 1) % ringQ.Modulus[0]
	ok, err = VerifyIntGenISISShowing(pub, &badQPayload, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 showing verified with tampered Q payload")
	}
	missingQPayload := *thetaProof
	missingQPayload.QPayload = nil
	missingQPayload.QPayloadBits = nil
	ok, err = VerifyIntGenISISShowing(pub, &missingQPayload, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 showing verified without Q payload")
	}
	badQRows := *thetaProof
	badQRows.QPayload = copyMatrix(thetaProof.QPayloadMatrix())
	badQRows.QPayloadBits = nil
	if len(badQRows.QPayload) > 1 {
		badQRows.QPayload = badQRows.QPayload[:len(badQRows.QPayload)-1]
	} else {
		badQRows.QPayload = append(badQRows.QPayload, append([]uint64(nil), badQRows.QPayload[0]...))
	}
	ok, err = VerifyIntGenISISShowing(pub, &badQRows, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 showing verified with tampered Q payload row count")
	}
	badQDegree := *thetaProof
	badQDegree.QPayload = copyMatrix(thetaProof.QPayloadMatrix())
	badQDegree.QPayloadBits = nil
	overflowCoeff := thetaProof.QDegreeBound + 1
	for len(badQDegree.QPayload[0]) <= overflowCoeff {
		badQDegree.QPayload[0] = append(badQDegree.QPayload[0], 0)
	}
	badQDegree.QPayload[0][overflowCoeff] = 1
	ok, err = VerifyIntGenISISShowing(pub, &badQDegree, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 showing verified with Q payload degree overflow")
	}
	redundantQ := *thetaProof
	redundantQ.QRoot[0] = 1
	ok, err = VerifyIntGenISISShowing(pub, &redundantQ, thetaOpts)
	if err == nil && ok {
		t.Fatal("theta>1 showing verified with redundant strict QRoot")
	}

	tamperedProof := *proof
	tamperedProof.RowLayout.IntGenISISShowing = &IntGenISISShowingRowLayout{}
	*tamperedProof.RowLayout.IntGenISISShowing = *proof.RowLayout.IntGenISISShowing
	tamperedProof.RowLayout.IntGenISISShowing.UShortnessRadix = 13
	ok, err = VerifyIntGenISISShowing(pub, &tamperedProof, opts)
	if err == nil && ok {
		t.Fatal("showing verifier accepted tampered u shortness metadata")
	}
	tamperedDegree := *proof
	tamperedDegree.QDegreeBound--
	ok, err = VerifyIntGenISISShowing(pub, &tamperedDegree, opts)
	if err == nil && ok {
		t.Fatal("showing verifier accepted tampered q degree")
	}

	unsafeOpts := opts
	unsafeOpts.UnsafeSigLookupShadowR121L2 = SigLookupShadowR121L2SameQ
	if _, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, unsafeOpts); err == nil {
		t.Fatal("build accepted unsafe R121/L2 shadow mode for IntGenISIS")
	}
	ok, err = VerifyIntGenISISShowing(pub, proof, unsafeOpts)
	if err == nil && ok {
		t.Fatal("verify accepted unsafe R121/L2 shadow mode for IntGenISIS")
	}
	rawR121Opts := opts
	rawR121Opts.SigShortnessRadix = 121
	rawR121Opts.SigShortnessL = 2
	if _, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, rawR121Opts); err == nil {
		t.Fatal("build accepted raw R121/L2 shortness override for IntGenISIS")
	}

	overBound := *cn
	overBound.Sig = clonePolySliceForIntGenISISTest(ringQ, cn.Sig)
	sigBound, err := intGenISISSignatureBoundFromPublic(pub)
	if err != nil {
		t.Fatalf("signature bound: %v", err)
	}
	overBound.Sig[0].Coeffs[0][0] = uint64(sigBound+1) % ringQ.Modulus[0]
	if _, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: &overBound}, opts); err == nil {
		t.Fatal("build accepted u coefficient above configured signature bound")
	}

	tampered := pub
	tampered.Com = []*ring.Poly{ringQ.NewPoly()}
	ok, err = VerifyIntGenISISShowing(tampered, proof, opts)
	if err == nil && ok {
		t.Fatal("showing verifier accepted forbidden public commitment")
	}

	tampered = pub
	tampered.B = clonePolySliceForIntGenISISTest(ringQ, pub.B)
	tampered.B[0].Coeffs[0][0] ^= 1
	ok, err = VerifyIntGenISISShowing(tampered, proof, opts)
	if err == nil && ok {
		t.Fatal("showing verifier accepted tampered target public data")
	}
}

func assertIntGenISISShowingPreparedConstraintsMatchRebuild(t *testing.T, ringQ *ring.Ring, pub PublicInputs, cn *CoeffNativeShowingWitness, params *prf.Params, opts SimOpts) {
	t.Helper()
	debugPub, err := bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), opts)
	if err != nil {
		t.Fatalf("bind strict showing public extras: %v", err)
	}
	rows, rowInputs, layout, _, companion, _, _, _, witnessCount, _, builtNCols, err := BuildCredentialRowsShowingIntGenISIS(
		ringQ,
		debugPub,
		WitnessInputs{CoeffNativeShowing: cn},
		params.LenKey,
		params.LenNonce,
		params.RF,
		params.RP,
		opts.PRFGroupRounds,
		opts,
	)
	if err != nil {
		t.Fatalf("strict showing rows: %v", err)
	}
	omega, err := deriveRelationWitnessOmega(ringQ.Modulus[0], opts.NLeaves, opts.NCols, opts.LVCSNCols, opts.Ell, pub.HashRelation)
	if err != nil {
		t.Fatalf("strict showing omega: %v", err)
	}
	if len(omega) < builtNCols {
		t.Fatalf("strict showing omega len=%d built ncols=%d", len(omega), builtNCols)
	}
	omegaWitness := omega[:builtNCols]
	preparedRowsNTT := nttRowsForIntGenISISTest(ringQ, rows)
	preparedSet, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, debugPub, layout, preparedRowsNTT, omegaWitness, companion, nil)
	if err != nil {
		t.Fatalf("strict showing prepared constraints: %v", err)
	}
	rebuiltRows := rows
	if opts.Theta > 1 {
		logical, lerr := normalizePreparedCredentialLogicalRows(ringQ, debugPub, rows, rowInputs, layout, witnessCount, omegaWitness, builtNCols)
		if lerr != nil {
			t.Fatalf("strict showing logical rows: %v", lerr)
		}
		rebuiltRows = logical.Rows
	}
	rebuiltRowsNTT := nttRowsForIntGenISISTest(ringQ, rebuiltRows)
	rebuiltSet, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, debugPub, layout, rebuiltRowsNTT, omegaWitness, companion, nil)
	if err != nil {
		t.Fatalf("strict showing rebuilt constraints: %v", err)
	}
	assertConstraintSetsEqualForIntGenISISTest(t, ringQ, preparedSet, rebuiltSet)
}

func nttRowsForIntGenISISTest(ringQ *ring.Ring, rows []*ring.Poly) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	for i := range rows {
		if rows[i] == nil {
			continue
		}
		out[i] = ringQ.NewPoly()
		ring.Copy(rows[i], out[i])
		ringQ.NTT(out[i], out[i])
	}
	return out
}

func assertConstraintSetsEqualForIntGenISISTest(t *testing.T, ringQ *ring.Ring, got, want ConstraintSet) {
	t.Helper()
	if got.ParallelAlgDeg != want.ParallelAlgDeg || got.AggregatedAlgDeg != want.AggregatedAlgDeg {
		t.Fatalf("constraint degrees got=(%d,%d) want=(%d,%d)", got.ParallelAlgDeg, got.AggregatedAlgDeg, want.ParallelAlgDeg, want.AggregatedAlgDeg)
	}
	assertConstraintBucketEqualForIntGenISISTest(t, ringQ, "FparInt", got.FparInt, want.FparInt, got.FparIntCoeffs, want.FparIntCoeffs)
	assertConstraintBucketEqualForIntGenISISTest(t, ringQ, "FparNorm", got.FparNorm, want.FparNorm, got.FparNormCoeffs, want.FparNormCoeffs)
	assertConstraintBucketEqualForIntGenISISTest(t, ringQ, "FaggInt", got.FaggInt, want.FaggInt, got.FaggIntCoeffs, want.FaggIntCoeffs)
	assertConstraintBucketEqualForIntGenISISTest(t, ringQ, "FaggNorm", got.FaggNorm, want.FaggNorm, got.FaggNormCoeffs, want.FaggNormCoeffs)
}

func assertConstraintBucketEqualForIntGenISISTest(t *testing.T, ringQ *ring.Ring, name string, gotPolys, wantPolys []*ring.Poly, gotCoeffs, wantCoeffs [][]uint64) {
	t.Helper()
	if len(gotPolys) != len(wantPolys) || len(gotCoeffs) != len(wantCoeffs) {
		t.Fatalf("%s lengths got polys/coeffs=%d/%d want=%d/%d", name, len(gotPolys), len(gotCoeffs), len(wantPolys), len(wantCoeffs))
	}
	for i := range gotPolys {
		switch {
		case gotPolys[i] == nil && wantPolys[i] == nil:
		case gotPolys[i] == nil || wantPolys[i] == nil:
			t.Fatalf("%s[%d] nil mismatch got=%v want=%v", name, i, gotPolys[i] == nil, wantPolys[i] == nil)
		default:
			for j := range gotPolys[i].Coeffs[0] {
				if gotPolys[i].Coeffs[0][j]%ringQ.Modulus[0] != wantPolys[i].Coeffs[0][j]%ringQ.Modulus[0] {
					t.Fatalf("%s[%d] ntt coeff[%d] got=%d want=%d", name, i, j, gotPolys[i].Coeffs[0][j]%ringQ.Modulus[0], wantPolys[i].Coeffs[0][j]%ringQ.Modulus[0])
				}
			}
		}
	}
	for i := range gotCoeffs {
		if len(gotCoeffs[i]) != len(wantCoeffs[i]) {
			t.Fatalf("%s coeff[%d] len got=%d want=%d", name, i, len(gotCoeffs[i]), len(wantCoeffs[i]))
		}
		for j := range gotCoeffs[i] {
			if gotCoeffs[i][j]%ringQ.Modulus[0] != wantCoeffs[i][j]%ringQ.Modulus[0] {
				t.Fatalf("%s coeff[%d][%d] got=%d want=%d", name, i, j, gotCoeffs[i][j]%ringQ.Modulus[0], wantCoeffs[i][j]%ringQ.Modulus[0])
			}
		}
	}
}

func intGenISISTestCoeffConst(ringQ *ring.Ring, v uint64) *ring.Poly {
	p := ringQ.NewPoly()
	p.Coeffs[0][0] = v % ringQ.Modulus[0]
	return p
}

func intGenISISTestPublicConstNTT(ringQ *ring.Ring, v uint64) *ring.Poly {
	p := intGenISISTestCoeffConst(ringQ, v)
	ringQ.NTT(p, p)
	return p
}

func intGenISISTestPublicBinomialNTT(ringQ *ring.Ring, c0, c1 uint64) *ring.Poly {
	p := ringQ.NewPoly()
	p.Coeffs[0][0] = c0 % ringQ.Modulus[0]
	p.Coeffs[0][1] = c1 % ringQ.Modulus[0]
	ringQ.NTT(p, p)
	return p
}

func intGenISISTestNTT(ringQ *ring.Ring, p *ring.Poly) *ring.Poly {
	out := ringQ.NewPoly()
	ring.Copy(p, out)
	ringQ.NTT(out, out)
	return out
}

func bucketHasNonZeroOmegaValue(ringQ *ring.Ring, omega []uint64, polys []*ring.Poly, coeffs [][]uint64) (bool, error) {
	if ringQ == nil {
		return false, nil
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
		for _, w := range omega {
			if EvalPoly(coeffVals, w%q, q)%q != 0 {
				return true, nil
			}
		}
	}
	return false, nil
}
