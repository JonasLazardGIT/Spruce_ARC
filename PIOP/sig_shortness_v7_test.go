package PIOP

import (
	"os"
	"path/filepath"
	"testing"

	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func skipSlowSigShortnessV7ResearchTest(t *testing.T) {
	t.Helper()
	if os.Getenv("SPRUCE_RUN_SLOW_V7_FULL") == "" {
		t.Skip("V7 full constraint/proof research checks are runtime-heavy; set SPRUCE_RUN_SLOW_V7_FULL=1 to run them")
	}
}

func buildSigShortnessV7Fixture(t *testing.T) transformBridgeFixture {
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
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		NCols:                16,
		Ell:                  18,
		DomainMode:           DomainModeExplicit,
		PRFGroupRounds:       2,
		CoeffPacking:         true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetCompactL1Research,
		ShowingReplayMode:    ShowingReplayModeFull,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	})
	omegaLVCS, domainPoints, err := func() ([]uint64, []uint64, error) {
		_, _, ncols, err := loadParamsAndOmegaForRelation(opts, publicParams.HashRelation)
		if err != nil {
			return nil, nil, err
		}
		return deriveExplicitDomainForRelation(ringQ.Modulus[0], opts.NLeaves, opts.NCols, ncols, opts.Ell, publicParams.HashRelation)
	}()
	if err != nil {
		t.Fatalf("derive omega/domain: %v", err)
	}
	omegaWitness := append([]uint64(nil), omegaLVCS[:opts.NCols]...)

	B, err := loadBAsNTTTest(ringQ, publicParams.BPath)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	cnWit, err := buildCoeffNativeShowingWitnessTest(ringQ, state, B)
	if err != nil {
		t.Fatalf("build coeff-native witness: %v", err)
	}
	wit := WitnessInputs{CoeffNativeShowing: cnWit}
	A, err := buildSignatureMatrixTest(ringQ, state, len(cnWit.Sig))
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	nonce, noncePublic := fixedNonceTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	pub := PublicInputs{
		A:            A,
		B:            B,
		Tag:          lanesFromElemsTest(make([]prf.Elem, params.LenTag), opts.NCols),
		Nonce:        noncePublic,
		BoundB:       publicParams.BoundB,
		HashRelation: publicParams.HashRelation,
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
	keyScalars, err := ExtractSignedPRFKeyScalarsFromCarrierOnOmega(ringQ, rows[layout.IdxCarrierM], omegaWitness, cnWit.PackedNCols, params.LenKey, publicParams.BoundB)
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

func clonePolysForSigShortnessV7Test(src []*ring.Poly, ringQ *ring.Ring) []*ring.Poly {
	if len(src) == 0 {
		return nil
	}
	out := make([]*ring.Poly, len(src))
	for i := range src {
		if src[i] == nil {
			continue
		}
		out[i] = ringQ.NewPoly()
		ring.Copy(src[i], out[i])
	}
	return out
}

func anyPolyNonZeroOnOmegaForSigShortnessV7Test(t *testing.T, ringQ *ring.Ring, omega []uint64, polys []*ring.Poly) bool {
	t.Helper()
	for i := range polys {
		vals, err := evalPolyOnOmegaTest(ringQ, omega, polys[i])
		if err != nil {
			t.Fatalf("eval poly[%d] on omega: %v", i, err)
		}
		for _, v := range vals {
			if v%ringQ.Modulus[0] != 0 {
				return true
			}
		}
	}
	return false
}

func TestSigShortnessV7CompactL1FullLayoutAndMetadata(t *testing.T) {
	fx := buildSigShortnessV7Fixture(t)
	if !sigShortnessV7EnabledForOpts(fx.opts) {
		t.Fatal("fixture opts did not enable V7")
	}
	if fx.layout.PackedSigChainBase < 0 || fx.layout.PackedSigChainGroupCount <= 0 || fx.layout.PackedSigChainRowsPerGroup <= 0 {
		t.Fatalf("missing packed shortness layout: %+v", fx.layout)
	}
	if fx.layout.IdxTSource >= 0 {
		t.Fatalf("compact full V7 should reconstruct T locally, got committed T source row %d", fx.layout.IdxTSource)
	}
	lastReplayRow := rowLayoutPostSignTHatIndex(fx.layout, rowLayoutReplayTHatCount(fx.layout)-1)
	if fx.layout.PackedSigChainBase <= lastReplayRow {
		t.Fatalf("packed shortness rows should start after replay rows: base=%d lastReplay=%d", fx.layout.PackedSigChainBase, lastReplayRow)
	}
	if fx.prfCompanion == nil {
		t.Fatal("missing PRF companion layout")
	}
	if fx.layout.PackedSigChainBase >= fx.prfCompanion.StartRow {
		t.Fatalf("packed shortness rows should precede PRF companion rows: shortness=%d prfStart=%d", fx.layout.PackedSigChainBase, fx.prfCompanion.StartRow)
	}
	firstShortnessRow := fx.layout.PackedSigChainBase
	shortnessCoeff, err := coeffFromNTTPoly(fx.ringQ, fx.rowsNTT[firstShortnessRow])
	if err != nil {
		t.Fatalf("packed shortness coeffs: %v", err)
	}
	if deg := maxDegreeFromCoeffs(shortnessCoeff); deg >= fx.opts.NCols {
		t.Fatalf("packed shortness row degree=%d want < witness ncols=%d", deg, fx.opts.NCols)
	}
	sig, err := buildSigShortnessProofV7Metadata(fx.ringQ, fx.layout, fx.opts)
	if err != nil {
		t.Fatalf("build V7 metadata: %v", err)
	}
	if sig == nil || sig.Version != sigShortnessProofVersionV7 || sig.V7 == nil {
		t.Fatalf("expected V7 metadata payload, got %+v", sig)
	}
	if sig.Opening != nil || len(sig.SupportSlots) != 0 {
		t.Fatalf("V7 should not carry legacy support opening data: %+v", sig)
	}
	if sig.V5 != nil || sig.V6 != nil {
		t.Fatalf("V7 should not carry legacy V5/V6 payloads: %+v", sig)
	}
}

func TestSigShortnessV7ConstraintFamiliesVanishOnWitnessOmega(t *testing.T) {
	skipSlowSigShortnessV7ResearchTest(t)
	fx := buildSigShortnessV7Fixture(t)
	set, err := buildSigShortnessV7ConstraintSet(fx.ringQ, fx.layout, fx.pub, fx.omegaWitness, fx.rowsNTT, fx.opts)
	if err != nil {
		t.Fatalf("build V7 shortness set: %v", err)
	}
	if len(set.FparNorm) == 0 || len(set.FaggNorm) == 0 {
		t.Fatalf("expected both FparNorm and FaggNorm families, got %+v", set)
	}
	if anyPolyNonZeroOnOmegaForSigShortnessV7Test(t, fx.ringQ, fx.omegaWitness, set.FparNorm) {
		t.Fatal("V7 FparNorm did not vanish on honest witness")
	}
	if anyPolyNonZeroOnOmegaForSigShortnessV7Test(t, fx.ringQ, fx.omegaWitness, set.FaggNorm) {
		t.Fatal("V7 FaggNorm did not vanish on honest witness")
	}
}

func TestSigShortnessV7TamperRejectsDigitAndTHatMismatch(t *testing.T) {
	skipSlowSigShortnessV7ResearchTest(t)
	fx := buildSigShortnessV7Fixture(t)

	t.Run("digit_row", func(t *testing.T) {
		rowsNTT := clonePolysForSigShortnessV7Test(fx.rowsNTT, fx.ringQ)
		rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(fx.layout, 0, 0, 0)
		if rowIdx < 0 {
			t.Fatal("missing packed digit row")
		}
		rowsNTT[rowIdx].Coeffs[0][0] = modAdd(rowsNTT[rowIdx].Coeffs[0][0], 1, fx.ringQ.Modulus[0])
		set, err := buildSigShortnessV7ConstraintSet(fx.ringQ, fx.layout, fx.pub, fx.omegaWitness, rowsNTT, fx.opts)
		if err != nil {
			t.Fatalf("build V7 shortness set after digit tamper: %v", err)
		}
		if !anyPolyNonZeroOnOmegaForSigShortnessV7Test(t, fx.ringQ, fx.omegaWitness, append(append([]*ring.Poly{}, set.FparNorm...), set.FaggNorm...)) {
			t.Fatal("digit tamper unexpectedly preserved all V7 constraints on omega")
		}
	})

	t.Run("t_hat_row", func(t *testing.T) {
		rowsNTT := clonePolysForSigShortnessV7Test(fx.rowsNTT, fx.ringQ)
		rowIdx := rowLayoutPostSignTHatIndex(fx.layout, 0)
		if rowIdx < 0 {
			t.Fatal("missing T-hat row")
		}
		rowsNTT[rowIdx].Coeffs[0][0] = modAdd(rowsNTT[rowIdx].Coeffs[0][0], 1, fx.ringQ.Modulus[0])
		set, err := buildSigShortnessV7ConstraintSet(fx.ringQ, fx.layout, fx.pub, fx.omegaWitness, rowsNTT, fx.opts)
		if err != nil {
			t.Fatalf("build V7 shortness set after T-hat tamper: %v", err)
		}
		if !anyPolyNonZeroOnOmegaForSigShortnessV7Test(t, fx.ringQ, fx.omegaWitness, set.FaggNorm) {
			t.Fatal("T-hat tamper unexpectedly preserved all V7 bridge constraints on omega")
		}
	})
}
