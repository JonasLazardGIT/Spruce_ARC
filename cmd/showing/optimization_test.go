package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/issuance"
	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/signverify"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func stablePaperTranscriptScore(rep PIOP.PaperTranscriptReport) int {
	return rep.Counters.OptimizedBytes +
		rep.SaltRoot.OptimizedBytes +
		rep.ExtraHash.OptimizedBytes +
		rep.R.OptimizedBytes +
		rep.Q.OptimizedBytes +
		rep.VTargets.OptimizedBytes +
		rep.BarSets.OptimizedBytes +
		rep.Pdecs.OptimizedBytes +
		rep.Mdecs.OptimizedBytes +
		rep.Tapes.OptimizedBytes
}

func optimizationPolyToInt64(r *ring.Ring, p *ring.Poly, ntt bool) []int64 {
	cp := r.NewPoly()
	ring.Copy(p, cp)
	if ntt {
		r.InvNTT(cp, cp)
	}
	out := make([]int64, r.N)
	q := int64(r.Modulus[0])
	half := q / 2
	for i, c := range cp.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		out[i] = v
	}
	return out
}

func optimizationPolyVecToInt64(r *ring.Ring, rows []*ring.Poly, ntt bool) [][]int64 {
	out := make([][]int64, len(rows))
	for i, p := range rows {
		out[i] = optimizationPolyToInt64(r, p, ntt)
	}
	return out
}

func optimizationIdentityAc(r *ring.Ring, cols int) [][]*ring.Poly {
	mat := make([][]*ring.Poly, cols)
	for i := 0; i < cols; i++ {
		mat[i] = make([]*ring.Poly, cols)
		for j := 0; j < cols; j++ {
			if i == j {
				p := r.NewPoly()
				p.Coeffs[0][0] = 1
				r.NTT(p, p)
				mat[i][j] = p
				continue
			}
			mat[i][j] = r.NewPoly()
		}
	}
	return mat
}

func buildDeterministicCredentialStateForPackedNCols(t *testing.T, packedNCols int) credential.State {
	t.Helper()
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	prfParams, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:       true,
		Theta:            1,
		EllPrime:         2,
		Rho:              2,
		NCols:            packedNCols,
		Ell:              18,
		Eta:              19,
		DomainMode:       PIOP.DomainModeExplicit,
		NLeaves:          4096,
		ShowingPreset:    PIOP.ShowingPresetCustom,
		CoeffPacking:     true,
		PRFGroupRounds:   2,
		PRFCompanionMode: PIOP.PRFCompanionModeOutputAudit,
	})
	if opts.NCols < 2*prfParams.LenKey {
		opts.NCols = 2 * prfParams.LenKey
	}
	if opts.NCols%2 != 0 {
		opts.NCols++
	}
	lvcsNCols := 96
	if lvcsNCols < opts.NCols {
		lvcsNCols = opts.NCols
	}
	opts.LVCSNCols = lvcsNCols
	opts.PostSignLVCSNCols = lvcsNCols
	opts.PRFLVCSNCols = lvcsNCols

	omega, err := deriveOmegaForOpts(ringQ, opts)
	if err != nil {
		t.Fatalf("derive optimization omega for ncols=%d: %v", opts.NCols, err)
	}
	q := ringQ.Modulus[0]
	rng := rand.New(rand.NewSource(1))
	sampleTernaryPoly := func(ncols int) *ring.Poly {
		p := ringQ.NewPoly()
		if ncols > len(p.Coeffs[0]) {
			ncols = len(p.Coeffs[0])
		}
		for i := 0; i < ncols; i++ {
			v := int64(rng.Intn(3) - 1)
			if v < 0 {
				p.Coeffs[0][i] = q - uint64(-v)%q
			} else {
				p.Coeffs[0][i] = uint64(v) % q
			}
		}
		return p
	}

	params := &credential.Params{
		Ac:           optimizationIdentityAc(ringQ, 5),
		HashRelation: credential.HashRelationBBS,
		BPath:        filepath.Join("Parameters", "Bmatrix.json"),
		AcPath:       filepath.Join("Parameters", "credential_public_bbs.json"),
		BoundB:       1,
		RingQ:        ringQ,
		LenM1:        1,
		LenM2:        1,
		LenRU0:       1,
		LenRU1:       1,
		LenR:         1,
	}
	inputs := issuance.Inputs{
		M1:  []*ring.Poly{ringQ.NewPoly()},
		M2:  []*ring.Poly{ringQ.NewPoly()},
		RU0: []*ring.Poly{sampleTernaryPoly(len(omega))},
		RU1: []*ring.Poly{sampleTernaryPoly(len(omega))},
		R:   []*ring.Poly{sampleTernaryPoly(len(omega))},
	}
	ch := issuance.Challenge{
		RI0: []*ring.Poly{ringQ.NewPoly()},
		RI1: []*ring.Poly{ringQ.NewPoly()},
	}
	com, err := issuance.PrepareCommit(params, inputs, omega)
	if err != nil {
		t.Fatalf("prepare commit for ncols=%d: %v", opts.NCols, err)
	}
	st, err := issuance.ApplyChallenge(params, inputs, ch, omega)
	if err != nil {
		t.Fatalf("apply challenge for ncols=%d: %v", opts.NCols, err)
	}
	sig, err := signverify.SignTarget(st.T, 2048, ntru.SamplerOpts{})
	if err != nil {
		t.Fatalf("sign target for ncols=%d: %v", opts.NCols, err)
	}

	out := credential.State{
		M1:                   optimizationPolyVecToInt64(ringQ, inputs.M1, false),
		M2:                   optimizationPolyVecToInt64(ringQ, inputs.M2, false),
		RU0:                  optimizationPolyVecToInt64(ringQ, inputs.RU0, false),
		RU1:                  optimizationPolyVecToInt64(ringQ, inputs.RU1, false),
		R:                    optimizationPolyVecToInt64(ringQ, inputs.R, false),
		R0:                   optimizationPolyVecToInt64(ringQ, st.R0, false),
		R1:                   optimizationPolyVecToInt64(ringQ, st.R1, false),
		K0:                   optimizationPolyVecToInt64(ringQ, st.K0, false),
		K1:                   optimizationPolyVecToInt64(ringQ, st.K1, false),
		T:                    append([]int64(nil), st.T...),
		Com:                  optimizationPolyVecToInt64(ringQ, com, true),
		RI0:                  optimizationPolyVecToInt64(ringQ, ch.RI0, true),
		RI1:                  optimizationPolyVecToInt64(ringQ, ch.RI1, true),
		CredentialPublicPath: filepath.Join("Parameters", "credential_public_bbs.json"),
		HashRelation:         credential.HashRelationBBS,
		BPath:                filepath.Join("Parameters", "Bmatrix.json"),
		PRFParamsPath:        filepath.Join("prf", "prf_params.json"),
		PackedNCols:          opts.NCols,
		B:                    optimizationPolyVecToInt64(ringQ, st.B, true),
	}
	out.SigS1 = append([]int64(nil), sig.Signature.S1...)
	out.SigS2 = append([]int64(nil), sig.Signature.S2...)
	return out
}

func buildShowingProofForOptimizationState(t *testing.T, st credential.State, opts PIOP.SimOpts) (*PIOP.Proof, PIOP.ProofReport) {
	t.Helper()
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	params, err := loadPRFParamsFromState(st)
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	wit, err := buildWitnessFromState(ringQ, st)
	if err != nil {
		t.Fatalf("build witness from optimization state: %v", err)
	}
	A, err := buildSignatureMatrix(ringQ, st, showingSignatureComponentCount(wit))
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	publicParams, err := loadCredentialPublicParamsFromState(st)
	if err != nil {
		t.Fatalf("load credential public params: %v", err)
	}
	B, err := loadBForShowing(ringQ, st, publicParams)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	key, err := prfKeyFromSignedWitness(ringQ, wit.CoeffNativeShowing, params.LenKey)
	if err != nil {
		t.Fatalf("derive prf key: %v", err)
	}
	nonce, noncePublic := sampleNonceForTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	pub := PIOP.PublicInputs{
		A:            A,
		B:            B,
		Tag:          lanesFromElems(tag, opts.NCols),
		Nonce:        noncePublic,
		BoundB:       publicParams.BoundB,
		HashRelation: publicParams.HashRelation,
	}
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		t.Fatalf("build showing for ncols=%d lvcs=%d preset=%s: %v", opts.NCols, opts.PostSignLVCSNCols, opts.ShowingPreset, err)
	}
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("verify showing for ncols=%d lvcs=%d preset=%s: %v", opts.NCols, opts.PostSignLVCSNCols, opts.ShowingPreset, err)
	}
	if !ok {
		t.Fatalf("verify showing returned ok=false for ncols=%d lvcs=%d preset=%s", opts.NCols, opts.PostSignLVCSNCols, opts.ShowingPreset)
	}
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		t.Fatalf("proof report: %v", err)
	}
	return proof, rep
}

func optimizationLVCSCandidates(ncols int) []int {
	seen := map[int]bool{}
	out := make([]int, 0, 32)
	add := func(v int) {
		if v < ncols || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for v := 24; v <= 256; v += 8 {
		add(v)
	}
	add(28)
	// keep deterministic ascending order
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestShowingFullReplayModeDeterministicPackedWidths(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	// The deterministic issuance fixture used here is currently admissible for
	// 64 and 128 columns. The 256-column case exceeds the present pre-sign
	// alias-degree budget and is left to the wider parameter sweep.
	for _, ncols := range []int{64, 128} {
		state := buildDeterministicCredentialStateForPackedNCols(t, ncols)
		lvcsNCols := 128
		if lvcsNCols < ncols {
			lvcsNCols = ncols
		}
		opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
			Credential:          true,
			NCols:               ncols,
			Ell:                 18,
			DomainMode:          PIOP.DomainModeExplicit,
			ShowingPreset:       PIOP.ShowingPresetSoundnessBalanced,
			ShowingReplayMode:   PIOP.ShowingReplayModeFull,
			CoeffPacking:        true,
			PRFGroupRounds:      2,
			PRFCompanionMode:    PIOP.PRFCompanionModeOutputAudit,
			LVCSNCols:           lvcsNCols,
			PostSignLVCSNCols:   lvcsNCols,
			PRFLVCSNCols:        lvcsNCols,
			CoeffNativeSigModel: PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
			SigShortnessProfile: PIOP.SigShortnessProfileR11L4Production,
		})
		wantBlocks := len(state.T) / ncols
		ringQ, err := credential.LoadDefaultRing()
		if err != nil {
			t.Fatalf("load ring: %v", err)
		}
		params, err := loadPRFParamsFromState(state)
		if err != nil {
			t.Fatalf("load prf params: %v", err)
		}
		wit, err := buildWitnessFromState(ringQ, state)
		if err != nil {
			t.Fatalf("build witness from state: %v", err)
		}
		A, err := buildSignatureMatrix(ringQ, state, showingSignatureComponentCount(wit))
		if err != nil {
			t.Fatalf("build A: %v", err)
		}
		publicParams, err := loadCredentialPublicParamsFromState(state)
		if err != nil {
			t.Fatalf("load credential public params: %v", err)
		}
		B, err := loadBForShowing(ringQ, state, publicParams)
		if err != nil {
			t.Fatalf("load B: %v", err)
		}
		key, err := prfKeyFromSignedWitness(ringQ, wit.CoeffNativeShowing, params.LenKey)
		if err != nil {
			t.Fatalf("derive prf key: %v", err)
		}
		nonce, noncePublic := sampleNonceForTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
		tag, err := prf.Tag(key, nonce, params)
		if err != nil {
			t.Fatalf("tag: %v", err)
		}
		pub := PIOP.PublicInputs{
			A:            A,
			B:            B,
			Tag:          lanesFromElems(tag, opts.NCols),
			Nonce:        noncePublic,
			BoundB:       publicParams.BoundB,
			HashRelation: publicParams.HashRelation,
		}
		_, _, layout, _, companionLayout, _, _, _, witnessCount, _, _, err := PIOP.BuildCredentialRowsShowing(
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
			t.Fatalf("build full replay rows for ncols=%d: %v", ncols, err)
		}
		if got := layout.ReplayBlockCount; got != wantBlocks {
			t.Fatalf("ncols=%d replay blocks=%d want %d", ncols, got, wantBlocks)
		}
		if got := layout.ReplayTHatCount; got != wantBlocks {
			t.Fatalf("ncols=%d replay T-hat count=%d want %d", ncols, got, wantBlocks)
		}
		if companionLayout == nil {
			t.Fatalf("ncols=%d missing prf companion layout", ncols)
		}
		if got := layout.SigCount; got != witnessCount {
			t.Fatalf("ncols=%d layout sig count=%d want witness count=%d", ncols, got, witnessCount)
		}
		if ncols == 64 {
			proof, rep := buildShowingProofForOptimizationState(t, state, opts)
			if got := proof.RowLayout.ReplayBlockCount; got != wantBlocks {
				t.Fatalf("ncols=%d proof replay blocks=%d want %d", ncols, got, wantBlocks)
			}
			if got := rep.TranscriptFocus.ReplayBlocks; got != wantBlocks {
				t.Fatalf("ncols=%d report replay blocks=%d want %d", ncols, got, wantBlocks)
			}
			if got := rep.TranscriptFocus.ReplayMode; got != string(PIOP.ShowingReplayModeFull) {
				t.Fatalf("ncols=%d replay mode=%q want %q", ncols, got, PIOP.ShowingReplayModeFull)
			}
		}
	}
}

func TestShowingProductionBetaAuditMatchesCalibrationPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)

	par, err := ntrurio.LoadParams(filepath.Join("Parameters", "Parameters.json"), true)
	if err != nil {
		t.Fatalf("load params: %v", err)
	}
	rawParams, err := os.ReadFile(filepath.Join("Parameters", "Parameters.json"))
	if err != nil {
		t.Fatalf("read params json: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(rawParams, &raw); err != nil {
		t.Fatalf("unmarshal params json: %v", err)
	}
	state, err := credential.LoadState(filepath.Join(root, "credential", "keys", "credential_state.json"))
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	calibration, err := signverify.CalibrateMeasuredBeta(signverify.SignPaths{
		ParamsPath:    filepath.Join("Parameters", "Parameters.json"),
		BFile:         filepath.Join("Parameters", "Bmatrix.json"),
		PublicKeyPath: filepath.Join("ntru_keys", "public.json"),
		PrivatePath:   filepath.Join("ntru_keys", "private.json"),
	}, 64, 2048, ntru.SamplerOpts{
		AutoTuneAlpha:       true,
		AutoTuneAlphaMargin: 1.00,
	})
	if err != nil {
		t.Fatalf("calibrate beta: %v", err)
	}
	audit := buildSignatureBoundAuditReport(state, par.Beta, calibration)

	if audit.ProductionBeta == 0 {
		t.Fatalf("production beta is zero")
	}
	if audit.CalibrationBatchMax <= 0 {
		t.Fatalf("calibration batch max=%d", audit.CalibrationBatchMax)
	}
	boundValue, ok := raw["bound"].(float64)
	if !ok {
		t.Fatalf("params bound missing or non-numeric: %#v", raw["bound"])
	}
	if uint64(audit.CalibrationBatchMax) != par.Beta || uint64(boundValue) != par.Beta {
		t.Fatalf("beta/bound mismatch: audit=%d beta=%d bound=%d", audit.CalibrationBatchMax, par.Beta, uint64(boundValue))
	}
	if audit.CalibrationMaxSample < 0 || audit.CalibrationMaxSample >= audit.CalibrationSamples {
		t.Fatalf("calibration max sample=%d outside samples=%d", audit.CalibrationMaxSample, audit.CalibrationSamples)
	}
	if calibration.PerSample[audit.CalibrationMaxSample] != audit.CalibrationBatchMax {
		t.Fatalf("batch max sample mismatch: per_sample[%d]=%d batch_max=%d", audit.CalibrationMaxSample, calibration.PerSample[audit.CalibrationMaxSample], audit.CalibrationBatchMax)
	}
	if audit.StateMaxS1 <= 0 || audit.StateMaxS2 <= 0 || audit.StateMax <= 0 {
		t.Fatalf("unexpected state norm audit: %+v", audit)
	}
	if uint64(audit.StateMax) > audit.ProductionBeta {
		t.Fatalf("state max=%d exceeds beta=%d", audit.StateMax, audit.ProductionBeta)
	}
	if audit.CalibrationBatchMax < audit.StateMax {
		t.Fatalf("calibration batch max=%d below persisted state max=%d", audit.CalibrationBatchMax, audit.StateMax)
	}
	if audit.SlackRatio <= 1 {
		t.Fatalf("slack ratio=%f want >1", audit.SlackRatio)
	}
	t.Logf("beta audit: beta=%d state_max={s1=%d s2=%d max=%d} calibration={samples=%d alpha=%.6f batch_max=%d idx=%d} slack=%.4f",
		audit.ProductionBeta,
		audit.StateMaxS1,
		audit.StateMaxS2,
		audit.StateMax,
		audit.CalibrationSamples,
		audit.CalibrationAlpha,
		audit.CalibrationBatchMax,
		audit.CalibrationMaxSample,
		audit.SlackRatio)
}

type shortnessCandidate struct {
	label   string
	profile string
	radix   int
	digits  int
}

func buildShortnessCandidatesForBeta(t *testing.T) []shortnessCandidate {
	t.Helper()
	root := showingTestRepoRoot(t)
	chdirForShowingTest(t, root)
	const ringQ = uint64(1054721)
	seen := map[string]bool{}
	add := func(out *[]shortnessCandidate, c shortnessCandidate) {
		key := fmt.Sprintf("%s:%s:%d:%d", c.label, c.profile, c.radix, c.digits)
		if seen[key] {
			return
		}
		seen[key] = true
		*out = append(*out, c)
	}

	out := []shortnessCandidate{
		{label: PIOP.SigShortnessProfileR11L4Production, profile: PIOP.SigShortnessProfileR11L4Production},
	}
	for digits := 2; digits <= 6; digits++ {
		base, gotDigits, _, err := PIOP.ResolveSignatureBoundShapeForOpts(ringQ, PIOP.SimOpts{
			CoeffNativeSigModel: PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
			SigShortnessL:       digits,
		})
		if err != nil {
			t.Logf("skip shortness L=%d: %v", digits, err)
			continue
		}
		if base > 16 {
			t.Logf("skip shortness L=%d: minimal radix=%d exceeds sweep cap", gotDigits, base)
			continue
		}
		add(&out, shortnessCandidate{
			label:  fmt.Sprintf("minimal_r%d_l%d", base, gotDigits),
			radix:  base,
			digits: gotDigits,
		})
		for radix := base + 1; radix <= 16; radix++ {
			add(&out, shortnessCandidate{
				label:  fmt.Sprintf("raw_r%d_l%d", radix, gotDigits),
				radix:  radix,
				digits: gotDigits,
			})
		}
	}
	return out
}

func presetLVCSNColsForOptimization(preset string) int {
	switch preset {
	case PIOP.ShowingPresetSoundnessBalanced:
		return 96
	case PIOP.ShowingPresetTranscriptFirst, PIOP.ShowingPresetProductionBalance:
		return 32
	default:
		return 32
	}
}

func TestShowingShortnessSweepKeepsProductionProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	type measured struct {
		shortnessCandidate
		score     int
		total     int
		pdecs     int
		vtargets  int
		barsets   int
		q         int
		soundness float64
	}
	better := func(got, best measured) bool {
		switch {
		case got.total != best.total:
			return got.total < best.total
		case got.pdecs+got.vtargets+got.barsets != best.pdecs+best.vtargets+best.barsets:
			return got.pdecs+got.vtargets+got.barsets < best.pdecs+best.vtargets+best.barsets
		case got.q != best.q:
			return got.q < best.q
		case got.digits != best.digits:
			return got.digits < best.digits
		default:
			return got.radix < best.radix
		}
	}

	var best *measured
	for _, cand := range buildShortnessCandidatesForBeta(t) {
		if cand.radix > 0 || cand.digits > 0 {
			if _, _, _, _, err := PIOP.ResolveSignatureShortnessMetricsForOpts(1054721, PIOP.SimOpts{
				CoeffNativeSigModel: PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
				SigShortnessRadix:   cand.radix,
				SigShortnessL:       cand.digits,
			}); err != nil {
				t.Logf("shortness candidate %s rejected before build: %v", cand.label, err)
				continue
			}
		}
		_, rep, _, _, _, _ := buildShowingProofForTestConfigWithResearchKnobs(
			t,
			PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
			false,
			false,
			"",
			8,
			PIOP.ShowingPresetSoundnessBalanced,
			cand.profile,
			cand.radix,
			cand.digits,
			16,
			presetLVCSNColsForOptimization(PIOP.ShowingPresetSoundnessBalanced),
		)
		got := measured{
			shortnessCandidate: cand,
			score:              stablePaperTranscriptScore(rep.PaperTranscript),
			total:              rep.PaperTranscript.OptimizedBytes,
			pdecs:              rep.PaperTranscript.Pdecs.OptimizedBytes,
			vtargets:           rep.PaperTranscript.VTargets.OptimizedBytes,
			barsets:            rep.PaperTranscript.BarSets.OptimizedBytes,
			q:                  rep.PaperTranscript.Q.OptimizedBytes,
			soundness:          rep.Soundness.TotalBits,
		}
		if rep.Soundness.TotalBits < 100 {
			t.Logf("shortness candidate %s rejected by theorem floor: %.2f", cand.label, rep.Soundness.TotalBits)
			continue
		}
		t.Logf("shortness candidate %s -> stable=%d total=%d Pdecs=%d VTargets=%d BarSets=%d Q=%d soundness=%.2f",
			cand.label, got.score, got.total, got.pdecs, got.vtargets, got.barsets, got.q, got.soundness)
		if best == nil || better(got, *best) {
			copy := got
			best = &copy
		}
	}
	if best == nil {
		t.Fatalf("no shortness candidates measured")
	}
	bestRadix, bestDigits, _, _, err := PIOP.ResolveSignatureShortnessMetricsForOpts(1054721, PIOP.SimOpts{
		CoeffNativeSigModel: PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		SigShortnessProfile: best.profile,
		SigShortnessRadix:   best.radix,
		SigShortnessL:       best.digits,
	})
	if err != nil {
		t.Fatalf("resolve best shortness candidate %s: %v", best.label, err)
	}
	if bestRadix != 11 || bestDigits != 4 {
		t.Fatalf("best shortness candidate=%s resolved to (R=%d,L=%d) want (11,4)", best.label, bestRadix, bestDigits)
	}
}

type nizkCandidate struct {
	label  string
	mutate func(*PIOP.SimOpts)
}

func TestShowingNIZKRetuneSelectsTheta3Eta43Preset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	candidates := []nizkCandidate{
		{
			label: "old_soundness_balanced_theta5_eta63",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 96, 96, 96
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4096, 4096, 4096
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 5, 2, 2, 63
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
		{
			label: "rho1_theta5_eta43",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 96, 96, 96
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4096, 4096, 4096
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 5, 1, 2, 43
				opts.Kappa = [4]int{0, 5, 0, 5}
			},
		},
		{
			label: "theta4_eta43",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 96, 96, 96
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4096, 4096, 4096
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 4, 2, 2, 43
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
		{
			label: "theta3_eta43",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 96, 96, 96
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4096, 4096, 4096
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 3, 2, 2, 43
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
		{
			label: "narrow_lvcs80_theta3_eta43",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 80, 80, 80
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 3072, 3072, 3072
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 3, 2, 2, 43
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
		{
			label: "wide_lvcs112_theta3_eta44",
			mutate: func(opts *PIOP.SimOpts) {
				opts.ShowingPreset = PIOP.ShowingPresetCustom
				opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols = 112, 112, 112
				opts.NLeaves, opts.PostSignNLeaves, opts.PRFNLeaves = 4608, 4608, 4608
				opts.Theta, opts.Rho, opts.EllPrime, opts.Eta = 3, 2, 2, 44
				opts.Kappa = [4]int{0, 0, 0, 5}
			},
		},
	}

	type measured struct {
		label     string
		score     int
		total     int
		pdecs     int
		vtargets  int
		barsets   int
		q         int
		soundness float64
	}
	var best *measured
	for _, cand := range candidates {
		_, rep, _, _, _, _ := buildShowingProofForTestConfigWithResearchKnobsAndMutator(
			t,
			PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
			false,
			false,
			"",
			8,
			PIOP.ShowingPresetSoundnessBalanced,
			PIOP.SigShortnessProfileR11L4Production,
			0,
			0,
			16,
			0,
			cand.mutate,
		)
		got := measured{
			label:     cand.label,
			score:     stablePaperTranscriptScore(rep.PaperTranscript),
			total:     rep.PaperTranscript.OptimizedBytes,
			pdecs:     rep.PaperTranscript.Pdecs.OptimizedBytes,
			vtargets:  rep.PaperTranscript.VTargets.OptimizedBytes,
			barsets:   rep.PaperTranscript.BarSets.OptimizedBytes,
			q:         rep.PaperTranscript.Q.OptimizedBytes,
			soundness: rep.Soundness.TotalBits,
		}
		t.Logf("nizk candidate %s -> stable=%d total=%d Pdecs=%d VTargets=%d BarSets=%d Q=%d soundness=%.2f",
			got.label, got.score, got.total, got.pdecs, got.vtargets, got.barsets, got.q, got.soundness)
		if got.soundness < 100 {
			continue
		}
		if best == nil || got.score < best.score {
			copy := got
			best = &copy
		}
	}
	if best == nil {
		t.Fatalf("no candidate met the theorem floor")
	}
	if best.label != "theta3_eta43" {
		t.Fatalf("best NIZK candidate=%s want theta3_eta43", best.label)
	}
}

func TestShowingPackedWidthAndLVCSRetuneSelectsShippedDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	type presetWinner struct {
		preset    string
		lvcsNCols int
		total     int
		pdecs     int
		vtargets  int
		barsets   int
		auth      int
		q         int
		nrows     int
		soundness float64
	}
	betterPreset := func(got, best presetWinner) bool {
		switch {
		case got.total != best.total:
			return got.total < best.total
		case got.pdecs+got.vtargets+got.barsets+got.auth != best.pdecs+best.vtargets+best.barsets+best.auth:
			return got.pdecs+got.vtargets+got.barsets+got.auth < best.pdecs+best.vtargets+best.barsets+best.auth
		case got.q != best.q:
			return got.q < best.q
		case got.nrows != best.nrows:
			return got.nrows < best.nrows
		default:
			return got.lvcsNCols < best.lvcsNCols
		}
	}

	type ncolsWinner struct {
		ncols         int
		sumTotal      int
		worstTotal    int
		sumPayload    int
		sumQ          int
		perPresetBest []presetWinner
	}
	betterNCols := func(got, best ncolsWinner) bool {
		switch {
		case got.sumTotal != best.sumTotal:
			return got.sumTotal < best.sumTotal
		case got.worstTotal != best.worstTotal:
			return got.worstTotal < best.worstTotal
		case got.sumPayload != best.sumPayload:
			return got.sumPayload < best.sumPayload
		case got.sumQ != best.sumQ:
			return got.sumQ < best.sumQ
		default:
			return got.ncols < best.ncols
		}
	}

	presets := []string{
		PIOP.ShowingPresetSoundnessBalanced,
		PIOP.ShowingPresetTranscriptFirst,
		PIOP.ShowingPresetProductionBalance,
	}
	ncolsCandidates := []int{16, 32, 64}

	currentState, err := credential.LoadState(filepath.Join(showingTestRepoRoot(t), "credential", "keys", "credential_state.json"))
	if err != nil {
		t.Fatalf("load shipped credential state: %v", err)
	}
	shippedNCols, err := PIOP.ResolvePackedNCols(currentState.PackedNCols, 0, 1024)
	if err != nil {
		t.Fatalf("resolve shipped packed ncols: %v", err)
	}

	var best *ncolsWinner
	for _, ncols := range ncolsCandidates {
		state := buildDeterministicCredentialStateForPackedNCols(t, ncols)
		got := ncolsWinner{ncols: ncols}
		admissibleNCols := true
		for _, preset := range presets {
			var presetBest *presetWinner
			for _, lvcsNCols := range optimizationLVCSCandidates(ncols) {
				opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
					Credential:           true,
					NCols:                ncols,
					Ell:                  18,
					DomainMode:           PIOP.DomainModeExplicit,
					PRFGroupRounds:       2,
					CoeffPacking:         true,
					CoeffNativeSigModel:  PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
					ShowingPreset:        preset,
					SigShortnessProfile:  PIOP.SigShortnessProfileR11L4Production,
					PRFCompanionMode:     PIOP.PRFCompanionModeOutputAudit,
					PRFCheckpointSamples: 8,
					LVCSNCols:            lvcsNCols,
					PostSignLVCSNCols:    lvcsNCols,
					PRFLVCSNCols:         lvcsNCols,
				})
				_, rep := buildShowingProofForOptimizationState(t, state, opts)
				if rep.Soundness.TotalBits < 100 {
					t.Logf("reject preset=%s ncols=%d lvcs=%d by theorem floor: %.2f", preset, ncols, lvcsNCols, rep.Soundness.TotalBits)
					continue
				}
				cand := presetWinner{
					preset:    preset,
					lvcsNCols: lvcsNCols,
					total:     rep.PaperTranscript.OptimizedBytes,
					pdecs:     rep.PaperTranscript.Pdecs.OptimizedBytes,
					vtargets:  rep.PaperTranscript.VTargets.OptimizedBytes,
					barsets:   rep.PaperTranscript.BarSets.OptimizedBytes,
					auth:      rep.PaperTranscript.Auth.OptimizedBytes,
					q:         rep.PaperTranscript.Q.OptimizedBytes,
					nrows:     rep.TranscriptFocus.NRows,
					soundness: rep.Soundness.TotalBits,
				}
				t.Logf("packed sweep preset=%s ncols=%d lvcs=%d -> total=%d payload=%d q=%d nrows=%d soundness=%.2f",
					preset,
					ncols,
					lvcsNCols,
					cand.total,
					cand.pdecs+cand.vtargets+cand.barsets+cand.auth,
					cand.q,
					cand.nrows,
					cand.soundness,
				)
				if presetBest == nil || betterPreset(cand, *presetBest) {
					copy := cand
					presetBest = &copy
				}
			}
			if presetBest == nil {
				t.Logf("reject ncols=%d because preset=%s has no admissible lvcs candidate", ncols, preset)
				admissibleNCols = false
				break
			}
			got.perPresetBest = append(got.perPresetBest, *presetBest)
			got.sumTotal += presetBest.total
			got.sumPayload += presetBest.pdecs + presetBest.vtargets + presetBest.barsets + presetBest.auth
			got.sumQ += presetBest.q
			if presetBest.total > got.worstTotal {
				got.worstTotal = presetBest.total
			}
		}
		if !admissibleNCols {
			continue
		}
		t.Logf("packed sweep ncols=%d -> sumTotal=%d worst=%d payload=%d q=%d winners=%+v",
			got.ncols, got.sumTotal, got.worstTotal, got.sumPayload, got.sumQ, got.perPresetBest)
		if best == nil || betterNCols(got, *best) {
			copy := got
			best = &copy
		}
	}
	if best == nil {
		t.Fatalf("no admissible packed-width candidate")
	}
	if best.ncols != shippedNCols {
		t.Fatalf("best packed width=%d want shipped PackedNCols=%d", best.ncols, shippedNCols)
	}
	for _, winner := range best.perPresetBest {
		shipped := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
			Credential:           true,
			NCols:                shippedNCols,
			Ell:                  18,
			DomainMode:           PIOP.DomainModeExplicit,
			PRFGroupRounds:       2,
			CoeffPacking:         true,
			CoeffNativeSigModel:  PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
			ShowingPreset:        winner.preset,
			SigShortnessProfile:  PIOP.SigShortnessProfileR11L4Production,
			PRFCompanionMode:     PIOP.PRFCompanionModeOutputAudit,
			PRFCheckpointSamples: 8,
		})
		if winner.lvcsNCols != shipped.PostSignLVCSNCols {
			t.Fatalf("best lvcs for preset=%s is %d want shipped %d", winner.preset, winner.lvcsNCols, shipped.PostSignLVCSNCols)
		}
	}
}
