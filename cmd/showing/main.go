package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/domain"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type lineCategory int

const (
	categoryStatus lineCategory = iota
	categorySoundness
	categoryGeometry
	categoryTranscript
	categoryWarning
)

const (
	ansiReset   = "\033[0m"
	ansiCyan    = "\033[36m"
	ansiYellow  = "\033[33m"
	ansiGreen   = "\033[32m"
	ansiMagenta = "\033[35m"
	ansiRed     = "\033[31m"
)

type cliRenderer struct {
	out          io.Writer
	err          io.Writer
	colorEnabled bool
}

var cli = newCLIRenderer(os.Stdout, os.Stderr)

func newCLIRenderer(out, err io.Writer) cliRenderer {
	return cliRenderer{
		out:          out,
		err:          err,
		colorEnabled: stdoutSupportsColor(),
	}
}

func stdoutSupportsColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return false
	}
	info, statErr := os.Stdout.Stat()
	if statErr != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func styleMessage(enabled bool, category lineCategory, msg string) string {
	if !enabled {
		return msg
	}
	return colorForCategory(category) + msg + ansiReset
}

func colorForCategory(category lineCategory) string {
	switch category {
	case categoryStatus:
		return ansiCyan
	case categorySoundness:
		return ansiYellow
	case categoryGeometry:
		return ansiGreen
	case categoryTranscript:
		return ansiMagenta
	case categoryWarning:
		return ansiRed
	default:
		return ""
	}
}

func (r cliRenderer) printf(category lineCategory, prefix, format string, args ...interface{}) {
	msg := prefix + fmt.Sprintf(format, args...)
	fmt.Fprintln(r.out, styleMessage(r.colorEnabled, category, msg))
}

func (r cliRenderer) errorf(prefix, format string, args ...interface{}) {
	msg := prefix + fmt.Sprintf(format, args...)
	fmt.Fprintln(r.err, styleMessage(r.colorEnabled, categoryWarning, msg))
}

func (r cliRenderer) fatalf(prefix, format string, args ...interface{}) {
	r.errorf(prefix, format, args...)
	os.Exit(1)
}

func main() {
	const (
		productionPRFGroupRounds = 2
		productionNCols          = 16
		productionEll            = 18
	)

	coeffModel := flag.String("coeff-model", "", "optional coeff-native post-sign model override (literal_packed_aggregated_v3)")
	showingPreset := flag.String("showing-preset", PIOP.ShowingPresetSoundnessBalanced, "showing transcript preset (soundness_balanced default with tuned lvcs=89; compact_l3, compact_l2, and compact_l1_research select the measured low-size profiles; transcript_first and production_balance keep the wide-LVCS theorem presets)")
	fullReplay := flag.Bool("full", false, "enable the theorem-clean full replay-image showing mode")
	ncolsOverride := flag.Int("ncols", 0, "optional witness support width override for transcript research")
	lvcsNColsOverride := flag.Int("lvcs-ncols", 0, "optional shared LVCS width override for transcript research")
	nLeavesOverride := flag.Int("nleaves", 0, "optional DECS/LVCS evaluation-domain size override for soundness research")
	etaOverride := flag.Int("eta", 0, "optional eta override for soundness research")
	thetaOverride := flag.Int("theta", 0, "optional theta override for soundness research")
	rhoOverride := flag.Int("rho", 0, "optional rho override for soundness research")
	ellPrimeOverride := flag.Int("ell-prime", 0, "optional ell-prime override for soundness research")
	kappa1Override := flag.Int("kappa1", -1, "optional round-1 grinding override for soundness research (large values are infeasible)")
	kappa2Override := flag.Int("kappa2", -1, "optional round-2 grinding override for soundness research")
	kappa3Override := flag.Int("kappa3", -1, "optional round-3 grinding override for soundness research")
	kappa4Override := flag.Int("kappa4", -1, "optional round-4 grinding override for soundness research")
	sigShortnessProfile := flag.String("sig-shortness-profile", "", "optional signature shortness profile override (named profiles: r11_l4_production, r24_l3_compact, r111_l2_compact, r12285_l1_research; r7_l4_experimental, r12_l3_default, r13_l3_legacy remain research/legacy)")
	sigShortnessRadix := flag.Int("sig-shortness-radix", 0, "optional raw signature shortness radix override for transcript research")
	sigShortnessDigits := flag.Int("sig-shortness-digits", 0, "optional raw signature shortness digit count override for transcript research")
	prfCompanionMode := flag.String("prf-companion-mode", string(PIOP.PRFCompanionModeOutputAudit), "prf companion mode (output_audit default; direct_auth remains research-only scaffolding; aux_instance enables the research-only split PRF proof)")
	prfCheckpointSamples := flag.Int("prf-checkpoint-samples", 8, "number of transcript-selected checkpoint audits for output_audit/direct_auth")
	flag.Parse()

	resolvedModel := *coeffModel
	if resolvedModel == "" {
		resolvedModel = PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3
	}
	effectiveNCols := productionNCols
	if *ncolsOverride > 0 {
		effectiveNCols = *ncolsOverride
	}
	effectivePostLVCS := 0
	effectivePostNLeaves := 0
	effectivePRFLVCS := 0
	effectivePRFNLeaves := 0
	if *lvcsNColsOverride > 0 {
		effectivePostLVCS = *lvcsNColsOverride
		effectivePRFLVCS = *lvcsNColsOverride
	}
	if *nLeavesOverride > 0 {
		effectivePostNLeaves = *nLeavesOverride
		effectivePRFNLeaves = *nLeavesOverride
	}
	effectiveEta := 0
	if *etaOverride > 0 {
		effectiveEta = *etaOverride
	}
	effectiveTheta := 0
	if *thetaOverride > 0 {
		effectiveTheta = *thetaOverride
	}
	effectiveRho := 0
	if *rhoOverride > 0 {
		effectiveRho = *rhoOverride
	}
	effectiveEllPrime := 0
	if *ellPrimeOverride > 0 {
		effectiveEllPrime = *ellPrimeOverride
	}
	effectiveKappa := [4]int{0, 0, 0, 0}
	if *kappa1Override >= 0 {
		effectiveKappa[0] = *kappa1Override
	}
	if *kappa2Override >= 0 {
		effectiveKappa[1] = *kappa2Override
	}
	if *kappa3Override >= 0 {
		effectiveKappa[2] = *kappa3Override
	}
	if *kappa4Override >= 0 {
		effectiveKappa[3] = *kappa4Override
	}

	if wd, err := os.Getwd(); err == nil {
		cli.printf(categoryStatus, "[showing-cli] ", "cwd=%s", wd)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "starting showing demo")
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		cli.fatalf("[showing-cli] ", "load ring: %v", err)
	}
	statePath := filepath.Join("credential", "keys", "credential_state.json")
	state, err := credential.LoadState(statePath)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load credential state: %v", err)
	}
	publicParams, err := loadCredentialPublicParamsFromState(state)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load credential public params: %v", err)
	}
	if state.HashRelation != "" && credential.NormalizeHashRelation(state.HashRelation) != credential.NormalizeHashRelation(publicParams.HashRelation) {
		cli.fatalf("[showing-cli] ", "credential state hash relation %q does not match public params relation %q", state.HashRelation, publicParams.HashRelation)
	}
	boundB := publicParams.BoundB
	params, err := loadPRFParamsFromState(state)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load prf params: %v", err)
	}
	opts := PIOP.SimOpts{
		Credential:           true,
		Theta:                effectiveTheta,
		EllPrime:             effectiveEllPrime,
		Rho:                  effectiveRho,
		NCols:                effectiveNCols,
		Ell:                  productionEll,
		Eta:                  effectiveEta,
		DomainMode:           PIOP.DomainModeExplicit,
		NLeaves:              effectivePostNLeaves,
		Kappa:                effectiveKappa,
		PRFGroupRounds:       productionPRFGroupRounds,
		CoeffPacking:         true,
		CoeffNativeSigModel:  resolvedModel,
		ShowingPreset:        *showingPreset,
		ShowingReplayMode:    PIOP.ShowingReplayModeReduced,
		SigShortnessProfile:  *sigShortnessProfile,
		SigShortnessRadix:    *sigShortnessRadix,
		SigShortnessL:        *sigShortnessDigits,
		PostSignLVCSNCols:    effectivePostLVCS,
		PostSignNLeaves:      effectivePostNLeaves,
		PRFLVCSNCols:         effectivePRFLVCS,
		PRFNLeaves:           effectivePRFNLeaves,
		PRFCompanionMode:     PIOP.PRFCompanionMode(*prfCompanionMode),
		PRFCheckpointSamples: *prfCheckpointSamples,
	}
	if *fullReplay {
		opts.ShowingReplayMode = PIOP.ShowingReplayModeFull
	}
	opts = PIOP.ResolveSimOptsDefaults(opts)
	effectivePostLVCS = opts.PostSignLVCSNCols
	effectivePRFLVCS = opts.PRFLVCSNCols
	effectivePostNLeaves = opts.PostSignNLeaves
	effectivePRFNLeaves = opts.PRFNLeaves
	resolvedShowingPreset := PIOP.ResolveShowingPresetLabelForOpts(opts)
	resolvedSigProfile := PIOP.ResolveSignatureShortnessProfileLabelForOpts(opts)
	sigBase, sigL, sigRowsPer, sigDegree, sigMetricErr := PIOP.ResolveSignatureShortnessMetricsForOpts(ringQ.Modulus[0], opts)
	if sigMetricErr != nil {
		cli.fatalf("[showing-cli] ", "resolve signature shortness profile: %v", sigMetricErr)
	}
	baselineOpts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:           true,
		NCols:                effectiveNCols,
		Ell:                  productionEll,
		DomainMode:           PIOP.DomainModeExplicit,
		PRFGroupRounds:       productionPRFGroupRounds,
		CoeffPacking:         true,
		CoeffNativeSigModel:  resolvedModel,
		ShowingPreset:        *showingPreset,
		ShowingReplayMode:    opts.ShowingReplayMode,
		PRFCompanionMode:     PIOP.PRFCompanionMode(*prfCompanionMode),
		PRFCheckpointSamples: *prfCheckpointSamples,
	})
	cli.printf(categoryStatus, "[showing-cli] ", "production showing profile (preset=%s replay=%s ell=%d eta=%d ell'=%d rho=%d theta=%d ncols=%d lvcs_ncols=%d nleaves=%d kappa={%d,%d,%d,%d} prf_group_rounds=%d prf_mode=%s prf_samples=%d sig_profile=%s sig_R=%d sig_L=%d sig_rows=%d sig_deg=%d)",
		resolvedShowingPreset, opts.ShowingReplayMode, opts.Ell, opts.Eta, opts.EllPrime, opts.Rho, opts.Theta, opts.NCols, effectivePostLVCS, opts.NLeaves, opts.Kappa[0], opts.Kappa[1], opts.Kappa[2], opts.Kappa[3], opts.PRFGroupRounds, opts.PRFCompanionMode, opts.PRFCheckpointSamples, resolvedSigProfile, sigBase, sigL, sigRowsPer, sigDegree)
	if opts.NCols != baselineOpts.NCols ||
		effectivePostLVCS != baselineOpts.PostSignLVCSNCols ||
		effectivePRFLVCS != baselineOpts.PRFLVCSNCols ||
		opts.NLeaves != baselineOpts.NLeaves ||
		effectivePostNLeaves != baselineOpts.PostSignNLeaves ||
		effectivePRFNLeaves != baselineOpts.PRFNLeaves ||
		opts.Eta != baselineOpts.Eta ||
		opts.Theta != baselineOpts.Theta ||
		opts.Rho != baselineOpts.Rho ||
		opts.EllPrime != baselineOpts.EllPrime ||
		opts.Kappa != baselineOpts.Kappa ||
		opts.ShowingReplayMode != baselineOpts.ShowingReplayMode ||
		opts.PRFCompanionMode != baselineOpts.PRFCompanionMode ||
		opts.PRFCheckpointSamples != baselineOpts.PRFCheckpointSamples ||
		resolvedShowingPreset != baselineOpts.ShowingPreset ||
		*sigShortnessProfile != "" || *sigShortnessRadix > 0 || *sigShortnessDigits > 0 {
		cli.printf(categoryWarning, "[showing-cli] ", "warning: transcript/soundness research overrides active (preset=%s replay=%s ncols=%d lvcs_ncols=%d nleaves=%d eta=%d theta=%d rho=%d ell'=%d kappa={%d,%d,%d,%d} sig_profile=%s sig_R=%d sig_L=%d)",
			resolvedShowingPreset, opts.ShowingReplayMode, opts.NCols, effectivePostLVCS, opts.NLeaves, opts.Eta, opts.Theta, opts.Rho, opts.EllPrime, opts.Kappa[0], opts.Kappa[1], opts.Kappa[2], opts.Kappa[3], resolvedSigProfile, sigBase, sigL)
	}
	for i, kappa := range opts.Kappa {
		if kappa >= 32 {
			cli.printf(categoryWarning, "[showing-cli] ", "warning: kappa%d=%d implies infeasible grinding in live proving; use large κ only for theorem-floor analysis, not production runs", i+1, kappa)
		}
	}
	if opts.ShowingReplayMode == PIOP.ShowingReplayModeFull {
		cli.printf(categoryStatus, "[showing-cli] ", "full replay mode selected: theorem-clean full replay statement with a larger authenticated showing surface than reduced engineering mode")
	}
	switch opts.PRFCompanionMode {
	case PIOP.PRFCompanionModeDirectAuth:
		cli.printf(categoryWarning, "[showing-cli] ", "warning: direct_auth is research-only; the live proof still keeps the PRF bridge inside Q until a new bridge object lands")
	case PIOP.PRFCompanionModeAuxInstance:
		cli.printf(categoryWarning, "[showing-cli] ", "warning: aux_instance is research-only; it moves the PRF bridge into a separate same-root auxiliary proof for transcript experiments")
	case "current":
		cli.fatalf("[showing-cli] ", "prf companion mode %q is no longer supported", opts.PRFCompanionMode)
	}
	if opts.PRFGroupRounds <= 0 {
		cli.fatalf("[showing-cli] ", "invalid fixed PRFGroupRounds=%d", opts.PRFGroupRounds)
	}
	if opts.NCols < 2*params.LenKey {
		cli.fatalf("[showing-cli] ", "production NCols=%d is too small for PRF key width %d", opts.NCols, 2*params.LenKey)
	}
	if opts.NCols%2 != 0 {
		cli.fatalf("[showing-cli] ", "production NCols=%d must be even", opts.NCols)
	}
	opts.LVCSNCols = effectivePostLVCS
	if opts.LVCSNCols < opts.NCols {
		cli.fatalf("[showing-cli] ", "production LVCSNCols=%d must be >= NCols=%d", opts.LVCSNCols, opts.NCols)
	}
	// Clamp ℓ so grouped PRF degree stays below the ring degree.
	if opts.PRFGroupRounds > 1 {
		prfDeg, derr := prf.MaxConstraintDegreeGrouped(params, opts.PRFGroupRounds)
		if derr != nil {
			cli.fatalf("[showing-cli] ", "compute grouped PRF degree: %v", derr)
		}
		maxEll := maxEllForGroupedPRF(int(ringQ.N), opts.NCols, int(prfDeg))
		if maxEll <= 0 {
			cli.fatalf("[showing-cli] ", "invalid grouped PRF parameters: N=%d ncols=%d prfDeg=%d g=%d", ringQ.N, opts.NCols, prfDeg, opts.PRFGroupRounds)
		}
		if opts.Ell > maxEll {
			cli.printf(categoryWarning, "[showing-cli] ", "warning: clamping ℓ from %d to %d for PRFGroupRounds=%d (avoids degree wrap-around)", opts.Ell, maxEll, opts.PRFGroupRounds)
			opts.Ell = maxEll
		}
	}
	omega, err := deriveOmegaForOpts(ringQ, opts)
	if err != nil {
		cli.fatalf("[showing-cli] ", "derive omega: %v", err)
	}
	ncols := len(omega)

	// Build public matrices.
	B, err := loadBForShowing(ringQ, state, publicParams)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load B: %v", err)
	}
	wit, err := buildWitnessFromState(ringQ, state)
	if err != nil {
		cli.fatalf("[showing-cli] ", "build witness: %v", err)
	}
	if wit.CoeffNativeShowing == nil {
		cli.fatalf("[showing-cli] ", "missing coeff-native showing witness in credential state")
	}
	A, err := buildSignatureMatrix(ringQ, state, showingSignatureComponentCount(wit))
	if err != nil {
		cli.fatalf("[showing-cli] ", "build A: %v", err)
	}

	// Active showing uses the coeff-native PRF key witness directly.
	key, err := prfKeyFromSignedWitness(ringQ, wit.CoeffNativeShowing, params.LenKey)
	if err != nil {
		cli.fatalf("[showing-cli] ", "prf key: %v", err)
	}
	nonce, noncePublic := sampleNonce(params.LenNonce, ncols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		cli.fatalf("[showing-cli] ", "prf tag: %v", err)
	}
	tagPublic := lanesFromElems(tag, ncols)

	pub := PIOP.PublicInputs{
		A:            A,
		B:            B,
		Tag:          tagPublic,
		Nonce:        noncePublic,
		BoundB:       boundB,
		HashRelation: publicParams.HashRelation,
	}

	cli.printf(categoryStatus, "[showing-cli] ", "building proof")
	proofStart := time.Now()
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		cli.fatalf("[showing-cli] ", "build showing: %v", err)
	}
	proofDur := time.Since(proofStart)

	verifyStart := time.Now()
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	verifyDur := time.Since(verifyStart)
	if err != nil || !ok {
		cli.fatalf("[showing-cli] ", "verify showing failed: ok=%v err=%v", ok, err)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "showing proof verified")
	printLogicalWitnessRowBreakdown("[showing-cli] ", proof)
	printCommittedWitnessRowBreakdown("[showing-cli] ", proof)
	printProofReport("[showing-cli] ", proof, opts, pub.BoundB, ringQ, proofDur, verifyDur)
}

func maxEllForGroupedPRF(ringN, ncols, prfDegree int) int {
	if ringN <= 0 || ncols <= 0 || prfDegree <= 1 {
		return 0
	}
	factor := prfDegree
	// Need: factor*(ncols+ell-1) <= ringN-1  =>  ell <= floor((ringN-1)/factor) - ncols + 1.
	maxDeg0 := (ringN - 1) / factor
	maxEll := maxDeg0 - ncols + 1
	if maxEll < 1 {
		return 0
	}
	return maxEll
}

func loadBForShowing(r *ring.Ring, st credential.State, public credential.PublicParams) ([]*ring.Poly, error) {
	bPath := public.BPath
	if bPath == "" {
		bPath = st.BPath
	}
	if bPath == "" {
		return nil, fmt.Errorf("missing B path in public params/state")
	}
	coeffs, err := ntrurio.LoadBMatrixCoeffs(bPath)
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

func loadPRFParamsFromState(st credential.State) (*prf.Params, error) {
	if st.PRFParamsPath != "" {
		if params, err := prf.LoadParamsFromFile(st.PRFParamsPath); err == nil {
			return params, nil
		}
	}
	return prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
}

func loadCredentialPublicParamsFromState(st credential.State) (credential.PublicParams, error) {
	if st.CredentialPublicPath == "" {
		return credential.PublicParams{}, fmt.Errorf("credential state missing credential_public_path")
	}
	return credential.LoadPublicParams(st.CredentialPublicPath)
}

func buildSignatureMatrix(r *ring.Ring, st credential.State, uCount int) ([][]*ring.Poly, error) {
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
	hNTT := polyFromInt64(r, st.NTRUPublic[0])
	r.NTT(hNTT, hNTT)
	negHNTT := r.NewPoly()
	r.Neg(hNTT, negHNTT)
	one := r.NewPoly()
	one.Coeffs[0][0] = 1 % r.Modulus[0]
	r.NTT(one, one)
	// Signature rows are loaded as U = [s1, s2] where s2 = h*s1 + t (mod q),
	// hence the post-sign equation is (-h)*s1 + s2 = t.
	return [][]*ring.Poly{{negHNTT, one}}, nil
}

func buildWitnessFromState(r *ring.Ring, st credential.State) (PIOP.WitnessInputs, error) {
	coeffNative, err := buildCoeffNativeShowingWitnessFromState(r, st)
	if err != nil {
		return PIOP.WitnessInputs{}, err
	}
	return PIOP.WitnessInputs{
		CoeffNativeShowing: coeffNative,
	}, nil
}

func buildCoeffNativeShowingWitnessFromState(r *ring.Ring, st credential.State) (*PIOP.CoeffNativeShowingWitness, error) {
	if r == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(st.SigS1) == 0 || len(st.SigS2) == 0 {
		return nil, fmt.Errorf("missing sig_s1/sig_s2 in credential state")
	}
	par, err := ntrurio.LoadParams(filepath.Join("Parameters", "Parameters.json"), true)
	if err != nil {
		return nil, fmt.Errorf("load signature bound: %w", err)
	}
	_, _, maxSig := st.SignatureCoordLinf()
	if uint64(maxSig) > par.Beta {
		return nil, fmt.Errorf("signature shortness blocker: max(|sig_s1|,|sig_s2|)=%d exceeds beta=%d under q=%d", maxSig, par.Beta, par.Q)
	}
	if len(st.M1) == 0 || len(st.M2) == 0 || len(st.R0) == 0 || len(st.R1) == 0 || len(st.T) == 0 {
		return nil, fmt.Errorf("missing signed base rows in credential state")
	}
	legacyNCols := 0
	if st.CoeffNativeShowing != nil {
		legacyNCols = st.CoeffNativeShowing.NCols
	}
	packedNCols, err := PIOP.ResolvePackedNCols(st.PackedNCols, legacyNCols, int(r.N))
	if err != nil {
		return nil, fmt.Errorf("resolve packed ncols: %w", err)
	}
	wit := &PIOP.CoeffNativeShowingWitness{
		Sig: []*ring.Poly{
			polyFromInt64(r, st.SigS1),
			polyFromInt64(r, st.SigS2),
		},
		M1:          polyFromInt64(r, st.M1[0]),
		M2:          polyFromInt64(r, st.M2[0]),
		R0:          polyFromInt64(r, st.R0[0]),
		R1:          polyFromInt64(r, st.R1[0]),
		T:           polyFromInt64(r, st.T),
		PackedNCols: packedNCols,
	}
	if err := wit.Validate(int(r.N)); err != nil {
		return nil, fmt.Errorf("invalid coeff-native showing witness: %w", err)
	}
	return wit, nil
}

func showingSignatureComponentCount(wit PIOP.WitnessInputs) int {
	if wit.CoeffNativeShowing != nil && len(wit.CoeffNativeShowing.Sig) > 0 {
		return len(wit.CoeffNativeShowing.Sig)
	}
	return len(wit.U)
}

func prfKeyFromSignedWitness(ringQ *ring.Ring, wit *PIOP.CoeffNativeShowingWitness, lenKey int) ([]prf.Elem, error) {
	if wit == nil {
		return nil, fmt.Errorf("missing coeff-native showing witness")
	}
	ncols, err := PIOP.ResolvePackedNCols(wit.PackedNCols, 0, int(ringQ.N))
	if err != nil {
		return nil, err
	}
	half := ncols / 2
	if half < lenKey {
		return nil, fmt.Errorf("packed ncols=%d leaves only %d upper-half lanes for lenKey=%d", ncols, half, lenKey)
	}
	out := make([]prf.Elem, lenKey)
	q := ringQ.Modulus[0]
	for i := 0; i < lenKey; i++ {
		out[i] = prf.Elem(wit.M2.Coeffs[0][half+i] % q)
	}
	return out, nil
}

func credentialPolysFromInt64(r *ring.Ring, vec [][]int64) []*ring.Poly {
	out := make([]*ring.Poly, len(vec))
	for i := range vec {
		out[i] = polyFromInt64(r, vec[i])
	}
	return out
}

func deriveOmegaForOpts(ringQ *ring.Ring, opts PIOP.SimOpts) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if opts.NCols <= 0 || opts.NCols > ringQ.N {
		return nil, fmt.Errorf("invalid ncols=%d", opts.NCols)
	}
	if opts.DomainMode == PIOP.DomainModeExplicit {
		nLeaves := opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		lvcsNCols := opts.LVCSNCols
		if lvcsNCols <= 0 {
			lvcsNCols = opts.NCols
		}
		if lvcsNCols < opts.NCols {
			return nil, fmt.Errorf("invalid lvcs ncols=%d < witness ncols=%d", lvcsNCols, opts.NCols)
		}
		dom, err := domain.NewDomain(ringQ.Modulus[0], nLeaves, lvcsNCols, opts.Ell, nil)
		if err != nil {
			return nil, err
		}
		if len(dom.Omega) < opts.NCols {
			return nil, fmt.Errorf("derived omega len=%d < witness ncols=%d", len(dom.Omega), opts.NCols)
		}
		return append([]uint64(nil), dom.Omega[:opts.NCols]...), nil
	}
	px := ringQ.NewPoly()
	px.Coeffs[0][1] = 1
	pts := ringQ.NewPoly()
	ringQ.NTT(px, pts)
	return append([]uint64(nil), pts.Coeffs[0][:opts.NCols]...), nil
}

func sampleNonce(lennonce, ncols int, q uint64) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lennonce)
	public := make([][]int64, lennonce)
	for i := 0; i < lennonce; i++ {
		v := randElem(q)
		nonce[i] = prf.Elem(v)
		public[i] = buildConstLane(ncols, int64(v))
	}
	return nonce, public
}

func randElem(q uint64) uint64 {
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(q))
	if err != nil {
		panic(err)
	}
	return n.Uint64()
}

func lanesFromElems(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = buildConstLane(ncols, int64(v))
	}
	return out
}

func elemsToPolys(r *ring.Ring, elems []prf.Elem) []*ring.Poly {
	rows := make([]*ring.Poly, len(elems))
	for i, v := range elems {
		rows[i] = polyConst(r, int64(v))
	}
	return rows
}

func polyConst(r *ring.Ring, v int64) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	var coeff uint64
	if v >= 0 {
		coeff = uint64(v % q)
	} else {
		coeff = uint64((v+q)%q) % uint64(q)
	}
	for i := 0; i < r.N; i++ {
		pNTT.Coeffs[0][i] = coeff
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func polyFromInt64(r *ring.Ring, coeffs []int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	for i := 0; i < r.N && i < len(coeffs); i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func polysFromInt64(r *ring.Ring, vec [][]int64) []*ring.Poly {
	out := make([]*ring.Poly, len(vec))
	for i := range vec {
		out[i] = polyFromInt64(r, vec[i])
	}
	return out
}

func buildConstLane(ncols int, v int64) []int64 {
	row := make([]int64, ncols)
	for i := range row {
		row[i] = v
	}
	return row
}

type committedWitnessBreakdown = PIOP.CommittedWitnessBreakdown

type logicalWitnessBreakdown = PIOP.LogicalWitnessBreakdown

func committedWitnessRowBreakdownFromProof(proof *PIOP.Proof) committedWitnessBreakdown {
	return PIOP.CommittedWitnessRowBreakdownFromProof(proof)
}

func logicalWitnessRowBreakdownFromProof(proof *PIOP.Proof) logicalWitnessBreakdown {
	return PIOP.LogicalWitnessRowBreakdownFromProof(proof)
}

func printWitnessGeometry(prefix string, geom PIOP.WitnessGeometrySnapshot) {
	if geom.ActualWitnessPolys <= 0 {
		return
	}
	cli.printf(categoryGeometry, prefix, "%s", formatWitnessGeometrySummary(geom))
}

func formatWitnessGeometrySummary(geom PIOP.WitnessGeometrySnapshot) string {
	line := fmt.Sprintf(
		"Geometry: witness=%d (post=%d prf=%d) committed=%d mask=%d blocks=%dx%d occupancy=%.1f%%",
		geom.ActualWitnessPolys,
		geom.ActualPostSignWitnessPolys,
		geom.ActualPRFWitnessPolys,
		geom.WitnessRowsCommitted,
		geom.MaskRowsCommitted,
		geom.PCSBlockCount,
		geom.RowsPerBlock,
		geom.OccupancyPct,
	)
	if geom.FinalBlockSlack > 0 || geom.PostSignPrefixSlack > 0 {
		line += fmt.Sprintf(" slack=%d/%d", geom.FinalBlockSlack, geom.PostSignPrefixSlack)
	}
	if geom.ActualPRFWitnessPolys > 0 || geom.ReplayPRFRows > 0 {
		line += fmt.Sprintf(" prf_replay=%.2fx", geom.ReplayToWitnessExpansion)
	}
	return line
}

func printCommittedWitnessRowBreakdown(prefix string, proof *PIOP.Proof) {
	breakdown := committedWitnessRowBreakdownFromProof(proof)
	if breakdown.TotalRows == 0 {
		return
	}
	if breakdown.SharedRows > 0 {
		coeffPct := 100.0 * float64(breakdown.CoeffNativeRows) / float64(breakdown.TotalRows)
		sharedPct := 100.0 * float64(breakdown.SharedRows) / float64(breakdown.TotalRows)
		prfPct := 100.0 * float64(breakdown.PRFRows) / float64(breakdown.TotalRows)
		cli.printf(categoryGeometry, prefix, "Witness rows: coeff_native=%d (%.1f%%), shared=%d (%.1f%%), prf=%d (%.1f%%), total=%d, mask=%d",
			breakdown.CoeffNativeRows,
			coeffPct,
			breakdown.SharedRows,
			sharedPct,
			breakdown.PRFRows,
			prfPct,
			breakdown.TotalRows,
			proof.MaskRowCount)
		return
	}
	coeffPct := 100.0 * float64(breakdown.CoeffNativeRows) / float64(breakdown.TotalRows)
	prfPct := 100.0 * float64(breakdown.PRFRows) / float64(breakdown.TotalRows)
	cli.printf(categoryGeometry, prefix, "Witness rows: coeff_native=%d (%.1f%%), prf=%d (%.1f%%), total=%d, mask=%d",
		breakdown.CoeffNativeRows,
		coeffPct,
		breakdown.PRFRows,
		prfPct,
		breakdown.TotalRows,
		proof.MaskRowCount)
}

func printLogicalWitnessRowBreakdown(prefix string, proof *PIOP.Proof) {
	breakdown := logicalWitnessRowBreakdownFromProof(proof)
	if breakdown.TotalRows == 0 {
		return
	}
	cli.printf(categoryGeometry, prefix, "Witness logical rows: sig_replay=%d, sig_shortness=%d, non_sig=%d, prf=%d, total=%d",
		breakdown.SigReplayRows,
		breakdown.SigShortnessRows,
		breakdown.NonSigRows,
		breakdown.PRFRows,
		breakdown.TotalRows)
}

func printPaperTranscriptBreakdown(prefix string, rep PIOP.ProofReport) {
	if rep.PaperTranscript.OptimizedBytes == 0 {
		cli.printf(categoryWarning, prefix, "paper transcript breakdown unavailable (total=0)")
		return
	}
	cli.printf(categoryTranscript, prefix, "Paper transcript breakdown (optimized, bytes, total=%d):", rep.PaperTranscript.OptimizedBytes)
	for _, row := range orderedPaperTranscriptRows(rep.PaperTranscript) {
		cli.printf(categoryTranscript, prefix, "  %-10s %8d  (%5.1f%%, %.0fb)", row.Label, row.Bytes, row.Percent, row.Bits)
	}
}

func printProofReport(prefix string, proof *PIOP.Proof, opts PIOP.SimOpts, boundB int64, ringQ *ring.Ring, proveDur, verifyDur time.Duration) {
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		cli.printf(categoryWarning, prefix, "report: %v", err)
		return
	}
	sigBase, sigL, sigRowsPer, sigDegree, sigErr := PIOP.ResolveSignatureShortnessMetricsForOpts(ringQ.Modulus[0], opts)
	if rep.PaperTranscript.OptimizedBytes > 0 {
		cli.printf(categoryTranscript, prefix, "%s", formatPaperTranscriptSummary(rep))
		cli.printf(categoryTranscript, prefix, "%s", formatPaperTranscriptReductionSummary(rep))
	}
	cli.printf(categoryTranscript, prefix, "Current verifier payload≈%.2f KB (%.0f bytes)", rep.ProofKB, float64(rep.ProofBytes))
	printPaperTranscriptBreakdown(prefix, rep)
	printTranscriptOptimizationFocus(prefix, rep)
	printStatementSummary(prefix, rep)
	printSigShortness(prefix, rep)
	cli.printf(categoryStatus, prefix, "Prover time≈%s", proveDur)
	cli.printf(categoryStatus, prefix, "Verifier time≈%s", verifyDur)
	cli.printf(categorySoundness, prefix, "Soundness Eq.(8): %s %s %s %s eq8_total=%.2f",
		formatSoundnessComponent("eps1", rep.Soundness.RawBits[0], rep.Soundness.Bits[0]),
		formatSoundnessComponent("eps2", rep.Soundness.RawBits[1], rep.Soundness.Bits[1]),
		formatSoundnessComponent("eps3", rep.Soundness.RawBits[2], rep.Soundness.Bits[2]),
		formatSoundnessComponent("eps4", rep.Soundness.RawBits[3], rep.Soundness.Bits[3]),
		displayBits(rep.Soundness.Eq8TotalBits))
	cli.printf(categorySoundness, prefix, "Soundness Thm.9: collision=%.2f round={%.2f,%.2f,%.2f,%.2f} total=%.2f qcaps=%v",
		rep.Soundness.CollisionBits,
		rep.Soundness.TheoremBits[0], rep.Soundness.TheoremBits[1], rep.Soundness.TheoremBits[2], rep.Soundness.TheoremBits[3],
		displayBits(rep.Soundness.TotalBits),
		rep.Soundness.QueryCaps)
	if note := formatSoundnessNotes(rep); note != "" {
		cli.printf(categorySoundness, prefix, "%s", note)
	}
	cli.printf(categoryGeometry, prefix, "Params: NCols(s)=%d pcs_ncols=%d nleaves=%d ddecs=%d ℓ=%d ℓ'=%d ρ=%d θ=%d η=%d κ={%d,%d,%d,%d} dQ=%d collision_bits=%d",
		rep.NCols, rep.PCSNCols, rep.NLeaves, rep.Soundness.DDECS, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta,
		rep.Kappa[0], rep.Kappa[1], rep.Kappa[2], rep.Kappa[3], rep.DQ, rep.Soundness.CollisionSpaceBits)
	printWitnessGeometry(prefix, rep.Geometry)
	if sigErr == nil {
		cli.printf(categoryGeometry, prefix, "Linf chain: sig(profile=%s,R=%d,L=%d,rows=%d,deg=%d) nonSig=carriers", rep.TranscriptFocus.SigShortnessProfile, sigBase, sigL, sigRowsPer, sigDegree)
	} else {
		cli.printf(categoryWarning, prefix, "Linf chain shape resolution warning: sigErr=%v", sigErr)
	}
	paperTranscriptKB := float64(rep.PaperTranscript.OptimizedBytes) / 1024.0
	cli.printf(categoryWarning, prefix, "Table row: %.2f %.3f %.2f %d %d %d %d %d %d",
		paperTranscriptKB, proveDur.Seconds(), rep.Soundness.TotalBits,
		rep.NCols, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta)
}

func displayBits(bits float64) float64 {
	if math.Abs(bits) < 0.005 {
		return 0
	}
	return bits
}

func formatSoundnessComponent(label string, rawBits, bits float64) string {
	if rawBits < bits {
		return fmt.Sprintf("%s=%.2f (clamped from raw %.2f)", label, bits, rawBits)
	}
	return fmt.Sprintf("%s=%.2f", label, bits)
}

func formatSoundnessNotes(rep PIOP.ProofReport) string {
	var notes []string
	for i := 0; i < len(rep.Soundness.Clamped); i++ {
		if rep.Soundness.Clamped[i] {
			notes = append(notes, fmt.Sprintf("eps%d raw term is negative and is paper-clamped to 0 before theorem-level grinding", i+1))
		}
	}
	for _, kappa := range rep.Kappa {
		if kappa > 0 {
			notes = append(notes, "Thm.9 round bits already include grinding κ; large κ improves theorem terms but increases prover work exponentially")
			break
		}
	}
	return strings.Join(notes, "; ")
}

func formatPaperTranscriptSummary(rep PIOP.ProofReport) string {
	return fmt.Sprintf("Paper transcript≈%.2f KB (%d bytes, optimized)",
		float64(rep.PaperTranscript.OptimizedBytes)/1024.0,
		rep.PaperTranscript.OptimizedBytes)
}

func formatPaperTranscriptReductionSummary(rep PIOP.ProofReport) string {
	return fmt.Sprintf("Paper reductions: R saved=%.0fb Q saved=%.0fb",
		rep.PaperTranscript.R.NaiveBits-rep.PaperTranscript.R.OptimizedBits,
		rep.PaperTranscript.Q.NaiveBits-rep.PaperTranscript.Q.OptimizedBits)
}

func printTranscriptOptimizationFocus(prefix string, rep PIOP.ProofReport) {
	if line := formatTranscriptOptimizationSummary(rep); line != "" {
		cli.printf(categoryGeometry, prefix, "%s", line)
	}
	if line := formatTranscriptBucketFocusSummary(rep); line != "" {
		cli.printf(categoryTranscript, prefix, "%s", line)
	}
	printReplayFamilyAudit(prefix, rep)
}

func printStatementSummary(prefix string, rep PIOP.ProofReport) {
	if line := formatStatementSummary(rep); line != "" {
		cli.printf(categoryStatus, prefix, "%s", line)
	}
}

func formatTranscriptOptimizationSummary(rep PIOP.ProofReport) string {
	focus := rep.TranscriptFocus
	if focus.NRows <= 0 {
		return ""
	}
	layout := "unpacked"
	if focus.PRFPacked {
		layout = "packed"
	}
	instances := ""
	if focus.MainLVCSNCols > 0 || focus.MainNLeaves > 0 || focus.PRFLVCSNCols > 0 || focus.PRFNLeaves > 0 || focus.HiddenShortnessLVCSNCols > 0 || focus.HiddenShortnessNLeaves > 0 {
		instances = fmt.Sprintf(
			" main=%d/%d prf=%d/%d hidden=%d/%d",
			focus.MainLVCSNCols,
			focus.MainNLeaves,
			focus.PRFLVCSNCols,
			focus.PRFNLeaves,
			focus.HiddenShortnessLVCSNCols,
			focus.HiddenShortnessNLeaves,
		)
	}
	if focus.PRFAuxInstance {
		instances += fmt.Sprintf(
			" prf_aux=on auxProof=%d auxOpening=%d bridgeRows=%d bridgeSlots=%d bridgeBlocks=%d bridgePad=%d",
			focus.PRFAuxProofBytes,
			focus.PRFAuxOpeningBytes,
			focus.PRFBridgeRowCount,
			focus.PRFBridgeSupportSlots,
			focus.PRFBridgeOpenedBlocks,
			focus.PRFBridgePaddingRows,
		)
	}
	return fmt.Sprintf(
		"Transcript focus: preset=%s replay=%s blocks=%d lvcs=%d nleaves=%d rowsBlock=%d maskChunks=%d witness=%d nrows=%d m=%d pcols=%d omitP=%d prf_scalars=%d prf_rows=%d (%s) entries=%d%s",
		focus.ShowingPreset,
		focus.ReplayMode,
		focus.ReplayBlocks,
		focus.LVCSNCols,
		focus.NLeaves,
		focus.RowsBlock,
		focus.MaskChunks,
		focus.WitnessRows,
		focus.NRows,
		focus.M,
		focus.PCols,
		focus.OmitP,
		focus.PRFLogicalScalars,
		focus.PRFPackedRows,
		layout,
		focus.RowOpeningEntries,
		instances,
	)
}

func formatStatementSummary(rep PIOP.ProofReport) string {
	class := rep.TranscriptFocus.StatementClass
	replay := rep.TranscriptFocus.ReplayMode
	shortness := rep.SigShortness.Mode
	if shortness == "" {
		shortness = rep.TranscriptFocus.ShortnessMode
	}
	if class == "" && replay == "" && shortness == "" {
		return ""
	}
	if shortness == "" {
		shortness = PIOP.SigShortnessModeNone
	}
	return fmt.Sprintf("Statement: class=%s replay=%s shortness=%s", class, replay, shortness)
}

func formatTranscriptBucketFocusSummary(rep PIOP.ProofReport) string {
	focus := rep.TranscriptFocus
	if focus.PdecsBytes <= 0 && focus.VTargetsBytes <= 0 && focus.BarSetsBytes <= 0 && focus.QBytes <= 0 && rep.PaperTranscript.SigShortness.OptimizedBytes <= 0 {
		return ""
	}
	return fmt.Sprintf(
		"Bucket focus: Pdecs=%d VTargets=%d BarSets=%d Q=%d SigShortness=%d",
		focus.PdecsBytes,
		focus.VTargetsBytes,
		focus.BarSetsBytes,
		focus.QBytes,
		rep.PaperTranscript.SigShortness.OptimizedBytes,
	)
}

func printSigShortness(prefix string, rep PIOP.ProofReport) {
	sig := rep.SigShortness
	if !sig.Enabled {
		return
	}
	mode := sig.Mode
	if mode == "" {
		mode = fmt.Sprintf("v%d", sig.Version)
	}
	cli.printf(categoryGeometry, prefix, "Sig shortness: %s v%d slots=%d blocks=%d opening=%d total=%d",
		mode,
		sig.Version,
		sig.SupportSlotCount,
		sig.OpenedBlockCount,
		sig.OpeningBytes,
		sig.ProofBytes,
	)
}

func printReplayFamilyAudit(prefix string, rep PIOP.ProofReport) {
	audit := rep.ReplayAudit
	if len(audit.Families) == 0 {
		return
	}
	cli.printf(categoryGeometry, prefix, "%s", formatReplayFamilyAuditSummary(rep))
	for _, entry := range audit.Families {
		cli.printf(categoryGeometry, prefix, "  replay[%s] selected=%3d/%-3d blocks=%2d/%-2d reduction=%s",
			entry.Family,
			entry.SelectedRowCount,
			entry.LogicalRowCount,
			entry.ActiveBlockCount,
			entry.TotalBlockCount,
			entry.ReductionEffect,
		)
	}
	printReplaySubfamilyAudit(prefix, audit.Subfamilies)
	cli.printf(categoryGeometry, prefix, "Replay audit note: selector-derived rows are authoritative; the family inventory above is intentionally a coarse factual summary.")
}

func printReplaySubfamilyAudit(prefix string, audit PIOP.ReplaySubfamilyAuditReport) {
	if len(audit.Entries) == 0 {
		return
	}
	cli.printf(categoryGeometry, prefix, "%s", formatReplaySubfamilyAuditSummary(audit))
	for _, entry := range audit.Entries {
		if entry.SelectedRowCount == 0 {
			continue
		}
		cli.printf(categoryGeometry, prefix, "  replay_sub[%s] selected=%3d/%-3d blocks=%2d/%-2d consumption=%s",
			entry.Kind,
			entry.SelectedRowCount,
			entry.LogicalRowCount,
			entry.ActiveBlockCount,
			entry.TotalBlockCount,
			entry.Consumption,
		)
	}
}

func formatReplayFamilyAuditSummary(rep PIOP.ProofReport) string {
	audit := rep.ReplayAudit
	if len(audit.Families) == 0 {
		return ""
	}
	selectedFamilies := make([]string, 0, len(audit.Families))
	for _, entry := range audit.Families {
		if entry.SelectedRowCount == 0 {
			continue
		}
		selectedFamilies = append(selectedFamilies, string(entry.Family))
	}
	selectedLabel := "none"
	if len(selectedFamilies) > 0 {
		selectedLabel = strings.Join(selectedFamilies, ", ")
	}
	return fmt.Sprintf(
		"Replay audit: selected=%d/%d rows reduction=%.2f%% activeBlocks=%d/%d selectedFamilies=%s",
		audit.Selector.SelectedRows,
		audit.Selector.WitnessRows,
		audit.Selector.ReductionPct,
		audit.Selector.ActiveBlocks,
		audit.Selector.FullBlocks,
		selectedLabel,
	)
}

func formatReplaySubfamilyAuditSummary(audit PIOP.ReplaySubfamilyAuditReport) string {
	if len(audit.Entries) == 0 {
		return ""
	}
	selected := make([]string, 0, len(audit.Entries))
	for _, entry := range audit.Entries {
		if entry.SelectedRowCount == 0 {
			continue
		}
		selected = append(selected, string(entry.Kind))
	}
	if len(selected) == 0 {
		return "Replay subaudit: selectedSubfamilies=none"
	}
	return fmt.Sprintf("Replay subaudit: selectedSubfamilies=%s", strings.Join(selected, ", "))
}

type paperTranscriptBreakdownRow struct {
	Label   string
	Bytes   int
	Bits    float64
	Percent float64
	order   int
}

func orderedPaperTranscriptRows(rep PIOP.PaperTranscriptReport) []paperTranscriptBreakdownRow {
	total := rep.OptimizedBytes
	rows := []paperTranscriptBreakdownRow{}
	add := func(label string, bucket PIOP.PaperTranscriptBucket, order int) {
		if bucket.OptimizedBytes <= 0 {
			return
		}
		pct := 0.0
		if total > 0 {
			pct = 100.0 * float64(bucket.OptimizedBytes) / float64(total)
		}
		rows = append(rows, paperTranscriptBreakdownRow{
			Label:   label,
			Bytes:   bucket.OptimizedBytes,
			Bits:    bucket.OptimizedBits,
			Percent: pct,
			order:   order,
		})
	}
	add("Counters", rep.Counters, 0)
	add("SaltRoot", rep.SaltRoot, 1)
	add("ExtraHash", rep.ExtraHash, 2)
	add("R", rep.R, 3)
	add("Q", rep.Q, 4)
	add("SigShortness", rep.SigShortness, 5)
	add("VTargets", rep.VTargets, 6)
	add("BarSets", rep.BarSets, 7)
	add("Pdecs", rep.Pdecs, 8)
	add("Mdecs", rep.Mdecs, 9)
	add("Auth", rep.Auth, 10)
	add("Tapes", rep.Tapes, 11)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes != rows[j].Bytes {
			return rows[i].Bytes > rows[j].Bytes
		}
		return rows[i].order < rows[j].order
	})
	return rows
}
