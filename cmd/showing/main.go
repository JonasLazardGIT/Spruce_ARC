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

const (
	defaultShowingProfile          = "showing_n512_x0len70_100"
	showingProfileN512X0Len70_100  = "showing_n512_x0len70_100"
	showingProfileN512X0Len70_128  = "showing_n512_x0len70_128"
	showingProfileN1024X0Len70_100 = "showing_n1024_x0len70_100"
	maintainedShowingX0Len         = 70
)

type maintainedShowingProfileSpec struct {
	Name            string
	RingDegree      int
	X0Len           int
	SoundnessTarget float64
	StatePath       string
	LVCSNCols       int
	NLeaves         int
	Eta             int
	Theta           int
	Rho             int
	EllPrime        int
	Kappa           [4]int
}

var maintainedShowingProfiles = []maintainedShowingProfileSpec{
	{
		Name:            showingProfileN512X0Len70_100,
		RingDegree:      512,
		X0Len:           maintainedShowingX0Len,
		SoundnessTarget: 100,
		StatePath:       filepath.Join("credential", "keys", "credential_state.n512_x0len70.json"),
		LVCSNCols:       70,
		NLeaves:         6400,
		Eta:             39,
		Theta:           3,
		Rho:             2,
		EllPrime:        2,
		Kappa:           [4]int{10, 0, 0, 6},
	},
	{
		Name:            showingProfileN512X0Len70_128,
		RingDegree:      512,
		X0Len:           maintainedShowingX0Len,
		SoundnessTarget: 128,
		StatePath:       filepath.Join("credential", "keys", "credential_state.n512_x0len70.json"),
		LVCSNCols:       70,
		NLeaves:         13120,
		Eta:             44,
		Theta:           2,
		Rho:             3,
		EllPrime:        4,
		Kappa:           [4]int{10, 10, 10, 10},
	},
	{
		Name:            showingProfileN1024X0Len70_100,
		RingDegree:      1024,
		X0Len:           maintainedShowingX0Len,
		SoundnessTarget: 100,
		StatePath:       filepath.Join("credential", "keys", "credential_state.n1024_x0len70.json"),
		LVCSNCols:       84,
		NLeaves:         5760,
		Eta:             41,
		Theta:           3,
		Rho:             2,
		EllPrime:        2,
		Kappa:           [4]int{10, 0, 0, 6},
	},
}

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

func showingProfileNames() []string {
	names := make([]string, 0, len(maintainedShowingProfiles))
	for _, profile := range maintainedShowingProfiles {
		names = append(names, profile.Name)
	}
	sort.Strings(names)
	return names
}

func lookupShowingProfile(name string) (maintainedShowingProfileSpec, bool) {
	for _, profile := range maintainedShowingProfiles {
		if profile.Name == name {
			return profile, true
		}
	}
	return maintainedShowingProfileSpec{}, false
}

func manualShowingResearchOverrideActive(setFlags map[string]bool) bool {
	for _, name := range []string{
		"ncols",
		"lvcs-ncols",
		"nleaves",
		"eta",
		"theta",
		"rho",
		"ell-prime",
		"kappa1",
		"kappa2",
		"kappa3",
		"kappa4",
		"sig-shortness-profile",
		"sig-shortness-radix",
		"sig-shortness-digits",
		"packed-sig-chain-group-size",
		"sig-shortness-ncols",
		"prf-companion-mode",
		"prf-checkpoint-samples",
		"unsafe-shadow-sig-lookup-r121-l2",
	} {
		if setFlags[name] {
			return true
		}
	}
	return false
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
		productionEll            = 0
	)

	coeffModel := flag.String("coeff-model", "", "optional coeff-native post-sign model override (literal_packed_aggregated_v3)")
	showingProfile := flag.String("showing-profile", defaultShowingProfile, fmt.Sprintf("maintained showing profile (%s); no flag uses %s", strings.Join(showingProfileNames(), ", "), defaultShowingProfile))
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
	sigShortnessProfile := flag.String("sig-shortness-profile", "", "optional signature shortness profile override (named profiles include r11_l4_production and r24_l3_compact)")
	sigShortnessRadix := flag.Int("sig-shortness-radix", 0, "optional raw signature shortness radix override for transcript research")
	sigShortnessDigits := flag.Int("sig-shortness-digits", 0, "optional raw signature shortness digit count override for transcript research")
	packedSigChainGroupSize := flag.Int("packed-sig-chain-group-size", 0, "reserved packed signature shortness group-size override; optimized inline-target profile requires 1")
	sigShortnessNCols := flag.Int("sig-shortness-ncols", 0, "reserved signature-shortness width override for future single-root packing research")
	prfCompanionMode := flag.String("prf-companion-mode", string(PIOP.PRFCompanionModeOutputAudit), "prf companion mode (output_audit default; direct_auth remains research-only; aux_instance enables the research-only split PRF proof)")
	prfCheckpointSamples := flag.Int("prf-checkpoint-samples", 8, "number of transcript-selected checkpoint audits for output_audit/direct_auth")
	statePathFlag := flag.String("state-path", "", "credential state path for showing; defaults to the selected maintained profile artifact")
	unsafeSigLookupShadow := flag.String("unsafe-shadow-sig-lookup-r121-l2", "", "UNSAFE internal R121/L2 signature lookup viability mode: free or same_q")
	flag.Parse()
	setFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	activeProfileName := strings.TrimSpace(*showingProfile)
	if activeProfileName == "" {
		activeProfileName = defaultShowingProfile
	}
	activeProfile, ok := lookupShowingProfile(activeProfileName)
	if !ok {
		cli.fatalf("[showing-cli] ", "unknown -showing-profile=%q (supported: %s)", activeProfileName, strings.Join(showingProfileNames(), ", "))
	}
	if !setFlags["state-path"] {
		*statePathFlag = activeProfile.StatePath
	}
	selectedRingDegree := activeProfile.RingDegree
	if *unsafeSigLookupShadow != "" && PIOP.NormalizeSigLookupShadowR121L2Mode(*unsafeSigLookupShadow) == PIOP.SigLookupShadowR121L2None {
		cli.fatalf("[showing-cli] ", "unknown unsafe shadow sig lookup mode %q", *unsafeSigLookupShadow)
	}

	resolvedModel := *coeffModel
	if resolvedModel == "" {
		resolvedModel = PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3
	}
	presetDefaults := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:          true,
		CoeffNativeSigModel: resolvedModel,
		ShowingPreset:       PIOP.ShowingPresetInlineTargetReplayCompactResearch,
	})
	effectiveNCols := productionNCols
	if *ncolsOverride > 0 {
		effectiveNCols = *ncolsOverride
	} else if presetDefaults.ShowingPreset == PIOP.ShowingPresetInlineTargetReplayCompactResearch {
		effectiveNCols = 16
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
	if *lvcsNColsOverride <= 0 {
		effectivePostLVCS = activeProfile.LVCSNCols
		effectivePRFLVCS = activeProfile.LVCSNCols
	}
	if *nLeavesOverride <= 0 {
		effectivePostNLeaves = activeProfile.NLeaves
		effectivePRFNLeaves = activeProfile.NLeaves
	}
	if *etaOverride <= 0 {
		effectiveEta = activeProfile.Eta
	}
	if *thetaOverride <= 0 {
		effectiveTheta = activeProfile.Theta
	}
	if *rhoOverride <= 0 {
		effectiveRho = activeProfile.Rho
	}
	if *ellPrimeOverride <= 0 {
		effectiveEllPrime = activeProfile.EllPrime
	}
	if *kappa1Override < 0 {
		effectiveKappa[0] = activeProfile.Kappa[0]
	}
	if *kappa2Override < 0 {
		effectiveKappa[1] = activeProfile.Kappa[1]
	}
	if *kappa3Override < 0 {
		effectiveKappa[2] = activeProfile.Kappa[2]
	}
	if *kappa4Override < 0 {
		effectiveKappa[3] = activeProfile.Kappa[3]
	}

	if wd, err := os.Getwd(); err == nil {
		cli.printf(categoryStatus, "[showing-cli] ", "cwd=%s", wd)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "starting showing demo")
	cli.printf(categoryStatus, "[showing-cli] ", "showing_profile=%s ring_degree=%d x0_len=%d target_bits=%.0f state=%s",
		activeProfile.Name, activeProfile.RingDegree, activeProfile.X0Len, activeProfile.SoundnessTarget, *statePathFlag)
	ringQ, err := credential.LoadRingWithDegree(selectedRingDegree)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load ring: %v", err)
	}
	if selectedRingDegree == 512 {
		cli.printf(categoryWarning, "[showing-cli] ", "UNSAFE RESEARCH MODE: selected ring_degree=512; this is a statement fork requiring fresh N=512 artifacts and is not production-valid without security review")
	}
	statePath := *statePathFlag
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
	if err := validateArtifactRingDegree(int(ringQ.N), statePath, state, publicParams); err != nil {
		cli.fatalf("[showing-cli] ", "%v", err)
	}
	if publicParams.X0Len != activeProfile.X0Len {
		cli.fatalf("[showing-cli] ", "public params x0_len=%d incompatible with showing profile %s x0_len=%d", publicParams.X0Len, activeProfile.Name, activeProfile.X0Len)
	}
	if state.X0Len != activeProfile.X0Len {
		cli.fatalf("[showing-cli] ", "credential state x0_len=%d incompatible with showing profile %s x0_len=%d", state.X0Len, activeProfile.Name, activeProfile.X0Len)
	}
	if err := credential.ValidateLiveHashRelation(publicParams.HashRelation); err != nil {
		cli.fatalf("[showing-cli] ", "%v", err)
	}
	boundB := publicParams.BoundB
	params, err := loadPRFParamsFromState(state)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load prf params: %v", err)
	}
	opts := PIOP.SimOpts{
		Credential:                  true,
		Theta:                       effectiveTheta,
		EllPrime:                    effectiveEllPrime,
		Rho:                         effectiveRho,
		NCols:                       effectiveNCols,
		Ell:                         productionEll,
		Eta:                         effectiveEta,
		RingDegree:                  selectedRingDegree,
		DomainMode:                  PIOP.DomainModeExplicit,
		NLeaves:                     effectivePostNLeaves,
		Kappa:                       effectiveKappa,
		PRFGroupRounds:              productionPRFGroupRounds,
		CoeffPacking:                true,
		CoeffNativeSigModel:         resolvedModel,
		ShowingPreset:               PIOP.ShowingPresetInlineTargetReplayCompactResearch,
		ShowingReplayMode:           PIOP.ShowingReplayModeFull,
		SigShortnessProfile:         *sigShortnessProfile,
		SigShortnessRadix:           *sigShortnessRadix,
		SigShortnessL:               *sigShortnessDigits,
		PackedSigChainGroupSize:     *packedSigChainGroupSize,
		SigShortnessNCols:           *sigShortnessNCols,
		PostSignLVCSNCols:           effectivePostLVCS,
		PostSignNLeaves:             effectivePostNLeaves,
		PRFLVCSNCols:                effectivePRFLVCS,
		PRFNLeaves:                  effectivePRFNLeaves,
		PRFCompanionMode:            PIOP.PRFCompanionMode(*prfCompanionMode),
		PRFCheckpointSamples:        *prfCheckpointSamples,
		AggregateR0Replay:           true,
		UnsafeSigLookupShadowR121L2: *unsafeSigLookupShadow,
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
		Credential:                  true,
		NCols:                       effectiveNCols,
		Ell:                         productionEll,
		RingDegree:                  selectedRingDegree,
		DomainMode:                  PIOP.DomainModeExplicit,
		PRFGroupRounds:              productionPRFGroupRounds,
		CoeffPacking:                true,
		CoeffNativeSigModel:         resolvedModel,
		ShowingPreset:               PIOP.ShowingPresetInlineTargetReplayCompactResearch,
		ShowingReplayMode:           opts.ShowingReplayMode,
		AggregateR0Replay:           true,
		PackedSigChainGroupSize:     *packedSigChainGroupSize,
		SigShortnessNCols:           *sigShortnessNCols,
		PRFCompanionMode:            PIOP.PRFCompanionMode(*prfCompanionMode),
		PRFCheckpointSamples:        *prfCheckpointSamples,
		UnsafeSigLookupShadowR121L2: *unsafeSigLookupShadow,
	})
	cli.printf(categoryStatus, "[showing-cli] ", "production showing profile (preset=%s replay=%s ring_degree=%d ell=%d eta=%d ell'=%d rho=%d theta=%d ncols=%d lvcs_ncols=%d nleaves=%d kappa={%d,%d,%d,%d} prf_group_rounds=%d prf_mode=%s prf_samples=%d sig_profile=%s sig_R=%d sig_L=%d sig_rows=%d sig_deg=%d)",
		resolvedShowingPreset, opts.ShowingReplayMode, ringQ.N, opts.Ell, opts.Eta, opts.EllPrime, opts.Rho, opts.Theta, opts.NCols, effectivePostLVCS, opts.NLeaves, opts.Kappa[0], opts.Kappa[1], opts.Kappa[2], opts.Kappa[3], opts.PRFGroupRounds, opts.PRFCompanionMode, opts.PRFCheckpointSamples, resolvedSigProfile, sigBase, sigL, sigRowsPer, sigDegree)
	researchOverridesActive := manualShowingResearchOverrideActive(setFlags)
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
		opts.RingDegree != baselineOpts.RingDegree ||
		opts.PackedSigChainGroupSize != baselineOpts.PackedSigChainGroupSize ||
		opts.SigShortnessNCols != baselineOpts.SigShortnessNCols ||
		opts.PRFCompanionMode != baselineOpts.PRFCompanionMode ||
		opts.PRFCheckpointSamples != baselineOpts.PRFCheckpointSamples ||
		opts.UnsafeSigLookupShadowR121L2 != baselineOpts.UnsafeSigLookupShadowR121L2 ||
		resolvedShowingPreset != baselineOpts.ShowingPreset ||
		*sigShortnessProfile != "" || *sigShortnessRadix > 0 || *sigShortnessDigits > 0 {
		researchOverridesActive = true
	}
	if researchOverridesActive {
		cli.printf(categoryWarning, "[showing-cli] ", "warning: transcript/soundness research overrides active (preset=%s replay=%s ring_degree=%d ncols=%d lvcs_ncols=%d nleaves=%d eta=%d theta=%d rho=%d ell'=%d kappa={%d,%d,%d,%d} sig_profile=%s sig_R=%d sig_L=%d)",
			resolvedShowingPreset, opts.ShowingReplayMode, ringQ.N, opts.NCols, effectivePostLVCS, opts.NLeaves, opts.Eta, opts.Theta, opts.Rho, opts.EllPrime, opts.Kappa[0], opts.Kappa[1], opts.Kappa[2], opts.Kappa[3], resolvedSigProfile, sigBase, sigL)
	}
	for i, kappa := range opts.Kappa {
		if kappa > 5 {
			cli.printf(categoryWarning, "[showing-cli] ", "grinding disclosure: kappa%d=%d is part of the selected theorem tuple and increases proving work by 2^%d for that round", i+1, kappa, kappa)
		}
		if kappa >= 32 {
			cli.printf(categoryWarning, "[showing-cli] ", "warning: kappa%d=%d implies infeasible grinding in live proving; use large κ only for theorem-floor analysis, not production runs", i+1, kappa)
		}
	}
	if opts.ShowingReplayMode == PIOP.ShowingReplayModeFull {
		cli.printf(categoryStatus, "[showing-cli] ", "full replay mode selected: maintained direct bb_tran full replay statement with a larger authenticated showing surface than reduced engineering mode")
	}
	switch PIOP.NormalizeSigLookupShadowR121L2Mode(opts.UnsafeSigLookupShadowR121L2) {
	case PIOP.SigLookupShadowR121L2Free:
		cli.printf(categoryWarning, "[showing-cli] ", "UNSOUND FREE-LOOKUP UPPER BOUND: R121/L2 signature shortness membership is not proved")
	case PIOP.SigLookupShadowR121L2SameQ:
		cli.printf(categoryWarning, "[showing-cli] ", "UNSAFE SAME-Q NEGATIVE CONTROL: R121/L2 signature shortness uses degree-121 membership inside Q")
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
	omega, err := deriveOmegaForOpts(ringQ, opts, publicParams.HashRelation)
	if err != nil {
		cli.fatalf("[showing-cli] ", "derive omega: %v", err)
	}
	ncols := len(omega)

	// Build public matrices.
	B, err := loadBForShowing(ringQ, state, publicParams)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load B: %v", err)
	}
	wit, err := buildWitnessFromState(ringQ, state, B, omega, boundB, publicParams.X0CoeffBound)
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

	nonce, noncePublic := sampleNonce(params.LenNonce, ncols, ringQ.Modulus[0])
	key, err := prfKeyFromWitnessOnOmega(ringQ, wit, omega, params.LenKey)
	if err != nil {
		cli.fatalf("[showing-cli] ", "prf key: %v", err)
	}
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		cli.fatalf("[showing-cli] ", "prf tag: %v", err)
	}
	tagPublic := lanesFromElems(tag, ncols)

	pub := PIOP.PublicInputs{
		A:                  A,
		B:                  B,
		Tag:                tagPublic,
		Nonce:              noncePublic,
		BoundB:             boundB,
		X0Len:              publicParams.X0Len,
		X0CoeffBound:       publicParams.X0CoeffBound,
		TargetDim:          publicParams.TargetDim,
		TargetHidingLambda: publicParams.TargetHidingLambda,
		RingDegree:         int(ringQ.N),
		HashRelation:       publicParams.HashRelation,
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
	verified, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	verifyDur := time.Since(verifyStart)
	if err != nil || !verified {
		cli.fatalf("[showing-cli] ", "verify showing failed: ok=%v err=%v", verified, err)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "showing proof verified")
	printLogicalWitnessRowBreakdown("[showing-cli] ", proof)
	printCommittedWitnessRowBreakdown("[showing-cli] ", proof)
	rep, reportOK := printProofReport("[showing-cli] ", proof, opts, pub.BoundB, ringQ, proofDur, verifyDur)
	if reportOK {
		if rep.X0Len != activeProfile.X0Len || rep.TranscriptFocus.X0Len != activeProfile.X0Len || rep.PaperTranscript.X0Len != activeProfile.X0Len {
			cli.fatalf("[showing-cli] ", "report x0_len mismatch for %s: proof=%d focus=%d transcript=%d want=%d",
				activeProfile.Name, rep.X0Len, rep.TranscriptFocus.X0Len, rep.PaperTranscript.X0Len, activeProfile.X0Len)
		}
		if rep.RingDegree != activeProfile.RingDegree || rep.TranscriptFocus.RingDegree != activeProfile.RingDegree || rep.PaperTranscript.RingDegree != activeProfile.RingDegree {
			cli.fatalf("[showing-cli] ", "report ring_degree mismatch for %s: proof=%d focus=%d transcript=%d want=%d",
				activeProfile.Name, rep.RingDegree, rep.TranscriptFocus.RingDegree, rep.PaperTranscript.RingDegree, activeProfile.RingDegree)
		}
		if rep.Soundness.TotalBits+1e-9 < activeProfile.SoundnessTarget {
			cli.fatalf("[showing-cli] ", "showing profile %s missed target: theorem bits %.2f < %.0f", activeProfile.Name, rep.Soundness.TotalBits, activeProfile.SoundnessTarget)
		}
	}
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
	meta, err := ntrurio.LoadBMatrixMetadata(bPath)
	if err != nil {
		return nil, err
	}
	if meta.TargetDim != public.TargetDim {
		return nil, fmt.Errorf("B target_dim=%d want %d", meta.TargetDim, public.TargetDim)
	}
	if meta.X0Len != public.X0Len {
		return nil, fmt.Errorf("B x0_len=%d want %d", meta.X0Len, public.X0Len)
	}
	if meta.RingDegree != int(r.N) {
		return nil, fmt.Errorf("B ring_degree=%d want %d", meta.RingDegree, r.N)
	}
	coeffs := meta.B
	out := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		if len(coeffs[i]) != int(r.N) {
			return nil, fmt.Errorf("B[%d] coefficient length=%d want ring_degree=%d", i, len(coeffs[i]), r.N)
		}
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

func validateArtifactRingDegree(ringDegree int, statePath string, st credential.State, public credential.PublicParams) error {
	if ringDegree <= 0 {
		return fmt.Errorf("invalid selected ring_degree=%d", ringDegree)
	}
	if got := public.InferRingDegree(); got > 0 && got != ringDegree {
		return fmt.Errorf("credential public params ring_degree=%d incompatible with selected ring_degree=%d; fresh N=%d artifacts are required", got, ringDegree, ringDegree)
	}
	if got := st.InferRingDegree(); got > 0 && got != ringDegree {
		return fmt.Errorf("credential state %s ring_degree=%d incompatible with selected ring_degree=%d; fresh N=%d artifacts are required", statePath, got, ringDegree, ringDegree)
	}
	if public.X0Len <= 0 {
		return fmt.Errorf("credential public params missing x0_len")
	}
	if st.X0Len <= 0 {
		return fmt.Errorf("credential state %s missing x0_len", statePath)
	}
	if st.X0Len != public.X0Len {
		return fmt.Errorf("credential state %s x0_len=%d incompatible with public params x0_len=%d; fresh matching artifacts are required", statePath, st.X0Len, public.X0Len)
	}
	if len(st.R0) != st.X0Len {
		return fmt.Errorf("credential state %s r0 rows=%d incompatible with x0_len=%d", statePath, len(st.R0), st.X0Len)
	}
	checkRows := func(label string, rows [][]int64, required bool) error {
		if len(rows) == 0 {
			if required {
				return fmt.Errorf("credential state %s missing %s rows", statePath, label)
			}
			return nil
		}
		for i := range rows {
			if len(rows[i]) != ringDegree {
				return fmt.Errorf("credential state %s %s[%d] coefficient length=%d want ring_degree=%d", statePath, label, i, len(rows[i]), ringDegree)
			}
		}
		return nil
	}
	if err := checkRows("mu", st.Mu, true); err != nil {
		return err
	}
	if err := checkRows("r0", st.R0, true); err != nil {
		return err
	}
	if err := checkRows("r1", st.R1, true); err != nil {
		return err
	}
	if err := checkRows("z", st.Z, true); err != nil {
		return err
	}
	if len(st.SigS1) > 0 && len(st.SigS1) != ringDegree {
		return fmt.Errorf("credential state %s sig_s1 coefficient length=%d want ring_degree=%d", statePath, len(st.SigS1), ringDegree)
	}
	if len(st.SigS2) > 0 && len(st.SigS2) != ringDegree {
		return fmt.Errorf("credential state %s sig_s2 coefficient length=%d want ring_degree=%d", statePath, len(st.SigS2), ringDegree)
	}
	if err := checkRows("ntru_public", st.NTRUPublic, false); err != nil {
		return err
	}
	if err := checkRows("embedded_b", st.B, false); err != nil {
		return err
	}
	return nil
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
	if len(st.NTRUPublic[0]) != int(r.N) {
		return nil, fmt.Errorf("NTRU public key coefficient length=%d want ring_degree=%d", len(st.NTRUPublic[0]), r.N)
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

func buildWitnessFromState(r *ring.Ring, st credential.State, B []*ring.Poly, omega []uint64, boundB, x0Bound int64) (PIOP.WitnessInputs, error) {
	coeffNative, err := buildCoeffNativeShowingWitnessFromState(r, st, B, omega, boundB, x0Bound)
	if err != nil {
		return PIOP.WitnessInputs{}, err
	}
	return PIOP.WitnessInputs{
		CoeffNativeShowing: coeffNative,
	}, nil
}

func buildCoeffNativeShowingWitnessFromState(r *ring.Ring, st credential.State, B []*ring.Poly, omega []uint64, boundB, x0Bound int64) (*PIOP.CoeffNativeShowingWitness, error) {
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
	if err := validateStateWitnessCoefficientLengths(st, int(r.N)); err != nil {
		return nil, err
	}
	if len(B) < 3+x0Len {
		return nil, fmt.Errorf("missing B matrix for target reconstruction: have %d want at least %d", len(B), 3+x0Len)
	}
	packedNCols, err := PIOP.ResolvePackedNCols(st.PackedNCols, 0, int(r.N))
	if err != nil {
		return nil, fmt.Errorf("resolve packed ncols: %w", err)
	}
	if err := credential.ValidateFullMuPayload(st.Mu, int(r.N), boundB); err != nil {
		return nil, fmt.Errorf("invalid credential mu payload: %w", err)
	}
	muPoly := polyFromInt64(r, st.Mu[0])
	_ = x0Bound
	_ = omega
	r0Polys := credentialPolysFromInt64(r, st.R0)
	r1Poly := polyFromInt64(r, st.R1[0])
	zPoly := polyFromInt64(r, st.Z[0])
	_, tCoeffs, err := credential.ComputeTargetVectorFromMu(r, B, muPoly, r0Polys, r1Poly)
	if err != nil {
		return nil, fmt.Errorf("recompute target from credential state: %w", err)
	}
	tPoly := polyFromInt64(r, tCoeffs)
	wit := &PIOP.CoeffNativeShowingWitness{
		Sig: []*ring.Poly{
			polyFromInt64(r, st.SigS1),
			polyFromInt64(r, st.SigS2),
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

func validateStateWitnessCoefficientLengths(st credential.State, ringDegree int) error {
	if ringDegree <= 0 {
		return fmt.Errorf("invalid ring degree %d", ringDegree)
	}
	checkRows := func(name string, rows [][]int64) error {
		for i := range rows {
			if len(rows[i]) != ringDegree {
				return fmt.Errorf("credential state %s[%d] coefficient length=%d want ring_degree=%d", name, i, len(rows[i]), ringDegree)
			}
		}
		return nil
	}
	if err := checkRows("mu", st.Mu); err != nil {
		return err
	}
	if err := checkRows("r0", st.R0); err != nil {
		return err
	}
	if err := checkRows("r1", st.R1); err != nil {
		return err
	}
	if err := checkRows("z", st.Z); err != nil {
		return err
	}
	if len(st.SigS1) != ringDegree {
		return fmt.Errorf("credential state sig_s1 coefficient length=%d want ring_degree=%d", len(st.SigS1), ringDegree)
	}
	if len(st.SigS2) != ringDegree {
		return fmt.Errorf("credential state sig_s2 coefficient length=%d want ring_degree=%d", len(st.SigS2), ringDegree)
	}
	return nil
}

func showingSignatureComponentCount(wit PIOP.WitnessInputs) int {
	if wit.CoeffNativeShowing != nil && len(wit.CoeffNativeShowing.Sig) > 0 {
		return len(wit.CoeffNativeShowing.Sig)
	}
	return 0
}

func prfKeyFromWitnessOnOmega(r *ring.Ring, wit PIOP.WitnessInputs, omega []uint64, lenKey int) ([]prf.Elem, error) {
	if r == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if wit.CoeffNativeShowing == nil {
		return nil, fmt.Errorf("missing coeff-native showing witness")
	}
	if wit.CoeffNativeShowing.Mu == nil {
		return nil, fmt.Errorf("coeff-native showing witness missing Mu row")
	}
	return PIOP.ExtractSignedPRFKeyElemsFromMuCoeffs(
		r,
		wit.CoeffNativeShowing.Mu,
		wit.CoeffNativeShowing.PackedNCols,
		lenKey,
	)
}

func prfKeyFromCarrierWitness(
	r *ring.Ring,
	wit PIOP.WitnessInputs,
	A [][]*ring.Poly,
	B []*ring.Poly,
	boundB int64,
	params *prf.Params,
	opts PIOP.SimOpts,
	omega []uint64,
	noncePublic [][]int64,
	publicParams credential.PublicParams,
) ([]prf.Elem, error) {
	if r == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if params == nil {
		return nil, fmt.Errorf("nil prf params")
	}
	if wit.CoeffNativeShowing == nil {
		return nil, fmt.Errorf("missing coeff-native showing witness")
	}
	opts.EnablePackedPRFWitnessRows = true
	opts.EnablePRFCompanion = true
	if opts.PRFCompanionMode == "" {
		opts.PRFCompanionMode = PIOP.PRFCompanionModeOutputAudit
	}
	dummyTag := make([][]int64, params.LenTag)
	for i := range dummyTag {
		dummyTag[i] = buildConstLane(len(omega), 0)
	}
	pub := PIOP.PublicInputs{
		A:                  A,
		B:                  B,
		Tag:                dummyTag,
		Nonce:              noncePublic,
		BoundB:             boundB,
		X0Len:              publicParams.X0Len,
		X0CoeffBound:       publicParams.X0CoeffBound,
		TargetDim:          publicParams.TargetDim,
		TargetHidingLambda: publicParams.TargetHidingLambda,
		RingDegree:         int(r.N),
		HashRelation:       publicParams.HashRelation,
	}
	rows, _, layout, _, _, _, _, _, _, _, _, err := PIOP.BuildCredentialRowsShowing(
		r,
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
		return nil, fmt.Errorf("build showing rows for carrier key extraction: %w", err)
	}
	ncols := wit.CoeffNativeShowing.PackedNCols
	if ncols <= 0 {
		ncols = len(omega)
	}
	keyStart := int(r.N) / 2
	keyBlock := keyStart / ncols
	keyCol := keyStart % ncols
	muPackWidth := PIOP.ResolveSimOptsDefaults(opts).MuWitnessPackWidth
	if layout.MuCarrierPackWidth > 0 {
		muPackWidth = layout.MuCarrierPackWidth
	}
	carrierRows := append([]int(nil), layout.CarrierMuBlockRows...)
	if len(carrierRows) == 0 {
		carrierRows = []int{layout.IdxCarrierM}
	}
	keyCarrierBlock := keyBlock / muPackWidth
	keyLane := keyBlock % muPackWidth
	if keyCarrierBlock < 0 || keyCarrierBlock >= len(carrierRows) {
		return nil, fmt.Errorf("missing carrier mu key block %d packed=%d among %d rows", keyBlock, keyCarrierBlock, len(carrierRows))
	}
	keyCarrierRow := carrierRows[keyCarrierBlock]
	if keyCarrierRow < 0 || keyCarrierRow >= len(rows) {
		return nil, fmt.Errorf("carrier mu key row %d out of range", keyCarrierRow)
	}
	var scalars []int64
	if muPackWidth == 1 {
		scalars, err = PIOP.ExtractSignedPRFKeyScalarsFromSingletonCarrierWindowOnOmega(
			r,
			rows[keyCarrierRow],
			omega,
			keyCol,
			params.LenKey,
			boundB,
		)
	} else {
		scalars, err = PIOP.ExtractSignedPRFKeyScalarsFromPackedMuCarrierWindowOnOmega(
			r,
			rows[keyCarrierRow],
			omega,
			keyCol,
			params.LenKey,
			boundB,
			muPackWidth,
			keyLane,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("extract signed prf key from carrier witness: %w", err)
	}
	out := make([]prf.Elem, len(scalars))
	q := int64(r.Modulus[0])
	for i := range scalars {
		v := scalars[i] % q
		if v < 0 {
			v += q
		}
		out[i] = prf.Elem(v)
	}
	return out, nil
}

func prfKeyFromState(r *ring.Ring, st credential.State, lenKey int) ([]prf.Elem, error) {
	if r == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(st.Mu) == 0 {
		return nil, fmt.Errorf("credential state missing mu")
	}
	keyStart := int(r.N) / 2
	if keyStart+lenKey > len(st.Mu[0]) {
		return nil, fmt.Errorf("credential mu row length %d is shorter than full-capacity key window [%d,%d)", len(st.Mu[0]), keyStart, keyStart+lenKey)
	}
	out := make([]prf.Elem, lenKey)
	q := int64(r.Modulus[0])
	for i := 0; i < lenKey; i++ {
		idx := keyStart + i
		v := st.Mu[0][idx] % q
		if v < 0 {
			v += q
		}
		out[i] = prf.Elem(v)
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

func deriveOmegaForOpts(ringQ *ring.Ring, opts PIOP.SimOpts, relation string) ([]uint64, error) {
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
		omegaWitness, err := PIOP.DeriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, opts.NCols, lvcsNCols, opts.Ell, relation)
		if err != nil {
			return nil, err
		}
		if len(omegaWitness) < opts.NCols {
			return nil, fmt.Errorf("derived omega len=%d < witness ncols=%d", len(omegaWitness), opts.NCols)
		}
		return append([]uint64(nil), omegaWitness[:opts.NCols]...), nil
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

func printProofReport(prefix string, proof *PIOP.Proof, opts PIOP.SimOpts, boundB int64, ringQ *ring.Ring, proveDur, verifyDur time.Duration) (PIOP.ProofReport, bool) {
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		cli.printf(categoryWarning, prefix, "report: %v", err)
		return PIOP.ProofReport{}, false
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
	printSigLookupShadow(prefix, rep)
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
	cli.printf(categoryGeometry, prefix, "Params: ring_degree=%d x0_len=%d NCols(s)=%d pcs_ncols=%d nleaves=%d ddecs=%d ℓ=%d ℓ'=%d ρ=%d θ=%d η=%d κ={%d,%d,%d,%d} dQ=%d collision_bits=%d",
		rep.RingDegree, rep.X0Len, rep.NCols, rep.PCSNCols, rep.NLeaves, rep.Soundness.DDECS, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta,
		rep.Kappa[0], rep.Kappa[1], rep.Kappa[2], rep.Kappa[3], rep.DQ, rep.Soundness.CollisionSpaceBits)
	printWitnessGeometry(prefix, rep.Geometry)
	if sigErr == nil {
		if rep.TranscriptFocus.SigShortnessDegree > 0 {
			sigDegree = rep.TranscriptFocus.SigShortnessDegree
		}
		cli.printf(categoryGeometry, prefix, "Linf chain: sig(profile=%s,R=%d,L=%d,rows=%d,deg=%d) nonSig=carriers", rep.TranscriptFocus.SigShortnessProfile, sigBase, sigL, sigRowsPer, sigDegree)
	} else {
		cli.printf(categoryWarning, prefix, "Linf chain shape resolution warning: sigErr=%v", sigErr)
	}
	paperTranscriptKB := float64(rep.PaperTranscript.OptimizedBytes) / 1024.0
	cli.printf(categoryWarning, prefix, "Table row: %.2f %.3f %.2f %d %d %d %d %d %d",
		paperTranscriptKB, proveDur.Seconds(), rep.Soundness.TotalBits,
		rep.NCols, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta)
	return rep, true
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
	rowFamilies := fmt.Sprintf(
		" rows(mhat=%d rhat0=%d r0b2=%d target_mr0=%d rhat1=%d zhat=%d that=%d sig=%d mask=%d)",
		focus.ReplayMHatSigmaRows,
		focus.ReplayRHat0Rows,
		focus.ReplayR0B2HatRows,
		focus.ReplayTargetMR0HatRows,
		focus.ReplayRHat1Rows,
		focus.ReplayZHatRows,
		focus.ReplayTHatRows,
		focus.InlinedShortnessRows,
		focus.MaskRows,
	)
	if focus.PackedSigShortnessRows > 0 {
		rowFamilies = fmt.Sprintf(
			" rows(mhat=%d rhat0=%d r0b2=%d target_mr0=%d rhat1=%d zhat=%d that=%d sig=%d(g=%d,w=%d,blocks=%d) mask=%d)",
			focus.ReplayMHatSigmaRows,
			focus.ReplayRHat0Rows,
			focus.ReplayR0B2HatRows,
			focus.ReplayTargetMR0HatRows,
			focus.ReplayRHat1Rows,
			focus.ReplayZHatRows,
			focus.ReplayTHatRows,
			focus.PackedSigShortnessRows,
			focus.PackedSigChainGroupSize,
			focus.PackedSigBlockWidth,
			focus.PackedSigEffectiveBlocks,
			focus.MaskRows,
		)
	}
	aggregateR0 := ""
	if focus.AggregateR0Replay {
		aggregateR0 = " aggregate_r0=true"
	}
	ringDegree := ""
	if focus.RingDegree > 0 {
		ringDegree = fmt.Sprintf(" ring_degree=%d", focus.RingDegree)
	}
	x0Len := ""
	if focus.X0Len > 0 {
		x0Len = fmt.Sprintf(" x0_len=%d", focus.X0Len)
	}
	return fmt.Sprintf(
		"Transcript focus: preset=%s replay=%s%s%s blocks=%d lvcs=%d nleaves=%d rowsBlock=%d maskChunks=%d witness=%d nrows=%d m=%d pcols=%d omitP=%d prf_scalars=%d prf_rows=%d (%s) mu_pack=%d mu_rows=%d mu_blocks=%d entries=%d%s%s%s",
		focus.ShowingPreset,
		focus.ReplayMode,
		ringDegree,
		x0Len,
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
		focus.MuPackWidth,
		focus.MuCarrierRows,
		focus.MuVirtualBlocks,
		focus.RowOpeningEntries,
		aggregateR0,
		rowFamilies,
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

func printSigLookupShadow(prefix string, rep PIOP.ProofReport) {
	focus := rep.TranscriptFocus
	if focus.SigLookupShadowMode == "" {
		return
	}
	cli.printf(categoryWarning, prefix, "Sig lookup shadow: mode=%s rows=%d->%d cells=%d table=%d",
		focus.SigLookupShadowMode,
		focus.SigRowsBefore,
		focus.SigRowsAfter,
		focus.SigLookupCells,
		focus.SigLookupTableSize,
	)
	if focus.SigLookupShadowMode == PIOP.SigLookupShadowR121L2Free {
		cli.printf(categoryWarning, prefix, "Sig lookup shadow budget: free_upper_bound=%d max_lookup_budget_for_35500=%d",
			focus.FreeLookupUpperBoundBytes,
			focus.MaxLookupBudgetFor35500,
		)
	}
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
