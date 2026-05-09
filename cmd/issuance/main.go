package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strings"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

const (
	defaultArtifactDir             = "credential/issuance"
	defaultHolderSecretPath        = defaultArtifactDir + "/holder_secret.json"
	defaultCommitRequestPath       = defaultArtifactDir + "/commit_request.json"
	defaultIssueChallengePath      = defaultArtifactDir + "/issue_challenge.json"
	defaultPreSignSubmissionPath   = defaultArtifactDir + "/presign_submission.json"
	defaultIssueResponsePath       = defaultArtifactDir + "/issue_response.json"
	defaultCredentialStatePath     = "credential/keys/credential_state.json"
	defaultCredentialSignaturePath = "credential/keys/signature.json"
	defaultPRFParamsPath           = "prf/prf_params.json"
	defaultDemoPublicParamsPath    = "Parameters/credential_public.demo.json"
	defaultNTRUParamsPath          = "Parameters/Parameters.json"
	defaultNTRUPublicKeyPath       = "ntru_keys/public.json"
	defaultNTRUPrivateKeyPath      = "ntru_keys/private.json"
)

func usage() {
	fmt.Println(`usage: issuance <setup-intgenisis-public|setup-demo-public|setup-ntru-keys|holder-commit|issuer-challenge|holder-prove|issuer-verify-sign|holder-finalize|demo-local|benchmark-x0|benchmark-intgenisis|benchmark-intgenisis-e2e|sweep-intgenisis|sweep-intgenisis-presets|sweep-intgenisis-estimate|sweep-intgenisis-runtime96|sweep-intgenisis-runtime96-deep|sweep-intgenisis-n1024-ternary-deep|sweep-intgenisis-n1024-ternary-lowleaves|sweep-intgenisis-n1024-smallfield90-zero|sweep-intgenisis-n1024-smallfield115-zero> [options]

Subcommands:
  setup-intgenisis-public Generate IntGenISIS MLWE-hiding credential public parameters
  setup-demo-public  Generate credential public parameters with a full random Ac matrix
  setup-ntru-keys    Generate separate NTRU params and key material
  holder-commit      Sample holder witness rows and write holder_secret/commit_request artifacts
  issuer-challenge   Sample issuer challenge rows from a commit request
  holder-prove       Build the pre-sign proof from holder secret + issuer challenge
  issuer-verify-sign Verify the pre-sign proof and sign the public target T
  holder-finalize    Verify and persist the final credential state
  demo-local         Run the full role-separated issuance flow in one process
  benchmark-x0      Benchmark legacy issuance + showing across x0 profiles
  benchmark-intgenisis Report IntGenISIS MLWE row inventories and proof metrics
  benchmark-intgenisis-e2e Run IntGenISIS issuance + showing and print paper transcript sizes
  sweep-intgenisis  Sweep SmallWood parameters for IntGenISIS profile-B Eq. (8) soundness
  sweep-intgenisis-presets Build fixed-LVCS preset frontiers for 96/128-bit IntGenISIS defaults
  sweep-intgenisis-estimate Estimate deep N=256/N=512 IntGenISIS transcript frontiers without building proofs
  sweep-intgenisis-runtime96 Estimate N=256 96-bit candidates ranked by showing_bytes*log2(nleaves)
  sweep-intgenisis-runtime96-deep Estimate a broader N=256 96-bit runtime frontier with more low-leaf axes
  sweep-intgenisis-n1024-ternary-deep Estimate N=1024 ternary transcript-size leaders for 96/128-bit targets
  sweep-intgenisis-n1024-ternary-lowleaves Estimate N=1024 ternary low-leaf candidates ranked by showing_bytes*log2(nleaves)
  sweep-intgenisis-n1024-smallfield90-zero Estimate N=1024 strict smallfield rho=1 ell'=1 candidates above 90 bits with zero grinding
  sweep-intgenisis-n1024-smallfield115-zero Estimate N=1024 strict smallfield rho=1 ell'=1 candidates above 115 bits with zero grinding`)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Printf("[issuance-cli] %v", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing subcommand")
	}
	switch args[0] {
	case "setup-intgenisis-public":
		return runSetupIntGenISISPublic(args[1:])
	case "setup-demo-public":
		return runSetupDemoPublic(args[1:])
	case "setup-ntru-keys":
		return runSetupNTRUKeys(args[1:])
	case "holder-commit":
		return runHolderCommit(args[1:])
	case "issuer-challenge":
		return runIssuerChallenge(args[1:])
	case "holder-prove":
		return runHolderProve(args[1:])
	case "issuer-verify-sign":
		return runIssuerVerifySign(args[1:])
	case "holder-finalize":
		return runHolderFinalize(args[1:])
	case "demo-local":
		return runDemoLocal(args[1:])
	case "benchmark-x0":
		return runBenchmarkX0(args[1:])
	case "benchmark-intgenisis":
		return runBenchmarkIntGenISIS(args[1:])
	case "benchmark-intgenisis-e2e":
		return runBenchmarkIntGenISISE2E(args[1:])
	case "sweep-intgenisis":
		return runSweepIntGenISIS(args[1:])
	case "sweep-intgenisis-presets":
		return runSweepIntGenISISPresets(args[1:])
	case "sweep-intgenisis-estimate":
		return runSweepIntGenISISEstimate(args[1:])
	case "sweep-intgenisis-runtime96":
		return runSweepIntGenISISRuntime96(args[1:])
	case "sweep-intgenisis-runtime96-deep":
		return runSweepIntGenISISRuntime96Deep(args[1:])
	case "sweep-intgenisis-n1024-ternary-deep":
		return runSweepIntGenISISN1024TernaryDeep(args[1:])
	case "sweep-intgenisis-n1024-ternary-lowleaves":
		return runSweepIntGenISISN1024TernaryLowLeaves(args[1:])
	case "sweep-intgenisis-n1024-smallfield90-zero":
		return runSweepIntGenISISN1024StrictSmallField90Zero(args[1:])
	case "sweep-intgenisis-n1024-smallfield115-zero":
		return runSweepIntGenISISN1024StrictSmallField115Zero(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runBenchmarkIntGenISIS(args []string) error {
	fs := flag.NewFlagSet("benchmark-intgenisis", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profiles := fs.String("profiles", credential.ProfileIntGenISISB, "comma-separated IntGenISIS profiles")
	packingFactor := fs.Int("s-sw", 16, "SmallWood packing factor")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return benchmarkIntGenISIS(*profiles, *packingFactor, *jsonOut)
}

func runBenchmarkIntGenISISE2E(args []string) error {
	fs := flag.NewFlagSet("benchmark-intgenisis-e2e", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactDir := fs.String("artifact-dir", "", "artifact directory; defaults to a temporary directory")
	profile := fs.String("profile", credential.ProfileIntGenISISB, "IntGenISIS profile name")
	profileBound := fs.Int64("profile-bound", 0, "override IntGenISIS public BoundB/CommitmentBound for bounded-range experiments; 0 uses the profile default")
	prfParamsPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	presetName := fs.String("preset", "", "named IntGenISIS preset (for example 96bit, fast96, 120bitsf, fast-local, sw96-lvcs64, sw128-lvcs64, n256-sw96, n256-sw128, n1024-sw90-smallfield, n1024-sw115-smallfield, n1024-sw120-smallfield, n1024-sw128)")
	preset96Bit := fs.Bool("96bit", false, "use the general IntGenISIS 96-bit preset")
	force := fs.Bool("force", false, "overwrite existing artifacts")
	seed := fs.Int64("seed", 11, "holder commitment sampling seed")
	ncols := fs.Int("ncols", 16, "SmallWood packing width")
	lvcsNCols := fs.Int("lvcs-ncols", 32, "LVCS width")
	nLeaves := fs.Int("nleaves", 4096, "explicit-domain leaf count")
	maxNLeaves := fs.Int("max-nleaves", intGenISISDefaultMaxNLeaves, "maximum explicit-domain leaves for issuance and showing; 0 disables the cap for uncapped research runs")
	eta := fs.Int("eta", 8, "SmallWood eta")
	theta := fs.Int("theta", 1, "SmallWood theta")
	rho := fs.Int("rho", 1, "SmallWood rho")
	ell := fs.Int("ell", 4, "SmallWood ell")
	ellPrime := fs.Int("ell-prime", 4, "SmallWood ell prime")
	kappa1 := fs.Int("kappa1", 0, "SmallWood theorem aggregation kappa round 1")
	kappa2 := fs.Int("kappa2", 0, "SmallWood theorem aggregation kappa round 2")
	kappa3 := fs.Int("kappa3", 0, "SmallWood theorem aggregation kappa round 3")
	kappa4 := fs.Int("kappa4", 0, "SmallWood theorem aggregation kappa round 4")
	issuanceNCols := fs.Int("issuance-ncols", 0, "issuance witness packing width override")
	issuanceLVCSNCols := fs.Int("issuance-lvcs-ncols", 0, "issuance LVCS width override")
	issuanceNLeaves := fs.Int("issuance-nleaves", 0, "issuance explicit-domain leaf count override")
	issuanceEta := fs.Int("issuance-eta", 0, "issuance eta override")
	issuanceTheta := fs.Int("issuance-theta", 0, "issuance theta override")
	issuanceRho := fs.Int("issuance-rho", 0, "issuance rho override")
	issuanceEll := fs.Int("issuance-ell", 0, "issuance ell override")
	issuanceEllPrime := fs.Int("issuance-ell-prime", 0, "issuance ell-prime override")
	showingNCols := fs.Int("showing-ncols", 0, "showing witness packing width override")
	showingLVCSNCols := fs.Int("showing-lvcs-ncols", 0, "showing LVCS width override")
	showingNLeaves := fs.Int("showing-nleaves", 0, "showing explicit-domain leaf count override")
	showingEta := fs.Int("showing-eta", 0, "showing eta override")
	showingTheta := fs.Int("showing-theta", 0, "showing theta override")
	showingRho := fs.Int("showing-rho", 0, "showing rho override")
	showingEll := fs.Int("showing-ell", 0, "showing ell override")
	showingEllPrime := fs.Int("showing-ell-prime", 0, "showing ell-prime override")
	showingShortnessRadix := fs.Int("showing-sig-shortness-radix", 0, "showing IntGenISIS u-shortness radix override")
	showingShortnessDigits := fs.Int("showing-sig-shortness-digits", 0, "showing IntGenISIS u-shortness digit-count override")
	showingCompressedRows := fs.Int("showing-compressed-rows", 0, "showing IntGenISIS M/s/e compression level: 0 none; bounded-range presets reject levels >0")
	showingReplayProjection := fs.String("showing-replay-projection", PIOP.IntGenISISReplayProjectionNone, "showing IntGenISIS replay projection mode: none, project_u_y_hat_v1, project_u_y_hat_and_y_view_v2, project_u_digits_and_y_view_v3, experimental project_u_digits_y_source_linear_v4, or experimental project_u_digits_y_w_residual_v5")
	showingTranscriptMode := fs.String("showing-transcript-mode", "", "showing transcript mode: baseline, column_widths_v1, or smallfield_2025_1085_v1; strict smallfield presets set this automatically")
	companionMode := fs.String("prf-companion-mode", string(PIOP.PRFCompanionModeOutputAudit), "PRF companion mode: output_audit, direct_auth, or aux_instance")
	prfGroupRounds := fs.Int("prf-group-rounds", 2, "grouped PRF rounds for the showing companion witness")
	checkpointSamples := fs.Int("prf-checkpoint-samples", 8, "PRF companion checkpoint samples")
	keygenTrials := fs.Int("keygen-trials", 10000, "maximum annulus keygen trials")
	keygenAttempts := fs.Int("attempts", 4, "annulus keygen attempts")
	ntruBeta := fs.Uint64("ntru-beta", 0, "optional research NTRU signature beta override; 0 keeps profile default")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	cpuProfile := fs.String("cpuprofile", "", "write CPU profile to this path")
	memProfile := fs.String("memprofile", "", "write heap allocation profile to this path")
	traceProfile := fs.String("trace", "", "write runtime trace to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, *preset96Bit)
	if err != nil {
		return err
	}
	baseKappa := [4]int{*kappa1, *kappa2, *kappa3, *kappa4}
	base := intGenISISTuning{
		NCols:             *ncols,
		LVCSNCols:         *lvcsNCols,
		NLeaves:           *nLeaves,
		Eta:               *eta,
		Theta:             *theta,
		Rho:               *rho,
		Ell:               *ell,
		EllPrime:          *ellPrime,
		Kappa:             baseKappa,
		PRFCompanionMode:  PIOP.PRFCompanionMode(*companionMode),
		PRFGroupRounds:    *prfGroupRounds,
		CheckpointSamples: *checkpointSamples,
	}
	issuance := intGenISISTuning{
		NCols:     *issuanceNCols,
		LVCSNCols: *issuanceLVCSNCols,
		NLeaves:   *issuanceNLeaves,
		Eta:       *issuanceEta,
		Theta:     *issuanceTheta,
		Rho:       *issuanceRho,
		Ell:       *issuanceEll,
		EllPrime:  *issuanceEllPrime,
		Kappa:     baseKappa,
	}
	showing := intGenISISTuning{
		NCols:              *showingNCols,
		LVCSNCols:          *showingLVCSNCols,
		NLeaves:            *showingNLeaves,
		Eta:                *showingEta,
		Theta:              *showingTheta,
		Rho:                *showingRho,
		Ell:                *showingEll,
		EllPrime:           *showingEllPrime,
		Kappa:              baseKappa,
		PRFCompanionMode:   PIOP.PRFCompanionMode(*companionMode),
		PRFGroupRounds:     *prfGroupRounds,
		CheckpointSamples:  *checkpointSamples,
		SigShortnessRadix:  *showingShortnessRadix,
		SigShortnessDigits: *showingShortnessDigits,
		CompressedRows:     *showingCompressedRows,
		ReplayProjection:   *showingReplayProjection,
		TranscriptMode:     *showingTranscriptMode,
	}
	if selectedPresetName != "" {
		preset, err := credential.MustLookupIntGenISISPreset(selectedPresetName)
		if err != nil {
			return err
		}
		if !setFlags["profile"] {
			*profile = preset.Profile
		}
		issuance = intGenISISTuningFromPresetSpec(preset.Issuance)
		showing = intGenISISTuningFromPresetSpec(preset.Showing)
		base = intGenISISTuningFromPresetSpec(preset.Showing)
		if preset.MaxNLeaves > 0 && !setFlags["max-nleaves"] {
			*maxNLeaves = preset.MaxNLeaves
		}
		applyCommonTuningFlagOverrides(&issuance, setFlags, *ncols, *lvcsNCols, *nLeaves, *eta, *theta, *rho, *ell, *ellPrime, baseKappa)
		applyCommonTuningFlagOverrides(&showing, setFlags, *ncols, *lvcsNCols, *nLeaves, *eta, *theta, *rho, *ell, *ellPrime, baseKappa)
		applyPrefixedTuningFlagOverrides(&issuance, setFlags, "issuance-", *issuanceNCols, *issuanceLVCSNCols, *issuanceNLeaves, *issuanceEta, *issuanceTheta, *issuanceRho, *issuanceEll, *issuanceEllPrime)
		applyPrefixedTuningFlagOverrides(&showing, setFlags, "showing-", *showingNCols, *showingLVCSNCols, *showingNLeaves, *showingEta, *showingTheta, *showingRho, *showingEll, *showingEllPrime)
		applyShowingSpecificFlagOverrides(&showing, setFlags, PIOP.PRFCompanionMode(*companionMode), *prfGroupRounds, *checkpointSamples, *showingShortnessRadix, *showingShortnessDigits, *showingCompressedRows, *showingReplayProjection, *showingTranscriptMode)
	}
	cfg := benchmarkIntGenISISE2EConfig{
		ArtifactDir:       *artifactDir,
		Profile:           *profile,
		ProfileBound:      *profileBound,
		PRFParamsPath:     *prfParamsPath,
		JSONOut:           *jsonOut,
		Force:             *force,
		Seed:              *seed,
		Issuance:          normalizeIntGenISISTuning(issuance, base, false),
		Showing:           normalizeIntGenISISTuning(showing, base, true),
		NCols:             *ncols,
		LVCSNCols:         *lvcsNCols,
		NLeaves:           *nLeaves,
		Eta:               *eta,
		Theta:             *theta,
		Rho:               *rho,
		Ell:               *ell,
		EllPrime:          *ellPrime,
		PRFCompanionMode:  PIOP.PRFCompanionMode(*companionMode),
		PRFGroupRounds:    *prfGroupRounds,
		CheckpointSamples: *checkpointSamples,
		KeygenTrials:      *keygenTrials,
		KeygenAttempts:    *keygenAttempts,
		NTRUBeta:          *ntruBeta,
		MaxTrials:         *maxTrials,
		MaxNLeaves:        *maxNLeaves,
	}
	return runWithBenchmarkProfiles(*cpuProfile, *memProfile, *traceProfile, func() error {
		_, err := benchmarkIntGenISISE2E(cfg)
		return err
	})
}

func runWithBenchmarkProfiles(cpuPath, memPath, tracePath string, fn func() error) (err error) {
	if cpuPath != "" {
		f, createErr := os.Create(cpuPath)
		if createErr != nil {
			return fmt.Errorf("create CPU profile %s: %w", cpuPath, createErr)
		}
		if startErr := pprof.StartCPUProfile(f); startErr != nil {
			_ = f.Close()
			return fmt.Errorf("start CPU profile %s: %w", cpuPath, startErr)
		}
		defer func() {
			pprof.StopCPUProfile()
			if closeErr := f.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("close CPU profile %s: %w", cpuPath, closeErr)
			}
		}()
	}
	if tracePath != "" {
		f, createErr := os.Create(tracePath)
		if createErr != nil {
			return fmt.Errorf("create trace %s: %w", tracePath, createErr)
		}
		if startErr := trace.Start(f); startErr != nil {
			_ = f.Close()
			return fmt.Errorf("start trace %s: %w", tracePath, startErr)
		}
		defer func() {
			trace.Stop()
			if closeErr := f.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("close trace %s: %w", tracePath, closeErr)
			}
		}()
	}
	err = fn()
	if memPath != "" {
		runtime.GC()
		f, createErr := os.Create(memPath)
		if createErr != nil {
			if err == nil {
				err = fmt.Errorf("create memory profile %s: %w", memPath, createErr)
			}
			return err
		}
		writeErr := pprof.WriteHeapProfile(f)
		closeErr := f.Close()
		if err == nil && writeErr != nil {
			err = fmt.Errorf("write memory profile %s: %w", memPath, writeErr)
		}
		if err == nil && closeErr != nil {
			err = fmt.Errorf("close memory profile %s: %w", memPath, closeErr)
		}
	}
	return err
}

func runSetupIntGenISISPublic(args []string) error {
	fs := flag.NewFlagSet("setup-intgenisis-public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", "", "output path for generated IntGenISIS credential public params")
	force := fs.Bool("force", false, "overwrite an existing output path")
	profileName := fs.String("profile", credential.ProfileIntGenISISB, "IntGenISIS profile name")
	bPath := fs.String("b-path", "", "B-matrix path recorded in the public params")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*outPath) == "" {
		*outPath = filepath.Join("Parameters", fmt.Sprintf("credential_public.%s.json", *profileName))
	}
	return setupIntGenISISPublic(*outPath, *force, *profileName, *bPath)
}

func runSetupNTRUKeys(args []string) error {
	fs := flag.NewFlagSet("setup-ntru-keys", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree for generated NTRU params/keys (supported: 1024, 512, or 256; 0 keeps default)")
	paramsOut := fs.String("params-out", "", "output path for generated NTRU params (default keeps canonical path for N=1024, research_n512 path for N=512, research_n256 path for N=256)")
	publicOut := fs.String("public-out", "", "output path for generated NTRU public key")
	privateOut := fs.String("private-out", "", "output path for generated NTRU private key")
	force := fs.Bool("force", false, "overwrite existing output paths")
	keygenTrials := fs.Int("keygen-trials", 10000, "maximum trials for each annulus keygen attempt")
	attempts := fs.Int("attempts", 4, "number of annulus keygen attempts before failing")
	ntruBeta := fs.Uint64("ntru-beta", 0, "optional research NTRU signature beta override; 0 keeps profile default")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return setupNTRUKeys(*researchRingDegree, *paramsOut, *publicOut, *privateOut, *force, *keygenTrials, *attempts, *ntruBeta)
}

func runSetupDemoPublic(args []string) error {
	fs := flag.NewFlagSet("setup-demo-public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", defaultDemoPublicParamsPath, "output path for generated credential public params")
	force := fs.Bool("force", false, "overwrite an existing output path")
	bPath := fs.String("b-path", "", "B-matrix path recorded in the public params (defaults from -hash-relation)")
	hashRelation := fs.String("hash-relation", credential.HashRelationBBTran, "hash relation recorded in the public params (bbs or bb_tran)")
	x0Profile := fs.String("x0-profile", "lhl_default", "x0 profile (legacy_scalar, lhl_default, lhl_alt)")
	x0Len := fs.Int("x0-len", 0, "optional x0 vector length override")
	x0Bound := fs.Int64("x0-bound", 0, "optional x0 coefficient bound override")
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree for generated public params (supported: 1024, 512, or 256; 0 keeps default)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return setupDemoPublic(*outPath, *force, *bPath, *hashRelation, *x0Profile, *x0Len, *x0Bound, *researchRingDegree)
}

func runHolderCommit(args []string) error {
	fs := flag.NewFlagSet("holder-commit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	publicPath := fs.String("public-params", credentialPublicPathDefault(), "credential public params path")
	prfPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	holderSecretPath := fs.String("holder-secret", defaultHolderSecretPath, "holder secret artifact path")
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
	expertInputPath := fs.String("expert-input", "", "optional expert witness JSON path")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset")
	preset96Bit := fs.Bool("96bit", false, "use the general IntGenISIS 96-bit issuance preset")
	seed := fs.Int64("seed", 0, "optional deterministic sampling seed")
	ncols := fs.Int("ncols", 0, "optional witness packing width override for issuance research")
	lvcsNCols := fs.Int("lvcs-ncols", 0, "optional LVCS width override for issuance research")
	nLeaves := fs.Int("nleaves", 0, "optional explicit-domain size override for issuance research")
	eta := fs.Int("eta", 0, "optional eta override for issuance research")
	theta := fs.Int("theta", 0, "optional theta override for issuance research")
	rho := fs.Int("rho", 0, "optional rho override for issuance research")
	ell := fs.Int("ell", 0, "optional ell override for issuance research")
	ellPrime := fs.Int("ell-prime", 0, "optional ell-prime override for issuance research")
	kappa1 := fs.Int("kappa1", 0, "optional theorem aggregation kappa round 1")
	kappa2 := fs.Int("kappa2", 0, "optional theorem aggregation kappa round 2")
	kappa3 := fs.Int("kappa3", 0, "optional theorem aggregation kappa round 3")
	kappa4 := fs.Int("kappa4", 0, "optional theorem aggregation kappa round 4")
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree override for issuance (supported: 1024, 512, or 256; 0 follows public params)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, *preset96Bit)
	if err != nil {
		return err
	}
	kappa := [4]int{*kappa1, *kappa2, *kappa3, *kappa4}
	ncolsVal, lvcsVal, nLeavesVal := *ncols, *lvcsNCols, *nLeaves
	etaVal, thetaVal, rhoVal, ellVal, ellPrimeVal := *eta, *theta, *rho, *ell, *ellPrime
	if selectedPresetName != "" {
		preset, err := credential.MustLookupIntGenISISPreset(selectedPresetName)
		if err != nil {
			return err
		}
		if !setFlags["public-params"] && preset.Profile != credential.ProfileIntGenISISB {
			*publicPath = filepath.Join("Parameters", fmt.Sprintf("credential_public.%s.json", preset.Profile))
		}
		t := intGenISISTuningFromPresetSpec(preset.Issuance)
		applyCommonTuningFlagOverrides(&t, setFlags, *ncols, *lvcsNCols, *nLeaves, *eta, *theta, *rho, *ell, *ellPrime, kappa)
		ncolsVal, lvcsVal, nLeavesVal = t.NCols, t.LVCSNCols, t.NLeaves
		etaVal, thetaVal, rhoVal, ellVal, ellPrimeVal = t.Eta, t.Theta, t.Rho, t.Ell, t.EllPrime
		kappa = t.Kappa
	}
	return holderCommit(*publicPath, *prfPath, *holderSecretPath, *commitRequestPath, *expertInputPath, *seed, issuanceRuntimeOverrides{
		NCols:      ncolsVal,
		LVCSNCols:  lvcsVal,
		NLeaves:    nLeavesVal,
		Ell:        ellVal,
		EllPrime:   ellPrimeVal,
		Eta:        etaVal,
		Theta:      thetaVal,
		Rho:        rhoVal,
		Kappa:      kappa,
		RingDegree: *researchRingDegree,
	})
}

func runIssuerChallenge(args []string) error {
	fs := flag.NewFlagSet("issuer-challenge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
	challengePath := fs.String("issue-challenge", defaultIssueChallengePath, "issuer challenge artifact path")
	seed := fs.Int64("seed", 0, "optional deterministic sampling seed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return issuerChallenge(*commitRequestPath, *challengePath, *seed)
}

func runHolderProve(args []string) error {
	fs := flag.NewFlagSet("holder-prove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	holderSecretPath := fs.String("holder-secret", defaultHolderSecretPath, "holder secret artifact path")
	challengePath := fs.String("issue-challenge", defaultIssueChallengePath, "issuer challenge artifact path")
	submissionPath := fs.String("presign-submission", defaultPreSignSubmissionPath, "pre-sign submission artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return holderProve(*holderSecretPath, *challengePath, *submissionPath)
}

func runIssuerVerifySign(args []string) error {
	fs := flag.NewFlagSet("issuer-verify-sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
	challengePath := fs.String("issue-challenge", defaultIssueChallengePath, "issuer challenge artifact path")
	submissionPath := fs.String("presign-submission", defaultPreSignSubmissionPath, "pre-sign submission artifact path")
	responsePath := fs.String("issue-response", defaultIssueResponsePath, "issuer response artifact path")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	ntruParamsPath := fs.String("ntru-params", defaultNTRUParamsPath, "NTRU params path used for signature beta bound")
	ntruPublicPath := fs.String("ntru-public-key", defaultNTRUPublicKeyPath, "NTRU public key path")
	ntruPrivatePath := fs.String("ntru-private-key", defaultNTRUPrivateKeyPath, "NTRU private key path")
	ntruSignaturePath := fs.String("ntru-signature-out", "", "optional issuer-side NTRU signature artifact path")
	verifierKeyOut := fs.String("verifier-key-out", "", "optional IntGenISIS public verifier key artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return issuerVerifySign(*commitRequestPath, *challengePath, *submissionPath, *responsePath, *maxTrials, ntruSigningPaths(*ntruParamsPath, *ntruPublicPath, *ntruPrivatePath, *ntruSignaturePath), *verifierKeyOut)
}

func runHolderFinalize(args []string) error {
	fs := flag.NewFlagSet("holder-finalize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	holderSecretPath := fs.String("holder-secret", defaultHolderSecretPath, "holder secret artifact path")
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
	challengePath := fs.String("issue-challenge", defaultIssueChallengePath, "issuer challenge artifact path")
	responsePath := fs.String("issue-response", defaultIssueResponsePath, "issuer response artifact path")
	statePath := fs.String("state-out", defaultCredentialStatePath, "final credential state path")
	signaturePath := fs.String("signature-out", defaultCredentialSignaturePath, "final signature artifact path")
	ntruParamsPath := fs.String("ntru-params", defaultNTRUParamsPath, "NTRU params path used when verifying seeded signature bundles")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return holderFinalize(*holderSecretPath, *commitRequestPath, *challengePath, *responsePath, *statePath, *signaturePath, *ntruParamsPath)
}

func runDemoLocal(args []string) error {
	fs := flag.NewFlagSet("demo-local", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	publicPath := fs.String("public-params", credentialPublicPathDefault(), "credential public params path")
	prfPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	artifactDir := fs.String("artifact-dir", defaultArtifactDir, "directory for intermediate issuance artifacts")
	statePath := fs.String("state-out", defaultCredentialStatePath, "final credential state path")
	signaturePath := fs.String("signature-out", defaultCredentialSignaturePath, "final signature artifact path")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset")
	preset96Bit := fs.Bool("96bit", false, "use the general IntGenISIS 96-bit issuance preset")
	seed := fs.Int64("seed", 0, "optional deterministic sampling seed")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	ncols := fs.Int("ncols", 0, "optional witness packing width override for issuance research")
	lvcsNCols := fs.Int("lvcs-ncols", 0, "optional LVCS width override for issuance research")
	nLeaves := fs.Int("nleaves", 0, "optional explicit-domain size override for issuance research")
	eta := fs.Int("eta", 0, "optional eta override for issuance research")
	theta := fs.Int("theta", 0, "optional theta override for issuance research")
	rho := fs.Int("rho", 0, "optional rho override for issuance research")
	ell := fs.Int("ell", 0, "optional ell override for issuance research")
	ellPrime := fs.Int("ell-prime", 0, "optional ell-prime override for issuance research")
	kappa1 := fs.Int("kappa1", 0, "optional theorem aggregation kappa round 1")
	kappa2 := fs.Int("kappa2", 0, "optional theorem aggregation kappa round 2")
	kappa3 := fs.Int("kappa3", 0, "optional theorem aggregation kappa round 3")
	kappa4 := fs.Int("kappa4", 0, "optional theorem aggregation kappa round 4")
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree override for issuance (supported: 1024, 512, or 256; 0 follows public params)")
	ntruParamsPath := fs.String("ntru-params", defaultNTRUParamsPath, "NTRU params path used for signature beta bound")
	ntruPublicPath := fs.String("ntru-public-key", defaultNTRUPublicKeyPath, "NTRU public key path")
	ntruPrivatePath := fs.String("ntru-private-key", defaultNTRUPrivateKeyPath, "NTRU private key path")
	ntruSignaturePath := fs.String("ntru-signature-out", "", "optional issuer-side NTRU signature artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, *preset96Bit)
	if err != nil {
		return err
	}
	kappa := [4]int{*kappa1, *kappa2, *kappa3, *kappa4}
	ncolsVal, lvcsVal, nLeavesVal := *ncols, *lvcsNCols, *nLeaves
	etaVal, thetaVal, rhoVal, ellVal, ellPrimeVal := *eta, *theta, *rho, *ell, *ellPrime
	if selectedPresetName != "" {
		preset, err := credential.MustLookupIntGenISISPreset(selectedPresetName)
		if err != nil {
			return err
		}
		if !setFlags["public-params"] && preset.Profile != credential.ProfileIntGenISISB {
			*publicPath = filepath.Join("Parameters", fmt.Sprintf("credential_public.%s.json", preset.Profile))
		}
		t := intGenISISTuningFromPresetSpec(preset.Issuance)
		applyCommonTuningFlagOverrides(&t, setFlags, *ncols, *lvcsNCols, *nLeaves, *eta, *theta, *rho, *ell, *ellPrime, kappa)
		ncolsVal, lvcsVal, nLeavesVal = t.NCols, t.LVCSNCols, t.NLeaves
		etaVal, thetaVal, rhoVal, ellVal, ellPrimeVal = t.Eta, t.Theta, t.Rho, t.Ell, t.EllPrime
		kappa = t.Kappa
	}
	return demoLocal(*publicPath, *prfPath, *artifactDir, *statePath, *signaturePath, *seed, *maxTrials, issuanceRuntimeOverrides{
		NCols:      ncolsVal,
		LVCSNCols:  lvcsVal,
		NLeaves:    nLeavesVal,
		Ell:        ellVal,
		EllPrime:   ellPrimeVal,
		Eta:        etaVal,
		Theta:      thetaVal,
		Rho:        rhoVal,
		Kappa:      kappa,
		RingDegree: *researchRingDegree,
	}, ntruSigningPaths(*ntruParamsPath, *ntruPublicPath, *ntruPrivatePath, *ntruSignaturePath))
}

func runBenchmarkX0(args []string) error {
	fs := flag.NewFlagSet("benchmark-x0", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profiles := fs.String("profiles", "legacy_scalar,lhl_default,lhl_alt", "comma-separated x0 benchmark profiles")
	runs := fs.Int("runs", 1, "number of benchmark runs per profile")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return benchmarkX0(*profiles, *runs, *jsonOut)
}
