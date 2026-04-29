package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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
	fmt.Println(`usage: issuance <setup-intgenisis-public|setup-demo-public|setup-ntru-keys|holder-commit|issuer-challenge|holder-prove|issuer-verify-sign|holder-finalize|demo-local|benchmark-x0|benchmark-intgenisis|benchmark-intgenisis-e2e|sweep-intgenisis|sweep-intgenisis-presets> [options]

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
  benchmark-intgenisis Report IntGenISIS MLWE row inventories and profile-B proof metrics
  benchmark-intgenisis-e2e Run profile-B issuance + showing and print paper transcript sizes
  sweep-intgenisis  Sweep SmallWood parameters for IntGenISIS profile-B Eq. (8) soundness
  sweep-intgenisis-presets Build fixed-LVCS preset frontiers for 96/128-bit IntGenISIS defaults`)
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
	prfParamsPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	presetName := fs.String("preset", "", "named IntGenISIS preset (fast-local, sw96-lvcs32, sw96-lvcs64, sw96-lvcs128, sw128-lvcs32, sw128-lvcs64, sw128-lvcs128)")
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
	showingCompressedRows := fs.Int("showing-compressed-rows", 0, "showing IntGenISIS M/s/e compression level: 0 none, 1 pack2, 2 pack3, 3 pack4")
	companionMode := fs.String("prf-companion-mode", string(PIOP.PRFCompanionModeOutputAudit), "PRF companion mode: output_audit, direct_auth, or aux_instance")
	checkpointSamples := fs.Int("prf-checkpoint-samples", 8, "PRF companion checkpoint samples")
	keygenTrials := fs.Int("keygen-trials", 10000, "maximum annulus keygen trials")
	keygenAttempts := fs.Int("attempts", 4, "annulus keygen attempts")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
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
		CheckpointSamples:  *checkpointSamples,
		SigShortnessRadix:  *showingShortnessRadix,
		SigShortnessDigits: *showingShortnessDigits,
		CompressedRows:     *showingCompressedRows,
	}
	if *presetName != "" {
		preset, err := credential.MustLookupIntGenISISPreset(*presetName)
		if err != nil {
			return err
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
		applyShowingSpecificFlagOverrides(&showing, setFlags, PIOP.PRFCompanionMode(*companionMode), *checkpointSamples, *showingShortnessRadix, *showingShortnessDigits, *showingCompressedRows)
	}
	_, err := benchmarkIntGenISISE2E(benchmarkIntGenISISE2EConfig{
		ArtifactDir:       *artifactDir,
		Profile:           *profile,
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
		CheckpointSamples: *checkpointSamples,
		KeygenTrials:      *keygenTrials,
		KeygenAttempts:    *keygenAttempts,
		MaxTrials:         *maxTrials,
		MaxNLeaves:        *maxNLeaves,
	})
	return err
}

func runSetupIntGenISISPublic(args []string) error {
	fs := flag.NewFlagSet("setup-intgenisis-public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", defaultDemoPublicParamsPath, "output path for generated IntGenISIS credential public params")
	force := fs.Bool("force", false, "overwrite an existing output path")
	profileName := fs.String("profile", credential.ProfileIntGenISISB, "IntGenISIS profile name")
	bPath := fs.String("b-path", "", "B-matrix path recorded in the public params")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return setupIntGenISISPublic(*outPath, *force, *profileName, *bPath)
}

func runSetupNTRUKeys(args []string) error {
	fs := flag.NewFlagSet("setup-ntru-keys", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree for generated NTRU params/keys (supported: 1024 or 512; 0 keeps default)")
	paramsOut := fs.String("params-out", "", "output path for generated NTRU params (default keeps canonical path for N=1024, research_n512 path for N=512)")
	publicOut := fs.String("public-out", "", "output path for generated NTRU public key")
	privateOut := fs.String("private-out", "", "output path for generated NTRU private key")
	force := fs.Bool("force", false, "overwrite existing output paths")
	keygenTrials := fs.Int("keygen-trials", 10000, "maximum trials for each annulus keygen attempt")
	attempts := fs.Int("attempts", 4, "number of annulus keygen attempts before failing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return setupNTRUKeys(*researchRingDegree, *paramsOut, *publicOut, *privateOut, *force, *keygenTrials, *attempts)
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
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree for generated public params (supported: 1024 or 512; 0 keeps default)")
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
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree override for issuance (supported: 1024 or 512; 0 follows public params)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
	kappa := [4]int{*kappa1, *kappa2, *kappa3, *kappa4}
	ncolsVal, lvcsVal, nLeavesVal := *ncols, *lvcsNCols, *nLeaves
	etaVal, thetaVal, rhoVal, ellVal, ellPrimeVal := *eta, *theta, *rho, *ell, *ellPrime
	if *presetName != "" {
		preset, err := credential.MustLookupIntGenISISPreset(*presetName)
		if err != nil {
			return err
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
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree override for issuance (supported: 1024 or 512; 0 follows public params)")
	ntruParamsPath := fs.String("ntru-params", defaultNTRUParamsPath, "NTRU params path used for signature beta bound")
	ntruPublicPath := fs.String("ntru-public-key", defaultNTRUPublicKeyPath, "NTRU public key path")
	ntruPrivatePath := fs.String("ntru-private-key", defaultNTRUPrivateKeyPath, "NTRU private key path")
	ntruSignaturePath := fs.String("ntru-signature-out", "", "optional issuer-side NTRU signature artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
	kappa := [4]int{*kappa1, *kappa2, *kappa3, *kappa4}
	ncolsVal, lvcsVal, nLeavesVal := *ncols, *lvcsNCols, *nLeaves
	etaVal, thetaVal, rhoVal, ellVal, ellPrimeVal := *eta, *theta, *rho, *ell, *ellPrime
	if *presetName != "" {
		preset, err := credential.MustLookupIntGenISISPreset(*presetName)
		if err != nil {
			return err
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
