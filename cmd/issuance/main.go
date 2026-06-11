package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

const (
	defaultArtifactDir             = "credential/issuance"
	defaultHolderSecretPath        = defaultArtifactDir + "/holder_secret.json"
	defaultCommitRequestPath       = defaultArtifactDir + "/commit_request.json"
	defaultPreSignSubmissionPath   = defaultArtifactDir + "/presign_submission.json"
	defaultIssueResponsePath       = defaultArtifactDir + "/issue_response.json"
	defaultCredentialStatePath     = "credential/keys/credential_state.json"
	defaultCredentialSignaturePath = "credential/keys/signature.json"
	defaultPRFParamsPath           = "prf/prf_params.json"
	defaultNTRUParamsPath          = "internal/source_data/Parameters.json"
	defaultNTRUPublicKeyPath       = "ntru_keys/public.json"
	defaultNTRUPrivateKeyPath      = "ntru_keys/private.json"
)

func usage() {
	fmt.Println(`usage: issuance <setup-intgenisis-public|setup-ntru-keys|holder-commit|holder-prove|issuer-verify-sign|holder-finalize|benchmark-intgenisis-e2e|gate-maintained-presets|gate-degree1024-maintained-presets> [options]

Subcommands:
  setup-intgenisis-public Generate IntGenISIS MLWE-hiding credential public parameters
  setup-ntru-keys    Generate separate NTRU params and key material
  holder-commit      Sample holder witness rows and write holder_secret/commit_request artifacts
  holder-prove       Build the IntGenISIS pre-sign proof from holder secret
  issuer-verify-sign Verify the pre-sign proof and sign the public target T
  holder-finalize    Verify and persist the final credential state
  benchmark-intgenisis-e2e Run IntGenISIS issuance + showing and print paper transcript sizes
  gate-maintained-presets Run live exact-byte gates for all maintained presets
  gate-degree1024-maintained-presets Run live gates for promoted degree-1024 maintained presets`)
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
	case "setup-ntru-keys":
		return runSetupNTRUKeys(args[1:])
	case "holder-commit":
		return runHolderCommit(args[1:])
	case "holder-prove":
		return runHolderProve(args[1:])
	case "issuer-verify-sign":
		return runIssuerVerifySign(args[1:])
	case "holder-finalize":
		return runHolderFinalize(args[1:])
	case "benchmark-intgenisis-e2e":
		return runBenchmarkIntGenISISE2E(args[1:])
	case "gate-maintained-presets":
		return runGateMaintainedPresets(args[1:])
	case "gate-degree1024-maintained-presets":
		return runGateDegree1024MaintainedPresets(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runBenchmarkIntGenISISE2E(args []string) error {
	cfg, err := parseBenchmarkIntGenISISE2EConfig(args)
	if err != nil {
		return err
	}
	_, err = benchmarkIntGenISISE2E(cfg)
	return err
}

func parseBenchmarkIntGenISISE2EConfig(args []string) (benchmarkIntGenISISE2EConfig, error) {
	fs := flag.NewFlagSet("benchmark-intgenisis-e2e", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactDir := fs.String("artifact-dir", "", "artifact directory; defaults to a temporary directory")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	presetName := fs.String("preset", "", "named IntGenISIS preset: n512-compact96, n1024-compact96, or n1024-compact125")
	force := fs.Bool("force", false, "overwrite existing artifacts")
	roQueryCaps := fs.String("ro-query-caps", "", "SmallWood random-oracle query caps Q0,Q1,Q2,Q3,Q4")
	acceptedIssuance := fs.Int("accepted-issuance", 1, "accepted issuance proof count for full-game soundness")
	acceptedShowing := fs.Int("accepted-showing", 1, "accepted showing proof count for full-game soundness")
	decsCollisionBits := fs.Int("decs-collision-bits", PIOP.ResolveDECSCollisionBits(0), "DECS collision hash/tape bits: "+PIOP.DECSCollisionBitsUsage())
	decsCollisionBytes := fs.Int("decs-collision-bytes", 0, "DECS collision hash/tape bytes: 16,17,18,20,24,28,32")
	if err := fs.Parse(args); err != nil {
		return benchmarkIntGenISISE2EConfig{}, err
	}
	var queryCaps [5]int
	queryCapsSet := false
	if strings.TrimSpace(*roQueryCaps) != "" {
		var err error
		queryCaps, err = PIOP.ParseROQueryCaps(*roQueryCaps)
		if err != nil {
			return benchmarkIntGenISISE2EConfig{}, err
		}
		queryCapsSet = true
	}
	if *acceptedIssuance < 0 || *acceptedShowing < 0 {
		return benchmarkIntGenISISE2EConfig{}, fmt.Errorf("accepted proof counts must be nonnegative")
	}
	collisionBits := *decsCollisionBits
	if *decsCollisionBytes > 0 {
		if err := PIOP.ValidateDECSCollisionBytes(*decsCollisionBytes); err != nil {
			return benchmarkIntGenISISE2EConfig{}, fmt.Errorf("-decs-collision-bytes: %w", err)
		}
		collisionBits = 8 * *decsCollisionBytes
	}
	if err := PIOP.ValidateDECSCollisionBits(collisionBits); err != nil {
		return benchmarkIntGenISISE2EConfig{}, fmt.Errorf("-decs-collision-bits: %w", err)
	}
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, false)
	if err != nil {
		return benchmarkIntGenISISE2EConfig{}, err
	}
	if selectedPresetName == "" {
		return benchmarkIntGenISISE2EConfig{}, fmt.Errorf("missing -preset (supported: %s)", strings.Join(credential.IntGenISISPresetNames(), ", "))
	}
	preset, err := credential.MustLookupIntGenISISPreset(selectedPresetName)
	if err != nil {
		return benchmarkIntGenISISE2EConfig{}, err
	}
	return benchmarkIntGenISISE2EConfig{
		ArtifactDir:       *artifactDir,
		Profile:           preset.Profile,
		PRFParamsPath:     defaultPRFParamsPath,
		JSONOut:           *jsonOut,
		Force:             *force,
		Seed:              11,
		Issuance:          intGenISISTuningFromPresetSpec(preset.Issuance),
		Showing:           intGenISISTuningFromPresetSpec(preset.Showing),
		KeygenTrials:      10000,
		KeygenAttempts:    defaultNTRUKeygenAttempts,
		NTRUBeta:          preset.NTRUBeta,
		MaxTrials:         2048,
		MaxNLeaves:        preset.MaxNLeaves,
		ROQueryCaps:       queryCaps,
		ROQueryCapsSet:    queryCapsSet,
		DECSCollisionBits: collisionBits,
		AcceptedIssuance:  *acceptedIssuance,
		AcceptedShowing:   *acceptedShowing,
	}, nil
}

func runSetupIntGenISISPublic(args []string) error {
	fs := flag.NewFlagSet("setup-intgenisis-public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", "", "output path for generated IntGenISIS credential public params")
	force := fs.Bool("force", false, "overwrite an existing output path")
	presetName := fs.String("preset", "", "named IntGenISIS preset: n512-compact96, n1024-compact96, or n1024-compact125")
	if err := fs.Parse(args); err != nil {
		return err
	}
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, false)
	if err != nil {
		return err
	}
	if selectedPresetName == "" {
		return fmt.Errorf("missing -preset (supported: %s)", strings.Join(credential.IntGenISISPresetNames(), ", "))
	}
	preset, err := credential.MustLookupIntGenISISPreset(selectedPresetName)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*outPath) == "" {
		*outPath = filepath.Join("internal", "source_data", fmt.Sprintf("credential_public.%s.json", preset.Profile))
	}
	return setupIntGenISISPublic(*outPath, *force, preset.Profile, "")
}

func runSetupNTRUKeys(args []string) error {
	fs := flag.NewFlagSet("setup-ntru-keys", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	presetName := fs.String("preset", "", "named IntGenISIS preset: n512-compact96, n1024-compact96, or n1024-compact125")
	paramsOut := fs.String("params-out", "", "output path for generated NTRU params")
	publicOut := fs.String("public-out", "", "output path for generated NTRU public key")
	privateOut := fs.String("private-out", "", "output path for generated NTRU private key")
	force := fs.Bool("force", false, "overwrite existing output paths")
	if err := fs.Parse(args); err != nil {
		return err
	}
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, false)
	if err != nil {
		return err
	}
	if selectedPresetName == "" {
		return fmt.Errorf("missing -preset (supported: %s)", strings.Join(credential.IntGenISISPresetNames(), ", "))
	}
	preset, err := credential.MustLookupIntGenISISPreset(selectedPresetName)
	if err != nil {
		return err
	}
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", preset.Profile)
	}
	return setupNTRUKeys(profile.N, *paramsOut, *publicOut, *privateOut, *force, 10000, defaultNTRUKeygenAttempts, preset.NTRUBeta)
}

func runHolderCommit(args []string) error {
	fs := flag.NewFlagSet("holder-commit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	publicPath := fs.String("public-params", credentialPublicPathDefault(), "credential public params path")
	prfPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	holderSecretPath := fs.String("holder-secret", defaultHolderSecretPath, "holder secret artifact path")
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset: n512-compact96, n1024-compact96, or n1024-compact125")
	if err := fs.Parse(args); err != nil {
		return err
	}
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, false)
	if err != nil {
		return err
	}
	if selectedPresetName == "" {
		return fmt.Errorf("missing -preset (supported: %s)", strings.Join(credential.IntGenISISPresetNames(), ", "))
	}
	preset, err := credential.MustLookupIntGenISISPreset(selectedPresetName)
	if err != nil {
		return err
	}
	if *publicPath == credentialPublicPathDefault() && preset.Profile != credential.ProfileIntGenISISB {
		*publicPath = filepath.Join("internal", "source_data", fmt.Sprintf("credential_public.%s.json", preset.Profile))
	}
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", preset.Profile)
	}
	tuning := intGenISISTuningFromPresetSpec(preset.Issuance)
	return holderCommit(*publicPath, *prfPath, *holderSecretPath, *commitRequestPath, "", 0, intGenISISTuningToIssuanceOverrides(tuning, profile.N))
}

func runHolderProve(args []string) error {
	fs := flag.NewFlagSet("holder-prove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	holderSecretPath := fs.String("holder-secret", defaultHolderSecretPath, "holder secret artifact path")
	submissionPath := fs.String("presign-submission", defaultPreSignSubmissionPath, "pre-sign submission artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return holderProve(*holderSecretPath, "", *submissionPath)
}

func runIssuerVerifySign(args []string) error {
	fs := flag.NewFlagSet("issuer-verify-sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
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
	return issuerVerifySign(*commitRequestPath, "", *submissionPath, *responsePath, *maxTrials, ntruSigningPaths(*ntruParamsPath, *ntruPublicPath, *ntruPrivatePath, *ntruSignaturePath), *verifierKeyOut)
}

func runHolderFinalize(args []string) error {
	fs := flag.NewFlagSet("holder-finalize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	holderSecretPath := fs.String("holder-secret", defaultHolderSecretPath, "holder secret artifact path")
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
	responsePath := fs.String("issue-response", defaultIssueResponsePath, "issuer response artifact path")
	statePath := fs.String("state-out", defaultCredentialStatePath, "final credential state path")
	signaturePath := fs.String("signature-out", defaultCredentialSignaturePath, "final signature artifact path")
	ntruParamsPath := fs.String("ntru-params", defaultNTRUParamsPath, "NTRU params path used when verifying seeded signature bundles")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return holderFinalize(*holderSecretPath, *commitRequestPath, "", *responsePath, *statePath, *signaturePath, *ntruParamsPath)
}
