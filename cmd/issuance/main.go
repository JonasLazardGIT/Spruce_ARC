package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

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
	defaultPRFParamsPath           = credential.IntGenISISPRFParamsDefault
	defaultNTRUParamsPath          = "internal/source_data/Parameters.json"
	defaultNTRUPublicKeyPath       = "ntru_keys/public.json"
	defaultNTRUPrivateKeyPath      = "ntru_keys/private.json"
)

func intGenISISPresetHelp() string {
	return strings.Join(credential.IntGenISISDefaultPresetNames(), ", ")
}

func intGenISISV2ArtifactDir(preset credential.IntGenISISPreset) string {
	return filepath.Join("artifacts", "smallwood-salted-v2", preset.CanonicalID)
}

func requiredIntGenISISCLIPreset(selector string) (credential.IntGenISISPreset, error) {
	selected, err := credential.ResolveIntGenISISPresetSelector(selector, false)
	if err != nil {
		return credential.IntGenISISPreset{}, err
	}
	if selected == "" {
		return credential.IntGenISISPreset{}, fmt.Errorf("missing -preset (available: %s)", intGenISISPresetHelp())
	}
	return credential.MustLookupIntGenISISPreset(selected)
}

func usage() {
	fmt.Println(`usage: issuance <command> [options]

Primary commands:
  list-presets                  List every executable PoC preset
  benchmark-intgenisis-e2e      Run issuance and showing for one preset
  gate-functional-presets       Functionally validate every executable preset

Manual protocol stages:
  setup-intgenisis-public       Generate IntGenISIS credential public parameters
  setup-ntru-keys               Generate separate NTRU params and key material
  holder-commit                 Write holder secret and commitment artifacts
  holder-prove                  Build the IntGenISIS pre-sign proof
  issuer-verify-sign            Verify the pre-sign proof and sign its target
  holder-finalize               Verify and persist the credential state

Reproduction command:
  gate-artifact-presets         Reproduce executable-preset exact-byte results

All configurations are experimental PoC presets. Security metadata is
informational and does not constitute a deployment claim.`)
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
	case "list-presets":
		return runListIntGenISISPresets(args[1:])
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
	case "gate-functional-presets":
		return runGateFunctionalPresets(args[1:])
	case "gate-artifact-presets":
		return runGateArtifactPresets(args[1:])
	case "gate-complete-system-presets":
		return runGateCompleteSystemPresets(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runListIntGenISISPresets(args []string) error {
	fs := flag.NewFlagSet("list-presets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PRESET\tPROFILE\tDESCRIPTION")
	for _, name := range credential.IntGenISISDefaultPresetNames() {
		preset, err := credential.MustLookupIntGenISISPreset(name)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", preset.CanonicalID, preset.SecurityProfile, preset.Description)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "All configurations are experimental PoC presets. Security metadata is informational and does not constitute a deployment claim.")
	return nil
}

func warnIntGenISISPreset(preset credential.IntGenISISPreset) {
	if preset.Lifecycle == credential.PresetComplete && preset.ClaimScope == credential.ClaimCompleteSystem && preset.CompleteSystemClaim {
		return
	}
	log.Printf("[issuance-cli] warning: preset %s is %s/%s (%s), not a complete-system deployment preset", preset.CanonicalID, preset.Lifecycle, preset.ClaimScope, preset.SecurityProfile)
}

func runBenchmarkIntGenISISE2E(args []string) error {
	cfg, err := parseBenchmarkIntGenISISE2EConfig(args)
	if err != nil {
		return err
	}
	if preset, ok := credential.LookupIntGenISISPreset(cfg.PresetName); ok {
		warnIntGenISISPreset(preset)
	}
	if cfg.Verbose {
		report, err := benchmarkIntGenISISE2E(cfg)
		if err != nil {
			return err
		}
		benchmarkIntGenISISE2EPrintReport(report, true)
		return nil
	}
	oldLog := log.Writer()
	log.SetOutput(io.Discard)
	report, err := benchmarkIntGenISISE2E(cfg)
	log.SetOutput(oldLog)
	if err != nil {
		return err
	}
	benchmarkIntGenISISE2EPrintReport(report, false)
	return nil
}

func parseBenchmarkIntGenISISE2EConfig(args []string) (benchmarkIntGenISISE2EConfig, error) {
	fs := flag.NewFlagSet("benchmark-intgenisis-e2e", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactDir := fs.String("artifact-dir", "", "artifact directory; defaults to a temporary directory")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	presetName := fs.String("preset", "", "named IntGenISIS preset: "+intGenISISPresetHelp())
	force := fs.Bool("force", false, "overwrite existing artifacts")
	verbose := fs.Bool("verbose", false, "print detailed benchmark diagnostics")
	if err := fs.Parse(args); err != nil {
		return benchmarkIntGenISISE2EConfig{}, err
	}
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, false)
	if err != nil {
		return benchmarkIntGenISISE2EConfig{}, err
	}
	if selectedPresetName == "" {
		return benchmarkIntGenISISE2EConfig{}, fmt.Errorf("missing -preset (available: %s; run list-presets for descriptions)", intGenISISPresetHelp())
	}
	preset, err := credential.MustLookupIntGenISISPreset(selectedPresetName)
	if err != nil {
		return benchmarkIntGenISISE2EConfig{}, err
	}
	return benchmarkIntGenISISE2EConfig{
		ArtifactDir:          *artifactDir,
		PresetName:           selectedPresetName,
		CanonicalPresetID:    preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PresetLifecycle:      preset.Lifecycle,
		ClaimScope:           preset.ClaimScope,
		PrimitiveProfileID:   preset.PrimitiveProfileID,
		PresetManifestDigest: credential.IntGenISISPresetManifestDigest(preset),
		ThreatModel:          preset.ThreatModel,
		Profile:              preset.Profile,
		SecurityProfile:      preset.SecurityProfile,
		SecurityMode:         string(preset.SecurityMode),
		CoreBitsRequired:     preset.CoreBitsRequired,
		CompleteSystemClaim:  preset.CompleteSystemClaim,
		PRFProfile:           preset.PRFProfile,
		PRFParamsPath:        preset.PRFParamsPath,
		PRFParamsDigest:      preset.PRFParamsDigest,
		JSONOut:              *jsonOut,
		Force:                *force,
		Verbose:              *verbose,
		Issuance:             intGenISISTuningFromPresetSpec(preset.Issuance),
		Showing:              intGenISISTuningFromPresetSpec(preset.Showing),
		KeygenTrials:         10000,
		KeygenAttempts:       defaultNTRUKeygenAttempts,
		NTRUBeta:             preset.NTRUBeta,
		MaxTrials:            2048,
		MaxNLeaves:           preset.MaxNLeaves,
	}, nil
}

func runSetupIntGenISISPublic(args []string) error {
	fs := flag.NewFlagSet("setup-intgenisis-public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", "", "output path for generated IntGenISIS credential public params")
	force := fs.Bool("force", false, "overwrite an existing output path")
	presetName := fs.String("preset", "", "named IntGenISIS preset: "+intGenISISPresetHelp())
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
	warnIntGenISISPreset(preset)
	if strings.TrimSpace(*outPath) == "" {
		*outPath = filepath.Join(intGenISISV2ArtifactDir(preset), fmt.Sprintf("credential_public.%s.json", preset.Profile))
	}
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", preset.Profile)
	}
	return setupIntGenISISPublicForPreset(*outPath, *force, profile, "", &preset)
}

func runSetupNTRUKeys(args []string) error {
	fs := flag.NewFlagSet("setup-ntru-keys", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	presetName := fs.String("preset", "", "named IntGenISIS preset: "+intGenISISPresetHelp())
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
	warnIntGenISISPreset(preset)
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", preset.Profile)
	}
	artifactDir := intGenISISV2ArtifactDir(preset)
	if *paramsOut == "" {
		*paramsOut = filepath.Join(artifactDir, "ntru_params.json")
	}
	if *publicOut == "" {
		*publicOut = filepath.Join(artifactDir, "ntru_public.json")
	}
	if *privateOut == "" {
		*privateOut = filepath.Join(artifactDir, "ntru_private.json")
	}
	return setupNTRUKeys(profile.N, *paramsOut, *publicOut, *privateOut, *force, 10000, defaultNTRUKeygenAttempts, preset.NTRUBeta)
}

func runHolderCommit(args []string) error {
	fs := flag.NewFlagSet("holder-commit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	publicPath := fs.String("public-params", "", "credential public params path; defaults beneath the selected v2 artifact directory")
	prfPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	holderSecretPath := fs.String("holder-secret", "", "holder secret artifact path")
	commitRequestPath := fs.String("commit-request", "", "commit request artifact path")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset: "+intGenISISPresetHelp())
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
	warnIntGenISISPreset(preset)
	artifactDir := intGenISISV2ArtifactDir(preset)
	if *publicPath == "" {
		*publicPath = filepath.Join(artifactDir, fmt.Sprintf("credential_public.%s.json", preset.Profile))
	}
	if *holderSecretPath == "" {
		*holderSecretPath = filepath.Join(artifactDir, "holder_secret.json")
	}
	if *commitRequestPath == "" {
		*commitRequestPath = filepath.Join(artifactDir, "commit_request.json")
	}
	publicParams, err := credential.LoadPublicParams(*publicPath)
	if err != nil {
		return fmt.Errorf("load IntGenISIS public params: %w", err)
	}
	if err := publicParams.ValidateIntGenISISPreset(preset); err != nil {
		return err
	}
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", preset.Profile)
	}
	tuning := intGenISISTuningFromPresetSpec(preset.Issuance)
	if *prfPath == defaultPRFParamsPath && preset.PRFParamsPath != "" {
		*prfPath = preset.PRFParamsPath
	}
	return holderCommit(*publicPath, *prfPath, *holderSecretPath, *commitRequestPath, "", intGenISISTuningToIssuanceOverrides(tuning, profile.N))
}

func runHolderProve(args []string) error {
	fs := flag.NewFlagSet("holder-prove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	holderSecretPath := fs.String("holder-secret", "", "holder secret artifact path")
	submissionPath := fs.String("presign-submission", "", "pre-sign submission artifact path")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset: "+intGenISISPresetHelp())
	if err := fs.Parse(args); err != nil {
		return err
	}
	preset, err := requiredIntGenISISCLIPreset(*presetName)
	if err != nil {
		return err
	}
	artifactDir := intGenISISV2ArtifactDir(preset)
	if *holderSecretPath == "" {
		*holderSecretPath = filepath.Join(artifactDir, "holder_secret.json")
	}
	if *submissionPath == "" {
		*submissionPath = filepath.Join(artifactDir, "presign_submission.json")
	}
	return holderProve(*holderSecretPath, "", *submissionPath)
}

func runIssuerVerifySign(args []string) error {
	fs := flag.NewFlagSet("issuer-verify-sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	commitRequestPath := fs.String("commit-request", "", "commit request artifact path")
	submissionPath := fs.String("presign-submission", "", "pre-sign submission artifact path")
	responsePath := fs.String("issue-response", "", "issuer response artifact path")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	ntruParamsPath := fs.String("ntru-params", "", "NTRU params path used for signature beta bound")
	ntruPublicPath := fs.String("ntru-public-key", "", "NTRU public key path")
	ntruPrivatePath := fs.String("ntru-private-key", "", "NTRU private key path")
	ntruSignaturePath := fs.String("ntru-signature-out", "", "optional issuer-side NTRU signature artifact path")
	verifierKeyOut := fs.String("verifier-key-out", "", "IntGenISIS public verifier key artifact path")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset: "+intGenISISPresetHelp())
	if err := fs.Parse(args); err != nil {
		return err
	}
	preset, err := requiredIntGenISISCLIPreset(*presetName)
	if err != nil {
		return err
	}
	artifactDir := intGenISISV2ArtifactDir(preset)
	if *commitRequestPath == "" {
		*commitRequestPath = filepath.Join(artifactDir, "commit_request.json")
	}
	if *submissionPath == "" {
		*submissionPath = filepath.Join(artifactDir, "presign_submission.json")
	}
	if *responsePath == "" {
		*responsePath = filepath.Join(artifactDir, "issue_response.json")
	}
	if *ntruParamsPath == "" {
		*ntruParamsPath = filepath.Join(artifactDir, "ntru_params.json")
	}
	if *ntruPublicPath == "" {
		*ntruPublicPath = filepath.Join(artifactDir, "ntru_public.json")
	}
	if *ntruPrivatePath == "" {
		*ntruPrivatePath = filepath.Join(artifactDir, "ntru_private.json")
	}
	if *ntruSignaturePath == "" {
		*ntruSignaturePath = filepath.Join(artifactDir, "ntru_signature.json")
	}
	if *verifierKeyOut == "" {
		*verifierKeyOut = filepath.Join(artifactDir, "intgenisis_verifier_key.json")
	}
	return issuerVerifySign(*commitRequestPath, "", *submissionPath, *responsePath, *maxTrials, ntruSigningPaths(*ntruParamsPath, *ntruPublicPath, *ntruPrivatePath, *ntruSignaturePath), *verifierKeyOut)
}

func runHolderFinalize(args []string) error {
	fs := flag.NewFlagSet("holder-finalize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	holderSecretPath := fs.String("holder-secret", "", "holder secret artifact path")
	commitRequestPath := fs.String("commit-request", "", "commit request artifact path")
	responsePath := fs.String("issue-response", "", "issuer response artifact path")
	statePath := fs.String("state-out", "", "final credential state path")
	signaturePath := fs.String("signature-out", "", "final signature artifact path")
	ntruParamsPath := fs.String("ntru-params", "", "NTRU params path used when verifying signature bundles")
	verifierKeyPath := fs.String("verifier-key", "", "trusted IntGenISIS v2 verifier key used to bind the issuer NTRU row")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset: "+intGenISISPresetHelp())
	if err := fs.Parse(args); err != nil {
		return err
	}
	preset, err := requiredIntGenISISCLIPreset(*presetName)
	if err != nil {
		return err
	}
	artifactDir := intGenISISV2ArtifactDir(preset)
	if *holderSecretPath == "" {
		*holderSecretPath = filepath.Join(artifactDir, "holder_secret.json")
	}
	if *commitRequestPath == "" {
		*commitRequestPath = filepath.Join(artifactDir, "commit_request.json")
	}
	if *responsePath == "" {
		*responsePath = filepath.Join(artifactDir, "issue_response.json")
	}
	if *statePath == "" {
		*statePath = filepath.Join(artifactDir, "credential_state.intgenisis.json")
	}
	if *signaturePath == "" {
		*signaturePath = filepath.Join(artifactDir, "credential_signature.json")
	}
	if *ntruParamsPath == "" {
		*ntruParamsPath = filepath.Join(artifactDir, "ntru_params.json")
	}
	if *verifierKeyPath == "" {
		*verifierKeyPath = filepath.Join(artifactDir, "intgenisis_verifier_key.json")
	}
	return holderFinalize(*holderSecretPath, *commitRequestPath, "", *responsePath, *statePath, *signaturePath, *ntruParamsPath, *verifierKeyPath)
}
