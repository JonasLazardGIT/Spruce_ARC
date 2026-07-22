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
	entries := credential.IntGenISISPresetPortfolio(false, false)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Available {
			names = append(names, entry.CanonicalID)
		}
	}
	return strings.Join(names, ", ")
}

func usage() {
	fmt.Println(`usage: issuance <list-presets|setup-intgenisis-public|setup-ntru-keys|holder-commit|holder-prove|issuer-verify-sign|holder-finalize|benchmark-intgenisis-e2e|gate-functional-presets|gate-artifact-presets|gate-proof-profiles|gate-candidate-presets|gate-complete-system-presets> [options]

Subcommands:
	  list-presets       List purpose-oriented public presets and their claim status
  setup-intgenisis-public Generate IntGenISIS MLWE-hiding credential public parameters
  setup-ntru-keys    Generate separate NTRU params and key material
  holder-commit      Sample holder witness rows and write holder_secret/commit_request artifacts
  holder-prove       Build the IntGenISIS pre-sign proof from holder secret
  issuer-verify-sign Verify the pre-sign proof and sign the public target T
  holder-finalize    Verify and persist the final credential state
  benchmark-intgenisis-e2e Run IntGenISIS issuance + showing and print paper transcript sizes
	  gate-functional-presets Prove, verify, serialize, and reject replay for public executable presets
	  gate-artifact-presets Reproduce historical exact-byte artifact results
	  gate-proof-profiles Check executable proof-layer profile claims
	  gate-candidate-presets Measure candidates and report their blockers
	  gate-complete-system-presets Require a completely passing deployment ledger
	  gate-maintained-presets Deprecated alias for gate-artifact-presets`)
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
	case "gate-proof-profiles":
		return runGateProofProfiles(args[1:])
	case "gate-candidate-presets":
		return runGateCandidatePresets(args[1:])
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
	includeResearch := fs.Bool("research", false, "include public research presets")
	includeAll := fs.Bool("all", false, "include internal, historical, and deprecated selectors")
	if err := fs.Parse(args); err != nil {
		return err
	}
	entries := credential.IntGenISISPresetPortfolio(*includeResearch || *includeAll, *includeAll)
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PRESET\tPURPOSE\tCLAIM\tSTATUS")
	for _, entry := range entries {
		claim := string(entry.ClaimScope)
		if entry.CanonicalID == credential.IntGenISISPresetPilotN1024BQ32R96V1 {
			claim = "complete*"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", entry.CanonicalID, entry.Purpose, claim, entry.Status)
		if *includeAll && entry.LegacySelector != "" {
			fmt.Fprintf(w, "  alias: %s\t\t\t\n", entry.LegacySelector)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "* Bounded CROM candidate: raw caps [2^32]^5 per proof-system phase ([2^33]^5 after one issuance plus one showing), at most 2^32 honest transcripts, and 2^32 tags per context.")
	fmt.Fprintln(os.Stdout, "No complete-system deployment preset is currently available.")
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
		return benchmarkIntGenISISE2EConfig{}, fmt.Errorf("missing -preset (public presets: %s; use list-presets -all for aliases)", intGenISISPresetHelp())
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
		*outPath = filepath.Join("internal", "source_data", fmt.Sprintf("credential_public.%s.json", preset.Profile))
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
	return setupNTRUKeys(profile.N, *paramsOut, *publicOut, *privateOut, *force, 10000, defaultNTRUKeygenAttempts, preset.NTRUBeta)
}

func runHolderCommit(args []string) error {
	fs := flag.NewFlagSet("holder-commit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	publicPath := fs.String("public-params", credentialPublicPathDefault(), "credential public params path")
	prfPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	holderSecretPath := fs.String("holder-secret", defaultHolderSecretPath, "holder secret artifact path")
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
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
	if *publicPath == credentialPublicPathDefault() && preset.Profile != credential.ProfileIntGenISISB {
		*publicPath = filepath.Join("internal", "source_data", fmt.Sprintf("credential_public.%s.json", preset.Profile))
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
