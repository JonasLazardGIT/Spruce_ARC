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
	defaultNTRUParamsPath          = "Parameters/Parameters.json"
	defaultNTRUPublicKeyPath       = "ntru_keys/public.json"
	defaultNTRUPrivateKeyPath      = "ntru_keys/private.json"
)

func usage() {
	fmt.Println(`usage: issuance <setup-intgenisis-public|setup-ntru-keys|holder-commit|holder-prove|issuer-verify-sign|holder-finalize|demo-local|benchmark-intgenisis-e2e|gate-degree1024-maintained-presets> [options]

Subcommands:
  setup-intgenisis-public Generate IntGenISIS MLWE-hiding credential public parameters
  setup-ntru-keys    Generate separate NTRU params and key material
  holder-commit      Sample holder witness rows and write holder_secret/commit_request artifacts
  holder-prove       Build the IntGenISIS pre-sign proof from holder secret
  issuer-verify-sign Verify the pre-sign proof and sign the public target T
  holder-finalize    Verify and persist the final credential state
  demo-local         Run the full role-separated issuance flow in one process
  benchmark-intgenisis-e2e Run IntGenISIS issuance + showing and print paper transcript sizes
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
	case "demo-local":
		return runDemoLocal(args[1:])
	case "benchmark-intgenisis-e2e":
		return runBenchmarkIntGenISISE2E(args[1:])
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
	fs := flag.NewFlagSet("benchmark-intgenisis-e2e", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactDir := fs.String("artifact-dir", "", "artifact directory; defaults to a temporary directory")
	profile := fs.String("profile", credential.ProfileIntGenISISB, "IntGenISIS profile name")
	profileBound := fs.Int64("profile-bound", 0, "override IntGenISIS public BoundB/CommitmentBound for bounded-range experiments; 0 uses the profile default")
	prfParamsPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	jsonOut := fs.String("json-out", "", "optional JSON output path")
	presetName := fs.String("preset", "", "named IntGenISIS preset: n512-compact96, n1024-compact96, or n1024-compact125")
	force := fs.Bool("force", false, "overwrite existing artifacts")
	seed := fs.Int64("seed", 11, "holder commitment sampling seed")
	ncols := fs.Int("ncols", 16, "SmallWood packing width")
	lvcsNCols := fs.Int("lvcs-ncols", 32, "LVCS width")
	nLeaves := fs.Int("nleaves", 4096, "explicit-domain leaf count")
	maxNLeaves := fs.Int("max-nleaves", intGenISISDefaultMaxNLeaves, "maximum explicit-domain leaves for issuance and showing; 0 disables the cap for uncapped local runs")
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
	ntruBeta := fs.Uint64("ntru-beta", 0, "optional NTRU signature beta override; 0 keeps profile default")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, false)
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
		if preset.NTRUBeta > 0 && !setFlags["ntru-beta"] {
			*ntruBeta = preset.NTRUBeta
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
	_, err = benchmarkIntGenISISE2E(cfg)
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
	ringDegree := fs.Int("ring-degree", 0, "ring degree for generated NTRU params/keys (supported: 1024 or 512; 0 keeps default)")
	paramsOut := fs.String("params-out", "", "output path for generated NTRU params")
	publicOut := fs.String("public-out", "", "output path for generated NTRU public key")
	privateOut := fs.String("private-out", "", "output path for generated NTRU private key")
	force := fs.Bool("force", false, "overwrite existing output paths")
	keygenTrials := fs.Int("keygen-trials", 10000, "maximum trials for each annulus keygen attempt")
	attempts := fs.Int("attempts", 4, "number of annulus keygen attempts before failing")
	ntruBeta := fs.Uint64("ntru-beta", 0, "optional NTRU signature beta override; 0 keeps profile default")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return setupNTRUKeys(*ringDegree, *paramsOut, *publicOut, *privateOut, *force, *keygenTrials, *attempts, *ntruBeta)
}

func runHolderCommit(args []string) error {
	fs := flag.NewFlagSet("holder-commit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	publicPath := fs.String("public-params", credentialPublicPathDefault(), "credential public params path")
	prfPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	holderSecretPath := fs.String("holder-secret", defaultHolderSecretPath, "holder secret artifact path")
	commitRequestPath := fs.String("commit-request", defaultCommitRequestPath, "commit request artifact path")
	expertInputPath := fs.String("expert-input", "", "optional expert witness JSON path")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset: n512-compact96, n1024-compact96, or n1024-compact125")
	seed := fs.Int64("seed", 0, "optional deterministic sampling seed")
	ncols := fs.Int("ncols", 0, "optional witness packing width override")
	lvcsNCols := fs.Int("lvcs-ncols", 0, "optional LVCS width override")
	nLeaves := fs.Int("nleaves", 0, "optional explicit-domain size override")
	eta := fs.Int("eta", 0, "optional eta override")
	theta := fs.Int("theta", 0, "optional theta override")
	rho := fs.Int("rho", 0, "optional rho override")
	ell := fs.Int("ell", 0, "optional ell override")
	ellPrime := fs.Int("ell-prime", 0, "optional ell-prime override")
	kappa1 := fs.Int("kappa1", 0, "optional theorem aggregation kappa round 1")
	kappa2 := fs.Int("kappa2", 0, "optional theorem aggregation kappa round 2")
	kappa3 := fs.Int("kappa3", 0, "optional theorem aggregation kappa round 3")
	kappa4 := fs.Int("kappa4", 0, "optional theorem aggregation kappa round 4")
	ringDegree := fs.Int("ring-degree", 0, "ring degree override for issuance (supported: 1024 or 512; 0 follows public params)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, false)
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
		RingDegree: *ringDegree,
	})
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

func runDemoLocal(args []string) error {
	fs := flag.NewFlagSet("demo-local", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	publicPath := fs.String("public-params", credentialPublicPathDefault(), "credential public params path")
	prfPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	artifactDir := fs.String("artifact-dir", defaultArtifactDir, "directory for intermediate issuance artifacts")
	statePath := fs.String("state-out", defaultCredentialStatePath, "final credential state path")
	signaturePath := fs.String("signature-out", defaultCredentialSignaturePath, "final signature artifact path")
	presetName := fs.String("preset", "", "named IntGenISIS issuance preset: n512-compact96, n1024-compact96, or n1024-compact125")
	seed := fs.Int64("seed", 0, "optional deterministic sampling seed")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	ncols := fs.Int("ncols", 0, "optional witness packing width override")
	lvcsNCols := fs.Int("lvcs-ncols", 0, "optional LVCS width override")
	nLeaves := fs.Int("nleaves", 0, "optional explicit-domain size override")
	eta := fs.Int("eta", 0, "optional eta override")
	theta := fs.Int("theta", 0, "optional theta override")
	rho := fs.Int("rho", 0, "optional rho override")
	ell := fs.Int("ell", 0, "optional ell override")
	ellPrime := fs.Int("ell-prime", 0, "optional ell-prime override")
	kappa1 := fs.Int("kappa1", 0, "optional theorem aggregation kappa round 1")
	kappa2 := fs.Int("kappa2", 0, "optional theorem aggregation kappa round 2")
	kappa3 := fs.Int("kappa3", 0, "optional theorem aggregation kappa round 3")
	kappa4 := fs.Int("kappa4", 0, "optional theorem aggregation kappa round 4")
	ringDegree := fs.Int("ring-degree", 0, "ring degree override for issuance (supported: 1024 or 512; 0 follows public params)")
	ntruParamsPath := fs.String("ntru-params", defaultNTRUParamsPath, "NTRU params path used for signature beta bound")
	ntruPublicPath := fs.String("ntru-public-key", defaultNTRUPublicKeyPath, "NTRU public key path")
	ntruPrivatePath := fs.String("ntru-private-key", defaultNTRUPrivateKeyPath, "NTRU private key path")
	ntruSignaturePath := fs.String("ntru-signature-out", "", "optional issuer-side NTRU signature artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	setFlags := visitedFlagNames(fs)
	selectedPresetName, err := credential.ResolveIntGenISISPresetSelector(*presetName, false)
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
		RingDegree: *ringDegree,
	}, ntruSigningPaths(*ntruParamsPath, *ntruPublicPath, *ntruPrivatePath, *ntruSignaturePath))
}
