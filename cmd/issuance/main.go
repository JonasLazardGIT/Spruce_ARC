package main

import (
	"flag"
	"fmt"
	"log"
	"os"

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
	fmt.Println(`usage: issuance <setup-intgenisis-public|setup-demo-public|setup-ntru-keys|holder-commit|issuer-challenge|holder-prove|issuer-verify-sign|holder-finalize|demo-local|benchmark-x0|benchmark-intgenisis> [options]

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
  benchmark-intgenisis Report IntGenISIS MLWE row inventories and benchmark labels`)
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
	seed := fs.Int64("seed", 0, "optional deterministic sampling seed")
	ncols := fs.Int("ncols", 0, "optional witness packing width override for issuance research")
	lvcsNCols := fs.Int("lvcs-ncols", 0, "optional LVCS width override for issuance research")
	nLeaves := fs.Int("nleaves", 0, "optional explicit-domain size override for issuance research")
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree override for issuance (supported: 1024 or 512; 0 follows public params)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return holderCommit(*publicPath, *prfPath, *holderSecretPath, *commitRequestPath, *expertInputPath, *seed, issuanceRuntimeOverrides{
		NCols:      *ncols,
		LVCSNCols:  *lvcsNCols,
		NLeaves:    *nLeaves,
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	return issuerVerifySign(*commitRequestPath, *challengePath, *submissionPath, *responsePath, *maxTrials, ntruSigningPaths(*ntruParamsPath, *ntruPublicPath, *ntruPrivatePath, *ntruSignaturePath))
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
	seed := fs.Int64("seed", 0, "optional deterministic sampling seed")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	ncols := fs.Int("ncols", 0, "optional witness packing width override for issuance research")
	lvcsNCols := fs.Int("lvcs-ncols", 0, "optional LVCS width override for issuance research")
	nLeaves := fs.Int("nleaves", 0, "optional explicit-domain size override for issuance research")
	researchRingDegree := fs.Int("research-ring-degree", 0, "opt-in research ring degree override for issuance (supported: 1024 or 512; 0 follows public params)")
	ntruParamsPath := fs.String("ntru-params", defaultNTRUParamsPath, "NTRU params path used for signature beta bound")
	ntruPublicPath := fs.String("ntru-public-key", defaultNTRUPublicKeyPath, "NTRU public key path")
	ntruPrivatePath := fs.String("ntru-private-key", defaultNTRUPrivateKeyPath, "NTRU private key path")
	ntruSignaturePath := fs.String("ntru-signature-out", "", "optional issuer-side NTRU signature artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return demoLocal(*publicPath, *prfPath, *artifactDir, *statePath, *signaturePath, *seed, *maxTrials, issuanceRuntimeOverrides{
		NCols:      *ncols,
		LVCSNCols:  *lvcsNCols,
		NLeaves:    *nLeaves,
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
