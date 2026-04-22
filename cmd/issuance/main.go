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
)

func usage() {
	fmt.Println(`usage: issuance <setup-demo-public|holder-commit|issuer-challenge|holder-prove|issuer-verify-sign|holder-finalize|demo-local> [options]

Subcommands:
  setup-demo-public  Generate credential public parameters with a full random Ac matrix
  holder-commit      Sample holder witness rows and write holder_secret/commit_request artifacts
  issuer-challenge   Sample issuer challenge rows from a commit request
  holder-prove       Build the pre-sign proof from holder secret + issuer challenge
  issuer-verify-sign Verify the pre-sign proof and sign the public target T
  holder-finalize    Verify and persist the final credential state
  demo-local         Run the full role-separated issuance flow in one process`)
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
	case "setup-demo-public":
		return runSetupDemoPublic(args[1:])
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
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runSetupDemoPublic(args []string) error {
	fs := flag.NewFlagSet("setup-demo-public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", defaultDemoPublicParamsPath, "output path for generated credential public params")
	force := fs.Bool("force", false, "overwrite an existing output path")
	bPath := fs.String("b-path", "", "B-matrix path recorded in the public params (defaults from -hash-relation)")
	hashRelation := fs.String("hash-relation", credential.HashRelationBBTran, "hash relation recorded in the public params (bbs or bb_tran)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return setupDemoPublic(*outPath, *force, *bPath, *hashRelation)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	return holderCommit(*publicPath, *prfPath, *holderSecretPath, *commitRequestPath, *expertInputPath, *seed, issuanceRuntimeOverrides{
		NCols:    *ncols,
		LVCSNCols: *lvcsNCols,
		NLeaves:  *nLeaves,
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	return issuerVerifySign(*commitRequestPath, *challengePath, *submissionPath, *responsePath, *maxTrials)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	return holderFinalize(*holderSecretPath, *commitRequestPath, *challengePath, *responsePath, *statePath, *signaturePath)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	return demoLocal(*publicPath, *prfPath, *artifactDir, *statePath, *signaturePath, *seed, *maxTrials, issuanceRuntimeOverrides{
		NCols:    *ncols,
		LVCSNCols: *lvcsNCols,
		NLeaves:  *nLeaves,
	})
}
