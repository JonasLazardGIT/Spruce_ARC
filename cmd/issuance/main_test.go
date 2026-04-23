package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func issuanceTestRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func chdirForIssuanceTest(t *testing.T, dir string) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

func maxAbsRows(rows [][]int64) int64 {
	var out int64
	for _, row := range rows {
		for _, v := range row {
			if v < 0 {
				v = -v
			}
			if v > out {
				out = v
			}
		}
	}
	return out
}

func TestRunWithoutSubcommandFails(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("run(nil) succeeded; want usage error")
	}
}

func TestDeriveOmegaForIssuanceOptsUsesRelationAwareWitnessOmega(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:          true,
		NCols:               16,
		LVCSNCols:           96,
		Ell:                 18,
		NLeaves:             4096,
		DomainMode:          PIOP.DomainModeExplicit,
		CoeffPacking:        true,
		CoeffNativeSigModel: PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
	})
	omega4096, err := deriveOmegaForIssuanceOpts(ringQ, credential.HashRelationBBTran, opts)
	if err != nil {
		t.Fatalf("deriveOmegaForIssuanceOpts(4096): %v", err)
	}
	opts.NLeaves = 8192
	omega8192, err := deriveOmegaForIssuanceOpts(ringQ, credential.HashRelationBBTran, opts)
	if err != nil {
		t.Fatalf("deriveOmegaForIssuanceOpts(8192): %v", err)
	}
	if len(omega4096) != len(omega8192) {
		t.Fatalf("omega length mismatch: 4096=%d 8192=%d", len(omega4096), len(omega8192))
	}
	for i := range omega4096 {
		if omega4096[i] != omega8192[i] {
			t.Fatalf("omega[%d] mismatch: 4096=%d 8192=%d", i, omega4096[i], omega8192[i])
		}
	}
}

func TestSetupDemoPublicRequiresForceToOverwrite(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	out := filepath.Join(t.TempDir(), "credential_public.json")
	if err := run([]string{"setup-demo-public", "-out", out, "-x0-profile", "legacy_scalar"}); err != nil {
		t.Fatalf("initial setup-demo-public: %v", err)
	}
	if err := run([]string{"setup-demo-public", "-out", out, "-x0-profile", "legacy_scalar"}); err == nil {
		t.Fatal("setup-demo-public overwrote existing file without -force")
	}
}

func TestSetupDemoPublicLHLProfileWritesParameterizedPublicParams(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	out := filepath.Join(t.TempDir(), "credential_public.json")
	if err := run([]string{"setup-demo-public", "-out", out, "-force", "-x0-profile", "lhl_alt"}); err != nil {
		t.Fatalf("setup-demo-public lhl_alt: %v", err)
	}
	public, err := credential.LoadPublicParams(out)
	if err != nil {
		t.Fatalf("load public params: %v", err)
	}
	if public.X0Len != 5 || public.X0CoeffBound != 8 {
		t.Fatalf("unexpected x0 params: len=%d bound=%d", public.X0Len, public.X0CoeffBound)
	}
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	params, err := public.ToIssuanceParams(ringQ)
	if err != nil {
		t.Fatalf("lift params: %v", err)
	}
	report, err := credential.BuildLHLReport(params)
	if err != nil {
		t.Fatalf("lhl report: %v", err)
	}
	if !report.SatisfiesLHL {
		t.Fatalf("lhl_alt should satisfy LHL: %+v", report)
	}
}

func TestRoleSeparatedIssuanceFlowPersistsTrapdoorFreeState(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	publicPath := filepath.Join(tmp, "credential_public.json")
	holderSecretPath := filepath.Join(tmp, "holder_secret.json")
	commitRequestPath := filepath.Join(tmp, "commit_request.json")
	challengePath := filepath.Join(tmp, "issue_challenge.json")
	submissionPath := filepath.Join(tmp, "presign_submission.json")
	responsePath := filepath.Join(tmp, "issue_response.json")
	statePath := filepath.Join(tmp, "credential_state.json")
	signaturePath := filepath.Join(tmp, "signature.json")

	if err := run([]string{"setup-demo-public", "-out", publicPath, "-force", "-x0-profile", "legacy_scalar"}); err != nil {
		t.Fatalf("setup-demo-public: %v", err)
	}
	if err := run([]string{"holder-commit", "-public-params", publicPath, "-holder-secret", holderSecretPath, "-commit-request", commitRequestPath, "-seed", "11"}); err != nil {
		t.Fatalf("holder-commit: %v", err)
	}
	if err := run([]string{"issuer-challenge", "-commit-request", commitRequestPath, "-issue-challenge", challengePath, "-seed", "12"}); err != nil {
		t.Fatalf("issuer-challenge: %v", err)
	}
	if err := run([]string{"holder-prove", "-holder-secret", holderSecretPath, "-issue-challenge", challengePath, "-presign-submission", submissionPath}); err != nil {
		t.Fatalf("holder-prove: %v", err)
	}
	if err := run([]string{"issuer-verify-sign", "-commit-request", commitRequestPath, "-issue-challenge", challengePath, "-presign-submission", submissionPath, "-issue-response", responsePath}); err != nil {
		t.Fatalf("issuer-verify-sign: %v", err)
	}
	if err := run([]string{"holder-finalize", "-holder-secret", holderSecretPath, "-commit-request", commitRequestPath, "-issue-challenge", challengePath, "-issue-response", responsePath, "-state-out", statePath, "-signature-out", signaturePath}); err != nil {
		t.Fatalf("holder-finalize: %v", err)
	}

	state, err := credential.LoadState(statePath)
	if err != nil {
		t.Fatalf("load credential state: %v", err)
	}
	if state.CredentialPublicPath != publicPath {
		t.Fatalf("credential_public_path=%q want %q", state.CredentialPublicPath, publicPath)
	}
	if maxAbsRows(state.K) <= 0 {
		t.Fatal("default issuance sampled zero K; want nonzero hidden key material")
	}
	if maxAbsRows(state.RI0) <= 0 && maxAbsRows(state.RI1) <= 0 {
		t.Fatal("default issuance sampled zero issuer challenge")
	}
	if len(state.NTRUPublic) == 0 {
		t.Fatal("credential state missing NTRU public key material")
	}
	rawState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state json: %v", err)
	}
	if strings.Contains(string(rawState), "ntru_private") || strings.Contains(string(rawState), "private.json") {
		t.Fatal("credential state leaked issuer trapdoor material")
	}
}

func TestDemoLocalDoesNotRewriteCanonicalPublicParams(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	before, err := os.ReadFile(credential.DefaultPublicParamsPath)
	if err != nil {
		t.Fatalf("read canonical public params before demo-local: %v", err)
	}
	tmp := t.TempDir()
	if err := run([]string{"demo-local", "-artifact-dir", filepath.Join(tmp, "artifacts"), "-state-out", filepath.Join(tmp, "credential_state.json"), "-signature-out", filepath.Join(tmp, "signature.json"), "-seed", "21"}); err != nil {
		t.Fatalf("demo-local: %v", err)
	}
	after, err := os.ReadFile(credential.DefaultPublicParamsPath)
	if err != nil {
		t.Fatalf("read canonical public params after demo-local: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("demo-local rewrote canonical credential public params")
	}
}

func TestDemoLocalWidthOverridesWriteTempStateWithoutTouchingCanonicalOutputs(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	readCanonical := func(path string) []byte {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read canonical file %s: %v", path, err)
		}
		return data
	}

	beforeState := readCanonical(defaultCredentialStatePath)
	beforeSig := readCanonical(defaultCredentialSignaturePath)

	tmp := t.TempDir()
	artifactDir := filepath.Join(tmp, "artifacts")
	statePath := filepath.Join(tmp, "credential_state.json")
	signaturePath := filepath.Join(tmp, "signature.json")
	if err := run([]string{
		"demo-local",
		"-artifact-dir", artifactDir,
		"-state-out", statePath,
		"-signature-out", signaturePath,
		"-seed", "21",
		"-ncols", "32",
		"-lvcs-ncols", "96",
		"-nleaves", "4096",
	}); err != nil {
		t.Fatalf("demo-local with width overrides: %v", err)
	}

	state, err := credential.LoadState(statePath)
	if err != nil {
		t.Fatalf("load overridden credential state: %v", err)
	}
	if state.PackedNCols != 32 {
		t.Fatalf("packed_ncols=%d want 32", state.PackedNCols)
	}
	for _, rel := range []string{
		"holder_secret.json",
		"commit_request.json",
		"issue_challenge.json",
		"presign_submission.json",
		"issue_response.json",
	} {
		if _, err := os.Stat(filepath.Join(artifactDir, rel)); err != nil {
			t.Fatalf("artifact %s missing: %v", rel, err)
		}
	}

	afterState := readCanonical(defaultCredentialStatePath)
	afterSig := readCanonical(defaultCredentialSignaturePath)
	if string(beforeState) != string(afterState) {
		t.Fatal("demo-local width override rewrote canonical credential state")
	}
	if string(beforeSig) != string(afterSig) {
		t.Fatal("demo-local width override rewrote canonical credential signature")
	}
}

func TestSampleHolderInputsRespectsX0ShapeAndBounds(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	public := credential.PublicParams{
		Version:            credential.PublicParamsVersion,
		HashRelation:       credential.HashRelationBBTran,
		BoundB:             1,
		X0Len:              6,
		X0CoeffBound:       5,
		TargetDim:          credential.DefaultTargetDim,
		TargetHidingLambda: credential.DefaultTargetHidingLambda,
		X0Distribution:     credential.X0DistributionUniformInterval,
		LenM:               1,
		LenK:               1,
		LenR0H:             6,
		LenR1H:             1,
		LenRBar:            1,
	}
	omega := make([]uint64, 16)
	for i := range omega {
		omega[i] = uint64(i + 1)
	}
	in, err := sampleHolderInputs(ringQ, public, omega, newLocalRNG(7))
	if err != nil {
		t.Fatalf("sample holder inputs: %v", err)
	}
	if len(in.R0H) != public.X0Len {
		t.Fatalf("r0h len=%d want %d", len(in.R0H), public.X0Len)
	}
	checkBound := func(p *ring.Poly, bound int64) {
		t.Helper()
		q := int64(ringQ.Modulus[0])
		for i := 0; i < len(omega); i++ {
			v := int64(PIOP.EvalPoly(p.Coeffs[0], omega[i]%ringQ.Modulus[0], ringQ.Modulus[0]))
			if v > q/2 {
				v -= q
			}
			if v < -bound || v > bound {
				t.Fatalf("coeff %d=%d outside bound [%d,%d]", i, v, -bound, bound)
			}
		}
	}
	for i := range in.R0H {
		checkBound(in.R0H[i], public.X0CoeffBound)
	}
	checkBound(in.R1H[0], public.BoundB)
}

func TestBenchmarkX0WritesJSONSmoke(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	out := filepath.Join(t.TempDir(), "benchmark_x0.json")
	if err := run([]string{"benchmark-x0", "-profiles", "lhl_default", "-runs", "1", "-json-out", out}); err != nil {
		t.Fatalf("benchmark-x0: %v", err)
	}
	var report benchmarkX0Report
	if err := readJSONFile(out, &report); err != nil {
		t.Fatalf("read benchmark json: %v", err)
	}
	if report.Version != benchmarkX0Version {
		t.Fatalf("benchmark report version=%d want %d", report.Version, benchmarkX0Version)
	}
	if len(report.Profiles) != 1 {
		t.Fatalf("benchmark profiles len=%d want 1", len(report.Profiles))
	}
	profile := report.Profiles[0]
	if profile.Profile != "lhl_default" {
		t.Fatalf("profile=%q want lhl_default", profile.Profile)
	}
	if profile.X0Len != 6 || profile.X0CoeffBound != 5 {
		t.Fatalf("unexpected x0 profile len=%d bound=%d", profile.X0Len, profile.X0CoeffBound)
	}
	if !profile.LHL.SatisfiesLHL {
		t.Fatalf("benchmark lhl_default should satisfy LHL: %+v", profile.LHL)
	}
	if profile.AvgIssuanceProveMS <= 0 || profile.AvgShowingProveMS <= 0 {
		t.Fatalf("expected positive benchmark timings, got issuance=%f showing=%f", profile.AvgIssuanceProveMS, profile.AvgShowingProveMS)
	}
	if profile.AvgShowingProofBytes <= 0 || profile.AvgShowingTranscript <= 0 {
		t.Fatalf("expected positive showing size metrics, got proof=%f transcript=%f", profile.AvgShowingProofBytes, profile.AvgShowingTranscript)
	}
	if len(profile.RunReports) != 1 {
		t.Fatalf("run reports len=%d want 1", len(profile.RunReports))
	}
	runReport := profile.RunReports[0]
	if runReport.ReplayWitnessRows <= 0 || runReport.CommittedWitnessRows <= 0 {
		t.Fatalf("expected positive witness geometry in run report: %+v", runReport)
	}
	if runReport.IssuancePaperBuckets.TotalBytes != runReport.IssuanceTranscriptBytes {
		t.Fatalf("issuance bucket total=%d want transcript=%d", runReport.IssuancePaperBuckets.TotalBytes, runReport.IssuanceTranscriptBytes)
	}
	if runReport.ShowingPaperBuckets.TotalBytes != runReport.ShowingTranscriptBytes {
		t.Fatalf("showing bucket total=%d want transcript=%d", runReport.ShowingPaperBuckets.TotalBytes, runReport.ShowingTranscriptBytes)
	}
	if runReport.IssuanceFocus.DQ <= 0 || runReport.ShowingFocus.DQ <= 0 {
		t.Fatalf("expected positive dq focus in run report: %+v", runReport)
	}
	if runReport.ShowingFocus.WitnessRows <= 0 || runReport.ShowingFocus.ReplayBlocks <= 0 {
		t.Fatalf("expected positive showing focus geometry in run report: %+v", runReport)
	}
}
