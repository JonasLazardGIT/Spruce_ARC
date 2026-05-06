package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"

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

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func runShowingCLIForIssuanceTest(t *testing.T, args ...string) {
	t.Helper()
	if err := runShowingCLIForIssuanceTestErr(t, args...); err != nil {
		t.Fatalf("showing CLI %v: %v", args, err)
	}
}

func runShowingCLIForIssuanceTestErr(t *testing.T, args ...string) error {
	t.Helper()
	cmdArgs := append([]string{"run", "./cmd/showing"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = issuanceTestRepoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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

func TestSetupIntGenISISPublicWritesProfileBParams(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	out := filepath.Join(tmp, "credential_public.intgenisis.json")
	bPath := filepath.Join(tmp, "Bmatrix.intgenisis.json")
	if err := run([]string{"setup-intgenisis-public", "-out", out, "-b-path", bPath, "-force"}); err != nil {
		t.Fatalf("setup-intgenisis-public: %v", err)
	}
	public, err := credential.LoadPublicParams(out)
	if err != nil {
		t.Fatalf("load public params: %v", err)
	}
	profile := credential.PrimaryIntGenISISProfile()
	if public.Profile != profile.Name || public.EllM != 1 || public.KS != 2 || public.NC != 1 || public.CommitmentBound != 4 {
		t.Fatalf("unexpected IntGenISIS public params: %+v", public)
	}
	if len(public.CM) != profile.NC || len(public.CM[0]) != profile.EllM {
		t.Fatalf("C_M dims=%dx%d", len(public.CM), len(public.CM[0]))
	}
	if len(public.AS) != profile.NC || len(public.AS[0]) != profile.KS {
		t.Fatalf("A_s dims=%dx%d", len(public.AS), len(public.AS[0]))
	}
	meta, err := ntrurio.LoadBMatrixMetadata(bPath)
	if err != nil {
		t.Fatalf("load B matrix: %v", err)
	}
	if meta.X0Len != profile.EllX0 || len(meta.B) != 3+profile.EllX0 {
		t.Fatalf("unexpected B metadata: x0_len=%d rows=%d", meta.X0Len, len(meta.B))
	}
}

func TestSetupIntGenISISPublicWritesProfileCWithSingleX0(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	out := filepath.Join(tmp, "credential_public.intgenisis_profile_c.json")
	bPath := filepath.Join(tmp, "Bmatrix.intgenisis_profile_c.json")
	if err := run([]string{"setup-intgenisis-public", "-profile", credential.ProfileIntGenISISC, "-out", out, "-b-path", bPath, "-force"}); err != nil {
		t.Fatalf("setup-intgenisis-public profile C: %v", err)
	}
	public, err := credential.LoadPublicParams(out)
	if err != nil {
		t.Fatalf("load public params: %v", err)
	}
	profile := credential.Ternary1024IntGenISISProfile()
	if public.Profile != profile.Name || public.RingDegree != profile.N || public.EllX0 != 1 || public.X0Len != 1 {
		t.Fatalf("unexpected profile-C public params: %+v", public)
	}
	meta, err := ntrurio.LoadBMatrixMetadata(bPath)
	if err != nil {
		t.Fatalf("load B matrix: %v", err)
	}
	if meta.X0Len != 1 || len(meta.B) != 4 || meta.RingDegree != 1024 {
		t.Fatalf("unexpected profile-C B metadata: x0_len=%d rows=%d ring=%d", meta.X0Len, len(meta.B), meta.RingDegree)
	}
}

func TestBenchmarkIntGenISISWritesRowInventory(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	jsonOut := filepath.Join(t.TempDir(), "benchmark_intgenisis.json")
	if err := run([]string{"benchmark-intgenisis", "-profiles", credential.ProfileIntGenISISB + "," + credential.ProfileIntGenISISA, "-json-out", jsonOut}); err != nil {
		t.Fatalf("benchmark-intgenisis: %v", err)
	}
	raw, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("read benchmark json: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"intgenisis_mlwe_presign",
		"intgenisis_mlwe_showing",
		`"showing_non_prf_rows": 416`,
		`"showing_non_prf_rows": 240`,
		`"measurement_status": "profile_b_live_presign"`,
		`"measurement_status": "profile_b_live_showing"`,
		`"proof_size_bytes": 0`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("benchmark json missing %q: %s", want, text)
		}
	}
}

func TestIntGenISISCLICommitProveAndChallengeGuard(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	publicPath := filepath.Join(tmp, "credential_public.intgenisis.json")
	bPath := filepath.Join(tmp, "Bmatrix.intgenisis.json")
	holderSecret := filepath.Join(tmp, "holder_secret.json")
	commitRequest := filepath.Join(tmp, "commit_request.json")
	submission := filepath.Join(tmp, "presign_submission.json")
	challenge := filepath.Join(tmp, "issue_challenge.json")
	if err := run([]string{"setup-intgenisis-public", "-out", publicPath, "-b-path", bPath, "-force"}); err != nil {
		t.Fatalf("setup-intgenisis-public: %v", err)
	}
	if err := run([]string{
		"holder-commit",
		"-public-params", publicPath,
		"-holder-secret", holderSecret,
		"-commit-request", commitRequest,
		"-seed", "11",
		"-ncols", "16",
		"-lvcs-ncols", "32",
	}); err != nil {
		t.Fatalf("holder-commit IntGenISIS: %v", err)
	}
	rawReq, err := os.ReadFile(commitRequest)
	if err != nil {
		t.Fatalf("read commit request: %v", err)
	}
	reqText := string(rawReq)
	for _, stale := range []string{"r0h", "r1h", "ri0", "ri1", `"t"`} {
		if strings.Contains(reqText, stale) {
			t.Fatalf("IntGenISIS commit request leaked stale field %q: %s", stale, reqText)
		}
	}
	if err := run([]string{"issuer-challenge", "-commit-request", commitRequest, "-issue-challenge", challenge}); err == nil {
		t.Fatal("issuer-challenge accepted IntGenISIS params")
	}
	if err := run([]string{
		"holder-prove",
		"-holder-secret", holderSecret,
		"-issue-challenge", challenge,
		"-presign-submission", submission,
	}); err != nil {
		t.Fatalf("holder-prove IntGenISIS: %v", err)
	}
	var sub preSignSubmissionFile
	if err := json.Unmarshal(mustReadFile(t, submission), &sub); err != nil {
		t.Fatalf("decode submission: %v", err)
	}
	if sub.Proof == nil {
		t.Fatal("IntGenISIS holder-prove did not write proof")
	}
	if len(sub.T) != 0 {
		t.Fatalf("IntGenISIS pre-sign submission exposed target T with len=%d", len(sub.T))
	}
}

func TestIntGenISISIssueResponseOmitsTargetAndVerifiesAUEqualsT(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)
	ringQ, err := credential.LoadRingWithDegree(credential.PrimaryIntGenISISProfile().N)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	target := make([]int64, ringQ.N)
	target[0] = 7
	resp := issueResponseFile{
		Version:              issuanceArtifactVersion,
		CredentialPublicPath: "Parameters/credential_public.intgenisis_profile_b.json",
		SigS1:                make([]int64, ringQ.N),
		SigS2:                append([]int64(nil), target...),
		NTRUPublic:           [][]int64{make([]int64, ringQ.N)},
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	for _, stale := range []string{`"t"`, `"signature"`} {
		if strings.Contains(string(raw), stale) {
			t.Fatalf("IntGenISIS response leaked stale field %q: %s", stale, string(raw))
		}
	}
	if err := verifyIntGenISISSignatureResponse(ringQ, resp, target); err != nil {
		t.Fatalf("verify response: %v", err)
	}
	staleT := resp
	staleT.T = append([]int64(nil), target...)
	if err := verifyIntGenISISSignatureResponse(ringQ, staleT, target); err == nil {
		t.Fatal("IntGenISIS response with serialized T accepted")
	}
	staleBundle := resp
	staleBundle.Signature = &keys.Signature{}
	if err := verifyIntGenISISSignatureResponse(ringQ, staleBundle, target); err == nil {
		t.Fatal("IntGenISIS response with serialized signature bundle accepted")
	}
	resp.SigS2[0]++
	if err := verifyIntGenISISSignatureResponse(ringQ, resp, target); err == nil {
		t.Fatal("modified signature response accepted")
	}
}

func TestIntGenISISFullCLIFlowPresentationReplay(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	publicPath := filepath.Join(tmp, "credential_public.intgenisis.json")
	bPath := filepath.Join(tmp, "Bmatrix.intgenisis.json")
	holderSecret := filepath.Join(tmp, "holder_secret.json")
	commitRequest := filepath.Join(tmp, "commit_request.json")
	submission := filepath.Join(tmp, "presign_submission.json")
	response := filepath.Join(tmp, "issue_response.json")
	statePath := filepath.Join(tmp, "credential_state.intgenisis.json")
	signaturePath := filepath.Join(tmp, "signature.json")
	verifierKey := filepath.Join(tmp, "intgenisis_verifier_key.json")
	ntruParams := filepath.Join(tmp, "ntru_params.json")
	ntruPublic := filepath.Join(tmp, "ntru_public.json")
	ntruPrivate := filepath.Join(tmp, "ntru_private.json")
	ntruSignature := filepath.Join(tmp, "ntru_signature.json")
	presentation := filepath.Join(tmp, "presentation.json")
	verifierState := filepath.Join(tmp, "verifier_state.json")

	if err := run([]string{"setup-intgenisis-public", "-out", publicPath, "-b-path", bPath, "-force"}); err != nil {
		t.Fatalf("setup-intgenisis-public: %v", err)
	}
	if err := run([]string{
		"setup-ntru-keys",
		"-research-ring-degree", "512",
		"-params-out", ntruParams,
		"-public-out", ntruPublic,
		"-private-out", ntruPrivate,
		"-force",
		"-keygen-trials", "500",
		"-attempts", "2",
	}); err != nil {
		t.Fatalf("setup-ntru-keys: %v", err)
	}
	if err := run([]string{
		"holder-commit",
		"-public-params", publicPath,
		"-holder-secret", holderSecret,
		"-commit-request", commitRequest,
		"-seed", "11",
		"-ncols", "16",
		"-lvcs-ncols", "32",
	}); err != nil {
		t.Fatalf("holder-commit: %v", err)
	}
	if err := run([]string{"holder-prove", "-holder-secret", holderSecret, "-presign-submission", submission}); err != nil {
		t.Fatalf("holder-prove: %v", err)
	}
	if err := run([]string{
		"issuer-verify-sign",
		"-commit-request", commitRequest,
		"-presign-submission", submission,
		"-issue-response", response,
		"-ntru-params", ntruParams,
		"-ntru-public-key", ntruPublic,
		"-ntru-private-key", ntruPrivate,
		"-ntru-signature-out", ntruSignature,
		"-verifier-key-out", verifierKey,
		"-max-trials", "512",
	}); err != nil {
		t.Fatalf("issuer-verify-sign: %v", err)
	}
	if err := run([]string{
		"holder-finalize",
		"-holder-secret", holderSecret,
		"-commit-request", commitRequest,
		"-issue-response", response,
		"-state-out", statePath,
		"-signature-out", signaturePath,
		"-ntru-params", ntruParams,
	}); err != nil {
		t.Fatalf("holder-finalize: %v", err)
	}
	runShowingCLIForIssuanceTest(t,
		"-showing-profile", "showing_intgenisis_profile_b",
		"-state-path", statePath,
		"-presentation-out", presentation,
		"-ncols", "16",
		"-lvcs-ncols", "32",
		"-nleaves", "4096",
		"-eta", "8",
		"-rho", "1",
		"-prf-checkpoint-samples", "2",
	)
	runShowingCLIForIssuanceTest(t,
		"-showing-profile", "showing_intgenisis_profile_b",
		"-verify-presentation", presentation,
		"-public-params", publicPath,
		"-verifier-key", verifierKey,
		"-verifier-state", verifierState,
		"-ncols", "16",
		"-lvcs-ncols", "32",
		"-nleaves", "4096",
		"-eta", "8",
		"-rho", "1",
		"-prf-checkpoint-samples", "2",
	)
	replayErr := runShowingCLIForIssuanceTestErr(t,
		"-showing-profile", "showing_intgenisis_profile_b",
		"-verify-presentation", presentation,
		"-public-params", publicPath,
		"-verifier-key", verifierKey,
		"-verifier-state", verifierState,
		"-ncols", "16",
		"-lvcs-ncols", "32",
		"-nleaves", "4096",
		"-eta", "8",
		"-rho", "1",
		"-prf-checkpoint-samples", "2",
	)
	if replayErr == nil || !strings.Contains(replayErr.Error(), "replayed IntGenISIS nonce/tag pair") {
		t.Fatalf("replay error=%v", replayErr)
	}
	var presTop map[string]json.RawMessage
	if err := json.Unmarshal(mustReadFile(t, presentation), &presTop); err != nil {
		t.Fatalf("decode presentation: %v", err)
	}
	for _, stale := range []string{"c", "T", "M", "m", "k", "s", "e", "mu_sig", "x0", "x1", "Z", "u", "r0", "r1", "LHL", "shared"} {
		if _, ok := presTop[stale]; ok {
			t.Fatalf("presentation leaked top-level field %q", stale)
		}
	}
	var key credential.IntGenISISVerifierKey
	if err := json.Unmarshal(mustReadFile(t, verifierKey), &key); err != nil {
		t.Fatalf("decode verifier key: %v", err)
	}
	if key.SignatureBound <= 0 {
		t.Fatalf("verifier key signature_bound=%d", key.SignatureBound)
	}
}

func TestBenchmarkIntGenISISE2ECommandWritesPaperTranscriptReport(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	reportPath := filepath.Join(tmp, "report.json")
	if err := run([]string{
		"benchmark-intgenisis-e2e",
		"-artifact-dir", tmp,
		"-force",
		"-keygen-trials", "500",
		"-attempts", "2",
		"-max-trials", "512",
		"-prf-checkpoint-samples", "2",
		"-json-out", reportPath,
	}); err != nil {
		t.Fatalf("benchmark-intgenisis-e2e: %v", err)
	}
	var report benchmarkIntGenISISE2EReport
	if err := json.Unmarshal(mustReadFile(t, reportPath), &report); err != nil {
		t.Fatalf("decode e2e report: %v", err)
	}
	if report.Profile != credential.ProfileIntGenISISB || !report.ReplayRejected {
		t.Fatalf("unexpected e2e report profile=%q replay=%v", report.Profile, report.ReplayRejected)
	}
	if report.Issuance.PaperTranscriptBytes <= 0 || report.Showing.PaperTranscriptBytes <= 0 {
		t.Fatalf("missing paper transcript bytes: issuance=%d showing=%d", report.Issuance.PaperTranscriptBytes, report.Showing.PaperTranscriptBytes)
	}
	if report.Showing.ShortnessRows != 256 || report.Showing.HatRows != 256 || report.Showing.YHatRows != 32 || report.Showing.YLinearConstraints != 512 {
		t.Fatalf("unexpected showing rows: shortness=%d hats=%d y_hats=%d y_linear=%d", report.Showing.ShortnessRows, report.Showing.HatRows, report.Showing.YHatRows, report.Showing.YLinearConstraints)
	}
}

func TestBenchmarkIntGenISISE2EProfileAPreset(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	reportPath := filepath.Join(tmp, "report_n256.json")
	if err := run([]string{
		"benchmark-intgenisis-e2e",
		"-96bit",
		"-artifact-dir", tmp,
		"-force",
		"-keygen-trials", "1000",
		"-attempts", "1",
		"-max-trials", "512",
		"-json-out", reportPath,
	}); err != nil {
		if strings.Contains(err.Error(), "annulus keygen panic") {
			t.Skipf("research N=256 annulus keygen is numerically unstable in this environment: %v", err)
		}
		t.Fatalf("benchmark-intgenisis-e2e n256: %v", err)
	}
	var report benchmarkIntGenISISE2EReport
	if err := json.Unmarshal(mustReadFile(t, reportPath), &report); err != nil {
		t.Fatalf("decode n256 report: %v", err)
	}
	if report.Profile != credential.ProfileIntGenISISA || !report.ReplayRejected {
		t.Fatalf("unexpected n256 report profile=%q replay=%v", report.Profile, report.ReplayRejected)
	}
	if report.Issuance.TotalRows <= 0 || report.Showing.TotalRows <= 0 || report.Showing.ReplayProjection == "" {
		t.Fatalf("missing n256 relation metrics: issuance=%+v showing=%+v", report.Issuance, report.Showing)
	}
	if got, want := report.Options.Issuance.LVCSNCols, 48; got != want {
		t.Fatalf("unexpected 96-bit issuance lvcs_ncols=%d want %d", got, want)
	}
	if got, want := report.Issuance.CommittedCols, 48; got != want {
		t.Fatalf("96-bit issuance committed_cols=%d want %d", got, want)
	}
	if got, want := report.Issuance.SmallFieldReplayRows, 54; got != want {
		t.Fatalf("96-bit issuance smallfield_replay_rows=%d want %d", got, want)
	}
	if bits := report.Issuance.SoundnessEq8Bits; bits < 96 || bits > 97 {
		t.Fatalf("96-bit issuance soundness_eq8_bits=%.2f want in [96,97]", bits)
	}
	if got, want := report.Options.Showing.LVCSNCols, 48; got != want {
		t.Fatalf("unexpected 96-bit showing lvcs_ncols=%d want %d", got, want)
	}
	if got, want := report.Showing.CommittedCols, 48; got != want {
		t.Fatalf("96-bit showing committed_cols=%d want %d", got, want)
	}
	if got, want := report.Showing.TotalRows, 380; got != want {
		t.Fatalf("96-bit showing rows=%d want %d", got, want)
	}
	if got, want := report.Showing.SmallFieldReplayRows, 144; got != want {
		t.Fatalf("96-bit showing smallfield_replay_rows=%d want %d", got, want)
	}
	if bits := report.Showing.SoundnessEq8Bits; bits < 96 || bits > 97 {
		t.Fatalf("96-bit showing soundness_eq8_bits=%.2f want in [96,97]", bits)
	}
}

func TestBenchmarkIntGenISISE2ERejectsOverLeafCap(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	err := run([]string{
		"benchmark-intgenisis-e2e",
		"-artifact-dir", tmp,
		"-force",
		"-nleaves", "8192",
		"-max-nleaves", "4096",
	})
	if err == nil {
		t.Fatalf("expected benchmark-intgenisis-e2e to reject nleaves above cap")
	}
	if !strings.Contains(err.Error(), "exceeds max-nleaves=4096") {
		t.Fatalf("unexpected cap error: %v", err)
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

func TestSetupDemoPublicResearch512WritesSeparateDegree(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	out := filepath.Join(tmp, "credential_public.research_n512.json")
	bPath := filepath.Join(tmp, "Bmatrix.research_n512.json")
	if err := run([]string{"setup-demo-public", "-out", out, "-b-path", bPath, "-force", "-x0-profile", "legacy_scalar", "-research-ring-degree", "512"}); err != nil {
		t.Fatalf("setup-demo-public research n512: %v", err)
	}
	public, err := credential.LoadPublicParams(out)
	if err != nil {
		t.Fatalf("load public params: %v", err)
	}
	if public.RingDegree != 512 {
		t.Fatalf("public ring_degree=%d want 512", public.RingDegree)
	}
	meta, err := ntrurio.LoadBMatrixMetadata(bPath)
	if err != nil {
		t.Fatalf("load B matrix: %v", err)
	}
	for i := range meta.B {
		if len(meta.B[i]) != 512 {
			t.Fatalf("B[%d] length=%d want 512", i, len(meta.B[i]))
		}
	}
}

func TestSetupNTRUKeysRefusesOverwriteBeforeKeygen(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	paramsPath := filepath.Join(tmp, "Parameters.research_n512.json")
	if err := os.WriteFile(paramsPath, []byte(`{"n":512,"q":1054721,"beta":6142}`), 0o644); err != nil {
		t.Fatalf("write existing params: %v", err)
	}
	err := run([]string{
		"setup-ntru-keys",
		"-research-ring-degree", "512",
		"-params-out", paramsPath,
		"-public-out", filepath.Join(tmp, "public.research_n512.json"),
		"-private-out", filepath.Join(tmp, "private.research_n512.json"),
	})
	if err == nil {
		t.Fatal("setup-ntru-keys overwrote existing params without -force")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResearch512SigningRejectsDefaultNTRUArtifacts(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	err := validateNTRUSigningArtifacts(ntruSigningPaths(defaultNTRUParamsPath, defaultNTRUPublicKeyPath, defaultNTRUPrivateKeyPath, ""), 512)
	if err == nil {
		t.Fatal("default N=1024 NTRU artifacts accepted for ring_degree=512")
	}
	if !strings.Contains(err.Error(), "incompatible with target ring_degree=512") {
		t.Fatalf("unexpected error: %v", err)
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
	if maxAbsRows(state.Mu) <= 0 {
		t.Fatal("default issuance sampled zero mu; want nonzero hidden payload material")
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
		MuLayout:           credential.MuLayoutFullCapacityHalvesV1,
		BoundB:             1,
		X0Len:              6,
		X0CoeffBound:       5,
		TargetDim:          credential.DefaultTargetDim,
		TargetHidingLambda: credential.DefaultTargetHidingLambda,
		X0Distribution:     credential.X0DistributionUniformInterval,
		LenMu:              1,
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
	muRows := polyVecToInt64(ringQ, in.Mu, false)
	if err := credential.ValidateFullMuPayload(muRows, int(ringQ.N), public.BoundB); err != nil {
		t.Fatalf("sampled mu is not a bounded full-capacity payload: %v", err)
	}
	nonzeroTail := 0
	for _, v := range muRows[0][len(omega):] {
		if v != 0 {
			nonzeroTail++
		}
	}
	if nonzeroTail == 0 {
		t.Fatal("sampled full-capacity mu has an all-zero tail")
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
