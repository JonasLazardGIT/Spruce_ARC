package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vSIS-Signature/credential"
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

func TestSetupDemoPublicRequiresForceToOverwrite(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	out := filepath.Join(t.TempDir(), "credential_public.json")
	if err := run([]string{"setup-demo-public", "-out", out}); err != nil {
		t.Fatalf("initial setup-demo-public: %v", err)
	}
	if err := run([]string{"setup-demo-public", "-out", out}); err == nil {
		t.Fatal("setup-demo-public overwrote existing file without -force")
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

	if err := run([]string{"setup-demo-public", "-out", publicPath, "-force"}); err != nil {
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
