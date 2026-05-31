package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	ntrurio "vSIS-Signature/ntru/io"
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

func TestRunWithoutSubcommandFails(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("run(nil) succeeded; want usage error")
	}
}

func TestRemovedIssuanceCommandsAreRejected(t *testing.T) {
	for _, command := range []string{
		"setup-demo-public",
		"issuer-challenge",
		"benchmark-x0",
		"benchmark-intgenisis",
		"sweep-intgenisis",
		"sweep-intgenisis-estimate",
	} {
		t.Run(command, func(t *testing.T) {
			err := run([]string{command})
			if err == nil {
				t.Fatalf("%s unexpectedly succeeded", command)
			}
			if !strings.Contains(err.Error(), "unknown subcommand") {
				t.Fatalf("unexpected error for %s: %v", command, err)
			}
		})
	}
}

func TestRemovedPresetSelectorsAreRejectedByCLI(t *testing.T) {
	for _, args := range [][]string{
		{"benchmark-intgenisis-e2e", "-96bit"},
		{"benchmark-intgenisis-e2e", "-preset", "sw96-lvcs64"},
		{"holder-commit", "-96bit"},
		{"holder-commit", "-preset", "n256-sw96"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			if err := run(args); err == nil {
				t.Fatalf("run(%v) unexpectedly succeeded", args)
			}
		})
	}
}

func TestSetupIntGenISISPublicWritesMaintainedProfileParams(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	for _, profile := range []credential.IntGenISISProfile{
		credential.PrimaryIntGenISISProfile(),
		credential.Ternary1024IntGenISISProfile(),
	} {
		t.Run(profile.Name, func(t *testing.T) {
			tmp := t.TempDir()
			out := filepath.Join(tmp, "credential_public."+profile.Name+".json")
			bPath := filepath.Join(tmp, "Bmatrix."+profile.Name+".json")
			if err := run([]string{"setup-intgenisis-public", "-profile", profile.Name, "-out", out, "-b-path", bPath, "-force"}); err != nil {
				t.Fatalf("setup-intgenisis-public: %v", err)
			}
			public, err := credential.LoadPublicParams(out)
			if err != nil {
				t.Fatalf("load public params: %v", err)
			}
			if public.Profile != profile.Name || public.RingDegree != profile.N || public.EllX0 != profile.EllX0 {
				t.Fatalf("unexpected public params: %+v", public)
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
			if meta.X0Len != profile.EllX0 || meta.RingDegree != profile.N || len(meta.B) != 3+profile.EllX0 {
				t.Fatalf("unexpected B metadata: x0_len=%d rows=%d ring=%d", meta.X0Len, len(meta.B), meta.RingDegree)
			}
		})
	}
}

func TestSetupNTRUKeysRejectsRemovedResearchDegree(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	err := run([]string{
		"setup-ntru-keys",
		"-ring-degree", "256",
		"-params-out", filepath.Join(t.TempDir(), "params.json"),
	})
	if err == nil {
		t.Fatal("setup-ntru-keys accepted removed N=256 degree")
	}
	if !strings.Contains(err.Error(), "supported:") || !strings.Contains(err.Error(), "512") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIntGenISISIssuanceTranscriptModePropagation(t *testing.T) {
	preset, ok := credential.LookupIntGenISISPreset(credential.IntGenISISPresetN1024Compact125)
	if !ok {
		t.Fatal("n1024-compact125 preset missing")
	}
	issuance := intGenISISTuningFromPresetSpec(preset.Issuance)
	showing := intGenISISTuningFromPresetSpec(preset.Showing)
	normalized := normalizeIntGenISISTuning(issuance, showing, false)
	if normalized.TranscriptMode != sweepTranscriptModeSmallField2025 {
		t.Fatalf("normalized issuance transcript mode=%q", normalized.TranscriptMode)
	}
	overrides := intGenISISTuningToIssuanceOverrides(normalized, credential.Ternary1024IntGenISISProfile().N)
	if overrides.TranscriptMode != sweepTranscriptModeSmallField2025 {
		t.Fatalf("issuance override transcript mode=%q", overrides.TranscriptMode)
	}
	opts := applyIssuanceRuntimeOverrides(PIOP.SimOpts{}, overrides)
	if opts.TranscriptVersion != PIOP.TranscriptVersionSmallWood2025 || opts.TranscriptProtocolMode != PIOP.TranscriptProtocolSmallField2025V1 {
		t.Fatalf("issuance opts transcript tuple=(%q,%q)", opts.TranscriptVersion, opts.TranscriptProtocolMode)
	}
	spec := smallWoodTuningSpecFromOpts(opts)
	if spec.TranscriptMode != sweepTranscriptModeSmallField2025 {
		t.Fatalf("persisted SmallWood transcript mode=%q", spec.TranscriptMode)
	}
	roundTrip := persistedIssuanceRuntimeOverridesWithSmallWood(spec.NCols, spec.LVCSNCols, spec.NLeaves, nil, spec)
	if roundTrip.TranscriptMode != sweepTranscriptModeSmallField2025 {
		t.Fatalf("round-trip override transcript mode=%q", roundTrip.TranscriptMode)
	}

	applyIssuanceSpecificFlagOverrides(&issuance, map[string]bool{"issuance-transcript-mode": true}, sweepTranscriptModeBaseline)
	baseline := normalizeIntGenISISTuning(issuance, showing, false)
	baselineOverrides := intGenISISTuningToIssuanceOverrides(baseline, credential.Ternary1024IntGenISISProfile().N)
	baselineOpts := applyIssuanceRuntimeOverrides(PIOP.SimOpts{}, baselineOverrides)
	if baselineOpts.TranscriptVersion != "" || baselineOpts.TranscriptProtocolMode != "" {
		t.Fatalf("baseline issuance opts transcript tuple=(%q,%q)", baselineOpts.TranscriptVersion, baselineOpts.TranscriptProtocolMode)
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

func TestIntGenISISCLICommitAndProveOmitLegacyChallengeMaterial(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	tmp := t.TempDir()
	publicPath := filepath.Join(tmp, "credential_public.intgenisis.json")
	bPath := filepath.Join(tmp, "Bmatrix.intgenisis.json")
	holderSecret := filepath.Join(tmp, "holder_secret.json")
	commitRequest := filepath.Join(tmp, "commit_request.json")
	submission := filepath.Join(tmp, "presign_submission.json")
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
	reqText := string(mustReadFile(t, commitRequest))
	for _, stale := range []string{"r0h", "r1h", "ri0", "ri1", `"t"`} {
		if strings.Contains(reqText, stale) {
			t.Fatalf("IntGenISIS commit request leaked stale field %q: %s", stale, reqText)
		}
	}
	if err := run([]string{
		"holder-prove",
		"-holder-secret", holderSecret,
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
	resp.SigS2[0]++
	if err := verifyIntGenISISSignatureResponse(ringQ, resp, target); err == nil {
		t.Fatal("modified signature response accepted")
	}
}
