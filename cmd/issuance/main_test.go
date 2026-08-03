package main

import (
	"bytes"
	"encoding/json"
	"log"
	"math"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/issuance"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/prf"

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
		"research-showing-transcript",
		"swe" + "ep-intgenisis",
		"swe" + "ep-intgenisis-estimate",
		"demo-local",
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
	removedDegree256 := "n" + "256-sw96"
	for _, args := range [][]string{
		{"benchmark-intgenisis-e2e", "-96bit"},
		{"benchmark-intgenisis-e2e", "-preset", "sw96-lvcs64"},
		{"holder-commit", "-96bit"},
		{"holder-commit", "-preset", removedDegree256},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			if err := run(args); err == nil {
				t.Fatalf("run(%v) unexpectedly succeeded", args)
			}
		})
	}
}

func TestBenchmarkRemovedTuningAndAccountingFlagsAreUnknown(t *testing.T) {
	for _, flagName := range []string{
		"-prf-companion-mode",
		"-showing-transcript-mode",
		"-ncols",
		"-fixed-transcript-size",
		"-ro-query-caps",
		"-accepted-issuance",
		"-accepted-showing",
		"-decs-collision-bits",
		"-decs-collision-bytes",
	} {
		t.Run(flagName, func(t *testing.T) {
			err := run([]string{"benchmark-intgenisis-e2e", "-preset", "n512-compact96", flagName, "x"})
			if err == nil {
				t.Fatalf("%s unexpectedly parsed", flagName)
			}
			if !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Fatalf("unexpected error for %s: %v", flagName, err)
			}
		})
	}
}

func TestBenchmarkIntGenISISE2EPropagatesPresetAccounting(t *testing.T) {
	cfg, err := parseBenchmarkIntGenISISE2EConfig([]string{
		"-preset", credential.IntGenISISPresetN1024Q16_96,
	})
	if err != nil {
		t.Fatalf("parse benchmark query-budget preset: %v", err)
	}
	wantCaps := [5]int{65536, 65536, 65536, 65536, 65536}
	if !cfg.Showing.ROQueryCapsSet || cfg.Showing.ROQueryCaps != wantCaps {
		t.Fatalf("showing query caps=%v set=%v", cfg.Showing.ROQueryCaps, cfg.Showing.ROQueryCapsSet)
	}
	if cfg.Showing.DECSCollisionBits != 136 {
		t.Fatalf("showing decs collision bits=%d", cfg.Showing.DECSCollisionBits)
	}
	if !cfg.Issuance.ROQueryCapsSet || cfg.Issuance.ROQueryCaps != cfg.Showing.ROQueryCaps {
		t.Fatalf("issuance query caps=%v set=%v", cfg.Issuance.ROQueryCaps, cfg.Issuance.ROQueryCapsSet)
	}
	if cfg.Issuance.DECSCollisionBits != 136 {
		t.Fatalf("issuance decs collision bits=%d", cfg.Issuance.DECSCollisionBits)
	}
	options := benchmarkIntGenISISE2EReportOptions(cfg)
	for phase, tuning := range map[string]intGenISISTuning{"issuance": options.Issuance, "showing": options.Showing} {
		if tuning.TranscriptOmissionMode != PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2 {
			t.Fatalf("benchmark report Options.%s transcript omission mode=%q", phase, tuning.TranscriptOmissionMode)
		}
	}
}

func TestBenchmarkIntGenISISE2EPropagatesBQ32ProfileMetadata(t *testing.T) {
	cfg, err := parseBenchmarkIntGenISISE2EConfig([]string{
		"-preset", credential.IntGenISISPresetN1024BQ32_96,
	})
	if err != nil {
		t.Fatalf("parse benchmark bq32 preset: %v", err)
	}
	if cfg.SecurityProfile != "BQ32-96" || cfg.SecurityMode != "residual_at_budget" {
		t.Fatalf("security tuple=(%q,%q)", cfg.SecurityProfile, cfg.SecurityMode)
	}
	if cfg.CompleteSystemClaim {
		t.Fatal("bq32 candidate should not parse as complete claim")
	}
	if cfg.PRFProfile != credential.IntGenISISPRFProfileTag9 || cfg.PRFParamsPath != credential.IntGenISISPRFParamsTag9 {
		t.Fatalf("PRF tuple=(%q,%q)", cfg.PRFProfile, cfg.PRFParamsPath)
	}
	if cfg.Showing.DECSHashBits != 168 || cfg.Showing.DECSTapeBits != 136 || cfg.Showing.FSCollisionBits != 168 || cfg.Showing.SaltBits != 168 {
		t.Fatalf("showing split widths=%+v", cfg.Showing)
	}
}

func TestBenchmarkIntGenISISE2EPropagatesWF128PoCPreset(t *testing.T) {
	cfg, err := parseBenchmarkIntGenISISE2EConfig([]string{
		"-preset", credential.IntGenISISPresetSystemN1024WF128CROMV2,
	})
	if err != nil {
		t.Fatalf("parse benchmark WF-128 preset: %v", err)
	}
	if cfg.SecurityProfile != "WF-128" || cfg.SecurityMode != "query_work_factor" || cfg.CompleteSystemClaim {
		t.Fatalf("security tuple=(%q,%q,%v)", cfg.SecurityProfile, cfg.SecurityMode, cfg.CompleteSystemClaim)
	}
	if cfg.PRFProfile != credential.IntGenISISPRFProfileTag13 || cfg.PRFParamsPath != credential.IntGenISISPRFParamsTag13 || cfg.PRFParamsDigest != credential.IntGenISISPRFParamsTag13Digest {
		t.Fatalf("PRF tuple=(%q,%q,%q)", cfg.PRFProfile, cfg.PRFParamsPath, cfg.PRFParamsDigest)
	}
	if cfg.Showing.ROQueryCapsSet || cfg.Showing.ROQueryCaps != [5]int{} || cfg.Showing.ROQueryCapBitsSet || cfg.Showing.ROQueryCapBits != [5]float64{} {
		t.Fatalf("WF-128 bounded-query caps=%+v", cfg.Showing)
	}
	if cfg.Showing.DECSCollisionBits != 264 || cfg.Showing.DECSHashBits != 264 || cfg.Showing.DECSTapeBits != 128 || cfg.Showing.FSCollisionBits != 264 || cfg.Showing.SaltBits != 256 {
		t.Fatalf("WF-128 widths=%+v", cfg.Showing)
	}
	if cfg.Showing.NCols != 32 || cfg.Showing.LVCSNCols != 42 || cfg.Showing.NLeaves != 327680 || cfg.Showing.Eta != 43 || cfg.Showing.Theta != 7 || cfg.Showing.Ell != 9 || cfg.Showing.Kappa != [4]int{1, 0, 2, 13} {
		t.Fatalf("WF-128 showing geometry=%+v", cfg.Showing)
	}
}

func TestWF128PoCPresetParameterAuditMatchesBindings(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetSystemN1024WF128CROMV2)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		t.Fatalf("missing security profile %q", preset.SecurityProfile)
	}
	params, digest, err := prf.LoadLocalOrBundledParamsWithDigest(preset.PRFParamsPath)
	if err != nil {
		t.Fatal(err)
	}
	if digest != preset.PRFParamsDigest {
		t.Fatalf("loaded PRF digest=%s want %s", digest, preset.PRFParamsDigest)
	}
	audit := credential.AuditIntGenISISSecurityParameters(profile, credential.IntGenISISSecurityParameterActuals{
		DECSHashBits:    preset.Showing.DECSHashBits,
		DECSTapeBits:    preset.Showing.DECSTapeBits,
		FSCollisionBits: preset.Showing.FSCollisionBits,
		SaltBits:        preset.Showing.SaltBits,
		PRFTagElements:  params.LenTag,
		PRFProfile:      preset.PRFProfile,
		TranscriptMode:  preset.Showing.TranscriptMode,
		Evidence: map[string]string{
			"decs_hash_bits":    credential.SecurityEvidenceMeasured,
			"decs_tape_bits":    credential.SecurityEvidenceMeasured,
			"fs_collision_bits": credential.SecurityEvidenceMeasured,
			"salt_bits":         credential.SecurityEvidenceMeasured,
			"prf_tag_elements":  credential.SecurityEvidenceLoadedParams,
			"prf_profile":       credential.SecurityEvidenceLoadedParams,
			"transcript_mode":   credential.SecurityEvidenceMeasured,
		},
	})
	if audit.Status != "pass" || len(audit.MissingActual) != 0 || len(audit.MissingEvidence) != 0 || len(audit.Mismatches) != 0 {
		t.Fatalf("WF-128 parameter audit=%+v", audit)
	}
	if audit.Required.ROQueryCapLog2Set || audit.Actual.ROQueryCapLog2Set {
		t.Fatalf("WF-128 audit must preserve unset bounded-query scope: %+v", audit)
	}
}

func TestBenchmarkActualROQueryCapsPreservesUnsetScope(t *testing.T) {
	metrics := benchmarkIntGenISISMetrics{ROQueryCaps: [5]int{1, 1, 1, 1, 1}}
	bits, set, mismatches := benchmarkActualROQueryCaps(credential.SecurityModeQueryWorkFactor, metrics, metrics)
	if set || bits != [5]float64{} || len(mismatches) != 0 {
		t.Fatalf("unset query scope=(%v,%v,%+v)", bits, set, mismatches)
	}
}

func TestBenchmarkActualROQueryCapsRecognizesSingleCandidateDefault(t *testing.T) {
	metrics := benchmarkIntGenISISMetrics{ROQueryCaps: [5]int{1, 1, 1, 1, 1}}
	bits, set, mismatches := benchmarkActualROQueryCaps(credential.SecurityModeSingleCandidate, metrics, metrics)
	if !set || bits != [5]float64{} || len(mismatches) != 0 {
		t.Fatalf("single-candidate query scope=(%v,%v,%+v)", bits, set, mismatches)
	}
}

func TestIntGenISISTuningFromPresetSpecPropagatesLogCaps(t *testing.T) {
	spec := credential.IntGenISISTuningPreset{
		ROQueryCapBits:         [5]float64{128, 128, 128, 128, 128},
		ROQueryCapBitsSet:      true,
		DECSHashBits:           512,
		DECSTapeBits:           256,
		FSCollisionBits:        512,
		SaltBits:               384,
		TranscriptOmissionMode: credential.IntGenISISTranscriptOmissionModeV2,
	}
	got := intGenISISTuningFromPresetSpec(spec)
	if got.ROQueryCapsSet || !got.ROQueryCapBitsSet || got.ROQueryCapBits != spec.ROQueryCapBits {
		t.Fatalf("log query caps were not preserved: %+v", got)
	}
	if got.DECSHashBits != 512 || got.DECSTapeBits != 256 || got.FSCollisionBits != 512 || got.SaltBits != 384 {
		t.Fatalf("security widths were not preserved: %+v", got)
	}
	if got.TranscriptOmissionMode != credential.IntGenISISTranscriptOmissionModeV2 {
		t.Fatalf("transcript omission mode was not preserved: %+v", got)
	}
}

func TestBenchmarkRelationReportIncludesDQBranches(t *testing.T) {
	metrics := benchmarkIntGenISISMetrics{
		TotalRows:            100,
		CoefficientViewRows:  20,
		ParallelAlgDegree:    11,
		AggregatedAlgDegree:  2,
		MaskDegreeBound:      400,
		DominantDegreeSource: "shortness",
	}
	opts := PIOP.SimOpts{NCols: 32, Ell: 4}
	report := benchmarkIntGenISISRelationReportFromMetrics(&PIOP.Proof{MaskRowCount: 5}, metrics, opts)
	wantParallel := 11*(32+4-1) + 31
	wantAggregate := 2 * (32 + 4 - 1)
	if report.DQParallel != wantParallel || report.DQAggregate != wantAggregate {
		t.Fatalf("dq branches parallel=%d aggregate=%d", report.DQParallel, report.DQAggregate)
	}
	if report.DQ != report.DQParallel || report.DominantDQBranch != "parallel" {
		t.Fatalf("unexpected dominant dq branch: %+v", report)
	}
	if report.RowCounts["mask"] != 5 || report.RowCounts["coefficient_view"] != 20 {
		t.Fatalf("row counts=%v", report.RowCounts)
	}
}

func TestBenchmarkReportCarriesFlattenedLedgerFields(t *testing.T) {
	report := benchmarkIntGenISISE2EReport{
		LedgerStatus:               string(credential.SecurityProfileCandidate),
		SoundnessBits:              100,
		UnlinkabilityBits:          101,
		CorrectnessBits:            102,
		PrimitiveBits:              103,
		CompositionBits:            104,
		ZeroKnowledgeBits:          105,
		RequiredPhaseAlgebraicBits: 97,
		PhaseAlgebraicSlackBits:    1,
		DominantSoundnessLimiter:   "full_game",
		LedgerTerms: []credential.SystemSecurityLedgerTerm{{
			Category: credential.SystemLedgerTermSoundness,
			Name:     "full_game",
			Bits:     100,
			Required: true,
			Status:   "pass",
		}},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ledger_status", "ledger_terms", "soundness_bits", "unlinkability_bits", "correctness_bits", "primitive_bits", "composition_bits", "zero_knowledge_bits", "required_phase_algebraic_bits", "phase_algebraic_slack_bits", "dominant_soundness_limiter"} {
		if !bytes.Contains(data, []byte(want)) {
			t.Fatalf("benchmark report JSON missing %s: %s", want, data)
		}
	}
}

func TestBenchmarkRequiredPhaseAlgebraicBitsForBQ32Current(t *testing.T) {
	fullGame := PIOP.FullGameSoundnessReport{
		AcceptedIssuance:     1,
		AcceptedShowing:      1,
		GlobalCollisionError: math.Pow(2, -99.67807190511263),
		GlobalCollisionBits:  99.67807190511263,
	}
	got := benchmarkRequiredPhaseAlgebraicBits(96, fullGame)
	if math.Abs(got-97.11735695063815) > 1e-9 {
		t.Fatalf("required phase algebraic bits=%f", got)
	}
}

func TestBenchmarkSecurityLedgerExplainsBQ32FullGameComponents(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetPilotN1024BQ32R96V2)
	if err != nil {
		t.Fatal(err)
	}
	cfg := benchmarkIntGenISISE2EConfig{
		PresetName:       preset.Name,
		SecurityProfile:  "BQ32-96",
		SecurityMode:     string(credential.SecurityModeResidualAtBudget),
		CoreBitsRequired: 128,
		PRFProfile:       preset.PRFProfile,
		PRFParamsPath:    credential.IntGenISISPRFParamsTag9,
		ThreatModel:      preset.ThreatModel,
		Issuance:         intGenISISTuning{TranscriptMode: intGenISISTranscriptModeSmallField2025},
		Showing:          intGenISISTuning{TranscriptMode: intGenISISTranscriptModeSmallField2025},
	}
	m := benchmarkIntGenISISMetrics{
		TheoremTotalBits:    96.00,
		AlgebraicTotalBits:  96.03,
		CollisionBits:       101.68,
		ROQueryCaps:         [5]int{1 << 32, 1 << 32, 1 << 32, 1 << 32, 1 << 32},
		ROQueryCapsSet:      true,
		DECSHashBits:        168,
		DECSTapeBits:        136,
		SaltBits:            168,
		TranscriptMode:      intGenISISTranscriptModeSmallField2025,
		EffectiveLambdaBits: 168,
	}
	ledger := benchmarkIntGenISISE2ESecurityLedger(
		cfg,
		credential.Ternary1024IntGenISISProfile(),
		m,
		m,
		PIOP.FullGameSoundnessReport{
			GlobalCollisionBits:         99.67807190511263,
			GlobalCollisionFullGameBits: 94.97,
		},
		true,
	)
	for _, name := range []string{"issuance_smallwood_extraction", "showing_smallwood_extraction", "ro_collision", "full_game", "challenge_bias"} {
		if ledgerTermByName(ledger, credential.SystemLedgerTermSoundness, name).Name == "" {
			t.Fatalf("missing soundness ledger component %q in %+v", name, ledger.Terms)
		}
	}
	for _, name := range []string{"tape_guessing", "programming_conflict"} {
		if ledgerTermByName(ledger, credential.SystemLedgerTermZeroKnowledge, name).Name == "" {
			t.Fatalf("missing zero-knowledge ledger component %q in %+v", name, ledger.Terms)
		}
	}
	fullGame := ledgerTermByName(ledger, credential.SystemLedgerTermSoundness, "full_game")
	if !fullGame.ReportOnly ||
		fullGame.Source != credential.SystemLedgerTermSourceExact ||
		fullGame.AccountingStatus != credential.SystemLedgerTermAccountingCurrentTheorem {
		t.Fatalf("full_game term=%+v", fullGame)
	}
	programming := ledgerTermByName(ledger, credential.SystemLedgerTermZeroKnowledge, "programming_conflict")
	if programming.Source != credential.SystemLedgerTermSourceConservative ||
		programming.AccountingStatus != credential.SystemLedgerTermAccountingRequiresTheory ||
		!programming.Conservative ||
		programming.Status != "pass" {
		t.Fatalf("programming term=%+v", programming)
	}
	if programming.Bits < 96 {
		t.Fatalf("programming placeholder accounting should clear BQ32-96: %+v", programming)
	}
	if tape := ledgerTermByName(ledger, credential.SystemLedgerTermZeroKnowledge, "tape_guessing"); tape.Status != "pass" {
		t.Fatalf("tape term should pass in zero-knowledge category: %+v", tape)
	}
	if ledgerTermByName(ledger, credential.SystemLedgerTermSoundness, "tape_guessing").Name != "" {
		t.Fatalf("tape term should not remain in soundness: %+v", ledger.Terms)
	}
	if ledger.SoundnessBits < 94.96 || ledger.SoundnessBits > 94.99 {
		t.Fatalf("soundness bits should reflect full-game composition blocker, got %f", ledger.SoundnessBits)
	}
	if ledger.ZeroKnowledgeBits <= 0 || ledger.ZeroKnowledgeBits < 96-1e-9 {
		t.Fatalf("zero-knowledge bits should clear target: %f", ledger.ZeroKnowledgeBits)
	}
	multiUser := ledgerTermByName(ledger, credential.SystemLedgerTermComposition, "multi_user")
	if multiUser.Required || multiUser.Status != "informational" {
		t.Fatalf("single-user scope should not create an active multi-user rejection: %+v", multiUser)
	}
	if !containsStringLocal(ledger.RejectionReasons, "full-game bits below target") {
		t.Fatalf("ledger did not explain full-game deficit: %+v", ledger.RejectionReasons)
	}
	if containsStringLocal(ledger.RejectionReasons, "programming conflict bits below target") {
		t.Fatalf("programming placeholder should not be reported as the current blocker: %+v", ledger.RejectionReasons)
	}
	if ledger.LedgerStatus != string(credential.SecurityProfileCandidate) || ledger.CompleteSystemClaim {
		t.Fatalf("BQ32 ledger should remain candidate-only: %+v", ledger)
	}
}

func TestBenchmarkIntGenISISE2EVerboseFlagParses(t *testing.T) {
	cfg, err := parseBenchmarkIntGenISISE2EConfig([]string{
		"-preset", credential.IntGenISISPresetN512Compact96,
		"-verbose",
	})
	if err != nil {
		t.Fatalf("parse verbose benchmark config: %v", err)
	}
	if !cfg.Verbose {
		t.Fatal("verbose flag was not carried into config")
	}
}

func TestBenchmarkPrintReportDefaultIsConcise(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	benchmarkIntGenISISE2EPrintReport(benchmarkIntGenISISE2EReport{
		Preset:      credential.IntGenISISPresetN512Compact96,
		Profile:     credential.ProfileIntGenISISB,
		ArtifactDir: "artifacts/n512-compact96",
		Timings: benchmarkIntGenISISE2ETimings{
			SetupPublicMS:    1,
			SetupNTRUKeysMS:  2,
			HolderCommitMS:   3,
			HolderProveMS:    4,
			IssuerSignMS:     5,
			HolderFinalizeMS: 6,
		},
		Showing: benchmarkIntGenISISMetrics{
			PaperTranscriptBytes: 22016,
			TheoremTotalBits:     96.5,
			ProvingMS:            7,
			VerificationMS:       8,
		},
		ReplayRejected: true,
	}, false)

	got := buf.String()
	for _, want := range []string{
		"status=pass",
		"preset=n512-compact96",
		"showing.paper_transcript_bytes=22016",
		"theorem_total_bits=96.50",
		"replay_rejected=true",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("concise benchmark output missing %q: %s", want, got)
		}
	}
	for _, stale := range []string{"paper_buckets", "source_bridge_constraints=0", "mdecs=0", "tapes=0", "compat_"} {
		if strings.Contains(got, stale) {
			t.Fatalf("concise benchmark output retained stale metric %q: %s", stale, got)
		}
	}
}

func TestBenchmarkMetricsJSONOmitsZeroOnlyFields(t *testing.T) {
	raw, err := json.Marshal(benchmarkIntGenISISMetrics{
		PaperTranscriptBytes: 22016,
		TheoremTotalBits:     96.5,
		PhaseTimings: nonZeroPhaseTimings([]PIOP.PhaseTiming{
			{Label: "cached", Milliseconds: 0},
			{Label: "prove", Milliseconds: 1.25},
		}),
	})
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	text := string(raw)
	for _, stale := range []string{
		`"mdecs_bytes":0`,
		`"tapes_bytes":0`,
		`"source_bridge_constraints":0`,
		`"ms":0`,
		`"cached"`,
	} {
		if strings.Contains(text, stale) {
			t.Fatalf("benchmark JSON retained stale field %q: %s", stale, text)
		}
	}
	if !strings.Contains(text, `"label":"prove"`) {
		t.Fatalf("benchmark JSON dropped non-zero timing: %s", text)
	}
}

func TestBenchmarkMetricsFromProofIncludesPaperBuckets(t *testing.T) {
	metrics := intGenISISMetricsFromProof(&PIOP.Proof{}, PIOP.ProofReport{
		PaperTranscript: PIOP.PaperTranscriptReport{
			OptimizedBytes: 128,
			Mdecs:          PIOP.PaperTranscriptBucket{OptimizedBytes: 7},
			Tapes:          PIOP.PaperTranscriptBucket{OptimizedBytes: 11},
		},
	}, PIOP.PublicInputs{}, PIOP.SimOpts{}, 0, 0, "test")
	if metrics.PaperTranscriptBytes != 128 {
		t.Fatalf("paper transcript bytes=%d want 128", metrics.PaperTranscriptBytes)
	}
	if metrics.MdecsBytes != 7 {
		t.Fatalf("mdecs bytes=%d want 7", metrics.MdecsBytes)
	}
	if metrics.TapesBytes != 11 {
		t.Fatalf("tapes bytes=%d want 11", metrics.TapesBytes)
	}
}

func TestCompleteSystemGateReportsUnavailableBeforeRunning(t *testing.T) {
	err := runGateCompleteSystemPresets([]string{"-artifact-dir", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "no complete-system deployment preset") {
		t.Fatalf("complete-system gate error=%v", err)
	}
}

func TestFunctionalGateIncludesEveryExecutablePreset(t *testing.T) {
	got := functionalPresetNames()
	want := credential.IntGenISISDefaultPresetNames()
	if len(got) != len(want) {
		t.Fatalf("functional presets=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("functional presets=%v want %v", got, want)
		}
		if _, err := credential.MustLookupIntGenISISPreset(got[i]); err != nil {
			t.Fatalf("functional preset %q does not resolve: %v", got[i], err)
		}
	}
}

func TestSpecializedPresetGatesAreRemoved(t *testing.T) {
	for _, command := range []string{"gate-proof-profiles", "gate-candidate-presets"} {
		if err := run([]string{command}); err == nil || !strings.Contains(err.Error(), "unknown subcommand") {
			t.Fatalf("removed command %q error=%v", command, err)
		}
	}
}

func TestSetupIntGenISISPublicWritesMaintainedProfileParams(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	for _, presetName := range []string{
		credential.IntGenISISPresetN512Compact96,
		credential.IntGenISISPresetN1024Compact125,
	} {
		t.Run(presetName, func(t *testing.T) {
			preset, err := credential.MustLookupIntGenISISPreset(presetName)
			if err != nil {
				t.Fatal(err)
			}
			profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
			if !ok {
				t.Fatalf("missing profile %s", preset.Profile)
			}
			tmp := t.TempDir()
			out := filepath.Join(tmp, "credential_public."+profile.Name+".json")
			bPath := filepath.Join(tmp, "Bmatrix."+profile.Name+".json")
			if err := run([]string{"setup-intgenisis-public", "-preset", presetName, "-out", out, "-force"}); err != nil {
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

func TestSetupNTRUKeysRejectsRemovedRingDegreeFlag(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	err := run([]string{
		"setup-ntru-keys",
		"-ring-degree", "256",
		"-params-out", filepath.Join(t.TempDir(), "params.json"),
	})
	if err == nil {
		t.Fatal("setup-ntru-keys accepted removed research degree")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") {
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
	if normalized.TranscriptMode != intGenISISTranscriptModeSmallField2025 {
		t.Fatalf("normalized issuance transcript mode=%q", normalized.TranscriptMode)
	}
	if normalized.TranscriptOmissionMode != credential.IntGenISISTranscriptOmissionModeV2 {
		t.Fatalf("normalized issuance transcript omission mode=%q", normalized.TranscriptOmissionMode)
	}
	overrides := intGenISISTuningToIssuanceOverrides(normalized, credential.Ternary1024IntGenISISProfile().N)
	if overrides.TranscriptMode != intGenISISTranscriptModeSmallField2025 {
		t.Fatalf("issuance override transcript mode=%q", overrides.TranscriptMode)
	}
	if overrides.TranscriptOmissionMode != credential.IntGenISISTranscriptOmissionModeV2 {
		t.Fatalf("issuance override transcript omission mode=%q", overrides.TranscriptOmissionMode)
	}
	if !overrides.FixedTranscriptSize {
		t.Fatalf("issuance override fixed transcript size=false")
	}
	opts := applyIssuanceRuntimeOverrides(PIOP.SimOpts{}, overrides)
	if opts.TranscriptVersion != PIOP.TranscriptVersionSmallWood2025V2 || opts.TranscriptProtocolMode != PIOP.TranscriptProtocolSmallField2025V2 {
		t.Fatalf("issuance opts transcript tuple=(%q,%q)", opts.TranscriptVersion, opts.TranscriptProtocolMode)
	}
	if opts.TranscriptOmissionMode != PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2 {
		t.Fatalf("issuance opts transcript omission mode=%q", opts.TranscriptOmissionMode)
	}
	if !opts.FixedTranscriptSize {
		t.Fatalf("issuance opts fixed transcript size=false")
	}
	spec := smallWoodTuningSpecFromOpts(opts)
	if spec.TranscriptMode != intGenISISTranscriptModeSmallField2025 {
		t.Fatalf("persisted SmallWood transcript mode=%q", spec.TranscriptMode)
	}
	if spec.TranscriptOmissionMode != credential.IntGenISISTranscriptOmissionModeV2 {
		t.Fatalf("persisted SmallWood transcript omission mode=%q", spec.TranscriptOmissionMode)
	}
	if !spec.FixedTranscriptSize {
		t.Fatalf("persisted SmallWood fixed transcript size=false")
	}
	roundTrip := persistedIssuanceRuntimeOverridesWithSmallWood(spec.NCols, spec.LVCSNCols, spec.NLeaves, nil, spec)
	if roundTrip.TranscriptMode != intGenISISTranscriptModeSmallField2025 {
		t.Fatalf("round-trip override transcript mode=%q", roundTrip.TranscriptMode)
	}
	if roundTrip.TranscriptOmissionMode != credential.IntGenISISTranscriptOmissionModeV2 {
		t.Fatalf("round-trip transcript omission mode=%q", roundTrip.TranscriptOmissionMode)
	}
	if !roundTrip.FixedTranscriptSize {
		t.Fatalf("round-trip fixed transcript size=false")
	}

	if !issuance.FixedTranscriptSize || issuance.TranscriptMode != intGenISISTranscriptModeSmallField2025 {
		t.Fatalf("preset issuance tuning lost maintained transcript defaults: %+v", issuance)
	}
}

func TestIssuanceSmallWoodAccountingOverridesRoundTrip(t *testing.T) {
	overrides := issuanceRuntimeOverrides{
		ROQueryCaps:         [5]int{0, 1, 2, 3, 4},
		ROQueryCapsSet:      true,
		ROQueryCapBits:      [5]float64{64, 64, 64, 64, 64},
		ROQueryCapBitsSet:   true,
		DECSCollisionBits:   256,
		DECSHashBits:        200,
		DECSTapeBits:        128,
		FSCollisionBits:     200,
		SaltBits:            128,
		DQOverride:          1200,
		FixedTranscriptSize: true,
	}
	opts := applyIssuanceRuntimeOverrides(PIOP.SimOpts{}, overrides)
	opts = PIOP.ResolveSimOptsDefaults(opts)
	spec := smallWoodTuningSpecFromOpts(opts)
	if !spec.ROQueryCapsSet {
		t.Fatal("persisted spec did not mark ro query caps explicit")
	}
	if spec.ROQueryCaps != overrides.ROQueryCaps {
		t.Fatalf("persisted ro query caps=%v", spec.ROQueryCaps)
	}
	if !spec.ROQueryCapBitsSet || spec.ROQueryCapBits != overrides.ROQueryCapBits {
		t.Fatalf("persisted ro query cap bits=%v set=%v", spec.ROQueryCapBits, spec.ROQueryCapBitsSet)
	}
	if spec.DECSCollisionBits != 256 {
		t.Fatalf("persisted decs collision bits=%d", spec.DECSCollisionBits)
	}
	if spec.DECSHashBits != 200 || spec.DECSTapeBits != 128 || spec.FSCollisionBits != 200 || spec.SaltBits != 128 {
		t.Fatalf("persisted split widths hash=%d tape=%d fs=%d salt=%d", spec.DECSHashBits, spec.DECSTapeBits, spec.FSCollisionBits, spec.SaltBits)
	}
	if spec.DQOverride != 1200 {
		t.Fatalf("persisted dQ override=%d", spec.DQOverride)
	}
	roundTrip := persistedIssuanceRuntimeOverridesWithSmallWood(spec.NCols, spec.LVCSNCols, spec.NLeaves, nil, spec)
	if !roundTrip.ROQueryCapsSet || roundTrip.ROQueryCaps != overrides.ROQueryCaps {
		t.Fatalf("round-trip query caps=%v set=%v", roundTrip.ROQueryCaps, roundTrip.ROQueryCapsSet)
	}
	if !roundTrip.ROQueryCapBitsSet || roundTrip.ROQueryCapBits != overrides.ROQueryCapBits {
		t.Fatalf("round-trip query cap bits=%v set=%v", roundTrip.ROQueryCapBits, roundTrip.ROQueryCapBitsSet)
	}
	if roundTrip.DECSCollisionBits != 256 {
		t.Fatalf("round-trip decs collision bits=%d", roundTrip.DECSCollisionBits)
	}
	if roundTrip.DECSHashBits != 200 || roundTrip.DECSTapeBits != 128 || roundTrip.FSCollisionBits != 200 || roundTrip.SaltBits != 128 {
		t.Fatalf("round-trip split widths hash=%d tape=%d fs=%d salt=%d", roundTrip.DECSHashBits, roundTrip.DECSTapeBits, roundTrip.FSCollisionBits, roundTrip.SaltBits)
	}
	if roundTrip.DQOverride != 1200 {
		t.Fatalf("round-trip dQ override=%d", roundTrip.DQOverride)
	}
}

func TestDeriveOmegaForIssuanceOptsUsesRelationAwareWitnessOmega(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)

	ringQ, err := credential.LoadRingWithDegree(0)
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
	holderSecret := filepath.Join(tmp, "holder_secret.json")
	commitRequest := filepath.Join(tmp, "commit_request.json")
	submission := filepath.Join(tmp, "presign_submission.json")
	if err := run([]string{"setup-intgenisis-public", "-preset", credential.IntGenISISPresetN512Compact96, "-out", publicPath, "-force"}); err != nil {
		t.Fatalf("setup-intgenisis-public: %v", err)
	}
	if err := run([]string{
		"holder-commit",
		"-preset", credential.IntGenISISPresetN512Compact96,
		"-public-params", publicPath,
		"-holder-secret", holderSecret,
		"-commit-request", commitRequest,
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
		"-preset", credential.IntGenISISPresetN512Compact96,
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
		CredentialPublicPath: "internal/source_data/credential_public.intgenisis_profile_b.json",
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

func TestIssueResponseBoundedHashInputsAreValidatedBeforeReduction(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{97})
	if err != nil {
		t.Fatal(err)
	}
	row := func() []int64 { return make([]int64, ringQ.N) }
	valid := issueResponseFile{
		MuSig: [][]int64{row()},
		X0:    [][]int64{row()},
		X1:    [][]int64{row()},
	}
	if _, err := signatureHashDataFromIssueResponse(ringQ, valid, 1, 1, 1); err != nil {
		t.Fatalf("valid bounded inputs rejected: %v", err)
	}
	for _, source := range []string{"mu_sig", "x0", "x1"} {
		t.Run(source, func(t *testing.T) {
			resp := issueResponseFile{
				MuSig: [][]int64{row()},
				X0:    [][]int64{row()},
				X1:    [][]int64{row()},
			}
			switch source {
			case "mu_sig":
				resp.MuSig[0][0] = int64(ringQ.Modulus[0]) + 1
			case "x0":
				resp.X0[0][0] = 2
			case "x1":
				resp.X1[0][0] = -2
			}
			if _, err := signatureHashDataFromIssueResponse(ringQ, resp, 1, 1, 1); err == nil || !strings.Contains(err.Error(), "outside ternary domain") {
				t.Fatalf("out-of-domain %s accepted before modular conversion: %v", source, err)
			}
		})
	}
	short := valid
	short.X1 = [][]int64{make([]int64, ringQ.N-1)}
	if _, err := signatureHashDataFromIssueResponse(ringQ, short, 1, 1, 1); err == nil || !strings.Contains(err.Error(), "coefficient length") {
		t.Fatalf("short x1 row accepted: %v", err)
	}
}

func TestIssueResponseRejectsRetiredSerializedTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issue_response.json")
	raw := []byte(`{"version":3,"credential_public_path":"public.json","t":[0],"mu_sig":[],"x0":[],"x1":[],"sig_s1":[],"sig_s2":[],"ntru_public":[]}`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	var resp issueResponseFile
	if err := readJSONFile(path, &resp); err == nil || !strings.Contains(err.Error(), "unknown field \"t\"") {
		t.Fatalf("retired target field accepted: %v", err)
	}
}

func TestIssuanceBLoaderChecksCanonicalCoefficientsWithoutRequiringNonzeroB0(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{97})
	if err != nil {
		t.Fatal(err)
	}
	rows := make([][]uint64, 4)
	for i := range rows {
		rows[i] = make([]uint64, ringQ.N)
	}
	rows[1][0] = 1
	rows[2][0] = 2
	rows[3][0] = 3
	path := filepath.Join(t.TempDir(), "Bmatrix.json")
	if err := ntrurio.SaveBMatrixCoeffs(path, rows); err != nil {
		t.Fatal(err)
	}
	public := credential.PublicParams{BPath: path, NC: 1, EllX0: 1}
	if _, err := loadBAsNTT(ringQ, public); err != nil {
		t.Fatalf("canonical B with zero-valued B0 rejected: %v", err)
	}
	rows[2][4] = ringQ.Modulus[0]
	if err := ntrurio.SaveBMatrixCoeffs(path, rows); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBAsNTT(ringQ, public); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("noncanonical B accepted: %v", err)
	}
}

func TestHolderFinalizeRejectsBoundedBBViolationsBeforePersisting(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)
	tmp := t.TempDir()
	presetID := credential.IntGenISISPresetN512Compact96
	publicPath := filepath.Join(tmp, "credential_public.json")
	holderSecret := filepath.Join(tmp, "holder_secret.json")
	commitRequest := filepath.Join(tmp, "commit_request.json")
	if err := run([]string{"setup-intgenisis-public", "-preset", presetID, "-out", publicPath, "-force"}); err != nil {
		t.Fatalf("setup public params: %v", err)
	}
	if err := run([]string{
		"holder-commit",
		"-preset", presetID,
		"-public-params", publicPath,
		"-holder-secret", holderSecret,
		"-commit-request", commitRequest,
	}); err != nil {
		t.Fatalf("holder commit: %v", err)
	}
	public, err := credential.LoadPublicParams(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := ntrurio.LoadBMatrixMetadata(public.BPath)
	if err != nil {
		t.Fatal(err)
	}
	// Make the valid ternary x1=0 noninvertible without changing any other
	// setup component. B0 remains the independently generated public row.
	meta.B[len(meta.B)-1] = make([]uint64, meta.RingDegree)
	if err := ntrurio.SaveBMatrixCoeffs(public.BPath, meta.B); err != nil {
		t.Fatal(err)
	}
	profile, ok := credential.LookupIntGenISISProfile(public.Profile)
	if !ok {
		t.Fatalf("unknown profile %q", public.Profile)
	}
	rows := func(count int) [][]int64 {
		out := make([][]int64, count)
		for i := range out {
			out[i] = make([]int64, profile.N)
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		tamper    func(*issueResponseFile)
		wantError string
	}{
		{
			name: "nonternary-x0",
			tamper: func(resp *issueResponseFile) {
				resp.X0[0][0] = 2
			},
			wantError: "outside ternary domain",
		},
		{
			name:      "noninvertible-x1",
			tamper:    func(*issueResponseFile) {},
			wantError: "denominator not invertible",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			responsePath := filepath.Join(tmp, tc.name+"-response.json")
			statePath := filepath.Join(tmp, tc.name+"-state.json")
			resp := issueResponseFile{
				Version:              issuanceArtifactVersion,
				CredentialPublicPath: publicPath,
				MuSig:                rows(profile.EllMuSig),
				X0:                   rows(profile.EllX0),
				X1:                   rows(profile.EllX1),
			}
			tc.tamper(&resp)
			if err := writeJSONFile(responsePath, resp, 0o644); err != nil {
				t.Fatal(err)
			}
			err := run([]string{
				"holder-finalize",
				"-preset", presetID,
				"-holder-secret", holderSecret,
				"-commit-request", commitRequest,
				"-issue-response", responsePath,
				"-state-out", statePath,
				"-ntru-params", filepath.Join(tmp, "not-reached-ntru-params.json"),
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("unexpected finalize result: %v", err)
			}
			if _, statErr := os.Stat(statePath); !os.IsNotExist(statErr) {
				t.Fatalf("credential state persisted after rejected response: %v", statErr)
			}
		})
	}
}

func TestHolderFinalizeBindsTrustedVerifierKeyBeforePersisting(t *testing.T) {
	root := issuanceTestRepoRoot(t)
	chdirForIssuanceTest(t, root)
	tmp := t.TempDir()
	presetID := credential.IntGenISISPresetN512Compact96
	publicPath := filepath.Join(tmp, "credential_public.json")
	holderSecretPath := filepath.Join(tmp, "holder_secret.json")
	commitRequestPath := filepath.Join(tmp, "commit_request.json")
	responsePath := filepath.Join(tmp, "issue_response.json")
	paramsPath := filepath.Join(tmp, "ntru_params.json")
	verifierKeyPath := filepath.Join(tmp, "verifier_key.json")
	statePath := filepath.Join(tmp, "credential_state.json")

	if err := run([]string{"setup-intgenisis-public", "-preset", presetID, "-out", publicPath, "-force"}); err != nil {
		t.Fatalf("setup public params: %v", err)
	}
	if err := run([]string{
		"holder-commit",
		"-preset", presetID,
		"-public-params", publicPath,
		"-holder-secret", holderSecretPath,
		"-commit-request", commitRequestPath,
	}); err != nil {
		t.Fatalf("holder commit: %v", err)
	}

	var secret holderSecretFile
	if err := readJSONFile(holderSecretPath, &secret); err != nil {
		t.Fatalf("read holder secret: %v", err)
	}
	rt, err := loadIssuanceRuntime(secret.CredentialPublicPath, secret.PRFParamsPath, persistedIssuanceRuntimeOverridesWithSmallWood(secret.PackedNCols, secret.LVCSNCols, secret.NLeaves, secret.Omega, secret.SmallWood))
	if err != nil {
		t.Fatalf("load issuance runtime: %v", err)
	}
	inputs, err := intGenISISInputsFromSecret(rt.ringQ, secret)
	if err != nil {
		t.Fatalf("load holder inputs: %v", err)
	}
	com, err := issuance.PrepareIntGenISISCommit(rt.params, inputs)
	if err != nil {
		t.Fatalf("prepare commitment: %v", err)
	}
	B, err := loadBAsNTT(rt.ringQ, rt.public)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	data, err := issuance.SampleSignatureHashData(rt.ringQ, B, rt.public.EllMuSig, rt.public.EllX0, mathrand.New(mathrand.NewSource(1)))
	if err != nil {
		t.Fatalf("sample bounded hash inputs: %v", err)
	}
	target, err := issuance.ComputeIntGenISISTarget(rt.ringQ, B, com, data)
	if err != nil {
		t.Fatalf("compute target: %v", err)
	}
	zeroPublic := [][]int64{make([]int64, rt.ringQ.N)}
	response := issueResponseFile{
		Version:              issuanceArtifactVersion,
		CredentialPublicPath: publicPath,
		MuSig:                polyVecToInt64(rt.ringQ, data.MuSig, false),
		X0:                   polyVecToInt64(rt.ringQ, data.X0, false),
		X1:                   polyVecToInt64(rt.ringQ, data.X1, false),
		SigS1:                make([]int64, rt.ringQ.N),
		SigS2:                append([]int64(nil), target.TCoeff...),
		NTRUPublic:           zeroPublic,
	}
	if err := writeJSONFile(responsePath, response, 0o644); err != nil {
		t.Fatalf("write response: %v", err)
	}
	if err := ntrurio.SaveParams(paramsPath, ntrurio.SystemParams{
		N:    rt.ringQ.N,
		Q:    rt.ringQ.Modulus[0],
		Beta: rt.ringQ.Modulus[0],
	}); err != nil {
		t.Fatalf("write NTRU params: %v", err)
	}
	publicDigest, err := credential.PublicParamsDigest(rt.public)
	if err != nil {
		t.Fatalf("digest public params: %v", err)
	}
	key := credential.IntGenISISVerifierKey{
		Version:              credential.IntGenISISVerifierKeyVersion,
		Profile:              rt.public.Profile,
		PresetID:             rt.public.PresetID,
		PresetVersion:        rt.public.PresetVersion,
		PresetManifestDigest: rt.public.PresetManifestDigest,
		RingDegree:           rt.ringQ.N,
		PublicParamsDigest:   publicDigest,
		NTRUPublic:           [][]int64{make([]int64, rt.ringQ.N)},
		SignatureBound:       int64(rt.ringQ.Modulus[0]),
	}

	mismatchedKey := key
	mismatchedKey.NTRUPublic = [][]int64{make([]int64, rt.ringQ.N)}
	mismatchedKey.NTRUPublic[0][0] = 1
	if err := credential.SaveIntGenISISVerifierKey(verifierKeyPath, mismatchedKey); err != nil {
		t.Fatalf("write mismatched verifier key: %v", err)
	}
	err = holderFinalize(holderSecretPath, commitRequestPath, "", responsePath, statePath, "", paramsPath, verifierKeyPath)
	if err == nil || !strings.Contains(err.Error(), "does not match trusted verifier key") {
		t.Fatalf("response under untrusted NTRU key accepted: %v", err)
	}
	if _, statErr := os.Stat(statePath); !os.IsNotExist(statErr) {
		t.Fatalf("credential state persisted after verifier-key mismatch: %v", statErr)
	}

	if err := credential.SaveIntGenISISVerifierKey(verifierKeyPath, key); err != nil {
		t.Fatalf("write matching verifier key: %v", err)
	}
	if err := holderFinalize(holderSecretPath, commitRequestPath, "", responsePath, statePath, "", paramsPath, verifierKeyPath); err != nil {
		t.Fatalf("finalize matching response: %v", err)
	}
	state, err := credential.LoadIntGenISISState(statePath)
	if err != nil {
		t.Fatalf("load persisted credential state: %v", err)
	}
	if err := state.ValidateAgainst(rt.public, key); err != nil {
		t.Fatalf("persisted state lost trusted issuer binding: %v", err)
	}
}

func ledgerTermByName(ledger credential.SystemSecurityLedger, category, name string) credential.SystemSecurityLedgerTerm {
	for _, term := range ledger.Terms {
		if term.Category == category && term.Name == name {
			return term
		}
	}
	return credential.SystemSecurityLedgerTerm{}
}

func TestBoundIssuanceOptionsRejectManifestMismatch(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetArtifactN1024SC125V2)
	if err != nil {
		t.Fatal(err)
	}
	params, err := prf.LoadLocalOrBundledParams(preset.PRFParamsPath)
	if err != nil {
		t.Fatal(err)
	}
	ringDegree := credential.Ternary1024IntGenISISProfile().N
	opts := defaultIssuanceOpts(params)
	opts.PRFParamsPath = preset.PRFParamsPath
	opts.RingDegree = ringDegree
	opts = applyIssuanceRuntimeOverrides(opts, intGenISISTuningToIssuanceOverrides(intGenISISTuningFromPresetSpec(preset.Issuance), ringDegree))
	opts = defaultIssuanceOptsResolved(params, opts)
	if err := validateBoundIssuanceOptions(opts, preset, params, ringDegree); err != nil {
		t.Fatalf("matching bound options rejected: %v", err)
	}
	opts.SaltBits++
	if err := validateBoundIssuanceOptions(opts, preset, params, ringDegree); err == nil {
		t.Fatal("modified salt width accepted under bound preset manifest")
	}
}

func containsStringLocal(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
