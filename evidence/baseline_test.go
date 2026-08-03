package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vSIS-Signature/credential"
)

func TestThreeRunBaselineBindsRunsAndIndependentMedians(t *testing.T) {
	reportsDir := t.TempDir()
	preset := mustTestPreset(t)
	writeSyntheticRunsForPreset(t, reportsDir, preset)
	baselines, err := GenerateThreeRunBaselines(BaselineOptions{
		SPRUCE_DIR: testSPRUCE_DIR(t), ReportsDir: reportsDir, CanonicalPresetID: preset.CanonicalID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(baselines) != 1 {
		t.Fatalf("got %d baselines", len(baselines))
	}
	baseline := baselines[0]
	if baseline.Schema != BaselineSchemaV2 || baseline.Version != BaselineVersionV2 ||
		baseline.Aggregation != BaselineAggregationV2 || baseline.RunCount != 3 || len(baseline.Runs) != 3 {
		t.Fatalf("unexpected baseline identity: %+v", baseline)
	}
	for i, run := range baseline.Runs {
		if run.Run != i+1 || len(run.Digest) != 64 || run.GeneratedAt == "" {
			t.Fatalf("invalid run provenance: %+v", run)
		}
	}
	want := BaselineTimings{
		Setup:    SetupTimings{SetupPublicMS: 10, SetupNTRUKeysMS: 20, HolderCommitMS: 30, HolderProveMS: 40, IssuerSignMS: 50, HolderFinalizeMS: 60},
		Issuance: PhaseTimings{ProvingMS: 20, VerificationMS: 15},
		Showing:  PhaseTimings{ProvingMS: 200, VerificationMS: 8},
	}
	if baseline.MedianTimings != want {
		t.Fatalf("median timings=%+v want %+v", baseline.MedianTimings, want)
	}
	canonical, err := os.ReadFile(filepath.Join(reportsDir, preset.CanonicalID, DefaultBenchmarkFileName))
	if err != nil {
		t.Fatal(err)
	}
	runTwo, err := os.ReadFile(filepath.Join(reportsDir, preset.CanonicalID, "runs", "run-02.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, runTwo) {
		t.Fatal("canonical report is not a byte-for-byte copy of run 02")
	}
	var report benchmarkReportWire
	if err := decodeStrictJSON(canonical, &report); err != nil {
		t.Fatal(err)
	}
	if report.Timings.SetupPublicMS == baseline.MedianTimings.Setup.SetupPublicMS {
		t.Fatal("test did not distinguish real canonical-run timings from independent medians")
	}
}

func TestThreeRunBaselineRejectsUnstableEvidence(t *testing.T) {
	tests := []struct {
		name string
		want string
		edit func(*benchmarkReportWire)
	}{
		{"bytes", "byte accounting differs", func(report *benchmarkReportWire) { report.Showing.PaperTranscriptBytes++ }},
		{"geometry", "geometry/relation accounting differs", func(report *benchmarkReportWire) {
			report.Showing.TotalRows++
			report.Showing.RelationCandidate.LogicalRows++
			report.Showing.RelationCandidate.RowCounts["total"]++
		}},
		{"security", "security accounting differs", func(report *benchmarkReportWire) { report.SoundnessBits++ }},
		{"environment", "benchmark environment differs", func(report *benchmarkReportWire) { report.Environment.NumCPU++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reportsDir := t.TempDir()
			preset := mustTestPreset(t)
			writeSyntheticRunsForPreset(t, reportsDir, preset)
			path := filepath.Join(reportsDir, preset.CanonicalID, "runs", "run-03.json")
			report, _, err := decodeBenchmarkReport(path)
			if err != nil {
				t.Fatal(err)
			}
			test.edit(&report)
			writeTestBenchmarkReport(t, path, report)
			_, err = GenerateThreeRunBaselines(BaselineOptions{
				SPRUCE_DIR: testSPRUCE_DIR(t), ReportsDir: reportsDir, CanonicalPresetID: preset.CanonicalID,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unstable %s evidence accepted: %v", test.name, err)
			}
		})
	}
}

func TestThreeRunBaselineAllowsOnlyMeasuredValidPrefixVariation(t *testing.T) {
	reportsDir := t.TempDir()
	preset := mustTestPreset(t)
	writeSyntheticRunsForPreset(t, reportsDir, preset)
	for run := 1; run <= BaselineRunCountV2; run++ {
		path := filepath.Join(reportsDir, preset.CanonicalID, "runs", baselineRunFileName(run))
		report, _, err := decodeBenchmarkReport(path)
		if err != nil {
			t.Fatal(err)
		}
		report.ValidPrefixCost = credential.ValidPrefixCostReport{
			Model: "measured_structural",
			Rounds: []credential.ValidPrefixRoundCost{{
				Round: 1, Label: "fs_round_1", PrefixPredicate: "stable predicate",
				StructuralPrerequisites: []string{"stable prerequisite"},
				MeasuredCumulativeMS:    float64(run * 10), EstimatedHashEquivalentLog2: float64(run),
				RawCapLog2: 64, ValidPrefixCapLog2: 64, AccountingStatus: "conservative_raw_fallback",
			}},
		}
		writeTestBenchmarkReport(t, path, report)
	}
	if _, err := GenerateThreeRunBaselines(BaselineOptions{
		SPRUCE_DIR: testSPRUCE_DIR(t), ReportsDir: reportsDir, CanonicalPresetID: preset.CanonicalID,
	}); err != nil {
		t.Fatalf("measured valid-prefix timing variation rejected: %v", err)
	}

	path := filepath.Join(reportsDir, preset.CanonicalID, "runs", baselineRunFileName(3))
	report, _, err := decodeBenchmarkReport(path)
	if err != nil {
		t.Fatal(err)
	}
	report.ValidPrefixCost.Rounds[0].PrefixPredicate = "tampered predicate"
	writeTestBenchmarkReport(t, path, report)
	if _, err := GenerateThreeRunBaselines(BaselineOptions{
		SPRUCE_DIR: testSPRUCE_DIR(t), ReportsDir: reportsDir, CanonicalPresetID: preset.CanonicalID,
	}); err == nil || !strings.Contains(err.Error(), "security accounting differs") {
		t.Fatalf("structural valid-prefix variation accepted: %v", err)
	}
}

func TestThreeRunBaselineRejectsExtraRunAndStrictSidecarTampering(t *testing.T) {
	reportsDir := t.TempDir()
	preset := mustTestPreset(t)
	writeSyntheticRunsForPreset(t, reportsDir, preset)
	runsDir := filepath.Join(reportsDir, preset.CanonicalID, "runs")
	if err := os.WriteFile(filepath.Join(runsDir, "run-04.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := GenerateThreeRunBaselines(BaselineOptions{
		SPRUCE_DIR: testSPRUCE_DIR(t), ReportsDir: reportsDir, CanonicalPresetID: preset.CanonicalID,
	})
	if err == nil || !strings.Contains(err.Error(), "exactly run-01.json through run-03.json") {
		t.Fatalf("extra run accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(runsDir, "run-04.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateThreeRunBaselines(BaselineOptions{
		SPRUCE_DIR: testSPRUCE_DIR(t), ReportsDir: reportsDir, CanonicalPresetID: preset.CanonicalID,
	}); err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(reportsDir, preset.CanonicalID, DefaultBaselineFileName)
	data, err := os.ReadFile(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), bytes.TrimSpace(data)...)
	unknown = append(unknown[:len(unknown)-1], []byte(`,"legacy_runs":1}`)...)
	if err := os.WriteFile(sidecar, unknown, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAndValidateBaseline(reportsDir, preset); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown sidecar field accepted: %v", err)
	}
}

func TestThreeRunBaselineRejectsSidecarMedianTampering(t *testing.T) {
	reportsDir := t.TempDir()
	preset := mustTestPreset(t)
	writeSyntheticRunsForPreset(t, reportsDir, preset)
	if _, err := GenerateThreeRunBaselines(BaselineOptions{
		SPRUCE_DIR: testSPRUCE_DIR(t), ReportsDir: reportsDir, CanonicalPresetID: preset.CanonicalID,
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(reportsDir, preset.CanonicalID, DefaultBaselineFileName)
	document, _, err := decodeBaselineDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	document.MedianTimings.Showing.ProvingMS++
	encoded, err := marshalBaselineDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAndValidateBaseline(reportsDir, preset); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered median accepted: %v", err)
	}
}

func mustTestPreset(t *testing.T) credential.IntGenISISPreset {
	t.Helper()
	preset, ok := credential.LookupIntGenISISPreset(canonicalV2PresetIDs[0])
	if !ok {
		t.Fatal("missing canonical test preset")
	}
	return preset
}

func writeTestBenchmarkReport(t *testing.T, path string, report benchmarkReportWire) {
	t.Helper()
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
