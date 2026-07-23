package credential

import (
	"encoding/json"
	"os"
	"testing"
)

type removedPresetArchive struct {
	Version        int                    `json:"version"`
	Metric         string                 `json:"metric"`
	RemovedPresets []removedPresetFixture `json:"removed_presets"`
}

type removedPresetFixture struct {
	CanonicalID        string  `json:"canonical_id"`
	LegacySelector     string  `json:"legacy_selector"`
	SecurityProfile    string  `json:"security_profile"`
	IssuanceBytes      int     `json:"issuance_bytes"`
	ShowingBytes       int     `json:"showing_bytes"`
	CombinedBytes      int     `json:"combined_bytes"`
	MinimumTheoremBits float64 `json:"minimum_theorem_bits"`
	ParameterAudit     string  `json:"parameter_audit"`
	Disposition        string  `json:"disposition"`
	Reason             string  `json:"reason"`
}

func TestRemovedPresetArchiveIsCompleteAndNonExecutable(t *testing.T) {
	raw, err := os.ReadFile("testdata/removed_intgenisis_presets.json")
	if err != nil {
		t.Fatal(err)
	}
	var archive removedPresetArchive
	if err := json.Unmarshal(raw, &archive); err != nil {
		t.Fatal(err)
	}
	if archive.Version != 1 || archive.Metric != "paper_transcript_bytes" {
		t.Fatalf("archive header=%+v", archive)
	}
	if len(archive.RemovedPresets) != 8 {
		t.Fatalf("removed preset fixtures=%d want 8", len(archive.RemovedPresets))
	}
	seen := make(map[string]bool, len(archive.RemovedPresets))
	for _, fixture := range archive.RemovedPresets {
		if fixture.CanonicalID == "" || fixture.LegacySelector == "" || fixture.SecurityProfile == "" ||
			fixture.IssuanceBytes <= 0 || fixture.ShowingBytes <= 0 || fixture.MinimumTheoremBits <= 0 ||
			fixture.Disposition == "" || fixture.Reason == "" {
			t.Fatalf("incomplete removed preset fixture: %+v", fixture)
		}
		if fixture.CombinedBytes != fixture.IssuanceBytes+fixture.ShowingBytes {
			t.Fatalf("%s combined bytes=%d want %d", fixture.CanonicalID, fixture.CombinedBytes, fixture.IssuanceBytes+fixture.ShowingBytes)
		}
		if fixture.ParameterAudit != "pass" && fixture.ParameterAudit != "rejected" {
			t.Fatalf("%s invalid archived parameter audit %q", fixture.CanonicalID, fixture.ParameterAudit)
		}
		if seen[fixture.CanonicalID] {
			t.Fatalf("duplicate removed preset fixture %q", fixture.CanonicalID)
		}
		seen[fixture.CanonicalID] = true
		for _, selector := range []string{fixture.CanonicalID, fixture.LegacySelector} {
			if _, ok := LookupIntGenISISPreset(selector); ok {
				t.Fatalf("archived selector %q remains executable", selector)
			}
		}
	}
}
