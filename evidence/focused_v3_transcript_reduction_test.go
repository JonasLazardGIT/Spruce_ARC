package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFocusedV3TranscriptReductionEvidence(t *testing.T) {
	path := filepath.Join("focused-v3-transcript-reduction.json")
	e, err := ReadFocusedV3TranscriptReductionEvidence(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFocusedV3TranscriptReductionEvidence(e); err != nil {
		t.Fatal(err)
	}
	// Raw benchmark bundles are intentionally ignored. Keep the ordinary test
	// hermetic while upgrading to the full artifact gate whenever the local
	// reproduction bundle is installed.
	for _, target := range e.Targets {
		for _, run := range target.Runs {
			if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(run.ReportPath))); os.IsNotExist(err) {
				t.Skip("focused-v3 transcript-reduction raw artifacts are not installed; summary contract passed")
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := ValidateFocusedV3TranscriptReductionArtifacts(e, ".."); err != nil {
		t.Fatal(err)
	}
}

func TestFocusedV3TranscriptReductionRejectsRegression(t *testing.T) {
	e, err := ReadFocusedV3TranscriptReductionEvidence(filepath.Join("focused-v3-transcript-reduction.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.Targets[0].Medians.ShowingProofWireBytes = e.Targets[0].PriorV3.ShowingProofWireBytes
	if err := ValidateFocusedV3TranscriptReductionEvidence(e); err == nil {
		t.Fatal("accepted a showing-proof size regression")
	}
}

func TestFocusedV3TranscriptReductionRejectsFrozenParameterChange(t *testing.T) {
	e, err := ReadFocusedV3TranscriptReductionEvidence(filepath.Join("focused-v3-transcript-reduction.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.Targets[0].Frozen.Showing.NLeaves++
	if err := ValidateFocusedV3TranscriptReductionEvidence(e); err == nil {
		t.Fatal("accepted a frozen NLeaves change")
	}
}

func TestFocusedV3TranscriptReductionRejectsFailedSecurityGate(t *testing.T) {
	e, err := ReadFocusedV3TranscriptReductionEvidence(filepath.Join("focused-v3-transcript-reduction.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.Targets[1].Runs[0].ShowingZKEligible = false
	if err := ValidateFocusedV3TranscriptReductionEvidence(e); err == nil {
		t.Fatal("accepted a failed showing zero-knowledge gate")
	}
}
