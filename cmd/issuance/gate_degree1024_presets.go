package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"vSIS-Signature/credential"
)

type maintainedPresetGate struct {
	Name                       string
	MinTheoremBits             float64
	ExpectedIssuancePaperBytes int
	ExpectedShowingPaperBytes  int
	ExpectedCombinedPaperBytes int
}

func runGateMaintainedPresets(args []string) error {
	log.Printf("[issuance-cli] gate-maintained-presets is deprecated; running gate-artifact-presets")
	return runMaintainedPresetGateCommand("gate-maintained-presets", args, allMaintainedPresetGates())
}

func runGateArtifactPresets(args []string) error {
	return runMaintainedPresetGateCommand("gate-artifact-presets", args, allMaintainedPresetGates())
}

func runGateDegree1024MaintainedPresets(args []string) error {
	return runMaintainedPresetGateCommand("gate-degree1024-maintained-presets", args, degree1024MaintainedPresetGates())
}

func runMaintainedPresetGateCommand(name string, args []string, gates []maintainedPresetGate) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactRoot := fs.String("artifact-dir", "", "artifact root for live benchmark artifacts; defaults to a temporary directory")
	artifactRootAlias := fs.String("artifact-root", "", "alias for -artifact-dir")
	keepArtifacts := fs.Bool("keep-artifacts", false, "keep temporary artifacts when artifact-dir is omitted")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root := *artifactRoot
	if root == "" {
		root = *artifactRootAlias
	}
	var err error
	if root == "" {
		root, err = os.MkdirTemp("", "spruce-degree1024-gate-*")
		if err != nil {
			return fmt.Errorf("create temporary artifact root: %w", err)
		}
		if !*keepArtifacts {
			defer os.RemoveAll(root)
		}
	} else if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("create artifact root %s: %w", root, err)
	}

	for _, gate := range gates {
		if err := runMaintainedPresetGate(root, gate); err != nil {
			return err
		}
	}
	return nil
}

func allMaintainedPresetGates() []maintainedPresetGate {
	gates := []maintainedPresetGate{
		{
			Name:                       credential.IntGenISISPresetPoCN512SC96V2,
			MinTheoremBits:             96,
			ExpectedIssuancePaperBytes: 15283,
			ExpectedShowingPaperBytes:  23963,
			ExpectedCombinedPaperBytes: 39246,
		},
	}
	return append(gates, degree1024MaintainedPresetGates()...)
}

func degree1024MaintainedPresetGates() []maintainedPresetGate {
	return []maintainedPresetGate{
		{
			Name:                       credential.IntGenISISPresetArtifactN1024SC125V2,
			MinTheoremBits:             125,
			ExpectedIssuancePaperBytes: 23926,
			ExpectedShowingPaperBytes:  40150,
			ExpectedCombinedPaperBytes: 64076,
		},
		{
			Name:                       "artifact-n1024-bq10-r96-v2",
			MinTheoremBits:             96,
			ExpectedIssuancePaperBytes: 19113,
			ExpectedShowingPaperBytes:  34388,
			ExpectedCombinedPaperBytes: 53501,
		},
		{
			Name:                       "artifact-n1024-bq16-r96-v2",
			MinTheoremBits:             96,
			ExpectedIssuancePaperBytes: 20592,
			ExpectedShowingPaperBytes:  35000,
			ExpectedCombinedPaperBytes: 55592,
		},
		{
			Name:                       credential.IntGenISISPresetPilotN1024BQ32R96V2,
			MinTheoremBits:             96,
			ExpectedIssuancePaperBytes: 24859,
			ExpectedShowingPaperBytes:  41159,
			ExpectedCombinedPaperBytes: 66018,
		},
		{
			Name:                       credential.IntGenISISPresetPoCN1024BQ64R128V2,
			MinTheoremBits:             128,
			ExpectedIssuancePaperBytes: 39950,
			ExpectedShowingPaperBytes:  64350,
			ExpectedCombinedPaperBytes: 104300,
		},
		{
			Name:                       credential.IntGenISISPresetPoCN1024BQ96R128V2,
			MinTheoremBits:             128,
			ExpectedIssuancePaperBytes: 52472,
			ExpectedShowingPaperBytes:  82972,
			ExpectedCombinedPaperBytes: 135444,
		},
		{
			Name:                       credential.IntGenISISPresetPoCN1024BQ128R128V3,
			MinTheoremBits:             128,
			ExpectedIssuancePaperBytes: 62029,
			ExpectedShowingPaperBytes:  96254,
			ExpectedCombinedPaperBytes: 158283,
		},
		{
			Name:                       credential.IntGenISISPresetSystemN1024WF128CROMV2,
			MinTheoremBits:             128,
			ExpectedIssuancePaperBytes: 26515,
			ExpectedShowingPaperBytes:  42739,
			ExpectedCombinedPaperBytes: 69254,
		},
	}
}

func runMaintainedPresetGate(root string, gate maintainedPresetGate) error {
	reportPath := filepath.Join(root, gate.Name+".json")
	artifactDir := filepath.Join(root, gate.Name)
	benchArgs := []string{
		"-preset", gate.Name,
		"-artifact-dir", artifactDir,
		"-json-out", reportPath,
		"-force",
	}
	if err := runBenchmarkIntGenISISE2E(benchArgs); err != nil {
		return fmt.Errorf("%s live benchmark: %w", gate.Name, err)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("%s read benchmark report: %w", gate.Name, err)
	}
	var report benchmarkIntGenISISE2EReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("%s decode benchmark report: %w", gate.Name, err)
	}
	issuance := report.Issuance
	showing := report.Showing
	combinedPaperBytes := issuance.PaperTranscriptBytes + showing.PaperTranscriptBytes
	if report.CanonicalPresetID != gate.Name {
		return fmt.Errorf("%s benchmark reported canonical preset ID %q", gate.Name, report.CanonicalPresetID)
	}
	if report.Modulus != credential.IntGenISISSharedModulusQ {
		return fmt.Errorf("%s q=%d, want %d", gate.Name, report.Modulus, credential.IntGenISISSharedModulusQ)
	}
	if showing.TheoremTotalBits < gate.MinTheoremBits {
		return fmt.Errorf("%s theorem bits %.2f below gate %.2f", gate.Name, showing.TheoremTotalBits, gate.MinTheoremBits)
	}
	if issuance.PaperTranscriptBytes != gate.ExpectedIssuancePaperBytes {
		return fmt.Errorf("%s issuance paper transcript bytes=%d, want %d", gate.Name, issuance.PaperTranscriptBytes, gate.ExpectedIssuancePaperBytes)
	}
	if showing.PaperTranscriptBytes != gate.ExpectedShowingPaperBytes {
		return fmt.Errorf("%s showing paper transcript bytes=%d, want %d", gate.Name, showing.PaperTranscriptBytes, gate.ExpectedShowingPaperBytes)
	}
	if combinedPaperBytes != gate.ExpectedCombinedPaperBytes {
		return fmt.Errorf("%s combined paper transcript bytes=%d, want %d", gate.Name, combinedPaperBytes, gate.ExpectedCombinedPaperBytes)
	}
	if showing.TranscriptSecurityStatus != credential.IntGenISISSecurityGateV2 {
		return fmt.Errorf("%s transcript security status=%q, want %s", gate.Name, showing.TranscriptSecurityStatus, credential.IntGenISISSecurityGateV2)
	}
	for i, clamped := range showing.Clamped {
		if clamped {
			return fmt.Errorf("%s soundness round %d is clamped", gate.Name, i+1)
		}
	}
	fmt.Printf("%s gate passed: q=%d issuance.paper_transcript_bytes=%d showing.paper_transcript_bytes=%d combined.paper_transcript_bytes=%d theorem_total_bits=%.2f status=%s\n",
		gate.Name,
		report.Modulus,
		issuance.PaperTranscriptBytes,
		showing.PaperTranscriptBytes,
		combinedPaperBytes,
		showing.TheoremTotalBits,
		showing.TranscriptSecurityStatus,
	)
	return nil
}
