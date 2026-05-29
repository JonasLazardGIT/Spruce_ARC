package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"vSIS-Signature/credential"
)

type degree1024PresetGate struct {
	Name           string
	MinTheoremBits float64
	MaxPaperBytes  int
}

func runGateDegree1024MaintainedPresets(args []string) error {
	fs := flag.NewFlagSet("gate-degree1024-maintained-presets", flag.ContinueOnError)
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

	gates := []degree1024PresetGate{
		{
			Name:           credential.IntGenISISPresetN1024Compact96,
			MinTheoremBits: 96,
			MaxPaperBytes:  27500,
		},
		{
			Name:           credential.IntGenISISPresetN1024Compact125,
			MinTheoremBits: 125,
			MaxPaperBytes:  35000,
		},
	}
	for _, gate := range gates {
		if err := runDegree1024PresetGate(root, gate); err != nil {
			return err
		}
	}
	return nil
}

func runDegree1024PresetGate(root string, gate degree1024PresetGate) error {
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
	showing := report.Showing
	if report.Modulus != credential.IntGenISISSharedModulusQ {
		return fmt.Errorf("%s q=%d, want %d", gate.Name, report.Modulus, credential.IntGenISISSharedModulusQ)
	}
	if showing.TheoremTotalBits < gate.MinTheoremBits {
		return fmt.Errorf("%s theorem bits %.2f below gate %.2f", gate.Name, showing.TheoremTotalBits, gate.MinTheoremBits)
	}
	if showing.PaperTranscriptBytes >= gate.MaxPaperBytes {
		return fmt.Errorf("%s paper transcript bytes %d above gate <%d", gate.Name, showing.PaperTranscriptBytes, gate.MaxPaperBytes)
	}
	if showing.TranscriptSecurityStatus != "smallwood_2025_1085_live" {
		return fmt.Errorf("%s transcript security status=%q, want smallwood_2025_1085_live", gate.Name, showing.TranscriptSecurityStatus)
	}
	for i, clamped := range showing.Clamped {
		if clamped {
			return fmt.Errorf("%s soundness round %d is clamped", gate.Name, i+1)
		}
	}
	fmt.Printf("%s gate passed: q=%d showing.paper_transcript_bytes=%d theorem_total_bits=%.2f status=%s\n",
		gate.Name,
		report.Modulus,
		showing.PaperTranscriptBytes,
		showing.TheoremTotalBits,
		showing.TranscriptSecurityStatus,
	)
	return nil
}
