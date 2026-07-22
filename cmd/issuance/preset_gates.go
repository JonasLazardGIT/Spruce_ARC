package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vSIS-Signature/credential"
)

type presetReportValidator func(credential.IntGenISISPreset, benchmarkIntGenISISE2EReport) error

func runGateFunctionalPresets(args []string) error {
	names := functionalPresetNames()
	return runPresetReportGateCommand("gate-functional-presets", args, names, func(preset credential.IntGenISISPreset, report benchmarkIntGenISISE2EReport) error {
		if err := validateFunctionalPresetReport(report); err != nil {
			return err
		}
		fmt.Printf("%s functional=pass parameter_audit=%s ledger=%s\n", preset.CanonicalID, report.ParameterAudit.Status, report.SecurityLedger.LedgerStatus)
		return nil
	})
}

func functionalPresetNames() []string {
	return credential.IntGenISISDefaultPresetNames()
}

func validateFunctionalPresetReport(report benchmarkIntGenISISE2EReport) error {
	if !report.ReplayRejected {
		return fmt.Errorf("replay rejection did not pass")
	}
	if report.Issuance.ProofSizeBytes <= 0 || report.Showing.ProofSizeBytes <= 0 {
		return fmt.Errorf("missing serialized issuance/showing proof")
	}
	return nil
}

func validatePresetTheoremTarget(preset credential.IntGenISISPreset, report benchmarkIntGenISISE2EReport) error {
	if report.Issuance.TheoremTotalBits < preset.TargetTheoremBits || report.Showing.TheoremTotalBits < preset.TargetTheoremBits {
		return fmt.Errorf("measured theorem bits issuance=%.2f showing=%.2f below %.2f", report.Issuance.TheoremTotalBits, report.Showing.TheoremTotalBits, preset.TargetTheoremBits)
	}
	return nil
}

func runGateProofProfiles(args []string) error {
	fs := flag.NewFlagSet("gate-proof-profiles", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	includeResearch := fs.Bool("research", false, "include public research proof profiles")
	root := fs.String("artifact-dir", "", "artifact root; defaults to a temporary directory")
	keep := fs.Bool("keep-artifacts", false, "keep temporary artifacts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	names := []string{
		credential.IntGenISISPresetPoCN512SC96V1,
		credential.IntGenISISPresetArtifactN1024SC96V1,
		credential.IntGenISISPresetArtifactN1024SC125V1,
		credential.IntGenISISPresetPilotN1024BQ32R96V1,
	}
	if *includeResearch {
		names = append(names, credential.IntGenISISPresetResearchN1024BQ32R128V1, credential.IntGenISISPresetResearchN1024BQ128R128V1)
	}
	forward := []string{}
	if *root != "" {
		forward = append(forward, "-artifact-dir", *root)
	}
	if *keep {
		forward = append(forward, "-keep-artifacts")
	}
	return runPresetReportGateCommandWithParsedFlags("gate-proof-profiles", forward, names, func(preset credential.IntGenISISPreset, report benchmarkIntGenISISE2EReport) error {
		if err := validateFunctionalPresetReport(report); err != nil {
			return err
		}
		if err := validatePresetTheoremTarget(preset, report); err != nil {
			return err
		}
		if err := validateProofProfileParameterAudit(preset, report.ParameterAudit); err != nil {
			return err
		}
		return nil
	})
}

func validateProofProfileParameterAudit(preset credential.IntGenISISPreset, audit credential.IntGenISISSecurityParameterAudit) error {
	if len(audit.MissingActual) != 0 || len(audit.MissingEvidence) != 0 {
		return fmt.Errorf("executed proof metadata is incomplete: missing=%v evidence=%v", audit.MissingActual, audit.MissingEvidence)
	}
	spec, _ := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	for _, mismatch := range audit.Mismatches {
		if preset.Lifecycle == credential.PresetResearch && preset.ClaimScope == credential.ClaimProofOnly && spec.Status == credential.SecurityProfileRequiresNewPrimitives && mismatch.Parameter == "prf_tag_elements" {
			continue
		}
		return fmt.Errorf("executed proof parameter mismatch: %+v", mismatch)
	}
	return nil
}

func runGateCandidatePresets(args []string) error {
	return runPresetReportGateCommand("gate-candidate-presets", args, []string{credential.IntGenISISPresetPilotN1024BQ32R96V1}, func(preset credential.IntGenISISPreset, report benchmarkIntGenISISE2EReport) error {
		if preset.Lifecycle != credential.PresetCandidate || preset.ClaimScope != credential.ClaimCompleteSystem {
			return fmt.Errorf("candidate classification mismatch")
		}
		if err := validateFunctionalPresetReport(report); err != nil {
			return err
		}
		if err := validatePresetTheoremTarget(preset, report); err != nil {
			return err
		}
		if report.ParameterAudit.Status != "pass" {
			return fmt.Errorf("executed parameters do not meet candidate requirements: missing=%v evidence=%v mismatches=%v", report.ParameterAudit.MissingActual, report.ParameterAudit.MissingEvidence, report.ParameterAudit.Mismatches)
		}
		if report.SecurityLedger.CompleteSystemClaim || len(report.SecurityLedger.RejectionReasons) == 0 {
			return fmt.Errorf("candidate must remain blocked with explicit ledger reasons")
		}
		fmt.Printf("%s blockers: %s\n", preset.CanonicalID, strings.Join(report.SecurityLedger.RejectionReasons, "; "))
		return nil
	})
}

func runGateCompleteSystemPresets(args []string) error {
	names := make([]string, 0)
	for _, name := range credential.IntGenISISPresetNames() {
		preset, _ := credential.LookupIntGenISISPreset(name)
		if preset.Lifecycle == credential.PresetComplete && preset.ClaimScope == credential.ClaimCompleteSystem && preset.CompleteSystemClaim {
			names = append(names, preset.CanonicalID)
		}
	}
	if len(names) == 0 {
		return fmt.Errorf("no complete-system deployment preset is currently available")
	}
	return runPresetReportGateCommand("gate-complete-system-presets", args, names, func(preset credential.IntGenISISPreset, report benchmarkIntGenISISE2EReport) error {
		if err := validateFunctionalPresetReport(report); err != nil {
			return err
		}
		if err := validatePresetTheoremTarget(preset, report); err != nil {
			return err
		}
		if report.ParameterAudit.Status != "pass" || report.SecurityLedger.LedgerStatus != string(credential.SecurityProfileCompleteLive) || !report.SecurityLedger.CompleteSystemClaim {
			return fmt.Errorf("complete-system ledger did not pass: %s", strings.Join(report.SecurityLedger.RejectionReasons, "; "))
		}
		if report.SecurityLedger.ValidPrefixConservative {
			return fmt.Errorf("complete preset relies on conservative valid-prefix accounting")
		}
		for _, term := range report.SecurityLedger.Terms {
			if term.Required && (term.ReportOnly || term.Source == credential.SystemLedgerTermSourceMissing || term.AccountingStatus == credential.SystemLedgerTermAccountingRequiresTheory) {
				return fmt.Errorf("required ledger term %s/%s is not complete-grade", term.Category, term.Name)
			}
		}
		if preset.SoundnessGate != "smallwood_2025_1085_live" {
			return fmt.Errorf("complete preset uses non-live soundness gate %q", preset.SoundnessGate)
		}
		return nil
	})
}

func runPresetReportGateCommand(name string, args, presets []string, validate presetReportValidator) error {
	return runPresetReportGateCommandWithParsedFlags(name, args, presets, validate)
}

func runPresetReportGateCommandWithParsedFlags(name string, args, presets []string, validate presetReportValidator) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactRoot := fs.String("artifact-dir", "", "artifact root; defaults to a temporary directory")
	keepArtifacts := fs.Bool("keep-artifacts", false, "keep temporary artifacts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	root := *artifactRoot
	if root == "" {
		var err error
		root, err = os.MkdirTemp("", "spruce-preset-gate-*")
		if err != nil {
			return err
		}
		if !*keepArtifacts {
			defer os.RemoveAll(root)
		}
	} else if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	for _, selector := range presets {
		preset, err := credential.MustLookupIntGenISISPreset(selector)
		if err != nil {
			return err
		}
		reportPath := filepath.Join(root, preset.CanonicalID+".json")
		artifactDir := filepath.Join(root, preset.CanonicalID)
		if err := runBenchmarkIntGenISISE2E([]string{"-preset", selector, "-artifact-dir", artifactDir, "-json-out", reportPath, "-force"}); err != nil {
			return fmt.Errorf("%s benchmark: %w", preset.CanonicalID, err)
		}
		data, err := os.ReadFile(reportPath)
		if err != nil {
			return err
		}
		var report benchmarkIntGenISISE2EReport
		if err := json.Unmarshal(data, &report); err != nil {
			return err
		}
		if report.CanonicalPresetID != preset.CanonicalID || report.PresetVersion != preset.PresetVersion || report.PresetManifestDigest != credential.IntGenISISPresetManifestDigest(preset) {
			return fmt.Errorf("%s: report canonical manifest binding mismatch", preset.CanonicalID)
		}
		if report.Profile != preset.Profile || report.SecurityProfile != preset.SecurityProfile || report.SecurityMode != preset.SecurityMode {
			return fmt.Errorf("%s: report primitive or security profile mismatch", preset.CanonicalID)
		}
		if report.PresetLifecycle != preset.Lifecycle || report.ClaimScope != preset.ClaimScope || report.PrimitiveProfileID != preset.PrimitiveProfileID || report.ThreatModel != preset.ThreatModel {
			return fmt.Errorf("%s: report classification or threat-model binding mismatch", preset.CanonicalID)
		}
		if report.PRFProfile != preset.PRFProfile || report.PRFParamsDigest != preset.PRFParamsDigest {
			return fmt.Errorf("%s: report PRF binding mismatch", preset.CanonicalID)
		}
		if err := validate(preset, report); err != nil {
			return fmt.Errorf("%s: %w", preset.CanonicalID, err)
		}
	}
	return nil
}
