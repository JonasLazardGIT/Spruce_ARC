package main

import (
	"strings"
	"testing"

	"vSIS-Signature/credential"
)

func TestExecutablePresetReportRequiresPassingAuditAndTheoremTarget(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN512Compact96)
	if err != nil {
		t.Fatal(err)
	}
	report := benchmarkIntGenISISE2EReport{
		ReplayRejected: true,
		Issuance: benchmarkIntGenISISMetrics{
			ProofSizeBytes:   1,
			TheoremTotalBits: preset.TargetTheoremBits,
		},
		Showing: benchmarkIntGenISISMetrics{
			ProofSizeBytes:   1,
			TheoremTotalBits: preset.TargetTheoremBits,
		},
		ParameterAudit: credential.IntGenISISSecurityParameterAudit{Status: "pass"},
	}
	if err := validateExecutablePresetReport(preset, report); err != nil {
		t.Fatalf("valid executable preset report rejected: %v", err)
	}
	report.ParameterAudit = credential.IntGenISISSecurityParameterAudit{
		Status: "rejected",
		Mismatches: []credential.IntGenISISSecurityParameterMismatch{{
			Parameter: "prf_tag_elements",
			Required:  ">= 9",
			Actual:    "7",
		}},
	}
	if err := validateExecutablePresetReport(preset, report); err == nil || !strings.Contains(err.Error(), "parameter audit rejected") {
		t.Fatalf("rejected parameter audit error=%v", err)
	}
	report.ParameterAudit = credential.IntGenISISSecurityParameterAudit{Status: "pass"}
	report.Showing.TheoremTotalBits--
	if err := validateExecutablePresetReport(preset, report); err == nil || !strings.Contains(err.Error(), "below") {
		t.Fatalf("under-target theorem report error=%v", err)
	}
}
