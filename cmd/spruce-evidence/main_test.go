package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vSIS-Signature/evidence"
)

func TestExportAndValidatePendingFromFlags(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	reports := filepath.Join(tmp, "reports")
	lock := filepath.Join(tmp, "evidence.lock.json")
	generated := filepath.Join(tmp, "generated")
	if err := run([]string{
		"export", "--spruce-dir", root, "--reports-dir", reports,
		"--lock-out", lock, "--paper-generated-dir", generated, "--allow-pending",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(generated, evidence.GeneratedMacrosFileName)); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"validate", "--spruce-dir", root, "--reports-dir", reports,
		"--lock", lock, "--paper-generated-dir", generated, "--allow-pending",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExportRequiresPaperGeneratedDirectory(t *testing.T) {
	if err := run([]string{"export", "--allow-pending"}); err == nil {
		t.Fatal("export accepted a missing paper generated directory")
	}
}

func TestBaselineRejectsNonCanonicalPreset(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	err = run([]string{"baseline", "--spruce-dir", root, "--reports-dir", t.TempDir(), "--preset", "poc-n512-sc96-v1"})
	if err == nil || !strings.Contains(err.Error(), "not a maintained canonical v2 identity") {
		t.Fatalf("retired baseline identity accepted: %v", err)
	}
}

func TestFocusedV3TimePendingValidationIsExplicit(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	record, err := evidence.NewPendingFocusedV3TimeOptimizationEvidence(
		root,
		"2026-08-05",
		"f8973f05473c9110081324a0f2671fa410fb12f3",
		"test fixture awaits measurements",
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "focused-v3-time.json")
	if err := evidence.WriteFocusedV3TimeOptimizationEvidence(path, record, true); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"focused-v3-time", "--spruce-dir", root, "--evidence", path}); err == nil {
		t.Fatal("focused-v3-time accepted pending evidence without --allow-pending")
	}
	if err := run([]string{"focused-v3-time", "--spruce-dir", root, "--evidence", path, "--allow-pending"}); err != nil {
		t.Fatal(err)
	}
}
