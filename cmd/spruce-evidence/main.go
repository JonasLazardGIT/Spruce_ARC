package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"vSIS-Signature/evidence"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "spruce-evidence: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "baseline":
		return runBaseline(args[1:])
	case "export":
		return runExport(args[1:])
	case "validate":
		return runValidate(args[1:])
	case "help", "-h", "--help":
		fmt.Fprintln(os.Stdout, usageText())
		return nil
	default:
		return fmt.Errorf("unknown operation %q\n%s", args[0], usageText())
	}
}

func runBaseline(args []string) error {
	flags := flag.NewFlagSet("baseline", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	spruceDir := flags.String("spruce-dir", "", "SPRUCE checkout (default: SPRUCE_DIR, then current directory)")
	reportsDir := flags.String("reports-dir", "", "v2 report root (default: artifacts/smallwood-salted-v2 below SPRUCE)")
	preset := flags.String("preset", "", "optional exact canonical v2 preset ID (default: all nine)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected baseline arguments: %v", flags.Args())
	}
	baselines, err := evidence.GenerateThreeRunBaselines(evidence.BaselineOptions{
		SPRUCE_DIR: *spruceDir, ReportsDir: *reportsDir, CanonicalPresetID: *preset,
	})
	if err != nil {
		return err
	}
	for _, baseline := range baselines {
		fmt.Fprintf(os.Stdout, "baselined %s from %d runs; sidecar_sha256=%s\n", baseline.CanonicalPresetID, baseline.RunCount, baseline.Digest)
	}
	return nil
}

func runExport(args []string) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	spruceDir := flags.String("spruce-dir", "", "SPRUCE checkout (default: SPRUCE_DIR, then current directory)")
	reportsDir := flags.String("reports-dir", "", "v2 report root (default: artifacts/smallwood-salted-v2 below SPRUCE)")
	lockOut := flags.String("lock-out", "", "artifact-lock JSON path (default: v2 artifact root)")
	generatedDir := flags.String("paper-generated-dir", "", "paper generated/ directory for tracked TeX (required)")
	allowPending := flags.Bool("allow-pending", false, "bootstrap a visibly pending lock when reports are missing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected export arguments: %v", flags.Args())
	}
	if *generatedDir == "" {
		return fmt.Errorf("export requires --paper-generated-dir")
	}
	root, err := evidence.ResolveSPRUCE_DIR(*spruceDir)
	if err != nil {
		return err
	}
	lock, err := evidence.BuildArtifactLock(evidence.BuildOptions{
		SPRUCE_DIR: root, ReportsDir: *reportsDir, AllowPending: *allowPending,
	})
	if err != nil {
		return err
	}
	output := *lockOut
	if output == "" {
		output = filepath.Join(root, filepath.FromSlash(evidence.DefaultArtifactSubdir), evidence.DefaultLockFileName)
	} else if !filepath.IsAbs(output) {
		output = filepath.Join(root, output)
	}
	if err := evidence.WriteArtifactLock(output, lock); err != nil {
		return err
	}
	if err := evidence.WriteGeneratedTeX(*generatedDir, lock); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "exported %s evidence lock %s\n", lock.Status, output)
	fmt.Fprintf(os.Stdout, "evidence_digest=%s source_digest=%s reports_digest=%s\n", lock.EvidenceDigest, lock.SourceTree.Digest, lock.ReportsDigest)
	return nil
}

func runValidate(args []string) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	spruceDir := flags.String("spruce-dir", "", "SPRUCE checkout (default: SPRUCE_DIR, then current directory)")
	reportsDir := flags.String("reports-dir", "", "v2 report root (default: artifacts/smallwood-salted-v2 below SPRUCE)")
	lockPath := flags.String("lock", "", "artifact-lock JSON path (default: v2 artifact root)")
	generatedDir := flags.String("paper-generated-dir", "", "optional generated/ directory to compare byte-for-byte")
	allowPending := flags.Bool("allow-pending", false, "accept a pending bootstrap lock (never use for final validation)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected validate arguments: %v", flags.Args())
	}
	root, err := evidence.ResolveSPRUCE_DIR(*spruceDir)
	if err != nil {
		return err
	}
	path := *lockPath
	if path == "" {
		path = filepath.Join(root, filepath.FromSlash(evidence.DefaultArtifactSubdir), evidence.DefaultLockFileName)
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if err := evidence.ValidateArtifactLockFile(path, evidence.ValidationOptions{
		SPRUCE_DIR: root, ReportsDir: *reportsDir, GeneratedTeXDir: *generatedDir, AllowPending: *allowPending,
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "validated v2 artifact lock %s\n", path)
	return nil
}

func usageError() error {
	return fmt.Errorf("missing operation\n%s", usageText())
}

func usageText() string {
	return "usage: spruce-evidence <baseline|export|validate> [flags]"
}
