package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"vSIS-Signature/credential"
)

const sourceDigestAlgorithm = "sha256_path_length_content_v2"

var canonicalV2PresetIDs = []string{
	"poc-n512-sc96-v2",
	"artifact-n1024-sc125-v2",
	"artifact-n1024-bq10-r96-v2",
	"artifact-n1024-bq16-r96-v2",
	"pilot-n1024-bq32-r96-v2",
	"poc-n1024-bq64-r128-v2",
	"poc-n1024-bq96-r128-v2",
	"poc-n1024-bq128-r128-v3",
	"system-n1024-wf128-crom-v2",
}

func CanonicalV2PresetIDs() []string {
	return append([]string(nil), canonicalV2PresetIDs...)
}

func ResolveSPRUCE_DIR(flagValue string) (string, error) {
	root := strings.TrimSpace(flagValue)
	if root == "" {
		root = strings.TrimSpace(os.Getenv("SPRUCE_DIR"))
	}
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve SPRUCE directory: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(abs, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("invalid SPRUCE directory %q: %w", abs, err)
	}
	if !strings.Contains(string(data), "module vSIS-Signature") {
		return "", fmt.Errorf("invalid SPRUCE directory %q: unexpected go.mod module", abs)
	}
	return filepath.Clean(abs), nil
}

func ResolveReportsDir(spruceDir, reportDir string) (string, error) {
	if strings.TrimSpace(reportDir) == "" {
		return filepath.Join(spruceDir, filepath.FromSlash(DefaultArtifactSubdir)), nil
	}
	if filepath.IsAbs(reportDir) {
		return filepath.Clean(reportDir), nil
	}
	return filepath.Join(spruceDir, reportDir), nil
}

func BuildArtifactLock(opts BuildOptions) (ArtifactLock, error) {
	root, err := ResolveSPRUCE_DIR(opts.SPRUCE_DIR)
	if err != nil {
		return ArtifactLock{}, err
	}
	reportsDir, err := ResolveReportsDir(root, opts.ReportsDir)
	if err != nil {
		return ArtifactLock{}, err
	}
	if err := validatePresetRegistryV2(); err != nil {
		return ArtifactLock{}, err
	}
	source, err := computeSourceTreeEvidence(root)
	if err != nil {
		return ArtifactLock{}, err
	}
	lock := ArtifactLock{
		Schema: LockSchemaV2, Version: LockVersionV2, Status: "complete",
		Identities: ProtocolIdentitiesV2(), SourceTree: source, Git: readGitEvidence(root),
		PresetCount: len(canonicalV2PresetIDs), Aggregation: BaselineAggregationV2,
		RunCount: BaselineRunCountV2, Presets: make([]PresetEvidence, 0, len(canonicalV2PresetIDs)),
	}
	reportDigests := make([]string, 0, 2*len(canonicalV2PresetIDs))
	runDigests := make([]string, 0, BaselineRunCountV2*len(canonicalV2PresetIDs))
	for _, canonicalID := range canonicalV2PresetIDs {
		preset, ok := credential.LookupIntGenISISPreset(canonicalID)
		if !ok {
			return ArtifactLock{}, fmt.Errorf("canonical v2 preset %q is not registered", canonicalID)
		}
		if err := validateCanonicalPreset(preset, canonicalID); err != nil {
			return ArtifactLock{}, err
		}
		entry := presetEvidence(preset)
		baseline, baselineErr := readAndValidateBaseline(reportsDir, preset)
		if baselineErr != nil {
			if !errors.Is(baselineErr, os.ErrNotExist) || !opts.AllowPending {
				if errors.Is(baselineErr, os.ErrNotExist) {
					return ArtifactLock{}, fmt.Errorf("missing v2 three-run baseline for %s at %s (place run-01.json through run-03.json below its runs directory, then run spruce-evidence baseline; --allow-pending is bootstrap-only)", canonicalID, filepath.Join(reportsDir, canonicalID, DefaultBaselineFileName))
				}
				return ArtifactLock{}, fmt.Errorf("invalid v2 three-run baseline for %s: %w", canonicalID, baselineErr)
			}
			entry.PendingReason = "v2 three-run benchmark baseline missing"
			lock.Status = "pending"
			lock.Presets = append(lock.Presets, entry)
			continue
		}
		reportPath := filepath.Join(reportsDir, canonicalID, DefaultBenchmarkFileName)
		report, raw, readErr := decodeBenchmarkReport(reportPath)
		if readErr != nil {
			if !errors.Is(readErr, os.ErrNotExist) || !opts.AllowPending {
				if errors.Is(readErr, os.ErrNotExist) {
					return ArtifactLock{}, fmt.Errorf("missing v2 benchmark report for %s at %s (run the benchmark or use --allow-pending only for bootstrap)", canonicalID, reportPath)
				}
				return ArtifactLock{}, fmt.Errorf("read v2 benchmark report for %s: %w", canonicalID, readErr)
			}
			entry.PendingReason = "v2 benchmark report missing"
			lock.Status = "pending"
			lock.Presets = append(lock.Presets, entry)
			continue
		}
		if err := validateBenchmarkReport(report, preset); err != nil {
			return ArtifactLock{}, fmt.Errorf("invalid v2 benchmark report for %s: %w", canonicalID, err)
		}
		benchmark := benchmarkEvidenceFromReport(report, raw, canonicalID)
		entry.Benchmark = &benchmark
		entry.Baseline = &baseline
		reportDigests = append(reportDigests,
			canonicalID+":canonical:"+benchmark.Digest,
			canonicalID+":baseline:"+baseline.Digest,
		)
		for _, run := range baseline.Runs {
			runDigests = append(runDigests, fmt.Sprintf("%s:run-%02d:%s", canonicalID, run.Run, run.Digest))
		}
		lock.Presets = append(lock.Presets, entry)
	}
	lock.RunDigestCount = len(runDigests)
	if lock.Status == "complete" && lock.RunDigestCount != BaselineRunCountV2*len(canonicalV2PresetIDs) {
		return ArtifactLock{}, fmt.Errorf("complete evidence binds %d run digests; want %d", lock.RunDigestCount, BaselineRunCountV2*len(canonicalV2PresetIDs))
	}
	lock.ReportsDigest = digestStrings("spruce-v2-canonical-and-baseline-set", reportDigests)
	lock.RunReportsDigest = digestStrings("spruce-v2-three-run-report-set", runDigests)
	lock.EvidenceDigest, err = artifactLockDigest(lock)
	if err != nil {
		return ArtifactLock{}, err
	}
	return lock, nil
}

func validatePresetRegistryV2() error {
	registered := credential.IntGenISISDefaultPresetNames()
	expected := CanonicalV2PresetIDs()
	sort.Strings(registered)
	sort.Strings(expected)
	if len(registered) != len(expected) {
		return fmt.Errorf("maintained preset registry has %d identities; v2 evidence requires exactly %d", len(registered), len(expected))
	}
	for i := range expected {
		if registered[i] != expected[i] {
			return fmt.Errorf("maintained preset registry identity %q does not match v2 evidence identity %q", registered[i], expected[i])
		}
	}
	return nil
}

func validateCanonicalPreset(preset credential.IntGenISISPreset, canonicalID string) error {
	if preset.CanonicalID != canonicalID || preset.PresetVersion != 2 {
		return fmt.Errorf("registered preset %q has non-v2 identity (%q,v%d)", canonicalID, preset.CanonicalID, preset.PresetVersion)
	}
	if preset.ClaimScope != credential.ClaimProofOnly || preset.CompleteSystemClaim {
		return fmt.Errorf("preset %s is not proof-only", canonicalID)
	}
	if err := preset.RateLimitPolicy.ValidateV2(); err != nil {
		return fmt.Errorf("preset %s: %w", canonicalID, err)
	}
	for phase, tuning := range map[string]credential.IntGenISISTuningPreset{"issuance": preset.Issuance, "showing": preset.Showing} {
		if tuning.TranscriptMode != ProtocolModeV2 || tuning.SoundnessGate != SecurityStatusV2 || !tuning.FixedTranscriptSize {
			return fmt.Errorf("preset %s %s transcript tuple is not v2", canonicalID, phase)
		}
		if tuning.TranscriptOmissionMode != OmissionDescriptorV2 {
			return fmt.Errorf("preset %s %s transcript omission mode=%q; want %q", canonicalID, phase, tuning.TranscriptOmissionMode, OmissionDescriptorV2)
		}
	}
	if preset.Showing.ReplayProjection != ShowingRelationV2 {
		return fmt.Errorf("preset %s showing relation=%q; want %q", canonicalID, preset.Showing.ReplayProjection, ShowingRelationV2)
	}
	return nil
}

func presetEvidence(preset credential.IntGenISISPreset) PresetEvidence {
	return PresetEvidence{
		CanonicalID: preset.CanonicalID, Selector: preset.Name, PresetVersion: preset.PresetVersion,
		ManifestDigest:     credential.IntGenISISPresetManifestDigest(preset),
		PrimitiveProfileID: preset.PrimitiveProfileID, SecurityProfile: preset.SecurityProfile,
		SecurityMode: preset.SecurityMode, Lifecycle: preset.Lifecycle, ClaimScope: preset.ClaimScope,
		CompleteSystemClaim: preset.CompleteSystemClaim, TargetTheoremBits: preset.TargetTheoremBits,
		RateLimitPolicy: preset.RateLimitPolicy, ShowingRelation: ShowingRelationV2,
		ShowingLayout: ShowingLayoutV2, PRFCompanionRelation: PRFCompanionRelationV2,
	}
}

func artifactLockDigest(lock ArtifactLock) (string, error) {
	copyLock := lock
	copyLock.EvidenceDigest = ""
	encoded, err := json.Marshal(copyLock)
	if err != nil {
		return "", fmt.Errorf("encode evidence lock for digest: %w", err)
	}
	digest := sha256.Sum256(append([]byte("spruce-paper-artifact-lock-v2\x00"), encoded...))
	return hex.EncodeToString(digest[:]), nil
}

func digestStrings(domain string, values []string) string {
	h := sha256.New()
	writeDigestPart(h, []byte(domain))
	for _, value := range values {
		writeDigestPart(h, []byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type digestWriter interface {
	Write([]byte) (int, error)
}

func writeDigestPart(w digestWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(value)
}

func computeSourceTreeEvidence(root string) (SourceTreeEvidence, error) {
	paths := make([]string, 0, 512)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if rel == ".git" || rel == "artifacts" {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source tree contains symlink %s", rel)
		}
		if !entry.Type().IsRegular() || !isSourceEvidenceFile(rel) {
			return nil
		}
		paths = append(paths, rel)
		return nil
	})
	if err != nil {
		return SourceTreeEvidence{}, fmt.Errorf("walk SPRUCE source tree: %w", err)
	}
	if len(paths) == 0 {
		return SourceTreeEvidence{}, fmt.Errorf("SPRUCE source tree contains no evidence files")
	}
	sort.Strings(paths)
	h := sha256.New()
	writeDigestPart(h, []byte(sourceDigestAlgorithm))
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return SourceTreeEvidence{}, fmt.Errorf("read source file %s: %w", rel, err)
		}
		writeDigestPart(h, []byte(rel))
		writeDigestPart(h, data)
	}
	return SourceTreeEvidence{Algorithm: sourceDigestAlgorithm, Digest: hex.EncodeToString(h.Sum(nil)), FileCount: len(paths)}, nil
}

func isSourceEvidenceFile(rel string) bool {
	if rel == "TODO.md" || rel == "results.md" {
		return false
	}
	base := filepath.Base(rel)
	if strings.HasSuffix(base, ".lock.json") || base == GeneratedMacrosFileName || base == GeneratedTableFileName {
		return false
	}
	if base == "Dockerfile" || base == "go.mod" || base == "go.sum" || base == "LICENSE" || base == "THIRD_PARTY_NOTICES.md" || base == ".gitignore" || base == ".dockerignore" {
		return true
	}
	switch strings.ToLower(filepath.Ext(base)) {
	case ".go", ".json", ".md", ".py", ".sage", ".sh", ".yml", ".yaml":
		return true
	default:
		return false
	}
}

func readGitEvidence(root string) *GitEvidence {
	cmd := exec.Command("git", "-C", root, "rev-parse", "--verify", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	revision := strings.TrimSpace(string(output))
	decoded, err := hex.DecodeString(revision)
	if err != nil || (len(decoded) != 20 && len(decoded) != 32) {
		return nil
	}
	return &GitEvidence{Revision: strings.ToLower(revision)}
}
