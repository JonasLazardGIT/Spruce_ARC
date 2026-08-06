package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
)

func MarshalArtifactLock(lock ArtifactLock) ([]byte, error) {
	encoded, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode artifact lock: %w", err)
	}
	return append(encoded, '\n'), nil
}

func WriteArtifactLock(path string, lock ArtifactLock) error {
	encoded, err := MarshalArtifactLock(lock)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, encoded, 0o644)
}

func ReadArtifactLock(path string) (ArtifactLock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ArtifactLock{}, err
	}
	if err := requireArtifactLockIdentityV2(data); err != nil {
		return ArtifactLock{}, err
	}
	var lock ArtifactLock
	if err := decodeStrictJSON(data, &lock); err != nil {
		return ArtifactLock{}, fmt.Errorf("decode artifact lock: %w", err)
	}
	return lock, nil
}

// requireArtifactLockIdentityV2 checks the epoch boundary before the complete
// object is inferred or validated. The second, strict decode still rejects
// unknown fields and trailing JSON after this identity-only preflight.
func requireArtifactLockIdentityV2(data []byte) error {
	var identity struct {
		Schema  string `json:"schema"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&identity); err != nil {
		return fmt.Errorf("decode artifact lock identity: %w", err)
	}
	if identity.Schema != LockSchemaV2 || identity.Version != LockVersionV2 {
		return fmt.Errorf("artifact lock schema (%q,v%d) is not (%q,v%d); no migration; rerun setup and issuance, then regenerate v2 evidence", identity.Schema, identity.Version, LockSchemaV2, LockVersionV2)
	}
	return nil
}

func ValidateArtifactLock(lock ArtifactLock, opts ValidationOptions) error {
	if lock.Schema != LockSchemaV2 || lock.Version != LockVersionV2 {
		return fmt.Errorf("artifact lock schema (%q,v%d) is not (%q,v%d); no migration", lock.Schema, lock.Version, LockSchemaV2, LockVersionV2)
	}
	if !reflect.DeepEqual(lock.Identities, ProtocolIdentitiesV2()) {
		return fmt.Errorf("artifact lock protocol/schema identities do not match the executable v2 epoch")
	}
	if lock.Status != "complete" && lock.Status != "pending" {
		return fmt.Errorf("invalid artifact lock status %q", lock.Status)
	}
	if lock.Status == "pending" && !opts.AllowPending {
		return fmt.Errorf("artifact lock is pending; final validation requires all seven historical-v2 benchmark reports")
	}
	if lock.PresetCount != len(canonicalV2PresetIDs) || len(lock.Presets) != len(canonicalV2PresetIDs) {
		return fmt.Errorf("artifact lock has %d/%d presets; want %d", lock.PresetCount, len(lock.Presets), len(canonicalV2PresetIDs))
	}
	if lock.Aggregation != BaselineAggregationV2 || lock.RunCount != BaselineRunCountV2 {
		return fmt.Errorf("artifact lock baseline tuple (%q,%d runs) does not match (%q,%d runs)", lock.Aggregation, lock.RunCount, BaselineAggregationV2, BaselineRunCountV2)
	}
	if lock.Status == "complete" && lock.RunDigestCount != BaselineRunCountV2*len(canonicalV2PresetIDs) {
		return fmt.Errorf("complete artifact lock binds %d run digests; want %d", lock.RunDigestCount, BaselineRunCountV2*len(canonicalV2PresetIDs))
	}
	wantDigest, err := artifactLockDigest(lock)
	if err != nil {
		return err
	}
	if lock.EvidenceDigest != wantDigest {
		return fmt.Errorf("artifact lock evidence digest mismatch: have %q want %q", lock.EvidenceDigest, wantDigest)
	}
	rebuilt, err := BuildArtifactLock(BuildOptions{
		SPRUCE_DIR: opts.SPRUCE_DIR, ReportsDir: opts.ReportsDir, AllowPending: opts.AllowPending,
	})
	if err != nil {
		return fmt.Errorf("recompute v2 evidence: %w", err)
	}
	if !reflect.DeepEqual(lock, rebuilt) {
		return explainLockDifference(lock, rebuilt)
	}
	if opts.GeneratedTeXDir != "" {
		if err := ValidateGeneratedTeX(opts.GeneratedTeXDir, lock); err != nil {
			return err
		}
	}
	return nil
}

func ValidateArtifactLockFile(path string, opts ValidationOptions) error {
	lock, err := ReadArtifactLock(path)
	if err != nil {
		return err
	}
	return ValidateArtifactLock(lock, opts)
}

func explainLockDifference(have, want ArtifactLock) error {
	if !reflect.DeepEqual(have.SourceTree, want.SourceTree) {
		return fmt.Errorf("source-tree evidence changed: lock=%s current=%s", have.SourceTree.Digest, want.SourceTree.Digest)
	}
	if !reflect.DeepEqual(have.Git, want.Git) {
		return fmt.Errorf("git revision evidence changed")
	}
	if have.ReportsDigest != want.ReportsDigest {
		return fmt.Errorf("canonical benchmark/baseline set changed: lock=%s current=%s", have.ReportsDigest, want.ReportsDigest)
	}
	if have.RunReportsDigest != want.RunReportsDigest || have.RunDigestCount != want.RunDigestCount {
		return fmt.Errorf("three-run benchmark set changed: lock=%s current=%s", have.RunReportsDigest, want.RunReportsDigest)
	}
	for i := range have.Presets {
		if !reflect.DeepEqual(have.Presets[i], want.Presets[i]) {
			return fmt.Errorf("preset evidence changed for %s", canonicalV2PresetIDs[i])
		}
	}
	return fmt.Errorf("artifact lock differs from recomputed v2 evidence")
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".spruce-evidence-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tmpName := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary output mode: %w", err)
	}
	if _, err := bytes.NewReader(data).WriteTo(tmp); err != nil {
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install output: %w", err)
	}
	keep = true
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}
