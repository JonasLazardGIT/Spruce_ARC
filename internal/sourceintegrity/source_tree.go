// Package sourceintegrity computes a canonical identity for the local Go
// implementation used to produce benchmark evidence. It is intentionally
// independent of Git's dirty bit: tracked modifications and untracked
// production sources are both included.
package sourceintegrity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const Algorithm = "sha256-length-framed-go-list-build-inputs-v2"

type Snapshot struct {
	Algorithm string
	Digest    string
	FileCount int
}

// Compute asks the Go tool for the exact local package inputs of the issuance
// benchmark and hashes every compiled source and go:embed asset, plus go.mod
// and go.sum. Tests, documentation, generated evidence, artifacts, scratch
// data, and build caches are absent because go list does not report them as
// inputs. External dependency source is represented by the authenticated
// module sums.
func Compute(root string) (Snapshot, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Snapshot{}, err
	}
	cmd := exec.Command("go", "list", "-deps", "-json", "./cmd/issuance")
	cmd.Dir = abs
	output, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return Snapshot{}, fmt.Errorf("sourceintegrity: go list issuance build inputs: %w: %s", err, strings.TrimSpace(string(exit.Stderr)))
		}
		return Snapshot{}, fmt.Errorf("sourceintegrity: go list issuance build inputs: %w", err)
	}
	type listedPackage struct {
		Dir          string
		GoFiles      []string
		CgoFiles     []string
		CFiles       []string
		CXXFiles     []string
		MFiles       []string
		HFiles       []string
		FFiles       []string
		SFiles       []string
		SwigFiles    []string
		SwigCXXFiles []string
		SysoFiles    []string
		EmbedFiles   []string
	}
	pathSet := map[string]struct{}{"go.mod": {}, "go.sum": {}}
	dec := json.NewDecoder(strings.NewReader(string(output)))
	for {
		var pkg listedPackage
		if err := dec.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return Snapshot{}, fmt.Errorf("sourceintegrity: decode go list output: %w", err)
		}
		pkgRel, err := filepath.Rel(abs, pkg.Dir)
		if err != nil || pkgRel == ".." || strings.HasPrefix(pkgRel, ".."+string(filepath.Separator)) {
			continue
		}
		groups := [][]string{pkg.GoFiles, pkg.CgoFiles, pkg.CFiles, pkg.CXXFiles, pkg.MFiles, pkg.HFiles, pkg.FFiles, pkg.SFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles, pkg.EmbedFiles}
		for _, group := range groups {
			for _, name := range group {
				path := filepath.Join(pkg.Dir, name)
				rel, err := filepath.Rel(abs, path)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return Snapshot{}, fmt.Errorf("sourceintegrity: local build input %q escapes source root", path)
				}
				pathSet[filepath.ToSlash(rel)] = struct{}{}
			}
		}
	}
	paths := make([]string, 0, len(pathSet))
	for rel := range pathSet {
		paths = append(paths, rel)
	}
	if len(paths) == 0 {
		return Snapshot{}, fmt.Errorf("sourceintegrity: production tree is empty")
	}
	sort.Strings(paths)
	h := sha256.New()
	writePart(h, []byte(Algorithm))
	for _, rel := range paths {
		path := filepath.Join(abs, filepath.FromSlash(rel))
		info, err := os.Lstat(path)
		if err != nil {
			return Snapshot{}, fmt.Errorf("sourceintegrity: stat %s: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return Snapshot{}, fmt.Errorf("sourceintegrity: build input %s is not a regular file", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return Snapshot{}, fmt.Errorf("sourceintegrity: read %s: %w", rel, err)
		}
		writePart(h, []byte(rel))
		writePart(h, data)
	}
	return Snapshot{Algorithm: Algorithm, Digest: hex.EncodeToString(h.Sum(nil)), FileCount: len(paths)}, nil
}

type digestWriter interface {
	Write([]byte) (int, error)
}

func writePart(w digestWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = w.Write(length[:])
	_, _ = w.Write(value)
}
