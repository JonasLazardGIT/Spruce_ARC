package sourceintegrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeBindsProductionSourcesOnly(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example\n")
	write("go.sum", "")
	write("cmd/issuance/main.go", "package main\n\nimport (\n  _ \"embed\"\n  _ \"example/pkg\"\n)\n\n//go:embed config.json\nvar config []byte\n\nfunc main() {}\n")
	write("cmd/issuance/config.json", "{\"version\":1}\n")
	write("pkg/untracked.go", "package pkg\n")
	write("pkg/source_test.go", "package pkg\n")
	write("README.md", "one\n")
	write("evidence/result.json", "{}\n")
	write("artifacts/run/report.json", "{}\n")
	write(".gocache/poison.go", "package poison\n")

	first, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.Algorithm != Algorithm || first.FileCount != 5 || len(first.Digest) != 64 {
		t.Fatalf("unexpected snapshot: %+v", first)
	}
	write("README.md", "two\n")
	write("pkg/source_test.go", "package pkg // changed\n")
	write(".gocache/poison.go", "package poison // changed\n")
	second, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatal("non-production files changed the source snapshot")
	}
	write("cmd/issuance/config.json", "{\"version\":2}\n")
	embedded, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	if embedded.Digest == first.Digest || embedded.FileCount != first.FileCount {
		t.Fatal("go:embed asset mutation was not bound")
	}
	write("pkg/untracked.go", "package pkg // changed\n")
	third, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	if third.Digest == embedded.Digest || third.FileCount != embedded.FileCount {
		t.Fatal("production source mutation was not bound")
	}
	write("pkg/new.go", "package pkg\n")
	fourth, err := Compute(root)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Digest == third.Digest || fourth.FileCount != third.FileCount+1 {
		t.Fatal("new production source was not bound")
	}
}
