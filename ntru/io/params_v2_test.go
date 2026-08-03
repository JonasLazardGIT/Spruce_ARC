package io

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemParamsV2RoundTripAndDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "params.json")
	want, err := CanonicalizeParams(SystemParams{N: 1024, Q: 1017857, Beta: 6142})
	if err != nil {
		t.Fatal(err)
	}
	if want.ParamsDigest != "ed0f664ac23b2a5aab2d528bd93c8a1daa605b3b9aa9298fba139920c3538149" {
		t.Fatalf("canonical params digest=%s", want.ParamsDigest)
	}
	if err := SaveParams(path, want); err != nil {
		t.Fatalf("SaveParams: %v", err)
	}
	got, err := LoadParams(path, false)
	if err != nil {
		t.Fatalf("LoadParams: %v", err)
	}
	if got != want {
		t.Fatalf("round trip=%+v want %+v", got, want)
	}
}

func TestSystemParamsV2RejectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "params.json")
	p, err := CanonicalizeParams(SystemParams{N: 1024, Q: 1017857, Beta: 6142})
	if err != nil {
		t.Fatal(err)
	}
	disk := systemParamsV2Disk{
		Version:      p.Version,
		ParamsDigest: p.ParamsDigest,
		N:            p.N,
		Q:            p.Q,
		K:            20,
		Beta:         p.Beta + 1,
		Bound:        p.Beta + 1,
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadParams(path, false); err == nil {
		t.Fatal("LoadParams accepted beta tampering under a stale digest")
	}
}

func TestSystemParamsV2RejectsLegacyArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	raw := []byte(`{"n":1024,"q":1017857,"k":20,"beta":6142,"bound":6142}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadParams(path, false); err == nil {
		t.Fatal("LoadParams silently upgraded a legacy params artifact")
	}
}

func TestSystemParamsV2RejectsRedundantFieldMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "params.json")
	p, err := CanonicalizeParams(SystemParams{N: 1024, Q: 1017857, Beta: 6142})
	if err != nil {
		t.Fatal(err)
	}
	disk := systemParamsV2Disk{
		Version:      p.Version,
		ParamsDigest: p.ParamsDigest,
		N:            p.N,
		Q:            p.Q,
		K:            19,
		Beta:         p.Beta,
		Bound:        p.Beta,
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadParams(path, false); err == nil {
		t.Fatal("LoadParams accepted an inconsistent k field")
	}
}
