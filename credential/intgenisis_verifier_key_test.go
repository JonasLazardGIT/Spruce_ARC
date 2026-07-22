package credential

import (
	"path/filepath"
	"testing"
)

func TestIntGenISISVerifierKeyRoundTrip(t *testing.T) {
	profile := PrimaryIntGenISISProfile()
	key := IntGenISISVerifierKey{
		Version:            IntGenISISVerifierKeyVersion,
		Profile:            profile.Name,
		RingDegree:         profile.N,
		PublicParamsDigest: "digest",
		NTRUPublic:         [][]int64{make([]int64, profile.N)},
	}
	path := filepath.Join(t.TempDir(), "verifier_key.json")
	if err := SaveIntGenISISVerifierKey(path, key); err != nil {
		t.Fatalf("save verifier key: %v", err)
	}
	got, err := LoadIntGenISISVerifierKey(path)
	if err != nil {
		t.Fatalf("load verifier key: %v", err)
	}
	if got.Profile != key.Profile || got.RingDegree != key.RingDegree || len(got.NTRUPublic[0]) != profile.N {
		t.Fatalf("unexpected verifier key: %+v", got)
	}
	got.NTRUPublic[0] = got.NTRUPublic[0][:profile.N-1]
	if err := got.Validate(); err == nil {
		t.Fatal("short verifier key accepted")
	}
}

func TestIntGenISISVerifierKeyRejectsTamperedPresetBinding(t *testing.T) {
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetPoCN512SC96V1)
	profile, _ := LookupIntGenISISProfile(preset.Profile)
	key := IntGenISISVerifierKey{
		Version:              IntGenISISVerifierKeyVersion,
		Profile:              preset.Profile,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PresetManifestDigest: IntGenISISPresetManifestDigest(preset),
		RingDegree:           profile.N,
		PublicParamsDigest:   "digest",
		NTRUPublic:           [][]int64{make([]int64, profile.N)},
	}
	if err := key.Validate(); err != nil {
		t.Fatalf("valid bound verifier key rejected: %v", err)
	}
	key.PresetVersion++
	if err := key.Validate(); err == nil {
		t.Fatal("tampered verifier-key preset binding accepted")
	}
}
