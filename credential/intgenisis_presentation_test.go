package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntGenISISPresentationPrivacyAndReplayState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "presentation.json")
	pres := IntGenISISPresentation{
		Version:            IntGenISISPresentationVersion,
		Profile:            ProfileIntGenISISB,
		PublicParamsDigest: "abc123",
		Nonce:              [][]int64{{1}, {2}},
		Tag:                [][]int64{{3}, {4}},
		Proof:              json.RawMessage(`{"root":"opaque"}`),
	}
	if err := SaveIntGenISISPresentation(path, pres); err != nil {
		t.Fatalf("save presentation: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read presentation: %v", err)
	}
	text := string(raw)
	for _, stale := range []string{`"c"`, `"M"`, `"m"`, `"k"`, `"s"`, `"e"`, `"mu_sig"`, `"x0"`, `"x1"`, `"Z"`, `"u"`, `"t"`} {
		if strings.Contains(text, stale) {
			t.Fatalf("presentation leaked private field %q: %s", stale, text)
		}
	}
	state := NewIntGenISISVerifierState()
	if err := state.MarkPresentation(pres); err != nil {
		t.Fatalf("mark first presentation: %v", err)
	}
	if err := state.MarkPresentation(pres); err == nil {
		t.Fatal("replayed presentation accepted")
	}
}

func TestIntGenISISPresentationRejectsTamperedPresetBinding(t *testing.T) {
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetPoCN512SC96V1)
	pres := IntGenISISPresentation{
		Version:              IntGenISISPresentationVersion,
		Profile:              preset.Profile,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PresetManifestDigest: IntGenISISPresetManifestDigest(preset),
		PublicParamsDigest:   "digest",
		Nonce:                [][]int64{{1}},
		Tag:                  [][]int64{{2}},
		Proof:                json.RawMessage(`{"proof":true}`),
	}
	if err := pres.Validate(); err != nil {
		t.Fatalf("valid bound presentation rejected: %v", err)
	}
	pres.PresetID = IntGenISISPresetArtifactN1024SC96V1
	if err := pres.Validate(); err == nil {
		t.Fatal("tampered presentation preset binding accepted")
	}
}
