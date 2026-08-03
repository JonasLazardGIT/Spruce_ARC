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
	pres := testPresentationV2(t)
	pres.Proof = json.RawMessage(`{"schema_version":2,"root":"opaque"}`)
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
	state := NewIntGenISISVerifierState(pres.PublicParamsDigest, pres.VerifierKeyDigest)
	if err := state.MarkPresentation(pres); err != nil {
		t.Fatalf("mark first presentation: %v", err)
	}
	if err := state.MarkPresentation(pres); err == nil {
		t.Fatal("replayed presentation accepted")
	}
}

func TestIntGenISISPresentationRejectsTamperedPresetBinding(t *testing.T) {
	pres := testPresentationV2(t)
	if err := pres.Validate(); err != nil {
		t.Fatalf("valid bound presentation rejected: %v", err)
	}
	pres.PresetManifestDigest = repeatedDigest(0xff)
	if err := pres.Validate(); err == nil {
		t.Fatal("tampered presentation preset binding accepted")
	}
}

func TestIntGenISISPresentationRejectsInnerV1Proof(t *testing.T) {
	pres := testPresentationV2(t)
	pres.Proof = json.RawMessage(`{"schema_version":1}`)
	requireNoMigrationError(t, pres.Validate())
}
