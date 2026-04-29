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
