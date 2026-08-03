package credential

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

type presentationContextVectorV2 struct {
	Version              int     `json:"version"`
	ContextEncoding      string  `json:"context_encoding"`
	RawContextHex        string  `json:"raw_context_hex"`
	FieldModulus         uint64  `json:"field_modulus"`
	QuotaSlots           uint32  `json:"quota_slots"`
	PresetManifestDigest string  `json:"preset_manifest_digest"`
	PublicParamsDigest   string  `json:"public_params_digest"`
	VerifierKeyDigest    string  `json:"verifier_key_digest"`
	ContextDigest        string  `json:"context_digest"`
	ContextLanes         []int64 `json:"context_lanes"`
}

func repeatedDigest(b byte) string {
	return strings.Repeat(fmt.Sprintf("%02x", b), 32)
}

func TestPresentationContextV2DeterministicAndDomainBound(t *testing.T) {
	raw := []byte("service=example;policy=upload;epoch=42")
	a, err := DerivePresentationContext(raw, 1017857, repeatedDigest(1), repeatedDigest(2), repeatedDigest(3))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DerivePresentationContext(raw, 1017857, repeatedDigest(1), repeatedDigest(2), repeatedDigest(3))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest || fmt.Sprint(a.Lanes) != fmt.Sprint(b.Lanes) {
		t.Fatal("context derivation is not deterministic")
	}
	if err := a.Validate(1017857); err != nil {
		t.Fatal(err)
	}
	c, err := DerivePresentationContext(raw, 1017857, repeatedDigest(1), repeatedDigest(2), repeatedDigest(4))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest == c.Digest || fmt.Sprint(a.Lanes) == fmt.Sprint(c.Lanes) {
		t.Fatal("verifier-key binding did not change context")
	}
}

func TestPublishedPresentationContextV2Vector(t *testing.T) {
	data, err := os.ReadFile("testdata/presentation_context_v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector presentationContextVectorV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("context test vector trailing JSON: %v", err)
	}
	if vector.Version != 2 || vector.ContextEncoding != IntGenISISContextEncodingV2 || vector.QuotaSlots != IntGenISISQuotaSlots {
		t.Fatalf("unexpected vector identity: %+v", vector)
	}
	raw, err := hex.DecodeString(vector.RawContextHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DerivePresentationContext(raw, vector.FieldModulus, vector.PresetManifestDigest, vector.PublicParamsDigest, vector.VerifierKeyDigest)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != vector.ContextDigest || fmt.Sprint(got.Lanes) != fmt.Sprint(vector.ContextLanes) {
		t.Fatalf("context vector mismatch: got %+v want digest=%s lanes=%v", got, vector.ContextDigest, vector.ContextLanes)
	}
}

func TestHolderUsageStateReservesSixteenSlotsAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "holder.json")
	pp := repeatedDigest(1)
	manifest := repeatedDigest(2)
	credential := repeatedDigest(3)
	context := repeatedDigest(4)

	var wg sync.WaitGroup
	results := make(chan uint8, IntGenISISQuotaSlots)
	errs := make(chan error, IntGenISISQuotaSlots)
	for i := uint32(0); i < IntGenISISQuotaSlots; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slot, err := ReserveIntGenISISSlot(path, pp, manifest, credential, context)
			if err != nil {
				errs <- err
				return
			}
			results <- slot
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	got := make([]int, 0, IntGenISISQuotaSlots)
	for slot := range results {
		got = append(got, int(slot))
	}
	sort.Ints(got)
	for i := 0; i < int(IntGenISISQuotaSlots); i++ {
		if got[i] != i {
			t.Fatalf("reserved slots=%v", got)
		}
	}
	if _, err := ReserveIntGenISISSlot(path, pp, manifest, credential, context); err == nil {
		t.Fatal("seventeenth slot reservation succeeded")
	}
}

func testPresentationV2(t *testing.T) IntGenISISPresentation {
	t.Helper()
	preset, err := MustLookupIntGenISISPreset(IntGenISISPresetN512Compact96)
	if err != nil {
		t.Fatal(err)
	}
	tagLen, _ := IntGenISISPRFProfileTagElements(preset.PRFProfile)
	return IntGenISISPresentation{
		Version:              IntGenISISPresentationVersion,
		PresetManifestDigest: IntGenISISPresetManifestDigest(preset),
		PublicParamsDigest:   repeatedDigest(5),
		VerifierKeyDigest:    repeatedDigest(6),
		ContextDigest:        repeatedDigest(7),
		Context:              make([]int64, IntGenISISContextLaneCount),
		Tag:                  make([]int64, tagLen),
		Proof:                json.RawMessage(`{"schema_version":2}`),
	}
}

func TestVerifierStateConcurrentDuplicateHasOneAcceptance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verifier.json")
	pres := testPresentationV2(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- CheckAndMarkIntGenISISPresentation(path, pres)
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful duplicate accepts=%d want 1", successes)
	}
}

func TestPresentationV2StrictAndPrivateWireShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "presentation.json")
	pres := testPresentationV2(t)
	if err := SaveIntGenISISPresentation(path, pres); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"nonce"`, `"slot"`, `"slot_bits"`, `"key"`} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("presentation leaked %s", forbidden)
		}
	}
	legacy := strings.Replace(string(data), "\n}", ",\n  \"nonce\": [[1]]\n}", 1)
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIntGenISISPresentation(path); err == nil {
		t.Fatal("legacy nonce field was silently accepted")
	}
}
