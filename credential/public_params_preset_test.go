package credential

import (
	"encoding/json"
	"testing"
)

func TestPublicParamsPresetBindingRejectsManifestMismatch(t *testing.T) {
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetArtifactN1024SC125V2)
	public := PublicParams{Profile: preset.Profile}
	if err := public.BindIntGenISISPreset(preset); err != nil {
		t.Fatal(err)
	}
	if err := public.ValidateIntGenISISPreset(preset); err != nil {
		t.Fatal(err)
	}
	extras := public.PresetTranscriptExtras(nil)
	if string(extras["IntGenISIS.preset_manifest_digest"].([]byte)) != public.PresetManifestDigest {
		t.Fatalf("manifest digest not exposed to transcript labels: %+v", extras)
	}
	if string(extras["IntGenISIS.transcript_version"].([]byte)) != IntGenISISTranscriptVersionV2 {
		t.Fatalf("transcript version not exposed to transcript labels: %+v", extras)
	}
	wantPolicy, err := json.Marshal(IntGenISISRateLimitPolicyV2())
	if err != nil {
		t.Fatal(err)
	}
	if string(extras["IntGenISIS.rate_limit_policy"].([]byte)) != string(wantPolicy) {
		t.Fatalf("rate-limit policy not exposed canonically: %+v", extras)
	}
	public.PresetManifestDigest = "tampered"
	if err := public.ValidateIntGenISISPreset(preset); err == nil {
		t.Fatal("tampered public manifest binding accepted")
	}
}
