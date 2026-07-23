package credential

import "testing"

func TestPublicParamsPresetBindingRejectsManifestMismatch(t *testing.T) {
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetArtifactN1024SC125V1)
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
	public.PresetManifestDigest = "tampered"
	if err := public.ValidateIntGenISISPreset(preset); err == nil {
		t.Fatal("tampered public manifest binding accepted")
	}
}
