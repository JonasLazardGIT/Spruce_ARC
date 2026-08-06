package credential

import (
	"bytes"
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

func TestV3PresetTranscriptBindsCompleteManifestBytes(t *testing.T) {
	for _, name := range []string{IntGenISISPresetPoCN1024BQ128R128V3, IntGenISISPresetSystemN1024WF128CROMV2} {
		preset, ok := LookupIntGenISISPreset(name)
		if !ok {
			t.Fatal("missing v3 target preset")
		}
		public := PublicParams{Profile: preset.Profile, Modulus: IntGenISISSharedModulusQ}
		if err := public.BindIntGenISISPreset(preset); err != nil {
			t.Fatal(err)
		}
		extras := public.PresetTranscriptExtras(nil)
		got, ok := extras["IntGenISIS.preset_manifest"].([]byte)
		if !ok || !bytes.Equal(got, IntGenISISPresetManifestCanonicalBytes(preset)) {
			t.Fatalf("%s did not absorb its complete canonical manifest", name)
		}
		var shape struct {
			Schema             string `json:"schema"`
			FieldProfileID     string `json:"field_profile_id"`
			FieldProfileDigest string `json:"field_profile_digest"`
			FieldProfile       []byte `json:"field_profile"`
		}
		if err := json.Unmarshal(got, &shape); err != nil || shape.Schema != "spruce.intgenisis.preset.v3" {
			t.Fatalf("%s canonical manifest schema=%q err=%v", name, shape.Schema, err)
		}
		if shape.FieldProfileID != preset.FieldProfileID || shape.FieldProfileDigest != preset.FieldProfileDigest ||
			!bytes.Equal(shape.FieldProfile, extras["IntGenISIS.field_profile"].([]byte)) {
			t.Fatalf("%s canonical manifest omitted or changed its complete field profile", name)
		}
		canonicalPRF, ok := extras["IntGenISIS.prf_params"].([]byte)
		if !ok || len(canonicalPRF) == 0 {
			t.Fatalf("%s transcript extras omitted complete PRF constants", name)
		}
	}
}

func TestPublicationV4PresetTranscriptBindsCompleteManifestAndRejectsWrongContext(t *testing.T) {
	for _, name := range IntGenISISPublicationPresetNamesV4() {
		t.Run(name, func(t *testing.T) {
			preset, ok := LookupIntGenISISPublicationPreset(name)
			if !ok {
				t.Fatal("missing publication-v4 target preset")
			}
			public := PublicParams{Profile: preset.Profile, Modulus: IntGenISISSharedModulusQ}
			if err := public.BindIntGenISISPreset(preset); err != nil {
				t.Fatal(err)
			}
			extras := public.PresetTranscriptExtras(nil)
			if got := string(extras["IntGenISIS.transcript_version"].([]byte)); got != IntGenISISTranscriptVersionV4 {
				t.Fatalf("transcript version=%q want %q", got, IntGenISISTranscriptVersionV4)
			}
			got, ok := extras["IntGenISIS.preset_manifest"].([]byte)
			if !ok || !bytes.Equal(got, IntGenISISPresetManifestCanonicalBytes(preset)) {
				t.Fatal("publication-v4 transcript omitted or changed its complete canonical manifest")
			}
			var shape struct {
				Schema           string                 `json:"schema"`
				PublicationLabel string                 `json:"publication_label"`
				Issuance         IntGenISISTuningPreset `json:"issuance"`
				Showing          IntGenISISTuningPreset `json:"showing"`
			}
			if err := json.Unmarshal(got, &shape); err != nil {
				t.Fatal(err)
			}
			if shape.Schema != "spruce.intgenisis.preset.v4" || shape.PublicationLabel != preset.PublicationLabel ||
				shape.Issuance.FSOutputBits != preset.Issuance.FSOutputBits || shape.Showing.FSOutputBits != preset.Showing.FSOutputBits {
				t.Fatalf("publication-v4 canonical shape=%+v", shape)
			}
		})
	}

	left, _ := LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetBQ96Q32V4)
	right, _ := LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetBQ96Q96V4)
	public := PublicParams{Profile: left.Profile, Modulus: IntGenISISSharedModulusQ}
	if err := public.BindIntGenISISPreset(left); err != nil {
		t.Fatal(err)
	}
	if err := public.ValidateIntGenISISPreset(right); err == nil {
		t.Fatal("public parameters accepted a different publication-v4 manifest context")
	}
}
