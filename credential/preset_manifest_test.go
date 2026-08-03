package credential

import (
	"math"
	"testing"
)

func TestCanonicalPresetAliasesResolveToOneManifest(t *testing.T) {
	tests := map[string]string{
		IntGenISISPresetPoCN512SC96V2:          IntGenISISPresetN512Compact96,
		IntGenISISPresetArtifactN1024SC125V2:   IntGenISISPresetN1024Compact125,
		IntGenISISPresetPilotN1024BQ32R96V2:    IntGenISISPresetN1024BQ32_96,
		IntGenISISPresetSystemN1024WF128CROMV2: IntGenISISPresetSystemN1024WF128CROMV2,
	}
	for alias, legacy := range tests {
		fromAlias, ok := LookupIntGenISISPreset(alias)
		if !ok {
			t.Fatalf("canonical alias %s missing", alias)
		}
		fromLegacy, ok := LookupIntGenISISPreset(legacy)
		if !ok {
			t.Fatalf("legacy selector %s missing", legacy)
		}
		if fromAlias.CanonicalID != alias || fromAlias.Name != legacy {
			t.Fatalf("alias %s resolved to %+v", alias, fromAlias)
		}
		if IntGenISISPresetManifestDigest(fromAlias) != IntGenISISPresetManifestDigest(fromLegacy) {
			t.Fatalf("alias %s and legacy selector %s have different manifests", alias, legacy)
		}
	}
}

func TestEveryCanonicalPresetIDResolves(t *testing.T) {
	for legacy, metadata := range intGenISISPresetMetadataRegistry() {
		fromCanonical, ok := LookupIntGenISISPreset(metadata.canonicalID)
		if !ok {
			t.Fatalf("canonical ID %q for %s did not resolve", metadata.canonicalID, legacy)
		}
		fromLegacy, _ := LookupIntGenISISPreset(legacy)
		if fromCanonical.Name != fromLegacy.Name || IntGenISISPresetManifestDigest(fromCanonical) != IntGenISISPresetManifestDigest(fromLegacy) {
			t.Fatalf("canonical ID %q resolved to a different manifest", metadata.canonicalID)
		}
	}
}

func TestEveryRegisteredPresetManifestValidates(t *testing.T) {
	for _, name := range IntGenISISPresetNames() {
		preset, _ := LookupIntGenISISPreset(name)
		if err := ValidateIntGenISISPresetManifest(preset); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestPresetManifestDigestBindsSecurityRelevantTuning(t *testing.T) {
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V2)
	digest := IntGenISISPresetManifestDigest(preset)
	mutated := preset
	mutated.Showing.SaltBits++
	if got := IntGenISISPresetManifestDigest(mutated); got == digest {
		t.Fatal("salt-width change did not change preset manifest digest")
	}
	mutated = preset
	mutated.ThreatModel.MaxProofsLog2++
	if got := IntGenISISPresetManifestDigest(mutated); got == digest {
		t.Fatal("threat-model change did not change preset manifest digest")
	}
	mutated = preset
	mutated.PRFParamsDigest = "different"
	if got := IntGenISISPresetManifestDigest(mutated); got == digest {
		t.Fatal("PRF parameter change did not change preset manifest digest")
	}
	mutated = preset
	mutated.Showing.TranscriptOmissionMode = "different"
	if got := IntGenISISPresetManifestDigest(mutated); got == digest {
		t.Fatal("transcript omission mode change did not change preset manifest digest")
	}
	mutated = preset
	mutated.PRFParamsPath = "/alternate/local/path/to/the-same-parameters.json"
	if got := IntGenISISPresetManifestDigest(mutated); got != digest {
		t.Fatal("operational PRF pathname changed canonical manifest identity")
	}
}

func TestPresetThreatModelsSeparatePerPhaseOracleCapsFromHonestVolume(t *testing.T) {
	for _, name := range IntGenISISPresetNames() {
		preset, _ := LookupIntGenISISPreset(name)
		if err := ValidatePresetThreatModel(preset.ThreatModel); err != nil {
			t.Fatalf("%s threat model: %v", name, err)
		}
	}
	pilot, _ := LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V2)
	if pilot.ThreatModel.MaxProofsLog2 != 32 || pilot.ThreatModel.MaxIssuanceProofsLog2 != 31 || pilot.ThreatModel.MaxShowingProofsLog2 != 31 {
		t.Fatalf("pilot proof-volume split=%+v", pilot.ThreatModel)
	}
	if pilot.ThreatModel.ROQueryCapScope != ROQueryCapPerPhaseGlobal || pilot.ThreatModel.AcceptedIssuance != 1 || pilot.ThreatModel.AcceptedShowing != 1 {
		t.Fatalf("pilot adversarial composition=%+v", pilot.ThreatModel)
	}
	poc, _ := LookupIntGenISISPreset(IntGenISISPresetPoCN512SC96V2)
	if poc.ThreatModel.TargetSingleCandidateBits != 96 || poc.ThreatModel.TargetResidualBits != 0 || poc.ThreatModel.TargetWorkFactorBits != 0 {
		t.Fatalf("single-candidate target encoded under the wrong semantics: %+v", poc.ThreatModel)
	}
}

func TestPresetManifestRejectsDivergentTargetsAndQueryScopes(t *testing.T) {
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V2)
	preset.ThreatModel.TargetResidualBits++
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("threat-model target differing from the selected profile was accepted")
	}
	preset, _ = LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V2)
	preset.Issuance.ROQueryCaps[0] /= 2
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("issuance query scope differing from the showing/profile scope was accepted")
	}
	preset, _ = LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V2)
	preset.ThreatModel.MaxProofsLog2 = math.NaN()
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("non-finite threat-model volume was accepted")
	}
	preset, _ = LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V2)
	preset.Showing.TranscriptOmissionMode = ""
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("missing showing transcript omission mode was accepted")
	}
}

func TestDefaultPresetNamesContainEveryExecutablePreset(t *testing.T) {
	names := IntGenISISDefaultPresetNames()
	if len(names) != len(IntGenISISPresetNames()) {
		t.Fatalf("canonical names=%d registry entries=%d", len(names), len(IntGenISISPresetNames()))
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		preset, ok := LookupIntGenISISPreset(name)
		if !ok {
			t.Fatalf("listed canonical ID %q did not resolve", name)
		}
		if preset.CanonicalID != name {
			t.Fatalf("listed canonical ID %q resolved to %q", name, preset.CanonicalID)
		}
		if seen[name] {
			t.Fatalf("duplicate canonical ID %q", name)
		}
		seen[name] = true
	}
}
