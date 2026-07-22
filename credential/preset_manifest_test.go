package credential

import (
	"math"
	"testing"
)

func TestCanonicalPresetAliasesResolveToOneManifest(t *testing.T) {
	tests := map[string]string{
		IntGenISISPresetPoCN512SC96V1:            IntGenISISPresetN512Compact96,
		IntGenISISPresetArtifactN1024SC96V1:      IntGenISISPresetN1024Compact96,
		IntGenISISPresetArtifactN1024SC125V1:     IntGenISISPresetN1024Compact125,
		IntGenISISPresetPilotN1024BQ32R96V1:      IntGenISISPresetN1024BQ32_96,
		IntGenISISPresetResearchN1024BQ32R128V1:  IntGenISISPresetN1024Q32_128,
		IntGenISISPresetResearchN1024BQ128R128V1: IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512,
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
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V1)
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
	pilot, _ := LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V1)
	if pilot.ThreatModel.MaxProofsLog2 != 32 || pilot.ThreatModel.MaxIssuanceProofsLog2 != 31 || pilot.ThreatModel.MaxShowingProofsLog2 != 31 {
		t.Fatalf("pilot proof-volume split=%+v", pilot.ThreatModel)
	}
	if pilot.ThreatModel.ROQueryCapScope != ROQueryCapPerPhaseGlobal || pilot.ThreatModel.AcceptedIssuance != 1 || pilot.ThreatModel.AcceptedShowing != 1 {
		t.Fatalf("pilot adversarial composition=%+v", pilot.ThreatModel)
	}
	artifact, _ := LookupIntGenISISPreset(IntGenISISPresetArtifactN1024SC96V1)
	if artifact.ThreatModel.TargetSingleCandidateBits != 96 || artifact.ThreatModel.TargetResidualBits != 0 || artifact.ThreatModel.TargetWorkFactorBits != 0 {
		t.Fatalf("single-candidate target encoded under the wrong semantics: %+v", artifact.ThreatModel)
	}
}

func TestPresetManifestRejectsDivergentTargetsAndQueryScopes(t *testing.T) {
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V1)
	preset.ThreatModel.TargetResidualBits++
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("threat-model target differing from the selected profile was accepted")
	}
	preset, _ = LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V1)
	preset.Issuance.ROQueryCaps[0] /= 2
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("issuance query scope differing from the showing/profile scope was accepted")
	}
	preset, _ = LookupIntGenISISPreset(IntGenISISPresetPilotN1024BQ32R96V1)
	preset.ThreatModel.MaxProofsLog2 = math.NaN()
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("non-finite threat-model volume was accepted")
	}
}

func TestDefaultPresetPortfolioHidesHistoricalAndResearchSelectors(t *testing.T) {
	entries := IntGenISISPresetPortfolio(false, false)
	want := []string{
		IntGenISISPresetPoCN512SC96V1,
		IntGenISISPresetArtifactN1024SC96V1,
		IntGenISISPresetArtifactN1024SC125V1,
		IntGenISISPresetPilotN1024BQ32R96V1,
		IntGenISISPresetSystemN1024WF128CROMV1,
	}
	if len(entries) != len(want) {
		t.Fatalf("default portfolio=%+v", entries)
	}
	for i := range want {
		if entries[i].CanonicalID != want[i] {
			t.Fatalf("default portfolio[%d]=%s want %s", i, entries[i].CanonicalID, want[i])
		}
		if entries[i].Available {
			preset, ok := LookupIntGenISISPreset(entries[i].CanonicalID)
			if !ok || !preset.VisibleByDefault {
				t.Fatalf("default portfolio entry %s is not marked visible", entries[i].CanonicalID)
			}
		}
	}
	if entries[len(entries)-1].Available || entries[len(entries)-1].ClaimScope != ClaimCompleteSystem {
		t.Fatalf("WF-128 portfolio entry=%+v", entries[len(entries)-1])
	}
	if _, err := MustLookupIntGenISISPreset(IntGenISISPresetSystemN1024WF128CROMV1); err == nil {
		t.Fatal("unavailable WF-128 preset unexpectedly resolved as executable")
	}
}
