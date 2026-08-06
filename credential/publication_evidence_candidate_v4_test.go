package credential

import "testing"

func TestPublicationEvidenceCandidateIsScopedAndManifestBound(t *testing.T) {
	base, ok := LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetBQ128Q64V4)
	if !ok {
		t.Fatal("missing publication base")
	}
	candidate := base
	candidate.Showing.LVCSNCols++
	candidate.LVCSNCols = candidate.Showing.LVCSNCols
	if err := ValidateIntGenISISPresetManifest(candidate); err != nil {
		t.Fatalf("test candidate is invalid: %v", err)
	}
	baseDigest := IntGenISISPresetManifestDigest(base)
	candidateDigest := IntGenISISPresetManifestDigest(candidate)
	if baseDigest == candidateDigest {
		t.Fatal("candidate tuning did not alter the manifest digest")
	}
	called := false
	if err := WithIntGenISISPublicationEvidenceCandidate(candidate, func() error {
		called = true
		got, ok := LookupIntGenISISPreset(candidate.CanonicalID)
		if !ok || IntGenISISPresetManifestDigest(got) != candidateDigest || got.Showing.LVCSNCols != candidate.Showing.LVCSNCols {
			t.Fatalf("scoped lookup did not return candidate: %+v", got)
		}
		if err := WithIntGenISISPublicationEvidenceCandidate(candidate, func() error { return nil }); err == nil {
			t.Fatal("nested evidence candidate session was accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("candidate callback did not run")
	}
	got, ok := LookupIntGenISISPreset(base.CanonicalID)
	if !ok || IntGenISISPresetManifestDigest(got) != baseDigest || got.Showing.LVCSNCols != base.Showing.LVCSNCols {
		t.Fatalf("candidate escaped callback scope: %+v", got)
	}
}

func TestPublicationEvidenceCandidateRejectsSecurityMutation(t *testing.T) {
	candidate, _ := LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetBQ96Q32V4)
	candidate.Showing.SaltBits -= 8
	if err := WithIntGenISISPublicationEvidenceCandidate(candidate, func() error { return nil }); err == nil {
		t.Fatal("undersized candidate security tuple was accepted")
	}
}
