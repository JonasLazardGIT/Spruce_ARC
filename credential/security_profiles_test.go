package credential

import "testing"

func TestIntGenISISSecurityProfileRegistryLabels(t *testing.T) {
	want := []string{
		"BQ128-128",
		"BQ32-128",
		"BQ32-96",
		"BQ64-128",
		"BQ64-96",
		"SC-125",
		"SC-96",
		"WF-128",
	}
	profiles := IntGenISISSecurityProfiles()
	if len(profiles) != len(want) {
		t.Fatalf("profiles=%v want exactly %v", intGenISISSecurityProfileTestLabels(profiles), want)
	}
	seen := make(map[string]bool, len(profiles))
	for i, profile := range profiles {
		if profile.Label != want[i] {
			t.Fatalf("profiles=%v want exactly %v", intGenISISSecurityProfileTestLabels(profiles), want)
		}
		if seen[profile.Label] {
			t.Fatalf("duplicate security profile label %q", profile.Label)
		}
		seen[profile.Label] = true
		if _, ok := LookupIntGenISISSecurityProfile(profile.Label); !ok {
			t.Fatalf("lookup failed for %s", profile.Label)
		}
	}
}

func TestIntGenISISSecurityProfileSpecsArePopulated(t *testing.T) {
	for _, profile := range IntGenISISSecurityProfiles() {
		if profile.Label == "" || profile.Mode == "" || profile.ROM == "" || profile.Status == "" {
			t.Fatalf("profile has empty required field: %+v", profile)
		}
		if profile.TargetBits <= 0 || profile.CoreBitsRequired <= 0 {
			t.Fatalf("profile %s target/core bits=(%v,%v)", profile.Label, profile.TargetBits, profile.CoreBitsRequired)
		}
		if profile.ROM != ROMModelCROM {
			t.Fatalf("profile %s ROM=%q want %q", profile.Label, profile.ROM, ROMModelCROM)
		}
		for _, cap := range profile.ROQueryCaps {
			if cap == 0 {
				t.Fatalf("profile %s has zero RO query cap in %v", profile.Label, profile.ROQueryCaps)
			}
		}
		if profile.SeedSlots != IntGenISISPRFSeedLen || profile.PackedKeyCoords != IntGenISISPRFPoseidonKeyLen {
			t.Fatalf("profile %s seed/key shape=(%d,%d)", profile.Label, profile.SeedSlots, profile.PackedKeyCoords)
		}
	}
}

func TestIntGenISISSecurityProfilesRequireNewPrimitives(t *testing.T) {
	for _, label := range []string{"BQ32-128", "BQ64-96", "BQ64-128", "BQ128-128"} {
		profile, ok := LookupIntGenISISSecurityProfile(label)
		if !ok {
			t.Fatalf("missing security profile %s", label)
		}
		if profile.Status != SecurityProfileRequiresNewPrimitives {
			t.Fatalf("profile %s status=%q want %q", label, profile.Status, SecurityProfileRequiresNewPrimitives)
		}
	}
}

func TestLookupIntGenISISSecurityProfileNormalizesLabels(t *testing.T) {
	profile, ok := LookupIntGenISISSecurityProfile(" sc-96 ")
	if !ok {
		t.Fatal("normalized SC-96 lookup failed")
	}
	if profile.Label != "SC-96" || profile.Mode != SecurityModeSingleCandidate {
		t.Fatalf("normalized lookup profile=%+v", profile)
	}
	if _, err := MustIntGenISISSecurityProfile("missing"); err == nil {
		t.Fatal("missing security profile lookup should fail")
	}
}

func intGenISISSecurityProfileTestLabels(profiles []IntGenISISSecurityProfileSpec) []string {
	out := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, profile.Label)
	}
	return out
}
