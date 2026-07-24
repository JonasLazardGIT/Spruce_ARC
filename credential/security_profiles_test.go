package credential

import (
	"math"
	"sort"
	"testing"
)

func TestIntGenISISSecurityProfileRegistryLabels(t *testing.T) {
	want := []string{
		"BQ10-128",
		"BQ10-96",
		"BQ128-128",
		"BQ16-128",
		"BQ16-96",
		"BQ32-128",
		"BQ32-96",
		"BQ64-128",
		"BQ64-96",
		"BQ96-128",
		"SC-125",
		"SC-96",
		"WF-128",
		"WF-128-ENG",
	}
	profiles := testIntGenISISSecurityProfiles()
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
	for _, profile := range testIntGenISISSecurityProfiles() {
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
	for _, label := range []string{"BQ10-128", "BQ16-128", "BQ32-128", "BQ64-96"} {
		profile, ok := LookupIntGenISISSecurityProfile(label)
		if !ok {
			t.Fatalf("missing security profile %s", label)
		}
		if profile.Status != SecurityProfileRequiresNewPrimitives {
			t.Fatalf("profile %s status=%q want %q", label, profile.Status, SecurityProfileRequiresNewPrimitives)
		}
	}
}

func TestNIZKScopedR128Profiles(t *testing.T) {
	tests := map[string]struct {
		capBits  float64
		hashBits int
		tapeBits int
	}{
		"BQ64-128":  {capBits: 64, hashBits: 264, tapeBits: 200},
		"BQ96-128":  {capBits: 96, hashBits: 328, tapeBits: 232},
		"BQ128-128": {capBits: 128, hashBits: 392, tapeBits: 264},
	}
	for label, want := range tests {
		profile, ok := LookupIntGenISISSecurityProfile(label)
		if !ok {
			t.Fatalf("missing security profile %s", label)
		}
		if profile.Status != SecurityProfileProofOnly || profile.TargetBits != 128 || profile.CoreBitsRequired != 128 {
			t.Fatalf("%s classification=%+v", label, profile)
		}
		if profile.MinDECSHashBits != want.hashBits || profile.MinFSCollisionBits != want.hashBits ||
			profile.MinDECSTapeBits != want.tapeBits || profile.MinSaltBits != 200 || profile.MinPRFTagElements != 10 {
			t.Fatalf("%s requirements=%+v", label, profile)
		}
		if len(profile.ROQueryCapBits) != 5 {
			t.Fatalf("%s query caps=%v", label, profile.ROQueryCapBits)
		}
		for _, got := range profile.ROQueryCapBits {
			if got != want.capBits {
				t.Fatalf("%s query cap=%v want %.0f", label, got, want.capBits)
			}
		}
	}
}

func TestBQ6496SaltBitsMatchPDFBareTarget(t *testing.T) {
	profile, ok := LookupIntGenISISSecurityProfile("BQ64-96")
	if !ok {
		t.Fatal("missing BQ64-96 profile")
	}
	if profile.MinSaltBits != 224 {
		t.Fatalf("BQ64-96 minimum salt bits=%d want 224 bare PDF target", profile.MinSaltBits)
	}
	if profile.Status != SecurityProfileRequiresNewPrimitives {
		t.Fatalf("BQ64-96 status=%q want %q", profile.Status, SecurityProfileRequiresNewPrimitives)
	}
}

func TestResidualBudgetProfilesExposeLogCaps(t *testing.T) {
	tests := map[string]float64{
		"BQ10-96":   10,
		"BQ10-128":  10,
		"BQ16-96":   16,
		"BQ16-128":  16,
		"BQ32-96":   32,
		"BQ32-128":  32,
		"BQ64-96":   64,
		"BQ64-128":  64,
		"BQ96-128":  96,
		"BQ128-128": 128,
	}
	for label, want := range tests {
		profile, ok := LookupIntGenISISSecurityProfile(label)
		if !ok {
			t.Fatalf("missing profile %s", label)
		}
		if len(profile.ROQueryCapBits) != 5 {
			t.Fatalf("%s log caps=%v want five entries", label, profile.ROQueryCapBits)
		}
		for _, got := range profile.ROQueryCapBits {
			if got != want {
				t.Fatalf("%s log cap=%v want %v in %v", label, got, want, profile.ROQueryCapBits)
			}
		}
		if want >= 64 && len(profile.ROQueryCaps) != 0 {
			t.Fatalf("%s uint64 caps should be empty for 2^%.0f budget: %v", label, want, profile.ROQueryCaps)
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
	if _, ok := LookupIntGenISISSecurityProfile("missing"); ok {
		t.Fatal("missing security profile lookup should fail")
	}
}

func TestSecurityProfileValidationRejectsNonFiniteTargets(t *testing.T) {
	profile, _ := LookupIntGenISISSecurityProfile("SC-96")
	profile.TargetBits = math.NaN()
	if err := validateIntGenISISSecurityProfileSpec(profile); err == nil {
		t.Fatal("NaN security target accepted")
	}
	profile, _ = LookupIntGenISISSecurityProfile("SC-96")
	profile.CoreBitsRequired = math.Inf(1)
	if err := validateIntGenISISSecurityProfileSpec(profile); err == nil {
		t.Fatal("infinite primitive requirement accepted")
	}
}

func testIntGenISISSecurityProfiles() []IntGenISISSecurityProfileSpec {
	profiles := intGenISISSecurityProfileSpecs()
	out := make([]IntGenISISSecurityProfileSpec, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, cloneIntGenISISSecurityProfileSpec(profile))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Label < out[j].Label
	})
	return out
}

func intGenISISSecurityProfileTestLabels(profiles []IntGenISISSecurityProfileSpec) []string {
	out := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		out = append(out, profile.Label)
	}
	return out
}
