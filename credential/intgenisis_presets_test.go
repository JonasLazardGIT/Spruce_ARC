package credential

import "testing"

func TestIntGenISISPresetRegistryIsMaintainedOnly(t *testing.T) {
	want := []string{
		IntGenISISPresetN1024Compact125,
		IntGenISISPresetN1024Compact96,
		IntGenISISPresetN1024Q10_128,
		IntGenISISPresetN1024Q10_96,
		IntGenISISPresetN1024Q16_128,
		IntGenISISPresetN1024Q16_96,
		IntGenISISPresetN1024Q32_128,
		IntGenISISPresetN1024Q32_96,
		IntGenISISPresetN512Compact96,
	}
	names := IntGenISISPresetNames()
	if len(names) != len(want) {
		t.Fatalf("preset names=%v want exactly %v", names, want)
	}
	for i, name := range want {
		if names[i] != name {
			t.Fatalf("preset names=%v want exactly %v", names, want)
		}
		p, ok := LookupIntGenISISPreset(name)
		if !ok {
			t.Fatalf("preset %q not found", name)
		}
		if p.Name != name {
			t.Fatalf("preset name=%q want %q", p.Name, name)
		}
		if p.TargetTheoremBits == 0 || p.SoundnessGate != "smallwood_2025_1085_live" {
			t.Fatalf("maintained preset %s has invalid target/gate: %+v", name, p)
		}
		if p.Showing.TranscriptMode != "smallfield_2025_1085_v1" || p.Showing.PRFCompanionMode != "direct_full" || !p.Showing.FixedTranscriptSize {
			t.Fatalf("maintained preset %s showing tuple=%+v", name, p.Showing)
		}
		if p.Issuance.PRFCompanionMode != "" || p.Issuance.SigShortnessRadix != 0 || p.Issuance.TranscriptMode != "smallfield_2025_1085_v1" || !p.Issuance.FixedTranscriptSize {
			t.Fatalf("maintained preset %s issuance tuple=%+v", name, p.Issuance)
		}
	}
}

func TestN512Compact96Preset(t *testing.T) {
	p, ok := LookupIntGenISISPreset(IntGenISISPresetN512Compact96)
	if !ok {
		t.Fatal("n512-compact96 missing")
	}
	if p.Profile != ProfileIntGenISISB || p.TargetTheoremBits != 96 || p.NTRUBeta != IntGenISISN512SignatureBeta {
		t.Fatalf("n512 target/profile/beta=(%q,%v,%d)", p.Profile, p.TargetTheoremBits, p.NTRUBeta)
	}
	if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 36 || p.Showing.NLeaves != 262144 || p.Showing.Eta != 36 {
		t.Fatalf("n512 showing tuple=%+v", p.Showing)
	}
	if p.Showing.Theta != 5 || p.Showing.Rho != 1 || p.Showing.Ell != 7 || p.Showing.EllPrime != 1 {
		t.Fatalf("n512 soundness tuple=%+v", p.Showing)
	}
	if p.Showing.Kappa != [4]int{0, 0, 6, 8} || p.Showing.SigShortnessRadix != 7 || p.Showing.SigShortnessDigits != 5 {
		t.Fatalf("n512 shortness tuple=%+v", p.Showing)
	}
	if p.Showing.ReplayProjection != "project_u_digits_and_y_view_v3" {
		t.Fatalf("n512 projection=%q", p.Showing.ReplayProjection)
	}
}

func TestN1024CompactPresets(t *testing.T) {
	compact96, ok := LookupIntGenISISPreset(IntGenISISPresetN1024Compact96)
	if !ok {
		t.Fatal("n1024-compact96 missing")
	}
	if compact96.Profile != ProfileIntGenISISC || compact96.TargetTheoremBits != 96 {
		t.Fatalf("compact96 target/profile=(%q,%v)", compact96.Profile, compact96.TargetTheoremBits)
	}
	if compact96.Showing.NCols != 32 || compact96.Showing.LVCSNCols != 43 || compact96.Showing.NLeaves != 230208 || compact96.Showing.Eta != 40 {
		t.Fatalf("compact96 showing tuple=%+v", compact96.Showing)
	}
	if compact96.Showing.Kappa != [4]int{0, 0, 6, 11} || compact96.Showing.SigShortnessRadix != 7 || compact96.Showing.SigShortnessDigits != 5 || compact96.Showing.CompressedRows != 1 {
		t.Fatalf("compact96 shortness/compression tuple=%+v", compact96.Showing)
	}
	if compact96.Showing.ReplayProjection != "project_u_digits_y_w_residual_v5" {
		t.Fatalf("compact96 projection=%q", compact96.Showing.ReplayProjection)
	}
	if compact96.Showing.ROQueryCapsSet || compact96.Showing.ROQueryCaps != [5]int{} || compact96.Showing.DECSCollisionBits != 0 {
		t.Fatalf("compact96 should use default accounting overrides: %+v", compact96.Showing)
	}

	compact125, ok := LookupIntGenISISPreset(IntGenISISPresetN1024Compact125)
	if !ok {
		t.Fatal("n1024-compact125 missing")
	}
	if compact125.Profile != ProfileIntGenISISC || compact125.TargetTheoremBits != 125 {
		t.Fatalf("compact125 target/profile=(%q,%v)", compact125.Profile, compact125.TargetTheoremBits)
	}
	if compact125.Showing.NCols != 32 || compact125.Showing.LVCSNCols != 46 || compact125.Showing.NLeaves != 608192 || compact125.Showing.Eta != 48 {
		t.Fatalf("compact125 showing tuple=%+v", compact125.Showing)
	}
	if compact125.Showing.Kappa != [4]int{0, 0, 0, 5} || compact125.Showing.SigShortnessRadix != 11 || compact125.Showing.SigShortnessDigits != 4 || compact125.Showing.CompressedRows != 1 {
		t.Fatalf("compact125 shortness/compression tuple=%+v", compact125.Showing)
	}
	if compact125.Showing.ReplayProjection != "project_u_digits_y_w_residual_v5" {
		t.Fatalf("compact125 projection=%q", compact125.Showing.ReplayProjection)
	}
	if compact125.Showing.ROQueryCapsSet || compact125.Showing.ROQueryCaps != [5]int{} || compact125.Showing.DECSCollisionBits != 0 {
		t.Fatalf("compact125 should use default accounting overrides: %+v", compact125.Showing)
	}
	if compact125.TargetTheoremBits >= 128 {
		t.Fatal("compact125 must remain a 125+ preset, not a claimed 128-bit preset")
	}
}

func TestN1024QueryBudgetPresets(t *testing.T) {
	for _, tc := range []struct {
		name       string
		caps       [5]int
		decsBits   int
		ncols      int
		lvcs       int
		nleaves    int
		eta        int
		theta      int
		ell        int
		kappa      [4]int
		radix      int
		digits     int
		targetBits float64
	}{
		{
			name:       IntGenISISPresetN1024Q10_128,
			caps:       [5]int{1024, 1024, 1024, 1024, 1024},
			decsBits:   160,
			ncols:      32,
			lvcs:       36,
			nleaves:    983040,
			eta:        44,
			theta:      7,
			ell:        9,
			kappa:      [4]int{0, 4, 8, 8},
			radix:      11,
			digits:     4,
			targetBits: 128,
		},
		{
			name:       IntGenISISPresetN1024Q16_128,
			caps:       [5]int{65536, 65536, 65536, 65536, 65536},
			decsBits:   168,
			ncols:      32,
			lvcs:       37,
			nleaves:    524288,
			eta:        44,
			theta:      8,
			ell:        10,
			kappa:      [4]int{0, 0, 0, 8},
			radix:      7,
			digits:     5,
			targetBits: 128,
		},
		{
			name:       IntGenISISPresetN1024Q32_128,
			caps:       [5]int{int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32)},
			decsBits:   200,
			ncols:      32,
			lvcs:       37,
			nleaves:    655360,
			eta:        48,
			theta:      9,
			ell:        11,
			kappa:      [4]int{0, 0, 0, 7},
			radix:      7,
			digits:     5,
			targetBits: 128,
		},
		{
			name:       IntGenISISPresetN1024Q10_96,
			caps:       [5]int{1024, 1024, 1024, 1024, 1024},
			decsBits:   128,
			ncols:      32,
			lvcs:       37,
			nleaves:    720896,
			eta:        40,
			theta:      6,
			ell:        7,
			kappa:      [4]int{0, 0, 0, 8},
			radix:      7,
			digits:     5,
			targetBits: 96,
		},
		{
			name:       IntGenISISPresetN1024Q16_96,
			caps:       [5]int{65536, 65536, 65536, 65536, 65536},
			decsBits:   136,
			ncols:      32,
			lvcs:       38,
			nleaves:    393216,
			eta:        40,
			theta:      6,
			ell:        8,
			kappa:      [4]int{0, 0, 3, 7},
			radix:      11,
			digits:     4,
			targetBits: 96,
		},
		{
			name:       IntGenISISPresetN1024Q32_96,
			caps:       [5]int{int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32)},
			decsBits:   168,
			ncols:      32,
			lvcs:       37,
			nleaves:    458752,
			eta:        44,
			theta:      7,
			ell:        9,
			kappa:      [4]int{0, 0, 2, 7},
			radix:      7,
			digits:     5,
			targetBits: 96,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := LookupIntGenISISPreset(tc.name)
			if !ok {
				t.Fatalf("%s missing", tc.name)
			}
			if p.Profile != ProfileIntGenISISC || p.TargetTheoremBits != tc.targetBits {
				t.Fatalf("%s target/profile=(%q,%v)", tc.name, p.Profile, p.TargetTheoremBits)
			}
			if p.Showing.NCols != tc.ncols || p.Showing.LVCSNCols != tc.lvcs || p.Showing.NLeaves != tc.nleaves || p.Showing.Eta != tc.eta {
				t.Fatalf("%s showing geometry=%+v", tc.name, p.Showing)
			}
			if p.Showing.Theta != tc.theta || p.Showing.Rho != 1 || p.Showing.Ell != tc.ell || p.Showing.EllPrime != 1 {
				t.Fatalf("%s soundness tuple=%+v", tc.name, p.Showing)
			}
			if p.Showing.Kappa != tc.kappa || !p.Showing.ROQueryCapsSet || p.Showing.ROQueryCaps != tc.caps || p.Showing.DECSCollisionBits != tc.decsBits {
				t.Fatalf("%s accounting tuple=%+v", tc.name, p.Showing)
			}
			if p.Showing.SigShortnessRadix != tc.radix || p.Showing.SigShortnessDigits != tc.digits || p.Showing.CompressedRows != 1 {
				t.Fatalf("%s shortness/compression tuple=%+v", tc.name, p.Showing)
			}
			if p.Issuance.ROQueryCaps != tc.caps || !p.Issuance.ROQueryCapsSet || p.Issuance.DECSCollisionBits != tc.decsBits {
				t.Fatalf("%s issuance accounting tuple=%+v", tc.name, p.Issuance)
			}
			if p.Issuance.PRFCompanionMode != "" || p.Issuance.SigShortnessRadix != 0 || p.Issuance.CompressedRows != 0 {
				t.Fatalf("%s issuance retained showing-only fields: %+v", tc.name, p.Issuance)
			}
		})
	}
}

func TestHistoricalPresetSelectorsAreRemoved(t *testing.T) {
	removedDegree256Fast := "n" + "256-sw96"
	removedDegree256High := "n" + "256-sw128"
	for _, name := range []string{
		"96bit", "120bitsf", "fast96", "fast-local",
		"sw96-lvcs64", "sw128-lvcs64", removedDegree256Fast, removedDegree256High,
		"n1024-sw90-smallfield", "n1024-sw128",
	} {
		if _, ok := LookupIntGenISISPreset(name); ok {
			t.Fatalf("removed preset selector %q still resolves", name)
		}
		if got, err := ResolveIntGenISISPresetSelector(name, false); err != nil || got != name {
			t.Fatalf("removed selector normalization changed %q -> %q, %v", name, got, err)
		}
	}
	if _, err := ResolveIntGenISISPresetSelector("", true); err == nil {
		t.Fatal("-96bit compatibility flag should be rejected")
	}
}
