package credential

import (
	"strings"
	"testing"
)

func TestIntGenISISPresetRegistryIncludesMaintainedAndResearchPresets(t *testing.T) {
	want := []string{
		IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512,
		IntGenISISPresetN1024BQ32_96,
		IntGenISISPresetN1024BQ64_128Theta13H256,
		IntGenISISPresetN1024BQ64_96Theta11,
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
		if p.TargetTheoremBits == 0 {
			t.Fatalf("preset %s has invalid target: %+v", name, p)
		}
		if name == IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512 {
			if p.SoundnessGate != "smallwood_2025_1085_nizk_q128_live" {
				t.Fatalf("BQ128 NIZK preset %s has invalid gate: %+v", name, p)
			}
		} else if name == IntGenISISPresetN1024BQ64_96Theta11 || name == IntGenISISPresetN1024BQ64_128Theta13H256 {
			if p.SoundnessGate != "smallwood_2025_1085_theorem_trail" {
				t.Fatalf("research preset %s has invalid gate: %+v", name, p)
			}
		} else if p.SoundnessGate != "smallwood_2025_1085_live" {
			t.Fatalf("maintained preset %s has invalid gate: %+v", name, p)
		}
		if p.Showing.TranscriptMode != "smallfield_2025_1085_v1" || p.Showing.PRFCompanionMode != "direct_full" || !p.Showing.FixedTranscriptSize {
			t.Fatalf("maintained preset %s showing tuple=%+v", name, p.Showing)
		}
		if p.Issuance.PRFCompanionMode != "" || p.Issuance.SigShortnessRadix != 0 || p.Issuance.TranscriptMode != "smallfield_2025_1085_v1" || !p.Issuance.FixedTranscriptSize {
			t.Fatalf("maintained preset %s issuance tuple=%+v", name, p.Issuance)
		}
	}
}

func TestIntGenISISPresetSecurityProfileMetadata(t *testing.T) {
	wantProfiles := map[string]string{
		IntGenISISPresetN512Compact96:                              "SC-96",
		IntGenISISPresetN1024Compact96:                             "SC-96",
		IntGenISISPresetN1024Compact125:                            "SC-125",
		IntGenISISPresetN1024BQ32_96:                               "BQ32-96",
		IntGenISISPresetN1024BQ64_96Theta11:                        "BQ64-96",
		IntGenISISPresetN1024BQ64_128Theta13H256:                   "BQ64-128",
		IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512: "BQ128-128",
		IntGenISISPresetN1024Q10_128:                               "BQ32-128",
		IntGenISISPresetN1024Q16_128:                               "BQ32-128",
		IntGenISISPresetN1024Q32_128:                               "BQ32-128",
		IntGenISISPresetN1024Q10_96:                                "BQ32-96",
		IntGenISISPresetN1024Q16_96:                                "BQ32-96",
		IntGenISISPresetN1024Q32_96:                                "BQ32-96",
	}
	for _, name := range IntGenISISPresetNames() {
		preset, ok := LookupIntGenISISPreset(name)
		if !ok {
			t.Fatalf("preset %q missing", name)
		}
		wantProfile, ok := wantProfiles[name]
		if !ok {
			t.Fatalf("preset %s missing expected security-profile classification", name)
		}
		if preset.SecurityProfile != wantProfile {
			t.Fatalf("preset %s security profile=%q want %q", name, preset.SecurityProfile, wantProfile)
		}
		profile, ok := LookupIntGenISISSecurityProfile(preset.SecurityProfile)
		if !ok {
			t.Fatalf("preset %s invalid security profile %q", name, preset.SecurityProfile)
		}
		if preset.SecurityMode != string(profile.Mode) {
			t.Fatalf("preset %s security mode=%q want %q", name, preset.SecurityMode, profile.Mode)
		}
		if preset.CoreBitsRequired != profile.CoreBitsRequired {
			t.Fatalf("preset %s core bits=%v want %v", name, preset.CoreBitsRequired, profile.CoreBitsRequired)
		}
		if preset.CompleteSystemClaim != (profile.Status == SecurityProfileCompleteLive) {
			t.Fatalf("preset %s complete claim=%v profile status=%q", name, preset.CompleteSystemClaim, profile.Status)
		}
	}
}

func TestN1024BQ128RawResidualNIZKOnlyPreset(t *testing.T) {
	p, ok := LookupIntGenISISPreset(IntGenISISPresetN1024BQ128_128RawResidualTheta13LVCS48H512)
	if !ok {
		t.Fatal("n1024-bq128 raw-residual NIZK preset missing")
	}
	if p.SecurityProfile != "BQ128-128" || p.SecurityMode != string(SecurityModeResidualAtBudget) {
		t.Fatalf("security tuple=(%q,%q)", p.SecurityProfile, p.SecurityMode)
	}
	if p.CoreBitsRequired != 256 || p.CompleteSystemClaim {
		t.Fatalf("BQ128 preset must stay primitive-blocked at system level: core/claim=(%v,%v)", p.CoreBitsRequired, p.CompleteSystemClaim)
	}
	if p.TargetTheoremBits != 128 || p.SoundnessGate != "smallwood_2025_1085_nizk_q128_live" {
		t.Fatalf("target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
	}
	if p.PRFProfile != IntGenISISPRFProfileTag9 || p.PRFParamsPath != IntGenISISPRFParamsTag9 {
		t.Fatalf("PRF tuple=(%q,%q)", p.PRFProfile, p.PRFParamsPath)
	}
	if p.Profile != ProfileIntGenISISC || p.LVCSNCols != 48 || p.MaxNLeaves != 983040 {
		t.Fatalf("profile/lvcs/max leaves=(%q,%d,%d)", p.Profile, p.LVCSNCols, p.MaxNLeaves)
	}
	if p.Showing.ROQueryCapsSet || p.Showing.ROQueryCaps != [5]int{} {
		t.Fatalf("BQ128 preset must use log caps, not legacy int caps: %+v", p.Showing)
	}
	wantCapBits := [5]float64{128, 128, 128, 128, 128}
	if !p.Showing.ROQueryCapBitsSet || p.Showing.ROQueryCapBits != wantCapBits {
		t.Fatalf("showing log caps=%v set=%v", p.Showing.ROQueryCapBits, p.Showing.ROQueryCapBitsSet)
	}
	if !p.Issuance.ROQueryCapBitsSet || p.Issuance.ROQueryCapBits != wantCapBits {
		t.Fatalf("issuance log caps=%v set=%v", p.Issuance.ROQueryCapBits, p.Issuance.ROQueryCapBitsSet)
	}
	if p.Showing.DECSHashBits != 512 || p.Showing.DECSTapeBits != 256 ||
		p.Showing.FSCollisionBits != 512 || p.Showing.SaltBits != 384 {
		t.Fatalf("showing widths hash=%d tape=%d fs=%d salt=%d",
			p.Showing.DECSHashBits, p.Showing.DECSTapeBits, p.Showing.FSCollisionBits, p.Showing.SaltBits)
	}
	if p.Issuance.DECSHashBits != p.Showing.DECSHashBits || p.Issuance.DECSTapeBits != p.Showing.DECSTapeBits ||
		p.Issuance.FSCollisionBits != p.Showing.FSCollisionBits || p.Issuance.SaltBits != p.Showing.SaltBits {
		t.Fatalf("issuance/showing width mismatch: issuance=%+v showing=%+v", p.Issuance, p.Showing)
	}
	if p.Showing.LVCSNCols != 48 || p.Showing.NLeaves != 983040 || p.Showing.Eta != 65 ||
		p.Showing.Theta != 13 || p.Showing.Ell != 18 || p.Showing.Kappa != [4]int{0, 0, 8, 5} {
		t.Fatalf("showing shape=%+v", p.Showing)
	}
	if p.Showing.SigShortnessRadix != 7 || p.Showing.SigShortnessDigits != 5 || p.Showing.CompressedRows != 1 ||
		p.Showing.ReplayProjection != "project_u_digits_y_w_residual_v5" ||
		p.Showing.TranscriptMode != "smallfield_2025_1085_v1" || !p.Showing.FixedTranscriptSize {
		t.Fatalf("showing execution tuple=%+v", p.Showing)
	}
	if p.Issuance.PRFCompanionMode != "" || p.Issuance.SigShortnessRadix != 0 || p.Issuance.CompressedRows != 0 {
		t.Fatalf("issuance retained showing-only fields: %+v", p.Issuance)
	}
	for _, needle := range []string{"NIZK-only", "2^128", "no valid-prefix discount", "Not a complete IntGenISIS credential-system claim"} {
		if !intGenISISPresetTestNotesContain(p.Notes, needle) {
			t.Fatalf("notes missing %q: %v", needle, p.Notes)
		}
	}
}

func TestN1024BQ32_96PresetIsCandidateWithSplitWidthsAndTag9(t *testing.T) {
	p, ok := LookupIntGenISISPreset(IntGenISISPresetN1024BQ32_96)
	if !ok {
		t.Fatal("n1024-bq32-96 missing")
	}
	if p.SecurityProfile != "BQ32-96" || p.SecurityMode != string(SecurityModeResidualAtBudget) {
		t.Fatalf("bq32 security tuple=(%q,%q)", p.SecurityProfile, p.SecurityMode)
	}
	if p.CompleteSystemClaim {
		t.Fatal("bq32 candidate must not be a complete system claim before live ledger status")
	}
	if p.PRFProfile != IntGenISISPRFProfileTag9 || p.PRFParamsPath != IntGenISISPRFParamsTag9 {
		t.Fatalf("bq32 PRF tuple=(%q,%q)", p.PRFProfile, p.PRFParamsPath)
	}
	if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 40 || p.Showing.NLeaves != 557056 || p.Showing.Eta != 44 {
		t.Fatalf("bq32 tuned geometry=%+v", p.Showing)
	}
	if p.MaxNLeaves != 557056 || p.Issuance.LVCSNCols != 40 || p.Issuance.NLeaves != 557056 || p.Issuance.Eta != 44 {
		t.Fatalf("bq32 issuance/max leaves geometry=(max=%d issuance=%+v)", p.MaxNLeaves, p.Issuance)
	}
	if p.Showing.Theta != 7 || p.Showing.Rho != 1 || p.Showing.Ell != 9 || p.Showing.EllPrime != 1 {
		t.Fatalf("bq32 soundness tuple=%+v", p.Showing)
	}
	if p.Showing.Kappa != [4]int{0, 0, 2, 7} {
		t.Fatalf("bq32 kappa=%+v", p.Showing.Kappa)
	}
	if p.Showing.DECSHashBits != 168 || p.Showing.DECSTapeBits != 128 || p.Showing.FSCollisionBits != 168 || p.Showing.SaltBits != 128 {
		t.Fatalf("bq32 split widths showing=%+v", p.Showing)
	}
	if p.Issuance.DECSHashBits != p.Showing.DECSHashBits || p.Issuance.DECSTapeBits != p.Showing.DECSTapeBits || p.Issuance.FSCollisionBits != p.Showing.FSCollisionBits {
		t.Fatalf("bq32 issuance/showing split width mismatch: issuance=%+v showing=%+v", p.Issuance, p.Showing)
	}
	if !p.Showing.ROQueryCapsSet || p.Showing.ROQueryCaps != [5]int{int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32)} {
		t.Fatalf("bq32 query caps=%v set=%v", p.Showing.ROQueryCaps, p.Showing.ROQueryCapsSet)
	}
}

func TestN1024BQ64TheoremTrailPresetsUseLogCapsAndRemainNonLive(t *testing.T) {
	tests := []struct {
		name         string
		profile      string
		coreBits     float64
		targetBits   float64
		lvcs         int
		nleaves      int
		eta          int
		theta        int
		ell          int
		kappa        [4]int
		hashBits     int
		tapeBits     int
		fsBits       int
		saltBits     int
		requiredNote string
	}{
		{
			name:         IntGenISISPresetN1024BQ64_96Theta11,
			profile:      "BQ64-96",
			coreBits:     160,
			targetBits:   164,
			lvcs:         43,
			nleaves:      983040,
			eta:          58,
			theta:        11,
			ell:          16,
			kappa:        [4]int{0, 11, 13, 2},
			hashBits:     232,
			tapeBits:     160,
			fsBits:       232,
			saltBits:     224,
			requiredNote: "160-bit primitive family",
		},
		{
			name:         IntGenISISPresetN1024BQ64_128Theta13H256,
			profile:      "BQ64-128",
			coreBits:     192,
			targetBits:   200,
			lvcs:         48,
			nleaves:      983040,
			eta:          65,
			theta:        13,
			ell:          18,
			kappa:        [4]int{0, 7, 13, 13},
			hashBits:     256,
			tapeBits:     192,
			fsBits:       256,
			saltBits:     256,
			requiredNote: "192-bit primitive family",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := LookupIntGenISISPreset(tc.name)
			if !ok {
				t.Fatalf("preset %s missing", tc.name)
			}
			if p.SecurityProfile != tc.profile || p.SecurityMode != string(SecurityModeResidualAtBudget) {
				t.Fatalf("security tuple=(%q,%q)", p.SecurityProfile, p.SecurityMode)
			}
			if p.CoreBitsRequired != tc.coreBits || p.CompleteSystemClaim {
				t.Fatalf("core/claim=(%v,%v)", p.CoreBitsRequired, p.CompleteSystemClaim)
			}
			if p.TargetTheoremBits != tc.targetBits || p.SoundnessGate != "smallwood_2025_1085_theorem_trail" {
				t.Fatalf("target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
			}
			if p.PRFProfile != IntGenISISPRFProfileTag9 || p.PRFParamsPath != IntGenISISPRFParamsTag9 {
				t.Fatalf("PRF tuple=(%q,%q)", p.PRFProfile, p.PRFParamsPath)
			}
			if p.Showing.ROQueryCapsSet || p.Showing.ROQueryCaps != [5]int{} {
				t.Fatalf("BQ64 trails must not use legacy int caps: %+v", p.Showing)
			}
			if !p.Showing.ROQueryCapBitsSet || p.Showing.ROQueryCapBits != [5]float64{64, 64, 64, 64, 64} {
				t.Fatalf("log caps=%v set=%v", p.Showing.ROQueryCapBits, p.Showing.ROQueryCapBitsSet)
			}
			if p.Issuance.ROQueryCapBits != p.Showing.ROQueryCapBits || !p.Issuance.ROQueryCapBitsSet {
				t.Fatalf("issuance log caps=%v set=%v", p.Issuance.ROQueryCapBits, p.Issuance.ROQueryCapBitsSet)
			}
			if p.Showing.LVCSNCols != tc.lvcs || p.Showing.NLeaves != tc.nleaves || p.Showing.Eta != tc.eta ||
				p.Showing.Theta != tc.theta || p.Showing.Ell != tc.ell || p.Showing.Kappa != tc.kappa {
				t.Fatalf("showing geometry=%+v", p.Showing)
			}
			if p.Showing.DECSHashBits != tc.hashBits || p.Showing.DECSTapeBits != tc.tapeBits ||
				p.Showing.FSCollisionBits != tc.fsBits || p.Showing.SaltBits != tc.saltBits {
				t.Fatalf("widths hash=%d tape=%d fs=%d salt=%d",
					p.Showing.DECSHashBits, p.Showing.DECSTapeBits, p.Showing.FSCollisionBits, p.Showing.SaltBits)
			}
			if !intGenISISPresetTestNotesContain(p.Notes, "external") || !intGenISISPresetTestNotesContain(p.Notes, tc.requiredNote) {
				t.Fatalf("notes missing theorem/primitive justification: %v", p.Notes)
			}
		})
	}
}

func TestCurrentQBudget128PresetsAreNotCompleteSystemClaims(t *testing.T) {
	for _, name := range []string{
		IntGenISISPresetN1024Q10_128,
		IntGenISISPresetN1024Q16_128,
		IntGenISISPresetN1024Q32_128,
	} {
		preset, ok := LookupIntGenISISPreset(name)
		if !ok {
			t.Fatalf("preset %s missing", name)
		}
		if preset.SecurityProfile != "BQ32-128" {
			t.Fatalf("preset %s security profile=%q want BQ32-128", name, preset.SecurityProfile)
		}
		if preset.CompleteSystemClaim {
			t.Fatalf("preset %s must remain proof/q-budget only", name)
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
	if compact125.SecurityProfile != "SC-125" || compact125.SecurityMode != string(SecurityModeSingleCandidate) || compact125.CompleteSystemClaim {
		t.Fatalf("compact125 security classification=%+v", compact125)
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
			decsBits:   152,
			ncols:      32,
			lvcs:       36,
			nleaves:    983040,
			eta:        44,
			theta:      7,
			ell:        9,
			kappa:      [4]int{0, 4, 9, 9},
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
			eta:        43,
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
			eta:        45,
			theta:      9,
			ell:        11,
			kappa:      [4]int{1, 0, 0, 8},
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

func intGenISISPresetTestNotesContain(notes []string, needle string) bool {
	for _, note := range notes {
		if strings.Contains(note, needle) {
			return true
		}
	}
	return false
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
