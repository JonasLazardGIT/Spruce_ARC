package credential

import "testing"

func TestIntGenISISPresetRegistryContainsOnlyCoherentUniquePresets(t *testing.T) {
	want := []string{
		IntGenISISPresetN1024BQ32_96,
		IntGenISISPresetN1024Compact125,
		IntGenISISPresetN1024Q10_96,
		IntGenISISPresetN1024Q16_96,
		IntGenISISPresetN512Compact96,
		IntGenISISPresetSystemN1024WF128CROMV1,
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
		if p.SoundnessGate != "smallwood_2025_1085_live" {
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
		IntGenISISPresetN512Compact96:          "SC-96",
		IntGenISISPresetN1024Compact125:        "SC-125",
		IntGenISISPresetN1024BQ32_96:           "BQ32-96",
		IntGenISISPresetN1024Q10_96:            "BQ10-96",
		IntGenISISPresetN1024Q16_96:            "BQ16-96",
		IntGenISISPresetSystemN1024WF128CROMV1: "WF-128",
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

func TestN1024WF128CROMPresetIsExecutableCandidate(t *testing.T) {
	p, ok := LookupIntGenISISPreset(IntGenISISPresetSystemN1024WF128CROMV1)
	if !ok {
		t.Fatal("system-n1024-wf128-crom-v1 missing")
	}
	if p.Name != IntGenISISPresetSystemN1024WF128CROMV1 || p.Profile != ProfileIntGenISISC || p.SecurityProfile != "WF-128" || p.SecurityMode != string(SecurityModeQueryWorkFactor) {
		t.Fatalf("WF-128 identity/profile=%+v", p)
	}
	if p.Lifecycle != PresetCandidate || p.ClaimScope != ClaimCompleteSystem || p.CompleteSystemClaim {
		t.Fatalf("WF-128 claim classification lifecycle=%q scope=%q complete=%v", p.Lifecycle, p.ClaimScope, p.CompleteSystemClaim)
	}
	if p.Showing.ROQueryCapsSet || p.Showing.ROQueryCaps != [5]int{} || p.Showing.ROQueryCapBitsSet || p.Showing.ROQueryCapBits != [5]float64{} {
		t.Fatalf("WF-128 must not carry bounded-query caps: %+v", p.Showing)
	}
	if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 43 || p.Showing.NLeaves != 524288 || p.Showing.Eta != 46 || p.Showing.Theta != 7 || p.Showing.Rho != 1 || p.Showing.Ell != 9 || p.Showing.EllPrime != 1 || p.Showing.Kappa != [4]int{0, 0, 4, 13} {
		t.Fatalf("WF-128 showing geometry=%+v", p.Showing)
	}
	if p.Showing.DECSCollisionBits != 264 || p.Showing.DECSHashBits != 264 || p.Showing.DECSTapeBits != 128 || p.Showing.FSCollisionBits != 264 || p.Showing.SaltBits != 256 {
		t.Fatalf("WF-128 widths=%+v", p.Showing)
	}
	if p.PRFProfile != IntGenISISPRFProfileTag13 || p.PRFParamsPath != IntGenISISPRFParamsTag13 || p.PRFParamsDigest != IntGenISISPRFParamsTag13Digest {
		t.Fatalf("WF-128 PRF binding=(%q,%q,%q)", p.PRFProfile, p.PRFParamsPath, p.PRFParamsDigest)
	}
	if p.Issuance.PRFCompanionMode != "" || p.Issuance.SigShortnessRadix != 0 || p.Issuance.CompressedRows != 0 || p.Issuance.DECSHashBits != p.Showing.DECSHashBits || p.Issuance.PRFProfile != p.PRFProfile {
		t.Fatalf("WF-128 issuance tuple=%+v", p.Issuance)
	}
	if p.ThreatModel.TargetWorkFactorBits != 128 || p.ThreatModel.ROQueryCapLog2 != [5]float64{} || p.ThreatModel.AcceptedIssuance != 1 || p.ThreatModel.AcceptedShowing != 1 {
		t.Fatalf("WF-128 threat model=%+v", p.ThreatModel)
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
	if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 40 || p.Showing.NLeaves != 786432 || p.Showing.Eta != 46 {
		t.Fatalf("bq32 tuned geometry=%+v", p.Showing)
	}
	if p.TargetTheoremBits != 99.5 || p.Showing.TargetTheoremBits != 99.5 || p.Issuance.TargetTheoremBits != 99.5 {
		t.Fatalf("bq32 engineering theorem target=(preset=%v issuance=%v showing=%v)", p.TargetTheoremBits, p.Issuance.TargetTheoremBits, p.Showing.TargetTheoremBits)
	}
	if p.MaxNLeaves != 786432 || p.Issuance.LVCSNCols != 40 || p.Issuance.NLeaves != 786432 || p.Issuance.Eta != 46 {
		t.Fatalf("bq32 issuance/max leaves geometry=(max=%d issuance=%+v)", p.MaxNLeaves, p.Issuance)
	}
	if p.Showing.Theta != 7 || p.Showing.Rho != 1 || p.Showing.Ell != 9 || p.Showing.EllPrime != 1 {
		t.Fatalf("bq32 soundness tuple=%+v", p.Showing)
	}
	if p.Showing.Kappa != [4]int{0, 0, 2, 7} {
		t.Fatalf("bq32 kappa=%+v", p.Showing.Kappa)
	}
	if p.Showing.DECSHashBits != 168 || p.Showing.DECSTapeBits != 136 || p.Showing.FSCollisionBits != 168 || p.Showing.SaltBits != 168 {
		t.Fatalf("bq32 split widths showing=%+v", p.Showing)
	}
	if p.Issuance.DECSHashBits != p.Showing.DECSHashBits || p.Issuance.DECSTapeBits != p.Showing.DECSTapeBits || p.Issuance.FSCollisionBits != p.Showing.FSCollisionBits {
		t.Fatalf("bq32 issuance/showing split width mismatch: issuance=%+v showing=%+v", p.Issuance, p.Showing)
	}
	if !p.Showing.ROQueryCapsSet || p.Showing.ROQueryCaps != [5]int{int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32), int(uint64(1) << 32)} {
		t.Fatalf("bq32 query caps=%v set=%v", p.Showing.ROQueryCaps, p.Showing.ROQueryCapsSet)
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

func TestN1024Compact125Preset(t *testing.T) {
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
		"n1024-compact96", "artifact-n1024-sc96-v1",
		"n1024-q32-96", "artifact-n1024-bq32-r96-historical-v1",
		"n1024-q10-128", "artifact-n1024-bq10-r128-historical-v1",
		"n1024-q16-128", "artifact-n1024-bq16-r128-historical-v1",
		"n1024-q32-128", "research-n1024-bq32-r128-v1",
		"n1024-bq64-96-theta11", "internal-n1024-bq64-r96-theta11-v1",
		"n1024-bq64-128-theta13-h256", "internal-n1024-bq64-r128-theta13-h256-v1",
		"n1024-bq128-128-raw128-residual128-theta13-lvcs48-h512", "research-n1024-bq128-r128-v1",
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

func TestIntGenISISPresetSecurityTupleUniquenessRejectsDuplicate(t *testing.T) {
	reg := intGenISISPresetRegistry()
	duplicate := reg[IntGenISISPresetN512Compact96]
	duplicate.Name = "duplicate-sc96"
	duplicate.CanonicalID = "duplicate-sc96-v1"
	reg[duplicate.Name] = duplicate
	if err := validateIntGenISISPresetSecurityTupleUniqueness(reg); err == nil {
		t.Fatal("duplicate security tuple was accepted")
	}
}

func TestRegisteredPRFProfilesExposeExecutedTagWidths(t *testing.T) {
	for profile, want := range map[string]int{
		IntGenISISPRFProfileDefault: 7,
		IntGenISISPRFProfileTag9:    9,
		IntGenISISPRFProfileTag13:   13,
	} {
		got, ok := IntGenISISPRFProfileTagElements(profile)
		if !ok || got != want {
			t.Fatalf("profile %s tag width=(%d,%v), want (%d,true)", profile, got, ok, want)
		}
	}
	for profile, want := range map[string]string{
		IntGenISISPRFProfileDefault: IntGenISISPRFParamsDefaultDigest,
		IntGenISISPRFProfileTag9:    IntGenISISPRFParamsTag9Digest,
		IntGenISISPRFProfileTag13:   IntGenISISPRFParamsTag13Digest,
	} {
		got, ok := IntGenISISPRFProfileParamsDigest(profile)
		if !ok || got != want {
			t.Fatalf("profile %s parameter digest=(%s,%v), want (%s,true)", profile, got, ok, want)
		}
	}
	if got := IntGenISISPRFSeedEntropyBits(); got <= 152 || got >= 153 {
		t.Fatalf("executed PRF seed entropy=%f, want between 152 and 153 bits", got)
	}
}
