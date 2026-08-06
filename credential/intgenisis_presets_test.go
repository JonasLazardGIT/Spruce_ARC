package credential

import "testing"

func TestIntGenISISPresetRegistryContainsOnlyCoherentUniquePresets(t *testing.T) {
	want := []string{
		IntGenISISPresetN1024BQ32_96,
		IntGenISISPresetN1024Compact125,
		IntGenISISPresetN1024Q10_96,
		IntGenISISPresetN1024Q16_96,
		IntGenISISPresetN512Compact96,
		IntGenISISPresetPoCN1024BQ128R128V3,
		IntGenISISPresetPoCN1024BQ64R128V2,
		IntGenISISPresetPoCN1024BQ96R128V2,
		IntGenISISPublicationPresetBQ128Q128V4,
		IntGenISISPublicationPresetBQ128Q64V4,
		IntGenISISPublicationPresetBQ96Q32V4,
		IntGenISISPublicationPresetBQ96Q96V4,
		IntGenISISPublicationPresetWF128V4,
		IntGenISISPresetSystemN1024WF128CROMV2,
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
		v3Target := name == IntGenISISPresetPoCN1024BQ128R128V3 || name == IntGenISISPresetSystemN1024WF128CROMV2
		v4Target := isIntGenISISPublicationPresetV4ID(name)
		wantGate := IntGenISISSecurityGateV2
		wantTranscript := IntGenISISTranscriptProtocolV2
		wantOmission := IntGenISISTranscriptOmissionModeV2
		if v3Target {
			wantGate = IntGenISISSecurityGateV3
			wantTranscript = IntGenISISTranscriptProtocolV3
			wantOmission = IntGenISISTranscriptOmissionModeV3
		}
		if v4Target {
			wantGate = IntGenISISSecurityGateV4
			wantTranscript = IntGenISISTranscriptProtocolV4
			wantOmission = IntGenISISTranscriptOmissionModeV3
		}
		wantCompanionMode := "direct_full"
		if v3Target || v4Target {
			wantCompanionMode = ""
		}
		if p.SoundnessGate != wantGate {
			t.Fatalf("maintained preset %s has invalid gate: %+v", name, p)
		}
		if p.Showing.TranscriptMode != wantTranscript || p.Showing.TranscriptOmissionMode != wantOmission || p.Showing.PRFCompanionMode != wantCompanionMode || !p.Showing.FixedTranscriptSize {
			t.Fatalf("maintained preset %s showing tuple=%+v", name, p.Showing)
		}
		if (v3Target || v4Target) && (p.Showing.PRFGroupRounds != 0 || p.Showing.CheckpointSamples != 0) {
			t.Fatalf("strict-v3 preset %s retained companion bridge metadata: %+v", name, p.Showing)
		}
		if p.Issuance.PRFCompanionMode != "" || p.Issuance.SigShortnessRadix != 0 || p.Issuance.TranscriptMode != wantTranscript || p.Issuance.TranscriptOmissionMode != wantOmission || !p.Issuance.FixedTranscriptSize {
			t.Fatalf("maintained preset %s issuance tuple=%+v", name, p.Issuance)
		}
		for phase, tuning := range map[string]IntGenISISTuningPreset{"issuance": p.Issuance, "showing": p.Showing} {
			if got, err := ResolveIntGenISISTranscriptOmission(tuning.TranscriptOmissionMode); err != nil || got != wantOmission {
				t.Fatalf("maintained preset %s %s omission mode did not resolve exactly: got=%q err=%v", name, phase, got, err)
			}
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
		IntGenISISPresetPoCN1024BQ64R128V2:     "BQ64-128",
		IntGenISISPresetPoCN1024BQ96R128V2:     "BQ96-128",
		IntGenISISPresetPoCN1024BQ128R128V3:    "BQ128-128",
		IntGenISISPresetSystemN1024WF128CROMV2: "WF-128",
		IntGenISISPublicationPresetBQ96Q32V4:   intGenISISPublicationSecurityProfileBQ96Q32V4,
		IntGenISISPublicationPresetBQ96Q96V4:   intGenISISPublicationSecurityProfileBQ96Q96V4,
		IntGenISISPublicationPresetWF128V4:     intGenISISPublicationSecurityProfileWF128V4,
		IntGenISISPublicationPresetBQ128Q64V4:  intGenISISPublicationSecurityProfileBQ128Q64V4,
		IntGenISISPublicationPresetBQ128Q128V4: intGenISISPublicationSecurityProfileBQ128Q128V4,
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
	p, ok := LookupIntGenISISPreset(IntGenISISPresetSystemN1024WF128CROMV2)
	if !ok {
		t.Fatal("system-n1024-wf128-crom-v2 missing")
	}
	if p.Name != IntGenISISPresetSystemN1024WF128CROMV2 || p.Profile != ProfileIntGenISISC || p.SecurityProfile != "WF-128" || p.SecurityMode != string(SecurityModeQueryWorkFactor) {
		t.Fatalf("WF-128 identity/profile=%+v", p)
	}
	if p.Lifecycle != PresetCandidate || p.ClaimScope != ClaimProofOnly || p.CompleteSystemClaim {
		t.Fatalf("WF-128 claim classification lifecycle=%q scope=%q complete=%v", p.Lifecycle, p.ClaimScope, p.CompleteSystemClaim)
	}
	if p.Showing.ROQueryCapsSet || p.Showing.ROQueryCaps != [5]int{} || p.Showing.ROQueryCapBitsSet || p.Showing.ROQueryCapBits != [5]float64{} {
		t.Fatalf("WF-128 must not carry bounded-query caps: %+v", p.Showing)
	}
	if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 41 || p.Showing.NLeaves != 327680 || p.Showing.Eta != 43 || p.Showing.Theta != 7 || p.Showing.Rho != 1 || p.Showing.Ell != 9 || p.Showing.EllPrime != 1 || p.Showing.Kappa != [4]int{1, 0, 2, 13} {
		t.Fatalf("WF-128 showing geometry=%+v", p.Showing)
	}
	if p.Issuance.LVCSNCols != 42 {
		t.Fatalf("WF-128 issuance L=%d want frozen incumbent 42", p.Issuance.LVCSNCols)
	}
	if p.Showing.DECSCollisionBits != 264 || p.Showing.DECSHashBits != 264 || p.Showing.DECSTapeBits != 128 || p.Showing.FSCollisionBits != 264 || p.Showing.SaltBits != 256 {
		t.Fatalf("WF-128 widths=%+v", p.Showing)
	}
	if p.PRFProfile != IntGenISISPRFProfileTag13 || p.PRFParamsPath != IntGenISISPRFParamsTag13 || p.PRFParamsDigest != IntGenISISPRFParamsTag13Digest {
		t.Fatalf("WF-128 PRF binding=(%q,%q,%q)", p.PRFProfile, p.PRFParamsPath, p.PRFParamsDigest)
	}
	if p.Issuance.PRFCompanionMode != "" || p.Issuance.SigShortnessRadix != 0 || p.Issuance.CompressedRows != 1 || p.Issuance.DECSHashBits != p.Showing.DECSHashBits || p.Issuance.PRFProfile != p.PRFProfile {
		t.Fatalf("WF-128 issuance tuple=%+v", p.Issuance)
	}
	if p.ThreatModel.TargetWorkFactorBits != 128 || p.ThreatModel.ROQueryCapLog2 != [5]float64{} || p.ThreatModel.AcceptedIssuance != 1 || p.ThreatModel.AcceptedShowing != 1 {
		t.Fatalf("WF-128 threat model=%+v", p.ThreatModel)
	}
}

func TestN1024NIZKScopedR128Presets(t *testing.T) {
	tests := []struct {
		name     string
		profile  string
		queryLog float64
		hashBits int
		tapeBits int
		nLeaves  int
		eta      int
		theta    int
		ell      int
		kappa    [4]int
	}{
		{IntGenISISPresetPoCN1024BQ64R128V2, "BQ64-128", 64, 264, 200, 835584, 53, 10, 13, [4]int{8, 2, 9, 13}},
		{IntGenISISPresetPoCN1024BQ96R128V2, "BQ96-128", 96, 328, 232, 557056, 55, 12, 16, [4]int{6, 0, 0, 13}},
		{IntGenISISPresetPoCN1024BQ128R128V3, "BQ128-128", 128, 392, 264, 688128, 59, 13, 18, [4]int{5, 6, 12, 13}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			preset, ok := LookupIntGenISISPreset(tc.name)
			if !ok {
				t.Fatalf("missing preset %s", tc.name)
			}
			if preset.Profile != ProfileIntGenISISC || preset.SecurityProfile != tc.profile ||
				preset.Lifecycle != PresetPoC || preset.ClaimScope != ClaimProofOnly ||
				preset.CompleteSystemClaim {
				t.Fatalf("incorrect identity or claim classification: %+v", preset)
			}
			if preset.CoreBitsRequired != 128 ||
				preset.TargetTheoremBits != 131.5405683813627 ||
				preset.Showing.TargetTheoremBits != preset.TargetTheoremBits {
				t.Fatalf("incorrect primitive or theorem target: %+v", preset)
			}
			wantCaps := [5]float64{tc.queryLog, tc.queryLog, tc.queryLog, tc.queryLog, tc.queryLog}
			if !preset.Showing.ROQueryCapBitsSet || preset.Showing.ROQueryCapsSet ||
				preset.Showing.ROQueryCapBits != wantCaps ||
				preset.ThreatModel.ROQueryCapLog2 != wantCaps {
				t.Fatalf("incorrect logarithmic NIZK query scope: %+v", preset)
			}
			if preset.ThreatModel.MaxProofsLog2 != 32 ||
				preset.ThreatModel.MaxIssuanceProofsLog2 != 31 ||
				preset.ThreatModel.MaxShowingProofsLog2 != 31 ||
				preset.ThreatModel.MaxTagsPerContextLog2 != 4 ||
				preset.ThreatModel.AcceptedIssuance != 1 ||
				preset.ThreatModel.AcceptedShowing != 1 {
				t.Fatalf("incorrect independent proof/tag volume: %+v", preset.ThreatModel)
			}
			showing := preset.Showing
			if showing.NCols != 32 || showing.LVCSNCols != 43 || showing.NLeaves != tc.nLeaves ||
				showing.Eta != tc.eta || showing.Theta != tc.theta || showing.Ell != tc.ell ||
				showing.Rho != 1 || showing.EllPrime != 1 || showing.Kappa != tc.kappa {
				t.Fatalf("incorrect measured SmallWood geometry: %+v", showing)
			}
			wantRadix, wantDigits := 7, 5
			if tc.name == IntGenISISPresetPoCN1024BQ128R128V3 {
				wantRadix, wantDigits = 11, 4
			}
			if showing.SigShortnessRadix != wantRadix || showing.SigShortnessDigits != wantDigits {
				t.Fatalf("incorrect signature shortness R/L=%d/%d want %d/%d", showing.SigShortnessRadix, showing.SigShortnessDigits, wantRadix, wantDigits)
			}
			if showing.DECSCollisionBits != tc.hashBits || showing.DECSHashBits != tc.hashBits ||
				showing.FSCollisionBits != tc.hashBits || showing.DECSTapeBits != tc.tapeBits ||
				showing.SaltBits != 200 {
				t.Fatalf("incorrect transcript widths: %+v", showing)
			}
			if preset.PRFProfile != IntGenISISPRFProfileTag10 ||
				preset.PRFParamsPath != IntGenISISPRFParamsTag10 ||
				preset.PRFParamsDigest != IntGenISISPRFParamsTag10Digest {
				t.Fatalf("incorrect tag-10 binding: %+v", preset)
			}
			if preset.Issuance.PRFCompanionMode != "" ||
				preset.Issuance.SigShortnessRadix != 0 ||
				(tc.name == IntGenISISPresetPoCN1024BQ128R128V3 && preset.Issuance.CompressedRows != 1) ||
				preset.Issuance.ROQueryCapBits != wantCaps ||
				preset.Issuance.PRFProfile != IntGenISISPRFProfileTag10 {
				t.Fatalf("incorrect derived issuance geometry: %+v", preset.Issuance)
			}
		})
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
	if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 43 || p.Showing.NLeaves != 442368 || p.Showing.Eta != 45 {
		t.Fatalf("bq32 tuned geometry=%+v", p.Showing)
	}
	if p.TargetTheoremBits != 99.5 || p.Showing.TargetTheoremBits != 99.5 || p.Issuance.TargetTheoremBits != 99.5 {
		t.Fatalf("bq32 engineering theorem target=(preset=%v issuance=%v showing=%v)", p.TargetTheoremBits, p.Issuance.TargetTheoremBits, p.Showing.TargetTheoremBits)
	}
	if p.MaxNLeaves != 442368 || p.Issuance.LVCSNCols != 43 || p.Issuance.NLeaves != 442368 || p.Issuance.Eta != 45 {
		t.Fatalf("bq32 issuance/max leaves geometry=(max=%d issuance=%+v)", p.MaxNLeaves, p.Issuance)
	}
	if p.Showing.Theta != 7 || p.Showing.Rho != 1 || p.Showing.Ell != 9 || p.Showing.EllPrime != 1 {
		t.Fatalf("bq32 soundness tuple=%+v", p.Showing)
	}
	if p.Showing.Kappa != [4]int{2, 0, 3, 13} {
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
	if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 35 || p.Showing.NLeaves != 147456 || p.Showing.Eta != 33 {
		t.Fatalf("n512 showing tuple=%+v", p.Showing)
	}
	if p.Showing.Theta != 5 || p.Showing.Rho != 1 || p.Showing.Ell != 7 || p.Showing.EllPrime != 1 {
		t.Fatalf("n512 soundness tuple=%+v", p.Showing)
	}
	if p.Showing.Kappa != [4]int{5, 2, 7, 13} || p.Showing.SigShortnessRadix != 7 || p.Showing.SigShortnessDigits != 5 {
		t.Fatalf("n512 shortness tuple=%+v", p.Showing)
	}
	if p.Showing.ReplayProjection != "project_u_digits_y_bounded_sources_v6" {
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
	if compact125.Showing.NCols != 32 || compact125.Showing.LVCSNCols != 42 || compact125.Showing.NLeaves != 264128 || compact125.Showing.Eta != 42 {
		t.Fatalf("compact125 showing tuple=%+v", compact125.Showing)
	}
	if compact125.Showing.Kappa != [4]int{0, 0, 0, 13} || compact125.Showing.SigShortnessRadix != 11 || compact125.Showing.SigShortnessDigits != 4 || compact125.Showing.CompressedRows != 1 {
		t.Fatalf("compact125 shortness/compression tuple=%+v", compact125.Showing)
	}
	if compact125.Showing.ReplayProjection != "project_u_digits_y_bounded_sources_v6" {
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
			lvcs:       34,
			nleaves:    376832,
			eta:        36,
			theta:      6,
			ell:        7,
			kappa:      [4]int{0, 0, 0, 13},
			radix:      7,
			digits:     5,
			targetBits: 96,
		},
		{
			name:       IntGenISISPresetN1024Q16_96,
			caps:       [5]int{65536, 65536, 65536, 65536, 65536},
			decsBits:   136,
			ncols:      32,
			lvcs:       36,
			nleaves:    212992,
			eta:        36,
			theta:      6,
			ell:        8,
			kappa:      [4]int{8, 0, 6, 13},
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

func TestRetiredV1CanonicalIDsNeverAliasV2Presets(t *testing.T) {
	retired := map[string]string{
		"poc-n512-sc96-v1":                      IntGenISISPresetPoCN512SC96V2,
		"artifact-n1024-sc125-v1":               IntGenISISPresetArtifactN1024SC125V2,
		"artifact-n1024-bq10-r96-historical-v1": "artifact-n1024-bq10-r96-v2",
		"artifact-n1024-bq16-r96-historical-v1": "artifact-n1024-bq16-r96-v2",
		"pilot-n1024-bq32-r96-v1":               IntGenISISPresetPilotN1024BQ32R96V2,
		"poc-n1024-bq64-r128-v1":                IntGenISISPresetPoCN1024BQ64R128V2,
		"poc-n1024-bq96-r128-v1":                IntGenISISPresetPoCN1024BQ96R128V2,
		"poc-n1024-bq128-r128-v2":               IntGenISISPresetPoCN1024BQ128R128V3,
		"system-n1024-wf128-crom-v1":            IntGenISISPresetSystemN1024WF128CROMV2,
	}
	aliases := intGenISISPresetAliases()
	for oldID, replacement := range retired {
		if _, ok := aliases[oldID]; ok {
			t.Fatalf("retired canonical ID %q remains an alias for %q", oldID, replacement)
		}
		if preset, ok := LookupIntGenISISPreset(oldID); ok {
			t.Fatalf("retired canonical ID %q resolved to current preset %q", oldID, preset.CanonicalID)
		}
		if got, err := ResolveIntGenISISPresetSelector(oldID, false); err != nil || got != oldID {
			t.Fatalf("retired canonical ID normalization changed %q -> %q, %v", oldID, got, err)
		}
		if _, ok := LookupIntGenISISPreset(replacement); !ok {
			t.Fatalf("v2 replacement %q for retired canonical ID %q is missing", replacement, oldID)
		}
	}
}

func TestStableShortPresetSelectorsResolveOnlyToV2Identities(t *testing.T) {
	want := map[string]string{
		IntGenISISPresetN512Compact96:   IntGenISISPresetPoCN512SC96V2,
		IntGenISISPresetN1024Compact125: IntGenISISPresetArtifactN1024SC125V2,
		IntGenISISPresetN1024Q10_96:     "artifact-n1024-bq10-r96-v2",
		IntGenISISPresetN1024Q16_96:     "artifact-n1024-bq16-r96-v2",
		IntGenISISPresetN1024BQ32_96:    IntGenISISPresetPilotN1024BQ32R96V2,
	}
	for selector, canonicalID := range want {
		preset, ok := LookupIntGenISISPreset(selector)
		if !ok {
			t.Fatalf("stable selector %q does not resolve", selector)
		}
		if preset.Name != selector || preset.CanonicalID != canonicalID || preset.PresetVersion != 2 {
			t.Fatalf("stable selector %q resolved to name=%q canonical_id=%q version=%d; want name=%q canonical_id=%q version=2", selector, preset.Name, preset.CanonicalID, preset.PresetVersion, selector, canonicalID)
		}
	}
}

func TestIntGenISISPresetSecurityTupleUniquenessRejectsDuplicate(t *testing.T) {
	reg := intGenISISPresetRegistry()
	duplicate := reg[IntGenISISPresetN512Compact96]
	duplicate.Name = "duplicate-sc96"
	duplicate.CanonicalID = "duplicate-sc96-v2"
	reg[duplicate.Name] = duplicate
	if err := validateIntGenISISPresetSecurityTupleUniqueness(reg); err == nil {
		t.Fatal("duplicate security tuple was accepted")
	}
}

func TestRegisteredPRFProfilesExposeExecutedTagWidths(t *testing.T) {
	for profile, want := range map[string]int{
		IntGenISISPRFProfileDefault: 7,
		IntGenISISPRFProfileTag9:    9,
		IntGenISISPRFProfileTag10:   10,
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
		IntGenISISPRFProfileTag10:   IntGenISISPRFParamsTag10Digest,
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
