package credential

import "testing"

func TestIntGenISISPresetRegistryIsMaintainedOnly(t *testing.T) {
	want := []string{
		IntGenISISPresetN1024Compact125,
		IntGenISISPresetN1024Compact96,
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
		if p.Showing.TranscriptMode != "smallfield_2025_1085_v1" || p.Showing.PRFCompanionMode != "direct_full" {
			t.Fatalf("maintained preset %s showing tuple=%+v", name, p.Showing)
		}
		if p.Issuance.PRFCompanionMode != "" || p.Issuance.SigShortnessRadix != 0 || p.Issuance.TranscriptMode != "smallfield_2025_1085_v1" {
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
	if compact125.TargetTheoremBits >= 128 {
		t.Fatal("compact125 must remain a 125+ preset, not a claimed 128-bit preset")
	}
}

func TestHistoricalPresetSelectorsAreRemoved(t *testing.T) {
	for _, name := range []string{
		"96bit", "120bitsf", "fast96", "fast-local",
		"sw96-lvcs64", "sw128-lvcs64", "n256-sw96", "n256-sw128",
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
