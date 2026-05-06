package credential

import "testing"

func TestIntGenISISPresetRegistryResolvesSecureNames(t *testing.T) {
	want := []string{
		IntGenISISPreset96Bit,
		IntGenISISPreset120BitSF,
		IntGenISISPresetFast96,
		IntGenISISPresetFastLocal,
		IntGenISISPresetSW96LVCS32,
		IntGenISISPresetSW96LVCS64,
		IntGenISISPresetSW96LVCS128,
		IntGenISISPresetSW128LVCS32,
		IntGenISISPresetSW128LVCS64,
		IntGenISISPresetSW128LVCS128,
		IntGenISISPresetN256SW96,
		IntGenISISPresetN256SW128,
		IntGenISISPresetN1024SW90SF,
		IntGenISISPresetN1024SW96,
		IntGenISISPresetN1024SW115SF,
		IntGenISISPresetN1024SW120SF,
		IntGenISISPresetN1024SW128,
	}
	for _, name := range want {
		t.Run(name, func(t *testing.T) {
			p, ok := LookupIntGenISISPreset(name)
			if !ok {
				t.Fatalf("preset %q not found", name)
			}
			if p.Name != name {
				t.Fatalf("preset name=%q want %q", p.Name, name)
			}
			wantProfile := ProfileIntGenISISB
			if name == IntGenISISPreset96Bit || name == IntGenISISPreset120BitSF || name == IntGenISISPresetFast96 || name == IntGenISISPresetN256SW96 || name == IntGenISISPresetN256SW128 {
				wantProfile = ProfileIntGenISISA
			}
			if name == IntGenISISPresetN1024SW90SF || name == IntGenISISPresetN1024SW96 || name == IntGenISISPresetN1024SW115SF || name == IntGenISISPresetN1024SW120SF || name == IntGenISISPresetN1024SW128 {
				wantProfile = ProfileIntGenISISC
			}
			if p.Profile != wantProfile {
				t.Fatalf("preset profile=%q want %q", p.Profile, wantProfile)
			}
			if name != IntGenISISPresetFastLocal {
				if name == IntGenISISPreset96Bit || name == IntGenISISPresetN256SW96 {
					if p.TargetTheoremBits != 96 || p.SoundnessGate != "theorem9_measured" {
						t.Fatalf("96-bit preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 16 || p.Showing.LVCSNCols != 48 || p.Showing.NLeaves != 262144 || p.Showing.Eta != 44 {
						t.Fatalf("96-bit preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 2 || p.Showing.Rho != 3 || p.Showing.Ell != 8 || p.Showing.EllPrime != 3 {
						t.Fatalf("96-bit preset soundness tuple=%+v", p.Showing)
					}
					if p.Showing.Kappa != ([4]int{}) || p.Showing.SigShortnessRadix != 7 || p.Showing.SigShortnessDigits != 5 || p.Showing.CompressedRows != 0 || p.Showing.ReplayProjection == "" {
						t.Fatalf("96-bit preset missing measured viable-frontier shape: %+v", p.Showing)
					}
				} else if name == IntGenISISPresetFast96 {
					if p.TargetTheoremBits != 96 || p.SoundnessGate != "theorem9_measured" {
						t.Fatalf("fast96 preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 52 || p.Showing.NLeaves != 11546 || p.Showing.Eta != 35 {
						t.Fatalf("fast96 preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 2 || p.Showing.Rho != 3 || p.Showing.Ell != 13 || p.Showing.EllPrime != 3 {
						t.Fatalf("fast96 preset soundness tuple=%+v", p.Showing)
					}
					if p.Showing.Kappa != ([4]int{}) || p.Showing.SigShortnessRadix != 5 || p.Showing.SigShortnessDigits != 6 || p.Showing.CompressedRows != 0 || p.Showing.ReplayProjection == "" {
						t.Fatalf("fast96 preset missing measured 25 KiB shape: %+v", p.Showing)
					}
				} else if name == IntGenISISPreset120BitSF {
					if p.TargetTheoremBits != 120 || p.SoundnessGate != "theorem9_measured" {
						t.Fatalf("120bitsf preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 36 || p.Showing.NLeaves != 618048 || p.Showing.Eta != 42 {
						t.Fatalf("120bitsf preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 2 || p.Showing.Rho != 3 || p.Showing.Ell != 9 || p.Showing.EllPrime != 4 {
						t.Fatalf("120bitsf preset soundness tuple=%+v", p.Showing)
					}
					if p.Showing.Kappa != ([4]int{}) || p.Showing.SigShortnessRadix != 5 || p.Showing.SigShortnessDigits != 6 || p.Showing.CompressedRows != 0 || p.Showing.ReplayProjection == "" {
						t.Fatalf("120bitsf preset missing measured small-field shape: %+v", p.Showing)
					}
				} else if name == IntGenISISPresetN256SW128 {
					if p.TargetTheoremBits != 128 || p.SoundnessGate != "theorem9_measured" {
						t.Fatalf("n256-sw128 preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 32 || p.Showing.NLeaves != 917504 || p.Showing.Eta != 40 {
						t.Fatalf("n256-sw128 preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 1 || p.Showing.Rho != 7 || p.Showing.Ell != 9 || p.Showing.EllPrime != 11 {
						t.Fatalf("n256-sw128 preset soundness tuple=%+v", p.Showing)
					}
					if p.Showing.Kappa != ([4]int{}) || p.Showing.SigShortnessRadix != 5 || p.Showing.SigShortnessDigits != 6 || p.Showing.CompressedRows != 0 || p.Showing.ReplayProjection == "" {
						t.Fatalf("n256-sw128 preset missing measured zero-kappa shape: %+v", p.Showing)
					}
				} else if name == IntGenISISPresetN1024SW96 {
					if p.TargetTheoremBits != 96 || p.SoundnessGate != "theorem9_seed" {
						t.Fatalf("n1024-sw96 preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 96 || p.Showing.NLeaves != 262144 || p.Showing.Eta != 44 {
						t.Fatalf("n1024-sw96 preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 2 || p.Showing.Rho != 3 || p.Showing.Ell != 8 || p.Showing.EllPrime != 3 {
						t.Fatalf("n1024-sw96 preset soundness tuple=%+v", p.Showing)
					}
				} else if name == IntGenISISPresetN1024SW90SF {
					if p.TargetTheoremBits != 90 || p.SoundnessGate != "smallwood_2025_1085_live" {
						t.Fatalf("n1024-sw90-smallfield preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 44 || p.Showing.NLeaves != 116864 || p.Showing.Eta != 37 {
						t.Fatalf("n1024-sw90-smallfield preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 5 || p.Showing.Rho != 1 || p.Showing.Ell != 7 || p.Showing.EllPrime != 1 {
						t.Fatalf("n1024-sw90-smallfield preset soundness tuple=%+v", p.Showing)
					}
					if p.Showing.Kappa != [4]int{3, 0, 0, 12} || p.Showing.SigShortnessRadix != 7 || p.Showing.SigShortnessDigits != 5 || p.Showing.CompressedRows != 1 {
						t.Fatalf("n1024-sw90-smallfield shortness/compression tuple=%+v", p.Showing)
					}
					if p.Showing.TranscriptMode != "smallfield_2025_1085_v1" || p.Issuance.TranscriptMode != "" {
						t.Fatalf("n1024-sw90-smallfield transcript modes: issuance=%q showing=%q", p.Issuance.TranscriptMode, p.Showing.TranscriptMode)
					}
				} else if name == IntGenISISPresetN1024SW115SF {
					if p.TargetTheoremBits != 115 || p.SoundnessGate != "smallwood_2025_1085_live" {
						t.Fatalf("n1024-sw115-smallfield preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 36 || p.Showing.NLeaves != 839680 || p.Showing.Eta != 41 {
						t.Fatalf("n1024-sw115-smallfield preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 7 || p.Showing.Rho != 1 || p.Showing.Ell != 8 || p.Showing.EllPrime != 1 {
						t.Fatalf("n1024-sw115-smallfield preset soundness tuple=%+v", p.Showing)
					}
					if p.Showing.Kappa != ([4]int{}) || p.Showing.SigShortnessRadix != 11 || p.Showing.SigShortnessDigits != 4 || p.Showing.CompressedRows != 1 {
						t.Fatalf("n1024-sw115-smallfield shortness/compression tuple=%+v", p.Showing)
					}
					if p.Showing.TranscriptMode != "smallfield_2025_1085_v1" || p.Issuance.TranscriptMode != "" {
						t.Fatalf("n1024-sw115-smallfield transcript modes: issuance=%q showing=%q", p.Issuance.TranscriptMode, p.Showing.TranscriptMode)
					}
				} else if name == IntGenISISPresetN1024SW120SF {
					if p.TargetTheoremBits != 120 || p.SoundnessGate != "smallwood_2025_1085_live" {
						t.Fatalf("n1024-sw120-smallfield preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 32 || p.Showing.LVCSNCols != 52 || p.Showing.NLeaves != 594752 || p.Showing.Eta != 52 {
						t.Fatalf("n1024-sw120-smallfield preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 7 || p.Showing.Rho != 1 || p.Showing.Ell != 9 || p.Showing.EllPrime != 1 {
						t.Fatalf("n1024-sw120-smallfield preset soundness tuple=%+v", p.Showing)
					}
					if p.Showing.SigShortnessRadix != 7 || p.Showing.SigShortnessDigits != 5 || p.Showing.CompressedRows != 0 {
						t.Fatalf("n1024-sw120-smallfield shortness/compression tuple=%+v", p.Showing)
					}
					if p.Showing.TranscriptMode != "smallfield_2025_1085_v1" || p.Issuance.TranscriptMode != "" {
						t.Fatalf("n1024-sw120-smallfield transcript modes: issuance=%q showing=%q", p.Issuance.TranscriptMode, p.Showing.TranscriptMode)
					}
				} else if name == IntGenISISPresetN1024SW128 {
					if p.TargetTheoremBits != 128 || p.SoundnessGate != "theorem9_seed" {
						t.Fatalf("n1024-sw128 preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.NCols != 64 || p.Showing.LVCSNCols != 128 || p.Showing.NLeaves != 917504 || p.Showing.Eta != 40 {
						t.Fatalf("n1024-sw128 preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.Theta != 1 || p.Showing.Rho != 7 || p.Showing.Ell != 9 || p.Showing.EllPrime != 11 {
						t.Fatalf("n1024-sw128 preset soundness tuple=%+v", p.Showing)
					}
				} else if name == IntGenISISPresetSW96LVCS64 || name == IntGenISISPresetSW128LVCS64 {
					wantTheorem := 96.0
					wantKappa := [4]int{0, 0, 0, 6}
					if name == IntGenISISPresetSW128LVCS64 {
						wantTheorem = 128
						wantKappa = [4]int{6, 0, 0, 11}
					}
					if p.TargetTheoremBits != wantTheorem || p.SoundnessGate != "theorem9_grinding" {
						t.Fatalf("default preset theorem target/gate=(%v,%q)", p.TargetTheoremBits, p.SoundnessGate)
					}
					if p.Showing.LVCSNCols != 70 || p.Showing.Kappa != wantKappa {
						t.Fatalf("default preset showing tuple=%+v", p.Showing)
					}
					if p.Showing.SigShortnessRadix != 11 || p.Showing.SigShortnessDigits != 4 || p.Showing.ReplayProjection == "" {
						t.Fatalf("default preset missing R11/L4 projection: %+v", p.Showing)
					}
				} else if p.TargetEq8Bits != 96 && p.TargetEq8Bits != 128 {
					t.Fatalf("target bits=%v", p.TargetEq8Bits)
				}
				if p.LVCSNCols != 32 && p.LVCSNCols != 36 && p.LVCSNCols != 42 && p.LVCSNCols != 44 && p.LVCSNCols != 46 && p.LVCSNCols != 48 && p.LVCSNCols != 52 && p.LVCSNCols != 56 && p.LVCSNCols != 64 && p.LVCSNCols != 70 && p.LVCSNCols != 96 && p.LVCSNCols != 128 {
					t.Fatalf("lvcs_ncols=%d", p.LVCSNCols)
				}
				if name != IntGenISISPresetSW96LVCS64 && name != IntGenISISPresetSW128LVCS64 && (p.Issuance.LVCSNCols != p.LVCSNCols || p.Showing.LVCSNCols != p.LVCSNCols) {
					t.Fatalf("preset %s not fixed-lvcs: issuance=%d showing=%d track=%d", name, p.Issuance.LVCSNCols, p.Showing.LVCSNCols, p.LVCSNCols)
				}
				if p.Showing.PRFCompanionMode == "" || p.Showing.CheckpointSamples <= 0 {
					t.Fatalf("secure preset missing showing PRF settings: %+v", p.Showing)
				}
			}
		})
	}
}

func TestIntGenISISPresetNamesSorted(t *testing.T) {
	names := IntGenISISPresetNames()
	if len(names) < 16 {
		t.Fatalf("preset names=%v", names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("names not sorted: %v", names)
		}
	}
}

func TestResolveIntGenISISPresetSelector(t *testing.T) {
	for _, alias := range []string{"96bit", "96-bit", "96_bit", "96", "sw96"} {
		if got, err := ResolveIntGenISISPresetSelector(alias, false); err != nil || got != IntGenISISPreset96Bit {
			t.Fatalf("alias %q resolved to %q, %v", alias, got, err)
		}
	}
	for _, alias := range []string{"120bitsf", "120", "120-bit-sf", "120_bit_sf", "120sf"} {
		if got, err := ResolveIntGenISISPresetSelector(alias, false); err != nil || got != IntGenISISPreset120BitSF {
			t.Fatalf("alias %q resolved to %q, %v", alias, got, err)
		}
	}
	for _, alias := range []string{"fast96", "fast-96", "fast_96", "runtime96", "runtime-96", "n256-fast96"} {
		if got, err := ResolveIntGenISISPresetSelector(alias, false); err != nil || got != IntGenISISPresetFast96 {
			t.Fatalf("alias %q resolved to %q, %v", alias, got, err)
		}
	}
	for _, alias := range []string{"n1024-sw96", "n1024-96", "n1024-ternary-sw96", "n1024-b1-sw96"} {
		if got, err := ResolveIntGenISISPresetSelector(alias, false); err != nil || got != IntGenISISPresetN1024SW96 {
			t.Fatalf("alias %q resolved to %q, %v", alias, got, err)
		}
	}
	for _, alias := range []string{"n1024-sw90-smallfield", "n1024-sw90", "n1024-90", "n1024-sw90-sf"} {
		if got, err := ResolveIntGenISISPresetSelector(alias, false); err != nil || got != IntGenISISPresetN1024SW90SF {
			t.Fatalf("alias %q resolved to %q, %v", alias, got, err)
		}
	}
	for _, alias := range []string{"n1024-sw115-smallfield", "n1024-sw115", "n1024-115", "n1024-sw115-sf"} {
		if got, err := ResolveIntGenISISPresetSelector(alias, false); err != nil || got != IntGenISISPresetN1024SW115SF {
			t.Fatalf("alias %q resolved to %q, %v", alias, got, err)
		}
	}
	for _, alias := range []string{"n1024-sw120-smallfield", "n1024-sw120", "n1024-120", "n1024-sw120-sf"} {
		if got, err := ResolveIntGenISISPresetSelector(alias, false); err != nil || got != IntGenISISPresetN1024SW120SF {
			t.Fatalf("alias %q resolved to %q, %v", alias, got, err)
		}
	}
	for _, alias := range []string{"n1024-sw128", "n1024-128", "n1024-ternary-sw128", "n1024-b1-sw128"} {
		if got, err := ResolveIntGenISISPresetSelector(alias, false); err != nil || got != IntGenISISPresetN1024SW128 {
			t.Fatalf("alias %q resolved to %q, %v", alias, got, err)
		}
	}
	if got, err := ResolveIntGenISISPresetSelector("", true); err != nil || got != IntGenISISPreset96Bit {
		t.Fatalf("-96bit selector resolved to %q, %v", got, err)
	}
	if _, err := ResolveIntGenISISPresetSelector(IntGenISISPresetSW128LVCS64, true); err == nil {
		t.Fatal("expected conflict between -96bit and explicit non-96bit preset")
	}
}
