package credential

import "testing"

func TestIntGenISISPresetRegistryResolvesSecureNames(t *testing.T) {
	want := []string{
		IntGenISISPresetFastLocal,
		IntGenISISPresetSW96LVCS32,
		IntGenISISPresetSW96LVCS64,
		IntGenISISPresetSW96LVCS128,
		IntGenISISPresetSW128LVCS32,
		IntGenISISPresetSW128LVCS64,
		IntGenISISPresetSW128LVCS128,
		IntGenISISPresetN256SW96,
		IntGenISISPresetN256SW128,
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
			if name == IntGenISISPresetN256SW96 || name == IntGenISISPresetN256SW128 {
				wantProfile = ProfileIntGenISISA
			}
			if p.Profile != wantProfile {
				t.Fatalf("preset profile=%q want %q", p.Profile, wantProfile)
			}
			if name != IntGenISISPresetFastLocal {
				if name == IntGenISISPresetSW96LVCS64 || name == IntGenISISPresetSW128LVCS64 || name == IntGenISISPresetN256SW96 || name == IntGenISISPresetN256SW128 {
					wantTheorem := 96.0
					wantKappa := [4]int{0, 0, 0, 6}
					if name == IntGenISISPresetSW128LVCS64 || name == IntGenISISPresetN256SW128 {
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
				if p.LVCSNCols != 32 && p.LVCSNCols != 64 && p.LVCSNCols != 70 && p.LVCSNCols != 128 {
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
	if len(names) < 9 {
		t.Fatalf("preset names=%v", names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("names not sorted: %v", names)
		}
	}
}
