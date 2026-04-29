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
			if p.Profile != ProfileIntGenISISB {
				t.Fatalf("preset profile=%q want %q", p.Profile, ProfileIntGenISISB)
			}
			if name != IntGenISISPresetFastLocal {
				if p.TargetEq8Bits != 96 && p.TargetEq8Bits != 128 {
					t.Fatalf("target bits=%v", p.TargetEq8Bits)
				}
				if p.LVCSNCols != 32 && p.LVCSNCols != 64 && p.LVCSNCols != 128 {
					t.Fatalf("lvcs_ncols=%d", p.LVCSNCols)
				}
				if p.Issuance.LVCSNCols != p.LVCSNCols || p.Showing.LVCSNCols != p.LVCSNCols {
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
	if len(names) < 7 {
		t.Fatalf("preset names=%v", names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("names not sorted: %v", names)
		}
	}
}
