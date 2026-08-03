package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntGenISISStateRoundTripOmitsOldRandomness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential_state.intgenisis.json")
	preset, err := MustLookupIntGenISISPreset(IntGenISISPresetN512Compact96)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := LookupIntGenISISProfile(preset.Profile)
	row := func(v int64) []int64 {
		out := make([]int64, profile.N)
		out[0] = v
		return out
	}
	layout, err := DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		t.Fatalf("layout: %v", err)
	}
	semantic, err := EncodeSemanticMessage(layout, [][]int64{row(1)}, makeSeedForTest())
	if err != nil {
		t.Fatalf("encode semantic message: %v", err)
	}
	st := IntGenISISState{
		Version:              IntGenISISStateVersion,
		Profile:              profile.Name,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PrimitiveProfileID:   preset.PrimitiveProfileID,
		PRFProfile:           preset.PRFProfile,
		TranscriptMode:       preset.Showing.TranscriptMode,
		PresetManifestDigest: IntGenISISPresetManifestDigest(preset),
		M:                    semantic.M,
		MAttr:                semantic.MAttr,
		K:                    semantic.K,
		S:                    [][]int64{row(1), row(-1)},
		E:                    [][]int64{row(0)},
		MuSig:                [][]int64{row(1)},
		X0:                   [][]int64{row(-1), row(0)},
		X1:                   [][]int64{row(1)},
		SigS1:                row(9),
		SigS2:                row(10),
		RingDegree:           profile.N,
		PackedNCols:          preset.Showing.NCols,
		CredentialPublicPath: "internal/source_data/credential_public.intgenisis_profile_b.json",
		HashRelation:         HashRelationBBTran,
		BPath:                "internal/source_data/Bmatrix.intgenisis_profile_b.json",
		PRFParamsPath:        preset.PRFParamsPath,
		NTRUPublic:           [][]int64{row(0)},
		SignatureBound:       20,
	}
	if err := SaveIntGenISISState(path, st); err != nil {
		t.Fatalf("save state: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	text := string(raw)
	for _, stale := range []string{"r0h", "r1h", "ri0", "ri1", "rbar", "target_hiding_lambda", "\"com\"", "\"t\""} {
		if strings.Contains(text, stale) {
			t.Fatalf("IntGenISIS state leaked stale field %q: %s", stale, text)
		}
	}
	got, err := LoadIntGenISISState(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if got.Profile != profile.Name || len(got.S) != profile.KS || len(got.X0) != profile.EllX0 {
		t.Fatalf("state mismatch: %+v", got)
	}
	for _, source := range []string{"mu_sig", "x0", "x1"} {
		t.Run("reject-nonternary-"+source, func(t *testing.T) {
			tampered, err := LoadIntGenISISState(path)
			if err != nil {
				t.Fatal(err)
			}
			switch source {
			case "mu_sig":
				tampered.MuSig[0][0] = 2
			case "x0":
				tampered.X0[0][0] = -2
			case "x1":
				tampered.X1[0][0] = 2
			}
			if err := tampered.Validate(); err == nil {
				t.Fatalf("state accepted %s coefficient outside ternary range", source)
			}
		})
	}
}

func TestIntGenISISStateRejectsTamperedPresetBinding(t *testing.T) {
	preset, _ := LookupIntGenISISPreset(IntGenISISPresetPoCN512SC96V2)
	profile, _ := LookupIntGenISISProfile(preset.Profile)
	row := func() []int64 { return make([]int64, profile.N) }
	layout, err := DefaultSemanticMessageLayout(profile, IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := EncodeSemanticMessage(layout, [][]int64{row()}, makeSeedForTest())
	if err != nil {
		t.Fatal(err)
	}
	state := IntGenISISState{
		Version:              IntGenISISStateVersion,
		Profile:              preset.Profile,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PrimitiveProfileID:   preset.PrimitiveProfileID,
		PRFProfile:           preset.PRFProfile,
		TranscriptMode:       preset.Showing.TranscriptMode,
		PresetManifestDigest: IntGenISISPresetManifestDigest(preset),
		M:                    semantic.M,
		MAttr:                semantic.MAttr,
		K:                    semantic.K,
		S:                    [][]int64{row(), row()},
		E:                    [][]int64{row()},
		MuSig:                [][]int64{row()},
		X0:                   [][]int64{row(), row()},
		X1:                   [][]int64{row()},
		SigS1:                row(),
		SigS2:                row(),
		RingDegree:           profile.N,
		PackedNCols:          preset.Showing.NCols,
		CredentialPublicPath: "credential_public.json",
		HashRelation:         HashRelationBBTran,
		BPath:                "Bmatrix.json",
		PRFParamsPath:        preset.PRFParamsPath,
		NTRUPublic:           [][]int64{row()},
		SignatureBound:       1,
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("valid bound state rejected: %v", err)
	}
	state.PresetManifestDigest = "tampered"
	if err := state.Validate(); err == nil {
		t.Fatal("tampered state preset binding accepted")
	}
	state.PresetManifestDigest = IntGenISISPresetManifestDigest(preset)
	state.PresetID = preset.Name
	if err := state.Validate(); err == nil {
		t.Fatal("non-canonical state preset selector accepted")
	}
}
