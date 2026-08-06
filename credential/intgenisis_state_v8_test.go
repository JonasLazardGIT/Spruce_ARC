package credential

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func testStateV8Artifacts(t testing.TB, presetName string) (IntGenISISState, IntGenISISStateCodecContext) {
	t.Helper()
	public := testPublicParamsV2(t, presetName)
	strictV3 := public.PresetVersion == IntGenISISPresetManifestVersionV3 && public.TranscriptMode == IntGenISISTranscriptProtocolV3
	strictV4 := public.PresetVersion == IntGenISISPresetManifestVersionV4 && public.TranscriptMode == IntGenISISTranscriptProtocolV4
	if !strictV3 && !strictV4 {
		t.Fatalf("target preset %q is not on a supported strict manifest/transcript epoch", presetName)
	}
	key := testVerifierKeyV2(t, public)
	key.SignatureBound = 6142
	profile, _ := LookupIntGenISISProfile(public.Profile)
	layout, err := DefaultSemanticMessageLayout(profile, IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	attributes := zeroRows(profile.EllM, profile.N)
	for i, slot := range layout.Attribute {
		attributes[slot.Poly][slot.Coeff] = int64(i%3 - 1)
	}
	seed := make([]int64, IntGenISISPRFSeedLen)
	for i := range seed {
		seed[i] = int64(i%9) - IntGenISISPRFSeedBound
	}
	semantic, err := EncodeSemanticMessage(layout, attributes, seed)
	if err != nil {
		t.Fatal(err)
	}
	makeTernaryRows := func(rows int, phase int) [][]int64 {
		out := zeroRows(rows, profile.N)
		for r := range out {
			for c := range out[r] {
				out[r][c] = int64((phase+r+c)%3 - 1)
			}
		}
		return out
	}
	sig1 := make([]int64, profile.N)
	sig2 := make([]int64, profile.N)
	values := []int64{-key.SignatureBound, -1, 0, 1, key.SignatureBound}
	for i := 0; i < profile.N; i++ {
		sig1[i] = values[i%len(values)]
		sig2[i] = values[(i+2)%len(values)]
	}
	path := "credential_public.intgenisis_profile_c.json"
	preset, _ := LookupIntGenISISPreset(public.PresetID)
	state := IntGenISISState{
		Version:              IntGenISISStateVersion,
		Profile:              public.Profile,
		PresetID:             public.PresetID,
		PresetVersion:        public.PresetVersion,
		PrimitiveProfileID:   public.PrimitiveProfileID,
		PRFProfile:           public.PRFProfile,
		TranscriptMode:       public.TranscriptMode,
		PresetManifestDigest: public.PresetManifestDigest,
		M:                    semantic.M,
		MAttr:                semantic.MAttr,
		K:                    semantic.K,
		S:                    makeTernaryRows(profile.KS, 0),
		E:                    makeTernaryRows(profile.NC, 1),
		MuSig:                makeTernaryRows(profile.EllMuSig, 2),
		X0:                   makeTernaryRows(profile.EllX0, 3),
		X1:                   makeTernaryRows(profile.EllX1, 4),
		SigS1:                sig1,
		SigS2:                sig2,
		RingDegree:           profile.N,
		PackedNCols:          preset.Showing.NCols,
		CredentialPublicPath: path,
		HashRelation:         public.HashRelation,
		BPath:                public.BPath,
		PRFParamsPath:        preset.PRFParamsPath,
		NTRUPublic:           cloneInt64Rows(key.NTRUPublic),
		SignatureBound:       key.SignatureBound,
	}
	ctx := IntGenISISStateCodecContext{Public: public, VerifierKey: key, PublicParamsPath: path}
	if err := state.ValidateAgainst(public, key); err != nil {
		t.Fatalf("state-v8 fixture: %v", err)
	}
	return state, ctx
}

func FuzzUnmarshalIntGenISISStateV8(f *testing.F) {
	state, ctx := testStateV8Artifacts(f, IntGenISISPresetSystemN1024WF128CROMV2)
	wire, err := MarshalIntGenISISStateV8(state, ctx)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte("SPRUCE-state-v8-invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, decodeErr := UnmarshalIntGenISISStateV8(data, ctx)
		if decodeErr != nil {
			return
		}
		reencoded, encodeErr := MarshalIntGenISISStateV8(decoded, ctx)
		if encodeErr != nil {
			t.Fatalf("accepted state did not re-encode: %v", encodeErr)
		}
		if !reflect.DeepEqual(reencoded, data) {
			t.Fatal("accepted state-v8 input was not canonical")
		}
	})
}

func TestTargetStateV8RejectsLegacyJSONIO(t *testing.T) {
	for _, presetID := range []string{
		IntGenISISPresetPoCN1024BQ128R128V3,
		IntGenISISPresetSystemN1024WF128CROMV2,
	} {
		t.Run(presetID, func(t *testing.T) {
			state, _ := testStateV8Artifacts(t, presetID)
			path := filepath.Join(t.TempDir(), "legacy-state.json")
			if err := SaveIntGenISISState(path, state); err == nil || !strings.Contains(err.Error(), "rejects legacy JSON") {
				t.Fatalf("legacy save error=%v, want explicit target rejection", err)
			}

			// Exercise the load boundary independently: a schema-7 JSON value is
			// structurally valid in memory but is not an accepted target artifact.
			raw, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadIntGenISISState(path); err == nil || !strings.Contains(err.Error(), "rejects legacy JSON") {
				t.Fatalf("legacy load error=%v, want explicit target rejection", err)
			}
		})
	}
}

func TestIntGenISISStateV8TargetRoundTripsAndSize(t *testing.T) {
	expectedBytes := map[string]int{
		IntGenISISPresetPoCN1024BQ128R128V3:    4926,
		IntGenISISPresetSystemN1024WF128CROMV2: 4894,
	}
	for _, presetName := range []string{IntGenISISPresetPoCN1024BQ128R128V3, IntGenISISPresetSystemN1024WF128CROMV2} {
		t.Run(presetName, func(t *testing.T) {
			state, ctx := testStateV8Artifacts(t, presetName)
			wire, err := MarshalIntGenISISStateV8(state, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(wire) > 5*1024+256 { // 5.25 KiB
				t.Fatalf("canonical state-v8=%d bytes exceeds 5.25 KiB", len(wire))
			}
			preset, _ := LookupIntGenISISPreset(ctx.Public.PresetID)
			bindingWidth := (maxInt(preset.Issuance.FSCollisionBits, preset.Showing.FSCollisionBits) + 7) / 8
			wantLen, err := intGenISISStateV8EncodedLen(Ternary1024IntGenISISProfile(), ctx.VerifierKey.SignatureBound, bindingWidth)
			if err != nil {
				t.Fatal(err)
			}
			if len(wire) != wantLen {
				t.Fatalf("canonical state-v8=%d want %d", len(wire), wantLen)
			}
			if len(wire) != expectedBytes[presetName] {
				t.Fatalf("canonical state-v8=%d want frozen target size %d", len(wire), expectedBytes[presetName])
			}
			t.Logf("canonical state-v8 bytes=%d", len(wire))
			decoded, err := UnmarshalIntGenISISStateV8(wire, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, state) {
				t.Fatal("state-v8 round trip changed credential state")
			}
			fingerprint, err := IntGenISISStateV8Fingerprint(wire, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(fingerprint) != 2*bindingWidth {
				t.Fatalf("fingerprint hex length=%d want %d", len(fingerprint), 2*bindingWidth)
			}

			path := filepath.Join(t.TempDir(), "credential.state.v8")
			if err := SaveIntGenISISStateV8(path, state, ctx); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("state-v8 mode=%o want 600", info.Mode().Perm())
			}
			loaded, err := LoadIntGenISISStateV8(path, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(loaded, state) {
				t.Fatal("saved state-v8 changed credential state")
			}
		})
	}
}

func TestIntGenISISStateV8StrictCanonicalBoundary(t *testing.T) {
	state, ctx := testStateV8Artifacts(t, IntGenISISPresetSystemN1024WF128CROMV2)
	wire, err := MarshalIntGenISISStateV8(state, ctx)
	if err != nil {
		t.Fatal(err)
	}
	for cut := 0; cut < len(wire); cut++ {
		if _, err := UnmarshalIntGenISISStateV8(wire[:cut], ctx); err == nil {
			t.Fatalf("state-v8 truncation at byte %d accepted", cut)
		}
	}
	if _, err := UnmarshalIntGenISISStateV8(append(append([]byte(nil), wire...), 0), ctx); err == nil {
		t.Fatal("state-v8 trailing byte accepted")
	}

	badVersion := append([]byte(nil), wire...)
	badVersion[7] = 7
	if _, err := UnmarshalIntGenISISStateV8(badVersion, ctx); err == nil {
		t.Fatal("state-v8 wrong version accepted")
	}
	badBinding := append([]byte(nil), wire...)
	badBinding[len(intGenISISStateV8Magic)] ^= 1
	if _, err := UnmarshalIntGenISISStateV8(badBinding, ctx); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("state-v8 altered public binding error=%v", err)
	}

	preset, _ := LookupIntGenISISPreset(ctx.Public.PresetID)
	bindingWidth := (maxInt(preset.Issuance.FSCollisionBits, preset.Showing.FSCollisionBits) + 7) / 8
	layout, _ := DefaultSemanticMessageLayout(Ternary1024IntGenISISProfile(), IntGenISISPRFPoseidonKeyLen)
	attributeOffset := len(intGenISISStateV8Magic) + 2*bindingWidth
	badTernary := append([]byte(nil), wire...)
	badTernary[attributeOffset] = 243
	if _, err := UnmarshalIntGenISISStateV8(badTernary, ctx); err == nil {
		t.Fatal("state-v8 noncanonical base-243 group accepted")
	}
	seedOffset := attributeOffset + packedTernary243Len(len(layout.Attribute))
	badSeed := append([]byte(nil), wire...)
	// The tenth seed group contains three values. 9^3 is the first encoding
	// with a nonzero omitted fourth digit.
	binary.LittleEndian.PutUint16(badSeed[seedOffset+18:], 729)
	if _, err := UnmarshalIntGenISISStateV8(badSeed, ctx); err == nil {
		t.Fatal("state-v8 noncanonical base-9 spare digits accepted")
	}

	ternaryOffset := seedOffset + packedBase9SeedLen(len(layout.Key))
	signatureOffset := ternaryOffset + packedTernary243Len(stateV8TernaryValueCount(Ternary1024IntGenISISProfile()))
	badSignature := append([]byte(nil), wire...)
	// Width is 14 at beta=6142. The all-one first lane is 16383 > 2*beta.
	badSignature[signatureOffset] = 0xff
	badSignature[signatureOffset+1] |= 0x3f
	if _, err := UnmarshalIntGenISISStateV8(badSignature, ctx); err == nil {
		t.Fatal("state-v8 shifted signature above trusted range accepted")
	}

	wrongKey := ctx
	wrongKey.VerifierKey.NTRUPublic = cloneInt64Rows(ctx.VerifierKey.NTRUPublic)
	wrongKey.VerifierKey.NTRUPublic[0][0] = 1
	if _, err := UnmarshalIntGenISISStateV8(wire, wrongKey); err == nil {
		t.Fatal("state-v8 wrong verifier key accepted")
	}
}

func TestStateV8PrimitivePackersCanonical(t *testing.T) {
	ternary := []int64{-1, 0, 1, 1, -1, 0, 1}
	packed, err := packCanonicalTernary243(ternary)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unpackCanonicalTernary243(packed, len(ternary))
	if err != nil || !reflect.DeepEqual(got, ternary) {
		t.Fatalf("ternary round trip=(%v,%v)", got, err)
	}
	noncanonical := append([]byte(nil), packed...)
	noncanonical[len(noncanonical)-1] += 9 // sets an omitted third digit
	if _, err := unpackCanonicalTernary243(noncanonical, len(ternary)); err == nil {
		t.Fatal("nonzero ternary spare digit accepted")
	}

	seed := make([]int64, IntGenISISPRFSeedLen)
	for i := range seed {
		seed[i] = int64(i%9) - 4
	}
	seedPacked, err := packCanonicalBase9Seed(seed)
	if err != nil {
		t.Fatal(err)
	}
	seedGot, err := unpackCanonicalBase9Seed(seedPacked, len(seed))
	if err != nil || !reflect.DeepEqual(seedGot, seed) {
		t.Fatalf("seed round trip=(%v,%v)", seedGot, err)
	}

	sig := []int64{-6142, -1, 0, 6142, 2, 3, -4, 5}
	sigPacked, err := packCanonicalShiftedSignature(sig, 6142)
	if err != nil {
		t.Fatal(err)
	}
	sigGot, err := unpackCanonicalShiftedSignature(sigPacked, len(sig), 6142)
	if err != nil || !reflect.DeepEqual(sigGot, sig) {
		t.Fatalf("signature round trip=(%v,%v)", sigGot, err)
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
