package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testVerifierKeyV2(t *testing.T, public PublicParams) IntGenISISVerifierKey {
	t.Helper()
	digest, err := PublicParamsDigest(public)
	if err != nil {
		t.Fatal(err)
	}
	return IntGenISISVerifierKey{
		Version:              IntGenISISVerifierKeyVersion,
		Profile:              public.Profile,
		PresetID:             public.PresetID,
		PresetVersion:        public.PresetVersion,
		PresetManifestDigest: public.PresetManifestDigest,
		RingDegree:           public.RingDegree,
		PublicParamsDigest:   digest,
		NTRUPublic:           [][]int64{make([]int64, public.RingDegree)},
		SignatureBound:       1,
	}
}

func testCredentialStateV7(t *testing.T, public PublicParams, key IntGenISISVerifierKey) IntGenISISState {
	t.Helper()
	profile, ok := LookupIntGenISISProfile(public.Profile)
	if !ok {
		t.Fatalf("unknown profile %q", public.Profile)
	}
	preset, ok := LookupIntGenISISPreset(public.PresetID)
	if !ok {
		t.Fatalf("unknown preset %q", public.PresetID)
	}
	row := func() []int64 { return make([]int64, profile.N) }
	layout, err := DefaultSemanticMessageLayout(profile, IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := EncodeSemanticMessage(layout, [][]int64{row()}, makeSeedForTest())
	if err != nil {
		t.Fatal(err)
	}
	return IntGenISISState{
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
		S:                    make([][]int64, profile.KS),
		E:                    make([][]int64, profile.NC),
		MuSig:                make([][]int64, profile.EllMuSig),
		X0:                   make([][]int64, profile.EllX0),
		X1:                   make([][]int64, profile.EllX1),
		SigS1:                row(),
		SigS2:                row(),
		RingDegree:           profile.N,
		PackedNCols:          preset.Showing.NCols,
		CredentialPublicPath: "credential_public.json",
		HashRelation:         public.HashRelation,
		BPath:                public.BPath,
		PRFParamsPath:        preset.PRFParamsPath,
		NTRUPublic:           [][]int64{append([]int64(nil), key.NTRUPublic[0]...)},
		SignatureBound:       key.SignatureBound,
	}
}

func fillZeroRows(rows [][]int64, n int) {
	for i := range rows {
		rows[i] = make([]int64, n)
	}
}

func testBoundPresentationV2(t *testing.T, public PublicParams, key IntGenISISVerifierKey) IntGenISISPresentation {
	t.Helper()
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest, err := key.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tagLen, ok := IntGenISISPRFProfileTagElements(public.PRFProfile)
	if !ok {
		t.Fatalf("unknown PRF profile %q", public.PRFProfile)
	}
	return IntGenISISPresentation{
		Version:              IntGenISISPresentationVersion,
		PresetManifestDigest: public.PresetManifestDigest,
		PublicParamsDigest:   publicDigest,
		VerifierKeyDigest:    keyDigest,
		ContextDigest:        repeatedDigest(0x41),
		Context:              make([]int64, IntGenISISContextLaneCount),
		Tag:                  make([]int64, tagLen),
		Proof:                json.RawMessage(`{"schema_version":2}`),
	}
}

func requireNoMigrationError(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "no migration") {
		t.Fatalf("expected explicit no-migration error, got %v", err)
	}
}

func TestPersistedArtifactsRejectOldSchemasWithoutMigration(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		raw  string
		load func(string) error
	}{
		{"public", `{"version":7,"legacy_only":true}`, func(path string) error { _, err := LoadPublicParams(path); return err }},
		{"credential-state", `{"version":6,"legacy_only":true}`, func(path string) error { _, err := LoadIntGenISISState(path); return err }},
		{"verifier-key", `{"version":1,"legacy_only":true}`, func(path string) error { _, err := LoadIntGenISISVerifierKey(path); return err }},
		{"presentation", `{"version":1,"nonce":[[1]]}`, func(path string) error { _, err := LoadIntGenISISPresentation(path); return err }},
		{"verifier-state", `{"version":1,"seen":{}}`, func(path string) error { _, err := LoadIntGenISISVerifierState(path); return err }},
		{"holder-state", `{"version":1,"next_slot_by_context":{}}`, func(path string) error { _, err := LoadIntGenISISHolderUsageState(path); return err }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(path, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			requireNoMigrationError(t, tc.load(path))
		})
	}
}

func TestPersistedArtifactsRejectUnknownAndTrailingJSON(t *testing.T) {
	public := testPublicParamsV2(t, IntGenISISPresetN512Compact96)
	key := testVerifierKeyV2(t, public)
	state := testCredentialStateV7(t, public, key)
	fillZeroRows(state.S, state.RingDegree)
	fillZeroRows(state.E, state.RingDegree)
	fillZeroRows(state.MuSig, state.RingDegree)
	fillZeroRows(state.X0, state.RingDegree)
	fillZeroRows(state.X1, state.RingDegree)
	pres := testBoundPresentationV2(t, public, key)
	verifierState := NewIntGenISISVerifierState(pres.PublicParamsDigest, pres.VerifierKeyDigest)

	tests := []struct {
		name string
		save func(string) error
		load func(string) error
	}{
		{"public", func(path string) error { return SavePublicParams(path, public) }, func(path string) error { _, err := LoadPublicParams(path); return err }},
		{"credential-state", func(path string) error { return SaveIntGenISISState(path, state) }, func(path string) error { _, err := LoadIntGenISISState(path); return err }},
		{"verifier-key", func(path string) error { return SaveIntGenISISVerifierKey(path, key) }, func(path string) error { _, err := LoadIntGenISISVerifierKey(path); return err }},
		{"presentation", func(path string) error { return SaveIntGenISISPresentation(path, pres) }, func(path string) error { _, err := LoadIntGenISISPresentation(path); return err }},
		{"verifier-state", func(path string) error { return SaveIntGenISISVerifierState(path, verifierState) }, func(path string) error { _, err := LoadIntGenISISVerifierState(path); return err }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name+".json")
			if err := tc.save(path); err != nil {
				t.Fatal(err)
			}
			valid, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			trimmed := strings.TrimSpace(string(valid))
			unknown := strings.TrimSuffix(trimmed, "}") + `,"unknown_v2_field":true}`
			if err := os.WriteFile(path, []byte(unknown), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.load(path); err == nil {
				t.Fatal("unknown JSON field accepted")
			}
			if err := os.WriteFile(path, append(valid, []byte("{}")...), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.load(path); err == nil {
				t.Fatal("trailing JSON value accepted")
			}
		})
	}
}

func TestV2ArtifactConsistencyIsExact(t *testing.T) {
	public := testPublicParamsV2(t, IntGenISISPresetN512Compact96)
	key := testVerifierKeyV2(t, public)
	pres := testBoundPresentationV2(t, public, key)
	state := testCredentialStateV7(t, public, key)
	fillZeroRows(state.S, state.RingDegree)
	fillZeroRows(state.E, state.RingDegree)
	fillZeroRows(state.MuSig, state.RingDegree)
	fillZeroRows(state.X0, state.RingDegree)
	fillZeroRows(state.X1, state.RingDegree)

	if err := key.ValidateAgainst(public); err != nil {
		t.Fatal(err)
	}
	if err := pres.ValidateAgainst(public, key); err != nil {
		t.Fatal(err)
	}
	if err := state.ValidateAgainst(public, key); err != nil {
		t.Fatal(err)
	}
	verifierState := NewIntGenISISVerifierState(pres.PublicParamsDigest, pres.VerifierKeyDigest)
	if err := verifierState.ValidateAgainst(public, key); err != nil {
		t.Fatal(err)
	}

	tamperedKey := key
	tamperedKey.PublicParamsDigest = repeatedDigest(0x55)
	if err := tamperedKey.ValidateAgainst(public); err == nil {
		t.Fatal("verifier key accepted a different public-parameter digest")
	}
	tamperedPresentation := pres
	tamperedPresentation.VerifierKeyDigest = repeatedDigest(0x56)
	if err := tamperedPresentation.ValidateAgainst(public, key); err == nil {
		t.Fatal("presentation accepted a different verifier-key digest")
	}
	tamperedState := state
	tamperedState.NTRUPublic = [][]int64{append([]int64(nil), state.NTRUPublic[0]...)}
	tamperedState.NTRUPublic[0][0] = 1
	if err := tamperedState.ValidateAgainst(public, key); err == nil {
		t.Fatal("credential state accepted a different NTRU public key")
	}
	verifierState.VerifierKeyDigest = repeatedDigest(0x57)
	if err := verifierState.ValidateAgainst(public, key); err == nil {
		t.Fatal("verifier replay state accepted a different verifier key")
	}
}

func TestPublicParamsRequiresExactV2PolicyAndNoDefaults(t *testing.T) {
	public := testPublicParamsV2(t, IntGenISISPresetN512Compact96)
	public.RateLimitPolicy.QuotaSlots--
	if err := (&public).Validate(); err == nil {
		t.Fatal("non-canonical rate-limit policy accepted")
	}
	public = testPublicParamsV2(t, IntGenISISPresetN512Compact96)
	public.PresetID = ""
	if err := (&public).Validate(); err == nil {
		t.Fatal("missing preset binding accepted")
	}
	public = testPublicParamsV2(t, IntGenISISPresetN512Compact96)
	public.Version = 0
	requireNoMigrationError(t, SavePublicParams(filepath.Join(t.TempDir(), "public.json"), public))
}
