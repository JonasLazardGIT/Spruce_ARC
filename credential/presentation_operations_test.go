package credential

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
)

func testPresentationOperationArtifacts(t *testing.T) (PublicParams, IntGenISISVerifierKey, IntGenISISState) {
	t.Helper()
	public := testPublicParamsV2(t, IntGenISISPresetN512Compact96)
	preset, err := MustLookupIntGenISISPreset(public.PresetID)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := LookupIntGenISISProfile(public.Profile)
	row := func(value int64) []int64 {
		out := make([]int64, profile.N)
		out[0] = value
		return out
	}
	layout, err := DefaultSemanticMessageLayout(profile, IntGenISISPRFPoseidonKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := EncodeSemanticMessage(layout, [][]int64{row(0)}, makeSeedForTest())
	if err != nil {
		t.Fatal(err)
	}
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		t.Fatal(err)
	}
	ntruPublic := [][]int64{row(0)}
	key := IntGenISISVerifierKey{
		Version:              IntGenISISVerifierKeyVersion,
		Profile:              profile.Name,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PresetManifestDigest: public.PresetManifestDigest,
		RingDegree:           profile.N,
		PublicParamsDigest:   publicDigest,
		NTRUPublic:           ntruPublic,
		SignatureBound:       20,
	}
	state := IntGenISISState{
		Version:              IntGenISISStateVersion,
		Profile:              profile.Name,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PrimitiveProfileID:   preset.PrimitiveProfileID,
		PRFProfile:           preset.PRFProfile,
		TranscriptMode:       preset.Showing.TranscriptMode,
		PresetManifestDigest: public.PresetManifestDigest,
		M:                    semantic.M,
		MAttr:                semantic.MAttr,
		K:                    semantic.K,
		S:                    [][]int64{row(0), row(0)},
		E:                    [][]int64{row(0)},
		MuSig:                [][]int64{row(0)},
		X0:                   [][]int64{row(0), row(0)},
		X1:                   [][]int64{row(0)},
		SigS1:                row(0),
		SigS2:                row(0),
		RingDegree:           profile.N,
		PackedNCols:          preset.Showing.NCols,
		CredentialPublicPath: "credential_public.json",
		HashRelation:         public.HashRelation,
		BPath:                public.BPath,
		PRFParamsPath:        preset.PRFParamsPath,
		NTRUPublic:           ntruPublic,
		SignatureBound:       key.SignatureBound,
	}
	if err := state.ValidateAgainst(public, key); err != nil {
		t.Fatalf("operation fixture: %v", err)
	}
	return public, key, state
}

func TestPresentationOperationsBurnBeforeProveAndAcceptOnce(t *testing.T) {
	public, key, state := testPresentationOperationArtifacts(t)
	holderStore := filepath.Join(t.TempDir(), "holder.json")
	verifierStore := filepath.Join(t.TempDir(), "verifier.json")
	context := []byte("service-policy/2026-08")
	tagLen, _ := IntGenISISPRFProfileTagElements(state.PRFProfile)

	firstSlot := uint8(255)
	pres, err := CreatePresentation(public, key, state, context, holderStore, func(binding PresentationContextBinding, slot uint8) ([]int64, json.RawMessage, error) {
		firstSlot = slot
		return make([]int64, tagLen), json.RawMessage(`{"schema_version":2}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstSlot != 0 {
		t.Fatalf("first reserved slot=%d want 0", firstSlot)
	}
	verifyCalls := 0
	verify := func(IntGenISISPresentation) (bool, error) {
		verifyCalls++
		return true, nil
	}
	if ok, err := VerifyProof(pres, public, key, context, verify); err != nil || !ok {
		t.Fatalf("proof-only verification=(%v,%v)", ok, err)
	}
	if _, err := VerifyProof(pres, public, key, []byte("different context"), verify); err == nil {
		t.Fatal("client-selected context was accepted")
	}
	if verifyCalls != 1 {
		t.Fatalf("proof verifier called before context rejection: calls=%d", verifyCalls)
	}
	if ok, err := VerifyAndAccept(pres, public, key, context, verifierStore, verify); err != nil || !ok {
		t.Fatalf("first acceptance=(%v,%v)", ok, err)
	}
	if ok, err := VerifyAndAccept(pres, public, key, context, verifierStore, verify); err == nil || ok {
		t.Fatalf("duplicate acceptance=(%v,%v)", ok, err)
	}
}

func TestCreatePresentationBurnsFailedProofSlotAndNamespacesContexts(t *testing.T) {
	public, key, state := testPresentationOperationArtifacts(t)
	holderStore := filepath.Join(t.TempDir(), "holder.json")
	tagLen, _ := IntGenISISPRFProfileTagElements(state.PRFProfile)
	failedSlot := uint8(255)
	_, err := CreatePresentation(public, key, state, []byte("context-a"), holderStore, func(_ PresentationContextBinding, slot uint8) ([]int64, json.RawMessage, error) {
		failedSlot = slot
		return nil, nil, errors.New("simulated prover failure")
	})
	if err == nil || failedSlot != 0 {
		t.Fatalf("failed proof reservation=(slot %d, err %v)", failedSlot, err)
	}
	nextSlot := uint8(255)
	_, err = CreatePresentation(public, key, state, []byte("context-a"), holderStore, func(_ PresentationContextBinding, slot uint8) ([]int64, json.RawMessage, error) {
		nextSlot = slot
		return make([]int64, tagLen), json.RawMessage(`{"schema_version":2}`), nil
	})
	if err != nil || nextSlot != 1 {
		t.Fatalf("slot after failed proof=(%d,%v), want (1,nil)", nextSlot, err)
	}
	independentSlot := uint8(255)
	_, err = CreatePresentation(public, key, state, []byte("context-b"), holderStore, func(_ PresentationContextBinding, slot uint8) ([]int64, json.RawMessage, error) {
		independentSlot = slot
		return make([]int64, tagLen), json.RawMessage(`{"schema_version":2}`), nil
	})
	if err != nil || independentSlot != 0 {
		t.Fatalf("independent context slot=(%d,%v), want (0,nil)", independentSlot, err)
	}
}
