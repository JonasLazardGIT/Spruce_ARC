package credential

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

func canonicalShowingProofHeaderForOperationTest() []byte {
	return append(append([]byte(nil), intGenISISCanonicalShowingProofV6Header[:]...), []byte("operation-test-proof")...)
}

func deriveContextForV3Test(t *testing.T, public PublicParams, key IntGenISISVerifierKey, raw []byte) PresentationContextBinding {
	t.Helper()
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest, err := key.Digest()
	if err != nil {
		t.Fatal(err)
	}
	binding, err := DerivePresentationContext(raw, public.Modulus, public.PresetManifestDigest, publicDigest, keyDigest)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func zeroTagForV3Test(t *testing.T, public PublicParams) []int64 {
	t.Helper()
	tagLen, ok := IntGenISISPRFProfileTagElements(public.PRFProfile)
	if !ok {
		t.Fatalf("unknown PRF profile %q", public.PRFProfile)
	}
	return make([]int64, tagLen)
}

func TestHolderUsageV3CanonicalFingerprintAndStrictBoundary(t *testing.T) {
	for _, presetName := range []string{IntGenISISPresetPoCN1024BQ128R128V3, IntGenISISPresetSystemN1024WF128CROMV2} {
		t.Run(presetName, func(t *testing.T) {
			credential, stateCtx := testStateV8Artifacts(t, presetName)
			fingerprint, err := IntGenISISCredentialFingerprintV3(credential, stateCtx)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := MarshalIntGenISISStateV8(credential, stateCtx)
			if err != nil {
				t.Fatal(err)
			}
			wantFingerprint, err := IntGenISISStateV8Fingerprint(wire, stateCtx)
			if err != nil {
				t.Fatal(err)
			}
			if fingerprint != wantFingerprint {
				t.Fatalf("holder fingerprint=%s want canonical state-v8 fingerprint=%s", fingerprint, wantFingerprint)
			}
			_, _, width, err := validateIntGenISISStateV8Context(stateCtx)
			if err != nil {
				t.Fatal(err)
			}
			if len(fingerprint) != 2*width {
				t.Fatalf("fingerprint hex length=%d want %d", len(fingerprint), 2*width)
			}
			if _, err := IntGenISISCredentialFingerprint(credential); err == nil || !strings.Contains(err.Error(), "canonical state-v8") {
				t.Fatalf("legacy target fingerprint error=%v", err)
			}

			binding := deriveContextForV3Test(t, stateCtx.Public, stateCtx.VerifierKey, []byte("holder-v3/context-a"))
			path := filepath.Join(t.TempDir(), "holder-v3.json")
			slot, err := ReserveIntGenISISSlotV3(path, credential, stateCtx, binding)
			if err != nil || slot != 0 {
				t.Fatalf("first v3 reservation=(%d,%v), want (0,nil)", slot, err)
			}
			usage, err := LoadIntGenISISHolderUsageStateV3(path, credential, stateCtx)
			if err != nil {
				t.Fatal(err)
			}
			if usage.Version != IntGenISISHolderUsageFormatVersionV3 || usage.CredentialFingerprint != fingerprint || len(usage.NextSlotByContext) != 1 {
				t.Fatalf("unexpected holder-v3 state: %+v", usage)
			}
			for contextID, next := range usage.NextSlotByContext {
				if len(contextID) != 2*width || next != 1 {
					t.Fatalf("context entry=(%q,%d), want configured width and next=1", contextID, next)
				}
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("holder-v3 mode=%o want 600", info.Mode().Perm())
			}

			changed := credential
			changed.SigS1 = append([]int64(nil), credential.SigS1...)
			changed.SigS1[0]++
			changedFingerprint, err := IntGenISISCredentialFingerprintV3(changed, stateCtx)
			if err != nil {
				t.Fatal(err)
			}
			if changedFingerprint == fingerprint {
				t.Fatal("different canonical state-v8 bytes retained the credential fingerprint")
			}
			if _, err := LoadIntGenISISHolderUsageStateV3(path, changed, stateCtx); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
				t.Fatalf("different credential loaded holder state: %v", err)
			}

			legacyPath := filepath.Join(t.TempDir(), "legacy-holder.json")
			legacy := NewIntGenISISHolderUsageState(repeatedDigest(1), stateCtx.Public.PresetManifestDigest, repeatedDigest(2))
			legacyRaw, err := json.Marshal(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(legacyPath, legacyRaw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadIntGenISISHolderUsageStateV3(legacyPath, credential, stateCtx); err == nil || !strings.Contains(err.Error(), "no migration") {
				t.Fatalf("legacy holder state accepted by v3 loader: %v", err)
			}
			if _, err := ReserveIntGenISISSlot(legacyPath, repeatedDigest(1), stateCtx.Public.PresetManifestDigest, repeatedDigest(2), binding.Digest); err == nil || !strings.Contains(err.Error(), "forbidden") {
				t.Fatalf("target accepted legacy holder reservation: %v", err)
			}
		})
	}
}

func TestHolderUsageV3AtomicQuotaAndContextNamespaces(t *testing.T) {
	credential, stateCtx := testStateV8Artifacts(t, IntGenISISPresetSystemN1024WF128CROMV2)
	contextA := deriveContextForV3Test(t, stateCtx.Public, stateCtx.VerifierKey, []byte("holder-v3/atomic-a"))
	path := filepath.Join(t.TempDir(), "holder-v3.json")

	var wg sync.WaitGroup
	results := make(chan uint8, IntGenISISQuotaSlots)
	errs := make(chan error, IntGenISISQuotaSlots)
	for i := uint32(0); i < IntGenISISQuotaSlots; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slot, err := ReserveIntGenISISSlotV3(path, credential, stateCtx, contextA)
			if err != nil {
				errs <- err
				return
			}
			results <- slot
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	got := make([]int, 0, IntGenISISQuotaSlots)
	for slot := range results {
		got = append(got, int(slot))
	}
	sort.Ints(got)
	for i := 0; i < int(IntGenISISQuotaSlots); i++ {
		if got[i] != i {
			t.Fatalf("reserved slots=%v", got)
		}
	}
	if _, err := ReserveIntGenISISSlotV3(path, credential, stateCtx, contextA); err == nil {
		t.Fatal("seventeenth holder-v3 slot succeeded")
	}
	contextB := deriveContextForV3Test(t, stateCtx.Public, stateCtx.VerifierKey, []byte("holder-v3/atomic-b"))
	if slot, err := ReserveIntGenISISSlotV3(path, credential, stateCtx, contextB); err != nil || slot != 0 {
		t.Fatalf("independent holder-v3 context reservation=(%d,%v), want (0,nil)", slot, err)
	}
}

func TestPresentationOperationsV3BurnVerifyAndReplay(t *testing.T) {
	credential, stateCtx := testStateV8Artifacts(t, IntGenISISPresetPoCN1024BQ128R128V3)
	public, key := stateCtx.Public, stateCtx.VerifierKey
	holderPath := filepath.Join(t.TempDir(), "holder-v3.json")
	verifierPath := filepath.Join(t.TempDir(), "verifier-v3.json")
	rawContext := []byte("service-policy/v3/2026-08")
	tag := zeroTagForV3Test(t, public)
	proof := canonicalShowingProofHeaderForOperationTest()

	reserved := uint8(255)
	var proverContext PresentationContextBinding
	pres, err := CreatePresentationV3(public, key, credential, stateCtx, rawContext, holderPath, func(context PresentationContextBinding, slot uint8) ([]int64, []byte, error) {
		reserved = slot
		proverContext = context
		return tag, proof, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if reserved != 0 {
		t.Fatalf("first presentation-v3 slot=%d want 0", reserved)
	}
	if !reflect.DeepEqual(pres.Tag, tag) || !reflect.DeepEqual(pres.CanonicalProof, proof) {
		t.Fatal("CreatePresentationV3 changed tag or proof")
	}

	verifyCalls := 0
	verify := func(got IntGenISISPresentationV3, codecCtx IntGenISISPresentationCodecContext) (bool, error) {
		verifyCalls++
		if !reflect.DeepEqual(got, pres) {
			t.Fatal("proof verifier received changed presentation-v3")
		}
		return reflect.DeepEqual(codecCtx.Context, proverContext.Lanes), nil
	}
	if ok, err := VerifyProofV3(pres, public, key, rawContext, verify); err != nil || !ok {
		t.Fatalf("proof-only v3 verification=(%v,%v)", ok, err)
	}
	if _, err := os.Stat(verifierPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("proof-only verification mutated replay state: %v", err)
	}
	if ok, err := VerifyProofV3(pres, public, key, []byte("different/service/context"), verify); err != nil || ok {
		t.Fatalf("wrong-context v3 verification=(%v,%v), want (false,nil)", ok, err)
	}
	if verifyCalls != 2 {
		t.Fatalf("v3 verifier calls=%d want 2", verifyCalls)
	}
	if ok, err := VerifyAndAcceptV3(pres, public, key, rawContext, verifierPath, verify); err != nil || !ok {
		t.Fatalf("first v3 acceptance=(%v,%v)", ok, err)
	}
	if ok, err := VerifyAndAcceptV3(pres, public, key, rawContext, verifierPath, verify); err == nil || ok || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("duplicate v3 acceptance=(%v,%v)", ok, err)
	}
	codecCtx := IntGenISISPresentationCodecContext{Public: public, VerifierKey: key, Context: append([]int64(nil), proverContext.Lanes...)}
	state, err := LoadIntGenISISVerifierStateV3(verifierPath, codecCtx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != IntGenISISVerifierStateVersionV3 || len(state.Seen) != 1 {
		t.Fatalf("unexpected verifier state-v3: %+v", state)
	}
	info, err := os.Stat(verifierPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("verifier state-v3 mode=%o want 600", info.Mode().Perm())
	}
	wrongKey := key
	wrongKey.NTRUPublic = cloneInt64Rows(key.NTRUPublic)
	wrongKey.NTRUPublic[0][0]++
	wrongCodecCtx := codecCtx
	wrongCodecCtx.VerifierKey = wrongKey
	if _, err := LoadIntGenISISVerifierStateV3(verifierPath, wrongCodecCtx); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("verifier state-v3 accepted wrong key binding: %v", err)
	}
}

func TestPresentationOperationsV3BurnFailedProofAndRejectMalformedBeforeVerify(t *testing.T) {
	credential, stateCtx := testStateV8Artifacts(t, IntGenISISPresetSystemN1024WF128CROMV2)
	public, key := stateCtx.Public, stateCtx.VerifierKey
	holderPath := filepath.Join(t.TempDir(), "holder-v3.json")
	rawContext := []byte("service-policy/v3/failure")

	failedSlot := uint8(255)
	_, err := CreatePresentationV3(public, key, credential, stateCtx, rawContext, holderPath, func(_ PresentationContextBinding, slot uint8) ([]int64, []byte, error) {
		failedSlot = slot
		return nil, nil, errors.New("simulated proof failure")
	})
	if err == nil || failedSlot != 0 {
		t.Fatalf("failed v3 proof reservation=(%d,%v)", failedSlot, err)
	}
	nextSlot := uint8(255)
	pres, err := CreatePresentationV3(public, key, credential, stateCtx, rawContext, holderPath, func(_ PresentationContextBinding, slot uint8) ([]int64, []byte, error) {
		nextSlot = slot
		return zeroTagForV3Test(t, public), canonicalShowingProofHeaderForOperationTest(), nil
	})
	if err != nil || nextSlot != 1 {
		t.Fatalf("slot after v3 prover failure=(%d,%v), want (1,nil)", nextSlot, err)
	}
	malformed := cloneIntGenISISPresentationV3(pres)
	malformed.CanonicalProof[8] = 2
	verifyCalls := 0
	if ok, err := VerifyProofV3(malformed, public, key, rawContext, func(IntGenISISPresentationV3, IntGenISISPresentationCodecContext) (bool, error) {
		verifyCalls++
		return true, nil
	}); err == nil || ok {
		t.Fatalf("malformed canonical proof accepted=(%v,%v)", ok, err)
	}
	if verifyCalls != 0 {
		t.Fatalf("proof verifier called for malformed envelope: %d", verifyCalls)
	}
}

func TestPresentationOperationsV3RejectEveryProofTruncationAtMandatoryVerifier(t *testing.T) {
	_, stateCtx := testStateV8Artifacts(t, IntGenISISPresetSystemN1024WF128CROMV2)
	public, key := stateCtx.Public, stateCtx.VerifierKey
	rawContext := []byte("service-policy/v3/truncation")
	fullProof := canonicalShowingProofHeaderForOperationTest()
	pres := IntGenISISPresentationV3{Tag: zeroTagForV3Test(t, public), CanonicalProof: fullProof}

	for cut := 0; cut < len(fullProof); cut++ {
		truncated := cloneIntGenISISPresentationV3(pres)
		truncated.CanonicalProof = truncated.CanonicalProof[:cut:cut]
		verifyCalls := 0
		ok, err := VerifyProofV3(truncated, public, key, rawContext, func(got IntGenISISPresentationV3, _ IntGenISISPresentationCodecContext) (bool, error) {
			verifyCalls++
			if len(got.CanonicalProof) != len(fullProof) {
				return false, errors.New("mandatory canonical proof decoder rejected truncation")
			}
			return true, nil
		})
		if err == nil || ok {
			t.Fatalf("presentation-v3 proof truncation at %d/%d accepted: ok=%v err=%v", cut, len(fullProof), ok, err)
		}
		if cut < len(intGenISISCanonicalShowingProofV6Header) && verifyCalls != 0 {
			t.Fatalf("header truncation %d reached proof verifier", cut)
		}
		if cut >= len(intGenISISCanonicalShowingProofV6Header) && verifyCalls != 1 {
			t.Fatalf("body truncation %d did not reach exactly one mandatory proof decode: calls=%d", cut, verifyCalls)
		}
	}
}

func TestVerifierStateV3ConcurrentDuplicateAndNoLegacyFallback(t *testing.T) {
	pres, codecCtx := testPresentationV3Artifacts(t, IntGenISISPresetSystemN1024WF128CROMV2)
	path := filepath.Join(t.TempDir(), "verifier-v3.json")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- CheckAndMarkIntGenISISPresentationV3(path, pres, codecCtx)
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent v3 duplicate accepts=%d want 1", successes)
	}

	legacyPath := filepath.Join(t.TempDir(), "legacy-verifier.json")
	publicDigest, err := PublicParamsDigest(codecCtx.Public)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest, err := codecCtx.VerifierKey.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIntGenISISVerifierState(legacyPath, NewIntGenISISVerifierState(publicDigest, keyDigest)); err != nil {
		t.Fatal(err)
	}
	if err := CheckAndMarkIntGenISISPresentationV3(legacyPath, pres, codecCtx); err == nil || !strings.Contains(err.Error(), "no migration") {
		t.Fatalf("legacy verifier state accepted by v3 transition: %v", err)
	}

	legacyPresentation := IntGenISISPresentation{
		Version:              IntGenISISPresentationVersion,
		PresetManifestDigest: codecCtx.Public.PresetManifestDigest,
		PublicParamsDigest:   publicDigest,
		VerifierKeyDigest:    keyDigest,
		ContextDigest:        repeatedDigest(8),
		Context:              append([]int64(nil), codecCtx.Context...),
		Tag:                  append([]int64(nil), pres.Tag...),
		Proof:                json.RawMessage(`{"schema_version":2}`),
	}
	if err := legacyPresentation.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("strict-v3 target accepted legacy presentation: %v", err)
	}
}

func TestUsageV3RejectsUnknownFieldsTrailingDataAndWrongBindings(t *testing.T) {
	credential, stateCtx := testStateV8Artifacts(t, IntGenISISPresetPoCN1024BQ128R128V3)
	binding := deriveContextForV3Test(t, stateCtx.Public, stateCtx.VerifierKey, []byte("holder-v3/strict-json"))
	path := filepath.Join(t.TempDir(), "holder-v3.json")
	if _, err := ReserveIntGenISISSlotV3(path, credential, stateCtx, binding); err != nil {
		t.Fatal(err)
	}
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(valid))
	unknown := strings.TrimSuffix(trimmed, "}") + `,"unknown_v3_field":true}`
	if err := os.WriteFile(path, []byte(unknown), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIntGenISISHolderUsageStateV3(path, credential, stateCtx); err == nil {
		t.Fatal("holder-v3 unknown JSON field accepted")
	}
	if err := os.WriteFile(path, append(valid, []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIntGenISISHolderUsageStateV3(path, credential, stateCtx); err == nil {
		t.Fatal("holder-v3 trailing JSON accepted")
	}

	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongKey := stateCtx.VerifierKey
	wrongKey.NTRUPublic = cloneInt64Rows(stateCtx.VerifierKey.NTRUPublic)
	wrongKey.NTRUPublic[0][0] = 1
	wrongStateCtx := stateCtx
	wrongStateCtx.VerifierKey = wrongKey
	if _, err := LoadIntGenISISHolderUsageStateV3(path, credential, wrongStateCtx); err == nil {
		t.Fatal("holder-v3 state accepted wrong verifier-key context")
	}
}

func TestPresentationOperationsV3AreTargetOnlyAndFailedVerificationDoesNotAccept(t *testing.T) {
	legacyPublic, legacyKey, legacyCredential := testPresentationOperationArtifacts(t)
	legacyStateCtx := IntGenISISStateCodecContext{
		Public:           legacyPublic,
		VerifierKey:      legacyKey,
		PublicParamsPath: legacyCredential.CredentialPublicPath,
	}
	legacyHolder := filepath.Join(t.TempDir(), "legacy-holder.json")
	proveCalls := 0
	if _, err := CreatePresentationV3(legacyPublic, legacyKey, legacyCredential, legacyStateCtx, []byte("legacy-context"), legacyHolder, func(PresentationContextBinding, uint8) ([]int64, []byte, error) {
		proveCalls++
		return nil, nil, nil
	}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("non-target preset entered presentation-v3 path: %v", err)
	}
	if proveCalls != 0 {
		t.Fatalf("v3 prover called for legacy preset: %d", proveCalls)
	}
	if _, err := os.Stat(legacyHolder); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target-only rejection created holder state: %v", err)
	}

	pres, codecCtx := testPresentationV3Artifacts(t, IntGenISISPresetPoCN1024BQ128R128V3)
	rawContext := []byte("proof-failure/context")
	derived, _, err := DeriveIntGenISISPresentationV3Context(codecCtx.Public, codecCtx.VerifierKey, rawContext)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the fixture's arbitrary codec context with the independent one
	// used by the operation. The metadata-free wire itself is unchanged.
	codecCtx.Context = derived.Lanes
	verifierPath := filepath.Join(t.TempDir(), "verifier-v3.json")
	if ok, err := VerifyAndAcceptV3(pres, codecCtx.Public, codecCtx.VerifierKey, rawContext, verifierPath, func(IntGenISISPresentationV3, IntGenISISPresentationCodecContext) (bool, error) {
		return false, nil
	}); err != nil || ok {
		t.Fatalf("failed proof verification result=(%v,%v), want (false,nil)", ok, err)
	}
	if _, err := os.Stat(verifierPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed proof verification created replay state: %v", err)
	}
}
