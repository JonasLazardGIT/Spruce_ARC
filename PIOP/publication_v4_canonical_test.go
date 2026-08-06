package PIOP

import (
	"bytes"
	"testing"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func canonicalPublicationV4PreSignContextForTest(t testing.TB, presetID string) CanonicalProofContext {
	t.Helper()
	chdirForPIOPIntGenISISTest(t)
	preset, ok := credential.LookupIntGenISISPublicationPreset(presetID)
	if !ok {
		t.Fatalf("missing publication-v4 preset %q", presetID)
	}
	if err := credential.ValidateIntGenISISPresetManifest(preset); err != nil {
		t.Fatalf("invalid publication-v4 preset %q: %v", presetID, err)
	}
	tuning := preset.Issuance
	protocol, transcriptVersion, err := credential.ResolveIntGenISISTranscript(tuning.TranscriptMode)
	if err != nil {
		t.Fatal(err)
	}
	ringQ, err := credential.LoadRingWithDegree(1024)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		t.Fatalf("missing profile %q", preset.Profile)
	}
	pp := credential.PublicParams{
		Profile:              preset.Profile,
		PresetID:             preset.CanonicalID,
		PresetVersion:        preset.PresetVersion,
		PrimitiveProfileID:   preset.PrimitiveProfileID,
		PRFProfile:           preset.PRFProfile,
		TranscriptMode:       preset.Showing.TranscriptMode,
		PresetManifestDigest: credential.IntGenISISPresetManifestDigest(preset),
		RateLimitPolicy:      preset.RateLimitPolicy,
		Modulus:              ringQ.Modulus[0],
	}
	zero := func() *ring.Poly { return ringQ.NewPoly() }
	pub := PublicInputs{
		Com:            []*ring.Poly{zero()},
		CM:             [][]*ring.Poly{{zero()}},
		AS:             [][]*ring.Poly{{zero()}},
		BoundB:         credential.IntGenISISLiveBound,
		HashInputBound: credential.IntGenISISHashInputBound,
		X0Len:          profile.EllX0,
		RingDegree:     1024,
		HashRelation:   credential.HashRelationBBTran,
		IntGenISIS:     true,
		Extras:         pp.PresetTranscriptExtras(nil),
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:                 true,
		PresetID:                   preset.CanonicalID,
		RingDegree:                 1024,
		NCols:                      tuning.NCols,
		LVCSNCols:                  tuning.LVCSNCols,
		NLeaves:                    tuning.NLeaves,
		Ell:                        tuning.Ell,
		EllPrime:                   tuning.EllPrime,
		Eta:                        tuning.Eta,
		Rho:                        tuning.Rho,
		Theta:                      tuning.Theta,
		Kappa:                      tuning.Kappa,
		ROQueryCaps:                tuning.ROQueryCaps,
		ROQueryCapsSet:             tuning.ROQueryCapsSet,
		ROQueryCapBits:             tuning.ROQueryCapBits,
		ROQueryCapBitsSet:          tuning.ROQueryCapBitsSet,
		AggregateROQueryCapLog2:    tuning.AggregateROQueryCapLog2,
		AggregateROQueryCapLog2Set: tuning.AggregateROQueryCapLog2Set,
		DECSCollisionBits:          tuning.DECSCollisionBits,
		DECSHashBits:               tuning.DECSHashBits,
		DECSTapeBits:               tuning.DECSTapeBits,
		FSCollisionBits:            tuning.FSCollisionBits,
		FSOutputBits:               tuning.FSOutputBits,
		SaltBits:                   tuning.SaltBits,
		DomainMode:                 DomainModeExplicit,
		TranscriptOmissionMode:     tuning.TranscriptOmissionMode,
		TranscriptProtocolMode:     protocol,
		TranscriptVersion:          transcriptVersion,
		FixedTranscriptSize:        tuning.FixedTranscriptSize,
		IntGenISISMSECompression:   tuning.CompressedRows,
		IntGenISISReplayProjection: tuning.ReplayProjection,
		SigShortnessRadix:          tuning.SigShortnessRadix,
		SigShortnessL:              tuning.SigShortnessDigits,
		PRFParamsPath:              tuning.PRFParamsPath,
	})
	return CanonicalProofContext{Kind: CanonicalProofPreSign, Public: pub, Options: opts}
}

func TestPublicationV4CanonicalProofAcceptanceSurface(t *testing.T) {
	ctx := canonicalPublicationV4PreSignContextForTest(t, credential.IntGenISISPublicationPresetBQ128Q128V4)
	g, err := deriveCanonicalProofGeometryV3(ctx)
	if err != nil {
		t.Fatalf("derive publication-v4 geometry: %v", err)
	}
	proof := canonicalSyntheticProofV3(t, g)
	policy, ok := PublicationV4WidthPolicyForPreset(ctx.Options.PresetID)
	if !ok {
		t.Fatal("missing manifest-derived publication policy")
	}
	if proof.TranscriptVersion != TranscriptVersionSmallWood2025V4 || proof.TranscriptProtocolMode != TranscriptProtocolSmallField2025V4 || proof.FSOutputBits != policy.FSOutputBits {
		t.Fatalf("publication-v4 proof tuple=(%q,%q,%d)", proof.TranscriptVersion, proof.TranscriptProtocolMode, proof.FSOutputBits)
	}
	for i, digest := range proof.Digests {
		if len(digest) != policy.FSOutputBits/8 {
			t.Fatalf("round %d digest bytes=%d want=%d", i, len(digest), policy.FSOutputBits/8)
		}
	}

	wire, err := MarshalCanonicalProof(proof, ctx)
	if err != nil {
		t.Fatalf("marshal publication-v4 proof: %v", err)
	}
	decoded, err := UnmarshalCanonicalProof(wire, ctx)
	if err != nil {
		t.Fatalf("unmarshal publication-v4 proof: %v", err)
	}
	for i, digest := range decoded.Digests {
		if len(digest) != policy.FSOutputBits/8 || !bytes.Equal(digest, proof.Digests[i]) {
			t.Fatalf("decoded round %d digest is not the exact context-derived value", i)
		}
	}
	reencoded, err := MarshalCanonicalProof(decoded, ctx)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatalf("publication-v4 canonical round trip: equal=%v err=%v", bytes.Equal(reencoded, wire), err)
	}
	if _, err := UnmarshalCanonicalProof(append(append([]byte(nil), wire...), 0), ctx); err == nil {
		t.Fatal("publication-v4 canonical decoder accepted trailing data")
	}

	matrices := canonicalProofMatricesV3{
		r:        copyMatrix(proof.R),
		qPayload: copyMatrix(proof.QPayloadMatrix()),
		vTargets: copyMatrix(proof.VTargetsMatrix()),
		barSets:  copyMatrix(proof.BarSetsMatrix()),
	}
	mutatedRoot := append([]byte(nil), proofRootBytes(proof)...)
	mutatedRoot[0] ^= 0x80
	mutated, err := grindCanonicalProofV3(g, mutatedRoot, proof.Salt, matrices)
	if err != nil {
		t.Fatalf("rederive root-mutated transcript: %v", err)
	}
	for i := range proof.Digests {
		if bytes.Equal(proof.Digests[i], mutated.Digests[i]) {
			t.Fatalf("root mutation did not change chained FS digest %d", i)
		}
	}

	wrongCtx := canonicalPublicationV4PreSignContextForTest(t, credential.IntGenISISPublicationPresetBQ128Q64V4)
	if _, err := UnmarshalCanonicalProof(wire, wrongCtx); err == nil {
		t.Fatal("publication-v4 proof accepted under a different manifest-bound preset")
	}
}

func TestPublicationV4PreparedContextsBindAllFivePresetIdentities(t *testing.T) {
	seen := make(map[string]string)
	for _, id := range credential.IntGenISISPublicationPresetNamesV4() {
		ctx := canonicalPublicationV4PreSignContextForTest(t, id)
		prepared, err := PrepareExecutionContext(ctx)
		if err != nil {
			t.Fatalf("prepare %s: %v", id, err)
		}
		digest := prepared.BindingDigest()
		if prior, ok := seen[digest]; ok {
			t.Fatalf("prepared context digest collision: %s and %s", prior, id)
		}
		seen[digest] = id

		ctx.Options.ExecutionPolicy = ExecutionPolicy{WorkerBudget: 15, DECSWorkers: 15, DECSChunkLeaves: 32, SemanticWorkers: 15, IssuancePlanWorkers: 15}
		operational, err := PrepareExecutionContext(ctx)
		if err != nil {
			t.Fatalf("prepare %s with operational policy: %v", id, err)
		}
		if operational.BindingDigest() != digest {
			t.Fatalf("%s execution policy changed cryptographic context identity", id)
		}
	}
	if len(seen) != 5 {
		t.Fatalf("prepared publication contexts=%d want 5", len(seen))
	}
}

func TestHistoricalV2V3FiatShamirReplayCompatibility(t *testing.T) {
	material := [][]byte{[]byte("historical-replay-material")}
	v2Params := FSParams{
		Lambda:             256,
		TranscriptVersion:  TranscriptVersionSmallWood2025V2,
		TranscriptProtocol: TranscriptProtocolSmallField2025V2,
	}
	proverV2, err := NewFSChecked(NewShake256XOF(fsDigestBytes), []byte("historical-v2-salt"), v2Params)
	if err != nil {
		t.Fatal(err)
	}
	digestV2, counterV2, _ := proverV2.GrindAndDerive(0, material, func(v []byte) []byte { return v })
	verifierV2, err := NewFSChecked(NewShake256XOF(fsDigestBytes), []byte("historical-v2-salt"), v2Params)
	if err != nil {
		t.Fatal(err)
	}
	replayedV2, err := verifyRoundDigest(verifierV2, 0, counterV2, material, digestV2, 0)
	if err != nil || len(replayedV2) != fsDigestBytes || !bytes.Equal(replayedV2, digestV2) {
		t.Fatalf("historical v2 replay failed: bytes=%d err=%v", len(replayedV2), err)
	}

	v3ctx := canonicalPreSignContextForTest(t, 13)
	v3g, err := deriveCanonicalProofGeometryV3(v3ctx)
	if err != nil {
		t.Fatal(err)
	}
	v3proof := canonicalSyntheticProofV3(t, v3g)
	if v3proof.FSOutputBits != 0 {
		t.Fatalf("historical v3 proof gained a serialized FS-width field: %d", v3proof.FSOutputBits)
	}
	v3wire, err := MarshalCanonicalProof(v3proof, v3ctx)
	if err != nil {
		t.Fatal(err)
	}
	v3decoded, err := UnmarshalCanonicalProof(v3wire, v3ctx)
	if err != nil {
		t.Fatalf("historical v3 replay failed: %v", err)
	}
	for i, digest := range v3decoded.Digests {
		if len(digest) != fsDigestBytes || !bytes.Equal(digest, v3proof.Digests[i]) {
			t.Fatalf("historical v3 round %d digest replay mismatch", i)
		}
	}
}
