package PIOP

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestStrictV3TailChallengeDeterministicVectorAndTamper(t *testing.T) {
	h4 := make([]byte, fsDigestBytes)
	for i := range h4 {
		h4[i] = byte(i)
	}
	const start, length, count = 40, 97, 9
	want := []int{41, 44, 45, 47, 62, 94, 103, 117, 127}

	derive := func() []int {
		return sampleDistinctIndices(
			start,
			length,
			count,
			newFSRNGForTranscript(TranscriptVersionSmallWood2025V3, "TailPoints", h4),
		)
	}
	if got := derive(); !reflect.DeepEqual(got, want) {
		t.Fatalf("strict-v3 exact tail vector=%v want %v", got, want)
	}
	if got := derive(); !reflect.DeepEqual(got, want) {
		t.Fatalf("strict-v3 tail replay=%v want deterministic %v", got, want)
	}
	if err := verifyTailChallengeV3(TranscriptVersionSmallWood2025V3, h4, want, start, length, count); err != nil {
		t.Fatalf("verify deterministic strict-v3 tail: %v", err)
	}

	tampered := append([]int(nil), want...)
	tampered[0] = start // valid and distinct, but not selected by Fiat--Shamir.
	sort.Ints(tampered)
	if err := verifyTailChallengeV3(TranscriptVersionSmallWood2025V3, h4, tampered, start, length, count); err == nil || !strings.Contains(err.Error(), "tail challenge mismatch") {
		t.Fatalf("strict-v3 accepted attacker-selected tail %v: %v", tampered, err)
	}

	// The closure is intentionally strict-v3-only. Historical v2 proofs keep
	// their existing verifier behavior byte-for-byte.
	if err := verifyTailChallengeV3(TranscriptVersionSmallWood2025V2, nil, tampered, start, length, count); err != nil {
		t.Fatalf("strict-v3 tail closure changed legacy behavior: %v", err)
	}
}

func TestStrictV3InMemoryVerifierRejectsTailTamper(t *testing.T) {
	ctx := canonicalPreSignContextForTest(t, 7)
	ringQ, err := credential.LoadRingWithDegree(1024)
	if err != nil {
		t.Fatal(err)
	}
	profile := credential.Ternary1024IntGenISISProfile()
	layout, err := credential.DefaultSemanticMessageLayout(profile, intGenISISPRFKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	message, err := credential.EncodeSemanticMessage(layout, credential.ZeroSemanticAttributes(layout), intGenISISTestPRFSeed())
	if err != nil {
		t.Fatal(err)
	}
	zero := func() *ring.Poly { return ringQ.NewPoly() }
	witness := WitnessInputs{
		M:     polysFromInt64ForIntGenISISTest(ringQ, message.M),
		MAttr: polysFromInt64ForIntGenISISTest(ringQ, message.MAttr),
		K:     polysFromInt64ForIntGenISISTest(ringQ, message.K),
		S:     []*ring.Poly{zero()},
		E:     []*ring.Poly{zero()},
	}
	proof, err := BuildIntGenISISPreSign(ringQ, ctx.Public, witness, ctx.Options)
	if err != nil {
		t.Fatalf("build strict-v3 pre-sign proof: %v", err)
	}
	if ok, verifyErr := VerifyIntGenISISPreSign(ctx.Public, proof, ctx.Options); verifyErr != nil || !ok {
		t.Fatalf("verify strict-v3 source proof: ok=%v err=%v", ok, verifyErr)
	}

	tampered := *proof
	tampered.Tail = append([]int(nil), proof.Tail...)
	tailStart := proof.LVCSNColsUsed + len(proof.Tail)
	replacement := tailStart
	used := make(map[int]bool, len(proof.Tail))
	for _, index := range proof.Tail {
		used[index] = true
	}
	for used[replacement] {
		replacement++
	}
	if replacement >= proof.NLeavesUsed {
		t.Fatal("test could not find a distinct in-range tail replacement")
	}
	tampered.Tail[0] = replacement
	sort.Ints(tampered.Tail)
	if ok, verifyErr := VerifyIntGenISISPreSign(ctx.Public, &tampered, ctx.Options); verifyErr == nil || ok || !strings.Contains(verifyErr.Error(), "Fiat-Shamir tail challenge mismatch") {
		t.Fatalf("strict-v3 in-memory verifier accepted attacker-selected tail: ok=%v err=%v", ok, verifyErr)
	}
}
