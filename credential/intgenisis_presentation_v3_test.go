package credential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func testPresentationV3Artifacts(t testing.TB, presetName string) (IntGenISISPresentationV3, IntGenISISPresentationCodecContext) {
	t.Helper()
	public := testPublicParamsV2(t, presetName)
	key := testVerifierKeyV2(t, public)
	key.SignatureBound = 6142
	tagLen, ok := IntGenISISPRFProfileTagElements(public.PRFProfile)
	if !ok {
		t.Fatalf("unknown PRF profile %q", public.PRFProfile)
	}
	tag := make([]int64, tagLen)
	for i := range tag {
		tag[i] = int64((uint64(i) * 100003) % public.Modulus)
	}
	if len(tag) > 0 {
		tag[len(tag)-1] = int64(public.Modulus - 1)
	}
	context := make([]int64, IntGenISISContextLaneCount)
	for i := range context {
		context[i] = int64(i + 1)
	}
	// The credential package treats these as opaque bytes to avoid an import
	// cycle. PIOP canonical decoding is mandatory before verification.
	proof := append(append([]byte(nil), intGenISISCanonicalShowingProofV6Header[:]...), []byte("canonical-proof-v6-test-vector")...)
	return IntGenISISPresentationV3{Tag: tag, CanonicalProof: proof}, IntGenISISPresentationCodecContext{
		Public: public, VerifierKey: key, Context: context,
	}
}

func FuzzUnmarshalIntGenISISPresentationV3(f *testing.F) {
	pres, ctx := testPresentationV3Artifacts(f, IntGenISISPresetSystemN1024WF128CROMV2)
	wire, err := MarshalIntGenISISPresentationV3(pres, ctx)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte("SPRUCE-presentation-v3-invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, decodeErr := UnmarshalIntGenISISPresentationV3(data, ctx)
		if decodeErr != nil {
			return
		}
		reencoded, encodeErr := MarshalIntGenISISPresentationV3(decoded, ctx)
		if encodeErr != nil {
			t.Fatalf("accepted presentation did not re-encode: %v", encodeErr)
		}
		if !reflect.DeepEqual(reencoded, data) {
			t.Fatal("accepted presentation-v3 input was not canonical")
		}
	})
}

func TestIntGenISISPresentationV3TargetRoundTrips(t *testing.T) {
	for _, presetName := range []string{IntGenISISPresetPoCN1024BQ128R128V3, IntGenISISPresetSystemN1024WF128CROMV2} {
		t.Run(presetName, func(t *testing.T) {
			pres, ctx := testPresentationV3Artifacts(t, presetName)
			wire, err := MarshalIntGenISISPresentationV3(pres, ctx)
			if err != nil {
				t.Fatal(err)
			}
			wantLen := len(intGenISISPresentationV3Magic) + packedFq20Len(len(pres.Tag)) + len(pres.CanonicalProof)
			if len(wire) != wantLen {
				t.Fatalf("presentation-v3 length=%d want %d", len(wire), wantLen)
			}
			got, err := UnmarshalIntGenISISPresentationV3(wire, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, pres) {
				t.Fatalf("presentation-v3 round trip mismatch: got %+v want %+v", got, pres)
			}

			path := filepath.Join(t.TempDir(), "presentation.v3")
			if err := SaveIntGenISISPresentationV3(path, pres, ctx); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o644 {
				t.Fatalf("presentation-v3 mode=%o want 644", info.Mode().Perm())
			}
			loaded, err := LoadIntGenISISPresentationV3(path, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(loaded, pres) {
				t.Fatal("saved presentation-v3 changed envelope")
			}
		})
	}
}

func TestIntGenISISPresentationV3CanonicalEnvelope(t *testing.T) {
	pres, ctx := testPresentationV3Artifacts(t, IntGenISISPresetSystemN1024WF128CROMV2)
	wire, err := MarshalIntGenISISPresentationV3(pres, ctx)
	if err != nil {
		t.Fatal(err)
	}
	minEnvelope := len(intGenISISPresentationV3Magic) + packedFq20Len(len(pres.Tag)) + len(intGenISISCanonicalShowingProofV6Header)
	for cut := 0; cut < minEnvelope; cut++ {
		if _, err := UnmarshalIntGenISISPresentationV3(wire[:cut], ctx); err == nil {
			t.Fatalf("presentation-v3 envelope truncation at byte %d accepted", cut)
		}
	}
	badVersion := append([]byte(nil), wire...)
	badVersion[7] = 2
	if _, err := UnmarshalIntGenISISPresentationV3(badVersion, ctx); err == nil {
		t.Fatal("presentation-v3 wrong version accepted")
	}
	proofOffset := len(intGenISISPresentationV3Magic) + packedFq20Len(len(pres.Tag))
	badProofVersion := append([]byte(nil), wire...)
	badProofVersion[proofOffset+8] = 2
	if _, err := UnmarshalIntGenISISPresentationV3(badProofVersion, ctx); err == nil {
		t.Fatal("presentation-v3 legacy proof schema accepted")
	}
	legacyP3 := append([]byte(nil), wire...)
	copy(legacyP3[proofOffset:proofOffset+8], []byte("SPRUCEP3"))
	legacyP3[proofOffset+8] = 3
	if _, err := UnmarshalIntGenISISPresentationV3(legacyP3, ctx); err == nil {
		t.Fatal("presentation-v3 legacy P3 canonical wire accepted")
	}
	retiredP4 := append([]byte(nil), wire...)
	copy(retiredP4[proofOffset:proofOffset+8], []byte("SPRUCEP4"))
	retiredP4[proofOffset+8] = 4
	if _, err := UnmarshalIntGenISISPresentationV3(retiredP4, ctx); err == nil {
		t.Fatal("presentation-v3 retired post-challenge P4 wire accepted")
	}
	retiredP5 := append([]byte(nil), wire...)
	copy(retiredP5[proofOffset:proofOffset+8], []byte("SPRUCEP5"))
	retiredP5[proofOffset+8] = 5
	if _, err := UnmarshalIntGenISISPresentationV3(retiredP5, ctx); err == nil {
		t.Fatal("presentation-v3 retired fixed-padding P5 wire accepted")
	}
	badProofKind := append([]byte(nil), wire...)
	badProofKind[proofOffset+9] = 1
	if _, err := UnmarshalIntGenISISPresentationV3(badProofKind, ctx); err == nil {
		t.Fatal("presentation-v3 presign proof accepted as showing")
	}

	badTag := append([]byte(nil), wire...)
	encodedQ, err := packCanonicalFq20([]int64{int64(ctx.Public.Modulus)}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	copy(badTag[len(intGenISISPresentationV3Magic):], encodedQ)
	if _, err := UnmarshalIntGenISISPresentationV3(badTag, ctx); err == nil {
		t.Fatal("presentation-v3 tag value >=q accepted")
	}

	// WF has 13 tag lanes (260 used bits), leaving four high spare bits.
	badSpare := append([]byte(nil), wire...)
	lastTagByte := len(intGenISISPresentationV3Magic) + packedFq20Len(len(pres.Tag)) - 1
	badSpare[lastTagByte] |= 0x80
	if _, err := UnmarshalIntGenISISPresentationV3(badSpare, ctx); err == nil {
		t.Fatal("presentation-v3 nonzero tag spare bits accepted")
	}

	badContext := ctx
	badContext.Context = append([]int64(nil), ctx.Context...)
	badContext.Context[0] = int64(ctx.Public.Modulus)
	if _, err := UnmarshalIntGenISISPresentationV3(wire, badContext); err == nil {
		t.Fatal("presentation-v3 noncanonical trusted context accepted")
	}
	// A different but well-formed key/context is rejected by the mandatory
	// PIOP canonical-proof decoder, not by this deliberately metadata-free
	// envelope. Keeping the envelope free of duplicate bindings is the point of
	// presentation format v3.
}

func TestCanonicalFq20RejectsAlternateEncodings(t *testing.T) {
	values := []int64{0, 1, IntGenISISSharedModulusQ - 1, 42}
	wire, err := packCanonicalFq20(values, IntGenISISSharedModulusQ)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unpackCanonicalFq20(wire, len(values), IntGenISISSharedModulusQ)
	if err != nil || !reflect.DeepEqual(got, values) {
		t.Fatalf("Fq20 round trip=(%v,%v)", got, err)
	}
	if _, err := unpackCanonicalFq20(wire[:len(wire)-1], len(values), IntGenISISSharedModulusQ); err == nil {
		t.Fatal("truncated Fq20 encoding accepted")
	}
	one, err := packCanonicalFq20([]int64{0}, IntGenISISSharedModulusQ)
	if err != nil {
		t.Fatal(err)
	}
	one[len(one)-1] |= 0x80 // 20 bits use the low nibble of byte 2.
	if _, err := unpackCanonicalFq20(one, 1, IntGenISISSharedModulusQ); err == nil {
		t.Fatal("nonzero Fq20 spare bits accepted")
	}
}

func TestPresentationV3DiagnosticIsNotProofFormat(t *testing.T) {
	pres, ctx := testPresentationV3Artifacts(t, IntGenISISPresetPoCN1024BQ128R128V3)
	wire, err := MarshalIntGenISISPresentationV3(pres, ctx)
	if err != nil {
		t.Fatal(err)
	}
	diagnostic, err := NewIntGenISISPresentationV3Diagnostic(wire, json.RawMessage(`{"verified":true,"modeled_messages":42}`), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostic.BinaryBytes != len(wire) || len(diagnostic.BinarySHAKEDigest) != 98 {
		t.Fatalf("diagnostic bytes/digest=(%d,%d), want (%d,98)", diagnostic.BinaryBytes, len(diagnostic.BinarySHAKEDigest), len(wire))
	}
	path := filepath.Join(t.TempDir(), "presentation.v3.diagnostic.json")
	if err := SaveIntGenISISPresentationV3Diagnostic(path, diagnostic); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"tag", "proof", "canonical_proof", "presentation"} {
		if _, ok := shape[forbidden]; ok {
			t.Fatalf("diagnostic sidecar contains lossless field %q", forbidden)
		}
	}
	for _, required := range []string{"format_version", "binary_shake_digest", "binary_bytes", "proof_report"} {
		if _, ok := shape[required]; !ok {
			t.Fatalf("diagnostic sidecar missing %q", required)
		}
	}
}
