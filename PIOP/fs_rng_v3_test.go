package PIOP

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"testing"

	kf "vSIS-Signature/internal/kfield"
)

func TestLegacyFSRNGVectorUnchanged(t *testing.T) {
	label := "legacy-vector"
	material := [][]byte{[]byte("first"), []byte("second")}

	seedHash := sha256.New()
	_, _ = seedHash.Write([]byte(label))
	for _, part := range material {
		_, _ = seedHash.Write(part)
	}
	seedBytes := seedHash.Sum(nil)
	var block [40]byte
	copy(block[:32], seedBytes)
	binary.LittleEndian.PutUint64(block[32:], 0)
	wantDigest := sha256.Sum256(block[:])
	want := binary.LittleEndian.Uint64(wantDigest[:8])

	got := newFSRNG(label, material...).nextU64()
	if got != want {
		t.Fatalf("legacy fsRNG first word=%d want %d", got, want)
	}
}

func TestFSRNGV3BindsFullMaterialAndBoundaries(t *testing.T) {
	prefixA := make([]byte, 64)
	prefixB := make([]byte, 64)
	copy(prefixA, bytes.Repeat([]byte{0x42}, 64))
	copy(prefixB, prefixA)
	prefixB[63] ^= 1
	if gotA, gotB := newFSRNGV3("full-width", prefixA).nextU64(), newFSRNGV3("full-width", prefixB).nextU64(); gotA == gotB {
		t.Fatal("v3 expansion ignored material beyond a narrow prefix")
	}

	left := newFSRNGV3("framing", []byte("ab"), []byte("c")).nextU64()
	right := newFSRNGV3("framing", []byte("a"), []byte("bc")).nextU64()
	if left == right {
		t.Fatal("v3 expansion did not bind material boundaries")
	}
}

func TestUniformUint64FromRejectsModuloBiasInterval(t *testing.T) {
	// 2^64 mod 10 = 6. Both 0 and 5 lie in the rejected prefix; 27 is
	// accepted and maps to 7.
	draws := []uint64{0, 5, 27}
	consumed := 0
	got := uniformUint64From(func() uint64 {
		v := draws[consumed]
		consumed++
		return v
	}, 10)
	if got != 7 || consumed != 3 {
		t.Fatalf("exact sample=(%d, draws=%d) want (7, 3)", got, consumed)
	}
}

func TestUniformUint64FromExactRejectionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modulus uint64
	}{
		{name: "target-fq", modulus: 1017857},
		{name: "bounded-97", modulus: 97},
		{name: "singleton", modulus: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			threshold := -tc.modulus % tc.modulus
			draws := []uint64{threshold, ^uint64(0)}
			if threshold > 0 {
				draws = append([]uint64{threshold - 1}, draws...)
			}
			consumed := 0
			got := uniformUint64From(func() uint64 {
				v := draws[consumed]
				consumed++
				return v
			}, tc.modulus)
			wantConsumed := 1
			if threshold > 0 {
				wantConsumed = 2
			}
			if got != threshold%tc.modulus || consumed != wantConsumed {
				t.Fatalf(
					"threshold=%d exact sample=(%d, draws=%d) want (%d, %d)",
					threshold, got, consumed, threshold%tc.modulus, wantConsumed,
				)
			}
		})
	}
}

func TestFSRNGV3ExactFqAndBoundedVectors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		label    string
		material []byte
		modulus  uint64
		want     []uint64
	}{
		{
			name:     "target-fq",
			label:    "fq-vector",
			material: []byte("SPRUCE-v3-Fq"),
			modulus:  1017857,
			want:     []uint64{504813, 279637, 618583, 261859, 213348, 947785, 743534, 323310},
		},
		{
			name:     "bounded-integer",
			label:    "bounded-vector",
			material: []byte("SPRUCE-v3-bounded"),
			modulus:  97,
			want:     []uint64{16, 0, 52, 93, 35, 41, 2, 75, 71, 49, 72, 89},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rng := newFSRNGV3(tc.label, tc.material)
			if !rng.exact {
				t.Fatal("v3 sampler was not marked exact")
			}
			got := make([]uint64, len(tc.want))
			for i := range got {
				got[i] = rng.nextMod(tc.modulus)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("exact vector=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestFSRNGV3ExactTargetKVector(t *testing.T) {
	profile, ok := kf.LookupSmallWoodFieldProfileV3(1017857, 7)
	if !ok {
		t.Fatal("missing maintained theta-7 profile")
	}
	omega := make([]uint64, 32)
	for i := range omega {
		omega[i] = uint64(i + 1)
	}
	K, _, err := profile.Validate(omega)
	if err != nil {
		t.Fatalf("validate profile: %v", err)
	}
	got, _, err := sampleSmallFieldKPoints(
		K, omega, 1, newFSRNGV3("k-target-vector", []byte("SPRUCE-v3-K")),
	)
	if err != nil {
		t.Fatalf("sample exact target K point: %v", err)
	}
	want := [][]uint64{{443093, 947424, 457993, 427330, 338440, 739194, 59345}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exact target K vector=%v want=%v", got, want)
	}
}

func TestFSRNGV3KMinusOmegaAndDistinctRejections(t *testing.T) {
	K, err := kf.NewUnchecked(5, 2, []uint64{2, 0, 1})
	if err != nil {
		t.Fatalf("NewUnchecked: %v", err)
	}
	omega := []uint64{0}

	// With this pinned stream the first candidate is (0,0), exactly the
	// embedded Omega point. The K\Omega sampler must discard it.
	zeroSeed := make([]byte, 8)
	probe := newFSRNGV3("k-minus-omega-rejection", zeroSeed)
	first := []uint64{probe.nextMod(5), probe.nextMod(5)}
	if !reflect.DeepEqual(first, []uint64{0, 0}) {
		t.Fatalf("pinned rejected K candidate=%v want [0 0]", first)
	}
	got, _, err := sampleSmallFieldKPoints(
		K, omega, 2, newFSRNGV3("k-minus-omega-rejection", zeroSeed),
	)
	if err != nil {
		t.Fatalf("sample K\\Omega rejection vector: %v", err)
	}
	want := [][]uint64{{4, 4}, {0, 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("K\\Omega rejection vector=%v want=%v", got, want)
	}

	// This second stream yields (3,3) twice before (2,4). The sampler must
	// reject the duplicate while retaining two distinct K points.
	var duplicateSeed [8]byte
	binary.BigEndian.PutUint64(duplicateSeed[:], 2)
	probe = newFSRNGV3("k-minus-omega-distinct", duplicateSeed[:])
	first = []uint64{probe.nextMod(5), probe.nextMod(5)}
	second := []uint64{probe.nextMod(5), probe.nextMod(5)}
	if !reflect.DeepEqual(first, []uint64{3, 3}) || !reflect.DeepEqual(second, first) {
		t.Fatalf("pinned duplicate K candidates=%v/%v want [3 3]/[3 3]", first, second)
	}
	got, _, err = sampleSmallFieldKPoints(
		K, omega, 2, newFSRNGV3("k-minus-omega-distinct", duplicateSeed[:]),
	)
	if err != nil {
		t.Fatalf("sample distinct K rejection vector: %v", err)
	}
	want = [][]uint64{{3, 3}, {2, 4}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("distinct K rejection vector=%v want=%v", got, want)
	}
}

func TestFSTranscriptV3FramesRoundMaterial(t *testing.T) {
	paramsV3 := FSParams{
		Lambda:             128,
		TranscriptVersion:  TranscriptVersionSmallWood2025V3,
		TranscriptProtocol: TranscriptProtocolSmallField2025V3,
	}
	derive := func(in []byte) []byte { return append([]byte(nil), in...) }
	leftFS := NewFS(NewShake256XOF(fsDigestBytes), []byte("salt"), paramsV3)
	left, _, _ := leftFS.GrindAndDerive(0, [][]byte{[]byte("ab"), []byte("c")}, derive)
	rightFS := NewFS(NewShake256XOF(fsDigestBytes), []byte("salt"), paramsV3)
	right, _, _ := rightFS.GrindAndDerive(0, [][]byte{[]byte("a"), []byte("bc")}, derive)
	if bytes.Equal(left, right) {
		t.Fatal("v3 FS round material framing is ambiguous")
	}
	if len(left) != fsDigestBytes || len(right) != fsDigestBytes {
		t.Fatalf("v3 digest widths=(%d,%d) want %d", len(left), len(right), fsDigestBytes)
	}

	// V2 deliberately keeps the historical concatenation behavior byte-for-byte.
	paramsV2 := FSParams{
		Lambda:             128,
		TranscriptVersion:  TranscriptVersionSmallWood2025V2,
		TranscriptProtocol: TranscriptProtocolSmallField2025V2,
	}
	legacyLeft, _, _ := NewFS(NewShake256XOF(fsDigestBytes), []byte("salt"), paramsV2).GrindAndDerive(0, [][]byte{[]byte("ab"), []byte("c")}, derive)
	legacyRight, _, _ := NewFS(NewShake256XOF(fsDigestBytes), []byte("salt"), paramsV2).GrindAndDerive(0, [][]byte{[]byte("a"), []byte("bc")}, derive)
	if !bytes.Equal(legacyLeft, legacyRight) {
		t.Fatal("v2 round expansion changed while adding v3 framing")
	}
}

func TestLabelsDigestV3UsesConfiguredFullWidth(t *testing.T) {
	opts := SimOpts{TranscriptVersion: TranscriptVersionSmallWood2025V3, FSCollisionBits: 168}
	labels := []PublicLabel{{Name: "statement", Data: []byte("payload")}}
	digest := computeLabelsDigestForOpts(labels, opts)
	if len(digest) != 21 {
		t.Fatalf("v3 labels digest width=%d want 21", len(digest))
	}
	if bytes.Equal(digest, computeLabelsDigest(labels)) {
		t.Fatal("v3 labels digest reused the legacy SHA-256 encoding")
	}
}

func TestSmallFieldKPointV3SamplesExactKMinusOmega(t *testing.T) {
	K, err := kf.NewUnchecked(5, 2, []uint64{2, 0, 1})
	if err != nil {
		t.Fatalf("NewUnchecked: %v", err)
	}
	omega := []uint64{0}
	foundEmbeddedOutsideOmega := false
	for seed := uint64(0); seed < 256; seed++ {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], seed)
		points, _, err := sampleSmallFieldKPoints(K, omega, 1, newFSRNGV3("k-minus-omega", encoded[:]))
		if err != nil {
			t.Fatalf("v3 sample seed %d: %v", seed, err)
		}
		if len(points) != 1 || len(points[0]) != K.Theta {
			t.Fatalf("v3 sample shape=%v", points)
		}
		if points[0][1] == 0 && points[0][0] != 0 {
			foundEmbeddedOutsideOmega = true
			break
		}
	}
	if !foundEmbeddedOutsideOmega {
		t.Fatal("v3 sampler never admitted an embedded F element in K\\Omega")
	}

	for seed := uint64(0); seed < 32; seed++ {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], seed)
		points, _, err := sampleSmallFieldKPoints(K, omega, 1, newFSRNG("legacy-k-minus-f", encoded[:]))
		if err != nil {
			t.Fatalf("v2 sample seed %d: %v", seed, err)
		}
		if points[0][1] == 0 {
			t.Fatalf("legacy v2 sampler behavior changed at seed %d: %v", seed, points[0])
		}
	}
}

func TestVerifierRowDegreeBoundV3IsGeometryDerived(t *testing.T) {
	v3 := &Proof{TranscriptVersion: TranscriptVersionSmallWood2025V3, RowDegreeBound: 52}
	got, err := verifierRowDegreeBound(v3, 49, 4)
	if err != nil || got != 52 {
		t.Fatalf("v3 row degree=(%d,%v) want (52,nil)", got, err)
	}
	v3.RowDegreeBound++
	if _, err := verifierRowDegreeBound(v3, 49, 4); err == nil {
		t.Fatal("v3 verifier accepted an attacker-inflated row degree bound")
	}

	v2 := &Proof{TranscriptVersion: TranscriptVersionSmallWood2025V2, RowDegreeBound: 0, MaskDegreeBound: 91}
	got, err = verifierRowDegreeBound(v2, 49, 4)
	if err != nil || got != 91 {
		t.Fatalf("legacy v2 row degree=(%d,%v) want (91,nil)", got, err)
	}
}

func TestStrictTranscriptTupleSelectsMatchingSchema(t *testing.T) {
	if !transcriptUsesStrictSmallField2025(TranscriptVersionSmallWood2025V3, TranscriptProtocolSmallField2025V3) {
		t.Fatal("v3 strict transcript tuple was not recognized")
	}
	if transcriptUsesStrictSmallField2025(TranscriptVersionSmallWood2025V3, TranscriptProtocolSmallField2025V2) {
		t.Fatal("mixed v2/v3 transcript tuple was accepted")
	}
	if got := proofSchemaVersionForTranscript(TranscriptVersionSmallWood2025V3); got != ProofSchemaVersionV3 {
		t.Fatalf("v3 schema=%d want %d", got, ProofSchemaVersionV3)
	}
}
