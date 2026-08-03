package decs

import (
	"bytes"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/tuneinsight/lattigo/v4/ring"
	"golang.org/x/crypto/sha3"
)

func v2TestContext(role CommitmentRole, saltByte byte) CommitmentContext {
	return CommitmentContext{
		TranscriptVersion: TranscriptVersionV2,
		Role:              role,
		Salt:              bytes.Repeat([]byte{saltByte}, 32),
	}
}

func makeV2FormalProver(t *testing.T) *Prover {
	t.Helper()
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	const (
		degree    = 7
		rowCount  = 4
		maskCount = 2
		nLeaves   = 64
		tapeBytes = 16
	)
	points := make([]uint64, nLeaves)
	for i := range points {
		points[i] = uint64(i + 1)
	}
	prover, err := NewProverWithParamsAndPointsFormalChecked(
		ringQ,
		formalRowsForCommitTest(rowCount, degree, ringQ.Modulus[0]),
		Params{Degree: degree, Eta: maskCount, TapeBytes: tapeBytes, HashBytes: 21},
		points,
	)
	if err != nil {
		t.Fatalf("new v2 prover: %v", err)
	}
	prover.MFormal = maskRowsForCommitTest(maskCount, degree, ringQ.Modulus[0])
	prover.tapes = make([]byte, nLeaves*tapeBytes)
	for i := range prover.tapes {
		prover.tapes[i] = byte((i*37 + 11) & 0xff)
	}
	return prover
}

func commitV2ForTest(t *testing.T, prover *Prover, ctx CommitmentContext, opts CommitOptions) []byte {
	t.Helper()
	root, err := prover.CommitInitV2WithOptions(ctx, opts)
	if err != nil {
		t.Fatalf("CommitInitV2WithOptions: %v", err)
	}
	return root
}

func ringBackedV2ProverFromFormal(source *Prover) *Prover {
	prover := &Prover{
		ringQ:   source.ringQ,
		P:       make([]*ring.Poly, len(source.PFormal)),
		M:       make([]*ring.Poly, len(source.MFormal)),
		params:  source.params,
		points:  append([]uint64(nil), source.points...),
		nLeaves: source.nLeaves,
		tapes:   append([]byte(nil), source.tapes...),
	}
	for i, row := range source.PFormal {
		prover.P[i] = source.ringQ.NewPoly()
		copy(prover.P[i].Coeffs[0], row)
	}
	for i, row := range source.MFormal {
		prover.M[i] = source.ringQ.NewPoly()
		copy(prover.M[i].Coeffs[0], row)
	}
	return prover
}

func cloneOpeningV2(open *DECSOpening) *DECSOpening {
	if open == nil {
		return nil
	}
	out := *open
	out.Indices = append([]int(nil), open.Indices...)
	out.IndexBits = append([]byte(nil), open.IndexBits...)
	out.Pvals = cloneUint64RowsV2(open.Pvals)
	out.Mvals = cloneUint64RowsV2(open.Mvals)
	out.PvalsBits = append([]byte(nil), open.PvalsBits...)
	out.MvalsBits = append([]byte(nil), open.MvalsBits...)
	out.PvalsColumnWidths = append([]uint8(nil), open.PvalsColumnWidths...)
	out.MvalsColumnWidths = append([]uint8(nil), open.MvalsColumnWidths...)
	out.POmitCols = append([]int(nil), open.POmitCols...)
	out.MOmitCols = append([]int(nil), open.MOmitCols...)
	out.Nodes = cloneByteRowsV2(open.Nodes)
	out.PathIndex = cloneIntRowsV2(open.PathIndex)
	out.PathBits = append([]byte(nil), open.PathBits...)
	out.Tapes = cloneByteRowsV2(open.Tapes)
	return &out
}

func cloneUint64RowsV2(rows [][]uint64) [][]uint64 {
	out := make([][]uint64, len(rows))
	for i := range rows {
		out[i] = append([]uint64(nil), rows[i]...)
	}
	return out
}

func cloneIntRowsV2(rows [][]int) [][]int {
	out := make([][]int, len(rows))
	for i := range rows {
		out[i] = append([]int(nil), rows[i]...)
	}
	return out
}

func cloneByteRowsV2(rows [][]byte) [][]byte {
	out := make([][]byte, len(rows))
	for i := range rows {
		out[i] = append([]byte(nil), rows[i]...)
	}
	return out
}

func TestV2FormalCommitModesMatchWithFixedIndependentTapes(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 7)
	serial := makeV2FormalProver(t)
	serialRoot := commitV2ForTest(t, serial, ctx, CommitOptions{FormalEvalMode: FormalEvalScalar, WorkerCount: 1})
	combined := makeV2FormalProver(t)
	combinedRoot := commitV2ForTest(t, combined, ctx, CommitOptions{FormalEvalMode: FormalEvalCombined, WorkerCount: 3})
	tiled := makeV2FormalProver(t)
	tiledRoot := commitV2ForTest(t, tiled, ctx, CommitOptions{FormalEvalMode: FormalEvalTiled, FormalEvalTileSize: 7, WorkerCount: 3})
	ringBacked := ringBackedV2ProverFromFormal(makeV2FormalProver(t))
	ringRoot := commitV2ForTest(t, ringBacked, ctx, CommitOptions{})
	if !bytes.Equal(serialRoot, combinedRoot) || !bytes.Equal(serialRoot, tiledRoot) || !bytes.Equal(serialRoot, ringRoot) {
		t.Fatalf("v2 roots differ by evaluation mode: scalar=%x combined=%x tiled=%x ring=%x", serialRoot, combinedRoot, tiledRoot, ringRoot)
	}
	serialOpen, err := serial.EvalOpenV2([]int{3, 17, 42})
	if err != nil {
		t.Fatal(err)
	}
	combinedOpen, err := combined.EvalOpenV2([]int{3, 17, 42})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(serialOpen, combinedOpen) {
		t.Fatal("v2 openings differ by evaluation mode")
	}
}

func TestV2OpeningSelectiveTapesAndStrictVerification(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 9)
	prover := makeV2FormalProver(t)
	root := commitV2ForTest(t, prover, ctx, CommitOptions{})
	if len(root) != prover.params.HashBytes {
		t.Fatalf("full root width=%d want=%d", len(root), prover.params.HashBytes)
	}
	indices := []int{3, 17, 42}
	open, err := prover.EvalOpenV2(indices)
	if err != nil {
		t.Fatalf("EvalOpenV2: %v", err)
	}
	if open.Version != OpeningVersionV2 || open.Role != ctx.Role || open.TapeBytes != prover.params.TapeBytes {
		t.Fatalf("unexpected v2 opening metadata: version=%d role=%q tapeBytes=%d", open.Version, open.Role, open.TapeBytes)
	}
	if len(open.Tapes) != len(indices) {
		t.Fatalf("v2 opening tapes=%d want=%d", len(open.Tapes), len(indices))
	}
	for i, idx := range indices {
		if !bytes.Equal(open.Tapes[i], prover.tapeAt(idx)) {
			t.Fatalf("opening tape[%d] is not leaf %d tape", i, idx)
		}
	}
	gamma, err := DeriveGammaV2(ctx, root, prover.params.Eta, prover.rowCount(), prover.ringQ.Modulus[0])
	if err != nil {
		t.Fatal(err)
	}
	rRows := prover.CommitStep2Formal(gamma)
	verifier, err := NewVerifierWithParamsAndPointsV2Checked(prover.ringQ, prover.rowCount(), prover.params, prover.points, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.VerifyEvalAtFormalHashV2(root, gamma, rRows, open, indices) {
		t.Fatal("baseline v2 opening rejected")
	}

	tests := map[string]func(*DECSOpening){
		"missing tape":    func(op *DECSOpening) { op.Tapes = op.Tapes[:len(op.Tapes)-1] },
		"extra tape":      func(op *DECSOpening) { op.Tapes = append(op.Tapes, bytes.Repeat([]byte{1}, op.TapeBytes)) },
		"short tape":      func(op *DECSOpening) { op.Tapes[0] = op.Tapes[0][:op.TapeBytes-1] },
		"long tape":       func(op *DECSOpening) { op.Tapes[0] = append(op.Tapes[0], 0) },
		"changed tape":    func(op *DECSOpening) { op.Tapes[0][0] ^= 1 },
		"wrong role":      func(op *DECSOpening) { op.Role = CommitmentRoleQPayload },
		"wrong version":   func(op *DECSOpening) { op.Version = 1 },
		"mixed indices":   func(op *DECSOpening) { op.IndexBits = []byte{0} },
		"short path":      func(op *DECSOpening) { op.PathIndex[0] = op.PathIndex[0][:len(op.PathIndex[0])-1] },
		"long path":       func(op *DECSOpening) { op.PathIndex[0] = append(op.PathIndex[0], op.PathIndex[0][0]) },
		"non-canonical P": func(op *DECSOpening) { op.Pvals[0][0] = prover.ringQ.Modulus[0] },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			tampered := cloneOpeningV2(open)
			mutate(tampered)
			if verifier.VerifyEvalAtFormalHashV2(root, gamma, rRows, tampered, indices) {
				t.Fatalf("accepted %s", name)
			}
		})
	}

	wrongSaltVerifier, err := NewVerifierWithParamsAndPointsV2Checked(prover.ringQ, prover.rowCount(), prover.params, prover.points, v2TestContext(CommitmentRoleMain, 10))
	if err != nil {
		t.Fatal(err)
	}
	if wrongSaltVerifier.VerifyEvalAtFormalHashV2(root, gamma, rRows, open, indices) {
		t.Fatal("accepted opening under changed salt")
	}
	if verifier.VerifyEvalAtFormalHashV2(root[:16], gamma, rRows, open, indices) {
		t.Fatal("accepted truncated v2 root")
	}

	packed := cloneOpeningV2(open)
	PackOpeningWithOptions(packed, OpeningPackOptions{FixedSize: true, NLeaves: len(prover.points), FieldBitWidth: 14})
	if len(packed.Tapes) != len(indices) {
		t.Fatalf("packing discarded selective tapes")
	}
	if !verifier.VerifyEvalAtFormalHashV2(root, gamma, rRows, packed, indices) {
		t.Fatal("packed v2 opening rejected")
	}
}

func TestV2SaltTapeAndRoleChangeRoot(t *testing.T) {
	base := makeV2FormalProver(t)
	root := commitV2ForTest(t, base, v2TestContext(CommitmentRoleMain, 1), CommitOptions{})
	changedSalt := makeV2FormalProver(t)
	saltRoot := commitV2ForTest(t, changedSalt, v2TestContext(CommitmentRoleMain, 2), CommitOptions{})
	changedTape := makeV2FormalProver(t)
	changedTape.tapes[0] ^= 1
	tapeRoot := commitV2ForTest(t, changedTape, v2TestContext(CommitmentRoleMain, 1), CommitOptions{})
	changedRole := makeV2FormalProver(t)
	roleRoot := commitV2ForTest(t, changedRole, v2TestContext(CommitmentRoleQPayload, 1), CommitOptions{})
	if bytes.Equal(root, saltRoot) || bytes.Equal(root, tapeRoot) || bytes.Equal(root, roleRoot) {
		t.Fatal("v2 root did not bind salt, tape, and role independently")
	}
}

func TestV2ContextRequiresAndBindsExactTranscriptIdentity(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 0x33)
	if ctx.TranscriptVersion != "smallwood_2025_1085_salted_decs_v2" {
		t.Fatalf("unexpected exact transcript identity %q", ctx.TranscriptVersion)
	}
	bad := ctx
	bad.TranscriptVersion = "2"
	if err := bad.Validate(); err == nil {
		t.Fatal("numeric-only transcript identity was accepted")
	}
	tape := bytes.Repeat([]byte{7}, 16)
	goodHash := hashLeafV2With(sha3.NewShake256(), ctx, 9, 11, 12289, []uint64{1}, []uint64{2}, tape, 21)
	badHash := hashLeafV2With(sha3.NewShake256(), bad, 9, 11, 12289, []uint64{1}, []uint64{2}, tape, 21)
	if bytes.Equal(goodHash, badHash) {
		t.Fatal("leaf encoder did not bind the exact transcript identity")
	}
}

type failingEntropyReader struct{}

func (failingEntropyReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestV2TapeAllocationEntropyAndRelease(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 3)
	prover := makeV2FormalProver(t)
	prover.tapes = nil
	prover.entropy = failingEntropyReader{}
	if _, err := prover.CommitInitV2WithOptions(ctx, CommitOptions{}); err == nil {
		t.Fatal("accepted failing tape entropy source")
	}
	prover = makeV2FormalProver(t)
	prover.tapes = nil
	if _, err := prover.CommitInitV2WithOptions(ctx, CommitOptions{MaxTapeBufferBytes: len(prover.points)*prover.params.TapeBytes - 1}); err == nil {
		t.Fatal("ignored configured tape allocation limit")
	}
	prover = makeV2FormalProver(t)
	commitV2ForTest(t, prover, ctx, CommitOptions{})
	prover.ReleaseTapes()
	if _, err := prover.EvalOpenV2([]int{1}); err == nil {
		t.Fatal("opened after private tapes were released")
	}
}

func TestV2EvalOpenRejectsDuplicateAndInvalidIndices(t *testing.T) {
	prover := makeV2FormalProver(t)
	commitV2ForTest(t, prover, v2TestContext(CommitmentRoleMain, 4), CommitOptions{})
	for _, indices := range [][]int{nil, {1, 1}, {2, 1}, {-1}, {len(prover.points)}} {
		if _, err := prover.EvalOpenV2(indices); err == nil {
			t.Fatalf("accepted malformed indices %v", indices)
		}
	}
}

func TestV2TapeAllocationCapAndCheckedMultiplication(t *testing.T) {
	if DefaultMaxTapeBufferBytes != 64<<20 {
		t.Fatalf("default tape cap=%d want=%d", DefaultMaxTapeBufferBytes, 64<<20)
	}
	overCap := &Prover{
		params:  Params{TapeBytes: 16},
		nLeaves: DefaultMaxTapeBufferBytes/16 + 1,
	}
	if err := overCap.ensureV2Tapes(0); err == nil {
		t.Fatal("accepted tape buffer above the locked 64 MiB cap")
	}
	maxInt := int(^uint(0) >> 1)
	overflow := &Prover{
		params:  Params{TapeBytes: 16},
		nLeaves: maxInt/16 + 1,
	}
	if err := overflow.ensureV2Tapes(0); err == nil {
		t.Fatal("accepted overflowing tape buffer multiplication")
	}
}

type v2PhaseLabelRecorder struct{ labels []string }

func (r *v2PhaseLabelRecorder) RecordDuration(label string, _ time.Duration) {
	r.labels = append(r.labels, label)
}

func TestV2PhaseReportingNeverEmitsNonceDerivation(t *testing.T) {
	prover := makeV2FormalProver(t)
	recorder := &v2PhaseLabelRecorder{}
	commitV2ForTest(t, prover, v2TestContext(CommitmentRoleMain, 12), CommitOptions{
		PhaseRecorder:   recorder,
		RecordSubphases: true,
	})
	for _, label := range recorder.labels {
		if label == "decs.nonce_derivation_cpu" {
			t.Fatal("v2 phase reporting disclosed a legacy nonce-derivation phase")
		}
	}
}

func TestMergeOpeningsV2AlignsAndDeduplicatesTapes(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 5)
	prover := makeV2FormalProver(t)
	commitV2ForTest(t, prover, ctx, CommitOptions{})
	mask, err := prover.EvalOpenV2([]int{5, 6})
	if err != nil {
		t.Fatal(err)
	}
	tail, err := prover.EvalOpenV2([]int{6, 9})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeOpeningsV2(ctx, mask, tail)
	if err != nil {
		t.Fatalf("MergeOpeningsV2: %v", err)
	}
	if got, want := merged.AllIndices(), []int{5, 6, 9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("merged indices=%v want=%v", got, want)
	}
	if len(merged.Tapes) != 3 {
		t.Fatalf("merged tapes=%d want=3", len(merged.Tapes))
	}
	for i, idx := range merged.AllIndices() {
		if !bytes.Equal(merged.Tapes[i], prover.tapeAt(idx)) {
			t.Fatalf("merged tape %d not aligned to leaf %d", i, idx)
		}
	}
	conflict := cloneOpeningV2(tail)
	conflict.Tapes[0][0] ^= 1
	if _, err := MergeOpeningsV2(ctx, mask, conflict); err == nil {
		t.Fatal("merged conflicting tapes for the same leaf")
	}
}

func TestV2FullUint64LeafIndicesAndCanonicalMerklePositions(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 6)
	tape := bytes.Repeat([]byte{3}, 16)
	leaf65535, err := HashLeafV2(ctx, 65535, 7, 12289, []uint64{1}, []uint64{2}, tape, 16)
	if err != nil {
		t.Fatal(err)
	}
	leaf65536, err := HashLeafV2(ctx, 65536, 7, 12289, []uint64{1}, []uint64{2}, tape, 16)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(leaf65535, leaf65536) {
		t.Fatal("leaf hash truncated uint64 index at 16 bits")
	}
	leaves := make([][]byte, 65537)
	zeroLeaf := bytes.Repeat([]byte{0xa5}, 16)
	for i := range leaves {
		leaves[i] = zeroLeaf
	}
	leaves[65535] = leaf65535
	leaves[65536] = leaf65536
	tree, err := BuildMerkleTreeFromLeafHashBytesV2(ctx, leaves, 16)
	if err != nil {
		t.Fatal(err)
	}
	for _, idx := range []int{65535, 65536} {
		path := make([][]byte, len(tree.layers)-1)
		cur := idx
		for level := range path {
			path[level] = tree.layers[level][cur^1]
			cur >>= 1
		}
		if !VerifyPathHashV2(ctx, leaves[idx], path, tree.RootHash(), uint64(idx)) {
			t.Fatalf("v2 Merkle path rejected large index %d", idx)
		}
	}
}

func TestV2PackedIndicesPreserveUintBoundaries(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	indices := []int{65535, 65536, maxInt}
	open := &DECSOpening{Indices: append([]int(nil), indices...)}
	open.packTailIndicesFixed(strconv.IntSize - 1)
	if err := validateOpeningIndexEncodingV2(open); err != nil {
		t.Fatalf("validate packed boundary indices: %v", err)
	}
	if got := open.AllIndices(); !reflect.DeepEqual(got, indices) {
		t.Fatalf("packed boundary indices=%v want=%v", got, indices)
	}
}
