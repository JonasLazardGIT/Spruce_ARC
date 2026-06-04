package decs

import "testing"

func TestPackOpeningFixedTailIndicesAboveLegacyLimit(t *testing.T) {
	open := &DECSOpening{
		Indices: []int{8192, 90000, 230207},
		Pvals:   [][]uint64{{1}, {2}, {3}},
		Mvals:   [][]uint64{{4}, {5}, {6}},
		R:       1,
		Eta:     1,
	}
	PackOpeningWithOptions(open, OpeningPackOptions{
		FixedSize:     true,
		NLeaves:       230208,
		FieldBitWidth: 20,
	})
	if len(open.Indices) != 0 {
		t.Fatalf("fixed opening kept explicit indices: %v", open.Indices)
	}
	if open.IndexBitWidth != 18 {
		t.Fatalf("index width=%d want 18", open.IndexBitWidth)
	}
	if got := open.AllIndices(); len(got) != 3 || got[0] != 8192 || got[1] != 90000 || got[2] != 230207 {
		t.Fatalf("decoded indices=%v", got)
	}
	if open.PvalsBitWidth != 20 || open.MvalsBitWidth != 20 {
		t.Fatalf("residue widths=(%d,%d) want 20", open.PvalsBitWidth, open.MvalsBitWidth)
	}
}

func TestPackOpeningFixedRowMajorPathsVerify(t *testing.T) {
	pr := makeDeterministicFormalProver(t)
	root, err := pr.CommitInitWithOptions(CommitOptions{})
	if err != nil {
		t.Fatalf("commit init: %v", err)
	}
	gamma := DeriveGamma(root, pr.params.Eta, pr.rowCount(), pr.ringQ.Modulus[0])
	rFormal := pr.CommitStep2Formal(gamma)
	open := pr.EvalOpen([]int{3, 17, 42, 211})
	PackOpeningWithOptions(open, OpeningPackOptions{
		FixedSize:     true,
		NLeaves:       len(pr.points),
		FieldBitWidth: 20,
	})
	if open.PathDepth <= 0 {
		t.Fatalf("missing fixed path depth")
	}
	if len(open.PathIndex) != 0 || len(open.PathBits) != 0 {
		t.Fatalf("fixed opening kept compact path material")
	}
	if want := open.EntryCount() * open.PathDepth; len(open.Nodes) != want {
		t.Fatalf("row-major nodes=%d want %d", len(open.Nodes), want)
	}
	verifier, err := NewVerifierWithParamsAndPointsChecked(pr.ringQ, pr.rowCount(), pr.params, pr.points)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if !verifier.VerifyEvalAtFormal(root, gamma, rFormal, open, []int{3, 17, 42, 211}) {
		t.Fatalf("fixed row-major opening did not verify")
	}
	tampered := *open
	tampered.Nodes = make([][]byte, len(open.Nodes))
	for i := range open.Nodes {
		tampered.Nodes[i] = append([]byte(nil), open.Nodes[i]...)
	}
	tampered.Nodes[0][0] ^= 1
	if verifier.VerifyEvalAtFormal(root, gamma, rFormal, &tampered, []int{3, 17, 42, 211}) {
		t.Fatalf("tampered row-major path verified")
	}
}

func TestPackOpeningFixedAuthenticationShapeIsConstant(t *testing.T) {
	pr := makeDeterministicFormalProver(t)
	if _, err := pr.CommitInitWithOptions(CommitOptions{}); err != nil {
		t.Fatalf("commit init: %v", err)
	}
	openA := pr.EvalOpen([]int{1, 2, 3, 4})
	openB := pr.EvalOpen([]int{17, 63, 127, 255})
	opts := OpeningPackOptions{FixedSize: true, NLeaves: len(pr.points), FieldBitWidth: 20}
	PackOpeningWithOptions(openA, opts)
	PackOpeningWithOptions(openB, opts)
	if openA.IndexBitWidth != openB.IndexBitWidth || len(openA.IndexBits) != len(openB.IndexBits) {
		t.Fatalf("index shape A=(%d,%d) B=(%d,%d)", openA.IndexBitWidth, len(openA.IndexBits), openB.IndexBitWidth, len(openB.IndexBits))
	}
	if openA.PathDepth != openB.PathDepth || len(openA.Nodes) != len(openB.Nodes) {
		t.Fatalf("path shape A=(%d,%d) B=(%d,%d)", openA.PathDepth, len(openA.Nodes), openB.PathDepth, len(openB.Nodes))
	}
	if len(openA.PvalsBits) != len(openB.PvalsBits) || len(openA.MvalsBits) != len(openB.MvalsBits) {
		t.Fatalf("residue shape A=(%d,%d) B=(%d,%d)", len(openA.PvalsBits), len(openA.MvalsBits), len(openB.PvalsBits), len(openB.MvalsBits))
	}
}
