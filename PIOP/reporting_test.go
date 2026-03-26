package PIOP

import (
	"math"
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestBuildPaperTranscriptReportLeafUsesFormulaicRAndQ(t *testing.T) {
	base := &Proof{
		VTargetsBits: []byte{1, 2},
		BarSetsBits:  []byte{3},
		PCSOpening:   testOpening(),
	}
	hugeR := cloneProofForPaperTest(base)
	hugeR.R = make([][]uint64, 31)
	for i := range hugeR.R {
		hugeR.R[i] = make([]uint64, 64)
	}

	params := paperTranscriptParams{
		Lambda:   128,
		Eta:      31,
		Ell:      18,
		EllPrime: 2,
		Rho:      2,
		Theta:    6,
		DQ:       180,
		DDECS:    45,
	}
	rep1 := buildPaperTranscriptReportLeaf(base, 12289, params)
	rep2 := buildPaperTranscriptReportLeaf(hugeR, 12289, params)

	logQ := math.Log2(12289)
	wantRNaive := float64(31*(45+1)) * logQ
	wantROpt := float64(31*(45+1-18)) * logQ
	wantQNaive := float64(2*180*6) * logQ
	wantQOpt := float64(2*(180-(2+1))*6) * logQ

	if math.Abs(rep1.R.NaiveBits-wantRNaive) > 1e-9 {
		t.Fatalf("R naive bits=%v, want %v", rep1.R.NaiveBits, wantRNaive)
	}
	if math.Abs(rep1.R.OptimizedBits-wantROpt) > 1e-9 {
		t.Fatalf("R optimized bits=%v, want %v", rep1.R.OptimizedBits, wantROpt)
	}
	if math.Abs(rep1.Q.NaiveBits-wantQNaive) > 1e-9 {
		t.Fatalf("Q naive bits=%v, want %v", rep1.Q.NaiveBits, wantQNaive)
	}
	if math.Abs(rep1.Q.OptimizedBits-wantQOpt) > 1e-9 {
		t.Fatalf("Q optimized bits=%v, want %v", rep1.Q.OptimizedBits, wantQOpt)
	}
	if rep1.R != rep2.R {
		t.Fatalf("R bucket should not depend on full in-memory proof.R: %+v vs %+v", rep1.R, rep2.R)
	}
}

func TestBuildOpeningPaperReportCountsCompressedResiduesAuthAndTapes(t *testing.T) {
	open := &decs.DECSOpening{
		FormatVersion:  1,
		PColsEncoded:   2,
		POmitCols:      []int{1},
		MFormatVersion: 1,
		MColsEncoded:   1,
		MOmitCols:      []int{0},
		MaskBase:       4,
		MaskCount:      2,
		Indices:        []int{9, 11},
		PvalsBits:      []byte{0xAA, 0xBB},
		PvalsBitWidth:  14,
		Mvals:          [][]uint64{{1}, {2}},
		Eta:            1,
		Nodes:          [][]byte{{0, 1}, {2, 3, 4}},
		PathIndex:      [][]int{{1, 2}, {3, 4}},
		NonceSeed:      []byte{7, 8, 9},
		NonceBytes:     24,
	}

	got := BuildOpeningPaperReport(open)
	if got.PdecsBits != 48 {
		t.Fatalf("Pdecs bits=%v, want 48", got.PdecsBits)
	}
	if got.MdecsBits != 36 {
		t.Fatalf("Mdecs bits=%v, want 36", got.MdecsBits)
	}
	if got.AuthBits != 200 {
		t.Fatalf("auth bits=%v, want 200", got.AuthBits)
	}
	if got.TapeBits != 32 {
		t.Fatalf("tape bits=%v, want 32", got.TapeBits)
	}
}

func TestBuildOpeningPaperReportUnpackedUsesPackedFieldWidthNotUint64Limbs(t *testing.T) {
	open := &decs.DECSOpening{
		Pvals: [][]uint64{
			{1, 2},
			{3, 4},
		},
		R: 2,
	}
	got := BuildOpeningPaperReport(open)
	if got.PdecsBits != 20 {
		t.Fatalf("Pdecs bits=%v, want 20", got.PdecsBits)
	}
	if got.PdecsBits >= float64(2*2*64) {
		t.Fatalf("Pdecs bits=%v still looks like uint64-matrix accounting", got.PdecsBits)
	}
}

func TestBuildPaperTranscriptReportSplitSumsChildren(t *testing.T) {
	ringQ, err := ring.NewRing(2048, []uint64{12289})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	opts := SimOpts{
		NCols:     16,
		LVCSNCols: 28,
		Ell:       18,
		EllPrime:  2,
		Rho:       2,
		Theta:     6,
		Eta:       31,
		Lambda:    128,
	}
	child1 := &Proof{
		QDegreeBound: 180,
		VTargetsBits: []byte{1},
		BarSetsBits:  []byte{2},
		PCSOpening:   testOpening(),
	}
	child2 := &Proof{
		QDegreeBound: 222,
		VTargetsBits: []byte{3, 4},
		BarSetsBits:  []byte{5},
		PCSOpening:   testOpening(),
	}
	split := &Proof{
		ShowingSplit: &ShowingSplitProof{
			PostSign: &ShowingProofSlice{Name: "post_sign", Proof: child1},
			PRF:      &ShowingProofSlice{Name: "prf", Proof: child2},
		},
	}
	postOpts, prfOpts := resolveShowingSplitSliceOpts(opts)
	rep1, err := BuildPaperTranscriptReport(child1, postOpts, ringQ)
	if err != nil {
		t.Fatalf("post-sign child paper report: %v", err)
	}
	rep2, err := BuildPaperTranscriptReport(child2, prfOpts, ringQ)
	if err != nil {
		t.Fatalf("prf child paper report: %v", err)
	}
	splitRep, err := BuildPaperTranscriptReport(split, opts, ringQ)
	if err != nil {
		t.Fatalf("split paper report: %v", err)
	}
	if math.Abs(splitRep.OptimizedBits-(rep1.OptimizedBits+rep2.OptimizedBits)) > 1e-9 {
		t.Fatalf("split optimized bits=%v, want %v", splitRep.OptimizedBits, rep1.OptimizedBits+rep2.OptimizedBits)
	}
	if math.Abs(splitRep.NaiveBits-(rep1.NaiveBits+rep2.NaiveBits)) > 1e-9 {
		t.Fatalf("split naive bits=%v, want %v", splitRep.NaiveBits, rep1.NaiveBits+rep2.NaiveBits)
	}
}

func TestMeasureProofSizeUnaffectedByPaperTranscriptReport(t *testing.T) {
	ringQ, err := ring.NewRing(2048, []uint64{12289})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	opts := SimOpts{
		NCols:     16,
		LVCSNCols: 28,
		Ell:       18,
		EllPrime:  2,
		Rho:       2,
		Theta:     6,
		Eta:       31,
		Lambda:    128,
	}
	proof := &Proof{
		QDegreeBound: 180,
		VTargetsBits: []byte{7, 8},
		BarSetsBits:  []byte{9},
		PCSOpening:   testOpening(),
		QOpening:     testOpening(),
	}
	before := MeasureProofSize(proof)
	if _, err := BuildPaperTranscriptReport(proof, opts, ringQ); err != nil {
		t.Fatalf("paper report: %v", err)
	}
	after := MeasureProofSize(proof)
	if before.Total != after.Total {
		t.Fatalf("MeasureProofSize changed after paper transcript report: before=%d after=%d", before.Total, after.Total)
	}
}

func TestAggregateSplitSoundnessUsesChildCollisionAndTheoremTerms(t *testing.T) {
	split := SplitProofReport{
		PostSign: &ProofReport{
			DQ: 111,
			Soundness: SoundnessBudget{
				Collision:          0.01,
				TheoremTerms:       [4]float64{0.02, 0.03, 0, 0},
				Eps:                [4]float64{0.10, 0.20, 0, 0},
				DDECS:              12,
				CommittedCols:      16,
				WitnessSupportCols: 16,
				CollisionSpaceBits: 128,
				NRows:              10,
				M:                  4,
			},
		},
		PRF: &ProofReport{
			DQ: 222,
			Soundness: SoundnessBudget{
				Collision:          0.02,
				TheoremTerms:       [4]float64{0.04, 0, 0.05, 0},
				Eps:                [4]float64{0.01, 0, 0.02, 0},
				DDECS:              20,
				CommittedCols:      28,
				WitnessSupportCols: 12,
				CollisionSpaceBits: 120,
				NRows:              7,
				M:                  2,
			},
		},
	}

	got := aggregateSplitSoundness(SimOpts{}, split)
	if got.Collision != 0.03 {
		t.Fatalf("collision=%v, want 0.03", got.Collision)
	}
	if got.TheoremTerms != [4]float64{0.06, 0.03, 0.05, 0} {
		t.Fatalf("theorem terms=%v", got.TheoremTerms)
	}
	if math.Abs(got.Total-0.17) > 1e-12 {
		t.Fatalf("total=%v, want 0.17", got.Total)
	}
	if got.DQ != 222 || got.DDECS != 20 || got.CommittedCols != 28 || got.NRows != 17 || got.M != 6 {
		t.Fatalf("aggregate geometry mismatch: %+v", got)
	}
}

func TestDeriveGrindingReportForSplitGreedyAndImpossible(t *testing.T) {
	split := SplitProofReport{
		PostSign: &ProofReport{
			Soundness: SoundnessBudget{
				Collision: 0,
				Eps:       [4]float64{0.25, 0.125, 0, 0},
				QueryCaps: [5]int{0, 1, 1, 0, 0},
			},
		},
	}
	got := deriveGrindingReportForSplit(split, 4)
	if !got.Achievable {
		t.Fatalf("expected achievable derived grinding")
	}
	if got.DerivedKappa != [4]int{3, 2, 0, 0} {
		t.Fatalf("derived kappa=%v, want [3 2 0 0]", got.DerivedKappa)
	}
	if got.DerivedTotal > math.Pow(2, -4) {
		t.Fatalf("derived total=%v exceeds target", got.DerivedTotal)
	}

	impossible := deriveGrindingReportForSplit(SplitProofReport{
		PostSign: &ProofReport{
			Soundness: SoundnessBudget{Collision: 0.2},
		},
	}, 4)
	if impossible.Achievable {
		t.Fatalf("expected impossible derived grinding report")
	}
}

func cloneProofForPaperTest(src *Proof) *Proof {
	if src == nil {
		return nil
	}
	dst := *src
	if len(src.VTargetsBits) > 0 {
		dst.VTargetsBits = append([]byte(nil), src.VTargetsBits...)
	}
	if len(src.BarSetsBits) > 0 {
		dst.BarSetsBits = append([]byte(nil), src.BarSetsBits...)
	}
	return &dst
}

func testOpening() *decs.DECSOpening {
	return &decs.DECSOpening{
		PvalsBits:     []byte{1, 2},
		MvalsBits:     []byte{3},
		PvalsBitWidth: 14,
		MvalsBitWidth: 14,
		R:             1,
		Eta:           1,
		NonceSeed:     []byte{4, 5},
	}
}
