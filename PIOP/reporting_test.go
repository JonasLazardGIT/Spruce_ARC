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

func TestResolveShowingStatementClassDistinguishesReducedAndTheoremCleanFull(t *testing.T) {
	reduced := ResolveShowingStatementClass(&Proof{
		RowLayout: RowLayout{
			IdxTHatBase:      4,
			ReplayTHatCount:  1,
			ReplayBlockCount: 1,
			SigBlocks:        3,
		},
	}, SimOpts{ShowingReplayMode: ShowingReplayModeReduced})
	if reduced != string(ShowingStatementClassReducedEngineeringReplay) {
		t.Fatalf("reduced statement class=%q want %q", reduced, ShowingStatementClassReducedEngineeringReplay)
	}
	full := ResolveShowingStatementClass(&Proof{
		RowLayout: RowLayout{
			HasExplicitBaseIdx: true,
			IdxTHatBase:        3,
			IdxMHatSigma:       6,
			IdxRHat0:           9,
			IdxRHat1:           12,
			IdxMSigmaR1Hat:     15,
			IdxR0R1Hat:         18,
			ReplayTHatCount:    3,
			ReplayBlockCount:   3,
			SigBlocks:          3,
		},
	}, SimOpts{ShowingReplayMode: ShowingReplayModeFull})
	if full != string(ShowingStatementClassTheoremCleanFullReplay) {
		t.Fatalf("full statement class=%q want %q", full, ShowingStatementClassTheoremCleanFullReplay)
	}
}

func TestResolveSigShortnessModeUsesHiddenV6Label(t *testing.T) {
	got := ResolveSigShortnessMode(&Proof{
		SigShortness: &SigShortnessProof{
			Version: sigShortnessProofVersionV6,
			V6:      &SigShortnessProofV6{},
		},
	})
	if got != SigShortnessModeHiddenV6 {
		t.Fatalf("sig shortness mode=%q want %q", got, SigShortnessModeHiddenV6)
	}
}

func TestResolveSigShortnessModeUsesHiddenV7Label(t *testing.T) {
	got := ResolveSigShortnessMode(&Proof{
		SigShortness: &SigShortnessProof{
			Version: sigShortnessProofVersionV7,
			V7:      &SigShortnessProofV7{},
		},
	})
	if got != SigShortnessModeHiddenV7 {
		t.Fatalf("sig shortness mode=%q want %q", got, SigShortnessModeHiddenV7)
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
