package PIOP

import (
	"bytes"
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

func TestPaperTranscriptReportIncludesRingDegree(t *testing.T) {
	ringQ, err := ring.NewRing(1024, []uint64{12289})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	proof := &Proof{
		RingDegree:   1024,
		RowLayout:    RowLayout{X0Len: 70},
		QDegreeBound: 12,
		VTargetsBits: []byte{1},
		BarSetsBits:  []byte{2},
		PCSOpening:   testOpening(),
		QOpening:     testOpening(),
	}
	rep, err := BuildPaperTranscriptReport(proof, SimOpts{
		RingDegree: 1024,
		NCols:      16,
		LVCSNCols:  16,
		Ell:        1,
		EllPrime:   1,
		Rho:        1,
		Theta:      1,
		Eta:        1,
		Lambda:     128,
	}, ringQ)
	if err != nil {
		t.Fatalf("paper transcript report: %v", err)
	}
	if rep.RingDegree != 1024 {
		t.Fatalf("paper transcript ring_degree=%d want 1024", rep.RingDegree)
	}
	if rep.X0Len != 70 {
		t.Fatalf("paper transcript x0_len=%d want 70", rep.X0Len)
	}
}

func TestStrictSmallWoodProofSizeExcludesLegacyQDECS(t *testing.T) {
	proof := &Proof{
		TranscriptVersion: TranscriptVersionSmallWood2025,
		R:                 [][]uint64{{1, 2, 3}, {4, 5, 6}},
		QRoot:             [16]byte{1},
		QRBits:            []byte{1, 2, 3},
		QPayloadBits:      []byte{4, 5},
		VTargetsBits:      []byte{6},
		BarSetsBits:       []byte{7},
		PCSOpening:        testOpening(),
		QOpening:          testOpening(),
	}
	parts, total := proofSizeBreakdown(proof)
	if total == 0 {
		t.Fatal("strict proof size unexpectedly zero")
	}
	if parts["QRoot"] != 0 || parts["QR"] != 0 || parts["QOpening"] != 0 {
		t.Fatalf("strict proof counted legacy Q DECS components: QRoot=%d QR=%d QOpening=%d", parts["QRoot"], parts["QR"], parts["QOpening"])
	}
	if parts["QPayload"] != len(proof.QPayloadBits) {
		t.Fatalf("strict proof QPayload bytes=%d want %d", parts["QPayload"], len(proof.QPayloadBits))
	}
	if parts["R"] != sizePackedUintMatrix(proof.R) {
		t.Fatalf("strict proof R bytes=%d want %d", parts["R"], sizePackedUintMatrix(proof.R))
	}
	audit, err := BuildProofPackingAudit(proof, 12289)
	if err != nil {
		t.Fatalf("packing audit: %v", err)
	}
	if audit.QR.Bytes != 0 || audit.QOpening.TotalBytes != 0 {
		t.Fatalf("strict packing audit counted legacy Q DECS components: QR=%d QOpening=%d", audit.QR.Bytes, audit.QOpening.TotalBytes)
	}
}

func TestSigShortnessV18LayoutDigestBindsRingDegree(t *testing.T) {
	layout := RowLayout{
		RingDegree: 1024,
		CoeffNativeSig: CoeffNativeSigLayout{
			PackedSigComponents: 2,
			PackedSigBlocks:     64,
			PackedSigBlockWidth: 16,
		},
		PackedSigChainBase:             10,
		PackedSigChainGroupCount:       128,
		PackedSigChainGroupSize:        1,
		PackedSigChainRowsPerGroup:     4,
		PackedSigChainBlockWidth:       16,
		PackedSigChainEffectiveBlocks:  64,
		PackedSigChainSourceBlockWidth: 16,
		ReplayBlockCount:               64,
		IdxM1:                          1,
		IdxM2:                          2,
		IdxCarrierM:                    3,
		IdxCarrierR1:                   4,
		IdxRHat1:                       5,
		IdxZHat:                        6,
	}
	digest1024 := buildSigShortnessV18LayoutDigest(layout)
	layout.RingDegree = 512
	digest512 := buildSigShortnessV18LayoutDigest(layout)
	if bytes.Equal(digest1024, digest512) {
		t.Fatal("V18 layout digest did not change when ring degree changed")
	}
}

func TestSigShortnessV18LayoutDigestBindsX0Len(t *testing.T) {
	layout := RowLayout{
		RingDegree: 1024,
		X0Len:      70,
		CoeffNativeSig: CoeffNativeSigLayout{
			PackedSigComponents: 2,
			PackedSigBlocks:     64,
			PackedSigBlockWidth: 16,
		},
		PackedSigChainBase:             10,
		PackedSigChainGroupCount:       128,
		PackedSigChainGroupSize:        1,
		PackedSigChainRowsPerGroup:     4,
		PackedSigChainBlockWidth:       16,
		PackedSigChainEffectiveBlocks:  64,
		PackedSigChainSourceBlockWidth: 16,
		ReplayBlockCount:               64,
		IdxM1:                          1,
		IdxM2:                          2,
		IdxCarrierM:                    3,
		IdxCarrierR1:                   4,
		IdxRHat1:                       5,
		IdxZHat:                        6,
	}
	digest70 := buildSigShortnessV18LayoutDigest(layout)
	layout.X0Len = 6
	digest6 := buildSigShortnessV18LayoutDigest(layout)
	if bytes.Equal(digest70, digest6) {
		t.Fatal("V18 layout digest did not change when x0_len changed")
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

func TestResolveShowingStatementClassDistinguishesReducedAndDirectFull(t *testing.T) {
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
			X0Len:              2,
			IdxTHatBase:        3,
			ReplayTHatRows:     []int{3, 4, 5},
			IdxMHatSigma:       6,
			ReplayMHatSigmaRows: []int{
				6, 7, 8,
			},
			IdxRHat0: 9,
			ReplayRHat0Rows: []int{
				9, 10,
				11, 12,
				13, 14,
			},
			IdxRHat1:         15,
			ReplayRHat1Rows:  []int{15, 16, 17},
			IdxZHat:          18,
			ReplayZHatRows:   []int{18, 19, 20},
			ReplayTHatCount:  3,
			ReplayBlockCount: 3,
			SigBlocks:        3,
		},
	}, SimOpts{ShowingReplayMode: ShowingReplayModeFull})
	if full != string(ShowingStatementClassTheoremCleanFullReplay) {
		t.Fatalf("full statement class=%q want %q", full, ShowingStatementClassTheoremCleanFullReplay)
	}
	incomplete := ResolveShowingStatementClass(&Proof{
		RowLayout: RowLayout{
			HasExplicitBaseIdx: true,
			X0Len:              2,
			IdxTHatBase:        3,
			ReplayTHatRows:     []int{3, 4, 5},
			IdxMHatSigma:       6,
			ReplayMHatSigmaRows: []int{
				6, 7, 8,
			},
			IdxRHat0: 9,
			ReplayRHat0Rows: []int{
				9, 10,
				11, 12,
				13, 14,
			},
			IdxRHat1:         15,
			ReplayRHat1Rows:  []int{15, 16, 17},
			IdxZHat:          -1,
			ReplayTHatCount:  3,
			ReplayBlockCount: 3,
			SigBlocks:        3,
		},
	}, SimOpts{ShowingReplayMode: ShowingReplayModeFull})
	if incomplete != string(ShowingStatementClassCustom) {
		t.Fatalf("incomplete full statement class=%q want %q", incomplete, ShowingStatementClassCustom)
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

func TestResolveSigShortnessModeUsesReplayCompactV18Label(t *testing.T) {
	got := ResolveSigShortnessMode(&Proof{
		SigShortness: &SigShortnessProof{
			Version: sigShortnessProofVersionV18,
			V18:     &SigShortnessProofV18{},
		},
	})
	if got != SigShortnessModeReplayCompactV18 {
		t.Fatalf("sig shortness mode=%q want %q", got, SigShortnessModeReplayCompactV18)
	}
}

func TestInlineTargetReplayCompactPresetDefaultsToCanonicalW84Tuple(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:           true,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        ShowingPresetInlineTargetReplayCompactResearch,
		PRFCompanionMode:     PRFCompanionModeDirectFull,
		PRFCheckpointSamples: 8,
	})
	if opts.ShowingReplayMode != ShowingReplayModeFull {
		t.Fatalf("inline-target replay mode=%q want full", opts.ShowingReplayMode)
	}
	if !opts.AggregateR0Replay {
		t.Fatalf("inline-target preset did not enable aggregate replay")
	}
	if opts.NCols != aggregateInlineTargetReplayCompactNCols {
		t.Fatalf("inline-target ncols=%d want %d", opts.NCols, aggregateInlineTargetReplayCompactNCols)
	}
	if opts.PackedSigChainGroupSize != aggregateInlineTargetReplayCompactGroupSize {
		t.Fatalf("inline-target group size=%d want %d", opts.PackedSigChainGroupSize, aggregateInlineTargetReplayCompactGroupSize)
	}
	if opts.MuWitnessPackWidth != 2 {
		t.Fatalf("inline-target mu witness pack width=%d want 2", opts.MuWitnessPackWidth)
	}
	if opts.SigShortnessProfile != aggregateInlineTargetReplayCompactSigProfile {
		t.Fatalf("inline-target sig profile=%q want %q", opts.SigShortnessProfile, aggregateInlineTargetReplayCompactSigProfile)
	}
	if opts.LVCSNCols != aggregateInlineTargetReplayCompactLVCSNCols || opts.PostSignLVCSNCols != aggregateInlineTargetReplayCompactLVCSNCols || opts.PRFLVCSNCols != aggregateInlineTargetReplayCompactLVCSNCols {
		t.Fatalf("inline-target LVCS tuple=(%d,%d,%d) want %d", opts.LVCSNCols, opts.PostSignLVCSNCols, opts.PRFLVCSNCols, aggregateInlineTargetReplayCompactLVCSNCols)
	}
	if opts.Ell != aggregateInlineTargetReplayCompactEll || opts.Eta != aggregateInlineTargetReplayCompactEta || opts.EllPrime != aggregateInlineTargetReplayCompactEllPrime || opts.Theta != aggregateInlineTargetReplayCompactTheta || opts.Rho != aggregateInlineTargetReplayCompactRho {
		t.Fatalf("inline-target params ell=%d eta=%d ell'=%d theta=%d rho=%d", opts.Ell, opts.Eta, opts.EllPrime, opts.Theta, opts.Rho)
	}
	if opts.Kappa != aggregateInlineTargetReplayCompactKappa {
		t.Fatalf("inline-target kappa=%v want %v", opts.Kappa, aggregateInlineTargetReplayCompactKappa)
	}
	if !sigShortnessV18EnabledForOpts(opts) {
		t.Fatalf("inline-target preset did not enable V18 shortness")
	}
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetInlineTargetReplayCompactResearch {
		t.Fatalf("inline-target resolved preset=%q want %q", got, ShowingPresetInlineTargetReplayCompactResearch)
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
