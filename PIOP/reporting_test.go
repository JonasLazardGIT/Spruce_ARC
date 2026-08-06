package PIOP

import (
	"bytes"
	"math"
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestPaperTranscriptReportLeafUsesFormulaicRAndQ(t *testing.T) {
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

func TestProofReportPreservesStructuralV3AndPublicationV4Status(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		protocol string
		want     string
	}{
		{"v3-unchanged", TranscriptVersionSmallWood2025V3, TranscriptProtocolSmallField2025V3, SmallField2025StatusLiveV3},
		{"v4-exact", TranscriptVersionSmallWood2025V4, TranscriptProtocolSmallField2025V4, SmallField2025StatusLiveV4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof := v2AccountingProofForTest()
			proof.SchemaVersion = ProofSchemaVersionV3
			proof.TranscriptVersion = tc.version
			proof.TranscriptProtocolMode = tc.protocol
			proof.SmallField2025.Mode = tc.protocol
			proof.SmallField2025.TranscriptOmission = &SmallField2025TranscriptOmission{
				Version:                      smallField2025TranscriptOmissionVersionV3,
				Mode:                         SmallField2025TranscriptOmissionModeCanonicalV3,
				OmitPdecsReconstructibleCols: true,
				AuthMultiproofCompact:        true,
			}
			focus := buildTranscriptOptimizationReport(
				proof,
				PaperTranscriptReport{},
				ProofPackingAudit{},
				SoundnessBudget{},
				WitnessGeometrySnapshot{},
				proof.PCSNColsUsed,
				proof.QDegreeBound,
				SimOpts{},
				12289,
			)
			if !focus.ZeroKnowledgeEligible || focus.TranscriptSecurityStatus != tc.want || focus.SmallField2025Status != tc.want {
				t.Fatalf("report status/metadata=%q/%q eligible=%v want %q", focus.TranscriptSecurityStatus, focus.SmallField2025Status, focus.ZeroKnowledgeEligible, tc.want)
			}
		})
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
	report, err := BuildProofReport(proof, SimOpts{
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
	rep := report.PaperTranscript
	if rep.RingDegree != 1024 {
		t.Fatalf("paper transcript ring_degree=%d want 1024", rep.RingDegree)
	}
	if rep.X0Len != 70 {
		t.Fatalf("paper transcript x0_len=%d want 70", rep.X0Len)
	}
}

func TestPaperTranscriptReportOptimizedTotalSumsAllBuckets(t *testing.T) {
	rep := buildPaperTranscriptReportLeaf(&Proof{
		VTargetsBits: []byte{1, 2},
		BarSetsBits:  []byte{3},
		PCSOpening:   testOpening(),
	}, 12289, paperTranscriptParams{
		Lambda:   128,
		Eta:      3,
		Ell:      1,
		EllPrime: 1,
		Rho:      1,
		Theta:    1,
		DQ:       8,
		DDECS:    4,
	})
	if rep.Mdecs.OptimizedBytes == 0 {
		t.Fatal("test fixture should exercise the Mdecs bucket")
	}
	wantBits := rep.Counters.OptimizedBits +
		rep.SaltRoot.OptimizedBits +
		rep.ExtraHash.OptimizedBits +
		rep.R.OptimizedBits +
		rep.Q.OptimizedBits +
		rep.SigShortness.OptimizedBits +
		rep.VTargets.OptimizedBits +
		rep.BarSets.OptimizedBits +
		rep.Pdecs.OptimizedBits +
		rep.Mdecs.OptimizedBits +
		rep.Auth.OptimizedBits +
		rep.Tapes.OptimizedBits
	if math.Abs(rep.OptimizedBits-wantBits) > 1e-9 {
		t.Fatalf("optimized bits=%v want bucket sum %v", rep.OptimizedBits, wantBits)
	}
	if rep.OptimizedBytes != bitsToBytes(wantBits) {
		t.Fatalf("optimized bytes=%d want rounded bucket sum %d", rep.OptimizedBytes, bitsToBytes(wantBits))
	}
}

func TestStrictV3PaperAccountingExactTargetComponents(t *testing.T) {
	type targetCase struct {
		name                                              string
		L, ell, theta, eta, dQ, nLeaves                   int
		saltBits, hashBits, tapeBits                      int
		logicalRows, layers, queries, nRows, pCols        int
		wantTotal, wantFixed, wantR, wantQ, wantP         int
		wantAuth, wantTapes, wantV, wantBar, wantPosFrame int
	}
	cases := []targetCase{
		{"WF128/issuance", 42, 9, 7, 43, 391, 327680, 256, 264, 128, 165, 4, 35, 233, 198, 27575, 648, 5471, 6828, 4455, 5643, 144, 3588, 798, 25},
		{"WF128/showing", 42, 9, 7, 43, 471, 327680, 256, 264, 128, 423, 11, 84, 520, 436, 39944, 648, 5471, 8225, 9810, 5643, 144, 8103, 1900, 25},
		{"WF128/showing-L41", 41, 9, 7, 43, 471, 327680, 256, 264, 128, 423, 11, 84, 520, 436, 39837, 648, 5364, 8225, 9810, 5643, 144, 8103, 1900, 25},
		{"BQ128/issuance", 43, 18, 13, 59, 472, 688128, 200, 392, 264, 165, 4, 65, 336, 271, 65091, 680, 8979, 15308, 12195, 17640, 594, 6760, 2935, 48},
		{"BQ128/showing", 43, 18, 13, 59, 570, 688128, 200, 392, 264, 423, 10, 143, 645, 502, 90494, 680, 8979, 18486, 22590, 17640, 594, 15080, 6445, 48},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mu := ceilDiv(tc.dQ, tc.L)
			maskRows := (mu + 1) * tc.theta
			replayRows := tc.layers * (32 + tc.theta)
			if got := ceilDiv(tc.logicalRows, tc.L); got != tc.layers {
				t.Fatalf("witness layers=%d want %d", got, tc.layers)
			}
			if got := (tc.layers + 1) * tc.theta; got != tc.queries {
				t.Fatalf("query rows=%d want %d", got, tc.queries)
			}
			if got := replayRows + maskRows; got != tc.nRows {
				t.Fatalf("opening rows=%d want %d (replay=%d mask=%d)", got, tc.nRows, replayRows, maskRows)
			}
			if got := tc.nRows - tc.queries; got != tc.pCols {
				t.Fatalf("P columns=%d want %d", got, tc.pCols)
			}

			omission := &SmallField2025TranscriptOmission{
				Version:                      smallField2025TranscriptOmissionVersionV3,
				Mode:                         SmallField2025TranscriptOmissionModeCanonicalV3,
				OmitPdecsReconstructibleCols: true,
				AuthMultiproofCompact:        true,
			}
			meta := &SmallField2025LVCSProof{
				Version:            smallField2025LVCSProofVersionV2,
				Mode:               TranscriptProtocolSmallField2025V3,
				Status:             SmallField2025StatusLive,
				ReductionEnabled:   true,
				HeadDomainMode:     SmallField2025HeadDomainV2,
				NRows:              tc.nRows,
				NCols:              tc.L,
				Theta:              tc.theta,
				WitnessLayers:      tc.layers,
				MaskRows:           tc.ell,
				QueryCount:         tc.queries,
				VHeadRows:          tc.queries,
				VHeadCols:          tc.L,
				VBarRows:           tc.queries,
				VBarCols:           tc.ell,
				MatrixDigest:       make([]byte, 32),
				PayloadDigest:      make([]byte, 32),
				TranscriptOmission: omission,
			}
			if got := len(smallField2025TranscriptBytes(meta)); got != 476 {
				t.Fatalf("strict-v3 fixed metadata bytes=%d want 476", got)
			}
			proof := &Proof{
				TranscriptVersion: TranscriptVersionSmallWood2025V3,
				SmallField2025:    meta,
				NLeavesUsed:       tc.nLeaves,
				RowLayout:         RowLayout{SigCount: tc.logicalRows},
				PCSGeometry: PCSGeometry{
					LogicalWitnessPolys: tc.logicalRows,
				},
				PCSOpening: &decs.DECSOpening{
					PColsEncoded: tc.pCols,
					R:            tc.nRows,
				},
			}
			proof.setVTargets(makeUint64Matrix(tc.queries, tc.L))
			proof.setBarSets(makeUint64Matrix(tc.queries, tc.ell))
			report := buildPaperTranscriptReportLeaf(proof, 1017857, paperTranscriptParams{
				Lambda: 256, SaltBits: tc.saltBits, DECSHashBits: tc.hashBits, DECSTapeBits: tc.tapeBits,
				Eta: tc.eta, Ell: tc.ell, EllPrime: 1, Rho: 1, Theta: tc.theta,
				DQ: tc.dQ, DDECS: tc.L + tc.ell - 1,
			})
			logQ := math.Log2(1017857)
			wantRBits := float64(tc.eta*(tc.L+tc.ell)) * logQ
			wantQNaiveBits := float64((tc.dQ+1)*tc.theta) * logQ
			wantQOptimizedBits := float64(tc.dQ*tc.theta) * logQ
			if math.Abs(report.R.NaiveBits-wantRBits) > 1e-9 || math.Abs(report.R.OptimizedBits-wantRBits) > 1e-9 ||
				math.Abs(report.Q.NaiveBits-wantQNaiveBits) > 1e-9 || math.Abs(report.Q.OptimizedBits-wantQOptimizedBits) > 1e-9 {
				t.Fatalf("strict-v3 R/Q formulas mismatch: R=%+v Q=%+v", report.R, report.Q)
			}
			fixed := report.Audit.FixedV3
			if fixed.CounterBytes != 16 || fixed.SaltBytes != (tc.saltBits+7)/8 || fixed.RootBytes != (tc.hashBits+7)/8 ||
				fixed.RoundDigestBytes != 64 || fixed.SmallFieldMetadataBytes != 476 ||
				fixed.DECSOpeningFrameBytes != tc.wantPosFrame || fixed.EmptyMOpeningFrameBytes != 1 ||
				fixed.TapeWidthFrameBytes != 1 || fixed.TotalBytes != tc.wantFixed {
				t.Fatalf("fixed paper frame mismatch: %+v", fixed)
			}
			if report.OptimizedBytes != tc.wantTotal || report.R.OptimizedBytes != tc.wantR || report.Q.OptimizedBytes != tc.wantQ ||
				report.Pdecs.OptimizedBytes != tc.wantP || report.Mdecs.OptimizedBytes != 0 ||
				report.Auth.OptimizedBytes != tc.wantAuth || report.Tapes.OptimizedBytes != tc.wantTapes ||
				report.VTargets.OptimizedBytes != tc.wantV || report.BarSets.OptimizedBytes != tc.wantBar {
				t.Fatalf("strict-v3 paper components mismatch: %+v", report)
			}
			shape, err := deriveSmallFieldMaskShapeV3(tc.dQ, tc.L, tc.theta)
			if err != nil {
				t.Fatal(err)
			}
			_, wantVElements, err := deriveCanonicalVTargetRowWidthsV3(tc.logicalRows, tc.layers, tc.L, tc.theta, shape.Nu)
			if err != nil {
				t.Fatal(err)
			}
			wantDenseVBytes := bitsToBytes(float64(tc.queries * tc.L * canonicalFqBitWidth))
			if report.VTargets.OptimizedBits != float64(wantVElements*canonicalFqBitWidth) ||
				report.Audit.VTargets.Bytes != tc.wantV || report.Audit.VTargets.OmissionMapBytes != 0 ||
				report.Audit.VTargets.ReconstructedBytesSaved != wantDenseVBytes-tc.wantV {
				t.Fatalf("strict-v3 trusted ragged VTargets mismatch: bucket=%+v audit=%+v", report.VTargets, report.Audit.VTargets)
			}
		})
	}
}

func TestStrictV3PaperAccountingFailsClosedWithoutTrustedGeometry(t *testing.T) {
	base := &Proof{
		TranscriptVersion: TranscriptVersionSmallWood2025V3,
		NLeavesUsed:       327680,
		SmallField2025: &SmallField2025LVCSProof{
			QueryCount: 35,
		},
	}
	params := paperTranscriptParams{
		Lambda: 256, SaltBits: 256, DECSHashBits: 264, DECSTapeBits: 128,
		Eta: 43, Ell: 9, EllPrime: 1, Rho: 1, Theta: 7, DQ: 391, DDECS: 50,
	}

	if got := buildPaperTranscriptReportLeaf(base, 1017857, params); got.OptimizedBytes != 0 || got.R.OptimizedBits != 0 || got.Q.OptimizedBits != 0 {
		t.Fatalf("strict-v3 report with no authoritative opening did not fail closed: %+v", got)
	}

	withOpening := cloneProofForPaperTest(base)
	withOpening.PCSOpening = &decs.DECSOpening{R: 233, PColsEncoded: 198}
	badDegree := params
	badDegree.DQ = 0
	if got := buildPaperTranscriptReportLeaf(withOpening, 1017857, badDegree); got.OptimizedBytes != 0 || got.R.OptimizedBits != 0 || got.Q.OptimizedBits != 0 {
		t.Fatalf("strict-v3 report with invalid Q degree did not fail closed: %+v", got)
	}
}

func makeUint64Matrix(rows, cols int) [][]uint64 {
	out := make([][]uint64, rows)
	for i := range out {
		out[i] = make([]uint64, cols)
	}
	return out
}

func TestStrictSmallWoodProofSizeExcludesLegacyQDECS(t *testing.T) {
	proof := &Proof{
		TranscriptVersion: TranscriptVersionSmallWood2025V2,
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
		Version:        decs.OpeningVersionV2,
		Role:           decs.CommitmentRoleMain,
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
		Tapes: [][]byte{
			bytes.Repeat([]byte{7}, 16),
			bytes.Repeat([]byte{8}, 16),
			bytes.Repeat([]byte{9}, 16),
			bytes.Repeat([]byte{10}, 16),
		},
		TapeBytes: 16,
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
	if got.TapeBits != 520 {
		t.Fatalf("tape bits=%v, want 520", got.TapeBits)
	}
	if got.Audit.Pdecs.MetadataBytes != 3 || got.Audit.Pdecs.StreamBytes != 3 || got.Audit.Pdecs.EncodedCols != 2 {
		t.Fatalf("unexpected Pdecs audit: %+v", got.Audit.Pdecs)
	}
	if got.Audit.Mdecs.MetadataBytes != 3 || got.Audit.Mdecs.StreamBytes != 2 || got.Audit.Mdecs.BitWidth != 2 {
		t.Fatalf("unexpected Mdecs audit: %+v", got.Audit.Mdecs)
	}
	if got.Audit.Auth.NodeCount != 2 || got.Audit.Auth.NodeBytes != 5 || got.Audit.Auth.PathIndexBytes != 16 || got.Audit.Auth.TotalBytes != 25 {
		t.Fatalf("unexpected auth audit: %+v", got.Audit.Auth)
	}
	if got.Audit.Tapes.TapeBytes != 64 || got.Audit.Tapes.TapeCount != 4 || got.Audit.Tapes.TapeMetadataBytes != 1 || got.Audit.Tapes.TotalBytes != 65 {
		t.Fatalf("unexpected tape audit: %+v", got.Audit.Tapes)
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

func TestEstimateVerifierMessageSizeUnaffectedByPaperTranscriptReport(t *testing.T) {
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
	before := EstimateVerifierMessageSize(proof)
	if _, err := BuildProofReport(proof, opts, ringQ); err != nil {
		t.Fatalf("paper report: %v", err)
	}
	after := EstimateVerifierMessageSize(proof)
	if before.Total != after.Total {
		t.Fatalf("modeled verifier-message estimate changed after paper transcript report: before=%d after=%d", before.Total, after.Total)
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

func TestResolveSigShortnessModeMarksRemovedVersionsUnsupported(t *testing.T) {
	got := ResolveSigShortnessMode(&Proof{
		SigShortness: &SigShortnessProof{
			Version: 6,
		},
	})
	if got != "sig_shortness_v6_unsupported" {
		t.Fatalf("sig shortness mode=%q want unsupported v6 label", got)
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
		ShowingPreset:        ShowingPresetInlineTargetReplayCompact,
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
	if got := ResolveShowingPresetLabelForOpts(opts); got != ShowingPresetInlineTargetReplayCompact {
		t.Fatalf("inline-target resolved preset=%q want %q", got, ShowingPresetInlineTargetReplayCompact)
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
		Version:       decs.OpeningVersionV2,
		Role:          decs.CommitmentRoleMain,
		Indices:       []int{0},
		PvalsBits:     []byte{1, 2},
		MvalsBits:     []byte{3},
		PvalsBitWidth: 14,
		MvalsBitWidth: 14,
		R:             1,
		Eta:           1,
		Tapes:         [][]byte{bytes.Repeat([]byte{4}, 16)},
		TapeBytes:     16,
	}
}
