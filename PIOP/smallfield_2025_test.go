package PIOP

import (
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestValidateSmallField2025RejectedMetadata(t *testing.T) {
	proof := minimalSmallField2025Proof()
	proof.SmallField2025 = &SmallField2025LVCSProof{
		Version:          smallField2025LVCSProofVersionV2,
		Mode:             TranscriptProtocolSmallField2025V2,
		Status:           SmallField2025StatusRejected,
		ReductionEnabled: false,
		HeadDomainMode:   SmallField2025HeadDomainV2,
	}
	if err := ValidateSmallField2025Proof(proof); err != nil {
		t.Fatalf("ValidateSmallField2025Proof rejected disabled fail-closed metadata: %v", err)
	}
}

func TestStrictV2DefaultsExactTranscriptOmissionDescriptor(t *testing.T) {
	opts := ResolveSimOptsDefaults(SimOpts{
		TranscriptVersion:      TranscriptVersionSmallWood2025V2,
		TranscriptProtocolMode: TranscriptProtocolSmallField2025V2,
	})
	if opts.TranscriptOmissionMode != SmallField2025TranscriptOmissionModeDigestBoundV2 {
		t.Fatalf("default omission mode=%q want=%q", opts.TranscriptOmissionMode, SmallField2025TranscriptOmissionModeDigestBoundV2)
	}
	desc, err := newSmallField2025TranscriptOmission("")
	if err != nil {
		t.Fatal(err)
	}
	if desc == nil || desc.Version != smallField2025TranscriptOmissionVersionV2 || desc.Mode != SmallField2025TranscriptOmissionModeDigestBoundV2 {
		t.Fatalf("empty live-mode default did not produce exact v2 descriptor: %+v", desc)
	}
}

func TestValidateSmallField2025CanonicalGates(t *testing.T) {
	proof := minimalSmallField2025Proof()
	proof.SmallField2025 = &SmallField2025LVCSProof{
		Version:        smallField2025LVCSProofVersionV2,
		Mode:           TranscriptProtocolSmallField2025V2,
		Status:         SmallField2025StatusRejected,
		HeadDomainMode: SmallField2025HeadDomainV2,
	}
	proof.Theta = 1
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatalf("ValidateSmallField2025Proof accepted theta=1")
	}
	proof = minimalSmallField2025Proof()
	proof.SmallField2025 = &SmallField2025LVCSProof{
		Version:        smallField2025LVCSProofVersionV2,
		Mode:           TranscriptProtocolSmallField2025V2,
		Status:         SmallField2025StatusRejected,
		HeadDomainMode: SmallField2025HeadDomainV2,
	}
	proof.KPoint = [][]uint64{{1, 2}, {3, 4}}
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatalf("ValidateSmallField2025Proof accepted ell_prime != 1")
	}
	proof = minimalSmallField2025Proof()
	proof.SmallField2025 = &SmallField2025LVCSProof{
		Version:        smallField2025LVCSProofVersionV2,
		Mode:           TranscriptProtocolSmallField2025V2,
		Status:         SmallField2025StatusRejected,
		HeadDomainMode: SmallField2025HeadDomainV2,
	}
	proof.QRoot[0] = 1
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatalf("ValidateSmallField2025Proof accepted redundant Q DECS material")
	}
}

func TestValidateSmallField2025LiveMetadataDigest(t *testing.T) {
	proof := liveSmallField2025ProofForTest()
	if err := ValidateSmallField2025Proof(proof); err != nil {
		t.Fatalf("ValidateSmallField2025Proof rejected live metadata: %v", err)
	}
	proof.SmallField2025.PayloadDigest = append([]byte(nil), proof.SmallField2025.PayloadDigest...)
	proof.SmallField2025.PayloadDigest[0] ^= 0x80
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatalf("ValidateSmallField2025Proof accepted tampered payload digest")
	}
}

func TestSmallField2025DigestBoundTranscriptKeepsMatrixPayloads(t *testing.T) {
	proof := liveSmallField2025ProofForTest()
	baseTranscript := smallField2025TranscriptBytes(proof.SmallField2025)
	if err := ValidateSmallField2025Proof(proof); err != nil {
		t.Fatalf("ValidateSmallField2025Proof rejected digest-bound omission: %v", err)
	}
	if proof.SmallField2025.TranscriptOmission == nil ||
		proof.SmallField2025.TranscriptOmission.Version != smallField2025TranscriptOmissionVersionV2 ||
		proof.SmallField2025.TranscriptOmission.Mode != SmallField2025TranscriptOmissionModeDigestBoundV2 ||
		len(baseTranscript) == 0 {
		t.Fatal("live transcript did not bind the exact v2 omission descriptor")
	}
	payloads := smallField2025Round4DirectPayloads(proof)
	if len(payloads) != 2 {
		t.Fatalf("round-4 direct payloads=%d want VTargets and BarSets retained", len(payloads))
	}
	report := buildPaperTranscriptReportLeaf(proof, 12289, paperTranscriptParams{Lambda: 128, Eta: 2, Ell: 2, Theta: 2, DQ: 8, DDECS: 4})
	if report.VTargets.OptimizedBytes == 0 || report.BarSets.OptimizedBytes == 0 {
		t.Fatalf("matrix buckets were incorrectly omitted: v=%d bar=%d", report.VTargets.OptimizedBytes, report.BarSets.OptimizedBytes)
	}
	if report.Audit.VTargets.Omitted || report.Audit.VTargets.ReconstructedBytesSaved != 0 {
		t.Fatalf("VTargets should not be omitted without reconstruction theorem support: %+v", report.Audit.VTargets)
	}
	if report.Audit.BarSets.Omitted || report.Audit.BarSets.ReconstructedBytesSaved != 0 {
		t.Fatalf("BarSets should not be omitted without reconstruction theorem support: %+v", report.Audit.BarSets)
	}
	if !report.Audit.Pdecs.Omitted || report.Audit.Pdecs.NonReconstructibleBytes == 0 || report.Audit.Pdecs.OmissionMapBytes == 0 {
		t.Fatalf("missing Pdecs omission audit: %+v", report.Audit.Pdecs)
	}
	proof.SmallField2025.TranscriptOmission.OmitVTargets = true
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatal("ValidateSmallField2025Proof accepted tampered omission descriptor")
	}
}

func TestSmallField2025LiveMetadataRejectsMissingOmissionDescriptor(t *testing.T) {
	proof := liveSmallField2025ProofForTest()
	proof.SmallField2025.TranscriptOmission = nil
	proof.SmallField2025.PayloadDigest = smallField2025PayloadDigest(proof, proof.SmallField2025)
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatal("live small-field metadata accepted a missing omission descriptor")
	}
}

func TestSmallField2025TranscriptOmissionRejectsUnsupportedFlags(t *testing.T) {
	proof := liveSmallField2025ProofForTest()
	proof.SmallField2025.TranscriptOmission = &SmallField2025TranscriptOmission{
		Version: smallField2025TranscriptOmissionVersionV2,
		Mode:    "unknown",
	}
	proof.SmallField2025.PayloadDigest = smallField2025PayloadDigest(proof, proof.SmallField2025)
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatal("ValidateSmallField2025Proof accepted unknown omission mode")
	}
	proof = liveSmallField2025ProofForTest()
	proof.SmallField2025.TranscriptOmission = &SmallField2025TranscriptOmission{
		Version:               smallField2025TranscriptOmissionVersionV2,
		Mode:                  SmallField2025TranscriptOmissionModeDigestBoundV2,
		OmitVTargets:          true,
		AuthMultiproofCompact: true,
	}
	proof.SmallField2025.PayloadDigest = smallField2025PayloadDigest(proof, proof.SmallField2025)
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatal("ValidateSmallField2025Proof accepted auth multiproof compact omission")
	}
}

func TestValidateSmallField2025RejectsTamperedOmissionMap(t *testing.T) {
	proof := minimalSmallField2025Proof()
	proof.CoeffMatrix = [][]uint64{
		{1, 0, 0, 0, 5, 7},
		{0, 1, 0, 0, 3, 4},
		{0, 0, 1, 0, 0, 0},
		{0, 0, 0, 1, 0, 0},
	}
	proof.setVTargets([][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10, 11, 12}})
	proof.setBarSets([][]uint64{{7, 8}, {9, 10}, {11, 12}, {13, 14}})
	proof.Tail = []int{5, 6}
	proof.PCSOpening = &decs.DECSOpening{
		FormatVersion:  decs.OpeningFormatOmitCols,
		MFormatVersion: decs.OpeningFormatOmitCols,
		R:              6,
		Eta:            2,
		Indices:        []int{5, 6},
		PColsEncoded:   2,
		POmitCols:      []int{0, 1, 2, 3},
		MColsEncoded:   0,
		MOmitCols:      []int{0, 1},
	}
	meta := &SmallField2025LVCSProof{
		Version:          smallField2025LVCSProofVersionV2,
		Mode:             TranscriptProtocolSmallField2025V2,
		Status:           SmallField2025StatusLive,
		ReductionEnabled: true,
		HeadDomainMode:   SmallField2025HeadDomainV2,
		NRows:            6,
		NCols:            3,
		Theta:            2,
		WitnessLayers:    1,
		MaskRows:         2,
		QueryCount:       4,
		VHeadRows:        4,
		VHeadCols:        3,
		VBarRows:         4,
		VBarCols:         2,
		POmitCols:        []int{0, 1, 2, 3},
		MOmitCols:        []int{0, 1},
		MatrixDigest:     smallField2025MatrixDigest(proof.CoeffMatrix),
		TranscriptOmission: &SmallField2025TranscriptOmission{
			Version:                      smallField2025TranscriptOmissionVersionV2,
			Mode:                         SmallField2025TranscriptOmissionModeDigestBoundV2,
			OmitPdecsReconstructibleCols: true,
		},
	}
	meta.PayloadDigest = smallField2025PayloadDigest(proof, meta)
	proof.SmallField2025 = meta
	if err := ValidateSmallField2025Proof(proof); err != nil {
		t.Fatalf("ValidateSmallField2025Proof rejected valid omission metadata: %v", err)
	}
	badMeta := *meta
	badMeta.POmitCols = []int{0, 1, 2, 4}
	proof.SmallField2025 = &badMeta
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatal("ValidateSmallField2025Proof accepted tampered P omission map")
	}
	proof.SmallField2025 = meta
	badOpen := *proof.PCSOpening
	badOpen.POmitCols = []int{0, 1, 2, 4}
	proof.PCSOpening = &badOpen
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatal("ValidateSmallField2025Proof accepted tampered opening omission map")
	}
}

func TestBuildSmallField2025CoeffPlanExtendsFullRankDeterministically(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	omega := []uint64{1, 2, 3}
	sf, err := deriveSmallFieldParamsNoRows(ringQ, omega, 2)
	if err != nil {
		t.Fatalf("derive small field: %v", err)
	}
	rows := make([][]uint64, 10)
	kPoint := sf.K.Phi([]uint64{7, 1})
	planA, err := buildSmallField2025CoeffPlan(ringQ, sf.K, omega, rows, kPoint, sf.OmegaS1, sf.MuInv, 5, 5, 5)
	if err != nil {
		t.Fatalf("build plan A: %v", err)
	}
	planB, err := buildSmallField2025CoeffPlan(ringQ, sf.K, omega, rows, kPoint, sf.OmegaS1, sf.MuInv, 5, 5, 5)
	if err != nil {
		t.Fatalf("build plan B: %v", err)
	}
	if got, want := len(planA.C), (planA.WitnessLayers+1)*sf.K.Theta; got != want {
		t.Fatalf("query rows=%d want %d", got, want)
	}
	if got, want := planA.ReplayRows, planA.WitnessLayers*sf.K.Theta; got != want {
		t.Fatalf("replay rows=%d want %d", got, want)
	}
	if len(planA.POmitCols) != len(planA.C) {
		t.Fatalf("omit cols=%d want %d", len(planA.POmitCols), len(planA.C))
	}
	if !matrixEqual(planA.C, planB.C) || !equalIntSlices(planA.POmitCols, planB.POmitCols) {
		t.Fatalf("smallfield2025 coefficient plan is not deterministic")
	}
	if pivots, ok := compressionPivotCols(planA.C, len(rows), ringQ.Modulus[0]); !ok || !equalIntSlices(pivots, planA.POmitCols) {
		t.Fatalf("plan is not full-rank or has unexpected pivots: ok=%v pivots=%v omit=%v", ok, pivots, planA.POmitCols)
	}
}

func TestValidateSmallField2025ProofAcceptsMatchingV3Tuple(t *testing.T) {
	proof := liveSmallField2025ProofForTest()
	proof.TranscriptVersion = TranscriptVersionSmallWood2025V3
	proof.TranscriptProtocolMode = TranscriptProtocolSmallField2025V3
	proof.SmallField2025.Mode = TranscriptProtocolSmallField2025V3
	proof.SmallField2025.TranscriptOmission = &SmallField2025TranscriptOmission{
		Version:                      smallField2025TranscriptOmissionVersionV3,
		Mode:                         SmallField2025TranscriptOmissionModeCanonicalV3,
		OmitPdecsReconstructibleCols: true,
		AuthMultiproofCompact:        true,
	}
	proof.SmallField2025.PayloadDigest = smallField2025PayloadDigest(proof, proof.SmallField2025)
	if err := ValidateSmallField2025Proof(proof); err != nil {
		t.Fatalf("ValidateSmallField2025Proof(v3): %v", err)
	}

	proof.SmallField2025.Mode = TranscriptProtocolSmallField2025V2
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatal("ValidateSmallField2025Proof accepted mixed v2/v3 metadata")
	}
}

func minimalSmallField2025Proof() *Proof {
	proof := &Proof{
		TranscriptVersion:      TranscriptVersionSmallWood2025V2,
		TranscriptProtocolMode: TranscriptProtocolSmallField2025V2,
		Theta:                  2,
		KPoint:                 [][]uint64{{1, 2}},
		PCSGeometry:            PCSGeometry{Kind: PCSGeometryKindSmallFieldMatrixV2},
	}
	proof.setQPayload([][]uint64{{1}, {2}})
	return proof
}

func liveSmallField2025ProofForTest() *Proof {
	proof := minimalSmallField2025Proof()
	proof.CoeffMatrix = [][]uint64{
		{1, 0, 0, 0, 5, 7},
		{0, 1, 0, 0, 3, 4},
		{0, 0, 1, 0, 0, 0},
		{0, 0, 0, 1, 0, 0},
	}
	proof.setVTargets([][]uint64{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}, {10, 11, 12}})
	proof.setBarSets([][]uint64{{7, 8}, {9, 10}, {11, 12}, {13, 14}})
	proof.Tail = []int{5, 6}
	proof.PCSOpening = &decs.DECSOpening{
		FormatVersion:  decs.OpeningFormatOmitCols,
		MFormatVersion: decs.OpeningFormatOmitCols,
		R:              6,
		Eta:            2,
		Indices:        []int{5, 6},
		PColsEncoded:   2,
		MColsEncoded:   0,
	}
	meta := &SmallField2025LVCSProof{
		Version:          smallField2025LVCSProofVersionV2,
		Mode:             TranscriptProtocolSmallField2025V2,
		Status:           SmallField2025StatusLive,
		ReductionEnabled: true,
		HeadDomainMode:   SmallField2025HeadDomainV2,
		NRows:            6,
		NCols:            3,
		Theta:            2,
		WitnessLayers:    1,
		MaskRows:         2,
		QueryCount:       4,
		VHeadRows:        4,
		VHeadCols:        3,
		VBarRows:         4,
		VBarCols:         2,
		MatrixDigest:     smallField2025MatrixDigest(proof.CoeffMatrix),
		TranscriptOmission: &SmallField2025TranscriptOmission{
			Version:                      smallField2025TranscriptOmissionVersionV2,
			Mode:                         SmallField2025TranscriptOmissionModeDigestBoundV2,
			OmitPdecsReconstructibleCols: true,
		},
	}
	meta.PayloadDigest = smallField2025PayloadDigest(proof, meta)
	proof.SmallField2025 = meta
	return proof
}
