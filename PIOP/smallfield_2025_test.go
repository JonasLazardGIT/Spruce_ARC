package PIOP

import (
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestValidateSmallField2025RejectedMetadata(t *testing.T) {
	proof := minimalSmallField2025Proof()
	proof.SmallField2025 = &SmallField2025LVCSProof{
		Version:          smallField2025LVCSProofVersionV1,
		Mode:             TranscriptProtocolSmallField2025V1,
		Status:           SmallField2025StatusRejected,
		ReductionEnabled: false,
		HeadDomainMode:   SmallField2025HeadDomainV1,
	}
	if err := ValidateSmallField2025Proof(proof); err != nil {
		t.Fatalf("ValidateSmallField2025Proof rejected disabled fail-closed metadata: %v", err)
	}
}

func TestValidateSmallField2025CanonicalGates(t *testing.T) {
	proof := minimalSmallField2025Proof()
	proof.SmallField2025 = &SmallField2025LVCSProof{
		Version:        smallField2025LVCSProofVersionV1,
		Mode:           TranscriptProtocolSmallField2025V1,
		Status:         SmallField2025StatusRejected,
		HeadDomainMode: SmallField2025HeadDomainV1,
	}
	proof.Theta = 1
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatalf("ValidateSmallField2025Proof accepted theta=1")
	}
	proof = minimalSmallField2025Proof()
	proof.SmallField2025 = &SmallField2025LVCSProof{
		Version:        smallField2025LVCSProofVersionV1,
		Mode:           TranscriptProtocolSmallField2025V1,
		Status:         SmallField2025StatusRejected,
		HeadDomainMode: SmallField2025HeadDomainV1,
	}
	proof.KPoint = [][]uint64{{1, 2}, {3, 4}}
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatalf("ValidateSmallField2025Proof accepted ell_prime != 1")
	}
	proof = minimalSmallField2025Proof()
	proof.SmallField2025 = &SmallField2025LVCSProof{
		Version:        smallField2025LVCSProofVersionV1,
		Mode:           TranscriptProtocolSmallField2025V1,
		Status:         SmallField2025StatusRejected,
		HeadDomainMode: SmallField2025HeadDomainV1,
	}
	proof.QRoot[0] = 1
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatalf("ValidateSmallField2025Proof accepted redundant Q DECS material")
	}
}

func TestValidateSmallField2025LiveMetadataDigest(t *testing.T) {
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
		Version:          smallField2025LVCSProofVersionV1,
		Mode:             TranscriptProtocolSmallField2025V1,
		Status:           SmallField2025StatusLive,
		ReductionEnabled: true,
		HeadDomainMode:   SmallField2025HeadDomainV1,
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
	}
	meta.PayloadDigest = smallField2025PayloadDigest(proof, meta)
	proof.SmallField2025 = meta
	if err := ValidateSmallField2025Proof(proof); err != nil {
		t.Fatalf("ValidateSmallField2025Proof rejected live metadata: %v", err)
	}
	proof.SmallField2025.PayloadDigest = append([]byte(nil), proof.SmallField2025.PayloadDigest...)
	proof.SmallField2025.PayloadDigest[0] ^= 0x80
	if err := ValidateSmallField2025Proof(proof); err == nil {
		t.Fatalf("ValidateSmallField2025Proof accepted tampered payload digest")
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

func minimalSmallField2025Proof() *Proof {
	proof := &Proof{
		TranscriptVersion:      TranscriptVersionSmallWood2025,
		TranscriptProtocolMode: TranscriptProtocolSmallField2025V1,
		Theta:                  2,
		KPoint:                 [][]uint64{{1, 2}},
		PCSGeometry:            PCSGeometry{Kind: PCSGeometryKindSmallFieldMatrixV1},
	}
	proof.setQPayload([][]uint64{{1}, {2}})
	return proof
}
