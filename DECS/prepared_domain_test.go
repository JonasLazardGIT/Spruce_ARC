package decs

import (
	"bytes"
	"reflect"
	"testing"

	swdomain "vSIS-Signature/internal/domain"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestPreparedDomainConstructorsMatchRawConstructors(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	points := make([]uint64, 64)
	for index := range points {
		points[index] = uint64(index + 1)
	}
	prepared, err := swdomain.NewPrepared(swdomain.Binding{Q: 12289, NLeaves: len(points), OmegaSize: 3, Ell: 2}, points)
	if err != nil {
		t.Fatal(err)
	}
	rows := formalRowsForCommitTest(4, 7, ringQ.Modulus[0])
	params := Params{Degree: 7, Eta: 2, TapeBytes: 16, HashBytes: 21}
	raw, err := NewProverWithParamsAndPointsFormalChecked(ringQ, rows, params, points)
	if err != nil {
		t.Fatal(err)
	}
	viaPrepared, err := NewProverWithParamsAndPreparedDomainFormalChecked(ringQ, rows, params, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(raw.PFormal, viaPrepared.PFormal) || !reflect.DeepEqual(raw.points, viaPrepared.points) {
		t.Fatal("prepared prover state differs from raw prover state")
	}
	masks := maskRowsForCommitTest(params.Eta, params.Degree, ringQ.Modulus[0])
	tapes := make([]byte, len(points)*params.TapeBytes)
	for index := range tapes {
		tapes[index] = byte(index*31 + 7)
	}
	for _, prover := range []*Prover{raw, viaPrepared} {
		prover.MFormal = cloneFormalRows(masks)
		prover.tapes = append([]byte(nil), tapes...)
	}
	ctx := v2TestContext(CommitmentRoleMain, 0x44)
	rawRoot := commitV2ForTest(t, raw, ctx, CommitOptions{FormalEvalMode: FormalEvalCombined})
	preparedRoot := commitV2ForTest(t, viaPrepared, ctx, CommitOptions{FormalEvalMode: FormalEvalCombined})
	if !bytes.Equal(rawRoot, preparedRoot) {
		t.Fatalf("prepared root differs: raw=%x prepared=%x", rawRoot, preparedRoot)
	}
	rawVerifier, err := NewVerifierWithParamsAndPointsV2Checked(ringQ, len(rows), params, points, ctx)
	if err != nil {
		t.Fatal(err)
	}
	preparedVerifier, err := NewVerifierWithParamsAndPreparedDomainV2Checked(ringQ, len(rows), params, prepared, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rawVerifier.points, preparedVerifier.points) {
		t.Fatal("prepared verifier points differ from raw verifier points")
	}

	points[0] = 999
	if viaPrepared.points[0] != 1 || preparedVerifier.points[0] != 1 {
		t.Fatal("prepared constructors retained caller point storage")
	}
}

func TestPreparedDomainConstructorsRejectWrongModulus(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	points := make([]uint64, 16)
	for index := range points {
		points[index] = uint64(index + 1)
	}
	prepared, err := swdomain.NewPrepared(swdomain.Binding{Q: 65537, NLeaves: len(points), OmegaSize: 3, Ell: 2}, points)
	if err != nil {
		t.Fatal(err)
	}
	params := Params{Degree: 4, Eta: 1, TapeBytes: 16, HashBytes: 21}
	if _, err := NewProverWithParamsAndPreparedDomainFormalChecked(ringQ, [][]uint64{{1}}, params, prepared); err == nil {
		t.Fatal("prover accepted wrong prepared modulus")
	}
	if _, err := NewVerifierWithParamsAndPreparedDomainV2Checked(ringQ, 1, params, prepared, v2TestContext(CommitmentRoleMain, 1)); err == nil {
		t.Fatal("verifier accepted wrong prepared modulus")
	}
}

func TestValidateFormalRowsDegree(t *testing.T) {
	const q = uint64(12289)
	valid := [][]uint64{{1, 2, 3}, {4, 5, 6, q, 2 * q}, nil}
	if err := ValidateFormalRowsDegree(valid, 2, q); err != nil {
		t.Fatalf("rejected coefficients that vanish above degree: %v", err)
	}
	invalid := cloneFormalRows(valid)
	invalid[1][4]++
	if err := ValidateFormalRowsDegree(invalid, 2, q); err == nil {
		t.Fatal("accepted nonzero coefficient above degree")
	}
	if err := ValidateFormalRowsDegree(valid, -1, q); err == nil {
		t.Fatal("accepted negative degree")
	}
	if err := ValidateFormalRowsDegree(valid, 2, 0); err == nil {
		t.Fatal("accepted zero modulus")
	}
	if err := ValidateFormalRowsDegree(valid, int(^uint(0)>>1), q); err != nil {
		t.Fatalf("maximum int degree should accept short rows without overflow: %v", err)
	}
}
