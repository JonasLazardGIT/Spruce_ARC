package lvcs

import (
	"bytes"
	"sync"
	"testing"

	decs "vSIS-Signature/DECS"
	swdomain "vSIS-Signature/internal/domain"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func newPreparedLVCSKey(t *testing.T, deferNTT bool) (*ring.Ring, *swdomain.Prepared, *ProverKey) {
	t.Helper()
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	points := make([]uint64, 16)
	for index := range points {
		points[index] = uint64(index + 1)
	}
	prepared, err := swdomain.NewPrepared(swdomain.Binding{Q: ringQ.Modulus[0], NLeaves: len(points), OmegaSize: 3, Ell: 2}, points)
	if err != nil {
		t.Fatal(err)
	}
	rows := []RowInput{
		{Head: []uint64{1, 2, 3}, Tail: []uint64{7, 8}},
		{Head: []uint64{12293, 5, 6}, Tail: []uint64{9, 10}},
	}
	params := decs.Params{Degree: 4, Eta: 2, TapeBytes: 16, HashBytes: 21}
	ctx := decs.CommitmentContext{
		TranscriptVersion: decs.TranscriptVersionV2,
		Role:              decs.CommitmentRoleMain,
		Salt:              bytes.Repeat([]byte{0x35}, 32),
	}
	_, key, err := CommitInitWithParamsAndPreparedDomainV2(
		ringQ, rows, 2, params, prepared, ctx,
		CommitOptions{DeferNTTMaterialization: deferNTT},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.DecsProver.ReleaseTapes)
	return ringQ, prepared, key
}

func TestPreparedCommitAndExactOmegaHeadEvaluation(t *testing.T) {
	ringQ, prepared, key := newPreparedLVCSKey(t, true)
	if key.PreparedDomain != prepared {
		t.Fatal("prepared identity was not retained")
	}
	points := prepared.CopyRange(0, prepared.Binding().OmegaSize)
	response, err := EvalOracle(ringQ, key, points, OracleLayout{})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]uint64{{1, 2, 3}, {4, 5, 6}}
	for rowIndex := range want {
		for pointIndex := range want[rowIndex] {
			if got := response.Witness[rowIndex][pointIndex]; got != want[rowIndex][pointIndex] {
				t.Fatalf("head[%d][%d]=%d want=%d", rowIndex, pointIndex, got, want[rowIndex][pointIndex])
			}
		}
	}
	response.Witness[0][0] = 999
	if key.Rows[0].Head[0] != 1 {
		t.Fatal("EvalOracle exposed retained head storage")
	}

	// Reordering one point must take the generic polynomial path and preserve
	// the mathematically expected response.
	points[0], points[1] = points[1], points[0]
	fallback, err := EvalOracle(ringQ, key, points, OracleLayout{})
	if err != nil {
		t.Fatal(err)
	}
	for rowIndex, coefficients := range key.RowPolyCoeffs {
		for pointIndex, point := range points {
			wantValue := evalPolyCoeffs(coefficients, point, ringQ.Modulus[0])
			if got := fallback.Witness[rowIndex][pointIndex]; got != wantValue {
				t.Fatalf("fallback[%d][%d]=%d want=%d", rowIndex, pointIndex, got, wantValue)
			}
		}
	}
}

func TestDeferredNTTMaterializationMatchesCoefficientsAndIsConcurrent(t *testing.T) {
	ringQ, _, key := newPreparedLVCSKey(t, true)
	if len(key.RowPolys) != 0 || len(key.MaskPolys) != 0 {
		t.Fatal("deferred key eagerly materialized NTT polynomials")
	}
	var wait sync.WaitGroup
	errors := make(chan error, 16)
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- key.MaterializeNTTPolys()
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(key.RowPolys) != len(key.RowPolyCoeffs) || len(key.MaskPolys) != key.Params.Eta {
		t.Fatalf("unexpected materialized dimensions rows=%d masks=%d", len(key.RowPolys), len(key.MaskPolys))
	}
	for rowIndex, nttPolynomial := range key.RowPolys {
		if nttPolynomial == nil {
			continue
		}
		coefficientPolynomial := ringQ.NewPoly()
		ringQ.InvNTT(nttPolynomial, coefficientPolynomial)
		for coefficientIndex, want := range key.RowPolyCoeffs[rowIndex] {
			if got := coefficientPolynomial.Coeffs[0][coefficientIndex]; got != want%ringQ.Modulus[0] {
				t.Fatalf("row %d coefficient %d=%d want=%d", rowIndex, coefficientIndex, got, want)
			}
		}
	}
	for maskIndex, nttPolynomial := range key.MaskPolys {
		if nttPolynomial == nil || maskIndex >= len(key.DecsProver.MFormal) {
			continue
		}
		coefficientPolynomial := ringQ.NewPoly()
		ringQ.InvNTT(nttPolynomial, coefficientPolynomial)
		for coefficientIndex, want := range key.DecsProver.MFormal[maskIndex] {
			if got := coefficientPolynomial.Coeffs[0][coefficientIndex]; got != want%ringQ.Modulus[0] {
				t.Fatalf("mask %d coefficient %d=%d want=%d", maskIndex, coefficientIndex, got, want)
			}
		}
	}
}

func TestPreparedLVCSBindingMismatchRejected(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	points := make([]uint64, 16)
	for index := range points {
		points[index] = uint64(index + 1)
	}
	prepared, err := swdomain.NewPrepared(swdomain.Binding{Q: 12289, NLeaves: len(points), OmegaSize: 4, Ell: 2}, points)
	if err != nil {
		t.Fatal(err)
	}
	params := decs.Params{Degree: 4, Eta: 1, TapeBytes: 16, HashBytes: 21}
	ctx := decs.CommitmentContext{TranscriptVersion: decs.TranscriptVersionV2, Role: decs.CommitmentRoleMain, Salt: bytes.Repeat([]byte{1}, 32)}
	rows := []RowInput{{Head: []uint64{1, 2, 3}, Tail: []uint64{4, 5}}}
	if _, _, err := CommitInitWithParamsAndPreparedDomainV2(ringQ, rows, 2, params, prepared, ctx, CommitOptions{}); err == nil {
		t.Fatal("commit accepted omega-size mismatch")
	}
	if _, err := NewVerifierWithParamsAndPreparedDomainV2(ringQ, 1, params, 3, prepared, ctx); err == nil {
		t.Fatal("verifier accepted omega-size mismatch")
	}
}

func TestAuthenticatedDirectHeadOpaqueProvenance(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	points := make([]uint64, 16)
	for index := range points {
		points[index] = uint64(index + 1)
	}
	prepared, err := swdomain.NewPrepared(swdomain.Binding{Q: 12289, NLeaves: len(points), OmegaSize: 3, Ell: 2}, points)
	if err != nil {
		t.Fatal(err)
	}
	input := RowInput{Head: []uint64{3, 5, 7}, PolyCoeffs: []uint64{1, 2}}
	derived, err := NewAuthenticatedDirectRowInput(ringQ, prepared, nil, input.PolyCoeffs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !equalUint64Slices(derived.Head, input.Head) || !directHeadProvenanceMatches(derived, trimCoeffsMod(derived.PolyCoeffs, ringQ.Modulus[0]), prepared, 3) {
		t.Fatal("derived direct row did not bind the expected head and provenance")
	}
	authenticated, err := AuthenticateDirectRowHead(ringQ, prepared, input)
	if err != nil {
		t.Fatal(err)
	}
	coefficients := trimCoeffsMod(authenticated.PolyCoeffs, ringQ.Modulus[0])
	if !directHeadProvenanceMatches(authenticated, coefficients, prepared, 3) {
		t.Fatal("fresh authenticated row did not retain opaque provenance")
	}
	authenticated.Head[0]++
	if directHeadProvenanceMatches(authenticated, coefficients, prepared, 3) {
		t.Fatal("head mutation did not invalidate opaque provenance")
	}
	input.Head[0] += ringQ.Modulus[0]
	if _, err := AuthenticateDirectRowHead(ringQ, prepared, input); err == nil {
		t.Fatal("accepted a noncanonical authenticated head")
	}
}

func TestLegacyTrustedHeadDoesNotEnterOmegaFastPath(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	points := make([]uint64, 16)
	for index := range points {
		points[index] = uint64(index + 1)
	}
	prepared, err := swdomain.NewPrepared(swdomain.Binding{Q: 12289, NLeaves: len(points), OmegaSize: 3, Ell: 2}, points)
	if err != nil {
		t.Fatal(err)
	}
	params := decs.Params{Degree: 4, Eta: 1, TapeBytes: 16, HashBytes: 21}
	ctx := decs.CommitmentContext{TranscriptVersion: decs.TranscriptVersionV2, Role: decs.CommitmentRoleMain, Salt: bytes.Repeat([]byte{3}, 32)}
	rows := []RowInput{{Head: []uint64{100, 101, 102}, PolyCoeffs: []uint64{9, 1}, TrustedHead: true}}
	_, key, err := CommitInitWithParamsAndPreparedDomainV2(ringQ, rows, 2, params, prepared, ctx, CommitOptions{DeferNTTMaterialization: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.DecsProver.ReleaseTapes)
	omega := prepared.CopyRange(0, prepared.Binding().OmegaSize)
	if isExactOmegaHeadRequest(key, omega) {
		t.Fatal("legacy unchecked TrustedHead entered exact-Omega fast path")
	}
	response, err := EvalOracle(ringQ, key, omega, OracleLayout{})
	if err != nil {
		t.Fatal(err)
	}
	for pointIndex, point := range omega {
		want := evalPolyCoeffs([]uint64{9, 1}, point, ringQ.Modulus[0])
		if got := response.Witness[0][pointIndex]; got != want {
			t.Fatalf("generic response[%d]=%d want committed value=%d", pointIndex, got, want)
		}
	}
}
