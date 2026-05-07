package lvcs

import (
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestCommitInitTrustedHeadSkipsOnlyDirectPolynomialHeadCheck(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	q := ringQ.Modulus[0]
	points := []uint64{1, 2, 3, 4, 5, 6, 7, 8}
	ncols := 3
	ell := 2
	coeffs := []uint64{7, 3, 11, 5, 2}
	head := make([]uint64, ncols)
	for i := 0; i < ncols; i++ {
		head[i] = evalPolyCoeffs(coeffs, points[i], q)
	}
	params := decs.Params{Degree: len(coeffs) - 1, Eta: 1, NonceBytes: 16}
	if _, pk, err := CommitInitWithParamsAndPoints(ringQ, []RowInput{{
		Head:        head,
		PolyCoeffs:  append([]uint64(nil), coeffs...),
		TrustedHead: true,
	}}, ell, params, points); err != nil {
		t.Fatalf("trusted direct polynomial commit: %v", err)
	} else if len(pk.Rows) != 1 || len(pk.Rows[0].Head) != len(head) {
		t.Fatalf("unexpected committed row head shape")
	}

	badHead := append([]uint64(nil), head...)
	badHead[0] = (badHead[0] + 1) % q
	if _, _, err := CommitInitWithParamsAndPoints(ringQ, []RowInput{{
		Head:       badHead,
		PolyCoeffs: append([]uint64(nil), coeffs...),
	}}, ell, params, points); err == nil {
		t.Fatalf("unchecked direct polynomial commit accepted mismatched head")
	}
}
