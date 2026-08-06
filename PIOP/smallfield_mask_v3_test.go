package PIOP

import (
	"bytes"
	"encoding/binary"
	"testing"

	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestSmallFieldMaskShapeV3Targets(t *testing.T) {
	for _, tc := range []struct {
		name            string
		d, ncols, theta int
		wantRows        int
	}{
		{"bq128", 472, 43, 13, 156},
		{"wf128-issuance", 391, 42, 7, 77},
		{"wf128-showing-l41", 471, 41, 7, 91},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shape, err := deriveSmallFieldMaskShapeV3(tc.d, tc.ncols, tc.theta)
			if err != nil {
				t.Fatalf("shape %+v: %v", tc, err)
			}
			if shape.NCols != tc.ncols || shape.RowsPerMask != tc.wantRows {
				t.Fatalf("shape %+v ncols/rows=%d/%d want=%d/%d", tc, shape.NCols, shape.RowsPerMask, tc.ncols, tc.wantRows)
			}
		})
	}
}

func TestSmallFieldV3TargetPCSGeometryUsesCorrectedMaskRows(t *testing.T) {
	const q = uint64(1017857)
	ringQ, err := ring.NewRing(1024, []uint64{q})
	if err != nil {
		t.Fatal(err)
	}
	omega := make([]uint64, 32)
	for i := range omega {
		omega[i] = uint64(i + 1)
	}
	for _, tc := range []struct {
		name         string
		theta        int
		lvcsNCols    int
		dq           int
		logicalRows  int
		wantReplay   int
		wantMaskRows int
		wantTotal    int
	}{
		{"bq128-issuance", 13, 43, 472, 165, 180, 156, 336},
		{"bq128-showing", 13, 43, 570, 423, 450, 195, 645},
		{"wf128-issuance", 7, 42, 391, 165, 156, 77, 233},
		{"wf128-showing", 7, 41, 471, 423, 429, 91, 520},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, ok := kf.LookupSmallWoodFieldProfileV3(q, tc.theta)
			if !ok {
				t.Fatalf("missing theta-%d profile", tc.theta)
			}
			K, extra, err := profile.Validate(omega)
			if err != nil {
				t.Fatal(err)
			}
			head := make([]uint64, len(omega))
			logical := make([]lvcs.RowInput, tc.logicalRows)
			for i := range logical {
				logical[i].Head = head
			}
			pcs, err := buildSmallFieldPCSRowsFromLiteralInputsV3(
				ringQ, omega, tc.lvcsNCols, 1, K, extra, logical,
				[]*KPoly{newZeroKPoly(tc.theta, tc.dq+1)}, tc.dq,
			)
			if err != nil {
				t.Fatal(err)
			}
			if pcs.PCSGeometry.ReplayWitnessRows != tc.wantReplay ||
				pcs.PCSGeometry.MaskRows != tc.wantMaskRows || pcs.MaskRowCount != tc.wantMaskRows ||
				len(pcs.RowInputs) != tc.wantTotal {
				t.Fatalf(
					"actual PCS replay/mask/mask-count/total=%d/%d/%d/%d want %d/%d/%d/%d",
					pcs.PCSGeometry.ReplayWitnessRows, pcs.PCSGeometry.MaskRows, pcs.MaskRowCount, len(pcs.RowInputs),
					tc.wantReplay, tc.wantMaskRows, tc.wantMaskRows, tc.wantTotal,
				)
			}
		})
	}
}

func TestSmallFieldMaskV3EvaluationAuthenticatedByVTargets(t *testing.T) {
	profile, ok := kf.LookupSmallWoodFieldProfileV3(1017857, 7)
	if !ok {
		t.Fatal("missing theta-7 profile")
	}
	K, e, err := profile.Validate([]uint64{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	const degree = 391
	mask := newZeroKPoly(K.Theta, degree+1)
	for d := 0; d <= degree; d++ {
		coords := make([]uint64, K.Theta)
		for j := range coords {
			coords[j] = uint64((d+1)*(j+3)) % K.Q
		}
		mask.setCoeffK(d, coords)
	}
	randomBytes := make([]byte, 8*K.Theta*64)
	for off := 0; off < len(randomBytes); off += 8 {
		binary.LittleEndian.PutUint64(randomBytes[off:], K.Q+1)
	}
	rows, shape, err := buildSmallFieldMaskLayerRowsV3(K, []*KPoly{mask}, 42, degree, bytes.NewReader(randomBytes))
	if err != nil {
		t.Fatal(err)
	}
	queries, err := smallFieldMaskEvalQueryRowsV3(K, e, len(rows), 0, shape)
	if err != nil {
		t.Fatal(err)
	}
	vTargets := computeVTargets(K.Q, rows, queries)
	got, err := smallFieldMaskEvalFromVTargetsV3(K, e, vTargets, 0, shape)
	if err != nil {
		t.Fatal(err)
	}
	want := K.Zero()
	evalKPolyAtKInto(K, &want, mask, e)
	if !elemEqual(K, got, want) {
		t.Fatalf("reconstructed M(e)=%v want=%v", got.Limb, want.Limb)
	}
	vTargets[0][0] = (vTargets[0][0] + 1) % K.Q
	tampered, err := smallFieldMaskEvalFromVTargetsV3(K, e, vTargets, 0, shape)
	if err != nil {
		t.Fatal(err)
	}
	if elemEqual(K, tampered, want) {
		t.Fatal("tampered mask VTarget preserved M(e)")
	}
}

func exactMaskRandomizerStreamV3(K *kf.Field, count int) ([]byte, []kf.Elem) {
	stream := make([]byte, 0, count*K.Theta*8)
	want := make([]kf.Elem, count)
	for sample := 0; sample < count; sample++ {
		want[sample] = K.Zero()
		for coord := 0; coord < K.Theta; coord++ {
			residue := uint64(1 + sample*K.Theta + coord)
			want[sample].Limb[coord] = residue
			var word [8]byte
			// This is above the rejection threshold and reduces to residue.
			binary.LittleEndian.PutUint64(word[:], K.Q*uint64(sample*K.Theta+coord+1)+residue)
			stream = append(stream, word[:]...)
		}
	}
	return stream, want
}

func TestSmallFieldMaskV3Eq2SignsAndIndependentRandomizers(t *testing.T) {
	profile, ok := kf.LookupSmallWoodFieldProfileV3(1017857, 7)
	if !ok {
		t.Fatal("missing theta-7 profile")
	}
	K, _, err := profile.Validate([]uint64{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	shape, err := deriveSmallFieldMaskShapeV3(391, 42, K.Theta)
	if err != nil {
		t.Fatal(err)
	}
	randomBytes, taus := exactMaskRandomizerStreamV3(K, shape.Nu-1)
	rows, gotShape, err := buildSmallFieldMaskLayerRowsV3(
		K, []*KPoly{newZeroKPoly(K.Theta, 392)}, 42, 391, bytes.NewReader(randomBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotShape != shape {
		t.Fatalf("shape=%+v want=%+v", gotShape, shape)
	}
	for boundary, tau := range taus {
		col := boundary + 1
		nextRow := 0
		if col == shape.Nu-1 {
			nextRow = shape.Delta
		}
		for coord, value := range tau.Limb {
			if got := rows[shape.Mu*K.Theta+coord][col-1]; got != value {
				t.Fatalf("tau[%d][%d] preceding sign=%d want +%d", boundary, coord, got, value)
			}
			if got, want := rows[nextRow*K.Theta+coord][col], K.Q-value; got != want {
				t.Fatalf("tau[%d][%d] next sign=%d want -%d", boundary, coord, got, value)
			}
		}
		if boundary > 0 && elemEqual(K, taus[boundary-1], tau) {
			t.Fatalf("adjacent Eq. (2) randomizers %d and %d are not independent draws", boundary-1, boundary)
		}
	}
}

func TestSmallFieldMaskV3ZeroShiftEvaluationAndQueryRank(t *testing.T) {
	profile, ok := kf.LookupSmallWoodFieldProfileV3(1017857, 7)
	if !ok {
		t.Fatal("missing theta-7 profile")
	}
	K, e, err := profile.Validate([]uint64{9, 10, 11, 12})
	if err != nil {
		t.Fatal(err)
	}
	const degree, ncols = 40, 8 // mu=5, nu=8, delta=0
	shape, err := deriveSmallFieldMaskShapeV3(degree, ncols, K.Theta)
	if err != nil {
		t.Fatal(err)
	}
	if shape.Delta != 0 {
		t.Fatalf("delta=%d want zero", shape.Delta)
	}
	randomBytes, _ := exactMaskRandomizerStreamV3(K, shape.Nu-1)
	rows, _, err := buildSmallFieldMaskLayerRowsV3(
		K, []*KPoly{newZeroKPoly(K.Theta, degree+1)}, ncols, degree, bytes.NewReader(randomBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	queries, err := smallFieldMaskEvalQueryRowsV3(K, e, len(rows), 0, shape)
	if err != nil {
		t.Fatal(err)
	}
	pivots, fullRank := compressionPivotCols(queries, len(rows), K.Q)
	if !fullRank || len(pivots) != K.Theta {
		t.Fatalf("semantic mask queries rank=%d full=%v want=%d", len(pivots), fullRank, K.Theta)
	}
	vTargets := computeVTargets(K.Q, rows, queries)
	got, err := smallFieldMaskEvalFromVTargetsV3(K, e, vTargets, 0, shape)
	if err != nil {
		t.Fatal(err)
	}
	if !K.IsZero(got) {
		t.Fatalf("zero mask with Eq. (2) randomizers evaluates to %v", got.Limb)
	}
}
