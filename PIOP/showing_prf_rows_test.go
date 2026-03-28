package PIOP

import (
	"reflect"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func testPackedPRFRow(ringQ *ring.Ring, head []uint64) *ring.Poly {
	pNTT := ringQ.NewPoly()
	for i := 0; i < len(head) && i < len(pNTT.Coeffs[0]); i++ {
		pNTT.Coeffs[0][i] = head[i] % ringQ.Modulus[0]
	}
	out := ringQ.NewPoly()
	ringQ.InvNTT(pNTT, out)
	return out
}

func TestPackPRFWitnessRowsRowMajorSlotsAndHeads(t *testing.T) {
	ringQ, err := ring.NewRing(2048, []uint64{12289})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	ncols := 4
	sboxRows := []*ring.Poly{
		testPackedPRFRow(ringQ, []uint64{7, 7, 7, 7}),
		testPackedPRFRow(ringQ, []uint64{8, 8, 8, 8}),
		testPackedPRFRow(ringQ, []uint64{9, 9, 9, 9}),
		testPackedPRFRow(ringQ, []uint64{10, 10, 10, 10}),
		testPackedPRFRow(ringQ, []uint64{11, 11, 11, 11}),
	}

	rows, keySlots, sboxSlots, err := packPRFWitnessRows(
		ringQ,
		ncols,
		10,
		[]int64{1, 2, 3},
		sboxRows,
		func(head []uint64) *ring.Poly { return testPackedPRFRow(ringQ, head) },
	)
	if err != nil {
		t.Fatalf("packPRFWitnessRows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("packed row count=%d, want 2", len(rows))
	}
	if !reflect.DeepEqual(keySlots, []PRFSlot{{Row: 10, Col: 0}, {Row: 10, Col: 1}, {Row: 10, Col: 2}}) {
		t.Fatalf("key slots=%v", keySlots)
	}
	wantSBox := []PRFSlot{
		{Row: 10, Col: 3},
		{Row: 11, Col: 0},
		{Row: 11, Col: 1},
		{Row: 11, Col: 2},
		{Row: 11, Col: 3},
	}
	if !reflect.DeepEqual(sboxSlots, wantSBox) {
		t.Fatalf("sbox slots=%v want %v", sboxSlots, wantSBox)
	}
	gotHeads := buildRowInputs(ringQ, rows, ncols)
	if !reflect.DeepEqual(gotHeads[0].Head, []uint64{1, 2, 3, 7}) {
		t.Fatalf("row 0 head=%v", gotHeads[0].Head)
	}
	if !reflect.DeepEqual(gotHeads[1].Head, []uint64{8, 9, 10, 11}) {
		t.Fatalf("row 1 head=%v", gotHeads[1].Head)
	}
}

func TestPackPRFWitnessRowsRejectsNonConstantScalarRows(t *testing.T) {
	ringQ, err := ring.NewRing(2048, []uint64{12289})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	_, _, _, err = packPRFWitnessRows(
		ringQ,
		4,
		0,
		[]int64{1, 2},
		[]*ring.Poly{testPackedPRFRow(ringQ, []uint64{3, 4, 3, 4})},
		func(head []uint64) *ring.Poly { return testPackedPRFRow(ringQ, head) },
	)
	if err == nil {
		t.Fatalf("expected non-constant PRF scalar row error")
	}
}
