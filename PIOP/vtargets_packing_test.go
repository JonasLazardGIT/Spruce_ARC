package PIOP

import (
	"reflect"
	"testing"
)

func TestProofVTargetsPackingRaggedRoundTrip(t *testing.T) {
	proof := &Proof{
		Theta:         3,
		MaskRowOffset: 10,
	}
	mat := [][]uint64{
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{9, 10, 11, 12},
		{13, 14, 15, 16},
		{17, 18, 0, 0},
		{19, 20, 0, 0},
	}
	proof.setVTargets(mat)
	if len(proof.VTargetsBits) == 0 {
		t.Fatalf("missing packed VTargets bits")
	}
	if got := proof.VTargetsBits[9]; got != vTargetsFormatRagged {
		t.Fatalf("VTargets format=%d want ragged=%d", got, vTargetsFormatRagged)
	}
	decoded := proof.VTargetsMatrix()
	if !reflect.DeepEqual(decoded, mat) {
		t.Fatalf("decoded ragged VTargets mismatch:\n got=%v\nwant=%v", decoded, mat)
	}
}

func TestProofVTargetsPackingDenseFallbackRoundTrip(t *testing.T) {
	proof := &Proof{
		Theta:         3,
		MaskRowOffset: 10,
	}
	mat := [][]uint64{
		{1, 2, 3, 4},
		{5, 6, 7, 8},
		{9, 10, 11, 12},
		{13, 14, 15, 16},
		{17, 18, 21, 22},
		{19, 20, 23, 24},
	}
	proof.setVTargets(mat)
	if len(proof.VTargetsBits) == 0 {
		t.Fatalf("missing packed VTargets bits")
	}
	if got := proof.VTargetsBits[9]; got != vTargetsFormatDense {
		t.Fatalf("VTargets format=%d want dense=%d", got, vTargetsFormatDense)
	}
	decoded := proof.VTargetsMatrix()
	if !reflect.DeepEqual(decoded, mat) {
		t.Fatalf("decoded dense VTargets mismatch:\n got=%v\nwant=%v", decoded, mat)
	}
}

func TestProofVTargetsPackingRowWidthRoundTrip(t *testing.T) {
	proof := &Proof{VTargetsWidthCodec: true}
	mat := [][]uint64{
		{0, 1, 0, 1},
		{1, 0, 1, 0},
		{1 << 18, 1<<18 + 1, 1<<18 + 2, 1<<18 + 3},
		{0, 1, 1, 0},
		{1, 1, 0, 0},
	}
	proof.setVTargets(mat)
	if len(proof.VTargetsBits) == 0 {
		t.Fatalf("missing packed VTargets bits")
	}
	if got := proof.VTargetsBits[9]; got != vTargetsFormatRowWidths {
		t.Fatalf("VTargets format=%d want row-width=%d", got, vTargetsFormatRowWidths)
	}
	if decoded := proof.VTargetsMatrix(); !reflect.DeepEqual(decoded, mat) {
		t.Fatalf("decoded row-width VTargets mismatch:\n got=%v\nwant=%v", decoded, mat)
	}
}

func TestProofVTargetsPackingColumnWidthRoundTrip(t *testing.T) {
	proof := &Proof{VTargetsWidthCodec: true}
	mat := [][]uint64{
		{0, 1, 0, 1, 1 << 18},
		{1, 0, 1, 0, 1<<18 + 1},
		{0, 0, 1, 1, 1<<18 + 2},
		{1, 1, 0, 0, 1<<18 + 3},
	}
	proof.setVTargets(mat)
	if len(proof.VTargetsBits) == 0 {
		t.Fatalf("missing packed VTargets bits")
	}
	if got := proof.VTargetsBits[9]; got != vTargetsFormatColumnWidths {
		t.Fatalf("VTargets format=%d want column-width=%d", got, vTargetsFormatColumnWidths)
	}
	if decoded := proof.VTargetsMatrix(); !reflect.DeepEqual(decoded, mat) {
		t.Fatalf("decoded column-width VTargets mismatch:\n got=%v\nwant=%v", decoded, mat)
	}
}
