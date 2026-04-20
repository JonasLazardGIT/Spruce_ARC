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
