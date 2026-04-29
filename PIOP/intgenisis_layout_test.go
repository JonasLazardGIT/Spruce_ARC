package PIOP

import (
	"testing"

	"vSIS-Signature/credential"
)

func TestIntGenISISRowInventoryProfileB(t *testing.T) {
	inv, err := BuildIntGenISISRowInventory(credential.ProfileIntGenISISB, 16)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if inv.PreSignRingPolys != 6 || inv.PreSignRows != 192 {
		t.Fatalf("presign inventory=%d polys/%d rows, want 6/192", inv.PreSignRingPolys, inv.PreSignRows)
	}
	if inv.ShowingRingPolys != 13 || inv.ShowingNonPRFRows != 416 {
		t.Fatalf("showing inventory=%d polys/%d rows, want 13/416", inv.ShowingRingPolys, inv.ShowingNonPRFRows)
	}
}

func TestIntGenISISRowInventoryProfileA(t *testing.T) {
	inv, err := BuildIntGenISISRowInventory(credential.ProfileIntGenISISA, 16)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if inv.PreSignRingPolys != 8 || inv.PreSignRows != 128 {
		t.Fatalf("presign inventory=%d polys/%d rows, want 8/128", inv.PreSignRingPolys, inv.PreSignRows)
	}
	if inv.ShowingRingPolys != 15 || inv.ShowingNonPRFRows != 240 {
		t.Fatalf("showing inventory=%d polys/%d rows, want 15/240", inv.ShowingRingPolys, inv.ShowingNonPRFRows)
	}
}
