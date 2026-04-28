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
	if inv.PreSignRingPolys != 4 || inv.PreSignRows != 128 {
		t.Fatalf("presign inventory=%d polys/%d rows, want 4/128", inv.PreSignRingPolys, inv.PreSignRows)
	}
	if inv.ShowingRingPolys != 11 || inv.ShowingNonPRFRows != 352 {
		t.Fatalf("showing inventory=%d polys/%d rows, want 11/352", inv.ShowingRingPolys, inv.ShowingNonPRFRows)
	}
}

func TestIntGenISISRowInventoryProfileA(t *testing.T) {
	inv, err := BuildIntGenISISRowInventory(credential.ProfileIntGenISISA, 16)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if inv.PreSignRingPolys != 6 || inv.PreSignRows != 96 {
		t.Fatalf("presign inventory=%d polys/%d rows, want 6/96", inv.PreSignRingPolys, inv.PreSignRows)
	}
	if inv.ShowingRingPolys != 13 || inv.ShowingNonPRFRows != 208 {
		t.Fatalf("showing inventory=%d polys/%d rows, want 13/208", inv.ShowingRingPolys, inv.ShowingNonPRFRows)
	}
}
