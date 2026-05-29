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

func TestIntGenISISRowInventoryProfileC(t *testing.T) {
	inv, err := BuildIntGenISISRowInventory(credential.ProfileIntGenISISC, 16)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if inv.PreSignRingPolys != 5 || inv.PreSignRows != 320 {
		t.Fatalf("presign inventory=%d polys/%d rows, want 5/320", inv.PreSignRingPolys, inv.PreSignRows)
	}
	if inv.ShowingRingPolys != 11 || inv.ShowingNonPRFRows != 704 {
		t.Fatalf("showing inventory=%d polys/%d rows, want 11/704", inv.ShowingRingPolys, inv.ShowingNonPRFRows)
	}
}
