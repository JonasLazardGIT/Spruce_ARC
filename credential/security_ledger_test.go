package credential

import (
	"math"
	"testing"
)

func TestIntGenISISTagCollisionBitsShowsTag9BQ32Margin(t *testing.T) {
	q := uint64(IntGenISISSharedModulusQ)
	q32 := uint64(1) << 32
	tag7 := IntGenISISTagCollisionBits(q, 7, q32)
	tag9 := IntGenISISTagCollisionBits(q, 9, q32)
	if tag7 >= 96 {
		t.Fatalf("tag7 collision bits=%f should not clear BQ32-96", tag7)
	}
	if tag9 < 96 {
		t.Fatalf("tag9 collision bits=%f want >=96", tag9)
	}
	wantDelta := 2 * math.Log2(float64(q))
	if math.Abs((tag9-tag7)-wantDelta) > 1e-9 {
		t.Fatalf("tag delta=%f want %f", tag9-tag7, wantDelta)
	}
}

func TestIntGenISISSystemSecurityLedgerFailsClosedForCandidates(t *testing.T) {
	ledger := EvaluateIntGenISISSystemSecurityLedger(SystemSecurityLedgerInput{
		SecurityProfile:   "BQ32-96",
		FullGameBits:      100,
		TagCollisionBits:  100,
		SaltCollisionBits: 128,
		PRFBits:           133,
		MLWEBits:          131,
		ReplayRejected:    true,
	})
	if ledger.LedgerStatus != string(SecurityProfileCandidate) {
		t.Fatalf("ledger status=%q want candidate", ledger.LedgerStatus)
	}
	if ledger.CompleteSystemClaim {
		t.Fatal("candidate ledger should not be complete")
	}
	if len(ledger.RejectionReasons) == 0 {
		t.Fatal("candidate ledger should explain rejection")
	}
}

func TestIntGenISISSystemSecurityLedgerRejectsNewPrimitiveProfiles(t *testing.T) {
	ledger := EvaluateIntGenISISSystemSecurityLedger(SystemSecurityLedgerInput{
		SecurityProfile:   "BQ32-128",
		FullGameBits:      128,
		TagCollisionBits:  128,
		SaltCollisionBits: 192,
		PRFBits:           133,
		MLWEBits:          131,
		ReplayRejected:    true,
	})
	if ledger.LedgerStatus != string(SecurityProfileRequiresNewPrimitives) {
		t.Fatalf("ledger status=%q want requires_new_primitives", ledger.LedgerStatus)
	}
	if ledger.CoreAvailableBits >= ledger.CoreBitsRequired {
		t.Fatalf("core bits unexpectedly satisfy blocked profile: %+v", ledger)
	}
}
