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
	if len(ledger.Terms) == 0 {
		t.Fatal("candidate ledger should expose ledger terms")
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

func TestIntGenISISSystemSecurityLedgerRejectsMissingRequiredTerms(t *testing.T) {
	ledger := EvaluateIntGenISISSystemSecurityLedger(SystemSecurityLedgerInput{
		SecurityProfile:  "BQ32-96",
		FullGameBits:     110,
		TagCollisionBits: 120,
		PRFBits:          133,
		MLWEBits:         131,
		ReplayRejected:   true,
	})
	if !containsString(ledger.RejectionReasons, "missing required ledger term correctness/salt_collision") {
		t.Fatalf("missing salt term rejection not found: %+v", ledger.RejectionReasons)
	}
	if !containsString(ledger.RejectionReasons, "missing required ledger term soundness/tape_guessing") {
		t.Fatalf("missing tape term rejection not found: %+v", ledger.RejectionReasons)
	}
}

func TestIntGenISISSystemSecurityLedgerBQ32Tag7FailsTagTermAndTag9Passes(t *testing.T) {
	tag7 := EvaluateIntGenISISSystemSecurityLedger(bq32LedgerInputForTagElements(7))
	if !containsString(tag7.RejectionReasons, "tag collision bits below target") {
		t.Fatalf("tag7 rejection reasons=%v", tag7.RejectionReasons)
	}
	if termStatus(tag7, SystemLedgerTermUnlinkability, "tag_collision") != "below_target" {
		t.Fatalf("tag7 term status=%q", termStatus(tag7, SystemLedgerTermUnlinkability, "tag_collision"))
	}

	tag9 := EvaluateIntGenISISSystemSecurityLedger(bq32LedgerInputForTagElements(9))
	if termStatus(tag9, SystemLedgerTermUnlinkability, "tag_collision") != "pass" {
		t.Fatalf("tag9 term status=%q reasons=%v", termStatus(tag9, SystemLedgerTermUnlinkability, "tag_collision"), tag9.RejectionReasons)
	}
	if tag9.LedgerStatus != string(SecurityProfileCandidate) || tag9.CompleteSystemClaim {
		t.Fatalf("tag9 BQ32 should remain candidate-only: %+v", tag9)
	}
}

func TestLogMathHelpersComposeProbabilities(t *testing.T) {
	if got := Log2Binom(8, 2); math.Abs(got-math.Log2(28)) > 1e-12 {
		t.Fatalf("Log2Binom(8,2)=%f", got)
	}
	sum := Log2SumExp([]float64{-100, -100})
	if math.Abs(BitsFromLog2Prob(sum)-99) > 1e-9 {
		t.Fatalf("two 100-bit events composed to %f bits", BitsFromLog2Prob(sum))
	}
}

func TestIntGenISISResourceDefaultsUseRawROCapsConservatively(t *testing.T) {
	spec, ok := LookupIntGenISISSecurityProfile("BQ32-96")
	if !ok {
		t.Fatal("missing BQ32-96 profile")
	}
	scope := DefaultIntGenISISAdversaryScope(spec)
	if scope.TagsPerContext != 1<<32 || scope.PRFAttempts != 1<<32 || scope.Users != 1 || scope.Contexts != 1 {
		t.Fatalf("scope defaults=%+v", scope)
	}
	budgets := ROBudgetVectorFromCaps(spec.ROQueryCaps)
	if budgets.Merkle != 1<<32 || budgets.FS[0] != 1<<32 || budgets.GuessTape != 1<<32 {
		t.Fatalf("budget defaults=%+v", budgets)
	}
	ledger := EvaluateIntGenISISSystemSecurityLedger(bq32LedgerInputForTagElements(9))
	if !ledger.ValidPrefixConservative {
		t.Fatal("unset valid-prefix caps should be reported as conservative")
	}
}

func bq32LedgerInputForTagElements(tagElements int) SystemSecurityLedgerInput {
	spec, _ := LookupIntGenISISSecurityProfile("BQ32-96")
	scope := DefaultIntGenISISAdversaryScope(spec)
	tagBits := IntGenISISTagCollisionBits(IntGenISISSharedModulusQ, tagElements, scope.TagsPerContext)
	return SystemSecurityLedgerInput{
		SecurityProfile:   "BQ32-96",
		FullGameBits:      130,
		ProofBits:         130,
		CollisionBits:     130,
		TagCollisionBits:  tagBits,
		SaltCollisionBits: IntGenISISSaltCollisionBits(128, scope.Proofs),
		TapeGuessingBits:  IntGenISISTapeGuessingBits(128, scope.TagsPerContext),
		ProgrammingBits:   130,
		ChallengeBiasBits: 130,
		MultiUserBits:     130,
		MultiContextBits:  130,
		PRFBits:           133,
		MLWEBits:          131,
		ReplayRejected:    true,
		Scope:             scope,
		ROBudgets:         ROBudgetVectorFromCaps(spec.ROQueryCaps),
	}
}

func termStatus(ledger SystemSecurityLedger, category, name string) string {
	for _, term := range ledger.Terms {
		if term.Category == category && term.Name == name {
			return term.Status
		}
	}
	return ""
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
