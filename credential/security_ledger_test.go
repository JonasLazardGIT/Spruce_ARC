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
	if !containsString(ledger.RejectionReasons, "missing required ledger term zero_knowledge/tape_guessing") {
		t.Fatalf("missing tape term rejection not found: %+v", ledger.RejectionReasons)
	}
}

func TestIntGenISISSystemSecurityLedgerBQ32Tag7FailsTagTermAndTag9Passes(t *testing.T) {
	tag7 := EvaluateIntGenISISSystemSecurityLedger(bq32LedgerInputForTagElements(7))
	if !containsString(tag7.RejectionReasons, "tag collision bits below target") {
		t.Fatalf("tag7 rejection reasons=%v", tag7.RejectionReasons)
	}
	if countString(tag7.RejectionReasons, "tag collision bits below target") != 1 {
		t.Fatalf("duplicate tag rejection reasons=%v", tag7.RejectionReasons)
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

func TestIntGenISISProgrammingConflictBitsUsesSeparateResourceBound(t *testing.T) {
	caps := [4]uint64{1 << 32, 1 << 32, 1 << 32, 1 << 32}
	got := IntGenISISProgrammingConflictBits(168, caps)
	want := 168.0 - 32.0 - 2.0
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("programming conflict bits=%f want %f", got, want)
	}
	if got := IntGenISISProgrammingConflictBits(168, [4]uint64{}); got != 0 {
		t.Fatalf("empty programming caps bits=%f want 0", got)
	}
	if got := IntGenISISBudgetCollisionBits(168, nil); got != 0 {
		t.Fatalf("empty collision caps bits=%f want 0", got)
	}
	logCaps := [4]float64{32, 32, 32, 32}
	if got := IntGenISISProgrammingConflictBitsLog(168, logCaps); math.Abs(got-want) > 1e-9 {
		t.Fatalf("log programming conflict bits=%f want %f", got, want)
	}
}

func TestLedgerTermsAnnotateSourceAndReportOnlyDoesNotCompose(t *testing.T) {
	if got := ledgerCategoryBits(nil, SystemLedgerTermComposition); got != 0 {
		t.Fatalf("empty category bits=%f want 0", got)
	}
	bits := ledgerCategoryBits([]SystemSecurityLedgerTerm{
		ExactLedgerTerm(SystemLedgerTermSoundness, "independent", 100, true, ""),
		ReportOnlyLedgerTerm(ExactLedgerTerm(SystemLedgerTermSoundness, "diagnostic", 1, true, "")),
		ExactLedgerTerm(SystemLedgerTermSoundness, "inactive", 1, false, ""),
	}, SystemLedgerTermSoundness)
	if math.Abs(bits-100) > 1e-9 {
		t.Fatalf("inactive/report-only term affected category bits: %f", bits)
	}

	input := bq32LedgerInputForTagElements(9)
	input.Terms = append(input.Terms,
		ConservativeLedgerTerm(SystemLedgerTermZeroKnowledge, "programming_conflict", 130, true, ""),
		ReportOnlyLedgerTerm(ExactLedgerTerm(SystemLedgerTermSoundness, "full_game", 130, true, "")),
	)
	ledger := EvaluateIntGenISISSystemSecurityLedger(input)
	if got := termSource(ledger, SystemLedgerTermZeroKnowledge, "programming_conflict"); got != SystemLedgerTermSourceConservative {
		t.Fatalf("programming source=%q", got)
	}
	if got := termAccountingStatus(ledger, SystemLedgerTermZeroKnowledge, "programming_conflict"); got != SystemLedgerTermAccountingRequiresTheory {
		t.Fatalf("programming accounting status=%q", got)
	}
	if got := termSource(ledger, SystemLedgerTermSoundness, "full_game"); got != SystemLedgerTermSourceExact {
		t.Fatalf("full_game source=%q", got)
	}
	if got := termAccountingStatus(ledger, SystemLedgerTermSoundness, "full_game"); got != SystemLedgerTermAccountingCurrentTheorem {
		t.Fatalf("full_game accounting status=%q", got)
	}
	if !termReportOnly(ledger, SystemLedgerTermSoundness, "full_game") {
		t.Fatal("full_game diagnostic term should be report-only")
	}
}

func TestLedgerClassifiesTapeAndProgrammingAsZeroKnowledge(t *testing.T) {
	input := bq32LedgerInputForTagElements(9)
	input.FullGameBits = 94.97315413067203
	input.ProofBits = 96.00108084061016
	input.CollisionBits = 99.67807190511263
	input.ChallengeBiasBits = 168
	input.TapeGuessingBits = 96
	input.ProgrammingBits = 134
	input.Terms = []SystemSecurityLedgerTerm{
		ReportOnlyLedgerTerm(ExactLedgerTerm(SystemLedgerTermSoundness, "proof_theorem", input.ProofBits, true, "proof theorem bits below target")),
		ExactLedgerTerm(SystemLedgerTermSoundness, "issuance_smallwood_extraction", 96.02955882557683, true, "issuance SmallWood extraction bits below target"),
		ExactLedgerTerm(SystemLedgerTermSoundness, "showing_smallwood_extraction", 96.02955882557683, true, "showing SmallWood extraction bits below target"),
		ExactLedgerTerm(SystemLedgerTermSoundness, "ro_collision", input.CollisionBits, true, "global RO/Merkle collision bits below target"),
		ReportOnlyLedgerTerm(ExactLedgerTerm(SystemLedgerTermSoundness, "full_game", input.FullGameBits, true, "full-game bits below target")),
		ConservativeLedgerTerm(SystemLedgerTermSoundness, "challenge_bias", input.ChallengeBiasBits, true, "challenge-bias bits below target"),
		ExactLedgerTerm(SystemLedgerTermZeroKnowledge, "tape_guessing", input.TapeGuessingBits, true, "tape guessing bits below target"),
		ConservativeLedgerTerm(SystemLedgerTermZeroKnowledge, "programming_conflict", input.ProgrammingBits, true, "programming conflict bits below target"),
	}
	ledger := EvaluateIntGenISISSystemSecurityLedger(input)

	if term := ledgerTermByCategoryName(ledger, SystemLedgerTermZeroKnowledge, "tape_guessing"); term.Name == "" || term.Status != "pass" {
		t.Fatalf("tape term not classified as passing zero-knowledge term: %+v", term)
	}
	if term := ledgerTermByCategoryName(ledger, SystemLedgerTermZeroKnowledge, "programming_conflict"); term.Name == "" || term.Status != "pass" {
		t.Fatalf("programming term not classified as passing zero-knowledge term: %+v", term)
	}
	if term := ledgerTermByCategoryName(ledger, SystemLedgerTermSoundness, "tape_guessing"); term.Name != "" {
		t.Fatalf("tape term should not remain in soundness: %+v", term)
	}
	if math.Abs(ledger.SoundnessBits-94.97315413067203) > 1e-9 {
		t.Fatalf("soundness bits=%f want full-game-only blocker 94.97315413067203", ledger.SoundnessBits)
	}
	if ledger.ZeroKnowledgeBits <= 0 || ledgerBitsBelowTarget(ledger.ZeroKnowledgeBits, 96) {
		t.Fatalf("zero-knowledge bits should clear target after reclassification: %f", ledger.ZeroKnowledgeBits)
	}
	if !containsString(ledger.RejectionReasons, "full-game bits below target") {
		t.Fatalf("full-game rejection missing: %+v", ledger.RejectionReasons)
	}
	if containsString(ledger.RejectionReasons, "zero_knowledge ledger bits below target") {
		t.Fatalf("zero-knowledge category should not be the BQ32 blocker: %+v", ledger.RejectionReasons)
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

func TestIntGenISISLogResourceCapsRepresentBQ128RawBudget(t *testing.T) {
	spec, ok := LookupIntGenISISSecurityProfile("BQ128-128")
	if !ok {
		t.Fatal("missing BQ128-128 profile")
	}
	if len(spec.ROQueryCaps) != 0 {
		t.Fatalf("BQ128 uint64 caps should be empty, got %v", spec.ROQueryCaps)
	}
	logs := ROBudgetLogVectorFromProfile(spec)
	if logs.RawLog2 != 128 || logs.FSLog2 != [4]float64{128, 128, 128, 128} || logs.CollisionLog2 != 128 {
		t.Fatalf("BQ128 log caps=%+v", logs)
	}
	ledger := EvaluateIntGenISISSystemSecurityLedger(SystemSecurityLedgerInput{
		SecurityProfile:   "BQ128-128",
		FullGameBits:      300,
		ProofBits:         300,
		CollisionBits:     300,
		TagCollisionBits:  300,
		SaltCollisionBits: 384,
		TapeGuessingBits:  128,
		ProgrammingBits:   300,
		ChallengeBiasBits: 512,
		MultiUserBits:     300,
		MultiContextBits:  300,
		PRFBits:           133,
		MLWEBits:          131,
		ReplayRejected:    true,
	})
	if ledger.ROBudgetLogs.RawLog2 != 128 || ledger.ROBudgetLogs.FSLog2[0] != 128 {
		t.Fatalf("ledger did not retain BQ128 log caps: %+v", ledger.ROBudgetLogs)
	}
}

func TestValidPrefixLogCapsRequireExplicitTheoremMode(t *testing.T) {
	input := bq32LedgerInputForTagElements(9)
	rawCollision := IntGenISISBudgetCollisionBitsLog(168, []float64{32, 32, 32, 32, 32})
	withValid := IntGenISISBudgetCollisionBitsLog(168, []float64{32, 32, 32, 32, 32})
	if math.Abs(rawCollision-withValid) > 1e-9 {
		t.Fatalf("valid-prefix caps should not affect raw collision bits: raw=%f valid=%f", rawCollision, withValid)
	}
	input.ROBudgetLogs = ROBudgetLogVectorFromProfile(IntGenISISSecurityProfileSpec{ROQueryCapBits: []float64{32, 32, 32, 32, 32}})
	input.ROBudgetLogs.ValidPrefixLog2 = [4]float64{20, 20, 20, 20}
	ledger := EvaluateIntGenISISSystemSecurityLedger(input)
	if !ledger.ValidPrefixConservative {
		t.Fatalf("valid-prefix caps should stay conservative until theorem mode is explicit: %+v", ledger.ValidPrefixAccounting)
	}
	if ledger.ROBudgetLogs.ValidPrefixLog2 != [4]float64{20, 20, 20, 20} {
		t.Fatalf("valid-prefix log caps not retained: %+v", ledger.ROBudgetLogs)
	}
	if ledger.ValidPrefixAccounting.TheoremMode != ValidPrefixTheoremModeCurrentRaw || ledger.ValidPrefixAccounting.UsesValidPrefixAccounting {
		t.Fatalf("valid-prefix caps should not affect current-theorem accounting: %+v", ledger.ValidPrefixAccounting)
	}

	input.UseValidPrefixAlgebraicCaps = true
	theoremCandidate := EvaluateIntGenISISSystemSecurityLedger(input)
	if theoremCandidate.ValidPrefixConservative || !theoremCandidate.ValidPrefixAccounting.UsesValidPrefixAccounting {
		t.Fatalf("explicit theorem mode should use valid-prefix algebraic caps: %+v", theoremCandidate.ValidPrefixAccounting)
	}
	if theoremCandidate.ValidPrefixAccounting.EffectiveAlgebraicCapLog2 != [4]float64{20, 20, 20, 20} {
		t.Fatalf("effective algebraic caps=%+v", theoremCandidate.ValidPrefixAccounting.EffectiveAlgebraicCapLog2)
	}
	if theoremCandidate.ValidPrefixAccounting.CollisionCapLog2 != 32 || theoremCandidate.ValidPrefixAccounting.ProgrammingCapLog2 != [4]float64{32, 32, 32, 32} {
		t.Fatalf("raw collision/programming caps changed: %+v", theoremCandidate.ValidPrefixAccounting)
	}
	if !containsString(theoremCandidate.RejectionReasons, ValidPrefixTheoremRequiredReason) {
		t.Fatalf("theorem-candidate ledger should remain blocked: %+v", theoremCandidate.RejectionReasons)
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

func termSource(ledger SystemSecurityLedger, category, name string) string {
	for _, term := range ledger.Terms {
		if term.Category == category && term.Name == name {
			return term.Source
		}
	}
	return ""
}

func termAccountingStatus(ledger SystemSecurityLedger, category, name string) string {
	for _, term := range ledger.Terms {
		if term.Category == category && term.Name == name {
			return term.AccountingStatus
		}
	}
	return ""
}

func termReportOnly(ledger SystemSecurityLedger, category, name string) bool {
	for _, term := range ledger.Terms {
		if term.Category == category && term.Name == name {
			return term.ReportOnly
		}
	}
	return false
}

func ledgerTermByCategoryName(ledger SystemSecurityLedger, category, name string) SystemSecurityLedgerTerm {
	for _, term := range ledger.Terms {
		if term.Category == category && term.Name == name {
			return term
		}
	}
	return SystemSecurityLedgerTerm{}
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func countString(vals []string, want string) int {
	count := 0
	for _, v := range vals {
		if v == want {
			count++
		}
	}
	return count
}
