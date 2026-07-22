package credential

import (
	"fmt"
	"math"
)

const (
	SystemLedgerTermSoundness     = "soundness"
	SystemLedgerTermUnlinkability = "unlinkability"
	SystemLedgerTermCorrectness   = "correctness"
	SystemLedgerTermPrimitive     = "primitive"
	SystemLedgerTermComposition   = "composition"
	SystemLedgerTermZeroKnowledge = "zero_knowledge"
	SystemLedgerTermModelScope    = "model_scope"

	SystemLedgerTermSourceMeasured     = "measured"
	SystemLedgerTermSourceExactTheorem = "exact_theorem"
	SystemLedgerTermSourceEstimator    = "estimator"
	SystemLedgerTermSourceConservative = "conservative"
	SystemLedgerTermSourceMissing      = "missing"
	SystemLedgerTermSourceExact        = SystemLedgerTermSourceExactTheorem

	SystemLedgerTermAccountingCurrentTheorem = "current_theorem_accounting"
	SystemLedgerTermAccountingRequiresTheory = "requires_theorem_accounting"
)

type ROBudgetVector struct {
	Merkle             uint64    `json:"merkle,omitempty"`
	FS                 [4]uint64 `json:"fs,omitempty"`
	ChallengeExpansion [4]uint64 `json:"challenge_expansion,omitempty"`
	GuessTape          uint64    `json:"guess_tape,omitempty"`
	Programming        [4]uint64 `json:"programming,omitempty"`
	ValidPrefixes      [4]uint64 `json:"valid_prefixes,omitempty"`
}

type ROBudgetLogVector struct {
	RawLog2                float64    `json:"raw_log2,omitempty"`
	MerkleLog2             float64    `json:"merkle_log2,omitempty"`
	FSLog2                 [4]float64 `json:"fs_log2,omitempty"`
	ChallengeExpansionLog2 [4]float64 `json:"challenge_expansion_log2,omitempty"`
	GuessTapeLog2          float64    `json:"guess_tape_log2,omitempty"`
	ProgrammingLog2        [4]float64 `json:"programming_log2,omitempty"`
	CollisionLog2          float64    `json:"collision_log2,omitempty"`
	ValidPrefixLog2        [4]float64 `json:"valid_prefix_log2,omitempty"`
}

type AdversaryScope struct {
	IssuanceQueries uint64 `json:"issuance_queries,omitempty"`
	Presentations   uint64 `json:"presentations,omitempty"`
	Verifications   uint64 `json:"verifications,omitempty"`
	PRFAttempts     uint64 `json:"prf_attempts,omitempty"`
	Users           uint64 `json:"users,omitempty"`
	Contexts        uint64 `json:"contexts,omitempty"`
	TagsPerContext  uint64 `json:"tags_per_context,omitempty"`
	Proofs          uint64 `json:"proofs,omitempty"`
}

type AdversaryScopeLog2 struct {
	IssuanceQueriesLog2 float64 `json:"issuance_queries_log2"`
	PresentationsLog2   float64 `json:"presentations_log2"`
	VerificationsLog2   float64 `json:"verifications_log2"`
	PRFAttemptsLog2     float64 `json:"prf_attempts_log2"`
	UsersLog2           float64 `json:"users_log2"`
	ContextsLog2        float64 `json:"contexts_log2"`
	TagsPerContextLog2  float64 `json:"tags_per_context_log2"`
	ProofsLog2          float64 `json:"proofs_log2"`
}

type SystemSecurityLedgerTerm struct {
	Category          string  `json:"category"`
	Name              string  `json:"name"`
	Bits              float64 `json:"bits,omitempty"`
	ActualBits        float64 `json:"actual_bits"`
	RequiredBits      float64 `json:"required_bits"`
	ActualValue       string  `json:"actual_value,omitempty"`
	RequiredValue     string  `json:"required_value,omitempty"`
	Required          bool    `json:"required,omitempty"`
	Conservative      bool    `json:"conservative,omitempty"`
	ReportOnly        bool    `json:"report_only,omitempty"`
	Source            string  `json:"source,omitempty"`
	AccountingStatus  string  `json:"accounting_status,omitempty"`
	Status            string  `json:"status,omitempty"`
	RejectionReason   string  `json:"rejection_reason,omitempty"`
	EvidenceReference string  `json:"evidence_reference,omitempty"`
	Scope             string  `json:"scope,omitempty"`
	Note              string  `json:"note,omitempty"`
}

type SystemSecurityLedgerInput struct {
	SecurityProfile             string
	SecurityMode                string
	ROMModel                    ROMModel
	CompleteSystemClaim         bool
	TargetBits                  float64
	CoreBitsRequired            float64
	CoreAvailableBits           float64
	ProofBits                   float64
	FullGameBits                float64
	CollisionBits               float64
	TagCollisionBits            float64
	SaltCollisionBits           float64
	TapeGuessingBits            float64
	ProgrammingBits             float64
	ChallengeBiasBits           float64
	MultiUserBits               float64
	MultiContextBits            float64
	PRFBits                     float64
	MLWEBits                    float64
	MSISBindingBits             float64
	SignatureBits               float64
	SeedEntropyBits             float64
	ReplayRejected              bool
	ROBudgets                   ROBudgetVector
	ROBudgetLogs                ROBudgetLogVector
	UseValidPrefixAlgebraicCaps bool
	Scope                       AdversaryScope
	ScopeLog2                   AdversaryScopeLog2
	ParameterAudit              IntGenISISSecurityParameterAudit
	Terms                       []SystemSecurityLedgerTerm
}

type SystemSecurityLedger struct {
	SecurityProfile         string                           `json:"security_profile"`
	SecurityMode            string                           `json:"security_mode"`
	ROMModel                ROMModel                         `json:"rom_model,omitempty"`
	CompleteSystemClaim     bool                             `json:"complete_system_claim"`
	TargetBits              float64                          `json:"target_bits"`
	CoreBitsRequired        float64                          `json:"core_required_bits"`
	CoreAvailableBits       float64                          `json:"core_available_bits"`
	ProofBits               float64                          `json:"proof_bits"`
	FullGameBits            float64                          `json:"full_game_bits"`
	CollisionBits           float64                          `json:"collision_bits"`
	TagCollisionBits        float64                          `json:"tag_collision_bits"`
	SaltCollisionBits       float64                          `json:"salt_collision_bits"`
	TapeGuessingBits        float64                          `json:"tape_guessing_bits,omitempty"`
	ProgrammingConflictBits float64                          `json:"programming_conflict_bits,omitempty"`
	ChallengeBiasBits       float64                          `json:"challenge_bias_bits,omitempty"`
	MultiUserLossBits       float64                          `json:"multi_user_loss_bits,omitempty"`
	MultiContextLossBits    float64                          `json:"multi_context_loss_bits,omitempty"`
	SoundnessBits           float64                          `json:"soundness_bits,omitempty"`
	UnlinkabilityBits       float64                          `json:"unlinkability_bits,omitempty"`
	CorrectnessBits         float64                          `json:"correctness_bits,omitempty"`
	PrimitiveBits           float64                          `json:"primitive_bits,omitempty"`
	CompositionBits         float64                          `json:"composition_bits,omitempty"`
	ZeroKnowledgeBits       float64                          `json:"zero_knowledge_bits,omitempty"`
	PRFBits                 float64                          `json:"prf_bits"`
	MLWEBits                float64                          `json:"mlwe_bits"`
	MSISBindingBits         float64                          `json:"msis_binding_bits,omitempty"`
	SignatureBits           float64                          `json:"signature_bits,omitempty"`
	SeedEntropyBits         float64                          `json:"seed_entropy_bits,omitempty"`
	ROBudgets               ROBudgetVector                   `json:"ro_budgets,omitempty"`
	ROBudgetLogs            ROBudgetLogVector                `json:"ro_budget_logs,omitempty"`
	AdversaryScope          AdversaryScope                   `json:"adversary_scope,omitempty"`
	AdversaryScopeLog2      AdversaryScopeLog2               `json:"adversary_scope_log2,omitempty"`
	ParameterAudit          IntGenISISSecurityParameterAudit `json:"parameter_audit"`
	ValidPrefixConservative bool                             `json:"valid_prefix_conservative,omitempty"`
	ValidPrefixAccounting   ValidPrefixAlgebraicAccounting   `json:"valid_prefix_accounting,omitempty"`
	Terms                   []SystemSecurityLedgerTerm       `json:"ledger_terms,omitempty"`
	LedgerStatus            string                           `json:"ledger_status"`
	RejectionReasons        []string                         `json:"ledger_rejection_reasons,omitempty"`
}

func EvaluateIntGenISISSystemSecurityLedger(input SystemSecurityLedgerInput) SystemSecurityLedger {
	spec, _ := LookupIntGenISISSecurityProfile(input.SecurityProfile)
	targetBits := input.TargetBits
	if targetBits <= 0 {
		targetBits = spec.TargetBits
	}
	coreRequired := input.CoreBitsRequired
	if coreRequired <= 0 {
		coreRequired = spec.CoreBitsRequired
	}
	coreAvailable := input.CoreAvailableBits
	if coreAvailable <= 0 {
		coreAvailable = minPositiveFloat64(input.PRFBits, input.MLWEBits)
	}
	fullGameBits := input.FullGameBits
	if fullGameBits <= 0 {
		fullGameBits = minPositiveFloat64(input.ProofBits, input.CollisionBits)
	}
	mode := input.SecurityMode
	if mode == "" {
		mode = string(spec.Mode)
	}
	scope := normalizeAdversaryScope(input.Scope)
	budgets := input.ROBudgets
	budgetLogs := input.ROBudgetLogs
	if isZeroROBudgetLogVector(budgetLogs) && !isZeroROBudgetVector(budgets) {
		budgetLogs = ROBudgetLogVectorFromBudgetVector(budgets)
	}
	validPrefixAccounting := SmallWoodValidPrefixAccounting(budgetLogs, input.UseValidPrefixAlgebraicCaps)
	ledger := SystemSecurityLedger{
		SecurityProfile:         input.SecurityProfile,
		SecurityMode:            mode,
		ROMModel:                input.ROMModel,
		CompleteSystemClaim:     false,
		TargetBits:              targetBits,
		CoreBitsRequired:        coreRequired,
		CoreAvailableBits:       coreAvailable,
		ProofBits:               input.ProofBits,
		FullGameBits:            fullGameBits,
		CollisionBits:           input.CollisionBits,
		TagCollisionBits:        input.TagCollisionBits,
		SaltCollisionBits:       input.SaltCollisionBits,
		TapeGuessingBits:        input.TapeGuessingBits,
		ProgrammingConflictBits: input.ProgrammingBits,
		ChallengeBiasBits:       input.ChallengeBiasBits,
		MultiUserLossBits:       input.MultiUserBits,
		MultiContextLossBits:    input.MultiContextBits,
		PRFBits:                 input.PRFBits,
		MLWEBits:                input.MLWEBits,
		MSISBindingBits:         input.MSISBindingBits,
		SignatureBits:           input.SignatureBits,
		SeedEntropyBits:         input.SeedEntropyBits,
		ROBudgets:               budgets,
		ROBudgetLogs:            budgetLogs,
		AdversaryScope:          scope,
		AdversaryScopeLog2:      input.ScopeLog2,
		ParameterAudit:          input.ParameterAudit,
		ValidPrefixConservative: validPrefixAccounting.ConservativeRawFallback,
		ValidPrefixAccounting:   validPrefixAccounting,
		LedgerStatus:            string(spec.Status),
	}
	if input.SecurityProfile == "" || spec.Label == "" {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "missing security profile")
		ledger.LedgerStatus = "rejected"
		return ledger
	}

	ledger.Terms = finalizeLedgerTerms(systemSecurityLedgerTerms(input, coreAvailable, spec), targetBits, coreRequired)
	ledger.SoundnessBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermSoundness)
	ledger.UnlinkabilityBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermUnlinkability)
	ledger.CorrectnessBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermCorrectness)
	ledger.PrimitiveBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermPrimitive)
	ledger.CompositionBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermComposition)
	ledger.ZeroKnowledgeBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermZeroKnowledge)

	if spec.Status != SecurityProfileCompleteLive {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "profile status is "+string(spec.Status))
	}
	if input.ParameterAudit.SecurityProfile != "" {
		ledger.RejectionReasons = append(ledger.RejectionReasons, SecurityParameterAuditRejectionReasons(input.ParameterAudit)...)
	} else if input.CompleteSystemClaim {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "missing executed-parameter audit")
	}
	if (len(spec.ROQueryCaps) > 0 || len(spec.ROQueryCapBits) > 0) && isZeroROBudgetVector(budgets) && isZeroROBudgetLogVector(budgetLogs) {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "missing actual RO query budget metadata")
	}
	if targetBits <= 0 {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "missing target bits")
	}
	if coreAvailable > 0 && coreRequired > 0 && ledgerBitsBelowTarget(coreAvailable, coreRequired) {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "primitive core below required bits")
	}
	if fullGameBits > 0 && targetBits > 0 && ledgerBitsBelowTarget(fullGameBits, targetBits) {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "full-game bits below target")
	}
	if input.TagCollisionBits > 0 && targetBits > 0 && ledgerBitsBelowTarget(input.TagCollisionBits, targetBits) {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "tag collision bits below target")
	}
	if input.SaltCollisionBits > 0 && targetBits > 0 && ledgerBitsBelowTarget(input.SaltCollisionBits, targetBits) {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "salt collision bits below target")
	}
	if !input.ReplayRejected {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "replay rejection did not pass")
	}
	if validPrefixAccounting.RequiresTheoremAccounting {
		ledger.RejectionReasons = append(ledger.RejectionReasons, validPrefixAccounting.RejectionReason)
	}
	ledger.RejectionReasons = append(ledger.RejectionReasons, ledgerTermRejectionReasons(ledger.Terms)...)
	ledger.RejectionReasons = append(ledger.RejectionReasons, ledgerTermReadinessReasons(ledger.Terms)...)
	if targetBits > 0 {
		for _, category := range []struct {
			name string
			bits float64
		}{
			{"soundness", ledger.SoundnessBits},
			{"unlinkability", ledger.UnlinkabilityBits},
			{"correctness", ledger.CorrectnessBits},
			{"primitive", ledger.PrimitiveBits},
			{"composition", ledger.CompositionBits},
			{"zero_knowledge", ledger.ZeroKnowledgeBits},
		} {
			if category.bits > 0 && ledgerBitsBelowTarget(category.bits, targetBits) {
				ledger.RejectionReasons = append(ledger.RejectionReasons, category.name+" ledger bits below target")
			}
		}
	}
	ledger.RejectionReasons = uniqueStrings(ledger.RejectionReasons)
	if len(ledger.RejectionReasons) == 0 {
		ledger.LedgerStatus = string(SecurityProfileCompleteLive)
		ledger.CompleteSystemClaim = input.CompleteSystemClaim
	}
	return ledger
}

func ROBudgetVectorFromCaps(caps []uint64) ROBudgetVector {
	var out ROBudgetVector
	if len(caps) > 0 {
		out.Merkle = caps[0]
	}
	for i := 0; i < len(out.FS) && i+1 < len(caps); i++ {
		out.FS[i] = caps[i+1]
		out.ChallengeExpansion[i] = caps[i+1]
		out.Programming[i] = caps[i+1]
		if caps[i+1] > out.GuessTape {
			out.GuessTape = caps[i+1]
		}
	}
	if out.GuessTape == 0 {
		out.GuessTape = maxUint64Slice(caps)
	}
	return out
}

func ROBudgetLogVectorFromCapBits(capBits []float64) ROBudgetLogVector {
	var out ROBudgetLogVector
	if len(capBits) > 0 {
		out.MerkleLog2 = capBits[0]
		out.RawLog2 = maxPositiveFloat64(out.RawLog2, capBits[0])
		out.CollisionLog2 = maxPositiveFloat64(out.CollisionLog2, capBits[0])
	}
	for i := 0; i < len(out.FSLog2) && i+1 < len(capBits); i++ {
		cap := capBits[i+1]
		out.FSLog2[i] = cap
		out.ChallengeExpansionLog2[i] = cap
		out.ProgrammingLog2[i] = cap
		out.GuessTapeLog2 = maxPositiveFloat64(out.GuessTapeLog2, cap)
		out.RawLog2 = maxPositiveFloat64(out.RawLog2, cap)
		out.CollisionLog2 = maxPositiveFloat64(out.CollisionLog2, cap)
	}
	if out.GuessTapeLog2 == 0 {
		out.GuessTapeLog2 = maxPositiveFloat64Slice(capBits)
	}
	if out.RawLog2 == 0 {
		out.RawLog2 = maxPositiveFloat64Slice(capBits)
	}
	if out.CollisionLog2 == 0 {
		out.CollisionLog2 = out.RawLog2
	}
	return out
}

func ROBudgetLogVectorFromBudgetVector(v ROBudgetVector) ROBudgetLogVector {
	var out ROBudgetLogVector
	if v.Merkle > 0 {
		out.MerkleLog2 = math.Log2(float64(v.Merkle))
		out.RawLog2 = maxPositiveFloat64(out.RawLog2, out.MerkleLog2)
		out.CollisionLog2 = maxPositiveFloat64(out.CollisionLog2, out.MerkleLog2)
	}
	if v.GuessTape > 0 {
		out.GuessTapeLog2 = math.Log2(float64(v.GuessTape))
		out.RawLog2 = maxPositiveFloat64(out.RawLog2, out.GuessTapeLog2)
	}
	for i := range v.FS {
		if v.FS[i] > 0 {
			out.FSLog2[i] = math.Log2(float64(v.FS[i]))
			out.RawLog2 = maxPositiveFloat64(out.RawLog2, out.FSLog2[i])
			out.CollisionLog2 = maxPositiveFloat64(out.CollisionLog2, out.FSLog2[i])
		}
		if v.ChallengeExpansion[i] > 0 {
			out.ChallengeExpansionLog2[i] = math.Log2(float64(v.ChallengeExpansion[i]))
			out.RawLog2 = maxPositiveFloat64(out.RawLog2, out.ChallengeExpansionLog2[i])
		}
		if v.Programming[i] > 0 {
			out.ProgrammingLog2[i] = math.Log2(float64(v.Programming[i]))
			out.RawLog2 = maxPositiveFloat64(out.RawLog2, out.ProgrammingLog2[i])
		}
		if v.ValidPrefixes[i] > 0 {
			out.ValidPrefixLog2[i] = math.Log2(float64(v.ValidPrefixes[i]))
		}
	}
	if out.CollisionLog2 == 0 {
		out.CollisionLog2 = out.RawLog2
	}
	return out
}

func IntGenISISTagCollisionBitsLog(q uint64, tagElements int, tagsPerContextLog2 float64) float64 {
	if q <= 1 || tagElements <= 0 {
		return 0
	}
	spaceBits := float64(tagElements) * math.Log2(float64(q))
	return spaceBits - log2BinomFromCountLog2(tagsPerContextLog2)
}

func IntGenISISSaltCollisionBitsLog(saltBits int, proofsLog2 float64) float64 {
	if saltBits <= 0 {
		return 0
	}
	return float64(saltBits) - log2BinomFromCountLog2(proofsLog2)
}

func IntGenISISTapeGuessingBits(tapeBits int, guesses uint64) float64 {
	if tapeBits <= 0 {
		return 0
	}
	if guesses <= 1 {
		return float64(tapeBits)
	}
	return float64(tapeBits) - math.Log2(float64(guesses))
}

func IntGenISISTapeGuessingBitsLog(tapeBits int, guessLog2 float64) float64 {
	if tapeBits <= 0 {
		return 0
	}
	if guessLog2 <= 0 {
		return float64(tapeBits)
	}
	return float64(tapeBits) - guessLog2
}

func AdversaryScopesFromThreatModel(model PresetThreatModel) (AdversaryScope, AdversaryScopeLog2) {
	logs := AdversaryScopeLog2{
		IssuanceQueriesLog2: model.MaxIssuanceProofsLog2,
		PresentationsLog2:   model.MaxShowingProofsLog2,
		VerificationsLog2:   model.MaxProofsLog2,
		PRFAttemptsLog2:     model.MaxTagsPerContextLog2,
		UsersLog2:           model.MaxUsersLog2,
		ContextsLog2:        model.MaxContextsLog2,
		TagsPerContextLog2:  model.MaxTagsPerContextLog2,
		ProofsLog2:          model.MaxProofsLog2,
	}
	scope := AdversaryScope{
		IssuanceQueries: countFromLog2(model.MaxIssuanceProofsLog2),
		Presentations:   countFromLog2(model.MaxShowingProofsLog2),
		Verifications:   countFromLog2(model.MaxProofsLog2),
		PRFAttempts:     countFromLog2(model.MaxTagsPerContextLog2),
		Users:           countFromLog2(model.MaxUsersLog2),
		Contexts:        countFromLog2(model.MaxContextsLog2),
		TagsPerContext:  countFromLog2(model.MaxTagsPerContextLog2),
		Proofs:          countFromLog2(model.MaxProofsLog2),
	}
	return scope, logs
}

func log2BinomFromCountLog2(countLog2 float64) float64 {
	if countLog2 <= 0 {
		return 0
	}
	if countLog2 <= 52 {
		count := uint64(math.Round(math.Exp2(countLog2)))
		if count < 2 {
			return 0
		}
		return Log2Binom(count, 2)
	}
	// log2(n(n-1)/2), evaluated without materializing n.
	return 2*countLog2 - 1 + math.Log2(1-math.Exp2(-countLog2))
}

func countFromLog2(countLog2 float64) uint64 {
	if countLog2 <= 0 {
		return 1
	}
	if countLog2 >= 63 {
		return 0
	}
	return uint64(math.Round(math.Exp2(countLog2)))
}

func IntGenISISProgrammingConflictBits(widthBits int, caps [4]uint64) float64 {
	if widthBits <= 0 {
		return 0
	}
	logTerms := make([]float64, 0, len(caps))
	for _, cap := range caps {
		if cap == 0 {
			continue
		}
		logTerms = append(logTerms, math.Log2(float64(cap))-float64(widthBits))
	}
	if len(logTerms) == 0 {
		return 0
	}
	return BitsFromLog2Prob(Log2SumExp(logTerms))
}

func IntGenISISProgrammingConflictBitsLog(widthBits int, caps [4]float64) float64 {
	if widthBits <= 0 {
		return 0
	}
	logTerms := make([]float64, 0, len(caps))
	for _, capLog2 := range caps {
		if capLog2 <= 0 {
			continue
		}
		logTerms = append(logTerms, capLog2-float64(widthBits))
	}
	if len(logTerms) == 0 {
		return 0
	}
	return BitsFromLog2Prob(Log2SumExp(logTerms))
}

func IntGenISISMultiScopeBitsLog(bits, countLog2 float64) float64 {
	if bits <= 0 {
		return 0
	}
	if countLog2 <= 0 {
		return bits
	}
	return bits - countLog2
}

func ExactLedgerTerm(category, name string, bits float64, required bool, reason string) SystemSecurityLedgerTerm {
	return SystemSecurityLedgerTerm{
		Category:         category,
		Name:             name,
		Bits:             bits,
		ActualBits:       bits,
		Required:         required,
		Source:           SystemLedgerTermSourceExact,
		AccountingStatus: SystemLedgerTermAccountingCurrentTheorem,
		RejectionReason:  reason,
	}
}

func ConservativeLedgerTerm(category, name string, bits float64, required bool, reason string) SystemSecurityLedgerTerm {
	return SystemSecurityLedgerTerm{
		Category:         category,
		Name:             name,
		Bits:             bits,
		ActualBits:       bits,
		Required:         required,
		Conservative:     true,
		Source:           SystemLedgerTermSourceConservative,
		AccountingStatus: SystemLedgerTermAccountingRequiresTheory,
		RejectionReason:  reason,
	}
}

func EstimatorLedgerTerm(category, name string, bits float64, required bool, reason string) SystemSecurityLedgerTerm {
	return SystemSecurityLedgerTerm{
		Category:         category,
		Name:             name,
		Bits:             bits,
		ActualBits:       bits,
		Required:         required,
		Source:           SystemLedgerTermSourceEstimator,
		AccountingStatus: SystemLedgerTermAccountingCurrentTheorem,
		RejectionReason:  reason,
	}
}

func LedgerTermWithNote(term SystemSecurityLedgerTerm, note string) SystemSecurityLedgerTerm {
	term.Note = note
	return term
}

func LedgerTermWithEvidence(term SystemSecurityLedgerTerm, reference, scope string) SystemSecurityLedgerTerm {
	term.EvidenceReference = reference
	term.Scope = scope
	return term
}

func ReportOnlyLedgerTerm(term SystemSecurityLedgerTerm) SystemSecurityLedgerTerm {
	term.ReportOnly = true
	return term
}

func systemSecurityLedgerTerms(input SystemSecurityLedgerInput, coreAvailable float64, spec IntGenISISSecurityProfileSpec) []SystemSecurityLedgerTerm {
	terms := append([]SystemSecurityLedgerTerm(nil), input.Terms...)
	add := func(category, name string, bits float64, required bool, reason string) {
		key := ledgerTermKey(category, name)
		for _, term := range terms {
			if ledgerTermKey(term.Category, term.Name) == key {
				return
			}
		}
		terms = append(terms, SystemSecurityLedgerTerm{
			Category:         category,
			Name:             name,
			Bits:             bits,
			Required:         required,
			Source:           SystemLedgerTermSourceExact,
			AccountingStatus: SystemLedgerTermAccountingCurrentTheorem,
			RejectionReason:  reason,
		})
	}
	add(SystemLedgerTermSoundness, "proof_theorem", input.ProofBits, true, "proof theorem bits below target")
	add(SystemLedgerTermSoundness, "full_game", input.FullGameBits, true, "full-game bits below target")
	add(SystemLedgerTermSoundness, "ro_collision", input.CollisionBits, true, "RO collision bits below target")
	add(SystemLedgerTermSoundness, "challenge_bias", input.ChallengeBiasBits, true, "challenge-bias bits below target")
	add(SystemLedgerTermZeroKnowledge, "tape_guessing", input.TapeGuessingBits, true, "tape guessing bits below target")
	add(SystemLedgerTermZeroKnowledge, "programming_conflict", input.ProgrammingBits, true, "programming conflict bits below target")
	add(SystemLedgerTermUnlinkability, "tag_collision", input.TagCollisionBits, true, "tag collision bits below target")
	add(SystemLedgerTermCorrectness, "salt_collision", input.SaltCollisionBits, true, "salt collision bits below target")
	add(SystemLedgerTermPrimitive, "prf_security", input.PRFBits, true, "PRF bits below primitive requirement")
	add(SystemLedgerTermPrimitive, "mlwe_hiding", input.MLWEBits, true, "MLWE bits below primitive requirement")
	add(SystemLedgerTermPrimitive, "msis_binding", input.MSISBindingBits, true, "MSIS binding bits below primitive requirement")
	add(SystemLedgerTermPrimitive, "lattice_signature", input.SignatureBits, true, "lattice signature bits below primitive requirement")
	add(SystemLedgerTermPrimitive, "seed_entropy", input.SeedEntropyBits, true, "seed entropy bits below primitive requirement")
	add(SystemLedgerTermPrimitive, "core_available", coreAvailable, false, "primitive core below target")
	add(SystemLedgerTermComposition, "multi_user", input.MultiUserBits, true, "multi-user lift bits below target")
	add(SystemLedgerTermComposition, "multi_context", input.MultiContextBits, true, "multi-context lift bits below target")
	modelKey := ledgerTermKey(SystemLedgerTermModelScope, "random_oracle_model")
	modelPresent := false
	for _, term := range terms {
		if ledgerTermKey(term.Category, term.Name) == modelKey {
			modelPresent = true
			break
		}
	}
	if !modelPresent {
		terms = append(terms, SystemSecurityLedgerTerm{
			Category:          SystemLedgerTermModelScope,
			Name:              "random_oracle_model",
			ActualValue:       string(input.ROMModel),
			RequiredValue:     string(spec.ROM),
			Required:          true,
			Source:            SystemLedgerTermSourceExact,
			AccountingStatus:  SystemLedgerTermAccountingCurrentTheorem,
			RejectionReason:   "random-oracle model does not match security profile",
			EvidenceReference: "preset.threat_model.rom",
			Scope:             "proof system",
		})
	}
	return terms
}

func finalizeLedgerTerms(terms []SystemSecurityLedgerTerm, targetBits, coreRequiredBits float64) []SystemSecurityLedgerTerm {
	out := append([]SystemSecurityLedgerTerm(nil), terms...)
	for i := range out {
		if out[i].Category == "" {
			out[i].Category = "unknown"
		}
		if out[i].Name == "" {
			out[i].Name = "unnamed"
		}
		if out[i].ActualBits == 0 && out[i].Bits > 0 {
			out[i].ActualBits = out[i].Bits
		}
		if out[i].Bits == 0 && out[i].ActualBits > 0 {
			out[i].Bits = out[i].ActualBits
		}
		if out[i].Required && out[i].RequiredBits == 0 && out[i].RequiredValue == "" {
			out[i].RequiredBits = targetBits
			if out[i].Category == SystemLedgerTermPrimitive && coreRequiredBits > 0 {
				out[i].RequiredBits = coreRequiredBits
			}
		}
		if out[i].Source == "" {
			switch {
			case out[i].ActualValue == "" && (out[i].ActualBits <= 0 || math.IsNaN(out[i].ActualBits)):
				out[i].Source = SystemLedgerTermSourceMissing
			case out[i].Conservative:
				out[i].Source = SystemLedgerTermSourceConservative
			default:
				out[i].Source = SystemLedgerTermSourceExact
			}
		}
		if out[i].AccountingStatus == "" {
			if out[i].Conservative || out[i].Source == SystemLedgerTermSourceConservative {
				out[i].AccountingStatus = SystemLedgerTermAccountingRequiresTheory
			} else {
				out[i].AccountingStatus = SystemLedgerTermAccountingCurrentTheorem
			}
		}
	}
	return out
}

func ledgerTermRejectionReasons(terms []SystemSecurityLedgerTerm) []string {
	reasons := make([]string, 0)
	for i := range terms {
		if !terms[i].Required {
			if terms[i].Status == "" {
				terms[i].Status = "informational"
			}
			continue
		}
		key := ledgerTermKey(terms[i].Category, terms[i].Name)
		if terms[i].RequiredValue != "" || terms[i].ActualValue != "" {
			switch {
			case terms[i].ActualValue == "":
				terms[i].Status = "missing"
				terms[i].Source = SystemLedgerTermSourceMissing
				reasons = append(reasons, "missing required ledger term "+key)
			case terms[i].ActualValue != terms[i].RequiredValue:
				terms[i].Status = "mismatch"
				if terms[i].RejectionReason != "" {
					reasons = append(reasons, terms[i].RejectionReason)
				} else {
					reasons = append(reasons, key+" value mismatch")
				}
			default:
				terms[i].Status = "pass"
			}
			continue
		}
		switch {
		case terms[i].ActualBits <= 0 || math.IsNaN(terms[i].ActualBits):
			terms[i].Status = "missing"
			terms[i].Source = SystemLedgerTermSourceMissing
			reasons = append(reasons, "missing required ledger term "+key)
		case terms[i].RequiredBits > 0 && ledgerBitsBelowTarget(terms[i].ActualBits, terms[i].RequiredBits):
			terms[i].Status = "below_target"
			if terms[i].RejectionReason != "" {
				reasons = append(reasons, terms[i].RejectionReason)
			} else {
				reasons = append(reasons, fmt.Sprintf("%s bits below target", key))
			}
		default:
			terms[i].Status = "pass"
		}
	}
	return reasons
}

func ledgerTermReadinessReasons(terms []SystemSecurityLedgerTerm) []string {
	reasons := make([]string, 0)
	for _, term := range terms {
		if !term.Required {
			continue
		}
		key := ledgerTermKey(term.Category, term.Name)
		if term.ReportOnly {
			reasons = append(reasons, "required ledger term "+key+" is report_only")
		}
		if term.Source == SystemLedgerTermSourceConservative || term.AccountingStatus == SystemLedgerTermAccountingRequiresTheory {
			reasons = append(reasons, "required ledger term "+key+" requires reviewed theorem accounting")
		}
		if term.EvidenceReference == "" {
			if term.Source == SystemLedgerTermSourceEstimator {
				reasons = append(reasons, "required ledger term "+key+" is missing estimator provenance")
			} else {
				reasons = append(reasons, "required ledger term "+key+" is missing evidence")
			}
		}
		if term.Scope == "" {
			reasons = append(reasons, "required ledger term "+key+" is missing scope")
		}
	}
	return reasons
}

func ledgerCategoryBits(terms []SystemSecurityLedgerTerm, category string) float64 {
	logTerms := make([]float64, 0)
	for _, term := range terms {
		if term.Category != category || !term.Required || term.ReportOnly || term.ActualBits <= 0 || math.IsNaN(term.ActualBits) {
			continue
		}
		logTerms = append(logTerms, -term.ActualBits)
	}
	if len(logTerms) == 0 {
		return 0
	}
	return BitsFromLog2Prob(Log2SumExp(logTerms))
}

func ledgerTermKey(category, name string) string {
	return category + "/" + name
}

func ledgerBitsBelowTarget(bits, target float64) bool {
	const tolerance = 1e-9
	return bits+tolerance < target
}

func normalizeAdversaryScope(scope AdversaryScope) AdversaryScope {
	def := AdversaryScope{
		IssuanceQueries: 1,
		Presentations:   1,
		Verifications:   1,
		PRFAttempts:     1,
		Users:           1,
		Contexts:        1,
		TagsPerContext:  1,
		Proofs:          1,
	}
	if scope.IssuanceQueries == 0 {
		scope.IssuanceQueries = def.IssuanceQueries
	}
	if scope.Presentations == 0 {
		scope.Presentations = def.Presentations
	}
	if scope.Verifications == 0 {
		scope.Verifications = def.Verifications
	}
	if scope.PRFAttempts == 0 {
		scope.PRFAttempts = def.PRFAttempts
	}
	if scope.Users == 0 {
		scope.Users = def.Users
	}
	if scope.Contexts == 0 {
		scope.Contexts = def.Contexts
	}
	if scope.TagsPerContext == 0 {
		scope.TagsPerContext = def.TagsPerContext
	}
	if scope.Proofs == 0 {
		scope.Proofs = def.Proofs
	}
	return scope
}

func isZeroROBudgetVector(v ROBudgetVector) bool {
	if v.Merkle != 0 || v.GuessTape != 0 {
		return false
	}
	for i := range v.FS {
		if v.FS[i] != 0 || v.ChallengeExpansion[i] != 0 || v.Programming[i] != 0 || v.ValidPrefixes[i] != 0 {
			return false
		}
	}
	return true
}

func isZeroROBudgetLogVector(v ROBudgetLogVector) bool {
	if v.RawLog2 != 0 || v.MerkleLog2 != 0 || v.GuessTapeLog2 != 0 || v.CollisionLog2 != 0 {
		return false
	}
	for i := range v.FSLog2 {
		if v.FSLog2[i] != 0 || v.ChallengeExpansionLog2[i] != 0 || v.ProgrammingLog2[i] != 0 || v.ValidPrefixLog2[i] != 0 {
			return false
		}
	}
	return true
}

func maxUint64Slice(vals []uint64) uint64 {
	var out uint64
	for _, v := range vals {
		if v > out {
			out = v
		}
	}
	return out
}

func maxPositiveFloat64(vals ...float64) float64 {
	var out float64
	for _, v := range vals {
		if v > out {
			out = v
		}
	}
	return out
}

func maxPositiveFloat64Slice(vals []float64) float64 {
	var out float64
	for _, v := range vals {
		if v > out {
			out = v
		}
	}
	return out
}

func uniqueStrings(vals []string) []string {
	if len(vals) < 2 {
		return vals
	}
	seen := make(map[string]struct{}, len(vals))
	out := vals[:0]
	for _, v := range vals {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
