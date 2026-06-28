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
)

type ROBudgetVector struct {
	Merkle             uint64    `json:"merkle,omitempty"`
	FS                 [4]uint64 `json:"fs,omitempty"`
	ChallengeExpansion [4]uint64 `json:"challenge_expansion,omitempty"`
	GuessTape          uint64    `json:"guess_tape,omitempty"`
	Programming        [4]uint64 `json:"programming,omitempty"`
	ValidPrefixes      [4]uint64 `json:"valid_prefixes,omitempty"`
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

type SystemSecurityLedgerTerm struct {
	Category        string  `json:"category"`
	Name            string  `json:"name"`
	Bits            float64 `json:"bits,omitempty"`
	Required        bool    `json:"required,omitempty"`
	Conservative    bool    `json:"conservative,omitempty"`
	Status          string  `json:"status,omitempty"`
	RejectionReason string  `json:"rejection_reason,omitempty"`
}

type SystemSecurityLedgerInput struct {
	SecurityProfile     string
	SecurityMode        string
	CompleteSystemClaim bool
	TargetBits          float64
	CoreBitsRequired    float64
	CoreAvailableBits   float64
	ProofBits           float64
	FullGameBits        float64
	CollisionBits       float64
	TagCollisionBits    float64
	SaltCollisionBits   float64
	TapeGuessingBits    float64
	ProgrammingBits     float64
	ChallengeBiasBits   float64
	MultiUserBits       float64
	MultiContextBits    float64
	PRFBits             float64
	MLWEBits            float64
	ReplayRejected      bool
	ROBudgets           ROBudgetVector
	Scope               AdversaryScope
	Terms               []SystemSecurityLedgerTerm
}

type SystemSecurityLedger struct {
	SecurityProfile         string                     `json:"security_profile"`
	SecurityMode            string                     `json:"security_mode"`
	CompleteSystemClaim     bool                       `json:"complete_system_claim"`
	TargetBits              float64                    `json:"target_bits"`
	CoreBitsRequired        float64                    `json:"core_required_bits"`
	CoreAvailableBits       float64                    `json:"core_available_bits"`
	ProofBits               float64                    `json:"proof_bits"`
	FullGameBits            float64                    `json:"full_game_bits"`
	CollisionBits           float64                    `json:"collision_bits"`
	TagCollisionBits        float64                    `json:"tag_collision_bits"`
	SaltCollisionBits       float64                    `json:"salt_collision_bits"`
	TapeGuessingBits        float64                    `json:"tape_guessing_bits,omitempty"`
	ProgrammingConflictBits float64                    `json:"programming_conflict_bits,omitempty"`
	ChallengeBiasBits       float64                    `json:"challenge_bias_bits,omitempty"`
	MultiUserLossBits       float64                    `json:"multi_user_loss_bits,omitempty"`
	MultiContextLossBits    float64                    `json:"multi_context_loss_bits,omitempty"`
	SoundnessBits           float64                    `json:"soundness_bits,omitempty"`
	UnlinkabilityBits       float64                    `json:"unlinkability_bits,omitempty"`
	CorrectnessBits         float64                    `json:"correctness_bits,omitempty"`
	PrimitiveBits           float64                    `json:"primitive_bits,omitempty"`
	PRFBits                 float64                    `json:"prf_bits"`
	MLWEBits                float64                    `json:"mlwe_bits"`
	ROBudgets               ROBudgetVector             `json:"ro_budgets,omitempty"`
	AdversaryScope          AdversaryScope             `json:"adversary_scope,omitempty"`
	ValidPrefixConservative bool                       `json:"valid_prefix_conservative,omitempty"`
	Terms                   []SystemSecurityLedgerTerm `json:"ledger_terms,omitempty"`
	LedgerStatus            string                     `json:"ledger_status"`
	RejectionReasons        []string                   `json:"ledger_rejection_reasons,omitempty"`
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
	scope := normalizeAdversaryScope(input.Scope, spec)
	budgets := input.ROBudgets
	if isZeroROBudgetVector(budgets) {
		budgets = ROBudgetVectorFromCaps(spec.ROQueryCaps)
	}
	ledger := SystemSecurityLedger{
		SecurityProfile:         input.SecurityProfile,
		SecurityMode:            mode,
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
		ROBudgets:               budgets,
		AdversaryScope:          scope,
		ValidPrefixConservative: !hasValidPrefixCaps(budgets),
		LedgerStatus:            string(spec.Status),
	}
	if input.SecurityProfile == "" || spec.Label == "" {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "missing security profile")
		ledger.LedgerStatus = "rejected"
		return ledger
	}

	ledger.Terms = finalizeLedgerTerms(systemSecurityLedgerTerms(input, coreAvailable))
	ledger.SoundnessBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermSoundness)
	ledger.UnlinkabilityBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermUnlinkability)
	ledger.CorrectnessBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermCorrectness)
	ledger.PrimitiveBits = ledgerCategoryBits(ledger.Terms, SystemLedgerTermPrimitive)

	if spec.Status != SecurityProfileCompleteLive {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "profile status is "+string(spec.Status))
	}
	if targetBits <= 0 {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "missing target bits")
	}
	if coreAvailable > 0 && coreRequired > 0 && coreAvailable < coreRequired {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "primitive core below required bits")
	}
	if fullGameBits > 0 && targetBits > 0 && fullGameBits < targetBits {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "full-game bits below target")
	}
	if input.TagCollisionBits > 0 && targetBits > 0 && input.TagCollisionBits < targetBits {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "tag collision bits below target")
	}
	if input.SaltCollisionBits > 0 && targetBits > 0 && input.SaltCollisionBits < targetBits {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "salt collision bits below target")
	}
	if !input.ReplayRejected {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "replay rejection did not pass")
	}
	ledger.RejectionReasons = append(ledger.RejectionReasons, ledgerTermRejectionReasons(ledger.Terms, targetBits)...)
	if targetBits > 0 {
		for _, category := range []struct {
			name string
			bits float64
		}{
			{"soundness", ledger.SoundnessBits},
			{"unlinkability", ledger.UnlinkabilityBits},
			{"correctness", ledger.CorrectnessBits},
			{"primitive", ledger.PrimitiveBits},
		} {
			if category.bits > 0 && category.bits < targetBits {
				ledger.RejectionReasons = append(ledger.RejectionReasons, category.name+" ledger bits below target")
			}
		}
	}
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

func DefaultIntGenISISAdversaryScope(spec IntGenISISSecurityProfileSpec) AdversaryScope {
	tagsPerContext := uint64(1)
	for _, cap := range spec.ROQueryCaps {
		if cap > tagsPerContext {
			tagsPerContext = cap
		}
	}
	return AdversaryScope{
		IssuanceQueries: 1,
		Presentations:   1,
		Verifications:   1,
		PRFAttempts:     tagsPerContext,
		Users:           1,
		Contexts:        1,
		TagsPerContext:  tagsPerContext,
		Proofs:          2,
	}
}

func IntGenISISTagCollisionBits(q uint64, tagElements int, tagsPerContext uint64) float64 {
	if q <= 1 || tagElements <= 0 {
		return 0
	}
	spaceBits := float64(tagElements) * math.Log2(float64(q))
	if tagsPerContext < 2 {
		return spaceBits
	}
	return spaceBits - Log2Binom(tagsPerContext, 2)
}

func IntGenISISSaltCollisionBits(saltBits int, proofs uint64) float64 {
	if saltBits <= 0 {
		return 0
	}
	if proofs < 2 {
		return float64(saltBits)
	}
	return float64(saltBits) - Log2Binom(proofs, 2)
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

func IntGenISISMultiScopeBits(bits float64, count uint64) float64 {
	if bits <= 0 {
		return 0
	}
	if count <= 1 {
		return bits
	}
	return bits - math.Log2(float64(count))
}

func IntGenISISBudgetCollisionBits(widthBits int, caps []uint64) float64 {
	if widthBits <= 0 {
		return 0
	}
	logTerms := make([]float64, 0, len(caps))
	for _, cap := range caps {
		if cap < 2 {
			continue
		}
		logTerms = append(logTerms, Log2Binom(cap, 2)-float64(widthBits))
	}
	return BitsFromLog2Prob(Log2SumExp(logTerms))
}

func systemSecurityLedgerTerms(input SystemSecurityLedgerInput, coreAvailable float64) []SystemSecurityLedgerTerm {
	terms := append([]SystemSecurityLedgerTerm(nil), input.Terms...)
	add := func(category, name string, bits float64, required bool, reason string) {
		key := ledgerTermKey(category, name)
		for _, term := range terms {
			if ledgerTermKey(term.Category, term.Name) == key {
				return
			}
		}
		terms = append(terms, SystemSecurityLedgerTerm{
			Category:        category,
			Name:            name,
			Bits:            bits,
			Required:        required,
			RejectionReason: reason,
		})
	}
	add(SystemLedgerTermSoundness, "proof_theorem", input.ProofBits, true, "proof theorem bits below target")
	add(SystemLedgerTermSoundness, "full_game", input.FullGameBits, true, "full-game bits below target")
	add(SystemLedgerTermSoundness, "ro_collision", input.CollisionBits, true, "RO collision bits below target")
	add(SystemLedgerTermSoundness, "tape_guessing", input.TapeGuessingBits, true, "tape guessing bits below target")
	add(SystemLedgerTermSoundness, "programming_conflict", input.ProgrammingBits, true, "programming conflict bits below target")
	add(SystemLedgerTermSoundness, "challenge_bias", input.ChallengeBiasBits, true, "challenge-bias bits below target")
	add(SystemLedgerTermUnlinkability, "tag_collision", input.TagCollisionBits, true, "tag collision bits below target")
	add(SystemLedgerTermCorrectness, "salt_collision", input.SaltCollisionBits, true, "salt collision bits below target")
	add(SystemLedgerTermPrimitive, "prf_security", input.PRFBits, true, "PRF bits below target")
	add(SystemLedgerTermPrimitive, "mlwe_hiding", input.MLWEBits, true, "MLWE bits below target")
	add(SystemLedgerTermPrimitive, "core_available", coreAvailable, true, "primitive core below target")
	add(SystemLedgerTermComposition, "multi_user", input.MultiUserBits, true, "multi-user lift bits below target")
	add(SystemLedgerTermComposition, "multi_context", input.MultiContextBits, true, "multi-context lift bits below target")
	return terms
}

func finalizeLedgerTerms(terms []SystemSecurityLedgerTerm) []SystemSecurityLedgerTerm {
	out := append([]SystemSecurityLedgerTerm(nil), terms...)
	for i := range out {
		if out[i].Category == "" {
			out[i].Category = "unknown"
		}
		if out[i].Name == "" {
			out[i].Name = "unnamed"
		}
	}
	return out
}

func ledgerTermRejectionReasons(terms []SystemSecurityLedgerTerm, targetBits float64) []string {
	reasons := make([]string, 0)
	for i := range terms {
		if !terms[i].Required {
			if terms[i].Status == "" {
				terms[i].Status = "informational"
			}
			continue
		}
		key := ledgerTermKey(terms[i].Category, terms[i].Name)
		switch {
		case terms[i].Bits <= 0 || math.IsNaN(terms[i].Bits):
			terms[i].Status = "missing"
			reasons = append(reasons, "missing required ledger term "+key)
		case targetBits > 0 && terms[i].Bits < targetBits:
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

func ledgerCategoryBits(terms []SystemSecurityLedgerTerm, category string) float64 {
	logTerms := make([]float64, 0)
	for _, term := range terms {
		if term.Category != category || term.Bits <= 0 || math.IsNaN(term.Bits) {
			continue
		}
		logTerms = append(logTerms, -term.Bits)
	}
	return BitsFromLog2Prob(Log2SumExp(logTerms))
}

func ledgerTermKey(category, name string) string {
	return category + "/" + name
}

func normalizeAdversaryScope(scope AdversaryScope, spec IntGenISISSecurityProfileSpec) AdversaryScope {
	def := DefaultIntGenISISAdversaryScope(spec)
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

func hasValidPrefixCaps(v ROBudgetVector) bool {
	for _, cap := range v.ValidPrefixes {
		if cap > 0 {
			return true
		}
	}
	return false
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
