package credential

const (
	ValidPrefixCostModelMeasuredStructural       = "measured_structural"
	ValidPrefixAccountingRawCaps                 = "raw_caps_current_theorem"
	ValidPrefixAccountingConservativeRawFallback = "conservative_raw_fallback"
	ValidPrefixAccountingResearchRequiresTheory  = "research_requires_theorem"
	ValidPrefixTheoremModeCurrentRaw             = "current_theorem_raw_caps"
	ValidPrefixTheoremModeCandidate              = "valid_prefix_theorem_candidate"

	ValidPrefixTheoremRequiredReason = "valid-prefix algebraic accounting requires a new theorem"
)

type ValidPrefixCostReport struct {
	Model                     string                 `json:"model,omitempty"`
	Source                    string                 `json:"source,omitempty"`
	ResearchOnly              bool                   `json:"research_only,omitempty"`
	ValidPrefixConservative   bool                   `json:"valid_prefix_conservative,omitempty"`
	WorkBudgetLog2            float64                `json:"work_budget_log2,omitempty"`
	RawCapLog2                float64                `json:"raw_cap_log2,omitempty"`
	EffectiveAlgebraicCapLog2 [4]float64             `json:"effective_algebraic_cap_log2,omitempty"`
	Rounds                    []ValidPrefixRoundCost `json:"rounds,omitempty"`
	Notes                     []string               `json:"notes,omitempty"`
}

type ValidPrefixRoundCost struct {
	Round                       int      `json:"round"`
	Label                       string   `json:"label"`
	PrefixPredicate             string   `json:"prefix_predicate"`
	StructuralPrerequisites     []string `json:"structural_prerequisites,omitempty"`
	MeasuredCumulativeMS        float64  `json:"measured_cumulative_ms,omitempty"`
	EstimatedHashEquivalentLog2 float64  `json:"estimated_hash_equivalent_log2,omitempty"`
	RawCapLog2                  float64  `json:"raw_cap_log2,omitempty"`
	ValidPrefixCapLog2          float64  `json:"valid_prefix_cap_log2,omitempty"`
	AccountingStatus            string   `json:"accounting_status,omitempty"`
}

type ValidPrefixAlgebraicAccounting struct {
	TheoremMode                string     `json:"theorem_mode,omitempty"`
	RawFSCapLog2               [4]float64 `json:"raw_fs_cap_log2,omitempty"`
	ValidPrefixCapLog2         [4]float64 `json:"valid_prefix_cap_log2,omitempty"`
	EffectiveAlgebraicCapLog2  [4]float64 `json:"effective_algebraic_cap_log2,omitempty"`
	ValidPrefixDiscountLog2    [4]float64 `json:"valid_prefix_discount_log2,omitempty"`
	CollisionCapLog2           float64    `json:"collision_cap_log2,omitempty"`
	ProgrammingCapLog2         [4]float64 `json:"programming_cap_log2,omitempty"`
	ChallengeBiasCapLog2       [4]float64 `json:"challenge_bias_cap_log2,omitempty"`
	UsesValidPrefixAccounting  bool       `json:"uses_valid_prefix_accounting,omitempty"`
	RequiresTheoremAccounting  bool       `json:"requires_theorem_accounting,omitempty"`
	ConservativeRawFallback    bool       `json:"conservative_raw_fallback,omitempty"`
	RawCollisionUnaffected     bool       `json:"raw_collision_unaffected,omitempty"`
	RawProgrammingUnaffected   bool       `json:"raw_programming_unaffected,omitempty"`
	RawChallengeBiasUnaffected bool       `json:"raw_challenge_bias_unaffected,omitempty"`
	RejectionReason            string     `json:"rejection_reason,omitempty"`
	Notes                      []string   `json:"notes,omitempty"`
}

func SmallWoodValidPrefixAccounting(logs ROBudgetLogVector, useValidPrefixAlgebraicCaps bool) ValidPrefixAlgebraicAccounting {
	rawCap := logs.RawLog2
	if rawCap <= 0 {
		rawCap = maxPositiveFloat64(logs.MerkleLog2, logs.CollisionLog2, logs.GuessTapeLog2)
		for i := range logs.FSLog2 {
			rawCap = maxPositiveFloat64(rawCap, logs.FSLog2[i], logs.ChallengeExpansionLog2[i], logs.ProgrammingLog2[i])
		}
	}
	out := ValidPrefixAlgebraicAccounting{
		TheoremMode:                ValidPrefixTheoremModeCurrentRaw,
		CollisionCapLog2:           firstPositiveFloat64(logs.CollisionLog2, rawCap),
		ConservativeRawFallback:    true,
		RawCollisionUnaffected:     true,
		RawProgrammingUnaffected:   true,
		RawChallengeBiasUnaffected: true,
		Notes: []string{
			"SmallWood algebraic terms use raw RO caps under the current theorem",
			"collision, programming, and challenge-bias terms always keep raw caps",
		},
	}
	hasValidCap := false
	for i := range out.RawFSCapLog2 {
		rawRound := firstPositiveFloat64(logs.FSLog2[i], rawCap)
		validRound := logs.ValidPrefixLog2[i]
		out.RawFSCapLog2[i] = rawRound
		out.ValidPrefixCapLog2[i] = validRound
		out.EffectiveAlgebraicCapLog2[i] = rawRound
		out.ProgrammingCapLog2[i] = firstPositiveFloat64(logs.ProgrammingLog2[i], rawRound)
		out.ChallengeBiasCapLog2[i] = firstPositiveFloat64(logs.ChallengeExpansionLog2[i], rawRound)
		if validRound > 0 {
			hasValidCap = true
		}
		if useValidPrefixAlgebraicCaps && validRound > 0 && (rawRound <= 0 || validRound < rawRound) {
			out.EffectiveAlgebraicCapLog2[i] = validRound
			if rawRound > validRound {
				out.ValidPrefixDiscountLog2[i] = rawRound - validRound
			}
			out.UsesValidPrefixAccounting = true
		}
	}
	if useValidPrefixAlgebraicCaps && hasValidCap {
		out.TheoremMode = ValidPrefixTheoremModeCandidate
		out.UsesValidPrefixAccounting = true
		out.RequiresTheoremAccounting = true
		out.ConservativeRawFallback = false
		out.RejectionReason = ValidPrefixTheoremRequiredReason
		out.Notes = append(out.Notes, "valid-prefix caps affect only SmallWood algebraic extraction terms")
	}
	return out
}

func firstPositiveFloat64(vals ...float64) float64 {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}
