package credential

import "math"

const (
	IntGenISISCommitmentEstimatorSource = "docs/SECURITY.md"
	IntGenISISCommitmentEstimatorName   = "malb/lattice-estimator"
	IntGenISISCommitmentEstimatorCommit = "4bfa63e364be9dd7fd1b2b531e2a11da8fb1c2ad"
	IntGenISISCommitmentEstimatorMode   = "rough"
	intGenISISCommitmentSecurityLambda  = 128
)

// IntGenISISCommitmentSecurity records the implementation-aligned security
// estimate for the Ajtai/MLWE commitment c = C_M*M + A_s*s + e.
type IntGenISISCommitmentSecurity struct {
	Source                       string  `json:"source,omitempty"`
	Estimator                    string  `json:"estimator,omitempty"`
	EstimatorCommit              string  `json:"estimator_commit,omitempty"`
	Mode                         string  `json:"mode,omitempty"`
	HidingAssumption             string  `json:"hiding_assumption,omitempty"`
	BindingAssumption            string  `json:"binding_assumption,omitempty"`
	OrdinaryMessageBound         int64   `json:"ordinary_message_bound,omitempty"`
	PRFSeedBound                 int64   `json:"prf_seed_bound,omitempty"`
	CommitmentBound              int64   `json:"commitment_bound,omitempty"`
	PRFSeedLen                   int     `json:"prf_seed_len,omitempty"`
	SemanticTailReserve          int     `json:"semantic_tail_reserve,omitempty"`
	MLWEHidingBits               float64 `json:"mlwe_hiding_bits,omitempty"`
	MLWEHidingAttack             string  `json:"mlwe_hiding_attack,omitempty"`
	MSISBindingBits              float64 `json:"msis_binding_bits,omitempty"`
	MSISBindingAttack            string  `json:"msis_binding_attack,omitempty"`
	MSISBindingNorm              string  `json:"msis_binding_norm,omitempty"`
	MSISBindingL2Bound           float64 `json:"msis_binding_l2_bound,omitempty"`
	MSISBindingLinfBound         int64   `json:"msis_binding_linf_bound,omitempty"`
	MSISBindingInfinite          bool    `json:"msis_binding_infinite,omitempty"`
	BindingDiffSpaceBits         float64 `json:"binding_diff_space_bits,omitempty"`
	StatisticalHidingSatisfied   bool    `json:"statistical_hiding_satisfied"`
	StatisticalHidingSlackBits   float64 `json:"statistical_hiding_slack_bits"`
	StatisticalBindingSlackBits  float64 `json:"statistical_binding_slack_bits"`
	StatisticalHidingModel       string  `json:"statistical_hiding_model,omitempty"`
	StatisticalBindingSlackModel string  `json:"statistical_binding_slack_model,omitempty"`
}

func (s IntGenISISCommitmentSecurity) ClonePtr() *IntGenISISCommitmentSecurity {
	out := s
	return &out
}

func intGenISISCommitmentSecurity(n int, q uint64, ellM, kS, nC int, ordinaryBound, seedBound, commitmentBound int64, seedLen, tailReserve int, mlweBits float64, mlweAttack string, msisBits float64, msisInfinite bool) IntGenISISCommitmentSecurity {
	statHideSlack := intGenISISStatisticalHidingSlackBits(n, q, kS, nC, commitmentBound)
	return IntGenISISCommitmentSecurity{
		Source:                       IntGenISISCommitmentEstimatorSource,
		Estimator:                    IntGenISISCommitmentEstimatorName,
		EstimatorCommit:              IntGenISISCommitmentEstimatorCommit,
		Mode:                         IntGenISISCommitmentEstimatorMode,
		HidingAssumption:             "computational MLWE for A_s*s+e with live s,e bound, not statistical hiding",
		BindingAssumption:            "MSIS rough estimator on [C_M|A_s|I] with mixed semantic-message bounds",
		OrdinaryMessageBound:         ordinaryBound,
		PRFSeedBound:                 seedBound,
		CommitmentBound:              commitmentBound,
		PRFSeedLen:                   seedLen,
		SemanticTailReserve:          tailReserve,
		MLWEHidingBits:               mlweBits,
		MLWEHidingAttack:             mlweAttack,
		MSISBindingBits:              msisBits,
		MSISBindingAttack:            "lattice",
		MSISBindingNorm:              "l2_mixed",
		MSISBindingL2Bound:           intGenISISMSISBindingL2Bound(n, ellM, kS, nC, ordinaryBound, seedBound, commitmentBound, seedLen, tailReserve),
		MSISBindingLinfBound:         intGenISISMSISBindingLinfBound(ordinaryBound, seedBound, commitmentBound),
		MSISBindingInfinite:          msisInfinite,
		BindingDiffSpaceBits:         intGenISISBindingDiffSpaceBits(n, ellM, kS, nC, ordinaryBound, seedBound, commitmentBound, seedLen, tailReserve),
		StatisticalHidingSatisfied:   statHideSlack >= 0,
		StatisticalHidingSlackBits:   statHideSlack,
		StatisticalBindingSlackBits:  intGenISISStatisticalBindingSlackBits(n, q, ellM, kS, nC, ordinaryBound, seedBound, commitmentBound, seedLen, tailReserve),
		StatisticalHidingModel:       "N*(k_s+n_c)*log2(2*commitment_bound+1) - (N*n_c*log2(q) + 2*lambda), lambda=128",
		StatisticalBindingSlackModel: "N*n_c*log2(q) - ((N*ell_M-tail_reserve)*log2(4*ordinary_message_bound+1) + prf_seed_len*log2(4*prf_seed_bound+1) + N*(k_s+n_c)*log2(4*commitment_bound+1))",
	}
}

func primaryIntGenISISCommitmentSecurity() IntGenISISCommitmentSecurity {
	return intGenISISCommitmentSecurity(512, IntGenISISSharedModulusQ, 1, 2, 1, IntGenISISLiveBound, IntGenISISPRFSeedBound, IntGenISISLiveBound, IntGenISISPRFSeedLen, IntGenISISPRFSeedTailReserve, 131.113, "dual_hybrid", 0, true)
}

func ternary1024IntGenISISCommitmentSecurity() IntGenISISCommitmentSecurity {
	return intGenISISCommitmentSecurity(1024, IntGenISISSharedModulusQ, 1, 1, 1, IntGenISISLiveBound, IntGenISISPRFSeedBound, IntGenISISLiveBound, IntGenISISPRFSeedLen, IntGenISISPRFSeedTailReserve, 131.113, "dual_hybrid", 0, true)
}

func intGenISISStatisticalHidingSlackBits(n int, q uint64, kS, nC int, b int64) float64 {
	randomness := float64(n*(kS+nC)) * math.Log2(float64(2*b+1))
	required := float64(n*nC)*math.Log2(float64(q)) + 2*float64(intGenISISCommitmentSecurityLambda)
	return randomness - required
}

func intGenISISStatisticalBindingSlackBits(n int, q uint64, ellM, kS, nC int, ordinaryBound, seedBound, commitmentBound int64, seedLen, tailReserve int) float64 {
	codomain := float64(n*nC) * math.Log2(float64(q))
	diffSpace := intGenISISBindingDiffSpaceBits(n, ellM, kS, nC, ordinaryBound, seedBound, commitmentBound, seedLen, tailReserve)
	return codomain - diffSpace
}

func intGenISISMSISBindingL2Bound(n int, ellM, kS, nC int, ordinaryBound, seedBound, commitmentBound int64, seedLen, tailReserve int) float64 {
	ordinaryCoeffCount := n*ellM - tailReserve
	ordinary := 2 * ordinaryBound
	seed := 2 * seedBound
	se := 2 * commitmentBound
	return math.Sqrt(
		float64(ordinaryCoeffCount)*float64(ordinary*ordinary) +
			float64(seedLen)*float64(seed*seed) +
			float64(n*(kS+nC))*float64(se*se),
	)
}

func intGenISISMSISBindingLinfBound(ordinaryBound, seedBound, commitmentBound int64) int64 {
	out := 2 * ordinaryBound
	if seed := 2 * seedBound; seed > out {
		out = seed
	}
	if se := 2 * commitmentBound; se > out {
		out = se
	}
	return out
}

func intGenISISBindingDiffSpaceBits(n int, ellM, kS, nC int, ordinaryBound, seedBound, commitmentBound int64, seedLen, tailReserve int) float64 {
	ordinaryCoeffCount := n*ellM - tailReserve
	return float64(ordinaryCoeffCount)*math.Log2(float64(4*ordinaryBound+1)) +
		float64(seedLen)*math.Log2(float64(4*seedBound+1)) +
		float64(n*(kS+nC))*math.Log2(float64(4*commitmentBound+1))
}
