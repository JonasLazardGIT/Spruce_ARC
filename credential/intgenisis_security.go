package credential

import "math"

const (
	IntGenISISCommitmentEstimatorSource = "docs/intgenisis_lattice_security.md"
	IntGenISISCommitmentEstimatorName   = "malb/lattice-estimator"
	IntGenISISCommitmentEstimatorCommit = "14c2c10e6f2f7a39072130627b2cec5495704701"
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
	MLWEHidingBits               float64 `json:"mlwe_hiding_bits,omitempty"`
	MLWEHidingAttack             string  `json:"mlwe_hiding_attack,omitempty"`
	MSISBindingBits              float64 `json:"msis_binding_bits,omitempty"`
	MSISBindingAttack            string  `json:"msis_binding_attack,omitempty"`
	MSISBindingNorm              string  `json:"msis_binding_norm,omitempty"`
	MSISBindingInfinite          bool    `json:"msis_binding_infinite,omitempty"`
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

func intGenISISCommitmentSecurity(profile string, n int, q uint64, ellM, kS, nC int, b int64, mlweBits float64, mlweAttack string, msisBits float64, msisInfinite bool) IntGenISISCommitmentSecurity {
	statHideSlack := intGenISISStatisticalHidingSlackBits(n, q, kS, nC, b)
	return IntGenISISCommitmentSecurity{
		Source:                       IntGenISISCommitmentEstimatorSource,
		Estimator:                    IntGenISISCommitmentEstimatorName,
		EstimatorCommit:              IntGenISISCommitmentEstimatorCommit,
		Mode:                         IntGenISISCommitmentEstimatorMode,
		HidingAssumption:             "computational MLWE, not statistical hiding",
		BindingAssumption:            "MSIS rough estimator on [C_M|A_s|I]",
		MLWEHidingBits:               mlweBits,
		MLWEHidingAttack:             mlweAttack,
		MSISBindingBits:              msisBits,
		MSISBindingAttack:            "lattice",
		MSISBindingNorm:              "l2",
		MSISBindingInfinite:          msisInfinite,
		StatisticalHidingSatisfied:   statHideSlack >= 0,
		StatisticalHidingSlackBits:   statHideSlack,
		StatisticalBindingSlackBits:  intGenISISStatisticalBindingSlackBits(n, q, ellM, kS, nC, b),
		StatisticalHidingModel:       "N*(k_s+n_c)*log2(2B+1) - (N*n_c*log2(q) + 2*lambda), lambda=128",
		StatisticalBindingSlackModel: "N*n_c*log2(q) - N*(ell_M+k_s+n_c)*log2(4B+1)",
	}
}

func primaryIntGenISISCommitmentSecurity() IntGenISISCommitmentSecurity {
	return intGenISISCommitmentSecurity(ProfileIntGenISISB, 512, IntGenISISSharedModulusQ, 1, 2, 1, 4, 203.816, "usvp", 586.336, false)
}

func ternary1024IntGenISISCommitmentSecurity() IntGenISISCommitmentSecurity {
	return intGenISISCommitmentSecurity(ProfileIntGenISISC, 1024, IntGenISISSharedModulusQ, 1, 1, 1, 1, 131.113, "dual_hybrid", 0, true)
}

func intGenISISStatisticalHidingSlackBits(n int, q uint64, kS, nC int, b int64) float64 {
	randomness := float64(n*(kS+nC)) * math.Log2(float64(2*b+1))
	required := float64(n*nC)*math.Log2(float64(q)) + 2*float64(intGenISISCommitmentSecurityLambda)
	return randomness - required
}

func intGenISISStatisticalBindingSlackBits(n int, q uint64, ellM, kS, nC int, b int64) float64 {
	codomain := float64(n*nC) * math.Log2(float64(q))
	diffSpace := float64(n*(ellM+kS+nC)) * math.Log2(float64(4*b+1))
	return codomain - diffSpace
}
