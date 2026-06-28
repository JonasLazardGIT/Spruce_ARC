package credential

import "math"

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
	PRFBits             float64
	MLWEBits            float64
	ReplayRejected      bool
}

type SystemSecurityLedger struct {
	SecurityProfile     string   `json:"security_profile"`
	SecurityMode        string   `json:"security_mode"`
	CompleteSystemClaim bool     `json:"complete_system_claim"`
	TargetBits          float64  `json:"target_bits"`
	CoreBitsRequired    float64  `json:"core_required_bits"`
	CoreAvailableBits   float64  `json:"core_available_bits"`
	ProofBits           float64  `json:"proof_bits"`
	FullGameBits        float64  `json:"full_game_bits"`
	CollisionBits       float64  `json:"collision_bits"`
	TagCollisionBits    float64  `json:"tag_collision_bits"`
	SaltCollisionBits   float64  `json:"salt_collision_bits"`
	PRFBits             float64  `json:"prf_bits"`
	MLWEBits            float64  `json:"mlwe_bits"`
	LedgerStatus        string   `json:"ledger_status"`
	RejectionReasons    []string `json:"ledger_rejection_reasons,omitempty"`
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
	ledger := SystemSecurityLedger{
		SecurityProfile:     input.SecurityProfile,
		SecurityMode:        mode,
		CompleteSystemClaim: false,
		TargetBits:          targetBits,
		CoreBitsRequired:    coreRequired,
		CoreAvailableBits:   coreAvailable,
		ProofBits:           input.ProofBits,
		FullGameBits:        fullGameBits,
		CollisionBits:       input.CollisionBits,
		TagCollisionBits:    input.TagCollisionBits,
		SaltCollisionBits:   input.SaltCollisionBits,
		PRFBits:             input.PRFBits,
		MLWEBits:            input.MLWEBits,
		LedgerStatus:        string(spec.Status),
	}
	if input.SecurityProfile == "" || spec.Label == "" {
		ledger.RejectionReasons = append(ledger.RejectionReasons, "missing security profile")
		ledger.LedgerStatus = "rejected"
		return ledger
	}
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
	if len(ledger.RejectionReasons) == 0 {
		ledger.LedgerStatus = string(SecurityProfileCompleteLive)
		ledger.CompleteSystemClaim = input.CompleteSystemClaim
	}
	return ledger
}

func IntGenISISTagCollisionBits(q uint64, tagElements int, tagsPerContext uint64) float64 {
	if q <= 1 || tagElements <= 0 {
		return 0
	}
	spaceBits := float64(tagElements) * math.Log2(float64(q))
	if tagsPerContext < 2 {
		return spaceBits
	}
	return spaceBits - log2BinomUint64(tagsPerContext, 2)
}

func IntGenISISSaltCollisionBits(saltBits int, proofs uint64) float64 {
	if saltBits <= 0 {
		return 0
	}
	if proofs < 2 {
		return float64(saltBits)
	}
	return float64(saltBits) - log2BinomUint64(proofs, 2)
}

func log2BinomUint64(n uint64, k uint64) float64 {
	if k > n {
		return math.Inf(-1)
	}
	if k == 0 || k == n {
		return 0
	}
	if k > n-k {
		k = n - k
	}
	if k == 1 {
		return math.Log2(float64(n))
	}
	if k == 2 {
		return math.Log2(float64(n)) + math.Log2(float64(n-1)) - 1
	}
	lnN, _ := math.Lgamma(float64(n) + 1)
	lnK, _ := math.Lgamma(float64(k) + 1)
	lnNK, _ := math.Lgamma(float64(n-k) + 1)
	return (lnN - lnK - lnNK) / math.Ln2
}

func minPositiveFloat64(vals ...float64) float64 {
	out := 0.0
	for _, v := range vals {
		if v <= 0 || math.IsInf(v, -1) || math.IsNaN(v) {
			continue
		}
		if out == 0 || v < out {
			out = v
		}
	}
	return out
}
