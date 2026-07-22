package credential

import (
	"fmt"
	"math"
)

const (
	SecurityEvidenceMeasured       = "measured"
	SecurityEvidenceExecutedPreset = "executed_preset"
	SecurityEvidenceLoadedParams   = "loaded_params"
	SecurityEvidenceMissing        = "missing"
)

type IntGenISISSecurityParameterRequirements struct {
	ROQueryCapLog2Set bool      `json:"ro_query_cap_log2_set,omitempty"`
	ROQueryCapLog2    []float64 `json:"ro_query_cap_log2,omitempty"`
	DECSHashBits      int       `json:"decs_hash_bits,omitempty"`
	DECSTapeBits      int       `json:"decs_tape_bits,omitempty"`
	FSCollisionBits   int       `json:"fs_collision_bits,omitempty"`
	SaltBits          int       `json:"salt_bits,omitempty"`
	PRFTagElements    int       `json:"prf_tag_elements,omitempty"`
}

type IntGenISISSecurityParameterActuals struct {
	ROQueryCapLog2Set bool              `json:"ro_query_cap_log2_set"`
	ROQueryCapLog2    []float64         `json:"ro_query_cap_log2,omitempty"`
	DECSHashBits      int               `json:"decs_hash_bits"`
	DECSTapeBits      int               `json:"decs_tape_bits"`
	FSCollisionBits   int               `json:"fs_collision_bits"`
	SaltBits          int               `json:"salt_bits"`
	PRFTagElements    int               `json:"prf_tag_elements"`
	PRFProfile        string            `json:"prf_profile,omitempty"`
	TranscriptMode    string            `json:"transcript_mode,omitempty"`
	Evidence          map[string]string `json:"evidence"`
}

type IntGenISISSecurityParameterMismatch struct {
	Parameter   string `json:"parameter"`
	Required    string `json:"required"`
	Actual      string `json:"actual"`
	Explanation string `json:"explanation"`
}

type IntGenISISSecurityParameterAudit struct {
	SecurityProfile string                                  `json:"security_profile"`
	Required        IntGenISISSecurityParameterRequirements `json:"required"`
	Actual          IntGenISISSecurityParameterActuals      `json:"actual"`
	MissingActual   []string                                `json:"missing_actual,omitempty"`
	MissingEvidence []string                                `json:"missing_evidence,omitempty"`
	Mismatches      []IntGenISISSecurityParameterMismatch   `json:"mismatches,omitempty"`
	Status          string                                  `json:"status"`
}

func IntGenISISSecurityRequirements(spec IntGenISISSecurityProfileSpec) IntGenISISSecurityParameterRequirements {
	required := IntGenISISSecurityParameterRequirements{
		DECSHashBits:    spec.MinDECSHashBits,
		DECSTapeBits:    spec.MinDECSTapeBits,
		FSCollisionBits: spec.MinFSCollisionBits,
		SaltBits:        spec.MinSaltBits,
		PRFTagElements:  spec.MinPRFTagElements,
	}
	if len(spec.ROQueryCapBits) > 0 {
		required.ROQueryCapLog2Set = true
		required.ROQueryCapLog2 = append([]float64(nil), spec.ROQueryCapBits...)
	} else if len(spec.ROQueryCaps) > 0 {
		required.ROQueryCapLog2Set = true
		required.ROQueryCapLog2 = make([]float64, len(spec.ROQueryCaps))
		for i, cap := range spec.ROQueryCaps {
			if cap > 0 {
				required.ROQueryCapLog2[i] = math.Log2(float64(cap))
			}
		}
	}
	return required
}

// AuditIntGenISISSecurityParameters compares requirements to executed values.
// It never fills an absent actual value from the security profile.
func AuditIntGenISISSecurityParameters(spec IntGenISISSecurityProfileSpec, actual IntGenISISSecurityParameterActuals) IntGenISISSecurityParameterAudit {
	if actual.Evidence == nil {
		actual.Evidence = make(map[string]string)
	}
	if !actual.ROQueryCapLog2Set {
		actual.ROQueryCapLog2 = nil
	}
	audit := IntGenISISSecurityParameterAudit{
		SecurityProfile: spec.Label,
		Required:        IntGenISISSecurityRequirements(spec),
		Actual:          actual,
		Status:          "pass",
	}
	requireActual := func(name string, present bool) {
		if !present {
			audit.MissingActual = append(audit.MissingActual, name)
			audit.Actual.Evidence[name] = SecurityEvidenceMissing
			return
		}
		if audit.Actual.Evidence[name] == "" {
			audit.MissingEvidence = append(audit.MissingEvidence, name)
		}
	}
	if spec.Mode != SecurityModeQueryWorkFactor || audit.Required.ROQueryCapLog2Set {
		requireActual("ro_query_cap_log2", actual.ROQueryCapLog2Set)
	}
	requireActual("decs_hash_bits", actual.DECSHashBits > 0)
	requireActual("decs_tape_bits", actual.DECSTapeBits > 0)
	requireActual("fs_collision_bits", actual.FSCollisionBits > 0)
	requireActual("salt_bits", actual.SaltBits > 0)
	requireActual("prf_tag_elements", actual.PRFTagElements > 0)
	requireActual("prf_profile", actual.PRFProfile != "")
	requireActual("transcript_mode", actual.TranscriptMode != "")
	if actual.ROQueryCapLog2Set {
		if len(actual.ROQueryCapLog2) != 5 {
			audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
				Parameter:   "ro_query_cap_log2",
				Required:    "five phase values",
				Actual:      fmt.Sprintf("%d values", len(actual.ROQueryCapLog2)),
				Explanation: "the executed bounded-query scope is incomplete",
			})
		}
		for i, value := range actual.ROQueryCapLog2 {
			if value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0) {
				continue
			}
			audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
				Parameter:   fmt.Sprintf("ro_query_cap_log2[%d]", i),
				Required:    "finite and non-negative",
				Actual:      fmt.Sprintf("%v", value),
				Explanation: "the executed query budget is invalid",
			})
		}
	}

	addMinMismatch := func(name string, required, got int) {
		if required <= 0 || got <= 0 || got >= required {
			return
		}
		audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
			Parameter:   name,
			Required:    fmt.Sprintf(">= %d", required),
			Actual:      fmt.Sprintf("%d", got),
			Explanation: "the executed parameter is below the security profile minimum",
		})
	}
	addMinMismatch("decs_hash_bits", audit.Required.DECSHashBits, actual.DECSHashBits)
	addMinMismatch("decs_tape_bits", audit.Required.DECSTapeBits, actual.DECSTapeBits)
	addMinMismatch("fs_collision_bits", audit.Required.FSCollisionBits, actual.FSCollisionBits)
	addMinMismatch("salt_bits", audit.Required.SaltBits, actual.SaltBits)
	addMinMismatch("prf_tag_elements", audit.Required.PRFTagElements, actual.PRFTagElements)

	if audit.Required.ROQueryCapLog2Set && actual.ROQueryCapLog2Set {
		for i := range audit.Required.ROQueryCapLog2 {
			if i >= len(actual.ROQueryCapLog2) {
				break
			}
			if math.Abs(audit.Required.ROQueryCapLog2[i]-actual.ROQueryCapLog2[i]) <= 1e-9 {
				continue
			}
			audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
				Parameter:   fmt.Sprintf("ro_query_cap_log2[%d]", i),
				Required:    fmt.Sprintf("%.0f", audit.Required.ROQueryCapLog2[i]),
				Actual:      fmt.Sprintf("%.0f", actual.ROQueryCapLog2[i]),
				Explanation: "the executed bounded-query scope differs from the selected security profile",
			})
		}
	}
	if len(audit.MissingActual) > 0 || len(audit.MissingEvidence) > 0 || len(audit.Mismatches) > 0 {
		audit.Status = "rejected"
	}
	return audit
}

func SecurityParameterAuditRejectionReasons(audit IntGenISISSecurityParameterAudit) []string {
	reasons := make([]string, 0, len(audit.MissingActual)+len(audit.MissingEvidence)+len(audit.Mismatches))
	for _, name := range audit.MissingActual {
		reasons = append(reasons, "missing actual security parameter "+name)
	}
	for _, name := range audit.MissingEvidence {
		reasons = append(reasons, "missing evidence for actual security parameter "+name)
	}
	for _, mismatch := range audit.Mismatches {
		reasons = append(reasons, fmt.Sprintf("parameter mismatch: %s actual %s required %s", mismatch.Parameter, mismatch.Actual, mismatch.Required))
	}
	return reasons
}
