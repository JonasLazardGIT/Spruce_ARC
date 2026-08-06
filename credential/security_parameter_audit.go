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
	ROQueryCapLog2Set          bool            `json:"ro_query_cap_log2_set,omitempty"`
	ROQueryCapLog2             []float64       `json:"ro_query_cap_log2,omitempty"`
	ROQueryCapScope            ROQueryCapScope `json:"ro_query_cap_scope,omitempty"`
	AggregateROQueryCapLog2Set bool            `json:"aggregate_ro_query_cap_log2_set,omitempty"`
	AggregateROQueryCapLog2    float64         `json:"aggregate_ro_query_cap_log2,omitempty"`
	DECSHashBits               int             `json:"decs_hash_bits,omitempty"`
	DECSTapeBits               int             `json:"decs_tape_bits,omitempty"`
	FSCollisionBits            int             `json:"fs_collision_bits,omitempty"`
	FSOutputBits               int             `json:"fs_output_bits,omitempty"`
	SaltBits                   int             `json:"salt_bits,omitempty"`
	PRFTagElements             int             `json:"prf_tag_elements,omitempty"`
}

type IntGenISISSecurityParameterActuals struct {
	ROQueryCapLog2Set          bool              `json:"ro_query_cap_log2_set"`
	ROQueryCapLog2             []float64         `json:"ro_query_cap_log2,omitempty"`
	ROQueryCapScope            ROQueryCapScope   `json:"ro_query_cap_scope,omitempty"`
	AggregateROQueryCapLog2Set bool              `json:"aggregate_ro_query_cap_log2_set,omitempty"`
	AggregateROQueryCapLog2    float64           `json:"aggregate_ro_query_cap_log2,omitempty"`
	DECSHashBits               int               `json:"decs_hash_bits"`
	DECSTapeBits               int               `json:"decs_tape_bits"`
	FSCollisionBits            int               `json:"fs_collision_bits"`
	FSOutputBits               int               `json:"fs_output_bits,omitempty"`
	SaltBits                   int               `json:"salt_bits"`
	PRFTagElements             int               `json:"prf_tag_elements"`
	PRFProfile                 string            `json:"prf_profile,omitempty"`
	TranscriptMode             string            `json:"transcript_mode,omitempty"`
	Evidence                   map[string]string `json:"evidence"`
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
		ROQueryCapScope: spec.ROQueryCapScope,
		DECSHashBits:    spec.MinDECSHashBits,
		DECSTapeBits:    spec.MinDECSTapeBits,
		FSCollisionBits: spec.MinFSCollisionBits,
		FSOutputBits:    spec.MinFSOutputBits,
		SaltBits:        spec.MinSaltBits,
		PRFTagElements:  spec.MinPRFTagElements,
	}
	if len(spec.ROQueryCapBits) > 0 {
		if required.ROQueryCapScope == "" {
			required.ROQueryCapScope = ROQueryCapPerPhaseGlobal
		}
		required.ROQueryCapLog2Set = true
		required.ROQueryCapLog2 = append([]float64(nil), spec.ROQueryCapBits...)
	} else if len(spec.ROQueryCaps) > 0 {
		if required.ROQueryCapScope == "" {
			required.ROQueryCapScope = ROQueryCapPerPhaseGlobal
		}
		required.ROQueryCapLog2Set = true
		required.ROQueryCapLog2 = make([]float64, len(spec.ROQueryCaps))
		for i, cap := range spec.ROQueryCaps {
			if cap > 0 {
				required.ROQueryCapLog2[i] = math.Log2(float64(cap))
			}
		}
	} else if spec.AggregateROQueryCapLog2Set {
		if required.ROQueryCapScope == "" {
			required.ROQueryCapScope = ROQueryCapAggregateComposedGame
		}
		required.AggregateROQueryCapLog2Set = true
		required.AggregateROQueryCapLog2 = spec.AggregateROQueryCapLog2
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
	if !actual.AggregateROQueryCapLog2Set {
		actual.AggregateROQueryCapLog2 = 0
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
	if audit.Required.ROQueryCapLog2Set {
		requireActual("ro_query_cap_log2", actual.ROQueryCapLog2Set)
	} else if spec.Mode != SecurityModeQueryWorkFactor && !audit.Required.AggregateROQueryCapLog2Set {
		// Preserve the legacy single-candidate audit boundary: it records the
		// executed (uncapped) vector even when the profile has no fixed values.
		requireActual("ro_query_cap_log2", actual.ROQueryCapLog2Set)
	}
	if audit.Required.AggregateROQueryCapLog2Set {
		requireActual("aggregate_ro_query_cap_log2", actual.AggregateROQueryCapLog2Set)
	}
	if spec.ROQueryCapScope != "" {
		requireActual("ro_query_cap_scope", actual.ROQueryCapScope != "")
	}
	requireActual("decs_hash_bits", actual.DECSHashBits > 0)
	requireActual("decs_tape_bits", actual.DECSTapeBits > 0)
	requireActual("fs_collision_bits", actual.FSCollisionBits > 0)
	if spec.MinFSOutputBits > 0 {
		requireActual("fs_output_bits", actual.FSOutputBits > 0)
	}
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
	if actual.AggregateROQueryCapLog2Set && (!finitePositive(actual.AggregateROQueryCapLog2) || actual.ROQueryCapLog2Set) {
		audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
			Parameter:   "aggregate_ro_query_cap_log2",
			Required:    "one finite positive aggregate scalar with no legacy vector",
			Actual:      fmt.Sprintf("scalar=%v vector_set=%v", actual.AggregateROQueryCapLog2, actual.ROQueryCapLog2Set),
			Explanation: "publication-v4 uses one aggregate complete-game query budget",
		})
	}
	if audit.Required.ROQueryCapScope == ROQueryCapAggregateComposedGame && actual.ROQueryCapLog2Set {
		audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
			Parameter:   "ro_query_cap_log2",
			Required:    "unset under aggregate_composed_game",
			Actual:      "legacy vector is set",
			Explanation: "publication-v4 forbids per-domain or per-phase query-cap vectors",
		})
	}
	if audit.Required.ROQueryCapScope == ROQueryCapAggregateComposedGame && !audit.Required.AggregateROQueryCapLog2Set && actual.AggregateROQueryCapLog2Set {
		audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
			Parameter:   "aggregate_ro_query_cap_log2",
			Required:    "unset for the work-factor profile",
			Actual:      fmt.Sprintf("%.6f", actual.AggregateROQueryCapLog2),
			Explanation: "WF128 publishes a security curve rather than a bounded-query scalar",
		})
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
	addMinMismatch("fs_output_bits", audit.Required.FSOutputBits, actual.FSOutputBits)
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
	if audit.Required.AggregateROQueryCapLog2Set && actual.AggregateROQueryCapLog2Set {
		if math.Abs(audit.Required.AggregateROQueryCapLog2-actual.AggregateROQueryCapLog2) > 1e-9 {
			audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
				Parameter:   "aggregate_ro_query_cap_log2",
				Required:    fmt.Sprintf("%.6f", audit.Required.AggregateROQueryCapLog2),
				Actual:      fmt.Sprintf("%.6f", actual.AggregateROQueryCapLog2),
				Explanation: "the executed aggregate query budget differs from the publication profile",
			})
		}
	}
	if spec.ROQueryCapScope != "" && actual.ROQueryCapScope != "" && actual.ROQueryCapScope != audit.Required.ROQueryCapScope {
		audit.Mismatches = append(audit.Mismatches, IntGenISISSecurityParameterMismatch{
			Parameter:   "ro_query_cap_scope",
			Required:    string(audit.Required.ROQueryCapScope),
			Actual:      string(actual.ROQueryCapScope),
			Explanation: "the query budget is scoped to a different adversarial game",
		})
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
