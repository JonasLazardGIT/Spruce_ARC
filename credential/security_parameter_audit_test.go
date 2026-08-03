package credential

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestSecurityParameterAuditUsesActualTagLength(t *testing.T) {
	spec, ok := LookupIntGenISISSecurityProfile("BQ32-128")
	if !ok {
		t.Fatal("missing BQ32-128 profile")
	}
	actual := completeSecurityParameterActuals([5]float64{32, 32, 32, 32, 32})
	actual.DECSHashBits = 200
	actual.DECSTapeBits = 160
	actual.FSCollisionBits = 200
	actual.SaltBits = 192
	actual.PRFTagElements = 7
	audit := AuditIntGenISISSecurityParameters(spec, actual)
	if audit.Status != "rejected" {
		t.Fatalf("audit status=%q", audit.Status)
	}
	if len(audit.Mismatches) != 1 || audit.Mismatches[0].Parameter != "prf_tag_elements" {
		t.Fatalf("tag-7 mismatch=%+v", audit.Mismatches)
	}
	if audit.Actual.PRFTagElements != 7 || audit.Required.PRFTagElements != 10 {
		t.Fatalf("tag audit actual/required=(%d,%d)", audit.Actual.PRFTagElements, audit.Required.PRFTagElements)
	}
}

func TestSecurityParameterAuditRejectsWrongExecutedQueryScope(t *testing.T) {
	spec, _ := LookupIntGenISISSecurityProfile("BQ32-96")
	actual := completeSecurityParameterActuals([5]float64{10, 10, 10, 10, 10})
	audit := AuditIntGenISISSecurityParameters(spec, actual)
	if audit.Status != "rejected" || len(audit.Mismatches) != 5 {
		t.Fatalf("Q10 execution under BQ32 profile audit=%+v", audit)
	}
	for _, mismatch := range audit.Mismatches {
		if mismatch.Parameter[:17] != "ro_query_cap_log2" {
			t.Fatalf("unexpected mismatch: %+v", mismatch)
		}
	}
}

func TestSecurityParameterAuditAcceptsHardenedBQ32Pilot(t *testing.T) {
	spec, _ := LookupIntGenISISSecurityProfile("BQ32-96")
	audit := AuditIntGenISISSecurityParameters(spec, completeSecurityParameterActuals([5]float64{32, 32, 32, 32, 32}))
	if audit.Status != "pass" || len(audit.MissingActual) != 0 || len(audit.Mismatches) != 0 {
		t.Fatalf("hardened BQ32 audit=%+v", audit)
	}
}

func TestSecurityParameterAuditAcceptsUnsetWorkFactorQueryScope(t *testing.T) {
	spec, _ := LookupIntGenISISSecurityProfile("WF-128")
	actual := completeSecurityParameterActuals([5]float64{})
	actual.ROQueryCapLog2Set = false
	actual.DECSHashBits = 264
	actual.DECSTapeBits = 128
	actual.FSCollisionBits = 264
	actual.SaltBits = 256
	actual.PRFTagElements = 13
	actual.PRFProfile = IntGenISISPRFProfileTag13
	delete(actual.Evidence, "ro_query_cap_log2")
	audit := AuditIntGenISISSecurityParameters(spec, actual)
	if audit.Status != "pass" || audit.Required.ROQueryCapLog2Set || audit.Actual.ROQueryCapLog2Set {
		t.Fatalf("unbounded WF-128 audit=%+v", audit)
	}
	raw, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ro_query_cap_log2\"") {
		t.Fatalf("unbounded WF-128 audit serialized a query-cap vector: %s", raw)
	}
}

func TestSecurityParameterAuditRejectsMissingActualMetadata(t *testing.T) {
	spec, _ := LookupIntGenISISSecurityProfile("SC-96")
	audit := AuditIntGenISISSecurityParameters(spec, IntGenISISSecurityParameterActuals{})
	if audit.Status != "rejected" || len(audit.MissingActual) != 8 {
		t.Fatalf("missing actual audit=%+v", audit)
	}
}

func TestSecurityParameterAuditRejectsUnsubstantiatedActualValue(t *testing.T) {
	spec, _ := LookupIntGenISISSecurityProfile("BQ32-96")
	actual := completeSecurityParameterActuals([5]float64{32, 32, 32, 32, 32})
	delete(actual.Evidence, "salt_bits")
	audit := AuditIntGenISISSecurityParameters(spec, actual)
	if audit.Status != "rejected" || len(audit.MissingEvidence) != 1 || audit.MissingEvidence[0] != "salt_bits" {
		t.Fatalf("missing-evidence audit=%+v", audit)
	}
}

func TestSecurityParameterAuditRejectsInvalidActualQueryScope(t *testing.T) {
	spec, _ := LookupIntGenISISSecurityProfile("SC-96")
	actual := completeSecurityParameterActuals([5]float64{})
	actual.ROQueryCapLog2[2] = math.NaN()
	audit := AuditIntGenISISSecurityParameters(spec, actual)
	if audit.Status != "rejected" || len(audit.Mismatches) != 1 || audit.Mismatches[0].Parameter != "ro_query_cap_log2[2]" {
		t.Fatalf("invalid actual query scope audit=%+v", audit)
	}
}

func completeSecurityParameterActuals(caps [5]float64) IntGenISISSecurityParameterActuals {
	return IntGenISISSecurityParameterActuals{
		ROQueryCapLog2Set: true,
		ROQueryCapLog2:    append([]float64(nil), caps[:]...),
		DECSHashBits:      168,
		DECSTapeBits:      136,
		FSCollisionBits:   168,
		SaltBits:          168,
		PRFTagElements:    9,
		PRFProfile:        IntGenISISPRFProfileTag9,
		TranscriptMode:    "smallfield_2025_1085_salted_tapes_v2",
		Evidence: map[string]string{
			"ro_query_cap_log2": SecurityEvidenceMeasured,
			"decs_hash_bits":    SecurityEvidenceMeasured,
			"decs_tape_bits":    SecurityEvidenceMeasured,
			"fs_collision_bits": SecurityEvidenceMeasured,
			"salt_bits":         SecurityEvidenceMeasured,
			"prf_tag_elements":  SecurityEvidenceLoadedParams,
			"prf_profile":       SecurityEvidenceLoadedParams,
			"transcript_mode":   SecurityEvidenceMeasured,
		},
	}
}
