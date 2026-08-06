package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"
)

// This file is deliberately target-only. It preserves the pre-fusion v3
// parameter-search decision that selected BQ L=43 and WF showing L=41; its
// 551/487-row projections and then-current paper totals are historical inputs,
// not the live post-fusion compiler geometry. Live strict-v3 geometry, exact
// accounting, and wire bytes are pinned by the PIOP target tests and the
// focused transcript-reduction evidence. Keeping this search snapshot stable
// demonstrates that the later structural reduction did not retune parameters,
// grinding, widths, or security caps.

const v3FrozenRetuneAuditVersion = 3

type v3FrozenPhase string

const (
	v3FrozenIssuance v3FrozenPhase = "issuance"
	v3FrozenShowing  v3FrozenPhase = "showing"
)

type v3FrozenRelationGeometry struct {
	LogicalRows      int `json:"logical_rows"`
	ParallelDegree   int `json:"parallel_degree"`
	AggregatedDegree int `json:"aggregated_degree"`
}

type v3FrozenTargetSpec struct {
	CanonicalID          string
	Kappa                [4]int
	ExpectedIssuePaper   int
	ExpectedShowingPaper int
	IssuanceRelation     v3FrozenRelationGeometry
	ShowingRelation      v3FrozenRelationGeometry
}

var v3FrozenTargetSpecs = []v3FrozenTargetSpec{
	{
		CanonicalID:          credential.IntGenISISPresetPoCN1024BQ128R128V3,
		Kappa:                [4]int{5, 6, 12, 13},
		ExpectedIssuePaper:   62614,
		ExpectedShowingPaper: 93416,
		IssuanceRelation:     v3FrozenRelationGeometry{LogicalRows: 165, ParallelDegree: 9, AggregatedDegree: 1},
		ShowingRelation:      v3FrozenRelationGeometry{LogicalRows: 551, ParallelDegree: 9, AggregatedDegree: 8},
	},
	{
		CanonicalID:          credential.IntGenISISPresetSystemN1024WF128CROMV2,
		Kappa:                [4]int{1, 0, 2, 13},
		ExpectedIssuePaper:   26672,
		ExpectedShowingPaper: 41284,
		IssuanceRelation:     v3FrozenRelationGeometry{LogicalRows: 165, ParallelDegree: 9, AggregatedDegree: 1},
		ShowingRelation:      v3FrozenRelationGeometry{LogicalRows: 487, ParallelDegree: 11, AggregatedDegree: 8},
	},
}

type v3FrozenGeometry struct {
	LogicalRows       int `json:"logical_rows"`
	ParallelDegree    int `json:"parallel_degree"`
	AggregatedDegree  int `json:"aggregated_degree"`
	DQParallel        int `json:"dq_parallel"`
	DQAggregate       int `json:"dq_aggregate"`
	DQ                int `json:"dq"`
	DDECS             int `json:"ddecs"`
	WitnessLayers     int `json:"witness_layers"`
	ReplayWitnessRows int `json:"replay_witness_rows"`
	MaskMu            int `json:"mask_mu"`
	MaskChunks        int `json:"mask_chunks"`
	MaskRows          int `json:"mask_rows"`
	OpeningRows       int `json:"opening_rows"`
	QueryCount        int `json:"query_count"`
	OpeningPCols      int `json:"opening_p_cols"`
	MerkleDepth       int `json:"merkle_depth"`
}

type v3FrozenSizeProjection struct {
	PaperStructuralBytes           int  `json:"paper_structural_bytes"`
	PaperFixedCalibrationBytes     int  `json:"paper_fixed_calibration_bytes"`
	PaperTranscriptBytes           int  `json:"paper_transcript_bytes"`
	CanonicalStructuralBytes       int  `json:"canonical_structural_bytes"`
	CanonicalFixedCalibrationBytes int  `json:"canonical_fixed_calibration_bytes"`
	CanonicalProofWireBytes        int  `json:"canonical_proof_wire_bytes_projection"`
	CanonicalPresentationBytes     int  `json:"canonical_presentation_wire_bytes_projection,omitempty"`
	PresentationOverheadBytes      int  `json:"presentation_overhead_bytes,omitempty"`
	CounterWidthClassFrozen        bool `json:"counter_width_class_frozen"`
	RequiresFreshWireMeasurement   bool `json:"requires_fresh_wire_measurement"`
}

type v3FrozenSecurityProjection struct {
	RawRoundBits       [4]float64 `json:"raw_round_bits"`
	QueryAdjustedBits  [4]float64 `json:"query_adjusted_bits"`
	AlgebraicTotalBits float64    `json:"algebraic_total_bits"`
	CollisionBits      float64    `json:"collision_bits"`
	OneProofTotalBits  float64    `json:"one_proof_total_bits"`
	TapeGuessingBits   float64    `json:"tape_guessing_bits"`
	TheoremTargetBits  float64    `json:"theorem_target_bits"`
	SecurityTargetBits float64    `json:"security_target_bits"`
	TheoremSlackBits   float64    `json:"theorem_slack_bits"`
}

type v3FrozenGates struct {
	FrozenKnobs      bool `json:"frozen_knobs"`
	Kappa            bool `json:"kappa"`
	NLeaves          bool `json:"nleaves"`
	Work             bool `json:"work"`
	NDECSByEta       bool `json:"ndecs_by_eta"`
	FourTerms        bool `json:"four_terms"`
	Collision        bool `json:"collision"`
	OneProof         bool `json:"one_proof"`
	PrimitiveProfile bool `json:"primitive_profile"`
	ZeroKnowledge    bool `json:"zero_knowledge"`
	FieldProfile     bool `json:"field_profile"`
	Transcript       bool `json:"transcript"`
	Manifest         bool `json:"manifest"`
}

func (g v3FrozenGates) all() bool {
	return g.FrozenKnobs && g.Kappa && g.NLeaves && g.Work && g.NDECSByEta &&
		g.FourTerms && g.Collision && g.OneProof && g.PrimitiveProfile &&
		g.ZeroKnowledge && g.FieldProfile && g.Transcript && g.Manifest
}

type v3FrozenCandidate struct {
	Phase                 v3FrozenPhase                     `json:"phase"`
	Tuning                credential.IntGenISISTuningPreset `json:"tuning"`
	Geometry              v3FrozenGeometry                  `json:"geometry"`
	Sizes                 v3FrozenSizeProjection            `json:"sizes"`
	Security              v3FrozenSecurityProjection        `json:"security"`
	Gates                 v3FrozenGates                     `json:"gates"`
	ProjectedWorkUnits    uint64                            `json:"projected_work_units"`
	NDECSByEta            uint64                            `json:"ndecs_by_eta"`
	Baseline              bool                              `json:"baseline"`
	ProjectionEligible    bool                              `json:"projection_eligible"`
	ProjectedSizeImproves bool                              `json:"projected_size_improves"`
	AdoptionEligible      bool                              `json:"adoption_eligible"`
	RejectionReasons      []string                          `json:"rejection_reasons,omitempty"`
}

type v3FrozenPhaseSearch struct {
	Phase                     v3FrozenPhase       `json:"phase"`
	CandidateCount            int                 `json:"candidate_count"`
	ProjectionEligibleCount   int                 `json:"projection_eligible_count"`
	ProjectedImprovementCount int                 `json:"projected_improvement_count"`
	AdoptionEligibleCount     int                 `json:"adoption_eligible_count"`
	Baseline                  v3FrozenCandidate   `json:"baseline"`
	Winner                    v3FrozenCandidate   `json:"winner"`
	Top                       []v3FrozenCandidate `json:"top,omitempty"`
	RejectionCounts           map[string]int      `json:"rejection_counts"`
	SelectionOrder            []string            `json:"selection_order"`
	all                       []v3FrozenCandidate
}

type v3FrozenCombinedCandidate struct {
	Issuance                 v3FrozenCandidate `json:"issuance"`
	Showing                  v3FrozenCandidate `json:"showing"`
	PresentationWireBytes    int               `json:"canonical_presentation_wire_bytes_projection"`
	ShowingPaperBytes        int               `json:"showing_paper_bytes"`
	CombinedPaperBytes       int               `json:"combined_paper_bytes"`
	TotalWorkUnits           uint64            `json:"total_work_units"`
	MaxPhaseNLeaves          int               `json:"max_phase_nleaves"`
	MinimumTheoremSlackBits  float64           `json:"minimum_theorem_slack_bits"`
	RequiresFreshMeasurement bool              `json:"requires_fresh_measurement"`
}

type v3FrozenPresetAudit struct {
	CanonicalID                string                    `json:"canonical_id"`
	ManifestDigest             string                    `json:"manifest_digest"`
	ClaimScope                 credential.ClaimScope     `json:"claim_scope"`
	Issuance                   v3FrozenPhaseSearch       `json:"issuance"`
	Showing                    v3FrozenPhaseSearch       `json:"showing"`
	CombinedWinner             v3FrozenCombinedCandidate `json:"combined_winner"`
	CombinedSelectionOrder     []string                  `json:"combined_selection_order"`
	CombinedPaperBaseline      int                       `json:"combined_paper_baseline"`
	CombinedPaperWinner        int                       `json:"combined_paper_winner"`
	ProjectedPresentationDelta int                       `json:"projected_presentation_delta"`
	RequiresThreeRunGate       bool                      `json:"requires_three_run_gate"`
	HistoricalWinnerReasons    []string                  `json:"historical_winner_rejection_reasons"`
}

type v3FrozenRetuneAudit struct {
	Version         int                   `json:"version"`
	GeneratedAt     string                `json:"generated_at"`
	Status          string                `json:"status"`
	SearchScope     string                `json:"search_scope"`
	NoGrinding      string                `json:"no_grinding_policy"`
	MeasurementRule string                `json:"measurement_rule"`
	Presets         []v3FrozenPresetAudit `json:"presets"`
}

type v3FrozenProjectionCalibration struct {
	PaperBaseline     int
	CanonicalBaseline int
}

func v3FrozenSpecFor(id string) (v3FrozenTargetSpec, bool) {
	for _, spec := range v3FrozenTargetSpecs {
		if id == spec.CanonicalID {
			return spec, true
		}
	}
	return v3FrozenTargetSpec{}, false
}

func v3FrozenTuningForPhase(preset credential.IntGenISISPreset, phase v3FrozenPhase) credential.IntGenISISTuningPreset {
	if phase == v3FrozenIssuance {
		return preset.Issuance
	}
	return preset.Showing
}

func v3FrozenRelationForPhase(spec v3FrozenTargetSpec, phase v3FrozenPhase) v3FrozenRelationGeometry {
	if phase == v3FrozenIssuance {
		return spec.IssuanceRelation
	}
	return spec.ShowingRelation
}

func v3FrozenExpectedPaperForPhase(spec v3FrozenTargetSpec, phase v3FrozenPhase) int {
	if phase == v3FrozenIssuance {
		return spec.ExpectedIssuePaper
	}
	return spec.ExpectedShowingPaper
}

func v3FrozenExpectedPaperForTuning(spec v3FrozenTargetSpec, phase v3FrozenPhase, tuning credential.IntGenISISTuningPreset) int {
	if spec.CanonicalID == credential.IntGenISISPresetSystemN1024WF128CROMV2 && phase == v3FrozenShowing && tuning.LVCSNCols == 41 {
		return 40950
	}
	return v3FrozenExpectedPaperForPhase(spec, phase)
}

func v3FrozenGeometryFor(t credential.IntGenISISTuningPreset, relation v3FrozenRelationGeometry) (v3FrozenGeometry, error) {
	if t.NCols != 32 || t.LVCSNCols < 32 || t.NLeaves <= 1 || t.NLeaves >= int(credential.IntGenISISSharedModulusQ) ||
		t.Eta <= 0 || t.Theta <= 1 || t.Rho != 1 || t.Ell <= 0 || t.EllPrime != 1 ||
		relation.LogicalRows <= 0 || relation.ParallelDegree <= 0 || relation.AggregatedDegree <= 0 {
		return v3FrozenGeometry{}, fmt.Errorf("invalid strict-v3 target geometry")
	}
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(
		relation.ParallelDegree, relation.AggregatedDegree, t.NCols, t.Ell,
	)
	layers := ceilDivInt(relation.LogicalRows, t.LVCSNCols)
	mu := ceilDivInt(dq, t.LVCSNCols)
	maskChunks := mu + 1 // Eq. (2): mu=ceil(dQ/L), followed by rows 0..mu.
	replayRows := layers * (t.NCols + t.Theta)
	maskRows := maskChunks * t.Theta * t.Rho
	openingRows := replayRows + maskRows
	queryCount := (layers + 1) * t.Theta
	if queryCount >= openingRows {
		return v3FrozenGeometry{}, fmt.Errorf("query count %d exhausts opening rows %d", queryCount, openingRows)
	}
	return v3FrozenGeometry{
		LogicalRows:       relation.LogicalRows,
		ParallelDegree:    relation.ParallelDegree,
		AggregatedDegree:  relation.AggregatedDegree,
		DQParallel:        dqParallel,
		DQAggregate:       dqAggregate,
		DQ:                dq,
		DDECS:             t.LVCSNCols + t.Ell - 1,
		WitnessLayers:     layers,
		ReplayWitnessRows: replayRows,
		MaskMu:            mu,
		MaskChunks:        maskChunks,
		MaskRows:          maskRows,
		OpeningRows:       openingRows,
		QueryCount:        queryCount,
		OpeningPCols:      openingRows - queryCount,
		MerkleDepth:       v3FrozenMerkleDepth(t.NLeaves),
	}, nil
}

func v3FrozenMerkleDepth(n int) int {
	depth := 0
	for size := 1; size < n; size <<= 1 {
		depth++
	}
	return depth
}

func v3FrozenPackedFq20Bytes(elements int) int {
	return (elements*20 + 7) / 8
}

func v3FrozenCeilBits(bits float64) int {
	return int(math.Ceil(bits / 8))
}

// v3FrozenPaperStructuralBytes is the exact varying part of the paper-facing
// projection.  The phase-independent 680-byte (BQ128) / 648-byte (WF128)
// framing term is recovered by calibrating at the corrected incumbent.  This
// keeps old v2 accounting untouched while making every grid delta exact.
func v3FrozenPaperStructuralBytes(t credential.IntGenISISTuningPreset, g v3FrozenGeometry) int {
	logQ := math.Log2(float64(credential.IntGenISISSharedModulusQ))
	rBytes := v3FrozenCeilBits(float64(t.Eta*t.LVCSNCols) * logQ)
	qElems := t.Rho * maxInt(g.DQ-(t.EllPrime+1), 0) * t.Theta
	qBytes := v3FrozenCeilBits(float64(qElems) * logQ)
	// The maintained paper report includes the canonical ten-byte packed-matrix
	// frame for each independently transmitted VTargets/BarSets matrix.
	vBytes := nizkProfilePackedMatrixHeaderBytes + v3FrozenPackedFq20Bytes(g.QueryCount*t.LVCSNCols)
	barBytes := nizkProfilePackedMatrixHeaderBytes + v3FrozenPackedFq20Bytes(g.QueryCount*t.Ell)
	pBytes := v3FrozenPackedFq20Bytes(t.Ell * g.OpeningPCols)
	authBytes := t.Ell * g.MerkleDepth * (t.DECSHashBits / 8)
	tapeBytes := t.Ell * (t.DECSTapeBits / 8)
	return rBytes + qBytes + vBytes + barBytes + pBytes + authBytes + tapeBytes
}

// v3FrozenCanonicalStructuralBytes exactly counts all varying 20-bit matrices,
// fixed worst-case positional multiproof padding, and independent tapes.  The
// calibrated fixed term contains magic/version/kind, root, salt, and the four
// actual minimal-LEB128 counters from the incumbent run.  A candidate remains
// a projection until a fresh proof confirms that its counters stay in the same
// byte-width class; the adoption gate below therefore always requires fresh
// wire measurement.
func v3FrozenCanonicalStructuralBytes(t credential.IntGenISISTuningPreset, g v3FrozenGeometry) int {
	rBytes := v3FrozenPackedFq20Bytes(t.Eta * (g.DDECS + 1))
	qBytes := v3FrozenPackedFq20Bytes(t.Theta * (g.DQ + 1))
	vBytes := v3FrozenPackedFq20Bytes(g.QueryCount * t.LVCSNCols)
	barBytes := v3FrozenPackedFq20Bytes(g.QueryCount * t.Ell)
	pBytes := v3FrozenPackedFq20Bytes(t.Ell * g.OpeningPCols)
	authNodes, err := decs.MerkleFrontierWorstCaseNodesV3(t.NLeaves, t.Ell)
	if err != nil {
		// Every caller first validates the candidate geometry. Reaching this
		// branch is therefore an internal search bug, not an ineligible point.
		panic(fmt.Sprintf("strict-v3 Merkle frontier bound: %v", err))
	}
	authBytes := authNodes * (t.DECSHashBits / 8)
	tapeBytes := t.Ell * (t.DECSTapeBits / 8)
	return rBytes + qBytes + vBytes + barBytes + pBytes + authBytes + tapeBytes
}

func v3FrozenNominalCounterBytes(kappa [4]int) int {
	// This is a counter-width class, not a bound: 2^k-1 is the final value in
	// the nominal grinding interval.  Actual bytes are calibrated from a fresh
	// proof whenever available and are remeasured before adoption.
	total := 0
	for _, k := range kappa {
		value := uint64(0)
		if k > 0 {
			value = (uint64(1) << uint(k)) - 1
		}
		for {
			total++
			value >>= 7
			if value == 0 {
				break
			}
		}
	}
	return total
}

func v3FrozenCanonicalDefaultFixedBytes(t credential.IntGenISISTuningPreset) int {
	return 10 + t.DECSHashBits/8 + (t.SaltBits+7)/8 + v3FrozenNominalCounterBytes(t.Kappa)
}

func v3FrozenPresentationOverhead(preset credential.IntGenISISPreset) (int, error) {
	tagElements, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok {
		return 0, fmt.Errorf("unknown PRF profile %q", preset.PRFProfile)
	}
	return 8 + v3FrozenPackedFq20Bytes(tagElements), nil
}

func v3FrozenQueryCapBits(t credential.IntGenISISTuningPreset) [5]float64 {
	if t.ROQueryCapBitsSet {
		return t.ROQueryCapBits
	}
	var out [5]float64
	if t.ROQueryCapsSet {
		for i, cap := range t.ROQueryCaps {
			if cap > 0 {
				out[i] = math.Log2(float64(cap))
			}
		}
	}
	// An unset cap is the executable default of one query, i.e. log2(1)=0.
	return out
}

func v3FrozenSecurityFor(preset credential.IntGenISISPreset, t credential.IntGenISISTuningPreset, g v3FrozenGeometry) (v3FrozenSecurityProjection, error) {
	profile, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		return v3FrozenSecurityProjection{}, fmt.Errorf("missing security profile %q", preset.SecurityProfile)
	}
	q := float64(credential.IntGenISISSharedModulusQ)
	logQ := math.Log2(q)
	raw := [4]float64{
		float64(t.Eta)*logQ - credential.Log2Binom(uint64(t.NLeaves), uint64(g.DDECS+2)),
		float64(t.Theta*t.Rho) * logQ,
		math.Log2(math.Pow(q, float64(t.Theta))-float64(t.NCols)) - math.Log2(float64(g.DQ)),
		credential.Log2Binom(uint64(t.NLeaves), uint64(t.Ell)) - credential.Log2Binom(uint64(g.DDECS), uint64(t.Ell)),
	}
	caps := v3FrozenQueryCapBits(t)
	var adjusted [4]float64
	for i := range adjusted {
		adjusted[i] = raw[i] - caps[i+1] + float64(t.Kappa[i])
		if adjusted[i] < 0 {
			adjusted[i] = 0
		}
	}
	algebraic := v3FrozenAggregateBits(adjusted[:])
	collisionSpace := minPositiveIntLocal(t.DECSHashBits, t.FSCollisionBits)
	if collisionSpace <= 0 {
		collisionSpace = maxInt(t.DECSHashBits, t.FSCollisionBits)
	}
	collisionTerms := make([]float64, 0, len(caps))
	for _, capBits := range caps {
		collisionTerms = append(collisionTerms, float64(collisionSpace)-2*capBits)
	}
	collision := v3FrozenAggregateBits(collisionTerms)
	oneProof := v3FrozenAggregateBits([]float64{algebraic, collision})
	maxCap := 0.0
	for _, cap := range caps {
		if cap > maxCap {
			maxCap = cap
		}
	}
	tapeGuessing := float64(t.DECSTapeBits) - maxCap
	return v3FrozenSecurityProjection{
		RawRoundBits:       raw,
		QueryAdjustedBits:  adjusted,
		AlgebraicTotalBits: algebraic,
		CollisionBits:      collision,
		OneProofTotalBits:  oneProof,
		TapeGuessingBits:   tapeGuessing,
		TheoremTargetBits:  preset.TargetTheoremBits,
		SecurityTargetBits: profile.TargetBits,
		TheoremSlackBits:   algebraic - preset.TargetTheoremBits,
	}, nil
}

func v3FrozenAggregateBits(bits []float64) float64 {
	if len(bits) == 0 {
		return 0
	}
	minBits := math.Inf(1)
	for _, bit := range bits {
		if bit <= 0 || math.IsNaN(bit) {
			return 0
		}
		if bit < minBits {
			minBits = bit
		}
	}
	sum := 0.0
	for _, bit := range bits {
		sum += math.Exp2(-(bit - minBits))
	}
	return minBits - math.Log2(sum)
}

func v3FrozenNonGridFieldsEqual(base, candidate credential.IntGenISISTuningPreset) bool {
	candidate.LVCSNCols = base.LVCSNCols
	candidate.NLeaves = base.NLeaves
	candidate.Eta = base.Eta
	candidate.Theta = base.Theta
	candidate.Ell = base.Ell
	return reflect.DeepEqual(base, candidate)
}

func v3FrozenTranscriptGate(t credential.IntGenISISTuningPreset) bool {
	return t.NCols == 32 && t.Rho == 1 && t.EllPrime == 1 && t.FixedTranscriptSize &&
		t.TranscriptMode == credential.IntGenISISTranscriptProtocolV3 &&
		t.TranscriptOmissionMode == credential.IntGenISISTranscriptOmissionModeV3 &&
		t.SoundnessGate == credential.IntGenISISSecurityGateV3 &&
		t.RelationVersion == 3 && t.LayoutVersion == 3
}

func v3FrozenPrimitiveProfileGate(preset credential.IntGenISISPreset, t credential.IntGenISISTuningPreset) bool {
	profile, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		return false
	}
	tagElements, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok {
		return false
	}
	caps := v3FrozenQueryCapBits(t)
	evidence := map[string]string{
		"ro_query_cap_log2": credential.SecurityEvidenceExecutedPreset,
		"decs_hash_bits":    credential.SecurityEvidenceExecutedPreset,
		"decs_tape_bits":    credential.SecurityEvidenceExecutedPreset,
		"fs_collision_bits": credential.SecurityEvidenceExecutedPreset,
		"salt_bits":         credential.SecurityEvidenceExecutedPreset,
		"prf_tag_elements":  credential.SecurityEvidenceLoadedParams,
		"prf_profile":       credential.SecurityEvidenceLoadedParams,
		"transcript_mode":   credential.SecurityEvidenceExecutedPreset,
	}
	audit := credential.AuditIntGenISISSecurityParameters(profile, credential.IntGenISISSecurityParameterActuals{
		ROQueryCapLog2Set: t.ROQueryCapBitsSet || t.ROQueryCapsSet,
		ROQueryCapLog2:    caps[:],
		DECSHashBits:      t.DECSHashBits,
		DECSTapeBits:      t.DECSTapeBits,
		FSCollisionBits:   t.FSCollisionBits,
		SaltBits:          t.SaltBits,
		PRFTagElements:    tagElements,
		PRFProfile:        preset.PRFProfile,
		TranscriptMode:    t.TranscriptMode,
		Evidence:          evidence,
	})
	return audit.Status == "pass"
}

func v3FrozenProspectiveManifestGate(preset credential.IntGenISISPreset, phase v3FrozenPhase, t credential.IntGenISISTuningPreset) bool {
	prospective := preset
	if phase == v3FrozenIssuance {
		prospective.Issuance = t
	} else {
		prospective.Showing = t
		prospective.LVCSNCols = t.LVCSNCols
	}
	prospective.MaxNLeaves = maxInt(prospective.Issuance.NLeaves, prospective.Showing.NLeaves)
	return credential.ValidateIntGenISISPresetManifest(prospective) == nil
}

func v3FrozenProjectCandidate(
	preset credential.IntGenISISPreset,
	spec v3FrozenTargetSpec,
	phase v3FrozenPhase,
	t credential.IntGenISISTuningPreset,
	relation v3FrozenRelationGeometry,
	baseline v3FrozenCandidate,
	calibration v3FrozenProjectionCalibration,
) (v3FrozenCandidate, error) {
	g, err := v3FrozenGeometryFor(t, relation)
	if err != nil {
		return v3FrozenCandidate{}, err
	}
	security, err := v3FrozenSecurityFor(preset, t, g)
	if err != nil {
		return v3FrozenCandidate{}, err
	}
	paperStructural := v3FrozenPaperStructuralBytes(t, g)
	canonicalStructural := v3FrozenCanonicalStructuralBytes(t, g)
	presentationOverhead, err := v3FrozenPresentationOverhead(preset)
	if err != nil {
		return v3FrozenCandidate{}, err
	}
	baseTuning := v3FrozenTuningForPhase(preset, phase)
	baselineWork := baseline.ProjectedWorkUnits
	baselineNDECSByEta := baseline.NDECSByEta
	work := uint64(t.NLeaves)*uint64(g.OpeningRows) + uint64(t.Theta)*uint64(g.DQ)
	ndecsByEta := uint64(t.NLeaves) * uint64(t.Eta)
	_, fieldProfileOK := kf.LookupSmallWoodFieldProfileV3(credential.IntGenISISSharedModulusQ, t.Theta)
	profile, profileOK := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	gates := v3FrozenGates{
		FrozenKnobs:      v3FrozenNonGridFieldsEqual(baseTuning, t),
		Kappa:            t.Kappa == spec.Kappa && t.Kappa == baseTuning.Kappa,
		NLeaves:          baselineWork == 0 || t.NLeaves <= baseTuning.NLeaves,
		Work:             baselineWork == 0 || work <= baselineWork,
		NDECSByEta:       baselineNDECSByEta == 0 || ndecsByEta <= baselineNDECSByEta,
		FourTerms:        security.AlgebraicTotalBits+1e-9 >= preset.TargetTheoremBits,
		Collision:        profileOK && security.CollisionBits+1e-9 >= profile.TargetBits,
		OneProof:         profileOK && security.OneProofTotalBits+1e-9 >= profile.TargetBits,
		PrimitiveProfile: v3FrozenPrimitiveProfileGate(preset, t),
		ZeroKnowledge:    profileOK && security.TapeGuessingBits+1e-9 >= profile.TargetBits,
		FieldProfile:     fieldProfileOK && t.Theta == baseTuning.Theta,
		Transcript:       v3FrozenTranscriptGate(t),
		Manifest:         v3FrozenProspectiveManifestGate(preset, phase, t),
	}
	candidate := v3FrozenCandidate{
		Phase:              phase,
		Tuning:             t,
		Geometry:           g,
		ProjectedWorkUnits: work,
		NDECSByEta:         ndecsByEta,
		Security:           security,
		Gates:              gates,
		Sizes: v3FrozenSizeProjection{
			PaperStructuralBytes:           paperStructural,
			PaperFixedCalibrationBytes:     calibration.PaperBaseline - v3FrozenPaperStructuralBytes(baseTuning, baseline.Geometry),
			CanonicalStructuralBytes:       canonicalStructural,
			CanonicalFixedCalibrationBytes: calibration.CanonicalBaseline - v3FrozenCanonicalStructuralBytes(baseTuning, baseline.Geometry),
			PresentationOverheadBytes:      presentationOverhead,
			CounterWidthClassFrozen:        t.Kappa == baseTuning.Kappa,
			RequiresFreshWireMeasurement:   true,
		},
	}
	candidate.Sizes.PaperTranscriptBytes = candidate.Sizes.PaperStructuralBytes + candidate.Sizes.PaperFixedCalibrationBytes
	candidate.Sizes.CanonicalProofWireBytes = candidate.Sizes.CanonicalStructuralBytes + candidate.Sizes.CanonicalFixedCalibrationBytes
	if phase == v3FrozenShowing {
		candidate.Sizes.CanonicalPresentationBytes = candidate.Sizes.CanonicalProofWireBytes + presentationOverhead
	}
	candidate.Baseline = t == baseTuning
	candidate.ProjectionEligible = gates.all()
	if phase == v3FrozenShowing {
		candidate.ProjectedSizeImproves = candidate.Sizes.CanonicalPresentationBytes < baseline.Sizes.CanonicalPresentationBytes
	} else {
		candidate.ProjectedSizeImproves = candidate.Sizes.CanonicalProofWireBytes < baseline.Sizes.CanonicalProofWireBytes
	}
	// Analytic eligibility is intentionally not called adoption eligibility:
	// the latter remains false until three fresh actual-wire/resource runs pass.
	candidate.AdoptionEligible = candidate.ProjectionEligible && candidate.ProjectedSizeImproves && !candidate.Sizes.RequiresFreshWireMeasurement
	candidate.RejectionReasons = v3FrozenGateRejectionReasons(candidate, baseline)
	return candidate, nil
}

func v3FrozenGateRejectionReasons(c v3FrozenCandidate, baseline v3FrozenCandidate) []string {
	var reasons []string
	add := func(ok bool, reason string) {
		if !ok {
			reasons = append(reasons, reason)
		}
	}
	add(c.Gates.FrozenKnobs, "changed a frozen non-grid knob")
	add(c.Gates.Kappa, "changed frozen kappa")
	add(c.Gates.NLeaves, "increased NLeaves")
	add(c.Gates.Work, "increased corrected projected work")
	add(c.Gates.NDECSByEta, "increased NDECS*eta")
	add(c.Gates.FourTerms, "four-term query-adjusted algebraic gate failed")
	add(c.Gates.Collision, "collision gate failed")
	add(c.Gates.OneProof, "one-proof algebraic-plus-collision gate failed")
	add(c.Gates.PrimitiveProfile, "primitive-profile gate failed")
	add(c.Gates.ZeroKnowledge, "zero-knowledge tape gate failed")
	add(c.Gates.FieldProfile, "fixed public field-profile gate failed")
	add(c.Gates.Transcript, "strict-v3 transcript gate failed")
	add(c.Gates.Manifest, "prospective manifest-v3 gate failed")
	if c.ProjectionEligible && !c.ProjectedSizeImproves && !c.Baseline {
		reasons = append(reasons, "does not improve projected canonical wire size")
	}
	if c.ProjectionEligible && c.ProjectedSizeImproves && c.Sizes.RequiresFreshWireMeasurement {
		reasons = append(reasons, "fresh actual wire plus three-run time/memory gate pending")
	}
	_ = baseline
	return reasons
}

func v3FrozenBaselineCandidate(
	preset credential.IntGenISISPreset,
	spec v3FrozenTargetSpec,
	phase v3FrozenPhase,
	relation v3FrozenRelationGeometry,
	calibration v3FrozenProjectionCalibration,
) (v3FrozenCandidate, error) {
	t := v3FrozenTuningForPhase(preset, phase)
	g, err := v3FrozenGeometryFor(t, relation)
	if err != nil {
		return v3FrozenCandidate{}, err
	}
	security, err := v3FrozenSecurityFor(preset, t, g)
	if err != nil {
		return v3FrozenCandidate{}, err
	}
	paperStructural := v3FrozenPaperStructuralBytes(t, g)
	canonicalStructural := v3FrozenCanonicalStructuralBytes(t, g)
	if calibration.PaperBaseline <= 0 {
		calibration.PaperBaseline = v3FrozenExpectedPaperForTuning(spec, phase, t)
	}
	if calibration.CanonicalBaseline <= 0 {
		calibration.CanonicalBaseline = canonicalStructural + v3FrozenCanonicalDefaultFixedBytes(t)
	}
	overhead, err := v3FrozenPresentationOverhead(preset)
	if err != nil {
		return v3FrozenCandidate{}, err
	}
	work := uint64(t.NLeaves)*uint64(g.OpeningRows) + uint64(t.Theta)*uint64(g.DQ)
	baseline := v3FrozenCandidate{
		Phase:                 phase,
		Tuning:                t,
		Geometry:              g,
		ProjectedWorkUnits:    work,
		NDECSByEta:            uint64(t.NLeaves) * uint64(t.Eta),
		Security:              security,
		Baseline:              true,
		ProjectionEligible:    true,
		ProjectedSizeImproves: false,
		Sizes: v3FrozenSizeProjection{
			PaperStructuralBytes:           paperStructural,
			PaperFixedCalibrationBytes:     calibration.PaperBaseline - paperStructural,
			PaperTranscriptBytes:           calibration.PaperBaseline,
			CanonicalStructuralBytes:       canonicalStructural,
			CanonicalFixedCalibrationBytes: calibration.CanonicalBaseline - canonicalStructural,
			CanonicalProofWireBytes:        calibration.CanonicalBaseline,
			PresentationOverheadBytes:      overhead,
			CounterWidthClassFrozen:        true,
			RequiresFreshWireMeasurement:   true,
		},
	}
	if phase == v3FrozenShowing {
		baseline.Sizes.CanonicalPresentationBytes = calibration.CanonicalBaseline + overhead
	}
	baseline.Gates = v3FrozenGates{
		FrozenKnobs: true, Kappa: true, NLeaves: true, Work: true, NDECSByEta: true,
		FourTerms:        security.AlgebraicTotalBits+1e-9 >= preset.TargetTheoremBits,
		Collision:        security.CollisionBits+1e-9 >= security.SecurityTargetBits,
		OneProof:         security.OneProofTotalBits+1e-9 >= security.SecurityTargetBits,
		PrimitiveProfile: v3FrozenPrimitiveProfileGate(preset, t),
		ZeroKnowledge:    security.TapeGuessingBits+1e-9 >= security.SecurityTargetBits,
		FieldProfile: func() bool {
			_, ok := kf.LookupSmallWoodFieldProfileV3(credential.IntGenISISSharedModulusQ, t.Theta)
			return ok
		}(),
		Transcript: v3FrozenTranscriptGate(t),
		Manifest:   credential.ValidateIntGenISISPresetManifest(preset) == nil,
	}
	baseline.ProjectionEligible = baseline.Gates.all()
	baseline.RejectionReasons = v3FrozenGateRejectionReasons(baseline, baseline)
	return baseline, nil
}

func v3FrozenSearchPhase(
	preset credential.IntGenISISPreset,
	spec v3FrozenTargetSpec,
	phase v3FrozenPhase,
	relation v3FrozenRelationGeometry,
	calibration v3FrozenProjectionCalibration,
) (v3FrozenPhaseSearch, error) {
	baseline, err := v3FrozenBaselineCandidate(preset, spec, phase, relation, calibration)
	if err != nil {
		return v3FrozenPhaseSearch{}, err
	}
	if !baseline.ProjectionEligible {
		return v3FrozenPhaseSearch{}, fmt.Errorf("%s %s corrected incumbent fails gates: %v", preset.CanonicalID, phase, baseline.RejectionReasons)
	}
	calibration.PaperBaseline = baseline.Sizes.PaperTranscriptBytes
	calibration.CanonicalBaseline = baseline.Sizes.CanonicalProofWireBytes
	incumbent := v3FrozenTuningForPhase(preset, phase)
	candidates := make([]v3FrozenCandidate, 0, 50000)
	for lvcs := maxInt(32, incumbent.LVCSNCols-4); lvcs <= incumbent.LVCSNCols+4; lvcs++ {
		for leafStep := -32; leafStep <= 0; leafStep++ {
			nleaves := incumbent.NLeaves + leafStep*16384
			if nleaves <= 1 || uint64(nleaves) >= credential.IntGenISISSharedModulusQ {
				continue
			}
			for eta := maxInt(1, incumbent.Eta-8); eta <= incumbent.Eta+2; eta++ {
				for theta := maxInt(2, incumbent.Theta-1); theta <= incumbent.Theta+1; theta++ {
					for ell := maxInt(1, incumbent.Ell-2); ell <= incumbent.Ell+2; ell++ {
						t := incumbent
						t.LVCSNCols, t.NLeaves, t.Eta, t.Theta, t.Ell = lvcs, nleaves, eta, theta, ell
						candidate, projectErr := v3FrozenProjectCandidate(preset, spec, phase, t, relation, baseline, calibration)
						if projectErr != nil {
							return v3FrozenPhaseSearch{}, projectErr
						}
						candidates = append(candidates, candidate)
					}
				}
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return v3FrozenPhaseCandidateLess(candidates[i], candidates[j])
	})
	search := v3FrozenPhaseSearch{
		Phase:           phase,
		CandidateCount:  len(candidates),
		Baseline:        baseline,
		Winner:          baseline,
		RejectionCounts: make(map[string]int),
		SelectionOrder: []string{
			"projection_gate", "projected_canonical_presentation_or_proof_bytes", "paper_phase_bytes",
			"projected_work", "nleaves", "theorem_slack_desc", "lexicographic_tuning",
		},
		all: candidates,
	}
	for _, candidate := range candidates {
		if candidate.ProjectionEligible {
			search.ProjectionEligibleCount++
			if candidate.ProjectedSizeImproves {
				search.ProjectedImprovementCount++
			}
		}
		if candidate.AdoptionEligible {
			search.AdoptionEligibleCount++
		}
		for _, reason := range candidate.RejectionReasons {
			search.RejectionCounts[reason]++
		}
	}
	// A no-change incumbent remains the selected result when no projected
	// improvement exists.  Projected improvements are still explicitly marked
	// measurement-pending, so this does not claim adoption.
	for _, candidate := range candidates {
		if !candidate.ProjectionEligible {
			continue
		}
		if candidate.Baseline || candidate.ProjectedSizeImproves {
			search.Winner = candidate
			break
		}
	}
	limit := 8
	if len(candidates) < limit {
		limit = len(candidates)
	}
	search.Top = append([]v3FrozenCandidate(nil), candidates[:limit]...)
	return search, nil
}

func v3FrozenCombinedFrom(issue, show v3FrozenCandidate) v3FrozenCombinedCandidate {
	return v3FrozenCombinedCandidate{
		Issuance:                 issue,
		Showing:                  show,
		PresentationWireBytes:    show.Sizes.CanonicalPresentationBytes,
		ShowingPaperBytes:        show.Sizes.PaperTranscriptBytes,
		CombinedPaperBytes:       issue.Sizes.PaperTranscriptBytes + show.Sizes.PaperTranscriptBytes,
		TotalWorkUnits:           issue.ProjectedWorkUnits + show.ProjectedWorkUnits,
		MaxPhaseNLeaves:          maxInt(issue.Tuning.NLeaves, show.Tuning.NLeaves),
		MinimumTheoremSlackBits:  math.Min(issue.Security.TheoremSlackBits, show.Security.TheoremSlackBits),
		RequiresFreshMeasurement: issue.Sizes.RequiresFreshWireMeasurement || show.Sizes.RequiresFreshWireMeasurement,
	}
}

// v3FrozenCombinedLess implements the adoption ordering from the plan. Since
// phases are searched independently, the old shared NLeaves tie-break becomes
// the maximum of the two phase domains; the final lexicographic comparison
// still binds both complete phase tuples deterministically.
func v3FrozenCombinedLess(left, right v3FrozenCombinedCandidate) bool {
	if left.PresentationWireBytes != right.PresentationWireBytes {
		return left.PresentationWireBytes < right.PresentationWireBytes
	}
	if left.ShowingPaperBytes != right.ShowingPaperBytes {
		return left.ShowingPaperBytes < right.ShowingPaperBytes
	}
	if left.CombinedPaperBytes != right.CombinedPaperBytes {
		return left.CombinedPaperBytes < right.CombinedPaperBytes
	}
	if left.TotalWorkUnits != right.TotalWorkUnits {
		return left.TotalWorkUnits < right.TotalWorkUnits
	}
	if left.MaxPhaseNLeaves != right.MaxPhaseNLeaves {
		return left.MaxPhaseNLeaves < right.MaxPhaseNLeaves
	}
	if math.Abs(left.MinimumTheoremSlackBits-right.MinimumTheoremSlackBits) > 1e-12 {
		return left.MinimumTheoremSlackBits > right.MinimumTheoremSlackBits
	}
	if v3FrozenTuningLess(left.Issuance.Tuning, right.Issuance.Tuning) {
		return true
	}
	if v3FrozenTuningLess(right.Issuance.Tuning, left.Issuance.Tuning) {
		return false
	}
	return v3FrozenTuningLess(left.Showing.Tuning, right.Showing.Tuning)
}

func v3FrozenCombinedWinner(issueSearch, showSearch v3FrozenPhaseSearch) (v3FrozenCombinedCandidate, error) {
	best := v3FrozenCombinedFrom(issueSearch.Baseline, showSearch.Baseline)
	found := false
	for _, issue := range issueSearch.all {
		if !issue.ProjectionEligible {
			continue
		}
		for _, show := range showSearch.all {
			if !show.ProjectionEligible || (!show.Baseline && !show.ProjectedSizeImproves) {
				continue
			}
			candidate := v3FrozenCombinedFrom(issue, show)
			if !found || v3FrozenCombinedLess(candidate, best) {
				best, found = candidate, true
			}
		}
	}
	if !found {
		return v3FrozenCombinedCandidate{}, fmt.Errorf("no combined projection-eligible target candidate")
	}
	return best, nil
}

func v3FrozenPhaseCandidateLess(left, right v3FrozenCandidate) bool {
	if left.ProjectionEligible != right.ProjectionEligible {
		return left.ProjectionEligible
	}
	leftBytes, rightBytes := left.Sizes.CanonicalProofWireBytes, right.Sizes.CanonicalProofWireBytes
	if left.Phase == v3FrozenShowing {
		leftBytes, rightBytes = left.Sizes.CanonicalPresentationBytes, right.Sizes.CanonicalPresentationBytes
	}
	if leftBytes != rightBytes {
		return leftBytes < rightBytes
	}
	if left.Sizes.PaperTranscriptBytes != right.Sizes.PaperTranscriptBytes {
		return left.Sizes.PaperTranscriptBytes < right.Sizes.PaperTranscriptBytes
	}
	if left.ProjectedWorkUnits != right.ProjectedWorkUnits {
		return left.ProjectedWorkUnits < right.ProjectedWorkUnits
	}
	if left.Tuning.NLeaves != right.Tuning.NLeaves {
		return left.Tuning.NLeaves < right.Tuning.NLeaves
	}
	if math.Abs(left.Security.TheoremSlackBits-right.Security.TheoremSlackBits) > 1e-12 {
		return left.Security.TheoremSlackBits > right.Security.TheoremSlackBits
	}
	return v3FrozenTuningLess(left.Tuning, right.Tuning)
}

func v3FrozenTuningLess(left, right credential.IntGenISISTuningPreset) bool {
	l := [5]int{left.LVCSNCols, left.NLeaves, left.Eta, left.Theta, left.Ell}
	r := [5]int{right.LVCSNCols, right.NLeaves, right.Eta, right.Theta, right.Ell}
	for i := range l {
		if l[i] != r[i] {
			return l[i] < r[i]
		}
	}
	return false
}

func v3FrozenBuildPresetAudit(preset credential.IntGenISISPreset, spec v3FrozenTargetSpec, issueCanonical, showCanonical int) (v3FrozenPresetAudit, error) {
	// Retuning evidence is intentionally anchored to the pre-adoption incumbent,
	// even after the measured L=41 WF128 showing winner becomes the live v3
	// manifest. This keeps the search audit reproducible as a 42 -> 41 decision.
	searchPreset := preset
	if searchPreset.CanonicalID == credential.IntGenISISPresetSystemN1024WF128CROMV2 && searchPreset.Showing.LVCSNCols == 41 {
		searchPreset.Showing.LVCSNCols = 42
		searchPreset.LVCSNCols = 42
	}
	issuance, err := v3FrozenSearchPhase(searchPreset, spec, v3FrozenIssuance, spec.IssuanceRelation, v3FrozenProjectionCalibration{
		PaperBaseline: v3FrozenExpectedPaperForTuning(spec, v3FrozenIssuance, searchPreset.Issuance), CanonicalBaseline: issueCanonical,
	})
	if err != nil {
		return v3FrozenPresetAudit{}, err
	}
	showing, err := v3FrozenSearchPhase(searchPreset, spec, v3FrozenShowing, spec.ShowingRelation, v3FrozenProjectionCalibration{
		PaperBaseline: v3FrozenExpectedPaperForTuning(spec, v3FrozenShowing, searchPreset.Showing), CanonicalBaseline: showCanonical,
	})
	if err != nil {
		return v3FrozenPresetAudit{}, err
	}
	combined, err := v3FrozenCombinedWinner(issuance, showing)
	if err != nil {
		return v3FrozenPresetAudit{}, err
	}
	historicalReasons := v3FrozenHistoricalWinnerRejectionReasons(searchPreset, spec, issuance.Baseline, showing.Baseline)
	return v3FrozenPresetAudit{
		CanonicalID:    preset.CanonicalID,
		ManifestDigest: credential.IntGenISISPresetManifestDigest(preset),
		ClaimScope:     preset.ClaimScope,
		Issuance:       issuance,
		Showing:        showing,
		CombinedWinner: combined,
		CombinedSelectionOrder: []string{
			"actual_canonical_presentation_bytes (projected until measured)", "showing_paper_bytes", "combined_paper_bytes",
			"total_work", "max_phase_nleaves", "minimum_theorem_slack_desc", "lexicographic_issuance_then_showing",
		},
		CombinedPaperBaseline:      issuance.Baseline.Sizes.PaperTranscriptBytes + showing.Baseline.Sizes.PaperTranscriptBytes,
		CombinedPaperWinner:        combined.CombinedPaperBytes,
		ProjectedPresentationDelta: combined.PresentationWireBytes - showing.Baseline.Sizes.CanonicalPresentationBytes,
		RequiresThreeRunGate:       combined.Showing.ProjectedSizeImproves,
		HistoricalWinnerReasons:    historicalReasons,
	}, nil
}

func v3FrozenHistoricalWinnerRejectionReasons(preset credential.IntGenISISPreset, spec v3FrozenTargetSpec, issueBaseline, showBaseline v3FrozenCandidate) []string {
	t := preset.Showing
	switch preset.CanonicalID {
	case credential.IntGenISISPresetPoCN1024BQ128R128V3:
		t.LVCSNCols, t.NLeaves, t.Eta, t.Theta, t.Ell = 55, 851968, 68, 13, 18
		t.Kappa = [4]int{7, 6, 12, 13}
	case credential.IntGenISISPresetSystemN1024WF128CROMV2:
		t.LVCSNCols, t.NLeaves, t.Eta, t.Theta, t.Ell = 42, 966656, 46, 7, 8
		t.Kappa = [4]int{11, 0, 8, 13}
	default:
		return []string{"not a maintained v3 target"}
	}
	candidate, err := v3FrozenProjectCandidate(preset, spec, v3FrozenShowing, t, spec.ShowingRelation, showBaseline, v3FrozenProjectionCalibration{
		PaperBaseline:     showBaseline.Sizes.PaperTranscriptBytes,
		CanonicalBaseline: showBaseline.Sizes.CanonicalProofWireBytes,
	})
	if err != nil {
		return []string{err.Error()}
	}
	reasons := make([]string, 0, len(candidate.RejectionReasons)+8)
	for _, reason := range candidate.RejectionReasons {
		reasons = append(reasons, "historical tuple: "+reason)
	}
	// Re-evaluate the historical shape under the mandatory frozen kappa.  This
	// is the security-relevant comparison: both old winners lose their four-term
	// target in addition to increasing the authentication domain.
	t.Kappa = spec.Kappa
	frozen, frozenErr := v3FrozenProjectCandidate(preset, spec, v3FrozenShowing, t, spec.ShowingRelation, showBaseline, v3FrozenProjectionCalibration{
		PaperBaseline:     showBaseline.Sizes.PaperTranscriptBytes,
		CanonicalBaseline: showBaseline.Sizes.CanonicalProofWireBytes,
	})
	if frozenErr != nil {
		reasons = append(reasons, "with frozen kappa: "+frozenErr.Error())
	} else {
		for _, reason := range frozen.RejectionReasons {
			reasons = append(reasons, "with frozen kappa: "+reason)
		}
	}
	_ = issueBaseline
	return reasons
}

func TestV3FrozenRetuneCorrectedTargetGeometry(t *testing.T) {
	type expectedShape struct {
		dq, layers, replay, chunks, masks, opening, queries, pcols int
	}
	wantShapes := map[string]map[v3FrozenPhase]expectedShape{
		credential.IntGenISISPresetPoCN1024BQ128R128V3: {
			v3FrozenIssuance: {472, 4, 180, 12, 156, 336, 65, 271},
			v3FrozenShowing:  {472, 13, 585, 12, 156, 741, 182, 559},
		},
		credential.IntGenISISPresetSystemN1024WF128CROMV2: {
			v3FrozenIssuance: {391, 4, 156, 11, 77, 233, 35, 198},
			v3FrozenShowing:  {471, 12, 468, 13, 91, 559, 91, 468},
		},
	}
	for _, spec := range v3FrozenTargetSpecs {
		preset, err := credential.MustLookupIntGenISISPreset(spec.CanonicalID)
		if err != nil {
			t.Fatal(err)
		}
		if preset.PresetVersion != 3 || preset.ProofSchemaVersion != 3 || preset.RelationVersion != 3 || preset.LayoutVersion != 3 ||
			preset.ClaimScope != credential.ClaimProofOnly || preset.Issuance.Kappa != spec.Kappa || preset.Showing.Kappa != spec.Kappa {
			t.Fatalf("%s is not the frozen proof-only schema-v3 target: %+v", spec.CanonicalID, preset)
		}
		for _, phase := range []v3FrozenPhase{v3FrozenIssuance, v3FrozenShowing} {
			baseline, err := v3FrozenBaselineCandidate(preset, spec, phase, v3FrozenRelationForPhase(spec, phase), v3FrozenProjectionCalibration{})
			if err != nil {
				t.Fatalf("%s %s: %v", spec.CanonicalID, phase, err)
			}
			if !baseline.ProjectionEligible || baseline.Sizes.PaperTranscriptBytes != v3FrozenExpectedPaperForTuning(spec, phase, v3FrozenTuningForPhase(preset, phase)) {
				t.Fatalf("%s %s baseline gates/bytes: %+v", spec.CanonicalID, phase, baseline)
			}
			wantRows := v3FrozenRelationForPhase(spec, phase).LogicalRows
			if baseline.Geometry.LogicalRows != wantRows || baseline.Geometry.MaskChunks != baseline.Geometry.MaskMu+1 {
				t.Fatalf("%s %s corrected geometry mismatch: %+v", spec.CanonicalID, phase, baseline.Geometry)
			}
			want := wantShapes[spec.CanonicalID][phase]
			got := baseline.Geometry
			if got.DQ != want.dq || got.WitnessLayers != want.layers || got.ReplayWitnessRows != want.replay ||
				got.MaskChunks != want.chunks || got.MaskRows != want.masks || got.OpeningRows != want.opening ||
				got.QueryCount != want.queries || got.OpeningPCols != want.pcols {
				t.Fatalf("%s %s corrected shape=%+v want=%+v", spec.CanonicalID, phase, got, want)
			}
		}
	}
}

func TestV3FrozenRetuneWFShowingL41GeometryAndGates(t *testing.T) {
	spec, _ := v3FrozenSpecFor(credential.IntGenISISPresetSystemN1024WF128CROMV2)
	preset, err := credential.MustLookupIntGenISISPreset(spec.CanonicalID)
	if err != nil {
		t.Fatal(err)
	}
	incumbent := preset
	incumbent.Showing.LVCSNCols = 42
	incumbent.LVCSNCols = 42
	baseline, err := v3FrozenBaselineCandidate(incumbent, spec, v3FrozenShowing, spec.ShowingRelation, v3FrozenProjectionCalibration{})
	if err != nil {
		t.Fatal(err)
	}
	tuning := incumbent.Showing
	tuning.LVCSNCols = 41
	candidate, err := v3FrozenProjectCandidate(incumbent, spec, v3FrozenShowing, tuning, spec.ShowingRelation, baseline, v3FrozenProjectionCalibration{
		PaperBaseline:     baseline.Sizes.PaperTranscriptBytes,
		CanonicalBaseline: baseline.Sizes.CanonicalProofWireBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Geometry.LogicalRows != 487 || candidate.Geometry.WitnessLayers != 12 || candidate.Geometry.MaskChunks != 13 ||
		candidate.Geometry.MaskRows != 91 || candidate.Geometry.OpeningRows != 559 || candidate.Geometry.QueryCount != 91 || candidate.Geometry.OpeningPCols != 468 {
		t.Fatalf("WF128 L=41 geometry=%+v", candidate.Geometry)
	}
	if candidate.Sizes.PaperTranscriptBytes != 40950 {
		t.Fatalf("WF128 L=41 paper bytes=%d want 40950", candidate.Sizes.PaperTranscriptBytes)
	}
	if delta := candidate.Sizes.CanonicalPresentationBytes - baseline.Sizes.CanonicalPresentationBytes; delta != -335 {
		t.Fatalf("WF128 L=41 projected canonical presentation delta=%d want -335", delta)
	}
	if !candidate.ProjectionEligible || !candidate.Gates.all() || !candidate.ProjectedSizeImproves {
		t.Fatalf("WF128 L=41 analytic gates failed: %+v", candidate)
	}
	if candidate.AdoptionEligible || !candidate.Sizes.RequiresFreshWireMeasurement {
		t.Fatalf("WF128 L=41 must remain measurement-pending before adoption: %+v", candidate)
	}
}

func TestV3FrozenRetuneFullGridWinners(t *testing.T) {
	want := map[string]struct {
		issueL, showL int
		showPaper     int
		combinedPaper int
	}{
		credential.IntGenISISPresetPoCN1024BQ128R128V3:    {43, 43, 93416, 156030},
		credential.IntGenISISPresetSystemN1024WF128CROMV2: {42, 41, 40950, 67622},
	}
	for _, spec := range v3FrozenTargetSpecs {
		preset, err := credential.MustLookupIntGenISISPreset(spec.CanonicalID)
		if err != nil {
			t.Fatal(err)
		}
		audit, err := v3FrozenBuildPresetAudit(preset, spec, 0, 0)
		if err != nil {
			t.Fatalf("%s search: %v", spec.CanonicalID, err)
		}
		w := want[spec.CanonicalID]
		if audit.Issuance.Winner.Tuning.LVCSNCols != w.issueL || audit.Showing.Winner.Tuning.LVCSNCols != w.showL ||
			audit.Showing.Winner.Sizes.PaperTranscriptBytes != w.showPaper {
			t.Fatalf("%s winners issue=%+v show=%+v", spec.CanonicalID, audit.Issuance.Winner, audit.Showing.Winner)
		}
		if audit.CombinedWinner.Issuance.Tuning.LVCSNCols != w.issueL || audit.CombinedWinner.Showing.Tuning.LVCSNCols != w.showL ||
			audit.CombinedPaperWinner != w.combinedPaper {
			t.Fatalf("%s combined ranking winner=%+v", spec.CanonicalID, audit.CombinedWinner)
		}
		if audit.Issuance.Winner.Tuning.Kappa != spec.Kappa || audit.Showing.Winner.Tuning.Kappa != spec.Kappa ||
			audit.Issuance.Winner.Tuning.NLeaves > preset.Issuance.NLeaves || audit.Showing.Winner.Tuning.NLeaves > preset.Showing.NLeaves {
			t.Fatalf("%s winner violated no-grinding/no-domain-growth policy", spec.CanonicalID)
		}
		historical := strings.Join(audit.HistoricalWinnerReasons, "; ")
		if len(audit.HistoricalWinnerReasons) == 0 || !strings.Contains(historical, "kappa") ||
			!strings.Contains(historical, "NLeaves") || !strings.Contains(historical, "with frozen kappa: four-term") {
			t.Fatalf("%s historical winner was not explicitly rejected: %v", spec.CanonicalID, audit.HistoricalWinnerReasons)
		}
		t.Logf("%s issue winner=(L=%d,N=%d,eta=%d,theta=%d,ell=%d,wire=%d,paper=%d) show winner=(L=%d,N=%d,eta=%d,theta=%d,ell=%d,wire=%d,paper=%d), analytic eligible=%d/%d (improving=%d) and %d/%d (improving=%d)",
			spec.CanonicalID,
			audit.Issuance.Winner.Tuning.LVCSNCols, audit.Issuance.Winner.Tuning.NLeaves, audit.Issuance.Winner.Tuning.Eta, audit.Issuance.Winner.Tuning.Theta, audit.Issuance.Winner.Tuning.Ell,
			audit.Issuance.Winner.Sizes.CanonicalProofWireBytes, audit.Issuance.Winner.Sizes.PaperTranscriptBytes,
			audit.Showing.Winner.Tuning.LVCSNCols, audit.Showing.Winner.Tuning.NLeaves, audit.Showing.Winner.Tuning.Eta, audit.Showing.Winner.Tuning.Theta, audit.Showing.Winner.Tuning.Ell,
			audit.Showing.Winner.Sizes.CanonicalPresentationBytes, audit.Showing.Winner.Sizes.PaperTranscriptBytes,
			audit.Issuance.ProjectionEligibleCount, audit.Issuance.CandidateCount, audit.Issuance.ProjectedImprovementCount,
			audit.Showing.ProjectionEligibleCount, audit.Showing.CandidateCount, audit.Showing.ProjectedImprovementCount,
		)
	}
}

func TestV3FrozenRetuneRejectsFrozenFieldProfileAndWidths(t *testing.T) {
	spec, _ := v3FrozenSpecFor(credential.IntGenISISPresetPoCN1024BQ128R128V3)
	preset, _ := credential.MustLookupIntGenISISPreset(spec.CanonicalID)
	baseline, err := v3FrozenBaselineCandidate(preset, spec, v3FrozenShowing, spec.ShowingRelation, v3FrozenProjectionCalibration{})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*credential.IntGenISISTuningPreset){
		"kappa":     func(t *credential.IntGenISISTuningPreset) { t.Kappa[0]++ },
		"query cap": func(t *credential.IntGenISISTuningPreset) { t.ROQueryCapBits[0]-- },
		"salt":      func(t *credential.IntGenISISTuningPreset) { t.SaltBits += 8 },
		"tape":      func(t *credential.IntGenISISTuningPreset) { t.DECSTapeBits += 8 },
		"theta":     func(t *credential.IntGenISISTuningPreset) { t.Theta-- },
	} {
		t.Run(name, func(t *testing.T) {
			tuning := preset.Showing
			mutate(&tuning)
			candidate, projectErr := v3FrozenProjectCandidate(preset, spec, v3FrozenShowing, tuning, spec.ShowingRelation, baseline, v3FrozenProjectionCalibration{
				PaperBaseline: baseline.Sizes.PaperTranscriptBytes, CanonicalBaseline: baseline.Sizes.CanonicalProofWireBytes,
			})
			if projectErr != nil {
				return // malformed geometry is also a fail-closed rejection.
			}
			if candidate.ProjectionEligible {
				t.Fatalf("mutated frozen target remained eligible: %+v", candidate)
			}
		})
	}
}

// TestV3FrozenRetuneAudit is opt-in because its inputs must be fresh measured
// schema-v3 reports.  It never edits presets.  The generated JSON is a search
// audit only; actual adoption additionally requires the three-run resource and
// actual-wire gates recorded by the caller.
func TestV3FrozenRetuneAudit(t *testing.T) {
	if os.Getenv("SPRUCE_V3_FROZEN_RETUNE") != "1" {
		t.Skip("set SPRUCE_V3_FROZEN_RETUNE=1 with fresh BQ/WF report paths to emit the target-only audit")
	}
	nizkProfileChdirRepoRoot(t)
	reportPaths := map[string]string{
		credential.IntGenISISPresetPoCN1024BQ128R128V3:    os.Getenv("SPRUCE_V3_FROZEN_RETUNE_BQ_REPORT"),
		credential.IntGenISISPresetSystemN1024WF128CROMV2: os.Getenv("SPRUCE_V3_FROZEN_RETUNE_WF_REPORT"),
	}
	outPath := os.Getenv("SPRUCE_V3_FROZEN_RETUNE_OUT")
	if outPath == "" {
		outPath = filepath.Join("artifacts", "smallwood-v3", "_retune", "frozen-retune-audit.json")
	}
	audit := v3FrozenRetuneAudit{
		Version:         v3FrozenRetuneAuditVersion,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Status:          "projection_pass_measurement_pending",
		SearchScope:     "target_only_independent_phases_lvcs_plusminus4_nleaves_steps_minus32_to0_eta_minus8_plus2_theta_plusminus1_ell_plusminus2",
		NoGrinding:      "kappa is byte-for-byte frozen; no candidate may increase NLeaves, corrected work, or NDECS*eta",
		MeasurementRule: "projected canonical bytes are calibrated at the actual incumbent; adoption requires actual wire improvement and three runs within 2x median proving time and peak memory",
	}
	for _, spec := range v3FrozenTargetSpecs {
		path := strings.TrimSpace(reportPaths[spec.CanonicalID])
		if path == "" {
			t.Fatalf("missing fresh report path for %s", spec.CanonicalID)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var report benchmarkIntGenISISE2EReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		preset, err := credential.MustLookupIntGenISISPreset(spec.CanonicalID)
		if err != nil {
			t.Fatal(err)
		}
		if report.CanonicalPresetID != spec.CanonicalID || report.PresetVersion != 3 ||
			report.PresetManifestDigest != credential.IntGenISISPresetManifestDigest(preset) ||
			report.Issuance.TranscriptMode != credential.IntGenISISTranscriptProtocolV3 ||
			report.Showing.TranscriptMode != credential.IntGenISISTranscriptProtocolV3 {
			t.Fatalf("%s is not a fresh report for the current strict-v3 manifest", path)
		}
		if err := v3FrozenUseCompilerGeometry(&spec, report); err != nil {
			t.Fatalf("%s compiler geometry: %v", spec.CanonicalID, err)
		}
		if report.Issuance.CanonicalProofWireBytes <= 0 || report.Showing.CanonicalProofWireBytes <= 0 {
			t.Fatalf("%s report lacks actual canonical proof lengths", spec.CanonicalID)
		}
		wantIssuePaper := v3FrozenExpectedPaperForTuning(spec, v3FrozenIssuance, preset.Issuance)
		wantShowPaper := v3FrozenExpectedPaperForTuning(spec, v3FrozenShowing, preset.Showing)
		if report.Issuance.PaperTranscriptBytes != wantIssuePaper || report.Showing.PaperTranscriptBytes != wantShowPaper {
			t.Fatalf("%s fresh paper transcript=%d/%d want corrected projection=%d/%d",
				spec.CanonicalID, report.Issuance.PaperTranscriptBytes, report.Showing.PaperTranscriptBytes, wantIssuePaper, wantShowPaper)
		}
		entry, err := v3FrozenBuildPresetAudit(preset, spec, report.Issuance.CanonicalProofWireBytes, report.Showing.CanonicalProofWireBytes)
		if err != nil {
			t.Fatalf("%s audit: %v", spec.CanonicalID, err)
		}
		audit.Presets = append(audit.Presets, entry)
	}
	encoded, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote strict-v3 frozen retune audit: %s", outPath)
}

func v3FrozenUseCompilerGeometry(spec *v3FrozenTargetSpec, report benchmarkIntGenISISE2EReport) error {
	if spec == nil {
		return fmt.Errorf("nil target spec")
	}
	issue := report.Issuance.RelationCandidate
	show := report.Showing.RelationCandidate
	gotIssue := v3FrozenRelationGeometry{issue.LogicalRows, issue.ParallelDegree, issue.AggregatedDegree}
	gotShow := v3FrozenRelationGeometry{show.LogicalRows, show.ParallelDegree, show.AggregatedDegree}
	if gotIssue != spec.IssuanceRelation || gotShow != spec.ShowingRelation {
		return fmt.Errorf("compiled issue/show=%+v/%+v want=%+v/%+v", gotIssue, gotShow, spec.IssuanceRelation, spec.ShowingRelation)
	}
	spec.IssuanceRelation, spec.ShowingRelation = gotIssue, gotShow
	return nil
}
