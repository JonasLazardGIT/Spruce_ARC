package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

const (
	nizkProfileSweepSummaryVersion  = 2
	nizkProfileSweepSummaryFilename = "nizk-profile-research-summary.json"

	nizkProfileBQ128RawResidualFrontierCandidate = "bq128-128-raw128-residual128-theta13-lvcs48-h512"
	nizkProfileFormalBackendFamily               = "formal_backend_sweep"
	nizkProfileScopedR128Family                  = "nizk_scoped_r128"

	nizkProfileFrontierCandidate              = "nizk_candidate"
	nizkProfileFrontierHighKResearch          = "high_k_research"
	nizkProfileFrontierRequiresNewPrimitives  = "requires_new_primitives"
	nizkProfileFrontierRequiresTheoremWork    = "requires_theorem_accounting_work"
	nizkProfileFrontierRequiresSplitTheorem   = "requires_split_theorem"
	nizkProfileFrontierValidPrefixResearch    = "valid_prefix_research"
	nizkProfileFrontierSerializerModelBlocked = "serializer_model_blocked"
	nizkProfileFrontierRejected               = "rejected"
	nizkProfileDefaultEngineeringTargetMargin = 2.0
	nizkProfileScopedR128FullGameTargetBits   = 130.0
	nizkProfileMinReplacementImprovementPct   = 2.0
	nizkProfileMaxReplacementProvingRatio     = 2.0
	bq6496ReductionBaselineBytes              = 69768
)

func benchmarkValidPrefixCostReport(spec credential.IntGenISISSecurityProfileSpec, timings []PIOP.PhaseTiming, explicitValidPrefixCaps [4]float64, researchAccounting bool) credential.ValidPrefixCostReport {
	return benchmarkValidPrefixCostReportFromBudget(credential.ROBudgetLogVectorFromCapBits(spec.ROQueryCapBits), timings, explicitValidPrefixCaps, researchAccounting)
}

type NIZKProfileSearchTarget struct {
	SecurityProfile        string                           `json:"security_profile"`
	Lane                   string                           `json:"lane"`
	TargetStatus           credential.SecurityProfileStatus `json:"target_status"`
	SecurityMode           string                           `json:"security_mode"`
	CoreBitsRequired       float64                          `json:"core_bits_required"`
	NIZKTargetBits         float64                          `json:"nizk_target_bits"`
	FullGameTargetBits     float64                          `json:"full_game_target_bits,omitempty"`
	QueryCapExponent       int                              `json:"query_cap_exponent"`
	HashFSBitsRange        [2]int                           `json:"hash_fs_bits_range"`
	TapeBitsRange          [2]int                           `json:"tape_bits_range"`
	SaltBitsRange          [2]int                           `json:"salt_bits_range"`
	TagElementsRange       [2]int                           `json:"tag_elements_range"`
	BareSaltBits           int                              `json:"bare_salt_bits"`
	EngineeringSaltBits    int                              `json:"engineering_salt_bits"`
	PrimitiveBlockerReason string                           `json:"primitive_blocker_reason"`
}

type NIZKProfileSearchCandidate struct {
	Name                        string
	Family                      string
	TargetProfile               string
	LaneOverride                string
	RelationEncoding            string
	ControlPreset               string
	CompilerBacked              bool
	PinnedLVCS                  bool
	DeriveEtaFloorOnly          bool
	RequiresTheoremAccounting   bool
	RequiresSplitTheorem        bool
	RelationFirstScore          float64
	ReductionLane               string
	ReductionModel              string
	FormalBackendCandidate      bool
	FormalBaselineLVCSNCols     int
	FormalProjectionOnlyReason  string
	HashFSBitsOverride          int
	TapeBitsOverride            int
	SaltBitsOverride            int
	TagElementsOverride         int
	NIZKTargetBitsOverride      float64
	RawQueryCapExponentOverride int
	ValidPrefixResearch         bool
	ValidPrefixCapExponent      [4]float64
	SerializerOmission          string
	ReconstructionAvailable     bool
	OmissionMapFSBound          bool
	Issuance                    intGenISISTuning
	Showing                     intGenISISTuning
	Relation                    benchmarkIntGenISISRelationReport
	Notes                       []string
}

type NIZKProfileSmallWoodReport struct {
	LVCSNCols                 int        `json:"lvcs_ncols"`
	NLeaves                   int        `json:"nleaves"`
	Eta                       int        `json:"eta"`
	EtaFloor                  int        `json:"eta_floor"`
	Theta                     int        `json:"theta"`
	Rho                       int        `json:"rho"`
	Ell                       int        `json:"ell"`
	EllPrime                  int        `json:"ell_prime"`
	Kappa                     [4]int     `json:"kappa"`
	RequiredKappa             [4]int     `json:"required_kappa"`
	RawQueryCapLog2           float64    `json:"raw_query_cap_log2,omitempty"`
	EffectiveQueryCapLog2     [4]float64 `json:"effective_query_cap_log2,omitempty"`
	UsesValidPrefixAccounting bool       `json:"uses_valid_prefix_accounting,omitempty"`
	AggregateOptimized        bool       `json:"aggregate_optimized,omitempty"`
	ExpectedGrindingWork      float64    `json:"expected_grinding_work,omitempty"`
	ExpectedGrindingWorkLog2  float64    `json:"expected_grinding_work_log2,omitempty"`
	LVCSWindow                []int      `json:"lvcs_window,omitempty"`
	EtaWindow                 []int      `json:"eta_window,omitempty"`
	ThetaWindow               []int      `json:"theta_window,omitempty"`
	EllWindow                 []int      `json:"ell_window,omitempty"`
	Notes                     []string   `json:"notes,omitempty"`
}

type NIZKProfilePhaseProjection struct {
	LogicalRows       int                        `json:"logical_rows"`
	DQ                int                        `json:"dq"`
	WitnessLayers     int                        `json:"witness_layers"`
	ReplayWitnessRows int                        `json:"replay_witness_rows"`
	MaskRows          int                        `json:"mask_rows"`
	OpeningRows       int                        `json:"opening_rows"`
	QueryCount        int                        `json:"query_count"`
	PColsEncoded      int                        `json:"p_cols_encoded"`
	ProverWorkUnits   uint64                     `json:"prover_work_units"`
	Transcript        PIOP.PaperTranscriptReport `json:"transcript"`
}

type NIZKProfileMeasurementSummary struct {
	Runs                         int     `json:"runs"`
	IssuanceBytes                int     `json:"issuance_bytes"`
	ShowingBytes                 int     `json:"showing_bytes"`
	CombinedBytes                int     `json:"combined_bytes"`
	MedianIssuanceProvingMS      float64 `json:"median_issuance_proving_ms"`
	MedianIssuanceVerificationMS float64 `json:"median_issuance_verification_ms"`
	MedianShowingProvingMS       float64 `json:"median_showing_proving_ms"`
	MedianShowingVerificationMS  float64 `json:"median_showing_verification_ms"`
	MedianCombinedProvingMS      float64 `json:"median_combined_proving_ms"`
	MedianCombinedVerificationMS float64 `json:"median_combined_verification_ms"`
	ExpectedGrindingWork         float64 `json:"expected_grinding_work"`
	ExpectedGrindingWorkLog2     float64 `json:"expected_grinding_work_log2"`
	IncumbentCombinedBytes       int     `json:"incumbent_combined_bytes,omitempty"`
	IncumbentMedianProvingMS     float64 `json:"incumbent_median_proving_ms,omitempty"`
	CombinedImprovementPercent   float64 `json:"combined_improvement_percent,omitempty"`
	ProvingTimeRatio             float64 `json:"proving_time_ratio,omitempty"`
	MeaningfulReplacement        bool    `json:"meaningful_replacement"`
}

type NIZKProfileFormalBackendDiagnostics struct {
	RingDegree                         int    `json:"ring_degree"`
	FormalBackendCandidate             bool   `json:"formal_backend_candidate"`
	LVCSAboveRing                      bool   `json:"lvcs_above_ring"`
	DQAboveRing                        bool   `json:"dq_above_ring,omitempty"`
	DQOverride                         int    `json:"dq_override,omitempty"`
	Measurable                         bool   `json:"measurable"`
	MeasurementBlocker                 string `json:"measurement_blocker,omitempty"`
	BaselineLVCSNCols                  int    `json:"baseline_lvcs_ncols,omitempty"`
	BaselineDDECS                      int    `json:"baseline_ddecs,omitempty"`
	DDECS                              int    `json:"ddecs"`
	BaselineRowBlocks                  int    `json:"baseline_row_blocks,omitempty"`
	RowBlocks                          int    `json:"row_blocks"`
	RowBlockDelta                      int    `json:"row_block_delta,omitempty"`
	BaselineDQBlocks                   int    `json:"baseline_dq_blocks,omitempty"`
	DQBlocks                           int    `json:"dq_blocks"`
	DQBlockDelta                       int    `json:"dq_block_delta,omitempty"`
	BaselinePaperTranscriptBytes       int    `json:"baseline_paper_transcript_bytes,omitempty"`
	ProjectedPaperTranscriptDeltaBytes int    `json:"projected_paper_transcript_delta_bytes,omitempty"`
	Tradeoff                           string `json:"tradeoff,omitempty"`
}

type NIZKProfileCandidateReport struct {
	SecurityProfile           string                                    `json:"security_profile"`
	Lane                      string                                    `json:"lane"`
	Candidate                 string                                    `json:"candidate"`
	Family                    string                                    `json:"family,omitempty"`
	RelationEncoding          string                                    `json:"relation_encoding"`
	ControlPreset             string                                    `json:"control_preset"`
	CompilerBacked            bool                                      `json:"compiler_backed"`
	FormalBackendCandidate    bool                                      `json:"formal_backend_candidate"`
	LVCSAboveRing             bool                                      `json:"lvcs_above_ring,omitempty"`
	RequiresTheoremWork       bool                                      `json:"requires_theorem_accounting,omitempty"`
	RequiresSplitTheorem      bool                                      `json:"requires_split_theorem,omitempty"`
	UsesValidPrefixAccounting bool                                      `json:"uses_valid_prefix_accounting,omitempty"`
	RelationFirstScore        float64                                   `json:"relation_first_score,omitempty"`
	TargetStatus              credential.SecurityProfileStatus          `json:"target_status"`
	FrontierClass             string                                    `json:"frontier_class"`
	PrimitiveBlockerReason    string                                    `json:"primitive_blocker_reason"`
	ForcedBySecurity          []string                                  `json:"forced_by_security,omitempty"`
	MeasurementStatus         string                                    `json:"measurement_status"`
	MeasurementSource         string                                    `json:"measurement_source,omitempty"`
	MeasurementError          string                                    `json:"measurement_error,omitempty"`
	IncumbentControl          bool                                      `json:"incumbent_control,omitempty"`
	MeasuredArtifactDir       string                                    `json:"measured_artifact_dir,omitempty"`
	MeasuredJSON              string                                    `json:"measured_json,omitempty"`
	LedgerStatus              string                                    `json:"ledger_status"`
	LedgerReasons             []string                                  `json:"ledger_rejection_reasons,omitempty"`
	NIZKTargetBits            float64                                   `json:"nizk_target_bits"`
	FullGameTargetBits        float64                                   `json:"full_game_target_bits,omitempty"`
	FullGameBits              float64                                   `json:"full_game_bits,omitempty"`
	GlobalCollisionBits       float64                                   `json:"global_collision_bits,omitempty"`
	CoreBitsRequired          float64                                   `json:"core_bits_required"`
	RawQueryCapLog2           float64                                   `json:"raw_query_cap_log2,omitempty"`
	EffectiveAlgebraicCapLog2 [4]float64                                `json:"effective_algebraic_cap_log2,omitempty"`
	AlgebraicAccounting       credential.ValidPrefixAlgebraicAccounting `json:"algebraic_accounting,omitempty"`
	HashFSBitsRange           [2]int                                    `json:"hash_fs_bits_range"`
	TapeBitsRange             [2]int                                    `json:"tape_bits_range"`
	SaltBitsRange             [2]int                                    `json:"salt_bits_range"`
	TagElementsRange          [2]int                                    `json:"tag_elements_range"`
	Relation                  benchmarkIntGenISISRelationReport         `json:"relation"`
	RelationSafety            NIZKProfileRelationSafetyReport           `json:"relation_safety"`
	SmallWood                 NIZKProfileSmallWoodReport                `json:"smallwood"`
	IssuanceAlgebraicBits     float64                                   `json:"issuance_algebraic_bits"`
	ShowingAlgebraicBits      float64                                   `json:"showing_algebraic_bits"`
	AlgebraicRoundBits        [4]float64                                `json:"algebraic_round_bits"`
	TranscriptBuckets         nizkProfileBucketDigest                   `json:"transcript_buckets"`
	PaperTranscriptBytes      int                                       `json:"paper_transcript_bytes"`
	IssuanceProjection        *NIZKProfilePhaseProjection               `json:"issuance_projection,omitempty"`
	ShowingProjection         *NIZKProfilePhaseProjection               `json:"showing_projection,omitempty"`
	CombinedPaperBytes        int                                       `json:"combined_paper_transcript_bytes,omitempty"`
	ProjectedProverWorkUnits  uint64                                    `json:"projected_prover_work_units,omitempty"`
	ExpectedGrindingWork      float64                                   `json:"expected_grinding_work,omitempty"`
	ExpectedGrindingWorkLog2  float64                                   `json:"expected_grinding_work_log2,omitempty"`
	TranscriptDrivers         []NIZKProfileTranscriptDriver             `json:"transcript_drivers,omitempty"`
	OptimizationLevers        []NIZKProfileOptimizationLever            `json:"optimization_levers,omitempty"`
	FormalBackendDiagnostics  *NIZKProfileFormalBackendDiagnostics      `json:"formal_backend_diagnostics,omitempty"`
	MeasuredIssuance          *nizkProfileMetricDigest                  `json:"measured_issuance,omitempty"`
	MeasuredShowing           *nizkProfileMetricDigest                  `json:"measured_showing,omitempty"`
	MeasurementSummary        *NIZKProfileMeasurementSummary            `json:"measurement_summary,omitempty"`
	BQ64Reduction             *BQ64ReductionReport                      `json:"bq64_reduction,omitempty"`
	ValidPrefixCost           credential.ValidPrefixCostReport          `json:"valid_prefix_cost,omitempty"`
	Notes                     []string                                  `json:"notes,omitempty"`
}

type NIZKProfileRelationSafetyReport struct {
	CertificateStatus         string   `json:"certificate_status"`
	CurrentTheoremSafe        bool     `json:"current_theorem_safe"`
	CompilerBacked            bool     `json:"compiler_backed"`
	RequiresTheoremAccounting bool     `json:"requires_theorem_accounting,omitempty"`
	RequiresSplitTheorem      bool     `json:"requires_split_theorem,omitempty"`
	BaselineRows              int      `json:"baseline_rows,omitempty"`
	BaselineDQ                int      `json:"baseline_dq,omitempty"`
	RowsDelta                 int      `json:"rows_delta,omitempty"`
	DQDelta                   int      `json:"dq_delta,omitempty"`
	RejectionReasons          []string `json:"rejection_reasons,omitempty"`
}

type BQ64ReductionReport struct {
	Candidate            string                       `json:"candidate"`
	Profile              string                       `json:"profile"`
	Lane                 string                       `json:"lane"`
	Model                string                       `json:"model"`
	BaselineBytes        int                          `json:"baseline_bytes"`
	TranscriptDeltaBytes int                          `json:"transcript_delta_bytes,omitempty"`
	AcceptanceStatus     string                       `json:"acceptance_status"`
	AcceptanceReasons    []string                     `json:"acceptance_reasons,omitempty"`
	Width                BQ64ReductionWidthModel      `json:"width"`
	Serializer           BQ64ReductionSerializerModel `json:"serializer"`
	MeasuredAudit        *PIOP.PaperTranscriptAudit   `json:"measured_audit,omitempty"`
}

type BQ64ReductionWidthModel struct {
	HashFSBits     int    `json:"hash_fs_bits"`
	TapeBits       int    `json:"tape_bits"`
	SaltBits       int    `json:"salt_bits"`
	TagElements    int    `json:"tag_elements"`
	Classification string `json:"classification,omitempty"`
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
}

type BQ64ReductionSerializerModel struct {
	OmitPdecs               bool   `json:"omit_pdecs,omitempty"`
	OmitVTargets            bool   `json:"omit_vtargets,omitempty"`
	OmitBarSets             bool   `json:"omit_barsets,omitempty"`
	ReconstructionAvailable bool   `json:"reconstruction_available"`
	OmissionMapFSBound      bool   `json:"omission_map_fs_bound"`
	Status                  string `json:"status"`
	Reason                  string `json:"reason,omitempty"`
}

type NIZKProfileTranscriptDriver struct {
	Component string  `json:"component"`
	Bytes     int     `json:"bytes"`
	Percent   float64 `json:"percent"`
	Driver    string  `json:"driver"`
}

type NIZKProfileOptimizationLever struct {
	Name                  string `json:"name"`
	Category              string `json:"category"`
	EstimatedSavingsBytes int    `json:"estimated_savings_bytes,omitempty"`
	SecurityConstraint    string `json:"security_constraint,omitempty"`
	ImplementationWork    string `json:"implementation_work,omitempty"`
	Notes                 string `json:"notes,omitempty"`
}

type NIZKProfileFrontierEntry struct {
	SecurityProfile           string                         `json:"security_profile"`
	Candidate                 string                         `json:"candidate"`
	Family                    string                         `json:"family,omitempty"`
	RelationEncoding          string                         `json:"relation_encoding"`
	FrontierClass             string                         `json:"frontier_class"`
	CompilerBacked            bool                           `json:"compiler_backed"`
	MeasurementStatus         string                         `json:"measurement_status"`
	RelationFirstScore        float64                        `json:"relation_first_score,omitempty"`
	AlgebraicBits             float64                        `json:"algebraic_bits"`
	PaperTranscriptBytes      int                            `json:"paper_transcript_bytes"`
	CombinedPaperBytes        int                            `json:"combined_paper_transcript_bytes,omitempty"`
	ProjectedProverWorkUnits  uint64                         `json:"projected_prover_work_units,omitempty"`
	ExpectedGrindingWork      float64                        `json:"expected_grinding_work,omitempty"`
	ExpectedGrindingWorkLog2  float64                        `json:"expected_grinding_work_log2,omitempty"`
	MeasurementSummary        *NIZKProfileMeasurementSummary `json:"measurement_summary,omitempty"`
	RequiredKappa             [4]int                         `json:"required_kappa"`
	Eta                       int                            `json:"eta"`
	Theta                     int                            `json:"theta"`
	Ell                       int                            `json:"ell"`
	LVCSNCols                 int                            `json:"lvcs_ncols"`
	NLeaves                   int                            `json:"nleaves"`
	DQ                        int                            `json:"dq"`
	DominantDegreeSource      string                         `json:"dominant_degree_source,omitempty"`
	TranscriptBuckets         nizkProfileBucketDigest        `json:"transcript_buckets"`
	TranscriptDrivers         []NIZKProfileTranscriptDriver  `json:"transcript_drivers,omitempty"`
	OptimizationLevers        []NIZKProfileOptimizationLever `json:"optimization_levers,omitempty"`
	PrimitiveBlockerBrief     string                         `json:"primitive_blocker_brief,omitempty"`
	UsesValidPrefixAccounting bool                           `json:"uses_valid_prefix_accounting,omitempty"`
	EffectiveAlgebraicCapLog2 [4]float64                     `json:"effective_algebraic_cap_log2,omitempty"`
	FormalBackendCandidate    bool                           `json:"formal_backend_candidate,omitempty"`
	LVCSAboveRing             bool                           `json:"lvcs_above_ring,omitempty"`
}

type NIZKProfileSweepSummary struct {
	Version        int                                   `json:"version"`
	GeneratedAt    string                                `json:"generated_at"`
	CandidateCount int                                   `json:"candidate_count"`
	RunCount       int                                   `json:"run_count"`
	Targets        []NIZKProfileSearchTarget             `json:"targets"`
	Results        []NIZKProfileCandidateReport          `json:"results"`
	Frontiers      map[string][]NIZKProfileFrontierEntry `json:"frontiers"`
}

func nizkProfileSearchTargets() []NIZKProfileSearchTarget {
	return []NIZKProfileSearchTarget{
		nizkProfileSearchTargetFromRegistry("BQ32-128", "engineering", 164, 32, [2]int{200, 256}, [2]int{160, 192}, [2]int{192, 256}, [2]int{10, 11}, 192, 256),
		nizkProfileSearchTargetFromRegistry("BQ64-96", "engineering", 164, 64, [2]int{232, 256}, [2]int{160, 192}, [2]int{224, 256}, [2]int{12, 13}, 224, 256),
		nizkProfileScopedR128SearchTarget("BQ64-128", 64),
		nizkProfileScopedR128SearchTarget("BQ96-128", 96),
		nizkProfileScopedR128SearchTarget("BQ128-128", 128),
	}
}

func nizkProfileSearchTargetFromRegistry(label, lane string, targetBits float64, queryCapExponent int, hashFS, tape, salt, tag [2]int, bareSalt, engineeringSalt int) NIZKProfileSearchTarget {
	spec, ok := credential.LookupIntGenISISSecurityProfile(label)
	if !ok {
		panic(fmt.Sprintf("missing security profile %s", label))
	}
	return NIZKProfileSearchTarget{
		SecurityProfile:        spec.Label,
		Lane:                   lane,
		TargetStatus:           spec.Status,
		SecurityMode:           string(spec.Mode),
		CoreBitsRequired:       spec.CoreBitsRequired,
		NIZKTargetBits:         targetBits,
		QueryCapExponent:       queryCapExponent,
		HashFSBitsRange:        hashFS,
		TapeBitsRange:          tape,
		SaltBitsRange:          salt,
		TagElementsRange:       tag,
		BareSaltBits:           bareSalt,
		EngineeringSaltBits:    engineeringSalt,
		PrimitiveBlockerReason: fmt.Sprintf("%s requires %.0f-bit lattice/PRF/key primitive work; this NIZK lane is research-only", spec.Label, spec.CoreBitsRequired),
	}
}

func nizkProfileSearchCandidates() []NIZKProfileSearchCandidate {
	bq32Preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		return nil
	}
	bq32Base := intGenISISTuningFromPresetSpec(bq32Preset.Showing)
	q32Base := nizkProfileArchivedQ32R128Base(bq32Base)
	candidates := []NIZKProfileSearchCandidate{
		nizkProfileCandidateFromTuning("control-bq32-96-current-relation", "bq32-96-current-relation", bq32Preset.Name, bq32Base, nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("control-q32-128-high-soundness", "q32-128-current-relation", bq32Preset.Name, q32Base, nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("bq32-nizk164-theta10-ell16-n1048576", "bq32-current-theta10-ell16", bq32Preset.Name, nizkProfileSmallWoodOnlyCandidate(bq32Base, 10, 16, 1048576, 44), nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("bq64-nizk164-theta12-ell16-n1048576", "bq32-current-theta12-ell16", bq32Preset.Name, nizkProfileSmallWoodOnlyCandidate(bq32Base, 12, 16, 1048576, 44), nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("bq64-128-theta14-ell20-n1048576", "bq32-current-theta14-ell20", bq32Preset.Name, nizkProfileSmallWoodOnlyCandidate(bq32Base, 14, 20, 1048576, 48), nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("bq64-128-theta16-ell24-n1048576-lvcs48", "bq32-current-theta16-ell24", bq32Preset.Name, nizkProfileSmallWoodOnlyCandidateWithLVCS(bq32Base, 16, 24, 1048576, 48, 48), nizkProfileRelationCurrentBQ32()),
	}
	candidates = append(candidates, nizkProfileGeneratedSearchCandidates(bq32Preset.Name, bq32Base, bq32Preset.Name, q32Base)...)
	candidates = append(candidates, nizkProfileBQ6496ReductionCandidates(bq32Preset.Name, bq32Base)...)
	candidates = append(candidates, nizkProfileScopedR128Candidates(bq32Preset.Name, bq32Base)...)
	candidates = append(candidates, nizkProfileValidPrefixTrailCandidates(bq32Preset.Name, bq32Base)...)
	return nizkProfileDeduplicateCandidates(candidates)
}

func nizkProfileArchivedQ32R128Base(base intGenISISTuning) intGenISISTuning {
	base.LVCSNCols = 37
	base.NLeaves = 655360
	base.Eta = 45
	base.Theta = 9
	base.Ell = 11
	base.Kappa = [4]int{1, 0, 0, 8}
	base.DECSCollisionBits = 200
	base.DECSHashBits = 0
	base.DECSTapeBits = 0
	base.FSCollisionBits = 0
	base.SaltBits = 0
	base.PRFProfile = credential.IntGenISISPRFProfileDefault
	base.PRFParamsPath = credential.IntGenISISPRFParamsDefault
	return base
}

func nizkProfileSearchCandidatesForFilter(filter string) []NIZKProfileSearchCandidate {
	candidates := nizkProfileSearchCandidates()
	if !nizkProfileFormalSweepEnabled(filter) {
		return candidates
	}
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		return candidates
	}
	candidates = append(candidates, nizkProfileFormalBackendSweepCandidates(preset.Name, intGenISISTuningFromPresetSpec(preset.Showing))...)
	return nizkProfileDeduplicateCandidates(candidates)
}

func nizkProfileSearchCandidatesForReports(reports []NIZKProfileCandidateReport) []NIZKProfileSearchCandidate {
	for _, report := range reports {
		if report.FormalBackendCandidate {
			return nizkProfileSearchCandidatesForFilter("formal")
		}
	}
	return nizkProfileSearchCandidates()
}

func nizkProfileFormalSweepEnabled(filter string) bool {
	lower := strings.ToLower(strings.TrimSpace(filter))
	return strings.Contains(lower, "formal") || nizkProfileEnvBool("SPRUCE_FORMAL_BACKEND_SWEEP")
}

func nizkProfileCandidateFromTuning(name, relationEncoding, preset string, showing intGenISISTuning, relation benchmarkIntGenISISRelationReport) NIZKProfileSearchCandidate {
	return nizkProfileCandidateFromTuningWithOptions(name, relationEncoding, preset, showing, relation, nizkProfileCandidateOptions{})
}

type nizkProfileCandidateOptions struct {
	Family                      string
	TargetProfile               string
	LaneOverride                string
	CompilerBacked              bool
	PinnedLVCS                  bool
	DeriveEtaFloorOnly          bool
	RequiresTheoremAccounting   bool
	RequiresSplitTheorem        bool
	RelationFirstScore          float64
	ReductionLane               string
	ReductionModel              string
	FormalBackendCandidate      bool
	FormalBaselineLVCSNCols     int
	FormalProjectionOnlyReason  string
	HashFSBitsOverride          int
	TapeBitsOverride            int
	SaltBitsOverride            int
	TagElementsOverride         int
	NIZKTargetBitsOverride      float64
	RawQueryCapExponentOverride int
	ValidPrefixResearch         bool
	ValidPrefixCapExponent      [4]float64
	SerializerOmission          string
	ReconstructionAvailable     bool
	OmissionMapFSBound          bool
	Notes                       []string
}

func nizkProfileCandidateFromTuningWithOptions(name, relationEncoding, preset string, showing intGenISISTuning, relation benchmarkIntGenISISRelationReport, opts nizkProfileCandidateOptions) NIZKProfileSearchCandidate {
	if showing.Rho <= 0 {
		showing.Rho = 1
	}
	if showing.EllPrime <= 0 {
		showing.EllPrime = 1
	}
	if showing.ReplayProjection == "" {
		showing.ReplayProjection = nizkProfileProjectionProjectUDigitsYWResidual
	}
	family := opts.Family
	if family == "" {
		family = "static_projection"
	}
	notes := []string{"projection-only research candidate; does not alter maintained presets"}
	notes = append(notes, opts.Notes...)
	if opts.DeriveEtaFloorOnly {
		notes = append(notes, "eta is derived from the target floor for this generated probe")
	}
	if opts.PinnedLVCS {
		notes = append(notes, "LVCSNCols is pinned to a row/dQ breakpoint for this probe")
	}
	if opts.RequiresTheoremAccounting {
		notes = append(notes, "requires split or lookup theorem/accounting before it can be considered a concrete NIZK candidate")
	}
	if opts.RequiresSplitTheorem {
		notes = append(notes, "split-proof model is research-only and requires a separate composition theorem")
	}
	if opts.ValidPrefixResearch {
		notes = append(notes, "valid-prefix accounting is research-only; raw collision/programming/challenge-bias terms still use raw RO caps")
	}
	if opts.FormalBackendCandidate {
		notes = append(notes, "formal-backend tuning probe; does not alter maintained presets or full-system claims")
	}
	if opts.FormalProjectionOnlyReason != "" {
		notes = append(notes, opts.FormalProjectionOnlyReason)
	}
	if opts.SerializerOmission != "" && (!opts.ReconstructionAvailable || !opts.OmissionMapFSBound) {
		notes = append(notes, "serializer omission is fail-closed until verifier reconstruction and Fiat-Shamir binding are available")
	}
	if opts.SerializerOmission == PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2 {
		showing.TranscriptOmissionMode = opts.SerializerOmission
		notes = append(notes, "digest-bound SmallWood payload omission is verifier-bound and internal to research transcript accounting")
	}
	return NIZKProfileSearchCandidate{
		Name:                        name,
		Family:                      family,
		TargetProfile:               opts.TargetProfile,
		LaneOverride:                opts.LaneOverride,
		RelationEncoding:            relationEncoding,
		ControlPreset:               preset,
		CompilerBacked:              opts.CompilerBacked,
		PinnedLVCS:                  opts.PinnedLVCS,
		DeriveEtaFloorOnly:          opts.DeriveEtaFloorOnly,
		RequiresTheoremAccounting:   opts.RequiresTheoremAccounting,
		RequiresSplitTheorem:        opts.RequiresSplitTheorem,
		RelationFirstScore:          opts.RelationFirstScore,
		ReductionLane:               opts.ReductionLane,
		ReductionModel:              opts.ReductionModel,
		FormalBackendCandidate:      opts.FormalBackendCandidate,
		FormalBaselineLVCSNCols:     opts.FormalBaselineLVCSNCols,
		FormalProjectionOnlyReason:  opts.FormalProjectionOnlyReason,
		HashFSBitsOverride:          opts.HashFSBitsOverride,
		TapeBitsOverride:            opts.TapeBitsOverride,
		SaltBitsOverride:            opts.SaltBitsOverride,
		TagElementsOverride:         opts.TagElementsOverride,
		NIZKTargetBitsOverride:      opts.NIZKTargetBitsOverride,
		RawQueryCapExponentOverride: opts.RawQueryCapExponentOverride,
		ValidPrefixResearch:         opts.ValidPrefixResearch,
		ValidPrefixCapExponent:      opts.ValidPrefixCapExponent,
		SerializerOmission:          opts.SerializerOmission,
		ReconstructionAvailable:     opts.ReconstructionAvailable,
		OmissionMapFSBound:          opts.OmissionMapFSBound,
		Issuance:                    nizkProfileIssuanceFromShowing(showing),
		Showing:                     showing,
		Relation:                    relation,
		Notes:                       notes,
	}
}

type nizkProfileRelationVariant struct {
	Prefix                    string
	Encoding                  string
	Family                    string
	ControlPreset             string
	Base                      intGenISISTuning
	Relation                  benchmarkIntGenISISRelationReport
	RequiresTheoremAccounting bool
	Notes                     []string
}

type nizkProfileSmallWoodShape struct {
	Name    string
	Theta   int
	Ell     int
	NLeaves int
	Notes   []string
}

func nizkProfileGeneratedSearchCandidates(bq32PresetName string, bq32Base intGenISISTuning, q32PresetName string, q32Base intGenISISTuning) []NIZKProfileSearchCandidate {
	var out []NIZKProfileSearchCandidate
	for _, variant := range nizkProfileGeneratedRelationVariants(bq32PresetName, bq32Base, q32PresetName, q32Base) {
		for _, shape := range nizkProfileSmallWoodShapes() {
			relation := nizkProfileRelationForEll(variant.Relation, shape.Ell)
			for _, lvcs := range nizkProfileLVCSBreakpoints(relation, shape, variant.Base.NCols) {
				showing := nizkProfileSmallWoodOnlyCandidateWithLVCS(variant.Base, shape.Theta, shape.Ell, shape.NLeaves, 1, lvcs)
				notes := append([]string(nil), variant.Notes...)
				notes = append(notes, shape.Notes...)
				out = append(out, nizkProfileCandidateFromTuningWithOptions(
					fmt.Sprintf("%s-%s-lvcs%d", variant.Prefix, shape.Name, lvcs),
					fmt.Sprintf("%s-%s-lvcs%d", variant.Encoding, shape.Name, lvcs),
					variant.ControlPreset,
					showing,
					relation,
					nizkProfileCandidateOptions{
						Family:                    variant.Family,
						PinnedLVCS:                true,
						DeriveEtaFloorOnly:        true,
						RequiresTheoremAccounting: variant.RequiresTheoremAccounting,
						RelationFirstScore:        nizkProfileRelationFirstScore(variant.Relation, showing),
						Notes:                     notes,
					},
				))
			}
		}
	}
	return out
}

func nizkProfileFormalBackendSweepCandidates(presetName string, base intGenISISTuning) []NIZKProfileSearchCandidate {
	type formalShape struct {
		Target  string
		Theta   int
		Ell     int
		NLeaves int
		Notes   []string
	}
	relation := nizkProfileRelationCurrentBQ32()
	shapes := []formalShape{
		{Target: "BQ32-128", Theta: 10, Ell: 15, NLeaves: 983040, Notes: []string{"BQ32-128 current-relation formal-width baseline check"}},
		{Target: "BQ64-96", Theta: 12, Ell: 16, NLeaves: 983040, Notes: []string{"BQ64-96 current-relation formal-width baseline check"}},
		{Target: "BQ64-128", Theta: 14, Ell: 18, NLeaves: 983040, Notes: []string{"BQ64-128 current-relation formal-width baseline check"}},
		{Target: "BQ128-128", Theta: 13, Ell: 18, NLeaves: 983040, Notes: []string{"BQ128-128 raw-cap proof-only formal-width baseline check"}},
	}
	mk := func(shape formalShape, nameSuffix string, showing intGenISISTuning, relation benchmarkIntGenISISRelationReport, opts nizkProfileCandidateOptions) NIZKProfileSearchCandidate {
		targetLabel := strings.ToLower(strings.ReplaceAll(shape.Target, "_", "-"))
		opts.Family = nizkProfileFormalBackendFamily
		opts.TargetProfile = shape.Target
		opts.CompilerBacked = true
		opts.PinnedLVCS = true
		opts.DeriveEtaFloorOnly = true
		opts.FormalBackendCandidate = true
		if opts.FormalBaselineLVCSNCols <= 0 {
			opts.FormalBaselineLVCSNCols = 48
		}
		opts.Notes = append(append([]string(nil), shape.Notes...), opts.Notes...)
		relation = nizkProfileRelationWithDQOverride(nizkProfileRelationForEll(relation, showing.Ell), showing.DQOverride)
		opts.RelationFirstScore = nizkProfileRelationFirstScore(relation, showing)
		return nizkProfileCandidateFromTuningWithOptions(
			fmt.Sprintf("formal-%s-%s", targetLabel, nameSuffix),
			fmt.Sprintf("formal-%s-%s", targetLabel, nameSuffix),
			presetName,
			showing,
			relation,
			opts,
		)
	}
	var out []NIZKProfileSearchCandidate
	for _, shape := range shapes {
		for _, lvcs := range []int{1025, 1152, 1536} {
			showing := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, shape.Theta, shape.Ell, shape.NLeaves, 1, lvcs)
			out = append(out, mk(shape, fmt.Sprintf("current-lvcs%d", lvcs), showing, relation, nizkProfileCandidateOptions{
				Notes: []string{"formal LVCS width exceeds the native ring degree; useful only if row/Q block savings offset larger dDECS"},
			}))
		}
		highDQ := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, shape.Theta, shape.Ell, shape.NLeaves, 1, 1152)
		highDQ.DQOverride = 1152
		out = append(out, mk(shape, "dq1152-lvcs1152", highDQ, relation, nizkProfileCandidateOptions{
			Notes: []string{"measured high-dQ override probe; dQ is bounded by explicit domain size rather than native ring degree"},
		}))
	}
	packed := shapes[2]
	packedRelation := relation
	packedRelation.LogicalRows = 320
	packedRelation.RowCounts = map[string]int{
		"total":     320,
		"bound":     49,
		"mask":      70,
		"prf":       7,
		"shortness": 168,
	}
	packedRelation.DominantDegreeSource = "formal_packing_projection"
	packedShowing := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, packed.Theta, packed.Ell, packed.NLeaves, 1, 1152)
	packedShowing.DQOverride = 1152
	out = append(out, mk(packed, "packedrows320-dq1152-lvcs1152", packedShowing, packedRelation, nizkProfileCandidateOptions{
		RequiresTheoremAccounting:  true,
		FormalProjectionOnlyReason: "packing row-count reduction is projection-only until a compiler-backed relation supplies these rows and dQ",
		Notes:                      []string{"models whether formal high-degree masks could pay for fewer committed rows"},
	}))
	rho := shapes[2]
	rhoShowing := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, rho.Theta, rho.Ell, rho.NLeaves, 1, 1152)
	rhoShowing.Rho = 2
	rhoShowing.EllPrime = 2
	out = append(out, mk(rho, "rho2-ellprime2-lvcs1152", rhoShowing, relation, nizkProfileCandidateOptions{
		RequiresTheoremAccounting:  true,
		FormalProjectionOnlyReason: "SmallField 2025 measured protocol requires rho=1 and ell_prime=1; non-default values are projection-only",
		Notes:                      []string{"fail-closed probe for rho/ell_prime tuning pressure"},
	}))
	return out
}

func nizkProfileBQ6496ReductionCandidates(presetName string, base intGenISISTuning) []NIZKProfileSearchCandidate {
	relation := nizkProfileRelationCurrentBQ32()
	baseline := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 12, 16, 983040, 1, 43)
	mk := func(name, lane, model string, showing intGenISISTuning, relation benchmarkIntGenISISRelationReport, opts nizkProfileCandidateOptions) NIZKProfileSearchCandidate {
		opts.Family = "bq64_96_reduction"
		opts.TargetProfile = "BQ64-96"
		opts.PinnedLVCS = true
		opts.DeriveEtaFloorOnly = true
		opts.ReductionLane = lane
		opts.ReductionModel = model
		if opts.HashFSBitsOverride == 0 {
			opts.HashFSBitsOverride = 232
		}
		if opts.TapeBitsOverride == 0 {
			opts.TapeBitsOverride = 160
		}
		if opts.SaltBitsOverride == 0 {
			opts.SaltBitsOverride = 224
		}
		if opts.TagElementsOverride == 0 {
			opts.TagElementsOverride = 12
		}
		opts.Notes = append([]string{"BQ64-96 transcript-reduction research lane; profile remains requires_new_primitives"}, opts.Notes...)
		return nizkProfileCandidateFromTuningWithOptions(name, "bq64-96-reduction-"+name, presetName, showing, relation, opts)
	}
	var out []NIZKProfileSearchCandidate
	out = append(out,
		mk("baseline-h232-s224", "baseline", "measured_control", baseline, relation, nizkProfileCandidateOptions{
			CompilerBacked: true,
			Notes:          []string{fmt.Sprintf("measured baseline is %d bytes for r7l5-current-theta12-ell16-n983040-lvcs43", bq6496ReductionBaselineBytes)},
		}),
		mk("engineering-salt256", "width_model", "salt_width", baseline, relation, nizkProfileCandidateOptions{
			CompilerBacked:   true,
			SaltBitsOverride: 256,
			Notes:            []string{"tests the practical engineering salt lane; hash/FS remains 232 and tape remains 160 bits"},
		}),
	)
	for lvcs := 44; lvcs <= 52; lvcs++ {
		showing := baseline
		showing.LVCSNCols = lvcs
		out = append(out, mk(fmt.Sprintf("lvcs%d-h232", lvcs), "smallwood_retune", fmt.Sprintf("lvcs_breakpoint_%d", lvcs), showing, relation, nizkProfileCandidateOptions{
			CompilerBacked: true,
			Notes:          []string{"dense LVCS breakpoint probe for BQ64-96; keeps VTargets and BarSets explicit"},
		}))
	}
	for _, lvcs := range []int{43, 48, 52} {
		showing := baseline
		showing.Theta = 11
		showing.LVCSNCols = lvcs
		out = append(out, mk(fmt.Sprintf("theta11-lvcs%d-h232", lvcs), "smallwood_retune", fmt.Sprintf("theta11_lvcs%d", lvcs), showing, relation, nizkProfileCandidateOptions{
			CompilerBacked: true,
			Notes:          []string{"tests whether one theta unit can be removed while preserving the BQ64-96 algebraic target"},
		}))
	}
	for _, lvcs := range []int{43, 48} {
		showing := baseline
		showing.Ell = 15
		showing.LVCSNCols = lvcs
		out = append(out, mk(fmt.Sprintf("ell15-lvcs%d-h232", lvcs), "smallwood_retune", fmt.Sprintf("ell15_lvcs%d", lvcs), showing, relation, nizkProfileCandidateOptions{
			CompilerBacked: true,
			Notes:          []string{"tests whether one opening layer can be removed while preserving eps4"},
		}))
	}
	theta11Ell15 := baseline
	theta11Ell15.Theta = 11
	theta11Ell15.Ell = 15
	theta11Ell15.LVCSNCols = 48
	out = append(out, mk("theta11-ell15-lvcs48-h232", "smallwood_retune", "theta11_ell15_lvcs48", theta11Ell15, relation, nizkProfileCandidateOptions{
		CompilerBacked: true,
		Notes:          []string{"combined byte-aggressive BQ64-96 probe; accepted only if all SmallWood terms remain inside the grinding cap"},
	}))
	theta12Ell17 := baseline
	theta12Ell17.Ell = 17
	theta12Ell17.LVCSNCols = 48
	out = append(out, mk("theta12-ell17-lvcs48-h232", "smallwood_retune", "theta12_ell17_lvcs48", theta12Ell17, relation, nizkProfileCandidateOptions{
		CompilerBacked: true,
		Notes:          []string{"security-slack fallback to compare against byte-aggressive theta/ell reductions"},
	}))
	for _, audit := range []struct {
		name     string
		model    string
		relation benchmarkIntGenISISRelationReport
		showing  intGenISISTuning
		split    bool
	}{
		{name: "bq64-96-r11-l4-theorem-research", model: "r11_l4_topcap", relation: nizkProfileRelationR11L4TopCap(), showing: nizkProfileR11L4Candidate(baseline)},
		{name: "bq64-96-mixed-radix-theorem-research", model: "mixed_radix_topcap", relation: nizkProfileRelationMixedRadix(), showing: nizkProfileMixedRadixCandidate(baseline)},
		{name: "bq64-96-full-r2-theorem-research", model: "full_r2_decomposition", relation: nizkProfileRelationFullR2(), showing: nizkProfileFullR2Candidate(baseline)},
		{name: "bq64-96-split-shortness-research", model: "split_shortness", relation: nizkProfileRelationSplitShortness(), showing: nizkProfileSplitShortnessCandidate(baseline), split: true},
	} {
		opts := nizkProfileCandidateOptions{
			RequiresTheoremAccounting: true,
			RequiresSplitTheorem:      audit.split,
			RelationFirstScore:        nizkProfileRelationFirstScore(audit.relation, audit.showing),
			Notes:                     []string{"radix/decomposition audit only; not a current-theorem BQ64-96 candidate"},
		}
		out = append(out, mk(audit.name, "radix_audit", audit.model, audit.showing, audit.relation, opts))
	}
	return out
}

func nizkProfileValidPrefixTrailCandidates(presetName string, base intGenISISTuning) []NIZKProfileSearchCandidate {
	relation := nizkProfileRelationCurrentBQ32()
	bq64LVCS48 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 48)
	bq64LVCS49 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 49)
	bq64LVCS50 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 50)
	bq64LVCS51 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 51)
	bq64LVCS52 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 52)
	bq64LVCS53 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 53)
	bq64LVCS59 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 59)
	bq64Theta13 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 48)
	bq64Theta13H256Omit := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 43)
	bq64Theta13LVCS49 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 49)
	bq64Theta13LVCS50 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 50)
	bq64Theta13LVCS51 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 51)
	bq64Theta13LVCS52 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 52)
	bq64Theta13LVCS53 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 53)
	bq64Theta13LVCS59 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 59)
	bq64Theta13Ell17 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 17, 983040, 1, 43)
	bq64Theta13Ell17LVCS48 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 17, 983040, 1, 48)
	bq128VP64 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 48)
	bq128VP64LVCS53 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 53)
	bq128VP64LVCS59 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 59)
	bq128VP64Ell17 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 17, 983040, 1, 48)
	bq128VP80 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 16, 22, 1572864, 1, 59)
	bq128RawResidualTheta13 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 18, 983040, 1, 48)
	bq128RawResidualTheta13Ell17 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 13, 17, 983040, 1, 48)
	bq128RawResidualTheta14Ell17 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 17, 983040, 1, 48)
	bq128Raw := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 20, 28, 983040, 1, 59)
	bq128RawLVCS64 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 20, 28, 983040, 1, 64)
	bq128RawEll27 := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 20, 27, 983040, 1, 59)
	mk := func(name, targetProfile string, showing intGenISISTuning, opts nizkProfileCandidateOptions) NIZKProfileSearchCandidate {
		opts.Family = "valid_prefix_trail"
		opts.TargetProfile = targetProfile
		opts.LaneOverride = "valid_prefix_research"
		opts.CompilerBacked = true
		opts.PinnedLVCS = true
		opts.DeriveEtaFloorOnly = true
		if opts.ValidPrefixResearch {
			opts.RequiresTheoremAccounting = true
		}
		opts.Notes = append([]string{"valid-prefix trail preset candidate; not a live preset and not a maintained gate"}, opts.Notes...)
		return nizkProfileCandidateFromTuningWithOptions(name, "valid-prefix-"+name, presetName, showing, relation, opts)
	}
	mkRawResidual := func(name string, showing intGenISISTuning, opts nizkProfileCandidateOptions) NIZKProfileSearchCandidate {
		opts.Family = "raw128_residual"
		opts.TargetProfile = "BQ128-128"
		opts.LaneOverride = "raw128_residual"
		opts.CompilerBacked = true
		opts.PinnedLVCS = true
		opts.DeriveEtaFloorOnly = true
		opts.Notes = append([]string{"raw 2^128 query-budget, 128-bit residual algebraic target; no valid-prefix discount"}, opts.Notes...)
		return nizkProfileCandidateFromTuningWithOptions(name, "raw128-residual-"+name, presetName, showing, relation, opts)
	}
	return []NIZKProfileSearchCandidate{
		mk("bq64-128-vp-lvcs48-h264", "BQ64-128", bq64LVCS48, nizkProfileCandidateOptions{
			HashFSBitsOverride:     264,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 64, 64},
			Notes:                  []string{"measured theorem-valid LVCS48 baseline reduction lane; valid-prefix cap equals raw cap"},
		}),
		mk("bq64-128-vp-lvcs48-h256", "BQ64-128", bq64LVCS48, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 64, 64},
			Notes:                  []string{"same LVCS48 shape with the bare 256-bit hash/FS research lane; tape remains 192 bits"},
		}),
		mk("bq64-128-vp-lvcs49-h256", "BQ64-128", bq64LVCS49, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 64, 64},
			Notes:                  []string{"dense LVCS49 valid-prefix probe between the accepted LVCS48 point and known high-k LVCS53 point"},
		}),
		mk("bq64-128-vp-lvcs50-h256", "BQ64-128", bq64LVCS50, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 64, 64},
			Notes:                  []string{"dense LVCS50 valid-prefix probe between the accepted LVCS48 point and known high-k LVCS53 point"},
		}),
		mk("bq64-128-vp-lvcs51-h256", "BQ64-128", bq64LVCS51, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 64, 64},
			Notes:                  []string{"dense LVCS51 valid-prefix probe between the accepted LVCS48 point and known high-k LVCS53 point"},
		}),
		mk("bq64-128-vp-lvcs52-h256", "BQ64-128", bq64LVCS52, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 64, 64},
			Notes:                  []string{"dense LVCS52 valid-prefix probe between the accepted LVCS48 point and known high-k LVCS53 point"},
		}),
		mk("bq64-128-vp-lvcs53-h256", "BQ64-128", bq64LVCS53, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 64, 64},
			Notes:                  []string{"LVCS53 breakpoint probe with explicit VTargets/BarSets; tests whether fewer row/opening blocks beat larger DECS columns"},
		}),
		mk("bq64-128-vp-lvcs59-h256", "BQ64-128", bq64LVCS59, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 64, 64},
			Notes:                  []string{"LVCS59 breakpoint probe with explicit VTargets/BarSets; expected to be useful only if row-block savings dominate R/Pdecs growth"},
		}),
		mk("bq64-128-vp-theta13-h256", "BQ64-128", bq64Theta13, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"byte-aggressive theta13 lane; only eligible when the round-3 valid-prefix cap reduces required grinding to the supported limit"},
		}),
		mk("bq64-128-vp-theta13-h256-vtargets-included-pdecs", "BQ64-128", bq64Theta13H256Omit, nizkProfileCandidateOptions{
			HashFSBitsOverride:      256,
			TapeBitsOverride:        192,
			SaltBitsOverride:        256,
			TagElementsOverride:     13,
			ValidPrefixResearch:     true,
			ValidPrefixCapExponent:  [4]float64{64, 64, 61, 64},
			SerializerOmission:      PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2,
			ReconstructionAvailable: true,
			OmissionMapFSBound:      true,
			Notes:                   []string{"safe serializer target: VTargets and BarSets remain explicit; only already-reconstructible Pdecs columns are descriptor-bound"},
		}),
		mk("bq64-128-vp-theta13-lvcs49-h256", "BQ64-128", bq64Theta13LVCS49, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"theta13 LVCS49 dense valid-prefix probe with explicit matrices"},
		}),
		mk("bq64-128-vp-theta13-lvcs50-h256", "BQ64-128", bq64Theta13LVCS50, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"theta13 LVCS50 dense valid-prefix probe with explicit matrices"},
		}),
		mk("bq64-128-vp-theta13-lvcs51-h256", "BQ64-128", bq64Theta13LVCS51, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"theta13 LVCS51 dense valid-prefix probe with explicit matrices"},
		}),
		mk("bq64-128-vp-theta13-lvcs52-h256", "BQ64-128", bq64Theta13LVCS52, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"theta13 LVCS52 dense valid-prefix probe with explicit matrices"},
		}),
		mk("bq64-128-vp-theta13-lvcs53-h256", "BQ64-128", bq64Theta13LVCS53, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"theta13 LVCS53 breakpoint probe with explicit matrices; checks whether byte gains survive the algebraic cap"},
		}),
		mk("bq64-128-vp-theta13-lvcs59-h256", "BQ64-128", bq64Theta13LVCS59, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"theta13 LVCS59 breakpoint probe with explicit matrices; likely byte-aggressive but kept research-only"},
		}),
		mk("bq64-128-vp-theta13-ell17-h256", "BQ64-128", bq64Theta13Ell17, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"safe retuning candidate: lowers ell by one while keeping VTargets and BarSets explicit"},
		}),
		mk("bq64-128-vp-theta13-ell17-lvcs48-h256", "BQ64-128", bq64Theta13Ell17LVCS48, nizkProfileCandidateOptions{
			HashFSBitsOverride:     256,
			TapeBitsOverride:       192,
			SaltBitsOverride:       256,
			TagElementsOverride:    13,
			ValidPrefixResearch:    true,
			ValidPrefixCapExponent: [4]float64{64, 64, 61, 64},
			Notes:                  []string{"safe retuning candidate: tests whether LVCS48 row-block savings compensate for larger column width at ell=17"},
		}),
		mk("bq128-128-vp64-lvcs48-h512", "BQ128-128", bq128VP64, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      200,
			RawQueryCapExponentOverride: 128,
			ValidPrefixResearch:         true,
			ValidPrefixCapExponent:      [4]float64{64, 64, 64, 64},
			Notes:                       []string{"raw collision budget remains 2^128; algebraic extraction uses a 2^64 valid-prefix research cap"},
		}),
		mk("bq128-128-vp64-lvcs48-h512-vtargets-included-pdecs", "BQ128-128", bq128VP64, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      200,
			RawQueryCapExponentOverride: 128,
			ValidPrefixResearch:         true,
			ValidPrefixCapExponent:      [4]float64{64, 64, 64, 64},
			SerializerOmission:          PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2,
			ReconstructionAvailable:     true,
			OmissionMapFSBound:          true,
			Notes:                       []string{"BQ128 vp64 serializer trail with VTargets/BarSets explicit and Pdecs omitted-column compression only"},
		}),
		mk("bq128-128-vp64-lvcs53-h512", "BQ128-128", bq128VP64LVCS53, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      200,
			RawQueryCapExponentOverride: 128,
			ValidPrefixResearch:         true,
			ValidPrefixCapExponent:      [4]float64{64, 64, 64, 64},
			Notes:                       []string{"BQ128 vp64 LVCS53 breakpoint probe; keeps explicit VTargets/BarSets and valid-prefix theorem status"},
		}),
		mk("bq128-128-vp64-lvcs59-h512", "BQ128-128", bq128VP64LVCS59, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      200,
			RawQueryCapExponentOverride: 128,
			ValidPrefixResearch:         true,
			ValidPrefixCapExponent:      [4]float64{64, 64, 64, 64},
			Notes:                       []string{"BQ128 vp64 LVCS59 breakpoint probe; tests whether auth/pdecs pressure offsets row-block savings"},
		}),
		mk("bq128-128-vp64-theta14-ell17-lvcs48-h512", "BQ128-128", bq128VP64Ell17, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      200,
			RawQueryCapExponentOverride: 128,
			ValidPrefixResearch:         true,
			ValidPrefixCapExponent:      [4]float64{64, 64, 64, 64},
			Notes:                       []string{"safe retuning candidate: tests ell=17 for vp64 while keeping explicit VTargets and BarSets"},
		}),
		mk("bq128-128-vp80-search", "BQ128-128", bq128VP80, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      216,
			RawQueryCapExponentOverride: 128,
			ValidPrefixResearch:         true,
			ValidPrefixCapExponent:      [4]float64{80, 80, 80, 80},
			Notes:                       []string{"search lane for a 2^80 valid-prefix algebraic budget over theta=16..18, ell=20..24 style shapes"},
		}),
		mk("bq128-128-vp80-search-vtargets-included-pdecs", "BQ128-128", bq128VP80, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      216,
			RawQueryCapExponentOverride: 128,
			ValidPrefixResearch:         true,
			ValidPrefixCapExponent:      [4]float64{80, 80, 80, 80},
			SerializerOmission:          PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2,
			ReconstructionAvailable:     true,
			OmissionMapFSBound:          true,
			Notes:                       []string{"BQ128 vp80 serializer search lane; VTargets/BarSets stay explicit pending a reconstruction theorem"},
		}),
		mkRawResidual(nizkProfileBQ128RawResidualFrontierCandidate, bq128RawResidualTheta13, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      128,
			RawQueryCapExponentOverride: 128,
			Notes:                       []string{"raw 2^128 query budget with 128-bit residual algebraic target; no valid-prefix discount"},
		}),
		mkRawResidual("bq128-128-raw128-residual128-theta13-ell17-lvcs48-h512", bq128RawResidualTheta13Ell17, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      128,
			RawQueryCapExponentOverride: 128,
			Notes:                       []string{"raw 2^128 residual-128 byte probe with theta13 and ell17; expected to classify by eps4/grinding"},
		}),
		mkRawResidual("bq128-128-raw128-residual128-theta14-ell17-lvcs48-h512", bq128RawResidualTheta14Ell17, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			NIZKTargetBitsOverride:      128,
			RawQueryCapExponentOverride: 128,
			Notes:                       []string{"raw 2^128 residual-128 fallback with theta14 and ell17; no valid-prefix discount"},
		}),
		mk("bq128-128-raw128-control", "BQ128-128", bq128Raw, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			RawQueryCapExponentOverride: 128,
			Notes:                       []string{"current raw-cap control: all SmallWood algebraic extraction terms pay the full 2^128 cap"},
		}),
		mk("bq128-128-raw128-control-vtargets-included-pdecs", "BQ128-128", bq128Raw, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			RawQueryCapExponentOverride: 128,
			SerializerOmission:          PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2,
			ReconstructionAvailable:     true,
			OmissionMapFSBound:          true,
			Notes:                       []string{"raw 2^128 control with VTargets/BarSets explicit and Pdecs omitted-column compression only; no valid-prefix algebraic discount"},
		}),
		mk("bq128-128-raw128-lvcs64-h512", "BQ128-128", bq128RawLVCS64, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			RawQueryCapExponentOverride: 128,
			Notes:                       []string{"raw 2^128 LVCS64 breakpoint probe; no valid-prefix algebraic discount and explicit matrix payloads"},
		}),
		mk("bq128-128-raw128-theta20-ell27-lvcs59-h512", "BQ128-128", bq128RawEll27, nizkProfileCandidateOptions{
			HashFSBitsOverride:          512,
			TapeBitsOverride:            256,
			SaltBitsOverride:            384,
			TagElementsOverride:         20,
			RawQueryCapExponentOverride: 128,
			Notes:                       []string{"safe raw-control retuning candidate: tests ell=27 without valid-prefix algebraic discount"},
		}),
	}
}

func nizkProfileGeneratedRelationVariants(bq32PresetName string, bq32Base intGenISISTuning, q32PresetName string, q32Base intGenISISTuning) []nizkProfileRelationVariant {
	return []nizkProfileRelationVariant{
		{
			Prefix:        "r7l5-current",
			Encoding:      "r7l5-current-projv5",
			Family:        "current_r7_l5",
			ControlPreset: bq32PresetName,
			Base:          bq32Base,
			Relation:      nizkProfileRelationCurrentBQ32(),
			Notes:         []string{"current BQ32-96 relation used as the baseline for high-security NIZK-only retuning"},
		},
		{
			Prefix:        "q32-control",
			Encoding:      "q32-128-current-relation-projv5",
			Family:        "q32_control",
			ControlPreset: q32PresetName,
			Base:          q32Base,
			Relation:      nizkProfileRelationCurrentBQ32(),
			Notes:         []string{"existing q32-128 proof-budget preset used as a high-soundness control"},
		},
	}
}

func nizkProfileSmallWoodShapes() []nizkProfileSmallWoodShape {
	return []nizkProfileSmallWoodShape{
		{Name: "theta9-ell15-n786432", Theta: 9, Ell: 15, NLeaves: 786432, Notes: []string{"BQ32-128 byte-pressure probe below the current theta10 frontier"}},
		{Name: "theta9-ell16-n1048576", Theta: 9, Ell: 16, NLeaves: 1048576},
		{Name: "theta10-ell15-n917504", Theta: 10, Ell: 15, NLeaves: 917504},
		{Name: "theta10-ell16-n1048576", Theta: 10, Ell: 16, NLeaves: 1048576},
		{Name: "theta11-ell16-n1048576", Theta: 11, Ell: 16, NLeaves: 1048576},
		{Name: "theta12-ell16-n983040", Theta: 12, Ell: 16, NLeaves: 983040, Notes: []string{"sub-q executable neighbor for BQ64-96 measured overlay"}},
		{Name: "theta12-ell16-n1048576", Theta: 12, Ell: 16, NLeaves: 1048576},
		{Name: "theta12-ell18-n1048576", Theta: 12, Ell: 18, NLeaves: 1048576},
		{Name: "theta13-ell18-n1048576", Theta: 13, Ell: 18, NLeaves: 1048576, Notes: []string{"BQ64-96 aggressive theta/ell reduction probe"}},
		{Name: "theta13-ell19-n1048576", Theta: 13, Ell: 19, NLeaves: 1048576},
		{Name: "theta14-ell18-n983040", Theta: 14, Ell: 18, NLeaves: 983040, Notes: []string{"sub-q executable neighbor for BQ64-128 measured overlay"}},
		{Name: "theta14-ell18-n1048576", Theta: 14, Ell: 18, NLeaves: 1048576},
		{Name: "theta14-ell19-n1048576", Theta: 14, Ell: 19, NLeaves: 1048576},
		{Name: "theta14-ell20-n1048576", Theta: 14, Ell: 20, NLeaves: 1048576},
		{Name: "theta15-ell20-n1310720", Theta: 15, Ell: 20, NLeaves: 1310720},
		{Name: "theta16-ell22-n1572864", Theta: 16, Ell: 22, NLeaves: 1572864},
		{Name: "theta16-ell24-n1048576", Theta: 16, Ell: 24, NLeaves: 1048576},
		{Name: "theta18-ell24-n2097152", Theta: 18, Ell: 24, NLeaves: 2097152},
		{Name: "theta20-ell28-n983040", Theta: 20, Ell: 28, NLeaves: 983040, Notes: []string{"sub-q executable stress probe for the BQ128-128 lane"}},
		{Name: "theta20-ell28-n2097152", Theta: 20, Ell: 28, NLeaves: 2097152},
		{Name: "theta22-ell32-n3145728", Theta: 22, Ell: 32, NLeaves: 3145728},
		{Name: "theta24-ell36-n4194304", Theta: 24, Ell: 36, NLeaves: 4194304, Notes: []string{"BQ128-128 extreme NIZK-only feasibility probe"}},
		{Name: "theta26-ell40-n4194304", Theta: 26, Ell: 40, NLeaves: 4194304},
	}
}

func nizkProfileLVCSBreakpoints(relation benchmarkIntGenISISRelationReport, shape nizkProfileSmallWoodShape, ncols int) []int {
	rows := maxInt(relation.LogicalRows, 1)
	dq := maxInt(relation.DQ, 1)
	minLVCS := maxInt(ncols, 32)
	vals := []int{
		minLVCS, 40, 48, 56, 64, 72, 80, 88, 92, 96, 104, 112, 128, 144, 160, 192, 224,
	}
	for blocks := 3; blocks <= 14; blocks++ {
		vals = append(vals, ceilDivInt(rows, blocks), ceilDivInt(dq, blocks))
	}
	continuous := math.Sqrt(float64(maxInt(shape.Ell, 1)) * (float64(rows*(ncols+shape.Theta)) + float64(dq*shape.Theta)) / 96.0)
	if continuous > 1 {
		center := int(math.Round(continuous))
		for delta := -4; delta <= 4; delta++ {
			vals = append(vals, center+delta)
		}
	}
	return nizkProfileBoundedUniqueInts(vals, minLVCS, 256)
}

func nizkProfileRelationFirstScore(relation benchmarkIntGenISISRelationReport, showing intGenISISTuning) float64 {
	lvcs := maxInt(showing.LVCSNCols, 1)
	theta := maxInt(showing.Theta, 1)
	ell := maxInt(showing.Ell, 1)
	eta := maxInt(showing.Eta, 1)
	rows := maxInt(relation.LogicalRows, 1)
	dq := maxInt(relation.DQ, 1)
	ddecs := lvcs + ell - 1
	rowBlocks := ceilDivInt(rows, lvcs)
	dqBlocks := ceilDivInt(dq, lvcs)
	return float64(theta*(rows+dq+lvcs) + ell*(rowBlocks*(32+theta)+dqBlocks*theta) + eta*(ddecs+lvcs))
}

func nizkProfileDeduplicateCandidates(candidates []NIZKProfileSearchCandidate) []NIZKProfileSearchCandidate {
	seen := make(map[string]struct{}, len(candidates))
	out := make([]NIZKProfileSearchCandidate, 0, len(candidates))
	for _, cand := range candidates {
		if _, ok := seen[cand.Name]; ok {
			continue
		}
		seen[cand.Name] = struct{}{}
		out = append(out, cand)
	}
	return out
}

func nizkProfileR11L4Candidate(base intGenISISTuning) intGenISISTuning {
	out := base
	out.SigShortnessRadix = 11
	out.SigShortnessDigits = 4
	out.CompressedRows = 1
	out.ReplayProjection = nizkProfileProjectionProjectUDigitsYWResidual
	return out
}

func nizkProfileMixedRadixCandidate(base intGenISISTuning) intGenISISTuning {
	out := base
	out.SigShortnessRadix = 11
	out.SigShortnessDigits = 4
	out.CompressedRows = 1
	out.ReplayProjection = nizkProfileProjectionProjectUDigitsYWResidual
	return out
}

func nizkProfileSplitShortnessCandidate(base intGenISISTuning) intGenISISTuning {
	out := base
	out.SigShortnessRadix = 7
	out.SigShortnessDigits = 5
	out.CompressedRows = 0
	out.ReplayProjection = nizkProfileProjectionProjectUDigitsYWResidual
	return out
}

func nizkProfileFullR2Candidate(base intGenISISTuning) intGenISISTuning {
	out := base
	out.SigShortnessRadix = 2
	out.SigShortnessDigits = 13
	out.CompressedRows = 0
	out.ReplayProjection = nizkProfileProjectionProjectUDigitsYWResidual
	return out
}

func nizkProfileSmallWoodOnlyCandidate(base intGenISISTuning, theta, ell, nleaves, eta int) intGenISISTuning {
	return nizkProfileSmallWoodOnlyCandidateWithLVCS(base, theta, ell, nleaves, eta, base.LVCSNCols)
}

func nizkProfileSmallWoodOnlyCandidateWithLVCS(base intGenISISTuning, theta, ell, nleaves, eta, lvcs int) intGenISISTuning {
	out := base
	out.Theta = theta
	out.Ell = ell
	out.NLeaves = nleaves
	out.Eta = eta
	out.LVCSNCols = lvcs
	out.Kappa = [4]int{}
	out.Rho = 1
	out.EllPrime = 1
	out.ReplayProjection = nizkProfileProjectionProjectUDigitsYWResidual
	return out
}

func nizkProfileRelationCurrentBQ32() benchmarkIntGenISISRelationReport {
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(9, 8, 32, 9)
	return benchmarkIntGenISISRelationReport{
		LogicalRows:      472,
		ParallelDegree:   9,
		AggregatedDegree: 8,
		DQParallel:       dqParallel,
		DQAggregate:      dqAggregate,
		DQ:               dq,
		MaskDegreeBound:  dq,
		RowCounts: map[string]int{
			"total":     472,
			"bound":     49,
			"mask":      70,
			"prf":       7,
			"shortness": 320,
		},
		ConstraintCounts: map[string]int{
			"fpar_int":            32,
			"prf_key_bridge":      8,
			"projected_signature": 1024,
			"range":               49,
			"shortness":           320,
			"source_bridge":       1024,
		},
		DominantDegreeSource: "compression",
		DominantDQBranch:     "parallel",
	}
}

func nizkProfileRelationMixedRadix() benchmarkIntGenISISRelationReport {
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(10, 8, 32, 9)
	return benchmarkIntGenISISRelationReport{
		LogicalRows:      440,
		ParallelDegree:   10,
		AggregatedDegree: 8,
		DQParallel:       dqParallel,
		DQAggregate:      dqAggregate,
		DQ:               dq,
		MaskDegreeBound:  dq,
		RowCounts: map[string]int{
			"total":     440,
			"bound":     49,
			"mask":      70,
			"prf":       7,
			"shortness": 288,
		},
		ConstraintCounts: map[string]int{
			"fpar_int":            32,
			"prf_key_bridge":      8,
			"projected_signature": 1024,
			"range":               49,
			"shortness":           288,
			"source_bridge":       1024,
		},
		DominantDegreeSource: "mixed_radix_shortness",
		DominantDQBranch:     "parallel",
	}
}

func nizkProfileRelationSplitShortness() benchmarkIntGenISISRelationReport {
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(7, 6, 32, 9)
	return benchmarkIntGenISISRelationReport{
		LogicalRows:      536,
		ParallelDegree:   7,
		AggregatedDegree: 6,
		DQParallel:       dqParallel,
		DQAggregate:      dqAggregate,
		DQ:               dq,
		MaskDegreeBound:  dq,
		RowCounts: map[string]int{
			"total":     536,
			"bound":     49,
			"mask":      70,
			"prf":       7,
			"shortness": 384,
		},
		ConstraintCounts: map[string]int{
			"fpar_int":            32,
			"prf_key_bridge":      8,
			"projected_signature": 1024,
			"range":               49,
			"shortness":           384,
			"source_bridge":       1024,
		},
		DominantDegreeSource: "split_shortness",
		DominantDQBranch:     "parallel",
	}
}

func nizkProfileRelationR11L4TopCap() benchmarkIntGenISISRelationReport {
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(11, 8, 32, 9)
	return benchmarkIntGenISISRelationReport{
		LogicalRows:      408,
		ParallelDegree:   11,
		AggregatedDegree: 8,
		DQParallel:       dqParallel,
		DQAggregate:      dqAggregate,
		DQ:               dq,
		MaskDegreeBound:  dq,
		RowCounts: map[string]int{
			"total":     408,
			"bound":     49,
			"mask":      70,
			"prf":       7,
			"shortness": 256,
		},
		ConstraintCounts: map[string]int{
			"fpar_int":            32,
			"prf_key_bridge":      8,
			"projected_signature": 1024,
			"range":               49,
			"shortness":           256,
			"source_bridge":       1024,
		},
		DominantDegreeSource: "shortness",
		DominantDQBranch:     "parallel",
	}
}

func nizkProfileRelationFullR2() benchmarkIntGenISISRelationReport {
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(9, 8, 32, 9)
	return benchmarkIntGenISISRelationReport{
		LogicalRows:      984,
		ParallelDegree:   9,
		AggregatedDegree: 8,
		DQParallel:       dqParallel,
		DQAggregate:      dqAggregate,
		DQ:               dq,
		MaskDegreeBound:  dq,
		RowCounts: map[string]int{
			"total":     984,
			"bound":     49,
			"mask":      70,
			"prf":       7,
			"shortness": 832,
		},
		ConstraintCounts: map[string]int{
			"fpar_int":            32,
			"prf_key_bridge":      8,
			"projected_signature": 1024,
			"range":               49,
			"shortness":           832,
			"source_bridge":       1024,
		},
		DominantDegreeSource: "full_r2_row_explosion",
		DominantDQBranch:     "parallel",
	}
}

func nizkProfileRelationForEll(relation benchmarkIntGenISISRelationReport, ell int) benchmarkIntGenISISRelationReport {
	out := relation
	if ell <= 0 {
		ell = 1
	}
	ncols := 32
	if out.DQParallel > 0 && out.ParallelDegree > 0 {
		dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(out.ParallelDegree, out.AggregatedDegree, ncols, ell)
		out.DQParallel = dqParallel
		out.DQAggregate = dqAggregate
		out.DQ = dq
		out.MaskDegreeBound = dq
		if dqParallel >= dqAggregate {
			out.DominantDQBranch = "parallel"
		} else {
			out.DominantDQBranch = "aggregate"
		}
	}
	return out
}

func nizkProfileRelationWithDQOverride(relation benchmarkIntGenISISRelationReport, dqOverride int) benchmarkIntGenISISRelationReport {
	if dqOverride <= 0 || dqOverride <= relation.DQ {
		return relation
	}
	out := relation
	out.DQ = dqOverride
	out.MaskDegreeBound = dqOverride
	out.DominantDQBranch = "override"
	return out
}

func nizkProfileRelationSafety(cand NIZKProfileSearchCandidate, relation benchmarkIntGenISISRelationReport, ell int) NIZKProfileRelationSafetyReport {
	baselineRelation := nizkProfileRelationCurrentBQ32()
	baseline := nizkProfileRelationForEll(baselineRelation, ell)
	out := NIZKProfileRelationSafetyReport{
		CertificateStatus:         "current_theorem_safe",
		CurrentTheoremSafe:        true,
		CompilerBacked:            cand.CompilerBacked,
		RequiresTheoremAccounting: cand.RequiresTheoremAccounting && !cand.ValidPrefixResearch,
		RequiresSplitTheorem:      cand.RequiresSplitTheorem,
		BaselineRows:              baseline.LogicalRows,
		BaselineDQ:                baseline.DQ,
		RowsDelta:                 relation.LogicalRows - baseline.LogicalRows,
		DQDelta:                   relation.DQ - baseline.DQ,
	}
	if !cand.CompilerBacked {
		out.RejectionReasons = append(out.RejectionReasons, "relation is projection-only until a compiled benchmark supplies rows and degree metadata")
	}
	if cand.RequiresTheoremAccounting && !cand.ValidPrefixResearch {
		out.RejectionReasons = append(out.RejectionReasons, "relation requires new theorem/accounting before current-theorem ranking")
	}
	if cand.RequiresSplitTheorem {
		out.RejectionReasons = append(out.RejectionReasons, "split relation requires a separate composition theorem")
	}
	if cand.Family != nizkProfileScopedR128Family {
		if relation.DQ > baseline.DQ {
			out.RejectionReasons = append(out.RejectionReasons, fmt.Sprintf("candidate dQ %d exceeds current safe dQ %d", relation.DQ, baseline.DQ))
		}
		if relation.LogicalRows > baseline.LogicalRows && relation.DQ >= baseline.DQ {
			out.RejectionReasons = append(out.RejectionReasons, fmt.Sprintf("candidate rows %d exceed current safe rows %d without a dQ reduction", relation.LogicalRows, baseline.LogicalRows))
		}
	}
	if len(out.RejectionReasons) > 0 {
		out.CurrentTheoremSafe = false
		out.CertificateStatus = "relation_theorem_blocked"
	}
	return out
}

func nizkProfileCandidateReport(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate) NIZKProfileCandidateReport {
	target = nizkProfileTargetForCandidate(target, cand)
	showing := cand.Showing
	relation := nizkProfileRelationWithDQOverride(nizkProfileRelationForEll(cand.Relation, maxInt(showing.Ell, 1)), showing.DQOverride)
	accounting := nizkProfileAlgebraicAccounting(target, cand)
	effectiveCaps := accounting.EffectiveAlgebraicCapLog2
	smallwood := deriveNIZKProfileSmallWoodReportWithCaps(target, relation, showing, cand.PinnedLVCS, cand.DeriveEtaFloorOnly, effectiveCaps, cand.ValidPrefixResearch)
	relation = nizkProfileRelationWithDQOverride(nizkProfileRelationForEll(cand.Relation, smallwood.Ell), showing.DQOverride)
	relationSafety := nizkProfileRelationSafety(cand, relation, smallwood.Ell)
	issuanceRelation := nizkProfileRelationWithDQOverride(nizkProfileIssuanceRelationForEll(smallwood.Ell), showing.DQOverride)
	issuanceRoundBits := nizkProfileProjectedRoundBits(target, issuanceRelation, smallwood)
	showingRoundBits := nizkProfileProjectedRoundBits(target, relation, smallwood)
	issuanceAlgebraicBits := nizkProfileAggregateBits(issuanceRoundBits)
	showingAlgebraicBits := nizkProfileAggregateBits(showingRoundBits)
	fullGame := nizkProfileProjectedFullGame(target, issuanceAlgebraicBits, showingAlgebraicBits)
	buckets := nizkProfileProjectedBuckets(target, relation, smallwood)
	buckets = nizkProfileApplyProjectedSerializerOmission(cand, buckets)
	paperTranscriptBytes := buckets.Q + buckets.R + buckets.Pdecs + buckets.Auth + buckets.Tapes + buckets.VTargets + buckets.BarSets + buckets.SigShortness
	combinedPaperBytes := 0
	projectedProverWorkUnits := uint64(0)
	var issuanceProjection, showingProjection NIZKProfilePhaseProjection
	var issuanceProjectionErr, showingProjectionErr error
	exactTwoPhaseProjection := target.FullGameTargetBits > 0 && cand.Family == nizkProfileScopedR128Family
	if exactTwoPhaseProjection {
		issuanceProjection, issuanceProjectionErr = nizkProfileProjectPhase(target, cand, issuanceRelation, smallwood)
		showingProjection, showingProjectionErr = nizkProfileProjectPhase(target, cand, relation, smallwood)
		if showingProjectionErr == nil {
			buckets = nizkProfileBucketDigestFromPaperTranscript(showingProjection.Transcript)
			buckets = nizkProfileApplyProjectedSerializerOmission(cand, buckets)
			paperTranscriptBytes = showingProjection.Transcript.OptimizedBytes
			projectedProverWorkUnits += showingProjection.ProverWorkUnits
		}
		if issuanceProjectionErr == nil {
			combinedPaperBytes += issuanceProjection.Transcript.OptimizedBytes
			projectedProverWorkUnits += issuanceProjection.ProverWorkUnits
		}
		if showingProjectionErr == nil {
			combinedPaperBytes += showingProjection.Transcript.OptimizedBytes
		}
	}
	formalDiagnostics := nizkProfileFormalBackendDiagnostics(target, cand, relation, smallwood, paperTranscriptBytes)
	lvcsAboveRing := formalDiagnostics != nil && formalDiagnostics.LVCSAboveRing
	ledgerStatus := string(target.TargetStatus)
	ledgerReasons := []string{target.PrimitiveBlockerReason}
	if cand.ValidPrefixResearch {
		ledgerStatus = string(credential.SecurityProfileRequiresTheory)
		ledgerReasons = append(ledgerReasons, "valid-prefix algebraic accounting requires a new theorem")
	}
	report := NIZKProfileCandidateReport{
		SecurityProfile:           target.SecurityProfile,
		Lane:                      target.Lane,
		Candidate:                 cand.Name,
		Family:                    cand.Family,
		RelationEncoding:          cand.RelationEncoding,
		ControlPreset:             cand.ControlPreset,
		CompilerBacked:            cand.CompilerBacked,
		FormalBackendCandidate:    cand.FormalBackendCandidate,
		LVCSAboveRing:             lvcsAboveRing,
		RequiresTheoremWork:       cand.RequiresTheoremAccounting || cand.ValidPrefixResearch,
		RequiresSplitTheorem:      cand.RequiresSplitTheorem,
		UsesValidPrefixAccounting: cand.ValidPrefixResearch,
		RelationFirstScore:        cand.RelationFirstScore,
		TargetStatus:              target.TargetStatus,
		PrimitiveBlockerReason:    target.PrimitiveBlockerReason,
		ForcedBySecurity:          nizkProfileForcedBySecurity(target),
		MeasurementStatus:         "projected",
		MeasurementSource:         "formula_projection",
		LedgerStatus:              ledgerStatus,
		LedgerReasons:             ledgerReasons,
		NIZKTargetBits:            target.NIZKTargetBits,
		FullGameTargetBits:        target.FullGameTargetBits,
		FullGameBits:              fullGame.GlobalCollisionFullGameBits,
		GlobalCollisionBits:       fullGame.GlobalCollisionBits,
		CoreBitsRequired:          target.CoreBitsRequired,
		RawQueryCapLog2:           float64(target.QueryCapExponent),
		EffectiveAlgebraicCapLog2: effectiveCaps,
		AlgebraicAccounting:       accounting,
		HashFSBitsRange:           target.HashFSBitsRange,
		TapeBitsRange:             target.TapeBitsRange,
		SaltBitsRange:             target.SaltBitsRange,
		TagElementsRange:          target.TagElementsRange,
		Relation:                  relation,
		RelationSafety:            relationSafety,
		SmallWood:                 smallwood,
		IssuanceAlgebraicBits:     issuanceAlgebraicBits,
		ShowingAlgebraicBits:      showingAlgebraicBits,
		AlgebraicRoundBits:        showingRoundBits,
		TranscriptBuckets:         buckets,
		PaperTranscriptBytes:      paperTranscriptBytes,
		CombinedPaperBytes:        combinedPaperBytes,
		ProjectedProverWorkUnits:  projectedProverWorkUnits,
		ExpectedGrindingWork:      smallwood.ExpectedGrindingWork,
		ExpectedGrindingWorkLog2:  smallwood.ExpectedGrindingWorkLog2,
		ValidPrefixCost:           nizkProfileValidPrefixCostReport(target, cand, nil),
		Notes:                     append([]string(nil), cand.Notes...),
		FormalBackendDiagnostics:  formalDiagnostics,
	}
	if exactTwoPhaseProjection {
		if issuanceProjectionErr == nil {
			report.IssuanceProjection = &issuanceProjection
		} else {
			report.MeasurementStatus = "projection_failed"
			report.MeasurementError = fmt.Sprintf("issuance projection: %v", issuanceProjectionErr)
		}
		if showingProjectionErr == nil {
			report.ShowingProjection = &showingProjection
		} else {
			report.MeasurementStatus = "projection_failed"
			if report.MeasurementError != "" {
				report.MeasurementError += "; "
			}
			report.MeasurementError += fmt.Sprintf("showing projection: %v", showingProjectionErr)
		}
	}
	report.BQ64Reduction = bq64ReductionReport(target, cand, report, nil)
	report.TranscriptDrivers = nizkProfileTranscriptDrivers(report.TranscriptBuckets, report.PaperTranscriptBytes)
	report.OptimizationLevers = nizkProfileOptimizationLevers(target, relation, report.SmallWood, report.TranscriptBuckets)
	report.FrontierClass = nizkProfileFrontierClass(report)
	report.IncumbentControl = nizkProfileIsIncumbentGeometry(report)
	return report
}

func nizkProfileApplyProjectedSerializerOmission(cand NIZKProfileSearchCandidate, buckets nizkProfileBucketDigest) nizkProfileBucketDigest {
	switch cand.SerializerOmission {
	case PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2:
		// The descriptor currently binds only already-reconstructible DECS
		// opening columns. VTargets and BarSets remain explicit until a
		// verifier reconstruction theorem is available.
	}
	return buckets
}

func nizkProfileTargetForCandidate(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate) NIZKProfileSearchTarget {
	out := target
	if cand.LaneOverride != "" {
		out.Lane = cand.LaneOverride
	}
	if cand.NIZKTargetBitsOverride > 0 {
		out.NIZKTargetBits = cand.NIZKTargetBitsOverride
	}
	if cand.RawQueryCapExponentOverride > 0 {
		out.QueryCapExponent = cand.RawQueryCapExponentOverride
	}
	if cand.HashFSBitsOverride > 0 {
		out.HashFSBitsRange = [2]int{cand.HashFSBitsOverride, cand.HashFSBitsOverride}
	}
	if cand.TapeBitsOverride > 0 {
		out.TapeBitsRange = [2]int{cand.TapeBitsOverride, cand.TapeBitsOverride}
	}
	if cand.SaltBitsOverride > 0 {
		out.SaltBitsRange = [2]int{cand.SaltBitsOverride, cand.SaltBitsOverride}
		out.BareSaltBits = cand.SaltBitsOverride
		out.EngineeringSaltBits = cand.SaltBitsOverride
	}
	if cand.TagElementsOverride > 0 {
		out.TagElementsRange = [2]int{cand.TagElementsOverride, cand.TagElementsOverride}
	}
	return out
}

func nizkProfileForcedBySecurity(target NIZKProfileSearchTarget) []string {
	queryScope := fmt.Sprintf("query semantics reserve a 2^%d random-oracle/adversary budget", target.QueryCapExponent)
	if target.SecurityMode == string(credential.SecurityModeQueryWorkFactor) {
		queryScope = "work-factor accounting leaves bounded random-oracle query caps unset"
	}
	return []string{
		fmt.Sprintf("core primitive family must support %.0f-bit lattice/PRF/key security", target.CoreBitsRequired),
		queryScope,
		fmt.Sprintf("hash/FS width lane is %d..%d bits", target.HashFSBitsRange[0], target.HashFSBitsRange[1]),
		fmt.Sprintf("DECS tape width lane is %d..%d bits", target.TapeBitsRange[0], target.TapeBitsRange[1]),
		fmt.Sprintf("salt width lane is %d..%d bits", target.SaltBitsRange[0], target.SaltBitsRange[1]),
		fmt.Sprintf("tag lane is %d..%d field elements", target.TagElementsRange[0], target.TagElementsRange[1]),
	}
}

func nizkProfileRawQueryCapLog2(target NIZKProfileSearchTarget) [4]float64 {
	raw := float64(target.QueryCapExponent)
	return [4]float64{raw, raw, raw, raw}
}

func nizkProfileROBudgetLogs(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate) credential.ROBudgetLogVector {
	raw := float64(target.QueryCapExponent)
	logs := credential.ROBudgetLogVectorFromCapBits([]float64{raw, raw, raw, raw, raw})
	if cand.ValidPrefixResearch {
		logs.ValidPrefixLog2 = cand.ValidPrefixCapExponent
	}
	return logs
}

func nizkProfileAlgebraicAccounting(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate) credential.ValidPrefixAlgebraicAccounting {
	return credential.SmallWoodValidPrefixAccounting(nizkProfileROBudgetLogs(target, cand), cand.ValidPrefixResearch)
}

func nizkProfileSmallWoodQueryCapLog2(target NIZKProfileSearchTarget, sw NIZKProfileSmallWoodReport) [4]float64 {
	if hasPositiveFloat64Array(sw.EffectiveQueryCapLog2) {
		return sw.EffectiveQueryCapLog2
	}
	return nizkProfileRawQueryCapLog2(target)
}

func nizkProfileValidPrefixCostReport(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, timings []PIOP.PhaseTiming) credential.ValidPrefixCostReport {
	spec, ok := credential.LookupIntGenISISSecurityProfile(target.SecurityProfile)
	if !ok {
		return credential.ValidPrefixCostReport{}
	}
	if cand.RawQueryCapExponentOverride > 0 {
		spec.ROQueryCapBits = []float64{float64(cand.RawQueryCapExponentOverride), float64(cand.RawQueryCapExponentOverride), float64(cand.RawQueryCapExponentOverride), float64(cand.RawQueryCapExponentOverride), float64(cand.RawQueryCapExponentOverride)}
		spec.ROQueryCaps = nil
	}
	return benchmarkValidPrefixCostReport(spec, timings, cand.ValidPrefixCapExponent, cand.ValidPrefixResearch)
}

func deriveNIZKProfileSmallWoodReport(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, base intGenISISTuning, pinnedLVCS bool, deriveEtaFloorOnly bool) NIZKProfileSmallWoodReport {
	return deriveNIZKProfileSmallWoodReportWithCaps(target, relation, base, pinnedLVCS, deriveEtaFloorOnly, nizkProfileRawQueryCapLog2(target), false)
}

func deriveNIZKProfileSmallWoodReportWithCaps(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, base intGenISISTuning, pinnedLVCS bool, deriveEtaFloorOnly bool, queryCapLog2 [4]float64, usesValidPrefix bool) NIZKProfileSmallWoodReport {
	lvcs := base.LVCSNCols
	if lvcs <= 0 {
		lvcs = base.NCols
	}
	if lvcs <= 0 {
		lvcs = 32
	}
	if !pinnedLVCS && relation.LogicalRows > 0 && relation.DQ > 0 {
		continuous := math.Sqrt(float64(base.Ell) * (float64(relation.LogicalRows*(base.NCols+base.Theta)) + float64(relation.DQ*base.Theta)) / float64(maxInt(base.Eta+base.Theta, 1)))
		if continuous > 1 {
			lvcs = int(math.Round(continuous))
		}
	}
	lvcs = maxInt(lvcs, base.NCols)
	etaFloor := nizkProfileEtaFloorWithCaps(target, relation, base, lvcs, queryCapLog2)
	aggregatePlan := nizkProfileGrindingPlan{}
	if target.FullGameTargetBits > 0 {
		aggregatePlan = nizkProfileOptimizeAggregateGrinding(target, relation, base, lvcs, queryCapLog2)
		if aggregatePlan.Eta > 0 {
			etaFloor = aggregatePlan.Eta
		}
	}
	eta := maxInt(base.Eta, etaFloor)
	if deriveEtaFloorOnly {
		eta = etaFloor
	}
	notes := []string{"eta is derived from the NIZK target and kept as a floor; no wide eta sweep"}
	if target.FullGameTargetBits > 0 {
		notes = append(notes, "grinding is optimized against the aggregate four-term error instead of assigning equal slack to each term")
	}
	if maxInt(base.Rho, 1) == 1 && maxInt(base.EllPrime, 1) == 1 {
		notes = append(notes, "rho=1 and ell_prime=1 are fixed for the small-field research lane")
	} else {
		notes = append(notes, "rho/ell_prime vary only as a fail-closed projection unless the measured SmallField protocol supports them")
	}
	out := NIZKProfileSmallWoodReport{
		LVCSNCols:                 lvcs,
		NLeaves:                   maxInt(base.NLeaves, 1),
		Eta:                       eta,
		EtaFloor:                  etaFloor,
		Theta:                     maxInt(base.Theta, 1),
		Rho:                       maxInt(base.Rho, 1),
		Ell:                       maxInt(base.Ell, 1),
		EllPrime:                  maxInt(base.EllPrime, 1),
		RawQueryCapLog2:           float64(target.QueryCapExponent),
		EffectiveQueryCapLog2:     queryCapLog2,
		UsesValidPrefixAccounting: usesValidPrefix,
		LVCSWindow: nizkProfileBoundedUniqueInts([]int{
			lvcs - 3, lvcs - 2, lvcs - 1, lvcs, lvcs + 1, lvcs + 2, lvcs + 3,
		}, maxInt(base.NCols, 1), maxInt(96, lvcs+3)),
		EtaWindow:   []int{eta},
		ThetaWindow: positiveWindow(maxInt(base.Theta, 1), 1),
		EllWindow:   positiveWindow(maxInt(base.Ell, 1), 1),
		Notes:       notes,
	}
	if target.FullGameTargetBits > 0 {
		if eta != aggregatePlan.Eta {
			aggregatePlan = nizkProfileOptimizeGrindingAtEta(target, relation, out, eta)
		}
		out.AggregateOptimized = aggregatePlan.Feasible
		out.ExpectedGrindingWork = aggregatePlan.ExpectedWork
		out.ExpectedGrindingWorkLog2 = aggregatePlan.ExpectedWorkLog2
		out.RequiredKappa = aggregatePlan.Kappa
	} else {
		out.RequiredKappa = nizkProfileRequiredKappa(target, relation, out)
	}
	for i := range out.RequiredKappa {
		out.Kappa[i] = out.RequiredKappa[i]
		if out.Kappa[i] > nizkProfileMaxSupportedGrinding {
			out.Kappa[i] = nizkProfileMaxSupportedGrinding
		}
	}
	return out
}

type nizkProfileGrindingPlan struct {
	Eta              int
	Kappa            [4]int
	AggregateBits    float64
	ExpectedWork     float64
	ExpectedWorkLog2 float64
	Feasible         bool
}

func nizkProfileEtaFloorWithCaps(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, base intGenISISTuning, lvcs int, queryCapLog2 [4]float64) int {
	ell := maxInt(base.Ell, 1)
	nleaves := maxInt(base.NLeaves, 1)
	ddecs := maxInt(lvcs, 1) + ell - 1
	perRoundTarget := target.NIZKTargetBits + nizkProfileDefaultEngineeringTargetMargin
	need := perRoundTarget + queryCapLog2[0] + credential.Log2Binom(uint64(nleaves), uint64(ddecs+2))
	return maxInt(1, int(math.Ceil(need/math.Log2(float64(credential.IntGenISISSharedModulusQ)))))
}

func nizkProfileRequiredKappa(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport) [4]int {
	if target.FullGameTargetBits > 0 {
		return nizkProfileOptimizeGrindingAtEta(target, relation, sw, sw.Eta).Kappa
	}
	raw := nizkProfileRawRoundBits(relation, sw)
	perRoundTarget := target.NIZKTargetBits + nizkProfileDefaultEngineeringTargetMargin
	queryCapLog2 := nizkProfileSmallWoodQueryCapLog2(target, sw)
	var out [4]int
	for i, bits := range raw {
		if bits < 0 || math.IsInf(bits, -1) || math.IsNaN(bits) {
			bits = 0
		}
		need := perRoundTarget + queryCapLog2[i] - bits
		if need > 0 {
			out[i] = int(math.Ceil(need))
		}
	}
	return out
}

func nizkProfileRawRoundBits(relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport) [4]float64 {
	q := float64(credential.IntGenISISSharedModulusQ)
	logQ := math.Log2(q)
	nleaves := maxInt(sw.NLeaves, 1)
	lvcs := maxInt(sw.LVCSNCols, 1)
	ell := maxInt(sw.Ell, 1)
	ddecs := lvcs + ell - 1
	dq := maxInt(relation.DQ, 1)
	var out [4]float64
	out[0] = float64(sw.Eta)*logQ - credential.Log2Binom(uint64(nleaves), uint64(ddecs+2))
	out[1] = float64(maxInt(sw.Theta*sw.Rho, 1)) * logQ
	out[2] = float64(maxInt(sw.Theta, 1))*logQ - math.Log2(float64(dq))
	out[3] = credential.Log2Binom(uint64(nleaves), uint64(ell)) - credential.Log2Binom(uint64(ddecs), uint64(ell))
	return out
}

func nizkProfileProjectedRoundBits(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport) [4]float64 {
	raw := nizkProfileRawRoundBits(relation, sw)
	queryCapLog2 := nizkProfileSmallWoodQueryCapLog2(target, sw)
	var out [4]float64
	for i, bits := range raw {
		if bits < 0 || math.IsNaN(bits) || math.IsInf(bits, -1) {
			bits = 0
		}
		out[i] = bits - queryCapLog2[i] + float64(sw.Kappa[i])
		if out[i] < 0 {
			out[i] = 0
		}
	}
	return out
}

func nizkProfileAggregateBits(roundBits [4]float64) float64 {
	logTerms := make([]float64, 0, len(roundBits))
	for _, bits := range roundBits {
		if bits <= 0 {
			return 0
		}
		logTerms = append(logTerms, -bits)
	}
	return credential.BitsFromLog2Prob(credential.Log2SumExp(logTerms))
}

func nizkProfileProjectedBuckets(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport) nizkProfileBucketDigest {
	fq := int(math.Ceil(math.Log2(float64(credential.IntGenISISSharedModulusQ))))
	lvcs := maxInt(sw.LVCSNCols, 1)
	ell := maxInt(sw.Ell, 1)
	theta := maxInt(sw.Theta, 1)
	dq := maxInt(relation.DQ, 1)
	rows := maxInt(relation.LogicalRows, 1)
	ddecs := lvcs + ell - 1
	nrows := ceilDivInt(rows, lvcs)*(32+theta) + ceilDivInt(dq, lvcs)*theta
	hashBytes := maxInt(target.HashFSBitsRange[0]/8, 1)
	tapeBytes := maxInt(target.TapeBitsRange[0]/8, 1)
	return nizkProfileBucketDigest{
		Q:            ceilDivInt(fq*theta*dq, 8),
		R:            ceilDivInt(fq*sw.Eta*maxInt(ddecs+1-ell, 0), 8),
		Pdecs:        ceilDivInt(fq*sw.Eta*(ddecs+1), 8),
		Auth:         hashBytes * ell * maxInt(int(math.Ceil(math.Log2(float64(maxInt(sw.NLeaves, 2))))), 1),
		Tapes:        tapeBytes * ell,
		SigShortness: 0,
		VTargets:     ceilDivInt(fq*theta*(dq+rows+lvcs-2), 8),
		BarSets:      ceilDivInt(fq*ell*nrows, 8),
	}
}

func nizkProfileFormalBackendDiagnostics(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport, paperBytes int) *NIZKProfileFormalBackendDiagnostics {
	if !cand.FormalBackendCandidate {
		return nil
	}
	ringDegree := nizkProfileCandidateRingDegree(cand)
	lvcs := maxInt(sw.LVCSNCols, 1)
	ell := maxInt(sw.Ell, 1)
	dq := maxInt(relation.DQ, 1)
	rows := maxInt(relation.LogicalRows, 1)
	baselineLVCS := cand.FormalBaselineLVCSNCols
	if baselineLVCS <= 0 {
		baselineLVCS = minInt(lvcs, maxInt(ringDegree, 1))
	}
	baselineLVCS = maxInt(baselineLVCS, maxInt(cand.Showing.NCols, 1))
	baselineBase := cand.Showing
	baselineBase.LVCSNCols = baselineLVCS
	baselineSW := deriveNIZKProfileSmallWoodReportWithCaps(target, relation, baselineBase, true, cand.DeriveEtaFloorOnly, sw.EffectiveQueryCapLog2, sw.UsesValidPrefixAccounting)
	baselineBuckets := nizkProfileProjectedBuckets(target, relation, baselineSW)
	baselineBytes := baselineBuckets.Q + baselineBuckets.R + baselineBuckets.Pdecs + baselineBuckets.Auth + baselineBuckets.Tapes + baselineBuckets.VTargets + baselineBuckets.BarSets + baselineBuckets.SigShortness
	measurable, blocker := nizkProfileFormalCandidateMeasurable(cand, sw)
	out := &NIZKProfileFormalBackendDiagnostics{
		RingDegree:                         ringDegree,
		FormalBackendCandidate:             true,
		LVCSAboveRing:                      lvcs > ringDegree,
		DQAboveRing:                        dq > ringDegree,
		DQOverride:                         cand.Showing.DQOverride,
		Measurable:                         measurable,
		MeasurementBlocker:                 blocker,
		BaselineLVCSNCols:                  baselineLVCS,
		BaselineDDECS:                      baselineLVCS + ell - 1,
		DDECS:                              lvcs + ell - 1,
		BaselineRowBlocks:                  ceilDivInt(rows, baselineLVCS),
		RowBlocks:                          ceilDivInt(rows, lvcs),
		BaselineDQBlocks:                   ceilDivInt(dq, baselineLVCS),
		DQBlocks:                           ceilDivInt(dq, lvcs),
		BaselinePaperTranscriptBytes:       baselineBytes,
		ProjectedPaperTranscriptDeltaBytes: paperBytes - baselineBytes,
	}
	out.RowBlockDelta = out.RowBlocks - out.BaselineRowBlocks
	out.DQBlockDelta = out.DQBlocks - out.BaselineDQBlocks
	switch {
	case out.ProjectedPaperTranscriptDeltaBytes < 0:
		out.Tradeoff = "formal width reduces projected transcript; measure this candidate before promotion"
	case out.RowBlockDelta == 0 && out.DQBlockDelta == 0:
		out.Tradeoff = "formal width gives no row/Q block reduction; larger dDECS is pure overhead"
	default:
		out.Tradeoff = "row/Q block savings do not offset larger dDECS in projection"
	}
	return out
}

func nizkProfileFormalCandidateMeasurable(cand NIZKProfileSearchCandidate, sw NIZKProfileSmallWoodReport) (bool, string) {
	if cand.FormalProjectionOnlyReason != "" {
		return false, cand.FormalProjectionOnlyReason
	}
	if sw.Rho != 1 || sw.EllPrime != 1 {
		return false, "SmallField 2025 measured protocol requires rho=1 and ell_prime=1"
	}
	q := int(credential.IntGenISISSharedModulusQ)
	if sw.NLeaves <= 0 {
		return false, "missing NLeaves for measured benchmark"
	}
	if sw.NLeaves >= q {
		return false, fmt.Sprintf("nLeaves=%d requires at least that many distinct explicit-domain field points, but current q=%d", sw.NLeaves, q)
	}
	if sw.LVCSNCols+sw.Ell > sw.NLeaves {
		return false, fmt.Sprintf("lvcs_ncols+ell=%d exceeds nLeaves=%d", sw.LVCSNCols+sw.Ell, sw.NLeaves)
	}
	return true, ""
}

func nizkProfileCandidateRingDegree(cand NIZKProfileSearchCandidate) int {
	if preset, ok := credential.LookupIntGenISISPreset(cand.ControlPreset); ok {
		if profile, ok := credential.LookupIntGenISISProfile(preset.Profile); ok && profile.N > 0 {
			return profile.N
		}
	}
	return credential.Ternary1024IntGenISISProfile().N
}

func bq64ReductionReport(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, report NIZKProfileCandidateReport, measured *PIOP.PaperTranscriptAudit) *BQ64ReductionReport {
	if !bq64ReductionCandidateApplies(target, cand) {
		return nil
	}
	width := bq64ReductionWidthModel(target)
	serializer := bq64ReductionSerializerModel(cand)
	baseline := bq64ReductionBaselineBytes(target.SecurityProfile)
	out := &BQ64ReductionReport{
		Candidate:            cand.Name,
		Profile:              target.SecurityProfile,
		Lane:                 cand.ReductionLane,
		Model:                cand.ReductionModel,
		BaselineBytes:        baseline,
		TranscriptDeltaBytes: report.PaperTranscriptBytes - baseline,
		Width:                width,
		Serializer:           serializer,
	}
	if measured != nil {
		audit := *measured
		out.MeasuredAudit = &audit
	}
	out.AcceptanceReasons = bq64ReductionAcceptanceReasons(report, out)
	if len(out.AcceptanceReasons) == 0 {
		out.AcceptanceStatus = "accepted_research_reduction"
	} else {
		out.AcceptanceStatus = "blocked"
	}
	return out
}

func bq64ReductionCandidateApplies(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate) bool {
	return target.SecurityProfile == "BQ64-96" && cand.Family == "bq64_96_reduction"
}

func bq64ReductionBaselineBytes(profile string) int {
	if profile == "BQ64-96" {
		return bq6496ReductionBaselineBytes
	}
	return 0
}

func bq64ReductionTargetBits(profile string) float64 {
	if profile == "BQ64-96" {
		return 164.25
	}
	return math.Inf(1)
}

func bq64ReductionWidthModel(target NIZKProfileSearchTarget) BQ64ReductionWidthModel {
	width := BQ64ReductionWidthModel{
		HashFSBits:  target.HashFSBitsRange[0],
		TapeBits:    target.TapeBitsRange[0],
		SaltBits:    target.SaltBitsRange[0],
		TagElements: target.TagElementsRange[0],
		Status:      "pass",
	}
	if target.SecurityProfile == "BQ64-96" {
		width.Classification = "bare"
		width.Reason = "BQ64-96 width candidate keeps hash/FS>=232, tape>=160, salt>=224, and tag lane>=12"
		if width.SaltBits >= 256 {
			width.Classification = "engineering"
		}
		if width.HashFSBits < 232 {
			width.Status = "fail_closed"
			width.Reason = "BQ64-96 hash/FS width below 232 is outside the PDF-aligned 2^64 query lane"
		}
		if width.TapeBits < 160 {
			width.Status = "fail_closed"
			width.Reason = "BQ64-96 tape width below 160 would lose the 2^64 residual tape-guessing margin"
		}
		if width.SaltBits < 224 {
			width.Status = "fail_closed"
			width.Reason = "BQ64-96 salt width below 224 is outside the bare collision lane"
		}
		if width.TagElements < 12 {
			width.Status = "fail_closed"
			width.Reason = "BQ64-96 tag lane below 12 is outside the profile target"
		}
	} else {
		width.Status = "fail_closed"
		width.Reason = "not the BQ64-96 reduction profile"
	}
	return width
}

func bq64ReductionSerializerModel(cand NIZKProfileSearchCandidate) BQ64ReductionSerializerModel {
	model := BQ64ReductionSerializerModel{
		ReconstructionAvailable: cand.ReconstructionAvailable,
		OmissionMapFSBound:      cand.OmissionMapFSBound,
		Status:                  "not_applicable",
	}
	switch cand.SerializerOmission {
	case "":
		model.Status = "audit_only"
		model.Reason = "candidate does not omit serializer payloads"
	case "pdecs":
		model.OmitPdecs = true
		model.Status = "serializer_safe_existing_path"
		model.Reason = "existing smallfield2025 opening compression binds omitted P/M columns through metadata and payload digests"
	case "vtargets":
		model.OmitVTargets = true
		model.Status = "blocked"
		model.Reason = "VTargets omission needs verifier byte-for-byte reconstruction before DECS verification"
	case "barsets":
		model.OmitBarSets = true
		model.Status = "blocked"
		model.Reason = "BarSets omission needs verifier byte-for-byte reconstruction before DECS verification"
	case PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2:
		model.OmitPdecs = true
		model.Status = "serializer_safe_existing_path"
		model.Reason = "descriptor binds the existing smallfield2025 omitted-column Pdecs reconstruction; VTargets and BarSets remain explicit"
	default:
		model.Status = "blocked"
		model.Reason = "unknown serializer omission model"
	}
	if cand.SerializerOmission != "" && (!cand.ReconstructionAvailable || !cand.OmissionMapFSBound) {
		model.Status = "blocked"
		if model.Reason == "" {
			model.Reason = "serializer omission is not reconstructible and Fiat-Shamir-bound"
		}
	}
	return model
}

func bq64ReductionAcceptanceReasons(report NIZKProfileCandidateReport, reduction *BQ64ReductionReport) []string {
	var reasons []string
	targetBits := bq64ReductionTargetBits(report.SecurityProfile)
	baselineBytes := bq64ReductionBaselineBytes(report.SecurityProfile)
	if report.SecurityProfile != "BQ64-96" {
		reasons = append(reasons, "not the BQ64-96 reduction profile")
	}
	if report.ShowingAlgebraicBits+1e-9 < targetBits {
		reasons = append(reasons, fmt.Sprintf("showing algebraic bits %.2f < %.2f", report.ShowingAlgebraicBits, targetBits))
	}
	for _, kappa := range report.SmallWood.RequiredKappa {
		if kappa > nizkProfileMaxSupportedGrinding {
			reasons = append(reasons, fmt.Sprintf("required grinding %d > supported cap %d", kappa, nizkProfileMaxSupportedGrinding))
			break
		}
	}
	if reduction.Width.Status != "pass" {
		reasons = append(reasons, reduction.Width.Reason)
	}
	if reduction.Serializer.Status == "blocked" {
		reasons = append(reasons, reduction.Serializer.Reason)
	}
	if report.RequiresTheoremWork {
		reasons = append(reasons, "requires split/theorem accounting before theorem-valid ranking")
	}
	if baselineBytes > 0 && report.PaperTranscriptBytes >= baselineBytes {
		reasons = append(reasons, fmt.Sprintf("paper transcript bytes %d >= measured baseline %d", report.PaperTranscriptBytes, baselineBytes))
	}
	if report.TargetStatus == credential.SecurityProfileRequiresNewPrimitives {
		reasons = append(reasons, "system profile remains requires_new_primitives even when NIZK terms pass")
	}
	return nizkProfileUniqueStrings(reasons)
}

func nizkProfileTranscriptDrivers(buckets nizkProfileBucketDigest, total int) []NIZKProfileTranscriptDriver {
	if total <= 0 {
		return nil
	}
	drivers := []NIZKProfileTranscriptDriver{
		{Component: "vtargets", Bytes: buckets.VTargets, Driver: "theta times dQ, logical rows, and LVCS width"},
		{Component: "pdecs", Bytes: buckets.Pdecs, Driver: "eta times DECS degree columns"},
		{Component: "r", Bytes: buckets.R, Driver: "eta times LVCS committed width"},
		{Component: "q", Bytes: buckets.Q, Driver: "theta times dQ"},
		{Component: "barsets", Bytes: buckets.BarSets, Driver: "ell times committed SmallWood row layers"},
		{Component: "auth", Bytes: buckets.Auth, Driver: "hash width times ell times Merkle depth"},
		{Component: "tapes", Bytes: buckets.Tapes, Driver: "tape width times ell"},
		{Component: "sig_shortness", Bytes: buckets.SigShortness, Driver: "standalone hidden shortness proof payload"},
	}
	out := drivers[:0]
	for _, driver := range drivers {
		if driver.Bytes <= 0 {
			continue
		}
		driver.Percent = 100 * float64(driver.Bytes) / float64(total)
		out = append(out, driver)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Component < out[j].Component
	})
	return out
}

func nizkProfileOptimizationLevers(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport, buckets nizkProfileBucketDigest) []NIZKProfileOptimizationLever {
	fq := int(math.Ceil(math.Log2(float64(credential.IntGenISISSharedModulusQ))))
	theta := maxInt(sw.Theta, 1)
	ell := maxInt(sw.Ell, 1)
	lvcs := maxInt(sw.LVCSNCols, 1)
	rows := maxInt(relation.LogicalRows, 1)
	dq := maxInt(relation.DQ, 1)
	hashBytes := maxInt(target.HashFSBitsRange[0]/8, 1)
	rowBlockRows := maxInt(32+theta, 1)
	dqBlockRows := theta
	perRowOrDQ := ceilDivInt(fq*theta, 8)
	per64RowsOrDQ := ceilDivInt(fq*theta*64, 8)
	perRowBlock := ceilDivInt(fq*ell*rowBlockRows, 8)
	perDQBlock := ceilDivInt(fq*ell*dqBlockRows, 8)
	perMerkleLevel := hashBytes * ell
	perEta := ceilDivInt(fq*(2*lvcs+ell), 8)
	levers := []NIZKProfileOptimizationLever{
		{
			Name:                  "compiler_backed_safe_relation_measurement",
			Category:              "measurement",
			EstimatedSavingsBytes: per64RowsOrDQ,
			SecurityConstraint:    "use only the current safe relation unless a new theorem/accounting path is added",
			ImplementationWork:    "run selected candidates through benchmark-intgenisis-e2e and replace projected rows, dQ, and buckets with compiled proof metadata",
			Notes:                 fmt.Sprintf("each real removed row or dQ unit saves about %d bytes across Q/VTargets at theta=%d; a 64-unit improvement saves about %d bytes", perRowOrDQ, theta, per64RowsOrDQ),
		},
		{
			Name:                  "lvcs_rowblock_breakpoint_sweep",
			Category:              "lvcs_layout",
			EstimatedSavingsBytes: perRowBlock,
			SecurityConstraint:    "changing LVCSNCols changes dDECS, eta floor, and eps4; keep the PDF relation-before-SmallWood order",
			ImplementationWork:    "sweep LVCSNCols around ceil(row/lvcs) and ceil(dQ/lvcs) breakpoints after relation compilation",
			Notes:                 fmt.Sprintf("rows=%d dQ=%d lvcs=%d; one logical-row block saves about %d bytes, one dQ block saves about %d bytes in barsets", rows, dq, lvcs, perRowBlock, perDQBlock),
		},
		{
			Name:                  "auth_multiproof_path_audit",
			Category:              "decs_domain",
			EstimatedSavingsBytes: perMerkleLevel,
			SecurityConstraint:    "NLeaves and ell drive eps4 and authentication; lowering them requires a fresh eps4 calculation",
			ImplementationWork:    "measure exact auth paths, omitted openings, and Merkle depth for finalists before changing NLeaves or ell",
			Notes:                 fmt.Sprintf("one Merkle level costs about %d bytes at hash=%dB ell=%d", perMerkleLevel, hashBytes, ell),
		},
		{
			Name:                  "pdecs_vtargets_barsets_serializer_dedup",
			Category:              "serializer_layout",
			EstimatedSavingsBytes: maxInt(perRowBlock, perDQBlock),
			SecurityConstraint:    "may remove duplicated encodings only when verifier reconstruction and challenge binding are unchanged",
			ImplementationWork:    "audit Pdecs, VTargets, BarSets, row openings, and omitted-entry accounting in the measured proof report",
			Notes:                 fmt.Sprintf("pdecs=%d vtargets=%d barsets=%d are the active byte pressure; target duplicated payloads before changing theorem parameters", buckets.Pdecs, buckets.VTargets, buckets.BarSets),
		},
		{
			Name:                  "avoid_eta_theta_growth",
			Category:              "smallwood_accounting",
			EstimatedSavingsBytes: perEta,
			SecurityConstraint:    "eta and theta are security terms, not serializer knobs; one eta costs about log2(q) bits of eps1 margin",
			ImplementationWork:    "use unequal error allocation and bounded grinding before increasing theta or eta",
			Notes:                 fmt.Sprintf("one eta repetition costs about %d bytes across R/Pdecs; current theta=%d eta=%d", perEta, theta, sw.Eta),
		},
	}
	return levers
}

func nizkProfileFrontierClass(report NIZKProfileCandidateReport) string {
	if report.MeasurementStatus == "projection_failed" {
		return nizkProfileFrontierRejected
	}
	if report.RequiresSplitTheorem {
		return nizkProfileFrontierRequiresSplitTheorem
	}
	if report.BQ64Reduction != nil && report.BQ64Reduction.Serializer.Status == "blocked" {
		return nizkProfileFrontierSerializerModelBlocked
	}
	for _, kappa := range report.SmallWood.RequiredKappa {
		if kappa > nizkProfileMaxSupportedGrinding {
			return nizkProfileFrontierHighKResearch
		}
	}
	if report.UsesValidPrefixAccounting {
		if nizkProfileMeetsSecurityTarget(report) {
			return nizkProfileFrontierValidPrefixResearch
		}
		return nizkProfileFrontierRequiresTheoremWork
	}
	if report.RequiresTheoremWork {
		return nizkProfileFrontierRequiresTheoremWork
	}
	if nizkProfileMeetsSecurityTarget(report) {
		return nizkProfileFrontierCandidate
	}
	if report.TargetStatus == credential.SecurityProfileRequiresNewPrimitives {
		return nizkProfileFrontierRequiresNewPrimitives
	}
	return nizkProfileFrontierRejected
}

func nizkProfileMeetsSecurityTarget(report NIZKProfileCandidateReport) bool {
	if report.IssuanceAlgebraicBits+1e-9 < report.NIZKTargetBits ||
		report.ShowingAlgebraicBits+1e-9 < report.NIZKTargetBits {
		return false
	}
	return report.FullGameTargetBits <= 0 || report.FullGameBits+1e-9 >= report.FullGameTargetBits
}

func nizkProfileReports(maxPerProfile int, filter string) []NIZKProfileCandidateReport {
	targets := nizkProfileSearchTargets()
	candidates := nizkProfileSearchCandidatesForFilter(filter)
	filter = strings.TrimSpace(filter)
	validPrefixEnabled := nizkProfileEnvBool("SPRUCE_VALID_PREFIX_SWEEP") || strings.Contains(strings.ToLower(filter), "vp") || strings.Contains(strings.ToLower(filter), "valid-prefix") || strings.Contains(strings.ToLower(filter), "valid_prefix")
	out := make([]NIZKProfileCandidateReport, 0, len(targets)*len(candidates))
	for _, target := range targets {
		perTarget := make([]NIZKProfileCandidateReport, 0, len(candidates))
		for _, cand := range candidates {
			if cand.TargetProfile != "" && cand.TargetProfile != target.SecurityProfile {
				continue
			}
			if cand.Family == "valid_prefix_trail" && !validPrefixEnabled {
				continue
			}
			if cand.Family == "bq64_96_reduction" {
				if target.SecurityProfile != "BQ64-96" {
					continue
				}
				if filter == "" || (!strings.Contains("BQ64-96", filter) && !strings.Contains(cand.Name, filter) && !strings.Contains(cand.RelationEncoding, filter)) {
					continue
				}
			}
			report := nizkProfileCandidateReport(target, cand)
			if filter != "" && !strings.Contains(report.SecurityProfile, filter) && !strings.Contains(report.Candidate, filter) && !strings.Contains(report.RelationEncoding, filter) {
				continue
			}
			perTarget = append(perTarget, report)
		}
		sort.SliceStable(perTarget, func(i, j int) bool {
			return nizkProfileReportLess(perTarget[i], perTarget[j])
		})
		if maxPerProfile > 0 && len(perTarget) > maxPerProfile {
			perTarget = perTarget[:maxPerProfile]
		}
		out = append(out, perTarget...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return nizkProfileReportLess(out[i], out[j])
	})
	return out
}

func nizkProfileReportForCandidate(profile, candidateName string) (NIZKProfileCandidateReport, bool) {
	var target NIZKProfileSearchTarget
	for _, candidateTarget := range nizkProfileSearchTargets() {
		if candidateTarget.SecurityProfile == profile {
			target = candidateTarget
			break
		}
	}
	if target.SecurityProfile == "" {
		return NIZKProfileCandidateReport{}, false
	}
	for _, candidate := range nizkProfileSearchCandidatesForFilter(candidateName) {
		if candidate.Name != candidateName {
			continue
		}
		if candidate.TargetProfile != "" && candidate.TargetProfile != profile {
			return NIZKProfileCandidateReport{}, false
		}
		return nizkProfileCandidateReport(target, candidate), true
	}
	return NIZKProfileCandidateReport{}, false
}

func nizkProfileReportsForCandidateSet(candidates []NIZKProfileSearchCandidate) []NIZKProfileCandidateReport {
	targets := make(map[string]NIZKProfileSearchTarget)
	for _, target := range nizkProfileSearchTargets() {
		targets[target.SecurityProfile] = target
	}
	reports := make([]NIZKProfileCandidateReport, 0, len(candidates))
	for _, candidate := range candidates {
		target, ok := targets[candidate.TargetProfile]
		if !ok {
			continue
		}
		reports = append(reports, nizkProfileCandidateReport(target, candidate))
	}
	sort.SliceStable(reports, func(i, j int) bool {
		return nizkProfileReportLess(reports[i], reports[j])
	})
	return reports
}

func nizkProfileShouldMeasureReport(report NIZKProfileCandidateReport) bool {
	if report.FormalBackendCandidate {
		return report.FormalBackendDiagnostics != nil &&
			report.FormalBackendDiagnostics.Measurable &&
			report.FormalBackendDiagnostics.ProjectedPaperTranscriptDeltaBytes < 0 &&
			(report.FrontierClass == nizkProfileFrontierCandidate ||
				report.FrontierClass == nizkProfileFrontierValidPrefixResearch ||
				report.FrontierClass == nizkProfileFrontierHighKResearch)
	}
	switch report.FrontierClass {
	case nizkProfileFrontierCandidate, nizkProfileFrontierValidPrefixResearch, nizkProfileFrontierHighKResearch:
		return true
	default:
		return false
	}
}

func nizkProfileReportMeasurable(report NIZKProfileCandidateReport) (bool, string) {
	if report.FormalBackendDiagnostics != nil && !report.FormalBackendDiagnostics.Measurable {
		return false, report.FormalBackendDiagnostics.MeasurementBlocker
	}
	q := int(credential.IntGenISISSharedModulusQ)
	if report.SmallWood.NLeaves <= 0 {
		return false, "missing NLeaves for measured benchmark"
	}
	if report.SmallWood.NLeaves >= q {
		return false, fmt.Sprintf("nLeaves=%d requires at least that many distinct explicit-domain field points, but current q=%d; keep as projection or use a larger/extension-domain primitive lane", report.SmallWood.NLeaves, q)
	}
	return true, ""
}

func nizkProfileChdirRepoRoot(t *testing.T) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if dir == wd {
				return
			}
			if err := os.Chdir(dir); err != nil {
				t.Fatalf("chdir repo root %s: %v", dir, err)
			}
			t.Cleanup(func() {
				_ = os.Chdir(wd)
			})
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", wd)
		}
		dir = parent
	}
}

func nizkProfileBenchmarkConfig(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, report NIZKProfileCandidateReport, root string, idx int) (benchmarkIntGenISISE2EConfig, error) {
	controlPreset := cand.ControlPreset
	if controlPreset == "" {
		controlPreset = credential.IntGenISISPresetN1024BQ32_96
	}
	preset, err := credential.MustLookupIntGenISISPreset(controlPreset)
	if err != nil {
		return benchmarkIntGenISISE2EConfig{}, err
	}
	showing := cand.Showing
	showing.LVCSNCols = report.SmallWood.LVCSNCols
	showing.NLeaves = report.SmallWood.NLeaves
	showing.Eta = report.SmallWood.Eta
	showing.Theta = report.SmallWood.Theta
	showing.Rho = report.SmallWood.Rho
	showing.Ell = report.SmallWood.Ell
	showing.EllPrime = report.SmallWood.EllPrime
	showing.Kappa = report.SmallWood.Kappa
	showing = nizkProfileApplyTargetWidths(target, showing)
	showing = nizkProfileApplyTargetQueryCaps(target, showing)
	prfProfile := preset.PRFProfile
	prfParamsPath := preset.PRFParamsPath
	prfParamsDigest := preset.PRFParamsDigest
	if target.FullGameTargetBits > 0 {
		prfProfile = credential.IntGenISISPRFProfileTag10
		prfParamsPath = credential.IntGenISISPRFParamsTag10
		var ok bool
		prfParamsDigest, ok = credential.IntGenISISPRFProfileParamsDigest(prfProfile)
		if !ok {
			return benchmarkIntGenISISE2EConfig{}, fmt.Errorf("missing digest for PRF profile %s", prfProfile)
		}
		showing.PRFProfile = prfProfile
		showing.PRFParamsPath = prfParamsPath
	}
	issuance := nizkProfileIssuanceFromShowing(showing)
	name := fmt.Sprintf("%03d-%s-%s", idx, nizkProfileSanitizeLabel(target.SecurityProfile), nizkProfileSanitizeLabel(cand.Name))
	maxNLeaves := maxInt(preset.MaxNLeaves, maxInt(issuance.NLeaves, showing.NLeaves))
	cfg := benchmarkIntGenISISE2EConfig{
		ArtifactDir:         filepath.Join(root, name),
		PresetName:          fmt.Sprintf("%s:%s:%s", preset.Name, target.SecurityProfile, cand.Name),
		Profile:             preset.Profile,
		SecurityProfile:     target.SecurityProfile,
		SecurityMode:        target.SecurityMode,
		CoreBitsRequired:    target.CoreBitsRequired,
		CompleteSystemClaim: false,
		PRFProfile:          prfProfile,
		PRFParamsPath:       prfParamsPath,
		PRFParamsDigest:     prfParamsDigest,
		JSONOut:             filepath.Join(root, name+".json"),
		Force:               true,
		Issuance:            issuance,
		Showing:             showing,
		KeygenTrials:        10000,
		KeygenAttempts:      defaultNTRUKeygenAttempts,
		NTRUBeta:            preset.NTRUBeta,
		MaxTrials:           2048,
		MaxNLeaves:          maxNLeaves,
	}
	if preset.SecurityProfile == target.SecurityProfile {
		cfg.ThreatModel = preset.ThreatModel
	} else if target.FullGameTargetBits > 0 {
		cfg.ThreatModel = nizkProfileScopedR128ThreatModel(target)
	}
	return cfg, nil
}

func nizkProfileApplyTargetWidths(target NIZKProfileSearchTarget, tuning intGenISISTuning) intGenISISTuning {
	tuning.DECSCollisionBits = target.HashFSBitsRange[0]
	tuning.DECSHashBits = target.HashFSBitsRange[0]
	tuning.DECSTapeBits = target.TapeBitsRange[0]
	tuning.FSCollisionBits = target.HashFSBitsRange[0]
	tuning.SaltBits = target.SaltBitsRange[0]
	return tuning
}

func nizkProfileApplyTargetQueryCaps(target NIZKProfileSearchTarget, tuning intGenISISTuning) intGenISISTuning {
	tuning.ROQueryCaps = [5]int{}
	tuning.ROQueryCapsSet = false
	if target.SecurityMode == string(credential.SecurityModeQueryWorkFactor) {
		tuning.ROQueryCapBits = [5]float64{}
		tuning.ROQueryCapBitsSet = false
		return tuning
	}
	raw := float64(target.QueryCapExponent)
	tuning.ROQueryCapBits = [5]float64{raw, raw, raw, raw, raw}
	tuning.ROQueryCapBitsSet = true
	return tuning
}

func nizkProfileReportWithMeasuredBenchmark(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, report NIZKProfileCandidateReport, bench benchmarkIntGenISISE2EReport, jsonOut string) NIZKProfileCandidateReport {
	out := report
	relation := bench.Showing.RelationCandidate
	if relation.LogicalRows <= 0 || relation.DQ <= 0 {
		relation = report.Relation
	}
	out.CompilerBacked = true
	out.MeasurementStatus = "measured"
	out.MeasurementSource = "benchmark_intgenisis_e2e"
	out.MeasurementError = ""
	out.MeasuredArtifactDir = bench.ArtifactDir
	out.MeasuredJSON = jsonOut
	out.Relation = relation
	out.SmallWood.LVCSNCols = firstPositiveInt(bench.Showing.LVCSNCols, out.SmallWood.LVCSNCols)
	out.SmallWood.NLeaves = firstPositiveInt(bench.Showing.NLeaves, out.SmallWood.NLeaves)
	out.SmallWood.Eta = firstPositiveInt(bench.Showing.Eta, out.SmallWood.Eta)
	out.SmallWood.Theta = firstPositiveInt(bench.Showing.Theta, out.SmallWood.Theta)
	out.SmallWood.Ell = firstPositiveInt(bench.Showing.Ell, out.SmallWood.Ell)
	out.SmallWood.Rho = firstPositiveInt(bench.Showing.Rho, out.SmallWood.Rho)
	out.SmallWood.EllPrime = firstPositiveInt(bench.Showing.EllPrime, out.SmallWood.EllPrime)
	out.SmallWood.RequiredKappa = nizkProfileRequiredKappa(target, relation, out.SmallWood)
	actualKappa := bench.Options.Showing.Kappa
	if actualKappa == [4]int{} && report.SmallWood.Kappa != [4]int{} {
		actualKappa = report.SmallWood.Kappa
	}
	out.SmallWood.Kappa = actualKappa
	out.SmallWood.ExpectedGrindingWork = nizkProfileExpectedGrindingWork(out.SmallWood.Kappa)
	out.SmallWood.ExpectedGrindingWorkLog2 = math.Log2(out.SmallWood.ExpectedGrindingWork)
	out.ExpectedGrindingWork = out.SmallWood.ExpectedGrindingWork
	out.ExpectedGrindingWorkLog2 = out.SmallWood.ExpectedGrindingWorkLog2
	if out.SmallWood.ExpectedGrindingWork > 0 {
		out.SmallWood.AggregateOptimized = out.SmallWood.Kappa == out.SmallWood.RequiredKappa
	}
	out.AlgebraicRoundBits = bench.Showing.AlgebraicBits
	out.IssuanceAlgebraicBits = bench.Issuance.AlgebraicTotalBits
	out.ShowingAlgebraicBits = bench.Showing.AlgebraicTotalBits
	out.FullGameBits = bench.FullGame.GlobalCollisionFullGameBits
	out.GlobalCollisionBits = bench.FullGame.GlobalCollisionBits
	out.RelationSafety = nizkProfileRelationSafety(cand, relation, out.SmallWood.Ell)
	out.TranscriptBuckets = nizkProfileBucketDigest{
		Q:            bench.Showing.QBytes,
		R:            bench.Showing.RBytes,
		Pdecs:        bench.Showing.PdecsBytes,
		Mdecs:        bench.Showing.MdecsBytes,
		Auth:         bench.Showing.AuthBytes,
		Tapes:        bench.Showing.TapesBytes,
		SigShortness: bench.Showing.SigShortnessBytes,
		VTargets:     bench.Showing.VTargetsBytes,
		BarSets:      bench.Showing.BarSetsBytes,
	}
	out.PaperTranscriptBytes = bench.Showing.PaperTranscriptBytes
	out.CombinedPaperBytes = bench.Issuance.PaperTranscriptBytes + bench.Showing.PaperTranscriptBytes
	out.FormalBackendCandidate = cand.FormalBackendCandidate
	out.FormalBackendDiagnostics = nizkProfileFormalBackendDiagnostics(target, cand, relation, out.SmallWood, out.PaperTranscriptBytes)
	out.LVCSAboveRing = out.FormalBackendDiagnostics != nil && out.FormalBackendDiagnostics.LVCSAboveRing
	issuance := nizkProfileMetricDigestFromMetrics(bench.Issuance)
	showing := nizkProfileMetricDigestFromMetrics(bench.Showing)
	out.MeasuredIssuance = &issuance
	out.MeasuredShowing = &showing
	out.ValidPrefixCost = nizkProfileValidPrefixCostReport(target, cand, bench.Showing.PhaseTimings)
	out.BQ64Reduction = bq64ReductionReport(target, cand, out, &bench.Showing.TranscriptAudit)
	out.TranscriptDrivers = nizkProfileTranscriptDrivers(out.TranscriptBuckets, out.PaperTranscriptBytes)
	out.OptimizationLevers = nizkProfileOptimizationLevers(target, relation, out.SmallWood, out.TranscriptBuckets)
	out.FrontierClass = nizkProfileFrontierClass(out)
	out.Notes = append(append([]string(nil), report.Notes...), fmt.Sprintf("measured with current safe relation and target transcript widths for %s", target.SecurityProfile))
	_ = cand
	return out
}

func firstPositiveInt(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

func nizkProfileReportLess(a, b NIZKProfileCandidateReport) bool {
	if a.SecurityProfile != b.SecurityProfile {
		return nizkProfileTargetOrder(a.SecurityProfile) < nizkProfileTargetOrder(b.SecurityProfile)
	}
	if nizkProfileIsBQ64ReductionFamily(a.Family) && nizkProfileIsBQ64ReductionFamily(b.Family) && a.SecurityProfile == b.SecurityProfile {
		if a.Family != b.Family {
			if nizkProfileIsBQ64ReductionFamily(a.Family) != nizkProfileIsBQ64ReductionFamily(b.Family) {
				return nizkProfileIsBQ64ReductionFamily(a.Family)
			}
			return nizkProfileFamilyRank(a.Family) < nizkProfileFamilyRank(b.Family)
		}
		if a.Family == "bq64_96_reduction" {
			if bq64ReductionCandidateRank(a.Candidate) != bq64ReductionCandidateRank(b.Candidate) {
				return bq64ReductionCandidateRank(a.Candidate) < bq64ReductionCandidateRank(b.Candidate)
			}
			return a.Candidate < b.Candidate
		}
	}
	if a.FrontierClass != b.FrontierClass {
		return nizkProfileFrontierRank(a.FrontierClass) < nizkProfileFrontierRank(b.FrontierClass)
	}
	if a.FrontierClass == nizkProfileFrontierCandidate {
		aHasCombinedProjection := a.CombinedPaperBytes > 0
		bHasCombinedProjection := b.CombinedPaperBytes > 0
		if aHasCombinedProjection != bHasCombinedProjection {
			return aHasCombinedProjection
		}
		if aHasCombinedProjection && a.CombinedPaperBytes != b.CombinedPaperBytes {
			return a.CombinedPaperBytes < b.CombinedPaperBytes
		}
		if a.PaperTranscriptBytes != b.PaperTranscriptBytes {
			return a.PaperTranscriptBytes < b.PaperTranscriptBytes
		}
		if a.ExpectedGrindingWork != b.ExpectedGrindingWork {
			return a.ExpectedGrindingWork < b.ExpectedGrindingWork
		}
		if a.ShowingAlgebraicBits != b.ShowingAlgebraicBits {
			return a.ShowingAlgebraicBits > b.ShowingAlgebraicBits
		}
		if nizkProfileFamilyRank(a.Family) != nizkProfileFamilyRank(b.Family) {
			return nizkProfileFamilyRank(a.Family) < nizkProfileFamilyRank(b.Family)
		}
		return a.Candidate < b.Candidate
	}
	if a.FrontierClass == nizkProfileFrontierValidPrefixResearch {
		if a.CombinedPaperBytes != b.CombinedPaperBytes {
			return a.CombinedPaperBytes < b.CombinedPaperBytes
		}
		if a.PaperTranscriptBytes != b.PaperTranscriptBytes {
			return a.PaperTranscriptBytes < b.PaperTranscriptBytes
		}
		if a.ShowingAlgebraicBits != b.ShowingAlgebraicBits {
			return a.ShowingAlgebraicBits > b.ShowingAlgebraicBits
		}
		return a.Candidate < b.Candidate
	}
	if a.ShowingAlgebraicBits != b.ShowingAlgebraicBits {
		return a.ShowingAlgebraicBits > b.ShowingAlgebraicBits
	}
	if a.PaperTranscriptBytes != b.PaperTranscriptBytes {
		return a.PaperTranscriptBytes < b.PaperTranscriptBytes
	}
	return a.Candidate < b.Candidate
}

func nizkProfileIsBQ64ReductionFamily(family string) bool {
	return family == "bq64_96_reduction"
}

func bq64ReductionCandidateRank(name string) int {
	switch name {
	case "baseline-h232-s224":
		return 0
	case "engineering-salt256":
		return 1
	case "lvcs44-h232":
		return 2
	case "lvcs45-h232":
		return 3
	case "lvcs46-h232":
		return 4
	case "lvcs47-h232":
		return 5
	case "lvcs48-h232":
		return 6
	case "lvcs49-h232":
		return 7
	case "lvcs50-h232":
		return 8
	case "lvcs51-h232":
		return 9
	case "lvcs52-h232":
		return 10
	case "theta11-lvcs43-h232":
		return 11
	case "theta11-lvcs48-h232":
		return 12
	case "theta11-lvcs52-h232":
		return 13
	case "ell15-lvcs43-h232":
		return 14
	case "ell15-lvcs48-h232":
		return 15
	case "theta11-ell15-lvcs48-h232":
		return 16
	case "theta12-ell17-lvcs48-h232":
		return 17
	case "bq64-96-r11-l4-theorem-research":
		return 18
	case "bq64-96-mixed-radix-theorem-research":
		return 19
	case "bq64-96-full-r2-theorem-research":
		return 20
	case "bq64-96-split-shortness-research":
		return 21
	default:
		return 100
	}
}

func nizkProfileFamilyRank(family string) int {
	switch family {
	case nizkProfileScopedR128Family:
		return 0
	case "current_r7_l5":
		return 1
	case "mixed_radix_topcap":
		return 2
	case "r11_l4_topcap":
		return 3
	case "q32_control":
		return 4
	case "row_compression_high_degree":
		return 5
	case "full_r2_decomposition":
		return 6
	case "split_shortness_theorem_track", "r121_l2_lookup_theorem_track":
		return 7
	case "bq64_96_reduction":
		return 8
	case "valid_prefix_trail":
		return 9
	default:
		return 10
	}
}

func nizkProfileFrontiers(results []NIZKProfileCandidateReport, limit int) map[string][]NIZKProfileFrontierEntry {
	if limit <= 0 {
		limit = 5
	}
	grouped := make(map[string][]NIZKProfileCandidateReport)
	for _, result := range results {
		grouped[result.SecurityProfile] = append(grouped[result.SecurityProfile], result)
	}
	out := make(map[string][]NIZKProfileFrontierEntry, len(grouped))
	for profile, entries := range grouped {
		scoped := false
		for _, entry := range entries {
			if entry.Family == nizkProfileScopedR128Family {
				scoped = true
				break
			}
		}
		if scoped {
			entries = nizkProfileParetoFrontier(entries)
		}
		sort.SliceStable(entries, func(i, j int) bool {
			return nizkProfileReportLess(entries[i], entries[j])
		})
		for i, result := range entries {
			if !scoped && i >= limit {
				break
			}
			out[profile] = append(out[profile], nizkProfileFrontierEntryFromReport(result))
		}
	}
	return out
}

func nizkProfileFrontierEntryFromReport(report NIZKProfileCandidateReport) NIZKProfileFrontierEntry {
	return NIZKProfileFrontierEntry{
		SecurityProfile:           report.SecurityProfile,
		Candidate:                 report.Candidate,
		Family:                    report.Family,
		RelationEncoding:          report.RelationEncoding,
		FrontierClass:             report.FrontierClass,
		CompilerBacked:            report.CompilerBacked,
		MeasurementStatus:         report.MeasurementStatus,
		RelationFirstScore:        report.RelationFirstScore,
		AlgebraicBits:             report.ShowingAlgebraicBits,
		PaperTranscriptBytes:      report.PaperTranscriptBytes,
		CombinedPaperBytes:        report.CombinedPaperBytes,
		ProjectedProverWorkUnits:  report.ProjectedProverWorkUnits,
		ExpectedGrindingWork:      report.ExpectedGrindingWork,
		ExpectedGrindingWorkLog2:  report.ExpectedGrindingWorkLog2,
		MeasurementSummary:        report.MeasurementSummary,
		RequiredKappa:             report.SmallWood.RequiredKappa,
		Eta:                       report.SmallWood.Eta,
		Theta:                     report.SmallWood.Theta,
		Ell:                       report.SmallWood.Ell,
		LVCSNCols:                 report.SmallWood.LVCSNCols,
		NLeaves:                   report.SmallWood.NLeaves,
		DQ:                        report.Relation.DQ,
		DominantDegreeSource:      report.Relation.DominantDegreeSource,
		TranscriptBuckets:         report.TranscriptBuckets,
		TranscriptDrivers:         append([]NIZKProfileTranscriptDriver(nil), report.TranscriptDrivers...),
		OptimizationLevers:        append([]NIZKProfileOptimizationLever(nil), report.OptimizationLevers...),
		PrimitiveBlockerBrief:     report.PrimitiveBlockerReason,
		UsesValidPrefixAccounting: report.UsesValidPrefixAccounting,
		EffectiveAlgebraicCapLog2: report.EffectiveAlgebraicCapLog2,
		FormalBackendCandidate:    report.FormalBackendCandidate,
		LVCSAboveRing:             report.LVCSAboveRing,
	}
}

func nizkProfileTargetOrder(label string) int {
	switch label {
	case "BQ32-128":
		return 0
	case "BQ64-96":
		return 1
	case "BQ64-128":
		return 2
	case "BQ96-128":
		return 3
	case "BQ128-128":
		return 4
	case "WF-128":
		return 5
	default:
		return 99
	}
}

func nizkProfileFrontierRank(class string) int {
	switch class {
	case nizkProfileFrontierCandidate:
		return 0
	case nizkProfileFrontierValidPrefixResearch:
		return 1
	case nizkProfileFrontierHighKResearch:
		return 2
	case nizkProfileFrontierRequiresTheoremWork:
		return 3
	case nizkProfileFrontierRequiresSplitTheorem:
		return 4
	case nizkProfileFrontierSerializerModelBlocked:
		return 5
	case nizkProfileFrontierRequiresNewPrimitives:
		return 6
	default:
		return 7
	}
}

func TestNIZKProfileSearchTargetsOrderAndStatuses(t *testing.T) {
	targets := nizkProfileSearchTargets()
	want := []string{"BQ32-128", "BQ64-96", "BQ64-128", "BQ96-128", "BQ128-128"}
	if len(targets) != len(want) {
		t.Fatalf("targets=%v want %v", targets, want)
	}
	for i, target := range targets {
		if target.SecurityProfile != want[i] {
			t.Fatalf("target order=%v want %v", targets, want)
		}
		if target.PrimitiveBlockerReason == "" || target.NIZKTargetBits <= 0 || target.CoreBitsRequired <= 0 {
			t.Fatalf("incomplete target: %+v", target)
		}
		if i < 2 {
			if target.TargetStatus != credential.SecurityProfileRequiresNewPrimitives {
				t.Fatalf("%s status=%q want %q", target.SecurityProfile, target.TargetStatus, credential.SecurityProfileRequiresNewPrimitives)
			}
			continue
		}
		if target.TargetStatus != credential.SecurityProfileProofOnly ||
			target.CoreBitsRequired != 128 ||
			target.FullGameTargetBits != nizkProfileScopedR128FullGameTargetBits ||
			math.Abs(target.NIZKTargetBits-131.5405683813627) > 1e-9 {
			t.Fatalf("incorrect NIZK-scoped R128 target: %+v", target)
		}
	}
}

func TestNIZKProfileBQ6496SaltTargetsMatchPDF(t *testing.T) {
	var target NIZKProfileSearchTarget
	for _, candidate := range nizkProfileSearchTargets() {
		if candidate.SecurityProfile == "BQ64-96" {
			target = candidate
			break
		}
	}
	if target.SecurityProfile == "" {
		t.Fatal("missing BQ64-96 target")
	}
	if target.BareSaltBits != 224 || target.EngineeringSaltBits != 256 || target.SaltBitsRange != [2]int{224, 256} {
		t.Fatalf("BQ64-96 salt target=%+v", target)
	}
}

func TestNIZKProfileBQ6496ReductionCandidatesOrderAndWidthModel(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	candidates := nizkProfileBQ6496ReductionCandidates(preset.Name, intGenISISTuningFromPresetSpec(preset.Showing))
	want := []string{
		"baseline-h232-s224",
		"engineering-salt256",
		"lvcs44-h232",
		"lvcs45-h232",
		"lvcs46-h232",
		"lvcs47-h232",
		"lvcs48-h232",
		"lvcs49-h232",
		"lvcs50-h232",
		"lvcs51-h232",
		"lvcs52-h232",
		"theta11-lvcs43-h232",
		"theta11-lvcs48-h232",
		"theta11-lvcs52-h232",
		"ell15-lvcs43-h232",
		"ell15-lvcs48-h232",
		"theta11-ell15-lvcs48-h232",
		"theta12-ell17-lvcs48-h232",
		"bq64-96-r11-l4-theorem-research",
		"bq64-96-mixed-radix-theorem-research",
		"bq64-96-full-r2-theorem-research",
		"bq64-96-split-shortness-research",
	}
	if len(candidates) != len(want) {
		t.Fatalf("candidates=%d want %d", len(candidates), len(want))
	}
	for i, cand := range candidates {
		if cand.Name != want[i] {
			t.Fatalf("candidate order[%d]=%q want %q", i, cand.Name, want[i])
		}
		if cand.Family != "bq64_96_reduction" || cand.TargetProfile != "BQ64-96" {
			t.Fatalf("%s family/target=%q/%q", cand.Name, cand.Family, cand.TargetProfile)
		}
		if cand.HashFSBitsOverride < 232 || cand.TapeBitsOverride < 160 || cand.TagElementsOverride < 12 {
			t.Fatalf("%s invalid width overrides hash=%d tape=%d tag=%d", cand.Name, cand.HashFSBitsOverride, cand.TapeBitsOverride, cand.TagElementsOverride)
		}
		if cand.SaltBitsOverride != 224 && cand.SaltBitsOverride != 256 {
			t.Fatalf("%s salt override=%d want 224 or 256", cand.Name, cand.SaltBitsOverride)
		}
	}
	if !candidates[len(candidates)-1].RequiresSplitTheorem {
		t.Fatalf("split-shortness audit should remain split-theorem-only: %+v", candidates[len(candidates)-1])
	}
}

func TestNIZKProfileBQ6496ReductionReportsFailClosed(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	reports := nizkProfileReportsForCandidateSet(
		nizkProfileBQ6496ReductionCandidates(preset.Name, intGenISISTuningFromPresetSpec(preset.Showing)),
	)
	seen := map[string]NIZKProfileCandidateReport{}
	for _, report := range reports {
		if report.Family == "bq64_96_reduction" {
			seen[report.Candidate] = report
		}
	}
	for _, want := range []string{"baseline-h232-s224", "engineering-salt256", "lvcs48-h232", "theta11-lvcs48-h232", "ell15-lvcs48-h232", "bq64-96-r11-l4-theorem-research", "bq64-96-mixed-radix-theorem-research", "bq64-96-full-r2-theorem-research", "bq64-96-split-shortness-research"} {
		report, ok := seen[want]
		if !ok {
			t.Fatalf("missing BQ64-96 reduction report %q", want)
		}
		if report.BQ64Reduction == nil {
			t.Fatalf("%s missing generic BQ64 reduction report", want)
		}
		if report.BQ64Reduction.BaselineBytes != bq6496ReductionBaselineBytes {
			t.Fatalf("%s baseline=%d want %d", want, report.BQ64Reduction.BaselineBytes, bq6496ReductionBaselineBytes)
		}
		if report.BQ64Reduction.Width.HashFSBits < 232 || report.BQ64Reduction.Width.TapeBits < 160 || report.BQ64Reduction.Width.TagElements < 12 {
			t.Fatalf("%s invalid width report: %+v", want, report.BQ64Reduction.Width)
		}
		if report.TranscriptBuckets.VTargets == 0 || report.TranscriptBuckets.BarSets == 0 {
			t.Fatalf("%s incorrectly omitted matrix payloads: %+v", want, report.TranscriptBuckets)
		}
	}
	if got := seen["baseline-h232-s224"].BQ64Reduction.Width.Classification; got != "bare" {
		t.Fatalf("baseline width classification=%q want bare", got)
	}
	if got := seen["engineering-salt256"].BQ64Reduction.Width.Classification; got != "engineering" {
		t.Fatalf("engineering salt width classification=%q want engineering", got)
	}
	for _, name := range []string{"bq64-96-r11-l4-theorem-research", "bq64-96-mixed-radix-theorem-research", "bq64-96-full-r2-theorem-research"} {
		if seen[name].FrontierClass != nizkProfileFrontierRequiresTheoremWork {
			t.Fatalf("%s frontier=%q want theorem work", name, seen[name].FrontierClass)
		}
	}
	if seen["bq64-96-split-shortness-research"].FrontierClass != nizkProfileFrontierRequiresSplitTheorem {
		t.Fatalf("split frontier=%q want %q", seen["bq64-96-split-shortness-research"].FrontierClass, nizkProfileFrontierRequiresSplitTheorem)
	}
}

func TestNIZKProfileValidPrefixTrailCandidatesOrderAndCaps(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	candidates := nizkProfileValidPrefixTrailCandidates(preset.Name, intGenISISTuningFromPresetSpec(preset.Showing))
	want := []string{
		"bq64-128-vp-lvcs48-h264",
		"bq64-128-vp-lvcs48-h256",
		"bq64-128-vp-lvcs49-h256",
		"bq64-128-vp-lvcs50-h256",
		"bq64-128-vp-lvcs51-h256",
		"bq64-128-vp-lvcs52-h256",
		"bq64-128-vp-lvcs53-h256",
		"bq64-128-vp-lvcs59-h256",
		"bq64-128-vp-theta13-h256",
		"bq64-128-vp-theta13-h256-vtargets-included-pdecs",
		"bq64-128-vp-theta13-lvcs49-h256",
		"bq64-128-vp-theta13-lvcs50-h256",
		"bq64-128-vp-theta13-lvcs51-h256",
		"bq64-128-vp-theta13-lvcs52-h256",
		"bq64-128-vp-theta13-lvcs53-h256",
		"bq64-128-vp-theta13-lvcs59-h256",
		"bq64-128-vp-theta13-ell17-h256",
		"bq64-128-vp-theta13-ell17-lvcs48-h256",
		"bq128-128-vp64-lvcs48-h512",
		"bq128-128-vp64-lvcs48-h512-vtargets-included-pdecs",
		"bq128-128-vp64-lvcs53-h512",
		"bq128-128-vp64-lvcs59-h512",
		"bq128-128-vp64-theta14-ell17-lvcs48-h512",
		"bq128-128-vp80-search",
		"bq128-128-vp80-search-vtargets-included-pdecs",
		nizkProfileBQ128RawResidualFrontierCandidate,
		"bq128-128-raw128-residual128-theta13-ell17-lvcs48-h512",
		"bq128-128-raw128-residual128-theta14-ell17-lvcs48-h512",
		"bq128-128-raw128-control",
		"bq128-128-raw128-control-vtargets-included-pdecs",
		"bq128-128-raw128-lvcs64-h512",
		"bq128-128-raw128-theta20-ell27-lvcs59-h512",
	}
	if len(candidates) != len(want) {
		t.Fatalf("candidates=%d want %d", len(candidates), len(want))
	}
	for i, cand := range candidates {
		if cand.Name != want[i] {
			t.Fatalf("candidate order[%d]=%q want %q", i, cand.Name, want[i])
		}
		if cand.Family != "valid_prefix_trail" && cand.Family != "raw128_residual" {
			t.Fatalf("%s family=%q", cand.Name, cand.Family)
		}
		if cand.TargetProfile != "BQ64-128" && cand.TargetProfile != "BQ128-128" {
			t.Fatalf("%s target profile=%q", cand.Name, cand.TargetProfile)
		}
		if cand.TargetProfile == "BQ64-128" && cand.TapeBitsOverride != 192 {
			t.Fatalf("%s BQ64 tape=%d want 192", cand.Name, cand.TapeBitsOverride)
		}
		if cand.TargetProfile == "BQ128-128" && cand.RawQueryCapExponentOverride != 128 {
			t.Fatalf("%s BQ128 raw cap exponent=%d want 128", cand.Name, cand.RawQueryCapExponentOverride)
		}
	}
}

func TestNIZKProfileValidPrefixReportsRemainTheoremBlocked(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	reports := nizkProfileReportsForCandidateSet(
		nizkProfileValidPrefixTrailCandidates(preset.Name, intGenISISTuningFromPresetSpec(preset.Showing)),
	)
	seen := map[string]NIZKProfileCandidateReport{}
	for _, report := range reports {
		if report.Family == "valid_prefix_trail" {
			seen[report.Candidate] = report
		}
	}
	for _, want := range []string{"bq64-128-vp-lvcs48-h264", "bq64-128-vp-lvcs48-h256", "bq64-128-vp-lvcs49-h256", "bq64-128-vp-lvcs50-h256", "bq64-128-vp-lvcs51-h256", "bq64-128-vp-lvcs52-h256", "bq64-128-vp-lvcs53-h256", "bq64-128-vp-lvcs59-h256", "bq64-128-vp-theta13-h256", "bq64-128-vp-theta13-h256-vtargets-included-pdecs", "bq64-128-vp-theta13-lvcs49-h256", "bq64-128-vp-theta13-lvcs50-h256", "bq64-128-vp-theta13-lvcs51-h256", "bq64-128-vp-theta13-lvcs52-h256", "bq64-128-vp-theta13-lvcs53-h256", "bq64-128-vp-theta13-lvcs59-h256", "bq64-128-vp-theta13-ell17-h256", "bq64-128-vp-theta13-ell17-lvcs48-h256", "bq128-128-vp64-lvcs48-h512", "bq128-128-vp64-lvcs48-h512-vtargets-included-pdecs", "bq128-128-vp64-lvcs53-h512", "bq128-128-vp64-lvcs59-h512", "bq128-128-vp64-theta14-ell17-lvcs48-h512", "bq128-128-vp80-search", "bq128-128-vp80-search-vtargets-included-pdecs"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("missing valid-prefix report %q", want)
		}
	}
	vp64 := seen["bq128-128-vp64-lvcs48-h512"]
	if !vp64.UsesValidPrefixAccounting || vp64.RawQueryCapLog2 != 128 || vp64.EffectiveAlgebraicCapLog2 != [4]float64{64, 64, 64, 64} {
		t.Fatalf("unexpected BQ128 vp64 cap accounting: %+v", vp64)
	}
	if vp64.LedgerStatus != string(credential.SecurityProfileRequiresTheory) || !containsStringLocal(vp64.LedgerReasons, "valid-prefix algebraic accounting requires a new theorem") {
		t.Fatalf("valid-prefix report should remain theorem-blocked: %+v", vp64)
	}
	targets := nizkProfileSearchTargets()
	var bq128Target NIZKProfileSearchTarget
	for _, target := range targets {
		if target.SecurityProfile == "BQ128-128" {
			bq128Target = target
			break
		}
	}
	var rawCand NIZKProfileSearchCandidate
	for _, cand := range nizkProfileValidPrefixTrailCandidates(preset.Name, intGenISISTuningFromPresetSpec(preset.Showing)) {
		if cand.Name == "bq128-128-raw128-control" {
			rawCand = cand
			break
		}
	}
	if bq128Target.SecurityProfile == "" || rawCand.Name == "" {
		t.Fatal("missing BQ128 raw-control target/candidate")
	}
	raw := nizkProfileCandidateReport(bq128Target, rawCand)
	if raw.UsesValidPrefixAccounting || raw.EffectiveAlgebraicCapLog2 != [4]float64{128, 128, 128, 128} {
		t.Fatalf("raw control should keep raw algebraic caps: %+v", raw)
	}
}

func TestNIZKProfileLegacyBQ128RawResidualUsesRawCapsButMissesEngineeringTarget(t *testing.T) {
	report, ok := nizkProfileReportForCandidate("BQ128-128", nizkProfileBQ128RawResidualFrontierCandidate)
	if !ok {
		t.Fatalf("missing candidate %q", nizkProfileBQ128RawResidualFrontierCandidate)
	}
	if report.SecurityProfile != "BQ128-128" || report.NIZKTargetBits != 128 || report.RawQueryCapLog2 != 128 {
		t.Fatalf("unexpected residual target report: %+v", report)
	}
	if report.TargetStatus != credential.SecurityProfileProofOnly ||
		report.LedgerStatus != string(credential.SecurityProfileProofOnly) ||
		report.CoreBitsRequired != 128 ||
		report.PrimitiveBlockerReason == "" {
		t.Fatalf("legacy residual target has incorrect proof-only classification: %+v", report)
	}
	if report.UsesValidPrefixAccounting || report.EffectiveAlgebraicCapLog2 != [4]float64{128, 128, 128, 128} {
		t.Fatalf("residual target should use raw algebraic caps: %+v", report)
	}
	if report.SmallWood.Theta != 13 || report.SmallWood.Ell != 18 || report.SmallWood.NLeaves != 983040 {
		t.Fatalf("unexpected residual target shape: %+v", report.SmallWood)
	}
	if report.SmallWood.RequiredKappa[2] > nizkProfileMaxSupportedGrinding || report.ShowingAlgebraicBits < 128 {
		t.Fatalf("theta13 residual target should clear the raw 2^128 residual-128 lane: %+v", report)
	}
	if report.FullGameBits >= report.FullGameTargetBits || report.FrontierClass != nizkProfileFrontierRejected {
		t.Fatalf("legacy residual-128 point should miss the 130-bit engineering target: %+v", report)
	}
	targets := nizkProfileSearchTargets()
	candidates := nizkProfileSearchCandidates()
	var target NIZKProfileSearchTarget
	for _, candidateTarget := range targets {
		if candidateTarget.SecurityProfile == "BQ128-128" {
			target = candidateTarget
			break
		}
	}
	var cand NIZKProfileSearchCandidate
	for _, candidate := range candidates {
		if candidate.Name == nizkProfileBQ128RawResidualFrontierCandidate {
			cand = candidate
			break
		}
	}
	if target.SecurityProfile == "" || cand.Name == "" {
		t.Fatalf("missing BQ128 target/candidate for measured config: target=%+v candidate=%+v", target, cand)
	}
	target = nizkProfileTargetForCandidate(target, cand)
	cfg, err := nizkProfileBenchmarkConfig(target, cand, report, t.TempDir(), 1)
	if err != nil {
		t.Fatalf("build measured config: %v", err)
	}
	wantCapBits := [5]float64{128, 128, 128, 128, 128}
	if cfg.Showing.ROQueryCapsSet || cfg.Showing.ROQueryCaps != [5]int{} ||
		!cfg.Showing.ROQueryCapBitsSet || cfg.Showing.ROQueryCapBits != wantCapBits {
		t.Fatalf("showing measured query caps should use BQ128 log caps: %+v", cfg.Showing)
	}
	if cfg.Issuance.ROQueryCapsSet || cfg.Issuance.ROQueryCaps != [5]int{} ||
		!cfg.Issuance.ROQueryCapBitsSet || cfg.Issuance.ROQueryCapBits != wantCapBits {
		t.Fatalf("issuance measured query caps should use BQ128 log caps: %+v", cfg.Issuance)
	}
}

func TestNIZKProfileScopedR128UsesRawCapsWithoutValidPrefixDiscount(t *testing.T) {
	raw, ok := nizkProfileReportForCandidate("BQ64-128", "bq64-128-r7l5-theta10-ell13-n917504-lvcs43")
	if !ok {
		t.Fatal("missing scoped BQ64 candidate")
	}
	if raw.UsesValidPrefixAccounting ||
		raw.EffectiveAlgebraicCapLog2 != [4]float64{64, 64, 64, 64} ||
		raw.FrontierClass != nizkProfileFrontierCandidate ||
		raw.FullGameBits < raw.FullGameTargetBits {
		t.Fatalf("scoped BQ64 candidate should satisfy the corrected target under raw caps: %+v", raw)
	}
	vpTheta13, ok := nizkProfileReportForCandidate("BQ64-128", "bq64-128-vp-theta13-h256")
	if !ok {
		t.Fatal("missing non-serializer valid-prefix theta13 report")
	}
	if !vpTheta13.UsesValidPrefixAccounting || vpTheta13.EffectiveAlgebraicCapLog2[2] != 61 {
		t.Fatalf("vp theta13 missing explicit round-3 cap: %+v", vpTheta13)
	}
	if vpTheta13.SmallWood.RequiredKappa[2] > nizkProfileMaxSupportedGrinding {
		t.Fatalf("vp theta13 should be within supported grinding: %+v", vpTheta13.SmallWood.RequiredKappa)
	}
	if vpTheta13.FrontierClass != nizkProfileFrontierRequiresTheoremWork {
		t.Fatalf("vp theta13 frontier=%q want %q", vpTheta13.FrontierClass, nizkProfileFrontierRequiresTheoremWork)
	}
	if vpTheta13.AlgebraicAccounting.TheoremMode != credential.ValidPrefixTheoremModeCandidate || !vpTheta13.AlgebraicAccounting.RequiresTheoremAccounting {
		t.Fatalf("vp theta13 should expose theorem-candidate accounting: %+v", vpTheta13.AlgebraicAccounting)
	}
	if vpTheta13.AlgebraicAccounting.CollisionCapLog2 != 64 || vpTheta13.AlgebraicAccounting.ProgrammingCapLog2 != [4]float64{64, 64, 64, 64} {
		t.Fatalf("vp theta13 changed raw collision/programming caps: %+v", vpTheta13.AlgebraicAccounting)
	}
	if vpTheta13.AlgebraicAccounting.ValidPrefixDiscountLog2[2] != 3 {
		t.Fatalf("vp theta13 round-3 discount=%+v want 3 bits", vpTheta13.AlgebraicAccounting.ValidPrefixDiscountLog2)
	}
}

func TestNIZKProfileBQ6496Theta11RemainsRejectedWithoutNewAccounting(t *testing.T) {
	report, ok := nizkProfileReportForCandidate("BQ64-96", "theta11-lvcs43-h232")
	if !ok {
		t.Fatal("missing BQ64-96 theta11 candidate")
	}
	if report.SecurityProfile != "BQ64-96" || report.Candidate != "theta11-lvcs43-h232" {
		t.Fatalf("unexpected report selected: %+v", report)
	}
	if report.AlgebraicAccounting.TheoremMode != credential.ValidPrefixTheoremModeCurrentRaw || report.UsesValidPrefixAccounting {
		t.Fatalf("BQ64-96 theta11 should use raw current-theorem accounting: %+v", report.AlgebraicAccounting)
	}
	if report.SmallWood.RequiredKappa[2] <= nizkProfileMaxSupportedGrinding || report.ShowingAlgebraicBits >= bq64ReductionTargetBits("BQ64-96") {
		t.Fatalf("BQ64-96 theta11 should remain below target/over grinding cap: %+v", report)
	}
	if report.FrontierClass != nizkProfileFrontierHighKResearch {
		t.Fatalf("BQ64-96 theta11 frontier=%q want high-k research", report.FrontierClass)
	}
}

func TestNIZKProfileRelationSafetyCertificatesCurrentTheoremBoundary(t *testing.T) {
	lvcs, ok := nizkProfileReportForCandidate("BQ64-96", "lvcs48-h232")
	if !ok {
		t.Fatal("missing safe BQ64-96 LVCS candidate")
	}
	if !lvcs.RelationSafety.CurrentTheoremSafe || lvcs.RelationSafety.CertificateStatus != "current_theorem_safe" {
		t.Fatalf("safe LVCS relation should have a current-theorem certificate: %+v", lvcs.RelationSafety)
	}
	split, ok := nizkProfileReportForCandidate("BQ64-96", "bq64-96-split-shortness-research")
	if !ok {
		t.Fatal("missing split-shortness research candidate")
	}
	if split.RelationSafety.CurrentTheoremSafe || split.RelationSafety.CertificateStatus != "relation_theorem_blocked" {
		t.Fatalf("split relation should be theorem-blocked: %+v", split.RelationSafety)
	}
	if !containsStringLocal(split.RelationSafety.RejectionReasons, "relation requires new theorem/accounting before current-theorem ranking") ||
		!containsStringLocal(split.RelationSafety.RejectionReasons, "split relation requires a separate composition theorem") {
		t.Fatalf("split relation missing theorem rejection reasons: %+v", split.RelationSafety)
	}
}

func TestNIZKProfileOptimizedSerializerTrailCandidates(t *testing.T) {
	t.Setenv("SPRUCE_VALID_PREFIX_SWEEP", "1")
	want := map[string]string{
		"bq64-128-vp-theta13-h256-vtargets-included-pdecs":   "BQ64-128",
		"bq128-128-vp64-lvcs48-h512-vtargets-included-pdecs": "BQ128-128",
		"bq128-128-vp80-search-vtargets-included-pdecs":      "BQ128-128",
	}
	var bq64 NIZKProfileCandidateReport
	for name, profile := range want {
		report, ok := nizkProfileReportForCandidate(profile, name)
		if !ok {
			t.Fatalf("missing optimized serializer candidate %q", name)
		}
		if report.TranscriptBuckets.VTargets == 0 || report.TranscriptBuckets.BarSets == 0 {
			t.Fatalf("%s incorrectly omitted matrix payloads: %+v", name, report.TranscriptBuckets)
		}
		if !report.UsesValidPrefixAccounting || !report.RequiresTheoremWork {
			t.Fatalf("%s should remain explicitly valid-prefix/theorem research: %+v", name, report)
		}
		if report.FrontierClass != nizkProfileFrontierValidPrefixResearch &&
			report.FrontierClass != nizkProfileFrontierRequiresTheoremWork {
			t.Fatalf("%s unexpected valid-prefix frontier=%q", name, report.FrontierClass)
		}
		if profile == "BQ64-128" {
			bq64 = report
		}
	}
	if bq64.PaperTranscriptBytes < 70000 {
		t.Fatalf("BQ64 corrected serializer target projected bytes=%d should include VTargets/BarSets", bq64.PaperTranscriptBytes)
	}
	raw, ok := nizkProfileReportForCandidate("BQ128-128", "bq128-128-raw128-control-vtargets-included-pdecs")
	if !ok {
		t.Fatal("missing raw serializer control")
	}
	if raw.UsesValidPrefixAccounting || raw.EffectiveAlgebraicCapLog2 != [4]float64{128, 128, 128, 128} {
		t.Fatalf("raw serializer control should preserve raw caps: %+v", raw)
	}
	if raw.TranscriptBuckets.VTargets == 0 || raw.TranscriptBuckets.BarSets == 0 {
		t.Fatalf("raw serializer control omitted matrix accounting: %+v", raw.TranscriptBuckets)
	}
}

func TestValidPrefixCostReportUsesMeasuredPhaseTimings(t *testing.T) {
	spec, ok := credential.LookupIntGenISISSecurityProfile("BQ64-128")
	if !ok {
		t.Fatal("missing BQ64-128 profile")
	}
	timings := []PIOP.PhaseTiming{
		{Label: "showing.rows", Milliseconds: 100},
		{Label: "showing.rows_ntt", Milliseconds: 5},
		{Label: "showing.constraints.total", Milliseconds: 300},
		{Label: "showing.lvcs_commit_total", Milliseconds: 4000},
		{Label: "RunMaskFS.Round1Gamma", Milliseconds: 25},
		{Label: "RunMaskFS.Round2GammaPrime", Milliseconds: 37},
		{Label: "RunMaskFS.BuildQAndMasks", Milliseconds: 468},
		{Label: "RunMaskFS.Round3Eval", Milliseconds: 665},
		{Label: "RunMaskFS.Round4TailOpen", Milliseconds: 44},
	}
	report := benchmarkValidPrefixCostReport(spec, timings, [4]float64{}, false)
	if !report.ValidPrefixConservative || len(report.Rounds) != 4 {
		t.Fatalf("expected conservative four-round report: %+v", report)
	}
	if report.Rounds[0].MeasuredCumulativeMS != 4405 || report.Rounds[3].MeasuredCumulativeMS != 5644 {
		t.Fatalf("unexpected cumulative round costs: %+v", report.Rounds)
	}
	if report.Rounds[0].RawCapLog2 != 64 || report.Rounds[0].ValidPrefixCapLog2 != 64 {
		t.Fatalf("raw fallback cap mismatch: %+v", report.Rounds[0])
	}
	research := benchmarkValidPrefixCostReport(spec, timings, [4]float64{64, 64, 61, 64}, true)
	if research.ValidPrefixConservative || research.Rounds[2].ValidPrefixCapLog2 != 61 || research.Rounds[2].AccountingStatus != credential.ValidPrefixAccountingResearchRequiresTheory {
		t.Fatalf("research valid-prefix cap not applied: %+v", research.Rounds[2])
	}
}

func TestNIZKProfileEtaDerivationUsesTargetFloor(t *testing.T) {
	target := nizkProfileSearchTargets()[0]
	cand := nizkProfileSearchCandidates()[0]
	sw := deriveNIZKProfileSmallWoodReport(target, cand.Relation, cand.Showing, cand.PinnedLVCS, cand.DeriveEtaFloorOnly)
	if sw.Eta < sw.EtaFloor {
		t.Fatalf("eta=%d below floor=%d", sw.Eta, sw.EtaFloor)
	}
	if len(sw.EtaWindow) != 1 || sw.EtaWindow[0] != sw.Eta {
		t.Fatalf("eta should not be wide-swept: %+v", sw)
	}
	if sw.EtaFloor <= 0 {
		t.Fatalf("missing eta floor: %+v", sw)
	}
}

func TestNIZKProfileCandidateOverGrindingLimitClassifiedHighK(t *testing.T) {
	report := NIZKProfileCandidateReport{
		TargetStatus:          credential.SecurityProfileRequiresNewPrimitives,
		NIZKTargetBits:        164,
		IssuanceAlgebraicBits: 100,
		ShowingAlgebraicBits:  100,
		SmallWood: NIZKProfileSmallWoodReport{
			RequiredKappa: [4]int{0, 0, nizkProfileMaxSupportedGrinding + 1, 0},
		},
	}
	if got := nizkProfileFrontierClass(report); got != nizkProfileFrontierHighKResearch {
		t.Fatalf("frontier=%q want %q", got, nizkProfileFrontierHighKResearch)
	}
}

func TestNIZKProfileSweepIntegrationSummary(t *testing.T) {
	all := nizkProfileReports(0, "")
	best := make([]NIZKProfileCandidateReport, 0, len(nizkProfileSearchTargets()))
	seenProfiles := make(map[string]bool)
	for _, report := range all {
		if report.LedgerStatus != string(report.TargetStatus) {
			t.Fatalf("%s ledger status=%q target status=%q", report.SecurityProfile, report.LedgerStatus, report.TargetStatus)
		}
		if report.PrimitiveBlockerReason == "" || len(report.LedgerReasons) == 0 {
			t.Fatalf("missing blocker reason: %+v", report)
		}
		if report.TargetStatus != credential.SecurityProfileRequiresNewPrimitives &&
			report.TargetStatus != credential.SecurityProfileProofOnly {
			t.Fatalf("unexpected promoted target status: %+v", report)
		}
		if !seenProfiles[report.SecurityProfile] {
			best = append(best, report)
			seenProfiles[report.SecurityProfile] = true
		}
	}
	candidates := nizkProfileSearchCandidates()
	if len(best) != len(nizkProfileSearchTargets()) {
		t.Fatalf("best reports=%d want one per profile", len(best))
	}
	summary := NIZKProfileSweepSummary{
		Version:        nizkProfileSweepSummaryVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		CandidateCount: len(nizkProfileSearchTargets()) * len(candidates),
		RunCount:       len(best),
		Targets:        nizkProfileSearchTargets(),
		Results:        best,
		Frontiers:      nizkProfileFrontiers(best, 3),
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"relation", "relation_safety", "algebraic_accounting", "theorem_mode", "raw_collision_unaffected", "smallwood", "ledger_status", "primitive_blocker_reason", "forced_by_security", "compiler_backed", "formal_backend_candidate", "measurement_status", "transcript_buckets", "transcript_drivers", "optimization_levers", "frontiers", "pdecs", "vtargets", "barsets"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("summary missing %s: %s", want, data)
		}
	}
	wantBest := map[string]string{
		"BQ32-128":  "r7l5-current-theta10-ell15-n917504-lvcs43",
		"BQ64-96":   "r7l5-current-theta12-ell16-n983040-lvcs43",
		"BQ64-128":  "bq64-128-r7l5-theta10-ell13-n917504-lvcs43",
		"BQ96-128":  "bq96-128-r11l4-theta12-ell15-n983040-lvcs41",
		"BQ128-128": "bq128-128-r7l5-theta13-ell18-n917504-lvcs55",
	}
	for _, result := range best {
		if result.Candidate != wantBest[result.SecurityProfile] {
			t.Fatalf("%s best candidate=%q want %q", result.SecurityProfile, result.Candidate, wantBest[result.SecurityProfile])
		}
		if result.FrontierClass != nizkProfileFrontierCandidate || !nizkProfileMeetsSecurityTarget(result) {
			t.Fatalf("best result did not meet the concrete NIZK frontier: %+v", result)
		}
		for _, kappa := range result.SmallWood.RequiredKappa {
			if kappa > nizkProfileMaxSupportedGrinding {
				t.Fatalf("best result exceeds grinding limit: %+v", result)
			}
		}
		if len(result.TranscriptDrivers) == 0 {
			t.Fatalf("%s missing transcript drivers", result.SecurityProfile)
		}
		wantDriver := "vtargets"
		if result.SecurityProfile == "BQ64-128" || result.SecurityProfile == "BQ96-128" {
			wantDriver = "pdecs"
		}
		if result.TranscriptDrivers[0].Component != wantDriver || result.TranscriptDrivers[0].Percent <= 20 {
			t.Fatalf("%s dominant transcript driver mismatch: %+v", result.SecurityProfile, result.TranscriptDrivers)
		}
		leverNames := make(map[string]bool)
		for _, lever := range result.OptimizationLevers {
			if lever.EstimatedSavingsBytes < 0 {
				t.Fatalf("negative estimated savings: %+v", lever)
			}
			leverNames[lever.Name] = true
		}
		for _, want := range []string{"compiler_backed_safe_relation_measurement", "lvcs_rowblock_breakpoint_sweep", "auth_multiproof_path_audit", "pdecs_vtargets_barsets_serializer_dedup", "avoid_eta_theta_growth"} {
			if !leverNames[want] {
				t.Fatalf("%s missing optimization lever %q: %+v", result.SecurityProfile, want, result.OptimizationLevers)
			}
		}
		if result.SecurityProfile == "BQ64-128" {
			if result.IssuanceProjection == nil || result.ShowingProjection == nil {
				t.Fatalf("BQ64-128 missing exact phase projections: %+v", result)
			}
			issuanceBytes := result.IssuanceProjection.Transcript.OptimizedBytes
			showingBytes := result.ShowingProjection.Transcript.OptimizedBytes
			if issuanceBytes <= 0 || showingBytes <= issuanceBytes ||
				result.CombinedPaperBytes != issuanceBytes+showingBytes {
				t.Fatalf("BQ64-128 malformed v2 projection accounting: %+v", result)
			}
			for phase, projection := range map[string]*NIZKProfilePhaseProjection{
				"issuance": result.IssuanceProjection,
				"showing":  result.ShowingProjection,
			} {
				tapes := projection.Transcript.Audit.Tapes
				if tapes.TapeCount != result.SmallWood.Ell || tapes.TapeBytes <= 0 ||
					tapes.TotalBytes != tapes.TapeBytes+tapes.TapeMetadataBytes {
					t.Fatalf("BQ64-128 %s projection lacks independent selective-tape accounting: %+v", phase, tapes)
				}
			}
			if result.SmallWood.Kappa != [4]int{13, 2, 8, 13} ||
				result.ExpectedGrindingWork != 16644 ||
				!result.SmallWood.AggregateOptimized {
				t.Fatalf("BQ64-128 aggregate grinding mismatch: %+v", result.SmallWood)
			}
		}
	}
}

func TestNIZKProfileConcreteCandidatesIncludeRelationAndSmallWoodVariants(t *testing.T) {
	candidates := nizkProfileSearchCandidates()
	wantNames := map[string]bool{
		"control-bq32-96-current-relation":    false,
		"control-q32-128-high-soundness":      false,
		"bq32-nizk164-theta10-ell16-n1048576": false,
	}
	wantFamilies := map[string]bool{
		"current_r7_l5": false,
		"q32_control":   false,
	}
	hasThetaBreakpoint := false
	hasBQ128Shape := false
	for _, cand := range candidates {
		if _, ok := wantNames[cand.Name]; ok {
			wantNames[cand.Name] = true
		}
		if _, ok := wantFamilies[cand.Family]; ok {
			wantFamilies[cand.Family] = true
		}
		if cand.Relation.DQ <= 0 || cand.Relation.LogicalRows <= 0 {
			t.Fatalf("candidate missing relation report: %+v", cand)
		}
		switch cand.Family {
		case "r11_l4_topcap", "mixed_radix_topcap", "split_shortness_theorem_track", "row_compression_high_degree", "full_r2_decomposition", "r121_l2_lookup_theorem_track":
			t.Fatalf("infeasible relation track %q should not be generated as an active NIZK candidate", cand.Family)
		}
		if cand.PinnedLVCS && strings.Contains(cand.Name, "theta13-ell18") {
			hasThetaBreakpoint = true
		}
		if cand.PinnedLVCS && strings.Contains(cand.Name, "theta20-ell28") {
			hasBQ128Shape = true
		}
	}
	for name, found := range wantNames {
		if !found {
			t.Fatalf("missing NIZK candidate %q", name)
		}
	}
	for family, found := range wantFamilies {
		if !found {
			t.Fatalf("missing NIZK relation family %q", family)
		}
	}
	if !hasThetaBreakpoint {
		t.Fatal("missing theta/ell breakpoint probes for BQ64-style tuning")
	}
	if !hasBQ128Shape {
		t.Fatal("missing BQ128-128 extreme NIZK-only shape probes")
	}
}

func TestNIZKProfileGeneratedCandidatesDeriveEtaAndPinLVCS(t *testing.T) {
	target := nizkProfileSearchTargets()[1]
	var cand NIZKProfileSearchCandidate
	for _, candidate := range nizkProfileSearchCandidates() {
		if candidate.PinnedLVCS && candidate.DeriveEtaFloorOnly && strings.Contains(candidate.Name, "theta12-ell16") {
			cand = candidate
			break
		}
	}
	if cand.Name == "" {
		t.Fatal("missing generated eta-floor candidate")
	}
	sw := deriveNIZKProfileSmallWoodReport(target, cand.Relation, cand.Showing, cand.PinnedLVCS, cand.DeriveEtaFloorOnly)
	if sw.Eta != sw.EtaFloor {
		t.Fatalf("eta=%d want floor=%d for generated candidate %+v", sw.Eta, sw.EtaFloor, cand)
	}
	if sw.LVCSNCols != cand.Showing.LVCSNCols {
		t.Fatalf("LVCS=%d want pinned=%d", sw.LVCSNCols, cand.Showing.LVCSNCols)
	}
}

func TestNIZKProfileFormalBackendCandidatesAreFilterGatedAndDiagnosed(t *testing.T) {
	for _, cand := range nizkProfileSearchCandidates() {
		if cand.FormalBackendCandidate || cand.Family == nizkProfileFormalBackendFamily {
			t.Fatalf("default candidate set included formal sweep candidate: %+v", cand)
		}
	}
	report, ok := nizkProfileReportForCandidate("BQ64-128", "formal-bq64-128-current-lvcs1025")
	if !ok {
		t.Fatal("missing formal LVCS candidate")
	}
	diag := report.FormalBackendDiagnostics
	if !report.FormalBackendCandidate || report.Family != nizkProfileFormalBackendFamily || diag == nil {
		t.Fatalf("missing formal diagnostics: %+v", report)
	}
	if report.SecurityProfile != "BQ64-128" || report.LedgerStatus != string(credential.SecurityProfileProofOnly) {
		t.Fatalf("formal candidate must remain proof-only: %+v", report)
	}
	if !report.LVCSAboveRing || !diag.LVCSAboveRing || report.SmallWood.LVCSNCols <= diag.RingDegree {
		t.Fatalf("formal LVCS width not above ring: report=%+v diag=%+v", report.SmallWood, diag)
	}
	if diag.BaselineLVCSNCols != 48 || diag.DDECS != report.SmallWood.LVCSNCols+report.SmallWood.Ell-1 {
		t.Fatalf("unexpected formal dDECS diagnostics: %+v", diag)
	}
	if diag.RowBlocks > diag.BaselineRowBlocks || diag.DQBlocks > diag.BaselineDQBlocks {
		t.Fatalf("formal row/Q blocks should not increase: %+v", diag)
	}
	if diag.Tradeoff == "" {
		t.Fatalf("missing formal tradeoff note: %+v", diag)
	}
	if nizkProfileShouldMeasureReport(report) && diag.ProjectedPaperTranscriptDeltaBytes >= 0 {
		t.Fatalf("formal candidate should not be selected for measurement without a projected byte win: %+v", diag)
	}
}

func TestNIZKProfileFormalDQOverridePropagatesToMeasuredConfig(t *testing.T) {
	report, ok := nizkProfileReportForCandidate("BQ64-128", "formal-bq64-128-dq1152-lvcs1152")
	if !ok {
		t.Fatal("missing formal dQ candidate")
	}
	if report.Relation.DQ != 1152 || report.Relation.MaskDegreeBound != 1152 || report.Relation.DominantDQBranch != "override" {
		t.Fatalf("dQ override not reflected in projection relation: %+v", report.Relation)
	}
	if report.FormalBackendDiagnostics == nil || !report.FormalBackendDiagnostics.DQAboveRing || report.FormalBackendDiagnostics.DQOverride != 1152 {
		t.Fatalf("missing dQ override diagnostics: %+v", report.FormalBackendDiagnostics)
	}
	var target NIZKProfileSearchTarget
	for _, candidateTarget := range nizkProfileSearchTargets() {
		if candidateTarget.SecurityProfile == report.SecurityProfile {
			target = candidateTarget
			break
		}
	}
	var cand NIZKProfileSearchCandidate
	for _, candidate := range nizkProfileSearchCandidatesForFilter("formal") {
		if candidate.Name == report.Candidate {
			cand = candidate
			break
		}
	}
	if target.SecurityProfile == "" || cand.Name == "" {
		t.Fatalf("missing target/candidate for formal report: target=%+v cand=%+v", target, cand)
	}
	cfg, err := nizkProfileBenchmarkConfig(nizkProfileTargetForCandidate(target, cand), cand, report, t.TempDir(), 1)
	if err != nil {
		t.Fatalf("formal benchmark config: %v", err)
	}
	if cfg.Showing.DQOverride != 1152 || cfg.Issuance.DQOverride != 1152 {
		t.Fatalf("dQ override not propagated into measured config: issuance=%d showing=%d", cfg.Issuance.DQOverride, cfg.Showing.DQOverride)
	}
}

func TestNIZKProfileFormalRhoEllPrimeProbeFailsClosed(t *testing.T) {
	report, ok := nizkProfileReportForCandidate("BQ64-128", "formal-bq64-128-rho2-ellprime2-lvcs1152")
	if !ok {
		t.Fatal("missing formal rho/ell-prime candidate")
	}
	if report.SmallWood.Rho != 2 || report.SmallWood.EllPrime != 2 {
		t.Fatalf("rho/ell_prime probe did not retain non-default values: %+v", report.SmallWood)
	}
	if !report.RequiresTheoremWork || report.RelationSafety.CurrentTheoremSafe {
		t.Fatalf("rho/ell_prime probe should remain fail-closed/theorem-blocked: %+v", report)
	}
	ok, reason := nizkProfileReportMeasurable(report)
	if ok || !strings.Contains(reason, "rho=1 and ell_prime=1") {
		t.Fatalf("rho/ell_prime probe should be measurement-blocked, ok=%v reason=%q", ok, reason)
	}
}

func TestNIZKProfileMaintainedByteGateBaselineLocked(t *testing.T) {
	type byteBaseline struct {
		issuance int
		showing  int
		combined int
	}
	want := map[string]byteBaseline{
		credential.IntGenISISPresetPoCN512SC96V2:          {15283, 23963, 39246},
		credential.IntGenISISPresetArtifactN1024SC125V2:   {23926, 40150, 64076},
		"artifact-n1024-bq10-r96-v2":                      {19113, 34388, 53501},
		"artifact-n1024-bq16-r96-v2":                      {20592, 35000, 55592},
		credential.IntGenISISPresetPilotN1024BQ32R96V2:    {24859, 41159, 66018},
		credential.IntGenISISPresetPoCN1024BQ64R128V2:     {39950, 64350, 104300},
		credential.IntGenISISPresetPoCN1024BQ96R128V2:     {52472, 82972, 135444},
		credential.IntGenISISPresetPoCN1024BQ128R128V3:    {57271, 90494, 147765},
		credential.IntGenISISPresetSystemN1024WF128CROMV2: {23790, 39837, 63627},
	}
	gates := allMaintainedPresetGates()
	if len(gates) != len(want) {
		t.Fatalf("maintained gates=%d want %d", len(gates), len(want))
	}
	seen := make(map[string]bool, len(gates))
	for _, gate := range gates {
		if seen[gate.Name] {
			t.Fatalf("duplicate maintained gate %s", gate.Name)
		}
		seen[gate.Name] = true
		got, ok := want[gate.Name]
		if !ok {
			t.Fatalf("unexpected maintained gate %s", gate.Name)
		}
		preset, ok := credential.LookupIntGenISISPreset(gate.Name)
		if !ok || preset.CanonicalID != gate.Name {
			t.Fatalf("maintained gate %q is not a canonical preset ID", gate.Name)
		}
		profile, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
		if !ok || gate.MinTheoremBits != profile.TargetBits {
			t.Fatalf("maintained theorem gate for %s=%v, want profile target %v", gate.Name, gate.MinTheoremBits, profile.TargetBits)
		}
		if gate.ExpectedIssuancePaperBytes != got.issuance ||
			gate.ExpectedShowingPaperBytes != got.showing ||
			gate.ExpectedCombinedPaperBytes != got.combined {
			t.Fatalf("maintained byte baseline changed for %s: got %d/%d/%d want %d/%d/%d",
				gate.Name,
				gate.ExpectedIssuancePaperBytes,
				gate.ExpectedShowingPaperBytes,
				gate.ExpectedCombinedPaperBytes,
				got.issuance,
				got.showing,
				got.combined,
			)
		}
		if gate.ExpectedCombinedPaperBytes != gate.ExpectedIssuancePaperBytes+gate.ExpectedShowingPaperBytes {
			t.Fatalf("maintained combined byte baseline is inconsistent for %s", gate.Name)
		}
		expectedStatus := credential.IntGenISISSecurityGateV2
		if gate.Name == credential.IntGenISISPresetPoCN1024BQ128R128V3 || gate.Name == credential.IntGenISISPresetSystemN1024WF128CROMV2 {
			expectedStatus = credential.IntGenISISSecurityGateV3
		}
		actualStatus := gate.ExpectedTranscriptStatus
		if actualStatus == "" {
			actualStatus = credential.IntGenISISSecurityGateV2
		}
		if actualStatus != expectedStatus {
			t.Fatalf("maintained transcript gate for %s=%q want %q", gate.Name, actualStatus, expectedStatus)
		}
	}
}

func TestNIZKProfileCandidateDQFollowsCandidateEll(t *testing.T) {
	report, ok := nizkProfileReportForCandidate("BQ64-128", "bq64-128-r7l5-theta10-ell13-n917504-lvcs43")
	if !ok {
		t.Fatal("missing BQ64-R128 frontier candidate")
	}
	wantParallel, wantAggregate, wantDQ := PIOP.ComputeDQBranchBounds(report.Relation.ParallelDegree, report.Relation.AggregatedDegree, 32, report.SmallWood.Ell)
	if report.Relation.DQParallel != wantParallel || report.Relation.DQAggregate != wantAggregate || report.Relation.DQ != wantDQ {
		t.Fatalf("dQ branches=%d/%d/%d want %d/%d/%d", report.Relation.DQParallel, report.Relation.DQAggregate, report.Relation.DQ, wantParallel, wantAggregate, wantDQ)
	}
	if report.Relation.DQ == 391 {
		t.Fatalf("advanced candidate reused baseline dQ=391 instead of ell=%d adjusted dQ", report.SmallWood.Ell)
	}
}

func TestNIZKProfileMeasuredBenchmarkReplacesProjectedBucketsAndRelation(t *testing.T) {
	target := nizkProfileSearchTargets()[0]
	report, ok := nizkProfileReportForCandidate("BQ32-128", "r7l5-current-theta10-ell15-n917504-lvcs43")
	if !ok {
		t.Fatal("missing BQ32-R128 frontier candidate")
	}
	var cand NIZKProfileSearchCandidate
	for _, candidate := range nizkProfileSearchCandidates() {
		if candidate.Name == report.Candidate {
			cand = candidate
			break
		}
	}
	if cand.Name == "" {
		t.Fatalf("missing candidate %q", report.Candidate)
	}
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(9, 8, 32, report.SmallWood.Ell)
	bench := benchmarkIntGenISISE2EReport{
		ArtifactDir: "/tmp/spruce-nizk-measured-test",
		Issuance: benchmarkIntGenISISMetrics{
			PaperTranscriptBytes: 100,
		},
		Showing: benchmarkIntGenISISMetrics{
			PaperTranscriptBytes: 12345,
			QBytes:               101,
			RBytes:               202,
			PdecsBytes:           303,
			AuthBytes:            404,
			TapesBytes:           505,
			VTargetsBytes:        606,
			BarSetsBytes:         707,
			LVCSNCols:            report.SmallWood.LVCSNCols,
			NLeaves:              report.SmallWood.NLeaves,
			Eta:                  report.SmallWood.Eta,
			Theta:                report.SmallWood.Theta,
			Ell:                  report.SmallWood.Ell,
			Rho:                  report.SmallWood.Rho,
			EllPrime:             report.SmallWood.EllPrime,
			RelationCandidate: benchmarkIntGenISISRelationReport{
				LogicalRows:          499,
				ParallelDegree:       9,
				AggregatedDegree:     8,
				DQParallel:           dqParallel,
				DQAggregate:          dqAggregate,
				DQ:                   dq,
				MaskDegreeBound:      dq,
				DominantDegreeSource: "compression",
				DominantDQBranch:     "parallel",
			},
		},
	}
	measured := nizkProfileReportWithMeasuredBenchmark(target, cand, report, bench, "/tmp/spruce-nizk-measured-test.json")
	if measured.MeasurementStatus != "measured" || !measured.CompilerBacked {
		t.Fatalf("measurement status not applied: %+v", measured)
	}
	if measured.Relation.LogicalRows != 499 || measured.Relation.DQ != dq {
		t.Fatalf("relation not replaced from benchmark: %+v", measured.Relation)
	}
	if measured.PaperTranscriptBytes != 12345 || measured.TranscriptBuckets.Q != 101 || measured.TranscriptBuckets.BarSets != 707 {
		t.Fatalf("buckets not replaced from benchmark: bytes=%d buckets=%+v", measured.PaperTranscriptBytes, measured.TranscriptBuckets)
	}
	if measured.MeasuredShowing == nil || measured.MeasuredIssuance == nil {
		t.Fatalf("missing measured metric digests: %+v", measured)
	}
}

func TestNIZKProfileBQ6496MeasuredReportCarriesTranscriptAudit(t *testing.T) {
	targets := nizkProfileSearchTargets()
	var target NIZKProfileSearchTarget
	for _, candidate := range targets {
		if candidate.SecurityProfile == "BQ64-96" {
			target = candidate
			break
		}
	}
	if target.SecurityProfile == "" {
		t.Fatal("missing BQ64-96 target")
	}
	var cand NIZKProfileSearchCandidate
	for _, candidate := range nizkProfileSearchCandidates() {
		if candidate.Family == "bq64_96_reduction" && candidate.Name == "baseline-h232-s224" {
			cand = candidate
			break
		}
	}
	if cand.Name == "" {
		t.Fatal("missing BQ64-96 baseline reduction candidate")
	}
	target = nizkProfileTargetForCandidate(target, cand)
	report := nizkProfileCandidateReport(target, cand)
	bench := benchmarkIntGenISISE2EReport{
		ArtifactDir: "/tmp/spruce-bq64-96-reduction-measured-test",
		Issuance:    benchmarkIntGenISISMetrics{PaperTranscriptBytes: 100},
		Showing: benchmarkIntGenISISMetrics{
			PaperTranscriptBytes: 69000,
			QBytes:               101,
			RBytes:               202,
			PdecsBytes:           303,
			AuthBytes:            404,
			TapesBytes:           505,
			VTargetsBytes:        606,
			BarSetsBytes:         707,
			LVCSNCols:            report.SmallWood.LVCSNCols,
			NLeaves:              report.SmallWood.NLeaves,
			Eta:                  report.SmallWood.Eta,
			Theta:                report.SmallWood.Theta,
			Ell:                  report.SmallWood.Ell,
			Rho:                  report.SmallWood.Rho,
			EllPrime:             report.SmallWood.EllPrime,
			TranscriptAudit: PIOP.PaperTranscriptAudit{
				Pdecs:    PIOP.OpeningResiduePaperAudit{EncodedCols: 16, OmittedCols: []int{1}, StreamBytes: 300},
				Auth:     PIOP.OpeningAuthPaperAudit{NodeCount: 96, PathDepth: 19, PathBitsBytes: 20, IndexBytes: 3, TotalBytes: 404},
				VTargets: PIOP.MatrixPayloadPaperAudit{Rows: 64, Cols: 43, BitWidth: 20, Bytes: 606},
				BarSets:  PIOP.MatrixPayloadPaperAudit{Rows: 12, Cols: 43, BitWidth: 20, Bytes: 707},
			},
			RelationCandidate: report.Relation,
		},
	}
	measured := nizkProfileReportWithMeasuredBenchmark(target, cand, report, bench, "/tmp/spruce-bq64-96-reduction-measured-test.json")
	if measured.BQ64Reduction == nil || measured.BQ64Reduction.Profile != "BQ64-96" || measured.BQ64Reduction.MeasuredAudit == nil {
		t.Fatalf("missing BQ64-96 measured reduction audit: %+v", measured.BQ64Reduction)
	}
	if measured.BQ64Reduction.Width.HashFSBits != 232 || measured.BQ64Reduction.Width.TapeBits != 160 {
		t.Fatalf("unexpected BQ64-96 width model: %+v", measured.BQ64Reduction.Width)
	}
}

func TestNIZKProfileLargeNLeavesRemainProjectionOnlyUnderCurrentQ(t *testing.T) {
	report, ok := nizkProfileReportForCandidate("BQ32-128", "bq32-nizk164-theta10-ell16-n1048576")
	if !ok {
		t.Fatal("missing large authentication-domain candidate")
	}
	if report.SmallWood.NLeaves < 1048576 {
		t.Fatalf("test selected small domain candidate: %+v", report)
	}
	if report.FrontierClass != nizkProfileFrontierCandidate {
		t.Fatalf("large-NLeaves candidate should remain allowed as a projection: %+v", report)
	}
	ok, reason := nizkProfileReportMeasurable(report)
	if ok {
		t.Fatalf("large-NLeaves candidate should not be measurable under q=%d", credential.IntGenISISSharedModulusQ)
	}
	if !strings.Contains(reason, "larger/extension-domain primitive lane") {
		t.Fatalf("unexpected unmeasurable reason: %q", reason)
	}
}

func TestNIZKProfileSearchUsesRetunedBQ3296Preset(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	if preset.SecurityProfile != "BQ32-96" || preset.CompleteSystemClaim {
		t.Fatalf("BQ32-96 security classification changed: %+v", preset)
	}
	if preset.Showing.LVCSNCols != 43 || preset.Showing.NLeaves != 442368 || preset.Showing.Eta != 45 || preset.Showing.Ell != 9 || preset.Showing.Kappa != [4]int{2, 0, 3, 13} {
		t.Fatalf("BQ32-96 tuning changed: %+v", preset.Showing)
	}
}

func TestInternalNIZKProfileSweep(t *testing.T) {
	validPrefixSweep := nizkProfileEnvBool("SPRUCE_VALID_PREFIX_SWEEP")
	if os.Getenv("SPRUCE_NIZK_PROFILE_SWEEP") != "1" && !validPrefixSweep {
		t.Skip("set SPRUCE_NIZK_PROFILE_SWEEP=1 or SPRUCE_VALID_PREFIX_SWEEP=1 to run the internal NIZK profile projection sweep")
	}
	maxPerProfile := 1
	maxPerProfileExplicit := false
	if raw := strings.TrimSpace(os.Getenv("SPRUCE_NIZK_PROFILE_SWEEP_MAX_PER_PROFILE")); raw != "" {
		maxPerProfileExplicit = true
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("invalid SPRUCE_NIZK_PROFILE_SWEEP_MAX_PER_PROFILE=%q: %v", raw, err)
		}
		if parsed >= 0 {
			maxPerProfile = parsed
		}
	}
	filter := os.Getenv("SPRUCE_NIZK_PROFILE_SWEEP_FILTER")
	if validPrefixSweep && strings.TrimSpace(filter) == "" {
		filter = "vp"
	}
	if !maxPerProfileExplicit &&
		(strings.Contains(filter, "BQ64-128") || strings.Contains(filter, "BQ96-128") || strings.Contains(filter, "BQ128-128") ||
			(nizkProfileEnvBool("SPRUCE_NIZK_PROFILE_SWEEP_MEASURED") && strings.Contains(filter, "BQ64-96"))) {
		maxPerProfile = 0
	}
	root := strings.TrimSpace(os.Getenv("SPRUCE_NIZK_PROFILE_SWEEP_ARTIFACT_ROOT"))
	if root == "" {
		root = filepath.Join(os.TempDir(), "spruce-nizk-profile-sweep")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create artifact root: %v", err)
	}
	targets := nizkProfileSearchTargets()
	results := nizkProfileReports(maxPerProfile, filter)
	candidates := nizkProfileSearchCandidatesForFilter(filter)
	if nizkProfileEnvBool("SPRUCE_NIZK_PROFILE_SWEEP_MEASURED") {
		defaultMaxE2E := 1
		if strings.Contains(filter, "BQ64-128") || strings.Contains(filter, "BQ96-128") || strings.Contains(filter, "BQ128-128") {
			defaultMaxE2E = 0
		}
		maxE2E := nizkProfileEnvInt("SPRUCE_NIZK_PROFILE_SWEEP_MAX_E2E", defaultMaxE2E)
		results = nizkProfileReportsWithMeasurements(t, results, root, maxE2E)
	}
	summary := NIZKProfileSweepSummary{
		Version:        nizkProfileSweepSummaryVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		CandidateCount: len(targets) * len(candidates),
		RunCount:       len(results),
		Targets:        targets,
		Results:        results,
		Frontiers:      nizkProfileFrontiers(results, 5),
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	path := filepath.Join(root, nizkProfileSweepSummaryFilename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	t.Logf("wrote NIZK profile research summary: %s", path)
}
