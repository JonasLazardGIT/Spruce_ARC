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
	nizkProfileSweepSummaryVersion  = 1
	nizkProfileSweepSummaryFilename = "nizk-profile-research-summary.json"

	nizkProfileBQ128RawResidualFrontierCandidate = "bq128-128-raw128-residual128-theta13-lvcs48-h512"
	nizkProfileFormalBackendFamily               = "formal_backend_sweep"

	nizkProfileFrontierCandidate              = "nizk_candidate"
	nizkProfileFrontierHighKResearch          = qBudget128CategoryHighKResearch
	nizkProfileFrontierRequiresNewPrimitives  = "requires_new_primitives"
	nizkProfileFrontierRequiresTheoremWork    = qBudget128CategoryRequiresTheoremAccounting
	nizkProfileFrontierRequiresSplitTheorem   = "requires_split_theorem"
	nizkProfileFrontierValidPrefixResearch    = "valid_prefix_research"
	nizkProfileFrontierSerializerModelBlocked = "serializer_model_blocked"
	nizkProfileFrontierRejected               = qBudget128CategoryRejected
	nizkProfileDefaultEngineeringTargetMargin = 2.0
	bq6496ReductionBaselineBytes              = 69768
	bq64128ReductionBaselineBytes             = 83223
)

type NIZKProfileSearchTarget struct {
	SecurityProfile        string                           `json:"security_profile"`
	Lane                   string                           `json:"lane"`
	TargetStatus           credential.SecurityProfileStatus `json:"target_status"`
	SecurityMode           string                           `json:"security_mode"`
	CoreBitsRequired       float64                          `json:"core_bits_required"`
	NIZKTargetBits         float64                          `json:"nizk_target_bits"`
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
	LVCSWindow                []int      `json:"lvcs_window,omitempty"`
	EtaWindow                 []int      `json:"eta_window,omitempty"`
	ThetaWindow               []int      `json:"theta_window,omitempty"`
	EllWindow                 []int      `json:"ell_window,omitempty"`
	Notes                     []string   `json:"notes,omitempty"`
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
	MeasuredArtifactDir       string                                    `json:"measured_artifact_dir,omitempty"`
	MeasuredJSON              string                                    `json:"measured_json,omitempty"`
	LedgerStatus              string                                    `json:"ledger_status"`
	LedgerReasons             []string                                  `json:"ledger_rejection_reasons,omitempty"`
	NIZKTargetBits            float64                                   `json:"nizk_target_bits"`
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
	TranscriptBuckets         qBudget128BucketDigest                    `json:"transcript_buckets"`
	PaperTranscriptBytes      int                                       `json:"paper_transcript_bytes"`
	TranscriptDrivers         []NIZKProfileTranscriptDriver             `json:"transcript_drivers,omitempty"`
	OptimizationLevers        []NIZKProfileOptimizationLever            `json:"optimization_levers,omitempty"`
	FormalBackendDiagnostics  *NIZKProfileFormalBackendDiagnostics      `json:"formal_backend_diagnostics,omitempty"`
	MeasuredIssuance          *qBudget128MetricDigest                   `json:"measured_issuance,omitempty"`
	MeasuredShowing           *qBudget128MetricDigest                   `json:"measured_showing,omitempty"`
	BQ64Reduction             *BQ64ReductionReport                      `json:"bq64_reduction,omitempty"`
	BQ64128Reduction          *BQ64128ReductionReport                   `json:"bq64_128_reduction,omitempty"`
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
	Candidate            string                     `json:"candidate"`
	Profile              string                     `json:"profile"`
	Lane                 string                     `json:"lane"`
	Model                string                     `json:"model"`
	BaselineBytes        int                        `json:"baseline_bytes"`
	TranscriptDeltaBytes int                        `json:"transcript_delta_bytes,omitempty"`
	AcceptanceStatus     string                     `json:"acceptance_status"`
	AcceptanceReasons    []string                   `json:"acceptance_reasons,omitempty"`
	Width                BQ64128WidthModel          `json:"width"`
	Serializer           BQ64128SerializerModel     `json:"serializer"`
	MeasuredAudit        *PIOP.PaperTranscriptAudit `json:"measured_audit,omitempty"`
}

type BQ64128ReductionReport = BQ64ReductionReport

type BQ64128WidthModel struct {
	HashFSBits     int    `json:"hash_fs_bits"`
	TapeBits       int    `json:"tape_bits"`
	SaltBits       int    `json:"salt_bits"`
	TagElements    int    `json:"tag_elements"`
	Classification string `json:"classification,omitempty"`
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
}

type BQ64128SerializerModel struct {
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
	RequiredKappa             [4]int                         `json:"required_kappa"`
	Eta                       int                            `json:"eta"`
	Theta                     int                            `json:"theta"`
	Ell                       int                            `json:"ell"`
	LVCSNCols                 int                            `json:"lvcs_ncols"`
	NLeaves                   int                            `json:"nleaves"`
	DQ                        int                            `json:"dq"`
	DominantDegreeSource      string                         `json:"dominant_degree_source,omitempty"`
	TranscriptBuckets         qBudget128BucketDigest         `json:"transcript_buckets"`
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
		nizkProfileSearchTargetFromRegistry("BQ64-128", "engineering", 200, 64, [2]int{264, 320}, [2]int{192, 256}, [2]int{256, 320}, [2]int{13, 14}, 256, 320),
		nizkProfileSearchTargetFromRegistry("BQ128-128", "engineering", 264, 128, [2]int{512, 512}, [2]int{256, 320}, [2]int{384, 512}, [2]int{20, 22}, 384, 512),
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
	q32Preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024Q32_128)
	if err != nil {
		return nil
	}
	bq32Base := intGenISISTuningFromPresetSpec(bq32Preset.Showing)
	q32Base := intGenISISTuningFromPresetSpec(q32Preset.Showing)
	candidates := []NIZKProfileSearchCandidate{
		nizkProfileCandidateFromTuning("control-bq32-96-current-relation", "bq32-96-current-relation", bq32Preset.Name, bq32Base, nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("control-q32-128-high-soundness", "q32-128-current-relation", q32Preset.Name, q32Base, nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("bq32-nizk164-theta10-ell16-n1048576", "bq32-current-theta10-ell16", bq32Preset.Name, nizkProfileSmallWoodOnlyCandidate(bq32Base, 10, 16, 1048576, 44), nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("bq64-nizk164-theta12-ell16-n1048576", "bq32-current-theta12-ell16", bq32Preset.Name, nizkProfileSmallWoodOnlyCandidate(bq32Base, 12, 16, 1048576, 44), nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("bq64-128-theta14-ell20-n1048576", "bq32-current-theta14-ell20", bq32Preset.Name, nizkProfileSmallWoodOnlyCandidate(bq32Base, 14, 20, 1048576, 48), nizkProfileRelationCurrentBQ32()),
		nizkProfileCandidateFromTuning("bq64-128-theta16-ell24-n1048576-lvcs48", "bq32-current-theta16-ell24", bq32Preset.Name, nizkProfileSmallWoodOnlyCandidateWithLVCS(bq32Base, 16, 24, 1048576, 48, 48), nizkProfileRelationCurrentBQ32()),
	}
	candidates = append(candidates, nizkProfileGeneratedSearchCandidates(bq32Preset.Name, bq32Base, q32Preset.Name, q32Base)...)
	candidates = append(candidates, nizkProfileBQ6496ReductionCandidates(bq32Preset.Name, bq32Base)...)
	candidates = append(candidates, nizkProfileBQ64128ReductionCandidates(bq32Preset.Name, bq32Base)...)
	candidates = append(candidates, nizkProfileValidPrefixTrailCandidates(bq32Preset.Name, bq32Base)...)
	return nizkProfileDeduplicateCandidates(candidates)
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
	return strings.Contains(lower, "formal") || qBudget128EnvBool("SPRUCE_FORMAL_BACKEND_SWEEP")
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
		showing.ReplayProjection = qBudget128ProjectionProjectUDigitsYWResidual
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
	if opts.SerializerOmission == PIOP.SmallField2025TranscriptOmissionModeDigestBoundV1 {
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
		Issuance:                    qBudget128IssuanceFromShowing(showing),
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

func nizkProfileBQ64128ReductionCandidates(presetName string, base intGenISISTuning) []NIZKProfileSearchCandidate {
	relation := nizkProfileRelationCurrentBQ32()
	baseline := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, 14, 18, 983040, 1, 43)
	mk := func(name, lane, model string, showing intGenISISTuning, opts nizkProfileCandidateOptions) NIZKProfileSearchCandidate {
		opts.Family = "bq64_128_reduction"
		opts.CompilerBacked = true
		opts.PinnedLVCS = true
		opts.DeriveEtaFloorOnly = true
		opts.ReductionLane = lane
		opts.ReductionModel = model
		if opts.TapeBitsOverride == 0 {
			opts.TapeBitsOverride = 192
		}
		if opts.SaltBitsOverride == 0 {
			opts.SaltBitsOverride = 256
		}
		if opts.TagElementsOverride == 0 {
			opts.TagElementsOverride = 13
		}
		opts.Notes = append([]string{"BQ64-128 transcript-reduction research lane; profile remains requires_new_primitives"}, opts.Notes...)
		return nizkProfileCandidateFromTuningWithOptions(name, "bq64-128-reduction-"+name, presetName, showing, relation, opts)
	}
	theta13 := baseline
	theta13.Theta = 13
	ell17 := baseline
	ell17.Ell = 17
	lvcsBreakpoint := baseline
	lvcsBreakpoint.LVCSNCols = 48
	lvcs49 := baseline
	lvcs49.LVCSNCols = 49
	lvcs50 := baseline
	lvcs50.LVCSNCols = 50
	lvcs51 := baseline
	lvcs51.LVCSNCols = 51
	lvcs52 := baseline
	lvcs52.LVCSNCols = 52
	theta13LVCS49 := theta13
	theta13LVCS49.LVCSNCols = 49
	theta13LVCS50 := theta13
	theta13LVCS50.LVCSNCols = 50
	theta13LVCS51 := theta13
	theta13LVCS51.LVCSNCols = 51
	theta13LVCS52 := theta13
	theta13LVCS52.LVCSNCols = 52
	split := baseline
	return []NIZKProfileSearchCandidate{
		mk("baseline", "baseline", "measured_control", baseline, nizkProfileCandidateOptions{
			HashFSBitsOverride: 264,
			Notes:              []string{fmt.Sprintf("measured baseline is %d bytes for r7l5-current-theta14-ell18-n983040-lvcs43", bq64128ReductionBaselineBytes)},
		}),
		mk("bare-hash256", "width_model", "hash_fs_width", baseline, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"tests the bare hash/Fiat-Shamir width model; tape remains 192 bits"},
		}),
		mk("bare-hash264", "width_model", "hash_fs_width", baseline, nizkProfileCandidateOptions{
			HashFSBitsOverride: 264,
			Notes:              []string{"tests the PDF-aligned engineering bare width; tape remains 192 bits"},
		}),
		mk("engineering-hash320", "width_model", "hash_fs_width", baseline, nizkProfileCandidateOptions{
			HashFSBitsOverride: 320,
			Notes:              []string{"tests the conservative engineering hash/Fiat-Shamir width lane; tape remains 192 bits"},
		}),
		mk("pdecs-dedup", "serializer_model", "pdecs_reconstructible_opening", baseline, nizkProfileCandidateOptions{
			HashFSBitsOverride:      264,
			SerializerOmission:      "pdecs",
			ReconstructionAvailable: true,
			OmissionMapFSBound:      true,
			Notes:                   []string{"uses the existing smallfield2025 omitted-column reconstruction model only; no new omission is live"},
		}),
		mk("vtargets-dedup", "serializer_model", "vtargets_reconstruction_required", baseline, nizkProfileCandidateOptions{
			HashFSBitsOverride: 264,
			SerializerOmission: "vtargets",
			Notes:              []string{"blocked until verifier can reconstruct VTargets byte-for-byte before DECS verification"},
		}),
		mk("auth-multiproof-audit", "serializer_model", "auth_multiproof_audit", baseline, nizkProfileCandidateOptions{
			HashFSBitsOverride: 264,
			Notes:              []string{"report-only audit of node count, depth, path bits, and index bytes"},
		}),
		mk("theta13", "smallwood_retune", "theta13", theta13, nizkProfileCandidateOptions{
			HashFSBitsOverride: 264,
			Notes:              []string{"tests whether one theta unit can be removed while keeping 200.25 showing algebraic bits"},
		}),
		mk("ell17", "smallwood_retune", "ell17", ell17, nizkProfileCandidateOptions{
			HashFSBitsOverride: 264,
			Notes:              []string{"tests whether one opening layer can be removed while preserving eps4"},
		}),
		mk("lvcs-breakpoint", "smallwood_retune", "lvcs_breakpoint_48", lvcsBreakpoint, nizkProfileCandidateOptions{
			HashFSBitsOverride: 264,
			Notes:              []string{"tests the next LVCS row-block breakpoint without changing the safe relation"},
		}),
		mk("lvcs49-h256", "smallwood_retune", "lvcs_breakpoint_49", lvcs49, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"dense LVCS probe below the known LVCS53 high-k cliff; VTargets and BarSets remain explicit"},
		}),
		mk("lvcs50-h256", "smallwood_retune", "lvcs_breakpoint_50", lvcs50, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"dense LVCS probe below the known LVCS53 high-k cliff; VTargets and BarSets remain explicit"},
		}),
		mk("lvcs51-h256", "smallwood_retune", "lvcs_breakpoint_51", lvcs51, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"dense LVCS probe below the known LVCS53 high-k cliff; VTargets and BarSets remain explicit"},
		}),
		mk("lvcs52-h256", "smallwood_retune", "lvcs_breakpoint_52", lvcs52, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"dense LVCS probe below the known LVCS53 high-k cliff; VTargets and BarSets remain explicit"},
		}),
		mk("theta13-lvcs49-h256", "smallwood_retune", "theta13_lvcs49", theta13LVCS49, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"byte-aggressive theta13 dense LVCS probe; expected to classify by exact grinding requirement"},
		}),
		mk("theta13-lvcs50-h256", "smallwood_retune", "theta13_lvcs50", theta13LVCS50, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"byte-aggressive theta13 dense LVCS probe; expected to classify by exact grinding requirement"},
		}),
		mk("theta13-lvcs51-h256", "smallwood_retune", "theta13_lvcs51", theta13LVCS51, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"byte-aggressive theta13 dense LVCS probe; expected to classify by exact grinding requirement"},
		}),
		mk("theta13-lvcs52-h256", "smallwood_retune", "theta13_lvcs52", theta13LVCS52, nizkProfileCandidateOptions{
			HashFSBitsOverride: 256,
			Notes:              []string{"byte-aggressive theta13 dense LVCS probe; expected to classify by exact grinding requirement"},
		}),
		mk("split-shortness-research", "split_theorem", "split_shortness", split, nizkProfileCandidateOptions{
			HashFSBitsOverride:        264,
			RequiresTheoremAccounting: true,
			RequiresSplitTheorem:      true,
			Notes:                     []string{"separates high-degree shortness only as theorem research; never selected as a theorem-valid reduction"},
		}),
	}
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
			SerializerOmission:      PIOP.SmallField2025TranscriptOmissionModeDigestBoundV1,
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
			SerializerOmission:          PIOP.SmallField2025TranscriptOmissionModeDigestBoundV1,
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
			SerializerOmission:          PIOP.SmallField2025TranscriptOmissionModeDigestBoundV1,
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
			SerializerOmission:          PIOP.SmallField2025TranscriptOmissionModeDigestBoundV1,
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
	return qBudget128BoundedUniqueInts(vals, minLVCS, 256)
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
	out.ReplayProjection = qBudget128ProjectionProjectUDigitsYWResidual
	return out
}

func nizkProfileMixedRadixCandidate(base intGenISISTuning) intGenISISTuning {
	out := base
	out.SigShortnessRadix = 11
	out.SigShortnessDigits = 4
	out.CompressedRows = 1
	out.ReplayProjection = qBudget128ProjectionProjectUDigitsYWResidual
	return out
}

func nizkProfileSplitShortnessCandidate(base intGenISISTuning) intGenISISTuning {
	out := base
	out.SigShortnessRadix = 7
	out.SigShortnessDigits = 5
	out.CompressedRows = 0
	out.ReplayProjection = qBudget128ProjectionProjectUDigitsYWResidual
	return out
}

func nizkProfileFullR2Candidate(base intGenISISTuning) intGenISISTuning {
	out := base
	out.SigShortnessRadix = 2
	out.SigShortnessDigits = 13
	out.CompressedRows = 0
	out.ReplayProjection = qBudget128ProjectionProjectUDigitsYWResidual
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
	out.ReplayProjection = qBudget128ProjectionProjectUDigitsYWResidual
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
	baseline := nizkProfileRelationForEll(nizkProfileRelationCurrentBQ32(), ell)
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
	if relation.DQ > baseline.DQ {
		out.RejectionReasons = append(out.RejectionReasons, fmt.Sprintf("candidate dQ %d exceeds current safe dQ %d", relation.DQ, baseline.DQ))
	}
	if relation.LogicalRows > baseline.LogicalRows && relation.DQ >= baseline.DQ {
		out.RejectionReasons = append(out.RejectionReasons, fmt.Sprintf("candidate rows %d exceed current safe rows %d without a dQ reduction", relation.LogicalRows, baseline.LogicalRows))
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
	roundBits := nizkProfileProjectedRoundBits(target, relation, smallwood)
	algebraicBits := nizkProfileAggregateBits(roundBits)
	buckets := nizkProfileProjectedBuckets(target, relation, smallwood)
	buckets = nizkProfileApplyProjectedSerializerOmission(cand, buckets)
	paperTranscriptBytes := buckets.Q + buckets.R + buckets.Pdecs + buckets.Auth + buckets.Tapes + buckets.VTargets + buckets.BarSets + buckets.SigShortness
	formalDiagnostics := nizkProfileFormalBackendDiagnostics(target, cand, relation, smallwood, paperTranscriptBytes)
	lvcsAboveRing := formalDiagnostics != nil && formalDiagnostics.LVCSAboveRing
	ledgerStatus := string(credential.SecurityProfileRequiresNewPrimitives)
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
		IssuanceAlgebraicBits:     algebraicBits,
		ShowingAlgebraicBits:      algebraicBits,
		AlgebraicRoundBits:        roundBits,
		TranscriptBuckets:         buckets,
		PaperTranscriptBytes:      paperTranscriptBytes,
		ValidPrefixCost:           nizkProfileValidPrefixCostReport(target, cand, nil),
		Notes:                     append([]string(nil), cand.Notes...),
		FormalBackendDiagnostics:  formalDiagnostics,
	}
	report.BQ64Reduction = bq64ReductionReport(target, cand, report, nil)
	report.BQ64128Reduction = bq64128ReductionReport(target, cand, report, nil)
	report.TranscriptDrivers = nizkProfileTranscriptDrivers(report.TranscriptBuckets, report.PaperTranscriptBytes)
	report.OptimizationLevers = nizkProfileOptimizationLevers(target, relation, report.SmallWood, report.TranscriptBuckets)
	report.FrontierClass = nizkProfileFrontierClass(report)
	return report
}

func nizkProfileApplyProjectedSerializerOmission(cand NIZKProfileSearchCandidate, buckets qBudget128BucketDigest) qBudget128BucketDigest {
	switch cand.SerializerOmission {
	case PIOP.SmallField2025TranscriptOmissionModeDigestBoundV1:
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
	return []string{
		fmt.Sprintf("core primitive family must support %.0f-bit lattice/PRF/key security", target.CoreBitsRequired),
		fmt.Sprintf("query semantics reserve a 2^%d random-oracle/adversary budget", target.QueryCapExponent),
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
	eta := maxInt(base.Eta, etaFloor)
	if deriveEtaFloorOnly {
		eta = etaFloor
	}
	notes := []string{"eta is derived from the NIZK target term and kept as a floor; no wide eta sweep"}
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
		LVCSWindow: qBudget128BoundedUniqueInts([]int{
			lvcs - 3, lvcs - 2, lvcs - 1, lvcs, lvcs + 1, lvcs + 2, lvcs + 3,
		}, maxInt(base.NCols, 1), maxInt(96, lvcs+3)),
		EtaWindow:   []int{eta},
		ThetaWindow: positiveWindow(maxInt(base.Theta, 1), 1),
		EllWindow:   positiveWindow(maxInt(base.Ell, 1), 1),
		Notes:       notes,
	}
	out.RequiredKappa = nizkProfileRequiredKappa(target, relation, out)
	for i := range out.RequiredKappa {
		out.Kappa[i] = out.RequiredKappa[i]
		if out.Kappa[i] > qBudget128MaxSupportedGrinding {
			out.Kappa[i] = qBudget128MaxSupportedGrinding
		}
	}
	return out
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

func nizkProfileProjectedBuckets(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport) qBudget128BucketDigest {
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
	return qBudget128BucketDigest{
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

func bq64128ReductionReport(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, report NIZKProfileCandidateReport, measured *PIOP.PaperTranscriptAudit) *BQ64128ReductionReport {
	if target.SecurityProfile != "BQ64-128" {
		return nil
	}
	return bq64ReductionReport(target, cand, report, measured)
}

func bq64ReductionReport(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, report NIZKProfileCandidateReport, measured *PIOP.PaperTranscriptAudit) *BQ64ReductionReport {
	if !bq64ReductionCandidateApplies(target, cand) {
		return nil
	}
	width := bq64ReductionWidthModel(target)
	serializer := bq64128SerializerModel(cand)
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
	switch target.SecurityProfile {
	case "BQ64-96":
		return cand.Family == "bq64_96_reduction"
	case "BQ64-128":
		return cand.Family == "bq64_128_reduction" || cand.TargetProfile == "BQ64-128"
	default:
		return false
	}
}

func bq64ReductionBaselineBytes(profile string) int {
	switch profile {
	case "BQ64-96":
		return bq6496ReductionBaselineBytes
	case "BQ64-128":
		return bq64128ReductionBaselineBytes
	default:
		return 0
	}
}

func bq64ReductionTargetBits(profile string) float64 {
	switch profile {
	case "BQ64-96":
		return 164.25
	case "BQ64-128":
		return 200.25
	default:
		return math.Inf(1)
	}
}

func bq64ReductionWidthModel(target NIZKProfileSearchTarget) BQ64128WidthModel {
	width := BQ64128WidthModel{
		HashFSBits:  target.HashFSBitsRange[0],
		TapeBits:    target.TapeBitsRange[0],
		SaltBits:    target.SaltBitsRange[0],
		TagElements: target.TagElementsRange[0],
		Status:      "pass",
	}
	switch target.SecurityProfile {
	case "BQ64-96":
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
	case "BQ64-128":
		width.Classification = "bare"
		width.Reason = "BQ64-128 width candidate keeps tape=192, salt=256, and tag lane=13"
		switch width.HashFSBits {
		case 320:
			width.Classification = "engineering"
		case 256:
			width.Classification = "measured_research"
			width.Reason = "BQ64-128 256-bit hash/FS lane is measured research and must pass ledger width review"
		case 264:
			width.Classification = "bare"
		default:
			width.Classification = "custom_research"
		}
		if width.HashFSBits < 256 {
			width.Status = "fail_closed"
			width.Reason = "BQ64-128 hash/FS width below 256 is outside the accepted research lanes"
		}
		if width.TapeBits < 192 {
			width.Status = "fail_closed"
			width.Reason = "BQ64-128 tape width below 192 would lose the 2^64 residual tape-guessing margin"
		}
		if width.SaltBits < 256 {
			width.Status = "fail_closed"
			width.Reason = "BQ64-128 salt width below 256 is outside the profile target"
		}
		if width.TagElements < 13 {
			width.Status = "fail_closed"
			width.Reason = "BQ64-128 tag lane below 13 is outside the profile target"
		}
	default:
		width.Status = "fail_closed"
		width.Reason = "not a BQ64 reduction profile"
	}
	return width
}

func bq64128SerializerModel(cand NIZKProfileSearchCandidate) BQ64128SerializerModel {
	model := BQ64128SerializerModel{
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
	case PIOP.SmallField2025TranscriptOmissionModeDigestBoundV1:
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
	if report.SecurityProfile != "BQ64-96" && report.SecurityProfile != "BQ64-128" {
		reasons = append(reasons, "not a BQ64 reduction profile")
	}
	if report.ShowingAlgebraicBits+1e-9 < targetBits {
		reasons = append(reasons, fmt.Sprintf("showing algebraic bits %.2f < %.2f", report.ShowingAlgebraicBits, targetBits))
	}
	for _, kappa := range report.SmallWood.RequiredKappa {
		if kappa > qBudget128MaxSupportedGrinding {
			reasons = append(reasons, fmt.Sprintf("required grinding %d > supported cap %d", kappa, qBudget128MaxSupportedGrinding))
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
	return qBudget128UniqueStrings(reasons)
}

func nizkProfileTranscriptDrivers(buckets qBudget128BucketDigest, total int) []NIZKProfileTranscriptDriver {
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

func nizkProfileOptimizationLevers(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport, buckets qBudget128BucketDigest) []NIZKProfileOptimizationLever {
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
	if report.RequiresSplitTheorem {
		return nizkProfileFrontierRequiresSplitTheorem
	}
	if report.BQ64Reduction != nil && report.BQ64Reduction.Serializer.Status == "blocked" {
		return nizkProfileFrontierSerializerModelBlocked
	}
	for _, kappa := range report.SmallWood.RequiredKappa {
		if kappa > qBudget128MaxSupportedGrinding {
			return nizkProfileFrontierHighKResearch
		}
	}
	if report.UsesValidPrefixAccounting {
		if report.IssuanceAlgebraicBits >= report.NIZKTargetBits && report.ShowingAlgebraicBits >= report.NIZKTargetBits {
			return nizkProfileFrontierValidPrefixResearch
		}
		return nizkProfileFrontierRequiresTheoremWork
	}
	if report.RequiresTheoremWork {
		return nizkProfileFrontierRequiresTheoremWork
	}
	if report.IssuanceAlgebraicBits >= report.NIZKTargetBits && report.ShowingAlgebraicBits >= report.NIZKTargetBits {
		return nizkProfileFrontierCandidate
	}
	if report.TargetStatus == credential.SecurityProfileRequiresNewPrimitives {
		return nizkProfileFrontierRequiresNewPrimitives
	}
	return nizkProfileFrontierRejected
}

func nizkProfileReports(maxPerProfile int, filter string) []NIZKProfileCandidateReport {
	targets := nizkProfileSearchTargets()
	candidates := nizkProfileSearchCandidatesForFilter(filter)
	filter = strings.TrimSpace(filter)
	validPrefixEnabled := qBudget128EnvBool("SPRUCE_VALID_PREFIX_SWEEP") || strings.Contains(strings.ToLower(filter), "vp") || strings.Contains(strings.ToLower(filter), "valid-prefix") || strings.Contains(strings.ToLower(filter), "valid_prefix")
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
			if cand.Family == "bq64_96_reduction" || cand.Family == "bq64_128_reduction" {
				wantProfile := "BQ64-128"
				if cand.Family == "bq64_96_reduction" {
					wantProfile = "BQ64-96"
				}
				if target.SecurityProfile != wantProfile {
					continue
				}
				if filter == "" || (!strings.Contains(wantProfile, filter) && !strings.Contains(cand.Name, filter) && !strings.Contains(cand.RelationEncoding, filter)) {
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

func nizkProfileReportsWithMeasurements(t *testing.T, reports []NIZKProfileCandidateReport, root string, maxE2E int) []NIZKProfileCandidateReport {
	t.Helper()
	if maxE2E <= 0 || len(reports) == 0 {
		return reports
	}
	nizkProfileChdirRepoRoot(t)
	targets := make(map[string]NIZKProfileSearchTarget)
	for _, target := range nizkProfileSearchTargets() {
		targets[target.SecurityProfile] = target
	}
	candidates := make(map[string]NIZKProfileSearchCandidate)
	for _, cand := range nizkProfileSearchCandidatesForReports(reports) {
		candidates[cand.Name] = cand
	}
	out := append([]NIZKProfileCandidateReport(nil), reports...)
	runCount := 0
	for i, report := range out {
		if runCount >= maxE2E {
			break
		}
		if !nizkProfileShouldMeasureReport(report) {
			continue
		}
		if ok, reason := nizkProfileReportMeasurable(report); !ok {
			out[i].MeasurementStatus = "measurement_domain_blocked"
			out[i].MeasurementError = reason
			continue
		}
		target, ok := targets[report.SecurityProfile]
		if !ok {
			out[i].MeasurementStatus = "measurement_failed"
			out[i].MeasurementError = "missing search target"
			continue
		}
		cand, ok := candidates[report.Candidate]
		if !ok {
			out[i].MeasurementStatus = "measurement_failed"
			out[i].MeasurementError = "missing search candidate"
			continue
		}
		target = nizkProfileTargetForCandidate(target, cand)
		cfg, err := nizkProfileBenchmarkConfig(target, cand, report, root, runCount+1)
		if err != nil {
			out[i].MeasurementStatus = "measurement_failed"
			out[i].MeasurementError = err.Error()
			continue
		}
		runCount++
		bench, err := benchmarkIntGenISISE2E(cfg)
		if err != nil {
			out[i].MeasurementStatus = "measurement_failed"
			out[i].MeasurementError = err.Error()
			out[i].MeasuredArtifactDir = cfg.ArtifactDir
			out[i].MeasuredJSON = cfg.JSONOut
			t.Logf("NIZK measured benchmark failed for %s/%s: %v", report.SecurityProfile, report.Candidate, err)
			continue
		}
		out[i] = nizkProfileReportWithMeasuredBenchmark(target, cand, report, bench, cfg.JSONOut)
		t.Logf("NIZK measured benchmark %s/%s paper_bytes=%d relation_rows=%d dQ=%d", report.SecurityProfile, report.Candidate, out[i].PaperTranscriptBytes, out[i].Relation.LogicalRows, out[i].Relation.DQ)
	}
	return out
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
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
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
	issuance := qBudget128IssuanceFromShowing(showing)
	name := fmt.Sprintf("%03d-%s-%s", idx, qBudget128SanitizeLabel(target.SecurityProfile), qBudget128SanitizeLabel(cand.Name))
	maxNLeaves := maxInt(preset.MaxNLeaves, maxInt(issuance.NLeaves, showing.NLeaves))
	return benchmarkIntGenISISE2EConfig{
		ArtifactDir:         filepath.Join(root, name),
		PresetName:          fmt.Sprintf("%s:%s:%s", preset.Name, target.SecurityProfile, cand.Name),
		Profile:             preset.Profile,
		SecurityProfile:     target.SecurityProfile,
		SecurityMode:        target.SecurityMode,
		CoreBitsRequired:    target.CoreBitsRequired,
		CompleteSystemClaim: false,
		PRFProfile:          preset.PRFProfile,
		PRFParamsPath:       preset.PRFParamsPath,
		JSONOut:             filepath.Join(root, name+".json"),
		Force:               true,
		Seed:                29,
		Issuance:            issuance,
		Showing:             showing,
		KeygenTrials:        10000,
		KeygenAttempts:      defaultNTRUKeygenAttempts,
		NTRUBeta:            preset.NTRUBeta,
		MaxTrials:           2048,
		MaxNLeaves:          maxNLeaves,
	}, nil
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
	raw := float64(target.QueryCapExponent)
	tuning.ROQueryCaps = [5]int{}
	tuning.ROQueryCapsSet = false
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
	for i := range out.SmallWood.RequiredKappa {
		out.SmallWood.Kappa[i] = out.SmallWood.RequiredKappa[i]
		if out.SmallWood.Kappa[i] > qBudget128MaxSupportedGrinding {
			out.SmallWood.Kappa[i] = qBudget128MaxSupportedGrinding
		}
	}
	out.AlgebraicRoundBits = nizkProfileProjectedRoundBits(target, relation, out.SmallWood)
	out.IssuanceAlgebraicBits = nizkProfileAggregateBits(out.AlgebraicRoundBits)
	out.ShowingAlgebraicBits = out.IssuanceAlgebraicBits
	out.RelationSafety = nizkProfileRelationSafety(cand, relation, out.SmallWood.Ell)
	out.TranscriptBuckets = qBudget128BucketDigest{
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
	out.FormalBackendCandidate = cand.FormalBackendCandidate
	out.FormalBackendDiagnostics = nizkProfileFormalBackendDiagnostics(target, cand, relation, out.SmallWood, out.PaperTranscriptBytes)
	out.LVCSAboveRing = out.FormalBackendDiagnostics != nil && out.FormalBackendDiagnostics.LVCSAboveRing
	issuance := qBudget128MetricDigestFromMetrics(bench.Issuance)
	showing := qBudget128MetricDigestFromMetrics(bench.Showing)
	out.MeasuredIssuance = &issuance
	out.MeasuredShowing = &showing
	out.ValidPrefixCost = nizkProfileValidPrefixCostReport(target, cand, bench.Showing.PhaseTimings)
	out.BQ64Reduction = bq64ReductionReport(target, cand, out, &bench.Showing.TranscriptAudit)
	out.BQ64128Reduction = bq64128ReductionReport(target, cand, out, &bench.Showing.TranscriptAudit)
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
	if (a.Family == "bq64_96_reduction" || a.Family == "bq64_128_reduction" || b.Family == "bq64_96_reduction" || b.Family == "bq64_128_reduction") && a.SecurityProfile == b.SecurityProfile {
		if a.Family != b.Family {
			if nizkProfileIsBQ64ReductionFamily(a.Family) != nizkProfileIsBQ64ReductionFamily(b.Family) {
				return nizkProfileIsBQ64ReductionFamily(a.Family)
			}
			return nizkProfileFamilyRank(a.Family) < nizkProfileFamilyRank(b.Family)
		}
		if a.Family == "bq64_96_reduction" || a.Family == "bq64_128_reduction" {
			if bq64ReductionCandidateRank(a.SecurityProfile, a.Candidate) != bq64ReductionCandidateRank(b.SecurityProfile, b.Candidate) {
				return bq64ReductionCandidateRank(a.SecurityProfile, a.Candidate) < bq64ReductionCandidateRank(b.SecurityProfile, b.Candidate)
			}
			return a.Candidate < b.Candidate
		}
	}
	if a.FrontierClass != b.FrontierClass {
		return nizkProfileFrontierRank(a.FrontierClass) < nizkProfileFrontierRank(b.FrontierClass)
	}
	if a.FrontierClass == nizkProfileFrontierCandidate {
		if a.PaperTranscriptBytes != b.PaperTranscriptBytes {
			return a.PaperTranscriptBytes < b.PaperTranscriptBytes
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
	return family == "bq64_96_reduction" || family == "bq64_128_reduction"
}

func bq64ReductionCandidateRank(profile, name string) int {
	if profile == "BQ64-96" {
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
	switch name {
	case "baseline":
		return 0
	case "bare-hash256":
		return 1
	case "bare-hash264":
		return 2
	case "engineering-hash320":
		return 3
	case "pdecs-dedup":
		return 4
	case "vtargets-dedup":
		return 5
	case "auth-multiproof-audit":
		return 6
	case "theta13":
		return 7
	case "ell17":
		return 8
	case "lvcs-breakpoint":
		return 9
	case "lvcs49-h256":
		return 10
	case "lvcs50-h256":
		return 11
	case "lvcs51-h256":
		return 12
	case "lvcs52-h256":
		return 13
	case "theta13-lvcs49-h256":
		return 14
	case "theta13-lvcs50-h256":
		return 15
	case "theta13-lvcs51-h256":
		return 16
	case "theta13-lvcs52-h256":
		return 17
	case "split-shortness-research":
		return 18
	default:
		return 100
	}
}

func nizkProfileFamilyRank(family string) int {
	switch family {
	case "current_r7_l5":
		return 0
	case "mixed_radix_topcap":
		return 1
	case "r11_l4_topcap":
		return 2
	case "q32_control":
		return 3
	case "row_compression_high_degree":
		return 4
	case "full_r2_decomposition":
		return 5
	case "split_shortness_theorem_track", "r121_l2_lookup_theorem_track":
		return 6
	case "bq64_96_reduction":
		return 7
	case "bq64_128_reduction":
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
		sort.SliceStable(entries, func(i, j int) bool {
			return nizkProfileReportLess(entries[i], entries[j])
		})
		for i, result := range entries {
			if i >= limit {
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
	case "BQ128-128":
		return 3
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
	want := []string{"BQ32-128", "BQ64-96", "BQ64-128", "BQ128-128"}
	if len(targets) != len(want) {
		t.Fatalf("targets=%v want %v", targets, want)
	}
	for i, target := range targets {
		if target.SecurityProfile != want[i] {
			t.Fatalf("target order=%v want %v", targets, want)
		}
		if target.TargetStatus != credential.SecurityProfileRequiresNewPrimitives {
			t.Fatalf("%s status=%q want %q", target.SecurityProfile, target.TargetStatus, credential.SecurityProfileRequiresNewPrimitives)
		}
		if target.PrimitiveBlockerReason == "" || target.NIZKTargetBits <= 0 || target.CoreBitsRequired <= 0 {
			t.Fatalf("incomplete target: %+v", target)
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
	reports := nizkProfileReports(0, "BQ64-96")
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

func TestNIZKProfileBQ64128ReductionCandidatesOrderAndWidthModel(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	candidates := nizkProfileBQ64128ReductionCandidates(preset.Name, intGenISISTuningFromPresetSpec(preset.Showing))
	want := []string{
		"baseline",
		"bare-hash256",
		"bare-hash264",
		"engineering-hash320",
		"pdecs-dedup",
		"vtargets-dedup",
		"auth-multiproof-audit",
		"theta13",
		"ell17",
		"lvcs-breakpoint",
		"lvcs49-h256",
		"lvcs50-h256",
		"lvcs51-h256",
		"lvcs52-h256",
		"theta13-lvcs49-h256",
		"theta13-lvcs50-h256",
		"theta13-lvcs51-h256",
		"theta13-lvcs52-h256",
		"split-shortness-research",
	}
	if len(candidates) != len(want) {
		t.Fatalf("candidates=%d want %d", len(candidates), len(want))
	}
	for i, cand := range candidates {
		if cand.Name != want[i] {
			t.Fatalf("candidate order[%d]=%q want %q", i, cand.Name, want[i])
		}
		if cand.Family != "bq64_128_reduction" {
			t.Fatalf("%s family=%q", cand.Name, cand.Family)
		}
		if cand.TapeBitsOverride != 192 {
			t.Fatalf("%s tape override=%d want 192", cand.Name, cand.TapeBitsOverride)
		}
		if cand.SaltBitsOverride != 256 || cand.TagElementsOverride != 13 {
			t.Fatalf("%s width overrides salt=%d tag=%d", cand.Name, cand.SaltBitsOverride, cand.TagElementsOverride)
		}
	}
}

func TestNIZKProfileBQ64128ReductionReportsFailClosed(t *testing.T) {
	reports := nizkProfileReports(0, "BQ64-128")
	seen := map[string]NIZKProfileCandidateReport{}
	for _, report := range reports {
		if report.Family == "bq64_128_reduction" {
			seen[report.Candidate] = report
		}
	}
	for _, want := range []string{"baseline", "bare-hash256", "bare-hash264", "engineering-hash320", "pdecs-dedup", "vtargets-dedup", "auth-multiproof-audit", "theta13", "ell17", "lvcs-breakpoint", "lvcs49-h256", "lvcs50-h256", "lvcs51-h256", "lvcs52-h256", "theta13-lvcs49-h256", "theta13-lvcs50-h256", "theta13-lvcs51-h256", "theta13-lvcs52-h256", "split-shortness-research"} {
		report, ok := seen[want]
		if !ok {
			t.Fatalf("missing BQ64-128 reduction report %q", want)
		}
		if report.BQ64Reduction == nil {
			t.Fatalf("%s missing generic BQ64 reduction report", want)
		}
		if report.BQ64128Reduction == nil {
			t.Fatalf("%s missing reduction report", want)
		}
		if report.BQ64128Reduction.Width.TapeBits != 192 {
			t.Fatalf("%s tape bits=%d want 192", want, report.BQ64128Reduction.Width.TapeBits)
		}
	}
	if got := seen["bare-hash256"].BQ64128Reduction.Width.HashFSBits; got != 256 {
		t.Fatalf("bare-hash256 hash width=%d want 256", got)
	}
	if got := seen["bare-hash264"].BQ64128Reduction.Width.HashFSBits; got != 264 {
		t.Fatalf("bare-hash264 hash width=%d want 264", got)
	}
	if got := seen["engineering-hash320"].BQ64128Reduction.Width.Classification; got != "engineering" {
		t.Fatalf("engineering-hash320 classification=%q want engineering", got)
	}
	if got := seen["bare-hash256"].BQ64128Reduction.Width.Classification; got != "measured_research" {
		t.Fatalf("bare-hash256 classification=%q want measured_research", got)
	}
	if seen["vtargets-dedup"].FrontierClass != nizkProfileFrontierSerializerModelBlocked {
		t.Fatalf("vtargets-dedup frontier=%q want %q", seen["vtargets-dedup"].FrontierClass, nizkProfileFrontierSerializerModelBlocked)
	}
	if seen["vtargets-dedup"].BQ64128Reduction.Serializer.ReconstructionAvailable || seen["vtargets-dedup"].BQ64128Reduction.Serializer.OmissionMapFSBound {
		t.Fatalf("vtargets-dedup should remain blocked without reconstruction: %+v", seen["vtargets-dedup"].BQ64128Reduction.Serializer)
	}
	if got := seen["pdecs-dedup"].BQ64128Reduction.Serializer.Status; got != "serializer_safe_existing_path" {
		t.Fatalf("pdecs-dedup serializer status=%q", got)
	}
	if seen["split-shortness-research"].FrontierClass != nizkProfileFrontierRequiresSplitTheorem {
		t.Fatalf("split frontier=%q want %q", seen["split-shortness-research"].FrontierClass, nizkProfileFrontierRequiresSplitTheorem)
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
	reports := nizkProfileReports(0, "vp")
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
	for _, cand := range nizkProfileSearchCandidates() {
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

func TestNIZKProfileBQ128RawResidual128UsesRawCaps(t *testing.T) {
	reports := nizkProfileReports(0, "raw128-residual128-theta13-lvcs48")
	if len(reports) != 1 {
		t.Fatalf("reports=%d want 1", len(reports))
	}
	report := reports[0]
	if report.Candidate != nizkProfileBQ128RawResidualFrontierCandidate {
		t.Fatalf("candidate=%q want %q", report.Candidate, nizkProfileBQ128RawResidualFrontierCandidate)
	}
	if report.SecurityProfile != "BQ128-128" || report.NIZKTargetBits != 128 || report.RawQueryCapLog2 != 128 {
		t.Fatalf("unexpected residual target report: %+v", report)
	}
	if report.TargetStatus != credential.SecurityProfileRequiresNewPrimitives ||
		report.LedgerStatus != string(credential.SecurityProfileRequiresNewPrimitives) ||
		report.CoreBitsRequired != 256 ||
		report.PrimitiveBlockerReason == "" {
		t.Fatalf("residual target must remain primitive-blocked: %+v", report)
	}
	if report.UsesValidPrefixAccounting || report.EffectiveAlgebraicCapLog2 != [4]float64{128, 128, 128, 128} {
		t.Fatalf("residual target should use raw algebraic caps: %+v", report)
	}
	if report.SmallWood.Theta != 13 || report.SmallWood.Ell != 18 || report.SmallWood.NLeaves != 983040 {
		t.Fatalf("unexpected residual target shape: %+v", report.SmallWood)
	}
	if report.SmallWood.RequiredKappa[2] > qBudget128MaxSupportedGrinding || report.ShowingAlgebraicBits < 128 {
		t.Fatalf("theta13 residual target should clear the raw 2^128 residual-128 lane: %+v", report)
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

func TestNIZKProfileTheta13EligibleOnlyWithExplicitValidPrefixCap(t *testing.T) {
	rawReports := nizkProfileReports(0, "BQ64-128")
	var rawTheta13 NIZKProfileCandidateReport
	for _, report := range rawReports {
		if report.Family == "bq64_128_reduction" && report.Candidate == "theta13" {
			rawTheta13 = report
			break
		}
	}
	if rawTheta13.Candidate == "" {
		t.Fatal("missing raw theta13 report")
	}
	if rawTheta13.SmallWood.RequiredKappa[2] <= qBudget128MaxSupportedGrinding || rawTheta13.FrontierClass != nizkProfileFrontierHighKResearch {
		t.Fatalf("raw theta13 should exceed grinding under raw caps: %+v", rawTheta13)
	}
	vpReports := nizkProfileReports(0, "bq64-128-vp-theta13")
	var vpTheta13 NIZKProfileCandidateReport
	for _, report := range vpReports {
		if report.Candidate == "bq64-128-vp-theta13-h256" {
			vpTheta13 = report
			break
		}
	}
	if vpTheta13.Candidate == "" {
		t.Fatalf("missing non-serializer vp theta13 report in %d reports", len(vpReports))
	}
	if !vpTheta13.UsesValidPrefixAccounting || vpTheta13.EffectiveAlgebraicCapLog2[2] != 61 {
		t.Fatalf("vp theta13 missing explicit round-3 cap: %+v", vpTheta13)
	}
	if vpTheta13.SmallWood.RequiredKappa[2] > qBudget128MaxSupportedGrinding {
		t.Fatalf("vp theta13 should be within supported grinding: %+v", vpTheta13.SmallWood.RequiredKappa)
	}
	if vpTheta13.FrontierClass != nizkProfileFrontierValidPrefixResearch {
		t.Fatalf("vp theta13 frontier=%q want %q", vpTheta13.FrontierClass, nizkProfileFrontierValidPrefixResearch)
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
	reports := nizkProfileReports(0, "theta11-lvcs43-h232")
	if len(reports) != 1 {
		t.Fatalf("theta11 reports=%d want 1", len(reports))
	}
	report := reports[0]
	if report.SecurityProfile != "BQ64-96" || report.Candidate != "theta11-lvcs43-h232" {
		t.Fatalf("unexpected report selected: %+v", report)
	}
	if report.AlgebraicAccounting.TheoremMode != credential.ValidPrefixTheoremModeCurrentRaw || report.UsesValidPrefixAccounting {
		t.Fatalf("BQ64-96 theta11 should use raw current-theorem accounting: %+v", report.AlgebraicAccounting)
	}
	if report.SmallWood.RequiredKappa[2] <= qBudget128MaxSupportedGrinding || report.ShowingAlgebraicBits >= bq64ReductionTargetBits("BQ64-96") {
		t.Fatalf("BQ64-96 theta11 should remain below target/over grinding cap: %+v", report)
	}
	if report.FrontierClass != nizkProfileFrontierHighKResearch {
		t.Fatalf("BQ64-96 theta11 frontier=%q want high-k research", report.FrontierClass)
	}
}

func TestNIZKProfileRelationSafetyCertificatesCurrentTheoremBoundary(t *testing.T) {
	reports := nizkProfileReports(0, "BQ64-128")
	seen := map[string]NIZKProfileCandidateReport{}
	for _, report := range reports {
		if report.Family == "bq64_128_reduction" {
			seen[report.Candidate] = report
		}
	}
	lvcs := seen["lvcs-breakpoint"]
	if lvcs.Candidate == "" {
		t.Fatal("missing lvcs-breakpoint report")
	}
	if !lvcs.RelationSafety.CurrentTheoremSafe || lvcs.RelationSafety.CertificateStatus != "current_theorem_safe" {
		t.Fatalf("safe LVCS relation should have a current-theorem certificate: %+v", lvcs.RelationSafety)
	}
	split := seen["split-shortness-research"]
	if split.Candidate == "" {
		t.Fatal("missing split-shortness report")
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
	reports := nizkProfileReports(0, "vtargets-included")
	seen := map[string]NIZKProfileCandidateReport{}
	for _, report := range reports {
		seen[report.Candidate] = report
	}
	want := []string{
		"bq64-128-vp-theta13-h256-vtargets-included-pdecs",
		"bq128-128-vp64-lvcs48-h512-vtargets-included-pdecs",
		"bq128-128-vp80-search-vtargets-included-pdecs",
	}
	for _, name := range want {
		report, ok := seen[name]
		if !ok {
			t.Fatalf("missing optimized serializer candidate %q", name)
		}
		if report.TranscriptBuckets.VTargets == 0 || report.TranscriptBuckets.BarSets == 0 {
			t.Fatalf("%s incorrectly omitted matrix payloads: %+v", name, report.TranscriptBuckets)
		}
		if report.FrontierClass != nizkProfileFrontierValidPrefixResearch {
			t.Fatalf("%s frontier=%q want %q", name, report.FrontierClass, nizkProfileFrontierValidPrefixResearch)
		}
	}
	bq64 := seen["bq64-128-vp-theta13-h256-vtargets-included-pdecs"]
	if bq64.PaperTranscriptBytes < 70000 {
		t.Fatalf("BQ64 corrected serializer target projected bytes=%d should include VTargets/BarSets", bq64.PaperTranscriptBytes)
	}
	rawReports := nizkProfileReports(0, "raw128-control-vtargets-included-pdecs")
	if len(rawReports) != 1 {
		t.Fatalf("raw serializer reports=%d want 1", len(rawReports))
	}
	raw := rawReports[0]
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
			RequiredKappa: [4]int{0, 0, qBudget128MaxSupportedGrinding + 1, 0},
		},
	}
	if got := nizkProfileFrontierClass(report); got != nizkProfileFrontierHighKResearch {
		t.Fatalf("frontier=%q want %q", got, nizkProfileFrontierHighKResearch)
	}
}

func TestNIZKProfileCandidatesRemainResearchOnly(t *testing.T) {
	for _, report := range nizkProfileReports(0, "") {
		if report.LedgerStatus != string(credential.SecurityProfileRequiresNewPrimitives) {
			t.Fatalf("%s ledger status=%q", report.SecurityProfile, report.LedgerStatus)
		}
		if report.PrimitiveBlockerReason == "" || len(report.LedgerReasons) == 0 {
			t.Fatalf("missing blocker reason: %+v", report)
		}
		if report.FrontierClass == nizkProfileFrontierCandidate && report.TargetStatus != credential.SecurityProfileRequiresNewPrimitives {
			t.Fatalf("unexpected live-style candidate: %+v", report)
		}
	}
}

func TestNIZKProfileSweepSummaryIncludesRequiredFields(t *testing.T) {
	results := nizkProfileReports(1, "")
	candidates := nizkProfileSearchCandidates()
	if len(results) != 4 {
		t.Fatalf("results=%d want one per profile", len(results))
	}
	summary := NIZKProfileSweepSummary{
		Version:        nizkProfileSweepSummaryVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		CandidateCount: len(nizkProfileSearchTargets()) * len(candidates),
		RunCount:       len(results),
		Targets:        nizkProfileSearchTargets(),
		Results:        results,
		Frontiers:      nizkProfileFrontiers(results, 3),
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
	reports := nizkProfileReports(0, "formal-bq64-128-current-lvcs1025")
	if len(reports) != 1 {
		t.Fatalf("formal reports=%d want 1", len(reports))
	}
	report := reports[0]
	diag := report.FormalBackendDiagnostics
	if !report.FormalBackendCandidate || report.Family != nizkProfileFormalBackendFamily || diag == nil {
		t.Fatalf("missing formal diagnostics: %+v", report)
	}
	if report.SecurityProfile != "BQ64-128" || report.LedgerStatus != string(credential.SecurityProfileRequiresNewPrimitives) {
		t.Fatalf("formal candidate must remain proof-only and primitive-blocked: %+v", report)
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
	reports := nizkProfileReports(0, "formal-bq64-128-dq1152-lvcs1152")
	if len(reports) != 1 {
		t.Fatalf("formal dQ reports=%d want 1", len(reports))
	}
	report := reports[0]
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
	reports := nizkProfileReports(0, "formal-bq64-128-rho2-ellprime2-lvcs1152")
	if len(reports) != 1 {
		t.Fatalf("formal rho reports=%d want 1", len(reports))
	}
	report := reports[0]
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
	want := map[string]int{
		credential.IntGenISISPresetN512Compact96:   22016,
		credential.IntGenISISPresetN1024Compact96:  26144,
		credential.IntGenISISPresetN1024Compact125: 35223,
		credential.IntGenISISPresetN1024Q10_128:    37093,
		credential.IntGenISISPresetN1024Q16_128:    42070,
		credential.IntGenISISPresetN1024Q32_128:    48691,
		credential.IntGenISISPresetN1024Q10_96:     29653,
		credential.IntGenISISPresetN1024Q16_96:     30591,
		credential.IntGenISISPresetN1024Q32_96:     37257,
	}
	gates := allMaintainedPresetGates()
	if len(gates) != len(want) {
		t.Fatalf("maintained gates=%d want %d", len(gates), len(want))
	}
	for _, gate := range gates {
		if got, ok := want[gate.Name]; !ok || gate.ExpectedPaperBytes != got {
			t.Fatalf("maintained byte baseline changed for %s: got %d want %d", gate.Name, gate.ExpectedPaperBytes, got)
		}
	}
}

func TestNIZKProfileCandidateDQFollowsCandidateEll(t *testing.T) {
	report := nizkProfileReports(1, "BQ64-128")[0]
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
	report := nizkProfileReports(1, "BQ32-128")[0]
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

func TestNIZKProfileBQ64128MeasuredReportCarriesTranscriptAudit(t *testing.T) {
	targets := nizkProfileSearchTargets()
	var target NIZKProfileSearchTarget
	for _, candidate := range targets {
		if candidate.SecurityProfile == "BQ64-128" {
			target = candidate
			break
		}
	}
	if target.SecurityProfile == "" {
		t.Fatal("missing BQ64-128 target")
	}
	var cand NIZKProfileSearchCandidate
	for _, candidate := range nizkProfileSearchCandidates() {
		if candidate.Family == "bq64_128_reduction" && candidate.Name == "baseline" {
			cand = candidate
			break
		}
	}
	if cand.Name == "" {
		t.Fatal("missing BQ64-128 baseline reduction candidate")
	}
	target = nizkProfileTargetForCandidate(target, cand)
	report := nizkProfileCandidateReport(target, cand)
	bench := benchmarkIntGenISISE2EReport{
		ArtifactDir: "/tmp/spruce-bq64-reduction-measured-test",
		Issuance:    benchmarkIntGenISISMetrics{PaperTranscriptBytes: 100},
		Showing: benchmarkIntGenISISMetrics{
			PaperTranscriptBytes: 82000,
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
				Pdecs:    PIOP.OpeningResiduePaperAudit{EncodedCols: 17, OmittedCols: []int{1, 2}, StreamBytes: 300},
				Auth:     PIOP.OpeningAuthPaperAudit{NodeCount: 128, PathDepth: 19, PathBitsBytes: 20, IndexBytes: 3, TotalBytes: 404},
				VTargets: PIOP.MatrixPayloadPaperAudit{Rows: 64, Cols: 43, BitWidth: 20, Bytes: 606},
				BarSets:  PIOP.MatrixPayloadPaperAudit{Rows: 12, Cols: 43, BitWidth: 20, Bytes: 707},
			},
			RelationCandidate: report.Relation,
		},
	}
	measured := nizkProfileReportWithMeasuredBenchmark(target, cand, report, bench, "/tmp/spruce-bq64-reduction-measured-test.json")
	if measured.MeasuredShowing == nil || measured.MeasuredShowing.TranscriptAudit.Auth.NodeCount != 128 {
		t.Fatalf("measured digest missing transcript audit: %+v", measured.MeasuredShowing)
	}
	if measured.BQ64Reduction == nil || measured.BQ64Reduction.MeasuredAudit == nil {
		t.Fatalf("missing generic BQ64 measured reduction audit: %+v", measured.BQ64Reduction)
	}
	if measured.BQ64128Reduction == nil || measured.BQ64128Reduction.MeasuredAudit == nil {
		t.Fatalf("missing BQ64-128 measured reduction audit: %+v", measured.BQ64128Reduction)
	}
	if measured.BQ64128Reduction.MeasuredAudit.Pdecs.EncodedCols != 17 || measured.BQ64128Reduction.MeasuredAudit.Auth.PathDepth != 19 {
		t.Fatalf("unexpected measured audit: %+v", measured.BQ64128Reduction.MeasuredAudit)
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
	if measured.BQ64128Reduction != nil {
		t.Fatalf("BQ64-96 should not populate BQ64-128 compatibility report: %+v", measured.BQ64128Reduction)
	}
	if measured.BQ64Reduction.Width.HashFSBits != 232 || measured.BQ64Reduction.Width.TapeBits != 160 {
		t.Fatalf("unexpected BQ64-96 width model: %+v", measured.BQ64Reduction.Width)
	}
}

func TestNIZKProfileBestPerProfilePrefersConcreteFrontier(t *testing.T) {
	results := nizkProfileReports(1, "")
	if len(results) != len(nizkProfileSearchTargets()) {
		t.Fatalf("results=%d want one best per target", len(results))
	}
	want := map[string]string{
		"BQ32-128":  "r7l5-current-theta10-ell15-n917504-lvcs43",
		"BQ64-96":   "r7l5-current-theta12-ell16-n983040-lvcs43",
		"BQ64-128":  "r7l5-current-theta14-ell18-n983040-lvcs43",
		"BQ128-128": nizkProfileBQ128RawResidualFrontierCandidate,
	}
	for _, result := range results {
		if result.Candidate != want[result.SecurityProfile] {
			t.Fatalf("%s best candidate=%q want %q", result.SecurityProfile, result.Candidate, want[result.SecurityProfile])
		}
		if result.FrontierClass != nizkProfileFrontierCandidate {
			t.Fatalf("best result did not reach the NIZK research frontier: %+v", result)
		}
		if result.TargetStatus != credential.SecurityProfileRequiresNewPrimitives || result.LedgerStatus != string(credential.SecurityProfileRequiresNewPrimitives) {
			t.Fatalf("best result must remain primitive-blocked: %+v", result)
		}
		if result.ShowingAlgebraicBits < result.NIZKTargetBits {
			t.Fatalf("best result below NIZK target: %+v", result)
		}
		for _, kappa := range result.SmallWood.RequiredKappa {
			if kappa > qBudget128MaxSupportedGrinding {
				t.Fatalf("best result exceeds grinding limit: %+v", result)
			}
		}
	}
}

func TestNIZKProfileLargeNLeavesRemainProjectionOnlyUnderCurrentQ(t *testing.T) {
	report := nizkProfileReports(0, "n1048576")[0]
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

func TestNIZKProfileTranscriptDiagnosisIdentifiesDominantBucketsAndLevers(t *testing.T) {
	results := nizkProfileReports(1, "")
	if len(results) == 0 {
		t.Fatal("missing NIZK profile reports")
	}
	for _, result := range results {
		if len(result.TranscriptDrivers) == 0 {
			t.Fatalf("%s missing transcript drivers", result.SecurityProfile)
		}
		if result.TranscriptDrivers[0].Component != "vtargets" {
			t.Fatalf("%s dominant driver=%q want vtargets: %+v", result.SecurityProfile, result.TranscriptDrivers[0].Component, result.TranscriptDrivers)
		}
		if result.TranscriptDrivers[0].Percent <= 20 {
			t.Fatalf("%s dominant driver percent too small: %+v", result.SecurityProfile, result.TranscriptDrivers[0])
		}
		leverNames := map[string]bool{}
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
	}
}

func TestNIZKProfileSearchKeepsBQ3296PresetUnchanged(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	if preset.SecurityProfile != "BQ32-96" || preset.CompleteSystemClaim {
		t.Fatalf("BQ32-96 security classification changed: %+v", preset)
	}
	if preset.Showing.LVCSNCols != 40 || preset.Showing.NLeaves != 557056 || preset.Showing.Eta != 44 || preset.Showing.Ell != 9 {
		t.Fatalf("BQ32-96 tuning changed: %+v", preset.Showing)
	}
}

func TestInternalNIZKProfileSweep(t *testing.T) {
	validPrefixSweep := qBudget128EnvBool("SPRUCE_VALID_PREFIX_SWEEP")
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
	if !maxPerProfileExplicit && qBudget128EnvBool("SPRUCE_NIZK_PROFILE_SWEEP_MEASURED") && (strings.Contains(filter, "BQ64-96") || strings.Contains(filter, "BQ64-128")) {
		maxPerProfile = 0
	}
	root := strings.TrimSpace(os.Getenv("SPRUCE_NIZK_PROFILE_SWEEP_ARTIFACT_ROOT"))
	if root == "" {
		root = filepath.Join(os.TempDir(), "spruce-nizk-profile-sweep")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create artifact root: %v", err)
	}
	results := nizkProfileReports(maxPerProfile, filter)
	candidates := nizkProfileSearchCandidatesForFilter(filter)
	if qBudget128EnvBool("SPRUCE_NIZK_PROFILE_SWEEP_MEASURED") {
		maxE2E := qBudget128EnvInt("SPRUCE_NIZK_PROFILE_SWEEP_MAX_E2E", 1)
		results = nizkProfileReportsWithMeasurements(t, results, root, maxE2E)
	}
	summary := NIZKProfileSweepSummary{
		Version:        nizkProfileSweepSummaryVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		CandidateCount: len(nizkProfileSearchTargets()) * len(candidates),
		RunCount:       len(results),
		Targets:        nizkProfileSearchTargets(),
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
