package evidence

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/sourceintegrity"
)

const (
	FocusedV3TimeOptimizationSchema  = "spruce.focused-v3-time-optimization"
	FocusedV3TimeOptimizationVersion = 1
	FocusedV3TimeOptimizationRuns    = 3
	FocusedV3TimePairedRuns          = 7

	FocusedV3TimeStatusPending  = "pending"
	FocusedV3TimeStatusAccepted = "accepted"

	FocusedV3TimePriorPath     = "evidence/focused-v3-final-size-optimization.json"
	FocusedV3TimeArtifactRoot  = "artifacts/smallwood-v3/time-optimization-v1"
	FocusedV3TimePairRoot      = "artifacts/smallwood-v3/time-optimization-pairs-v1"
	FocusedV3TimePairSchema    = "spruce.focused-v3-time-paired-run"
	FocusedV3TimeCounterReason = "minimal_uleb128_value_dependent_width_v1"
	FocusedV3TimePaperHEAD     = "d19818571f04c8c12425e2e7c10ceb41f7a1762d"

	// FocusedV3TimeFreshPendingReason records every known blocker to adopting
	// the checked fresh-run projection. BQ128 still clears the required
	// 128-bit phase gate; the separate executable-preset engineering gate is
	// stricter and currently misses its frozen manifest target in showing.
	FocusedV3TimeFreshPendingReason = "six fresh optimized runs are authenticated; awaiting seven paired fixed-entropy end-to-end trials with allocation counters; BQ128 executable-preset engineering gate unresolved: algebraic_total_bits issuance=131.548362, showing=131.511683, manifest TargetTheoremBits=131.540568; showing is 0.028885 bits below that engineering target while the required 128-bit phase gate passes with 3.511683 bits of slack"
)

// FocusedV3TimeOptimizationBuildOptions supplies the fixed-entropy paired
// measurements that cannot be recovered from the three fresh production
// reports. BuildFocusedV3TimeOptimizationEvidence reads, hashes, and validates
// those six production bundles; it never runs the benchmark itself.
type FocusedV3TimeOptimizationBuildOptions struct {
	SPRUCE_DIR string
	MeasuredOn string
	Paper      FocusedV3PaperTreeEvidence
	PairedRuns map[string][]FocusedV3TimePairedRun
}

// FocusedV3TimeOptimizationEvidence deliberately separates paired
// fixed-entropy adoption measurements from fresh production runs. Exact byte
// equality is authoritative for the former. The latter may have different
// minimal counter widths because their entropy is fresh.
type FocusedV3TimeOptimizationEvidence struct {
	Schema                   string                            `json:"schema"`
	Version                  int                               `json:"version"`
	Status                   string                            `json:"status"`
	PendingReason            string                            `json:"pending_reason,omitempty"`
	MeasuredOn               string                            `json:"measured_on"`
	ClaimScope               string                            `json:"claim_scope"`
	ImplementationBaseCommit string                            `json:"implementation_base_commit"`
	SourceInput              FocusedV3TimeSourceInput          `json:"source_input,omitempty"`
	Environment              FocusedV3TimeEnvironment          `json:"environment,omitempty"`
	PriorEvidence            FocusedV3TimePriorEvidence        `json:"prior_evidence"`
	Paper                    FocusedV3PaperTreeEvidence        `json:"paper_repository"`
	Claims                   FocusedV3TimeClaims               `json:"claims"`
	Protocol                 FocusedV3TimeProtocol             `json:"protocol"`
	MeasurementPolicy        FocusedV3TimeMeasurementPolicy    `json:"measurement_policy"`
	Targets                  []FocusedV3TimeOptimizationTarget `json:"targets"`
}

type FocusedV3TimeSourceInput struct {
	Algorithm string `json:"algorithm,omitempty"`
	Digest    string `json:"digest,omitempty"`
	FileCount int    `json:"file_count,omitempty"`
}

type FocusedV3TimeEnvironment struct {
	GoVersion  string `json:"go_version,omitempty"`
	GOOS       string `json:"goos,omitempty"`
	GOARCH     string `json:"goarch,omitempty"`
	NumCPU     int    `json:"num_cpu,omitempty"`
	GOMAXPROCS int    `json:"gomaxprocs,omitempty"`
}

type FocusedV3TimePriorEvidence struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Schema  string `json:"schema"`
	Version int    `json:"version"`
}

type FocusedV3TimeClaims struct {
	FullGameSecurity     bool   `json:"full_game_security"`
	QROMSecurity         bool   `json:"qrom_security"`
	Unconditional        bool   `json:"unconditional_security"`
	AccountingStatus     string `json:"accounting_status"`
	OptimizationBoundary string `json:"optimization_boundary"`
}

type FocusedV3TimeProtocol struct {
	ProofSchemaVersion         int    `json:"proof_schema_version"`
	CanonicalProofCodecVersion int    `json:"canonical_proof_codec_version"`
	CanonicalProofCodecProfile string `json:"canonical_proof_codec_profile"`
	MerkleTopology             string `json:"merkle_topology"`
	TranscriptDomain           string `json:"transcript_domain"`
	CounterEncoding            string `json:"counter_encoding"`
	EqualityPolicy             string `json:"fixed_entropy_equality_policy"`
}

type FocusedV3TimeMeasurementPolicy struct {
	WarmupsExcluded              int     `json:"warmups_excluded"`
	AlternatingPairedRuns        int     `json:"alternating_paired_runs"`
	FreshProductionRuns          int     `json:"fresh_production_runs"`
	GOMAXPROCS                   int     `json:"gomaxprocs"`
	MinimumTopLevelImprovementPC float64 `json:"minimum_top_level_improvement_percent"`
	MinimumAgreeingPairs         int     `json:"minimum_agreeing_pairs"`
	MaximumMedianRegressionPC    float64 `json:"maximum_phase_regression_percent"`
	MaximumPeakRSSFactor         float64 `json:"maximum_peak_rss_factor"`
	EntropyPolicy                string  `json:"entropy_policy"`
}

type FocusedV3TimeOptimizationTarget struct {
	CanonicalID             string                            `json:"canonical_id"`
	ManifestDigest          string                            `json:"manifest_digest"`
	Kappa                   [4]int                            `json:"kappa"`
	BaselineAccepted        FocusedV3NonResearchPrior         `json:"baseline_accepted"`
	IssuanceGeometry        FocusedV3NonResearchGeometry      `json:"issuance_geometry"`
	ShowingGeometry         FocusedV3NonResearchGeometry      `json:"showing_geometry"`
	PairedRuns              []FocusedV3TimePairedRun          `json:"paired_runs,omitempty"`
	PairedSummary           *FocusedV3TimePairedTargetSummary `json:"paired_summary,omitempty"`
	FreshRuns               []FocusedV3TimeFreshRun           `json:"fresh_runs,omitempty"`
	FreshMedians            *FocusedV3TimeFreshMedians        `json:"fresh_medians,omitempty"`
	CounterWidthExplanation string                            `json:"counter_width_explanation,omitempty"`
}

type FocusedV3TimePerformance struct {
	ProvingMS      float64 `json:"proving_ms"`
	VerificationMS float64 `json:"verification_ms"`
	AllocatedBytes uint64  `json:"allocated_bytes"`
	Allocations    uint64  `json:"allocations"`
	PeakRSSBytes   uint64  `json:"peak_rss_bytes"`
}

type FocusedV3TimeDifferentialPhase struct {
	Baseline             FocusedV3TimePerformance `json:"baseline"`
	Candidate            FocusedV3TimePerformance `json:"candidate"`
	BaselineProofSHA256  string                   `json:"baseline_proof_sha256"`
	CandidateProofSHA256 string                   `json:"candidate_proof_sha256"`
	BaselineCounters     [4]uint64                `json:"baseline_counters"`
	CandidateCounters    [4]uint64                `json:"candidate_counters"`
	ByteIdentical        bool                     `json:"byte_identical"`
}

type FocusedV3TimePairedRun struct {
	Pair                         int                            `json:"pair"`
	EntropySeedSHA256            string                         `json:"entropy_seed_sha256"`
	Issuance                     FocusedV3TimeDifferentialPhase `json:"issuance"`
	Showing                      FocusedV3TimeDifferentialPhase `json:"showing"`
	BaselineInternalTraceSHA256  string                         `json:"baseline_internal_trace_sha256"`
	CandidateInternalTraceSHA256 string                         `json:"candidate_internal_trace_sha256"`
	InternalTraceByteIdentical   bool                           `json:"internal_trace_byte_identical"`
	BaselinePresentationSHA256   string                         `json:"baseline_presentation_sha256"`
	CandidatePresentationSHA256  string                         `json:"candidate_presentation_sha256"`
	PresentationByteIdentical    bool                           `json:"presentation_byte_identical"`
	MeasurementArtifactPath      string                         `json:"measurement_artifact_path"`
	MeasurementArtifactSHA256    string                         `json:"measurement_artifact_sha256"`
}

// FocusedV3TimePairedArtifact is the raw, runner-produced record bound by an
// accepted summary. Its embedded run deliberately leaves its own path/digest
// empty, avoiding a self-referential hash.
type FocusedV3TimePairedArtifact struct {
	Schema      string                 `json:"schema"`
	Version     int                    `json:"version"`
	CanonicalID string                 `json:"canonical_id"`
	Run         FocusedV3TimePairedRun `json:"run"`
}

type FocusedV3TimeDistribution struct {
	BaselineProvingMedianMS       float64 `json:"baseline_proving_median_ms"`
	BaselineProvingMADMS          float64 `json:"baseline_proving_mad_ms"`
	CandidateProvingMedianMS      float64 `json:"candidate_proving_median_ms"`
	CandidateProvingMADMS         float64 `json:"candidate_proving_mad_ms"`
	BaselineVerificationMedianMS  float64 `json:"baseline_verification_median_ms"`
	CandidateVerificationMedianMS float64 `json:"candidate_verification_median_ms"`
	BaselineAllocatedBytesMedian  uint64  `json:"baseline_allocated_bytes_median"`
	BaselineAllocatedBytesMAD     uint64  `json:"baseline_allocated_bytes_mad"`
	CandidateAllocatedBytesMedian uint64  `json:"candidate_allocated_bytes_median"`
	CandidateAllocatedBytesMAD    uint64  `json:"candidate_allocated_bytes_mad"`
	BaselineAllocationsMedian     uint64  `json:"baseline_allocations_median"`
	BaselineAllocationsMAD        uint64  `json:"baseline_allocations_mad"`
	CandidateAllocationsMedian    uint64  `json:"candidate_allocations_median"`
	CandidateAllocationsMAD       uint64  `json:"candidate_allocations_mad"`
	BaselinePeakRSSMedianBytes    uint64  `json:"baseline_peak_rss_median_bytes"`
	BaselinePeakRSSMADBytes       uint64  `json:"baseline_peak_rss_mad_bytes"`
	CandidatePeakRSSMedianBytes   uint64  `json:"candidate_peak_rss_median_bytes"`
	CandidatePeakRSSMADBytes      uint64  `json:"candidate_peak_rss_mad_bytes"`
	AgreeingPairs                 int     `json:"agreeing_pairs"`
}

type FocusedV3TimePairedTargetSummary struct {
	Issuance FocusedV3TimeDistribution `json:"issuance"`
	Showing  FocusedV3TimeDistribution `json:"showing"`
}

// FocusedV3TimePaperComponents is paper accounting, not a serialized wire.
// CanonicalWire below is the independently audited physical proof wire.
type FocusedV3TimePaperComponents struct {
	FixedBytes              int `json:"fixed_bytes"`
	RBytes                  int `json:"r_bytes"`
	QBytes                  int `json:"q_bytes"`
	PDECSBytes              int `json:"pdecs_bytes"`
	MDECSBytes              int `json:"mdecs_bytes"`
	AuthenticationBytes     int `json:"authentication_bytes"`
	TapeBytes               int `json:"tape_bytes"`
	SignatureShortnessBytes int `json:"signature_shortness_bytes"`
	VTargetsBytes           int `json:"vtargets_bytes"`
	BarSetsBytes            int `json:"barsets_bytes"`
	TotalBytes              int `json:"total_bytes"`
}

type FocusedV3TimeTheorem struct {
	AlgebraicTerms     [4]float64 `json:"algebraic_terms"`
	AlgebraicBits      [4]float64 `json:"algebraic_bits"`
	AlgebraicTotalBits float64    `json:"algebraic_total_bits"`
	TheoremBits        [4]float64 `json:"theorem_bits"`
	TheoremTotalBits   float64    `json:"theorem_total_bits"`
}

type FocusedV3TimeFreshPhase struct {
	ProvingMS             float64                        `json:"proving_ms"`
	VerificationMS        float64                        `json:"verification_ms"`
	VerificationPassed    bool                           `json:"verification_passed"`
	MeasurementStatus     string                         `json:"measurement_status"`
	ZeroKnowledgeEligible bool                           `json:"zero_knowledge_eligible"`
	FSCounters            [4]uint64                      `json:"fs_counters"`
	PhaseTimings          []PIOP.PhaseTiming             `json:"phase_timings"`
	CanonicalWire         PIOP.CanonicalProofWireAuditV6 `json:"canonical_wire"`
	Paper                 FocusedV3TimePaperComponents   `json:"paper"`
	Theorem               FocusedV3TimeTheorem           `json:"theorem"`
	ProofSHA256           string                         `json:"proof_sha256"`
}

type FocusedV3TimeFreshRun struct {
	Run                  int                     `json:"run"`
	ArtifactDirectory    string                  `json:"artifact_directory"`
	ReportPath           string                  `json:"report_path"`
	ReportSHA256         string                  `json:"report_sha256"`
	ResourcePath         string                  `json:"resource_path"`
	ResourceSHA256       string                  `json:"resource_sha256"`
	StateBytes           int                     `json:"state_bytes"`
	StateSHA256          string                  `json:"state_sha256"`
	PresentationBytes    int                     `json:"presentation_bytes"`
	PresentationSHA256   string                  `json:"presentation_sha256"`
	PeakRSSBytes         uint64                  `json:"peak_rss_bytes"`
	ParameterAuditStatus string                  `json:"parameter_audit_status"`
	ReplayRejected       bool                    `json:"replay_rejected"`
	Issuance             FocusedV3TimeFreshPhase `json:"issuance"`
	Showing              FocusedV3TimeFreshPhase `json:"showing"`
}

type FocusedV3TimeFreshMedians struct {
	IssuanceProvingMS      float64 `json:"issuance_proving_ms"`
	ShowingProvingMS       float64 `json:"showing_proving_ms"`
	IssuanceVerificationMS float64 `json:"issuance_verification_ms"`
	ShowingVerificationMS  float64 `json:"showing_verification_ms"`
	PeakRSSBytes           uint64  `json:"peak_rss_bytes"`
}

func focusedV3TimeClaims() FocusedV3TimeClaims {
	return FocusedV3TimeClaims{
		AccountingStatus:     "deferred_proof_only",
		OptimizationBoundary: "prover_only_exact_output_v1",
	}
}

func focusedV3TimeProtocol() FocusedV3TimeProtocol {
	return FocusedV3TimeProtocol{
		ProofSchemaVersion:         PIOP.ProofSchemaVersionV3,
		CanonicalProofCodecVersion: PIOP.CanonicalProofCodecVersionV6,
		CanonicalProofCodecProfile: PIOP.CanonicalProofCodecProfileV6,
		MerkleTopology:             decs.MerkleTopologyExactNV3,
		TranscriptDomain:           "strict-v3",
		CounterEncoding:            "minimal_unsigned_leb128_to_uint64_fs_v1",
		EqualityPolicy:             "fixed_entropy_complete_canonical_bytes_and_counters_v1",
	}
}

func focusedV3TimePolicy() FocusedV3TimeMeasurementPolicy {
	return FocusedV3TimeMeasurementPolicy{
		WarmupsExcluded: 1, AlternatingPairedRuns: 7, FreshProductionRuns: 3,
		GOMAXPROCS: 15, MinimumTopLevelImprovementPC: 3,
		MinimumAgreeingPairs: 5, MaximumMedianRegressionPC: 2,
		MaximumPeakRSSFactor: 2,
		EntropyPolicy:        "seven_fixed_test_only_seeds_paired_baseline_candidate_v1",
	}
}

func focusedV3TimeExpectedGeometry(id string) (FocusedV3NonResearchGeometry, FocusedV3NonResearchGeometry, bool) {
	switch id {
	case credential.IntGenISISPresetPoCN1024BQ128R128V3:
		return FocusedV3NonResearchGeometry{49, 2, 156, 90, 246, 39, 207, 9, 8, 472},
			FocusedV3NonResearchGeometry{423, 10, 195, 450, 645, 143, 502, 11, 8, 570}, true
	case credential.IntGenISISPresetSystemN1024WF128CROMV2:
		return FocusedV3NonResearchGeometry{49, 2, 77, 78, 155, 21, 134, 9, 8, 391},
			FocusedV3NonResearchGeometry{423, 11, 91, 429, 520, 84, 436, 11, 8, 471}, true
	default:
		return FocusedV3NonResearchGeometry{}, FocusedV3NonResearchGeometry{}, false
	}
}

// ReadFocusedV3TimeOptimizationEvidence rejects unknown fields and trailing
// JSON so a future evidence epoch cannot be silently interpreted as v1.
func ReadFocusedV3TimeOptimizationEvidence(path string) (FocusedV3TimeOptimizationEvidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	var out FocusedV3TimeOptimizationEvidence
	if err := decodeStrictJSON(data, &out); err != nil {
		return FocusedV3TimeOptimizationEvidence{}, fmt.Errorf("decode focused-v3 time evidence: %w", err)
	}
	return out, nil
}

// ValidateFocusedV3TimeOptimizationEvidence validates the self-contained
// summary. Use ValidateFocusedV3TimeOptimizationArtifacts to additionally bind
// it to the live source snapshot, predecessor, and raw run files.
func ValidateFocusedV3TimeOptimizationEvidence(e FocusedV3TimeOptimizationEvidence, allowPending bool) error {
	if e.Schema != FocusedV3TimeOptimizationSchema || e.Version != FocusedV3TimeOptimizationVersion {
		return fmt.Errorf("focused-v3 time evidence identity=(%q,v%d)", e.Schema, e.Version)
	}
	if _, err := time.Parse("2006-01-02", e.MeasuredOn); err != nil {
		return fmt.Errorf("focused-v3 time measured_on: %w", err)
	}
	if e.ClaimScope != string(credential.ClaimProofOnly) || e.Claims != focusedV3TimeClaims() {
		return fmt.Errorf("focused-v3 time security claim boundary is invalid")
	}
	if e.Protocol != focusedV3TimeProtocol() || e.MeasurementPolicy != focusedV3TimePolicy() {
		return fmt.Errorf("focused-v3 time protocol/measurement policy changed")
	}
	if e.PriorEvidence.Path != FocusedV3TimePriorPath || !validHexDigest(e.PriorEvidence.SHA256, 64) ||
		e.PriorEvidence.Schema != "spruce.focused-v3-final-size-optimization" || e.PriorEvidence.Version != 1 {
		return fmt.Errorf("focused-v3 time predecessor binding is invalid")
	}
	if !validHexDigest(e.ImplementationBaseCommit, 40) {
		return fmt.Errorf("focused-v3 time implementation base commit is invalid")
	}
	if e.Status == FocusedV3TimeStatusPending {
		if !allowPending {
			return fmt.Errorf("focused-v3 time evidence is pending: %s", e.PendingReason)
		}
		if e.PendingReason == "" || len(e.Targets) != len(focusedV3TargetPresetIDs) || e.Paper.HeadBefore != FocusedV3TimePaperHEAD || !e.Paper.CleanBefore ||
			(e.Paper.HeadAfter != "" && (e.Paper.HeadAfter != FocusedV3TimePaperHEAD || !e.Paper.CleanAfter)) {
			return fmt.Errorf("focused-v3 time pending record is incomplete")
		}
		if err := validateFocusedV3TimeTargets(e.Targets, true); err != nil {
			return err
		}
		if focusedV3TimeEvidenceHasFreshRuns(e) {
			if e.PendingReason != FocusedV3TimeFreshPendingReason {
				return fmt.Errorf("focused-v3 time pending fresh-run record does not enumerate every known blocker")
			}
			if !focusedV3TimeValidSourceEnvironment(e) {
				return fmt.Errorf("focused-v3 time pending fresh-run source/environment boundary is incomplete")
			}
			if e.Paper.HeadAfter != FocusedV3TimePaperHEAD || !e.Paper.CleanAfter {
				return fmt.Errorf("focused-v3 time pending fresh-run paper checkpoint is incomplete")
			}
		}
		return nil
	}
	if e.Status != FocusedV3TimeStatusAccepted || e.PendingReason != "" {
		return fmt.Errorf("focused-v3 time status=%q", e.Status)
	}
	if !focusedV3TimeValidSourceEnvironment(e) {
		return fmt.Errorf("focused-v3 time source/environment boundary is incomplete")
	}
	if e.Paper.HeadBefore != FocusedV3TimePaperHEAD || e.Paper.HeadAfter != FocusedV3TimePaperHEAD || !e.Paper.CleanBefore || !e.Paper.CleanAfter {
		return fmt.Errorf("focused-v3 time paper repository was not held clean and unchanged")
	}
	return validateFocusedV3TimeTargets(e.Targets, false)
}

func focusedV3TimeValidSourceEnvironment(e FocusedV3TimeOptimizationEvidence) bool {
	return e.SourceInput.Algorithm == sourceintegrity.Algorithm && validHexDigest(e.SourceInput.Digest, 64) && e.SourceInput.FileCount > 0 &&
		e.Environment.GoVersion == "go1.23.12" && e.Environment.GOOS == "darwin" && e.Environment.GOARCH == "arm64" &&
		e.Environment.NumCPU == 15 && e.Environment.GOMAXPROCS == 15
}

func focusedV3TimeEvidenceHasFreshRuns(e FocusedV3TimeOptimizationEvidence) bool {
	for _, target := range e.Targets {
		if len(target.FreshRuns) != 0 {
			return true
		}
	}
	return false
}

func validateFocusedV3TimeTargets(targets []FocusedV3TimeOptimizationTarget, pending bool) error {
	if len(targets) != len(focusedV3TargetPresetIDs) {
		return fmt.Errorf("focused-v3 time targets=%d want=%d", len(targets), len(focusedV3TargetPresetIDs))
	}
	seen := make(map[string]bool, len(targets))
	for _, target := range targets {
		preset, ok := credential.LookupIntGenISISPreset(target.CanonicalID)
		if !ok || seen[target.CanonicalID] {
			return fmt.Errorf("focused-v3 time unknown/duplicate target %q", target.CanonicalID)
		}
		seen[target.CanonicalID] = true
		issueGeometry, showGeometry, ok := focusedV3TimeExpectedGeometry(target.CanonicalID)
		if !ok || target.ManifestDigest != credential.IntGenISISPresetManifestDigest(preset) ||
			target.Kappa != preset.Issuance.Kappa || target.Kappa != preset.Showing.Kappa ||
			target.IssuanceGeometry != issueGeometry || target.ShowingGeometry != showGeometry {
			return fmt.Errorf("focused-v3 time target %s manifest/kappa/geometry mismatch", target.CanonicalID)
		}
		if err := validateFocusedV3TimeBaseline(target.BaselineAccepted); err != nil {
			return fmt.Errorf("focused-v3 time target %s baseline: %w", target.CanonicalID, err)
		}
		if pending {
			if len(target.PairedRuns) != 0 || target.PairedSummary != nil {
				return fmt.Errorf("focused-v3 time pending target %s contains paired-run claims", target.CanonicalID)
			}
			if len(target.FreshRuns) != 0 {
				if err := validateFocusedV3TimeFreshTarget(target, true); err != nil {
					return err
				}
			} else if target.FreshMedians != nil || target.CounterWidthExplanation != "" {
				return fmt.Errorf("focused-v3 time pending target %s has fresh-run summary without runs", target.CanonicalID)
			}
			continue
		}
		if err := validateFocusedV3TimeAcceptedTarget(target); err != nil {
			return err
		}
	}
	for _, id := range focusedV3TargetPresetIDs {
		if !seen[id] {
			return fmt.Errorf("focused-v3 time evidence missing %s", id)
		}
	}
	return nil
}

func validateFocusedV3TimeBaseline(b FocusedV3NonResearchPrior) error {
	if b.PersistentStateBytes <= 0 || b.IssuanceProofWireBytes <= 0 || b.ShowingProofWireBytes <= 0 || b.PresentationWireBytes <= 0 ||
		b.PaperIssuanceBytes <= 0 || b.PaperShowingBytes <= 0 || !finitePositive(b.IssuanceProvingMS) || !finitePositive(b.ShowingProvingMS) || b.PeakRSSBytes == 0 {
		return fmt.Errorf("incomplete accepted predecessor metrics")
	}
	return nil
}

func validateFocusedV3TimeAcceptedTarget(target FocusedV3TimeOptimizationTarget) error {
	if len(target.PairedRuns) != FocusedV3TimePairedRuns {
		return fmt.Errorf("focused-v3 time target %s paired runs=%d want=%d", target.CanonicalID, len(target.PairedRuns), FocusedV3TimePairedRuns)
	}
	seenSeeds := make(map[string]struct{}, FocusedV3TimePairedRuns)
	for i, pair := range target.PairedRuns {
		if pair.Pair != i+1 || !validHexDigest(pair.EntropySeedSHA256, 64) {
			return fmt.Errorf("focused-v3 time target %s invalid paired run %d", target.CanonicalID, i+1)
		}
		if _, duplicate := seenSeeds[pair.EntropySeedSHA256]; duplicate {
			return fmt.Errorf("focused-v3 time target %s repeats entropy seed in pair %d", target.CanonicalID, pair.Pair)
		}
		seenSeeds[pair.EntropySeedSHA256] = struct{}{}
		wantArtifactPath, err := focusedV3TimePairedArtifactPath(target.CanonicalID, pair.Pair)
		if err != nil || pair.MeasurementArtifactPath != wantArtifactPath || !validHexDigest(pair.MeasurementArtifactSHA256, 64) {
			return fmt.Errorf("focused-v3 time target %s pair %d raw measurement binding is invalid", target.CanonicalID, pair.Pair)
		}
		if err := validateFocusedV3TimeDifferentialPhase(pair.Issuance); err != nil {
			return fmt.Errorf("focused-v3 time target %s pair %d issuance: %w", target.CanonicalID, pair.Pair, err)
		}
		if err := validateFocusedV3TimeDifferentialPhase(pair.Showing); err != nil {
			return fmt.Errorf("focused-v3 time target %s pair %d showing: %w", target.CanonicalID, pair.Pair, err)
		}
		if !pair.PresentationByteIdentical || !validHexDigest(pair.BaselinePresentationSHA256, 64) ||
			pair.BaselinePresentationSHA256 != pair.CandidatePresentationSHA256 {
			return fmt.Errorf("focused-v3 time target %s pair %d presentation changed", target.CanonicalID, pair.Pair)
		}
		if !pair.InternalTraceByteIdentical || !validHexDigest(pair.BaselineInternalTraceSHA256, 64) ||
			pair.BaselineInternalTraceSHA256 != pair.CandidateInternalTraceSHA256 {
			return fmt.Errorf("focused-v3 time target %s pair %d internal transcript trace changed", target.CanonicalID, pair.Pair)
		}
	}
	wantSummary := focusedV3TimeSummarizePairs(target.PairedRuns)
	if target.PairedSummary == nil || !reflect.DeepEqual(*target.PairedSummary, wantSummary) {
		return fmt.Errorf("focused-v3 time target %s paired summary is inconsistent", target.CanonicalID)
	}
	for label, summary := range map[string]FocusedV3TimeDistribution{"issuance": wantSummary.Issuance, "showing": wantSummary.Showing} {
		if summary.AgreeingPairs < focusedV3TimePolicy().MinimumAgreeingPairs ||
			summary.CandidateProvingMedianMS > summary.BaselineProvingMedianMS*0.97 ||
			summary.CandidateVerificationMedianMS > summary.BaselineVerificationMedianMS*1.02 ||
			summary.CandidatePeakRSSMedianBytes > 2*summary.BaselinePeakRSSMedianBytes {
			return fmt.Errorf("focused-v3 time target %s %s failed cumulative adoption gate", target.CanonicalID, label)
		}
	}
	return validateFocusedV3TimeFreshTarget(target, false)
}

func validateFocusedV3TimeFreshTarget(target FocusedV3TimeOptimizationTarget, pending bool) error {
	if len(target.FreshRuns) != FocusedV3TimeOptimizationRuns {
		return fmt.Errorf("focused-v3 time target %s fresh runs=%d want=%d", target.CanonicalID, len(target.FreshRuns), FocusedV3TimeOptimizationRuns)
	}
	issueCounterWidths, showCounterWidths := make(map[int]bool), make(map[int]bool)
	for i, run := range target.FreshRuns {
		if err := validateFocusedV3TimeFreshRun(target, run, i+1); err != nil {
			return err
		}
		if !pending {
			preset, _ := credential.LookupIntGenISISPreset(target.CanonicalID)
			if run.Issuance.Theorem.AlgebraicTotalBits+1e-9 < preset.TargetTheoremBits ||
				run.Showing.Theorem.AlgebraicTotalBits+1e-9 < preset.TargetTheoremBits {
				return fmt.Errorf("focused-v3 time target %s run %d failed executable-preset engineering gate: algebraic_total_bits issuance=%.6f showing=%.6f target=%.6f",
					target.CanonicalID, i+1, run.Issuance.Theorem.AlgebraicTotalBits, run.Showing.Theorem.AlgebraicTotalBits, preset.TargetTheoremBits)
			}
		}
		issueCounterWidths[run.Issuance.CanonicalWire.CounterBytes] = true
		showCounterWidths[run.Showing.CanonicalWire.CounterBytes] = true
	}
	widthVaries := len(issueCounterWidths) > 1 || len(showCounterWidths) > 1
	if widthVaries && target.CounterWidthExplanation != FocusedV3TimeCounterReason {
		return fmt.Errorf("focused-v3 time target %s has unexplained minimal-counter width variation", target.CanonicalID)
	}
	if !widthVaries && target.CounterWidthExplanation != "" {
		return fmt.Errorf("focused-v3 time target %s has a counter-width explanation without variation", target.CanonicalID)
	}
	wantMedians := focusedV3TimeFreshMedians(target.FreshRuns)
	if target.FreshMedians == nil || !reflect.DeepEqual(*target.FreshMedians, wantMedians) {
		return fmt.Errorf("focused-v3 time target %s fresh medians are inconsistent", target.CanonicalID)
	}
	return nil
}

func validateFocusedV3TimeDifferentialPhase(phase FocusedV3TimeDifferentialPhase) error {
	if err := validateFocusedV3TimePerformance(phase.Baseline); err != nil {
		return err
	}
	if err := validateFocusedV3TimePerformance(phase.Candidate); err != nil {
		return err
	}
	if !phase.ByteIdentical || !validHexDigest(phase.BaselineProofSHA256, 64) ||
		phase.BaselineProofSHA256 != phase.CandidateProofSHA256 || phase.BaselineCounters != phase.CandidateCounters {
		return fmt.Errorf("fixed-entropy proof bytes or counters changed")
	}
	if phase.Candidate.PeakRSSBytes > 2*phase.Baseline.PeakRSSBytes {
		return fmt.Errorf("candidate peak RSS exceeds 2x paired baseline")
	}
	return nil
}

func validateFocusedV3TimePerformance(p FocusedV3TimePerformance) error {
	if !finitePositive(p.ProvingMS) || !finitePositive(p.VerificationMS) || p.AllocatedBytes == 0 || p.Allocations == 0 || p.PeakRSSBytes == 0 {
		return fmt.Errorf("incomplete paired performance measurement")
	}
	return nil
}

func validateFocusedV3TimeFreshRun(target FocusedV3TimeOptimizationTarget, run FocusedV3TimeFreshRun, wantRun int) error {
	alias, _ := focusedV3NonResearchTargetAlias(target.CanonicalID)
	wantDir := filepath.ToSlash(filepath.Join(FocusedV3TimeArtifactRoot, alias, fmt.Sprintf("run-%d", wantRun)))
	if run.Run != wantRun || run.ArtifactDirectory != wantDir || run.ReportPath != wantDir+"/report.json" || run.ResourcePath != wantDir+"/resource.txt" ||
		!validHexDigest(run.ReportSHA256, 64) || !validHexDigest(run.ResourceSHA256, 64) || !validHexDigest(run.StateSHA256, 64) ||
		!validHexDigest(run.PresentationSHA256, 64) || run.StateBytes != target.BaselineAccepted.PersistentStateBytes ||
		run.PresentationBytes <= run.Showing.CanonicalWire.TotalBytes || run.PeakRSSBytes == 0 || run.PeakRSSBytes > 2*target.BaselineAccepted.PeakRSSBytes ||
		run.ParameterAuditStatus != "pass" || !run.ReplayRejected {
		return fmt.Errorf("focused-v3 time target %s fresh run %d failed identity/resource/security gates", target.CanonicalID, wantRun)
	}
	if err := validateFocusedV3TimeFreshPhase("issuance", run.Issuance, target.IssuanceGeometry, target.BaselineAccepted.PaperIssuanceBytes); err != nil {
		return fmt.Errorf("focused-v3 time target %s run %d: %w", target.CanonicalID, wantRun, err)
	}
	if err := validateFocusedV3TimeFreshPhase("showing", run.Showing, target.ShowingGeometry, target.BaselineAccepted.PaperShowingBytes); err != nil {
		return fmt.Errorf("focused-v3 time target %s run %d: %w", target.CanonicalID, wantRun, err)
	}
	return nil
}

func validateFocusedV3TimeFreshPhase(label string, phase FocusedV3TimeFreshPhase, geometry FocusedV3NonResearchGeometry, paperBytes int) error {
	wantMeasurement := "e2e_presign"
	if label == "showing" {
		wantMeasurement = "e2e_showing_standalone"
	}
	if !finitePositive(phase.ProvingMS) || !finitePositive(phase.VerificationMS) || !phase.VerificationPassed ||
		phase.MeasurementStatus != wantMeasurement || !phase.ZeroKnowledgeEligible || len(phase.PhaseTimings) == 0 ||
		!validHexDigest(phase.ProofSHA256, 64) || phase.Theorem.AlgebraicTotalBits < 128 || phase.Theorem.TheoremTotalBits < 128 {
		return fmt.Errorf("%s phase measurement/security evidence is incomplete", label)
	}
	timingLabels := make(map[string]bool, len(phase.PhaseTimings))
	for _, timing := range phase.PhaseTimings {
		if timing.Label == "" || !finitePositive(timing.Milliseconds) {
			return fmt.Errorf("%s phase contains an invalid timing sample", label)
		}
		timingLabels[timing.Label] = true
	}
	for _, required := range focusedV3TimeRequiredPhaseLabels(label) {
		if !timingLabels[required] {
			return fmt.Errorf("%s phase is missing required timing %q", label, required)
		}
	}
	if phase.CanonicalWire.CodecVersion != PIOP.CanonicalProofCodecVersionV6 || phase.CanonicalWire.CodecProfile != PIOP.CanonicalProofCodecProfileV6 ||
		phase.CanonicalWire.ProofSchemaVersion != PIOP.ProofSchemaVersionV3 || phase.CanonicalWire.FieldEncoding != PIOP.CanonicalProofFieldEncodingV6 ||
		phase.CanonicalWire.QKernelEncoding != PIOP.CanonicalProofQKernelEncodingV6 || phase.CanonicalWire.RadixQGroupElements != PIOP.CanonicalProofRadixQGroupElementsV6 ||
		phase.CanonicalWire.MerkleTopology != decs.MerkleTopologyExactNV3 || phase.CanonicalWire.CounterBytes < 4 ||
		phase.CanonicalWire.MerklePaddingNodes != 0 || phase.CanonicalWire.MerkleNodesUsed <= 0 || phase.CanonicalWire.MerkleNodesUsed > phase.CanonicalWire.MerkleNodesBound ||
		focusedV3TimeWireComponentTotal(phase.CanonicalWire) != phase.CanonicalWire.TotalBytes {
		return fmt.Errorf("%s canonical proof-wire decomposition is invalid", label)
	}
	if phase.Paper.TotalBytes != paperBytes || !focusedV3TimeNonnegativePaperComponents(phase.Paper) || focusedV3TimePaperComponentTotal(phase.Paper) != phase.Paper.TotalBytes {
		return fmt.Errorf("%s paper transcript component accounting changed", label)
	}
	if !focusedV3TimeFiniteTheorem(phase.Theorem) || geometry.LogicalRows <= 0 {
		return fmt.Errorf("%s theorem/geometry binding is invalid", label)
	}
	return nil
}

func focusedV3TimeRequiredPhaseLabels(label string) []string {
	replayLabel := label + ".replay_preparation"
	if label == "showing" {
		replayLabel = label + ".constraints.replay_plan"
	}
	required := []string{
		label + ".domain_preparation",
		label + ".rows",
		replayLabel,
		label + ".lvcs_commit_total",
		label + ".semantic_q.plan",
		label + ".semantic_q.evaluation",
		label + ".semantic_q.interpolation",
		label + ".semantic_q.audit",
		"RunMaskFS.Round4TailOpen",
		label + ".canonical_encode",
		label + ".prove_total",
		label + ".verify_total",
	}
	for round := 1; round <= 4; round++ {
		required = append(required,
			fmt.Sprintf("%s.fs.round%d.prefix", label, round),
			fmt.Sprintf("%s.fs.round%d.counter_loop", label, round),
		)
	}
	return required
}

func focusedV3TimeNonnegativePaperComponents(p FocusedV3TimePaperComponents) bool {
	for _, value := range []int{p.FixedBytes, p.RBytes, p.QBytes, p.PDECSBytes, p.MDECSBytes, p.AuthenticationBytes, p.TapeBytes, p.SignatureShortnessBytes, p.VTargetsBytes, p.BarSetsBytes, p.TotalBytes} {
		if value < 0 {
			return false
		}
	}
	return true
}

func focusedV3TimeWireComponentTotal(a PIOP.CanonicalProofWireAuditV6) int {
	return a.HeaderBytes + a.RootBytes + a.SaltBytes + a.CounterBytes + a.RBytes + a.QBytes + a.VTargetsBytes + a.BarSetsBytes + a.OpeningPBytes + a.TapeBytes + a.AuthenticationBytes
}

func focusedV3TimePaperComponentTotal(p FocusedV3TimePaperComponents) int {
	return p.FixedBytes + p.RBytes + p.QBytes + p.PDECSBytes + p.MDECSBytes + p.AuthenticationBytes + p.TapeBytes + p.SignatureShortnessBytes + p.VTargetsBytes + p.BarSetsBytes
}

func focusedV3TimeFiniteTheorem(t FocusedV3TimeTheorem) bool {
	for _, vector := range [][4]float64{t.AlgebraicTerms, t.AlgebraicBits, t.TheoremBits} {
		for _, v := range vector {
			if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
				return false
			}
		}
	}
	return finitePositive(t.AlgebraicTotalBits) && finitePositive(t.TheoremTotalBits)
}

func focusedV3TimeSummarizePairs(runs []FocusedV3TimePairedRun) FocusedV3TimePairedTargetSummary {
	issue := make([]FocusedV3TimeDifferentialPhase, 0, len(runs))
	show := make([]FocusedV3TimeDifferentialPhase, 0, len(runs))
	for _, run := range runs {
		issue = append(issue, run.Issuance)
		show = append(show, run.Showing)
	}
	return FocusedV3TimePairedTargetSummary{Issuance: focusedV3TimeDistribution(issue), Showing: focusedV3TimeDistribution(show)}
}

func focusedV3TimeDistribution(phases []FocusedV3TimeDifferentialPhase) FocusedV3TimeDistribution {
	baseProve, candProve, baseVerify, candVerify := []float64{}, []float64{}, []float64{}, []float64{}
	baseBytes, candBytes, baseAllocs, candAllocs, baseRSS, candRSS := []uint64{}, []uint64{}, []uint64{}, []uint64{}, []uint64{}, []uint64{}
	agree := 0
	for _, p := range phases {
		baseProve, candProve = append(baseProve, p.Baseline.ProvingMS), append(candProve, p.Candidate.ProvingMS)
		baseVerify, candVerify = append(baseVerify, p.Baseline.VerificationMS), append(candVerify, p.Candidate.VerificationMS)
		baseBytes, candBytes = append(baseBytes, p.Baseline.AllocatedBytes), append(candBytes, p.Candidate.AllocatedBytes)
		baseAllocs, candAllocs = append(baseAllocs, p.Baseline.Allocations), append(candAllocs, p.Candidate.Allocations)
		baseRSS, candRSS = append(baseRSS, p.Baseline.PeakRSSBytes), append(candRSS, p.Candidate.PeakRSSBytes)
		if p.Candidate.ProvingMS < p.Baseline.ProvingMS {
			agree++
		}
	}
	return FocusedV3TimeDistribution{
		BaselineProvingMedianMS: medianFloat(baseProve), BaselineProvingMADMS: focusedV3TimeMADFloat(baseProve),
		CandidateProvingMedianMS: medianFloat(candProve), CandidateProvingMADMS: focusedV3TimeMADFloat(candProve),
		BaselineVerificationMedianMS: medianFloat(baseVerify), CandidateVerificationMedianMS: medianFloat(candVerify),
		BaselineAllocatedBytesMedian: medianUint64(baseBytes), BaselineAllocatedBytesMAD: focusedV3TimeMADUint64(baseBytes),
		CandidateAllocatedBytesMedian: medianUint64(candBytes), CandidateAllocatedBytesMAD: focusedV3TimeMADUint64(candBytes),
		BaselineAllocationsMedian: medianUint64(baseAllocs), BaselineAllocationsMAD: focusedV3TimeMADUint64(baseAllocs),
		CandidateAllocationsMedian: medianUint64(candAllocs), CandidateAllocationsMAD: focusedV3TimeMADUint64(candAllocs),
		BaselinePeakRSSMedianBytes: medianUint64(baseRSS), BaselinePeakRSSMADBytes: focusedV3TimeMADUint64(baseRSS),
		CandidatePeakRSSMedianBytes: medianUint64(candRSS), CandidatePeakRSSMADBytes: focusedV3TimeMADUint64(candRSS), AgreeingPairs: agree,
	}
}

func focusedV3TimeMADFloat(values []float64) float64 {
	median := medianFloat(values)
	deviations := make([]float64, len(values))
	for i, value := range values {
		deviations[i] = math.Abs(value - median)
	}
	return medianFloat(deviations)
}

func focusedV3TimeMADUint64(values []uint64) uint64 {
	median := medianUint64(values)
	deviations := make([]uint64, len(values))
	for i, value := range values {
		if value >= median {
			deviations[i] = value - median
		} else {
			deviations[i] = median - value
		}
	}
	return medianUint64(deviations)
}

func focusedV3TimeFreshMedians(runs []FocusedV3TimeFreshRun) FocusedV3TimeFreshMedians {
	issueProve, showProve, issueVerify, showVerify := []float64{}, []float64{}, []float64{}, []float64{}
	rss := []uint64{}
	for _, run := range runs {
		issueProve, showProve = append(issueProve, run.Issuance.ProvingMS), append(showProve, run.Showing.ProvingMS)
		issueVerify, showVerify = append(issueVerify, run.Issuance.VerificationMS), append(showVerify, run.Showing.VerificationMS)
		rss = append(rss, run.PeakRSSBytes)
	}
	return FocusedV3TimeFreshMedians{
		IssuanceProvingMS: medianFloat(issueProve), ShowingProvingMS: medianFloat(showProve),
		IssuanceVerificationMS: medianFloat(issueVerify), ShowingVerificationMS: medianFloat(showVerify), PeakRSSBytes: medianUint64(rss),
	}
}

// MarshalFocusedV3TimeOptimizationEvidence emits the canonical reviewable
// representation. Pending scaffolds are allowed only when explicitly asked.
func MarshalFocusedV3TimeOptimizationEvidence(e FocusedV3TimeOptimizationEvidence, allowPending bool) ([]byte, error) {
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, allowPending); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func WriteFocusedV3TimeOptimizationEvidence(path string, e FocusedV3TimeOptimizationEvidence, allowPending bool) error {
	data, err := MarshalFocusedV3TimeOptimizationEvidence(e, allowPending)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o644)
}

// NewPendingFocusedV3TimeOptimizationEvidence creates a fail-closed scaffold.
// It binds the immutable predecessor and target identities but intentionally
// contains no source, performance, proof, or acceptance claim.
func NewPendingFocusedV3TimeOptimizationEvidence(root, measuredOn, baseCommit, reason string) (FocusedV3TimeOptimizationEvidence, error) {
	root, err := ResolveSPRUCE_DIR(root)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	if measuredOn == "" {
		measuredOn = time.Now().UTC().Format("2006-01-02")
	}
	prior, priorData, err := focusedV3TimeReadPrior(root)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	if reason == "" {
		reason = "awaiting seven paired fixed-entropy trials and three fresh optimized runs per target; " +
			"BQ128 executable-preset engineering gate remains unresolved because showing algebraic_total_bits=131.511683 is below manifest TargetTheoremBits=131.540568 while the required 128-bit phase gate passes"
	}
	paperDir := filepath.Clean(filepath.Join(root, "..", "Better-Lattice-based-Blind-Signatures"))
	paperHead, paperClean, err := CaptureFocusedV3GitTreeState(paperDir)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	if paperHead != FocusedV3TimePaperHEAD || !paperClean {
		return FocusedV3TimeOptimizationEvidence{}, fmt.Errorf("focused-v3 time paper checkout is not at the required clean checkpoint")
	}
	e := FocusedV3TimeOptimizationEvidence{
		Schema: FocusedV3TimeOptimizationSchema, Version: FocusedV3TimeOptimizationVersion,
		Status: FocusedV3TimeStatusPending, PendingReason: reason, MeasuredOn: measuredOn,
		ClaimScope: string(credential.ClaimProofOnly), ImplementationBaseCommit: baseCommit,
		PriorEvidence: FocusedV3TimePriorEvidence{Path: FocusedV3TimePriorPath, SHA256: sha256Hex(priorData), Schema: prior.Schema, Version: prior.Version},
		Paper:         FocusedV3PaperTreeEvidence{HeadBefore: paperHead, CleanBefore: true},
		Claims:        focusedV3TimeClaims(), Protocol: focusedV3TimeProtocol(), MeasurementPolicy: focusedV3TimePolicy(),
	}
	for _, id := range focusedV3TargetPresetIDs {
		preset, _ := credential.LookupIntGenISISPreset(id)
		priorTarget, ok := focusedV3TimeLookupPriorTarget(prior, id)
		if !ok {
			return FocusedV3TimeOptimizationEvidence{}, fmt.Errorf("focused-v3 time predecessor missing %s", id)
		}
		issueGeometry, showGeometry, _ := focusedV3TimeExpectedGeometry(id)
		e.Targets = append(e.Targets, FocusedV3TimeOptimizationTarget{
			CanonicalID: id, ManifestDigest: credential.IntGenISISPresetManifestDigest(preset), Kappa: preset.Issuance.Kappa,
			BaselineAccepted: priorTarget.Medians, IssuanceGeometry: issueGeometry, ShowingGeometry: showGeometry,
		})
	}
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, true); err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	return e, nil
}

// BuildPendingFocusedV3TimeOptimizationFreshEvidence authenticates the six
// fresh production runs while deliberately leaving the record pending. It is
// used when fresh end-to-end evidence exists but the seven paired
// fixed-entropy allocation trials required for final adoption do not and the
// frozen BQ128 manifest-bound engineering gate remains unresolved.
func BuildPendingFocusedV3TimeOptimizationFreshEvidence(root, measuredOn string) (FocusedV3TimeOptimizationEvidence, error) {
	root, err := ResolveSPRUCE_DIR(root)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	commit, _, err := CaptureFocusedV3GitTreeState(root)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	e, err := NewPendingFocusedV3TimeOptimizationEvidence(
		root,
		measuredOn,
		commit,
		FocusedV3TimeFreshPendingReason,
	)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	source, err := sourceintegrity.Compute(root)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	e.SourceInput = FocusedV3TimeSourceInput{Algorithm: source.Algorithm, Digest: source.Digest, FileCount: source.FileCount}
	e.Environment = FocusedV3TimeEnvironment{
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		NumCPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0),
	}
	for i := range e.Targets {
		target := &e.Targets[i]
		for run := 1; run <= FocusedV3TimeOptimizationRuns; run++ {
			fresh, err := focusedV3TimeBuildFreshRun(root, e.SourceInput, e.ImplementationBaseCommit, *target, run)
			if err != nil {
				return FocusedV3TimeOptimizationEvidence{}, fmt.Errorf("build pending fresh %s run %d: %w", target.CanonicalID, run, err)
			}
			target.FreshRuns = append(target.FreshRuns, fresh)
		}
		freshMedians := focusedV3TimeFreshMedians(target.FreshRuns)
		target.FreshMedians = &freshMedians
		if focusedV3TimeCounterWidthsVary(target.FreshRuns) {
			target.CounterWidthExplanation = FocusedV3TimeCounterReason
		}
	}
	paperDir := filepath.Clean(filepath.Join(root, "..", "Better-Lattice-based-Blind-Signatures"))
	paperHead, paperClean, err := CaptureFocusedV3GitTreeState(paperDir)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	if paperHead != e.Paper.HeadBefore || !paperClean {
		return FocusedV3TimeOptimizationEvidence{}, fmt.Errorf("paper checkout changed while building pending fresh-run evidence")
	}
	e.Paper.HeadAfter, e.Paper.CleanAfter = paperHead, true
	if err := ValidateFocusedV3TimeOptimizationArtifacts(e, root, true); err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	return e, nil
}

// BuildFocusedV3TimeOptimizationEvidence projects the fixed six fresh run
// directories plus caller-supplied paired measurements into an accepted
// record. Paper must already contain matching clean before/after checkpoints.
func BuildFocusedV3TimeOptimizationEvidence(opts FocusedV3TimeOptimizationBuildOptions) (FocusedV3TimeOptimizationEvidence, error) {
	root, err := ResolveSPRUCE_DIR(opts.SPRUCE_DIR)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	measuredOn := opts.MeasuredOn
	if measuredOn == "" {
		measuredOn = time.Now().UTC().Format("2006-01-02")
	}
	prior, priorData, err := focusedV3TimeReadPrior(root)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	source, err := sourceintegrity.Compute(root)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	commit, _, err := CaptureFocusedV3GitTreeState(root)
	if err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	e := FocusedV3TimeOptimizationEvidence{
		Schema: FocusedV3TimeOptimizationSchema, Version: FocusedV3TimeOptimizationVersion, Status: FocusedV3TimeStatusAccepted,
		MeasuredOn: measuredOn, ClaimScope: string(credential.ClaimProofOnly), ImplementationBaseCommit: commit,
		SourceInput:   FocusedV3TimeSourceInput{Algorithm: source.Algorithm, Digest: source.Digest, FileCount: source.FileCount},
		Environment:   FocusedV3TimeEnvironment{GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0)},
		PriorEvidence: FocusedV3TimePriorEvidence{Path: FocusedV3TimePriorPath, SHA256: sha256Hex(priorData), Schema: prior.Schema, Version: prior.Version},
		Paper:         opts.Paper, Claims: focusedV3TimeClaims(), Protocol: focusedV3TimeProtocol(), MeasurementPolicy: focusedV3TimePolicy(),
	}
	for _, id := range focusedV3TargetPresetIDs {
		preset, _ := credential.LookupIntGenISISPreset(id)
		priorTarget, ok := focusedV3TimeLookupPriorTarget(prior, id)
		if !ok {
			return FocusedV3TimeOptimizationEvidence{}, fmt.Errorf("focused-v3 time predecessor missing %s", id)
		}
		issueGeometry, showGeometry, _ := focusedV3TimeExpectedGeometry(id)
		target := FocusedV3TimeOptimizationTarget{
			CanonicalID: id, ManifestDigest: credential.IntGenISISPresetManifestDigest(preset), Kappa: preset.Issuance.Kappa,
			BaselineAccepted: priorTarget.Medians, IssuanceGeometry: issueGeometry, ShowingGeometry: showGeometry,
			PairedRuns: append([]FocusedV3TimePairedRun(nil), opts.PairedRuns[id]...),
		}
		pairedSummary := focusedV3TimeSummarizePairs(target.PairedRuns)
		target.PairedSummary = &pairedSummary
		for run := 1; run <= FocusedV3TimeOptimizationRuns; run++ {
			fresh, err := focusedV3TimeBuildFreshRun(root, e.SourceInput, e.ImplementationBaseCommit, target, run)
			if err != nil {
				return FocusedV3TimeOptimizationEvidence{}, fmt.Errorf("build %s run %d: %w", id, run, err)
			}
			target.FreshRuns = append(target.FreshRuns, fresh)
		}
		freshMedians := focusedV3TimeFreshMedians(target.FreshRuns)
		target.FreshMedians = &freshMedians
		if focusedV3TimeCounterWidthsVary(target.FreshRuns) {
			target.CounterWidthExplanation = FocusedV3TimeCounterReason
		}
		e.Targets = append(e.Targets, target)
	}
	if err := ValidateFocusedV3TimeOptimizationArtifacts(e, root, false); err != nil {
		return FocusedV3TimeOptimizationEvidence{}, err
	}
	return e, nil
}

// ValidateFocusedV3TimeOptimizationArtifacts validates the checked summary,
// predecessor digest, current build-input snapshot, and every raw report,
// resource sidecar, state, proof, and presentation digest.
func ValidateFocusedV3TimeOptimizationArtifacts(e FocusedV3TimeOptimizationEvidence, root string, allowPending bool) error {
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, allowPending); err != nil {
		return err
	}
	root, err := ResolveSPRUCE_DIR(root)
	if err != nil {
		return err
	}
	prior, priorData, err := focusedV3TimeReadPrior(root)
	if err != nil {
		return err
	}
	if sha256Hex(priorData) != e.PriorEvidence.SHA256 || prior.Schema != e.PriorEvidence.Schema || prior.Version != e.PriorEvidence.Version {
		return fmt.Errorf("focused-v3 time predecessor digest/identity mismatch")
	}
	for _, target := range e.Targets {
		priorTarget, ok := focusedV3TimeLookupPriorTarget(prior, target.CanonicalID)
		if !ok || !reflect.DeepEqual(priorTarget.Medians, target.BaselineAccepted) || priorTarget.ShowingGeometry != target.ShowingGeometry ||
			priorTarget.ManifestDigest != target.ManifestDigest || priorTarget.Kappa != target.Kappa {
			return fmt.Errorf("focused-v3 time predecessor projection mismatch for %s", target.CanonicalID)
		}
	}
	if e.Status == FocusedV3TimeStatusPending && !focusedV3TimeEvidenceHasFreshRuns(e) {
		return nil
	}
	// Accepted evidence is bound to the live checkout. Pending historical
	// scaffolds remain bound to the commit and source digest recorded by each
	// raw artifact so they stay replayable after later implementation commits.
	if e.Status == FocusedV3TimeStatusAccepted {
		head, _, err := CaptureFocusedV3GitTreeState(root)
		if err != nil {
			return err
		}
		if head != e.ImplementationBaseCommit {
			return fmt.Errorf("focused-v3 time implementation base commit changed")
		}
		source, err := sourceintegrity.Compute(root)
		if err != nil {
			return err
		}
		if source.Algorithm != e.SourceInput.Algorithm || source.Digest != e.SourceInput.Digest || source.FileCount != e.SourceInput.FileCount {
			return fmt.Errorf("focused-v3 time live source-input digest changed")
		}
	}
	for _, target := range e.Targets {
		for _, pair := range target.PairedRuns {
			path, err := focusedV3NonResearchPath(root, pair.MeasurementArtifactPath)
			if err != nil {
				return err
			}
			data, _, err := readFocusedV3NonResearchRegularFile(path)
			if err != nil {
				return fmt.Errorf("focused-v3 time paired artifact %s pair %d: %w", target.CanonicalID, pair.Pair, err)
			}
			if sha256Hex(data) != pair.MeasurementArtifactSHA256 {
				return fmt.Errorf("focused-v3 time paired artifact digest changed for %s pair %d", target.CanonicalID, pair.Pair)
			}
			var raw FocusedV3TimePairedArtifact
			if err := decodeStrictJSON(data, &raw); err != nil {
				return fmt.Errorf("decode focused-v3 time paired artifact %s pair %d: %w", target.CanonicalID, pair.Pair, err)
			}
			wantRun := pair
			wantRun.MeasurementArtifactPath = ""
			wantRun.MeasurementArtifactSHA256 = ""
			if raw.Schema != FocusedV3TimePairSchema || raw.Version != 1 || raw.CanonicalID != target.CanonicalID || !reflect.DeepEqual(raw.Run, wantRun) {
				return fmt.Errorf("focused-v3 time paired artifact projection changed for %s pair %d", target.CanonicalID, pair.Pair)
			}
		}
		for _, run := range target.FreshRuns {
			fresh, err := focusedV3TimeBuildFreshRun(root, e.SourceInput, e.ImplementationBaseCommit, target, run.Run)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(fresh, run) {
				return fmt.Errorf("focused-v3 time raw projection changed for %s run %d", target.CanonicalID, run.Run)
			}
		}
	}
	return nil
}

func focusedV3TimePairedArtifactPath(canonicalID string, pair int) (string, error) {
	alias, ok := focusedV3NonResearchTargetAlias(canonicalID)
	if !ok || pair < 1 || pair > FocusedV3TimePairedRuns {
		return "", fmt.Errorf("invalid focused-v3 time paired artifact identity %q/%d", canonicalID, pair)
	}
	return filepath.ToSlash(filepath.Join(FocusedV3TimePairRoot, alias, fmt.Sprintf("pair-%d", pair), "pair.json")), nil
}

type focusedV3TimePrior struct {
	Schema  string                     `json:"schema"`
	Version int                        `json:"version"`
	Targets []focusedV3TimePriorTarget `json:"targets"`
}

type focusedV3TimePriorTarget struct {
	CanonicalID     string                       `json:"canonical_id"`
	ManifestDigest  string                       `json:"manifest_digest"`
	Kappa           [4]int                       `json:"kappa"`
	ShowingGeometry FocusedV3NonResearchGeometry `json:"showing_geometry"`
	Medians         FocusedV3NonResearchPrior    `json:"-"`
	RawMedians      struct {
		PersistentStateBytes   int     `json:"state_bytes"`
		IssuanceProofWireBytes int     `json:"issuance_proof_bytes"`
		ShowingProofWireBytes  int     `json:"showing_proof_bytes"`
		PresentationWireBytes  int     `json:"presentation_bytes"`
		PaperIssuanceBytes     int     `json:"issuance_paper_bytes"`
		PaperShowingBytes      int     `json:"showing_paper_bytes"`
		IssuanceProvingMS      float64 `json:"issuance_proving_ms"`
		ShowingProvingMS       float64 `json:"showing_proving_ms"`
		PeakRSSBytes           uint64  `json:"peak_rss_bytes"`
	} `json:"medians"`
}

func focusedV3TimeReadPrior(root string) (focusedV3TimePrior, []byte, error) {
	path, err := focusedV3NonResearchPath(root, FocusedV3TimePriorPath)
	if err != nil {
		return focusedV3TimePrior{}, nil, err
	}
	data, _, err := readFocusedV3NonResearchRegularFile(path)
	if err != nil {
		return focusedV3TimePrior{}, nil, err
	}
	var prior focusedV3TimePrior
	if err := json.Unmarshal(data, &prior); err != nil {
		return focusedV3TimePrior{}, nil, err
	}
	if prior.Schema != "spruce.focused-v3-final-size-optimization" || prior.Version != 1 {
		return focusedV3TimePrior{}, nil, fmt.Errorf("focused-v3 time predecessor identity changed")
	}
	for i := range prior.Targets {
		m := prior.Targets[i].RawMedians
		prior.Targets[i].Medians = FocusedV3NonResearchPrior{
			PersistentStateBytes: m.PersistentStateBytes, IssuanceProofWireBytes: m.IssuanceProofWireBytes,
			ShowingProofWireBytes: m.ShowingProofWireBytes, PresentationWireBytes: m.PresentationWireBytes,
			PaperIssuanceBytes: m.PaperIssuanceBytes, PaperShowingBytes: m.PaperShowingBytes,
			IssuanceProvingMS: m.IssuanceProvingMS, ShowingProvingMS: m.ShowingProvingMS, PeakRSSBytes: m.PeakRSSBytes,
		}
	}
	return prior, data, nil
}

func focusedV3TimeLookupPriorTarget(prior focusedV3TimePrior, id string) (focusedV3TimePriorTarget, bool) {
	for _, target := range prior.Targets {
		if target.CanonicalID == id {
			return target, true
		}
	}
	return focusedV3TimePriorTarget{}, false
}

type focusedV3TimeRawSizes struct {
	StateBytes         int `json:"persistent_credential_state_bytes"`
	IssuanceProofBytes int `json:"issuance_proof_wire_bytes"`
	ShowingProofBytes  int `json:"showing_proof_wire_bytes"`
	PresentationBytes  int `json:"presentation_wire_bytes"`
	IssuancePaperBytes int `json:"issuance_paper_transcript_bytes"`
	ShowingPaperBytes  int `json:"showing_paper_transcript_bytes"`
}

type focusedV3TimeRawPhase struct {
	ProvingMS                  float64                         `json:"proving_ms"`
	VerificationMS             float64                         `json:"verification_ms"`
	MeasurementStatus          string                          `json:"measurement_status"`
	PhaseTimings               []PIOP.PhaseTiming              `json:"phase_timings"`
	FSCounters                 *[4]uint64                      `json:"fs_counters"`
	CanonicalWire              *PIOP.CanonicalProofWireAuditV6 `json:"canonical_wire_audit"`
	CanonicalProofWireBytes    int                             `json:"canonical_proof_wire_bytes"`
	CanonicalPresentationBytes int                             `json:"canonical_presentation_wire_bytes"`
	PaperTranscriptBytes       int                             `json:"paper_transcript_bytes"`
	QBytes                     int                             `json:"q_bytes"`
	RBytes                     int                             `json:"r_bytes"`
	PDECSBytes                 int                             `json:"pdecs_bytes"`
	MDECSBytes                 int                             `json:"mdecs_bytes"`
	AuthBytes                  int                             `json:"auth_bytes"`
	TapesBytes                 int                             `json:"tapes_bytes"`
	SigShortnessBytes          int                             `json:"sig_shortness_bytes"`
	VTargetsBytes              int                             `json:"vtargets_bytes"`
	BarSetsBytes               int                             `json:"barsets_bytes"`
	TranscriptAudit            PIOP.PaperTranscriptAudit       `json:"transcript_audit"`
	AlgebraicTerms             [4]float64                      `json:"algebraic_terms"`
	AlgebraicBits              [4]float64                      `json:"algebraic_bits"`
	AlgebraicTotalBits         float64                         `json:"algebraic_total_bits"`
	TheoremBits                [4]float64                      `json:"theorem_bits"`
	TheoremTotalBits           float64                         `json:"theorem_total_bits"`
	ZeroKnowledgeEligible      bool                            `json:"zero_knowledge_eligible"`
	TotalRows                  int                             `json:"total_rows"`
	PaperShapeWitnessLayers    int                             `json:"paper_shape_witness_layers"`
	ParallelDegree             int                             `json:"parallel_degree"`
	AggregatedDegree           int                             `json:"aggregated_degree"`
	DQ                         int                             `json:"dq"`
	PaperShapeMaskRows         int                             `json:"paper_shape_mask_rows"`
	ReplayRows                 int                             `json:"smallfield_replay_rows"`
	PaperShapeNRows            int                             `json:"paper_shape_nrows"`
	PaperShapeQueries          int                             `json:"paper_shape_queries"`
	OpeningCols                int                             `json:"opening_cols"`
}

type focusedV3TimeRawReport struct {
	Version                  int                                         `json:"version"`
	CanonicalPresetID        string                                      `json:"canonical_preset_id"`
	ClaimScope               credential.ClaimScope                       `json:"claim_scope"`
	CompleteSystemClaim      bool                                        `json:"complete_system_claim"`
	PresetManifestDigest     string                                      `json:"preset_manifest_digest"`
	LedgerStatus             string                                      `json:"ledger_status"`
	FullGameAccountingStatus string                                      `json:"full_game_accounting_status"`
	ArtifactDir              string                                      `json:"artifact_dir"`
	Environment              benchmarkEnvironmentWire                    `json:"environment"`
	Options                  benchmarkOptionsWire                        `json:"options"`
	CanonicalSizes           *focusedV3TimeRawSizes                      `json:"canonical_sizes"`
	Issuance                 focusedV3TimeRawPhase                       `json:"issuance"`
	Showing                  focusedV3TimeRawPhase                       `json:"showing"`
	Artifacts                benchmarkArtifactsWire                      `json:"artifacts"`
	ParameterAudit           credential.IntGenISISSecurityParameterAudit `json:"parameter_audit"`
	ReplayRejected           bool                                        `json:"replay_rejected"`
}

func focusedV3TimeBuildFreshRun(root string, source FocusedV3TimeSourceInput, baseCommit string, target FocusedV3TimeOptimizationTarget, runNumber int) (FocusedV3TimeFreshRun, error) {
	alias, ok := focusedV3NonResearchTargetAlias(target.CanonicalID)
	if !ok {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("unknown target")
	}
	runDir := filepath.ToSlash(filepath.Join(FocusedV3TimeArtifactRoot, alias, fmt.Sprintf("run-%d", runNumber)))
	reportRel, resourceRel := runDir+"/report.json", runDir+"/resource.txt"
	reportPath, err := focusedV3NonResearchPath(root, reportRel)
	if err != nil {
		return FocusedV3TimeFreshRun{}, err
	}
	resourcePath, err := focusedV3NonResearchPath(root, resourceRel)
	if err != nil {
		return FocusedV3TimeFreshRun{}, err
	}
	reportData, _, err := readFocusedV3NonResearchRegularFile(reportPath)
	if err != nil {
		return FocusedV3TimeFreshRun{}, err
	}
	resourceData, _, err := readFocusedV3NonResearchRegularFile(resourcePath)
	if err != nil {
		return FocusedV3TimeFreshRun{}, err
	}
	var raw focusedV3TimeRawReport
	if err := json.Unmarshal(reportData, &raw); err != nil {
		return FocusedV3TimeFreshRun{}, err
	}
	if raw.CanonicalSizes == nil || raw.Issuance.FSCounters == nil || raw.Showing.FSCounters == nil || raw.Issuance.CanonicalWire == nil || raw.Showing.CanonicalWire == nil {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("report is missing canonical sizes, counters, or wire audits")
	}
	if raw.Version != 2 || raw.CanonicalPresetID != target.CanonicalID || raw.PresetManifestDigest != target.ManifestDigest ||
		raw.ClaimScope != credential.ClaimProofOnly || raw.CompleteSystemClaim || raw.LedgerStatus != string(credential.ClaimProofOnly) ||
		raw.FullGameAccountingStatus != "deferred_proof_only" || raw.ArtifactDir != runDir || raw.ParameterAudit.Status != "pass" || !raw.ReplayRejected {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("report identity/security boundary mismatch")
	}
	if raw.Environment.SourceTreeAlgorithm != source.Algorithm || raw.Environment.SourceTreeDigest != source.Digest || raw.Environment.SourceTreeFileCount != source.FileCount ||
		raw.Environment.GoVersion != "go1.23.12" || raw.Environment.GOOS != "darwin" || raw.Environment.GOARCH != "arm64" || raw.Environment.NumCPU != 15 || raw.Environment.GOMAXPROCS != 15 {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("report source/environment mismatch")
	}
	if raw.Environment.VCS != "git" || raw.Environment.Commit != baseCommit || raw.Environment.Modified == nil || !*raw.Environment.Modified {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("report git/worktree boundary mismatch")
	}
	if raw.Options.Issuance.Kappa != target.Kappa || raw.Options.Showing.Kappa != target.Kappa {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("report changed frozen kappa")
	}
	if focusedV3TimeRawGeometry(raw.Issuance) != target.IssuanceGeometry || focusedV3TimeRawGeometry(raw.Showing) != target.ShowingGeometry {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("report changed accepted geometry")
	}
	rss, err := focusedV3TranscriptResourceRSS(resourcePath)
	if err != nil {
		return FocusedV3TimeFreshRun{}, err
	}
	stateData, issueProof, presentationData, showProof, err := focusedV3TimeReadCoreArtifacts(root, runDir, raw.Artifacts, target.CanonicalID)
	if err != nil {
		return FocusedV3TimeFreshRun{}, err
	}
	sizes := *raw.CanonicalSizes
	if len(stateData) != sizes.StateBytes || len(issueProof) != sizes.IssuanceProofBytes || len(showProof) != sizes.ShowingProofBytes || len(presentationData) != sizes.PresentationBytes ||
		raw.Issuance.CanonicalProofWireBytes != sizes.IssuanceProofBytes || raw.Showing.CanonicalProofWireBytes != sizes.ShowingProofBytes || raw.Showing.CanonicalPresentationBytes != sizes.PresentationBytes {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("report canonical artifact lengths mismatch")
	}
	if raw.Issuance.CanonicalWire.TotalBytes != len(issueProof) || raw.Showing.CanonicalWire.TotalBytes != len(showProof) {
		return FocusedV3TimeFreshRun{}, fmt.Errorf("canonical wire audit does not equal proof bytes")
	}
	return FocusedV3TimeFreshRun{
		Run: runNumber, ArtifactDirectory: runDir, ReportPath: reportRel, ReportSHA256: sha256Hex(reportData), ResourcePath: resourceRel, ResourceSHA256: sha256Hex(resourceData),
		StateBytes: len(stateData), StateSHA256: sha256Hex(stateData), PresentationBytes: len(presentationData), PresentationSHA256: sha256Hex(presentationData),
		PeakRSSBytes: rss, ParameterAuditStatus: raw.ParameterAudit.Status, ReplayRejected: raw.ReplayRejected,
		Issuance: focusedV3TimeFreshPhase(raw.Issuance, issueProof), Showing: focusedV3TimeFreshPhase(raw.Showing, showProof),
	}, nil
}

func focusedV3TimeRawGeometry(p focusedV3TimeRawPhase) FocusedV3NonResearchGeometry {
	return FocusedV3NonResearchGeometry{
		LogicalRows: p.TotalRows, Layers: p.PaperShapeWitnessLayers, MaskRows: p.PaperShapeMaskRows, ReplayRows: p.ReplayRows,
		PhysicalRows: p.PaperShapeNRows, Queries: p.PaperShapeQueries, OpeningPColumns: p.OpeningCols,
		ParallelDegree: p.ParallelDegree, AggregatedDegree: p.AggregatedDegree, QDegree: p.DQ,
	}
}

func focusedV3TimeFreshPhase(raw focusedV3TimeRawPhase, proof []byte) FocusedV3TimeFreshPhase {
	return FocusedV3TimeFreshPhase{
		ProvingMS: raw.ProvingMS, VerificationMS: raw.VerificationMS, VerificationPassed: raw.VerificationMS > 0,
		MeasurementStatus: raw.MeasurementStatus, ZeroKnowledgeEligible: raw.ZeroKnowledgeEligible,
		FSCounters: *raw.FSCounters, PhaseTimings: append([]PIOP.PhaseTiming(nil), raw.PhaseTimings...), CanonicalWire: *raw.CanonicalWire,
		Paper: FocusedV3TimePaperComponents{
			FixedBytes: raw.TranscriptAudit.FixedV3.TotalBytes, RBytes: raw.RBytes, QBytes: raw.QBytes, PDECSBytes: raw.PDECSBytes, MDECSBytes: raw.MDECSBytes,
			AuthenticationBytes: raw.AuthBytes, TapeBytes: raw.TapesBytes, SignatureShortnessBytes: raw.SigShortnessBytes,
			VTargetsBytes: raw.VTargetsBytes, BarSetsBytes: raw.BarSetsBytes, TotalBytes: raw.PaperTranscriptBytes,
		},
		Theorem: FocusedV3TimeTheorem{
			AlgebraicTerms: raw.AlgebraicTerms, AlgebraicBits: raw.AlgebraicBits, AlgebraicTotalBits: raw.AlgebraicTotalBits,
			TheoremBits: raw.TheoremBits, TheoremTotalBits: raw.TheoremTotalBits,
		},
		ProofSHA256: sha256Hex(proof),
	}
}

func focusedV3TimeReadCoreArtifacts(root, runDir string, reported benchmarkArtifactsWire, id string) ([]byte, []byte, []byte, []byte, error) {
	wantState, wantSubmission, wantPresentation := runDir+"/credential_state.intgenisis.v8", runDir+"/presign_submission.json", runDir+"/presentation.intgenisis.v3"
	if reported.State != wantState || reported.Submission != wantSubmission || reported.Presentation != wantPresentation {
		return nil, nil, nil, nil, fmt.Errorf("report core artifact paths changed")
	}
	read := func(rel string) ([]byte, error) {
		path, err := focusedV3NonResearchPath(root, rel)
		if err != nil {
			return nil, err
		}
		data, _, err := readFocusedV3NonResearchRegularFile(path)
		return data, err
	}
	state, err := read(wantState)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	submission, err := read(wantSubmission)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var envelope struct {
		CanonicalProof []byte `json:"canonical_proof"`
	}
	if err := json.Unmarshal(submission, &envelope); err != nil || len(envelope.CanonicalProof) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("decode canonical issuance proof: %w", err)
	}
	presentation, err := read(wantPresentation)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	preset, _ := credential.LookupIntGenISISPreset(id)
	tagCount, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok {
		return nil, nil, nil, nil, fmt.Errorf("unknown tag profile")
	}
	offset := 8 + (tagCount*20+7)/8
	if offset >= len(presentation) {
		return nil, nil, nil, nil, fmt.Errorf("presentation envelope is truncated")
	}
	return state, envelope.CanonicalProof, presentation, presentation[offset:], nil
}

func focusedV3TimeCounterWidthsVary(runs []FocusedV3TimeFreshRun) bool {
	issue, show := map[int]bool{}, map[int]bool{}
	for _, run := range runs {
		issue[run.Issuance.CanonicalWire.CounterBytes] = true
		show[run.Showing.CanonicalWire.CounterBytes] = true
	}
	return len(issue) > 1 || len(show) > 1
}
