package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	kfield "vSIS-Signature/internal/kfield"
)

const (
	PublicationV4CandidateLockSchema  = "spruce.publication-candidate-lock.v4"
	PublicationV4BenchmarkBatchSchema = "spruce.publication-benchmark-batch.v4"
	PublicationV4EvidenceVersion      = 4
	PublicationV4PresetCount          = 5
	PublicationV4FinalistCount        = 12
	PublicationV4FinalRunsPerPreset   = 7
	PublicationV4RunsPerPreset        = PublicationV4FinalistCount + 2*3 + PublicationV4FinalRunsPerPreset
	PublicationV4TotalRuns            = PublicationV4PresetCount * PublicationV4RunsPerPreset
)

var publicationV4Labels = []string{
	credential.IntGenISISPublicationLabelBQ96Q32,
	credential.IntGenISISPublicationLabelBQ96Q96,
	credential.IntGenISISPublicationLabelWF128,
	credential.IntGenISISPublicationLabelBQ128Q64,
	credential.IntGenISISPublicationLabelBQ128Q128,
}

// PublicationV4CandidateBinding is the manifest-bound tuning record emitted
// by the analytic search. Field order intentionally mirrors the producer: the
// content digest is over encoding/json's deterministic struct encoding.
type PublicationV4CandidateBinding struct {
	CanonicalID      string                            `json:"canonical_id"`
	PublicationLabel string                            `json:"publication_label"`
	ManifestDigest   string                            `json:"manifest_digest"`
	ManifestStatus   string                            `json:"manifest_status"`
	Issuance         credential.IntGenISISTuningPreset `json:"issuance"`
	Showing          credential.IntGenISISTuningPreset `json:"showing"`
	CandidateDigest  string                            `json:"candidate_digest"`
	SelectionStatus  string                            `json:"selection_status"`
	Projection       *PublicationV4CandidateProjection `json:"projection,omitempty"`
}

type PublicationV4CandidateProjection struct {
	ShowingProofMaxBytes    int        `json:"showing_proof_max_bytes"`
	PresentationMaxBytes    int        `json:"presentation_max_bytes"`
	ShowingPaperBytes       int        `json:"showing_paper_structural_bytes"`
	CombinedProofMaxBytes   int        `json:"combined_proof_max_bytes"`
	CombinedPaperBytes      int        `json:"combined_paper_structural_bytes"`
	ExpectedGrindingWork    uint64     `json:"expected_grinding_work"`
	ProjectedWorkUnits      uint64     `json:"projected_work_units"`
	MinimumSecuritySlack    float64    `json:"minimum_security_slack_bits"`
	RawRoundBitsIssuance    [4]float64 `json:"raw_round_bits_issuance"`
	RawRoundBitsShowing     [4]float64 `json:"raw_round_bits_showing"`
	RequiredNativeRoundBits float64    `json:"required_native_round_bits"`
}

type PublicationV4FinalistExecution struct {
	CandidateDigest string `json:"candidate_digest"`
	ReportFile      string `json:"report_file"`
	ReportSHA256    string `json:"report_sha256"`
	Status          string `json:"status"`
}

type PublicationV4PresetSearchResult struct {
	CanonicalID            string                                   `json:"canonical_id"`
	PublicationLabel       string                                   `json:"publication_label"`
	ManifestDigest         string                                   `json:"manifest_digest"`
	CandidateCount         int                                      `json:"candidate_count"`
	EligibleCount          int                                      `json:"eligible_count"`
	Winner                 PublicationV4CandidateBinding            `json:"winner"`
	Finalists              []PublicationV4CandidateBinding          `json:"finalists"`
	ExecutedFinalists      []PublicationV4FinalistExecution         `json:"executed_finalists"`
	MeasurementStatus      string                                   `json:"measurement_status"`
	BoundaryHits           []string                                 `json:"boundary_hits,omitempty"`
	SupportFloorHits       []string                                 `json:"support_floor_hits,omitempty"`
	ExpandableBoundaryHits []string                                 `json:"expandable_boundary_hits,omitempty"`
	WinnerInterior         bool                                     `json:"winner_interior"`
	LowerBoundExclusions   []string                                 `json:"lower_bound_exclusions"`
	CertifiedSupportFloors []PublicationV4SupportFloorCertification `json:"certified_support_floors"`
	EnvelopesSearched      []PublicationV4SearchEnvelope            `json:"envelopes_searched"`
}

type PublicationV4SupportFloorCertification struct {
	Dimension string `json:"dimension"`
	Minimum   int    `json:"minimum"`
	Basis     string `json:"basis"`
}

type PublicationV4SourceBinding struct {
	Algorithm     string `json:"algorithm"`
	Digest        string `json:"digest"`
	FileCount     int    `json:"file_count"`
	Commit        string `json:"git_commit"`
	Modified      bool   `json:"git_modified"`
	BuildSHA256   string `json:"build_sha256"`
	MachineDigest string `json:"machine_digest"`
	CPUModel      string `json:"cpu_model"`
	CPUFeatures   string `json:"cpu_features"`
}

type PublicationV4StoppingEvidence struct {
	WinnerInterior               bool     `json:"winner_interior"`
	NearFrontierInterior         bool     `json:"near_frontier_interior"`
	ExactIntegerRoots            bool     `json:"exact_integer_roots"`
	AdmissibleLowerBoundsApplied bool     `json:"admissible_lower_bounds_applied"`
	ProjectionMeasurementPending bool     `json:"projection_measurement_pending"`
	UnresolvedBoundaries         []string `json:"unresolved_boundaries"`
	BoundaryExpansionRule        string   `json:"boundary_expansion_rule"`
	StableExpandedEnvelopes      int      `json:"stable_expanded_envelopes"`
	SupportFloorsCertified       bool     `json:"support_floors_certified"`
}

type PublicationV4SearchEnvelope struct {
	LIssuanceMin int    `json:"l_issuance_min"`
	LIssuanceMax int    `json:"l_issuance_max"`
	LShowingMin  int    `json:"l_showing_min"`
	LShowingMax  int    `json:"l_showing_max"`
	ThetaMin     int    `json:"theta_min"`
	ThetaMax     int    `json:"theta_max"`
	EllMin       int    `json:"ell_min"`
	EllMax       int    `json:"ell_max"`
	KappaMin     int    `json:"kappa_min"`
	KappaMax     int    `json:"kappa_max"`
	NLeavesMin   string `json:"nleaves_min"`
	NLeavesMax   int    `json:"nleaves_max"`
}

type PublicationV4CandidateLock struct {
	Schema              string                            `json:"schema"`
	Version             int                               `json:"version"`
	Status              string                            `json:"status"`
	SearchAlgorithm     string                            `json:"search_algorithm"`
	Ranking             []string                          `json:"ranking"`
	Envelope            PublicationV4SearchEnvelope       `json:"envelope"`
	EnvelopesSearched   []PublicationV4SearchEnvelope     `json:"envelopes_searched"`
	CounterBound        string                            `json:"counter_bound"`
	MerkleBound         string                            `json:"merkle_bound"`
	Source              PublicationV4SourceBinding        `json:"source"`
	Stopping            PublicationV4StoppingEvidence     `json:"stopping_evidence"`
	NoLivePresetRewrite bool                              `json:"no_live_preset_rewrite"`
	PresetCount         int                               `json:"preset_count"`
	Presets             []PublicationV4PresetSearchResult `json:"presets"`
	ContentDigest       string                            `json:"content_digest"`
}

type PublicationV4Environment struct {
	GoVersion           string `json:"go_version"`
	GOOS                string `json:"goos"`
	GOARCH              string `json:"goarch"`
	NumCPU              int    `json:"num_cpu"`
	GOMAXPROCS          int    `json:"gomaxprocs"`
	VCS                 string `json:"vcs,omitempty"`
	Commit              string `json:"commit,omitempty"`
	CommitTime          string `json:"commit_time,omitempty"`
	Modified            *bool  `json:"modified,omitempty"`
	SourceTreeAlgorithm string `json:"source_tree_algorithm,omitempty"`
	SourceTreeDigest    string `json:"source_tree_digest,omitempty"`
	SourceTreeFileCount int    `json:"source_tree_file_count,omitempty"`
	BuildSHA256         string `json:"build_sha256"`
	CPUModel            string `json:"cpu_model"`
	CPUFeatures         string `json:"cpu_features"`
	MachineDigest       string `json:"machine_digest"`
}

type PublicationV4RunMetrics struct {
	CredentialStateBytes   int     `json:"credential_state_bytes"`
	IssuanceProofBytes     int     `json:"issuance_proof_wire_bytes"`
	ShowingProofBytes      int     `json:"showing_proof_wire_bytes"`
	IssuanceProofMaxBytes  int     `json:"issuance_proof_max_bytes"`
	ShowingProofMaxBytes   int     `json:"showing_proof_max_bytes"`
	PresentationBytes      int     `json:"presentation_wire_bytes"`
	PresentationMaxBytes   int     `json:"presentation_max_bytes"`
	IssuancePaperBytes     int     `json:"issuance_paper_transcript_bytes"`
	ShowingPaperBytes      int     `json:"showing_paper_transcript_bytes"`
	IssuanceProvingMS      float64 `json:"issuance_proving_ms"`
	IssuanceVerificationMS float64 `json:"issuance_verification_ms"`
	ShowingProvingMS       float64 `json:"showing_proving_ms"`
	ShowingVerificationMS  float64 `json:"showing_verification_ms"`
	AllocatedBytes         uint64  `json:"allocated_bytes"`
	Allocations            uint64  `json:"allocations"`
	PeakRSSBytes           uint64  `json:"peak_rss_bytes"`
}

type PublicationV4PhaseWireRun struct {
	CounterBytes          int       `json:"counter_bytes"`
	FSCounters            [4]uint64 `json:"fs_counters"`
	AuthenticationBytes   int       `json:"authentication_bytes"`
	MerkleNodesUsed       int       `json:"merkle_nodes_used"`
	MerkleNodesBound      int       `json:"merkle_nodes_bound"`
	DeterministicMaxBytes int       `json:"deterministic_max_bytes"`
}

type PublicationV4BenchmarkRun struct {
	Stage                    string                    `json:"stage"`
	CandidateRank            int                       `json:"candidate_rank"`
	CandidateRun             int                       `json:"candidate_run"`
	Round                    int                       `json:"round"`
	RotationPosition         int                       `json:"rotation_position"`
	CanonicalID              string                    `json:"canonical_id"`
	PublicationLabel         string                    `json:"publication_label"`
	CandidateDigest          string                    `json:"candidate_digest"`
	ManifestDigest           string                    `json:"manifest_digest"`
	RunDirectory             string                    `json:"run_directory"`
	ReportFile               string                    `json:"report_file"`
	ReportSHA256             string                    `json:"report_sha256"`
	ResourceFile             string                    `json:"resource_file"`
	ResourceSHA256           string                    `json:"resource_sha256"`
	Environment              PublicationV4Environment  `json:"environment"`
	Metrics                  PublicationV4RunMetrics   `json:"metrics"`
	ConfiguredFSBits         int                       `json:"configured_fs_output_bits"`
	ObservedFSBits           [][4]int                  `json:"observed_fs_digest_bits"`
	IssuanceWire             PublicationV4PhaseWireRun `json:"issuance_wire"`
	ShowingWire              PublicationV4PhaseWireRun `json:"showing_wire"`
	ReplayRejected           bool                      `json:"replay_rejected"`
	TamperRejected           bool                      `json:"tamper_rejected"`
	ArtifactHashesVerified   bool                      `json:"artifact_hashes_verified"`
	ArtifactSHA256           map[string]string         `json:"artifact_sha256"`
	FullGameAccountingStatus string                    `json:"full_game_accounting_status"`
	LedgerStatus             string                    `json:"ledger_status"`
	ParameterAuditStatus     string                    `json:"parameter_audit_status"`
}

type PublicationV4BenchmarkScheduleEntry struct {
	Sequence         int    `json:"sequence"`
	Stage            string `json:"stage"`
	CanonicalID      string `json:"canonical_id"`
	CandidateDigest  string `json:"candidate_digest"`
	CandidateRank    int    `json:"candidate_rank"`
	CandidateRun     int    `json:"candidate_run"`
	RotationPosition int    `json:"rotation_position"`
}

type PublicationV4BenchmarkAcceptance struct {
	ExactFivePresets        bool `json:"exact_five_presets"`
	LockStoppingCertified   bool `json:"lock_stopping_certified"`
	FinalistRunCounts       bool `json:"finalist_run_counts"`
	CandidateManifests      bool `json:"candidate_manifests"`
	ReplayRejected          bool `json:"replay_rejected"`
	TamperRejected          bool `json:"tamper_rejected"`
	ArtifactHashesVerified  bool `json:"artifact_hashes_verified"`
	FSWidthsVerified        bool `json:"fs_widths_verified"`
	AggregateQueryPolicy    bool `json:"aggregate_query_policy"`
	SourceBuildMachine      bool `json:"source_build_machine"`
	CanonicalSizes          bool `json:"canonical_sizes"`
	Resources               bool `json:"resources"`
	FullGameAccounting      bool `json:"full_game_accounting"`
	ProjectedWinnerMeasured bool `json:"projected_winner_measured"`
	LiveManifestAdopted     bool `json:"live_manifest_adopted"`
}

type PublicationV4Distribution struct {
	Median float64 `json:"median"`
	MAD    float64 `json:"mad"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

type PublicationV4PresetAggregate struct {
	CanonicalID            string                    `json:"canonical_id"`
	PublicationLabel       string                    `json:"publication_label"`
	CandidateDigest        string                    `json:"candidate_digest"`
	Runs                   int                       `json:"runs"`
	CredentialStateBytes   PublicationV4Distribution `json:"credential_state_bytes"`
	IssuanceProofBytes     PublicationV4Distribution `json:"issuance_proof_wire_bytes"`
	ShowingProofBytes      PublicationV4Distribution `json:"showing_proof_wire_bytes"`
	IssuanceProofMaxBytes  PublicationV4Distribution `json:"issuance_proof_max_bytes"`
	ShowingProofMaxBytes   PublicationV4Distribution `json:"showing_proof_max_bytes"`
	PresentationBytes      PublicationV4Distribution `json:"presentation_wire_bytes"`
	PresentationMaxBytes   PublicationV4Distribution `json:"presentation_max_bytes"`
	IssuancePaperBytes     PublicationV4Distribution `json:"issuance_paper_transcript_bytes"`
	ShowingPaperBytes      PublicationV4Distribution `json:"showing_paper_transcript_bytes"`
	IssuanceProvingMS      PublicationV4Distribution `json:"issuance_proving_ms"`
	IssuanceVerificationMS PublicationV4Distribution `json:"issuance_verification_ms"`
	ShowingProvingMS       PublicationV4Distribution `json:"showing_proving_ms"`
	ShowingVerificationMS  PublicationV4Distribution `json:"showing_verification_ms"`
	AllocatedBytes         PublicationV4Distribution `json:"allocated_bytes"`
	Allocations            PublicationV4Distribution `json:"allocations"`
	PeakRSSBytes           PublicationV4Distribution `json:"peak_rss_bytes"`
}

type PublicationV4BenchmarkBatch struct {
	Schema               string                                `json:"schema"`
	Version              int                                   `json:"version"`
	Status               string                                `json:"status"`
	GeneratedAt          string                                `json:"generated_at"`
	BatchID              string                                `json:"batch_id"`
	CandidateLockFile    string                                `json:"candidate_lock_file"`
	CandidateLockDigest  string                                `json:"candidate_lock_digest"`
	RunsPerPreset        int                                   `json:"runs_per_preset"`
	Rotation             [][]string                            `json:"rotation"`
	ExecutionPolicy      string                                `json:"execution_policy"`
	Schedule             []PublicationV4BenchmarkScheduleEntry `json:"schedule"`
	Acceptance           PublicationV4BenchmarkAcceptance      `json:"acceptance"`
	SourceAndMachineSame bool                                  `json:"source_and_machine_consistent"`
	Environment          PublicationV4Environment              `json:"environment"`
	Runs                 []PublicationV4BenchmarkRun           `json:"runs"`
	Presets              []PublicationV4PresetAggregate        `json:"presets"`
	ReportsDigest        string                                `json:"reports_digest"`
}

type publicationV4RunKey struct {
	preset, stage string
	rank, run     int
}

// DecodePublicationV4CandidateLock and DecodePublicationV4BenchmarkBatch are
// deliberately strict at every typed level and reject trailing JSON.
func DecodePublicationV4CandidateLock(data []byte) (PublicationV4CandidateLock, error) {
	var lock PublicationV4CandidateLock
	if err := decodeStrictJSON(data, &lock); err != nil {
		return PublicationV4CandidateLock{}, fmt.Errorf("decode publication-v4 candidate lock: %w", err)
	}
	return lock, nil
}

func DecodePublicationV4BenchmarkBatch(data []byte) (PublicationV4BenchmarkBatch, error) {
	var batch PublicationV4BenchmarkBatch
	if err := decodeStrictJSON(data, &batch); err != nil {
		return PublicationV4BenchmarkBatch{}, fmt.Errorf("decode publication-v4 benchmark batch: %w", err)
	}
	return batch, nil
}

// ValidatePublicationV4CandidateLock authenticates the exhaustive-search
// result and every retained prospective manifest. It accepts measurement-
// pending locks because the immutable lock is consumed by the separate,
// content-addressed execution batch; final evidence must validate both.
func ValidatePublicationV4CandidateLock(lock PublicationV4CandidateLock) error {
	if lock.Schema != PublicationV4CandidateLockSchema || lock.Version != PublicationV4EvidenceVersion {
		return fmt.Errorf("candidate lock identity (%q,v%d) is not publication v4", lock.Schema, lock.Version)
	}
	if lock.Status != "analytic_complete_measurement_pending" || strings.TrimSpace(lock.SearchAlgorithm) == "" ||
		strings.TrimSpace(lock.CounterBound) == "" || strings.TrimSpace(lock.MerkleBound) == "" || !lock.NoLivePresetRewrite {
		return fmt.Errorf("candidate lock is missing its search/no-rewrite policy")
	}
	if !lock.Stopping.WinnerInterior || !lock.Stopping.NearFrontierInterior ||
		!lock.Stopping.ExactIntegerRoots || !lock.Stopping.AdmissibleLowerBoundsApplied || !lock.Stopping.ProjectionMeasurementPending ||
		!lock.Stopping.SupportFloorsCertified || len(lock.Stopping.UnresolvedBoundaries) != 0 || lock.Stopping.StableExpandedEnvelopes < 2 ||
		strings.TrimSpace(lock.Stopping.BoundaryExpansionRule) == "" {
		return fmt.Errorf("candidate lock does not certify the boundary-expanded stopping rule")
	}
	if err := validatePublicationV4SourceBinding(lock.Source); err != nil {
		return fmt.Errorf("candidate lock source: %w", err)
	}
	wantRanking := []string{
		"eligible", "showing_proof_max_bytes", "presentation_max_bytes", "showing_paper_transcript_bytes",
		"combined_proof_max_bytes", "combined_paper_transcript_bytes", "expected_grinding_work",
		"projected_work_units", "minimum_security_slack_desc", "lexicographic_tuning_including_phase_nleaves",
	}
	if !reflect.DeepEqual(lock.Ranking, wantRanking) {
		return fmt.Errorf("candidate lock ranking is not the publication-v4 deterministic order")
	}
	if err := validatePublicationV4SearchEnvelopes(lock.Envelope, lock.EnvelopesSearched); err != nil {
		return fmt.Errorf("candidate lock did not cover and expand the required search envelope")
	}
	names := credential.IntGenISISPublicationPresetNamesV4()
	if lock.PresetCount != PublicationV4PresetCount || len(lock.Presets) != PublicationV4PresetCount || len(names) != PublicationV4PresetCount {
		return fmt.Errorf("candidate lock does not contain exactly five publication presets")
	}
	for i := range lock.Presets {
		result := lock.Presets[i]
		base, ok := credential.LookupIntGenISISPublicationPreset(names[i])
		if !ok || result.CanonicalID != names[i] || result.PublicationLabel != publicationV4Labels[i] {
			return fmt.Errorf("candidate lock preset %d is not in canonical paper order", i)
		}
		if result.ManifestDigest != credential.IntGenISISPresetManifestDigest(base) {
			return fmt.Errorf("candidate lock base manifest mismatch for %s", result.CanonicalID)
		}
		if result.CandidateCount < result.EligibleCount || result.EligibleCount < PublicationV4FinalistCount ||
			len(result.Finalists) != PublicationV4FinalistCount ||
			!publicationV4CertifiedResultBoundaries(result, lock.EnvelopesSearched[0]) ||
			!reflect.DeepEqual(result.EnvelopesSearched, lock.EnvelopesSearched) {
			return fmt.Errorf("candidate lock search result for %s is incomplete", result.CanonicalID)
		}
		seen := make(map[string]struct{}, PublicationV4FinalistCount)
		for rank := range result.Finalists {
			candidate := result.Finalists[rank]
			if err := validatePublicationV4Candidate(candidate, base); err != nil {
				return fmt.Errorf("candidate lock %s finalist %d: %w", result.CanonicalID, rank+1, err)
			}
			if _, duplicate := seen[candidate.CandidateDigest]; duplicate {
				return fmt.Errorf("candidate lock %s repeats finalist digest %s", result.CanonicalID, candidate.CandidateDigest)
			}
			seen[candidate.CandidateDigest] = struct{}{}
			if rank > 0 && publicationV4CandidateLess(candidate, result.Finalists[rank-1]) {
				return fmt.Errorf("candidate lock %s finalists are not deterministically ranked", result.CanonicalID)
			}
		}
		if !reflect.DeepEqual(result.Winner, result.Finalists[0]) {
			return fmt.Errorf("candidate lock %s winner is not finalist rank 1", result.CanonicalID)
		}
		for _, execution := range result.ExecutedFinalists {
			if _, ok := seen[execution.CandidateDigest]; !ok || strings.TrimSpace(execution.ReportFile) == "" ||
				!validHexDigest(execution.ReportSHA256, sha256.Size*2) || execution.Status != "pass" {
				return fmt.Errorf("candidate lock %s has an invalid finalist execution", result.CanonicalID)
			}
		}
	}
	got := lock.ContentDigest
	lock.ContentDigest = ""
	want, err := publicationV4Digest(lock)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("candidate lock content digest mismatch: have %q want %q", got, want)
	}
	return nil
}

func validatePublicationV4SearchEnvelopes(final PublicationV4SearchEnvelope, searched []PublicationV4SearchEnvelope) error {
	initial := PublicationV4SearchEnvelope{
		LIssuanceMin: 32, LIssuanceMax: 64, LShowingMin: 32, LShowingMax: 64,
		ThetaMin: 5, ThetaMax: 16, EllMin: 6, EllMax: 22, KappaMin: 0, KappaMax: 13,
		NLeavesMin: "L+2*ell", NLeavesMax: int(credential.IntGenISISSharedModulusQ - 1),
	}
	if len(searched) < 3 || searched[0] != initial || final != searched[len(searched)-1] {
		return fmt.Errorf("missing exact initial/final envelope binding")
	}
	previous := searched[0]
	for i := 1; i < len(searched); i++ {
		current := searched[i]
		if current.LIssuanceMin != initial.LIssuanceMin || current.LShowingMin != initial.LShowingMin ||
			current.ThetaMin != initial.ThetaMin || current.EllMin != initial.EllMin ||
			current.KappaMin != initial.KappaMin || current.KappaMax != initial.KappaMax ||
			current.NLeavesMin != initial.NLeavesMin || current.NLeavesMax != initial.NLeavesMax ||
			(current.LIssuanceMax-previous.LIssuanceMax != 0 && current.LIssuanceMax-previous.LIssuanceMax != 16) ||
			(current.LShowingMax-previous.LShowingMax != 0 && current.LShowingMax-previous.LShowingMax != 16) ||
			(current.ThetaMax-previous.ThetaMax != 0 && current.ThetaMax-previous.ThetaMax != 2) ||
			(current.EllMax-previous.EllMax != 0 && current.EllMax-previous.EllMax != 4) {
			return fmt.Errorf("envelope %d is not a supported monotone expansion", i+1)
		}
		if current.LIssuanceMax == previous.LIssuanceMax && current.LShowingMax == previous.LShowingMax &&
			current.ThetaMax == previous.ThetaMax && current.EllMax == previous.EllMax {
			return fmt.Errorf("envelope %d does not expand a supported boundary", i+1)
		}
		previous = current
	}
	return nil
}

func publicationV4CertifiedResultBoundaries(result PublicationV4PresetSearchResult, initial PublicationV4SearchEnvelope) bool {
	if !result.WinnerInterior || len(result.ExpandableBoundaryHits) != 0 || len(result.CertifiedSupportFloors) != 4 {
		return false
	}
	wantFloors := []PublicationV4SupportFloorCertification{
		{Dimension: "l_issuance_lower", Minimum: initial.LIssuanceMin, Basis: "user_frozen_ncols_32_and_supported_lvcs_envelope"},
		{Dimension: "l_showing_lower", Minimum: initial.LShowingMin, Basis: "user_frozen_ncols_32_and_supported_lvcs_envelope"},
		{Dimension: "theta_lower", Minimum: initial.ThetaMin, Basis: "approved_publication_extension_field_support_floor"},
		{Dimension: "ell_lower", Minimum: initial.EllMin, Basis: "approved_publication_decs_opening_support_floor"},
	}
	if !reflect.DeepEqual(result.CertifiedSupportFloors, wantFloors) {
		return false
	}
	allowed := make(map[string]bool, len(wantFloors))
	for _, floor := range wantFloors {
		allowed[floor.Dimension] = true
	}
	partition := make(map[string]int, len(result.BoundaryHits))
	for _, hit := range result.BoundaryHits {
		partition[hit]++
	}
	for _, hit := range result.SupportFloorHits {
		if !allowed[hit] {
			return false
		}
		partition[hit]--
	}
	for _, hit := range result.ExpandableBoundaryHits {
		if strings.HasSuffix(hit, "_lower") {
			return false
		}
		partition[hit]--
	}
	for _, count := range partition {
		if count != 0 {
			return false
		}
	}
	joined := strings.ToLower(strings.Join(result.LowerBoundExclusions, "\n"))
	for _, marker := range []string{"lvcsncols < 32", "theta < 5", "ell < 6"} {
		if !strings.Contains(joined, marker) {
			return false
		}
	}
	return true
}

func validatePublicationV4Candidate(binding PublicationV4CandidateBinding, base credential.IntGenISISPreset) error {
	if binding.CanonicalID != base.CanonicalID || binding.PublicationLabel != base.PublicationLabel ||
		binding.ManifestStatus != "pinned_validated" || !validHexDigest(binding.ManifestDigest, sha256.Size*2) ||
		!validHexDigest(binding.CandidateDigest, sha256.Size*2) || binding.Projection == nil {
		return fmt.Errorf("candidate identity/manifest/projection is incomplete")
	}
	candidate := base
	candidate.Issuance, candidate.Showing = binding.Issuance, binding.Showing
	candidate.LVCSNCols = binding.Showing.LVCSNCols
	candidate.MaxNLeaves = maxPublicationV4Int(binding.Issuance.NLeaves, binding.Showing.NLeaves)
	if binding.Issuance.Theta != binding.Showing.Theta {
		return fmt.Errorf("issuance/showing theta mismatch")
	}
	profile, ok := kfield.LookupSmallWoodFieldProfileV3(credential.IntGenISISSharedModulusQ, binding.Showing.Theta)
	if !ok {
		return fmt.Errorf("theta %d has no pinned extension-field profile", binding.Showing.Theta)
	}
	digest, err := profile.DigestHex(32)
	if err != nil {
		return err
	}
	candidate.FieldProfileID, candidate.FieldProfileDigest = profile.ID, digest
	if err := credential.ValidateIntGenISISPresetManifest(candidate); err != nil {
		return fmt.Errorf("prospective manifest is invalid: %w", err)
	}
	if got := credential.IntGenISISPresetManifestDigest(candidate); got != binding.ManifestDigest {
		return fmt.Errorf("prospective manifest digest=%s want %s", got, binding.ManifestDigest)
	}
	projection := binding.Projection
	if projection.ShowingProofMaxBytes <= 0 || projection.PresentationMaxBytes < projection.ShowingProofMaxBytes ||
		projection.ShowingPaperBytes <= 0 || projection.CombinedProofMaxBytes <= projection.ShowingProofMaxBytes ||
		projection.CombinedPaperBytes <= projection.ShowingPaperBytes || projection.ExpectedGrindingWork == 0 ||
		projection.ProjectedWorkUnits == 0 || !finiteNonnegative(projection.MinimumSecuritySlack) ||
		math.Abs(projection.RequiredNativeRoundBits-base.TargetTheoremBits) > 1e-8 {
		return fmt.Errorf("candidate projection has invalid size/work/security values")
	}
	for phase, pair := range []struct {
		raw   [4]float64
		kappa [4]int
	}{{projection.RawRoundBitsIssuance, binding.Issuance.Kappa}, {projection.RawRoundBitsShowing, binding.Showing.Kappa}} {
		for round := range pair.raw {
			if !finitePositive(pair.raw[round]) || pair.kappa[round] < 0 || pair.kappa[round] > 13 ||
				pair.raw[round]+float64(pair.kappa[round])+1e-8 < projection.RequiredNativeRoundBits {
				return fmt.Errorf("phase %d round %d fails the native security gate", phase+1, round+1)
			}
		}
	}
	copyBinding := binding
	copyBinding.CandidateDigest = ""
	wantDigest, err := publicationV4Digest(copyBinding)
	if err != nil {
		return err
	}
	if binding.CandidateDigest != wantDigest {
		return fmt.Errorf("candidate content digest mismatch")
	}
	return nil
}

func publicationV4CandidateLess(left, right PublicationV4CandidateBinding) bool {
	l, r := left.Projection, right.Projection
	if l == nil || r == nil {
		return r != nil
	}
	ints := [][2]int{
		{l.ShowingProofMaxBytes, r.ShowingProofMaxBytes}, {l.PresentationMaxBytes, r.PresentationMaxBytes},
		{l.ShowingPaperBytes, r.ShowingPaperBytes}, {l.CombinedProofMaxBytes, r.CombinedProofMaxBytes},
		{l.CombinedPaperBytes, r.CombinedPaperBytes},
	}
	for _, pair := range ints {
		if pair[0] != pair[1] {
			return pair[0] < pair[1]
		}
	}
	if l.ExpectedGrindingWork != r.ExpectedGrindingWork {
		return l.ExpectedGrindingWork < r.ExpectedGrindingWork
	}
	if l.ProjectedWorkUnits != r.ProjectedWorkUnits {
		return l.ProjectedWorkUnits < r.ProjectedWorkUnits
	}
	if math.Abs(l.MinimumSecuritySlack-r.MinimumSecuritySlack) > 1e-12 {
		return l.MinimumSecuritySlack > r.MinimumSecuritySlack
	}
	lv := publicationV4TuningLexicographic(left)
	rv := publicationV4TuningLexicographic(right)
	for i := range lv {
		if lv[i] != rv[i] {
			return lv[i] < rv[i]
		}
	}
	return left.CandidateDigest < right.CandidateDigest
}

func publicationV4TuningLexicographic(binding PublicationV4CandidateBinding) []int {
	return []int{
		binding.Showing.SigShortnessRadix, binding.Showing.SigShortnessDigits,
		binding.Showing.LVCSNCols, binding.Issuance.LVCSNCols,
		binding.Showing.NLeaves, binding.Issuance.NLeaves,
		binding.Showing.Eta, binding.Issuance.Eta, binding.Showing.Theta, binding.Showing.Ell,
		binding.Showing.Kappa[0], binding.Showing.Kappa[1], binding.Showing.Kappa[2], binding.Showing.Kappa[3],
		binding.Issuance.Kappa[0], binding.Issuance.Kappa[1], binding.Issuance.Kappa[2], binding.Issuance.Kappa[3],
	}
}

func validatePublicationV4SourceBinding(source PublicationV4SourceBinding) error {
	if strings.TrimSpace(source.Algorithm) == "" || !validHexDigest(source.Digest, sha256.Size*2) || source.FileCount <= 0 ||
		strings.TrimSpace(source.Commit) == "" || !validHexDigest(source.BuildSHA256, sha256.Size*2) ||
		!validHexDigest(source.MachineDigest, sha256.Size*2) || strings.TrimSpace(source.CPUModel) == "" ||
		strings.TrimSpace(source.CPUFeatures) == "" {
		return fmt.Errorf("incomplete source/build/machine binding")
	}
	return nil
}

func publicationV4Digest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func maxPublicationV4Int(left, right int) int {
	if left > right {
		return left
	}
	return right
}

// ValidatePublicationV4BenchmarkBatch recomputes all invariants carried by
// the summary. ValidatePublicationV4BenchmarkArtifacts additionally reopens
// and hashes the lock, raw reports, resource logs, and artifact bundles.
func ValidatePublicationV4BenchmarkBatch(batch PublicationV4BenchmarkBatch, lock PublicationV4CandidateLock) error {
	if err := ValidatePublicationV4CandidateLock(lock); err != nil {
		return fmt.Errorf("candidate lock: %w", err)
	}
	if batch.Schema != PublicationV4BenchmarkBatchSchema || batch.Version != PublicationV4EvidenceVersion {
		return fmt.Errorf("benchmark batch identity (%q,v%d) is not publication v4", batch.Schema, batch.Version)
	}
	const executionPolicy = "top-12 once; analytic top-3 three total runs including screening; analytic winner seven additional fresh final runs; cyclic preset rotation"
	if batch.Status != "accepted" || strings.TrimSpace(batch.BatchID) == "" ||
		strings.TrimSpace(batch.CandidateLockFile) == "" || batch.ExecutionPolicy != executionPolicy {
		return fmt.Errorf("benchmark batch is missing its identity/execution policy")
	}
	if _, err := time.Parse(time.RFC3339Nano, batch.GeneratedAt); err != nil {
		return fmt.Errorf("benchmark batch generated_at is invalid: %w", err)
	}
	if batch.CandidateLockDigest != lock.ContentDigest {
		return fmt.Errorf("benchmark batch candidate-lock digest mismatch")
	}
	if batch.RunsPerPreset != PublicationV4FinalRunsPerPreset || !batch.SourceAndMachineSame || !publicationV4AcceptanceComplete(batch.Acceptance) {
		return fmt.Errorf("benchmark batch acceptance envelope is incomplete")
	}
	if err := validatePublicationV4Environment(batch.Environment); err != nil {
		return fmt.Errorf("benchmark batch environment: %w", err)
	}
	modified := batch.Environment.Modified != nil && *batch.Environment.Modified
	if lock.Source.Algorithm != batch.Environment.SourceTreeAlgorithm || lock.Source.Digest != batch.Environment.SourceTreeDigest ||
		lock.Source.FileCount != batch.Environment.SourceTreeFileCount || lock.Source.Commit != batch.Environment.Commit ||
		lock.Source.Modified != modified || lock.Source.BuildSHA256 != batch.Environment.BuildSHA256 ||
		lock.Source.MachineDigest != batch.Environment.MachineDigest || lock.Source.CPUModel != batch.Environment.CPUModel ||
		lock.Source.CPUFeatures != batch.Environment.CPUFeatures {
		return fmt.Errorf("benchmark batch environment does not match candidate lock")
	}
	names := credential.IntGenISISPublicationPresetNamesV4()
	if err := validatePublicationV4Rotation(batch.Rotation, names); err != nil {
		return err
	}
	if len(batch.Runs) != PublicationV4TotalRuns || len(batch.Schedule) != PublicationV4TotalRuns {
		return fmt.Errorf("benchmark batch has %d runs/%d schedule entries; want %d", len(batch.Runs), len(batch.Schedule), PublicationV4TotalRuns)
	}
	results := make(map[string]PublicationV4PresetSearchResult, PublicationV4PresetCount)
	for _, result := range lock.Presets {
		results[result.CanonicalID] = result
	}
	seenRuns := make(map[publicationV4RunKey]struct{}, PublicationV4TotalRuns)
	seenFiles := make(map[string]struct{}, PublicationV4TotalRuns*2)
	for i := range batch.Runs {
		run := batch.Runs[i]
		schedule := batch.Schedule[i]
		if schedule.Sequence != i+1 || schedule.Stage != run.Stage || schedule.CanonicalID != run.CanonicalID ||
			schedule.CandidateDigest != run.CandidateDigest || schedule.CandidateRank != run.CandidateRank ||
			schedule.CandidateRun != run.CandidateRun || schedule.RotationPosition != run.RotationPosition {
			return fmt.Errorf("benchmark schedule entry %d does not bind run %d", i+1, i+1)
		}
		result, ok := results[run.CanonicalID]
		if !ok || run.PublicationLabel != result.PublicationLabel {
			return fmt.Errorf("benchmark run %d has an unknown publication identity", i+1)
		}
		if err := validatePublicationV4RunStage(run, result, batch.RunsPerPreset); err != nil {
			return fmt.Errorf("benchmark run %d: %w", i+1, err)
		}
		key := publicationV4RunKey{run.CanonicalID, run.Stage, run.CandidateRank, run.CandidateRun}
		if _, duplicate := seenRuns[key]; duplicate {
			return fmt.Errorf("benchmark batch repeats run tuple %+v", key)
		}
		seenRuns[key] = struct{}{}
		for role, path := range map[string]string{"report": run.ReportFile, "resource": run.ResourceFile} {
			if strings.TrimSpace(path) == "" || strings.TrimSpace(run.RunDirectory) == "" {
				return fmt.Errorf("benchmark run %d has an empty %s path", i+1, role)
			}
			if _, duplicate := seenFiles[path]; duplicate {
				return fmt.Errorf("benchmark batch reuses %s path %q", role, path)
			}
			seenFiles[path] = struct{}{}
		}
		if !validHexDigest(run.ReportSHA256, sha256.Size*2) || !validHexDigest(run.ResourceSHA256, sha256.Size*2) ||
			!run.ReplayRejected || !run.TamperRejected || !run.ArtifactHashesVerified || len(run.ArtifactSHA256) != 15 {
			return fmt.Errorf("benchmark run %d lacks report/resource/artifact or replay/tamper evidence", i+1)
		}
		if run.FullGameAccountingStatus != "aggregate_composed_game_v4" || run.ParameterAuditStatus != "pass" || strings.TrimSpace(run.LedgerStatus) == "" {
			return fmt.Errorf("benchmark run %d lacks passing full-game/audit status", i+1)
		}
		for role, digest := range run.ArtifactSHA256 {
			if strings.TrimSpace(role) == "" || !validHexDigest(digest, sha256.Size*2) {
				return fmt.Errorf("benchmark run %d has an invalid artifact digest", i+1)
			}
		}
		if !reflect.DeepEqual(run.Environment, batch.Environment) {
			return fmt.Errorf("benchmark run %d changed source/build/machine environment", i+1)
		}
		preset, _ := credential.LookupIntGenISISPublicationPreset(run.CanonicalID)
		candidate := result.Finalists[run.CandidateRank-1]
		if run.ManifestDigest != candidate.ManifestDigest {
			return fmt.Errorf("benchmark run %d manifest digest does not match candidate rank", i+1)
		}
		projection := candidate.Projection
		if projection == nil || run.Metrics.ShowingProofMaxBytes != projection.ShowingProofMaxBytes ||
			run.Metrics.PresentationMaxBytes != projection.PresentationMaxBytes ||
			run.Metrics.ShowingPaperBytes != projection.ShowingPaperBytes ||
			run.Metrics.IssuanceProofMaxBytes+run.Metrics.ShowingProofMaxBytes != projection.CombinedProofMaxBytes ||
			run.Metrics.IssuancePaperBytes+run.Metrics.ShowingPaperBytes != projection.CombinedPaperBytes {
			return fmt.Errorf("benchmark run %d does not realize its analytic candidate projection", i+1)
		}
		if run.ConfiguredFSBits != preset.Showing.FSOutputBits || candidate.Issuance.FSOutputBits != run.ConfiguredFSBits ||
			candidate.Showing.FSOutputBits != run.ConfiguredFSBits || len(run.ObservedFSBits) != 2 {
			return fmt.Errorf("benchmark run %d configured FS width is inconsistent", i+1)
		}
		for phase := range run.ObservedFSBits {
			for round, bits := range run.ObservedFSBits[phase] {
				if bits != run.ConfiguredFSBits {
					return fmt.Errorf("benchmark run %d phase %d round %d observed FS width=%d want=%d", i+1, phase+1, round+1, bits, run.ConfiguredFSBits)
				}
			}
		}
		if err := validatePublicationV4RunMetrics(run); err != nil {
			return fmt.Errorf("benchmark run %d: %w", i+1, err)
		}
	}
	if err := validatePublicationV4RunCounts(seenRuns, lock, batch.RunsPerPreset); err != nil {
		return err
	}
	if err := validatePublicationV4FinalRotation(batch.Runs, batch.Rotation); err != nil {
		return err
	}
	wantAggregates := publicationV4AggregateFinalRuns(batch.Runs, names)
	if !reflect.DeepEqual(batch.Presets, wantAggregates) {
		return fmt.Errorf("benchmark batch preset median/MAD summaries do not match the 35 final runs")
	}
	wantReportsDigest, err := publicationV4ReportsDigest(batch.Runs)
	if err != nil {
		return err
	}
	if batch.ReportsDigest != wantReportsDigest {
		return fmt.Errorf("benchmark batch reports digest mismatch: have %q want %q", batch.ReportsDigest, wantReportsDigest)
	}
	return nil
}

func publicationV4AcceptanceComplete(a PublicationV4BenchmarkAcceptance) bool {
	return a.ExactFivePresets && a.LockStoppingCertified && a.FinalistRunCounts && a.CandidateManifests &&
		a.ReplayRejected && a.TamperRejected && a.ArtifactHashesVerified && a.FSWidthsVerified &&
		a.AggregateQueryPolicy && a.SourceBuildMachine && a.CanonicalSizes && a.Resources &&
		a.FullGameAccounting && a.ProjectedWinnerMeasured && a.LiveManifestAdopted
}

func validatePublicationV4Environment(env PublicationV4Environment) error {
	if strings.TrimSpace(env.GoVersion) == "" || strings.TrimSpace(env.GOOS) == "" || strings.TrimSpace(env.GOARCH) == "" ||
		env.NumCPU <= 0 || env.GOMAXPROCS <= 0 || strings.TrimSpace(env.VCS) == "" || strings.TrimSpace(env.Commit) == "" ||
		strings.TrimSpace(env.CommitTime) == "" || env.Modified == nil || strings.TrimSpace(env.SourceTreeAlgorithm) == "" ||
		!validHexDigest(env.SourceTreeDigest, sha256.Size*2) || env.SourceTreeFileCount <= 0 ||
		!validHexDigest(env.BuildSHA256, sha256.Size*2) || strings.TrimSpace(env.CPUModel) == "" ||
		strings.TrimSpace(env.CPUFeatures) == "" || !validHexDigest(env.MachineDigest, sha256.Size*2) {
		return fmt.Errorf("incomplete environment tuple")
	}
	if _, err := time.Parse(time.RFC3339, env.CommitTime); err != nil {
		return fmt.Errorf("invalid commit time: %w", err)
	}
	machineBytes, err := json.Marshal(struct {
		GoVersion, GOOS, GOARCH, CPUModel, CPUFeatures string
		NumCPU, GOMAXPROCS                             int
	}{env.GoVersion, env.GOOS, env.GOARCH, env.CPUModel, env.CPUFeatures, env.NumCPU, env.GOMAXPROCS})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(machineBytes)
	if env.MachineDigest != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("machine digest does not match the reported machine tuple")
	}
	return nil
}

func validatePublicationV4Rotation(rotation [][]string, names []string) error {
	if len(rotation) != PublicationV4FinalRunsPerPreset {
		return fmt.Errorf("benchmark final rotation has %d rounds; want %d", len(rotation), PublicationV4FinalRunsPerPreset)
	}
	for round := range rotation {
		if len(rotation[round]) != PublicationV4PresetCount {
			return fmt.Errorf("benchmark final rotation round %d has %d presets", round+1, len(rotation[round]))
		}
		for position := range names {
			if rotation[round][position] != names[(round+position)%len(names)] {
				return fmt.Errorf("benchmark final rotation is not the canonical cyclic schedule")
			}
		}
	}
	return nil
}

func validatePublicationV4RunStage(run PublicationV4BenchmarkRun, result PublicationV4PresetSearchResult, finalRuns int) error {
	if run.CandidateRank < 1 || run.CandidateRank > len(result.Finalists) {
		return fmt.Errorf("candidate rank %d is out of range", run.CandidateRank)
	}
	wantDigest := result.Finalists[run.CandidateRank-1].CandidateDigest
	if run.CandidateDigest != wantDigest {
		return fmt.Errorf("candidate digest does not match rank %d", run.CandidateRank)
	}
	switch run.Stage {
	case "screening":
		if run.CandidateRun != 1 || run.Round != run.CandidateRun || run.RotationPosition < 1 || run.RotationPosition > PublicationV4PresetCount {
			return fmt.Errorf("invalid screening stage tuple")
		}
	case "confirmation":
		if run.CandidateRank > 3 || run.CandidateRun < 2 || run.CandidateRun > 3 || run.Round != run.CandidateRun ||
			run.RotationPosition < 1 || run.RotationPosition > PublicationV4PresetCount {
			return fmt.Errorf("invalid confirmation stage tuple")
		}
	case "final":
		if run.CandidateRank != 1 || run.CandidateRun < 1 || run.CandidateRun > finalRuns ||
			run.Round != run.CandidateRun || run.RotationPosition < 1 || run.RotationPosition > PublicationV4PresetCount {
			return fmt.Errorf("invalid final stage tuple")
		}
	default:
		return fmt.Errorf("unknown execution stage %q", run.Stage)
	}
	return nil
}

func validatePublicationV4RunCounts(seen map[publicationV4RunKey]struct{}, lock PublicationV4CandidateLock, finalRuns int) error {
	for _, result := range lock.Presets {
		for rank := 1; rank <= PublicationV4FinalistCount; rank++ {
			if _, ok := seen[publicationV4RunKey{result.CanonicalID, "screening", rank, 1}]; !ok {
				return fmt.Errorf("benchmark batch is missing %s screening rank %d", result.CanonicalID, rank)
			}
		}
		for rank := 1; rank <= 3; rank++ {
			for run := 2; run <= 3; run++ {
				if _, ok := seen[publicationV4RunKey{result.CanonicalID, "confirmation", rank, run}]; !ok {
					return fmt.Errorf("benchmark batch is missing %s confirmation rank %d run %d", result.CanonicalID, rank, run)
				}
			}
		}
		for run := 1; run <= finalRuns; run++ {
			if _, ok := seen[publicationV4RunKey{result.CanonicalID, "final", 1, run}]; !ok {
				return fmt.Errorf("benchmark batch is missing %s final run %d", result.CanonicalID, run)
			}
		}
	}
	return nil
}

func validatePublicationV4RunMetrics(run PublicationV4BenchmarkRun) error {
	m := run.Metrics
	positive := []int{
		m.CredentialStateBytes, m.IssuanceProofBytes, m.ShowingProofBytes,
		m.IssuanceProofMaxBytes, m.ShowingProofMaxBytes, m.PresentationBytes,
		m.PresentationMaxBytes, m.IssuancePaperBytes, m.ShowingPaperBytes,
	}
	for _, value := range positive {
		if value <= 0 {
			return fmt.Errorf("canonical size/resource metrics are not positive")
		}
	}
	for _, value := range []float64{m.IssuanceProvingMS, m.IssuanceVerificationMS, m.ShowingProvingMS, m.ShowingVerificationMS} {
		if !finiteNonnegative(value) {
			return fmt.Errorf("timing metric is non-finite or negative")
		}
	}
	if m.AllocatedBytes == 0 || m.Allocations == 0 || m.PeakRSSBytes == 0 {
		return fmt.Errorf("allocation/RSS evidence is missing")
	}
	if err := validatePublicationV4PhaseWire(m.IssuanceProofBytes, run.ConfiguredFSBits, run.IssuanceWire); err != nil {
		return fmt.Errorf("issuance wire projection: %w", err)
	}
	if err := validatePublicationV4PhaseWire(m.ShowingProofBytes, run.ConfiguredFSBits, run.ShowingWire); err != nil {
		return fmt.Errorf("showing wire projection: %w", err)
	}
	if m.IssuanceProofMaxBytes != run.IssuanceWire.DeterministicMaxBytes ||
		m.ShowingProofMaxBytes != run.ShowingWire.DeterministicMaxBytes ||
		m.PresentationBytes < m.ShowingProofBytes ||
		m.PresentationMaxBytes != m.PresentationBytes-m.ShowingProofBytes+m.ShowingProofMaxBytes {
		return fmt.Errorf("canonical proof/presentation maximum is inconsistent")
	}
	return nil
}

func validatePublicationV4PhaseWire(actual, fsBits int, wire PublicationV4PhaseWireRun) error {
	if fsBits <= 0 || fsBits%8 != 0 || wire.CounterBytes <= 0 || wire.MerkleNodesUsed <= 0 ||
		wire.MerkleNodesBound < wire.MerkleNodesUsed || wire.AuthenticationBytes <= 0 || wire.DeterministicMaxBytes < actual {
		return fmt.Errorf("invalid compact-wire counters/frontier")
	}
	counterBytes := 0
	for _, counter := range wire.FSCounters {
		counterBytes += publicationV4UvarintBytes(counter)
	}
	rootBytes := fsBits / 8
	wantMaximum := actual - wire.CounterBytes - wire.AuthenticationBytes + 4*10 + wire.MerkleNodesBound*rootBytes
	if wire.CounterBytes != counterBytes || wire.AuthenticationBytes != wire.MerkleNodesUsed*rootBytes || wire.DeterministicMaxBytes != wantMaximum {
		return fmt.Errorf("wire projector does not exactly account for counters/frontier")
	}
	return nil
}

func publicationV4UvarintBytes(value uint64) int {
	bytes := 1
	for value >= 0x80 {
		value >>= 7
		bytes++
	}
	return bytes
}

func validatePublicationV4FinalRotation(runs []PublicationV4BenchmarkRun, rotation [][]string) error {
	seen := make(map[[2]int]string, PublicationV4PresetCount*PublicationV4FinalRunsPerPreset)
	for _, run := range runs {
		if run.Stage != "final" {
			continue
		}
		key := [2]int{run.Round, run.RotationPosition}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("benchmark final rotation repeats round/position %v", key)
		}
		seen[key] = run.CanonicalID
	}
	for round := 1; round <= len(rotation); round++ {
		for position := 1; position <= len(rotation[round-1]); position++ {
			if seen[[2]int{round, position}] != rotation[round-1][position-1] {
				return fmt.Errorf("benchmark final run order differs from its rotation matrix")
			}
		}
	}
	return nil
}

func publicationV4AggregateFinalRuns(runs []PublicationV4BenchmarkRun, names []string) []PublicationV4PresetAggregate {
	out := make([]PublicationV4PresetAggregate, 0, len(names))
	for i, name := range names {
		selected := make([]PublicationV4BenchmarkRun, 0, PublicationV4FinalRunsPerPreset)
		for _, run := range runs {
			if run.Stage == "final" && run.CanonicalID == name {
				selected = append(selected, run)
			}
		}
		if len(selected) == 0 {
			continue
		}
		values := func(pick func(PublicationV4RunMetrics) float64) []float64 {
			out := make([]float64, len(selected))
			for i := range selected {
				out[i] = pick(selected[i].Metrics)
			}
			return out
		}
		first := selected[0]
		out = append(out, PublicationV4PresetAggregate{
			CanonicalID: name, PublicationLabel: publicationV4Labels[i], CandidateDigest: first.CandidateDigest, Runs: len(selected),
			CredentialStateBytes:   publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.CredentialStateBytes) })),
			IssuanceProofBytes:     publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.IssuanceProofBytes) })),
			ShowingProofBytes:      publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.ShowingProofBytes) })),
			IssuanceProofMaxBytes:  publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.IssuanceProofMaxBytes) })),
			ShowingProofMaxBytes:   publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.ShowingProofMaxBytes) })),
			PresentationBytes:      publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.PresentationBytes) })),
			PresentationMaxBytes:   publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.PresentationMaxBytes) })),
			IssuancePaperBytes:     publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.IssuancePaperBytes) })),
			ShowingPaperBytes:      publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.ShowingPaperBytes) })),
			IssuanceProvingMS:      publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return m.IssuanceProvingMS })),
			IssuanceVerificationMS: publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return m.IssuanceVerificationMS })),
			ShowingProvingMS:       publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return m.ShowingProvingMS })),
			ShowingVerificationMS:  publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return m.ShowingVerificationMS })),
			AllocatedBytes:         publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.AllocatedBytes) })),
			Allocations:            publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.Allocations) })),
			PeakRSSBytes:           publicationV4DistributionFor(values(func(m PublicationV4RunMetrics) float64 { return float64(m.PeakRSSBytes) })),
		})
	}
	return out
}

func publicationV4DistributionFor(values []float64) PublicationV4Distribution {
	if len(values) == 0 {
		return PublicationV4Distribution{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	median := publicationV4Median(sorted)
	deviations := make([]float64, len(sorted))
	for i := range sorted {
		deviations[i] = math.Abs(sorted[i] - median)
	}
	sort.Float64s(deviations)
	return PublicationV4Distribution{Median: median, MAD: publicationV4Median(deviations), Min: sorted[0], Max: sorted[len(sorted)-1]}
}

func publicationV4Median(sorted []float64) float64 {
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

func publicationV4ReportsDigest(runs []PublicationV4BenchmarkRun) (string, error) {
	parts := make([]string, 0, len(runs))
	for _, run := range runs {
		parts = append(parts, fmt.Sprintf("%s:%02d:%02d:%02d:%s:%s:%s:%s", run.Stage, run.CandidateRank,
			run.CandidateRun, run.RotationPosition, run.CanonicalID, run.CandidateDigest, run.ReportSHA256, run.ResourceSHA256))
	}
	return publicationV4Digest(parts)
}

// ValidatePublicationV4BenchmarkArtifacts is the final paper-evidence gate.
// batchPath may be absolute or relative to spruceRoot; every referenced file
// must remain below spruceRoot and be a regular, non-symlink file.
func ValidatePublicationV4BenchmarkArtifacts(batchPath, spruceRoot string) error {
	root, err := ResolveSPRUCE_DIR(spruceRoot)
	if err != nil {
		return err
	}
	resolvedBatch, err := publicationV4ResolvePath(root, batchPath)
	if err != nil {
		return err
	}
	batchData, err := publicationV4ReadRegularFile(resolvedBatch)
	if err != nil {
		return fmt.Errorf("read publication-v4 batch: %w", err)
	}
	batch, err := DecodePublicationV4BenchmarkBatch(batchData)
	if err != nil {
		return err
	}
	lockPath, err := publicationV4ResolvePath(root, batch.CandidateLockFile)
	if err != nil {
		return err
	}
	lockData, err := publicationV4ReadRegularFile(lockPath)
	if err != nil {
		return fmt.Errorf("read publication-v4 candidate lock: %w", err)
	}
	lock, err := DecodePublicationV4CandidateLock(lockData)
	if err != nil {
		return err
	}
	if err := ValidatePublicationV4BenchmarkBatch(batch, lock); err != nil {
		return err
	}
	results := make(map[string]PublicationV4PresetSearchResult, len(lock.Presets))
	for _, result := range lock.Presets {
		results[result.CanonicalID] = result
	}
	for i := range batch.Runs {
		run := batch.Runs[i]
		result := results[run.CanonicalID]
		candidate := result.Finalists[run.CandidateRank-1]
		if err := validatePublicationV4RunArtifacts(root, run, candidate); err != nil {
			return fmt.Errorf("publication-v4 run %d (%s/%s/rank-%d/run-%d): %w", i+1, run.CanonicalID, run.Stage, run.CandidateRank, run.CandidateRun, err)
		}
	}
	return nil
}

func validatePublicationV4RunArtifacts(root string, run PublicationV4BenchmarkRun, candidate PublicationV4CandidateBinding) error {
	runDir, err := publicationV4ResolvePath(root, run.RunDirectory)
	if err != nil {
		return err
	}
	info, err := os.Lstat(runDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("run directory is missing, not a directory, or a symlink")
	}
	reportPath, err := publicationV4ResolveRunFile(root, runDir, run.ReportFile)
	if err != nil {
		return err
	}
	resourcePath, err := publicationV4ResolveRunFile(root, runDir, run.ResourceFile)
	if err != nil {
		return err
	}
	reportData, err := publicationV4ReadRegularFile(reportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	resourceData, err := publicationV4ReadRegularFile(resourcePath)
	if err != nil {
		return fmt.Errorf("read resource log: %w", err)
	}
	if sha256Hex(reportData) != run.ReportSHA256 || sha256Hex(resourceData) != run.ResourceSHA256 {
		return fmt.Errorf("report/resource digest mismatch")
	}
	var report benchmarkReportWire
	if err := decodeStrictJSON(reportData, &report); err != nil {
		return fmt.Errorf("strict raw report decode: %w", err)
	}
	if err := validatePublicationV4RawReport(report, run, candidate); err != nil {
		return err
	}
	if !reflect.DeepEqual(report.ArtifactSHA256, run.ArtifactSHA256) {
		return fmt.Errorf("raw report and batch artifact digest maps differ")
	}
	paths := publicationV4ArtifactPaths(report.Artifacts)
	artifactData, err := publicationV4ReadArtifactSet(root, runDir, paths, run.ArtifactSHA256)
	if err != nil {
		return err
	}
	if len(artifactData["state"]) != run.Metrics.CredentialStateBytes || len(artifactData["presentation"]) != run.Metrics.PresentationBytes {
		return fmt.Errorf("canonical state/presentation file lengths differ from report")
	}
	var submission struct {
		Version        int    `json:"version"`
		CanonicalProof []byte `json:"canonical_proof"`
	}
	if err := json.Unmarshal(artifactData["presign_submission"], &submission); err != nil || submission.Version != credential.IntGenISISIssuanceArtifactFormatVersionV4 || len(submission.CanonicalProof) != run.Metrics.IssuanceProofBytes {
		return fmt.Errorf("canonical issuance proof length differs from report")
	}
	tagElements, ok := credential.IntGenISISPRFProfileTagElements(candidate.Showing.PRFProfile)
	if !ok {
		return fmt.Errorf("candidate PRF profile is unknown")
	}
	presentationOffset := 8 + (tagElements*20+7)/8
	if presentationOffset >= len(artifactData["presentation"]) || len(artifactData["presentation"])-presentationOffset != run.Metrics.ShowingProofBytes {
		return fmt.Errorf("canonical showing proof length differs from report")
	}
	if !bytes.HasPrefix(artifactData["state"], []byte{'S', 'P', 'R', 'S', 'T', 'A', 'T', 8}) ||
		!bytes.HasPrefix(artifactData["presentation"], []byte{'S', 'P', 'R', 'P', 'R', 'E', 'S', 3}) {
		return fmt.Errorf("canonical state/presentation header mismatch")
	}
	bindingPath := filepath.Join(runDir, "candidate-binding.json")
	bindingData, err := publicationV4ReadRegularFile(bindingPath)
	if err != nil {
		return fmt.Errorf("read candidate binding: %w", err)
	}
	var executed PublicationV4CandidateBinding
	if err := decodeStrictJSON(bindingData, &executed); err != nil || !reflect.DeepEqual(executed, candidate) {
		return fmt.Errorf("executed candidate binding differs from candidate lock")
	}
	return nil
}

func publicationV4ReadArtifactSet(root, runDir string, paths, digests map[string]string) (map[string][]byte, error) {
	if len(paths) != 15 || len(digests) != len(paths) {
		return nil, fmt.Errorf("artifact set has %d paths/%d digests; want 15", len(paths), len(digests))
	}
	artifactData := make(map[string][]byte, len(paths))
	for role, encodedPath := range paths {
		path, err := publicationV4ResolveRunFile(root, runDir, encodedPath)
		if err != nil {
			return nil, fmt.Errorf("artifact %s: %w", role, err)
		}
		data, err := publicationV4ReadRegularFile(path)
		if err != nil {
			return nil, fmt.Errorf("read artifact %s: %w", role, err)
		}
		if len(data) == 0 || !validHexDigest(digests[role], sha256.Size*2) || sha256Hex(data) != digests[role] {
			return nil, fmt.Errorf("artifact %s digest/size mismatch", role)
		}
		artifactData[role] = data
	}
	return artifactData, nil
}

func validatePublicationV4RawReport(report benchmarkReportWire, run PublicationV4BenchmarkRun, candidate PublicationV4CandidateBinding) error {
	if report.Version != ArtifactSchemasV2().E2EReport || report.PresetVersion != credential.IntGenISISPresetManifestVersionV4 ||
		report.CanonicalPresetID != run.CanonicalID || report.PresetManifestDigest != candidate.ManifestDigest ||
		report.ClaimScope != credential.ClaimProofOnly || report.CompleteSystemClaim || report.ArtifactDir != run.RunDirectory {
		return fmt.Errorf("raw report identity/claim/artifact-directory mismatch")
	}
	if _, err := time.Parse(time.RFC3339, report.Generated); err != nil {
		return fmt.Errorf("raw report generated_at is invalid")
	}
	if report.CanonicalSizes == nil || report.CanonicalSizes.CredentialStateBytes != run.Metrics.CredentialStateBytes ||
		report.CanonicalSizes.IssuanceProofWireBytes != run.Metrics.IssuanceProofBytes ||
		report.CanonicalSizes.ShowingProofWireBytes != run.Metrics.ShowingProofBytes ||
		report.CanonicalSizes.PresentationWireBytes != run.Metrics.PresentationBytes ||
		report.CanonicalSizes.IssuancePaperBytes != run.Metrics.IssuancePaperBytes ||
		report.CanonicalSizes.ShowingPaperBytes != run.Metrics.ShowingPaperBytes {
		return fmt.Errorf("raw canonical size projection differs from batch")
	}
	if report.Resources.AllocatedBytes != run.Metrics.AllocatedBytes || report.Resources.Allocations != run.Metrics.Allocations ||
		report.Resources.PeakRSSBytes != run.Metrics.PeakRSSBytes {
		return fmt.Errorf("raw allocation/RSS projection differs from batch")
	}
	if !report.ReplayRejected || !report.TamperRejected || !report.ArtifactHashesVerified ||
		!report.Issuance.CanonicalTamperRejected || !report.Showing.CanonicalTamperRejected {
		return fmt.Errorf("raw replay/tamper/artifact gates did not pass")
	}
	if report.FullGameAccountingStatus != "aggregate_composed_game_v4" || report.ParameterAudit.Status != "pass" ||
		len(report.ParameterAudit.MissingActual) != 0 || len(report.ParameterAudit.MissingEvidence) != 0 || len(report.ParameterAudit.Mismatches) != 0 {
		return fmt.Errorf("raw security-parameter/full-game audit did not pass")
	}
	if report.FullGameAccountingStatus != run.FullGameAccountingStatus || report.ParameterAudit.Status != run.ParameterAuditStatus ||
		report.LedgerStatus != run.LedgerStatus || report.LedgerStatus != report.SecurityLedger.LedgerStatus ||
		report.SecurityLedger.CompleteSystemClaim || report.SecurityLedger.SecurityProfile != report.SecurityProfile ||
		report.SecurityLedger.SecurityMode != report.SecurityMode {
		return fmt.Errorf("raw proof-only ledger/full-game projection differs from batch")
	}
	if !reflect.DeepEqual(publicationV4EnvironmentFromWire(report.Environment), run.Environment) {
		return fmt.Errorf("raw report environment differs from batch")
	}
	if err := validatePublicationV4RawTuning(report.Options.Issuance, candidate.Issuance, candidate.CanonicalID); err != nil {
		return fmt.Errorf("raw issuance tuning: %w", err)
	}
	if err := validatePublicationV4RawTuning(report.Options.Showing, candidate.Showing, candidate.CanonicalID); err != nil {
		return fmt.Errorf("raw showing tuning: %w", err)
	}
	if err := validatePublicationV4RawPhase(report.Issuance, candidate.Issuance, run.IssuanceWire, run.Metrics.IssuanceProofBytes); err != nil {
		return fmt.Errorf("raw issuance phase: %w", err)
	}
	if err := validatePublicationV4RawPhase(report.Showing, candidate.Showing, run.ShowingWire, run.Metrics.ShowingProofBytes); err != nil {
		return fmt.Errorf("raw showing phase: %w", err)
	}
	if err := validatePublicationV4RawSecurity(report, candidate); err != nil {
		return err
	}
	return nil
}

func validatePublicationV4RawTuning(got benchmarkTuningWire, want credential.IntGenISISTuningPreset, canonicalID string) error {
	if got.PresetID != canonicalID || got.NCols != want.NCols || got.LVCSNCols != want.LVCSNCols ||
		got.NLeaves != want.NLeaves || got.Eta != want.Eta || got.Theta != want.Theta || got.Rho != want.Rho ||
		got.Ell != want.Ell || got.EllPrime != want.EllPrime || got.DQOverride != 0 || got.Kappa != want.Kappa ||
		got.ROQueryCaps != want.ROQueryCaps || !equalFloatArray(got.ROQueryCapBits, want.ROQueryCapBits) ||
		math.Abs(got.AggregateROQueryCapLog2-want.AggregateROQueryCapLog2) > 1e-9 ||
		got.DECSCollisionBits != want.DECSCollisionBits || got.DECSHashBits != want.DECSHashBits ||
		got.DECSTapeBits != want.DECSTapeBits || got.FSCollisionBits != want.FSCollisionBits || got.FSOutputBits != want.FSOutputBits ||
		got.SaltBits != want.SaltBits || got.PRFProfile != want.PRFProfile || got.PRFParamsPath != want.PRFParamsPath ||
		got.PRFCompanionMode != string(want.PRFCompanionMode) || got.PRFGroupRounds != want.PRFGroupRounds ||
		got.CheckpointSamples != want.CheckpointSamples || got.SigShortnessRadix != want.SigShortnessRadix ||
		got.SigShortnessDigits != want.SigShortnessDigits || got.CompressedRows != want.CompressedRows ||
		got.ReplayProjection != want.ReplayProjection || got.TranscriptMode != credential.IntGenISISTranscriptProtocolV4 ||
		got.TranscriptMode != want.TranscriptMode || got.TranscriptOmissionMode != want.TranscriptOmissionMode ||
		got.FixedTranscriptSize != want.FixedTranscriptSize {
		return fmt.Errorf("executed tuning differs from candidate manifest")
	}
	return nil
}

func validatePublicationV4RawPhase(got benchmarkPhaseWire, want credential.IntGenISISTuningPreset, projected PublicationV4PhaseWireRun, actual int) error {
	if got.CanonicalWireAudit == nil || got.CanonicalProofWireBytes != actual || got.ProofSizeBytes != actual ||
		got.CanonicalWireAudit.TotalBytes != actual || !got.CanonicalTamperRejected || !got.ZeroKnowledgeEligible ||
		got.TranscriptMode != credential.IntGenISISTranscriptProtocolV4 ||
		got.TranscriptSecurityStatus != credential.IntGenISISSecurityGateV4 || got.FSOutputBits != want.FSOutputBits ||
		got.ObservedFSDigestBits != [4]int{want.FSOutputBits, want.FSOutputBits, want.FSOutputBits, want.FSOutputBits} ||
		got.DECSHashBits != want.DECSHashBits || got.DECSTapeBits != want.DECSTapeBits || got.SaltBits != want.SaltBits ||
		got.RootWidthBytes*8 != want.DECSHashBits || got.TapeWidthBytes*8 != want.DECSTapeBits ||
		got.LVCSNCols != want.LVCSNCols || got.NLeaves != want.NLeaves || got.Eta != want.Eta || got.Theta != want.Theta ||
		got.Rho != want.Rho || got.Ell != want.Ell || got.EllPrime != want.EllPrime || !finiteNonnegative(got.ProvingMS) ||
		!finiteNonnegative(got.VerificationMS) || got.PaperTranscriptBytes <= 0 {
		return fmt.Errorf("phase width/geometry/wire/tamper tuple differs from candidate")
	}
	if got.AggregateQueryBudget != want.AggregateROQueryCapLog2Set ||
		math.Abs(got.AggregateQueryCapLog2-want.AggregateROQueryCapLog2) > 1e-9 {
		return fmt.Errorf("phase aggregate-query scalar differs from candidate")
	}
	if want.AggregateROQueryCapLog2Set && (got.ROQueryCaps != [5]int{} ||
		got.ROQueryCapBits != [5]float64{-1, -1, -1, -1, -1} || got.WorkFactorMode || got.WorkFactorBits != 0 ||
		got.WorkFactorComponents != [6]float64{} || got.NativeAlgebraicTerms != [4]float64{} ||
		got.NativeAlgebraicBits != [4]float64{}) {
		return fmt.Errorf("bounded-query phase carries contradictory work-factor fields")
	}
	if got.TotalRows <= 0 || got.DQ <= 0 || got.LVCSNCols <= 0 {
		return fmt.Errorf("phase relation geometry is empty")
	}
	blocks := (got.TotalRows + got.LVCSNCols - 1) / got.LVCSNCols
	mu := (got.DQ + got.LVCSNCols - 1) / got.LVCSNCols
	replayRows := blocks * (want.NCols + want.Theta)
	maskRows := (mu + 1) * want.Theta * want.Rho
	committedRows := replayRows + maskRows
	auditRows := (blocks + 1) * want.Theta
	openingCols := committedRows - auditRows
	relation := got.RelationCandidate
	if got.RowsBlock != blocks || got.SmallFieldReplayRows != replayRows || got.MaskRows != maskRows ||
		got.PaperShapeNRows != committedRows || got.PaperShapeQueries != auditRows ||
		got.PaperShapeWitnessLayers != blocks || got.PaperShapeMaskRows != maskRows ||
		got.AuditRows != auditRows || got.OpeningCols != openingCols || got.DDECS != want.LVCSNCols+want.Ell-1 ||
		got.WitnessSupportCols != want.NCols || got.CommittedCols != want.LVCSNCols || !got.PaperShapeCanonical ||
		relation.LogicalRows != got.TotalRows || relation.RowCounts["total"] != got.TotalRows ||
		relation.ParallelDegree != got.ParallelAlgDegree || relation.AggregatedDegree != got.AggregatedAlgDegree ||
		relation.DQ != got.DQ || relation.ParallelDegree <= 0 || relation.AggregatedDegree <= 0 {
		return fmt.Errorf("phase reported geometry does not satisfy the executable B/mu/replay/mask/opening identities")
	}
	audit := got.CanonicalWireAudit
	wantProjected := PublicationV4PhaseWireRun{
		CounterBytes: audit.CounterBytes, FSCounters: got.FSCounters, AuthenticationBytes: audit.AuthenticationBytes,
		MerkleNodesUsed: audit.MerkleNodesUsed, MerkleNodesBound: audit.MerkleNodesBound,
		DeterministicMaxBytes: actual - audit.CounterBytes - audit.AuthenticationBytes + 4*10 + audit.MerkleNodesBound*audit.RootBytes,
	}
	if !reflect.DeepEqual(projected, wantProjected) {
		return fmt.Errorf("raw canonical wire audit differs from batch projector")
	}
	return nil
}

func validatePublicationV4RawSecurity(report benchmarkReportWire, candidate PublicationV4CandidateBinding) error {
	if candidate.Projection == nil {
		return fmt.Errorf("publication candidate has no analytic projection")
	}
	preset, ok := credential.LookupIntGenISISPublicationPreset(candidate.CanonicalID)
	if !ok {
		return fmt.Errorf("publication preset disappeared")
	}
	if report.SecurityProfile != preset.SecurityProfile || report.SecurityMode != preset.SecurityMode ||
		report.PRFProfile != preset.PRFProfile || report.PRFParamsDigest != preset.PRFParamsDigest ||
		!reflect.DeepEqual(report.ThreatModel, preset.ThreatModel) || report.ParameterAudit.SecurityProfile != preset.SecurityProfile {
		return fmt.Errorf("raw report security/primitive profile differs from manifest")
	}
	spec, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		return fmt.Errorf("publication security profile disappeared")
	}
	recomputedAudit := credential.AuditIntGenISISSecurityParameters(spec, report.ParameterAudit.Actual)
	if !reflect.DeepEqual(report.ParameterAudit, recomputedAudit) {
		return fmt.Errorf("raw parameter audit is not reproducible from actual values")
	}
	actual := report.ParameterAudit.Actual
	tagElements, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok || actual.ROQueryCapScope != credential.ROQueryCapAggregateComposedGame || actual.ROQueryCapLog2Set || len(actual.ROQueryCapLog2) != 0 ||
		actual.DECSHashBits != candidate.Showing.DECSHashBits || actual.DECSTapeBits != candidate.Showing.DECSTapeBits ||
		actual.FSCollisionBits != candidate.Showing.FSCollisionBits || actual.FSOutputBits != candidate.Showing.FSOutputBits ||
		actual.SaltBits != candidate.Showing.SaltBits || actual.PRFTagElements != tagElements || actual.PRFProfile != preset.PRFProfile ||
		actual.TranscriptMode != credential.IntGenISISTranscriptProtocolV4 {
		return fmt.Errorf("raw parameter actuals do not equal the manifest-bound primitive tuple")
	}
	full := report.FullGame
	if full.AcceptedIssuance != preset.ThreatModel.AcceptedIssuance || full.AcceptedShowing != preset.ThreatModel.AcceptedShowing ||
		full.CollisionSpaceBits != candidate.Showing.FSOutputBits {
		return fmt.Errorf("raw full-game accepted-proof/collision tuple differs from manifest")
	}
	maxNativeBits, err := validatePublicationV4NativeBranches(report, candidate)
	if err != nil {
		return err
	}
	if !publicationV4FloatClose(full.MaxNativeAlgebraicBits, maxNativeBits) ||
		!publicationV4FloatClose(full.MaxNativeAlgebraicError, math.Exp2(-maxNativeBits)) {
		return fmt.Errorf("raw full-game maximum native coefficient does not equal the minimum of all eight branches")
	}
	noQueryCap := [5]float64{-1, -1, -1, -1, -1}
	if report.Issuance.ROQueryCaps != [5]int{} || report.Showing.ROQueryCaps != [5]int{} ||
		report.Issuance.ROQueryCapBits != noQueryCap || report.Showing.ROQueryCapBits != noQueryCap {
		return fmt.Errorf("raw publication-v4 phases expose legacy per-domain query caps")
	}
	if preset.ThreatModel.AggregateROQueryCapLog2Set {
		qBits := preset.ThreatModel.AggregateROQueryCapLog2
		if !actual.AggregateROQueryCapLog2Set || math.Abs(actual.AggregateROQueryCapLog2-qBits) > 1e-9 ||
			full.AccountingMode != PIOP.FullGameAccountingAggregateV4 || math.Abs(full.AggregateQueryCapLog2-qBits) > 1e-9 ||
			full.IssuanceQueryCaps != [5]int{} || full.ShowingQueryCaps != [5]int{} || full.GlobalQueryCaps != [5]int{} ||
			full.IssuanceQueryCapBits != noQueryCap || full.ShowingQueryCapBits != noQueryCap ||
			full.GlobalQueryCapBits != noQueryCap ||
			!finitePositive(full.MaxNativeAlgebraicError) || full.MaxNativeAlgebraicBits+1e-8 < candidate.Projection.RequiredNativeRoundBits {
			return fmt.Errorf("raw report does not use one aggregate-Q full-game budget")
		}
		collision := math.Exp2(2*qBits - float64(candidate.Showing.FSOutputBits))
		algebraic := math.Exp2(qBits) * full.MaxNativeAlgebraicError
		if algebraic > 1 {
			algebraic = 1
		}
		composed := collision + algebraic
		if composed > 1 {
			composed = 1
		}
		if !publicationV4FloatClose(full.GlobalCollisionError, collision) ||
			!publicationV4FloatClose(full.ConservativeFullGameError, composed) ||
			!publicationV4FloatClose(full.GlobalCollisionFullGameError, composed) ||
			!publicationV4FloatClose(full.IssuanceAlgebraicContribution+full.ShowingAlgebraicContribution, algebraic) ||
			full.ConservativeFullGameBits+1e-8 < preset.ThreatModel.TargetResidualBits ||
			float64(candidate.Showing.DECSTapeBits)-qBits+1e-8 < preset.ThreatModel.TargetResidualBits {
			return fmt.Errorf("raw aggregate-Q formula introduces a hidden phase/domain budget or misses a primitive gate")
		}
	} else {
		if err := validatePublicationV4WFPhase(report.Issuance, candidate.Issuance, candidate.Projection.RawRoundBitsIssuance, preset.ThreatModel.TargetWorkFactorBits); err != nil {
			return fmt.Errorf("raw WF128 issuance phase: %w", err)
		}
		if err := validatePublicationV4WFPhase(report.Showing, candidate.Showing, candidate.Projection.RawRoundBitsShowing, preset.ThreatModel.TargetWorkFactorBits); err != nil {
			return fmt.Errorf("raw WF128 showing phase: %w", err)
		}
		fullWorkFactor := math.Min(report.Issuance.WorkFactorBits, report.Showing.WorkFactorBits)
		if actual.AggregateROQueryCapLog2Set || actual.AggregateROQueryCapLog2 != 0 ||
			full.AccountingMode != PIOP.FullGameAccountingWorkFactorV4 || full.AggregateQueryCapLog2 != 0 ||
			!publicationV4FloatClose(full.WorkFactorBits, fullWorkFactor) ||
			!publicationV4FloatClose(full.IssuanceWorkFactorBits, report.Issuance.WorkFactorBits) ||
			!publicationV4FloatClose(full.ShowingWorkFactorBits, report.Showing.WorkFactorBits) ||
			full.WorkFactorBits+1e-8 < preset.ThreatModel.TargetWorkFactorBits ||
			full.IssuanceQueryCaps != [5]int{} || full.ShowingQueryCaps != [5]int{} || full.GlobalQueryCaps != [5]int{} ||
			full.IssuanceQueryCapBits != noQueryCap || full.ShowingQueryCapBits != noQueryCap || full.GlobalQueryCapBits != noQueryCap ||
			float64(candidate.Showing.FSOutputBits)/2+1e-8 < preset.ThreatModel.TargetWorkFactorBits ||
			float64(candidate.Showing.DECSTapeBits)+1e-8 < preset.ThreatModel.TargetWorkFactorBits {
			return fmt.Errorf("raw WF128 work-factor/collision/tape curve is incomplete")
		}
	}
	return nil
}

func validatePublicationV4NativeBranches(report benchmarkReportWire, candidate PublicationV4CandidateBinding) (float64, error) {
	minimum := math.Inf(1)
	phases := []struct {
		name      string
		got       benchmarkPhaseWire
		tuning    credential.IntGenISISTuningPreset
		projected [4]float64
	}{
		{name: "issuance", got: report.Issuance, tuning: candidate.Issuance, projected: candidate.Projection.RawRoundBitsIssuance},
		{name: "showing", got: report.Showing, tuning: candidate.Showing, projected: candidate.Projection.RawRoundBitsShowing},
	}
	for _, phase := range phases {
		for i := range phase.projected {
			if !finiteNonnegative(phase.projected[i]) || !finiteNonnegative(phase.got.RawRoundBits[i]) ||
				!finiteNonnegative(phase.got.RoundBits[i]) ||
				math.Abs(phase.got.RawRoundBits[i]-phase.projected[i]) > 1e-8 ||
				math.Abs(phase.got.RoundBits[i]-phase.projected[i]) > 1e-8 {
				return 0, fmt.Errorf("raw %s branch %d differs from the candidate's exact native calculation", phase.name, i+1)
			}
			bits := phase.got.RoundBits[i] + float64(phase.tuning.Kappa[i])
			if bits+1e-8 < candidate.Projection.RequiredNativeRoundBits {
				return 0, fmt.Errorf("raw %s native branch %d falls below the candidate gate", phase.name, i+1)
			}
			if bits < minimum {
				minimum = bits
			}
		}
	}
	if math.IsInf(minimum, 1) {
		return 0, fmt.Errorf("raw report contains no native algebraic branch")
	}
	return minimum, nil
}

func validatePublicationV4WFPhase(got benchmarkPhaseWire, want credential.IntGenISISTuningPreset, raw [4]float64, target float64) error {
	if !got.WorkFactorMode || got.AggregateQueryBudget || got.AggregateQueryCapLog2 != 0 ||
		got.CollisionSpaceBits != want.FSOutputBits || got.ROQueryCaps != [5]int{} {
		return fmt.Errorf("phase did not select exclusive native work-factor accounting")
	}
	wantComponents := [6]float64{float64(want.FSOutputBits) / 2, 0, 0, 0, 0, float64(want.DECSTapeBits)}
	minimum := wantComponents[0]
	for i := range raw {
		// The analytic search and executable proof path independently evaluate
		// the same logarithmic formulas. Their raw values may therefore differ
		// within the explicitly accepted 1e-8 numerical tolerance. Derived
		// native terms must exactly follow the measured raw report, rather than
		// the nearby analytic projection.
		wantBits := got.RoundBits[i] + float64(want.Kappa[i])
		wantComponents[i+1] = wantBits
		if !finiteNonnegative(got.RawRoundBits[i]) || !finiteNonnegative(got.RoundBits[i]) ||
			!publicationV4FloatClose(got.RawRoundBits[i], raw[i]) || !publicationV4FloatClose(got.RoundBits[i], raw[i]) ||
			!publicationV4FloatClose(got.NativeAlgebraicBits[i], wantBits) ||
			!publicationV4FloatClose(got.NativeAlgebraicTerms[i], math.Exp2(-wantBits)) || wantBits+1e-8 < target {
			return fmt.Errorf("native algebraic branch %d does not equal raw+kappa", i)
		}
		if wantBits < minimum {
			minimum = wantBits
		}
	}
	if wantComponents[5] < minimum {
		minimum = wantComponents[5]
	}
	for i := range wantComponents {
		if !publicationV4FloatClose(got.WorkFactorComponents[i], wantComponents[i]) {
			return fmt.Errorf("work-factor component %d=%g want %g", i, got.WorkFactorComponents[i], wantComponents[i])
		}
	}
	if !publicationV4FloatClose(got.WorkFactorBits, minimum) || got.WorkFactorBits+1e-8 < target {
		return fmt.Errorf("phase work factor=%g want min component %g and target %g", got.WorkFactorBits, minimum, target)
	}
	noRoundBits := [4]float64{-1, -1, -1, -1}
	noQueryCap := [5]float64{-1, -1, -1, -1, -1}
	if got.TheoremBits != noRoundBits || got.AlgebraicBits != noRoundBits || got.ROQueryCapBits != noQueryCap ||
		got.TheoremTotalBits != -1 || got.AlgebraicTotal != 0 || got.AlgebraicTotalBits != -1 ||
		got.AlgebraicTerms != [4]float64{} || got.Collision != 0 || got.CollisionBits != -1 ||
		got.OneProofTotal != 0 || got.OneProofTotalBits != -1 {
		return fmt.Errorf("query-adjusted fields were not marked inapplicable")
	}
	return nil
}

func publicationV4FloatClose(left, right float64) bool {
	if math.IsNaN(left) || math.IsNaN(right) || math.IsInf(left, 0) || math.IsInf(right, 0) {
		return false
	}
	scale := math.Max(1e-300, math.Max(math.Abs(left), math.Abs(right)))
	return math.Abs(left-right) <= scale*1e-10
}

func publicationV4EnvironmentFromWire(env benchmarkEnvironmentWire) PublicationV4Environment {
	return PublicationV4Environment{
		GoVersion: env.GoVersion, GOOS: env.GOOS, GOARCH: env.GOARCH, NumCPU: env.NumCPU, GOMAXPROCS: env.GOMAXPROCS,
		VCS: env.VCS, Commit: env.Commit, CommitTime: env.CommitTime, Modified: env.Modified,
		SourceTreeAlgorithm: env.SourceTreeAlgorithm, SourceTreeDigest: env.SourceTreeDigest, SourceTreeFileCount: env.SourceTreeFileCount,
		BuildSHA256: env.BuildSHA256, CPUModel: env.CPUModel, CPUFeatures: env.CPUFeatures, MachineDigest: env.MachineDigest,
	}
}

func publicationV4ArtifactPaths(paths benchmarkArtifactsWire) map[string]string {
	return map[string]string{
		"public_params": paths.PublicParams, "b_matrix": paths.BMatrix, "holder_secret": paths.HolderSecret,
		"commit_request": paths.CommitRequest, "presign_submission": paths.Submission, "issue_response": paths.Response,
		"state": paths.State, "verifier_key": paths.VerifierKey, "presentation": paths.Presentation,
		"holder_usage_state": paths.HolderUsageState, "verifier_state": paths.VerifierState, "ntru_params": paths.NTRUParams,
		"ntru_public": paths.NTRUPublic, "ntru_private": paths.NTRUPrivate, "ntru_signature": paths.NTRUSignature,
	}
}

func publicationV4ResolvePath(root, encoded string) (string, error) {
	if strings.TrimSpace(encoded) == "" {
		return "", fmt.Errorf("empty publication-v4 path")
	}
	path := filepath.Clean(filepath.FromSlash(encoded))
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("publication-v4 path %q escapes SPRUCE root", encoded)
	}
	return abs, nil
}

func publicationV4ResolveRunFile(root, runDir, encoded string) (string, error) {
	path, err := publicationV4ResolvePath(root, encoded)
	if err != nil {
		return "", err
	}
	if filepath.Dir(path) != runDir {
		return "", fmt.Errorf("run file %q escapes its run directory", encoded)
	}
	return path, nil
}

func publicationV4ReadRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular non-symlink file", path)
	}
	return os.ReadFile(path)
}
