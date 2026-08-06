package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"vSIS-Signature/credential"
)

const (
	publicationCandidateLockSchemaV4 = "spruce.publication-candidate-lock.v4"
	publicationCandidateLockVersion  = 4
	publicationBenchmarkSchemaV4     = "spruce.publication-benchmark-batch.v4"
	publicationBenchmarkVersion      = 4
	publicationDefaultRuns           = 7
	publicationPresetCount           = 5
)

var publicationV4ExpectedLabels = []string{
	credential.IntGenISISPublicationLabelBQ96Q32,
	credential.IntGenISISPublicationLabelBQ96Q96,
	credential.IntGenISISPublicationLabelWF128,
	credential.IntGenISISPublicationLabelBQ128Q64,
	credential.IntGenISISPublicationLabelBQ128Q128,
}

type publicationCandidateBinding struct {
	CanonicalID      string                            `json:"canonical_id"`
	PublicationLabel string                            `json:"publication_label"`
	ManifestDigest   string                            `json:"manifest_digest"`
	ManifestStatus   string                            `json:"manifest_status"`
	Issuance         credential.IntGenISISTuningPreset `json:"issuance"`
	Showing          credential.IntGenISISTuningPreset `json:"showing"`
	CandidateDigest  string                            `json:"candidate_digest"`
	SelectionStatus  string                            `json:"selection_status"`
	Projection       *publicationCandidateProjection   `json:"projection,omitempty"`
}

type publicationCandidateProjection struct {
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

type publicationPresetSearchResult struct {
	CanonicalID            string                                 `json:"canonical_id"`
	PublicationLabel       string                                 `json:"publication_label"`
	ManifestDigest         string                                 `json:"manifest_digest"`
	CandidateCount         int                                    `json:"candidate_count"`
	EligibleCount          int                                    `json:"eligible_count"`
	Winner                 publicationCandidateBinding            `json:"winner"`
	Finalists              []publicationCandidateBinding          `json:"finalists"`
	ExecutedFinalists      []publicationFinalistExecution         `json:"executed_finalists"`
	MeasurementStatus      string                                 `json:"measurement_status"`
	BoundaryHits           []string                               `json:"boundary_hits,omitempty"`
	SupportFloorHits       []string                               `json:"support_floor_hits,omitempty"`
	ExpandableBoundaryHits []string                               `json:"expandable_boundary_hits,omitempty"`
	WinnerInterior         bool                                   `json:"winner_interior"`
	LowerBoundExclusions   []string                               `json:"lower_bound_exclusions"`
	CertifiedSupportFloors []publicationSupportFloorCertification `json:"certified_support_floors"`
	EnvelopesSearched      []publicationSearchEnvelope            `json:"envelopes_searched"`
}

type publicationSupportFloorCertification struct {
	Dimension string `json:"dimension"`
	Minimum   int    `json:"minimum"`
	Basis     string `json:"basis"`
}

type publicationFinalistExecution struct {
	CandidateDigest string `json:"candidate_digest"`
	ReportFile      string `json:"report_file"`
	ReportSHA256    string `json:"report_sha256"`
	Status          string `json:"status"`
}

type publicationSourceBinding struct {
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

type publicationStoppingEvidence struct {
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

type publicationSearchEnvelope struct {
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

type publicationCandidateLock struct {
	Schema              string                          `json:"schema"`
	Version             int                             `json:"version"`
	Status              string                          `json:"status"`
	SearchAlgorithm     string                          `json:"search_algorithm"`
	Ranking             []string                        `json:"ranking"`
	Envelope            publicationSearchEnvelope       `json:"envelope"`
	EnvelopesSearched   []publicationSearchEnvelope     `json:"envelopes_searched"`
	CounterBound        string                          `json:"counter_bound"`
	MerkleBound         string                          `json:"merkle_bound"`
	Source              publicationSourceBinding        `json:"source"`
	Stopping            publicationStoppingEvidence     `json:"stopping_evidence"`
	NoLivePresetRewrite bool                            `json:"no_live_preset_rewrite"`
	PresetCount         int                             `json:"preset_count"`
	Presets             []publicationPresetSearchResult `json:"presets"`
	ContentDigest       string                          `json:"content_digest"`
}

type publicationRunMetrics struct {
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

type publicationPhaseWireRun struct {
	CounterBytes          int       `json:"counter_bytes"`
	FSCounters            [4]uint64 `json:"fs_counters"`
	AuthenticationBytes   int       `json:"authentication_bytes"`
	MerkleNodesUsed       int       `json:"merkle_nodes_used"`
	MerkleNodesBound      int       `json:"merkle_nodes_bound"`
	DeterministicMaxBytes int       `json:"deterministic_max_bytes"`
}

type publicationBenchmarkRun struct {
	Stage                    string                            `json:"stage"`
	CandidateRank            int                               `json:"candidate_rank"`
	CandidateRun             int                               `json:"candidate_run"`
	Round                    int                               `json:"round"`
	RotationPosition         int                               `json:"rotation_position"`
	CanonicalID              string                            `json:"canonical_id"`
	PublicationLabel         string                            `json:"publication_label"`
	CandidateDigest          string                            `json:"candidate_digest"`
	ManifestDigest           string                            `json:"manifest_digest"`
	RunDirectory             string                            `json:"run_directory"`
	ReportFile               string                            `json:"report_file"`
	ReportSHA256             string                            `json:"report_sha256"`
	ResourceFile             string                            `json:"resource_file"`
	ResourceSHA256           string                            `json:"resource_sha256"`
	Environment              benchmarkIntGenISISE2EEnvironment `json:"environment"`
	Metrics                  publicationRunMetrics             `json:"metrics"`
	ConfiguredFSBits         int                               `json:"configured_fs_output_bits"`
	ObservedFSBits           [][4]int                          `json:"observed_fs_digest_bits"`
	IssuanceWire             publicationPhaseWireRun           `json:"issuance_wire"`
	ShowingWire              publicationPhaseWireRun           `json:"showing_wire"`
	ReplayRejected           bool                              `json:"replay_rejected"`
	TamperRejected           bool                              `json:"tamper_rejected"`
	ArtifactHashesVerified   bool                              `json:"artifact_hashes_verified"`
	ArtifactSHA256           map[string]string                 `json:"artifact_sha256"`
	FullGameAccountingStatus string                            `json:"full_game_accounting_status"`
	LedgerStatus             string                            `json:"ledger_status"`
	ParameterAuditStatus     string                            `json:"parameter_audit_status"`
}

type publicationBenchmarkScheduleEntry struct {
	Sequence         int    `json:"sequence"`
	Stage            string `json:"stage"`
	CanonicalID      string `json:"canonical_id"`
	CandidateDigest  string `json:"candidate_digest"`
	CandidateRank    int    `json:"candidate_rank"`
	CandidateRun     int    `json:"candidate_run"`
	RotationPosition int    `json:"rotation_position"`
}

type publicationBenchmarkAcceptance struct {
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

type publicationDistribution struct {
	Median float64 `json:"median"`
	MAD    float64 `json:"mad"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

type publicationPresetAggregate struct {
	CanonicalID            string                  `json:"canonical_id"`
	PublicationLabel       string                  `json:"publication_label"`
	CandidateDigest        string                  `json:"candidate_digest"`
	Runs                   int                     `json:"runs"`
	CredentialStateBytes   publicationDistribution `json:"credential_state_bytes"`
	IssuanceProofBytes     publicationDistribution `json:"issuance_proof_wire_bytes"`
	ShowingProofBytes      publicationDistribution `json:"showing_proof_wire_bytes"`
	IssuanceProofMaxBytes  publicationDistribution `json:"issuance_proof_max_bytes"`
	ShowingProofMaxBytes   publicationDistribution `json:"showing_proof_max_bytes"`
	PresentationBytes      publicationDistribution `json:"presentation_wire_bytes"`
	PresentationMaxBytes   publicationDistribution `json:"presentation_max_bytes"`
	IssuancePaperBytes     publicationDistribution `json:"issuance_paper_transcript_bytes"`
	ShowingPaperBytes      publicationDistribution `json:"showing_paper_transcript_bytes"`
	IssuanceProvingMS      publicationDistribution `json:"issuance_proving_ms"`
	IssuanceVerificationMS publicationDistribution `json:"issuance_verification_ms"`
	ShowingProvingMS       publicationDistribution `json:"showing_proving_ms"`
	ShowingVerificationMS  publicationDistribution `json:"showing_verification_ms"`
	AllocatedBytes         publicationDistribution `json:"allocated_bytes"`
	Allocations            publicationDistribution `json:"allocations"`
	PeakRSSBytes           publicationDistribution `json:"peak_rss_bytes"`
}

type publicationBenchmarkBatch struct {
	Schema               string                              `json:"schema"`
	Version              int                                 `json:"version"`
	Status               string                              `json:"status"`
	GeneratedAt          string                              `json:"generated_at"`
	BatchID              string                              `json:"batch_id"`
	CandidateLockFile    string                              `json:"candidate_lock_file"`
	CandidateLockDigest  string                              `json:"candidate_lock_digest"`
	RunsPerPreset        int                                 `json:"runs_per_preset"`
	Rotation             [][]string                          `json:"rotation"`
	ExecutionPolicy      string                              `json:"execution_policy"`
	Schedule             []publicationBenchmarkScheduleEntry `json:"schedule"`
	Acceptance           publicationBenchmarkAcceptance      `json:"acceptance"`
	SourceAndMachineSame bool                                `json:"source_and_machine_consistent"`
	Environment          benchmarkIntGenISISE2EEnvironment   `json:"environment"`
	Runs                 []publicationBenchmarkRun           `json:"runs"`
	Presets              []publicationPresetAggregate        `json:"presets"`
	ReportsDigest        string                              `json:"reports_digest"`
}

func publicationV4Presets() ([]credential.IntGenISISPreset, error) {
	names := credential.IntGenISISPublicationPresetNamesV4()
	if len(names) != publicationPresetCount {
		return nil, fmt.Errorf("publication-v4 registry has %d presets; want exactly %d", len(names), publicationPresetCount)
	}
	seen := make(map[string]struct{}, len(names))
	presets := make([]credential.IntGenISISPreset, 0, len(names))
	for i, name := range names {
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("publication-v4 registry repeats %q", name)
		}
		seen[name] = struct{}{}
		preset, ok := credential.LookupIntGenISISPublicationPreset(name)
		if !ok {
			return nil, fmt.Errorf("publication-v4 registry entry %q does not resolve as an exact v4 preset", name)
		}
		if preset.CanonicalID != name || preset.PublicationLabel != publicationV4ExpectedLabels[i] {
			return nil, fmt.Errorf("publication-v4 registry entry %d has identity (%q,%q); want (%q,%q)", i, preset.CanonicalID, preset.PublicationLabel, name, publicationV4ExpectedLabels[i])
		}
		if err := credential.ValidateIntGenISISPresetManifest(preset); err != nil {
			return nil, fmt.Errorf("publication-v4 preset %s has an invalid manifest: %w", name, err)
		}
		presets = append(presets, preset)
	}
	return presets, nil
}

func runListPublicationPresets(args []string) error {
	fs := flag.NewFlagSet("list-publication-presets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOutput := fs.Bool("json", false, "emit the exact-five registry as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("list-publication-presets accepts no positional arguments")
	}
	presets, err := publicationV4Presets()
	if err != nil {
		return err
	}
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(presets)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "LABEL\tCANONICAL PRESET\tNOMINAL TARGET\tNATIVE ROUND TARGET\tAGGREGATE Q\tFS/HASH BITS\tISSUE/SHOW L")
	for _, preset := range presets {
		query := "WF"
		nominal := preset.ThreatModel.TargetWorkFactorBits
		if preset.ThreatModel.AggregateROQueryCapLog2Set {
			query = fmt.Sprintf("2^%.0f", preset.ThreatModel.AggregateROQueryCapLog2)
			nominal = preset.ThreatModel.TargetResidualBits
		}
		fmt.Fprintf(w, "%s\t%s\t%.0f\t%.6f\t%s\t%d\t%d/%d\n",
			preset.PublicationLabel, preset.CanonicalID, nominal, preset.TargetTheoremBits, query,
			preset.Showing.FSOutputBits, preset.Issuance.LVCSNCols, preset.Showing.LVCSNCols)
	}
	return w.Flush()
}

func publicationBindingFromPreset(preset credential.IntGenISISPreset, status string) (publicationCandidateBinding, error) {
	binding := publicationCandidateBinding{
		CanonicalID: preset.CanonicalID, PublicationLabel: preset.PublicationLabel,
		ManifestDigest: credential.IntGenISISPresetManifestDigest(preset),
		ManifestStatus: "pinned_validated",
		Issuance:       preset.Issuance, Showing: preset.Showing, SelectionStatus: status,
	}
	digest, err := publicationDigest(binding)
	if err != nil {
		return publicationCandidateBinding{}, err
	}
	binding.CandidateDigest = digest
	return binding, nil
}

func publicationRegistryCandidateLock() (publicationCandidateLock, error) {
	presets, err := publicationV4Presets()
	if err != nil {
		return publicationCandidateLock{}, err
	}
	source, err := publicationCurrentSourceBinding()
	if err != nil {
		return publicationCandidateLock{}, err
	}
	envelope := publicationInitialEnvelope()
	lock := publicationCandidateLock{
		Schema: publicationCandidateLockSchemaV4, Version: publicationCandidateLockVersion,
		Status: "registry_seed_lock", SearchAlgorithm: "exact-five registry seeds; tune-publication-presets replaces projections deterministically",
		Ranking: publicationRankingOrder(), Envelope: envelope, EnvelopesSearched: []publicationSearchEnvelope{envelope},
		CounterBound: "four minimal unsigned LEB128 uint64 counters; deterministic maximum 40 bytes",
		MerkleBound:  "DECS.MerkleFrontierWorstCaseNodesV3(NLeaves,Ell)", Source: source, NoLivePresetRewrite: true, PresetCount: len(presets),
		Stopping: publicationStoppingEvidence{
			WinnerInterior: true, NearFrontierInterior: true, ProjectionMeasurementPending: true,
			BoundaryExpansionRule: "registry seed lock: no optimization or boundary claim",
		},
	}
	for _, preset := range presets {
		binding, bindErr := publicationBindingFromPreset(preset, "registry_seed")
		if bindErr != nil {
			return publicationCandidateLock{}, bindErr
		}
		lock.Presets = append(lock.Presets, publicationPresetSearchResult{
			CanonicalID: preset.CanonicalID, PublicationLabel: preset.PublicationLabel,
			ManifestDigest: binding.ManifestDigest, CandidateCount: 1, EligibleCount: 1,
			Winner: binding, Finalists: []publicationCandidateBinding{binding},
			MeasurementStatus: "analytic_search_not_run_registry_seed_only", WinnerInterior: true,
			LowerBoundExclusions: []string{"none: registry seed lock is non-final"},
		})
	}
	if err := finalizePublicationCandidateLock(&lock); err != nil {
		return publicationCandidateLock{}, err
	}
	return lock, nil
}

func publicationCurrentSourceBinding() (publicationSourceBinding, error) {
	env, err := benchmarkIntGenISISE2EEnvironmentSnapshot()
	if err != nil {
		return publicationSourceBinding{}, err
	}
	modified := false
	if env.Modified != nil {
		modified = *env.Modified
	}
	return publicationSourceBinding{
		Algorithm: env.SourceTreeAlgorithm, Digest: env.SourceTreeDigest,
		FileCount: env.SourceTreeFileCount, Commit: env.Commit, Modified: modified,
		BuildSHA256: env.BuildSHA256, MachineDigest: env.MachineDigest,
		CPUModel: env.CPUModel, CPUFeatures: env.CPUFeatures,
	}, nil
}

func publicationInitialEnvelope() publicationSearchEnvelope {
	return publicationSearchEnvelope{
		LIssuanceMin: 32, LIssuanceMax: 64, LShowingMin: 32, LShowingMax: 64,
		ThetaMin: 5, ThetaMax: 16, EllMin: 6, EllMax: 22, KappaMin: 0, KappaMax: 13,
		NLeavesMin: "L+2*ell", NLeavesMax: int(credential.IntGenISISSharedModulusQ - 1),
	}
}

func publicationRankingOrder() []string {
	return []string{
		"eligible", "showing_proof_max_bytes", "presentation_max_bytes", "showing_paper_transcript_bytes",
		"combined_proof_max_bytes", "combined_paper_transcript_bytes", "expected_grinding_work",
		"projected_work_units", "minimum_security_slack_desc", "lexicographic_tuning_including_phase_nleaves",
	}
}

func finalizePublicationCandidateLock(lock *publicationCandidateLock) error {
	if lock == nil {
		return errors.New("nil publication candidate lock")
	}
	lock.ContentDigest = ""
	digest, err := publicationDigest(*lock)
	if err != nil {
		return err
	}
	lock.ContentDigest = digest
	return validatePublicationCandidateLock(*lock)
}

func validatePublicationCandidateLock(lock publicationCandidateLock) error {
	if lock.Schema != publicationCandidateLockSchemaV4 || lock.Version != publicationCandidateLockVersion {
		return fmt.Errorf("candidate lock identity (%q,v%d) is not publication v4", lock.Schema, lock.Version)
	}
	names := credential.IntGenISISPublicationPresetNamesV4()
	if lock.PresetCount != publicationPresetCount || len(lock.Presets) != publicationPresetCount || len(names) != publicationPresetCount {
		return fmt.Errorf("candidate lock does not contain the exact five publication presets")
	}
	if lock.Source.Algorithm == "" || len(lock.Source.Digest) != sha256.Size*2 || lock.Source.FileCount <= 0 ||
		len(lock.Source.BuildSHA256) != sha256.Size*2 || len(lock.Source.MachineDigest) != sha256.Size*2 || !lock.NoLivePresetRewrite {
		return fmt.Errorf("candidate lock has incomplete source/no-rewrite binding")
	}
	if lock.Status == "analytic_complete_measurement_pending" {
		if len(lock.EnvelopesSearched) < 3 || lock.Stopping.StableExpandedEnvelopes < 2 || !lock.Stopping.WinnerInterior ||
			!lock.Stopping.NearFrontierInterior || !lock.Stopping.ExactIntegerRoots || !lock.Stopping.AdmissibleLowerBoundsApplied ||
			!lock.Stopping.SupportFloorsCertified || len(lock.Stopping.UnresolvedBoundaries) != 0 || lock.Stopping.BoundaryExpansionRule == "" {
			return fmt.Errorf("complete analytic lock lacks the required two-expanded-envelope stopping certificate")
		}
	}
	for i, result := range lock.Presets {
		if result.CanonicalID != names[i] || result.PublicationLabel != publicationV4ExpectedLabels[i] || result.Winner.CanonicalID != result.CanonicalID || result.Winner.PublicationLabel != result.PublicationLabel {
			return fmt.Errorf("candidate lock preset %d is out of canonical paper order", i)
		}
		preset, ok := credential.LookupIntGenISISPublicationPreset(result.CanonicalID)
		if !ok {
			return fmt.Errorf("candidate lock refers to unknown publication preset %q", result.CanonicalID)
		}
		manifestDigest := credential.IntGenISISPresetManifestDigest(preset)
		if result.ManifestDigest != manifestDigest {
			return fmt.Errorf("candidate lock base manifest changed for %s", result.CanonicalID)
		}
		if len(result.Finalists) == 0 {
			return fmt.Errorf("candidate lock has no finalists for %s", result.CanonicalID)
		}
		if strings.HasPrefix(lock.Status, "analytic_") && len(result.EnvelopesSearched) != len(lock.EnvelopesSearched) {
			return fmt.Errorf("candidate lock preset %s lacks its envelope search history", result.CanonicalID)
		}
		if strings.HasPrefix(lock.Status, "analytic_") {
			if err := validatePublicationSupportFloorEvidence(result, lock.EnvelopesSearched[0]); err != nil {
				return fmt.Errorf("candidate lock preset %s: %w", result.CanonicalID, err)
			}
		}
		if result.Winner.CandidateDigest != result.Finalists[0].CandidateDigest {
			return fmt.Errorf("candidate lock winner is not finalist rank 1 for %s", result.CanonicalID)
		}
		for rank, candidate := range result.Finalists {
			if err := validatePublicationCandidateBinding(result, candidate); err != nil {
				return fmt.Errorf("%s finalist rank %d: %w", result.CanonicalID, rank+1, err)
			}
		}
	}
	gotDigest := lock.ContentDigest
	lock.ContentDigest = ""
	wantDigest, err := publicationDigest(lock)
	if err != nil {
		return err
	}
	if gotDigest != wantDigest {
		return fmt.Errorf("candidate lock content digest mismatch: have %q want %q", gotDigest, wantDigest)
	}
	return nil
}

func validatePublicationSupportFloorEvidence(result publicationPresetSearchResult, initial publicationSearchEnvelope) error {
	want := publicationCertifiedSupportFloors(initial)
	if !reflect.DeepEqual(result.CertifiedSupportFloors, want) {
		return fmt.Errorf("certified lower support floors do not match the approved initial envelope")
	}
	certified := make(map[string]struct{}, len(want))
	for _, floor := range want {
		certified[floor.Dimension] = struct{}{}
	}
	for _, hit := range result.SupportFloorHits {
		if !strings.HasSuffix(hit, "_lower") {
			return fmt.Errorf("support-floor hit %q is expandable", hit)
		}
		if _, ok := certified[hit]; !ok {
			return fmt.Errorf("support-floor hit %q has no certification", hit)
		}
	}
	for _, hit := range result.ExpandableBoundaryHits {
		if strings.HasSuffix(hit, "_lower") {
			return fmt.Errorf("expandable hit %q is a certified lower floor", hit)
		}
	}
	seen := make(map[string]int, len(result.BoundaryHits))
	for _, hit := range result.BoundaryHits {
		seen[hit]++
	}
	for _, hit := range append(append([]string(nil), result.SupportFloorHits...), result.ExpandableBoundaryHits...) {
		seen[hit]--
	}
	for hit, count := range seen {
		if count != 0 {
			return fmt.Errorf("raw boundary hit partition mismatch at %q", hit)
		}
	}
	if len(result.LowerBoundExclusions) < 3 {
		return fmt.Errorf("lower support-floor exclusions are incomplete")
	}
	return nil
}

func validatePublicationCandidateBinding(result publicationPresetSearchResult, candidate publicationCandidateBinding) error {
	if candidate.CanonicalID != result.CanonicalID || candidate.PublicationLabel != result.PublicationLabel ||
		candidate.Issuance.Theta != candidate.Showing.Theta || candidate.Issuance.Ell != candidate.Showing.Ell {
		return fmt.Errorf("candidate identity or shared field tuple mismatch")
	}
	gotDigest := candidate.CandidateDigest
	candidate.CandidateDigest = ""
	wantDigest, err := publicationDigest(candidate)
	if err != nil || gotDigest == "" || gotDigest != wantDigest {
		return fmt.Errorf("candidate content digest mismatch")
	}
	switch candidate.ManifestStatus {
	case "pinned_validated":
		if candidate.ManifestDigest == "" {
			return fmt.Errorf("pinned candidate has no manifest digest")
		}
		if _, err := publicationPresetFromBinding(candidate); err != nil {
			return err
		}
	case "field_profile_generation_required":
		if candidate.ManifestDigest != "" || candidate.SelectionStatus != "projected_field_profile_pending" {
			return fmt.Errorf("pending field profile is mislabeled as an executable manifest")
		}
	default:
		return fmt.Errorf("unknown manifest status %q", candidate.ManifestStatus)
	}
	return nil
}

func readPublicationCandidateLock(path string) (publicationCandidateLock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return publicationCandidateLock{}, err
	}
	var lock publicationCandidateLock
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&lock); err != nil {
		return publicationCandidateLock{}, fmt.Errorf("decode publication candidate lock: %w", err)
	}
	if err := validatePublicationCandidateLock(lock); err != nil {
		return publicationCandidateLock{}, err
	}
	return lock, nil
}

func runTunePublicationPresets(args []string) error {
	fs := flag.NewFlagSet("tune-publication-presets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "required path for the content-addressed candidate lock")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("tune-publication-presets accepts no positional arguments")
	}
	if strings.TrimSpace(*out) == "" {
		return fmt.Errorf("missing -out")
	}
	lock, err := tunePublicationCandidateLock()
	if err != nil {
		return err
	}
	outPath := filepath.Clean(*out)
	if info, statErr := os.Stat(outPath); statErr == nil && info.IsDir() || filepath.Ext(outPath) == "" {
		outPath = filepath.Join(outPath, "candidate-lock.json")
	}
	if err := writePublicationJSONAtomic(outPath, lock); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "publication candidate lock %s written to %s\n", lock.ContentDigest, outPath)
	return nil
}

func runBenchmarkPublicationPresets(args []string) error {
	fs := flag.NewFlagSet("benchmark-publication-presets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	runs := fs.Int("runs", publicationDefaultRuns, "fresh complete runs per preset")
	artifactRoot := fs.String("artifact-dir", filepath.Join("artifacts", "publication-v4", "benchmarks"), "root for a new unique batch directory")
	jsonOut := fs.String("json-out", "", "batch summary JSON path; defaults inside the new batch directory")
	candidateLockPath := fs.String("candidate-lock", "", "optional tune-publication-presets lock; default locks current exact-five manifests")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("benchmark-publication-presets accepts no positional arguments")
	}
	if *runs <= 0 || *runs > 100 {
		return fmt.Errorf("-runs must be in [1,100]")
	}
	if strings.TrimSpace(*artifactRoot) == "" {
		return fmt.Errorf("-artifact-dir must not be empty")
	}
	var lock publicationCandidateLock
	var err error
	if strings.TrimSpace(*candidateLockPath) == "" {
		lock, err = publicationRegistryCandidateLock()
	} else {
		lock, err = readPublicationCandidateLock(*candidateLockPath)
	}
	if err != nil {
		return err
	}
	if err := requirePublicationLockExecutable(lock); err != nil {
		return err
	}
	batchDir, batchID, err := createPublicationBatchDir(*artifactRoot)
	if err != nil {
		return err
	}
	lockFile := filepath.Join(batchDir, "candidate-lock.json")
	if err := writePublicationJSONAtomic(lockFile, lock); err != nil {
		return err
	}
	if strings.TrimSpace(*jsonOut) == "" {
		*jsonOut = filepath.Join(batchDir, "benchmark-publication-presets.json")
	}
	batch, err := benchmarkPublicationBatch(lock, lockFile, batchDir, batchID, *runs)
	if err != nil {
		return err
	}
	if err := writePublicationJSONAtomic(*jsonOut, batch); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "publication benchmark batch %s (%d reports) written to %s\n", batch.BatchID, len(batch.Runs), *jsonOut)
	return nil
}

func runBenchmarkPublicationCandidate(args []string) error {
	fs := flag.NewFlagSet("benchmark-publication-candidate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	candidatePath := fs.String("candidate", "", "internal candidate-binding JSON")
	artifactDir := fs.String("artifact-dir", "", "fresh artifact directory")
	jsonOut := fs.String("json-out", "", "raw report output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *candidatePath == "" || *artifactDir == "" || *jsonOut == "" {
		return fmt.Errorf("benchmark-publication-candidate requires -candidate, -artifact-dir, and -json-out")
	}
	var binding publicationCandidateBinding
	if err := readJSONFile(*candidatePath, &binding); err != nil {
		return err
	}
	result := publicationPresetSearchResult{CanonicalID: binding.CanonicalID, PublicationLabel: binding.PublicationLabel}
	if err := validatePublicationCandidateBinding(result, binding); err != nil {
		return err
	}
	candidate, err := publicationPresetFromBinding(binding)
	if err != nil {
		return err
	}
	return credential.WithIntGenISISPublicationEvidenceCandidate(candidate, func() error {
		cfg, err := parseBenchmarkIntGenISISE2EConfig([]string{"-preset", candidate.CanonicalID, "-artifact-dir", *artifactDir, "-json-out", *jsonOut})
		if err != nil {
			return err
		}
		_, err = benchmarkIntGenISISE2E(cfg)
		return err
	})
}

func requirePublicationLockMatchesRegistry(lock publicationCandidateLock) error {
	if err := validatePublicationCandidateLock(lock); err != nil {
		return err
	}
	for _, result := range lock.Presets {
		preset, _ := credential.LookupIntGenISISPublicationPreset(result.CanonicalID)
		if result.Winner.Issuance != preset.Issuance || result.Winner.Showing != preset.Showing {
			return fmt.Errorf("candidate %s is not adopted by the live manifest; update the registry and rerun tuning before benchmarking", result.CanonicalID)
		}
	}
	return nil
}

func requirePublicationLockExecutable(lock publicationCandidateLock) error {
	if err := validatePublicationCandidateLock(lock); err != nil {
		return err
	}
	for _, result := range lock.Presets {
		for rank, binding := range result.Finalists {
			if binding.ManifestStatus != "pinned_validated" {
				return fmt.Errorf("candidate %s rank %d requires a pinned theta=%d field profile before execution", result.CanonicalID, rank+1, binding.Showing.Theta)
			}
			if _, err := publicationPresetFromBinding(binding); err != nil {
				return err
			}
		}
	}
	return nil
}

func createPublicationBatchDir(root string) (string, string, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", "", fmt.Errorf("create publication artifact root: %w", err)
	}
	base := time.Now().UTC().Format("20060102T150405.000000000Z") + fmt.Sprintf("-p%d", os.Getpid())
	for suffix := 0; suffix < 1000; suffix++ {
		id := base
		if suffix > 0 {
			id = fmt.Sprintf("%s-%03d", base, suffix)
		}
		path := filepath.Join(root, "batch-"+id)
		if err := os.Mkdir(path, 0o755); err == nil {
			return path, id, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", "", fmt.Errorf("create unique publication batch directory: %w", err)
		}
	}
	return "", "", fmt.Errorf("could not allocate a unique publication batch directory below %s", root)
}

func publicationRotation(names []string, runs int) [][]string {
	out := make([][]string, runs)
	for round := 0; round < runs; round++ {
		out[round] = make([]string, len(names))
		for position := range names {
			out[round][position] = names[(round+position)%len(names)]
		}
	}
	return out
}

func benchmarkPublicationBatch(lock publicationCandidateLock, lockFile, batchDir, batchID string, runs int) (publicationBenchmarkBatch, error) {
	names := credential.IntGenISISPublicationPresetNamesV4()
	rotation := publicationRotation(names, runs)
	schedule, err := publicationBenchmarkSchedule(lock, runs)
	if err != nil {
		return publicationBenchmarkBatch{}, err
	}
	batch := publicationBenchmarkBatch{
		Schema: publicationBenchmarkSchemaV4, Version: publicationBenchmarkVersion,
		Status:      "running",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), BatchID: batchID,
		CandidateLockFile: lockFile, CandidateLockDigest: lock.ContentDigest,
		RunsPerPreset: runs, Rotation: rotation, SourceAndMachineSame: true,
		ExecutionPolicy: "top-12 once; analytic top-3 three total runs including screening; analytic winner seven additional fresh final runs; cyclic preset rotation",
		Schedule:        schedule,
	}
	var reference *benchmarkIntGenISISE2EEnvironment
	for _, entry := range schedule {
		binding, err := publicationScheduledBinding(lock, entry)
		if err != nil {
			return publicationBenchmarkBatch{}, err
		}
		runDir := filepath.Join(batchDir, fmt.Sprintf("%03d-%s-rank-%02d-run-%02d-position-%02d-%s", entry.Sequence, entry.Stage, entry.CandidateRank, entry.CandidateRun, entry.RotationPosition, strings.ToLower(binding.PublicationLabel)))
		rawReportPath := filepath.Join(runDir, "benchmark-intgenisis-e2e.json")
		resourcePath := filepath.Join(runDir, "resource.txt")
		report, peakRSS, resourceDigest, err := executePublicationBenchmarkRun(binding, runDir, rawReportPath, resourcePath)
		if err != nil {
			return publicationBenchmarkBatch{}, fmt.Errorf("publication batch sequence %d stage %s preset %s: %w", entry.Sequence, entry.Stage, entry.CanonicalID, err)
		}
		modified := report.Environment.Modified != nil && *report.Environment.Modified
		if report.Environment.SourceTreeAlgorithm != lock.Source.Algorithm || report.Environment.SourceTreeDigest != lock.Source.Digest ||
			report.Environment.SourceTreeFileCount != lock.Source.FileCount || report.Environment.Commit != lock.Source.Commit || modified != lock.Source.Modified ||
			report.Environment.BuildSHA256 != lock.Source.BuildSHA256 || report.Environment.MachineDigest != lock.Source.MachineDigest {
			return publicationBenchmarkBatch{}, fmt.Errorf("benchmark source no longer matches candidate lock at %s sequence %d", entry.CanonicalID, entry.Sequence)
		}
		if reference == nil {
			copy := report.Environment
			reference = &copy
			batch.Environment = copy
		} else if !reflect.DeepEqual(*reference, report.Environment) {
			batch.SourceAndMachineSame = false
			return publicationBenchmarkBatch{}, fmt.Errorf("source or machine environment changed within publication batch at %s sequence %d", entry.CanonicalID, entry.Sequence)
		}
		run, err := publicationRunFromReport(report, rawReportPath, resourcePath, resourceDigest, runDir, entry.CandidateRun, entry.RotationPosition, peakRSS, binding)
		if err != nil {
			return publicationBenchmarkBatch{}, err
		}
		run.Stage, run.CandidateRank, run.CandidateRun = entry.Stage, entry.CandidateRank, entry.CandidateRun
		batch.Runs = append(batch.Runs, run)
	}
	batch.Presets = aggregatePublicationRuns(batch.Runs, names)
	digestParts := make([]string, 0, len(batch.Runs))
	for _, run := range batch.Runs {
		digestParts = append(digestParts, fmt.Sprintf("%s:%02d:%02d:%02d:%s:%s:%s:%s", run.Stage, run.CandidateRank, run.CandidateRun, run.RotationPosition, run.CanonicalID, run.CandidateDigest, run.ReportSHA256, run.ResourceSHA256))
	}
	digest, err := publicationDigest(digestParts)
	if err != nil {
		return publicationBenchmarkBatch{}, err
	}
	batch.ReportsDigest = digest
	batch.Acceptance = publicationBatchAcceptance(lock, batch)
	if publicationCriticalAcceptance(batch.Acceptance) {
		batch.Status = "accepted"
	} else {
		batch.Status = "evidence_complete_not_accepted"
	}
	return batch, nil
}

func publicationBenchmarkSchedule(lock publicationCandidateLock, finalRuns int) ([]publicationBenchmarkScheduleEntry, error) {
	byName := make(map[string]publicationPresetSearchResult, len(lock.Presets))
	for _, result := range lock.Presets {
		byName[result.CanonicalID] = result
	}
	names := credential.IntGenISISPublicationPresetNamesV4()
	var out []publicationBenchmarkScheduleEntry
	appendGroup := func(stage string, rank, candidateRun, rotation int) error {
		for position := range names {
			name := names[(rotation+position)%len(names)]
			result := byName[name]
			if rank <= 0 || rank > len(result.Finalists) {
				return fmt.Errorf("%s has %d finalists; schedule requires rank %d", name, len(result.Finalists), rank)
			}
			binding := result.Finalists[rank-1]
			out = append(out, publicationBenchmarkScheduleEntry{Sequence: len(out) + 1, Stage: stage, CanonicalID: name, CandidateDigest: binding.CandidateDigest, CandidateRank: rank, CandidateRun: candidateRun, RotationPosition: position + 1})
		}
		return nil
	}
	for rank := 1; rank <= publicationFinalistCount; rank++ {
		if err := appendGroup("screening", rank, 1, rank-1); err != nil {
			return nil, err
		}
	}
	group := publicationFinalistCount
	for candidateRun := 2; candidateRun <= 3; candidateRun++ {
		for rank := 1; rank <= 3; rank++ {
			if err := appendGroup("confirmation", rank, candidateRun, group); err != nil {
				return nil, err
			}
			group++
		}
	}
	for candidateRun := 1; candidateRun <= finalRuns; candidateRun++ {
		if err := appendGroup("final", 1, candidateRun, candidateRun-1); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func publicationScheduledBinding(lock publicationCandidateLock, entry publicationBenchmarkScheduleEntry) (publicationCandidateBinding, error) {
	for _, result := range lock.Presets {
		if result.CanonicalID != entry.CanonicalID {
			continue
		}
		if entry.CandidateRank <= 0 || entry.CandidateRank > len(result.Finalists) {
			break
		}
		binding := result.Finalists[entry.CandidateRank-1]
		if binding.CandidateDigest != entry.CandidateDigest {
			break
		}
		return binding, nil
	}
	return publicationCandidateBinding{}, fmt.Errorf("schedule candidate binding mismatch at sequence %d", entry.Sequence)
}

func executePublicationBenchmarkRun(binding publicationCandidateBinding, runDir, reportPath, resourcePath string) (benchmarkIntGenISISE2EReport, uint64, string, error) {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", err
	}
	executable, err := os.Executable()
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", err
	}
	timeArgs := []string{"-l", executable}
	if runtime.GOOS != "darwin" {
		timeArgs = []string{"-v", executable}
	}
	timeArgs = append(timeArgs,
		"benchmark-publication-candidate", "-candidate", filepath.Join(runDir, "candidate-binding.json"),
		"-artifact-dir", runDir, "-json-out", reportPath,
	)
	if err := writePublicationJSONAtomic(filepath.Join(runDir, "candidate-binding.json"), binding); err != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", err
	}
	resource, err := os.OpenFile(resourcePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", err
	}
	cmd := exec.Command("/usr/bin/time", timeArgs...)
	cmd.Stdout = resource
	cmd.Stderr = resource
	runErr := cmd.Run()
	closeErr := resource.Close()
	if runErr != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", fmt.Errorf("isolated benchmark child failed: %w (resource log %s)", runErr, resourcePath)
	}
	if closeErr != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", closeErr
	}
	var report benchmarkIntGenISISE2EReport
	if err := readJSONFile(reportPath, &report); err != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", fmt.Errorf("decode isolated benchmark report: %w", err)
	}
	resourceData, err := os.ReadFile(resourcePath)
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", err
	}
	peakRSS, err := publicationPeakRSS(resourceData)
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", fmt.Errorf("parse isolated benchmark resources: %w", err)
	}
	report.Resources.PeakRSSBytes = peakRSS
	if err := writePublicationJSONAtomic(reportPath, report); err != nil {
		return benchmarkIntGenISISE2EReport{}, 0, "", fmt.Errorf("enrich raw report with peak RSS: %w", err)
	}
	sum := sha256.Sum256(resourceData)
	return report, peakRSS, hex.EncodeToString(sum[:]), nil
}

func publicationPeakRSS(data []byte) (uint64, error) {
	for _, line := range strings.Split(string(data), "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "maximum resident set size") {
			continue
		}
		if strings.Contains(lower, "kbytes") {
			parts := strings.Split(line, ":")
			parsed, err := strconv.ParseUint(strings.TrimSpace(parts[len(parts)-1]), 10, 64)
			if err != nil {
				return 0, err
			}
			return parsed * 1024, nil
		}
		for _, field := range strings.Fields(line) {
			if parsed, err := strconv.ParseUint(field, 10, 64); err == nil {
				return parsed, nil
			}
		}
	}
	return 0, fmt.Errorf("resource output has no maximum resident set size")
}

func publicationRunFromReport(report benchmarkIntGenISISE2EReport, reportPath, resourcePath, resourceDigest, runDir string, round, position int, peakRSS uint64, binding publicationCandidateBinding) (publicationBenchmarkRun, error) {
	if report.CanonicalPresetID != binding.CanonicalID || report.PresetManifestDigest != binding.ManifestDigest {
		return publicationBenchmarkRun{}, fmt.Errorf("benchmark report binding mismatch for %s", binding.CanonicalID)
	}
	if report.CanonicalSizes == nil || report.CanonicalSizes.IssuanceProofWireBytes <= 0 || report.CanonicalSizes.ShowingProofWireBytes <= 0 || report.CanonicalSizes.PresentationWireBytes <= 0 {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s lacks canonical wire sizes", binding.CanonicalID)
	}
	if !report.ReplayRejected {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s did not reject replay", binding.CanonicalID)
	}
	if !report.TamperRejected || !report.Issuance.CanonicalTamperRejected || !report.Showing.CanonicalTamperRejected {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s did not reject canonical tampering in both phases", binding.CanonicalID)
	}
	if !report.ArtifactHashesVerified || len(report.ArtifactSHA256) != 15 {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s lacks the complete artifact hash set", binding.CanonicalID)
	}
	recomputedArtifacts, err := benchmarkIntGenISISE2EArtifactHashes(report.Artifacts)
	if err != nil || !reflect.DeepEqual(recomputedArtifacts, report.ArtifactSHA256) {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s artifact hashes do not verify from disk", binding.CanonicalID)
	}
	if peakRSS == 0 || report.Resources.PeakRSSBytes != peakRSS || report.Resources.AllocatedBytes == 0 || report.Resources.Allocations == 0 {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s lacks complete isolated resource measurements", binding.CanonicalID)
	}
	if report.FullGameAccountingStatus != "aggregate_composed_game_v4" || report.ParameterAudit.Status != "pass" || report.LedgerStatus == "" {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s lacks passing aggregate composed-game/audit accounting", binding.CanonicalID)
	}
	if report.Issuance.CanonicalWireAudit == nil || report.Showing.CanonicalWireAudit == nil {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s lacks canonical wire audits", binding.CanonicalID)
	}
	configuredFS := binding.Showing.FSOutputBits
	if configuredFS <= 0 || binding.Issuance.FSOutputBits != configuredFS || report.Issuance.FSOutputBits != configuredFS || report.Showing.FSOutputBits != configuredFS {
		return publicationBenchmarkRun{}, fmt.Errorf("publication report %s configured FS width does not match the candidate", binding.CanonicalID)
	}
	if binding.Showing.AggregateROQueryCapLog2Set {
		if !binding.Issuance.AggregateROQueryCapLog2Set || !report.ThreatModel.AggregateROQueryCapLog2Set ||
			report.ThreatModel.AggregateROQueryCapLog2 != binding.Showing.AggregateROQueryCapLog2 ||
			!report.Issuance.AggregateQueryBudget || !report.Showing.AggregateQueryBudget ||
			report.Issuance.AggregateQueryCapLog2 != binding.Showing.AggregateROQueryCapLog2 || report.Showing.AggregateQueryCapLog2 != binding.Showing.AggregateROQueryCapLog2 {
			return publicationBenchmarkRun{}, fmt.Errorf("publication report %s does not implement its one aggregate oracle budget", binding.CanonicalID)
		}
	} else if binding.Issuance.AggregateROQueryCapLog2Set || report.ThreatModel.AggregateROQueryCapLog2Set || report.Issuance.AggregateQueryBudget || report.Showing.AggregateQueryBudget {
		return publicationBenchmarkRun{}, fmt.Errorf("publication WF report %s unexpectedly claims a bounded-query budget", binding.CanonicalID)
	}
	for phase, observed := range map[string][4]int{"issuance": report.Issuance.ObservedFSDigestBits, "showing": report.Showing.ObservedFSDigestBits} {
		for i, bits := range observed {
			if bits != configuredFS {
				return publicationBenchmarkRun{}, fmt.Errorf("publication report %s %s round %d observed FS width=%d want=%d", binding.CanonicalID, phase, i+1, bits, configuredFS)
			}
		}
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return publicationBenchmarkRun{}, fmt.Errorf("read fresh publication report: %w", err)
	}
	sum := sha256.Sum256(raw)
	phaseWire := func(actual int, metrics benchmarkIntGenISISMetrics) publicationPhaseWireRun {
		audit := metrics.CanonicalWireAudit
		maximum := actual - audit.CounterBytes - audit.AuthenticationBytes + 4*10 + audit.MerkleNodesBound*audit.RootBytes
		return publicationPhaseWireRun{
			CounterBytes: audit.CounterBytes, FSCounters: metrics.FSCounters,
			AuthenticationBytes: audit.AuthenticationBytes, MerkleNodesUsed: audit.MerkleNodesUsed,
			MerkleNodesBound: audit.MerkleNodesBound, DeterministicMaxBytes: maximum,
		}
	}
	issuanceWire := phaseWire(report.CanonicalSizes.IssuanceProofWireBytes, report.Issuance)
	showingWire := phaseWire(report.CanonicalSizes.ShowingProofWireBytes, report.Showing)
	if binding.Projection != nil {
		projection := binding.Projection
		presentationMax := report.CanonicalSizes.PresentationWireBytes - report.CanonicalSizes.ShowingProofWireBytes + showingWire.DeterministicMaxBytes
		if showingWire.DeterministicMaxBytes != projection.ShowingProofMaxBytes || presentationMax != projection.PresentationMaxBytes ||
			report.CanonicalSizes.ShowingPaperBytes != projection.ShowingPaperBytes ||
			issuanceWire.DeterministicMaxBytes+showingWire.DeterministicMaxBytes != projection.CombinedProofMaxBytes ||
			report.CanonicalSizes.IssuancePaperBytes+report.CanonicalSizes.ShowingPaperBytes != projection.CombinedPaperBytes {
			return publicationBenchmarkRun{}, fmt.Errorf("publication report %s projector/serialization assertion failed", binding.CanonicalID)
		}
	}
	return publicationBenchmarkRun{
		Round: round, RotationPosition: position, CanonicalID: binding.CanonicalID,
		PublicationLabel: binding.PublicationLabel, CandidateDigest: binding.CandidateDigest,
		ManifestDigest: binding.ManifestDigest, RunDirectory: runDir, ReportFile: reportPath,
		ReportSHA256: hex.EncodeToString(sum[:]), ResourceFile: resourcePath, ResourceSHA256: resourceDigest, Environment: report.Environment,
		Metrics: publicationRunMetrics{
			CredentialStateBytes:  report.CanonicalSizes.CredentialStateBytes,
			IssuanceProofBytes:    report.CanonicalSizes.IssuanceProofWireBytes,
			ShowingProofBytes:     report.CanonicalSizes.ShowingProofWireBytes,
			IssuanceProofMaxBytes: issuanceWire.DeterministicMaxBytes,
			ShowingProofMaxBytes:  showingWire.DeterministicMaxBytes,
			PresentationBytes:     report.CanonicalSizes.PresentationWireBytes,
			PresentationMaxBytes:  report.CanonicalSizes.PresentationWireBytes - report.CanonicalSizes.ShowingProofWireBytes + showingWire.DeterministicMaxBytes,
			IssuancePaperBytes:    report.CanonicalSizes.IssuancePaperBytes,
			ShowingPaperBytes:     report.CanonicalSizes.ShowingPaperBytes,
			IssuanceProvingMS:     report.Issuance.ProvingMS, IssuanceVerificationMS: report.Issuance.VerificationMS,
			ShowingProvingMS: report.Showing.ProvingMS, ShowingVerificationMS: report.Showing.VerificationMS,
			AllocatedBytes: report.Resources.AllocatedBytes, Allocations: report.Resources.Allocations, PeakRSSBytes: peakRSS,
		},
		ConfiguredFSBits: configuredFS,
		ObservedFSBits:   [][4]int{report.Issuance.ObservedFSDigestBits, report.Showing.ObservedFSDigestBits},
		IssuanceWire:     issuanceWire, ShowingWire: showingWire,
		ReplayRejected: report.ReplayRejected, TamperRejected: report.TamperRejected,
		ArtifactHashesVerified: report.ArtifactHashesVerified, ArtifactSHA256: report.ArtifactSHA256,
		FullGameAccountingStatus: report.FullGameAccountingStatus, LedgerStatus: report.LedgerStatus,
		ParameterAuditStatus: report.ParameterAudit.Status,
	}, nil
}

func publicationBatchAcceptance(lock publicationCandidateLock, batch publicationBenchmarkBatch) publicationBenchmarkAcceptance {
	a := publicationBenchmarkAcceptance{
		ExactFivePresets: len(lock.Presets) == publicationPresetCount && len(batch.Presets) == publicationPresetCount,
		LockStoppingCertified: lock.Status == "analytic_complete_measurement_pending" && lock.Stopping.WinnerInterior && lock.Stopping.NearFrontierInterior &&
			lock.Stopping.ExactIntegerRoots && lock.Stopping.AdmissibleLowerBoundsApplied && len(lock.Stopping.UnresolvedBoundaries) == 0 &&
			lock.Stopping.SupportFloorsCertified && len(lock.EnvelopesSearched) >= 3 && lock.Stopping.StableExpandedEnvelopes >= 2 && lock.Stopping.BoundaryExpansionRule != "",
		CandidateManifests: true, ReplayRejected: true, TamperRejected: true, ArtifactHashesVerified: true,
		FSWidthsVerified: true, AggregateQueryPolicy: true, SourceBuildMachine: batch.SourceAndMachineSame,
		CanonicalSizes: true, Resources: true, FullGameAccounting: true, ProjectedWinnerMeasured: true,
		LiveManifestAdopted: true,
	}
	for _, result := range lock.Presets {
		if len(result.Finalists) != publicationFinalistCount || result.Winner.CandidateDigest != result.Finalists[0].CandidateDigest {
			a.CandidateManifests = false
		}
		for _, binding := range result.Finalists {
			if binding.ManifestStatus != "pinned_validated" {
				a.CandidateManifests = false
			}
		}
		live, ok := credential.LookupIntGenISISPublicationPreset(result.CanonicalID)
		if !ok || result.Winner.Issuance != live.Issuance || result.Winner.Showing != live.Showing || result.Winner.ManifestDigest != credential.IntGenISISPresetManifestDigest(live) {
			a.LiveManifestAdopted = false
		}
	}
	for _, run := range batch.Runs {
		if !run.ReplayRejected {
			a.ReplayRejected = false
		}
		if !run.TamperRejected {
			a.TamperRejected = false
		}
		if !run.ArtifactHashesVerified || len(run.ArtifactSHA256) != 15 {
			a.ArtifactHashesVerified = false
		}
		if run.ConfiguredFSBits <= 0 || len(run.ObservedFSBits) != 2 {
			a.FSWidthsVerified = false
		}
		for _, phase := range run.ObservedFSBits {
			for _, bits := range phase {
				if bits != run.ConfiguredFSBits {
					a.FSWidthsVerified = false
				}
			}
		}
		if run.Metrics.IssuanceProofBytes <= 0 || run.Metrics.ShowingProofBytes <= 0 || run.Metrics.PresentationBytes <= 0 || run.Metrics.CredentialStateBytes <= 0 {
			a.CanonicalSizes = false
		}
		if run.Metrics.PeakRSSBytes == 0 || run.Metrics.AllocatedBytes == 0 || run.Metrics.Allocations == 0 {
			a.Resources = false
		}
		if run.FullGameAccountingStatus != "aggregate_composed_game_v4" || run.ParameterAuditStatus != "pass" || run.LedgerStatus == "" {
			a.FullGameAccounting = false
		}
	}
	a.FinalistRunCounts = publicationBatchRunCountsValid(lock, batch)
	if !a.FinalistRunCounts {
		a.ProjectedWinnerMeasured = false
	}
	return a
}

func publicationBatchRunCountsValid(lock publicationCandidateLock, batch publicationBenchmarkBatch) bool {
	type key struct {
		name, stage        string
		rank, candidateRun int
	}
	counts := make(map[key]int, len(batch.Runs))
	for _, run := range batch.Runs {
		counts[key{run.CanonicalID, run.Stage, run.CandidateRank, run.CandidateRun}]++
	}
	for _, result := range lock.Presets {
		for rank := 1; rank <= publicationFinalistCount; rank++ {
			if counts[key{result.CanonicalID, "screening", rank, 1}] != 1 {
				return false
			}
		}
		for rank := 1; rank <= 3; rank++ {
			for candidateRun := 2; candidateRun <= 3; candidateRun++ {
				if counts[key{result.CanonicalID, "confirmation", rank, candidateRun}] != 1 {
					return false
				}
			}
		}
		for candidateRun := 1; candidateRun <= batch.RunsPerPreset; candidateRun++ {
			if counts[key{result.CanonicalID, "final", 1, candidateRun}] != 1 {
				return false
			}
		}
	}
	want := publicationPresetCount * (publicationFinalistCount + 2*3 + batch.RunsPerPreset)
	return len(batch.Runs) == want && len(batch.Schedule) == want
}

func publicationCriticalAcceptance(a publicationBenchmarkAcceptance) bool {
	return a.ExactFivePresets && a.LockStoppingCertified && a.FinalistRunCounts && a.CandidateManifests &&
		a.ReplayRejected && a.TamperRejected && a.ArtifactHashesVerified && a.FSWidthsVerified &&
		a.AggregateQueryPolicy && a.SourceBuildMachine && a.CanonicalSizes && a.Resources &&
		a.FullGameAccounting && a.ProjectedWinnerMeasured && a.LiveManifestAdopted
}

func aggregatePublicationRuns(runs []publicationBenchmarkRun, names []string) []publicationPresetAggregate {
	out := make([]publicationPresetAggregate, 0, len(names))
	for _, name := range names {
		var selected []publicationBenchmarkRun
		for _, run := range runs {
			if run.CanonicalID == name && run.Stage == "final" {
				selected = append(selected, run)
			}
		}
		if len(selected) == 0 {
			continue
		}
		values := func(pick func(publicationRunMetrics) float64) []float64 {
			v := make([]float64, len(selected))
			for i := range selected {
				v[i] = pick(selected[i].Metrics)
			}
			return v
		}
		first := selected[0]
		out = append(out, publicationPresetAggregate{
			CanonicalID: name, PublicationLabel: first.PublicationLabel, CandidateDigest: first.CandidateDigest, Runs: len(selected),
			CredentialStateBytes:   publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.CredentialStateBytes) })),
			IssuanceProofBytes:     publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.IssuanceProofBytes) })),
			ShowingProofBytes:      publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.ShowingProofBytes) })),
			IssuanceProofMaxBytes:  publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.IssuanceProofMaxBytes) })),
			ShowingProofMaxBytes:   publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.ShowingProofMaxBytes) })),
			PresentationBytes:      publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.PresentationBytes) })),
			PresentationMaxBytes:   publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.PresentationMaxBytes) })),
			IssuancePaperBytes:     publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.IssuancePaperBytes) })),
			ShowingPaperBytes:      publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.ShowingPaperBytes) })),
			IssuanceProvingMS:      publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return m.IssuanceProvingMS })),
			IssuanceVerificationMS: publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return m.IssuanceVerificationMS })),
			ShowingProvingMS:       publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return m.ShowingProvingMS })),
			ShowingVerificationMS:  publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return m.ShowingVerificationMS })),
			AllocatedBytes:         publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.AllocatedBytes) })),
			Allocations:            publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.Allocations) })),
			PeakRSSBytes:           publicationDistributionFor(values(func(m publicationRunMetrics) float64 { return float64(m.PeakRSSBytes) })),
		})
	}
	return out
}

func publicationDistributionFor(values []float64) publicationDistribution {
	if len(values) == 0 {
		return publicationDistribution{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	median := publicationMedian(sorted)
	deviations := make([]float64, len(sorted))
	for i, value := range sorted {
		deviations[i] = math.Abs(value - median)
	}
	sort.Float64s(deviations)
	return publicationDistribution{Median: median, MAD: publicationMedian(deviations), Min: sorted[0], Max: sorted[len(sorted)-1]}
}

func publicationMedian(sorted []float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func publicationDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func writePublicationJSONAtomic(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".publication-v4-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if _, err := tmp.Write(encoded); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	keep = true
	return nil
}
