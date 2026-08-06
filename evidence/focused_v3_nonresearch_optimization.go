package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/sourceintegrity"
	"vSIS-Signature/prf"
)

const (
	FocusedV3NonResearchOptimizationSchema  = "spruce.focused-v3-nonresearch-optimization"
	FocusedV3NonResearchOptimizationVersion = 2
	FocusedV3NonResearchOptimizationRuns    = 3

	focusedV3NonResearchPriorPath        = "evidence/focused-v3-transcript-reduction.json"
	focusedV3NonResearchIssuanceLayout   = "intgenisis_presign_source_only_ternary_carrier_v3"
	focusedV3NonResearchIssuanceRelation = "intgenisis_presign_full_ring_source_only_v3"
	focusedV3NonResearchShowingLayout    = "intgenisis_showing_input_trace_ternary_carrier_v3"
	focusedV3NonResearchTranscriptLive   = "smallwood_2025_1085_salted_tapes_v3_live"
	focusedV3NonResearchArtifactRoot     = "artifacts/smallwood-v3/nonresearch-optimization"
)

// FocusedV3NonResearchOptimizationBuildOptions identifies the immutable raw
// inputs for one evidence epoch. Paper is supplied by the caller so the CLI
// can bracket generation with two independent read-only paper-tree checks.
type FocusedV3NonResearchOptimizationBuildOptions struct {
	SPRUCE_DIR string
	MeasuredOn string
	Paper      FocusedV3PaperTreeEvidence
}

// FocusedV3NonResearchOptimizationEvidence binds the source-only issuance
// relation and the canonical proof-v5 wire changes to six raw production
// runs. It deliberately remains a per-proof SmallWood record: full credential
// game accounting is not inferred from these measurements.
type FocusedV3NonResearchOptimizationEvidence struct {
	Schema                   string                                  `json:"schema"`
	Version                  int                                     `json:"version"`
	MeasuredOn               string                                  `json:"measured_on"`
	ClaimScope               string                                  `json:"claim_scope"`
	ImplementationBaseCommit string                                  `json:"implementation_base_commit"`
	Environment              FocusedV3NonResearchEnvironment         `json:"environment"`
	PriorEvidence            FocusedV3TranscriptReductionPriorSource `json:"prior_v3_evidence"`
	Paper                    FocusedV3PaperTreeEvidence              `json:"paper_repository"`
	Targets                  []FocusedV3NonResearchTarget            `json:"targets"`
}

type FocusedV3NonResearchEnvironment struct {
	GoVersion           string `json:"go_version"`
	GOOS                string `json:"goos"`
	GOARCH              string `json:"goarch"`
	NumCPU              int    `json:"num_cpu"`
	GOMAXPROCS          int    `json:"gomaxprocs"`
	VCS                 string `json:"vcs"`
	Commit              string `json:"commit"`
	CommitTime          string `json:"commit_time"`
	Modified            bool   `json:"modified"`
	SourceTreeAlgorithm string `json:"source_tree_algorithm"`
	SourceTreeDigest    string `json:"source_tree_digest"`
	SourceTreeFileCount int    `json:"source_tree_file_count"`
}

type FocusedV3NonResearchTarget struct {
	CanonicalID      string                               `json:"canonical_id"`
	ManifestDigest   string                               `json:"manifest_digest"`
	Kappa            [4]int                               `json:"kappa"`
	PriorAccepted    FocusedV3NonResearchPrior            `json:"prior_accepted"`
	Frozen           FocusedV3NonResearchFrozen           `json:"frozen_parameters"`
	Protocol         FocusedV3NonResearchProtocolIdentity `json:"protocol_identity"`
	IssuanceGeometry FocusedV3NonResearchGeometry         `json:"issuance_geometry"`
	ShowingGeometry  FocusedV3NonResearchGeometry         `json:"showing_geometry"`
	Runs             []FocusedV3NonResearchRun            `json:"runs"`
	Medians          FocusedV3NonResearchMedian           `json:"medians"`
}

type FocusedV3NonResearchPrior struct {
	PersistentStateBytes   int     `json:"persistent_state_bytes"`
	IssuanceProofWireBytes int     `json:"issuance_proof_wire_bytes"`
	ShowingProofWireBytes  int     `json:"showing_proof_wire_bytes"`
	PresentationWireBytes  int     `json:"presentation_wire_bytes"`
	PaperIssuanceBytes     int     `json:"paper_issuance_bytes"`
	PaperShowingBytes      int     `json:"paper_showing_bytes"`
	IssuanceProvingMS      float64 `json:"median_issuance_proving_ms"`
	ShowingProvingMS       float64 `json:"median_showing_proving_ms"`
	PeakRSSBytes           uint64  `json:"median_peak_rss_bytes"`
}

type FocusedV3NonResearchFrozen struct {
	Issuance FocusedV3NonResearchTuning `json:"issuance"`
	Showing  FocusedV3NonResearchTuning `json:"showing"`
}

// FocusedV3NonResearchTuning includes every maintained knob that could trade
// work/security for size, plus the relation selectors. A new value requires a
// new evidence epoch rather than being normalized during validation.
type FocusedV3NonResearchTuning struct {
	NCols                  int        `json:"ncols"`
	LVCSNCols              int        `json:"lvcs_ncols"`
	NLeaves                int        `json:"nleaves"`
	Eta                    int        `json:"eta"`
	Theta                  int        `json:"theta"`
	Rho                    int        `json:"rho"`
	Ell                    int        `json:"ell"`
	EllPrime               int        `json:"ell_prime"`
	DQOverride             int        `json:"dq_override"`
	Kappa                  [4]int     `json:"kappa"`
	ROQueryCaps            [5]int     `json:"ro_query_caps"`
	ROQueryCapBits         [5]float64 `json:"ro_query_cap_bits"`
	DECSCollisionBits      int        `json:"decs_collision_bits"`
	DECSHashBits           int        `json:"decs_hash_bits"`
	DECSTapeBits           int        `json:"decs_tape_bits"`
	FSCollisionBits        int        `json:"fs_collision_bits"`
	SaltBits               int        `json:"salt_bits"`
	PRFProfile             string     `json:"prf_profile"`
	PRFCompanionMode       string     `json:"prf_companion_mode"`
	PRFGroupRounds         int        `json:"prf_group_rounds"`
	CheckpointSamples      int        `json:"checkpoint_samples"`
	SigShortnessRadix      int        `json:"sig_shortness_radix"`
	SigShortnessDigits     int        `json:"sig_shortness_digits"`
	CompressedRows         int        `json:"compressed_rows"`
	ReplayProjection       string     `json:"replay_projection"`
	TranscriptMode         string     `json:"transcript_mode"`
	TranscriptOmissionMode string     `json:"transcript_omission_mode"`
	FixedTranscriptSize    bool       `json:"fixed_transcript_size"`
	SoundnessGate          string     `json:"soundness_gate"`
	RelationVersion        int        `json:"relation_version"`
	LayoutVersion          int        `json:"layout_version"`
}

type FocusedV3NonResearchProtocolIdentity struct {
	ProofSchemaVersion            int    `json:"proof_schema_version"`
	CanonicalProofCodecVersion    int    `json:"canonical_proof_codec_version"`
	CanonicalProofCodecProfile    string `json:"canonical_proof_codec_profile"`
	CanonicalProofFieldEncoding   string `json:"canonical_proof_field_encoding"`
	CanonicalProofQKernelEncoding string `json:"canonical_proof_q_kernel_encoding"`
	CanonicalProofRadixQGroupSize int    `json:"canonical_proof_radix_q_group_elements"`
	CanonicalProofMerkleTopology  string `json:"canonical_proof_merkle_topology"`
	IssuanceLayoutVersion         string `json:"issuance_layout_version"`
	IssuanceRelationVersion       string `json:"issuance_relation_version"`
	ShowingLayoutVersion          string `json:"showing_layout_version"`
	ShowingInputTraceRelation     int    `json:"showing_input_trace_relation_version"`
}

type FocusedV3NonResearchGeometry struct {
	LogicalRows      int `json:"logical_rows"`
	Layers           int `json:"layers"`
	MaskRows         int `json:"mask_rows"`
	ReplayRows       int `json:"replay_rows"`
	PhysicalRows     int `json:"physical_rows"`
	Queries          int `json:"queries"`
	OpeningPColumns  int `json:"opening_p_columns"`
	ParallelDegree   int `json:"parallel_degree"`
	AggregatedDegree int `json:"aggregated_degree"`
	QDegree          int `json:"q_degree"`
}

type FocusedV3NonResearchArtifactProjection struct {
	StatePath           string `json:"state_path"`
	StateSHA256         string `json:"state_sha256"`
	SubmissionPath      string `json:"submission_path"`
	SubmissionSHA256    string `json:"submission_sha256"`
	IssuanceProofSHA256 string `json:"issuance_proof_sha256"`
	PresentationPath    string `json:"presentation_path"`
	PresentationSHA256  string `json:"presentation_sha256"`
	ShowingProofSHA256  string `json:"showing_proof_sha256"`
	// Files binds every artifact named by the production report. Report and
	// resource digests remain on the run itself, while the two proof digests
	// above bind the canonical proof byte strings nested in their containers.
	Files []FocusedV3NonResearchFileDigest `json:"files"`
}

type FocusedV3NonResearchFileDigest struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type FocusedV3NonResearchRun struct {
	Run                    int                                    `json:"run"`
	ArtifactDirectory      string                                 `json:"artifact_directory"`
	ReportPath             string                                 `json:"report_path"`
	ReportSHA256           string                                 `json:"report_sha256"`
	ResourcePath           string                                 `json:"resource_path"`
	ResourceSHA256         string                                 `json:"resource_sha256"`
	Artifacts              FocusedV3NonResearchArtifactProjection `json:"artifacts"`
	PersistentStateBytes   int                                    `json:"persistent_state_bytes"`
	IssuanceProofWireBytes int                                    `json:"issuance_proof_wire_bytes"`
	ShowingProofWireBytes  int                                    `json:"showing_proof_wire_bytes"`
	PresentationWireBytes  int                                    `json:"presentation_wire_bytes"`
	PaperIssuanceBytes     int                                    `json:"paper_issuance_bytes"`
	PaperShowingBytes      int                                    `json:"paper_showing_bytes"`
	IssuanceProvingMS      float64                                `json:"issuance_proving_ms"`
	ShowingProvingMS       float64                                `json:"showing_proving_ms"`
	IssuanceVerificationMS float64                                `json:"issuance_verification_ms"`
	ShowingVerificationMS  float64                                `json:"showing_verification_ms"`
	PeakRSSBytes           uint64                                 `json:"peak_rss_bytes"`
	IssuanceTheoremBits    float64                                `json:"issuance_theorem_bits"`
	ShowingTheoremBits     float64                                `json:"showing_theorem_bits"`
	ParameterAuditStatus   string                                 `json:"parameter_audit_status"`
	IssuanceZKEligible     bool                                   `json:"issuance_zero_knowledge_eligible"`
	ShowingZKEligible      bool                                   `json:"showing_zero_knowledge_eligible"`
	ReplayRejected         bool                                   `json:"replay_rejected"`
}

type FocusedV3NonResearchMedian struct {
	PersistentStateBytes   int     `json:"persistent_state_bytes"`
	IssuanceProofWireBytes int     `json:"issuance_proof_wire_bytes"`
	ShowingProofWireBytes  int     `json:"showing_proof_wire_bytes"`
	PresentationWireBytes  int     `json:"presentation_wire_bytes"`
	PaperIssuanceBytes     int     `json:"paper_issuance_bytes"`
	PaperShowingBytes      int     `json:"paper_showing_bytes"`
	IssuanceProvingMS      float64 `json:"issuance_proving_ms"`
	ShowingProvingMS       float64 `json:"showing_proving_ms"`
	PeakRSSBytes           uint64  `json:"peak_rss_bytes"`
}

// BuildFocusedV3NonResearchOptimizationEvidence projects the fixed BQ128 and
// WF128 three-run production bundles into a reviewable evidence record. It
// does not run a benchmark and never rewrites a raw artifact.
func BuildFocusedV3NonResearchOptimizationEvidence(opts FocusedV3NonResearchOptimizationBuildOptions) (FocusedV3NonResearchOptimizationEvidence, error) {
	root, err := ResolveSPRUCE_DIR(opts.SPRUCE_DIR)
	if err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, err
	}
	measuredOn := opts.MeasuredOn
	if measuredOn == "" {
		measuredOn = time.Now().UTC().Format("2006-01-02")
	}
	if _, err := time.Parse("2006-01-02", measuredOn); err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("focused-v3 non-research measured_on: %w", err)
	}
	if !validHexDigest(opts.Paper.HeadBefore, 40) || opts.Paper.HeadBefore != opts.Paper.HeadAfter || !opts.Paper.CleanBefore || !opts.Paper.CleanAfter {
		return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("focused-v3 non-research build requires an unchanged clean paper checkpoint")
	}

	priorPath, err := focusedV3NonResearchPath(root, focusedV3NonResearchPriorPath)
	if err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, err
	}
	priorData, _, err := readFocusedV3NonResearchRegularFile(priorPath)
	if err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("read prior focused-v3 evidence: %w", err)
	}
	prior, err := ReadFocusedV3TranscriptReductionEvidence(priorPath)
	if err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, err
	}
	if err := ValidateFocusedV3TranscriptReductionEvidence(prior); err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("validate prior focused-v3 evidence: %w", err)
	}

	e := FocusedV3NonResearchOptimizationEvidence{
		Schema: FocusedV3NonResearchOptimizationSchema, Version: FocusedV3NonResearchOptimizationVersion,
		MeasuredOn: measuredOn, ClaimScope: string(credential.ClaimProofOnly), Paper: opts.Paper,
		PriorEvidence: FocusedV3TranscriptReductionPriorSource{Path: focusedV3NonResearchPriorPath, SHA256: sha256Hex(priorData)},
	}
	var commonRawEnvironment *benchmarkEnvironmentWire
	for _, id := range focusedV3TargetPresetIDs {
		preset, ok := credential.LookupIntGenISISPreset(id)
		if !ok {
			return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("missing focused-v3 non-research preset %q", id)
		}
		priorAccepted, issuanceGeometry, showingGeometry, _, _, ok := focusedV3NonResearchExpectedTarget(id)
		if !ok {
			return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("missing focused-v3 non-research target definition %q", id)
		}
		priorTarget, ok := focusedV3NonResearchPriorTarget(prior, id)
		if !ok || !focusedV3NonResearchPriorMatches(priorTarget, priorAccepted) {
			return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("prior focused-v3 evidence projection mismatch for %s", id)
		}
		target := FocusedV3NonResearchTarget{
			CanonicalID: id, ManifestDigest: credential.IntGenISISPresetManifestDigest(preset), Kappa: preset.Issuance.Kappa,
			PriorAccepted: priorAccepted,
			Frozen: FocusedV3NonResearchFrozen{
				Issuance: focusedV3NonResearchTuning(preset.Issuance),
				Showing:  focusedV3NonResearchTuning(preset.Showing),
			},
			Protocol: focusedV3NonResearchProtocol(), IssuanceGeometry: issuanceGeometry, ShowingGeometry: showingGeometry,
		}
		alias, ok := focusedV3NonResearchTargetAlias(id)
		if !ok {
			return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("missing artifact alias for %s", id)
		}
		for runNumber := 1; runNumber <= FocusedV3NonResearchOptimizationRuns; runNumber++ {
			run, rawEnvironment, err := buildFocusedV3NonResearchRun(root, alias, runNumber, preset)
			if err != nil {
				return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("build %s run %d: %w", id, runNumber, err)
			}
			if commonRawEnvironment == nil {
				copyEnvironment := rawEnvironment
				commonRawEnvironment = &copyEnvironment
			} else if !reflect.DeepEqual(*commonRawEnvironment, rawEnvironment) {
				return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("benchmark environment differs in %s run %d", id, runNumber)
			}
			target.Runs = append(target.Runs, run)
		}
		target.Medians = focusedV3NonResearchMedians(target.Runs)
		e.Targets = append(e.Targets, target)
	}
	if commonRawEnvironment == nil {
		return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("no focused-v3 non-research raw reports")
	}
	e.Environment, err = focusedV3NonResearchImplementationEnvironment(root, *commonRawEnvironment)
	if err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, err
	}
	e.ImplementationBaseCommit = e.Environment.Commit
	if err := ValidateFocusedV3NonResearchOptimizationArtifacts(e, root); err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("validate generated focused-v3 non-research evidence: %w", err)
	}
	return e, nil
}

// MarshalFocusedV3NonResearchOptimizationEvidence returns the canonical
// human-reviewable encoding used by the evidence epoch.
func MarshalFocusedV3NonResearchOptimizationEvidence(e FocusedV3NonResearchOptimizationEvidence) ([]byte, error) {
	if err := ValidateFocusedV3NonResearchOptimizationEvidence(e); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode focused-v3 non-research evidence: %w", err)
	}
	return append(encoded, '\n'), nil
}

// WriteFocusedV3NonResearchOptimizationEvidence atomically installs a
// canonical evidence file without mutating any raw run artifact.
func WriteFocusedV3NonResearchOptimizationEvidence(path string, e FocusedV3NonResearchOptimizationEvidence) error {
	encoded, err := MarshalFocusedV3NonResearchOptimizationEvidence(e)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, encoded, 0o644)
}

// CaptureFocusedV3GitTreeState is a read-only git checkpoint used to prove
// that evidence generation did not alter the adjacent paper repository.
func CaptureFocusedV3GitTreeState(dir string) (head string, clean bool, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", false, err
	}
	head, err = focusedV3NonResearchGitOutput(abs, "rev-parse", "HEAD")
	if err != nil {
		return "", false, fmt.Errorf("read git HEAD for %s: %w", abs, err)
	}
	status, err := focusedV3NonResearchGitOutput(abs, "status", "--porcelain=v1", "--untracked-files=normal")
	if err != nil {
		return "", false, fmt.Errorf("read git status for %s: %w", abs, err)
	}
	return strings.TrimSpace(head), strings.TrimSpace(status) == "", nil
}

func buildFocusedV3NonResearchRun(root, alias string, runNumber int, preset credential.IntGenISISPreset) (FocusedV3NonResearchRun, benchmarkEnvironmentWire, error) {
	runDir := filepath.ToSlash(filepath.Join(focusedV3NonResearchArtifactRoot, alias, fmt.Sprintf("run-%d", runNumber)))
	reportRel, resourceRel := runDir+"/report.json", runDir+"/resource.txt"
	reportPath, err := focusedV3NonResearchPath(root, reportRel)
	if err != nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, err
	}
	resourcePath, err := focusedV3NonResearchPath(root, resourceRel)
	if err != nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, err
	}
	reportData, _, err := readFocusedV3NonResearchRegularFile(reportPath)
	if err != nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, err
	}
	if err := requireBenchmarkReportVersionV2(reportData); err != nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, err
	}
	var raw focusedV3NonResearchRawReport
	if err := json.Unmarshal(reportData, &raw); err != nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, fmt.Errorf("decode report: %w", err)
	}
	resourceData, _, err := readFocusedV3NonResearchRegularFile(resourcePath)
	if err != nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, err
	}
	rss, err := focusedV3TranscriptResourceRSS(resourcePath)
	if err != nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, err
	}
	if raw.CanonicalSizes == nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, fmt.Errorf("report has no canonical_sizes")
	}
	if raw.ArtifactDir != runDir {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, fmt.Errorf("report artifact_dir=%q want=%q", raw.ArtifactDir, runDir)
	}
	artifacts, err := buildFocusedV3NonResearchArtifactProjection(root, runDir, preset, raw.Artifacts, *raw.CanonicalSizes)
	if err != nil {
		return FocusedV3NonResearchRun{}, benchmarkEnvironmentWire{}, err
	}
	s := *raw.CanonicalSizes
	run := FocusedV3NonResearchRun{
		Run: runNumber, ArtifactDirectory: runDir,
		ReportPath: reportRel, ReportSHA256: sha256Hex(reportData), ResourcePath: resourceRel, ResourceSHA256: sha256Hex(resourceData), Artifacts: artifacts,
		PersistentStateBytes: s.PersistentStateBytes, IssuanceProofWireBytes: s.IssuanceProofWireBytes, ShowingProofWireBytes: s.ShowingProofWireBytes, PresentationWireBytes: s.PresentationWireBytes,
		PaperIssuanceBytes: s.PaperIssuanceBytes, PaperShowingBytes: s.PaperShowingBytes,
		IssuanceProvingMS: raw.Issuance.ProvingMS, ShowingProvingMS: raw.Showing.ProvingMS, IssuanceVerificationMS: raw.Issuance.VerificationMS, ShowingVerificationMS: raw.Showing.VerificationMS,
		PeakRSSBytes: rss, IssuanceTheoremBits: raw.Issuance.TheoremTotalBits, ShowingTheoremBits: raw.Showing.TheoremTotalBits,
		ParameterAuditStatus: raw.ParameterAudit.Status, IssuanceZKEligible: raw.Issuance.ZeroKnowledgeEligible, ShowingZKEligible: raw.Showing.ZeroKnowledgeEligible, ReplayRejected: raw.ReplayRejected,
	}
	return run, raw.Environment, nil
}

func focusedV3NonResearchMedians(runs []FocusedV3NonResearchRun) FocusedV3NonResearchMedian {
	states, issueWires, showWires, presentations := make([]int, 0, len(runs)), make([]int, 0, len(runs)), make([]int, 0, len(runs)), make([]int, 0, len(runs))
	issuePapers, showPapers := make([]int, 0, len(runs)), make([]int, 0, len(runs))
	issueMS, showMS := make([]float64, 0, len(runs)), make([]float64, 0, len(runs))
	rss := make([]uint64, 0, len(runs))
	for _, run := range runs {
		states = append(states, run.PersistentStateBytes)
		issueWires = append(issueWires, run.IssuanceProofWireBytes)
		showWires = append(showWires, run.ShowingProofWireBytes)
		presentations = append(presentations, run.PresentationWireBytes)
		issuePapers = append(issuePapers, run.PaperIssuanceBytes)
		showPapers = append(showPapers, run.PaperShowingBytes)
		issueMS = append(issueMS, run.IssuanceProvingMS)
		showMS = append(showMS, run.ShowingProvingMS)
		rss = append(rss, run.PeakRSSBytes)
	}
	return FocusedV3NonResearchMedian{
		PersistentStateBytes: medianInt(states), IssuanceProofWireBytes: medianInt(issueWires), ShowingProofWireBytes: medianInt(showWires), PresentationWireBytes: medianInt(presentations),
		PaperIssuanceBytes: medianInt(issuePapers), PaperShowingBytes: medianInt(showPapers), IssuanceProvingMS: medianFloat(issueMS), ShowingProvingMS: medianFloat(showMS), PeakRSSBytes: medianUint64(rss),
	}
}

type focusedV3NonResearchArtifactPath struct {
	role string
	path string
}

func buildFocusedV3NonResearchArtifactProjection(root, runDir string, preset credential.IntGenISISPreset, reported benchmarkArtifactsWire, sizes focusedV3NonResearchRawSizes) (FocusedV3NonResearchArtifactProjection, error) {
	want := focusedV3NonResearchArtifactPaths(runDir)
	got := focusedV3NonResearchReportedArtifactPaths(reported)
	if !reflect.DeepEqual(got, want) {
		return FocusedV3NonResearchArtifactProjection{}, fmt.Errorf("report artifact paths differ from the fixed production bundle")
	}
	projection := FocusedV3NonResearchArtifactProjection{}
	dataByRole := make(map[string][]byte, len(want))
	for _, item := range want {
		abs, err := focusedV3NonResearchPath(root, item.path)
		if err != nil {
			return FocusedV3NonResearchArtifactProjection{}, err
		}
		data, info, err := readFocusedV3NonResearchRegularFile(abs)
		if err != nil {
			return FocusedV3NonResearchArtifactProjection{}, fmt.Errorf("read %s artifact: %w", item.role, err)
		}
		dataByRole[item.role] = data
		projection.Files = append(projection.Files, FocusedV3NonResearchFileDigest{Role: item.role, Path: item.path, Bytes: info.Size(), SHA256: sha256Hex(data)})
	}
	state := dataByRole["state"]
	submission := dataByRole["presign_submission"]
	presentation := dataByRole["presentation"]
	var submissionEnvelope struct {
		Version        int    `json:"version"`
		CanonicalProof []byte `json:"canonical_proof"`
	}
	if err := json.Unmarshal(submission, &submissionEnvelope); err != nil {
		return FocusedV3NonResearchArtifactProjection{}, fmt.Errorf("decode presign submission: %w", err)
	}
	tagCount, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok {
		return FocusedV3NonResearchArtifactProjection{}, fmt.Errorf("unknown target PRF profile %q", preset.PRFProfile)
	}
	proofOffset := 8 + (tagCount*20+7)/8
	if proofOffset > len(presentation) {
		return FocusedV3NonResearchArtifactProjection{}, fmt.Errorf("presentation is shorter than its fixed envelope")
	}
	showProof := presentation[proofOffset:]
	if len(state) != sizes.PersistentStateBytes || len(submissionEnvelope.CanonicalProof) != sizes.IssuanceProofWireBytes || len(showProof) != sizes.ShowingProofWireBytes || len(presentation) != sizes.PresentationWireBytes {
		return FocusedV3NonResearchArtifactProjection{}, fmt.Errorf("canonical artifact lengths differ from the report")
	}
	projection.StatePath, projection.StateSHA256 = reported.State, sha256Hex(state)
	projection.SubmissionPath, projection.SubmissionSHA256, projection.IssuanceProofSHA256 = reported.Submission, sha256Hex(submission), sha256Hex(submissionEnvelope.CanonicalProof)
	projection.PresentationPath, projection.PresentationSHA256, projection.ShowingProofSHA256 = reported.Presentation, sha256Hex(presentation), sha256Hex(showProof)
	return projection, nil
}

func focusedV3NonResearchArtifactPaths(runDir string) []focusedV3NonResearchArtifactPath {
	return []focusedV3NonResearchArtifactPath{
		{role: "public_params", path: runDir + "/credential_public.intgenisis_profile_c.json"},
		{role: "b_matrix", path: runDir + "/Bmatrix.intgenisis_profile_c.json"},
		{role: "holder_secret", path: runDir + "/holder_secret.json"},
		{role: "commit_request", path: runDir + "/commit_request.json"},
		{role: "presign_submission", path: runDir + "/presign_submission.json"},
		{role: "issue_response", path: runDir + "/issue_response.json"},
		{role: "state", path: runDir + "/credential_state.intgenisis.v8"},
		{role: "verifier_key", path: runDir + "/intgenisis_verifier_key.json"},
		{role: "presentation", path: runDir + "/presentation.intgenisis.v3"},
		{role: "holder_usage_state", path: runDir + "/holder_usage_state.json"},
		{role: "verifier_state", path: runDir + "/verifier_state.json"},
		{role: "ntru_params", path: runDir + "/ntru_params.json"},
		{role: "ntru_public", path: runDir + "/ntru_public.json"},
		{role: "ntru_private", path: runDir + "/ntru_private.json"},
		{role: "ntru_signature", path: runDir + "/ntru_signature.json"},
	}
}

func focusedV3NonResearchReportedArtifactPaths(reported benchmarkArtifactsWire) []focusedV3NonResearchArtifactPath {
	return []focusedV3NonResearchArtifactPath{
		{role: "public_params", path: reported.PublicParams}, {role: "b_matrix", path: reported.BMatrix}, {role: "holder_secret", path: reported.HolderSecret},
		{role: "commit_request", path: reported.CommitRequest}, {role: "presign_submission", path: reported.Submission}, {role: "issue_response", path: reported.Response},
		{role: "state", path: reported.State}, {role: "verifier_key", path: reported.VerifierKey}, {role: "presentation", path: reported.Presentation},
		{role: "holder_usage_state", path: reported.HolderUsageState}, {role: "verifier_state", path: reported.VerifierState}, {role: "ntru_params", path: reported.NTRUParams},
		{role: "ntru_public", path: reported.NTRUPublic}, {role: "ntru_private", path: reported.NTRUPrivate}, {role: "ntru_signature", path: reported.NTRUSignature},
	}
}

func focusedV3NonResearchTargetAlias(id string) (string, bool) {
	switch id {
	case credential.IntGenISISPresetPoCN1024BQ128R128V3:
		return "bq128", true
	case credential.IntGenISISPresetSystemN1024WF128CROMV2:
		return "wf128", true
	default:
		return "", false
	}
}

func focusedV3NonResearchImplementationEnvironment(root string, raw benchmarkEnvironmentWire) (FocusedV3NonResearchEnvironment, error) {
	if raw.GoVersion == "" || raw.GOOS == "" || raw.GOARCH == "" || raw.NumCPU <= 0 || raw.GOMAXPROCS <= 0 ||
		raw.SourceTreeAlgorithm == "" || !validHexDigest(raw.SourceTreeDigest, 64) || raw.SourceTreeFileCount <= 0 {
		return FocusedV3NonResearchEnvironment{}, fmt.Errorf("raw benchmark environment is incomplete")
	}
	source, err := sourceintegrity.Compute(root)
	if err != nil {
		return FocusedV3NonResearchEnvironment{}, fmt.Errorf("compute current implementation source snapshot: %w", err)
	}
	if raw.SourceTreeAlgorithm != source.Algorithm || raw.SourceTreeDigest != source.Digest || raw.SourceTreeFileCount != source.FileCount {
		return FocusedV3NonResearchEnvironment{}, fmt.Errorf("raw benchmark source snapshot differs from the current implementation")
	}
	head, clean, err := CaptureFocusedV3GitTreeState(root)
	if err != nil {
		return FocusedV3NonResearchEnvironment{}, err
	}
	commitTimeText, err := focusedV3NonResearchGitOutput(root, "show", "-s", "--format=%cI", "HEAD")
	if err != nil {
		return FocusedV3NonResearchEnvironment{}, fmt.Errorf("read implementation commit time: %w", err)
	}
	commitTime, err := time.Parse(time.RFC3339, strings.TrimSpace(commitTimeText))
	if err != nil {
		return FocusedV3NonResearchEnvironment{}, fmt.Errorf("parse implementation commit time: %w", err)
	}
	// runtime.Version is checked as a guard against projecting a report made by
	// a different Go runtime through a newly built generator.
	if raw.GoVersion != runtime.Version() || raw.GOOS != runtime.GOOS || raw.GOARCH != runtime.GOARCH || raw.NumCPU != runtime.NumCPU() || raw.GOMAXPROCS != runtime.GOMAXPROCS(0) {
		return FocusedV3NonResearchEnvironment{}, fmt.Errorf("raw benchmark runtime differs from the evidence-generator runtime")
	}
	return FocusedV3NonResearchEnvironment{
		GoVersion: raw.GoVersion, GOOS: raw.GOOS, GOARCH: raw.GOARCH, NumCPU: raw.NumCPU, GOMAXPROCS: raw.GOMAXPROCS,
		VCS: "git", Commit: head, CommitTime: commitTime.UTC().Format(time.RFC3339), Modified: !clean,
		SourceTreeAlgorithm: source.Algorithm, SourceTreeDigest: source.Digest, SourceTreeFileCount: source.FileCount,
	}, nil
}

func focusedV3NonResearchGitOutput(dir string, args ...string) (string, error) {
	commandArgs := append([]string{"-C", dir}, args...)
	output, err := exec.Command("git", commandArgs...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func readFocusedV3NonResearchRegularFile(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) != info.Size() {
		return nil, nil, fmt.Errorf("%s changed while being read", path)
	}
	return data, info, nil
}

func ReadFocusedV3NonResearchOptimizationEvidence(path string) (FocusedV3NonResearchOptimizationEvidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, err
	}
	var out FocusedV3NonResearchOptimizationEvidence
	if err := decodeStrictJSON(data, &out); err != nil {
		return FocusedV3NonResearchOptimizationEvidence{}, fmt.Errorf("decode focused-v3 non-research evidence: %w", err)
	}
	return out, nil
}

func focusedV3NonResearchProtocol() FocusedV3NonResearchProtocolIdentity {
	return FocusedV3NonResearchProtocolIdentity{
		ProofSchemaVersion:            PIOP.ProofSchemaVersionV3,
		CanonicalProofCodecVersion:    PIOP.CanonicalProofCodecVersionV5,
		CanonicalProofCodecProfile:    PIOP.CanonicalProofCodecProfileV5,
		CanonicalProofFieldEncoding:   PIOP.CanonicalProofFieldEncodingV5,
		CanonicalProofQKernelEncoding: PIOP.CanonicalProofQKernelEncodingV5,
		CanonicalProofRadixQGroupSize: PIOP.CanonicalProofRadixQGroupElementsV5,
		CanonicalProofMerkleTopology:  decs.MerkleTopologyExactNV3,
		IssuanceLayoutVersion:         focusedV3NonResearchIssuanceLayout,
		IssuanceRelationVersion:       focusedV3NonResearchIssuanceRelation,
		ShowingLayoutVersion:          focusedV3NonResearchShowingLayout,
		ShowingInputTraceRelation:     int(prf.InputTraceRelationVersionV3),
	}
}

func focusedV3NonResearchTuning(t credential.IntGenISISTuningPreset) FocusedV3NonResearchTuning {
	return FocusedV3NonResearchTuning{
		NCols: t.NCols, LVCSNCols: t.LVCSNCols, NLeaves: t.NLeaves, Eta: t.Eta, Theta: t.Theta, Rho: t.Rho, Ell: t.Ell, EllPrime: t.EllPrime, DQOverride: 0,
		Kappa: t.Kappa, ROQueryCaps: t.ROQueryCaps, ROQueryCapBits: t.ROQueryCapBits,
		DECSCollisionBits: t.DECSCollisionBits, DECSHashBits: t.DECSHashBits, DECSTapeBits: t.DECSTapeBits, FSCollisionBits: t.FSCollisionBits, SaltBits: t.SaltBits,
		PRFProfile: t.PRFProfile, PRFCompanionMode: string(t.PRFCompanionMode), PRFGroupRounds: t.PRFGroupRounds, CheckpointSamples: t.CheckpointSamples,
		SigShortnessRadix: t.SigShortnessRadix, SigShortnessDigits: t.SigShortnessDigits, CompressedRows: t.CompressedRows, ReplayProjection: t.ReplayProjection,
		TranscriptMode: t.TranscriptMode, TranscriptOmissionMode: t.TranscriptOmissionMode, FixedTranscriptSize: t.FixedTranscriptSize,
		SoundnessGate: t.SoundnessGate, RelationVersion: t.RelationVersion, LayoutVersion: t.LayoutVersion,
	}
}

func focusedV3NonResearchExpectedTarget(id string) (FocusedV3NonResearchPrior, FocusedV3NonResearchGeometry, FocusedV3NonResearchGeometry, int, int, bool) {
	switch id {
	case credential.IntGenISISPresetPoCN1024BQ128R128V3:
		return FocusedV3NonResearchPrior{
				PersistentStateBytes: 4926, IssuanceProofWireBytes: 60426, ShowingProofWireBytes: 87091, PresentationWireBytes: 87124,
				PaperIssuanceBytes: 65091, PaperShowingBytes: 91756, IssuanceProvingMS: 1646.125, ShowingProvingMS: 3261.918, PeakRSSBytes: 547487744,
			}, FocusedV3NonResearchGeometry{
				LogicalRows: 49, Layers: 2, MaskRows: 156, ReplayRows: 90, PhysicalRows: 246, Queries: 39, OpeningPColumns: 207,
				ParallelDegree: 9, AggregatedDegree: 8, QDegree: 472,
			}, FocusedV3NonResearchGeometry{
				LogicalRows: 487, Layers: 12, MaskRows: 156, ReplayRows: 540, PhysicalRows: 696, Queries: 169, OpeningPColumns: 527,
				ParallelDegree: 9, AggregatedDegree: 8, QDegree: 472,
			}, 57271, 91756, true
	case credential.IntGenISISPresetSystemN1024WF128CROMV2:
		return FocusedV3NonResearchPrior{
				PersistentStateBytes: 4894, IssuanceProofWireBytes: 25935, ShowingProofWireBytes: 38199, PresentationWireBytes: 38240,
				PaperIssuanceBytes: 27575, PaperShowingBytes: 39837, IssuanceProvingMS: 573.129, ShowingProvingMS: 1470.093, PeakRSSBytes: 299810816,
			}, FocusedV3NonResearchGeometry{
				LogicalRows: 49, Layers: 2, MaskRows: 77, ReplayRows: 78, PhysicalRows: 155, Queries: 21, OpeningPColumns: 134,
				ParallelDegree: 9, AggregatedDegree: 8, QDegree: 391,
			}, FocusedV3NonResearchGeometry{
				LogicalRows: 423, Layers: 11, MaskRows: 91, ReplayRows: 429, PhysicalRows: 520, Queries: 84, OpeningPColumns: 436,
				ParallelDegree: 11, AggregatedDegree: 8, QDegree: 471,
			}, 23790, 39837, true
	default:
		return FocusedV3NonResearchPrior{}, FocusedV3NonResearchGeometry{}, FocusedV3NonResearchGeometry{}, 0, 0, false
	}
}

func ValidateFocusedV3NonResearchOptimizationEvidence(e FocusedV3NonResearchOptimizationEvidence) error {
	if e.Schema != FocusedV3NonResearchOptimizationSchema || e.Version != FocusedV3NonResearchOptimizationVersion {
		return fmt.Errorf("focused-v3 non-research evidence identity=(%q,v%d)", e.Schema, e.Version)
	}
	if e.ClaimScope != string(credential.ClaimProofOnly) {
		return fmt.Errorf("focused-v3 non-research claim scope=%q", e.ClaimScope)
	}
	if _, err := time.Parse("2006-01-02", e.MeasuredOn); err != nil {
		return fmt.Errorf("focused-v3 non-research measured_on: %w", err)
	}
	if !validHexDigest(e.ImplementationBaseCommit, 40) || e.Environment.GoVersion == "" || e.Environment.GOOS == "" || e.Environment.GOARCH == "" || e.Environment.NumCPU <= 0 || e.Environment.GOMAXPROCS <= 0 ||
		e.Environment.VCS != "git" || e.Environment.Commit != e.ImplementationBaseCommit || e.Environment.SourceTreeAlgorithm != sourceintegrity.Algorithm ||
		!validHexDigest(e.Environment.SourceTreeDigest, 64) || e.Environment.SourceTreeFileCount <= 0 {
		return fmt.Errorf("focused-v3 non-research implementation/environment boundary is incomplete")
	}
	if _, err := time.Parse(time.RFC3339, e.Environment.CommitTime); err != nil {
		return fmt.Errorf("focused-v3 non-research environment commit_time: %w", err)
	}
	if e.PriorEvidence.Path != focusedV3NonResearchPriorPath || !validHexDigest(e.PriorEvidence.SHA256, 64) {
		return fmt.Errorf("focused-v3 non-research prior evidence binding is invalid")
	}
	if !validHexDigest(e.Paper.HeadBefore, 40) || e.Paper.HeadBefore != e.Paper.HeadAfter || !e.Paper.CleanBefore || !e.Paper.CleanAfter {
		return fmt.Errorf("focused-v3 non-research paper boundary is incomplete")
	}
	if len(e.Targets) != len(focusedV3TargetPresetIDs) {
		return fmt.Errorf("focused-v3 non-research targets=%d want=%d", len(e.Targets), len(focusedV3TargetPresetIDs))
	}
	seen := make(map[string]bool, len(e.Targets))
	for _, target := range e.Targets {
		preset, ok := credential.LookupIntGenISISPreset(target.CanonicalID)
		if !ok || !isFocusedV3TargetPresetID(target.CanonicalID) || seen[target.CanonicalID] {
			return fmt.Errorf("invalid or duplicate focused-v3 non-research target %q", target.CanonicalID)
		}
		seen[target.CanonicalID] = true
		if err := ValidateFocusedV3TargetPreset(preset); err != nil {
			return err
		}
		// Version 2 is an immutable codec-v5 evidence epoch. Reconstruct its
		// target manifest rather than comparing it to an evolved live preset:
		// BQ128 moved from R7/L5 to R11/L4 in the subsequent codec-v6 epoch.
		epochPreset := preset
		if target.CanonicalID == credential.IntGenISISPresetPoCN1024BQ128R128V3 {
			epochPreset.Showing.SigShortnessRadix = 7
			epochPreset.Showing.SigShortnessDigits = 5
		}
		wantEpochManifest := credential.IntGenISISPresetManifestDigest(epochPreset)
		if target.CanonicalID == credential.IntGenISISPresetPoCN1024BQ128R128V3 {
			// This digest is fixed by the six checked codec-v5 raw reports. It
			// intentionally does not follow later non-tuning manifest metadata.
			wantEpochManifest = "f08dc90c5e319dfd667a4b960050aa2f0932eb2353a528c280299354452d3a08"
		}
		if target.ManifestDigest != wantEpochManifest || target.Kappa != epochPreset.Issuance.Kappa || target.Kappa != epochPreset.Showing.Kappa {
			return fmt.Errorf("focused-v3 non-research target %s does not bind its codec-v5 epoch manifest/kappa: manifest=%s/%s kappa=%v/%v/%v", target.CanonicalID, target.ManifestDigest, wantEpochManifest, target.Kappa, epochPreset.Issuance.Kappa, epochPreset.Showing.Kappa)
		}
		prior, issuanceGeometry, showingGeometry, issuePaper, showPaper, ok := focusedV3NonResearchExpectedTarget(target.CanonicalID)
		if !ok || target.PriorAccepted != prior || target.IssuanceGeometry != issuanceGeometry || target.ShowingGeometry != showingGeometry || target.Protocol != focusedV3NonResearchProtocol() {
			return fmt.Errorf("focused-v3 non-research target %s identity/geometry mismatch", target.CanonicalID)
		}
		wantFrozen := FocusedV3NonResearchFrozen{Issuance: focusedV3NonResearchTuning(epochPreset.Issuance), Showing: focusedV3NonResearchTuning(epochPreset.Showing)}
		if !reflect.DeepEqual(target.Frozen, wantFrozen) {
			return fmt.Errorf("focused-v3 non-research target %s changed a frozen knob", target.CanonicalID)
		}
		if err := validateFocusedV3NonResearchRuns(target, preset.CoreBitsRequired, issuePaper, showPaper); err != nil {
			return err
		}
	}
	for _, id := range focusedV3TargetPresetIDs {
		if !seen[id] {
			return fmt.Errorf("focused-v3 non-research evidence missing %s", id)
		}
	}
	return nil
}

func validateFocusedV3NonResearchRuns(target FocusedV3NonResearchTarget, targetBits float64, issuePaper, showPaper int) error {
	if len(target.Runs) != FocusedV3NonResearchOptimizationRuns {
		return fmt.Errorf("focused-v3 non-research target %s runs=%d want=%d", target.CanonicalID, len(target.Runs), FocusedV3NonResearchOptimizationRuns)
	}
	runs := append([]FocusedV3NonResearchRun(nil), target.Runs...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].Run < runs[j].Run })
	states, issueWires, showWires, presentations := make([]int, 0, 3), make([]int, 0, 3), make([]int, 0, 3), make([]int, 0, 3)
	issuePapers, showPapers := make([]int, 0, 3), make([]int, 0, 3)
	issueMS, showMS := make([]float64, 0, 3), make([]float64, 0, 3)
	rss := make([]uint64, 0, 3)
	alias, ok := focusedV3NonResearchTargetAlias(target.CanonicalID)
	if !ok {
		return fmt.Errorf("focused-v3 non-research target %s has no artifact alias", target.CanonicalID)
	}
	for i, run := range runs {
		wantDir := filepath.ToSlash(filepath.Join(focusedV3NonResearchArtifactRoot, alias, fmt.Sprintf("run-%d", i+1)))
		if run.Run != i+1 || run.ArtifactDirectory == "" || run.ReportPath == "" || run.ResourcePath == "" ||
			!validHexDigest(run.ReportSHA256, 64) || !validHexDigest(run.ResourceSHA256, 64) ||
			!validFocusedV3NonResearchArtifactProjection(run.Artifacts, wantDir) {
			return fmt.Errorf("focused-v3 non-research target %s run %d identity is invalid", target.CanonicalID, run.Run)
		}
		if run.ArtifactDirectory != wantDir || run.ReportPath != wantDir+"/report.json" || run.ResourcePath != wantDir+"/resource.txt" {
			return fmt.Errorf("focused-v3 non-research target %s run %d does not use the fixed artifact path", target.CanonicalID, run.Run)
		}
		if run.PersistentStateBytes <= 0 || run.PersistentStateBytes > FocusedV3StateByteLimit || run.IssuanceProofWireBytes <= 0 || run.ShowingProofWireBytes <= 0 ||
			run.PresentationWireBytes <= run.ShowingProofWireBytes || run.PaperIssuanceBytes != issuePaper || run.PaperShowingBytes != showPaper ||
			!finitePositive(run.IssuanceProvingMS) || !finitePositive(run.ShowingProvingMS) || !finitePositive(run.IssuanceVerificationMS) || !finitePositive(run.ShowingVerificationMS) || run.PeakRSSBytes == 0 ||
			run.IssuanceTheoremBits < targetBits || run.ShowingTheoremBits < targetBits || run.ParameterAuditStatus != "pass" || !run.IssuanceZKEligible || !run.ShowingZKEligible || !run.ReplayRejected {
			return fmt.Errorf("focused-v3 non-research target %s run %d failed measurement/security gates", target.CanonicalID, run.Run)
		}
		if run.IssuanceProvingMS > 2*target.PriorAccepted.IssuanceProvingMS || run.ShowingProvingMS > 2*target.PriorAccepted.ShowingProvingMS || run.PeakRSSBytes > 2*target.PriorAccepted.PeakRSSBytes {
			return fmt.Errorf("focused-v3 non-research target %s run %d exceeds the per-run 2x prior-accepted resource gate", target.CanonicalID, run.Run)
		}
		states = append(states, run.PersistentStateBytes)
		issueWires = append(issueWires, run.IssuanceProofWireBytes)
		showWires = append(showWires, run.ShowingProofWireBytes)
		presentations = append(presentations, run.PresentationWireBytes)
		issuePapers = append(issuePapers, run.PaperIssuanceBytes)
		showPapers = append(showPapers, run.PaperShowingBytes)
		issueMS = append(issueMS, run.IssuanceProvingMS)
		showMS = append(showMS, run.ShowingProvingMS)
		rss = append(rss, run.PeakRSSBytes)
	}
	wantMedian := FocusedV3NonResearchMedian{
		PersistentStateBytes: medianInt(states), IssuanceProofWireBytes: medianInt(issueWires), ShowingProofWireBytes: medianInt(showWires), PresentationWireBytes: medianInt(presentations),
		PaperIssuanceBytes: medianInt(issuePapers), PaperShowingBytes: medianInt(showPapers), IssuanceProvingMS: medianFloat(issueMS), ShowingProvingMS: medianFloat(showMS), PeakRSSBytes: medianUint64(rss),
	}
	if !reflect.DeepEqual(target.Medians, wantMedian) {
		return fmt.Errorf("focused-v3 non-research target %s median record is inconsistent", target.CanonicalID)
	}
	prior, after := target.PriorAccepted, target.Medians
	if after.PersistentStateBytes > prior.PersistentStateBytes || after.IssuanceProofWireBytes >= prior.IssuanceProofWireBytes || after.ShowingProofWireBytes >= prior.ShowingProofWireBytes ||
		after.PresentationWireBytes >= prior.PresentationWireBytes || after.PaperIssuanceBytes >= prior.PaperIssuanceBytes || after.PaperShowingBytes > prior.PaperShowingBytes {
		return fmt.Errorf("focused-v3 non-research target %s did not improve wire/issuance paper sizes without state or showing-paper growth", target.CanonicalID)
	}
	if after.IssuanceProvingMS > 2*prior.IssuanceProvingMS || after.ShowingProvingMS > 2*prior.ShowingProvingMS || after.PeakRSSBytes > 2*prior.PeakRSSBytes {
		return fmt.Errorf("focused-v3 non-research target %s exceeds the 2x prior-accepted median resource gate", target.CanonicalID)
	}
	return nil
}

func validFocusedV3NonResearchArtifactProjection(a FocusedV3NonResearchArtifactProjection, runDir string) bool {
	if a.StatePath == "" || a.SubmissionPath == "" || a.PresentationPath == "" ||
		!validHexDigest(a.StateSHA256, 64) || !validHexDigest(a.SubmissionSHA256, 64) || !validHexDigest(a.IssuanceProofSHA256, 64) ||
		!validHexDigest(a.PresentationSHA256, 64) || !validHexDigest(a.ShowingProofSHA256, 64) {
		return false
	}
	want := focusedV3NonResearchArtifactPaths(runDir)
	if len(a.Files) != len(want) {
		return false
	}
	var state, submission, presentation *FocusedV3NonResearchFileDigest
	for i, file := range a.Files {
		if file.Role != want[i].role || file.Path != want[i].path || file.Bytes <= 0 || !validHexDigest(file.SHA256, 64) {
			return false
		}
		switch file.Role {
		case "state":
			state = &a.Files[i]
		case "presign_submission":
			submission = &a.Files[i]
		case "presentation":
			presentation = &a.Files[i]
		}
	}
	return state != nil && submission != nil && presentation != nil &&
		a.StatePath == state.Path && a.StateSHA256 == state.SHA256 &&
		a.SubmissionPath == submission.Path && a.SubmissionSHA256 == submission.SHA256 &&
		a.PresentationPath == presentation.Path && a.PresentationSHA256 == presentation.SHA256
}

type focusedV3NonResearchRawSizes struct {
	PersistentStateBytes   int `json:"persistent_credential_state_bytes"`
	IssuanceProofWireBytes int `json:"issuance_proof_wire_bytes"`
	ShowingProofWireBytes  int `json:"showing_proof_wire_bytes"`
	PresentationWireBytes  int `json:"presentation_wire_bytes"`
	PaperIssuanceBytes     int `json:"issuance_paper_transcript_bytes"`
	PaperShowingBytes      int `json:"showing_paper_transcript_bytes"`
}

type focusedV3NonResearchRawReport struct {
	Version                  int                                         `json:"version"`
	CanonicalPresetID        string                                      `json:"canonical_preset_id"`
	PresetVersion            int                                         `json:"preset_version"`
	ClaimScope               credential.ClaimScope                       `json:"claim_scope"`
	CompleteSystemClaim      bool                                        `json:"complete_system_claim"`
	PresetManifestDigest     string                                      `json:"preset_manifest_digest"`
	CoreBitsRequired         float64                                     `json:"core_required_bits"`
	LedgerStatus             string                                      `json:"ledger_status"`
	FullGameAccountingStatus string                                      `json:"full_game_accounting_status"`
	ProfileBound             int64                                       `json:"profile_bound"`
	ArtifactDir              string                                      `json:"artifact_dir"`
	Environment              benchmarkEnvironmentWire                    `json:"environment"`
	Options                  benchmarkOptionsWire                        `json:"options"`
	CanonicalSizes           *focusedV3NonResearchRawSizes               `json:"canonical_sizes"`
	Issuance                 benchmarkPhaseWire                          `json:"issuance"`
	Showing                  benchmarkPhaseWire                          `json:"showing"`
	Artifacts                benchmarkArtifactsWire                      `json:"artifacts"`
	ParameterAudit           credential.IntGenISISSecurityParameterAudit `json:"parameter_audit"`
	SecurityLedger           credential.SystemSecurityLedger             `json:"security_ledger"`
	ReplayRejected           bool                                        `json:"replay_rejected"`
}

// ValidateFocusedV3NonResearchOptimizationArtifacts proves that the evidence
// summary is an exact projection of its predecessor and the six immutable raw
// reports/resource files/canonical artifacts.
func ValidateFocusedV3NonResearchOptimizationArtifacts(e FocusedV3NonResearchOptimizationEvidence, spruceRoot string) error {
	if err := ValidateFocusedV3NonResearchOptimizationEvidence(e); err != nil {
		return err
	}
	root, err := filepath.Abs(spruceRoot)
	if err != nil {
		return err
	}
	// This is an immutable historical epoch. Each raw report below must bind
	// the source snapshot recorded in the summary, but an evolved checkout is
	// not required to hash to that old snapshot. Requiring the live tree here
	// would make preserved evidence invalid as soon as codec v6 is implemented.
	priorPath, err := focusedV3NonResearchPath(root, e.PriorEvidence.Path)
	if err != nil {
		return err
	}
	if err := checkFocusedV3TranscriptDigest(priorPath, e.PriorEvidence.SHA256); err != nil {
		return fmt.Errorf("focused-v3 non-research prior evidence: %w", err)
	}
	prior, err := ReadFocusedV3TranscriptReductionEvidence(priorPath)
	if err != nil {
		return err
	}
	for _, target := range e.Targets {
		priorTarget, ok := focusedV3NonResearchPriorTarget(prior, target.CanonicalID)
		if !ok || !focusedV3NonResearchPriorMatches(priorTarget, target.PriorAccepted) {
			return fmt.Errorf("focused-v3 non-research prior projection mismatch for %s", target.CanonicalID)
		}
		for _, run := range target.Runs {
			if err := validateFocusedV3NonResearchRawRun(root, e, target, run); err != nil {
				return err
			}
		}
	}
	return nil
}

func focusedV3NonResearchPriorTarget(e FocusedV3TranscriptReductionEvidence, id string) (FocusedV3TranscriptReductionTarget, bool) {
	for _, target := range e.Targets {
		if target.CanonicalID == id {
			return target, true
		}
	}
	return FocusedV3TranscriptReductionTarget{}, false
}

func focusedV3NonResearchPriorMatches(target FocusedV3TranscriptReductionTarget, prior FocusedV3NonResearchPrior) bool {
	m := target.Medians
	// focused-v3-transcript-reduction.json is immutable historical evidence.
	// Its proof-v4 paper estimator incorrectly removed two Q coordinates per K
	// limb.  Correct the projection here by one field element per limb while
	// preserving every measured wire/runtime value from that evidence epoch.
	paperCorrection := 0
	switch target.CanonicalID {
	case credential.IntGenISISPresetPoCN1024BQ128R128V3:
		paperCorrection = 33
	case credential.IntGenISISPresetSystemN1024WF128CROMV2:
		paperCorrection = 17
	default:
		return false
	}
	return m.PersistentStateBytes == prior.PersistentStateBytes && m.IssuanceProofWireBytes == prior.IssuanceProofWireBytes && m.ShowingProofWireBytes == prior.ShowingProofWireBytes &&
		m.PresentationWireBytes == prior.PresentationWireBytes && m.PaperIssuanceBytes+paperCorrection == prior.PaperIssuanceBytes && m.PaperShowingBytes+paperCorrection == prior.PaperShowingBytes &&
		closeFloat(m.IssuanceProvingMS, prior.IssuanceProvingMS) && closeFloat(m.ShowingProvingMS, prior.ShowingProvingMS) && m.PeakRSSBytes == prior.PeakRSSBytes
}

func validateFocusedV3NonResearchRawRun(root string, e FocusedV3NonResearchOptimizationEvidence, target FocusedV3NonResearchTarget, run FocusedV3NonResearchRun) error {
	reportPath, err := focusedV3NonResearchPath(root, run.ReportPath)
	if err != nil {
		return err
	}
	resourcePath, err := focusedV3NonResearchPath(root, run.ResourcePath)
	if err != nil {
		return err
	}
	artifactDir, err := focusedV3NonResearchPath(root, run.ArtifactDirectory)
	if err != nil {
		return err
	}
	if filepath.Dir(reportPath) != artifactDir || filepath.Dir(resourcePath) != artifactDir {
		return fmt.Errorf("focused-v3 non-research %s run %d report/resource escape artifact directory", target.CanonicalID, run.Run)
	}
	if err := checkFocusedV3TranscriptDigest(reportPath, run.ReportSHA256); err != nil {
		return fmt.Errorf("%s run %d report: %w", target.CanonicalID, run.Run, err)
	}
	if err := checkFocusedV3TranscriptDigest(resourcePath, run.ResourceSHA256); err != nil {
		return fmt.Errorf("%s run %d resource: %w", target.CanonicalID, run.Run, err)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}
	var raw focusedV3NonResearchRawReport
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode focused-v3 non-research raw report: %w", err)
	}
	preset, _ := credential.LookupIntGenISISPreset(target.CanonicalID)
	if raw.Version != 2 || raw.CanonicalPresetID != target.CanonicalID || raw.PresetVersion != preset.PresetVersion || raw.PresetManifestDigest != target.ManifestDigest ||
		raw.ClaimScope != credential.ClaimProofOnly || raw.CompleteSystemClaim || raw.LedgerStatus != string(credential.ClaimProofOnly) || raw.FullGameAccountingStatus != "deferred_proof_only" ||
		raw.ProfileBound != credential.IntGenISISLiveBound || raw.CoreBitsRequired != preset.CoreBitsRequired || raw.SecurityLedger.CompleteSystemClaim || raw.SecurityLedger.LedgerStatus != string(credential.ClaimProofOnly) ||
		raw.ParameterAudit.Status != "pass" || !raw.ReplayRejected || !focusedV3NonResearchEnvironmentMatches(raw.Environment, e.Environment) {
		return fmt.Errorf("focused-v3 non-research %s run %d report identity/security boundary mismatch", target.CanonicalID, run.Run)
	}
	if focusedV3NonResearchTuningWire(raw.Options.Issuance, preset.Issuance) != target.Frozen.Issuance || focusedV3NonResearchTuningWire(raw.Options.Showing, preset.Showing) != target.Frozen.Showing {
		return fmt.Errorf("focused-v3 non-research %s run %d changed a frozen option", target.CanonicalID, run.Run)
	}
	if raw.CanonicalSizes == nil {
		return fmt.Errorf("focused-v3 non-research %s run %d has no canonical size record", target.CanonicalID, run.Run)
	}
	s := *raw.CanonicalSizes
	if s.PersistentStateBytes != run.PersistentStateBytes || s.IssuanceProofWireBytes != run.IssuanceProofWireBytes || s.ShowingProofWireBytes != run.ShowingProofWireBytes ||
		s.PresentationWireBytes != run.PresentationWireBytes || s.PaperIssuanceBytes != run.PaperIssuanceBytes || s.PaperShowingBytes != run.PaperShowingBytes ||
		raw.Issuance.ProvingMS != run.IssuanceProvingMS || raw.Showing.ProvingMS != run.ShowingProvingMS || raw.Issuance.VerificationMS != run.IssuanceVerificationMS || raw.Showing.VerificationMS != run.ShowingVerificationMS ||
		raw.Issuance.TheoremTotalBits != run.IssuanceTheoremBits || raw.Showing.TheoremTotalBits != run.ShowingTheoremBits || raw.ParameterAudit.Status != run.ParameterAuditStatus ||
		raw.Issuance.ZeroKnowledgeEligible != run.IssuanceZKEligible || raw.Showing.ZeroKnowledgeEligible != run.ShowingZKEligible || raw.ReplayRejected != run.ReplayRejected {
		return fmt.Errorf("focused-v3 non-research %s run %d measurement projection mismatch", target.CanonicalID, run.Run)
	}
	if err := validateFocusedV3NonResearchPhase("issuance", raw.Issuance, target.Protocol, target.IssuanceGeometry, target.Frozen.Issuance, s.IssuanceProofWireBytes, s.PaperIssuanceBytes, preset.CoreBitsRequired); err != nil {
		return fmt.Errorf("focused-v3 non-research %s run %d: %w", target.CanonicalID, run.Run, err)
	}
	if err := validateFocusedV3NonResearchPhase("showing", raw.Showing, target.Protocol, target.ShowingGeometry, target.Frozen.Showing, s.ShowingProofWireBytes, s.PaperShowingBytes, preset.CoreBitsRequired); err != nil {
		return fmt.Errorf("focused-v3 non-research %s run %d: %w", target.CanonicalID, run.Run, err)
	}
	if raw.Showing.CanonicalPresentationBytes != s.PresentationWireBytes {
		return fmt.Errorf("focused-v3 non-research %s run %d presentation metric mismatch", target.CanonicalID, run.Run)
	}
	if raw.ArtifactDir != run.ArtifactDirectory ||
		!reflect.DeepEqual(focusedV3NonResearchReportedArtifactPaths(raw.Artifacts), focusedV3NonResearchArtifactPaths(run.ArtifactDirectory)) ||
		raw.Artifacts.State != run.Artifacts.StatePath || raw.Artifacts.Submission != run.Artifacts.SubmissionPath || raw.Artifacts.Presentation != run.Artifacts.PresentationPath {
		return fmt.Errorf("focused-v3 non-research %s run %d artifact projection mismatch", target.CanonicalID, run.Run)
	}
	if err := validateFocusedV3NonResearchArtifacts(root, artifactDir, preset, run); err != nil {
		return fmt.Errorf("focused-v3 non-research %s run %d artifacts: %w", target.CanonicalID, run.Run, err)
	}
	rss, err := focusedV3TranscriptResourceRSS(resourcePath)
	if err != nil {
		return err
	}
	if rss != run.PeakRSSBytes {
		return fmt.Errorf("focused-v3 non-research %s run %d RSS=%d want=%d", target.CanonicalID, run.Run, rss, run.PeakRSSBytes)
	}
	return nil
}

func focusedV3NonResearchEnvironmentMatches(raw benchmarkEnvironmentWire, want FocusedV3NonResearchEnvironment) bool {
	rawCommitTime, rawTimeErr := time.Parse(time.RFC3339, raw.CommitTime)
	wantCommitTime, wantTimeErr := time.Parse(time.RFC3339, want.CommitTime)
	return raw.GoVersion == want.GoVersion && raw.GOOS == want.GOOS && raw.GOARCH == want.GOARCH && raw.NumCPU == want.NumCPU && raw.GOMAXPROCS == want.GOMAXPROCS &&
		raw.VCS == want.VCS && raw.Commit == want.Commit && rawTimeErr == nil && wantTimeErr == nil && rawCommitTime.Equal(wantCommitTime) && raw.Modified != nil && *raw.Modified == want.Modified &&
		raw.SourceTreeAlgorithm == want.SourceTreeAlgorithm && raw.SourceTreeDigest == want.SourceTreeDigest && raw.SourceTreeFileCount == want.SourceTreeFileCount
}

func focusedV3NonResearchTuningWire(t benchmarkTuningWire, preset credential.IntGenISISTuningPreset) FocusedV3NonResearchTuning {
	return FocusedV3NonResearchTuning{
		NCols: t.NCols, LVCSNCols: t.LVCSNCols, NLeaves: t.NLeaves, Eta: t.Eta, Theta: t.Theta, Rho: t.Rho, Ell: t.Ell, EllPrime: t.EllPrime, DQOverride: t.DQOverride,
		Kappa: t.Kappa, ROQueryCaps: t.ROQueryCaps, ROQueryCapBits: t.ROQueryCapBits,
		DECSCollisionBits: t.DECSCollisionBits, DECSHashBits: t.DECSHashBits, DECSTapeBits: t.DECSTapeBits, FSCollisionBits: t.FSCollisionBits, SaltBits: t.SaltBits,
		PRFProfile: t.PRFProfile, PRFCompanionMode: t.PRFCompanionMode, PRFGroupRounds: t.PRFGroupRounds, CheckpointSamples: t.CheckpointSamples,
		SigShortnessRadix: t.SigShortnessRadix, SigShortnessDigits: t.SigShortnessDigits, CompressedRows: t.CompressedRows, ReplayProjection: t.ReplayProjection,
		TranscriptMode: t.TranscriptMode, TranscriptOmissionMode: t.TranscriptOmissionMode, FixedTranscriptSize: t.FixedTranscriptSize,
		// These relation selectors are manifest-bound and are intentionally
		// absent from the CLI tuning JSON, so they come from the exact live
		// preset after all transmitted knobs have been checked above.
		SoundnessGate: preset.SoundnessGate, RelationVersion: preset.RelationVersion, LayoutVersion: preset.LayoutVersion,
	}
}

func validateFocusedV3NonResearchPhase(label string, phase benchmarkPhaseWire, protocol FocusedV3NonResearchProtocolIdentity, geometry FocusedV3NonResearchGeometry, tuning FocusedV3NonResearchTuning, wireBytes, paperBytes int, targetBits float64) error {
	kind := "presign"
	wantLayout, wantRelation, wantInputTrace := protocol.IssuanceLayoutVersion, protocol.IssuanceRelationVersion, 0
	if label == "showing" {
		kind, wantLayout, wantRelation, wantInputTrace = "showing", protocol.ShowingLayoutVersion, "", protocol.ShowingInputTraceRelation
	}
	if phase.ProofSchemaVersion != protocol.ProofSchemaVersion || phase.CanonicalProofKind != kind || phase.CanonicalProofCodecVersion != protocol.CanonicalProofCodecVersion ||
		phase.CanonicalProofCodecProfile != protocol.CanonicalProofCodecProfile || phase.CanonicalProofFieldEncoding != protocol.CanonicalProofFieldEncoding ||
		phase.CanonicalProofQKernelEncoding != protocol.CanonicalProofQKernelEncoding || phase.CanonicalProofRadixQGroupSize != protocol.CanonicalProofRadixQGroupSize ||
		phase.CanonicalProofMerkleTopology != protocol.CanonicalProofMerkleTopology || phase.LayoutVersion != wantLayout || phase.RelationVersion != wantRelation || phase.PRFInputTraceRelationVersion != wantInputTrace {
		return fmt.Errorf("%s protocol/relation identity mismatch", label)
	}
	if phase.CanonicalProofWireBytes != wireBytes || phase.ProofSizeBytes != wireBytes || phase.PaperTranscriptBytes != paperBytes || phase.CanonicalWireAudit == nil {
		return fmt.Errorf("%s canonical/paper size identity mismatch", label)
	}
	if err := validateFocusedV3NonResearchWireAudit(*phase.CanonicalWireAudit, protocol, tuning.Theta, wireBytes, phase.RootWidthBytes); err != nil {
		return fmt.Errorf("%s canonical wire audit: %w", label, err)
	}
	gotGeometry := FocusedV3NonResearchGeometry{
		LogicalRows: phase.TotalRows, Layers: phase.RowsBlock, MaskRows: phase.MaskRows, ReplayRows: phase.SmallFieldReplayRows, PhysicalRows: phase.PaperShapeNRows,
		Queries: phase.PaperShapeQueries, OpeningPColumns: phase.OpeningCols, ParallelDegree: phase.ParallelAlgDegree, AggregatedDegree: phase.AggregatedAlgDegree, QDegree: phase.PaperConservativeDQ,
	}
	if gotGeometry != geometry || phase.LVCSNCols != tuning.LVCSNCols || phase.NLeaves != tuning.NLeaves || phase.Eta != tuning.Eta || phase.Theta != tuning.Theta || phase.Rho != tuning.Rho || phase.Ell != tuning.Ell || phase.EllPrime != tuning.EllPrime {
		return fmt.Errorf("%s geometry/frozen tuning mismatch", label)
	}
	if phase.TranscriptMode != tuning.TranscriptMode || phase.TranscriptSecurityStatus != focusedV3NonResearchTranscriptLive || !phase.FixedTranscriptSize || phase.TranscriptSizeMode != "fixed" ||
		!phase.PaperShapeCanonical || !phase.ZeroKnowledgeEligible || phase.MeasurementStatus == "" || phase.TheoremTotalBits < targetBits || phase.AlgebraicTotalBits < targetBits || anyTrue(phase.Clamped) ||
		phase.DECSHashBits != tuning.DECSHashBits || phase.DECSTapeBits != tuning.DECSTapeBits || phase.SaltBits != tuning.SaltBits || phase.RootWidthBytes*8 != tuning.DECSHashBits {
		return fmt.Errorf("%s applicable SmallWood proof-security gate failed", label)
	}
	return nil
}

func validateFocusedV3NonResearchWireAudit(a PIOP.CanonicalProofWireAuditV5, protocol FocusedV3NonResearchProtocolIdentity, theta, totalBytes, rootWidth int) error {
	if a.CodecVersion != protocol.CanonicalProofCodecVersion || a.CodecProfile != protocol.CanonicalProofCodecProfile || a.ProofSchemaVersion != protocol.ProofSchemaVersion ||
		a.FieldEncoding != protocol.CanonicalProofFieldEncoding || a.QKernelEncoding != protocol.CanonicalProofQKernelEncoding || a.RadixQGroupElements != protocol.CanonicalProofRadixQGroupSize || a.MerkleTopology != protocol.CanonicalProofMerkleTopology {
		return fmt.Errorf("codec identity mismatch")
	}
	sum := a.HeaderBytes + a.RootBytes + a.SaltBytes + a.CounterBytes + a.RBytes + a.QBytes + a.VTargetsBytes + a.BarSetsBytes + a.OpeningPBytes + a.TapeBytes + a.AuthenticationBytes
	if sum != a.TotalBytes || a.TotalBytes != totalBytes || a.HeaderBytes != 10 || a.RootBytes != rootWidth || a.CounterBytes <= 0 {
		return fmt.Errorf("component sum/header/root mismatch")
	}
	if a.QOmittedFieldElements != theta || a.QFullFieldElements-a.QWireFieldElements != a.QOmittedFieldElements || a.QWireFieldElements <= 0 {
		return fmt.Errorf("Q-kernel omission mismatch")
	}
	if a.MerkleNodesUsed <= 0 || a.MerklePaddingNodes < 0 || a.MerkleNodesUsed+a.MerklePaddingNodes != a.MerkleNodesBound || a.AuthenticationBytes != a.MerkleNodesBound*rootWidth {
		return fmt.Errorf("exact-N Merkle frontier/padding mismatch")
	}
	return nil
}

func validateFocusedV3NonResearchArtifacts(root, artifactDir string, preset credential.IntGenISISPreset, run FocusedV3NonResearchRun) error {
	wantFiles := focusedV3NonResearchArtifactPaths(run.ArtifactDirectory)
	if len(run.Artifacts.Files) != len(wantFiles) {
		return fmt.Errorf("artifact bundle entries=%d want=%d", len(run.Artifacts.Files), len(wantFiles))
	}
	for i, want := range wantFiles {
		recorded := run.Artifacts.Files[i]
		if recorded.Role != want.role || recorded.Path != want.path || recorded.Bytes <= 0 || !validHexDigest(recorded.SHA256, 64) {
			return fmt.Errorf("artifact bundle entry %d does not match canonical role/path", i)
		}
		absPath, err := focusedV3NonResearchPath(root, recorded.Path)
		if err != nil {
			return err
		}
		if filepath.Dir(absPath) != artifactDir {
			return fmt.Errorf("artifact bundle entry %s escapes run directory", recorded.Path)
		}
		data, info, err := readFocusedV3NonResearchRegularFile(absPath)
		if err != nil {
			return fmt.Errorf("read %s artifact bundle entry: %w", recorded.Role, err)
		}
		if info.Size() != recorded.Bytes || sha256Hex(data) != recorded.SHA256 {
			return fmt.Errorf("artifact bundle entry %s size/digest mismatch", recorded.Role)
		}
	}
	paths := []struct{ rel, digest string }{
		{run.Artifacts.StatePath, run.Artifacts.StateSHA256}, {run.Artifacts.SubmissionPath, run.Artifacts.SubmissionSHA256}, {run.Artifacts.PresentationPath, run.Artifacts.PresentationSHA256},
	}
	abs := make([]string, len(paths))
	for i, item := range paths {
		var err error
		abs[i], err = focusedV3NonResearchPath(root, item.rel)
		if err != nil {
			return err
		}
		if filepath.Dir(abs[i]) != artifactDir {
			return fmt.Errorf("artifact %s escapes run directory", item.rel)
		}
		if err := checkFocusedV3TranscriptDigest(abs[i], item.digest); err != nil {
			return fmt.Errorf("artifact %s: %w", item.rel, err)
		}
	}
	state, err := os.ReadFile(abs[0])
	if err != nil {
		return err
	}
	stateInfo, err := os.Stat(abs[0])
	if err != nil {
		return err
	}
	if len(state) != run.PersistentStateBytes || stateInfo.Mode().Perm() != 0o600 || len(state) < 8 || !bytes.Equal(state[:8], []byte{'S', 'P', 'R', 'S', 'T', 'A', 'T', 8}) {
		return fmt.Errorf("state-v8 bytes/mode/header mismatch")
	}
	submissionData, err := os.ReadFile(abs[1])
	if err != nil {
		return err
	}
	var submission struct {
		Version        int    `json:"version"`
		CanonicalProof []byte `json:"canonical_proof"`
	}
	if err := json.Unmarshal(submissionData, &submission); err != nil {
		return err
	}
	if submission.Version != 4 || len(submission.CanonicalProof) != run.IssuanceProofWireBytes || !bytes.HasPrefix(submission.CanonicalProof, []byte{'S', 'P', 'R', 'U', 'C', 'E', 'P', '5', 5, 1}) || sha256Hex(submission.CanonicalProof) != run.Artifacts.IssuanceProofSHA256 {
		return fmt.Errorf("issuance artifact/proof-v5 projection mismatch")
	}
	presentation, err := os.ReadFile(abs[2])
	if err != nil {
		return err
	}
	presentationInfo, err := os.Stat(abs[2])
	if err != nil {
		return err
	}
	tagCount, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok {
		return fmt.Errorf("unknown target PRF profile %q", preset.PRFProfile)
	}
	proofOffset := 8 + (tagCount*20+7)/8
	if len(presentation) != run.PresentationWireBytes || presentationInfo.Mode().Perm() != 0o644 || proofOffset+10 > len(presentation) ||
		!bytes.Equal(presentation[:8], []byte{'S', 'P', 'R', 'P', 'R', 'E', 'S', 3}) || !bytes.HasPrefix(presentation[proofOffset:], []byte{'S', 'P', 'R', 'U', 'C', 'E', 'P', '5', 5, 2}) {
		return fmt.Errorf("presentation-v3 envelope/proof header mismatch")
	}
	showProof := presentation[proofOffset:]
	if len(showProof) != run.ShowingProofWireBytes || sha256Hex(showProof) != run.Artifacts.ShowingProofSHA256 {
		return fmt.Errorf("showing proof-v5 projection mismatch")
	}
	return nil
}

func focusedV3NonResearchPath(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("focused-v3 non-research path %q is not relative", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("focused-v3 non-research path %q escapes repository", rel)
	}
	abs := filepath.Join(root, clean)
	check, err := filepath.Rel(root, abs)
	if err != nil || check == ".." || strings.HasPrefix(check, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("focused-v3 non-research path %q escapes repository", rel)
	}
	return abs, nil
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
