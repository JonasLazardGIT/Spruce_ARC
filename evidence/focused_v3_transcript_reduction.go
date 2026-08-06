package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"vSIS-Signature/credential"
)

const (
	FocusedV3TranscriptReductionSchema  = "spruce.focused-v3-transcript-reduction"
	FocusedV3TranscriptReductionVersion = 1
	FocusedV3TranscriptReductionRuns    = 3
	focusedV3TranscriptLiveStatus       = "smallwood_2025_1085_salted_tapes_v3_live"
)

// FocusedV3TranscriptReductionEvidence is a new evidence epoch. It keeps the
// first strict-v3 size record immutable and states its corrected paper
// accounting explicitly before comparing the structural transcript reduction.
type FocusedV3TranscriptReductionEvidence struct {
	Schema                   string                                  `json:"schema"`
	Version                  int                                     `json:"version"`
	MeasuredOn               string                                  `json:"measured_on"`
	ClaimScope               string                                  `json:"claim_scope"`
	ImplementationBaseCommit string                                  `json:"implementation_base_commit"`
	Environment              FocusedV3TranscriptReductionEnvironment `json:"environment"`
	PriorEvidence            FocusedV3TranscriptReductionPriorSource `json:"prior_v3_evidence"`
	Paper                    FocusedV3PaperTreeEvidence              `json:"paper_repository"`
	Targets                  []FocusedV3TranscriptReductionTarget    `json:"targets"`
}

type FocusedV3TranscriptReductionEnvironment struct {
	GoVersion  string `json:"go_version"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	NumCPU     int    `json:"num_cpu"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	VCS        string `json:"vcs"`
	Commit     string `json:"commit"`
	CommitTime string `json:"commit_time"`
	Modified   bool   `json:"modified"`
}

type FocusedV3TranscriptReductionPriorSource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type FocusedV3TranscriptReductionTarget struct {
	CanonicalID    string                               `json:"canonical_id"`
	ManifestDigest string                               `json:"manifest_digest"`
	Kappa          [4]int                               `json:"kappa"`
	PriorV3        FocusedV3TranscriptReductionPrior    `json:"prior_v3_corrected"`
	Frozen         FocusedV3TranscriptReductionFrozen   `json:"frozen_parameters"`
	Adopted        FocusedV3TranscriptReductionGeometry `json:"adopted_showing_geometry"`
	Runs           []FocusedV3TranscriptReductionRun    `json:"runs"`
	Medians        FocusedV3TranscriptReductionMedian   `json:"medians"`
}

type FocusedV3TranscriptReductionPrior struct {
	PersistentStateBytes   int                                  `json:"persistent_state_bytes"`
	IssuanceProofWireBytes int                                  `json:"issuance_proof_wire_bytes"`
	ShowingProofWireBytes  int                                  `json:"showing_proof_wire_bytes"`
	PresentationWireBytes  int                                  `json:"presentation_wire_bytes"`
	PaperIssuanceBytes     int                                  `json:"corrected_paper_issuance_bytes"`
	PaperShowingBytes      int                                  `json:"corrected_paper_showing_bytes"`
	IssuanceProvingMS      float64                              `json:"median_issuance_proving_ms"`
	ShowingProvingMS       float64                              `json:"median_showing_proving_ms"`
	PeakRSSBytes           uint64                               `json:"median_peak_rss_bytes"`
	ShowingGeometry        FocusedV3TranscriptReductionGeometry `json:"showing_geometry"`
}

type FocusedV3TranscriptReductionFrozen struct {
	Issuance FocusedV3TranscriptReductionTuning `json:"issuance"`
	Showing  FocusedV3TranscriptReductionTuning `json:"showing"`
}

type FocusedV3TranscriptReductionTuning struct {
	NCols                  int        `json:"ncols"`
	LVCSNCols              int        `json:"lvcs_ncols"`
	NLeaves                int        `json:"nleaves"`
	Eta                    int        `json:"eta"`
	Theta                  int        `json:"theta"`
	Rho                    int        `json:"rho"`
	Ell                    int        `json:"ell"`
	EllPrime               int        `json:"ell_prime"`
	Kappa                  [4]int     `json:"kappa"`
	ROQueryCaps            [5]int     `json:"ro_query_caps"`
	ROQueryCapBits         [5]float64 `json:"ro_query_cap_bits"`
	DECSCollisionBits      int        `json:"decs_collision_bits"`
	DECSHashBits           int        `json:"decs_hash_bits"`
	DECSTapeBits           int        `json:"decs_tape_bits"`
	FSCollisionBits        int        `json:"fs_collision_bits"`
	SaltBits               int        `json:"salt_bits"`
	PRFProfile             string     `json:"prf_profile"`
	TranscriptMode         string     `json:"transcript_mode"`
	TranscriptOmissionMode string     `json:"transcript_omission_mode"`
	FixedTranscriptSize    bool       `json:"fixed_transcript_size"`
}

type FocusedV3TranscriptReductionGeometry struct {
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

type FocusedV3TranscriptReductionRun struct {
	Run                      int     `json:"run"`
	ArtifactDirectory        string  `json:"artifact_directory"`
	ReportPath               string  `json:"report_path"`
	ReportSHA256             string  `json:"report_sha256"`
	ResourcePath             string  `json:"resource_path"`
	ResourceSHA256           string  `json:"resource_sha256"`
	PersistentStateBytes     int     `json:"persistent_state_bytes"`
	IssuanceProofWireBytes   int     `json:"issuance_proof_wire_bytes"`
	ShowingProofWireBytes    int     `json:"showing_proof_wire_bytes"`
	PresentationWireBytes    int     `json:"presentation_wire_bytes"`
	PaperIssuanceBytes       int     `json:"paper_issuance_bytes"`
	PaperShowingBytes        int     `json:"paper_showing_bytes"`
	IssuanceProvingMS        float64 `json:"issuance_proving_ms"`
	ShowingProvingMS         float64 `json:"showing_proving_ms"`
	IssuanceVerificationMS   float64 `json:"issuance_verification_ms"`
	ShowingVerificationMS    float64 `json:"showing_verification_ms"`
	PeakRSSBytes             uint64  `json:"peak_rss_bytes"`
	IssuanceTheoremBits      float64 `json:"issuance_theorem_bits"`
	ShowingTheoremBits       float64 `json:"showing_theorem_bits"`
	ParameterAuditStatus     string  `json:"parameter_audit_status"`
	IssuanceZKEligible       bool    `json:"issuance_zero_knowledge_eligible"`
	ShowingZKEligible        bool    `json:"showing_zero_knowledge_eligible"`
	IssuanceTranscriptStatus string  `json:"issuance_transcript_security_status"`
	ShowingTranscriptStatus  string  `json:"showing_transcript_security_status"`
	ReplayRejected           bool    `json:"replay_rejected"`
	ApplicableGatesPassed    bool    `json:"applicable_proof_security_gates_passed"`
}

type FocusedV3TranscriptReductionMedian struct {
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

func ReadFocusedV3TranscriptReductionEvidence(path string) (FocusedV3TranscriptReductionEvidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FocusedV3TranscriptReductionEvidence{}, err
	}
	var out FocusedV3TranscriptReductionEvidence
	if err := decodeStrictJSON(data, &out); err != nil {
		return FocusedV3TranscriptReductionEvidence{}, fmt.Errorf("decode focused-v3 transcript-reduction evidence: %w", err)
	}
	return out, nil
}

func ValidateFocusedV3TranscriptReductionEvidence(e FocusedV3TranscriptReductionEvidence) error {
	if e.Schema != FocusedV3TranscriptReductionSchema || e.Version != FocusedV3TranscriptReductionVersion {
		return fmt.Errorf("focused-v3 transcript evidence identity=(%q,v%d)", e.Schema, e.Version)
	}
	if e.ClaimScope != string(credential.ClaimProofOnly) {
		return fmt.Errorf("focused-v3 transcript evidence claim scope=%q", e.ClaimScope)
	}
	if _, err := time.Parse("2006-01-02", e.MeasuredOn); err != nil {
		return fmt.Errorf("focused-v3 transcript evidence measured_on: %w", err)
	}
	if !validHexDigest(e.ImplementationBaseCommit, 40) || e.Environment.Commit != e.ImplementationBaseCommit || !e.Environment.Modified ||
		e.Environment.GoVersion == "" || e.Environment.GOOS == "" || e.Environment.GOARCH == "" || e.Environment.NumCPU <= 0 || e.Environment.GOMAXPROCS <= 0 {
		return fmt.Errorf("focused-v3 transcript implementation/environment boundary is incomplete")
	}
	if e.PriorEvidence.Path != "evidence/focused-v3-size-optimization.json" || !validHexDigest(e.PriorEvidence.SHA256, 64) {
		return fmt.Errorf("focused-v3 transcript prior evidence source is invalid")
	}
	if !validHexDigest(e.Paper.HeadBefore, 40) || e.Paper.HeadBefore != e.Paper.HeadAfter || !e.Paper.CleanBefore || !e.Paper.CleanAfter {
		return fmt.Errorf("focused-v3 transcript paper boundary is incomplete")
	}
	if len(e.Targets) != len(focusedV3TargetPresetIDs) {
		return fmt.Errorf("focused-v3 transcript targets=%d want=%d", len(e.Targets), len(focusedV3TargetPresetIDs))
	}
	seen := make(map[string]bool, len(e.Targets))
	for _, target := range e.Targets {
		preset, ok := credential.LookupIntGenISISPreset(target.CanonicalID)
		if !ok || !isFocusedV3TargetPresetID(target.CanonicalID) || seen[target.CanonicalID] {
			return fmt.Errorf("invalid or duplicate focused-v3 transcript target %q", target.CanonicalID)
		}
		seen[target.CanonicalID] = true
		if err := ValidateFocusedV3TargetPreset(preset); err != nil {
			return err
		}
		historicalManifest, manifestOK := focusedV3HistoricalManifestDigest(target.CanonicalID)
		if !manifestOK || target.ManifestDigest != historicalManifest || target.Kappa != preset.Issuance.Kappa || target.Kappa != preset.Showing.Kappa {
			return fmt.Errorf("focused-v3 transcript target %s manifest/kappa mismatch", target.CanonicalID)
		}
		wantPrior, wantAdopted, ok := focusedV3TranscriptExpectedTarget(target.CanonicalID)
		if !ok || target.PriorV3 != wantPrior || target.Adopted != wantAdopted {
			return fmt.Errorf("focused-v3 transcript target %s prior/adopted geometry mismatch", target.CanonicalID)
		}
		wantFrozen := FocusedV3TranscriptReductionFrozen{
			Issuance: focusedV3TranscriptTuning(preset.Issuance),
			Showing:  focusedV3TranscriptTuning(preset.Showing),
		}
		if !reflect.DeepEqual(target.Frozen, wantFrozen) {
			return fmt.Errorf("focused-v3 transcript target %s changed a frozen manifest parameter", target.CanonicalID)
		}
		if err := validateFocusedV3TranscriptRuns(target, preset.CoreBitsRequired); err != nil {
			return err
		}
	}
	for _, id := range focusedV3TargetPresetIDs {
		if !seen[id] {
			return fmt.Errorf("focused-v3 transcript evidence missing %s", id)
		}
	}
	return nil
}

func focusedV3TranscriptExpectedTarget(id string) (FocusedV3TranscriptReductionPrior, FocusedV3TranscriptReductionGeometry, bool) {
	switch id {
	case credential.IntGenISISPresetPoCN1024BQ128R128V3:
		return FocusedV3TranscriptReductionPrior{
			PersistentStateBytes: 4926, IssuanceProofWireBytes: 60688, ShowingProofWireBytes: 91490, PresentationWireBytes: 91523,
			PaperIssuanceBytes: 65296, PaperShowingBytes: 96098, IssuanceProvingMS: 1868.58, ShowingProvingMS: 4667.92, PeakRSSBytes: 562085888,
			ShowingGeometry: FocusedV3TranscriptReductionGeometry{LogicalRows: 551, Layers: 13, MaskRows: 156, ReplayRows: 585, PhysicalRows: 741, Queries: 182, OpeningPColumns: 559, ParallelDegree: 9, AggregatedDegree: 8, QDegree: 472},
		}, FocusedV3TranscriptReductionGeometry{LogicalRows: 487, Layers: 12, MaskRows: 156, ReplayRows: 540, PhysicalRows: 696, Queries: 169, OpeningPColumns: 527, ParallelDegree: 9, AggregatedDegree: 8, QDegree: 472}, true
	case credential.IntGenISISPresetSystemN1024WF128CROMV2:
		return FocusedV3TranscriptReductionPrior{
			PersistentStateBytes: 4894, IssuanceProofWireBytes: 26039, ShowingProofWireBytes: 40319, PresentationWireBytes: 40360,
			PaperIssuanceBytes: 27655, PaperShowingBytes: 41933, IssuanceProvingMS: 575.994, ShowingProvingMS: 1742.816, PeakRSSBytes: 287752192,
			ShowingGeometry: FocusedV3TranscriptReductionGeometry{LogicalRows: 487, Layers: 12, MaskRows: 91, ReplayRows: 468, PhysicalRows: 559, Queries: 91, OpeningPColumns: 468, ParallelDegree: 11, AggregatedDegree: 8, QDegree: 471},
		}, FocusedV3TranscriptReductionGeometry{LogicalRows: 423, Layers: 11, MaskRows: 91, ReplayRows: 429, PhysicalRows: 520, Queries: 84, OpeningPColumns: 436, ParallelDegree: 11, AggregatedDegree: 8, QDegree: 471}, true
	default:
		return FocusedV3TranscriptReductionPrior{}, FocusedV3TranscriptReductionGeometry{}, false
	}
}

func focusedV3TranscriptTuning(t credential.IntGenISISTuningPreset) FocusedV3TranscriptReductionTuning {
	return FocusedV3TranscriptReductionTuning{
		NCols: t.NCols, LVCSNCols: t.LVCSNCols, NLeaves: t.NLeaves, Eta: t.Eta, Theta: t.Theta, Rho: t.Rho, Ell: t.Ell, EllPrime: t.EllPrime,
		Kappa: t.Kappa, ROQueryCaps: t.ROQueryCaps, ROQueryCapBits: t.ROQueryCapBits,
		DECSCollisionBits: t.DECSCollisionBits, DECSHashBits: t.DECSHashBits, DECSTapeBits: t.DECSTapeBits, FSCollisionBits: t.FSCollisionBits, SaltBits: t.SaltBits,
		PRFProfile: t.PRFProfile, TranscriptMode: t.TranscriptMode, TranscriptOmissionMode: t.TranscriptOmissionMode, FixedTranscriptSize: t.FixedTranscriptSize,
	}
}

func validateFocusedV3TranscriptRuns(target FocusedV3TranscriptReductionTarget, targetBits float64) error {
	if len(target.Runs) != FocusedV3TranscriptReductionRuns {
		return fmt.Errorf("focused-v3 transcript target %s runs=%d want=%d", target.CanonicalID, len(target.Runs), FocusedV3TranscriptReductionRuns)
	}
	runs := append([]FocusedV3TranscriptReductionRun(nil), target.Runs...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].Run < runs[j].Run })
	issueMS, showMS := make([]float64, 0, len(runs)), make([]float64, 0, len(runs))
	rss := make([]uint64, 0, len(runs))
	state, issueWire, showWire, presentation, issuePaper, showPaper := make([]int, 0, len(runs)), make([]int, 0, len(runs)), make([]int, 0, len(runs)), make([]int, 0, len(runs)), make([]int, 0, len(runs)), make([]int, 0, len(runs))
	for i, run := range runs {
		if run.Run != i+1 || !validHexDigest(run.ReportSHA256, 64) || !validHexDigest(run.ResourceSHA256, 64) || run.ArtifactDirectory == "" || run.ReportPath == "" || run.ResourcePath == "" {
			return fmt.Errorf("focused-v3 transcript target %s run %d identity is invalid", target.CanonicalID, run.Run)
		}
		if run.PersistentStateBytes <= 0 || run.PersistentStateBytes > FocusedV3StateByteLimit || run.IssuanceProofWireBytes <= 0 || run.ShowingProofWireBytes <= 0 ||
			run.PresentationWireBytes <= run.ShowingProofWireBytes || run.PaperIssuanceBytes <= 0 || run.PaperShowingBytes <= 0 ||
			run.IssuanceProvingMS <= 0 || run.ShowingProvingMS <= 0 || run.IssuanceVerificationMS <= 0 || run.ShowingVerificationMS <= 0 || run.PeakRSSBytes == 0 {
			return fmt.Errorf("focused-v3 transcript target %s run %d has invalid measurement values", target.CanonicalID, run.Run)
		}
		if run.IssuanceTheoremBits < targetBits || run.ShowingTheoremBits < targetBits || run.ParameterAuditStatus != "pass" ||
			!run.IssuanceZKEligible || !run.ShowingZKEligible || run.IssuanceTranscriptStatus != focusedV3TranscriptLiveStatus ||
			run.ShowingTranscriptStatus != focusedV3TranscriptLiveStatus || !run.ReplayRejected || !run.ApplicableGatesPassed {
			return fmt.Errorf("focused-v3 transcript target %s run %d failed an applicable proof-security gate", target.CanonicalID, run.Run)
		}
		issueMS = append(issueMS, run.IssuanceProvingMS)
		showMS = append(showMS, run.ShowingProvingMS)
		rss = append(rss, run.PeakRSSBytes)
		state = append(state, run.PersistentStateBytes)
		issueWire = append(issueWire, run.IssuanceProofWireBytes)
		showWire = append(showWire, run.ShowingProofWireBytes)
		presentation = append(presentation, run.PresentationWireBytes)
		issuePaper = append(issuePaper, run.PaperIssuanceBytes)
		showPaper = append(showPaper, run.PaperShowingBytes)
	}
	wantMedian := FocusedV3TranscriptReductionMedian{
		PersistentStateBytes: medianInt(state), IssuanceProofWireBytes: medianInt(issueWire), ShowingProofWireBytes: medianInt(showWire), PresentationWireBytes: medianInt(presentation),
		PaperIssuanceBytes: medianInt(issuePaper), PaperShowingBytes: medianInt(showPaper), IssuanceProvingMS: medianFloat(issueMS), ShowingProvingMS: medianFloat(showMS), PeakRSSBytes: medianUint64(rss),
	}
	if !reflect.DeepEqual(target.Medians, wantMedian) {
		return fmt.Errorf("focused-v3 transcript target %s median record is inconsistent", target.CanonicalID)
	}
	prior, after := target.PriorV3, target.Medians
	if after.PersistentStateBytes > prior.PersistentStateBytes || after.IssuanceProofWireBytes >= prior.IssuanceProofWireBytes || after.ShowingProofWireBytes >= prior.ShowingProofWireBytes ||
		after.PresentationWireBytes >= prior.PresentationWireBytes || after.PaperIssuanceBytes >= prior.PaperIssuanceBytes || after.PaperShowingBytes >= prior.PaperShowingBytes {
		return fmt.Errorf("focused-v3 transcript target %s did not improve every proof/transcript size without increasing state", target.CanonicalID)
	}
	if after.IssuanceProvingMS > 2*prior.IssuanceProvingMS || after.ShowingProvingMS > 2*prior.ShowingProvingMS || after.PeakRSSBytes > 2*prior.PeakRSSBytes {
		return fmt.Errorf("focused-v3 transcript target %s exceeds the 2x prior-v3 resource gate", target.CanonicalID)
	}
	return nil
}

// ValidateFocusedV3TranscriptReductionArtifacts checks that the evidence
// record is an exact projection of its immutable prior record and six raw
// report/resource files, rather than a hand-maintained summary.
func ValidateFocusedV3TranscriptReductionArtifacts(e FocusedV3TranscriptReductionEvidence, spruceRoot string) error {
	if err := ValidateFocusedV3TranscriptReductionEvidence(e); err != nil {
		return err
	}
	root, err := filepath.Abs(spruceRoot)
	if err != nil {
		return err
	}
	priorPath, err := focusedV3TranscriptEvidencePath(root, e.PriorEvidence.Path)
	if err != nil {
		return err
	}
	if err := checkFocusedV3TranscriptDigest(priorPath, e.PriorEvidence.SHA256); err != nil {
		return fmt.Errorf("prior-v3 evidence: %w", err)
	}
	priorEvidence, err := ReadFocusedV3SizeEvidence(priorPath)
	if err != nil {
		return err
	}
	for _, target := range e.Targets {
		priorTarget, ok := focusedV3SizeTargetByID(priorEvidence, target.CanonicalID)
		if !ok {
			return fmt.Errorf("prior-v3 evidence missing %s", target.CanonicalID)
		}
		if priorTarget.Medians.PersistentStateBytes != target.PriorV3.PersistentStateBytes || priorTarget.Medians.IssuanceProofWireBytes != target.PriorV3.IssuanceProofWireBytes ||
			priorTarget.Medians.ShowingProofWireBytes != target.PriorV3.ShowingProofWireBytes || priorTarget.Medians.PresentationWireBytes != target.PriorV3.PresentationWireBytes ||
			!closeFloat(priorTarget.Medians.IssuanceProvingMS, target.PriorV3.IssuanceProvingMS) || !closeFloat(priorTarget.Medians.ShowingProvingMS, target.PriorV3.ShowingProvingMS) ||
			priorTarget.Medians.PeakRSSBytes != target.PriorV3.PeakRSSBytes {
			return fmt.Errorf("prior-v3 medians for %s do not match the bound historical record", target.CanonicalID)
		}
		for _, run := range target.Runs {
			if err := validateFocusedV3TranscriptRawRun(root, e, target, run); err != nil {
				return err
			}
		}
	}
	return nil
}

type focusedV3TranscriptRawReport struct {
	Version                  int                                     `json:"version"`
	CanonicalPresetID        string                                  `json:"canonical_preset_id"`
	ClaimScope               credential.ClaimScope                   `json:"claim_scope"`
	CompleteSystemClaim      bool                                    `json:"complete_system_claim"`
	PresetManifestDigest     string                                  `json:"preset_manifest_digest"`
	LedgerStatus             string                                  `json:"ledger_status"`
	FullGameAccountingStatus string                                  `json:"full_game_accounting_status"`
	ProfileBound             int64                                   `json:"profile_bound"`
	Environment              FocusedV3TranscriptReductionEnvironment `json:"environment"`
	Options                  benchmarkOptionsWire                    `json:"options"`
	CanonicalSizes           struct {
		PersistentStateBytes   int `json:"persistent_credential_state_bytes"`
		IssuanceProofWireBytes int `json:"issuance_proof_wire_bytes"`
		ShowingProofWireBytes  int `json:"showing_proof_wire_bytes"`
		PresentationWireBytes  int `json:"presentation_wire_bytes"`
		PaperIssuanceBytes     int `json:"issuance_paper_transcript_bytes"`
		PaperShowingBytes      int `json:"showing_paper_transcript_bytes"`
	} `json:"canonical_sizes"`
	Issuance       benchmarkPhaseWire     `json:"issuance"`
	Showing        benchmarkPhaseWire     `json:"showing"`
	Artifacts      benchmarkArtifactsWire `json:"artifacts"`
	ParameterAudit struct {
		Status string `json:"status"`
	} `json:"parameter_audit"`
	ReplayRejected bool `json:"replay_rejected"`
}

func validateFocusedV3TranscriptRawRun(root string, e FocusedV3TranscriptReductionEvidence, target FocusedV3TranscriptReductionTarget, run FocusedV3TranscriptReductionRun) error {
	reportPath, err := focusedV3TranscriptEvidencePath(root, run.ReportPath)
	if err != nil {
		return err
	}
	resourcePath, err := focusedV3TranscriptEvidencePath(root, run.ResourcePath)
	if err != nil {
		return err
	}
	artifactDir, err := focusedV3TranscriptEvidencePath(root, run.ArtifactDirectory)
	if err != nil {
		return err
	}
	if filepath.Dir(reportPath) != artifactDir || filepath.Dir(resourcePath) != artifactDir {
		return fmt.Errorf("focused-v3 transcript target %s run %d paths escape their artifact directory", target.CanonicalID, run.Run)
	}
	if err := checkFocusedV3TranscriptDigest(reportPath, run.ReportSHA256); err != nil {
		return fmt.Errorf("focused-v3 transcript target %s run %d report: %w", target.CanonicalID, run.Run, err)
	}
	if err := checkFocusedV3TranscriptDigest(resourcePath, run.ResourceSHA256); err != nil {
		return fmt.Errorf("focused-v3 transcript target %s run %d resource: %w", target.CanonicalID, run.Run, err)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return err
	}
	var raw focusedV3TranscriptRawReport
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decode raw focused-v3 transcript report: %w", err)
	}
	if raw.Version != 2 || raw.CanonicalPresetID != target.CanonicalID || raw.PresetManifestDigest != target.ManifestDigest || raw.ClaimScope != credential.ClaimProofOnly || raw.CompleteSystemClaim ||
		raw.LedgerStatus != string(credential.ClaimProofOnly) || raw.FullGameAccountingStatus != "deferred_proof_only" || raw.ProfileBound != 1 || !reflect.DeepEqual(raw.Environment, e.Environment) {
		return fmt.Errorf("focused-v3 transcript target %s run %d report identity/security boundary mismatch", target.CanonicalID, run.Run)
	}
	if focusedV3TranscriptTuningWire(raw.Options.Issuance) != target.Frozen.Issuance || focusedV3TranscriptTuningWire(raw.Options.Showing) != target.Frozen.Showing {
		return fmt.Errorf("focused-v3 transcript target %s run %d changed a frozen parameter", target.CanonicalID, run.Run)
	}
	sizes := raw.CanonicalSizes
	if sizes.PersistentStateBytes != run.PersistentStateBytes || sizes.IssuanceProofWireBytes != run.IssuanceProofWireBytes || sizes.ShowingProofWireBytes != run.ShowingProofWireBytes ||
		sizes.PresentationWireBytes != run.PresentationWireBytes || sizes.PaperIssuanceBytes != run.PaperIssuanceBytes || sizes.PaperShowingBytes != run.PaperShowingBytes ||
		raw.Issuance.ProofSizeBytes != sizes.IssuanceProofWireBytes || raw.Showing.ProofSizeBytes != sizes.ShowingProofWireBytes ||
		raw.Issuance.PaperTranscriptBytes != sizes.PaperIssuanceBytes || raw.Showing.PaperTranscriptBytes != sizes.PaperShowingBytes ||
		raw.Issuance.ProvingMS != run.IssuanceProvingMS || raw.Showing.ProvingMS != run.ShowingProvingMS || raw.Issuance.VerificationMS != run.IssuanceVerificationMS || raw.Showing.VerificationMS != run.ShowingVerificationMS ||
		raw.Issuance.TheoremTotalBits != run.IssuanceTheoremBits || raw.Showing.TheoremTotalBits != run.ShowingTheoremBits {
		return fmt.Errorf("focused-v3 transcript target %s run %d measurement projection mismatch", target.CanonicalID, run.Run)
	}
	if raw.ParameterAudit.Status != run.ParameterAuditStatus || raw.Issuance.ZeroKnowledgeEligible != run.IssuanceZKEligible || raw.Showing.ZeroKnowledgeEligible != run.ShowingZKEligible ||
		raw.Issuance.TranscriptSecurityStatus != run.IssuanceTranscriptStatus || raw.Showing.TranscriptSecurityStatus != run.ShowingTranscriptStatus || raw.ReplayRejected != run.ReplayRejected ||
		!raw.Issuance.PaperShapeCanonical || !raw.Showing.PaperShapeCanonical || !raw.Issuance.FixedTranscriptSize || !raw.Showing.FixedTranscriptSize || raw.Issuance.MeasurementStatus == "" || raw.Showing.MeasurementStatus == "" ||
		raw.Issuance.TheoremTotalBits < 128 || raw.Showing.TheoremTotalBits < 128 || anyTrue(raw.Issuance.Clamped) || anyTrue(raw.Showing.Clamped) || !run.ApplicableGatesPassed {
		return fmt.Errorf("focused-v3 transcript target %s run %d raw proof-security gates failed", target.CanonicalID, run.Run)
	}
	gotGeometry := FocusedV3TranscriptReductionGeometry{
		LogicalRows: raw.Showing.TotalRows, Layers: raw.Showing.RowsBlock, MaskRows: raw.Showing.MaskRows, ReplayRows: raw.Showing.SmallFieldReplayRows,
		PhysicalRows: raw.Showing.PaperShapeNRows, Queries: raw.Showing.PaperShapeQueries, OpeningPColumns: raw.Showing.OpeningCols,
		ParallelDegree: raw.Showing.ParallelAlgDegree, AggregatedDegree: raw.Showing.AggregatedAlgDegree, QDegree: raw.Showing.PaperConservativeDQ,
	}
	if gotGeometry != target.Adopted {
		return fmt.Errorf("focused-v3 transcript target %s run %d geometry mismatch", target.CanonicalID, run.Run)
	}
	statePath, err := focusedV3TranscriptEvidencePath(root, raw.Artifacts.State)
	if err != nil {
		return err
	}
	presentationPath, err := focusedV3TranscriptEvidencePath(root, raw.Artifacts.Presentation)
	if err != nil {
		return err
	}
	stateInfo, err := os.Stat(statePath)
	if err != nil {
		return err
	}
	presentationInfo, err := os.Stat(presentationPath)
	if err != nil {
		return err
	}
	if stateInfo.Size() != int64(run.PersistentStateBytes) || stateInfo.Mode().Perm() != 0o600 || presentationInfo.Size() != int64(run.PresentationWireBytes) {
		return fmt.Errorf("focused-v3 transcript target %s run %d state/presentation artifact mismatch", target.CanonicalID, run.Run)
	}
	rssBytes, err := focusedV3TranscriptResourceRSS(resourcePath)
	if err != nil {
		return err
	}
	if rssBytes != run.PeakRSSBytes {
		return fmt.Errorf("focused-v3 transcript target %s run %d RSS=%d want %d", target.CanonicalID, run.Run, rssBytes, run.PeakRSSBytes)
	}
	return nil
}

func focusedV3TranscriptTuningWire(t benchmarkTuningWire) FocusedV3TranscriptReductionTuning {
	return FocusedV3TranscriptReductionTuning{
		NCols: t.NCols, LVCSNCols: t.LVCSNCols, NLeaves: t.NLeaves, Eta: t.Eta, Theta: t.Theta, Rho: t.Rho, Ell: t.Ell, EllPrime: t.EllPrime,
		Kappa: t.Kappa, ROQueryCaps: t.ROQueryCaps, ROQueryCapBits: t.ROQueryCapBits,
		DECSCollisionBits: t.DECSCollisionBits, DECSHashBits: t.DECSHashBits, DECSTapeBits: t.DECSTapeBits, FSCollisionBits: t.FSCollisionBits, SaltBits: t.SaltBits,
		PRFProfile: t.PRFProfile, TranscriptMode: t.TranscriptMode, TranscriptOmissionMode: t.TranscriptOmissionMode, FixedTranscriptSize: t.FixedTranscriptSize,
	}
}

func focusedV3TranscriptEvidencePath(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("focused-v3 transcript evidence path %q is not relative", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("focused-v3 transcript evidence path %q escapes the repository", rel)
	}
	abs := filepath.Join(root, clean)
	relCheck, err := filepath.Rel(root, abs)
	if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("focused-v3 transcript evidence path %q escapes the repository", rel)
	}
	return abs, nil
}

func checkFocusedV3TranscriptDigest(path, want string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("sha256 mismatch")
	}
	return nil
}

func focusedV3TranscriptResourceRSS(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "maximum resident set size") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			break
		}
		value, parseErr := strconv.ParseUint(fields[0], 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("parse maximum resident set size: %w", parseErr)
		}
		return value, nil
	}
	return 0, fmt.Errorf("resource file %s has no maximum resident set size", path)
}

func focusedV3SizeTargetByID(e FocusedV3SizeEvidence, id string) (FocusedV3TargetEvidence, bool) {
	for _, target := range e.Targets {
		if target.CanonicalID == id {
			return target, true
		}
	}
	return FocusedV3TargetEvidence{}, false
}

func validHexDigest(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func anyTrue(values [4]bool) bool {
	for _, value := range values {
		if value {
			return true
		}
	}
	return false
}
