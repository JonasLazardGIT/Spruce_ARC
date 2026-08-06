package evidence

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"vSIS-Signature/credential"
)

const (
	FocusedV3SizeEvidenceSchema  = "spruce.focused-v3-size-optimization"
	FocusedV3SizeEvidenceVersion = 1
	FocusedV3RunCount            = 3
	FocusedV3StateByteLimit      = 5*1024 + 256 // 5.25 KiB
)

// FocusedV3SizeEvidence is the reviewed, target-only measurement record for
// BQ128/WF128. The seven historical-v2 presets remain in ArtifactLock v2 and
// are intentionally absent here.
type FocusedV3SizeEvidence struct {
	Schema         string                     `json:"schema"`
	Version        int                        `json:"version"`
	MeasuredOn     string                     `json:"measured_on"`
	ClaimScope     string                     `json:"claim_scope"`
	BaselineCommit string                     `json:"baseline_commit"`
	Paper          FocusedV3PaperTreeEvidence `json:"paper_repository"`
	Targets        []FocusedV3TargetEvidence  `json:"targets"`
}

type FocusedV3PaperTreeEvidence struct {
	HeadBefore  string `json:"head_before"`
	CleanBefore bool   `json:"clean_before"`
	HeadAfter   string `json:"head_after"`
	CleanAfter  bool   `json:"clean_after"`
}

type FocusedV3TargetEvidence struct {
	CanonicalID    string                    `json:"canonical_id"`
	ManifestDigest string                    `json:"manifest_digest"`
	Kappa          [4]int                    `json:"kappa"`
	Baseline       FocusedV3BaselineEvidence `json:"baseline"`
	Adopted        FocusedV3AdoptedEvidence  `json:"adopted"`
	Runs           []FocusedV3RunEvidence    `json:"runs"`
	Medians        FocusedV3MedianEvidence   `json:"medians"`
}

type FocusedV3BaselineEvidence struct {
	PersistentCompactJSONBytes int     `json:"persistent_compact_json_bytes"`
	ModeledIssuanceBytes       int     `json:"modeled_issuance_verifier_message_bytes"`
	ModeledShowingBytes        int     `json:"modeled_showing_verifier_message_bytes"`
	PaperIssuanceBytes         int     `json:"paper_issuance_bytes"`
	PaperShowingBytes          int     `json:"paper_showing_bytes"`
	ShowingLogicalRows         int     `json:"showing_logical_rows"`
	IssuanceProvingMS          float64 `json:"median_issuance_proving_ms"`
	ShowingProvingMS           float64 `json:"median_showing_proving_ms"`
	PeakRSSBytes               uint64  `json:"median_peak_rss_bytes"`
}

type FocusedV3AdoptedEvidence struct {
	IssuanceLVCSNCols  int `json:"issuance_lvcs_ncols"`
	ShowingLVCSNCols   int `json:"showing_lvcs_ncols"`
	NLeaves            int `json:"nleaves"`
	Eta                int `json:"eta"`
	Theta              int `json:"theta"`
	Ell                int `json:"ell"`
	ShowingLogicalRows int `json:"showing_logical_rows"`
	ShowingLayers      int `json:"showing_layers"`
	ShowingMaskRows    int `json:"showing_mask_rows"`
	ShowingOpeningRows int `json:"showing_opening_rows"`
	ParallelDegree     int `json:"showing_parallel_degree"`
	AggregatedDegree   int `json:"showing_aggregated_degree"`
}

type FocusedV3RunEvidence struct {
	Run                      int     `json:"run"`
	ReportSHA256             string  `json:"report_sha256"`
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
	Verified                 bool    `json:"verified"`
	ReplayRejected           bool    `json:"replay_rejected"`
	ZeroKnowledgeEligible    bool    `json:"zero_knowledge_eligible"`
	TranscriptSecurityStatus string  `json:"transcript_security_status"`
}

type FocusedV3MedianEvidence struct {
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

// focusedV3HistoricalManifestDigest returns the manifest bound by the first
// two strict-v3 evidence epochs.  Those JSON records are immutable historical
// measurements: later relation/layout epochs deliberately change the live
// manifest digest and must not make an older record appear corrupt.  A new
// evidence epoch is responsible for binding the current manifest.
func focusedV3HistoricalManifestDigest(id string) (string, bool) {
	switch id {
	case credential.IntGenISISPresetPoCN1024BQ128R128V3:
		return "1a3e05201fa7dc6b8695ee8b41dc1ad7197b80a547e693fae21e8a959a3c687b", true
	case credential.IntGenISISPresetSystemN1024WF128CROMV2:
		return "5708b4fb21021410378dae050a78e0da00659f7f35fb6a5f857f8fa3fa0b79fc", true
	default:
		return "", false
	}
}

func focusedV3ExpectedAdopted(id string) (FocusedV3AdoptedEvidence, bool) {
	switch id {
	case credential.IntGenISISPresetPoCN1024BQ128R128V3:
		return FocusedV3AdoptedEvidence{
			IssuanceLVCSNCols: 43, ShowingLVCSNCols: 43,
			NLeaves: 688128, Eta: 59, Theta: 13, Ell: 18,
			ShowingLogicalRows: 551, ShowingLayers: 13,
			ShowingMaskRows: 156, ShowingOpeningRows: 741,
			ParallelDegree: 9, AggregatedDegree: 8,
		}, true
	case credential.IntGenISISPresetSystemN1024WF128CROMV2:
		return FocusedV3AdoptedEvidence{
			IssuanceLVCSNCols: 42, ShowingLVCSNCols: 41,
			NLeaves: 327680, Eta: 43, Theta: 7, Ell: 9,
			ShowingLogicalRows: 487, ShowingLayers: 12,
			ShowingMaskRows: 91, ShowingOpeningRows: 559,
			ParallelDegree: 11, AggregatedDegree: 8,
		}, true
	default:
		return FocusedV3AdoptedEvidence{}, false
	}
}

func ReadFocusedV3SizeEvidence(path string) (FocusedV3SizeEvidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FocusedV3SizeEvidence{}, err
	}
	var out FocusedV3SizeEvidence
	if err := decodeStrictJSON(data, &out); err != nil {
		return FocusedV3SizeEvidence{}, fmt.Errorf("decode focused-v3 size evidence: %w", err)
	}
	return out, nil
}

func ValidateFocusedV3SizeEvidence(e FocusedV3SizeEvidence) error {
	if e.Schema != FocusedV3SizeEvidenceSchema || e.Version != FocusedV3SizeEvidenceVersion {
		return fmt.Errorf("focused-v3 evidence identity=(%q,v%d)", e.Schema, e.Version)
	}
	if e.ClaimScope != string(credential.ClaimProofOnly) {
		return fmt.Errorf("focused-v3 evidence claim scope=%q", e.ClaimScope)
	}
	if len(e.BaselineCommit) != 40 || len(e.Paper.HeadBefore) != 40 || e.Paper.HeadBefore != e.Paper.HeadAfter || !e.Paper.CleanBefore || !e.Paper.CleanAfter {
		return fmt.Errorf("focused-v3 source/paper revision boundary is incomplete")
	}
	if len(e.Targets) != len(focusedV3TargetPresetIDs) {
		return fmt.Errorf("focused-v3 evidence targets=%d want=%d", len(e.Targets), len(focusedV3TargetPresetIDs))
	}
	seen := make(map[string]bool, len(e.Targets))
	for _, target := range e.Targets {
		preset, ok := credential.LookupIntGenISISPreset(target.CanonicalID)
		if !ok || !isFocusedV3TargetPresetID(target.CanonicalID) || seen[target.CanonicalID] {
			return fmt.Errorf("invalid or duplicate focused-v3 target %q", target.CanonicalID)
		}
		seen[target.CanonicalID] = true
		if err := ValidateFocusedV3TargetPreset(preset); err != nil {
			return err
		}
		historicalManifest, manifestOK := focusedV3HistoricalManifestDigest(target.CanonicalID)
		if !manifestOK || target.ManifestDigest != historicalManifest || target.Kappa != preset.Showing.Kappa || target.Kappa != preset.Issuance.Kappa {
			return fmt.Errorf("focused-v3 target %s manifest/kappa mismatch", target.CanonicalID)
		}
		expectedAdopted, ok := focusedV3ExpectedAdopted(target.CanonicalID)
		if !ok || target.Adopted != expectedAdopted {
			return fmt.Errorf("focused-v3 target %s adopted compiled geometry differs from the reviewed target", target.CanonicalID)
		}
		if target.Adopted.IssuanceLVCSNCols != preset.Issuance.LVCSNCols || target.Adopted.ShowingLVCSNCols != preset.Showing.LVCSNCols ||
			target.Adopted.NLeaves != preset.Showing.NLeaves || target.Adopted.Eta != preset.Showing.Eta || target.Adopted.Theta != preset.Showing.Theta || target.Adopted.Ell != preset.Showing.Ell {
			return fmt.Errorf("focused-v3 target %s adopted tuple differs from manifest", target.CanonicalID)
		}
		if len(target.Runs) != FocusedV3RunCount {
			return fmt.Errorf("focused-v3 target %s runs=%d want=%d", target.CanonicalID, len(target.Runs), FocusedV3RunCount)
		}
		if err := validateFocusedV3Runs(target); err != nil {
			return err
		}
	}
	for _, id := range focusedV3TargetPresetIDs {
		if !seen[id] {
			return fmt.Errorf("focused-v3 evidence missing %s", id)
		}
	}
	return nil
}

func validateFocusedV3Runs(target FocusedV3TargetEvidence) error {
	runs := append([]FocusedV3RunEvidence(nil), target.Runs...)
	sort.Slice(runs, func(i, j int) bool { return runs[i].Run < runs[j].Run })
	issueMS := make([]float64, 0, len(runs))
	showMS := make([]float64, 0, len(runs))
	rss := make([]uint64, 0, len(runs))
	stateWire := make([]int, 0, len(runs))
	issueWire := make([]int, 0, len(runs))
	showWire := make([]int, 0, len(runs))
	presentationWire := make([]int, 0, len(runs))
	issuePaper := make([]int, 0, len(runs))
	showPaper := make([]int, 0, len(runs))
	for i, run := range runs {
		if run.Run != i+1 || len(run.ReportSHA256) != 64 || len(run.ResourceSHA256) != 64 ||
			!run.Verified || !run.ReplayRejected || !run.ZeroKnowledgeEligible ||
			run.TranscriptSecurityStatus != "smallwood_2025_1085_salted_tapes_v3_live" {
			return fmt.Errorf("focused-v3 target %s run %d failed identity/security checks", target.CanonicalID, run.Run)
		}
		if strings.Trim(run.ReportSHA256+run.ResourceSHA256, "0123456789abcdef") != "" {
			return fmt.Errorf("focused-v3 target %s run %d has a non-hex digest", target.CanonicalID, run.Run)
		}
		if run.PersistentStateBytes <= 0 || run.PersistentStateBytes > FocusedV3StateByteLimit ||
			run.IssuanceProofWireBytes <= 0 || run.ShowingProofWireBytes <= 0 || run.PresentationWireBytes <= run.ShowingProofWireBytes ||
			run.PaperIssuanceBytes <= 0 || run.PaperShowingBytes <= 0 || run.IssuanceTheoremBits < 128 || run.ShowingTheoremBits < 128 {
			return fmt.Errorf("focused-v3 target %s run %d failed size/theorem checks", target.CanonicalID, run.Run)
		}
		issueMS = append(issueMS, run.IssuanceProvingMS)
		showMS = append(showMS, run.ShowingProvingMS)
		rss = append(rss, run.PeakRSSBytes)
		stateWire = append(stateWire, run.PersistentStateBytes)
		issueWire = append(issueWire, run.IssuanceProofWireBytes)
		showWire = append(showWire, run.ShowingProofWireBytes)
		presentationWire = append(presentationWire, run.PresentationWireBytes)
		issuePaper = append(issuePaper, run.PaperIssuanceBytes)
		showPaper = append(showPaper, run.PaperShowingBytes)
	}
	if target.Medians.PersistentStateBytes != medianInt(stateWire) || target.Medians.IssuanceProofWireBytes != medianInt(issueWire) ||
		target.Medians.ShowingProofWireBytes != medianInt(showWire) || target.Medians.PresentationWireBytes != medianInt(presentationWire) ||
		target.Medians.PaperIssuanceBytes != medianInt(issuePaper) || target.Medians.PaperShowingBytes != medianInt(showPaper) ||
		!closeFloat(target.Medians.IssuanceProvingMS, medianFloat(issueMS)) || !closeFloat(target.Medians.ShowingProvingMS, medianFloat(showMS)) ||
		target.Medians.PeakRSSBytes != medianUint64(rss) {
		return fmt.Errorf("focused-v3 target %s median record is inconsistent", target.CanonicalID)
	}
	if target.Medians.IssuanceProvingMS > 2*target.Baseline.IssuanceProvingMS ||
		target.Medians.ShowingProvingMS > 2*target.Baseline.ShowingProvingMS ||
		target.Medians.PeakRSSBytes > 2*target.Baseline.PeakRSSBytes {
		return fmt.Errorf("focused-v3 target %s exceeds the 2x resource gate", target.CanonicalID)
	}
	return nil
}

func medianInt(values []int) int {
	v := append([]int(nil), values...)
	sort.Ints(v)
	return v[len(v)/2]
}

func medianFloat(values []float64) float64 {
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	return v[len(v)/2]
}

func medianUint64(values []uint64) uint64 {
	v := append([]uint64(nil), values...)
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[len(v)/2]
}

func closeFloat(left, right float64) bool {
	return math.Abs(left-right) <= 0.0005
}
