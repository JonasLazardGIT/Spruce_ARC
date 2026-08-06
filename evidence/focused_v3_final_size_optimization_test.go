package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

type finalSizeOptimizationEvidence struct {
	Schema                   string                 `json:"schema"`
	Version                  int                    `json:"version"`
	MeasuredOn               string                 `json:"measured_on"`
	ClaimScope               string                 `json:"claim_scope"`
	ImplementationBaseCommit string                 `json:"implementation_base_commit"`
	SourceTreeDigest         string                 `json:"source_tree_digest"`
	Paper                    finalSizePaperBoundary `json:"paper_repository"`
	Protocol                 finalSizeProtocol      `json:"protocol"`
	Targets                  []finalSizeTarget      `json:"targets"`
}

type finalSizePaperBoundary struct {
	HeadBefore  string `json:"head_before"`
	HeadAfter   string `json:"head_after"`
	CleanBefore bool   `json:"clean_before"`
	CleanAfter  bool   `json:"clean_after"`
}

type finalSizeProtocol struct {
	ProofSchemaVersion         int    `json:"proof_schema_version"`
	CanonicalProofCodecVersion int    `json:"canonical_proof_codec_version"`
	CanonicalProofCodecProfile string `json:"canonical_proof_codec_profile"`
	MerkleTopology             string `json:"merkle_topology"`
	MerkleWire                 string `json:"merkle_wire"`
}

type finalSizeShortness struct {
	Radix          int   `json:"radix"`
	Digits         int   `json:"digits"`
	Capacity       int64 `json:"capacity"`
	SignatureBound int64 `json:"signature_bound"`
}

type finalSizeGeometry struct {
	LogicalRows      int `json:"logical_rows"`
	Layers           int `json:"layers"`
	ParallelDegree   int `json:"parallel_degree"`
	AggregatedDegree int `json:"aggregated_degree"`
	QDegree          int `json:"q_degree"`
	MaskRows         int `json:"mask_rows"`
	ReplayRows       int `json:"replay_rows"`
	PhysicalRows     int `json:"physical_rows"`
	Queries          int `json:"queries"`
	OpeningPColumns  int `json:"opening_p_columns"`
}

type finalSizeMetrics struct {
	StateBytes         int     `json:"state_bytes"`
	IssuanceProofBytes int     `json:"issuance_proof_bytes"`
	ShowingProofBytes  int     `json:"showing_proof_bytes"`
	PresentationBytes  int     `json:"presentation_bytes"`
	IssuancePaperBytes int     `json:"issuance_paper_bytes"`
	ShowingPaperBytes  int     `json:"showing_paper_bytes"`
	IssuanceProvingMS  float64 `json:"issuance_proving_ms"`
	ShowingProvingMS   float64 `json:"showing_proving_ms"`
	PeakRSSBytes       uint64  `json:"peak_rss_bytes"`
}

type finalSizeRun struct {
	Run                 int     `json:"run"`
	ReportPath          string  `json:"report_path"`
	ReportSHA256        string  `json:"report_sha256"`
	ResourcePath        string  `json:"resource_path"`
	ResourceSHA256      string  `json:"resource_sha256"`
	StateBytes          int     `json:"state_bytes"`
	IssuanceProofBytes  int     `json:"issuance_proof_bytes"`
	ShowingProofBytes   int     `json:"showing_proof_bytes"`
	PresentationBytes   int     `json:"presentation_bytes"`
	IssuancePaperBytes  int     `json:"issuance_paper_bytes"`
	ShowingPaperBytes   int     `json:"showing_paper_bytes"`
	IssuanceProvingMS   float64 `json:"issuance_proving_ms"`
	ShowingProvingMS    float64 `json:"showing_proving_ms"`
	PeakRSSBytes        uint64  `json:"peak_rss_bytes"`
	IssuanceAuthNodes   int     `json:"issuance_auth_nodes"`
	ShowingAuthNodes    int     `json:"showing_auth_nodes"`
	ParameterAudit      string  `json:"parameter_audit"`
	ReplayRejected      bool    `json:"replay_rejected"`
	IssuanceZK          bool    `json:"issuance_zk"`
	ShowingZK           bool    `json:"showing_zk"`
	IssuanceTheoremBits float64 `json:"issuance_theorem_bits"`
	ShowingTheoremBits  float64 `json:"showing_theorem_bits"`
}

type finalSizeTarget struct {
	CanonicalID        string             `json:"canonical_id"`
	ManifestDigest     string             `json:"manifest_digest"`
	Kappa              [4]int             `json:"kappa"`
	SignatureShortness finalSizeShortness `json:"signature_shortness"`
	ShowingGeometry    finalSizeGeometry  `json:"showing_geometry"`
	AcceptedCodec5     finalSizeMetrics   `json:"accepted_codec5"`
	Medians            finalSizeMetrics   `json:"medians"`
	Runs               []finalSizeRun     `json:"runs"`
}

func TestFocusedV3FinalSizeOptimizationEvidence(t *testing.T) {
	data, err := os.ReadFile("focused-v3-final-size-optimization.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidence finalSizeOptimizationEvidence
	if err := decodeStrictJSON(data, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Schema != "spruce.focused-v3-final-size-optimization" || evidence.Version != 1 || evidence.ClaimScope != string(credential.ClaimProofOnly) ||
		!validHexDigest(evidence.ImplementationBaseCommit, 40) || !validHexDigest(evidence.SourceTreeDigest, 64) {
		t.Fatalf("invalid final-size evidence boundary: %+v", evidence)
	}
	if evidence.Paper.HeadBefore != evidence.Paper.HeadAfter || !validHexDigest(evidence.Paper.HeadBefore, 40) || !evidence.Paper.CleanBefore || !evidence.Paper.CleanAfter {
		t.Fatalf("paper tree was not held read-only and clean: %+v", evidence.Paper)
	}
	wantProtocol := finalSizeProtocol{
		ProofSchemaVersion:         PIOP.ProofSchemaVersionV3,
		CanonicalProofCodecVersion: PIOP.CanonicalProofCodecVersionV6,
		CanonicalProofCodecProfile: PIOP.CanonicalProofCodecProfileV6,
		MerkleTopology:             decs.MerkleTopologyExactNV3,
		MerkleWire:                 "exact-tail-frontier-unpadded-v1",
	}
	if evidence.Protocol != wantProtocol || len(evidence.Targets) != 2 {
		t.Fatalf("unexpected protocol/target count: %+v", evidence.Protocol)
	}

	wantGeometry := map[string]finalSizeGeometry{
		credential.IntGenISISPresetPoCN1024BQ128R128V3:    {423, 10, 11, 8, 570, 195, 450, 645, 143, 502},
		credential.IntGenISISPresetSystemN1024WF128CROMV2: {423, 11, 11, 8, 471, 91, 429, 520, 84, 436},
	}
	seen := make(map[string]bool, 2)
	for _, target := range evidence.Targets {
		preset, ok := credential.LookupIntGenISISPreset(target.CanonicalID)
		if !ok || seen[target.CanonicalID] {
			t.Fatalf("unknown/duplicate target %q", target.CanonicalID)
		}
		seen[target.CanonicalID] = true
		if target.ManifestDigest != credential.IntGenISISPresetManifestDigest(preset) || target.Kappa != preset.Showing.Kappa || target.Kappa != preset.Issuance.Kappa {
			t.Fatalf("target %s does not bind current manifest/kappa", target.CanonicalID)
		}
		if target.SignatureShortness != (finalSizeShortness{11, 4, 7320, 6142}) || target.ShowingGeometry != wantGeometry[target.CanonicalID] {
			t.Fatalf("target %s shortness/geometry mismatch: %+v %+v", target.CanonicalID, target.SignatureShortness, target.ShowingGeometry)
		}
		validateFinalSizeRuns(t, target)
	}
	for id := range wantGeometry {
		if !seen[id] {
			t.Fatalf("missing target %s", id)
		}
	}
}

func validateFinalSizeRuns(t *testing.T, target finalSizeTarget) {
	t.Helper()
	if len(target.Runs) != 3 {
		t.Fatalf("%s runs=%d want 3", target.CanonicalID, len(target.Runs))
	}
	states, issueWire, showWire, presentations := []int{}, []int{}, []int{}, []int{}
	issuePaper, showPaper := []int{}, []int{}
	issueMS, showMS := []float64{}, []float64{}
	rss := []uint64{}
	for i, run := range target.Runs {
		if run.Run != i+1 || !validHexDigest(run.ReportSHA256, 64) || !validHexDigest(run.ResourceSHA256, 64) ||
			run.ParameterAudit != "pass" || !run.ReplayRejected || !run.IssuanceZK || !run.ShowingZK ||
			run.IssuanceTheoremBits < 128 || run.ShowingTheoremBits < 128 || run.IssuanceAuthNodes <= 0 || run.ShowingAuthNodes <= 0 {
			t.Fatalf("%s invalid run %d: %+v", target.CanonicalID, i+1, run)
		}
		if run.IssuanceProvingMS > 2*target.AcceptedCodec5.IssuanceProvingMS || run.ShowingProvingMS > 2*target.AcceptedCodec5.ShowingProvingMS || run.PeakRSSBytes > 2*target.AcceptedCodec5.PeakRSSBytes {
			t.Fatalf("%s run %d exceeds 2x accepted codec-v5 resources", target.CanonicalID, run.Run)
		}
		states = append(states, run.StateBytes)
		issueWire = append(issueWire, run.IssuanceProofBytes)
		showWire = append(showWire, run.ShowingProofBytes)
		presentations = append(presentations, run.PresentationBytes)
		issuePaper = append(issuePaper, run.IssuancePaperBytes)
		showPaper = append(showPaper, run.ShowingPaperBytes)
		issueMS = append(issueMS, run.IssuanceProvingMS)
		showMS = append(showMS, run.ShowingProvingMS)
		rss = append(rss, run.PeakRSSBytes)
		validateFinalSizeRawArtifactsIfPresent(t, target, run)
	}
	wantMedian := finalSizeMetrics{
		medianInt(states), medianInt(issueWire), medianInt(showWire), medianInt(presentations), medianInt(issuePaper), medianInt(showPaper),
		medianFloat(issueMS), medianFloat(showMS), medianUint64(rss),
	}
	if !reflect.DeepEqual(target.Medians, wantMedian) {
		t.Fatalf("%s medians=%+v want %+v", target.CanonicalID, target.Medians, wantMedian)
	}
	if target.Medians.StateBytes > target.AcceptedCodec5.StateBytes || target.Medians.IssuanceProofBytes >= target.AcceptedCodec5.IssuanceProofBytes ||
		target.Medians.ShowingProofBytes >= target.AcceptedCodec5.ShowingProofBytes || target.Medians.PresentationBytes >= target.AcceptedCodec5.PresentationBytes ||
		target.Medians.IssuancePaperBytes > target.AcceptedCodec5.IssuancePaperBytes || target.Medians.ShowingPaperBytes > target.AcceptedCodec5.ShowingPaperBytes ||
		target.Medians.IssuanceProvingMS > 2*target.AcceptedCodec5.IssuanceProvingMS || target.Medians.ShowingProvingMS > 2*target.AcceptedCodec5.ShowingProvingMS || target.Medians.PeakRSSBytes > 2*target.AcceptedCodec5.PeakRSSBytes {
		t.Fatalf("%s did not satisfy size/resource adoption gates", target.CanonicalID)
	}
}

func validateFinalSizeRawArtifactsIfPresent(t *testing.T, target finalSizeTarget, run finalSizeRun) {
	t.Helper()
	reportPath := filepath.Join("..", filepath.FromSlash(run.ReportPath))
	resourcePath := filepath.Join("..", filepath.FromSlash(run.ResourcePath))
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		return
	} else if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{reportPath: run.ReportSHA256, resourcePath: run.ResourceSHA256} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != want {
			t.Fatalf("artifact digest mismatch for %s", path)
		}
	}
	var raw struct {
		CanonicalPresetID    string `json:"canonical_preset_id"`
		PresetManifestDigest string `json:"preset_manifest_digest"`
		ReplayRejected       bool   `json:"replay_rejected"`
		CanonicalSizes       struct {
			State        int `json:"persistent_credential_state_bytes"`
			IssueProof   int `json:"issuance_proof_wire_bytes"`
			ShowProof    int `json:"showing_proof_wire_bytes"`
			Presentation int `json:"presentation_wire_bytes"`
			IssuePaper   int `json:"issuance_paper_transcript_bytes"`
			ShowPaper    int `json:"showing_paper_transcript_bytes"`
		} `json:"canonical_sizes"`
		Issuance struct {
			Audit PIOP.CanonicalProofWireAuditV6 `json:"canonical_wire_audit"`
		} `json:"issuance"`
		Showing struct {
			Audit PIOP.CanonicalProofWireAuditV6 `json:"canonical_wire_audit"`
		} `json:"showing"`
	}
	data, err := os.ReadFile(reportPath)
	if err != nil || json.Unmarshal(data, &raw) != nil {
		t.Fatalf("decode raw report %s: %v", reportPath, err)
	}
	if raw.CanonicalPresetID != target.CanonicalID || raw.PresetManifestDigest != target.ManifestDigest || !raw.ReplayRejected ||
		raw.CanonicalSizes.State != run.StateBytes || raw.CanonicalSizes.IssueProof != run.IssuanceProofBytes || raw.CanonicalSizes.ShowProof != run.ShowingProofBytes ||
		raw.CanonicalSizes.Presentation != run.PresentationBytes || raw.CanonicalSizes.IssuePaper != run.IssuancePaperBytes || raw.CanonicalSizes.ShowPaper != run.ShowingPaperBytes {
		t.Fatalf("raw report projection mismatch for %s run %d", target.CanonicalID, run.Run)
	}
	for phase, audit := range map[string]PIOP.CanonicalProofWireAuditV6{"issuance": raw.Issuance.Audit, "showing": raw.Showing.Audit} {
		wantNodes := run.IssuanceAuthNodes
		if phase == "showing" {
			wantNodes = run.ShowingAuthNodes
		}
		if audit.CodecVersion != PIOP.CanonicalProofCodecVersionV6 || audit.CodecProfile != PIOP.CanonicalProofCodecProfileV6 ||
			audit.MerklePaddingNodes != 0 || audit.MerkleNodesUsed != wantNodes || audit.MerkleNodesUsed > audit.MerkleNodesBound ||
			audit.AuthenticationBytes != audit.MerkleNodesUsed*audit.RootBytes {
			t.Fatalf("%s %s exact-frontier audit mismatch: %+v", target.CanonicalID, phase, audit)
		}
	}
}
