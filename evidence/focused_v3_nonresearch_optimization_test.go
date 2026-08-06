package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/sourceintegrity"
)

func testFocusedV3NonResearchEvidence(t *testing.T) FocusedV3NonResearchOptimizationEvidence {
	t.Helper()
	digest := strings.Repeat("a", 64)
	e := FocusedV3NonResearchOptimizationEvidence{
		Schema: FocusedV3NonResearchOptimizationSchema, Version: FocusedV3NonResearchOptimizationVersion,
		MeasuredOn: "2026-08-04", ClaimScope: string(credential.ClaimProofOnly), ImplementationBaseCommit: strings.Repeat("b", 40),
		Environment: FocusedV3NonResearchEnvironment{
			GoVersion: "go1.23.12", GOOS: "darwin", GOARCH: "arm64", NumCPU: 15, GOMAXPROCS: 15,
			VCS: "git", Commit: strings.Repeat("b", 40), CommitTime: "2026-08-03T17:20:12Z", Modified: true,
			SourceTreeAlgorithm: sourceintegrity.Algorithm, SourceTreeDigest: digest, SourceTreeFileCount: 123,
		},
		PriorEvidence: FocusedV3TranscriptReductionPriorSource{Path: focusedV3NonResearchPriorPath, SHA256: digest},
		Paper:         FocusedV3PaperTreeEvidence{HeadBefore: strings.Repeat("c", 40), CleanBefore: true, HeadAfter: strings.Repeat("c", 40), CleanAfter: true},
	}
	for _, id := range focusedV3TargetPresetIDs {
		preset, ok := credential.LookupIntGenISISPreset(id)
		if !ok {
			t.Fatalf("missing target preset %s", id)
		}
		prior, issueGeometry, showGeometry, issuePaper, showPaper, ok := focusedV3NonResearchExpectedTarget(id)
		if !ok {
			t.Fatalf("missing target expectations %s", id)
		}
		epochPreset := preset
		epochManifest := credential.IntGenISISPresetManifestDigest(epochPreset)
		if id == credential.IntGenISISPresetPoCN1024BQ128R128V3 {
			epochPreset.Showing.SigShortnessRadix = 7
			epochPreset.Showing.SigShortnessDigits = 5
			epochManifest = "f08dc90c5e319dfd667a4b960050aa2f0932eb2353a528c280299354452d3a08"
		}
		target := FocusedV3NonResearchTarget{
			CanonicalID: id, ManifestDigest: epochManifest, Kappa: epochPreset.Issuance.Kappa, PriorAccepted: prior,
			Frozen:   FocusedV3NonResearchFrozen{Issuance: focusedV3NonResearchTuning(epochPreset.Issuance), Showing: focusedV3NonResearchTuning(epochPreset.Showing)},
			Protocol: focusedV3NonResearchProtocol(), IssuanceGeometry: issueGeometry, ShowingGeometry: showGeometry,
		}
		overhead := 33
		if id == credential.IntGenISISPresetSystemN1024WF128CROMV2 {
			overhead = 41
		}
		for runNumber := 1; runNumber <= 3; runNumber++ {
			issueWire := prior.IssuanceProofWireBytes - 1000 + runNumber
			showWire := prior.ShowingProofWireBytes - 100 + runNumber
			alias, ok := focusedV3NonResearchTargetAlias(id)
			if !ok {
				t.Fatalf("missing target alias %s", id)
			}
			base := focusedV3NonResearchArtifactRoot + "/" + alias + "/run-" + string(rune('0'+runNumber))
			files := make([]FocusedV3NonResearchFileDigest, 0, len(focusedV3NonResearchArtifactPaths(base)))
			for _, item := range focusedV3NonResearchArtifactPaths(base) {
				files = append(files, FocusedV3NonResearchFileDigest{Role: item.role, Path: item.path, Bytes: 1, SHA256: digest})
			}
			target.Runs = append(target.Runs, FocusedV3NonResearchRun{
				Run: runNumber, ArtifactDirectory: base, ReportPath: base + "/report.json", ReportSHA256: digest, ResourcePath: base + "/resource.txt", ResourceSHA256: digest,
				Artifacts: FocusedV3NonResearchArtifactProjection{
					StatePath: base + "/credential_state.intgenisis.v8", StateSHA256: digest, SubmissionPath: base + "/presign_submission.json", SubmissionSHA256: digest,
					IssuanceProofSHA256: digest, PresentationPath: base + "/presentation.intgenisis.v3", PresentationSHA256: digest, ShowingProofSHA256: digest, Files: files,
				},
				PersistentStateBytes: prior.PersistentStateBytes, IssuanceProofWireBytes: issueWire, ShowingProofWireBytes: showWire, PresentationWireBytes: showWire + overhead,
				PaperIssuanceBytes: issuePaper, PaperShowingBytes: showPaper, IssuanceProvingMS: prior.IssuanceProvingMS / 2, ShowingProvingMS: prior.ShowingProvingMS / 2,
				IssuanceVerificationMS: 1, ShowingVerificationMS: 1, PeakRSSBytes: prior.PeakRSSBytes, IssuanceTheoremBits: 130, ShowingTheoremBits: 130,
				ParameterAuditStatus: "pass", IssuanceZKEligible: true, ShowingZKEligible: true, ReplayRejected: true,
			})
		}
		target.Medians = FocusedV3NonResearchMedian{
			PersistentStateBytes:   prior.PersistentStateBytes,
			IssuanceProofWireBytes: target.Runs[1].IssuanceProofWireBytes, ShowingProofWireBytes: target.Runs[1].ShowingProofWireBytes, PresentationWireBytes: target.Runs[1].PresentationWireBytes,
			PaperIssuanceBytes: issuePaper, PaperShowingBytes: showPaper, IssuanceProvingMS: prior.IssuanceProvingMS / 2, ShowingProvingMS: prior.ShowingProvingMS / 2, PeakRSSBytes: prior.PeakRSSBytes,
		}
		e.Targets = append(e.Targets, target)
	}
	return e
}

func TestFocusedV3NonResearchEvidenceContract(t *testing.T) {
	e := testFocusedV3NonResearchEvidence(t)
	if err := ValidateFocusedV3NonResearchOptimizationEvidence(e); err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name   string
		mutate func(*FocusedV3NonResearchOptimizationEvidence)
	}{
		{"codec epoch", func(e *FocusedV3NonResearchOptimizationEvidence) {
			e.Targets[0].Protocol.CanonicalProofCodecVersion = 3
		}},
		{"live manifest", func(e *FocusedV3NonResearchOptimizationEvidence) {
			e.Targets[0].ManifestDigest = strings.Repeat("d", 64)
		}},
		{"source snapshot", func(e *FocusedV3NonResearchOptimizationEvidence) {
			e.Environment.SourceTreeAlgorithm = "untrusted"
		}},
		{"issuance geometry", func(e *FocusedV3NonResearchOptimizationEvidence) { e.Targets[0].IssuanceGeometry.LogicalRows++ }},
		{"exact run count", func(e *FocusedV3NonResearchOptimizationEvidence) { e.Targets[0].Runs = e.Targets[0].Runs[:2] }},
		{"frozen compression", func(e *FocusedV3NonResearchOptimizationEvidence) { e.Targets[0].Frozen.Issuance.CompressedRows = 0 }},
		{"resource gate", func(e *FocusedV3NonResearchOptimizationEvidence) {
			p := e.Targets[0].PriorAccepted.IssuanceProvingMS
			for i := range e.Targets[0].Runs {
				e.Targets[0].Runs[i].IssuanceProvingMS = 2*p + 1
			}
			e.Targets[0].Medians.IssuanceProvingMS = 2*p + 1
		}},
		{"single-run resource gate", func(e *FocusedV3NonResearchOptimizationEvidence) {
			e.Targets[0].Runs[0].PeakRSSBytes = 2*e.Targets[0].PriorAccepted.PeakRSSBytes + 1
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			mutated := testFocusedV3NonResearchEvidence(t)
			tc.mutate(&mutated)
			if err := ValidateFocusedV3NonResearchOptimizationEvidence(mutated); err == nil {
				t.Fatal("mutation was accepted")
			}
		})
	}
}

// The summary contract is hermetic and always checked once its tracked JSON
// exists. Raw benchmark bundles live under ignored artifacts/; when present,
// this test upgrades to the complete local digest/artifact gate. The
// focused-v3-nonresearch CLI always requires and validates the full bundle.
func TestFocusedV3NonResearchOptimizationEvidenceFile(t *testing.T) {
	path := filepath.Join("focused-v3-nonresearch-optimization.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("focused-v3 non-research evidence awaits six accepted runs")
	} else if err != nil {
		t.Fatal(err)
	}
	e, err := ReadFocusedV3NonResearchOptimizationEvidence(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFocusedV3NonResearchOptimizationEvidence(e); err != nil {
		t.Fatal(err)
	}
	for _, target := range e.Targets {
		for _, run := range target.Runs {
			if _, err := os.Stat(filepath.Join("..", filepath.FromSlash(run.ReportPath))); os.IsNotExist(err) {
				t.Skip("focused-v3 raw artifacts are not installed; summary contract passed")
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := ValidateFocusedV3NonResearchOptimizationArtifacts(e, ".."); err != nil {
		t.Fatal(err)
	}
}

func TestFocusedV3NonResearchWireAuditRequiresExactComponentsQKernelAndMerkle(t *testing.T) {
	protocol := focusedV3NonResearchProtocol()
	audit := PIOP.CanonicalProofWireAuditV5{
		CodecVersion: protocol.CanonicalProofCodecVersion, CodecProfile: protocol.CanonicalProofCodecProfile, ProofSchemaVersion: protocol.ProofSchemaVersion,
		FieldEncoding: protocol.CanonicalProofFieldEncoding, QKernelEncoding: protocol.CanonicalProofQKernelEncoding, RadixQGroupElements: protocol.CanonicalProofRadixQGroupSize,
		MerkleTopology: protocol.CanonicalProofMerkleTopology, HeaderBytes: 10, RootBytes: 49, SaltBytes: 25, CounterBytes: 4,
		RBytes: 11, QBytes: 12, VTargetsBytes: 13, BarSetsBytes: 14, OpeningPBytes: 15, TapeBytes: 16, AuthenticationBytes: 147,
		QFullFieldElements: 128, QWireFieldElements: 115, QOmittedFieldElements: 13, MerkleNodesUsed: 2, MerkleNodesBound: 3, MerklePaddingNodes: 1,
	}
	audit.TotalBytes = audit.HeaderBytes + audit.RootBytes + audit.SaltBytes + audit.CounterBytes + audit.RBytes + audit.QBytes + audit.VTargetsBytes + audit.BarSetsBytes + audit.OpeningPBytes + audit.TapeBytes + audit.AuthenticationBytes
	if err := validateFocusedV3NonResearchWireAudit(audit, protocol, 13, audit.TotalBytes, 49); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PIOP.CanonicalProofWireAuditV5){
		func(a *PIOP.CanonicalProofWireAuditV5) { a.TotalBytes++ },
		func(a *PIOP.CanonicalProofWireAuditV5) { a.QOmittedFieldElements-- },
		func(a *PIOP.CanonicalProofWireAuditV5) { a.MerklePaddingNodes++ },
		func(a *PIOP.CanonicalProofWireAuditV5) { a.CodecProfile = "legacy" },
	} {
		bad := audit
		mutate(&bad)
		if err := validateFocusedV3NonResearchWireAudit(bad, protocol, 13, audit.TotalBytes, 49); err == nil {
			t.Fatal("invalid wire audit was accepted")
		}
	}
}

func TestFocusedV3NonResearchCanonicalArtifactProjection(t *testing.T) {
	root := t.TempDir()
	relDir := "artifacts/nonresearch/bq/run-1"
	absDir := filepath.Join(root, filepath.FromSlash(relDir))
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		t.Fatal(err)
	}
	state := append([]byte{'S', 'P', 'R', 'S', 'T', 'A', 'T', 8}, []byte("state")...)
	issueProof := append([]byte{'S', 'P', 'R', 'U', 'C', 'E', 'P', '5', 5, 1}, []byte("issue")...)
	showProof := append([]byte{'S', 'P', 'R', 'U', 'C', 'E', 'P', '5', 5, 2}, []byte("show")...)
	presentation := append([]byte{'S', 'P', 'R', 'P', 'R', 'E', 'S', 3}, make([]byte, 25)...)
	presentation = append(presentation, showProof...)
	submission, err := json.Marshal(struct {
		Version        int    `json:"version"`
		CanonicalProof []byte `json:"canonical_proof"`
	}{4, issueProof})
	if err != nil {
		t.Fatal(err)
	}
	stateRel, submissionRel, presentationRel := relDir+"/credential_state.intgenisis.v8", relDir+"/presign_submission.json", relDir+"/presentation.intgenisis.v3"
	if err := os.WriteFile(filepath.Join(root, stateRel), state, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, submissionRel), submission, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, presentationRel), presentation, 0o644); err != nil {
		t.Fatal(err)
	}
	core := map[string]bool{
		"state": true, "presign_submission": true, "presentation": true,
	}
	for _, item := range focusedV3NonResearchArtifactPaths(relDir) {
		if core[item.role] {
			continue
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(item.path)), []byte("artifact-"+item.role), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files := make([]FocusedV3NonResearchFileDigest, 0, len(focusedV3NonResearchArtifactPaths(relDir)))
	for _, item := range focusedV3NonResearchArtifactPaths(relDir) {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item.path)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, FocusedV3NonResearchFileDigest{Role: item.role, Path: item.path, Bytes: int64(len(data)), SHA256: sha256Hex(data)})
	}
	run := FocusedV3NonResearchRun{
		ArtifactDirectory:    relDir,
		PersistentStateBytes: len(state), IssuanceProofWireBytes: len(issueProof), ShowingProofWireBytes: len(showProof), PresentationWireBytes: len(presentation),
		Artifacts: FocusedV3NonResearchArtifactProjection{
			StatePath: stateRel, StateSHA256: sha256Hex(state), SubmissionPath: submissionRel, SubmissionSHA256: sha256Hex(submission), IssuanceProofSHA256: sha256Hex(issueProof),
			PresentationPath: presentationRel, PresentationSHA256: sha256Hex(presentation), ShowingProofSHA256: sha256Hex(showProof), Files: files,
		},
	}
	if !validFocusedV3NonResearchArtifactProjection(run.Artifacts, relDir) {
		t.Fatal("canonical artifact projection was rejected")
	}
	for _, mutate := range []func(*FocusedV3NonResearchArtifactProjection){
		func(a *FocusedV3NonResearchArtifactProjection) { a.StatePath = relDir + "/alternate-state.v8" },
		func(a *FocusedV3NonResearchArtifactProjection) { a.SubmissionSHA256 = strings.Repeat("e", 64) },
		func(a *FocusedV3NonResearchArtifactProjection) {
			a.PresentationPath = relDir + "/alternate-presentation.v3"
		},
	} {
		bad := run.Artifacts
		bad.Files = append([]FocusedV3NonResearchFileDigest(nil), run.Artifacts.Files...)
		mutate(&bad)
		if validFocusedV3NonResearchArtifactProjection(bad, relDir) {
			t.Fatal("accepted a dedicated core path/digest decoupled from Files")
		}
	}
	preset, _ := credential.LookupIntGenISISPreset(credential.IntGenISISPresetPoCN1024BQ128R128V3)
	if err := validateFocusedV3NonResearchArtifacts(root, absDir, preset, run); err != nil {
		t.Fatal(err)
	}
	for i := range run.Artifacts.Files {
		bad := run
		bad.Artifacts.Files = append([]FocusedV3NonResearchFileDigest(nil), run.Artifacts.Files...)
		bad.Artifacts.Files[i].SHA256 = strings.Repeat("e", 64)
		if err := validateFocusedV3NonResearchArtifacts(root, absDir, preset, bad); err == nil {
			t.Fatalf("accepted changed Files digest at entry %d", i)
		}
	}
	for _, item := range focusedV3NonResearchArtifactPaths(relDir) {
		if core[item.role] {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(item.path))
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(append([]byte(nil), original...), '!'), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateFocusedV3NonResearchArtifacts(root, absDir, preset, run); err == nil {
			t.Fatalf("accepted changed non-core artifact %s", item.role)
		}
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run.Artifacts.ShowingProofSHA256 = strings.Repeat("f", 64)
	if err := validateFocusedV3NonResearchArtifacts(root, absDir, preset, run); err == nil {
		t.Fatal("accepted a presentation with the wrong showing-proof digest")
	}
	run.Artifacts.ShowingProofSHA256 = sha256Hex(showProof)
	run.Artifacts.Files[0].Path = relDir + "/wrong.json"
	if err := validateFocusedV3NonResearchArtifacts(root, absDir, preset, run); err == nil {
		t.Fatal("accepted a noncanonical artifact role/path entry")
	}
}

func TestFocusedV3NonResearchReportedArtifactBundleRequiresCanonicalPaths(t *testing.T) {
	runDir := "artifacts/smallwood-v3/nonresearch-optimization/bq128/run-1"
	want := focusedV3NonResearchArtifactPaths(runDir)
	reported := benchmarkArtifactsWire{
		PublicParams: runDir + "/credential_public.intgenisis_profile_c.json", BMatrix: runDir + "/Bmatrix.intgenisis_profile_c.json",
		HolderSecret: runDir + "/holder_secret.json", CommitRequest: runDir + "/commit_request.json", Submission: runDir + "/presign_submission.json",
		Response: runDir + "/issue_response.json", State: runDir + "/credential_state.intgenisis.v8", VerifierKey: runDir + "/intgenisis_verifier_key.json",
		Presentation: runDir + "/presentation.intgenisis.v3", HolderUsageState: runDir + "/holder_usage_state.json", VerifierState: runDir + "/verifier_state.json",
		NTRUParams: runDir + "/ntru_params.json", NTRUPublic: runDir + "/ntru_public.json", NTRUPrivate: runDir + "/ntru_private.json", NTRUSignature: runDir + "/ntru_signature.json",
	}
	if got := focusedV3NonResearchReportedArtifactPaths(reported); !reflect.DeepEqual(got, want) {
		t.Fatal("canonical raw report bundle was rejected")
	}
	reported.PublicParams = runDir + "/alternate-public.json"
	if got := focusedV3NonResearchReportedArtifactPaths(reported); reflect.DeepEqual(got, want) {
		t.Fatal("accepted a decoupled non-core raw report path")
	}
}
