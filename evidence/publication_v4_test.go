package evidence

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func TestPublicationV4StrictBatchAcceptance(t *testing.T) {
	env := publicationV4TestEnvironment(t)
	lock := publicationV4TestLock(t, env)
	batch := publicationV4TestBatch(t, lock, env)
	if err := ValidatePublicationV4CandidateLock(lock); err != nil {
		t.Fatalf("valid candidate lock rejected: %v", err)
	}
	floorLock := publicationV4Clone(t, lock)
	floorLock.Presets[0].BoundaryHits = []string{"l_issuance_lower"}
	floorLock.Presets[0].SupportFloorHits = []string{"l_issuance_lower"}
	floorLock.ContentDigest = ""
	floorLock.ContentDigest, _ = publicationV4Digest(floorLock)
	if err := ValidatePublicationV4CandidateLock(floorLock); err != nil {
		t.Fatalf("explicit hard support-floor exclusion rejected: %v", err)
	}
	upperLock := publicationV4Clone(t, floorLock)
	upperLock.Presets[0].BoundaryHits = append(upperLock.Presets[0].BoundaryHits, "theta_upper")
	upperLock.Presets[0].ExpandableBoundaryHits = []string{"theta_upper"}
	upperLock.ContentDigest = ""
	upperLock.ContentDigest, _ = publicationV4Digest(upperLock)
	if err := ValidatePublicationV4CandidateLock(upperLock); err == nil {
		t.Fatal("expandable upper boundary accepted as a support floor")
	}
	badFloorLock := publicationV4Clone(t, floorLock)
	badFloorLock.Presets[0].CertifiedSupportFloors[0].Minimum--
	badFloorLock.ContentDigest = ""
	badFloorLock.ContentDigest, _ = publicationV4Digest(badFloorLock)
	if err := ValidatePublicationV4CandidateLock(badFloorLock); err == nil {
		t.Fatal("support-floor minimum differing from the initial envelope was accepted")
	}
	badBasisLock := publicationV4Clone(t, floorLock)
	badBasisLock.Presets[0].CertifiedSupportFloors[2].Basis = "unrecorded-field-floor"
	badBasisLock.ContentDigest = ""
	badBasisLock.ContentDigest, _ = publicationV4Digest(badBasisLock)
	if err := ValidatePublicationV4CandidateLock(badBasisLock); err == nil {
		t.Fatal("support-floor certification with an unapproved basis was accepted")
	}
	badPartitionLock := publicationV4Clone(t, floorLock)
	badPartitionLock.Presets[0].BoundaryHits = append(badPartitionLock.Presets[0].BoundaryHits, "ell_lower")
	badPartitionLock.ContentDigest = ""
	badPartitionLock.ContentDigest, _ = publicationV4Digest(badPartitionLock)
	if err := ValidatePublicationV4CandidateLock(badPartitionLock); err == nil {
		t.Fatal("incomplete raw/support/expandable boundary partition was accepted")
	}
	if err := ValidatePublicationV4BenchmarkBatch(batch, lock); err != nil {
		t.Fatalf("valid benchmark batch rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PublicationV4BenchmarkBatch, *PublicationV4CandidateLock)
	}{
		{"not-exact-five", func(_ *PublicationV4BenchmarkBatch, lock *PublicationV4CandidateLock) {
			lock.Presets = lock.Presets[:4]
		}},
		{"not-seven-final", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) { batch.RunsPerPreset = 6 }},
		{"source-changed", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].Environment.BuildSHA256 = strings.Repeat("f", 64)
		}},
		{"report-hash", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].ReportSHA256 = "bad"
		}},
		{"replay", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].ReplayRejected = false
		}},
		{"tamper", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].TamperRejected = false
		}},
		{"artifact-hash", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].ArtifactHashesVerified = false
		}},
		{"fs-width", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].ObservedFSBits[1][3] -= 8
		}},
		{"full-game-status", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].FullGameAccountingStatus = "legacy"
		}},
		{"canonical-size", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].Metrics.ShowingProofMaxBytes++
		}},
		{"resources", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Runs[0].Metrics.PeakRSSBytes = 0
		}},
		{"summary-median", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Presets[0].ShowingProofBytes.Median++
		}},
		{"reports-digest", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.ReportsDigest = strings.Repeat("0", 64)
		}},
		{"live-adoption", func(batch *PublicationV4BenchmarkBatch, _ *PublicationV4CandidateLock) {
			batch.Acceptance.LiveManifestAdopted = false
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotBatch := publicationV4Clone(t, batch)
			gotLock := publicationV4Clone(t, lock)
			tc.mutate(&gotBatch, &gotLock)
			if err := ValidatePublicationV4BenchmarkBatch(gotBatch, gotLock); err == nil {
				t.Fatalf("mutation accepted")
			}
		})
	}
}

func TestPublicationV4StrictJSONAndHistoricalPartition(t *testing.T) {
	env := publicationV4TestEnvironment(t)
	lock := publicationV4TestLock(t, env)
	batch := publicationV4TestBatch(t, lock, env)
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePublicationV4BenchmarkBatch(data)
	if err != nil || !reflect.DeepEqual(decoded, batch) {
		t.Fatalf("strict batch round trip failed: %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown_publication_field"] = true
	unknown, _ := json.Marshal(object)
	if _, err := DecodePublicationV4BenchmarkBatch(unknown); err == nil {
		t.Fatal("unknown batch field accepted")
	}
	if _, err := DecodePublicationV4BenchmarkBatch(append(data, []byte(" {}")...)); err == nil {
		t.Fatal("trailing batch JSON accepted")
	}
	if err := validatePresetRegistryV2(); err != nil {
		t.Fatalf("publication v4 broke the historical evidence partition: %v", err)
	}
	if len(CanonicalV2PresetIDs()) != 7 || len(FocusedV3TargetPresetIDs()) != 2 || len(credential.IntGenISISPublicationPresetNamesV4()) != 5 {
		t.Fatal("evidence epoch partitions are not 7 historical-v2 + 2 focused-v3 + 5 publication-v4")
	}
}

func TestPublicationV4EvidenceRankingMatchesProducerOrder(t *testing.T) {
	lowSlackSmallN := PublicationV4CandidateBinding{
		Showing:    credential.IntGenISISTuningPreset{NLeaves: 100},
		Projection: &PublicationV4CandidateProjection{ShowingProofMaxBytes: 1, MinimumSecuritySlack: 0.1},
	}
	highSlackLargeN := PublicationV4CandidateBinding{
		Showing:    credential.IntGenISISTuningPreset{NLeaves: 200},
		Projection: &PublicationV4CandidateProjection{ShowingProofMaxBytes: 1, MinimumSecuritySlack: 0.2},
	}
	if !publicationV4CandidateLess(highSlackLargeN, lowSlackSmallN) {
		t.Fatal("evidence ranking placed lexicographic NLeaves before security slack")
	}
}

func TestPublicationV4LocalRegeneratedLockSchema(t *testing.T) {
	path := filepath.Join("..", "artifacts", "publication-v4", "final", "tuning", "candidate-lock.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("local regenerated publication-v4 lock is not installed")
	}
	if err != nil {
		t.Fatal(err)
	}
	lock, err := DecodePublicationV4CandidateLock(data)
	if err != nil {
		t.Fatalf("decode regenerated lock: %v", err)
	}
	if err := ValidatePublicationV4CandidateLock(lock); err != nil {
		t.Fatalf("validate regenerated lock: %v", err)
	}
}

func TestPublicationV4LocalAcceptedArtifacts(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	pattern := filepath.Join(root, "artifacts", "publication-v4", "final", "benchmarks", "batch-*", "benchmark-publication-presets.json")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("local accepted publication-v4 batch is not installed")
	}
	if err := ValidatePublicationV4BenchmarkArtifacts(matches[len(matches)-1], root); err != nil {
		t.Fatalf("validate accepted publication-v4 artifacts: %v", err)
	}
}

func TestPublicationV4AggregateQAndWFAccountingModes(t *testing.T) {
	env := publicationV4TestEnvironment(t)
	lock := publicationV4TestLock(t, env)
	for i, result := range lock.Presets {
		candidate := result.Finalists[0]
		report := publicationV4TestSecurityReport(t, candidate)
		if err := validatePublicationV4RawSecurity(report, candidate); err != nil {
			t.Fatalf("%s valid security report rejected: %v", result.PublicationLabel, err)
		}
		bad := report
		if i == 2 {
			bad.FullGame.AccountingMode = PIOP.FullGameAccountingAggregateV4
			bad.FullGame.AggregateQueryCapLog2 = 64
		} else {
			bad.FullGame.AccountingMode = PIOP.FullGameAccountingWorkFactorV4
		}
		if err := validatePublicationV4RawSecurity(bad, candidate); err == nil {
			t.Fatalf("%s accepted the wrong aggregate-Q/WF accounting mode", result.PublicationLabel)
		}
		bad = publicationV4TestSecurityReport(t, candidate)
		bad.FullGame.MaxNativeAlgebraicBits++
		bad.FullGame.MaxNativeAlgebraicError = math.Exp2(-bad.FullGame.MaxNativeAlgebraicBits)
		if err := validatePublicationV4RawSecurity(bad, candidate); err == nil {
			t.Fatalf("%s accepted a self-consistent but non-native full-game coefficient", result.PublicationLabel)
		}
		for label, mutate := range map[string]func(*benchmarkReportWire){
			"issuance": func(report *benchmarkReportWire) { report.FullGame.IssuanceQueryCapBits[4] = 0 },
			"showing":  func(report *benchmarkReportWire) { report.FullGame.ShowingQueryCapBits[2] = 64 },
			"global":   func(report *benchmarkReportWire) { report.FullGame.GlobalQueryCapBits[0] = 0 },
		} {
			bad = publicationV4TestSecurityReport(t, candidate)
			mutate(&bad)
			if err := validatePublicationV4RawSecurity(bad, candidate); err == nil {
				t.Fatalf("%s accepted finite %s legacy query-cap evidence", result.PublicationLabel, label)
			}
		}
		if i == 2 {
			drift := publicationV4TestSecurityReport(t, candidate)
			drift.Issuance.RawRoundBits[0] += 2e-9
			drift.Issuance.RoundBits[0] = drift.Issuance.RawRoundBits[0]
			drift.Issuance.NativeAlgebraicBits[0] = drift.Issuance.RoundBits[0] + float64(candidate.Issuance.Kappa[0])
			drift.Issuance.NativeAlgebraicTerms[0] = math.Exp2(-drift.Issuance.NativeAlgebraicBits[0])
			drift.Issuance.WorkFactorComponents[1] = drift.Issuance.NativeAlgebraicBits[0]
			if err := validatePublicationV4RawSecurity(drift, candidate); err != nil {
				t.Fatalf("WF128 rejected measured/projected numerical drift with exact measured native terms: %v", err)
			}
			bad = publicationV4TestSecurityReport(t, candidate)
			bad.Issuance.NativeAlgebraicBits[0] = 127
			bad.Issuance.NativeAlgebraicTerms[0] = math.Exp2(-127)
			bad.Issuance.WorkFactorComponents[1] = 127
			bad.Issuance.WorkFactorBits = 127
			if err := validatePublicationV4RawSecurity(bad, candidate); err == nil {
				t.Fatal("WF128 accepted a sub-128-bit issuance branch")
			}
			bad = publicationV4TestSecurityReport(t, candidate)
			bad.Showing.TheoremBits[3] = 0
			if err := validatePublicationV4RawSecurity(bad, candidate); err == nil {
				t.Fatal("WF128 accepted a query-adjusted showing field without the -1 sentinel")
			}
			bad = publicationV4TestSecurityReport(t, candidate)
			bad.FullGame.AggregateQueryCapLog2 = 64
			if err := validatePublicationV4RawSecurity(bad, candidate); err == nil {
				t.Fatal("WF128 accepted an invented aggregate-Q scalar")
			}
		}
	}
}

func TestPublicationV4RawPhasesRequireV4TranscriptSecurityStatus(t *testing.T) {
	env := publicationV4TestEnvironment(t)
	lock := publicationV4TestLock(t, env)
	candidate := lock.Presets[0].Winner
	for _, tc := range []struct {
		name   string
		tuning credential.IntGenISISTuningPreset
	}{
		{name: "issuance", tuning: candidate.Issuance},
		{name: "showing", tuning: candidate.Showing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phase, projection, actual := publicationV4TestRawPhase(tc.tuning)
			if err := validatePublicationV4RawPhase(phase, tc.tuning, projection, actual); err != nil {
				t.Fatalf("valid v4 phase rejected: %v", err)
			}
			phase.TranscriptSecurityStatus = credential.IntGenISISSecurityGateV3
			if err := validatePublicationV4RawPhase(phase, tc.tuning, projection, actual); err == nil {
				t.Fatal("v3 transcript security label accepted for a publication-v4 phase")
			}
			phase, projection, actual = publicationV4TestRawPhase(tc.tuning)
			phase.ROQueryCaps[2] = 1
			if err := validatePublicationV4RawPhase(phase, tc.tuning, projection, actual); err == nil {
				t.Fatal("hidden per-domain query cap accepted beside the aggregate-Q scalar")
			}
		})
	}
}

func TestPublicationV4ArtifactFilesAreRehashedFailClosed(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "run")
	if err := os.Mkdir(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	roles := []string{"public_params", "b_matrix", "holder_secret", "commit_request", "presign_submission", "issue_response", "state", "verifier_key", "presentation", "holder_usage_state", "verifier_state", "ntru_params", "ntru_public", "ntru_private", "ntru_signature"}
	paths, digests := make(map[string]string, 15), make(map[string]string, 15)
	for _, role := range roles {
		path := filepath.Join(runDir, role+".bin")
		data := []byte("publication-v4-artifact-" + role)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths[role], digests[role] = path, sha256Hex(data)
	}
	got, err := publicationV4ReadArtifactSet(root, runDir, paths, digests)
	if err != nil || len(got) != 15 {
		t.Fatalf("valid artifact set rejected: %v", err)
	}
	badDigest := publicationV4Clone(t, digests)
	badDigest["state"] = strings.Repeat("0", 64)
	if _, err := publicationV4ReadArtifactSet(root, runDir, paths, badDigest); err == nil {
		t.Fatal("artifact content/digest mutation accepted")
	}
	missing := publicationV4Clone(t, digests)
	delete(missing, "state")
	if _, err := publicationV4ReadArtifactSet(root, runDir, paths, missing); err == nil {
		t.Fatal("incomplete artifact hash map accepted")
	}
	escape := publicationV4Clone(t, paths)
	escape["state"] = filepath.Join(root, "outside.bin")
	if _, err := publicationV4ReadArtifactSet(root, runDir, escape, digests); err == nil {
		t.Fatal("artifact outside its run directory accepted")
	}
	statePath := paths["state"]
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths["presentation"], statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := publicationV4ReadArtifactSet(root, runDir, paths, digests); err == nil {
		t.Fatal("symlink artifact accepted")
	}
}

func publicationV4TestEnvironment(t *testing.T) PublicationV4Environment {
	t.Helper()
	modified := true
	env := PublicationV4Environment{
		GoVersion: "go1.test", GOOS: "darwin", GOARCH: "arm64", NumCPU: 8, GOMAXPROCS: 8,
		VCS: "git", Commit: strings.Repeat("1", 40), CommitTime: "2026-08-05T00:00:00Z", Modified: &modified,
		SourceTreeAlgorithm: "sha256-test", SourceTreeDigest: strings.Repeat("a", 64), SourceTreeFileCount: 100,
		BuildSHA256: strings.Repeat("b", 64), CPUModel: "test cpu", CPUFeatures: "test-features",
	}
	machine, err := json.Marshal(struct {
		GoVersion, GOOS, GOARCH, CPUModel, CPUFeatures string
		NumCPU, GOMAXPROCS                             int
	}{env.GoVersion, env.GOOS, env.GOARCH, env.CPUModel, env.CPUFeatures, env.NumCPU, env.GOMAXPROCS})
	if err != nil {
		t.Fatal(err)
	}
	env.MachineDigest = sha256Hex(machine)
	return env
}

func publicationV4TestLock(t *testing.T, env PublicationV4Environment) PublicationV4CandidateLock {
	t.Helper()
	initial := PublicationV4SearchEnvelope{
		LIssuanceMin: 32, LIssuanceMax: 64, LShowingMin: 32, LShowingMax: 64,
		ThetaMin: 5, ThetaMax: 16, EllMin: 6, EllMax: 22, KappaMin: 0, KappaMax: 13,
		NLeavesMin: "L+2*ell", NLeavesMax: int(credential.IntGenISISSharedModulusQ - 1),
	}
	expanded := initial
	expanded.LIssuanceMax += 16
	envelope := expanded
	envelope.LIssuanceMax += 16
	envelopes := []PublicationV4SearchEnvelope{initial, expanded, envelope}
	lock := PublicationV4CandidateLock{
		Schema: PublicationV4CandidateLockSchema, Version: PublicationV4EvidenceVersion,
		Status: "analytic_complete_measurement_pending", SearchAlgorithm: "test exhaustive publication-v4 search",
		Ranking:  []string{"eligible", "showing_proof_max_bytes", "presentation_max_bytes", "showing_paper_transcript_bytes", "combined_proof_max_bytes", "combined_paper_transcript_bytes", "expected_grinding_work", "projected_work_units", "minimum_security_slack_desc", "lexicographic_tuning_including_phase_nleaves"},
		Envelope: envelope, EnvelopesSearched: envelopes,
		CounterBound: "four uint64 varints, maximum 40 bytes", MerkleBound: "exact compact frontier",
		Source: PublicationV4SourceBinding{
			Algorithm: env.SourceTreeAlgorithm, Digest: env.SourceTreeDigest, FileCount: env.SourceTreeFileCount,
			Commit: env.Commit, Modified: *env.Modified, BuildSHA256: env.BuildSHA256, MachineDigest: env.MachineDigest,
			CPUModel: env.CPUModel, CPUFeatures: env.CPUFeatures,
		},
		Stopping: PublicationV4StoppingEvidence{
			WinnerInterior: true, NearFrontierInterior: true, ExactIntegerRoots: true, AdmissibleLowerBoundsApplied: true,
			ProjectionMeasurementPending: true, BoundaryExpansionRule: "expand all near boundaries", StableExpandedEnvelopes: 2,
			SupportFloorsCertified: true,
		},
		NoLivePresetRewrite: true, PresetCount: PublicationV4PresetCount,
	}
	for _, preset := range credential.IntGenISISPublicationPresetsV4() {
		result := PublicationV4PresetSearchResult{
			CanonicalID: preset.CanonicalID, PublicationLabel: preset.PublicationLabel,
			ManifestDigest: credential.IntGenISISPresetManifestDigest(preset), CandidateCount: 1000, EligibleCount: 1000,
			MeasurementStatus: "analytic finalists retained", WinnerInterior: true,
			LowerBoundExclusions: []string{
				"LVCSNCols < 32 is excluded by the user-frozen NCols=32 setting and the supported publication LVCS envelope",
				"theta < 5 is outside the approved publication extension-field search support floor",
				"ell < 6 is outside the approved publication DECS opening search support floor",
			},
			CertifiedSupportFloors: []PublicationV4SupportFloorCertification{
				{Dimension: "l_issuance_lower", Minimum: 32, Basis: "user_frozen_ncols_32_and_supported_lvcs_envelope"},
				{Dimension: "l_showing_lower", Minimum: 32, Basis: "user_frozen_ncols_32_and_supported_lvcs_envelope"},
				{Dimension: "theta_lower", Minimum: 5, Basis: "approved_publication_extension_field_support_floor"},
				{Dimension: "ell_lower", Minimum: 6, Basis: "approved_publication_decs_opening_support_floor"},
			},
			EnvelopesSearched: envelopes,
		}
		for rank := 1; rank <= PublicationV4FinalistCount; rank++ {
			showMax := 20000 + rank*100
			binding := PublicationV4CandidateBinding{
				CanonicalID: preset.CanonicalID, PublicationLabel: preset.PublicationLabel,
				ManifestDigest: credential.IntGenISISPresetManifestDigest(preset), ManifestStatus: "pinned_validated",
				Issuance: preset.Issuance, Showing: preset.Showing, SelectionStatus: "test-ranked-finalist",
				Projection: &PublicationV4CandidateProjection{
					ShowingProofMaxBytes: showMax, PresentationMaxBytes: showMax + 100, ShowingPaperBytes: 9000 + rank,
					CombinedProofMaxBytes: showMax + 18000 + rank*100, CombinedPaperBytes: 16000 + rank*2,
					ExpectedGrindingWork: uint64(100 + rank), ProjectedWorkUnits: uint64(100000 + rank), MinimumSecuritySlack: 1,
					RawRoundBitsIssuance:    [4]float64{preset.TargetTheoremBits, preset.TargetTheoremBits, preset.TargetTheoremBits, preset.TargetTheoremBits},
					RawRoundBitsShowing:     [4]float64{preset.TargetTheoremBits, preset.TargetTheoremBits, preset.TargetTheoremBits, preset.TargetTheoremBits},
					RequiredNativeRoundBits: preset.TargetTheoremBits,
				},
			}
			binding.CandidateDigest, _ = publicationV4Digest(binding)
			result.Finalists = append(result.Finalists, binding)
		}
		result.Winner = result.Finalists[0]
		lock.Presets = append(lock.Presets, result)
	}
	lock.ContentDigest, _ = publicationV4Digest(lock)
	return lock
}

func publicationV4TestBatch(t *testing.T, lock PublicationV4CandidateLock, env PublicationV4Environment) PublicationV4BenchmarkBatch {
	t.Helper()
	names := credential.IntGenISISPublicationPresetNamesV4()
	rotation := make([][]string, PublicationV4FinalRunsPerPreset)
	for round := range rotation {
		for position := range names {
			rotation[round] = append(rotation[round], names[(round+position)%len(names)])
		}
	}
	results := make(map[string]PublicationV4PresetSearchResult, len(lock.Presets))
	for _, result := range lock.Presets {
		results[result.CanonicalID] = result
	}
	batch := PublicationV4BenchmarkBatch{
		Schema: PublicationV4BenchmarkBatchSchema, Version: PublicationV4EvidenceVersion, Status: "accepted",
		GeneratedAt: "2026-08-05T00:00:00Z", BatchID: "test-batch", CandidateLockFile: "artifacts/publication-test/candidate-lock.json",
		CandidateLockDigest: lock.ContentDigest, RunsPerPreset: PublicationV4FinalRunsPerPreset, Rotation: rotation,
		ExecutionPolicy: "top-12 once; analytic top-3 three total runs including screening; analytic winner seven additional fresh final runs; cyclic preset rotation",
		Acceptance: PublicationV4BenchmarkAcceptance{
			ExactFivePresets: true, LockStoppingCertified: true, FinalistRunCounts: true, CandidateManifests: true,
			ReplayRejected: true, TamperRejected: true, ArtifactHashesVerified: true, FSWidthsVerified: true,
			AggregateQueryPolicy: true, SourceBuildMachine: true, CanonicalSizes: true, Resources: true,
			FullGameAccounting: true, ProjectedWinnerMeasured: true, LiveManifestAdopted: true,
		},
		SourceAndMachineSame: true, Environment: env,
	}
	appendGroup := func(stage string, rank, candidateRun, shift int) {
		for position := range names {
			name := names[(shift+position)%len(names)]
			candidate := results[name].Finalists[rank-1]
			entry := PublicationV4BenchmarkScheduleEntry{
				Sequence: len(batch.Schedule) + 1, Stage: stage, CanonicalID: name, CandidateDigest: candidate.CandidateDigest,
				CandidateRank: rank, CandidateRun: candidateRun, RotationPosition: position + 1,
			}
			batch.Schedule = append(batch.Schedule, entry)
			batch.Runs = append(batch.Runs, publicationV4TestRun(entry, candidate, env))
		}
	}
	for rank := 1; rank <= PublicationV4FinalistCount; rank++ {
		appendGroup("screening", rank, 1, rank-1)
	}
	group := PublicationV4FinalistCount
	for candidateRun := 2; candidateRun <= 3; candidateRun++ {
		for rank := 1; rank <= 3; rank++ {
			appendGroup("confirmation", rank, candidateRun, group)
			group++
		}
	}
	for candidateRun := 1; candidateRun <= PublicationV4FinalRunsPerPreset; candidateRun++ {
		appendGroup("final", 1, candidateRun, candidateRun-1)
	}
	batch.Presets = publicationV4AggregateFinalRuns(batch.Runs, names)
	batch.ReportsDigest, _ = publicationV4ReportsDigest(batch.Runs)
	return batch
}

func publicationV4TestRun(entry PublicationV4BenchmarkScheduleEntry, candidate PublicationV4CandidateBinding, env PublicationV4Environment) PublicationV4BenchmarkRun {
	projection := candidate.Projection
	rootBytes := candidate.Showing.FSOutputBits / 8
	counters := [4]uint64{0, 1, 127, 128}
	counterBytes := 0
	for _, counter := range counters {
		counterBytes += publicationV4UvarintBytes(counter)
	}
	phase := func(maximum int) (int, PublicationV4PhaseWireRun) {
		used, bound := 10, 12
		auth := used * rootBytes
		actual := maximum + counterBytes + auth - 4*10 - bound*rootBytes
		return actual, PublicationV4PhaseWireRun{
			CounterBytes: counterBytes, FSCounters: counters, AuthenticationBytes: auth,
			MerkleNodesUsed: used, MerkleNodesBound: bound, DeterministicMaxBytes: maximum,
		}
	}
	showMax := projection.ShowingProofMaxBytes
	issueMax := projection.CombinedProofMaxBytes - showMax
	issueActual, issueWire := phase(issueMax)
	showActual, showWire := phase(showMax)
	presentationActual := showActual + 100
	sequence := entry.Sequence
	runDir := "artifacts/publication-test/run-" + leftPadPublicationV4(sequence)
	artifactHashes := make(map[string]string, 15)
	for _, role := range []string{"public_params", "b_matrix", "holder_secret", "commit_request", "presign_submission", "issue_response", "state", "verifier_key", "presentation", "holder_usage_state", "verifier_state", "ntru_params", "ntru_public", "ntru_private", "ntru_signature"} {
		artifactHashes[role] = sha256Hex([]byte(role + runDir))
	}
	fsBits := candidate.Showing.FSOutputBits
	return PublicationV4BenchmarkRun{
		Stage: entry.Stage, CandidateRank: entry.CandidateRank, CandidateRun: entry.CandidateRun,
		Round: entry.CandidateRun, RotationPosition: entry.RotationPosition, CanonicalID: entry.CanonicalID,
		PublicationLabel: candidate.PublicationLabel, CandidateDigest: candidate.CandidateDigest, ManifestDigest: candidate.ManifestDigest,
		RunDirectory: runDir, ReportFile: runDir + "/benchmark-intgenisis-e2e.json", ReportSHA256: sha256Hex([]byte("report" + runDir)),
		ResourceFile: runDir + "/resource.txt", ResourceSHA256: sha256Hex([]byte("resource" + runDir)), Environment: env,
		Metrics: PublicationV4RunMetrics{
			CredentialStateBytes: 5000, IssuanceProofBytes: issueActual, ShowingProofBytes: showActual,
			IssuanceProofMaxBytes: issueMax, ShowingProofMaxBytes: showMax, PresentationBytes: presentationActual,
			PresentationMaxBytes: projection.PresentationMaxBytes,
			IssuancePaperBytes:   projection.CombinedPaperBytes - projection.ShowingPaperBytes, ShowingPaperBytes: projection.ShowingPaperBytes,
			IssuanceProvingMS: float64(sequence), IssuanceVerificationMS: float64(sequence) / 10,
			ShowingProvingMS: float64(sequence) * 2, ShowingVerificationMS: float64(sequence) / 5,
			AllocatedBytes: uint64(1000000 + sequence), Allocations: uint64(1000 + sequence), PeakRSSBytes: uint64(2000000 + sequence),
		},
		ConfiguredFSBits: fsBits, ObservedFSBits: [][4]int{{fsBits, fsBits, fsBits, fsBits}, {fsBits, fsBits, fsBits, fsBits}},
		IssuanceWire: issueWire, ShowingWire: showWire, ReplayRejected: true, TamperRejected: true,
		ArtifactHashesVerified: true, ArtifactSHA256: artifactHashes, FullGameAccountingStatus: "aggregate_composed_game_v4",
		LedgerStatus: "proof-only", ParameterAuditStatus: "pass",
	}
}

func publicationV4TestRawPhase(tuning credential.IntGenISISTuningPreset) (benchmarkPhaseWire, PublicationV4PhaseWireRun, int) {
	actual := 5000
	rootBytes := tuning.DECSHashBits / 8
	tapeBytes := tuning.DECSTapeBits / 8
	counters := [4]uint64{}
	counterBytes := 4
	merkleNodesUsed, merkleNodesBound := 1, 2
	authenticationBytes := merkleNodesUsed * rootBytes
	audit := &PIOP.CanonicalProofWireAuditV6{
		RootBytes: rootBytes, CounterBytes: counterBytes, AuthenticationBytes: authenticationBytes,
		TotalBytes: actual, MerkleNodesUsed: merkleNodesUsed, MerkleNodesBound: merkleNodesBound,
	}
	projected := PublicationV4PhaseWireRun{
		CounterBytes: counterBytes, FSCounters: counters, AuthenticationBytes: authenticationBytes,
		MerkleNodesUsed: merkleNodesUsed, MerkleNodesBound: merkleNodesBound,
		DeterministicMaxBytes: actual - counterBytes - authenticationBytes + 4*10 + merkleNodesBound*rootBytes,
	}
	totalRows := tuning.LVCSNCols
	dq := tuning.LVCSNCols
	blocks := 1
	mu := 1
	replayRows := blocks * (tuning.NCols + tuning.Theta)
	maskRows := (mu + 1) * tuning.Theta * tuning.Rho
	committedRows := replayRows + maskRows
	auditRows := (blocks + 1) * tuning.Theta
	parallelDegree, aggregatedDegree := 2, 3
	phase := benchmarkPhaseWire{
		ProofSizeBytes: actual, CanonicalProofWireBytes: actual, CanonicalWireAudit: audit,
		CanonicalTamperRejected: true, PaperTranscriptBytes: 6000, TapeWidthBytes: tapeBytes,
		RootWidthBytes: rootBytes, ZeroKnowledgeEligible: true, ProvingMS: 1, VerificationMS: 1,
		FSCounters: counters, TotalRows: totalRows, RowsBlock: blocks, AuditRows: auditRows,
		OpeningCols: committedRows - auditRows, ParallelAlgDegree: parallelDegree, AggregatedAlgDegree: aggregatedDegree,
		FSOutputBits:         tuning.FSOutputBits,
		ObservedFSDigestBits: [4]int{tuning.FSOutputBits, tuning.FSOutputBits, tuning.FSOutputBits, tuning.FSOutputBits},
		AggregateQueryBudget: tuning.AggregateROQueryCapLog2Set, AggregateQueryCapLog2: tuning.AggregateROQueryCapLog2,
		ROQueryCapBits: [5]float64{-1, -1, -1, -1, -1},
		DECSHashBits:   tuning.DECSHashBits, DECSTapeBits: tuning.DECSTapeBits, SaltBits: tuning.SaltBits,
		TranscriptMode: credential.IntGenISISTranscriptProtocolV4, TranscriptSecurityStatus: credential.IntGenISISSecurityGateV4,
		DQ: dq, DDECS: tuning.LVCSNCols + tuning.Ell - 1, WitnessSupportCols: tuning.NCols,
		CommittedCols: tuning.LVCSNCols, LVCSNCols: tuning.LVCSNCols, NLeaves: tuning.NLeaves,
		Eta: tuning.Eta, Ell: tuning.Ell, Theta: tuning.Theta, Rho: tuning.Rho, EllPrime: tuning.EllPrime,
		SmallFieldReplayRows: replayRows, MaskRows: maskRows, PaperShapeNRows: committedRows,
		PaperShapeQueries: auditRows, PaperShapeWitnessLayers: blocks, PaperShapeMaskRows: maskRows,
		PaperShapeCanonical: true,
		RelationCandidate: relationCandidateWire{
			LogicalRows: totalRows, ParallelDegree: parallelDegree, AggregatedDegree: aggregatedDegree,
			DQ: dq, RowCounts: map[string]int{"total": totalRows},
		},
	}
	return phase, projected, actual
}

func leftPadPublicationV4(value int) string {
	if value < 10 {
		return "00" + string(rune('0'+value))
	}
	if value < 100 {
		return "0" + string(rune('0'+value/10)) + string(rune('0'+value%10))
	}
	return string(rune('0'+value/100)) + string(rune('0'+(value/10)%10)) + string(rune('0'+value%10))
}

func publicationV4TestSecurityReport(t *testing.T, candidate PublicationV4CandidateBinding) benchmarkReportWire {
	t.Helper()
	preset, ok := credential.LookupIntGenISISPublicationPreset(candidate.CanonicalID)
	if !ok {
		t.Fatal("missing publication preset")
	}
	spec, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		t.Fatal("missing publication security profile")
	}
	tagElements, _ := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	evidenceMap := map[string]string{
		"ro_query_cap_scope": credential.SecurityEvidenceExecutedPreset, "decs_hash_bits": credential.SecurityEvidenceExecutedPreset,
		"decs_tape_bits": credential.SecurityEvidenceExecutedPreset, "fs_collision_bits": credential.SecurityEvidenceExecutedPreset,
		"fs_output_bits": credential.SecurityEvidenceExecutedPreset, "salt_bits": credential.SecurityEvidenceExecutedPreset,
		"prf_tag_elements": credential.SecurityEvidenceLoadedParams, "prf_profile": credential.SecurityEvidenceLoadedParams,
		"transcript_mode": credential.SecurityEvidenceExecutedPreset,
	}
	actual := credential.IntGenISISSecurityParameterActuals{
		ROQueryCapScope: credential.ROQueryCapAggregateComposedGame, DECSHashBits: candidate.Showing.DECSHashBits,
		DECSTapeBits: candidate.Showing.DECSTapeBits, FSCollisionBits: candidate.Showing.FSCollisionBits,
		FSOutputBits: candidate.Showing.FSOutputBits, SaltBits: candidate.Showing.SaltBits, PRFTagElements: tagElements,
		PRFProfile: preset.PRFProfile, TranscriptMode: credential.IntGenISISTranscriptProtocolV4, Evidence: evidenceMap,
	}
	full := PIOP.FullGameSoundnessReport{
		AcceptedIssuance: preset.ThreatModel.AcceptedIssuance, AcceptedShowing: preset.ThreatModel.AcceptedShowing,
		CollisionSpaceBits: candidate.Showing.FSOutputBits,
	}
	noQueryCap := [5]float64{-1, -1, -1, -1, -1}
	issuancePhase := benchmarkPhaseWire{RawRoundBits: candidate.Projection.RawRoundBitsIssuance, RoundBits: candidate.Projection.RawRoundBitsIssuance, ROQueryCapBits: noQueryCap}
	showingPhase := benchmarkPhaseWire{RawRoundBits: candidate.Projection.RawRoundBitsShowing, RoundBits: candidate.Projection.RawRoundBitsShowing, ROQueryCapBits: noQueryCap}
	if preset.ThreatModel.AggregateROQueryCapLog2Set {
		qBits := preset.ThreatModel.AggregateROQueryCapLog2
		actual.AggregateROQueryCapLog2Set, actual.AggregateROQueryCapLog2 = true, qBits
		actual.Evidence["aggregate_ro_query_cap_log2"] = credential.SecurityEvidenceExecutedPreset
		nativeBits := math.Inf(1)
		for i, bits := range candidate.Projection.RawRoundBitsIssuance {
			nativeBits = math.Min(nativeBits, bits+float64(candidate.Issuance.Kappa[i]))
		}
		for i, bits := range candidate.Projection.RawRoundBitsShowing {
			nativeBits = math.Min(nativeBits, bits+float64(candidate.Showing.Kappa[i]))
		}
		nativeError := math.Exp2(-nativeBits)
		collision := math.Exp2(2*qBits - float64(candidate.Showing.FSOutputBits))
		algebraic := math.Exp2(qBits) * nativeError
		composed := collision + algebraic
		full.AccountingMode = PIOP.FullGameAccountingAggregateV4
		full.AggregateQueryCapLog2 = qBits
		full.MaxNativeAlgebraicError = nativeError
		full.MaxNativeAlgebraicBits = nativeBits
		full.IssuanceQueryCapBits = [5]float64{-1, -1, -1, -1, -1}
		full.ShowingQueryCapBits = [5]float64{-1, -1, -1, -1, -1}
		full.GlobalQueryCapBits = [5]float64{-1, -1, -1, -1, -1}
		full.ConservativeFullGameError = composed
		full.ConservativeFullGameBits = -math.Log2(composed)
		full.GlobalCollisionFullGameError = composed
		full.GlobalCollisionFullGameBits = -math.Log2(composed)
		full.GlobalCollisionError = collision
		full.GlobalCollisionBits = -math.Log2(collision)
		full.IssuanceAlgebraicContribution = algebraic
	} else {
		makeWFPhase := func(tuning credential.IntGenISISTuningPreset, raw [4]float64) benchmarkPhaseWire {
			phase := benchmarkPhaseWire{
				WorkFactorMode: true, CollisionSpaceBits: tuning.FSOutputBits,
				RawRoundBits: raw, RoundBits: raw,
				TheoremBits: [4]float64{-1, -1, -1, -1}, AlgebraicBits: [4]float64{-1, -1, -1, -1},
				TheoremTotalBits: -1, AlgebraicTotalBits: -1, CollisionBits: -1, OneProofTotalBits: -1,
				ROQueryCapBits: [5]float64{-1, -1, -1, -1, -1},
			}
			phase.WorkFactorComponents[0] = float64(tuning.FSOutputBits) / 2
			phase.WorkFactorComponents[5] = float64(tuning.DECSTapeBits)
			phase.WorkFactorBits = phase.WorkFactorComponents[0]
			for i := range raw {
				phase.NativeAlgebraicBits[i] = raw[i] + float64(tuning.Kappa[i])
				phase.NativeAlgebraicTerms[i] = math.Exp2(-phase.NativeAlgebraicBits[i])
				phase.WorkFactorComponents[i+1] = phase.NativeAlgebraicBits[i]
				if phase.NativeAlgebraicBits[i] < phase.WorkFactorBits {
					phase.WorkFactorBits = phase.NativeAlgebraicBits[i]
				}
			}
			if phase.WorkFactorComponents[5] < phase.WorkFactorBits {
				phase.WorkFactorBits = phase.WorkFactorComponents[5]
			}
			return phase
		}
		issuancePhase = makeWFPhase(candidate.Issuance, candidate.Projection.RawRoundBitsIssuance)
		showingPhase = makeWFPhase(candidate.Showing, candidate.Projection.RawRoundBitsShowing)
		maxNativeBits := math.Inf(1)
		for _, phase := range [][4]float64{issuancePhase.NativeAlgebraicBits, showingPhase.NativeAlgebraicBits} {
			for _, bits := range phase {
				if bits < maxNativeBits {
					maxNativeBits = bits
				}
			}
		}
		full.AccountingMode = PIOP.FullGameAccountingWorkFactorV4
		full.WorkFactorBits = math.Min(issuancePhase.WorkFactorBits, showingPhase.WorkFactorBits)
		full.IssuanceWorkFactorBits = issuancePhase.WorkFactorBits
		full.ShowingWorkFactorBits = showingPhase.WorkFactorBits
		full.MaxNativeAlgebraicBits = maxNativeBits
		full.MaxNativeAlgebraicError = math.Exp2(-maxNativeBits)
		full.ConservativeFullGameError = math.Exp2(-full.WorkFactorBits)
		full.ConservativeFullGameBits = full.WorkFactorBits
		full.GlobalCollisionFullGameError = full.ConservativeFullGameError
		full.GlobalCollisionFullGameBits = full.WorkFactorBits
		full.GlobalCollisionError = math.Exp2(-float64(candidate.Showing.FSOutputBits) / 2)
		full.GlobalCollisionBits = float64(candidate.Showing.FSOutputBits) / 2
		full.IssuanceQueryCapBits = [5]float64{-1, -1, -1, -1, -1}
		full.ShowingQueryCapBits = [5]float64{-1, -1, -1, -1, -1}
		full.GlobalQueryCapBits = [5]float64{-1, -1, -1, -1, -1}
	}
	return benchmarkReportWire{
		SecurityProfile: preset.SecurityProfile, SecurityMode: preset.SecurityMode, PRFProfile: preset.PRFProfile,
		PRFParamsDigest: preset.PRFParamsDigest, ThreatModel: preset.ThreatModel, FullGame: full,
		ParameterAudit: credential.AuditIntGenISISSecurityParameters(spec, actual),
		Issuance:       issuancePhase, Showing: showingPhase,
	}
}

func publicationV4Clone[T any](t *testing.T, value T) T {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
