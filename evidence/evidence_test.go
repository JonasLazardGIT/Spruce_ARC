package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func TestPendingLockIsStableAndExplicit(t *testing.T) {
	root := testSPRUCE_DIR(t)
	reports := t.TempDir()
	one, err := BuildArtifactLock(BuildOptions{SPRUCE_DIR: root, ReportsDir: reports, AllowPending: true})
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildArtifactLock(BuildOptions{SPRUCE_DIR: root, ReportsDir: reports, AllowPending: true})
	if err != nil {
		t.Fatal(err)
	}
	left, _ := MarshalArtifactLock(one)
	right, _ := MarshalArtifactLock(two)
	if string(left) != string(right) {
		t.Fatal("pending lock is not stable")
	}
	if one.Status != "pending" || len(one.Presets) != 7 {
		t.Fatalf("status=%q presets=%d", one.Status, len(one.Presets))
	}
	for _, preset := range one.Presets {
		if preset.Benchmark != nil || preset.Baseline != nil || preset.PendingReason == "" {
			t.Fatalf("preset %s is not explicitly pending", preset.CanonicalID)
		}
	}
	if err := ValidateArtifactLock(one, ValidationOptions{SPRUCE_DIR: root, ReportsDir: reports}); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("final validation accepted pending lock: %v", err)
	}
	if err := ValidateArtifactLock(one, ValidationOptions{SPRUCE_DIR: root, ReportsDir: reports, AllowPending: true}); err != nil {
		t.Fatalf("bootstrap validation: %v", err)
	}
}

func TestMissingFinalReportNamesTheRequiredV2Artifact(t *testing.T) {
	root := testSPRUCE_DIR(t)
	reports := t.TempDir()
	_, err := BuildArtifactLock(BuildOptions{SPRUCE_DIR: root, ReportsDir: reports})
	if err == nil || !strings.Contains(err.Error(), canonicalV2PresetIDs[0]) ||
		!strings.Contains(err.Error(), DefaultBaselineFileName) || !strings.Contains(err.Error(), "--allow-pending") {
		t.Fatalf("missing-report error is not actionable: %v", err)
	}
}

func TestCompleteLockReportsAndGeneratedTeXRoundTrip(t *testing.T) {
	root := testSPRUCE_DIR(t)
	reports := t.TempDir()
	writeSyntheticReports(t, reports)
	lock, err := BuildArtifactLock(BuildOptions{SPRUCE_DIR: root, ReportsDir: reports})
	if err != nil {
		t.Fatal(err)
	}
	if lock.Status != "complete" || lock.ReportsDigest == "" || lock.RunReportsDigest == "" ||
		lock.RunCount != 3 || lock.RunDigestCount != 21 || lock.EvidenceDigest == "" {
		t.Fatalf("incomplete lock metadata: %+v", lock)
	}
	encodedLock, err := MarshalArtifactLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedLock), root) || strings.Contains(string(encodedLock), reports) {
		t.Fatal("artifact lock exposes an absolute checkout or report path")
	}
	lockPath := filepath.Join(t.TempDir(), DefaultLockFileName)
	if err := WriteArtifactLock(lockPath, lock); err != nil {
		t.Fatal(err)
	}
	generated := t.TempDir()
	if err := WriteGeneratedTeX(generated, lock); err != nil {
		t.Fatal(err)
	}
	if err := ValidateArtifactLockFile(lockPath, ValidationOptions{
		SPRUCE_DIR: root, ReportsDir: reports, GeneratedTeXDir: generated,
	}); err != nil {
		t.Fatal(err)
	}
	macros, err := os.ReadFile(filepath.Join(generated, GeneratedMacrosFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(macros), lock.EvidenceDigest) || strings.Contains(string(macros), root) {
		t.Fatal("generated macros omit the digest or expose an absolute checkout path")
	}
	if err := os.WriteFile(filepath.Join(generated, GeneratedTableFileName), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGeneratedTeX(generated, lock); err == nil {
		t.Fatal("tampered generated TeX accepted")
	}
}

func TestStrictLockJSONRejectsUnknownAndTrailing(t *testing.T) {
	root := testSPRUCE_DIR(t)
	lock, err := BuildArtifactLock(BuildOptions{SPRUCE_DIR: root, ReportsDir: t.TempDir(), AllowPending: true})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), encoded[:len(encoded)-1]...)
	unknown = append(unknown, []byte(`,"legacy_version":1}`)...)
	path := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(path, unknown, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArtifactLock(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field was not rejected: %v", err)
	}
	if err := os.WriteFile(path, append(encoded, []byte(` {}`)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArtifactLock(path); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing JSON was not rejected: %v", err)
	}
	legacy := lock
	legacy.Version = 1
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacyBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadArtifactLock(path); err == nil || !strings.Contains(err.Error(), "no migration") {
		t.Fatalf("legacy lock was not rejected: %v", err)
	}
}

func TestReportDigestTamperingFailsValidation(t *testing.T) {
	root := testSPRUCE_DIR(t)
	reports := t.TempDir()
	writeSyntheticReports(t, reports)
	lock, err := BuildArtifactLock(BuildOptions{SPRUCE_DIR: root, ReportsDir: reports})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(reports, canonicalV2PresetIDs[0], DefaultBenchmarkFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateArtifactLock(lock, ValidationOptions{SPRUCE_DIR: root, ReportsDir: reports}); err == nil || !strings.Contains(err.Error(), "canonical report is not an exact copy") {
		t.Fatalf("report tampering was not detected: %v", err)
	}
}

func TestBenchmarkReportJSONIsRecursivelyStrict(t *testing.T) {
	preset, ok := credential.LookupIntGenISISPreset(canonicalV2PresetIDs[0])
	if !ok {
		t.Fatal("missing canonical preset")
	}
	encoded, err := json.Marshal(syntheticReport(preset))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	issuance := object["issuance"].(map[string]any)
	issuance["nonce_seed"] = "legacy"
	tampered, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), DefaultBenchmarkFileName)
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeBenchmarkReport(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("nested unknown report field accepted: %v", err)
	}
	if err := os.WriteFile(path, append(encoded, []byte(` {}`)...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeBenchmarkReport(path); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing report JSON accepted: %v", err)
	}
}

func TestBenchmarkReportRejectsLegacyIdentityBeforeInference(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultBenchmarkFileName)
	legacy := []byte(`{"version":1,"nonce_seed":"legacy"}`)
	if err := os.WriteFile(path, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeBenchmarkReport(path); err == nil || !strings.Contains(err.Error(), "no migration") {
		t.Fatalf("legacy report did not fail at the v2 epoch boundary: %v", err)
	}
}

func TestBenchmarkReportRejectsMixedV2Accounting(t *testing.T) {
	preset, ok := credential.LookupIntGenISISPreset(canonicalV2PresetIDs[0])
	if !ok {
		t.Fatal("missing canonical preset")
	}
	tests := []struct {
		name   string
		mutate func(*benchmarkReportWire)
	}{
		{"manifest", func(report *benchmarkReportWire) { report.PresetManifestDigest = strings.Repeat("0", 64) }},
		{"tape mode", func(report *benchmarkReportWire) { report.Showing.TapeDisclosureMode = "seed_derived" }},
		{"omission mode", func(report *benchmarkReportWire) { report.Options.Showing.TranscriptOmissionMode = "legacy_omission" }},
		{"leaf version", func(report *benchmarkReportWire) { report.Showing.LeafEncodingVersion = 1 }},
		{"root width", func(report *benchmarkReportWire) { report.Showing.RootWidthBytes-- }},
		{"eligibility", func(report *benchmarkReportWire) { report.Showing.ZeroKnowledgeEligible = false }},
		{"cubic degree", func(report *benchmarkReportWire) {
			report.Showing.ParallelDegree = 2
			report.Showing.ParallelAlgDegree = 2
			report.Showing.RelationCandidate.ParallelDegree = 2
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := syntheticReport(preset)
			test.mutate(&report)
			if err := validateBenchmarkReport(report, preset); err == nil {
				t.Fatal("mixed/invalid accounting accepted")
			}
		})
	}
}

func TestResolveSPRUCE_DIRFromEnvironment(t *testing.T) {
	root := testSPRUCE_DIR(t)
	t.Setenv("SPRUCE_DIR", root)
	got, err := ResolveSPRUCE_DIR("")
	if err != nil {
		t.Fatal(err)
	}
	if got != root {
		t.Fatalf("got %q want %q", got, root)
	}
}

func TestLockedV2IdentitiesAndPresetOrder(t *testing.T) {
	identities := ProtocolIdentitiesV2()
	if identities.ProtocolMode != credential.IntGenISISTranscriptProtocolV2 ||
		identities.TranscriptVersion != credential.IntGenISISTranscriptVersionV2 ||
		identities.SecurityStatus != credential.IntGenISISSecurityGateV2 ||
		identities.PCSGeometry != "smallfield_matrix_v2" ||
		identities.OmissionDescriptor != "digest_bound_payload_v2" ||
		identities.LeafEncodingVersion != 2 || identities.TapeDisclosureMode != "independent_selective" {
		t.Fatalf("unexpected v2 identities: %+v", identities)
	}
	schemas := identities.Schemas
	if schemas.PIOPProof != 2 || schemas.DECSOpening != 2 || schemas.PublicParameters != 8 ||
		schemas.IssuanceRequest != 3 || schemas.PresignSubmission != 3 || schemas.IssuanceResponse != 3 || schemas.HolderSecret != 3 ||
		schemas.CredentialState != 7 || schemas.VerifierKey != 2 || schemas.Presentation != 2 ||
		schemas.VerifierState != 2 || schemas.E2EReport != 2 || schemas.BMatrix != 3 || schemas.NTRUParameters != 2 {
		t.Fatalf("unexpected v2 schemas: %+v", schemas)
	}
	want := []string{
		"poc-n512-sc96-v2", "artifact-n1024-sc125-v2", "artifact-n1024-bq10-r96-v2",
		"artifact-n1024-bq16-r96-v2", "pilot-n1024-bq32-r96-v2", "poc-n1024-bq64-r128-v2",
		"poc-n1024-bq96-r128-v2",
	}
	got := CanonicalV2PresetIDs()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("canonical preset order=%v", got)
	}
}

func TestFocusedV3TargetsAreDisjointAndStrict(t *testing.T) {
	want := []string{
		credential.IntGenISISPresetPoCN1024BQ128R128V3,
		credential.IntGenISISPresetSystemN1024WF128CROMV2,
	}
	got := FocusedV3TargetPresetIDs()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("focused v3 target order=%v", got)
	}
	historical := make(map[string]bool, len(canonicalV2PresetIDs))
	for _, id := range canonicalV2PresetIDs {
		historical[id] = true
	}
	for _, id := range got {
		if historical[id] {
			t.Fatalf("focused v3 target %s also appears in the historical-v2 lock", id)
		}
		preset, ok := credential.LookupIntGenISISPreset(id)
		if !ok {
			t.Fatalf("missing focused v3 target %s", id)
		}
		if err := ValidateFocusedV3TargetPreset(preset); err != nil {
			t.Fatalf("focused v3 target %s: %v", id, err)
		}
	}

	nontarget, ok := credential.LookupIntGenISISPreset(canonicalV2PresetIDs[0])
	if !ok {
		t.Fatal("missing historical-v2 preset")
	}
	if err := ValidateFocusedV3TargetPreset(nontarget); err == nil || !strings.Contains(err.Error(), "not a focused v3 target") {
		t.Fatalf("historical-v2 preset accepted as focused v3 evidence: %v", err)
	}
}

func testSPRUCE_DIR(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func writeSyntheticReports(t *testing.T, reports string) {
	t.Helper()
	for _, canonicalID := range canonicalV2PresetIDs {
		preset, ok := credential.LookupIntGenISISPreset(canonicalID)
		if !ok {
			t.Fatalf("missing preset %s", canonicalID)
		}
		writeSyntheticRunsForPreset(t, reports, preset)
	}
	if _, err := GenerateThreeRunBaselines(BaselineOptions{SPRUCE_DIR: testSPRUCE_DIR(t), ReportsDir: reports}); err != nil {
		t.Fatal(err)
	}
}

func writeSyntheticRunsForPreset(t *testing.T, reports string, preset credential.IntGenISISPreset) {
	t.Helper()
	dir := filepath.Join(reports, preset.CanonicalID, "runs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for run := 1; run <= BaselineRunCountV2; run++ {
		report := syntheticReport(preset)
		applySyntheticRunTimings(&report, run)
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, baselineRunFileName(run)), append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func applySyntheticRunTimings(report *benchmarkReportWire, run int) {
	report.Generated = fmt.Sprintf("2026-08-0%dT00:00:00Z", run)
	setupPublic := [3]float64{1, 100, 10}
	setupNTRU := [3]float64{200, 2, 20}
	holderCommit := [3]float64{30, 300, 3}
	holderProve := [3]float64{4, 40, 400}
	issuerSign := [3]float64{500, 50, 5}
	holderFinalize := [3]float64{60, 6, 600}
	issuanceProve := [3]float64{10, 30, 20}
	issuanceVerify := [3]float64{50, 5, 15}
	showingProve := [3]float64{300, 100, 200}
	showingVerify := [3]float64{8, 7, 9}
	i := run - 1
	report.Timings = benchmarkTimingsWire{
		SetupPublicMS: setupPublic[i], SetupNTRUKeysMS: setupNTRU[i],
		HolderCommitMS: holderCommit[i], HolderProveMS: holderProve[i],
		IssuerSignMS: issuerSign[i], HolderFinalizeMS: holderFinalize[i],
	}
	report.Issuance.ProvingMS, report.Issuance.VerificationMS = issuanceProve[i], issuanceVerify[i]
	report.Showing.ProvingMS, report.Showing.VerificationMS = showingProve[i], showingVerify[i]
}

func syntheticReport(preset credential.IntGenISISPreset) benchmarkReportWire {
	issuanceTuning := tuningWireFromPreset(preset.Issuance)
	showingTuning := tuningWireFromPreset(preset.Showing)
	securitySpec, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		panic("missing synthetic-report security profile " + preset.SecurityProfile)
	}
	ledgerStatus := string(securitySpec.Status)
	return benchmarkReportWire{
		Version: 2, Generated: "2026-08-03T00:00:00Z", Preset: preset.Name,
		CanonicalPresetID: preset.CanonicalID, PresetVersion: preset.PresetVersion,
		PresetLifecycle: preset.Lifecycle, ClaimScope: preset.ClaimScope,
		PrimitiveProfileID:   preset.PrimitiveProfileID,
		PresetManifestDigest: credential.IntGenISISPresetManifestDigest(preset),
		ThreatModel:          preset.ThreatModel, Profile: preset.Profile,
		SecurityProfile: preset.SecurityProfile, SecurityMode: preset.SecurityMode,
		CompleteSystemClaim: false, PRFProfile: preset.PRFProfile,
		PRFParamsPath: preset.PRFParamsPath, PRFParamsDigest: preset.PRFParamsDigest,
		LedgerStatus: ledgerStatus, CoreBitsRequired: preset.CoreBitsRequired,
		CoreAvailableBits: 128, SoundnessBits: preset.TargetTheoremBits,
		ZeroKnowledgeBits: preset.TargetTheoremBits, PrimitiveBits: 128,
		CompositionBits: preset.TargetTheoremBits, TagCollisionBits: 128,
		SaltCollisionBits: 128, TapeGuessingBits: 128, ProgrammingBits: 128,
		ChallengeBiasBits: 128, RequiredPhaseAlgebraicBits: 90,
		PhaseAlgebraicSlackBits: 6, Modulus: 12289, ProfileBound: 1,
		ArtifactDir: "artifacts/smallwood-salted-v2/" + preset.CanonicalID,
		MaxNLeaves:  preset.MaxNLeaves,
		Options:     benchmarkOptionsWire{Issuance: issuanceTuning, Showing: showingTuning},
		Environment: benchmarkEnvironmentWire{GoVersion: "go-test", GOOS: "linux", GOARCH: "amd64", NumCPU: 1, GOMAXPROCS: 1}, Timings: benchmarkTimingsWire{
			SetupPublicMS: 1, SetupNTRUKeysMS: 2, HolderCommitMS: 3,
			HolderProveMS: 4, IssuerSignMS: 5, HolderFinalizeMS: 6,
		},
		Issuance: syntheticPhase(preset.Issuance, false),
		Showing:  syntheticPhase(preset.Showing, true),
		FullGame: PIOP.FullGameSoundnessReport{
			AcceptedIssuance:         preset.ThreatModel.AcceptedIssuance,
			AcceptedShowing:          preset.ThreatModel.AcceptedShowing,
			ConservativeFullGameBits: 100, GlobalCollisionBits: 100, GlobalCollisionFullGameBits: 100,
		},
		SecurityLedger: credential.SystemSecurityLedger{
			SecurityProfile: preset.SecurityProfile, SecurityMode: preset.SecurityMode,
			CompleteSystemClaim: false, LedgerStatus: ledgerStatus,
			TargetBits: preset.TargetTheoremBits, FullGameBits: 100,
		},
		ParameterAudit: credential.IntGenISISSecurityParameterAudit{Status: "pass"},
		ReplayRejected: true, Notes: []string{},
	}
}

func tuningWireFromPreset(tuning credential.IntGenISISTuningPreset) benchmarkTuningWire {
	return benchmarkTuningWire{
		NCols: tuning.NCols, LVCSNCols: tuning.LVCSNCols, NLeaves: tuning.NLeaves,
		Eta: tuning.Eta, Theta: tuning.Theta, Rho: tuning.Rho, Ell: tuning.Ell,
		EllPrime: tuning.EllPrime, Kappa: tuning.Kappa, ROQueryCaps: tuning.ROQueryCaps,
		ROQueryCapBits: tuning.ROQueryCapBits, DECSCollisionBits: tuning.DECSCollisionBits,
		DECSHashBits: tuning.DECSHashBits, DECSTapeBits: tuning.DECSTapeBits,
		FSCollisionBits: tuning.FSCollisionBits, SaltBits: tuning.SaltBits,
		PRFProfile: tuning.PRFProfile, PRFParamsPath: tuning.PRFParamsPath,
		PRFCompanionMode: tuning.PRFCompanionMode, PRFGroupRounds: tuning.PRFGroupRounds,
		CheckpointSamples: tuning.CheckpointSamples, SigShortnessRadix: tuning.SigShortnessRadix,
		SigShortnessDigits: tuning.SigShortnessDigits, CompressedRows: tuning.CompressedRows,
		ReplayProjection: tuning.ReplayProjection, TranscriptMode: tuning.TranscriptMode,
		TranscriptOmissionMode: tuning.TranscriptOmissionMode,
		FixedTranscriptSize:    tuning.FixedTranscriptSize,
	}
}

func syntheticPhase(tuning credential.IntGenISISTuningPreset, showing bool) benchmarkPhaseWire {
	hashBits, tapeBits, saltBits := tuning.DECSHashBits, tuning.DECSTapeBits, tuning.SaltBits
	if hashBits == 0 {
		hashBits = 256
	}
	if tapeBits == 0 {
		tapeBits = 128
	}
	if saltBits == 0 {
		saltBits = 256
	}
	relation := ""
	layout := ""
	prfRows := 0
	prfRelationVersion := 0
	if showing {
		relation = ShowingRelationV2
		layout = ShowingLayoutV2
		prfRows = 7
		prfRelationVersion = PRFCompanionRelationV2
	}
	return benchmarkPhaseWire{
		ProofSizeBytes: 2000, PaperTranscriptBytes: 1000, PaperTranscriptKB: 1,
		QBytes: 100, RBytes: 100, PdecsBytes: 100, AuthBytes: 100, TapesBytes: 100,
		TapeBytes: tapeBits / 8, TapeCount: 1, TapeWidthBytes: tapeBits / 8,
		TapeDisclosureMode: TapeDisclosureModeV2, LeafEncodingVersion: LeafEncodingVersionV2,
		RootWidthBytes: hashBits / 8, ZeroKnowledgeEligible: true,
		SigShortnessBytes: 100, VTargetsBytes: 100, BarSetsBytes: 100,
		TranscriptAudit: PIOP.PaperTranscriptAudit{Tapes: PIOP.OpeningTapePaperAudit{
			TapeBytes: tapeBits / 8, TapeCount: 1, TotalBytes: tapeBits / 8,
		}},
		ProvingMS: 10, VerificationMS: 5, TotalRows: 200, PRFRows: prfRows,
		CoefficientViewRows: 20, BoundRows: 10, ShortnessRows: 10, HatRows: 10,
		ReplayProjection: relation, LayoutVersion: layout, PRFCompanionRelationVersion: prfRelationVersion,
		ParallelDegree: 3, AggregatedDegree: 3,
		ParallelAlgDegree: 3, AggregatedAlgDegree: 3, MaskDegreeBound: 3,
		DominantDegreeSource: "formal_relation", TernaryRows: 10,
		TheoremBits: [4]float64{100, 100, 100, 100}, TheoremTotalBits: 100,
		ROQueryCaps: tuning.ROQueryCaps, ROQueryCapBits: tuning.ROQueryCapBits,
		CollisionSpaceBits: hashBits, FSLambdaBits: hashBits, EffectiveLambdaBits: hashBits,
		DECSHashBits: hashBits, DECSTapeBits: tapeBits, SaltBits: saltBits,
		TranscriptMode: ProtocolModeV2, AlgebraicTotalBits: 200, CollisionBits: 100,
		OneProofTotalBits: 100, SoundnessEq8Bits: 100, DQ: 3, DDECS: 3,
		WitnessSupportCols: 32, CommittedCols: tuning.LVCSNCols, ProofReportBuckets: 1,
		LVCSNCols: tuning.LVCSNCols, NLeaves: tuning.NLeaves, Eta: tuning.Eta,
		Ell: tuning.Ell, Theta: tuning.Theta, Rho: tuning.Rho, EllPrime: tuning.EllPrime,
		FixedTranscriptSize: true, TranscriptSizeMode: "fixed",
		PaperShapeCanonical: true, PaperShapeNRows: 200, PaperShapeQueries: 10, PaperShapeWitnessLayers: 1,
		TranscriptSecurityStatus: SecurityStatusV2, MeasurementStatus: "verified_v2",
		RelationCandidate: relationCandidateWire{
			LogicalRows: 200, ParallelDegree: 3, AggregatedDegree: 3, DQ: 3,
			MaskDegreeBound: 3, RowCounts: map[string]int{"total": 200},
			ConstraintCounts:     map[string]int{"range": 10},
			DominantDegreeSource: "formal_relation", DominantDQBranch: "parallel",
		},
	}
}
