package evidence

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/sourceintegrity"
)

const focusedV3TimeTestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestValidateFocusedV3TimeOptimizationEvidence(t *testing.T) {
	e := focusedV3TimeValidAcceptedEvidence(t)
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, false); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*FocusedV3TimeOptimizationEvidence)
	}{
		{"scope", func(e *FocusedV3TimeOptimizationEvidence) { e.ClaimScope = "complete" }},
		{"full-game claim", func(e *FocusedV3TimeOptimizationEvidence) { e.Claims.FullGameSecurity = true }},
		{"source", func(e *FocusedV3TimeOptimizationEvidence) { e.SourceInput.Digest = "bad" }},
		{"manifest", func(e *FocusedV3TimeOptimizationEvidence) { e.Targets[0].ManifestDigest = focusedV3TimeTestDigest }},
		{"kappa", func(e *FocusedV3TimeOptimizationEvidence) { e.Targets[0].Kappa[0]++ }},
		{"fixed proof", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].PairedRuns[0].Issuance.CandidateProofSHA256 = strings.Repeat("b", 64)
		}},
		{"fixed counter", func(e *FocusedV3TimeOptimizationEvidence) { e.Targets[0].PairedRuns[0].Showing.CandidateCounters[3]++ }},
		{"duplicate entropy seed", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].PairedRuns[1].EntropySeedSHA256 = e.Targets[0].PairedRuns[0].EntropySeedSHA256
		}},
		{"paired artifact path", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].PairedRuns[0].MeasurementArtifactPath = "wrong"
		}},
		{"presentation", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].PairedRuns[0].PresentationByteIdentical = false
		}},
		{"internal trace", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].PairedRuns[0].CandidateInternalTraceSHA256 = strings.Repeat("b", 64)
		}},
		{"summary", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].PairedSummary.Showing.CandidateProvingMedianMS++
		}},
		{"geometry", func(e *FocusedV3TimeOptimizationEvidence) { e.Targets[0].ShowingGeometry.LogicalRows++ }},
		{"theorem", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].FreshRuns[0].Showing.Theorem.TheoremTotalBits = 127
		}},
		{"engineering theorem target", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].FreshRuns[0].Showing.Theorem.AlgebraicTotalBits = 131
		}},
		{"paper size", func(e *FocusedV3TimeOptimizationEvidence) { e.Targets[0].FreshRuns[0].Showing.Paper.QBytes++ }},
		{"wire size", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].FreshRuns[0].Showing.CanonicalWire.TotalBytes++
		}},
		{"verification", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].FreshRuns[0].Showing.VerificationPassed = false
		}},
		{"zero knowledge", func(e *FocusedV3TimeOptimizationEvidence) {
			e.Targets[0].FreshRuns[0].Showing.ZeroKnowledgeEligible = false
		}},
		{"replay", func(e *FocusedV3TimeOptimizationEvidence) { e.Targets[0].FreshRuns[0].ReplayRejected = false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mutated := focusedV3TimeCloneEvidence(t, e)
			tt.mutate(&mutated)
			if err := ValidateFocusedV3TimeOptimizationEvidence(mutated, false); err == nil {
				t.Fatal("mutated evidence was accepted")
			}
		})
	}
}

func TestFocusedV3TimeOptimizationRequiresFiveDirectionsAndThreePercent(t *testing.T) {
	e := focusedV3TimeValidAcceptedEvidence(t)
	for i := 0; i < 3; i++ {
		e.Targets[0].PairedRuns[i].Showing.Candidate.ProvingMS = 101
	}
	summary := focusedV3TimeSummarizePairs(e.Targets[0].PairedRuns)
	e.Targets[0].PairedSummary = &summary
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, false); err == nil {
		t.Fatal("four-of-seven improvement direction was accepted")
	}

	e = focusedV3TimeValidAcceptedEvidence(t)
	for i := range e.Targets[0].PairedRuns {
		e.Targets[0].PairedRuns[i].Issuance.Candidate.ProvingMS = 98
	}
	summary = focusedV3TimeSummarizePairs(e.Targets[0].PairedRuns)
	e.Targets[0].PairedSummary = &summary
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, false); err == nil {
		t.Fatal("two-percent cumulative improvement was accepted")
	}
}

func TestFocusedV3TimeCounterWidthVariationRequiresExplanation(t *testing.T) {
	e := focusedV3TimeValidAcceptedEvidence(t)
	e.Targets[0].FreshRuns[1].Showing.CanonicalWire.CounterBytes++
	e.Targets[0].FreshRuns[1].Showing.CanonicalWire.TotalBytes++
	e.Targets[0].FreshRuns[1].PresentationBytes++
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, false); err == nil {
		t.Fatal("unexplained counter-width variation was accepted")
	}
	e.Targets[0].CounterWidthExplanation = FocusedV3TimeCounterReason
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, false); err != nil {
		t.Fatal(err)
	}
}

func TestPendingFocusedV3TimeOptimizationIsFailClosed(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewPendingFocusedV3TimeOptimizationEvidence(root, "2026-08-05", "f8973f05473c9110081324a0f2671fa410fb12f3", "measurements not installed")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, false); err == nil {
		t.Fatal("pending evidence was accepted without allowPending")
	}
	if err := ValidateFocusedV3TimeOptimizationArtifacts(e, root, true); err != nil {
		t.Fatal(err)
	}
}

func TestPendingFocusedV3TimeOptimizationCanBindFreshRuns(t *testing.T) {
	e := focusedV3TimeValidAcceptedEvidence(t)
	e.Status = FocusedV3TimeStatusPending
	e.PendingReason = FocusedV3TimeFreshPendingReason
	for i := range e.Targets {
		e.Targets[i].PairedRuns = nil
		e.Targets[i].PairedSummary = nil
	}
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, true); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, false); err == nil {
		t.Fatal("partial fresh-run evidence was accepted as final")
	}
	e.PendingReason = "paired trials pending"
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, true); err == nil {
		t.Fatal("pending fresh-run evidence omitted the BQ128 engineering-gate blocker")
	}
	e.PendingReason = FocusedV3TimeFreshPendingReason
	e.Targets[0].FreshRuns[0].ReportSHA256 = "bad"
	if err := ValidateFocusedV3TimeOptimizationEvidence(e, true); err == nil {
		t.Fatal("malformed pending fresh-run evidence was accepted")
	}
}

func TestFocusedV3TimeFreshPendingReasonTracksAllKnownBlockers(t *testing.T) {
	for _, fragment := range []string{
		"seven paired fixed-entropy",
		"allocation counters",
		"BQ128 executable-preset engineering gate",
		"131.511683",
		"TargetTheoremBits=131.540568",
		"128-bit phase gate passes",
	} {
		if !strings.Contains(FocusedV3TimeFreshPendingReason, fragment) {
			t.Fatalf("pending reason omits %q", fragment)
		}
	}
}

func TestCheckedFocusedV3TimeOptimizationScaffold(t *testing.T) {
	path := "focused-v3-time-optimization.json"
	e, err := ReadFocusedV3TimeOptimizationEvidence(path)
	if err != nil {
		t.Fatal(err)
	}
	if e.Status == FocusedV3TimeStatusPending {
		if err := ValidateFocusedV3TimeOptimizationArtifacts(e, "..", true); err != nil {
			t.Fatal(err)
		}
		t.Skip("time-optimization evidence is explicitly pending required adoption gates")
	}
	if err := ValidateFocusedV3TimeOptimizationArtifacts(e, "..", false); err != nil {
		t.Fatal(err)
	}
}

func focusedV3TimeValidAcceptedEvidence(t *testing.T) FocusedV3TimeOptimizationEvidence {
	t.Helper()
	e := FocusedV3TimeOptimizationEvidence{
		Schema: FocusedV3TimeOptimizationSchema, Version: FocusedV3TimeOptimizationVersion, Status: FocusedV3TimeStatusAccepted,
		MeasuredOn: "2026-08-05", ClaimScope: string(credential.ClaimProofOnly), ImplementationBaseCommit: "f8973f05473c9110081324a0f2671fa410fb12f3",
		SourceInput:   FocusedV3TimeSourceInput{Algorithm: sourceintegrity.Algorithm, Digest: focusedV3TimeTestDigest, FileCount: 200},
		Environment:   FocusedV3TimeEnvironment{GoVersion: "go1.23.12", GOOS: "darwin", GOARCH: "arm64", NumCPU: 15, GOMAXPROCS: 15},
		PriorEvidence: FocusedV3TimePriorEvidence{Path: FocusedV3TimePriorPath, SHA256: focusedV3TimeTestDigest, Schema: "spruce.focused-v3-final-size-optimization", Version: 1},
		Paper:         FocusedV3PaperTreeEvidence{HeadBefore: "d19818571f04c8c12425e2e7c10ceb41f7a1762d", HeadAfter: "d19818571f04c8c12425e2e7c10ceb41f7a1762d", CleanBefore: true, CleanAfter: true},
		Claims:        focusedV3TimeClaims(), Protocol: focusedV3TimeProtocol(), MeasurementPolicy: focusedV3TimePolicy(),
	}
	for _, id := range focusedV3TargetPresetIDs {
		preset, _ := credential.LookupIntGenISISPreset(id)
		issueGeometry, showGeometry, _ := focusedV3TimeExpectedGeometry(id)
		target := FocusedV3TimeOptimizationTarget{
			CanonicalID: id, ManifestDigest: credential.IntGenISISPresetManifestDigest(preset), Kappa: preset.Issuance.Kappa,
			BaselineAccepted: FocusedV3NonResearchPrior{PersistentStateBytes: 10, IssuanceProofWireBytes: 160, ShowingProofWireBytes: 160, PresentationWireBytes: 200, PaperIssuanceBytes: 100, PaperShowingBytes: 100, IssuanceProvingMS: 100, ShowingProvingMS: 100, PeakRSSBytes: 1000},
			IssuanceGeometry: issueGeometry, ShowingGeometry: showGeometry,
		}
		for pair := 1; pair <= FocusedV3TimePairedRuns; pair++ {
			artifactPath, err := focusedV3TimePairedArtifactPath(id, pair)
			if err != nil {
				t.Fatal(err)
			}
			phase := FocusedV3TimeDifferentialPhase{
				Baseline:            FocusedV3TimePerformance{ProvingMS: 100, VerificationMS: 10, AllocatedBytes: 1000, Allocations: 100, PeakRSSBytes: 1000},
				Candidate:           FocusedV3TimePerformance{ProvingMS: 90, VerificationMS: 10, AllocatedBytes: 900, Allocations: 90, PeakRSSBytes: 900},
				BaselineProofSHA256: focusedV3TimeTestDigest, CandidateProofSHA256: focusedV3TimeTestDigest,
				BaselineCounters: [4]uint64{0, 1, 255, 256}, CandidateCounters: [4]uint64{0, 1, 255, 256}, ByteIdentical: true,
			}
			target.PairedRuns = append(target.PairedRuns, FocusedV3TimePairedRun{
				Pair: pair, EntropySeedSHA256: fmt.Sprintf("%064x", pair), Issuance: phase, Showing: phase,
				BaselineInternalTraceSHA256: focusedV3TimeTestDigest, CandidateInternalTraceSHA256: focusedV3TimeTestDigest, InternalTraceByteIdentical: true,
				BaselinePresentationSHA256: focusedV3TimeTestDigest, CandidatePresentationSHA256: focusedV3TimeTestDigest, PresentationByteIdentical: true,
				MeasurementArtifactPath: artifactPath, MeasurementArtifactSHA256: focusedV3TimeTestDigest,
			})
		}
		pairedSummary := focusedV3TimeSummarizePairs(target.PairedRuns)
		target.PairedSummary = &pairedSummary
		for run := 1; run <= FocusedV3TimeOptimizationRuns; run++ {
			alias, _ := focusedV3NonResearchTargetAlias(id)
			dir := filepath.ToSlash(filepath.Join(FocusedV3TimeArtifactRoot, alias, "run-"+string(rune('0'+run))))
			issuePhase := focusedV3TimeTestFreshPhase("e2e_presign")
			showPhase := focusedV3TimeTestFreshPhase("e2e_showing_standalone")
			target.FreshRuns = append(target.FreshRuns, FocusedV3TimeFreshRun{
				Run: run, ArtifactDirectory: dir, ReportPath: dir + "/report.json", ReportSHA256: focusedV3TimeTestDigest,
				ResourcePath: dir + "/resource.txt", ResourceSHA256: focusedV3TimeTestDigest,
				StateBytes: 10, StateSHA256: focusedV3TimeTestDigest, PresentationBytes: 200, PresentationSHA256: focusedV3TimeTestDigest,
				PeakRSSBytes: 900, ParameterAuditStatus: "pass", ReplayRejected: true, Issuance: issuePhase, Showing: showPhase,
			})
		}
		freshMedians := focusedV3TimeFreshMedians(target.FreshRuns)
		target.FreshMedians = &freshMedians
		e.Targets = append(e.Targets, target)
	}
	return e
}

func focusedV3TimeTestFreshPhase(measurementStatus string) FocusedV3TimeFreshPhase {
	label := "issuance"
	if measurementStatus == "e2e_showing_standalone" {
		label = "showing"
	}
	phaseTimings := make([]PIOP.PhaseTiming, 0, len(focusedV3TimeRequiredPhaseLabels(label)))
	for _, required := range focusedV3TimeRequiredPhaseLabels(label) {
		phaseTimings = append(phaseTimings, PIOP.PhaseTiming{Label: required, Milliseconds: 1})
	}
	wire := PIOP.CanonicalProofWireAuditV6{
		CodecVersion: PIOP.CanonicalProofCodecVersionV6, CodecProfile: PIOP.CanonicalProofCodecProfileV6,
		ProofSchemaVersion: PIOP.ProofSchemaVersionV3, FieldEncoding: PIOP.CanonicalProofFieldEncodingV6,
		QKernelEncoding: PIOP.CanonicalProofQKernelEncodingV6, RadixQGroupElements: PIOP.CanonicalProofRadixQGroupElementsV6,
		MerkleTopology: decs.MerkleTopologyExactNV3,
		HeaderBytes:    10, RootBytes: 49, SaltBytes: 25, CounterBytes: 6,
		RBytes: 10, QBytes: 10, VTargetsBytes: 10, BarSetsBytes: 10, OpeningPBytes: 10, TapeBytes: 10, AuthenticationBytes: 10,
		TotalBytes: 160, MerkleNodesUsed: 1, MerkleNodesBound: 1,
	}
	return FocusedV3TimeFreshPhase{
		ProvingMS: 90, VerificationMS: 10, VerificationPassed: true, MeasurementStatus: measurementStatus, ZeroKnowledgeEligible: true,
		FSCounters: [4]uint64{0, 1, 255, 256}, PhaseTimings: phaseTimings, CanonicalWire: wire,
		Paper: FocusedV3TimePaperComponents{FixedBytes: 10, RBytes: 10, QBytes: 10, PDECSBytes: 10, MDECSBytes: 10, AuthenticationBytes: 10, TapeBytes: 10, SignatureShortnessBytes: 10, VTargetsBytes: 10, BarSetsBytes: 10, TotalBytes: 100},
		Theorem: FocusedV3TimeTheorem{
			AlgebraicTerms: [4]float64{1, 1, 1, 1}, AlgebraicBits: [4]float64{132, 132, 132, 132}, AlgebraicTotalBits: 132,
			TheoremBits: [4]float64{130, 130, 130, 130}, TheoremTotalBits: 128.5,
		},
		ProofSHA256: focusedV3TimeTestDigest,
	}
}

func focusedV3TimeCloneEvidence(t *testing.T, in FocusedV3TimeOptimizationEvidence) FocusedV3TimeOptimizationEvidence {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out FocusedV3TimeOptimizationEvidence
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
