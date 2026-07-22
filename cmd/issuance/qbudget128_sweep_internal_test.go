package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

const (
	qBudget128SweepTargetBits = 128.0

	qBudget128CategorySafePreset                  = "safe_preset"
	qBudget128CategoryHighKResearch               = "high_k_research"
	qBudget128CategoryRequiresTheoremAccounting   = "requires_theorem_accounting_work"
	qBudget128CategoryRejected                    = "rejected"
	qBudget128ResearchSummaryVersion              = 1
	qBudget128DefaultFrontierLimit                = 10
	qBudget128DefaultMaxE2E                       = 1
	qBudget128MaxSupportedGrinding                = 13
	qBudget128HighKThreshold                      = 10
	qBudget128HighKDeltaThreshold                 = 4
	qBudget128ResearchSummaryFilename             = "qbudget128-research-summary.json"
	qBudget128CollisionBitsQ10_128                = 152
	qBudget128CollisionBitsQ16_128                = 168
	qBudget128CollisionBitsQ32_128                = 200
	qBudget128QueryCapQ10                         = 1024
	qBudget128QueryCapQ16                         = 65536
	qBudget128QueryCapQ32                         = int(uint64(1) << 32)
	securityProfileFrontierCandidateByteReduction = "candidate_byte_reduction"
	securityProfileFrontierSecurityOnlyCandidate  = "security_only_candidate"
	qBudget128ProjectionNone                      = "none"
	qBudget128ProjectionProjectUDigitsYViewV3     = PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3
	qBudget128ProjectionProjectUDigitsYWResidual  = PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5

	securityProfileSweepSummaryVersion  = 1
	securityProfileSweepSummaryFilename = "security-profile-research-summary.json"
	bq32PreTuningShowingPaperBytes      = 37244
	bq32CandidateSoundnessThreshold     = 96.25
	bq32CandidateFullGameThreshold      = 96.25
	bq32CandidateZeroKnowledgeThreshold = 96.0
)

type qBudget128SweepCandidate struct {
	Name     string
	Family   string
	Issuance intGenISISTuning
	Showing  intGenISISTuning
}

type qBudget128BucketDigest struct {
	Q            int `json:"q"`
	R            int `json:"r"`
	Pdecs        int `json:"pdecs"`
	Mdecs        int `json:"mdecs,omitempty"`
	Auth         int `json:"auth"`
	Tapes        int `json:"tapes,omitempty"`
	SigShortness int `json:"sig_shortness"`
	VTargets     int `json:"vtargets"`
	BarSets      int `json:"barsets"`
}

type qBudget128MetricDigest struct {
	PaperTranscriptBytes     int                               `json:"paper_transcript_bytes"`
	PaperTranscriptKB        float64                           `json:"paper_transcript_kb"`
	Buckets                  qBudget128BucketDigest            `json:"buckets"`
	TranscriptAudit          PIOP.PaperTranscriptAudit         `json:"transcript_audit,omitempty"`
	TheoremTotalBits         float64                           `json:"theorem_total_bits"`
	CollisionBits            float64                           `json:"collision_bits"`
	AlgebraicBits            [4]float64                        `json:"algebraic_bits"`
	RawRoundBits             [4]float64                        `json:"raw_round_bits"`
	Clamped                  [4]bool                           `json:"clamped"`
	DQ                       int                               `json:"dq"`
	DDECS                    int                               `json:"ddecs"`
	RowsBlock                int                               `json:"rows_block"`
	OpeningCols              int                               `json:"opening_cols"`
	ShortnessRows            int                               `json:"shortness_rows"`
	Theta                    int                               `json:"theta"`
	Rho                      int                               `json:"rho"`
	EllPrime                 int                               `json:"ell_prime"`
	DECSHashBits             int                               `json:"decs_hash_bits"`
	DECSTapeBits             int                               `json:"decs_tape_bits"`
	PDecsBitWidth            int                               `json:"pdecs_bit_width,omitempty"`
	VTargetsBitWidth         int                               `json:"vtargets_bit_width,omitempty"`
	ParallelAlgDegree        int                               `json:"parallel_alg_degree,omitempty"`
	AggregatedAlgDegree      int                               `json:"aggregated_alg_degree,omitempty"`
	DominantDegreeSource     string                            `json:"dominant_degree_source,omitempty"`
	RelationCandidate        benchmarkIntGenISISRelationReport `json:"relation_candidate,omitempty"`
	TranscriptSecurityStatus string                            `json:"transcript_security_status,omitempty"`
	ProvingMS                float64                           `json:"proving_ms"`
	VerificationMS           float64                           `json:"verification_ms"`
}

type qBudget128SweepResult struct {
	Preset         string                          `json:"preset"`
	Candidate      string                          `json:"candidate"`
	Family         string                          `json:"family,omitempty"`
	Category       string                          `json:"category"`
	Accepted       bool                            `json:"accepted"`
	Reason         string                          `json:"reason,omitempty"`
	Simplicity     int                             `json:"simplicity_score"`
	Kappa          [4]int                          `json:"kappa"`
	ShowOptions    intGenISISTuning                `json:"showing_options"`
	Issuance       qBudget128MetricDigest          `json:"issuance,omitempty"`
	Showing        qBudget128MetricDigest          `json:"showing,omitempty"`
	ReplayRejected bool                            `json:"replay_rejected"`
	Artifacts      benchmarkIntGenISISE2EArtifacts `json:"artifacts,omitempty"`
}

type qBudget128FrontierEntry struct {
	Category           string                 `json:"category"`
	Preset             string                 `json:"preset,omitempty"`
	Candidate          string                 `json:"candidate"`
	Family             string                 `json:"family,omitempty"`
	Accepted           bool                   `json:"accepted,omitempty"`
	Reason             string                 `json:"reason,omitempty"`
	Bytes              int                    `json:"bytes,omitempty"`
	TheoremTotalBits   float64                `json:"theorem_total_bits,omitempty"`
	CollisionBits      float64                `json:"collision_bits,omitempty"`
	AlgebraicBits      [4]float64             `json:"algebraic_bits,omitempty"`
	Buckets            qBudget128BucketDigest `json:"buckets,omitempty"`
	Kappa              [4]int                 `json:"kappa,omitempty"`
	Simplicity         int                    `json:"simplicity_score,omitempty"`
	RequiresCodeChange bool                   `json:"requires_code_change,omitempty"`
}

type qBudget128SweepSummary struct {
	Version        int                                  `json:"version"`
	GeneratedAt    string                               `json:"generated_at"`
	TargetBits     float64                              `json:"target_bits"`
	Presets        []string                             `json:"presets"`
	CandidateCount int                                  `json:"candidate_count"`
	RunCount       int                                  `json:"run_count"`
	AcceptedCount  int                                  `json:"accepted_count"`
	Results        []qBudget128SweepResult              `json:"results"`
	Frontiers      map[string][]qBudget128FrontierEntry `json:"frontiers"`
}

type securityProfileSweepCandidate struct {
	Name                  string                           `json:"name"`
	SecurityProfile       string                           `json:"security_profile"`
	TargetStatus          credential.SecurityProfileStatus `json:"target_status"`
	Preset                string                           `json:"preset"`
	PredictedFullGameBits float64                          `json:"predicted_full_game_bits,omitempty"`
	Issuance              intGenISISTuning                 `json:"issuance"`
	Showing               intGenISISTuning                 `json:"showing"`
}

type securityProfileSweepResult struct {
	Candidate                  string                            `json:"candidate"`
	Preset                     string                            `json:"preset"`
	SecurityProfile            string                            `json:"security_profile"`
	FrontierClass              string                            `json:"frontier_class"`
	Accepted                   bool                              `json:"accepted"`
	LedgerStatus               string                            `json:"ledger_status"`
	LedgerReasons              []string                          `json:"ledger_rejection_reasons,omitempty"`
	Reason                     string                            `json:"reason,omitempty"`
	Relation                   benchmarkIntGenISISRelationReport `json:"relation_candidate,omitempty"`
	PaperBytes                 int                               `json:"paper_transcript_bytes,omitempty"`
	BaselinePaperBytes         int                               `json:"baseline_paper_transcript_bytes,omitempty"`
	TranscriptDeltaBytes       int                               `json:"transcript_delta_bytes,omitempty"`
	FullGameBits               float64                           `json:"full_game_bits,omitempty"`
	SoundnessBits              float64                           `json:"soundness_bits,omitempty"`
	ZeroKnowledgeBits          float64                           `json:"zero_knowledge_bits,omitempty"`
	RequiredPhaseAlgebraicBits float64                           `json:"required_phase_algebraic_bits,omitempty"`
	PhaseAlgebraicSlackBits    float64                           `json:"phase_algebraic_slack_bits,omitempty"`
	DominantSoundnessLimiter   string                            `json:"dominant_soundness_limiter,omitempty"`
	TagCollisionBits           float64                           `json:"tag_collision_bits,omitempty"`
	ReplayRejected             bool                              `json:"replay_rejected"`
	Artifacts                  benchmarkIntGenISISE2EArtifacts   `json:"artifacts,omitempty"`
}

type securityProfileSweepSummary struct {
	Version        int                          `json:"version"`
	GeneratedAt    string                       `json:"generated_at"`
	CandidateCount int                          `json:"candidate_count"`
	RunCount       int                          `json:"run_count"`
	AcceptedCount  int                          `json:"accepted_count"`
	Results        []securityProfileSweepResult `json:"results"`
}

func TestSecurityProfileSweepCandidateGeneration(t *testing.T) {
	candidates := securityProfileSweepCandidates()
	if len(candidates) == 0 {
		t.Fatal("no security-profile candidates generated")
	}
	wantNames := map[string]bool{
		"bq32-current-control":                     false,
		"bq32-safe-n524288-lvcs37-eta44-ell9":      false,
		"bq32-rowblock-n557056-lvcs40-eta44-ell9":  false,
		"bq32-rowblock-n589824-lvcs44-eta47-ell9":  false,
		"bq32-fallback-ell10-lvcs37-n458752-eta44": false,
	}
	foundBQ32 := false
	for _, cand := range candidates {
		if _, ok := wantNames[cand.Name]; ok {
			wantNames[cand.Name] = true
		}
		if cand.SecurityProfile == "BQ32-96" {
			foundBQ32 = true
			if cand.TargetStatus != credential.SecurityProfileCandidate {
				t.Fatalf("BQ32 target status=%q", cand.TargetStatus)
			}
			if cand.Showing.DECSHashBits != 168 || cand.Showing.DECSTapeBits != 136 || cand.Showing.SaltBits != 168 || cand.Showing.PRFParamsPath != credential.IntGenISISPRFParamsTag9 {
				t.Fatalf("BQ32 candidate did not carry split/tag9 metadata: %+v", cand.Showing)
			}
		}
	}
	if !foundBQ32 {
		t.Fatal("missing BQ32-96 security-profile candidate")
	}
	for name, found := range wantNames {
		if !found {
			t.Fatalf("missing BQ32 tuning candidate %q", name)
		}
	}
}

func TestSecurityProfileCandidateAcceptanceRequiresLedgerAndByteReduction(t *testing.T) {
	report := securityProfileSyntheticReport(37100, 96.5, 96.5, 96)
	accepted, frontier, reason := securityProfileCandidateAcceptance(report)
	if !accepted || frontier != securityProfileFrontierCandidateByteReduction || !strings.Contains(reason, "accepted") {
		t.Fatalf("byte-reducing candidate not accepted: accepted=%v frontier=%q reason=%q", accepted, frontier, reason)
	}

	report = securityProfileSyntheticReport(37244, 96.5, 96.5, 96)
	accepted, frontier, reason = securityProfileCandidateAcceptance(report)
	if accepted || frontier != securityProfileFrontierSecurityOnlyCandidate || !strings.Contains(reason, "showing transcript bytes") {
		t.Fatalf("security-only candidate should not be accepted for preset update: accepted=%v frontier=%q reason=%q", accepted, frontier, reason)
	}

	report = securityProfileSyntheticReport(37100, 95.9, 96.5, 96)
	accepted, _, reason = securityProfileCandidateAcceptance(report)
	if accepted || !strings.Contains(reason, "soundness bits") {
		t.Fatalf("weak soundness candidate accepted: accepted=%v reason=%q", accepted, reason)
	}
}

func TestSecurityProfileSweepResultOrderingPrefersByteReducingCandidates(t *testing.T) {
	results := []securityProfileSweepResult{
		{Candidate: "security-only", PaperBytes: 37400, TranscriptDeltaBytes: 156, FullGameBits: 98, SoundnessBits: 98, ZeroKnowledgeBits: 96, ReplayRejected: true},
		{Candidate: "rejected-small", PaperBytes: 36000, TranscriptDeltaBytes: -1244, FullGameBits: 95, SoundnessBits: 95, ZeroKnowledgeBits: 96, ReplayRejected: true},
		{Candidate: "accepted-byte", Accepted: true, PaperBytes: 37100, TranscriptDeltaBytes: -144, FullGameBits: 96.5, SoundnessBits: 96.5, ZeroKnowledgeBits: 96, ReplayRejected: true},
	}
	sort.SliceStable(results, func(i, j int) bool {
		return securityProfileSweepResultLess(results[i], results[j])
	})
	if results[0].Candidate != "accepted-byte" {
		t.Fatalf("first result=%+v", results[0])
	}
}

func securityProfileSyntheticReport(showingBytes int, soundnessBits, fullGameBits, zeroKnowledgeBits float64) benchmarkIntGenISISE2EReport {
	target := 96.0
	return benchmarkIntGenISISE2EReport{
		SecurityProfile: "BQ32-96",
		ReplayRejected:  true,
		Showing: benchmarkIntGenISISMetrics{
			PaperTranscriptBytes: showingBytes,
		},
		SecurityLedger: credential.SystemSecurityLedger{
			SecurityProfile:   "BQ32-96",
			TargetBits:        target,
			SoundnessBits:     soundnessBits,
			FullGameBits:      fullGameBits,
			ZeroKnowledgeBits: zeroKnowledgeBits,
			UnlinkabilityBits: target,
			CorrectnessBits:   target,
			PrimitiveBits:     128,
			TagCollisionBits:  116,
			SaltCollisionBits: 128,
			LedgerStatus:      string(credential.SecurityProfileCandidate),
			RejectionReasons:  []string{"profile status is candidate"},
			Terms: []credential.SystemSecurityLedgerTerm{
				{Category: credential.SystemLedgerTermSoundness, Name: "full_game", Bits: fullGameBits, Required: true, Status: "pass"},
				{Category: credential.SystemLedgerTermZeroKnowledge, Name: "tape_guessing", Bits: zeroKnowledgeBits, Required: true, Status: "pass"},
				{Category: credential.SystemLedgerTermUnlinkability, Name: "tag_collision", Bits: 116, Required: true, Status: "pass"},
				{Category: credential.SystemLedgerTermCorrectness, Name: "salt_collision", Bits: 128, Required: true, Status: "pass"},
				{Category: credential.SystemLedgerTermPrimitive, Name: "core_available", Bits: 128, Required: true, Status: "pass"},
			},
		},
	}
}

func TestInternalSecurityProfileSweep(t *testing.T) {
	if os.Getenv("SPRUCE_SECURITY_PROFILE_SWEEP") != "1" {
		t.Skip("set SPRUCE_SECURITY_PROFILE_SWEEP=1 to run live security-profile sweep")
	}
	root := os.Getenv("SPRUCE_SECURITY_PROFILE_SWEEP_ARTIFACT_ROOT")
	if root == "" {
		root = t.TempDir()
	} else if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create artifact root: %v", err)
	}
	maxRuns := qBudget128EnvInt("SPRUCE_SECURITY_PROFILE_SWEEP_MAX_E2E", 1)
	filter := os.Getenv("SPRUCE_SECURITY_PROFILE_SWEEP_FILTER")
	restoreWD := qBudget128ChdirRepoRoot(t)
	defer restoreWD()

	candidates := securityProfileFilterCandidates(securityProfileSweepCandidates(), filter)
	results := make([]securityProfileSweepResult, 0, len(candidates))
	runCount := 0
	acceptedCount := 0
	for _, cand := range candidates {
		if maxRuns > 0 && runCount >= maxRuns {
			break
		}
		preset, err := credential.MustLookupIntGenISISPreset(cand.Preset)
		if err != nil {
			t.Fatal(err)
		}
		qcand := qBudget128SweepCandidate{Name: cand.Name, Family: cand.SecurityProfile, Issuance: cand.Issuance, Showing: cand.Showing}
		report, err := benchmarkIntGenISISE2E(qBudget128BenchmarkConfig(preset, qcand, root, runCount))
		runCount++
		result := securityProfileSweepResult{
			Candidate:       cand.Name,
			Preset:          cand.Preset,
			SecurityProfile: cand.SecurityProfile,
			FrontierClass:   qBudget128CategoryRejected,
		}
		if err != nil {
			result.LedgerReasons = []string{err.Error()}
		} else {
			result = securityProfileSweepResultFromReport(cand, report)
		}
		if result.Accepted {
			acceptedCount++
		}
		results = append(results, result)
		t.Logf("%s/%s frontier=%s ledger=%s accepted=%v reasons=%v", cand.Preset, cand.Name, result.FrontierClass, result.LedgerStatus, result.Accepted, result.LedgerReasons)
	}
	sort.SliceStable(results, func(i, j int) bool {
		return securityProfileSweepResultLess(results[i], results[j])
	})
	summary := securityProfileSweepSummary{
		Version:        securityProfileSweepSummaryVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		CandidateCount: len(candidates),
		RunCount:       runCount,
		AcceptedCount:  acceptedCount,
		Results:        results,
	}
	if err := qBudget128WriteSecurityProfileSweepSummary(filepath.Join(root, securityProfileSweepSummaryFilename), summary); err != nil {
		t.Fatalf("write summary: %v", err)
	}
}

func TestQBudget128SweepCandidateGeneration(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024Q32_128)
	if err != nil {
		t.Fatal(err)
	}
	candidates := qBudget128SweepCandidates(preset)
	if len(candidates) == 0 {
		t.Fatal("no q-budget candidates generated")
	}
	wants := []string{
		"lvcs37-n655360-eta45-theta9-ell11-r7l5-comp1-projv5-c200-k1-0-0-8",
		"lvcs37-n655360-eta45-theta8-ell11-r7l5-comp1-projv5-c200-k1-0-10-8",
		"lvcs37-n655360-eta45-theta9-ell11-r24l3-comp1-projv5-c200-k1-0-0-8",
		"lvcs37-n655360-eta45-theta9-ell11-r7l5-comp2-projv5-c200-k1-0-0-8",
	}
	for _, want := range wants {
		if !qBudget128CandidateNamesContain(candidates, want) {
			t.Fatalf("missing retained q32 research candidate %q", want)
		}
	}
	if len(candidates) > 50000 {
		t.Fatalf("focused candidate generator produced %d candidates; keep default research set bounded", len(candidates))
	}
	for _, cand := range candidates {
		if cand.Issuance.PRFCompanionMode != "" ||
			cand.Issuance.PRFGroupRounds != 0 ||
			cand.Issuance.SigShortnessRadix != 0 ||
			cand.Issuance.CompressedRows != 0 ||
			cand.Issuance.ReplayProjection != "" {
			t.Fatalf("issuance candidate retained showing-only fields: %+v", cand.Issuance)
		}
		if !cand.Issuance.ROQueryCapsSet || cand.Issuance.ROQueryCaps != cand.Showing.ROQueryCaps {
			t.Fatalf("issuance/showing query caps mismatch: %+v", cand)
		}
		if cand.Issuance.DECSCollisionBits != cand.Showing.DECSCollisionBits {
			t.Fatalf("issuance/showing DECS width mismatch: %+v", cand)
		}
		if cand.Showing.Rho != 1 || cand.Showing.EllPrime != 1 {
			t.Fatalf("candidate changed fixed proof knobs: %+v", cand.Showing)
		}
	}

	q16, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024Q16_128)
	if err != nil {
		t.Fatal(err)
	}
	for _, cand := range qBudget128SweepCandidates(q16) {
		if cand.Showing.DECSCollisionBits != qBudget128CollisionBitsQ16_128 {
			t.Fatalf("q16 safe track changed collision width: %+v", cand.Showing)
		}
	}
}

func TestQBudget128ValidationRequiresEachAlgebraicRound(t *testing.T) {
	report := benchmarkIntGenISISE2EReport{
		Issuance:       qBudget128AcceptedMetrics(),
		Showing:        qBudget128AcceptedMetrics(),
		ReplayRejected: true,
	}
	if err := qBudget128ValidateSweepReport("accepted", report); err != nil {
		t.Fatalf("accepted metrics rejected: %v", err)
	}
	report.Showing.AlgebraicBits[2] = 127.99
	err := qBudget128ValidateSweepReport("weak-round", report)
	if err == nil || !strings.Contains(err.Error(), "algebraic round 3") {
		t.Fatalf("missing algebraic-round rejection: %v", err)
	}
}

func TestQBudget128AcceptedCategoryMarksHighK(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024Q32_128)
	if err != nil {
		t.Fatal(err)
	}
	base := intGenISISTuningFromPresetSpec(preset.Showing)
	cand := qBudget128SweepCandidate{Name: "high-k", Showing: base, Issuance: qBudget128IssuanceFromShowing(base)}
	cand.Showing.Kappa[2] = 10
	if got := qBudget128AcceptedCategory(cand, base); got != qBudget128CategoryHighKResearch {
		t.Fatalf("category=%q want high-k", got)
	}
	cand.Showing.Kappa = base.Kappa
	if got := qBudget128AcceptedCategory(cand, base); got != qBudget128CategorySafePreset {
		t.Fatalf("category=%q want safe", got)
	}
}

func TestInternalQBudget128Sweep(t *testing.T) {
	if os.Getenv("SPRUCE_QBUDGET128_SWEEP") != "1" {
		t.Skip("set SPRUCE_QBUDGET128_SWEEP=1 to run live q-budget sweep")
	}
	presetNames := qBudget128SweepPresetNames()
	root := os.Getenv("SPRUCE_QBUDGET128_SWEEP_ARTIFACT_ROOT")
	if root == "" {
		root = t.TempDir()
	} else if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create artifact root: %v", err)
	}
	filter := os.Getenv("SPRUCE_QBUDGET128_SWEEP_FILTER")
	maxRuns := qBudget128EnvInt("SPRUCE_QBUDGET128_SWEEP_MAX_E2E", qBudget128DefaultMaxE2E)
	frontierLimit := qBudget128EnvInt("SPRUCE_QBUDGET128_SWEEP_FRONTIER_LIMIT", qBudget128DefaultFrontierLimit)
	expanded := qBudget128EnvBool("SPRUCE_QBUDGET128_SWEEP_EXPANDED")
	requireAccepted := qBudget128EnvBool("SPRUCE_QBUDGET128_SWEEP_REQUIRE_ACCEPTED")

	restoreWD := qBudget128ChdirRepoRoot(t)
	defer restoreWD()

	results := make([]qBudget128SweepResult, 0)
	candidateCount := 0
	runCount := 0
	acceptedCount := 0
	stop := false
	for _, presetName := range presetNames {
		preset, err := credential.MustLookupIntGenISISPreset(presetName)
		if err != nil {
			t.Fatal(err)
		}
		base := intGenISISTuningFromPresetSpec(preset.Showing)
		candidates := qBudget128SweepCandidatesForMode(preset, expanded)
		candidateCount += len(candidates)
		candidates = qBudget128FilterCandidates(preset.Name, candidates, filter)
		for _, cand := range candidates {
			if maxRuns > 0 && runCount >= maxRuns {
				stop = true
				break
			}
			report, err := benchmarkIntGenISISE2E(qBudget128BenchmarkConfig(preset, cand, root, runCount))
			runCount++
			var result qBudget128SweepResult
			if err != nil {
				result = qBudget128RejectedResult(preset.Name, cand, base, fmt.Sprintf("benchmark: %v", err))
			} else {
				result = qBudget128ResultFromReport(preset.Name, cand, base, report)
			}
			if result.Accepted {
				acceptedCount++
			}
			results = append(results, result)
			t.Logf("%s/%s category=%s accepted=%v bytes=%d theorem=%.2f collision=%.2f reason=%s",
				preset.Name,
				cand.Name,
				result.Category,
				result.Accepted,
				result.Showing.PaperTranscriptBytes,
				result.Showing.TheoremTotalBits,
				result.Showing.CollisionBits,
				result.Reason,
			)
		}
		if stop {
			break
		}
	}
	summary := qBudget128SweepSummary{
		Version:        qBudget128ResearchSummaryVersion,
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		TargetBits:     qBudget128SweepTargetBits,
		Presets:        presetNames,
		CandidateCount: candidateCount,
		RunCount:       runCount,
		AcceptedCount:  acceptedCount,
		Results:        results,
		Frontiers:      qBudget128BuildFrontiers(results, frontierLimit),
	}
	summaryPath := filepath.Join(root, qBudget128ResearchSummaryFilename)
	if err := qBudget128WriteSweepSummary(summaryPath, summary); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	t.Logf("wrote q-budget research summary: %s", summaryPath)
	if requireAccepted && acceptedCount == 0 {
		t.Fatalf("no accepted q-budget candidates in %d runs", runCount)
	}
}

func qBudget128SweepCandidates(preset credential.IntGenISISPreset) []qBudget128SweepCandidate {
	return qBudget128SweepCandidatesForMode(preset, false)
}

func securityProfileSweepCandidates() []securityProfileSweepCandidate {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		return nil
	}
	spec, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		return nil
	}
	baseShowing := intGenISISTuningFromPresetSpec(preset.Showing)
	candidate := func(name string, predicted float64, tune func(*intGenISISTuning)) securityProfileSweepCandidate {
		showing := baseShowing
		if tune != nil {
			tune(&showing)
		}
		return securityProfileSweepCandidate{
			Name:                  name,
			SecurityProfile:       spec.Label,
			TargetStatus:          spec.Status,
			Preset:                preset.Name,
			PredictedFullGameBits: predicted,
			Issuance:              qBudget128IssuanceFromShowing(showing),
			Showing:               showing,
		}
	}
	return []securityProfileSweepCandidate{
		candidate("bq32-current-control", 96.38, nil),
		candidate("bq32-safe-n524288-lvcs37-eta44-ell9", 96.50, func(showing *intGenISISTuning) {
			showing.NLeaves = 524288
			showing.LVCSNCols = 37
			showing.Eta = 44
			showing.Ell = 9
		}),
		candidate("bq32-rowblock-n557056-lvcs40-eta44-ell9", 96.38, func(showing *intGenISISTuning) {
			showing.NLeaves = 557056
			showing.LVCSNCols = 40
			showing.Eta = 44
			showing.Ell = 9
		}),
		candidate("bq32-rowblock-n589824-lvcs44-eta47-ell9", 96.06, func(showing *intGenISISTuning) {
			showing.NLeaves = 589824
			showing.LVCSNCols = 44
			showing.Eta = 47
			showing.Ell = 9
		}),
		candidate("bq32-fallback-ell10-lvcs37-n458752-eta44", 98.85, func(showing *intGenISISTuning) {
			showing.NLeaves = 458752
			showing.LVCSNCols = 37
			showing.Eta = 44
			showing.Ell = 10
		}),
	}
}

func securityProfileFilterCandidates(candidates []securityProfileSweepCandidate, filter string) []securityProfileSweepCandidate {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return candidates
	}
	out := candidates[:0]
	for _, cand := range candidates {
		if strings.Contains(cand.Name, filter) || strings.Contains(cand.Preset, filter) || strings.Contains(cand.SecurityProfile, filter) {
			out = append(out, cand)
		}
	}
	return out
}

func securityProfileSweepResultFromReport(cand securityProfileSweepCandidate, report benchmarkIntGenISISE2EReport) securityProfileSweepResult {
	accepted, frontierClass, reason := securityProfileCandidateAcceptance(report)
	return securityProfileSweepResult{
		Candidate:                  cand.Name,
		Preset:                     cand.Preset,
		SecurityProfile:            cand.SecurityProfile,
		FrontierClass:              frontierClass,
		Accepted:                   accepted,
		LedgerStatus:               report.SecurityLedger.LedgerStatus,
		LedgerReasons:              report.SecurityLedger.RejectionReasons,
		Reason:                     reason,
		Relation:                   report.Showing.RelationCandidate,
		PaperBytes:                 report.Showing.PaperTranscriptBytes,
		BaselinePaperBytes:         bq32PreTuningShowingPaperBytes,
		TranscriptDeltaBytes:       report.Showing.PaperTranscriptBytes - bq32PreTuningShowingPaperBytes,
		FullGameBits:               report.SecurityLedger.FullGameBits,
		SoundnessBits:              report.SecurityLedger.SoundnessBits,
		ZeroKnowledgeBits:          report.SecurityLedger.ZeroKnowledgeBits,
		RequiredPhaseAlgebraicBits: report.RequiredPhaseAlgebraicBits,
		PhaseAlgebraicSlackBits:    report.PhaseAlgebraicSlackBits,
		DominantSoundnessLimiter:   report.DominantSoundnessLimiter,
		TagCollisionBits:           report.SecurityLedger.TagCollisionBits,
		ReplayRejected:             report.ReplayRejected,
		Artifacts:                  report.Artifacts,
	}
}

func securityProfileCandidateAcceptance(report benchmarkIntGenISISE2EReport) (bool, string, string) {
	reasons := securityProfileCandidateAcceptanceReasons(report)
	if len(reasons) == 0 {
		return true, securityProfileFrontierCandidateByteReduction, "accepted for candidate preset tuning"
	}
	securityOnlyReasons := securityProfileCandidateAcceptanceReasonsIgnoringBytes(report)
	if len(securityOnlyReasons) == 0 {
		return false, securityProfileFrontierSecurityOnlyCandidate, strings.Join(reasons, "; ")
	}
	return false, securityProfileFrontierClass(report.SecurityLedger), strings.Join(reasons, "; ")
}

func securityProfileCandidateAcceptanceReasons(report benchmarkIntGenISISE2EReport) []string {
	reasons := securityProfileCandidateAcceptanceReasonsIgnoringBytes(report)
	if report.Showing.PaperTranscriptBytes >= bq32PreTuningShowingPaperBytes {
		reasons = append(reasons, fmt.Sprintf("showing transcript bytes %d >= baseline %d", report.Showing.PaperTranscriptBytes, bq32PreTuningShowingPaperBytes))
	}
	return reasons
}

func securityProfileCandidateAcceptanceReasonsIgnoringBytes(report benchmarkIntGenISISE2EReport) []string {
	var reasons []string
	if report.SecurityProfile != "BQ32-96" {
		reasons = append(reasons, "not a BQ32-96 candidate")
	}
	if securityProfileBitsBelow(report.SecurityLedger.SoundnessBits, bq32CandidateSoundnessThreshold) {
		reasons = append(reasons, fmt.Sprintf("soundness bits %.2f < %.2f", report.SecurityLedger.SoundnessBits, bq32CandidateSoundnessThreshold))
	}
	if securityProfileBitsBelow(report.SecurityLedger.FullGameBits, bq32CandidateFullGameThreshold) {
		reasons = append(reasons, fmt.Sprintf("full-game bits %.2f < %.2f", report.SecurityLedger.FullGameBits, bq32CandidateFullGameThreshold))
	}
	if securityProfileBitsBelow(report.SecurityLedger.ZeroKnowledgeBits, bq32CandidateZeroKnowledgeThreshold) {
		reasons = append(reasons, fmt.Sprintf("zero-knowledge bits %.2f < %.2f", report.SecurityLedger.ZeroKnowledgeBits, bq32CandidateZeroKnowledgeThreshold))
	}
	target := report.SecurityLedger.TargetBits
	for _, category := range []struct {
		name string
		bits float64
	}{
		{"unlinkability", report.SecurityLedger.UnlinkabilityBits},
		{"correctness", report.SecurityLedger.CorrectnessBits},
		{"primitive", report.SecurityLedger.PrimitiveBits},
	} {
		if securityProfileBitsBelow(category.bits, target) {
			reasons = append(reasons, fmt.Sprintf("%s bits %.2f < %.2f", category.name, category.bits, target))
		}
	}
	for _, term := range report.SecurityLedger.Terms {
		if term.Required && term.Status != "pass" {
			reasons = append(reasons, fmt.Sprintf("%s/%s status=%s", term.Category, term.Name, term.Status))
		}
	}
	if !report.ReplayRejected {
		reasons = append(reasons, "replay was accepted")
	}
	return qBudget128UniqueStrings(reasons)
}

func securityProfileBitsBelow(bits, target float64) bool {
	const tolerance = 1e-9
	return target > 0 && bits+tolerance < target
}

func securityProfileSweepResultLess(a, b securityProfileSweepResult) bool {
	if a.Accepted != b.Accepted {
		return a.Accepted
	}
	aSecurity := securityProfileSweepResultClearsSecurity(a)
	bSecurity := securityProfileSweepResultClearsSecurity(b)
	if aSecurity != bSecurity {
		return aSecurity
	}
	if a.TranscriptDeltaBytes != b.TranscriptDeltaBytes {
		return a.TranscriptDeltaBytes < b.TranscriptDeltaBytes
	}
	if a.FullGameBits != b.FullGameBits {
		return a.FullGameBits > b.FullGameBits
	}
	if a.SoundnessBits != b.SoundnessBits {
		return a.SoundnessBits > b.SoundnessBits
	}
	if a.PaperBytes != b.PaperBytes {
		return a.PaperBytes < b.PaperBytes
	}
	return a.Candidate < b.Candidate
}

func securityProfileSweepResultClearsSecurity(result securityProfileSweepResult) bool {
	return !securityProfileBitsBelow(result.SoundnessBits, bq32CandidateSoundnessThreshold) &&
		!securityProfileBitsBelow(result.FullGameBits, bq32CandidateFullGameThreshold) &&
		!securityProfileBitsBelow(result.ZeroKnowledgeBits, bq32CandidateZeroKnowledgeThreshold) &&
		result.ReplayRejected
}

func securityProfileFrontierClass(ledger credential.SystemSecurityLedger) string {
	switch ledger.LedgerStatus {
	case string(credential.SecurityProfileCompleteLive):
		if ledger.CompleteSystemClaim {
			return "complete_safe_preset"
		}
		return "proof_only_preset"
	case string(credential.SecurityProfileProofOnly):
		return "proof_only_preset"
	case string(credential.SecurityProfileRequiresNewPrimitives):
		return "requires_new_primitives"
	case string(credential.SecurityProfileCandidate), string(credential.SecurityProfileRequiresTheory):
		return "requires_theorem_accounting"
	default:
		return qBudget128CategoryRejected
	}
}

func qBudget128SweepCandidatesForMode(preset credential.IntGenISISPreset, expanded bool) []qBudget128SweepCandidate {
	base := intGenISISTuningFromPresetSpec(preset.Showing)
	widths := qBudget128CollisionWidths(base)
	shortness := qBudget128ShortnessCandidates(base)
	compressions := qBudget128CompressionCandidates(base)
	projections := qBudget128ProjectionCandidates(base)
	lvcs := qBudget128LVCSCandidates(base)
	localLVCS := qBudget128LocalLVCSCandidates(base)
	nleaves := qBudget128NLeavesCandidates(base)
	localLeaves := qBudget128LocalNLeavesCandidates(base)
	etas := qBudget128EtaCandidates(base)
	thetas := qBudget128ThetaCandidates(base)
	ells := qBudget128EllCandidates(base)
	kappas := qBudget128KappaVariants(base.Kappa)
	theta8Kappas := qBudget128Theta8KappaVariants(base.Kappa)

	seen := make(map[string]struct{})
	out := make([]qBudget128SweepCandidate, 0, 20000)
	add := func(family string, showing intGenISISTuning) {
		showing.Rho = 1
		showing.EllPrime = 1
		if showing.DECSCollisionBits <= 0 {
			showing.DECSCollisionBits = base.DECSCollisionBits
		}
		name := qBudget128CandidateName(showing)
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, qBudget128SweepCandidate{
			Name:     name,
			Family:   family,
			Issuance: qBudget128IssuanceFromShowing(showing),
			Showing:  showing,
		})
	}

	add("baseline", base)

	for _, value := range lvcs {
		showing := base
		showing.LVCSNCols = value
		add("single_lvcs", showing)
	}
	for _, value := range nleaves {
		showing := base
		showing.NLeaves = value
		add("single_nleaves", showing)
	}
	for _, value := range etas {
		showing := base
		showing.Eta = value
		add("single_eta", showing)
	}
	for _, value := range thetas {
		showing := base
		showing.Theta = value
		add("single_theta", showing)
	}
	for _, value := range ells {
		showing := base
		showing.Ell = value
		add("single_ell", showing)
	}
	for _, sh := range shortness {
		showing := base
		showing.SigShortnessRadix = sh.radix
		showing.SigShortnessDigits = sh.digits
		add("single_shortness", showing)
	}
	for _, compression := range compressions {
		showing := base
		showing.CompressedRows = compression
		add("single_compression", showing)
	}
	for _, projection := range projections {
		showing := base
		showing.ReplayProjection = projection
		add("single_projection", showing)
	}
	for _, kappa := range kappas {
		showing := base
		showing.Kappa = kappa
		add("single_kappa", showing)
	}

	for _, l := range localLVCS {
		for _, n := range localLeaves {
			for _, ell := range ells {
				showing := base
				showing.LVCSNCols = l
				showing.NLeaves = n
				showing.Ell = ell
				add("lvcs_nleaves_ell", showing)
			}
		}
	}

	for _, eta := range etas {
		for _, theta := range thetas {
			for _, ell := range ells {
				for _, kappa := range qBudget128KappasForTheta(base.Kappa, base.Theta, theta, kappas, theta8Kappas) {
					showing := base
					showing.Eta = eta
					showing.Theta = theta
					showing.Ell = ell
					showing.Kappa = kappa
					add("eta_theta_ell_kappa", showing)
				}
			}
		}
	}

	for _, l := range localLVCS {
		for _, n := range localLeaves {
			for _, eta := range etas {
				for _, ell := range ells {
					for _, sh := range shortness[:minInt(len(shortness), 2)] {
						for _, kappa := range theta8Kappas {
							showing := base
							showing.LVCSNCols = l
							showing.NLeaves = n
							showing.Eta = eta
							showing.Theta = 8
							showing.Ell = ell
							showing.SigShortnessRadix = sh.radix
							showing.SigShortnessDigits = sh.digits
							showing.Kappa = kappa
							add("theta8_high_k", showing)
						}
					}
				}
			}
		}
	}

	for _, sh := range shortness {
		for _, compression := range compressions {
			for _, projection := range projections {
				for _, width := range widths {
					showing := base
					showing.SigShortnessRadix = sh.radix
					showing.SigShortnessDigits = sh.digits
					showing.CompressedRows = compression
					showing.ReplayProjection = projection
					showing.DECSCollisionBits = width
					add("shape_codec_projection", showing)
				}
			}
		}
	}

	if expanded {
		for _, l := range lvcs {
			for _, n := range nleaves {
				for _, eta := range etas {
					for _, theta := range thetas {
						for _, ell := range ells {
							for _, sh := range shortness {
								for _, compression := range compressions {
									for _, projection := range projections {
										for _, kappa := range qBudget128KappasForTheta(base.Kappa, base.Theta, theta, kappas, theta8Kappas) {
											showing := base
											showing.LVCSNCols = l
											showing.NLeaves = n
											showing.Eta = eta
											showing.Theta = theta
											showing.Ell = ell
											showing.SigShortnessRadix = sh.radix
											showing.SigShortnessDigits = sh.digits
											showing.CompressedRows = compression
											showing.ReplayProjection = projection
											showing.Kappa = kappa
											add("expanded_grid", showing)
											if limit := qBudget128EnvInt("SPRUCE_QBUDGET128_SWEEP_MAX_CANDIDATES", 0); limit > 0 && len(out) >= limit {
												return out
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return out
}

func qBudget128CandidateName(showing intGenISISTuning) string {
	kappa := showing.Kappa
	return fmt.Sprintf("lvcs%d-n%d-eta%d-theta%d-ell%d-%s-comp%d-%s-c%d-k%d-%d-%d-%d",
		showing.LVCSNCols,
		showing.NLeaves,
		showing.Eta,
		showing.Theta,
		showing.Ell,
		qBudget128ShortnessLabel(showing.SigShortnessRadix, showing.SigShortnessDigits),
		showing.CompressedRows,
		qBudget128ProjectionLabel(showing.ReplayProjection),
		showing.DECSCollisionBits,
		kappa[0],
		kappa[1],
		kappa[2],
		kappa[3],
	)
}

func qBudget128ShortnessLabel(radix, digits int) string {
	return fmt.Sprintf("r%dl%d", radix, digits)
}

func qBudget128ProjectionLabel(projection string) string {
	switch projection {
	case "", qBudget128ProjectionNone:
		return "projnone"
	case qBudget128ProjectionProjectUDigitsYViewV3:
		return "projv3"
	case qBudget128ProjectionProjectUDigitsYWResidual:
		return "projv5"
	default:
		return "proj" + qBudget128SanitizeLabel(projection)
	}
}

func qBudget128SanitizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	replacer := strings.NewReplacer("_", "", "-", "", ".", "", "/", "")
	return replacer.Replace(s)
}

func qBudget128IssuanceFromShowing(showing intGenISISTuning) intGenISISTuning {
	issuance := showing
	issuance.PRFCompanionMode = ""
	issuance.PRFGroupRounds = 0
	issuance.CheckpointSamples = 0
	issuance.SigShortnessRadix = 0
	issuance.SigShortnessDigits = 0
	issuance.CompressedRows = 0
	issuance.ReplayProjection = ""
	return issuance
}

func qBudget128CollisionWidths(base intGenISISTuning) []int {
	minWidth := base.DECSCollisionBits
	if base.ROQueryCapsSet {
		switch base.ROQueryCaps[0] {
		case qBudget128QueryCapQ10:
			minWidth = qBudget128CollisionBitsQ10_128
		case qBudget128QueryCapQ16:
			minWidth = qBudget128CollisionBitsQ16_128
		case qBudget128QueryCapQ32:
			minWidth = qBudget128CollisionBitsQ32_128
		}
	}
	if minWidth <= 0 {
		minWidth = base.DECSCollisionBits
	}
	return qBudget128UniqueInts([]int{minWidth})
}

func qBudget128ShortnessCandidates(base intGenISISTuning) []struct {
	radix  int
	digits int
} {
	candidates := []struct {
		radix  int
		digits int
	}{
		{radix: base.SigShortnessRadix, digits: base.SigShortnessDigits},
		{radix: 7, digits: 5},
		{radix: 11, digits: 4},
		{radix: 24, digits: 3},
		{radix: 111, digits: 2},
	}
	seen := map[string]struct{}{}
	out := candidates[:0]
	for _, c := range candidates {
		if c.radix <= 0 || c.digits <= 0 {
			continue
		}
		key := qBudget128ShortnessLabel(c.radix, c.digits)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

func qBudget128CompressionCandidates(base intGenISISTuning) []int {
	return qBudget128UniqueInts([]int{base.CompressedRows, 1, 0, 2})
}

func qBudget128ProjectionCandidates(base intGenISISTuning) []string {
	return qBudget128UniqueStrings([]string{
		base.ReplayProjection,
		qBudget128ProjectionProjectUDigitsYWResidual,
		qBudget128ProjectionProjectUDigitsYViewV3,
		qBudget128ProjectionNone,
	})
}

func qBudget128LVCSCandidates(base intGenISISTuning) []int {
	vals := []int{base.LVCSNCols, 32, 34, 36, 37, 38, 40, 42, 44, 46, 48, 50, 52, 56, 64}
	for _, rows := range []int{407, 471} {
		for blocks := 7; blocks <= 16; blocks++ {
			col := ceilDivInt(rows, blocks)
			vals = append(vals, col-1, col, col+1)
		}
	}
	return qBudget128BoundedUniqueInts(vals, 32, 64)
}

func qBudget128LocalLVCSCandidates(base intGenISISTuning) []int {
	vals := []int{base.LVCSNCols - 3, base.LVCSNCols - 2, base.LVCSNCols - 1, base.LVCSNCols, base.LVCSNCols + 1, base.LVCSNCols + 2, base.LVCSNCols + 3, 44, 46, 48}
	return qBudget128BoundedUniqueInts(vals, 32, 64)
}

func qBudget128NLeavesCandidates(base intGenISISTuning) []int {
	vals := []int{
		262144, 327680, 393216, 458752,
		524288, 557056, 589824, 622592, 655360, 688128, 720896,
		786432, 851968, 917504, 983040, 1048576,
		base.NLeaves - 65536, base.NLeaves - 32768, base.NLeaves, base.NLeaves + 32768, base.NLeaves + 65536,
	}
	return qBudget128BoundedUniqueInts(vals, 262144, 1048576)
}

func qBudget128LocalNLeavesCandidates(base intGenISISTuning) []int {
	vals := []int{base.NLeaves - 65536, base.NLeaves - 32768, base.NLeaves, base.NLeaves + 32768, base.NLeaves + 65536, 524288, 655360}
	return qBudget128BoundedUniqueInts(vals, 262144, 1048576)
}

func qBudget128EtaCandidates(base intGenISISTuning) []int {
	if base.ROQueryCapsSet && base.ROQueryCaps[0] == qBudget128QueryCapQ32 {
		return qBudget128BoundedUniqueInts([]int{base.Eta, 44, 45, 46, 47}, 1, 80)
	}
	return qBudget128BoundedUniqueInts([]int{base.Eta, base.Eta - 1, base.Eta + 1, 42, 43, 44, 45, 46}, 1, 80)
}

func qBudget128ThetaCandidates(base intGenISISTuning) []int {
	vals := []int{base.Theta, base.Theta - 1, base.Theta + 1, 8, 9, 10}
	if base.ROQueryCapsSet && base.ROQueryCaps[0] == qBudget128QueryCapQ16 {
		vals = append(vals, 7)
	}
	return qBudget128BoundedUniqueInts(vals, 2, 12)
}

func qBudget128EllCandidates(base intGenISISTuning) []int {
	return qBudget128BoundedUniqueInts([]int{base.Ell, base.Ell - 2, base.Ell - 1, base.Ell + 1, base.Ell + 2, 9, 10, 11, 12}, 1, 16)
}

func qBudget128KappaVariants(base [4]int) [][4]int {
	deltas := [][4]int{
		{0, 0, 0, 0},
		{0, 0, 0, 1},
		{0, 0, 1, 1},
		{1, 0, 0, 1},
		{0, 0, 1, 2},
		{1, 0, 0, 2},
		{2, 0, 0, 2},
		{3, 0, 0, 2},
		{4, 0, 0, 2},
	}
	out := make([][4]int, 0, len(deltas))
	seen := make(map[[4]int]struct{})
	for _, delta := range deltas {
		next := base
		for i := range next {
			next[i] += delta[i]
			if next[i] > qBudget128MaxSupportedGrinding {
				next[i] = qBudget128MaxSupportedGrinding
			}
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}

func qBudget128Theta8KappaVariants(base [4]int) [][4]int {
	out := make([][4]int, 0, 4)
	seen := make(map[[4]int]struct{})
	for k2 := 10; k2 <= qBudget128MaxSupportedGrinding; k2++ {
		next := base
		if next[2] < k2 {
			next[2] = k2
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}

func qBudget128KappasForTheta(base [4]int, baseTheta, theta int, regular, theta8 [][4]int) [][4]int {
	if theta < baseTheta || theta == 8 {
		return qBudget128MergeKappas(regular, theta8)
	}
	return regular
}

func qBudget128MergeKappas(groups ...[][4]int) [][4]int {
	out := make([][4]int, 0)
	seen := make(map[[4]int]struct{})
	for _, group := range groups {
		for _, k := range group {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	return out
}

func qBudget128BenchmarkConfig(preset credential.IntGenISISPreset, cand qBudget128SweepCandidate, root string, idx int) benchmarkIntGenISISE2EConfig {
	name := fmt.Sprintf("%03d-%s", idx, cand.Name)
	maxNLeaves := maxInt(preset.MaxNLeaves, maxInt(cand.Issuance.NLeaves, cand.Showing.NLeaves))
	return benchmarkIntGenISISE2EConfig{
		ArtifactDir:         filepath.Join(root, name),
		PresetName:          preset.Name + ":" + cand.Name,
		Profile:             preset.Profile,
		SecurityProfile:     preset.SecurityProfile,
		SecurityMode:        preset.SecurityMode,
		CoreBitsRequired:    preset.CoreBitsRequired,
		CompleteSystemClaim: preset.CompleteSystemClaim,
		PRFProfile:          preset.PRFProfile,
		PRFParamsPath:       preset.PRFParamsPath,
		JSONOut:             filepath.Join(root, name+".json"),
		Force:               true,
		Issuance:            cand.Issuance,
		Showing:             cand.Showing,
		KeygenTrials:        10000,
		KeygenAttempts:      defaultNTRUKeygenAttempts,
		NTRUBeta:            preset.NTRUBeta,
		MaxTrials:           2048,
		MaxNLeaves:          maxNLeaves,
	}
}

func qBudget128ValidateSweepReport(name string, report benchmarkIntGenISISE2EReport) error {
	reasons := qBudget128ValidationReasons(name, report)
	if len(reasons) > 0 {
		return fmt.Errorf("%s", strings.Join(reasons, "; "))
	}
	return nil
}

func qBudget128ValidationReasons(name string, report benchmarkIntGenISISE2EReport) []string {
	var reasons []string
	for phase, metrics := range map[string]benchmarkIntGenISISMetrics{
		"issuance": report.Issuance,
		"showing":  report.Showing,
	} {
		if metrics.TheoremTotalBits < qBudget128SweepTargetBits {
			reasons = append(reasons, fmt.Sprintf("%s theorem bits %.2f < %.2f", phase, metrics.TheoremTotalBits, qBudget128SweepTargetBits))
		}
		if metrics.CollisionBits < qBudget128SweepTargetBits {
			reasons = append(reasons, fmt.Sprintf("%s collision bits %.2f < %.2f", phase, metrics.CollisionBits, qBudget128SweepTargetBits))
		}
		for i, bits := range metrics.AlgebraicBits {
			if bits < qBudget128SweepTargetBits {
				reasons = append(reasons, fmt.Sprintf("%s algebraic round %d bits %.2f < %.2f", phase, i+1, bits, qBudget128SweepTargetBits))
			}
		}
		if metrics.TranscriptSecurityStatus != "smallwood_2025_1085_live" {
			reasons = append(reasons, fmt.Sprintf("%s status=%q", phase, metrics.TranscriptSecurityStatus))
		}
		for i, clamped := range metrics.Clamped {
			if clamped {
				reasons = append(reasons, fmt.Sprintf("%s round %d is clamped", phase, i+1))
			}
		}
	}
	if !report.ReplayRejected {
		reasons = append(reasons, fmt.Sprintf("%s replay was accepted", name))
	}
	return reasons
}

func qBudget128ResultFromReport(presetName string, cand qBudget128SweepCandidate, base intGenISISTuning, report benchmarkIntGenISISE2EReport) qBudget128SweepResult {
	reasons := qBudget128ValidationReasons(cand.Name, report)
	accepted := len(reasons) == 0
	category := qBudget128CategoryRejected
	reason := strings.Join(reasons, "; ")
	if accepted {
		category = qBudget128AcceptedCategory(cand, base)
		reason = "accepted"
	}
	return qBudget128SweepResult{
		Preset:         presetName,
		Candidate:      cand.Name,
		Family:         cand.Family,
		Category:       category,
		Accepted:       accepted,
		Reason:         reason,
		Simplicity:     qBudget128SimplicityScore(cand.Showing, base),
		Kappa:          cand.Showing.Kappa,
		ShowOptions:    cand.Showing,
		Issuance:       qBudget128MetricDigestFromMetrics(report.Issuance),
		Showing:        qBudget128MetricDigestFromMetrics(report.Showing),
		ReplayRejected: report.ReplayRejected,
		Artifacts:      report.Artifacts,
	}
}

func qBudget128RejectedResult(presetName string, cand qBudget128SweepCandidate, base intGenISISTuning, reason string) qBudget128SweepResult {
	return qBudget128SweepResult{
		Preset:      presetName,
		Candidate:   cand.Name,
		Family:      cand.Family,
		Category:    qBudget128CategoryRejected,
		Accepted:    false,
		Reason:      reason,
		Simplicity:  qBudget128SimplicityScore(cand.Showing, base),
		Kappa:       cand.Showing.Kappa,
		ShowOptions: cand.Showing,
	}
}

func qBudget128MetricDigestFromMetrics(m benchmarkIntGenISISMetrics) qBudget128MetricDigest {
	return qBudget128MetricDigest{
		PaperTranscriptBytes: m.PaperTranscriptBytes,
		PaperTranscriptKB:    m.PaperTranscriptKB,
		TranscriptAudit:      m.TranscriptAudit,
		Buckets: qBudget128BucketDigest{
			Q:            m.QBytes,
			R:            m.RBytes,
			Pdecs:        m.PdecsBytes,
			Mdecs:        m.MdecsBytes,
			Auth:         m.AuthBytes,
			Tapes:        m.TapesBytes,
			SigShortness: m.SigShortnessBytes,
			VTargets:     m.VTargetsBytes,
			BarSets:      m.BarSetsBytes,
		},
		TheoremTotalBits:         m.TheoremTotalBits,
		CollisionBits:            m.CollisionBits,
		AlgebraicBits:            m.AlgebraicBits,
		RawRoundBits:             m.RawRoundBits,
		Clamped:                  m.Clamped,
		DQ:                       m.DQ,
		DDECS:                    m.DDECS,
		RowsBlock:                m.RowsBlock,
		OpeningCols:              m.OpeningCols,
		ShortnessRows:            m.ShortnessRows,
		Theta:                    m.Theta,
		Rho:                      m.Rho,
		EllPrime:                 m.EllPrime,
		DECSHashBits:             m.DECSHashBits,
		DECSTapeBits:             m.DECSTapeBits,
		PDecsBitWidth:            m.PDecsBitWidth,
		VTargetsBitWidth:         m.VTargetsBitWidth,
		ParallelAlgDegree:        m.ParallelAlgDegree,
		AggregatedAlgDegree:      m.AggregatedAlgDegree,
		DominantDegreeSource:     m.DominantDegreeSource,
		RelationCandidate:        m.RelationCandidate,
		TranscriptSecurityStatus: m.TranscriptSecurityStatus,
		ProvingMS:                m.ProvingMS,
		VerificationMS:           m.VerificationMS,
	}
}

func qBudget128AcceptedCategory(cand qBudget128SweepCandidate, base intGenISISTuning) string {
	if qBudget128IsHighK(cand.Showing.Kappa, base.Kappa) {
		return qBudget128CategoryHighKResearch
	}
	return qBudget128CategorySafePreset
}

func qBudget128IsHighK(kappa, base [4]int) bool {
	if qBudget128KappaMax(kappa) > qBudget128HighKThreshold {
		return true
	}
	return qBudget128KappaDeltaWeight(kappa, base) > qBudget128HighKDeltaThreshold
}

func qBudget128BuildFrontiers(results []qBudget128SweepResult, limit int) map[string][]qBudget128FrontierEntry {
	if limit <= 0 {
		limit = qBudget128DefaultFrontierLimit
	}
	groups := map[string][]qBudget128SweepResult{
		qBudget128CategorySafePreset:    nil,
		qBudget128CategoryHighKResearch: nil,
		qBudget128CategoryRejected:      nil,
	}
	for _, result := range results {
		groups[result.Category] = append(groups[result.Category], result)
	}
	out := make(map[string][]qBudget128FrontierEntry)
	for category, group := range groups {
		out[category] = []qBudget128FrontierEntry{}
		sort.SliceStable(group, func(i, j int) bool {
			return qBudget128ResultLess(group[i], group[j])
		})
		if len(group) > limit {
			group = group[:limit]
		}
		for _, result := range group {
			out[category] = append(out[category], qBudget128FrontierEntry{
				Category:         result.Category,
				Preset:           result.Preset,
				Candidate:        result.Candidate,
				Family:           result.Family,
				Accepted:         result.Accepted,
				Reason:           result.Reason,
				Bytes:            result.Showing.PaperTranscriptBytes,
				TheoremTotalBits: result.Showing.TheoremTotalBits,
				CollisionBits:    result.Showing.CollisionBits,
				AlgebraicBits:    result.Showing.AlgebraicBits,
				Buckets:          result.Showing.Buckets,
				Kappa:            result.Kappa,
				Simplicity:       result.Simplicity,
			})
		}
	}
	out[qBudget128CategoryRequiresTheoremAccounting] = qBudget128ProtocolResearchFrontier()
	return out
}

func qBudget128ProtocolResearchFrontier() []qBudget128FrontierEntry {
	return []qBudget128FrontierEntry{
		{
			Category:           qBudget128CategoryRequiresTheoremAccounting,
			Candidate:          "hash_tape_decoupling",
			Reason:             "hash/tape split is implemented, but this frontier still requires full ledger and profile promotion before byte-saving candidates can be accepted",
			RequiresCodeChange: true,
		},
		{
			Category:           qBudget128CategoryRequiresTheoremAccounting,
			Candidate:          "smallfield_payload_reduction",
			Reason:             "Pdecs/VTargets/BarSets reductions must preserve strict SmallField2025 LVCS EvalStep2 binding and metadata digest checks",
			RequiresCodeChange: true,
		},
		{
			Category:           qBudget128CategoryRequiresTheoremAccounting,
			Candidate:          "prf_companion_row_reduction",
			Reason:             "PRF companion row changes must preserve key/nonce/tag binding and transcript coordinate digest binding",
			RequiresCodeChange: true,
		},
	}
}

func qBudget128ResultLess(a, b qBudget128SweepResult) bool {
	ab, bb := qBudget128ComparableBytes(a), qBudget128ComparableBytes(b)
	if ab != bb {
		return ab < bb
	}
	if a.Showing.TheoremTotalBits != b.Showing.TheoremTotalBits {
		return a.Showing.TheoremTotalBits > b.Showing.TheoremTotalBits
	}
	ams := a.Showing.ProvingMS + a.Showing.VerificationMS
	bms := b.Showing.ProvingMS + b.Showing.VerificationMS
	if ams != bms {
		return ams < bms
	}
	if qBudget128KappaMax(a.Kappa) != qBudget128KappaMax(b.Kappa) {
		return qBudget128KappaMax(a.Kappa) < qBudget128KappaMax(b.Kappa)
	}
	if qBudget128KappaWeight(a.Kappa) != qBudget128KappaWeight(b.Kappa) {
		return qBudget128KappaWeight(a.Kappa) < qBudget128KappaWeight(b.Kappa)
	}
	if a.Simplicity != b.Simplicity {
		return a.Simplicity < b.Simplicity
	}
	if a.Preset != b.Preset {
		return a.Preset < b.Preset
	}
	return a.Candidate < b.Candidate
}

func qBudget128ComparableBytes(result qBudget128SweepResult) int {
	if result.Showing.PaperTranscriptBytes > 0 {
		return result.Showing.PaperTranscriptBytes
	}
	return int(^uint(0) >> 1)
}

func qBudget128SimplicityScore(showing, base intGenISISTuning) int {
	score := 0
	score += absInt(showing.LVCSNCols - base.LVCSNCols)
	score += absInt(showing.NLeaves-base.NLeaves) / 32768
	score += absInt(showing.Eta - base.Eta)
	score += 2 * absInt(showing.Theta-base.Theta)
	score += absInt(showing.Ell - base.Ell)
	score += qBudget128KappaDeltaWeight(showing.Kappa, base.Kappa)
	if showing.SigShortnessRadix != base.SigShortnessRadix || showing.SigShortnessDigits != base.SigShortnessDigits {
		score += 2
	}
	if showing.CompressedRows != base.CompressedRows {
		score += 2
	}
	if showing.ReplayProjection != base.ReplayProjection {
		score += 3
	}
	if showing.DECSCollisionBits != base.DECSCollisionBits {
		score += 5
	}
	return score
}

func qBudget128WriteSweepSummary(path string, summary qBudget128SweepSummary) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func qBudget128WriteSecurityProfileSweepSummary(path string, summary securityProfileSweepSummary) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func qBudget128AcceptedMetrics() benchmarkIntGenISISMetrics {
	return benchmarkIntGenISISMetrics{
		PaperTranscriptBytes:     1,
		TheoremTotalBits:         129,
		CollisionBits:            129,
		AlgebraicBits:            [4]float64{129, 130, 131, 132},
		TranscriptSecurityStatus: "smallwood_2025_1085_live",
	}
}

func qBudget128SweepPresetNames() []string {
	raw := os.Getenv("SPRUCE_QBUDGET128_SWEEP_PRESETS")
	if raw == "" {
		raw = os.Getenv("SPRUCE_QBUDGET128_SWEEP_PRESET")
	}
	if raw == "" {
		return []string{credential.IntGenISISPresetN1024Q32_128}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name != "" {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return []string{credential.IntGenISISPresetN1024Q32_128}
	}
	return out
}

func qBudget128FilterCandidates(presetName string, candidates []qBudget128SweepCandidate, filter string) []qBudget128SweepCandidate {
	if filter == "" {
		return candidates
	}
	out := candidates[:0]
	for _, cand := range candidates {
		if strings.Contains(cand.Name, filter) || strings.Contains(presetName+":"+cand.Name, filter) || strings.Contains(cand.Family, filter) {
			out = append(out, cand)
		}
	}
	return out
}

func qBudget128CandidateNamesContain(candidates []qBudget128SweepCandidate, want string) bool {
	for _, cand := range candidates {
		if cand.Name == want {
			return true
		}
	}
	return false
}

func qBudget128EnvInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func qBudget128EnvBool(name string) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func qBudget128KappaWeight(k [4]int) int {
	sum := 0
	for _, v := range k {
		sum += v
	}
	return sum
}

func qBudget128KappaDeltaWeight(k, base [4]int) int {
	sum := 0
	for i, v := range k {
		sum += absInt(v - base[i])
	}
	return sum
}

func qBudget128KappaMax(k [4]int) int {
	max := 0
	for _, v := range k {
		if v > max {
			max = v
		}
	}
	return max
}

func qBudget128UniqueInts(vals []int) []int {
	return qBudget128BoundedUniqueInts(vals, -int(^uint(0)>>1), int(^uint(0)>>1))
}

func qBudget128BoundedUniqueInts(vals []int, min, max int) []int {
	seen := make(map[int]struct{}, len(vals))
	out := make([]int, 0, len(vals))
	for _, v := range vals {
		if v < min || v > max {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func qBudget128UniqueStrings(vals []string) []string {
	seen := make(map[string]struct{}, len(vals))
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			v = qBudget128ProjectionNone
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func ceilDivInt(a, b int) int {
	if b <= 0 {
		return 0
	}
	if a <= 0 {
		return 0
	}
	return (a + b - 1) / b
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func qBudget128ChdirRepoRoot(t *testing.T) func() {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if chdirErr := os.Chdir(dir); chdirErr != nil {
				t.Fatalf("chdir repo root: %v", chdirErr)
			}
			return func() {
				if err := os.Chdir(wd); err != nil {
					t.Fatalf("restore working directory: %v", err)
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", wd)
		}
	}
}
