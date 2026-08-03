package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

const v2NinePresetRetuneAuditVersion = 2

type v2RetunePhaseProjection struct {
	PaperTranscriptBytes int        `json:"paper_transcript_bytes"`
	TheoremBits          float64    `json:"theorem_bits"`
	RawRoundBits         [4]float64 `json:"raw_round_bits"`
	RoundTheoremBits     [4]float64 `json:"round_theorem_bits"`
	LogicalRows          int        `json:"logical_rows"`
	ParallelDegree       int        `json:"parallel_degree"`
	AggregatedDegree     int        `json:"aggregated_degree"`
	DQ                   int        `json:"dq"`
}

type v2RetuneCandidate struct {
	LVCSNCols            int                     `json:"lvcs_ncols"`
	NLeaves              int                     `json:"nleaves"`
	Eta                  int                     `json:"eta"`
	Theta                int                     `json:"theta"`
	Ell                  int                     `json:"ell"`
	Kappa                [4]int                  `json:"kappa"`
	Issuance             v2RetunePhaseProjection `json:"issuance"`
	Showing              v2RetunePhaseProjection `json:"showing"`
	CombinedPaperBytes   int                     `json:"combined_paper_bytes"`
	ProjectedWorkUnits   uint64                  `json:"projected_work_units"`
	ExpectedGrindingWork float64                 `json:"expected_grinding_work"`
	ProjectedProverScore float64                 `json:"projected_prover_score"`
	Eligible             bool                    `json:"eligible"`
	RejectionReason      string                  `json:"rejection_reason,omitempty"`
}

type v2RetunePresetAudit struct {
	CanonicalID                string            `json:"canonical_id"`
	ManifestDigest             string            `json:"manifest_digest"`
	BaselineReport             string            `json:"baseline_report"`
	Baseline                   v2RetuneCandidate `json:"baseline"`
	Winner                     v2RetuneCandidate `json:"winner"`
	CandidateCount             int               `json:"candidate_count"`
	EligibleCandidateCount     int               `json:"eligible_candidate_count"`
	CompilerGeometrySource     string            `json:"compiler_geometry_source"`
	SearchScope                string            `json:"search_scope"`
	SelectionOrder             []string          `json:"selection_order"`
	RequiredAlgebraicBits      float64           `json:"required_algebraic_bits"`
	FixedSerializerCalibration struct {
		IssuanceBytes int `json:"issuance_bytes"`
		ShowingBytes  int `json:"showing_bytes"`
	} `json:"fixed_serializer_calibration"`
	BaselineProjectionExact bool `json:"baseline_projection_exact"`
	WinnerTouchesBoundary   bool `json:"winner_touches_boundary"`
}

type v2NinePresetRetuneAudit struct {
	Version     int                   `json:"version"`
	GeneratedAt string                `json:"generated_at"`
	Status      string                `json:"status"`
	Presets     []v2RetunePresetAudit `json:"presets"`
}

// TestNinePresetV2RetuneAudit is an opt-in, evidence-producing audit.  It uses
// the compiler-derived relation rows and degrees from one fresh v2 baseline
// report per canonical preset. The declared local grid changes only SmallWood
// geometry and grinding. Relation/transcript identities, cryptographic widths,
// query model, PRF, policy, rho, ell-prime, and primitive bindings remain fixed.
func TestNinePresetV2RetuneAudit(t *testing.T) {
	if os.Getenv("SPRUCE_V2_NINE_PRESET_RETUNE") != "1" {
		t.Skip("set SPRUCE_V2_NINE_PRESET_RETUNE=1 to run the nine-preset v2 breakpoint audit")
	}
	nizkProfileChdirRepoRoot(t)
	baselineRoot := os.Getenv("SPRUCE_V2_RETUNE_BASELINE_ROOT")
	if baselineRoot == "" {
		baselineRoot = filepath.Join("artifacts", "retune-v2", "baseline")
	}
	output := os.Getenv("SPRUCE_V2_RETUNE_AUDIT_OUT")
	if output == "" {
		output = filepath.Join("artifacts", "retune-v2", "nine-preset-retune-audit.json")
	}

	audit := v2NinePresetRetuneAudit{
		Version:     v2NinePresetRetuneAuditVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Status:      "pass",
		Presets:     make([]v2RetunePresetAudit, 0, len(credential.IntGenISISDefaultPresetNames())),
	}
	filter := strings.TrimSpace(os.Getenv("SPRUCE_V2_RETUNE_FILTER"))
	for _, canonicalID := range credential.IntGenISISDefaultPresetNames() {
		if filter != "" && !strings.Contains(canonicalID, filter) {
			continue
		}
		preset, err := credential.MustLookupIntGenISISPreset(canonicalID)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(baselineRoot, preset.CanonicalID, "run-1.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s baseline: %v", preset.CanonicalID, err)
		}
		var report benchmarkIntGenISISE2EReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatalf("decode %s baseline: %v", preset.CanonicalID, err)
		}
		if report.Version != benchmarkIntGenISISE2EVersion || report.CanonicalPresetID != preset.CanonicalID ||
			report.PresetVersion != preset.PresetVersion || report.PresetManifestDigest != credential.IntGenISISPresetManifestDigest(preset) {
			t.Fatalf("%s baseline is not bound to the current v2 preset", preset.CanonicalID)
		}

		entry, candidates, err := v2RetunePresetBreakpoints(preset, report, path)
		if err != nil {
			t.Fatalf("%s breakpoint audit: %v", preset.CanonicalID, err)
		}
		entry.CandidateCount = len(candidates)
		for _, candidate := range candidates {
			if candidate.Eligible {
				entry.EligibleCandidateCount++
			}
		}
		audit.Presets = append(audit.Presets, entry)
		t.Logf("%s baseline=%d/%d/%d winner_lvcs=%d winner=%d/%d/%d eligible=%d/%d",
			preset.CanonicalID,
			entry.Baseline.Issuance.PaperTranscriptBytes,
			entry.Baseline.Showing.PaperTranscriptBytes,
			entry.Baseline.CombinedPaperBytes,
			entry.Winner.LVCSNCols,
			entry.Winner.Issuance.PaperTranscriptBytes,
			entry.Winner.Showing.PaperTranscriptBytes,
			entry.Winner.CombinedPaperBytes,
			entry.EligibleCandidateCount,
			entry.CandidateCount,
		)
	}
	encoded, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote nine-preset v2 retune audit: %s", output)
}

func v2RetunePresetBreakpoints(preset credential.IntGenISISPreset, report benchmarkIntGenISISE2EReport, reportPath string) (v2RetunePresetAudit, []v2RetuneCandidate, error) {
	entry := v2RetunePresetAudit{
		CanonicalID:            preset.CanonicalID,
		ManifestDigest:         credential.IntGenISISPresetManifestDigest(preset),
		BaselineReport:         filepath.ToSlash(reportPath),
		CompilerGeometrySource: "benchmark_intgenisis_e2e_v2_relation_candidate",
		SearchScope:            "convergence_grid_lvcs_plusminus4_nleaves_minus32_plus4_x16384_eta_minus8_plus2_theta_plusminus1_ell_plusminus2_kappa_exact_0_to_13",
		SelectionOrder:         []string{"combined_paper_bytes", "showing_paper_bytes", "projected_prover_score", "nleaves", "lexicographic_tuning"},
	}
	requiredTarget, err := v2RetuneRequiredAlgebraicTarget(preset, report)
	if err != nil {
		return v2RetunePresetAudit{}, nil, err
	}
	entry.RequiredAlgebraicBits = requiredTarget
	rawBaseline, err := v2RetuneProjectTuningCandidate(preset, report, preset.Showing, requiredTarget, 0, 0)
	if err != nil {
		return v2RetunePresetAudit{}, nil, err
	}
	issuanceCalibration := report.Issuance.PaperTranscriptBytes - rawBaseline.Issuance.PaperTranscriptBytes
	showingCalibration := report.Showing.PaperTranscriptBytes - rawBaseline.Showing.PaperTranscriptBytes
	if issuanceCalibration < 0 || showingCalibration < 0 {
		return v2RetunePresetAudit{}, nil, fmt.Errorf("negative fixed serializer calibration %d/%d", issuanceCalibration, showingCalibration)
	}
	entry.FixedSerializerCalibration.IssuanceBytes = issuanceCalibration
	entry.FixedSerializerCalibration.ShowingBytes = showingCalibration
	candidates := make([]v2RetuneCandidate, 0, 54945)
	for lvcs := maxInt(32, preset.Showing.LVCSNCols-4); lvcs <= preset.Showing.LVCSNCols+4; lvcs++ {
		for leafStep := -32; leafStep <= 4; leafStep++ {
			nleaves := preset.Showing.NLeaves + leafStep*16384
			if nleaves <= 1 || uint64(nleaves) >= credential.IntGenISISSharedModulusQ {
				continue
			}
			for eta := maxInt(1, preset.Showing.Eta-8); eta <= preset.Showing.Eta+2; eta++ {
				for theta := maxInt(2, preset.Showing.Theta-1); theta <= preset.Showing.Theta+1; theta++ {
					for ell := maxInt(1, preset.Showing.Ell-2); ell <= preset.Showing.Ell+2; ell++ {
						tuning := preset.Showing
						tuning.LVCSNCols = lvcs
						tuning.NLeaves = nleaves
						tuning.Eta = eta
						tuning.Theta = theta
						tuning.Ell = ell
						kappa, grinding, ok := v2RetuneOptimizeSharedKappa(requiredTarget, report, tuning)
						if !ok {
							candidates = append(candidates, v2RetuneCandidate{
								LVCSNCols: lvcs, NLeaves: nleaves, Eta: eta, Theta: theta, Ell: ell,
								RejectionReason: "no shared kappa in [0,13]^4 preserves both phase algebraic targets",
							})
							continue
						}
						tuning.Kappa = kappa
						candidate, err := v2RetuneProjectTuningCandidate(preset, report, tuning, requiredTarget, issuanceCalibration, showingCalibration)
						if err != nil {
							return v2RetunePresetAudit{}, nil, err
						}
						candidate.ExpectedGrindingWork = grinding
						candidate.ProjectedProverScore = float64(candidate.ProjectedWorkUnits) + grinding
						candidates = append(candidates, candidate)
					}
				}
			}
		}
	}
	baseline, err := v2RetuneProjectTuningCandidate(preset, report, preset.Showing, requiredTarget, issuanceCalibration, showingCalibration)
	if err != nil {
		return v2RetunePresetAudit{}, nil, err
	}
	entry.Baseline = baseline
	entry.BaselineProjectionExact = baseline.Issuance.PaperTranscriptBytes == report.Issuance.PaperTranscriptBytes &&
		baseline.Showing.PaperTranscriptBytes == report.Showing.PaperTranscriptBytes
	if !entry.BaselineProjectionExact {
		return v2RetunePresetAudit{}, nil, fmt.Errorf("baseline projection bytes %d/%d do not match measured %d/%d",
			baseline.Issuance.PaperTranscriptBytes, baseline.Showing.PaperTranscriptBytes,
			report.Issuance.PaperTranscriptBytes, report.Showing.PaperTranscriptBytes)
	}
	sort.SliceStable(candidates, func(i, j int) bool { return v2RetuneCandidateLess(candidates[i], candidates[j]) })
	for _, candidate := range candidates {
		if candidate.Eligible {
			entry.Winner = candidate
			entry.WinnerTouchesBoundary = v2RetuneWinnerTouchesBoundary(preset.Showing, candidate)
			return entry, candidates, nil
		}
	}
	return v2RetunePresetAudit{}, nil, fmt.Errorf("no LVCS breakpoint preserves both phase targets")
}

func v2RetuneProjectTuningCandidate(preset credential.IntGenISISPreset, report benchmarkIntGenISISE2EReport, showingTuning credential.IntGenISISTuningPreset, requiredTarget float64, issuanceCalibration, showingCalibration int) (v2RetuneCandidate, error) {
	issuanceTuning := showingTuning
	issuanceTuning.PRFCompanionMode = ""
	issuanceTuning.PRFGroupRounds = 0
	issuanceTuning.CheckpointSamples = 0
	issuanceTuning.SigShortnessRadix = 0
	issuanceTuning.SigShortnessDigits = 0
	issuanceTuning.CompressedRows = 0
	issuanceTuning.ReplayProjection = ""
	candidate := v2RetuneCandidate{
		LVCSNCols: showingTuning.LVCSNCols, NLeaves: showingTuning.NLeaves,
		Eta: showingTuning.Eta, Theta: showingTuning.Theta, Ell: showingTuning.Ell, Kappa: showingTuning.Kappa,
	}
	issuance, issuanceWork, err := v2RetuneProjectPhase(preset, report.Issuance, issuanceTuning)
	if err != nil {
		return v2RetuneCandidate{}, fmt.Errorf("issuance: %w", err)
	}
	showing, showingWork, err := v2RetuneProjectPhase(preset, report.Showing, showingTuning)
	if err != nil {
		return v2RetuneCandidate{}, fmt.Errorf("showing: %w", err)
	}
	candidate.Issuance = issuance
	candidate.Showing = showing
	candidate.Issuance.PaperTranscriptBytes += issuanceCalibration
	candidate.Showing.PaperTranscriptBytes += showingCalibration
	candidate.CombinedPaperBytes = candidate.Issuance.PaperTranscriptBytes + candidate.Showing.PaperTranscriptBytes
	candidate.ProjectedWorkUnits = issuanceWork + showingWork
	candidate.Eligible = issuance.TheoremBits >= requiredTarget && showing.TheoremBits >= requiredTarget
	if !candidate.Eligible {
		candidate.RejectionReason = fmt.Sprintf("projected algebraic bits issuance=%.6f showing=%.6f below required %.6f", issuance.TheoremBits, showing.TheoremBits, requiredTarget)
	}
	return candidate, nil
}

func v2RetuneProjectPhase(preset credential.IntGenISISPreset, measured benchmarkIntGenISISMetrics, tuning credential.IntGenISISTuningPreset) (v2RetunePhaseProjection, uint64, error) {
	relation := measured.RelationCandidate
	if relation.LogicalRows <= 0 || relation.ParallelDegree <= 0 || relation.AggregatedDegree <= 0 {
		return v2RetunePhaseProjection{}, 0, fmt.Errorf("missing compiler relation geometry")
	}
	_, _, dq := PIOP.ComputeDQBranchBounds(relation.ParallelDegree, relation.AggregatedDegree, tuning.NCols, tuning.Ell)
	projected, err := nizkProfileProjectPaperTranscript(nizkProfilePaperProjectionParams{
		Q:                      credential.IntGenISISSharedModulusQ,
		Lambda:                 256,
		SaltBits:               measured.SaltBits,
		DECSHashBits:           measured.DECSHashBits,
		DECSTapeBits:           measured.DECSTapeBits,
		RingDegree:             reportRingDegree(preset),
		NCols:                  tuning.NCols,
		LVCSNCols:              tuning.LVCSNCols,
		NLeaves:                tuning.NLeaves,
		Eta:                    tuning.Eta,
		Ell:                    tuning.Ell,
		EllPrime:               tuning.EllPrime,
		Rho:                    tuning.Rho,
		Theta:                  tuning.Theta,
		DQ:                     dq,
		LogicalRows:            relation.LogicalRows,
		TranscriptOmissionMode: tuning.TranscriptOmissionMode,
	})
	if err != nil {
		return v2RetunePhaseProjection{}, 0, err
	}
	sw := NIZKProfileSmallWoodReport{
		LVCSNCols: tuning.LVCSNCols, NLeaves: tuning.NLeaves, Eta: tuning.Eta, Theta: tuning.Theta,
		Rho: tuning.Rho, Ell: tuning.Ell, EllPrime: tuning.EllPrime, Kappa: tuning.Kappa,
		EffectiveQueryCapLog2: [4]float64{measured.ROQueryCapBits[1], measured.ROQueryCapBits[2], measured.ROQueryCapBits[3], measured.ROQueryCapBits[4]},
	}
	projectedRelation := relation
	projectedRelation.DQ = dq
	raw := nizkProfileRawRoundBits(projectedRelation, sw)
	round := nizkProfileProjectedRoundBits(NIZKProfileSearchTarget{}, projectedRelation, sw)
	work := uint64(tuning.NLeaves)*uint64(projected.OpeningRows) + uint64(tuning.Theta)*uint64(dq)
	return v2RetunePhaseProjection{
		PaperTranscriptBytes: projected.Transcript.OptimizedBytes,
		TheoremBits:          nizkProfileAggregateBits(round),
		RawRoundBits:         raw,
		RoundTheoremBits:     round,
		LogicalRows:          relation.LogicalRows,
		ParallelDegree:       relation.ParallelDegree,
		AggregatedDegree:     relation.AggregatedDegree,
		DQ:                   dq,
	}, work, nil
}

func reportRingDegree(preset credential.IntGenISISPreset) int {
	profile, ok := credential.LookupIntGenISISProfile(preset.Profile)
	if !ok {
		return 0
	}
	return profile.N
}

func v2RetuneCandidateLess(left, right v2RetuneCandidate) bool {
	if left.Eligible != right.Eligible {
		return left.Eligible
	}
	if left.CombinedPaperBytes != right.CombinedPaperBytes {
		return left.CombinedPaperBytes < right.CombinedPaperBytes
	}
	if left.Showing.PaperTranscriptBytes != right.Showing.PaperTranscriptBytes {
		return left.Showing.PaperTranscriptBytes < right.Showing.PaperTranscriptBytes
	}
	if left.ProjectedProverScore != right.ProjectedProverScore {
		return left.ProjectedProverScore < right.ProjectedProverScore
	}
	if left.NLeaves != right.NLeaves {
		return left.NLeaves < right.NLeaves
	}
	leftTuple := [8]int{left.LVCSNCols, left.NLeaves, left.Eta, left.Theta, left.Ell, left.Kappa[0], left.Kappa[1], left.Kappa[2]}
	rightTuple := [8]int{right.LVCSNCols, right.NLeaves, right.Eta, right.Theta, right.Ell, right.Kappa[0], right.Kappa[1], right.Kappa[2]}
	for i := range leftTuple {
		if leftTuple[i] != rightTuple[i] {
			return leftTuple[i] < rightTuple[i]
		}
	}
	return left.Kappa[3] < right.Kappa[3]
}

func v2RetuneOptimizeSharedKappa(target float64, report benchmarkIntGenISISE2EReport, tuning credential.IntGenISISTuningPreset) ([4]int, float64, bool) {
	issuanceBase := v2RetuneBaseRoundBits(report.Issuance, tuning)
	showingBase := v2RetuneBaseRoundBits(report.Showing, tuning)
	targetProbability := math.Exp2(-target)
	bestWork := math.Inf(1)
	best := [4]int{}
	found := false
	for k0 := 0; k0 <= nizkProfileMaxSupportedGrinding; k0++ {
		for k1 := 0; k1 <= nizkProfileMaxSupportedGrinding; k1++ {
			for k2 := 0; k2 <= nizkProfileMaxSupportedGrinding; k2++ {
				k3 := 0
				feasible := true
				for _, base := range [][4]float64{issuanceBase, showingBase} {
					partial := math.Exp2(-(base[0] + float64(k0))) +
						math.Exp2(-(base[1] + float64(k1))) +
						math.Exp2(-(base[2] + float64(k2)))
					remaining := targetProbability - partial
					if remaining <= 0 {
						feasible = false
						break
					}
					required := int(math.Ceil(-math.Log2(remaining) - base[3] - 1e-12))
					if required > k3 {
						k3 = required
					}
				}
				if !feasible {
					continue
				}
				k3 = maxInt(k3, 0)
				if k3 > nizkProfileMaxSupportedGrinding {
					continue
				}
				candidate := [4]int{k0, k1, k2, k3}
				work := 0.0
				for _, kappa := range candidate {
					work += math.Exp2(float64(kappa))
				}
				if !found || work < bestWork-1e-12 || (math.Abs(work-bestWork) <= 1e-12 && v2RetuneKappaLess(candidate, best)) {
					best, bestWork, found = candidate, work, true
				}
			}
		}
	}
	return best, bestWork, found
}

func v2RetuneRequiredAlgebraicTarget(preset credential.IntGenISISPreset, report benchmarkIntGenISISE2EReport) (float64, error) {
	spec, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		return 0, fmt.Errorf("missing security profile %q", preset.SecurityProfile)
	}
	required := preset.TargetTheoremBits
	targetProbability := math.Exp2(-spec.TargetBits)
	for label, collisionBits := range map[string]float64{
		"issuance": report.Issuance.CollisionBits,
		"showing":  report.Showing.CollisionBits,
	} {
		collisionProbability := math.Exp2(-collisionBits)
		remaining := targetProbability - collisionProbability
		if remaining <= 0 {
			return 0, fmt.Errorf("%s collision term %.6f cannot sustain %.6f theorem bits", label, collisionBits, spec.TargetBits)
		}
		phaseRequired := -math.Log2(remaining)
		if phaseRequired > required {
			required = phaseRequired
		}
	}
	return required, nil
}

func v2RetuneBaseRoundBits(measured benchmarkIntGenISISMetrics, tuning credential.IntGenISISTuningPreset) [4]float64 {
	relation := measured.RelationCandidate
	_, _, relation.DQ = PIOP.ComputeDQBranchBounds(relation.ParallelDegree, relation.AggregatedDegree, tuning.NCols, tuning.Ell)
	sw := NIZKProfileSmallWoodReport{
		LVCSNCols: tuning.LVCSNCols, NLeaves: tuning.NLeaves, Eta: tuning.Eta,
		Theta: tuning.Theta, Rho: tuning.Rho, Ell: tuning.Ell, EllPrime: tuning.EllPrime,
	}
	raw := nizkProfileRawRoundBits(relation, sw)
	for i := range raw {
		raw[i] -= measured.ROQueryCapBits[i+1]
	}
	return raw
}

func v2RetuneKappaLess(left, right [4]int) bool {
	for i := range left {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return false
}

func v2RetuneWinnerTouchesBoundary(incumbent credential.IntGenISISTuningPreset, winner v2RetuneCandidate) bool {
	return winner.LVCSNCols == maxInt(32, incumbent.LVCSNCols-4) || winner.LVCSNCols == incumbent.LVCSNCols+4 ||
		winner.NLeaves == incumbent.NLeaves-32*16384 || winner.NLeaves == incumbent.NLeaves+4*16384 ||
		winner.Eta == maxInt(1, incumbent.Eta-8) || winner.Eta == incumbent.Eta+2 ||
		winner.Theta == maxInt(2, incumbent.Theta-1) || winner.Theta == incumbent.Theta+1 ||
		winner.Ell == maxInt(1, incumbent.Ell-2) || winner.Ell == incumbent.Ell+2
}
