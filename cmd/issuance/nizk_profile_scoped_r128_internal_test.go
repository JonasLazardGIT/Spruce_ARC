package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func nizkProfileScopedR128SearchTarget(label string, queryCapExponent int) NIZKProfileSearchTarget {
	spec, ok := credential.LookupIntGenISISSecurityProfile(label)
	if !ok {
		panic(fmt.Sprintf("missing security profile %s", label))
	}
	queryCaps := [5]float64{
		float64(queryCapExponent),
		float64(queryCapExponent),
		float64(queryCapExponent),
		float64(queryCapExponent),
		float64(queryCapExponent),
	}
	collisionOnly := PIOP.SoundnessBudget{
		CollisionSpaceBits: spec.MinDECSHashBits,
		QueryCapBits:       queryCaps,
	}
	fullGame := PIOP.ComposeFullGameSoundness(collisionOnly, collisionOnly, 1, 1)
	phaseTarget := benchmarkRequiredPhaseAlgebraicBits(nizkProfileScopedR128FullGameTargetBits, fullGame)
	if phaseTarget <= 0 {
		panic(fmt.Sprintf("%s collision width cannot sustain %.0f full-game bits", label, nizkProfileScopedR128FullGameTargetBits))
	}
	return NIZKProfileSearchTarget{
		SecurityProfile:        spec.Label,
		Lane:                   "nizk_scoped_poc",
		TargetStatus:           spec.Status,
		SecurityMode:           string(spec.Mode),
		CoreBitsRequired:       spec.CoreBitsRequired,
		NIZKTargetBits:         phaseTarget,
		FullGameTargetBits:     nizkProfileScopedR128FullGameTargetBits,
		QueryCapExponent:       queryCapExponent,
		HashFSBitsRange:        [2]int{spec.MinDECSHashBits, spec.MinDECSHashBits},
		TapeBitsRange:          [2]int{spec.MinDECSTapeBits, spec.MinDECSTapeBits},
		SaltBitsRange:          [2]int{spec.MinSaltBits, spec.MinSaltBits},
		TagElementsRange:       [2]int{spec.MinPRFTagElements, spec.MinPRFTagElements},
		BareSaltBits:           spec.MinSaltBits,
		EngineeringSaltBits:    spec.MinSaltBits,
		PrimitiveBlockerReason: fmt.Sprintf("%s is proof-only: the 2^%d caps cover the five NIZK oracle domains, while the unchanged primitive family is assumed independently at %.0f bits", spec.Label, queryCapExponent, spec.CoreBitsRequired),
	}
}

func nizkProfileScopedR128Candidates(presetName string, base intGenISISTuning) []NIZKProfileSearchCandidate {
	type targetShape struct {
		Profile  string
		HashBits int
		TapeBits int
		Thetas   []int
		Ells     []int
	}
	targets := []targetShape{
		{Profile: "BQ64-128", HashBits: 264, TapeBits: 200, Thetas: []int{10, 11}, Ells: []int{13, 14, 15, 16}},
		{Profile: "BQ96-128", HashBits: 328, TapeBits: 232, Thetas: []int{11, 12}, Ells: []int{15, 16, 17, 18}},
		{Profile: "BQ128-128", HashBits: 392, TapeBits: 264, Thetas: []int{13, 14}, Ells: []int{17, 18, 19}},
	}
	type relationLane struct {
		Name     string
		Relation benchmarkIntGenISISRelationReport
		Apply    func(intGenISISTuning) intGenISISTuning
	}
	relations := []relationLane{
		{
			Name:     "r7l5",
			Relation: nizkProfileRelationCurrentBQ32(),
			Apply: func(tuning intGenISISTuning) intGenISISTuning {
				return tuning
			},
		},
		{
			Name:     "r11l4",
			Relation: nizkProfileRelationR11L4TopCap(),
			Apply:    nizkProfileR11L4Candidate,
		},
	}
	nleaves := []int{1 << 19, 600000, 655360, 720896, 786432, 917504, 983040}
	lvcsBreakpoints := make([]int, 0, 25)
	for width := 32; width <= 56; width++ {
		lvcsBreakpoints = append(lvcsBreakpoints, width)
	}
	out := make([]NIZKProfileSearchCandidate, 0, len(targets)*len(relations)*2*3*len(nleaves)*len(lvcsBreakpoints))
	for _, target := range targets {
		for _, relationLane := range relations {
			for _, theta := range target.Thetas {
				for _, ell := range target.Ells {
					relation := nizkProfileRelationForEll(relationLane.Relation, ell)
					for _, domainSize := range nleaves {
						for _, lvcs := range lvcsBreakpoints {
							showing := nizkProfileSmallWoodOnlyCandidateWithLVCS(base, theta, ell, domainSize, 1, lvcs)
							showing = relationLane.Apply(showing)
							showing.PRFProfile = credential.IntGenISISPRFProfileTag10
							showing.PRFParamsPath = credential.IntGenISISPRFParamsTag10
							name := fmt.Sprintf(
								"%s-%s-theta%d-ell%d-n%d-lvcs%d",
								strings.ToLower(target.Profile),
								relationLane.Name,
								theta,
								ell,
								domainSize,
								lvcs,
							)
							out = append(out, nizkProfileCandidateFromTuningWithOptions(
								name,
								"current-theorem-"+relationLane.Name,
								presetName,
								showing,
								relation,
								nizkProfileCandidateOptions{
									Family:              nizkProfileScopedR128Family,
									TargetProfile:       target.Profile,
									CompilerBacked:      true,
									PinnedLVCS:          true,
									DeriveEtaFloorOnly:  true,
									HashFSBitsOverride:  target.HashBits,
									TapeBitsOverride:    target.TapeBits,
									SaltBitsOverride:    200,
									TagElementsOverride: 10,
									RelationFirstScore:  nizkProfileRelationFirstScore(relation, showing),
									Notes: []string{
										"current raw-cap theorem only; no valid-prefix discount or serializer omission",
										"eta and grinding are derived from exact one-issuance/one-showing full-game composition",
										"tag and honest-proof volume are independently scoped to 2^32 per context",
									},
								},
							))
						}
					}
				}
			}
		}
	}
	return out
}

func nizkProfileIssuanceRelationForEll(ell int) benchmarkIntGenISISRelationReport {
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(9, 1, 32, maxInt(ell, 1))
	return benchmarkIntGenISISRelationReport{
		LogicalRows:          165,
		ParallelDegree:       9,
		AggregatedDegree:     1,
		DQParallel:           dqParallel,
		DQAggregate:          dqAggregate,
		DQ:                   dq,
		MaskDegreeBound:      dq,
		RowCounts:            map[string]int{"total": 165, "bound": 160},
		DominantDegreeSource: "bounded_range",
		DominantDQBranch:     "parallel",
	}
}

func nizkProfileProjectedFullGame(target NIZKProfileSearchTarget, issuanceBits, showingBits float64) PIOP.FullGameSoundnessReport {
	raw := float64(target.QueryCapExponent)
	queryCaps := [5]float64{raw, raw, raw, raw, raw}
	issuance := PIOP.SoundnessBudget{
		AlgebraicTotal:     math.Exp2(-issuanceBits),
		CollisionSpaceBits: target.HashFSBitsRange[0],
		QueryCapBits:       queryCaps,
	}
	showing := PIOP.SoundnessBudget{
		AlgebraicTotal:     math.Exp2(-showingBits),
		CollisionSpaceBits: target.HashFSBitsRange[0],
		QueryCapBits:       queryCaps,
	}
	return PIOP.ComposeFullGameSoundness(issuance, showing, 1, 1)
}

func nizkProfileOptimizeAggregateGrinding(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, base intGenISISTuning, lvcs int, queryCapLog2 [4]float64) nizkProfileGrindingPlan {
	ell := maxInt(base.Ell, 1)
	nleaves := maxInt(base.NLeaves, 1)
	ddecs := maxInt(lvcs, 1) + ell - 1
	logQ := math.Log2(float64(credential.IntGenISISSharedModulusQ))
	minEta := int(math.Ceil(
		(target.NIZKTargetBits + queryCapLog2[0] +
			credential.Log2Binom(uint64(nleaves), uint64(ddecs+2)) -
			float64(nizkProfileMaxSupportedGrinding)) / logQ,
	))
	minEta = maxInt(minEta, 1)

	sw := NIZKProfileSmallWoodReport{
		LVCSNCols:             lvcs,
		NLeaves:               nleaves,
		Theta:                 maxInt(base.Theta, 1),
		Rho:                   maxInt(base.Rho, 1),
		Ell:                   ell,
		EllPrime:              maxInt(base.EllPrime, 1),
		EffectiveQueryCapLog2: queryCapLog2,
	}
	for eta := minEta; eta <= minEta+4; eta++ {
		plan := nizkProfileOptimizeGrindingAtEta(target, relation, sw, eta)
		if plan.Feasible {
			return plan
		}
	}
	return nizkProfileGrindingPlan{
		Eta:   minEta,
		Kappa: [4]int{nizkProfileMaxSupportedGrinding + 1, nizkProfileMaxSupportedGrinding + 1, nizkProfileMaxSupportedGrinding + 1, nizkProfileMaxSupportedGrinding + 1},
	}
}

func nizkProfileOptimizeGrindingAtEta(target NIZKProfileSearchTarget, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport, eta int) nizkProfileGrindingPlan {
	sw.Eta = eta
	raw := nizkProfileWorstPhaseRawRoundBits(relation, sw)
	caps := nizkProfileSmallWoodQueryCapLog2(target, sw)
	baseBits := [4]float64{}
	for i := range baseBits {
		baseBits[i] = raw[i] - caps[i]
	}
	targetProb := math.Exp2(-target.NIZKTargetBits)
	best := nizkProfileGrindingPlan{Eta: eta}
	bestMaxKappa := math.MaxInt
	bestKappaSum := math.MaxInt
	const comparisonSlack = 1e-12

	for k0 := 0; k0 <= nizkProfileMaxSupportedGrinding; k0++ {
		p0 := math.Exp2(-(baseBits[0] + float64(k0)))
		for k1 := 0; k1 <= nizkProfileMaxSupportedGrinding; k1++ {
			p1 := math.Exp2(-(baseBits[1] + float64(k1)))
			for k2 := 0; k2 <= nizkProfileMaxSupportedGrinding; k2++ {
				partial := p0 + p1 + math.Exp2(-(baseBits[2] + float64(k2)))
				remaining := targetProb - partial
				if remaining <= 0 {
					continue
				}
				k3 := int(math.Ceil(-math.Log2(remaining) - baseBits[3] - comparisonSlack))
				k3 = maxInt(k3, 0)
				if k3 > nizkProfileMaxSupportedGrinding {
					continue
				}
				kappa := [4]int{k0, k1, k2, k3}
				roundBits := [4]float64{}
				for i := range roundBits {
					roundBits[i] = baseBits[i] + float64(kappa[i])
				}
				aggregateBits := nizkProfileAggregateBits(roundBits)
				if aggregateBits+1e-9 < target.NIZKTargetBits {
					continue
				}
				expectedWork := 0.0
				maxKappa := 0
				kappaSum := 0
				for _, k := range kappa {
					expectedWork += math.Exp2(float64(k))
					maxKappa = maxInt(maxKappa, k)
					kappaSum += k
				}
				if best.Feasible &&
					(expectedWork > best.ExpectedWork+comparisonSlack ||
						(math.Abs(expectedWork-best.ExpectedWork) <= comparisonSlack &&
							(maxKappa > bestMaxKappa || (maxKappa == bestMaxKappa && kappaSum >= bestKappaSum)))) {
					continue
				}
				best = nizkProfileGrindingPlan{
					Eta:              eta,
					Kappa:            kappa,
					AggregateBits:    aggregateBits,
					ExpectedWork:     expectedWork,
					ExpectedWorkLog2: math.Log2(expectedWork),
					Feasible:         true,
				}
				bestMaxKappa = maxKappa
				bestKappaSum = kappaSum
			}
		}
	}
	return best
}

func nizkProfileWorstPhaseRawRoundBits(showingRelation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport) [4]float64 {
	showing := nizkProfileRawRoundBits(showingRelation, sw)
	issuance := nizkProfileRawRoundBits(nizkProfileIssuanceRelationForEll(sw.Ell), sw)
	for i := range showing {
		if issuance[i] < showing[i] {
			showing[i] = issuance[i]
		}
	}
	return showing
}

func nizkProfileProjectPhase(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, relation benchmarkIntGenISISRelationReport, sw NIZKProfileSmallWoodReport) (NIZKProfilePhaseProjection, error) {
	projected, err := nizkProfileProjectPaperTranscript(nizkProfilePaperProjectionParams{
		Q:                      credential.IntGenISISSharedModulusQ,
		Lambda:                 256,
		SaltBits:               target.SaltBitsRange[0],
		DECSHashBits:           target.HashFSBitsRange[0],
		DECSTapeBits:           target.TapeBitsRange[0],
		RingDegree:             1024,
		NCols:                  32,
		LVCSNCols:              sw.LVCSNCols,
		NLeaves:                sw.NLeaves,
		Eta:                    sw.Eta,
		Ell:                    sw.Ell,
		EllPrime:               sw.EllPrime,
		Rho:                    sw.Rho,
		Theta:                  sw.Theta,
		DQ:                     relation.DQ,
		LogicalRows:            relation.LogicalRows,
		TranscriptOmissionMode: cand.SerializerOmission,
	})
	if err != nil {
		return NIZKProfilePhaseProjection{}, err
	}
	proverWorkUnits := uint64(sw.NLeaves)*uint64(projected.OpeningRows) +
		uint64(sw.Theta)*uint64(maxInt(relation.DQ, 1))
	return NIZKProfilePhaseProjection{
		LogicalRows:       relation.LogicalRows,
		DQ:                relation.DQ,
		WitnessLayers:     projected.WitnessLayers,
		ReplayWitnessRows: projected.ReplayWitnessRows,
		MaskRows:          projected.MaskRows,
		OpeningRows:       projected.OpeningRows,
		QueryCount:        projected.QueryCount,
		PColsEncoded:      projected.PColsEncoded,
		ProverWorkUnits:   proverWorkUnits,
		Transcript:        projected.Transcript,
	}, nil
}

func nizkProfileBucketDigestFromPaperTranscript(report PIOP.PaperTranscriptReport) nizkProfileBucketDigest {
	return nizkProfileBucketDigest{
		Q:            report.Q.OptimizedBytes,
		R:            report.R.OptimizedBytes,
		Pdecs:        report.Pdecs.OptimizedBytes,
		Mdecs:        report.Mdecs.OptimizedBytes,
		Auth:         report.Auth.OptimizedBytes,
		Tapes:        report.Tapes.OptimizedBytes,
		SigShortness: report.SigShortness.OptimizedBytes,
		VTargets:     report.VTargets.OptimizedBytes,
		BarSets:      report.BarSets.OptimizedBytes,
	}
}

func nizkProfileReportsWithMeasurements(t *testing.T, reports []NIZKProfileCandidateReport, root string, maxE2E int) []NIZKProfileCandidateReport {
	t.Helper()
	if len(reports) == 0 {
		return reports
	}
	nizkProfileChdirRepoRoot(t)
	targets := make(map[string]NIZKProfileSearchTarget)
	for _, target := range nizkProfileSearchTargets() {
		targets[target.SecurityProfile] = target
	}
	candidates := make(map[string]NIZKProfileSearchCandidate)
	for _, cand := range nizkProfileSearchCandidatesForReports(reports) {
		candidates[cand.Name] = cand
	}
	out := append([]NIZKProfileCandidateReport(nil), reports...)
	measurementSet := nizkProfileMeasurementSet(out)
	repeats := nizkProfileEnvInt("SPRUCE_NIZK_PROFILE_SWEEP_REPEATS", 3)
	if repeats <= 0 {
		repeats = 3
	}
	finalistCount := 0
	runCount := 0
	for i, report := range out {
		if _, ok := measurementSet[report.Candidate]; !ok {
			continue
		}
		if maxE2E > 0 && finalistCount >= maxE2E {
			break
		}
		if !nizkProfileShouldMeasureReport(report) {
			continue
		}
		if ok, reason := nizkProfileReportMeasurable(report); !ok {
			out[i].MeasurementStatus = "measurement_domain_blocked"
			out[i].MeasurementError = reason
			continue
		}
		target, ok := targets[report.SecurityProfile]
		if !ok {
			out[i].MeasurementStatus = "measurement_failed"
			out[i].MeasurementError = "missing search target"
			continue
		}
		cand, ok := candidates[report.Candidate]
		if !ok {
			out[i].MeasurementStatus = "measurement_failed"
			out[i].MeasurementError = "missing search candidate"
			continue
		}
		target = nizkProfileTargetForCandidate(target, cand)
		finalistCount++
		benches := make([]benchmarkIntGenISISE2EReport, 0, repeats)
		jsonPaths := make([]string, 0, repeats)
		for repeat := 0; repeat < repeats; repeat++ {
			measurementReport := report
			if report.IncumbentControl {
				if tuning, ok := nizkProfileIncumbentTuning(report.SecurityProfile); ok {
					measurementReport.SmallWood.Eta = tuning.Eta
					measurementReport.SmallWood.Kappa = tuning.Kappa
				}
			}
			cfg, err := nizkProfileBenchmarkConfig(target, cand, measurementReport, root, runCount+1)
			if err != nil {
				out[i].MeasurementStatus = "measurement_failed"
				out[i].MeasurementError = err.Error()
				break
			}
			runCount++
			if bench, ok := nizkProfileLoadMeasuredBenchmark(cfg.JSONOut); ok {
				benches = append(benches, bench)
				jsonPaths = append(jsonPaths, cfg.JSONOut)
				t.Logf("reused NIZK measurement %s/%s run=%d from %s", report.SecurityProfile, report.Candidate, repeat+1, cfg.JSONOut)
				continue
			}
			bench, err := benchmarkIntGenISISE2E(cfg)
			if err != nil {
				out[i].MeasurementStatus = "measurement_failed"
				out[i].MeasurementError = err.Error()
				out[i].MeasuredArtifactDir = cfg.ArtifactDir
				out[i].MeasuredJSON = cfg.JSONOut
				t.Logf("NIZK measured benchmark failed for %s/%s run=%d: %v", report.SecurityProfile, report.Candidate, repeat+1, err)
				break
			}
			benches = append(benches, bench)
			jsonPaths = append(jsonPaths, cfg.JSONOut)
		}
		if len(benches) != repeats {
			continue
		}
		out[i] = nizkProfileReportWithMeasuredBenchmarks(target, cand, report, benches, jsonPaths)
		t.Logf(
			"NIZK measured benchmark %s/%s runs=%d combined_bytes=%d showing_bytes=%d median_prove_ms=%.3f median_verify_ms=%.3f grinding_work=%.0f",
			report.SecurityProfile,
			report.Candidate,
			repeats,
			out[i].CombinedPaperBytes,
			out[i].PaperTranscriptBytes,
			out[i].MeasurementSummary.MedianCombinedProvingMS,
			out[i].MeasurementSummary.MedianCombinedVerificationMS,
			out[i].ExpectedGrindingWork,
		)
	}
	nizkProfileAnnotateReplacementThresholds(out)
	return out
}

func nizkProfileLoadMeasuredBenchmark(path string) (benchmarkIntGenISISE2EReport, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, false
	}
	var report benchmarkIntGenISISE2EReport
	if err := json.Unmarshal(data, &report); err != nil {
		return benchmarkIntGenISISE2EReport{}, false
	}
	if report.Issuance.PaperTranscriptBytes <= 0 || report.Showing.PaperTranscriptBytes <= 0 {
		return benchmarkIntGenISISE2EReport{}, false
	}
	return report, true
}

func nizkProfileMeasurementSet(reports []NIZKProfileCandidateReport) map[string]struct{} {
	out := make(map[string]struct{})
	grouped := make(map[string][]NIZKProfileCandidateReport)
	scoped := false
	for _, report := range reports {
		if report.Family != nizkProfileScopedR128Family {
			continue
		}
		scoped = true
		grouped[report.SecurityProfile] = append(grouped[report.SecurityProfile], report)
		if report.IncumbentControl {
			out[report.Candidate] = struct{}{}
		}
	}
	if !scoped {
		for _, report := range reports {
			if nizkProfileShouldMeasureReport(report) {
				out[report.Candidate] = struct{}{}
			}
		}
		return out
	}
	for _, entries := range grouped {
		for _, report := range nizkProfileParetoFrontier(entries) {
			out[report.Candidate] = struct{}{}
		}
	}
	return out
}

func nizkProfileReportWithMeasuredBenchmarks(target NIZKProfileSearchTarget, cand NIZKProfileSearchCandidate, report NIZKProfileCandidateReport, benches []benchmarkIntGenISISE2EReport, jsonPaths []string) NIZKProfileCandidateReport {
	out := nizkProfileReportWithMeasuredBenchmark(target, cand, report, benches[0], jsonPaths[0])
	issuanceProving := make([]float64, 0, len(benches))
	issuanceVerification := make([]float64, 0, len(benches))
	showingProving := make([]float64, 0, len(benches))
	showingVerification := make([]float64, 0, len(benches))
	combinedProving := make([]float64, 0, len(benches))
	combinedVerification := make([]float64, 0, len(benches))
	for _, bench := range benches {
		issuanceProving = append(issuanceProving, bench.Issuance.ProvingMS)
		issuanceVerification = append(issuanceVerification, bench.Issuance.VerificationMS)
		showingProving = append(showingProving, bench.Showing.ProvingMS)
		showingVerification = append(showingVerification, bench.Showing.VerificationMS)
		combinedProving = append(combinedProving, bench.Issuance.ProvingMS+bench.Showing.ProvingMS)
		combinedVerification = append(combinedVerification, bench.Issuance.VerificationMS+bench.Showing.VerificationMS)
	}
	summary := &NIZKProfileMeasurementSummary{
		Runs:                         len(benches),
		IssuanceBytes:                benches[0].Issuance.PaperTranscriptBytes,
		ShowingBytes:                 benches[0].Showing.PaperTranscriptBytes,
		CombinedBytes:                benches[0].Issuance.PaperTranscriptBytes + benches[0].Showing.PaperTranscriptBytes,
		MedianIssuanceProvingMS:      nizkProfileMedian(issuanceProving),
		MedianIssuanceVerificationMS: nizkProfileMedian(issuanceVerification),
		MedianShowingProvingMS:       nizkProfileMedian(showingProving),
		MedianShowingVerificationMS:  nizkProfileMedian(showingVerification),
		MedianCombinedProvingMS:      nizkProfileMedian(combinedProving),
		MedianCombinedVerificationMS: nizkProfileMedian(combinedVerification),
		ExpectedGrindingWork:         out.ExpectedGrindingWork,
		ExpectedGrindingWorkLog2:     out.ExpectedGrindingWorkLog2,
	}
	out.MeasurementSummary = summary
	out.MeasurementSource = fmt.Sprintf("benchmark_intgenisis_e2e_median_%d", len(benches))
	out.Notes = append(out.Notes, fmt.Sprintf("timings are medians of %d complete issuance/showing measurements", len(benches)))
	return out
}

func nizkProfileMedian(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

func nizkProfileAnnotateReplacementThresholds(reports []NIZKProfileCandidateReport) {
	incumbents := make(map[string]*NIZKProfileMeasurementSummary)
	for i := range reports {
		if reports[i].IncumbentControl && reports[i].MeasurementSummary != nil {
			incumbents[reports[i].SecurityProfile] = reports[i].MeasurementSummary
		}
	}
	for i := range reports {
		summary := reports[i].MeasurementSummary
		incumbent := incumbents[reports[i].SecurityProfile]
		if summary == nil || incumbent == nil || incumbent.CombinedBytes <= 0 || incumbent.MedianCombinedProvingMS <= 0 {
			continue
		}
		summary.IncumbentCombinedBytes = incumbent.CombinedBytes
		summary.IncumbentMedianProvingMS = incumbent.MedianCombinedProvingMS
		summary.CombinedImprovementPercent = 100 * float64(incumbent.CombinedBytes-summary.CombinedBytes) / float64(incumbent.CombinedBytes)
		summary.ProvingTimeRatio = summary.MedianCombinedProvingMS / incumbent.MedianCombinedProvingMS
		summary.MeaningfulReplacement = !reports[i].IncumbentControl &&
			summary.CombinedImprovementPercent >= nizkProfileMinReplacementImprovementPct &&
			summary.ProvingTimeRatio <= nizkProfileMaxReplacementProvingRatio &&
			nizkProfileMeetsSecurityTarget(reports[i])
	}
}

func nizkProfileScopedR128ThreatModel(target NIZKProfileSearchTarget) credential.PresetThreatModel {
	raw := float64(target.QueryCapExponent)
	return credential.PresetThreatModel{
		ROM:                     credential.ROMModelCROM,
		SecurityMode:            credential.SecurityModeResidualAtBudget,
		TargetResidualBits:      128,
		ROQueryCapLog2:          [5]float64{raw, raw, raw, raw, raw},
		ROQueryCapScope:         credential.ROQueryCapPerPhaseGlobal,
		MaxProofsLog2:           32,
		MaxIssuanceProofsLog2:   31,
		MaxShowingProofsLog2:    31,
		MaxTagsPerContextLog2:   32,
		DomainSeparatedContexts: true,
		ProofVolumeScope:        credential.ProofVolumeHonestTranscripts,
		AcceptedIssuance:        1,
		AcceptedShowing:         1,
	}
}

func nizkProfileExpectedGrindingWork(kappa [4]int) float64 {
	work := 0.0
	for _, bits := range kappa {
		work += math.Exp2(float64(maxInt(bits, 0)))
	}
	return work
}

func nizkProfileIncumbentTuning(profile string) (intGenISISTuning, bool) {
	presetName := ""
	switch profile {
	case "BQ64-128":
		presetName = credential.IntGenISISPresetPoCN1024BQ64R128V1
	case "BQ96-128":
		presetName = credential.IntGenISISPresetPoCN1024BQ96R128V1
	case "BQ128-128":
		presetName = credential.IntGenISISPresetPoCN1024BQ128R128V2
	default:
		return intGenISISTuning{}, false
	}
	preset, err := credential.MustLookupIntGenISISPreset(presetName)
	if err != nil {
		return intGenISISTuning{}, false
	}
	return intGenISISTuningFromPresetSpec(preset.Showing), true
}

func nizkProfileIsIncumbentGeometry(report NIZKProfileCandidateReport) bool {
	tuning, ok := nizkProfileIncumbentTuning(report.SecurityProfile)
	if !ok || report.Relation.LogicalRows != 472 || report.Relation.ParallelDegree != 9 || report.Relation.AggregatedDegree != 8 {
		return false
	}
	return report.SmallWood.LVCSNCols == tuning.LVCSNCols &&
		report.SmallWood.NLeaves == tuning.NLeaves &&
		report.SmallWood.Theta == tuning.Theta &&
		report.SmallWood.Rho == tuning.Rho &&
		report.SmallWood.Ell == tuning.Ell &&
		report.SmallWood.EllPrime == tuning.EllPrime
}

func nizkProfileParetoFrontier(reports []NIZKProfileCandidateReport) []NIZKProfileCandidateReport {
	eligible := make([]NIZKProfileCandidateReport, 0, len(reports))
	for _, report := range reports {
		if report.Family == nizkProfileScopedR128Family &&
			report.FrontierClass == nizkProfileFrontierCandidate &&
			nizkProfileShouldMeasureReport(report) {
			eligible = append(eligible, report)
		}
	}
	frontier := make([]NIZKProfileCandidateReport, 0, len(eligible))
	for i, candidate := range eligible {
		dominated := false
		for j, other := range eligible {
			if i == j {
				continue
			}
			if nizkProfileDominates(other, candidate) {
				dominated = true
				break
			}
		}
		if !dominated {
			frontier = append(frontier, candidate)
		}
	}
	sort.SliceStable(frontier, func(i, j int) bool {
		return nizkProfileReportLess(frontier[i], frontier[j])
	})
	return frontier
}

func nizkProfileDominates(a, b NIZKProfileCandidateReport) bool {
	if a.SecurityProfile != b.SecurityProfile {
		return false
	}
	noWorse := a.CombinedPaperBytes <= b.CombinedPaperBytes &&
		a.ProjectedProverWorkUnits <= b.ProjectedProverWorkUnits
	if !noWorse {
		return false
	}
	return a.CombinedPaperBytes < b.CombinedPaperBytes ||
		a.ProjectedProverWorkUnits < b.ProjectedProverWorkUnits ||
		(a.Candidate < b.Candidate &&
			a.CombinedPaperBytes == b.CombinedPaperBytes &&
			a.ProjectedProverWorkUnits == b.ProjectedProverWorkUnits)
}

func TestNIZKProfileScopedR128GridCoversRequestedBreakpoints(t *testing.T) {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetN1024BQ32_96)
	if err != nil {
		t.Fatal(err)
	}
	candidates := nizkProfileScopedR128Candidates(preset.Name, intGenISISTuningFromPresetSpec(preset.Showing))
	widths := map[int]bool{}
	domains := map[int]bool{}
	openings := map[string]bool{}
	for _, candidate := range candidates {
		widths[candidate.Showing.LVCSNCols] = true
		domains[candidate.Showing.NLeaves] = true
		openings[fmt.Sprintf("%s/%d", candidate.TargetProfile, candidate.Showing.Ell)] = true
	}
	for width := 32; width <= 56; width++ {
		if !widths[width] {
			t.Fatalf("missing LVCS width breakpoint %d", width)
		}
	}
	for _, domain := range []int{1 << 19, 600000, 655360, 720896, 786432, 917504, 983040} {
		if !domains[domain] {
			t.Fatalf("missing authentication-domain breakpoint %d", domain)
		}
	}
	for key, want := range map[string]bool{
		"BQ64-128/13": true,
		"BQ96-128/15": true,
	} {
		if openings[key] != want {
			t.Fatalf("missing opening-count breakpoint %s", key)
		}
	}
}

func TestNIZKProfileParetoFrontierAndReplacementThresholds(t *testing.T) {
	report := func(name string, bytes int, work uint64, incumbent bool) NIZKProfileCandidateReport {
		return NIZKProfileCandidateReport{
			SecurityProfile:          "BQ64-128",
			Candidate:                name,
			Family:                   nizkProfileScopedR128Family,
			FrontierClass:            nizkProfileFrontierCandidate,
			CombinedPaperBytes:       bytes,
			ProjectedProverWorkUnits: work,
			IncumbentControl:         incumbent,
			NIZKTargetBits:           100,
			IssuanceAlgebraicBits:    101,
			ShowingAlgebraicBits:     101,
			FullGameTargetBits:       100,
			FullGameBits:             101,
		}
	}
	reports := []NIZKProfileCandidateReport{
		report("small", 90, 120, false),
		report("balanced", 100, 100, false),
		report("fast", 110, 90, false),
		report("dominated", 110, 130, false),
		report("incumbent", 120, 140, true),
	}
	frontier := nizkProfileParetoFrontier(reports)
	if got, want := len(frontier), 3; got != want {
		t.Fatalf("pareto frontier size=%d want %d: %+v", got, want, frontier)
	}
	measurementSet := nizkProfileMeasurementSet(reports)
	for _, name := range []string{"small", "balanced", "fast", "incumbent"} {
		if _, ok := measurementSet[name]; !ok {
			t.Fatalf("measurement set omitted %s: %+v", name, measurementSet)
		}
	}
	if _, ok := measurementSet["dominated"]; ok {
		t.Fatalf("measurement set retained dominated point: %+v", measurementSet)
	}

	reports[4].MeasurementSummary = &NIZKProfileMeasurementSummary{
		CombinedBytes:           1000,
		MedianCombinedProvingMS: 10,
	}
	reports[0].MeasurementSummary = &NIZKProfileMeasurementSummary{
		CombinedBytes:           975,
		MedianCombinedProvingMS: 19,
	}
	nizkProfileAnnotateReplacementThresholds(reports)
	if !reports[0].MeasurementSummary.MeaningfulReplacement {
		t.Fatalf("2.5%% improvement at 1.9x proving work should qualify: %+v", reports[0].MeasurementSummary)
	}
	reports[0].MeasurementSummary.MedianCombinedProvingMS = 21
	nizkProfileAnnotateReplacementThresholds(reports)
	if reports[0].MeasurementSummary.MeaningfulReplacement {
		t.Fatalf("candidate above 2x proving work should not qualify: %+v", reports[0].MeasurementSummary)
	}

	if got, want := nizkProfileMedian([]float64{4, 1, 3, 2}), 2.5; got != want {
		t.Fatalf("median=%v want %v", got, want)
	}
}
