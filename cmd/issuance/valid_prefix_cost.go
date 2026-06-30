package main

import (
	"math"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func benchmarkValidPrefixCostReport(spec credential.IntGenISISSecurityProfileSpec, timings []PIOP.PhaseTiming, explicitValidPrefixCaps [4]float64, researchAccounting bool) credential.ValidPrefixCostReport {
	logs := credential.ROBudgetLogVectorFromProfile(spec)
	rawCap := logs.RawLog2
	if rawCap <= 0 {
		rawCap = maxFloat64Array(logs.FSLog2)
	}
	workBudgetLog2 := rawCap
	cumulativeMS := benchmarkValidPrefixCumulativeMS(timings)
	predicates := benchmarkValidPrefixPredicates()
	report := credential.ValidPrefixCostReport{
		Model:                   credential.ValidPrefixCostModelMeasuredStructural,
		Source:                  "phase_timings",
		ResearchOnly:            researchAccounting || hasPositiveFloat64Array(explicitValidPrefixCaps),
		ValidPrefixConservative: !researchAccounting && !hasPositiveFloat64Array(explicitValidPrefixCaps),
		WorkBudgetLog2:          workBudgetLog2,
		RawCapLog2:              rawCap,
		Notes: []string{
			"collision, programming, and challenge-bias terms continue to use raw RO caps",
			"valid-prefix caps are research-only unless the current theorem explicitly accounts for them",
		},
	}
	for i := 0; i < 4; i++ {
		roundRawCap := logs.FSLog2[i]
		if roundRawCap <= 0 {
			roundRawCap = rawCap
		}
		hashCostLog2 := benchmarkHashEquivalentCostLog2(cumulativeMS[i])
		validCap := roundRawCap
		accountingStatus := credential.ValidPrefixAccountingConservativeRawFallback
		if explicitValidPrefixCaps[i] > 0 {
			validCap = math.Min(roundRawCap, explicitValidPrefixCaps[i])
			accountingStatus = credential.ValidPrefixAccountingResearchRequiresTheory
		} else if researchAccounting && workBudgetLog2 > 0 && hashCostLog2 > 0 {
			validCap = math.Min(roundRawCap, math.Max(0, workBudgetLog2-hashCostLog2))
			accountingStatus = credential.ValidPrefixAccountingResearchRequiresTheory
		} else if !report.ValidPrefixConservative {
			accountingStatus = credential.ValidPrefixAccountingRawCaps
		}
		report.EffectiveAlgebraicCapLog2[i] = validCap
		report.Rounds = append(report.Rounds, credential.ValidPrefixRoundCost{
			Round:                       i + 1,
			Label:                       predicates[i].label,
			PrefixPredicate:             predicates[i].predicate,
			StructuralPrerequisites:     append([]string(nil), predicates[i].prerequisites...),
			MeasuredCumulativeMS:        cumulativeMS[i],
			EstimatedHashEquivalentLog2: hashCostLog2,
			RawCapLog2:                  roundRawCap,
			ValidPrefixCapLog2:          validCap,
			AccountingStatus:            accountingStatus,
		})
	}
	return report
}

type benchmarkValidPrefixPredicate struct {
	label         string
	predicate     string
	prerequisites []string
}

func benchmarkValidPrefixPredicates() [4]benchmarkValidPrefixPredicate {
	return [4]benchmarkValidPrefixPredicate{
		{
			label:     "fs_round_1",
			predicate: "salt/root-bound first Fiat-Shamir query is syntactically canonical and tied to a partial Merkle tree",
			prerequisites: []string{
				"canonical salt",
				"canonical DECS/LVCS root",
				"partial Merkle tree defined by prior hash queries",
			},
		},
		{
			label:     "fs_round_2",
			predicate: "round-2 query extends the round-1 prefix with canonical gamma values and committed opening shape",
			prerequisites: []string{
				"valid round-1 prefix",
				"domain-separated round-2 transcript",
				"commitment-bound opening metadata",
			},
		},
		{
			label:     "fs_round_3",
			predicate: "round-3 query extends a canonical Q/mask prefix that can still satisfy verifier degree checks",
			prerequisites: []string{
				"valid round-2 prefix",
				"canonical Q payload",
				"mask rows and LVCS columns consistent with the relation",
			},
		},
		{
			label:     "fs_round_4",
			predicate: "round-4 query extends the verifier-openable tail prefix and remains replay-check extendable",
			prerequisites: []string{
				"valid round-3 prefix",
				"canonical evaluation targets",
				"Merkle authentication paths and opening indices consistent with the DECS verifier",
			},
		},
	}
}

func benchmarkValidPrefixCumulativeMS(timings []PIOP.PhaseTiming) [4]float64 {
	base := benchmarkPhaseTimingMS(timings,
		"showing.rows",
		"showing.rows_ntt",
		"showing.constraints.total",
		"showing.lvcs_commit_total",
	)
	round1 := base
	round2 := round1 + benchmarkPhaseTimingMS(timings, "RunMaskFS.Round1Gamma")
	round3 := round2 + benchmarkPhaseTimingMS(timings, "RunMaskFS.Round2GammaPrime", "RunMaskFS.BuildQAndMasks")
	round4 := round3 + benchmarkPhaseTimingMS(timings, "RunMaskFS.Round3Eval", "RunMaskFS.Round4TailOpen")
	return [4]float64{round1, round2, round3, round4}
}

func benchmarkPhaseTimingMS(timings []PIOP.PhaseTiming, labels ...string) float64 {
	want := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		want[label] = struct{}{}
	}
	var total float64
	for _, timing := range timings {
		if _, ok := want[timing.Label]; ok {
			total += timing.Milliseconds
		}
	}
	return total
}

func benchmarkHashEquivalentCostLog2(ms float64) float64 {
	if ms <= 0 {
		return 0
	}
	return math.Log2(ms * 1000)
}

func maxFloat64Array(vals [4]float64) float64 {
	var out float64
	for _, v := range vals {
		if v > out {
			out = v
		}
	}
	return out
}

func hasPositiveFloat64Array(vals [4]float64) bool {
	for _, v := range vals {
		if v > 0 {
			return true
		}
	}
	return false
}
