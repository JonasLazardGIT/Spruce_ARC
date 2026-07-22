package main

import (
	"fmt"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func nizkProfileWF128TuningCandidates() []NIZKProfileSearchCandidate {
	preset, err := credential.MustLookupIntGenISISPreset(credential.IntGenISISPresetSystemN1024WF128CROMV1)
	if err != nil {
		return nil
	}
	base := intGenISISTuningFromPresetSpec(preset.Showing)
	relation := nizkProfileRelationWF128()
	type shape struct {
		name        string
		lvcs        int
		nleaves     int
		eta         int
		theta       int
		ell         int
		tapeBits    int
		pinnedEta   bool
		description string
	}
	shapes := []shape{
		{
			name: "wf128-baseline-v1-lvcs36-n983040-eta44-theta7-ell9-tape128", lvcs: 36, nleaves: 983040, eta: 44, theta: 7, ell: 9, tapeBits: 128, pinnedEta: true,
			description: "pre-retune WF-128 transcript geometry retained as the projection and measurement control; grinding is retargeted to the sweep margin",
		},
		{
			name: "wf128-tape136-lvcs36-n983040-theta7-ell9", lvcs: 36, nleaves: 983040, theta: 7, ell: 9, tapeBits: 136,
			description: "tests the engineering tape-width lane without changing SmallWood geometry",
		},
		{
			name: "wf128-lvcs37-n983040-theta7-ell9", lvcs: 37, nleaves: 983040, theta: 7, ell: 9, tapeBits: 128,
			description: "first dQ block-count breakpoint above the current committed width",
		},
		{
			name: "wf128-lvcs40-n983040-theta7-ell9", lvcs: 40, nleaves: 983040, theta: 7, ell: 9, tapeBits: 128,
			description: "simultaneous logical-row and dQ block-count breakpoint",
		},
		{
			name: "wf128-lvcs41-n983040-theta7-ell9", lvcs: 41, nleaves: 983040, theta: 7, ell: 9, tapeBits: 128,
			description: "next logical-row block-count breakpoint",
		},
		{
			name: "wf128-lvcs43-n983040-theta7-ell9", lvcs: 43, nleaves: 983040, theta: 7, ell: 9, tapeBits: 128,
			description: "next dQ block-count breakpoint",
		},
		{
			name: "wf128-lvcs46-n983040-theta7-ell9", lvcs: 46, nleaves: 983040, theta: 7, ell: 9, tapeBits: 128,
			description: "nine-block logical-row breakpoint",
		},
		{
			name: "wf128-lvcs48-n983040-theta7-ell9", lvcs: 48, nleaves: 983040, theta: 7, ell: 9, tapeBits: 128,
			description: "ten-block dQ breakpoint",
		},
		{
			name: "wf128-n524288-lvcs36-theta7-ell9", lvcs: 36, nleaves: 524288, theta: 7, ell: 9, tapeBits: 128,
			description: "19-level explicit-domain authentication breakpoint",
		},
		{
			name: "wf128-n655360-lvcs36-theta7-ell9", lvcs: 36, nleaves: 655360, theta: 7, ell: 9, tapeBits: 128,
			description: "intermediate explicit-domain probe for eta and final-opening pressure",
		},
		{
			name: "wf128-n786432-lvcs36-theta7-ell9", lvcs: 36, nleaves: 786432, theta: 7, ell: 9, tapeBits: 128,
			description: "sub-q explicit-domain probe shared with the bounded-query pilot lane",
		},
		{
			name: "wf128-theta6-ell8-lvcs40-n983040", lvcs: 40, nleaves: 983040, theta: 6, ell: 8, tapeBits: 128,
			description: "byte-aggressive theta/ell probe retained only if required grinding stays supported",
		},
		{
			name: "wf128-theta7-ell8-lvcs40-n983040", lvcs: 40, nleaves: 983040, theta: 7, ell: 8, tapeBits: 128,
			description: "one-opening-layer reduction at a row/dQ breakpoint",
		},
		{
			name: "wf128-theta8-ell10-lvcs40-n983040", lvcs: 40, nleaves: 983040, theta: 8, ell: 10, tapeBits: 128,
			description: "soundness-slack control for the byte-aggressive probes",
		},
		{
			name: "wf128-n524288-lvcs43-theta7-ell9", lvcs: 43, nleaves: 524288, theta: 7, ell: 9, tapeBits: 128,
			description: "combines the authentication-depth and dQ block-count breakpoints",
		},
		{
			name: "wf128-n524288-lvcs37-theta7-ell9", lvcs: 37, nleaves: 524288, theta: 7, ell: 9, tapeBits: 128,
			description: "combines the authentication-depth and first dQ block-count breakpoints",
		},
		{
			name: "wf128-n524288-lvcs40-theta7-ell9", lvcs: 40, nleaves: 524288, theta: 7, ell: 9, tapeBits: 128,
			description: "combines the authentication-depth with simultaneous row and dQ block-count breakpoints",
		},
		{
			name: "wf128-n524288-lvcs41-theta7-ell9", lvcs: 41, nleaves: 524288, theta: 7, ell: 9, tapeBits: 128,
			description: "combines the authentication-depth and ten-block logical-row breakpoint",
		},
		{
			name: "wf128-n524288-lvcs46-theta7-ell9", lvcs: 46, nleaves: 524288, theta: 7, ell: 9, tapeBits: 128,
			description: "combines the authentication-depth and nine-block logical-row breakpoint",
		},
		{
			name: "wf128-n524288-lvcs48-theta7-ell9", lvcs: 48, nleaves: 524288, theta: 7, ell: 9, tapeBits: 128,
			description: "combines the authentication-depth and ten-block dQ breakpoint",
		},
		{
			name: "wf128-n786432-lvcs43-theta7-ell9", lvcs: 43, nleaves: 786432, theta: 7, ell: 9, tapeBits: 128,
			description: "combines the sub-q domain with the dQ block-count breakpoint",
		},
	}

	out := make([]NIZKProfileSearchCandidate, 0, len(shapes))
	for _, candidateShape := range shapes {
		showing := base
		showing.LVCSNCols = candidateShape.lvcs
		showing.NLeaves = candidateShape.nleaves
		if candidateShape.eta > 0 {
			showing.Eta = candidateShape.eta
		}
		showing.Theta = candidateShape.theta
		showing.Ell = candidateShape.ell
		showing.Kappa = [4]int{}
		relationForShape := nizkProfileRelationForEll(relation, showing.Ell)
		out = append(out, nizkProfileCandidateFromTuningWithOptions(
			candidateShape.name,
			fmt.Sprintf("wf128-live-r11l4-theta%d-ell%d-lvcs%d-n%d", showing.Theta, showing.Ell, showing.LVCSNCols, showing.NLeaves),
			preset.Name,
			showing,
			relationForShape,
			nizkProfileCandidateOptions{
				Family:                 nizkProfileWF128TuningFamily,
				TargetProfile:          "WF-128",
				LaneOverride:           "poc_engineering",
				CompilerBacked:         true,
				PinnedLVCS:             true,
				DeriveEtaFloorOnly:     !candidateShape.pinnedEta,
				HashFSBitsOverride:     264,
				TapeBitsOverride:       candidateShape.tapeBits,
				SaltBitsOverride:       256,
				TagElementsOverride:    13,
				NIZKTargetBitsOverride: 132,
				RelationFirstScore:     nizkProfileRelationFirstScore(relationForShape, showing),
				Notes: []string{
					candidateShape.description,
					"work-factor accounting keeps bounded random-oracle query caps unset",
					"candidate changes are measured against the executable tag-13 WF-128 control before any preset retune",
				},
			},
		))
	}
	return nizkProfileDeduplicateCandidates(out)
}

func nizkProfileRelationWF128() benchmarkIntGenISISRelationReport {
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(11, 8, 32, 9)
	return benchmarkIntGenISISRelationReport{
		LogicalRows:      408,
		ParallelDegree:   11,
		AggregatedDegree: 8,
		DQParallel:       dqParallel,
		DQAggregate:      dqAggregate,
		DQ:               dq,
		MaskDegreeBound:  dq,
		RowCounts: map[string]int{
			"total":     408,
			"bound":     49,
			"mask":      98,
			"prf":       7,
			"shortness": 256,
		},
		ConstraintCounts: map[string]int{
			"fpar_int":            32,
			"prf_key_bridge":      8,
			"projected_signature": 1024,
			"range":               49,
			"shortness":           256,
			"source_bridge":       1024,
		},
		DominantDegreeSource: "shortness",
		DominantDQBranch:     "parallel",
	}
}

func TestNIZKProfileWF128SweepIsOptIn(t *testing.T) {
	for _, target := range nizkProfileSearchTargets() {
		if target.SecurityProfile == "WF-128" {
			t.Fatalf("default research target set unexpectedly contains WF-128: %+v", target)
		}
	}
	targets := nizkProfileSearchTargetsForFilter("wf128")
	if len(targets) != 1 || targets[0].SecurityProfile != "WF-128" {
		t.Fatalf("WF-128 targets=%+v", targets)
	}
	if targets[0].SecurityMode != string(credential.SecurityModeQueryWorkFactor) || targets[0].TargetStatus != credential.SecurityProfileCandidate || targets[0].QueryCapExponent != 0 {
		t.Fatalf("WF-128 target semantics=%+v", targets[0])
	}
	for _, cand := range nizkProfileSearchCandidatesForFilter("WF-128") {
		if cand.Family != nizkProfileWF128TuningFamily || cand.TargetProfile != "WF-128" {
			t.Fatalf("WF-128 filter leaked candidate %+v", cand)
		}
	}
}

func TestNIZKProfileWF128RelationMatchesMeasuredControl(t *testing.T) {
	relation := nizkProfileRelationWF128()
	if relation.LogicalRows != 408 || relation.ParallelDegree != 11 || relation.AggregatedDegree != 8 || relation.DQParallel != 471 || relation.DQAggregate != 320 || relation.DQ != 471 || relation.MaskDegreeBound != 471 {
		t.Fatalf("WF-128 relation=%+v", relation)
	}
	wantRows := map[string]int{"total": 408, "bound": 49, "mask": 98, "prf": 7, "shortness": 256}
	for label, want := range wantRows {
		if relation.RowCounts[label] != want {
			t.Fatalf("WF-128 relation row %s=%d want %d", label, relation.RowCounts[label], want)
		}
	}
}

func TestNIZKProfileWF128CandidatesStayExecutableAndUnbounded(t *testing.T) {
	candidates := nizkProfileWF128TuningCandidates()
	if len(candidates) < 10 {
		t.Fatalf("WF-128 candidates=%d want a focused breakpoint family", len(candidates))
	}
	q := int(credential.IntGenISISSharedModulusQ)
	for _, cand := range candidates {
		if cand.ControlPreset != credential.IntGenISISPresetSystemN1024WF128CROMV1 || !cand.CompilerBacked || !cand.PinnedLVCS {
			t.Fatalf("WF-128 candidate provenance=%+v", cand)
		}
		if cand.Showing.NLeaves <= 0 || cand.Showing.NLeaves >= q {
			t.Fatalf("WF-128 candidate %s nLeaves=%d q=%d", cand.Name, cand.Showing.NLeaves, q)
		}
		if cand.Showing.ROQueryCapsSet || cand.Showing.ROQueryCaps != [5]int{} || cand.Showing.ROQueryCapBitsSet || cand.Showing.ROQueryCapBits != [5]float64{} {
			t.Fatalf("WF-128 candidate %s carries bounded query caps", cand.Name)
		}
	}
	reports := nizkProfileReports(0, "wf128")
	if len(reports) != len(candidates) {
		t.Fatalf("WF-128 reports=%d candidates=%d", len(reports), len(candidates))
	}
	for _, report := range reports {
		if report.SecurityProfile != "WF-128" || report.LedgerStatus != string(credential.SecurityProfileCandidate) {
			t.Fatalf("WF-128 report classification=%+v", report)
		}
		if report.SmallWood.NLeaves >= q {
			t.Fatalf("WF-128 report %s nLeaves=%d q=%d", report.Candidate, report.SmallWood.NLeaves, q)
		}
	}
}

func TestNIZKProfileWF128MeasuredConfigUsesTag13AndNoQueryCap(t *testing.T) {
	reports := nizkProfileReports(0, "wf128-baseline-v1-lvcs36")
	if len(reports) != 1 {
		t.Fatalf("WF-128 control reports=%d", len(reports))
	}
	report := reports[0]
	var cand NIZKProfileSearchCandidate
	for _, candidate := range nizkProfileWF128TuningCandidates() {
		if candidate.Name == report.Candidate {
			cand = candidate
			break
		}
	}
	if cand.Name == "" {
		t.Fatalf("missing WF-128 control candidate %q", report.Candidate)
	}
	target := nizkProfileTargetForCandidate(nizkProfileWF128SearchTarget(), cand)
	cfg, err := nizkProfileBenchmarkConfig(target, cand, report, t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PRFProfile != credential.IntGenISISPRFProfileTag13 || cfg.PRFParamsPath != credential.IntGenISISPRFParamsTag13 || cfg.PRFParamsDigest != credential.IntGenISISPRFParamsTag13Digest {
		t.Fatalf("WF-128 measured PRF binding=(%q,%q,%q)", cfg.PRFProfile, cfg.PRFParamsPath, cfg.PRFParamsDigest)
	}
	for phase, tuning := range map[string]intGenISISTuning{"issuance": cfg.Issuance, "showing": cfg.Showing} {
		if tuning.ROQueryCapsSet || tuning.ROQueryCaps != [5]int{} || tuning.ROQueryCapBitsSet || tuning.ROQueryCapBits != [5]float64{} {
			t.Fatalf("WF-128 measured %s carries bounded query caps: %+v", phase, tuning)
		}
	}
	if cfg.ThreatModel.SecurityMode != credential.SecurityModeQueryWorkFactor || cfg.ThreatModel.ROQueryCapLog2 != [5]float64{} {
		t.Fatalf("WF-128 measured threat model=%+v", cfg.ThreatModel)
	}
	if report.RelationSafety.BaselineRows != 408 || report.RelationSafety.BaselineDQ != 471 || !report.RelationSafety.CurrentTheoremSafe {
		t.Fatalf("WF-128 relation safety=%+v", report.RelationSafety)
	}
	wantBuckets := qBudget128BucketDigest{
		Q:        8243,
		R:        3960,
		Pdecs:    4950,
		Auth:     5940,
		Tapes:    144,
		VTargets: 15978,
		BarSets:  12735,
	}
	if report.TranscriptBuckets != wantBuckets || report.PaperTranscriptBytes != 51950 {
		t.Fatalf("WF-128 control projection changed: bytes=%d buckets=%+v want bytes=51950 buckets=%+v", report.PaperTranscriptBytes, report.TranscriptBuckets, wantBuckets)
	}
	if !strings.Contains(strings.Join(report.ForcedBySecurity, "\n"), "query caps unset") {
		t.Fatalf("WF-128 forced security notes=%v", report.ForcedBySecurity)
	}
}
