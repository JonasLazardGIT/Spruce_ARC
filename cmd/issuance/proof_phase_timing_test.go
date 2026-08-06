package main

import (
	"encoding/json"
	"strings"
	"testing"

	"vSIS-Signature/PIOP"
)

func TestBenchmarkValidPrefixCumulativeMSSupportsIssuanceLabels(t *testing.T) {
	timings := []PIOP.PhaseTiming{
		{Label: "issuance.domain_prepare", Milliseconds: 1},
		{Label: "issuance.rows", Milliseconds: 2},
		{Label: "issuance.lvcs_commit_total", Milliseconds: 3},
		{Label: "RunMaskFS.Round1Gamma", Milliseconds: 4},
		{Label: "RunMaskFS.Round2GammaPrime", Milliseconds: 5},
		{Label: "RunMaskFS.BuildQAndMasks", Milliseconds: 6},
		{Label: "RunMaskFS.Round3Eval", Milliseconds: 7},
		{Label: "RunMaskFS.Round4TailOpen", Milliseconds: 8},
	}
	got := benchmarkValidPrefixCumulativeMS(timings)
	want := [4]float64{6, 10, 21, 36}
	if got != want {
		t.Fatalf("issuance cumulative phases=%v want %v", got, want)
	}
}

func TestBenchmarkMetricsSerializesAuthoritativeFSCounters(t *testing.T) {
	report := benchmarkIntGenISISMetrics{FSCounters: [4]uint64{0, 1, 255, 256}}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"fs_counters":[0,1,255,256]`) {
		t.Fatalf("metrics JSON omits counters: %s", encoded)
	}
}
