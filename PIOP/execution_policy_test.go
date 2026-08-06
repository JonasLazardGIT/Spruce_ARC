package PIOP

import "testing"

func TestExecutionPolicyZeroValuePreservesCompatibilityLimits(t *testing.T) {
	p := ExecutionPolicy{}
	if err := p.Validate(); err != nil {
		t.Fatalf("zero policy: %v", err)
	}
	if got := p.semanticWorkerCount(); got < 1 || got > 8 {
		t.Fatalf("zero policy semantic workers=%d, want [1,8]", got)
	}
	if got := p.decsWorkerCount(); got != 0 {
		t.Fatalf("zero policy DECS workers=%d, want historical default 0", got)
	}
	if got := p.issuancePlanWorkerCount(); got != 1 {
		t.Fatalf("zero policy issuance workers=%d, want serial compatibility", got)
	}
}

func TestExecutionPolicyFailsClosed(t *testing.T) {
	bad := []ExecutionPolicy{
		{WorkerBudget: -1},
		{WorkerBudget: 2, DECSWorkers: 3},
		{DECSChunkLeaves: -1},
		{SHA3Backend: "unknown"},
		{SHA3Backend: SHA3BackendARM64},
	}
	for _, policy := range bad {
		if err := policy.Validate(); err == nil {
			t.Fatalf("accepted invalid policy %+v", policy)
		}
	}
}

func TestTargetedLatencyExecutionPolicyIsExplicit(t *testing.T) {
	p, err := TargetedLatencyExecutionPolicy(15, 64)
	if err != nil {
		t.Fatal(err)
	}
	if p.semanticWorkerCount() != 15 || p.decsWorkerCount() != 15 || p.issuancePlanWorkerCount() != 15 || p.DECSChunkLeaves != 64 {
		t.Fatalf("unexpected targeted policy %+v", p)
	}
}
