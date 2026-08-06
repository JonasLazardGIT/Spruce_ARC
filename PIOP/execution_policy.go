package PIOP

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/cpu"
)

// SHA3Backend names a local hashing implementation. It is operational only:
// selecting a backend never changes domains, framing, or requested widths.
type SHA3Backend string

const (
	SHA3BackendGeneric SHA3Backend = "generic"
	SHA3BackendAuto    SHA3Backend = "auto"
	SHA3BackendARM64   SHA3Backend = "arm64-sha3"
)

const maxExecutionWorkers = 64

// ExecutionPolicy contains bounded, non-cryptographic scheduling controls.
// Its zero value is the compatibility path: DECS uses its historical static
// ranges and semantic-Q retains its historical eight-worker ceiling.
type ExecutionPolicy struct {
	WorkerBudget        int         `json:"worker_budget,omitempty"`
	DECSWorkers         int         `json:"decs_workers,omitempty"`
	DECSChunkLeaves     int         `json:"decs_chunk_leaves,omitempty"`
	SemanticWorkers     int         `json:"semantic_workers,omitempty"`
	IssuancePlanWorkers int         `json:"issuance_plan_workers,omitempty"`
	SHA3Backend         SHA3Backend `json:"sha3_backend,omitempty"`
}

func (p ExecutionPolicy) Validate() error {
	for name, value := range map[string]int{
		"worker budget":         p.WorkerBudget,
		"DECS workers":          p.DECSWorkers,
		"semantic workers":      p.SemanticWorkers,
		"issuance plan workers": p.IssuancePlanWorkers,
	} {
		if value < 0 || value > maxExecutionWorkers {
			return fmt.Errorf("PIOP: %s=%d outside [0,%d]", name, value, maxExecutionWorkers)
		}
	}
	if p.DECSChunkLeaves < 0 || p.DECSChunkLeaves > 1<<20 {
		return fmt.Errorf("PIOP: DECS chunk leaves=%d outside [0,%d]", p.DECSChunkLeaves, 1<<20)
	}
	if p.WorkerBudget > 0 && (p.DECSWorkers > p.WorkerBudget || p.SemanticWorkers > p.WorkerBudget || p.IssuancePlanWorkers > p.WorkerBudget) {
		return fmt.Errorf("PIOP: phase worker count exceeds worker budget")
	}
	if p.SHA3Backend != "" && p.SHA3Backend != SHA3BackendGeneric && p.SHA3Backend != SHA3BackendAuto && p.SHA3Backend != SHA3BackendARM64 {
		return fmt.Errorf("PIOP: unsupported SHA3 backend %q", p.SHA3Backend)
	}
	if p.SHA3Backend == SHA3BackendARM64 && !ARM64SHA3BackendAvailable() {
		return fmt.Errorf("PIOP: ARM64 SHA3 backend has not passed promotion gates")
	}
	return nil
}

func (p ExecutionPolicy) effectiveBudget() int {
	workers := p.WorkerBudget
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		return 1
	}
	if workers > maxExecutionWorkers {
		return maxExecutionWorkers
	}
	return workers
}

func (p ExecutionPolicy) decsWorkerCount() int {
	if p.DECSWorkers > 0 {
		return p.DECSWorkers
	}
	if p.WorkerBudget > 0 {
		return p.WorkerBudget
	}
	return 0
}

func (p ExecutionPolicy) semanticWorkerCount() int {
	if p.SemanticWorkers > 0 {
		return p.SemanticWorkers
	}
	if p != (ExecutionPolicy{}) {
		return p.effectiveBudget()
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func (p ExecutionPolicy) issuancePlanWorkerCount() int {
	if p.IssuancePlanWorkers > 0 {
		return p.IssuancePlanWorkers
	}
	if p.WorkerBudget > 0 {
		return p.WorkerBudget
	}
	return 1
}

// ARM64CPUHasSHA3Instructions is a capability fact, not a promotion decision.
func ARM64CPUHasSHA3Instructions() bool {
	return runtime.GOARCH == "arm64" && cpu.ARM64.HasSHA3
}

// ARM64SHA3BackendAvailable remains fail closed until an in-tree assembly
// backend passes differential known-answer and end-to-end performance gates.
func ARM64SHA3BackendAvailable() bool { return false }

// TargetedLatencyExecutionPolicy returns a portable candidate policy. Callers
// must benchmark it on their machine; proof APIs never select it implicitly.
func TargetedLatencyExecutionPolicy(workers int, chunkLeaves int) (ExecutionPolicy, error) {
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	p := ExecutionPolicy{
		WorkerBudget: workers, DECSWorkers: workers,
		DECSChunkLeaves: chunkLeaves, SemanticWorkers: workers,
		IssuancePlanWorkers: workers, SHA3Backend: SHA3BackendGeneric,
	}
	if err := p.Validate(); err != nil {
		return ExecutionPolicy{}, err
	}
	return p, nil
}
