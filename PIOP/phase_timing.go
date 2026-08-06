package PIOP

import (
	"sync"
	"time"
)

// PhaseTiming is a lightweight benchmark-only timing sample.
type PhaseTiming struct {
	Label        string  `json:"label"`
	Milliseconds float64 `json:"ms"`
}

// PhaseRecorder records opt-in benchmark phase timings. It is intentionally
// local to one proof/build/verify run and is not used for transcript material.
type PhaseRecorder struct {
	mu                  sync.Mutex
	entries             []PhaseTiming
	recordDECSSubphases bool
}

func NewPhaseRecorder() *PhaseRecorder {
	return &PhaseRecorder{}
}

// NewDetailedPhaseRecorder additionally enables the expensive per-leaf DECS
// timing split. It is intended for isolated benchmark runs only; ordinary
// proof reports use NewPhaseRecorder and avoid clock reads inside leaf loops.
func NewDetailedPhaseRecorder() *PhaseRecorder {
	return &PhaseRecorder{recordDECSSubphases: true}
}

// DECSSubphasesEnabled is consumed through a private capability check by the
// PIOP-to-LVCS adapter. It is not transcript material.
func (r *PhaseRecorder) DECSSubphasesEnabled() bool {
	return r != nil && r.recordDECSSubphases
}

// phaseTimingStart avoids reading the clock on production paths where timing
// instrumentation is disabled. Callers only pass the result to time.Since
// after checking the same recorder is non-nil.
func phaseTimingStart(recorder *PhaseRecorder) time.Time {
	if recorder == nil {
		return time.Time{}
	}
	return time.Now()
}

func (r *PhaseRecorder) RecordDuration(label string, d time.Duration) {
	if r == nil || label == "" || d <= 0 {
		return
	}
	r.mu.Lock()
	r.entries = append(r.entries, PhaseTiming{
		Label:        label,
		Milliseconds: float64(d.Nanoseconds()) / 1e6,
	})
	r.mu.Unlock()
}

func (r *PhaseRecorder) Snapshot() []PhaseTiming {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PhaseTiming, len(r.entries))
	copy(out, r.entries)
	return out
}
