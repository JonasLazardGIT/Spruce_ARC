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
	mu      sync.Mutex
	entries []PhaseTiming
}

func NewPhaseRecorder() *PhaseRecorder {
	return &PhaseRecorder{}
}

func (r *PhaseRecorder) RecordDuration(label string, d time.Duration) {
	if r == nil || label == "" {
		return
	}
	r.mu.Lock()
	r.entries = append(r.entries, PhaseTiming{
		Label:        label,
		Milliseconds: float64(d.Microseconds()) / 1000.0,
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
