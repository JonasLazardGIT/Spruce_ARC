package credential

import (
	"fmt"
	"math"
)

// LHLReport records the leftover-hash-lemma target-hiding check for the active
// runtime parameters.
type LHLReport struct {
	RingDegree           int
	Modulus              uint64
	TargetDim            int
	TargetHidingLambda   int
	X0Len                int
	X0CoeffBound         int64
	AvailableEntropyBits float64
	RequiredEntropyBits  float64
	NormalizedLeft       float64
	NormalizedRight      float64
	SlackBits            float64
	SatisfiesLHL         bool
}

func BuildLHLReport(p *Params) (LHLReport, error) {
	if p == nil || p.RingQ == nil {
		return LHLReport{}, fmt.Errorf("nil params or ring")
	}
	if p.X0Len <= 0 {
		return LHLReport{}, fmt.Errorf("invalid X0Len=%d", p.X0Len)
	}
	if p.X0CoeffBound <= 0 {
		return LHLReport{}, fmt.Errorf("invalid X0CoeffBound=%d", p.X0CoeffBound)
	}
	if p.TargetDim <= 0 {
		return LHLReport{}, fmt.Errorf("invalid TargetDim=%d", p.TargetDim)
	}
	if p.TargetHidingLambda <= 0 {
		return LHLReport{}, fmt.Errorf("invalid TargetHidingLambda=%d", p.TargetHidingLambda)
	}
	logAlphabet := math.Log2(float64(2*p.X0CoeffBound + 1))
	logModulus := math.Log2(float64(p.RingQ.Modulus[0]))
	normLeft := float64(p.X0Len) * logAlphabet
	normRight := float64(p.TargetDim)*logModulus + (2.0*float64(p.TargetHidingLambda))/float64(p.RingQ.N)
	available := float64(p.RingQ.N) * normLeft
	required := float64(p.RingQ.N)*float64(p.TargetDim)*logModulus + 2.0*float64(p.TargetHidingLambda)
	slack := available - required
	return LHLReport{
		RingDegree:           p.RingQ.N,
		Modulus:              p.RingQ.Modulus[0],
		TargetDim:            p.TargetDim,
		TargetHidingLambda:   p.TargetHidingLambda,
		X0Len:                p.X0Len,
		X0CoeffBound:         p.X0CoeffBound,
		AvailableEntropyBits: available,
		RequiredEntropyBits:  required,
		NormalizedLeft:       normLeft,
		NormalizedRight:      normRight,
		SlackBits:            slack,
		SatisfiesLHL:         slack >= 0,
	}, nil
}
