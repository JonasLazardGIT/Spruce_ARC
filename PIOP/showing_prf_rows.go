package PIOP

import (
	"fmt"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type packedCompanionWitness struct {
	Rows                []*ring.Poly
	KeySlots            []CoeffSlot
	CheckpointSlots     []CoeffSlot
	FinalTagSlots       []CoeffSlot
	TotalLogicalScalars int
}

func packPRFCompanionWitnessRows(
	ringQ *ring.Ring,
	ncols int,
	startRow int,
	mode PRFCompanionMode,
	denseKeyPacking bool,
	key []prf.Elem,
	grouped *prf.GroupedWitness,
	makeRowFromHead func([]uint64) *ring.Poly,
) (*packedCompanionWitness, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if grouped == nil {
		return nil, fmt.Errorf("nil grouped witness")
	}
	if ncols <= 0 {
		return nil, fmt.Errorf("invalid ncols=%d", ncols)
	}
	if makeRowFromHead == nil {
		return nil, fmt.Errorf("nil packed PRF row builder")
	}
	out := &packedCompanionWitness{
		KeySlots:        make([]CoeffSlot, 0, len(key)),
		CheckpointSlots: make([]CoeffSlot, 0, len(grouped.CheckpointOutputs)),
		FinalTagSlots:   make([]CoeffSlot, 0, len(grouped.FinalTagState)),
	}
	head := make([]uint64, ncols)
	used := 0
	keyStart := 0
	if len(key) > 0 && !denseKeyPacking {
		half := ncols / 2
		if half >= len(key) {
			keyStart = half
		}
	}
	flush := func() {
		if used == 0 {
			return
		}
		out.Rows = append(out.Rows, makeRowFromHead(append([]uint64(nil), head...)))
		for i := range head {
			head[i] = 0
		}
		used = 0
	}
	appendScalar := func(v uint64) CoeffSlot {
		slot := CoeffSlot{
			Row:   startRow + len(out.Rows),
			Coeff: used,
		}
		head[used] = v % ringQ.Modulus[0]
		used++
		out.TotalLogicalScalars++
		if used == ncols {
			flush()
		}
		return slot
	}
	if denseKeyPacking && len(key) > 0 {
		half := ncols / 2
		if half <= 0 || half < len(key) {
			return nil, fmt.Errorf("dense PRF companion key packing requires ncols/2 >= lenkey; got ncols=%d lenkey=%d", ncols, len(key))
		}
		prefix := half
		if prefix > len(grouped.FinalTagState) {
			prefix = len(grouped.FinalTagState)
		}
		finalTagIdx := 0
		for finalTagIdx < prefix {
			v := grouped.FinalTagState[finalTagIdx]
			out.FinalTagSlots = append(out.FinalTagSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
			finalTagIdx++
		}
		if used < half {
			used = half
		}
		for _, v := range key {
			out.KeySlots = append(out.KeySlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
		}
		for _, v := range grouped.CheckpointOutputs {
			out.CheckpointSlots = append(out.CheckpointSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
		}
		for finalTagIdx < len(grouped.FinalTagState) {
			v := grouped.FinalTagState[finalTagIdx]
			out.FinalTagSlots = append(out.FinalTagSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
			finalTagIdx++
		}
		flush()
		return out, nil
	}

	if keyStart > 0 {
		used = keyStart
	}
	for _, v := range key {
		out.KeySlots = append(out.KeySlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
	}
	for _, v := range grouped.CheckpointOutputs {
		out.CheckpointSlots = append(out.CheckpointSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
	}
	for _, v := range grouped.FinalTagState {
		out.FinalTagSlots = append(out.FinalTagSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
	}
	flush()
	return out, nil
}
