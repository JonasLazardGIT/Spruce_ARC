package PIOP

import (
	"fmt"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type packedCompanionWitness struct {
	Rows                  []*ring.Poly
	KeySlots              []CoeffSlot
	CheckpointSlots       []CoeffSlot
	FinalRoundOutputSlots []CoeffSlot
	FinalTagSlots         []CoeffSlot
	TotalLogicalScalars   int
}

func prfCompanionRelationVersion(mode PRFCompanionMode) uint8 {
	if normalizePRFCompanionMode(mode) == PRFCompanionModeDirectFull {
		return 1
	}
	return 0
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
		KeySlots:              make([]CoeffSlot, 0, len(key)),
		CheckpointSlots:       make([]CoeffSlot, 0, len(grouped.CheckpointOutputs)),
		FinalRoundOutputSlots: make([]CoeffSlot, 0, len(grouped.FinalRoundOutputs)),
		FinalTagSlots:         make([]CoeffSlot, 0, len(grouped.FinalTagState)),
	}
	includeFinalRoundOutputs := normalizePRFCompanionMode(mode) == PRFCompanionModeDirectFull
	head := make([]uint64, ncols)
	used := 0
	keyStart := 0
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
		if ncols < len(key) {
			return nil, fmt.Errorf("dense PRF companion key packing requires ncols >= lenkey; got ncols=%d lenkey=%d", ncols, len(key))
		}
		for _, v := range key {
			out.KeySlots = append(out.KeySlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
		}
		flush()
		for _, v := range grouped.CheckpointOutputs {
			out.CheckpointSlots = append(out.CheckpointSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
		}
		if includeFinalRoundOutputs {
			for _, v := range grouped.FinalRoundOutputs {
				out.FinalRoundOutputSlots = append(out.FinalRoundOutputSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
			}
		}
		for _, v := range grouped.FinalTagState {
			out.FinalTagSlots = append(out.FinalTagSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
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
	flush()
	for _, v := range grouped.CheckpointOutputs {
		out.CheckpointSlots = append(out.CheckpointSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
	}
	if includeFinalRoundOutputs {
		for _, v := range grouped.FinalRoundOutputs {
			out.FinalRoundOutputSlots = append(out.FinalRoundOutputSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
		}
	}
	for _, v := range grouped.FinalTagState {
		out.FinalTagSlots = append(out.FinalTagSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
	}
	flush()
	return out, nil
}
