package PIOP

import (
	"fmt"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func extractPackedPRFScalarsFromRows(ringQ *ring.Ring, rows []*ring.Poly, ncols int) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if ncols <= 0 {
		return nil, fmt.Errorf("invalid ncols=%d", ncols)
	}
	rowInputs := buildRowInputs(ringQ, rows, ncols)
	out := make([]uint64, len(rowInputs))
	for i, in := range rowInputs {
		if len(in.Head) == 0 {
			return nil, fmt.Errorf("empty PRF scalar row %d", i)
		}
		val := in.Head[0] % ringQ.Modulus[0]
		for col := 1; col < len(in.Head); col++ {
			if in.Head[col]%ringQ.Modulus[0] != val {
				return nil, fmt.Errorf("PRF scalar row %d is not constant across packed columns", i)
			}
		}
		out[i] = val
	}
	return out, nil
}

func packPRFWitnessRows(
	ringQ *ring.Ring,
	ncols int,
	startRow int,
	key []int64,
	sboxRows []*ring.Poly,
	makeRowFromHead func([]uint64) *ring.Poly,
) ([]*ring.Poly, []PRFSlot, []PRFSlot, error) {
	if ringQ == nil {
		return nil, nil, nil, fmt.Errorf("nil ring")
	}
	if ncols <= 0 {
		return nil, nil, nil, fmt.Errorf("invalid ncols=%d", ncols)
	}
	if makeRowFromHead == nil {
		return nil, nil, nil, fmt.Errorf("nil packed PRF row builder")
	}
	sboxVals, err := extractPackedPRFScalarsFromRows(ringQ, sboxRows, ncols)
	if err != nil {
		return nil, nil, nil, err
	}
	total := len(key) + len(sboxVals)
	if total == 0 {
		return nil, nil, nil, nil
	}

	packedRows := make([]*ring.Poly, 0, ceilDiv(total, ncols))
	keySlots := make([]PRFSlot, 0, len(key))
	sboxSlots := make([]PRFSlot, 0, len(sboxVals))
	head := make([]uint64, ncols)
	used := 0
	flush := func() {
		if used == 0 {
			return
		}
		headCopy := append([]uint64(nil), head...)
		packedRows = append(packedRows, makeRowFromHead(headCopy))
		for i := range head {
			head[i] = 0
		}
		used = 0
	}
	appendScalar := func(v uint64) PRFSlot {
		rowIdx := startRow + len(packedRows)
		slot := PRFSlot{Row: rowIdx, Col: used}
		head[used] = v % ringQ.Modulus[0]
		used++
		if used == ncols {
			flush()
		}
		return slot
	}
	for _, v := range key {
		keySlots = append(keySlots, appendScalar(liftToField(ringQ.Modulus[0], v)))
	}
	for _, v := range sboxVals {
		sboxSlots = append(sboxSlots, appendScalar(v))
	}
	flush()
	return packedRows, keySlots, sboxSlots, nil
}

type packedCompanionWitness struct {
	Rows                 []*ring.Poly
	KeySlots             []CoeffSlot
	CheckpointSlots      []CoeffSlot
	CheckpointInputSlots []CoeffSlot
	FinalTagSlots        []CoeffSlot
	TotalLogicalScalars  int
}

func packPRFCompanionWitnessRows(
	ringQ *ring.Ring,
	ncols int,
	startRow int,
	mode PRFCompanionMode,
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
	mode = normalizePRFCompanionMode(mode)
	out := &packedCompanionWitness{
		KeySlots:             make([]CoeffSlot, 0, len(key)),
		CheckpointSlots:      make([]CoeffSlot, 0, len(grouped.CheckpointOutputs)),
		CheckpointInputSlots: make([]CoeffSlot, 0, len(grouped.CheckpointInputs)),
		FinalTagSlots:        make([]CoeffSlot, 0, len(grouped.FinalTagState)),
	}
	head := make([]uint64, ncols)
	used := 0
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
	includeLegacyFamilies := mode == PRFCompanionModeCurrent
	if includeLegacyFamilies {
		for _, v := range key {
			out.KeySlots = append(out.KeySlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
		}
	}
	for _, v := range grouped.CheckpointOutputs {
		out.CheckpointSlots = append(out.CheckpointSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
	}
	if includeLegacyFamilies {
		for _, v := range grouped.CheckpointInputs {
			out.CheckpointInputSlots = append(out.CheckpointInputSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
		}
	}
	for _, v := range grouped.FinalTagState {
		out.FinalTagSlots = append(out.FinalTagSlots, appendScalar(uint64(v)%ringQ.Modulus[0]))
	}
	flush()
	return out, nil
}
