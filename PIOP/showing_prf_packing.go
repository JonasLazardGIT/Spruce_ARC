package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func remapPRFLayout(layout *PRFLayout, remap []int) (*PRFLayout, error) {
	if layout == nil {
		return nil, nil
	}
	remapSlot := func(slot PRFSlot) (PRFSlot, error) {
		if slot.Row < 0 {
			return slot, nil
		}
		if slot.Row >= len(remap) || remap[slot.Row] < 0 {
			return PRFSlot{}, fmt.Errorf("pruned required prf row %d", slot.Row)
		}
		slot.Row = remap[slot.Row]
		return slot, nil
	}
	out := clonePRFLayout(layout)
	if out.StartIdx >= 0 {
		if out.StartIdx >= len(remap) || remap[out.StartIdx] < 0 {
			return nil, fmt.Errorf("pruned required prf start row %d", out.StartIdx)
		}
		out.StartIdx = remap[out.StartIdx]
	}
	for i := range out.KeySlots {
		slot, err := remapSlot(out.KeySlots[i])
		if err != nil {
			return nil, err
		}
		out.KeySlots[i] = slot
	}
	for i := range out.SBoxSlots {
		slot, err := remapSlot(out.SBoxSlots[i])
		if err != nil {
			return nil, err
		}
		out.SBoxSlots[i] = slot
	}
	return out, nil
}

func buildOmegaDeltaSelectors(ringQ *ring.Ring, omega []uint64) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return nil, nil, fmt.Errorf("|omega|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	q := ringQ.Modulus[0]
	theta := make([]*ring.Poly, ncols)
	coeff := make([][]uint64, ncols)
	for col := 0; col < ncols; col++ {
		vals := make([]uint64, ncols)
		vals[col] = 1
		c := Interpolate(omega, vals, q)
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], c)
		pNTT := ringQ.NewPoly()
		ring.Copy(p, pNTT)
		ringQ.NTT(pNTT, pNTT)
		theta[col] = pNTT
		full := make([]uint64, ringQ.N)
		copy(full, c)
		for i := range full {
			full[i] %= q
		}
		coeff[col] = trimPoly(full, q)
	}
	return theta, coeff, nil
}
