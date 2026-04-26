package PIOP

import "fmt"

func resolveMuWitnessPackWidth(opts SimOpts) int {
	if opts.MuWitnessPackWidth <= 0 {
		return 1
	}
	return opts.MuWitnessPackWidth
}

func validateMuWitnessPackWidth(width int) error {
	switch width {
	case 1, 2, 4:
		return nil
	default:
		return fmt.Errorf("unsupported mu witness pack width %d", width)
	}
}

func buildMuCarrierDecodePolys(bound int64, packWidth int, q uint64) ([][]uint64, []uint64, error) {
	if err := validateMuWitnessPackWidth(packWidth); err != nil {
		return nil, nil, err
	}
	if packWidth == 1 {
		decode, err := buildSingletonCarrierDecodePoly(bound, q)
		if err != nil {
			return nil, nil, err
		}
		membership, err := buildSingletonCarrierMembershipPoly(bound, q)
		if err != nil {
			return nil, nil, err
		}
		return [][]uint64{decode}, membership, nil
	}
	decode, err := buildPackedMuCarrierDecodePolys(bound, packWidth, q)
	if err != nil {
		return nil, nil, err
	}
	membership, err := buildPackedMuCarrierMembershipPoly(bound, packWidth, q)
	if err != nil {
		return nil, nil, err
	}
	return decode, membership, nil
}

func buildPackedMuCarrierHeads(muHeads [][]uint64, q uint64, bound int64, packWidth int) ([][]uint64, error) {
	if err := validateMuWitnessPackWidth(packWidth); err != nil {
		return nil, err
	}
	if packWidth == 1 {
		out := make([][]uint64, len(muHeads))
		for block := range muHeads {
			head := make([]uint64, len(muHeads[block]))
			for col := range head {
				code, err := encodeSingletonCarrier(centeredLift(muHeads[block][col], q), bound)
				if err != nil {
					return nil, fmt.Errorf("encode carrier Mu block=%d col=%d: %w", block, col, err)
				}
				head[col] = liftToField(q, int64(code))
			}
			out[block] = head
		}
		return out, nil
	}
	if len(muHeads)%packWidth != 0 {
		return nil, fmt.Errorf("mu block count=%d is not divisible by pack width=%d", len(muHeads), packWidth)
	}
	if len(muHeads) == 0 {
		return nil, nil
	}
	ncols := len(muHeads[0])
	out := make([][]uint64, len(muHeads)/packWidth)
	for row := range out {
		head := make([]uint64, ncols)
		for col := 0; col < ncols; col++ {
			vals := make([]int64, packWidth)
			for lane := 0; lane < packWidth; lane++ {
				block := row*packWidth + lane
				if len(muHeads[block]) != ncols {
					return nil, fmt.Errorf("mu block %d width=%d want %d", block, len(muHeads[block]), ncols)
				}
				vals[lane] = centeredLift(muHeads[block][col], q)
			}
			code, err := encodePackedMuCarrier(vals, bound)
			if err != nil {
				return nil, fmt.Errorf("encode packed carrier Mu row=%d col=%d: %w", row, col, err)
			}
			head[col] = liftToField(q, int64(code))
		}
		out[row] = head
	}
	return out, nil
}
