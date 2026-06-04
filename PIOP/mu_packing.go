package PIOP

import "fmt"

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
