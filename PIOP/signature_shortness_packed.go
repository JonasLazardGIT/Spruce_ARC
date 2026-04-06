package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildSigShortnessPackedMembershipFormalCoeffs(
	ringQ *ring.Ring,
	packedSourceRows []*ring.Poly,
	packedRows [][]*ring.Poly,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(packedRows) == 0 {
		return nil, nil, fmt.Errorf("empty packed signature shortness rows")
	}
	if len(packedSourceRows) > 0 && len(packedRows) != len(packedSourceRows) {
		return nil, nil, fmt.Errorf("packed row groups=%d want %d", len(packedRows), len(packedSourceRows))
	}
	groupCount := len(packedRows)
	cd := ChainDecomp{D: make([][]*ring.Poly, groupCount)}
	if spec.UsesAbsRow {
		cd.M = make([]*ring.Poly, groupCount)
	}
	for g := 0; g < groupCount; g++ {
		rows := packedRows[g]
		if spec.UsesAbsRow {
			if len(rows) != spec.L+1 {
				return nil, nil, fmt.Errorf("packed shortness rows/group=%d want %d", len(rows), spec.L+1)
			}
			cd.M[g] = rows[0]
			cd.D[g] = rows[1:]
		} else {
			if len(rows) != spec.L {
				return nil, nil, fmt.Errorf("packed shortness rows/group=%d want %d", len(rows), spec.L)
			}
			cd.D[g] = rows
		}
	}
	if len(packedSourceRows) == 0 {
		return buildPackedDigitMembershipFormalCoeffs(ringQ, packedRows, spec)
	}
	rows, coeffs := buildFparLinfChainComposeFormalCoeffs(ringQ, packedSourceRows, cd, spec)
	return rows, coeffs, nil
}

func buildPackedDigitMembershipFormalCoeffs(
	ringQ *ring.Ring,
	packedRows [][]*ring.Poly,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	outPolys := make([]*ring.Poly, 0, len(packedRows)*spec.L)
	outCoeffs := make([][]uint64, 0, len(packedRows)*spec.L)
	for g := range packedRows {
		if len(packedRows[g]) != spec.L {
			return nil, nil, fmt.Errorf("packed shortness rows/group=%d want %d", len(packedRows[g]), spec.L)
		}
		for lane := 0; lane < spec.L; lane++ {
			pi := composeFPolyWithRowNTT(ringQ, packedRows[g][lane], spec.PDi[lane])
			coeff, err := coeffFromNTTPoly(ringQ, pi)
			if err != nil {
				return nil, nil, fmt.Errorf("packed digit membership coeffs: %w", err)
			}
			outCoeffs = append(outCoeffs, trimPoly(coeff, ringQ.Modulus[0]))
			outPolys = append(outPolys, pi)
		}
	}
	return outPolys, outCoeffs, nil
}
