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
	if len(packedSourceRows) == 0 {
		return nil, nil, fmt.Errorf("empty packed signature source rows")
	}
	if len(packedRows) != len(packedSourceRows) {
		return nil, nil, fmt.Errorf("packed row groups=%d want %d", len(packedRows), len(packedSourceRows))
	}
	cd := ChainDecomp{D: make([][]*ring.Poly, len(packedSourceRows))}
	if spec.UsesAbsRow {
		cd.M = make([]*ring.Poly, len(packedSourceRows))
	}
	for g := range packedSourceRows {
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
	rows, coeffs := buildFparLinfChainComposeFormalCoeffs(ringQ, packedSourceRows, cd, spec)
	return rows, coeffs, nil
}
