package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type postSignNonSigFamily struct {
	Label          string
	Blocks         int
	ComponentCount int
	Block0Base     int
	ExtraNTTBase   int
	CoeffBase      int
}

type nonSigBridgeFamily struct {
	Label          string
	Blocks         int
	ComponentCount int
	Block0Base     int
	ExtraNTTBase   int
	CoeffBase      int
}

func collectNonSigBoundRows(families []nonSigBridgeFamily) []int {
	if len(families) == 0 {
		return nil
	}
	out := make([]int, 0)
	for _, fam := range families {
		for b := 0; b < fam.Blocks; b++ {
			base := fam.CoeffBase + b*fam.ComponentCount
			for j := 0; j < fam.ComponentCount; j++ {
				out = append(out, base+j)
			}
		}
	}
	return out
}

func postSignNonSigFamilies(layout RowLayout) []nonSigBridgeFamily {
	blocks := layout.NonSigBlocks
	if blocks <= 0 {
		return nil
	}
	families := make([]nonSigBridgeFamily, 0, 3)
	if layout.MsgCompCount > 0 && layout.MsgCoeffBase >= 0 {
		families = append(families, nonSigBridgeFamily{
			Label:          "PostSignMsgBridge",
			Blocks:         blocks,
			ComponentCount: layout.MsgCompCount,
			Block0Base:     rowLayoutPostSignM1(layout),
			ExtraNTTBase:   layout.MsgExtraNTTBase,
			CoeffBase:      layout.MsgCoeffBase,
		})
	}
	if layout.RndCompCount > 0 && layout.RndCoeffBase >= 0 {
		families = append(families, nonSigBridgeFamily{
			Label:          "PostSignRndBridge",
			Blocks:         blocks,
			ComponentCount: layout.RndCompCount,
			Block0Base:     rowLayoutPostSignR0(layout),
			ExtraNTTBase:   layout.RndExtraNTTBase,
			CoeffBase:      layout.RndCoeffBase,
		})
	}
	if layout.X1CompCount > 0 && layout.X1CoeffBase >= 0 {
		families = append(families, nonSigBridgeFamily{
			Label:          "PostSignX1Bridge",
			Blocks:         blocks,
			ComponentCount: layout.X1CompCount,
			Block0Base:     rowLayoutPostSignR(layout),
			ExtraNTTBase:   layout.X1ExtraNTTBase,
			CoeffBase:      layout.X1CoeffBase,
		})
	}
	return families
}

func hasPostSignNonSigFamilies(layout RowLayout) bool {
	return len(postSignNonSigFamilies(layout)) > 0
}

func postSignBoundRowIndices(layout RowLayout) []int {
	if rowLayoutHasCoeffNativeSig(layout) {
		if rowLayoutCoeffNativeUsesCompressedNonSigScalars(layout) {
			return uniqueNonNegativeIndices([]int{
				rowLayoutCoeffNativePostSignMsgSumIndex(layout),
				rowLayoutCoeffNativePostSignRndSumIndex(layout),
				rowLayoutCoeffNativePostSignX1Index(layout),
			})
		}
		rows := make([]int, 0, layout.CoeffNativeSig.UCount+layout.CoeffNativeSig.X0Count+1)
		for i := 0; i < layout.CoeffNativeSig.UCount; i++ {
			rows = append(rows, rowLayoutCoeffNativeUIndex(layout, i))
		}
		for i := 0; i < layout.CoeffNativeSig.X0Count; i++ {
			rows = append(rows, rowLayoutCoeffNativeX0Index(layout, i))
		}
		rows = append(rows, rowLayoutCoeffNativeX1Index(layout))
		return uniqueNonNegativeIndices(rows)
	}
	// BoundB is enforced on the inner post-sign fixture rows:
	//   M1,M2,R0,R1
	// Signature shortness is enforced separately on the packed signature rows.
	return rowLayoutPostSignBoundRows(layout)
}

func preSignNonSigFamilies(layout RowLayout) []nonSigBridgeFamily {
	blocks := layout.NonSigBlocks
	if blocks <= 0 {
		return nil
	}
	families := make([]nonSigBridgeFamily, 0, 3)
	if layout.MsgCompCount > 0 && layout.MsgCoeffBase >= 0 {
		families = append(families, nonSigBridgeFamily{
			Label:          "PreSignMsgBridge",
			Blocks:         blocks,
			ComponentCount: layout.MsgCompCount,
			Block0Base:     rowLayoutPostSignM1(layout),
			ExtraNTTBase:   layout.MsgExtraNTTBase,
			CoeffBase:      layout.MsgCoeffBase,
		})
	}
	if layout.RndCompCount > 0 && layout.RndCoeffBase >= 0 {
		families = append(families, nonSigBridgeFamily{
			Label:          "PreSignRndBridge",
			Blocks:         blocks,
			ComponentCount: layout.RndCompCount,
			Block0Base:     rowLayoutPreSignRU0(layout),
			ExtraNTTBase:   layout.RndExtraNTTBase,
			CoeffBase:      layout.RndCoeffBase,
		})
	}
	if layout.X1CompCount > 0 && layout.X1CoeffBase >= 0 {
		families = append(families, nonSigBridgeFamily{
			Label:          "PreSignCarryBridge",
			Blocks:         blocks,
			ComponentCount: layout.X1CompCount,
			Block0Base:     rowLayoutPreSignK0(layout),
			ExtraNTTBase:   layout.X1ExtraNTTBase,
			CoeffBase:      layout.X1CoeffBase,
		})
	}
	return families
}

func hasPreSignNonSigFamilies(layout RowLayout) bool {
	return len(preSignNonSigFamilies(layout)) > 0
}

func preSignBoundRowIndices(layout RowLayout) []int {
	// BoundB is enforced on the inner pre-sign fixture rows:
	//   M1,M2,RU0,RU1,R,R0,R1
	return rowLayoutPreSignBoundRows(layout)
}

func preSignCarryRowIndices(layout RowLayout) []int {
	// Carry rows (K0,K1) remain bounded separately in pre-sign.
	return rowLayoutPreSignCarryRows(layout)
}

func buildNonSigBridgeConstraintsFormal(
	ringQ *ring.Ring,
	rowsNTT []*ring.Poly,
	omega []uint64,
	families []nonSigBridgeFamily,
	root [16]byte,
	checks int,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(families) == 0 {
		return nil, nil, nil
	}
	bridgeRows := make([]*ring.Poly, 0)
	bridgeCoeffs := make([][]uint64, 0)
	for _, fam := range families {
		if fam.Blocks <= 0 || fam.ComponentCount <= 0 {
			continue
		}
		if fam.Blocks > 1 && fam.ExtraNTTBase < 0 {
			return nil, nil, fmt.Errorf("%s missing extra NTT base", fam.Label)
		}
		if fam.CoeffBase < 0 {
			return nil, nil, fmt.Errorf("%s missing coefficient base", fam.Label)
		}
		nttRows := make([][]*ring.Poly, fam.ComponentCount)
		coefRows := make([][]*ring.Poly, fam.ComponentCount)
		for j := 0; j < fam.ComponentCount; j++ {
			nttRows[j] = make([]*ring.Poly, fam.Blocks)
			coefRows[j] = make([]*ring.Poly, fam.Blocks)
			for b := 0; b < fam.Blocks; b++ {
				nIdx := fam.Block0Base + j
				if b > 0 {
					nIdx = fam.ExtraNTTBase + (b-1)*fam.ComponentCount + j
				}
				cIdx := fam.CoeffBase + b*fam.ComponentCount + j
				if nIdx < 0 || nIdx >= len(rowsNTT) {
					return nil, nil, fmt.Errorf("%s NTT row idx %d out of range (rows=%d)", fam.Label, nIdx, len(rowsNTT))
				}
				if cIdx < 0 || cIdx >= len(rowsNTT) {
					return nil, nil, fmt.Errorf("%s coeff row idx %d out of range (rows=%d)", fam.Label, cIdx, len(rowsNTT))
				}
				nttRows[j][b] = rowsNTT[nIdx]
				coefRows[j][b] = rowsNTT[cIdx]
			}
		}
		rows, coeffs, err := buildRowSetNTTCoeffBridgeConstraintsFormal(
			ringQ,
			omega,
			root,
			checks,
			nttRows,
			coefRows,
			fam.Label,
		)
		if err != nil {
			return nil, nil, err
		}
		bridgeRows = append(bridgeRows, rows...)
		bridgeCoeffs = append(bridgeCoeffs, coeffs...)
	}
	return bridgeRows, bridgeCoeffs, nil
}

func buildPostSignNonSigBridgeConstraintsFormal(
	ringQ *ring.Ring,
	rowsNTT []*ring.Poly,
	omega []uint64,
	layout RowLayout,
	root [16]byte,
	checks int,
) ([]*ring.Poly, [][]uint64, error) {
	return buildNonSigBridgeConstraintsFormal(ringQ, rowsNTT, omega, postSignNonSigFamilies(layout), root, checks)
}

func buildPreSignNonSigBridgeConstraintsFormal(
	ringQ *ring.Ring,
	rowsNTT []*ring.Poly,
	omega []uint64,
	layout RowLayout,
	root [16]byte,
	checks int,
) ([]*ring.Poly, [][]uint64, error) {
	return buildNonSigBridgeConstraintsFormal(ringQ, rowsNTT, omega, preSignNonSigFamilies(layout), root, checks)
}
