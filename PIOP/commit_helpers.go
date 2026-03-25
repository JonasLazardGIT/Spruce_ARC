package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildRowInputs constructs LVCS row heads from row polynomials by evaluating
// them on Ω (NTT form) and truncating to ncols.
func buildRowInputs(ringQ *ring.Ring, rows []*ring.Poly, ncols int) []lvcs.RowInput {
	rowInputs := make([]lvcs.RowInput, len(rows))
	tmp := ringQ.NewPoly()
	for i := range rows {
		ringQ.NTT(rows[i], tmp)
		head := tmp.Coeffs[0]
		if ncols < len(head) {
			head = head[:ncols]
		}
		headCopy := append([]uint64(nil), head...)
		rowInputs[i] = lvcs.RowInput{Head: headCopy}
	}
	return rowInputs
}

func rowOracleDegreeFloor(ringQ *ring.Ring, rows []lvcs.RowInput, ell int) int {
	if ringQ == nil || len(rows) == 0 {
		return 0
	}
	if ell < 0 {
		ell = 0
	}
	q := ringQ.Modulus[0]
	maxDeg := 0
	for _, row := range rows {
		deg := 0
		switch {
		case len(row.PolyCoeffs) > 0:
			deg = maxDegreeFromCoeffs(row.PolyCoeffs)
		case row.Poly != nil:
			deg = maxDegreeFromCoeffs(trimCoeffsCopy(row.Poly.Coeffs[0], q))
		default:
			if len(row.Head) > 0 {
				deg = len(row.Head) + ell - 1
			}
		}
		if deg > maxDeg {
			maxDeg = deg
		}
	}
	return maxDeg
}

// commitRows wraps LVCS.CommitInitWithParamsAndPoints and assigns the witness
// and mask layout for a retained proof slice.
func commitRows(ringQ *ring.Ring, rows []lvcs.RowInput, ell int, decsParams decs.Params, witnessCount, maskOffset, maskCount int, points []uint64) (root [16]byte, pk *lvcs.ProverKey, oracleLayout lvcs.OracleLayout, err error) {
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	if len(rows) == 0 {
		err = fmt.Errorf("no rows to commit")
		return
	}
	root, pk, err = lvcs.CommitInitWithParamsAndPoints(ringQ, rows, ell, decsParams, points)
	if err != nil {
		return
	}
	oracleLayout.Witness = lvcs.LayoutSegment{Offset: 0, Count: witnessCount}
	oracleLayout.Mask = lvcs.LayoutSegment{Offset: maskOffset, Count: maskCount}
	if err = pk.SetLayout(oracleLayout); err != nil {
		return
	}
	return
}
