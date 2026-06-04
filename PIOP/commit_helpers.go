package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildRowInputs constructs LVCS row heads from row polynomials by evaluating
// them on the implicit NTT domain and truncating to ncols.
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

// buildRowInputsExplicit constructs LVCS row heads by evaluating the row
// polynomials on the explicit Ω domain.
func buildRowInputsExplicit(ringQ *ring.Ring, rows []*ring.Poly, omega []uint64, ncols int) ([]lvcs.RowInput, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty rows")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if ncols <= 0 {
		return nil, fmt.Errorf("invalid ncols=%d", ncols)
	}
	if len(omega) < ncols {
		return nil, fmt.Errorf("omega len=%d < ncols=%d", len(omega), ncols)
	}
	rowInputs := make([]lvcs.RowInput, len(rows))
	for i, row := range rows {
		head, err := rowHeadOnOmega(ringQ, omega, row, ncols)
		if err != nil {
			return nil, fmt.Errorf("row %d head on omega: %w", i, err)
		}
		rowInputs[i] = lvcs.RowInput{Head: head}
	}
	return rowInputs, nil
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

func requiredExplicitPCSNColsForRows(ringQ *ring.Ring, rows []lvcs.RowInput, ell int) int {
	if ringQ == nil || len(rows) == 0 {
		return 0
	}
	maxDeg := rowOracleDegreeFloor(ringQ, rows, ell)
	required := maxDeg - ell + 1
	if required < 1 {
		required = 1
	}
	return required
}

// commitRows wraps LVCS.CommitInitWithParamsAndPoints and assigns the witness
// and mask layout for a retained proof slice.
func commitRows(ringQ *ring.Ring, rows []lvcs.RowInput, ell int, decsParams decs.Params, witnessCount, maskOffset, maskCount int, points []uint64, phase decs.CommitPhaseRecorder) (root [16]byte, pk *lvcs.ProverKey, oracleLayout lvcs.OracleLayout, err error) {
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	if len(rows) == 0 {
		err = fmt.Errorf("no rows to commit")
		return
	}
	root, pk, err = lvcs.CommitInitWithParamsAndPointsWithOptions(ringQ, rows, ell, decsParams, points, lvcs.CommitOptions{
		PhaseRecorder:      phase,
		DecsFormalEvalMode: decs.FormalEvalCombined,
	})
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
