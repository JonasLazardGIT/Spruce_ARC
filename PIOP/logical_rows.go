package PIOP

import (
	"fmt"

	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type normalizedLogicalRows struct {
	Rows      []*ring.Poly
	RowInputs []lvcs.RowInput
	Count     int
}

func normalizePreparedCredentialLogicalRows(
	ringQ *ring.Ring,
	pub PublicInputs,
	rows []*ring.Poly,
	rowInputs []lvcs.RowInput,
	layout RowLayout,
	witnessCount int,
	omegaWitness []uint64,
	witnessNCols int,
) (normalizedLogicalRows, error) {
	var out normalizedLogicalRows
	if ringQ == nil {
		return out, fmt.Errorf("nil ring")
	}
	if witnessCount < 0 || witnessCount > len(rows) || witnessCount > len(rowInputs) {
		return out, fmt.Errorf("invalid witness count=%d rows=%d rowInputs=%d", witnessCount, len(rows), len(rowInputs))
	}
	if witnessNCols <= 0 {
		return out, fmt.Errorf("invalid witness ncols=%d", witnessNCols)
	}
	if len(omegaWitness) < witnessNCols {
		return out, fmt.Errorf("omega witness len=%d < witness ncols=%d", len(omegaWitness), witnessNCols)
	}
	omega := omegaWitness[:witnessNCols]
	q := ringQ.Modulus[0]
	thetaRows := 0
	if pub.IntGenISIS && layout.IntGenISISPreSign != nil {
		thetaRows = layout.IntGenISISPreSign.ThetaRows()
	}
	if pub.IntGenISIS && layout.IntGenISISShowing != nil {
		thetaRows = layout.IntGenISISShowing.CoreRowCount
	}
	if thetaRows < 0 {
		thetaRows = 0
	}
	if thetaRows > witnessCount {
		return out, fmt.Errorf("theta rows=%d exceed witness count=%d", thetaRows, witnessCount)
	}

	out.Rows = make([]*ring.Poly, witnessCount)
	out.RowInputs = make([]lvcs.RowInput, witnessCount)
	out.Count = witnessCount
	for i := 0; i < witnessCount; i++ {
		if rows[i] == nil {
			return out, fmt.Errorf("nil logical row %d", i)
		}
		p := ringQ.NewPoly()
		ring.Copy(rows[i], p)
		if pub.IntGenISIS && i < thetaRows {
			ntt := ringQ.NewPoly()
			ring.Copy(rows[i], ntt)
			ringQ.NTT(ntt, ntt)
			theta, err := thetaPolyFromNTT(ringQ, ntt, omega)
			if err != nil {
				return out, fmt.Errorf("row %d IntGenISIS theta: %w", i, err)
			}
			p = ringQ.NewPoly()
			ringQ.InvNTT(theta, p)
		}
		head, err := rowHeadOnOmega(ringQ, omega, p, witnessNCols)
		if err != nil {
			return out, fmt.Errorf("logical row %d head: %w", i, err)
		}
		if !(pub.IntGenISIS && i < thetaRows) && len(rowInputs[i].Head) > 0 {
			if len(rowInputs[i].Head) != len(head) {
				return out, fmt.Errorf("logical row %d head width=%d want %d", i, len(rowInputs[i].Head), len(head))
			}
			for j := range head {
				if rowInputs[i].Head[j]%q != head[j]%q {
					return out, fmt.Errorf("logical row %d head[%d] mismatch got=%d want=%d", i, j, rowInputs[i].Head[j]%q, head[j]%q)
				}
			}
		}
		out.Rows[i] = p
		out.RowInputs[i] = lvcs.RowInput{
			Head:       head,
			Poly:       p,
			PolyCoeffs: trimCoeffsCopy(p.Coeffs[0], q),
		}
	}
	return out, nil
}
