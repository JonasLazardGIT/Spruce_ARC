package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildIntGenISISPreSign builds the committed-message pre-sign proof surface.
// The witness rows are exactly M, s, and e; the only algebraic residual in this
// first IntGenISIS relation is C_M M + A_s s + e - c.
func BuildIntGenISISPreSign(ringQ *ring.Ring, pub PublicInputs, wit WitnessInputs, opts SimOpts) (*Proof, error) {
	opts.applyDefaults()
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	pub.IntGenISIS = true
	if err := validateIntGenISISPreSignInputs(pub, wit); err != nil {
		return nil, err
	}
	witnessRows := append([]*ring.Poly{}, wit.M...)
	witnessRows = append(witnessRows, wit.S...)
	witnessRows = append(witnessRows, wit.E...)
	rowsNTT := make([]*ring.Poly, len(witnessRows))
	for i := range witnessRows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(witnessRows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	matrix, err := buildIntGenISISCommitmentMatrix(ringQ, pub.CM, pub.AS)
	if err != nil {
		return nil, err
	}
	residuals, err := BuildCommitConstraints(ringQ, matrix, rowsNTT, pub.Com)
	if err != nil {
		return nil, err
	}
	set := ConstraintSet{
		FparInt:          residuals,
		ParallelAlgDeg:   1,
		AggregatedAlgDeg: 1,
	}
	ncols := opts.NCols
	if ncols <= 0 {
		ncols = int(ringQ.N)
	}
	lvcsNCols := opts.LVCSNCols
	if lvcsNCols <= 0 {
		lvcsNCols = ncols
	}
	// The prepared IntGenISIS pre-sign surface commits exactly the witness
	// rows over their packing width. Keeping the PCS prefix equal to ncols
	// avoids mixing a wider legacy LVCS prefix into the row-opening transcript.
	lvcsNCols = ncols
	var omega []uint64
	var omegaWitness []uint64
	var domainPoints []uint64
	if opts.DomainMode == DomainModeExplicit {
		nLeaves := opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		if lvcsNCols+opts.Ell > int(ringQ.N) {
			return nil, fmt.Errorf("explicit domain: need lvcs_ncols+ell <= ring dimension (lvcs_ncols=%d ell=%d ringN=%d)", lvcsNCols, opts.Ell, ringQ.N)
		}
		var derr error
		omega, domainPoints, derr = deriveExplicitDomainForRelation(ringQ.Modulus[0], nLeaves, ncols, lvcsNCols, opts.Ell, pub.HashRelation)
		if derr != nil {
			return nil, fmt.Errorf("derive explicit domain: %w", derr)
		}
		omegaWitness, derr = deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, ncols, lvcsNCols, opts.Ell, pub.HashRelation)
		if derr != nil {
			return nil, fmt.Errorf("derive witness omega: %w", derr)
		}
	} else {
		var derr error
		omegaWitness, derr = ringDomainSlots(ringQ)
		if derr != nil {
			return nil, derr
		}
		if len(omegaWitness) > ncols {
			omegaWitness = omegaWitness[:ncols]
		}
	}
	rho := opts.Rho
	if rho <= 0 {
		rho = 1
	}
	rows := append([]*ring.Poly{}, witnessRows...)
	for i := 0; i < rho; i++ {
		rows = append(rows, ringQ.NewPoly())
	}
	actualRowInputs := make([]lvcs.RowInput, len(rows))
	for i := range rows {
		head, herr := rowHeadOnOmega(ringQ, omegaWitness, rows[i], ncols)
		if herr != nil {
			return nil, fmt.Errorf("row %d head: %w", i, herr)
		}
		actualRowInputs[i] = lvcs.RowInput{Head: head}
	}
	layout := RowLayout{
		RingDegree: int(ringQ.N),
		SigCount:   len(witnessRows),
		X0Len:      2,
		IntGenISISPreSign: &IntGenISISPreSignRowLayout{
			MStart:         0,
			MCount:         len(wit.M),
			SStart:         len(wit.M),
			SCount:         len(wit.S),
			EStart:         len(wit.M) + len(wit.S),
			ECount:         len(wit.E),
			CommitmentRows: len(pub.Com),
		},
	}
	prepared := &preparedCredentialBuild{
		rows:          rows,
		rowInputs:     actualRowInputs,
		rowLayout:     layout,
		decsParams:    decs.Params{},
		maskRowOffset: len(witnessRows),
		maskRowCount:  rho,
		witnessCount:  len(witnessRows),
		witnessNCols:  ncols,
		omega:         omega,
		omegaWitness:  omegaWitness,
		domainPoints:  domainPoints,
	}
	opts.Credential = true
	return buildWithConstraintsPrepared(pub, wit, set, opts, FSModeCredential, prepared)
}

func VerifyIntGenISISPreSign(pub PublicInputs, proof *Proof, opts SimOpts) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("nil proof")
	}
	pub.IntGenISIS = true
	opts.applyDefaults()
	opts.Credential = true
	set := ConstraintSet{}
	return VerifyWithConstraints(proof, set, pub, opts, FSModeCredential)
}

func validateIntGenISISPreSignInputs(pub PublicInputs, wit WitnessInputs) error {
	if len(pub.Com) == 0 {
		return fmt.Errorf("missing commitment c")
	}
	if len(pub.CM) == 0 {
		return fmt.Errorf("missing C_M")
	}
	if len(pub.AS) == 0 {
		return fmt.Errorf("missing A_s")
	}
	if len(wit.M) == 0 {
		return fmt.Errorf("missing M witness")
	}
	if len(wit.S) == 0 {
		return fmt.Errorf("missing s witness")
	}
	if len(wit.E) == 0 {
		return fmt.Errorf("missing e witness")
	}
	if len(pub.CM) != len(pub.Com) || len(pub.AS) != len(pub.Com) || len(wit.E) != len(pub.Com) {
		return fmt.Errorf("commitment dimension mismatch")
	}
	return nil
}

func buildIntGenISISCommitmentMatrix(ringQ *ring.Ring, cm, as [][]*ring.Poly) ([][]*ring.Poly, error) {
	if len(cm) == 0 || len(as) == 0 || len(cm) != len(as) {
		return nil, fmt.Errorf("invalid C_M/A_s dimensions")
	}
	rows := len(cm)
	out := make([][]*ring.Poly, rows)
	for i := 0; i < rows; i++ {
		if len(cm[i]) == 0 || len(as[i]) == 0 {
			return nil, fmt.Errorf("empty C_M/A_s row %d", i)
		}
		out[i] = make([]*ring.Poly, 0, len(cm[i])+len(as[i])+rows)
		out[i] = append(out[i], cm[i]...)
		out[i] = append(out[i], as[i]...)
		for j := 0; j < rows; j++ {
			id := ringQ.NewPoly()
			if i == j {
				id.Coeffs[0][0] = 1 % ringQ.Modulus[0]
				ringQ.NTT(id, id)
			}
			out[i] = append(out[i], id)
		}
	}
	return out, nil
}

func buildIntGenISISPreSignConstraintSetFromRows(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	l := layout.IntGenISISPreSign
	if l == nil {
		return ConstraintSet{}, fmt.Errorf("missing IntGenISIS pre-sign layout")
	}
	if l.WitnessRows() > len(rowsNTT) {
		return ConstraintSet{}, fmt.Errorf("rows=%d want at least %d", len(rowsNTT), l.WitnessRows())
	}
	q := ringQ.Modulus[0]
	rowCoeff := func(idx int) ([]uint64, error) {
		if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
			return nil, fmt.Errorf("invalid row index %d", idx)
		}
		tmp := ringQ.NewPoly()
		ringQ.InvNTT(rowsNTT[idx], tmp)
		return trimCoeffsCopy(tmp.Coeffs[0], q), nil
	}
	thetaCoeff := func(p *ring.Poly, name string) ([]uint64, error) {
		theta, err := thetaPolyFromNTT(ringQ, p, omega)
		if err != nil {
			return nil, fmt.Errorf("theta %s: %w", name, err)
		}
		coeff, err := coeffFromNTTPoly(ringQ, theta)
		if err != nil {
			return nil, fmt.Errorf("theta %s coeffs: %w", name, err)
		}
		return trimPoly(coeff, q), nil
	}
	residualCoeffs := make([][]uint64, l.CommitmentRows)
	for out := 0; out < l.CommitmentRows; out++ {
		comCoeff, err := thetaCoeff(pub.Com[out], fmt.Sprintf("Com[%d]", out))
		if err != nil {
			return ConstraintSet{}, err
		}
		res := polySub([]uint64{0}, comCoeff, q)
		for j := 0; j < l.MCount; j++ {
			aCoeff, err := thetaCoeff(pub.CM[out][j], fmt.Sprintf("C_M[%d][%d]", out, j))
			if err != nil {
				return ConstraintSet{}, err
			}
			rCoeff, err := rowCoeff(l.MStart + j)
			if err != nil {
				return ConstraintSet{}, err
			}
			res = polyAdd(res, polyMul(aCoeff, rCoeff, q), q)
		}
		for j := 0; j < l.SCount; j++ {
			aCoeff, err := thetaCoeff(pub.AS[out][j], fmt.Sprintf("A_s[%d][%d]", out, j))
			if err != nil {
				return ConstraintSet{}, err
			}
			rCoeff, err := rowCoeff(l.SStart + j)
			if err != nil {
				return ConstraintSet{}, err
			}
			res = polyAdd(res, polyMul(aCoeff, rCoeff, q), q)
		}
		eCoeff, err := rowCoeff(l.EStart + out)
		if err != nil {
			return ConstraintSet{}, err
		}
		res = polyAdd(res, eCoeff, q)
		residualCoeffs[out] = trimPoly(res, q)
	}
	fpar := make([]*ring.Poly, len(residualCoeffs))
	for i := range residualCoeffs {
		if len(residualCoeffs[i]) <= int(ringQ.N) {
			fpar[i] = nttPolyFromFormalCoeffsIfFits(ringQ, residualCoeffs[i])
		}
	}
	return ConstraintSet{
		FparInt:          fpar,
		FparIntCoeffs:    residualCoeffs,
		ParallelAlgDeg:   1,
		AggregatedAlgDeg: 1,
	}, nil
}

func zeroFormalRows(n int) [][]uint64 {
	out := make([][]uint64, n)
	for i := range out {
		out[i] = []uint64{0}
	}
	return out
}
