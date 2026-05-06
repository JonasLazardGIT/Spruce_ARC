package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildIntGenISISPreSign builds the committed-message pre-sign proof surface.
// The witness rows are M, m, k, s, and e. The algebraic residuals enforce the
// commitment equation plus the deterministic semantic binding M=m||k.
func BuildIntGenISISPreSign(ringQ *ring.Ring, pub PublicInputs, wit WitnessInputs, opts SimOpts) (*Proof, error) {
	opts.applyDefaults()
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	pub.IntGenISIS = true
	var err error
	pub, err = bindIntGenISISPublicExtras(pub, int(ringQ.N))
	if err != nil {
		return nil, err
	}
	if err := validateIntGenISISPreSignInputs(ringQ, pub, wit); err != nil {
		return nil, err
	}
	x0Len, err := intGenISISX0LenFromPublic(pub)
	if err != nil {
		return nil, err
	}
	witnessRows := append([]*ring.Poly{}, wit.M...)
	witnessRows = append(witnessRows, wit.MAttr...)
	witnessRows = append(witnessRows, wit.K...)
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
	commitRowsNTT := make([]*ring.Poly, 0, len(wit.M)+len(wit.S)+len(wit.E))
	commitRowsNTT = append(commitRowsNTT, rowsNTT[:len(wit.M)]...)
	sStartForCommit := len(wit.M) + len(wit.MAttr) + len(wit.K)
	commitRowsNTT = append(commitRowsNTT, rowsNTT[sStartForCommit:sStartForCommit+len(wit.S)]...)
	commitRowsNTT = append(commitRowsNTT, rowsNTT[sStartForCommit+len(wit.S):sStartForCommit+len(wit.S)+len(wit.E)]...)
	residuals, err := BuildCommitConstraints(ringQ, matrix, commitRowsNTT, pub.Com)
	if err != nil {
		return nil, err
	}
	binding, err := intGenISISMessageBindingResiduals(ringQ, wit.M, wit.MAttr, wit.K)
	if err != nil {
		return nil, err
	}
	residuals = append(residuals, binding...)
	set := ConstraintSet{
		FparInt:          residuals,
		ParallelAlgDeg:   intGenISISMembershipDegree(pub.BoundB),
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
	viewRowsPerPoly := int(ringQ.N) / ncols
	mViewStart := len(rows)
	mViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, wit.M, ncols)
	if err != nil {
		return nil, fmt.Errorf("M coefficient views: %w", err)
	}
	rows = append(rows, mViewRows...)
	mAttrViewStart := len(rows)
	mAttrViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, wit.MAttr, ncols)
	if err != nil {
		return nil, fmt.Errorf("m coefficient views: %w", err)
	}
	rows = append(rows, mAttrViewRows...)
	kViewStart := len(rows)
	kViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, wit.K, ncols)
	if err != nil {
		return nil, fmt.Errorf("k coefficient views: %w", err)
	}
	rows = append(rows, kViewRows...)
	sViewStart := len(rows)
	sViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, wit.S, ncols)
	if err != nil {
		return nil, fmt.Errorf("s coefficient views: %w", err)
	}
	rows = append(rows, sViewRows...)
	eViewStart := len(rows)
	eViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, wit.E, ncols)
	if err != nil {
		return nil, fmt.Errorf("e coefficient views: %w", err)
	}
	rows = append(rows, eViewRows...)
	boundViewStart := mViewStart
	boundViewCount := len(rows) - boundViewStart
	coreRowCount := len(witnessRows)
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
		SigCount:   len(rows) - rho,
		X0Len:      x0Len,
		IntGenISISPreSign: &IntGenISISPreSignRowLayout{
			MStart:          0,
			MCount:          len(wit.M),
			MAttrStart:      len(wit.M),
			MAttrCount:      len(wit.MAttr),
			KStart:          len(wit.M) + len(wit.MAttr),
			KCount:          len(wit.K),
			SStart:          len(wit.M) + len(wit.MAttr) + len(wit.K),
			SCount:          len(wit.S),
			EStart:          len(wit.M) + len(wit.MAttr) + len(wit.K) + len(wit.S),
			ECount:          len(wit.E),
			CoreRowCount:    coreRowCount,
			BoundViewStart:  boundViewStart,
			BoundViewCount:  boundViewCount,
			MViewStart:      mViewStart,
			MAttrViewStart:  mAttrViewStart,
			KViewStart:      kViewStart,
			SViewStart:      sViewStart,
			EViewStart:      eViewStart,
			ViewRowsPerPoly: viewRowsPerPoly,
			CommitmentRows:  len(pub.Com),
		},
	}
	prepared := &preparedCredentialBuild{
		rows:          rows,
		rowInputs:     actualRowInputs,
		rowLayout:     layout,
		decsParams:    decs.Params{},
		maskRowOffset: len(rows) - rho,
		maskRowCount:  rho,
		witnessCount:  len(rows) - rho,
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
	var err error
	ringN := pub.RingDegree
	if ringN == 0 && proof.RowLayout.RingDegree > 0 {
		ringN = proof.RowLayout.RingDegree
	}
	pub, err = bindIntGenISISPublicExtras(pub, ringN)
	if err != nil {
		return false, err
	}
	opts.applyDefaults()
	if err := validateIntGenISISProofDegreeMetadata(proof, pub, opts); err != nil {
		return false, err
	}
	opts.Credential = true
	set := ConstraintSet{}
	return VerifyWithConstraints(proof, set, pub, opts, FSModeCredential)
}

func validateIntGenISISPreSignInputs(ringQ *ring.Ring, pub PublicInputs, wit WitnessInputs) error {
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
	if len(wit.MAttr) == 0 {
		return fmt.Errorf("missing m witness")
	}
	if len(wit.K) == 0 {
		return fmt.Errorf("missing k witness")
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
	if len(wit.MAttr) != len(wit.M) || len(wit.K) != len(wit.M) {
		return fmt.Errorf("semantic dimension mismatch M=%d m=%d k=%d", len(wit.M), len(wit.MAttr), len(wit.K))
	}
	if err := validateIntGenISISSemanticPolys(ringQ, pub.BoundB, wit.M, wit.MAttr, wit.K); err != nil {
		return fmt.Errorf("semantic message: %w", err)
	}
	if err := validateIntGenISISPolicyPolys(ringQ, pub, wit.M, wit.MAttr, wit.K); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if err := validateIntGenISISLiveBoundPolys(ringQ, pub.BoundB, "s", wit.S); err != nil {
		return err
	}
	if err := validateIntGenISISLiveBoundPolys(ringQ, pub.BoundB, "e", wit.E); err != nil {
		return err
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
	residualCoeffs := make([][]uint64, 0, l.CommitmentRows+l.MCount)
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
		residualCoeffs = append(residualCoeffs, trimPoly(res, q))
	}
	for i := 0; i < l.MCount; i++ {
		mCoeff, err := rowCoeff(l.MStart + i)
		if err != nil {
			return ConstraintSet{}, err
		}
		mAttrCoeff, err := rowCoeff(l.MAttrStart + i)
		if err != nil {
			return ConstraintSet{}, err
		}
		kCoeff, err := rowCoeff(l.KStart + i)
		if err != nil {
			return ConstraintSet{}, err
		}
		res := polySub(polySub(mCoeff, mAttrCoeff, q), kCoeff, q)
		residualCoeffs = append(residualCoeffs, trimPoly(res, q))
	}
	policy, err := intGenISISPolicyFromPublic(pub)
	if err != nil {
		return ConstraintSet{}, err
	}
	semanticLayout, err := intGenISISSemanticLayout(int(ringQ.N), pub.BoundB)
	if err != nil {
		return ConstraintSet{}, err
	}
	policyRows, err := intGenISISPolicyCoeffViewCoeffs(ringQ, policy, semanticLayout, omega, len(omega))
	if err != nil {
		return ConstraintSet{}, err
	}
	if len(policyRows) > 0 {
		if l.MAttrViewStart <= 0 || l.ViewRowsPerPoly <= 0 {
			return ConstraintSet{}, fmt.Errorf("policy requires m coefficient-view rows")
		}
		if len(policyRows) != l.MAttrCount*l.ViewRowsPerPoly {
			return ConstraintSet{}, fmt.Errorf("policy view rows=%d want %d", len(policyRows), l.MAttrCount*l.ViewRowsPerPoly)
		}
		for i := range policyRows {
			mAttrCoeff, err := rowCoeff(l.MAttrViewStart + i)
			if err != nil {
				return ConstraintSet{}, err
			}
			residualCoeffs = append(residualCoeffs, trimPoly(polySub(mAttrCoeff, policyRows[i], q), q))
		}
	}
	fpar := make([]*ring.Poly, len(residualCoeffs))
	for i := range residualCoeffs {
		if len(residualCoeffs[i]) <= int(ringQ.N) {
			fpar[i] = nttPolyFromFormalCoeffsIfFits(ringQ, residualCoeffs[i])
		}
	}
	boundRows := intGenISISViewRowIndices(l.BoundViewStart, l.BoundViewCount)
	boundPolys, boundCoeffs, err := intGenISISLiveMembershipRows(ringQ, rowsNTT, boundRows, pub.BoundB)
	if err != nil {
		return ConstraintSet{}, err
	}
	policyDegree := intGenISISPolicyDegree(policy)
	membershipDegree := intGenISISMembershipDegree(pub.BoundB)
	return ConstraintSet{
		FparInt:          fpar,
		FparIntCoeffs:    residualCoeffs,
		FparNorm:         boundPolys,
		FparNormCoeffs:   boundCoeffs,
		ParallelAlgDeg:   maxInt(maxInt(1, membershipDegree), policyDegree),
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
