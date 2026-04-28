package PIOP

import (
	"fmt"
	"path/filepath"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func (wit *CoeffNativeShowingWitness) ValidateIntGenISIS(ringN int, pub PublicInputs) error {
	if wit == nil {
		return fmt.Errorf("nil IntGenISIS showing witness")
	}
	if len(wit.Sig) == 0 {
		return fmt.Errorf("missing signature preimage rows")
	}
	if wit.M == nil {
		return fmt.Errorf("missing semantic message M row")
	}
	if len(wit.S) == 0 {
		return fmt.Errorf("missing commitment secret s rows")
	}
	if len(wit.E) == 0 {
		return fmt.Errorf("missing commitment error e rows")
	}
	if len(wit.MuSig) != 1 {
		return fmt.Errorf("mu_sig rows=%d want 1", len(wit.MuSig))
	}
	if len(wit.X0) != 2 {
		return fmt.Errorf("x0 rows=%d want 2", len(wit.X0))
	}
	if wit.X1 == nil {
		return fmt.Errorf("missing x1 row")
	}
	if wit.Z == nil {
		return fmt.Errorf("missing Z row")
	}
	if len(pub.A) > 0 && len(pub.A[0]) > 0 && len(wit.Sig) != len(pub.A[0]) {
		return fmt.Errorf("signature preimage rows=%d want %d", len(wit.Sig), len(pub.A[0]))
	}
	if len(pub.CM) > 0 && len(pub.CM[0]) > 0 && len(wit.S) > 0 && len(wit.MuSig) > 0 {
		if len(pub.CM[0]) != 1 {
			return fmt.Errorf("C_M cols=%d want ell_M=1", len(pub.CM[0]))
		}
	}
	check := func(name string, rows []*ring.Poly) error {
		for i, p := range rows {
			if p == nil || len(p.Coeffs) == 0 {
				return fmt.Errorf("nil %s row %d", name, i)
			}
			if ringN > 0 && len(p.Coeffs[0]) != ringN {
				return fmt.Errorf("%s row %d width=%d want ringN=%d", name, i, len(p.Coeffs[0]), ringN)
			}
		}
		return nil
	}
	if err := check("sig", wit.Sig); err != nil {
		return err
	}
	if err := check("M", []*ring.Poly{wit.M}); err != nil {
		return err
	}
	if err := check("s", wit.S); err != nil {
		return err
	}
	if err := check("e", wit.E); err != nil {
		return err
	}
	if err := check("mu_sig", wit.MuSig); err != nil {
		return err
	}
	if err := check("x0", wit.X0); err != nil {
		return err
	}
	if err := check("x1", []*ring.Poly{wit.X1}); err != nil {
		return err
	}
	if err := check("Z", []*ring.Poly{wit.Z}); err != nil {
		return err
	}
	if wit.PackedNCols <= 0 {
		return fmt.Errorf("invalid packed ncols=%d", wit.PackedNCols)
	}
	return nil
}

func BuildCredentialRowsShowingIntGenISIS(
	ringQ *ring.Ring,
	pub PublicInputs,
	wit WitnessInputs,
	prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds int,
	opts SimOpts,
) (
	rows []*ring.Poly,
	rowInputs []lvcs.RowInput,
	layout RowLayout,
	prfLayout *PRFLayout,
	prfCompanionLayout *PRFCompanionLayout,
	decsParams decs.Params,
	maskRowOffset, maskRowCount, witnessCount, startIdx, ncols int,
	err error,
) {
	if ringQ == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("nil ring")
	}
	if !pub.IntGenISIS {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("IntGenISIS showing rows require IntGenISIS public inputs")
	}
	cn := wit.CoeffNativeShowing
	if err := cn.ValidateIntGenISIS(int(ringQ.N), pub); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	opts.applyDefaults()
	ncols = opts.NCols
	if ncols <= 0 {
		ncols = cn.PackedNCols
	}
	if ncols <= 0 {
		ncols = int(ringQ.N)
	}
	if ncols > int(ringQ.N) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("ncols=%d exceeds ringN=%d", ncols, ringQ.N)
	}
	lvcsNCols := resolvePCSNCols(opts, ncols)
	if lvcsNCols < ncols {
		lvcsNCols = ncols
	}
	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	ell := opts.Ell
	if ell <= 0 {
		ell = 1
	}
	var omegaWitness []uint64
	if opts.DomainMode == DomainModeExplicit {
		omegaWitness, err = deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, ncols, lvcsNCols, ell, pub.HashRelation)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("derive witness omega: %w", err)
		}
	} else {
		omegaWitness, err = ringDomainSlots(ringQ)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		if len(omegaWitness) > ncols {
			omegaWitness = omegaWitness[:ncols]
		}
	}
	q := ringQ.Modulus[0]
	makeRowInput := func(p *ring.Poly) (lvcs.RowInput, error) {
		head, herr := rowHeadOnOmega(ringQ, omegaWitness, p, ncols)
		if herr != nil {
			return lvcs.RowInput{}, herr
		}
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		return lvcs.RowInput{Head: head, Poly: cp}, nil
	}
	makeRowFromHead := func(head []uint64) *ring.Poly {
		pNTT := BuildThetaPrime(ringQ, head, omegaWitness)
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(pNTT, coeff)
		return coeff
	}

	rows = append(rows, cn.Sig...)
	uStart := 0
	mStart := len(rows)
	rows = append(rows, cn.M)
	sStart := len(rows)
	rows = append(rows, cn.S...)
	eStart := len(rows)
	rows = append(rows, cn.E...)
	muSigStart := len(rows)
	rows = append(rows, cn.MuSig...)
	x0Start := len(rows)
	rows = append(rows, cn.X0...)
	x1Start := len(rows)
	rows = append(rows, cn.X1)
	zStart := len(rows)
	rows = append(rows, cn.Z)
	coreRowCount := len(rows)

	rowInputs = make([]lvcs.RowInput, 0, coreRowCount)
	for i := 0; i < coreRowCount; i++ {
		in, ierr := makeRowInput(rows[i])
		if ierr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("row %d input: %w", i, ierr)
		}
		rowInputs = append(rowInputs, in)
	}

	companionMode := normalizePRFCompanionMode(opts.PRFCompanionMode)
	if companionMode != "" {
		if prfGroupRounds <= 0 {
			prfGroupRounds = 1
		}
		key, kerr := ExtractSignedPRFKeyElemsFromMuCoeffs(ringQ, cn.M, ncols, prfParamsLenKey)
		if kerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("extract IntGenISIS PRF key from M: %w", kerr)
		}
		nonceElems := make([]prf.Elem, len(pub.Nonce))
		for i := range pub.Nonce {
			if len(pub.Nonce[i]) == 0 {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("public nonce lane %d is empty", i)
			}
			nonceElems[i] = prf.Elem(liftToField(q, pub.Nonce[i][0]))
		}
		params, perr := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("load prf params: %w", perr)
		}
		groupedWitness, gwerr := prf.TraceGroupedWitness(key, nonceElems, params, prfGroupRounds)
		if gwerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("trace prf witness: %w", gwerr)
		}
		companionStart := len(rows)
		startIdx = companionStart
		packed, perr := packPRFCompanionWitnessRows(ringQ, ncols, companionStart, companionMode, true, key, groupedWitness, makeRowFromHead)
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack prf companion rows: %w", perr)
		}
		rows = append(rows, packed.Rows...)
		for i, p := range packed.Rows {
			in, ierr := makeRowInput(p)
			if ierr != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("prf row %d input: %w", i, ierr)
			}
			rowInputs = append(rowInputs, in)
		}
		rowSemantics := make([]RowSemantics, len(packed.Rows))
		for i := range rowSemantics {
			rowSemantics[i] = CoeffPackedRow
		}
		dataSlots := append([]CoeffSlot(nil), packed.KeySlots...)
		dataSlots = append(dataSlots, packed.CheckpointSlots...)
		dataRows := len(uniqueRowsFromCoeffSlots(dataSlots))
		helperRows := maxInt(len(packed.Rows)-dataRows, 0)
		prfCompanionLayout = &PRFCompanionLayout{
			StartRow:           companionStart,
			PackWidth:          ncols,
			KeySource:          KeySourceIndependentWitness,
			KeySlots:           packed.KeySlots,
			CheckpointSlots:    packed.CheckpointSlots,
			FinalTagSlots:      packed.FinalTagSlots,
			HelperFamilies:     []string{"final_tag_state"},
			ReplayRows:         len(packed.Rows),
			PackedRows:         len(packed.Rows),
			PackedLogicalCount: packed.TotalLogicalScalars,
			HelperRowCount:     helperRows,
			DataRows:           dataRows,
			HelperRows:         helperRows,
			KeyCount:           len(packed.KeySlots),
			CheckpointCount:    len(packed.CheckpointSlots),
			TagCount:           len(pub.Tag),
			RowSemantics:       rowSemantics,
		}
		if companionMode == PRFCompanionModeAuxInstance {
			var aerr error
			rows, aerr = appendPRFBridgeStripeRows(ringQ, rows, prfCompanionLayout, lvcsNCols)
			if aerr != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("append prf bridge stripe rows: %w", aerr)
			}
			for i := len(rowInputs); i < len(rows); i++ {
				in, ierr := makeRowInput(rows[i])
				if ierr != nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("prf bridge row %d input: %w", i, ierr)
				}
				rowInputs = append(rowInputs, in)
			}
		}
	}

	layout = RowLayout{
		RingDegree:         int(ringQ.N),
		SigCount:           len(rows),
		X0Len:              2,
		HasExplicitBaseIdx: true,
		IntGenISISShowing: &IntGenISISShowingRowLayout{
			UStart:       uStart,
			UCount:       len(cn.Sig),
			MStart:       mStart,
			MCount:       1,
			SStart:       sStart,
			SCount:       len(cn.S),
			EStart:       eStart,
			ECount:       len(cn.E),
			MuSigStart:   muSigStart,
			MuSigCount:   len(cn.MuSig),
			X0Start:      x0Start,
			X0Count:      len(cn.X0),
			X1Start:      x1Start,
			X1Count:      1,
			ZStart:       zStart,
			ZCount:       1,
			CoreRowCount: coreRowCount,
		},
	}
	decsParams = decs.Params{Degree: int(ringQ.N) - 1, Eta: opts.Eta, NonceBytes: 16}
	maskRowOffset = len(rows)
	maskRowCount = opts.Rho
	if maskRowCount <= 0 {
		maskRowCount = 1
	}
	witnessCount = len(rows)
	zeroHead := make([]uint64, ncols)
	for i := 0; i < maskRowCount; i++ {
		rows = append(rows, ringQ.NewPoly())
		rowInputs = append(rowInputs, lvcs.RowInput{Head: append([]uint64(nil), zeroHead...)})
	}
	return rows, rowInputs, layout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols, nil
}

func buildIntGenISISShowingConstraintSetFromRows(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return ConstraintSet{}, fmt.Errorf("empty omega")
	}
	if !pub.IntGenISIS {
		return ConstraintSet{}, fmt.Errorf("IntGenISIS showing constraints require IntGenISIS public inputs")
	}
	l := layout.IntGenISISShowing
	if l == nil {
		return ConstraintSet{}, fmt.Errorf("missing IntGenISIS showing layout")
	}
	if len(pub.A) != 1 || len(pub.A[0]) != l.UCount {
		return ConstraintSet{}, fmt.Errorf("A dimensions=%dx? want 1x%d", len(pub.A), l.UCount)
	}
	if len(pub.B) != 3+l.X0Count {
		return ConstraintSet{}, fmt.Errorf("B length=%d want %d", len(pub.B), 3+l.X0Count)
	}
	if len(pub.CM) != l.ECount || len(pub.AS) != l.ECount {
		return ConstraintSet{}, fmt.Errorf("commitment public dimensions mismatch")
	}
	if len(rowsNTT) < l.CoreRowCount {
		return ConstraintSet{}, fmt.Errorf("rows=%d want at least %d", len(rowsNTT), l.CoreRowCount)
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
	sig := []uint64{0}
	for i := 0; i < l.UCount; i++ {
		aCoeff, err := thetaCoeff(pub.A[0][i], fmt.Sprintf("A[0][%d]", i))
		if err != nil {
			return ConstraintSet{}, err
		}
		uCoeff, err := rowCoeff(l.UStart + i)
		if err != nil {
			return ConstraintSet{}, err
		}
		sig = polyAdd(sig, polyMul(aCoeff, uCoeff, q), q)
	}
	b0, err := thetaCoeff(pub.B[0], "B[0]")
	if err != nil {
		return ConstraintSet{}, err
	}
	sig = polySub(sig, b0, q)
	b1, err := thetaCoeff(pub.B[1], "B[1]")
	if err != nil {
		return ConstraintSet{}, err
	}
	muCoeff, err := rowCoeff(l.MuSigStart)
	if err != nil {
		return ConstraintSet{}, err
	}
	sig = polySub(sig, polyMul(b1, muCoeff, q), q)
	for i := 0; i < l.X0Count; i++ {
		bCoeff, err := thetaCoeff(pub.B[2+i], fmt.Sprintf("B[%d]", 2+i))
		if err != nil {
			return ConstraintSet{}, err
		}
		x0Coeff, err := rowCoeff(l.X0Start + i)
		if err != nil {
			return ConstraintSet{}, err
		}
		sig = polySub(sig, polyMul(bCoeff, x0Coeff, q), q)
	}
	zCoeff, err := rowCoeff(l.ZStart)
	if err != nil {
		return ConstraintSet{}, err
	}
	sig = polySub(sig, zCoeff, q)
	for i := 0; i < l.MCount; i++ {
		cmCoeff, err := thetaCoeff(pub.CM[0][i], fmt.Sprintf("C_M[0][%d]", i))
		if err != nil {
			return ConstraintSet{}, err
		}
		mCoeff, err := rowCoeff(l.MStart + i)
		if err != nil {
			return ConstraintSet{}, err
		}
		sig = polySub(sig, polyMul(cmCoeff, mCoeff, q), q)
	}
	for i := 0; i < l.SCount; i++ {
		asCoeff, err := thetaCoeff(pub.AS[0][i], fmt.Sprintf("A_s[0][%d]", i))
		if err != nil {
			return ConstraintSet{}, err
		}
		sCoeff, err := rowCoeff(l.SStart + i)
		if err != nil {
			return ConstraintSet{}, err
		}
		sig = polySub(sig, polyMul(asCoeff, sCoeff, q), q)
	}
	eCoeff, err := rowCoeff(l.EStart)
	if err != nil {
		return ConstraintSet{}, err
	}
	sig = polySub(sig, eCoeff, q)

	b3Coeff, err := thetaCoeff(pub.B[len(pub.B)-1], fmt.Sprintf("B[%d]", len(pub.B)-1))
	if err != nil {
		return ConstraintSet{}, err
	}
	x1Coeff, err := rowCoeff(l.X1Start)
	if err != nil {
		return ConstraintSet{}, err
	}
	den := polySub(b3Coeff, x1Coeff, q)
	inv := polySub(polyMul(den, zCoeff, q), []uint64{1 % q}, q)

	sig = trimPoly(sig, q)
	inv = trimPoly(inv, q)
	fpar := make([]*ring.Poly, 2)
	coeffs := [][]uint64{sig, inv}
	for i := range coeffs {
		if len(coeffs[i]) <= int(ringQ.N) {
			fpar[i] = nttPolyFromFormalCoeffsIfFits(ringQ, coeffs[i])
		}
	}
	return ConstraintSet{
		FparInt:          fpar,
		FparIntCoeffs:    coeffs,
		ParallelAlgDeg:   2,
		AggregatedAlgDeg: 2,
	}, nil
}

func BuildIntGenISISShowingCombined(pub PublicInputs, wit WitnessInputs, opts SimOpts) (*Proof, error) {
	opts.applyDefaults()
	if !opts.Credential || !opts.CoeffPacking {
		return nil, fmt.Errorf("IntGenISIS showing requires credential coeff-packing mode")
	}
	if wit.CoeffNativeShowing == nil {
		return nil, fmt.Errorf("IntGenISIS showing requires coeff-native witness")
	}
	pub.IntGenISIS = true
	opts.EnablePackedPRFWitnessRows = true
	opts.EnablePRFCompanion = true
	if normalizePRFCompanionMode(opts.PRFCompanionMode) == "" {
		opts.PRFCompanionMode = PRFCompanionModeOutputAudit
	}
	for attempt := 0; attempt < 4; attempt++ {
		ringQ, omega, pcsNCols, err := loadParamsAndOmegaForRelation(opts, pub.HashRelation)
		if err != nil {
			return nil, fmt.Errorf("load params: %w", err)
		}
		witnessNCols := opts.NCols
		if witnessNCols <= 0 {
			witnessNCols = pcsNCols
		}
		if opts.DomainMode == DomainModeExplicit {
			nLeaves := opts.NLeaves
			if nLeaves <= 0 {
				nLeaves = int(ringQ.N)
			}
			if pcsNCols < witnessNCols {
				pcsNCols = witnessNCols
			}
			derivedOmega, _, derr := deriveExplicitDomainForRelation(ringQ.Modulus[0], nLeaves, witnessNCols, pcsNCols, opts.Ell, pub.HashRelation)
			if derr != nil {
				return nil, fmt.Errorf("explicit domain: %w", derr)
			}
			omega = derivedOmega
		}
		params, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
		if err != nil {
			return nil, fmt.Errorf("load prf params: %w", err)
		}
		groupRounds := opts.PRFGroupRounds
		if groupRounds <= 0 {
			groupRounds = 1
		}
		rows, rowInputs, layout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, builtNCols, err := BuildCredentialRowsShowingIntGenISIS(ringQ, pub, wit, params.LenKey, params.LenNonce, params.RF, params.RP, groupRounds, opts)
		if err != nil {
			return nil, fmt.Errorf("build IntGenISIS showing rows: %w", err)
		}
		requiredPCSNCols := requiredExplicitPCSNColsForRows(ringQ, rowInputs, opts.Ell)
		if requiredPCSNCols > pcsNCols {
			opts = bumpExplicitPCSNCols(opts, requiredPCSNCols)
			continue
		}
		rowsNTT := make([]*ring.Poly, len(rows))
		for i := range rows {
			rowsNTT[i] = ringQ.NewPoly()
			ring.Copy(rows[i], rowsNTT[i])
			ringQ.NTT(rowsNTT[i], rowsNTT[i])
		}
		postSet, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, pub, layout, rowsNTT, omega[:builtNCols])
		if err != nil {
			return nil, fmt.Errorf("build IntGenISIS showing constraints: %w", err)
		}
		set := ConstraintSet{
			FparInt:            postSet.FparInt,
			FparIntCoeffs:      postSet.FparIntCoeffs,
			FparNorm:           postSet.FparNorm,
			FparNormCoeffs:     postSet.FparNormCoeffs,
			FaggInt:            postSet.FaggInt,
			FaggIntCoeffs:      postSet.FaggIntCoeffs,
			FaggNorm:           postSet.FaggNorm,
			FaggNormCoeffs:     postSet.FaggNormCoeffs,
			ParallelAlgDeg:     postSet.ParallelAlgDeg,
			AggregatedAlgDeg:   postSet.AggregatedAlgDeg,
			PRFLayout:          prfLayout,
			PRFCompanionLayout: prfCompanionLayout,
		}
		prepared := &preparedCredentialBuild{
			rows:                  rows,
			rowInputs:             rowInputs,
			rowLayout:             layout,
			decsParams:            decsParams,
			maskRowOffset:         maskRowOffset,
			maskRowCount:          maskRowCount,
			witnessCount:          witnessCount,
			witnessNCols:          builtNCols,
			omega:                 omega,
			skipConstraintRebuild: false,
		}
		opts.Credential = true
		proof, err := buildWithConstraintsPrepared(pub, wit, set, opts, FSModeCredential, prepared)
		if err != nil {
			return nil, err
		}
		return proof, nil
	}
	return nil, fmt.Errorf("could not stabilize explicit PCS width for IntGenISIS showing rows")
}

func VerifyIntGenISISShowing(pub PublicInputs, proof *Proof, opts SimOpts) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("nil proof")
	}
	pub.IntGenISIS = true
	verifySet := ConstraintSet{}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	return VerifyWithConstraints(proof, verifySet, pub, opts, FSModeCredential)
}
