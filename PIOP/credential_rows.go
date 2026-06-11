package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func firstIndex(indices []int) int {
	if len(indices) == 0 {
		return -1
	}
	return indices[0]
}

// buildCredentialRows maps credential witnesses into the pre-sign row order.
// The retained pre-sign layout commits carriers, decoded aliases, and the
// minimal replay-facing transform aliases for the public-target hash.
func buildCredentialRows(ringQ *ring.Ring, relation string, wit WitnessInputs, opts SimOpts, boundB int64, x0Bound int64) (rows []*ring.Poly, rowInputs []lvcs.RowInput, layout RowLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, ncols int, err error) {
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	opts.applyDefaults()
	if opts.NCols <= 0 {
		opts.NCols = int(ringQ.N)
	}
	ncols = opts.NCols
	if boundB <= 0 {
		err = fmt.Errorf("invalid bounded scalar carrier bound %d", boundB)
		return
	}
	if x0Bound <= 0 {
		err = fmt.Errorf("invalid x0 carrier bound %d", x0Bound)
		return
	}

	require := func(vec []*ring.Poly, name string) error {
		if len(vec) == 0 {
			return fmt.Errorf("missing witness row %s", name)
		}
		return nil
	}
	if len(wit.Mu) == 0 && len(wit.M1) > 0 {
		wit.Mu = wit.M1
	}
	if err = require(wit.Mu, "Mu"); err != nil {
		return
	}
	if err = require(wit.RU0, "RU0"); err != nil {
		return
	}
	if err = require(wit.RU1, "RU1"); err != nil {
		return
	}
	if err = require(wit.R, "R"); err != nil {
		return
	}
	if err = require(wit.R0, "R0"); err != nil {
		return
	}
	if err = require(wit.R1, "R1"); err != nil {
		return
	}
	if err = require(wit.K0, "K0"); err != nil {
		return
	}
	if err = require(wit.K1, "K1"); err != nil {
		return
	}
	useBBTran := relationUsesBBTran(relation)
	if useBBTran {
		if err = require(wit.Z, "Z"); err != nil {
			return
		}
	}

	var explicitOmega []uint64
	if opts.DomainMode == DomainModeExplicit {
		if opts.NLeaves <= 0 {
			opts.NLeaves = int(ringQ.N)
		}
		pcsNCols := resolvePCSNCols(opts, ncols)
		omegaWitness, omegaErr := deriveRelationWitnessOmega(ringQ.Modulus[0], opts.NLeaves, ncols, pcsNCols, opts.Ell, relation)
		if omegaErr != nil {
			err = fmt.Errorf("derive explicit witness omega: %w", omegaErr)
			return
		}
		explicitOmega = omegaWitness
	}

	omegaForSurface := explicitOmega
	if opts.DomainMode != DomainModeExplicit {
		omegaForSurface = make([]uint64, ncols)
	}
	surface, derr := DerivePreSignCarrierAndAliasRows(ringQ, boundB, x0Bound, omegaForSurface, opts.DomainMode, PreSignRawRows{
		Mu:  wit.Mu[0],
		M1:  firstPoly(wit.M1),
		M2:  firstPoly(wit.M2),
		RU0: wit.RU0,
		RU1: wit.RU1[0],
		R:   wit.R[0],
		R0:  wit.R0,
		R1:  wit.R1[0],
		K0:  wit.K0,
		K1:  wit.K1[0],
	})
	if derr != nil {
		return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, derr
	}
	transformSurface, terr := DerivePreSignTransformAliases(ringQ, omegaForSurface, opts.DomainMode, surface)
	if terr != nil {
		return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, terr
	}
	if len(surface.AliasMuRows) > 1 {
		muHead, herr := nttHeadFromCoeffPoly(ringQ, wit.Mu[0], len(omegaForSurface))
		if herr != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, fmt.Errorf("pre-sign full mu transform head: %w", herr)
		}
		muHatRow, herr := buildCommittedRowFromHead(ringQ, muHead, omegaForSurface, opts.DomainMode)
		if herr != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, fmt.Errorf("pre-sign full mu transform row: %w", herr)
		}
		muHatNTT := ringQ.NewPoly()
		ring.Copy(muHatRow, muHatNTT)
		ringQ.NTT(muHatNTT, muHatNTT)
		muHatCoeff, herr := coeffFromNTTPoly(ringQ, muHatNTT)
		if herr != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, fmt.Errorf("pre-sign full mu transform coeffs: %w", herr)
		}
		transformSurface.MHat1 = muHatRow
		transformSurface.MHat1Coeff = trimPoly(muHatCoeff, ringQ.Modulus[0])
		if len(transformSurface.Rows) > PreSignTransformAliasMHat1 {
			transformSurface.Rows[PreSignTransformAliasMHat1] = muHatRow
		}
		if len(transformSurface.Coeffs) > PreSignTransformAliasMHat1 {
			transformSurface.Coeffs[PreSignTransformAliasMHat1] = transformSurface.MHat1Coeff
		}
	}
	x0Len := len(surface.AliasR0Rows)
	carrierMuRows := surface.CarrierMuRows
	if len(carrierMuRows) == 0 && surface.CarrierM != nil {
		carrierMuRows = []*ring.Poly{surface.CarrierM}
	}
	rows = make([]*ring.Poly, 0)
	carrierMuBlockRows := make([]int, 0, len(carrierMuRows))
	for _, row := range carrierMuRows {
		carrierMuBlockRows = append(carrierMuBlockRows, len(rows))
		rows = append(rows, row)
	}
	carrierRU0Rows := make([]int, 0, len(surface.CarrierRU0Rows))
	for _, row := range surface.CarrierRU0Rows {
		carrierRU0Rows = append(carrierRU0Rows, len(rows))
		rows = append(rows, row)
	}
	idxCarrierRU1 := len(rows)
	rows = append(rows, surface.CarrierRU1)
	idxCarrierRBar := len(rows)
	rows = append(rows, surface.CarrierRBar)
	carrierR0Rows := make([]int, 0, len(surface.CarrierR0Rows))
	for _, row := range surface.CarrierR0Rows {
		carrierR0Rows = append(carrierR0Rows, len(rows))
		rows = append(rows, row)
	}
	idxCarrierR1 := len(rows)
	rows = append(rows, surface.CarrierR1)
	carrierK0Rows := make([]int, 0, len(surface.CarrierK0Rows))
	for _, row := range surface.CarrierK0Rows {
		carrierK0Rows = append(carrierK0Rows, len(rows))
		rows = append(rows, row)
	}
	idxCarrierK1 := len(rows)
	rows = append(rows, surface.CarrierK1)

	aliasMuRows := surface.AliasMuRows
	if len(aliasMuRows) == 0 && surface.AliasM1 != nil {
		aliasMuRows = []*ring.Poly{surface.AliasM1}
	}
	aliasMuBlockRows := make([]int, 0, len(aliasMuRows))
	for _, row := range aliasMuRows {
		aliasMuBlockRows = append(aliasMuBlockRows, len(rows))
		rows = append(rows, row)
	}
	idxM1 := firstIndex(aliasMuBlockRows)
	idxM2 := len(rows)
	rows = append(rows, surface.AliasM2)
	aliasRU0Rows := make([]int, 0, len(surface.AliasRU0Rows))
	for _, row := range surface.AliasRU0Rows {
		aliasRU0Rows = append(aliasRU0Rows, len(rows))
		rows = append(rows, row)
	}
	idxRU1 := len(rows)
	rows = append(rows, surface.AliasRU1)
	idxR := len(rows)
	rows = append(rows, surface.AliasRBar)
	aliasR0Rows := make([]int, 0, len(surface.AliasR0Rows))
	for _, row := range surface.AliasR0Rows {
		aliasR0Rows = append(aliasR0Rows, len(rows))
		rows = append(rows, row)
	}
	idxR1 := len(rows)
	rows = append(rows, surface.AliasR1)
	aliasK0Rows := make([]int, 0, len(surface.AliasK0Rows))
	for _, row := range surface.AliasK0Rows {
		aliasK0Rows = append(aliasK0Rows, len(rows))
		rows = append(rows, row)
	}
	idxK1 := len(rows)
	rows = append(rows, surface.AliasK1)

	idxMHat1 := len(rows)
	rows = append(rows, transformSurface.MHat1)
	idxMHat2 := len(rows)
	rows = append(rows, transformSurface.MHat2)
	replayRHat0Rows := make([]int, 0, len(transformSurface.RHat0Rows))
	for _, row := range transformSurface.RHat0Rows {
		replayRHat0Rows = append(replayRHat0Rows, len(rows))
		rows = append(rows, row)
	}
	idxRHat1 := len(rows)
	rows = append(rows, transformSurface.RHat1)
	idxZHat := -1
	if useBBTran {
		zHead, derr := nttHeadFromCoeffPoly(ringQ, wit.Z[0], len(omegaForSurface))
		if derr != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, fmt.Errorf("pre-sign bb_tran z head: %w", derr)
		}
		zHatRow, derr := buildCommittedRowFromHead(ringQ, zHead, omegaForSurface, opts.DomainMode)
		if derr != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, derr
		}
		idxZHat = len(rows)
		rows = append(rows, zHatRow)
	}

	if opts.DomainMode == DomainModeExplicit {
		rowInputs, err = buildRowInputsExplicit(ringQ, rows, explicitOmega, ncols)
		if err != nil {
			return
		}
	} else {
		rowInputs = buildRowInputs(ringQ, rows, ncols)
	}

	nonSigBlocks := 0
	msgCompCount := 0
	msgExtraNTTBase := -1
	msgCoeffBase := -1
	rndCompCount := 0
	rndExtraNTTBase := -1
	rndCoeffBase := -1
	x1CompCount := 0
	x1ExtraNTTBase := -1
	x1CoeffBase := -1

	// Row inputs already derived above.
	for i := range rowInputs {
		if i < len(rows) {
			rowInputs[i].Poly = rows[i]
		}
	}

	// Layout: we only set counts; range/chain bases unused for credential mode.
	witnessCount = len(rows)
	hasBaseIdx := true
	layout = RowLayout{
		RingDegree:         int(ringQ.N),
		SigCount:           witnessCount,
		MsgCount:           0,
		RndCount:           0,
		HasExplicitBaseIdx: hasBaseIdx,
		X0Len:              x0Len,
		IdxMu:              idxM1,
		IdxM1:              idxM1,
		IdxM2:              idxM2,
		IdxRU0:             firstIndex(aliasRU0Rows),
		IdxRU1:             idxRU1,
		IdxR:               idxR,
		IdxR0:              firstIndex(aliasR0Rows),
		IdxR1:              idxR1,
		IdxK0:              firstIndex(aliasK0Rows),
		IdxK1:              idxK1,
		IdxZ:               -1,
		IdxMSigmaR1:        -1,
		IdxR0R1:            -1,
		IdxMHat1:           idxMHat1,
		IdxMHat2:           idxMHat2,
		IdxRHat0:           firstIndex(replayRHat0Rows),
		IdxR0B2Hat:         -1,
		IdxTargetMR0Hat:    -1,
		IdxRHat1:           idxRHat1,
		IdxZHat:            -1,
		IdxMSigmaR1Hat:     -1,
		IdxR0R1Hat:         -1,
		IdxCarrierM:        firstIndex(carrierMuBlockRows),
		CarrierMuBlockRows: carrierMuBlockRows,
		AliasMuBlockRows:   aliasMuBlockRows,
		IdxCarrierPreRU:    firstIndex(carrierRU0Rows),
		IdxCarrierRU1:      idxCarrierRU1,
		IdxCarrierPreR:     idxCarrierRBar,
		IdxCarrierCtr:      firstIndex(carrierR0Rows),
		IdxCarrierR1:       idxCarrierR1,
		IdxCarrierK:        firstIndex(carrierK0Rows),
		IdxCarrierK1:       idxCarrierK1,
		CarrierRU0Rows:     carrierRU0Rows,
		CarrierR0Rows:      carrierR0Rows,
		CarrierK0Rows:      carrierK0Rows,
		AliasRU0Rows:       aliasRU0Rows,
		AliasR0Rows:        aliasR0Rows,
		AliasK0Rows:        aliasK0Rows,
		IdxTSource:         -1,
		IdxSigHatBase:      -1,
		SigHatExtraBase:    -1,
		IdxTHatBase:        -1,
		ReplayBlockCount:   1,
		ReplayRHat0Rows:    replayRHat0Rows,
		NonSigBlocks:       nonSigBlocks,
		MsgCompCount:       msgCompCount,
		MsgExtraNTTBase:    msgExtraNTTBase,
		MsgCoeffBase:       msgCoeffBase,
		RndCompCount:       rndCompCount,
		RndExtraNTTBase:    rndExtraNTTBase,
		RndCoeffBase:       rndCoeffBase,
		X1CompCount:        x1CompCount,
		X1ExtraNTTBase:     x1ExtraNTTBase,
		X1CoeffBase:        x1CoeffBase,
	}
	if useBBTran {
		layout.IdxZHat = idxZHat
	}

	// Masks start after witness rows.
	maskRowOffset = len(rows)
	maskRowCount = opts.Rho
	if maskRowCount > 0 {
		zeroHead := make([]uint64, ncols)
		for i := 0; i < maskRowCount; i++ {
			rows = append(rows, ringQ.NewPoly())
			rowInputs = append(rowInputs, lvcs.RowInput{Head: zeroHead})
		}
	}

	// DECS params: degree bound must be explicit (paper Eq.(3)), but callers
	// may still rely on the ncols+ell-1 heuristic. Do not clip silently: if the
	// Degree bound exceeds the ring dimension.
	maxDegree := opts.DQOverride
	if maxDegree <= 0 {
		maxDegree = ncols + opts.Ell - 1
	}
	if maxDegree < 0 || maxDegree >= int(ringQ.N) {
		err = fmt.Errorf("invalid degree bound %d (ringN=%d)", maxDegree, ringQ.N)
		return
	}
	decsParams = applyDECSCollisionWidth(decs.Params{Degree: maxDegree, Eta: opts.Eta, NonceBytes: 16}, opts)
	return
}
