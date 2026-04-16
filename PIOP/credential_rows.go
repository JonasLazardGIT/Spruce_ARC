package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildCredentialRows maps credential witnesses into the pre-sign row order.
// The retained pre-sign layout commits carriers, decoded aliases, and the
// minimal replay-facing transform aliases for the public-target hash.
func buildCredentialRows(ringQ *ring.Ring, relation string, wit WitnessInputs, opts SimOpts, bound int64) (rows []*ring.Poly, rowInputs []lvcs.RowInput, layout RowLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, ncols int, err error) {
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	opts.applyDefaults()
	if opts.NCols <= 0 {
		opts.NCols = int(ringQ.N)
	}
	ncols = opts.NCols
	if bound <= 0 {
		err = fmt.Errorf("invalid bound %d for carrier encoding", bound)
		return
	}

	require := func(vec []*ring.Poly, name string) error {
		if len(vec) == 0 {
			return fmt.Errorf("missing witness row %s", name)
		}
		return nil
	}
	if err = require(wit.M1, "M1"); err != nil {
		return
	}
	if err = require(wit.M2, "M2"); err != nil {
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
	surface, derr := DerivePreSignCarrierAndAliasRows(ringQ, bound, omegaForSurface, opts.DomainMode, PreSignRawRows{
		M1:  wit.M1[0],
		M2:  wit.M2[0],
		RU0: wit.RU0[0],
		RU1: wit.RU1[0],
		R:   wit.R[0],
		R0:  wit.R0[0],
		R1:  wit.R1[0],
		K0:  wit.K0[0],
		K1:  wit.K1[0],
	})
	if derr != nil {
		return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, derr
	}
	transformSurface, terr := DerivePreSignTransformAliases(ringQ, omegaForSurface, opts.DomainMode, surface)
	if terr != nil {
		return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, terr
	}
	useBBTran := relationUsesBBTran(relation)
	var mSigmaR1Row, r0R1Row *ring.Poly
	if useBBTran {
		q := ringQ.Modulus[0]
		mSigmaR1Coeff, r0R1Coeff, derr := buildBBTranProductInterpCoeffs(
			q,
			omegaForSurface,
			surface.AliasCoeffs[PreSignAliasM1],
			surface.AliasCoeffs[PreSignAliasM2],
			surface.AliasCoeffs[PreSignAliasR0],
			surface.AliasCoeffs[PreSignAliasR1],
		)
		if derr != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, derr
		}
		mSigmaR1Row, err = coeffPolyFromFormalCoeffs(ringQ, mSigmaR1Coeff, "pre-sign bb_tran mSigmaR1")
		if err != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, err
		}
		r0R1Row, err = coeffPolyFromFormalCoeffs(ringQ, r0R1Coeff, "pre-sign bb_tran r0R1")
		if err != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, err
		}
	}
	rows = []*ring.Poly{
		surface.CarrierRows[PreSignCarrierM],
		surface.CarrierRows[PreSignCarrierPreRU],
		surface.CarrierRows[PreSignCarrierPreR],
		surface.CarrierRows[PreSignCarrierCtr],
		surface.CarrierRows[PreSignCarrierK],
		surface.AliasRows[PreSignAliasM1],
		surface.AliasRows[PreSignAliasM2],
		surface.AliasRows[PreSignAliasRU0],
		surface.AliasRows[PreSignAliasRU1],
		surface.AliasRows[PreSignAliasR],
		surface.AliasRows[PreSignAliasR0],
		surface.AliasRows[PreSignAliasR1],
		surface.AliasRows[PreSignAliasK0],
		surface.AliasRows[PreSignAliasK1],
	}
	if useBBTran {
		rows = append(rows, mSigmaR1Row, r0R1Row)
	}
	rows = append(rows,
		transformSurface.Rows[PreSignTransformAliasMHat1],
		transformSurface.Rows[PreSignTransformAliasMHat2],
		transformSurface.Rows[PreSignTransformAliasRHat0],
		transformSurface.Rows[PreSignTransformAliasRHat1],
	)
	if useBBTran {
		mSigmaR1HatRow, _, derr := deriveTransformAliasRowFromSource(ringQ, omegaForSurface, opts.DomainMode, mSigmaR1Row, "pre-sign bb_tran mSigmaR1")
		if derr != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, derr
		}
		r0R1HatRow, _, derr := deriveTransformAliasRowFromSource(ringQ, omegaForSurface, opts.DomainMode, r0R1Row, "pre-sign bb_tran r0R1")
		if derr != nil {
			return nil, nil, RowLayout{}, decs.Params{}, 0, 0, 0, 0, derr
		}
		rows = append(rows, mSigmaR1HatRow, r0R1HatRow)
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
		SigCount:           witnessCount,
		MsgCount:           0,
		RndCount:           0,
		HasExplicitBaseIdx: hasBaseIdx,
		IdxM1:              5,
		IdxM2:              6,
		IdxRU0:             7,
		IdxRU1:             8,
		IdxR:               9,
		IdxR0:              10,
		IdxR1:              11,
		IdxK0:              12,
		IdxK1:              13,
		IdxMSigmaR1:        -1,
		IdxR0R1:            -1,
		IdxMHat1:           14,
		IdxMHat2:           15,
		IdxRHat0:           16,
		IdxRHat1:           17,
		IdxMSigmaR1Hat:     -1,
		IdxR0R1Hat:         -1,
		IdxCarrierM:        0,
		IdxCarrierPreRU:    1,
		IdxCarrierPreR:     2,
		IdxCarrierCtr:      3,
		IdxCarrierK:        4,
		IdxTSource:         -1,
		IdxSigHatBase:      -1,
		SigHatExtraBase:    -1,
		IdxTHatBase:        -1,
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
		layout.IdxMSigmaR1 = 14
		layout.IdxR0R1 = 15
		layout.IdxMHat1 = 16
		layout.IdxMHat2 = 17
		layout.IdxRHat0 = 18
		layout.IdxRHat1 = 19
		layout.IdxMSigmaR1Hat = 20
		layout.IdxR0R1Hat = 21
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
	decsParams = decs.Params{Degree: maxDegree, Eta: opts.Eta, NonceBytes: 16}
	return
}
