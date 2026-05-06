package PIOP

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	intGenISISShowingLayoutVersionYLinearV1              = "intgenisis_showing_y_linear_v1"
	intGenISISShowingLayoutVersionProjectionUYHatV1      = "intgenisis_showing_project_u_y_hat_v1"
	intGenISISShowingLayoutVersionProjectionUYHatYViewV2 = "intgenisis_showing_project_u_y_hat_y_view_v2"
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
	if wit.MAttr == nil {
		return fmt.Errorf("missing semantic message m row")
	}
	if wit.K == nil {
		return fmt.Errorf("missing semantic message k row")
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
	x0Len, err := intGenISISX0LenFromPublic(pub)
	if err != nil {
		return err
	}
	if len(wit.X0) != x0Len {
		return fmt.Errorf("x0 rows=%d want %d", len(wit.X0), x0Len)
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
	if err := check("m", []*ring.Poly{wit.MAttr}); err != nil {
		return err
	}
	if err := check("k", []*ring.Poly{wit.K}); err != nil {
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
	x0Len, err := intGenISISX0LenFromPublic(pub)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := validateIntGenISISSemanticPolys(ringQ, pub.BoundB, []*ring.Poly{cn.M}, []*ring.Poly{cn.MAttr}, []*ring.Poly{cn.K}); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("semantic message: %w", err)
	}
	if err := validateIntGenISISLiveBoundPolys(ringQ, pub.BoundB, "s", cn.S); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := validateIntGenISISLiveBoundPolys(ringQ, pub.BoundB, "e", cn.E); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	sigBound, err := intGenISISSignatureBoundFromPublic(pub)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := validateIntGenISISBoundedPolys(ringQ, sigBound, "u", cn.Sig); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	opts.applyDefaults()
	if err := validateIntGenISISReplayProjection(opts.IntGenISISReplayProjection); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	if err := rejectIntGenISISUnsafeSigLookup(opts); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	replayProjection := normalizeIntGenISISReplayProjection(opts.IntGenISISReplayProjection)
	layoutVersion := intGenISISShowingLayoutVersionYLinearV1
	layoutReplayProjection := ""
	if replayProjection == IntGenISISReplayProjectionProjectUYHatV1 {
		layoutVersion = intGenISISShowingLayoutVersionProjectionUYHatV1
		layoutReplayProjection = replayProjection
	} else if replayProjection == IntGenISISReplayProjectionProjectUYHatYViewV2 {
		layoutVersion = intGenISISShowingLayoutVersionProjectionUYHatYViewV2
		layoutReplayProjection = replayProjection
	}
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
	shortSpec, err := intGenISISUShortnessSpecForOpts(q, sigBound, opts)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	mseCompressionDesc, err := intGenISISMSECompressionDescriptorForBound(opts.IntGenISISMSECompression, pub.BoundB)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
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

	viewRowsPerPoly := int(ringQ.N) / ncols
	coreRowCount := 0
	uStart := -1
	mStart := -1
	mAttrStart := -1
	kStart := -1
	sStart := -1
	eStart := -1
	muSigStart := -1
	x0Start := -1
	x1Start := -1
	zStart := -1
	rowInputs = make([]lvcs.RowInput, 0)
	appendRowsWithInputs := func(label string, polys []*ring.Poly) error {
		for _, p := range polys {
			idx := len(rows)
			rows = append(rows, p)
			in, ierr := makeRowInput(p)
			if ierr != nil {
				return fmt.Errorf("%s row %d input: %w", label, idx, ierr)
			}
			rowInputs = append(rowInputs, in)
		}
		return nil
	}
	uViewStart := len(rows)
	uViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, cn.Sig, ncols)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("u coefficient views: %w", err)
	}
	if err := appendRowsWithInputs("u coefficient view", uViewRows); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	uShortnessStart := len(rows)
	uShortnessRows, err := intGenISISUShortnessDigitRows(ringQ, omegaWitness, cn.Sig, ncols, shortSpec)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("u shortness digit rows: %w", err)
	}
	if err := appendRowsWithInputs("u shortness digit", uShortnessRows); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
	}
	boundViewStart := len(rows)
	mViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, []*ring.Poly{cn.M}, ncols)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("M coefficient views: %w", err)
	}
	sViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, cn.S, ncols)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("s coefficient views: %w", err)
	}
	eViewRows, err := intGenISISCoeffViewRows(ringQ, omegaWitness, cn.E, ncols)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("e coefficient views: %w", err)
	}
	mViewStart := -1
	sViewStart := -1
	eViewStart := -1
	mCarrierStart := -1
	sCarrierStart := -1
	eCarrierStart := -1
	mCarrierCount := 0
	sCarrierCount := 0
	eCarrierCount := 0
	if mseCompressionDesc.Level > 0 {
		mCarrierStart = len(rows)
		mCarrierRows, cerr := intGenISISBuildTernaryCarrierRows(ringQ, omegaWitness, mViewRows, mseCompressionDesc.PackWidth, makeRowFromHead, "M")
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		if err := appendRowsWithInputs("M compressed carrier", mCarrierRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		mCarrierCount = len(mCarrierRows)
		sCarrierStart = len(rows)
		sCarrierRows, cerr := intGenISISBuildTernaryCarrierRows(ringQ, omegaWitness, sViewRows, mseCompressionDesc.PackWidth, makeRowFromHead, "s")
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		if err := appendRowsWithInputs("s compressed carrier", sCarrierRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		sCarrierCount = len(sCarrierRows)
		eCarrierStart = len(rows)
		eCarrierRows, cerr := intGenISISBuildTernaryCarrierRows(ringQ, omegaWitness, eViewRows, mseCompressionDesc.PackWidth, makeRowFromHead, "e")
		if cerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, cerr
		}
		if err := appendRowsWithInputs("e compressed carrier", eCarrierRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		eCarrierCount = len(eCarrierRows)
	} else {
		mViewStart = len(rows)
		if err := appendRowsWithInputs("M coefficient view", mViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		sViewStart = len(rows)
		if err := appendRowsWithInputs("s coefficient view", sViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
		eViewStart = len(rows)
		if err := appendRowsWithInputs("e coefficient view", eViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}
	boundViewCount := len(rows) - boundViewStart
	yViewStart := -1
	yViewRows := []*ring.Poly(nil)
	if replayProjection != IntGenISISReplayProjectionProjectUYHatYViewV2 {
		yCoeff, yerr := intGenISISCommitmentLinearYCoeff(ringQ, pub, cn)
		if yerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("commitment-linear Y: %w", yerr)
		}
		yViewStart = len(rows)
		yViewRows, err = intGenISISCoeffViewRows(ringQ, omegaWitness, []*ring.Poly{yCoeff}, ncols)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("Y coefficient views: %w", err)
		}
		if err := appendRowsWithInputs("Y coefficient view", yViewRows); err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, err
		}
	}
	buildAndAppendHats := func(label string, coeffRows []*ring.Poly) (int, int, error) {
		start := len(rows)
		hatRows, herr := intGenISISHatRowsFromCoeffViews(ringQ, omegaWitness, coeffRows, viewRowsPerPoly, makeRowFromHead, label)
		if herr != nil {
			return 0, 0, herr
		}
		if err := appendRowsWithInputs(label+" hat", hatRows); err != nil {
			return 0, 0, err
		}
		return start, len(hatRows), nil
	}
	buildAndAppendDirectHats := func(label string, polys []*ring.Poly) (int, int, error) {
		coeffRows, cerr := intGenISISCoeffViewRows(ringQ, omegaWitness, polys, ncols)
		if cerr != nil {
			return 0, 0, cerr
		}
		return buildAndAppendHats(label, coeffRows)
	}
	uHatStart, uHatCount := -1, 0
	yHatStart, yHatCount := -1, 0
	if replayProjection == IntGenISISReplayProjectionNone {
		uHatStart, uHatCount, err = buildAndAppendHats("u", uViewRows)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("u hats: %w", err)
		}
		yHatStart, yHatCount, err = buildAndAppendHats("Y", yViewRows)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("Y hats: %w", err)
		}
	}
	muSigHatStart, muSigHatCount, err := buildAndAppendDirectHats("mu_sig", cn.MuSig)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("mu_sig hats: %w", err)
	}
	x0HatStart, x0HatCount, err := buildAndAppendDirectHats("x0", cn.X0)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("x0 hats: %w", err)
	}
	x1HatStart, x1HatCount, err := buildAndAppendDirectHats("x1", []*ring.Poly{cn.X1})
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("x1 hats: %w", err)
	}
	zHatStart, zHatCount, err := buildAndAppendDirectHats("Z", []*ring.Poly{cn.Z})
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("Z hats: %w", err)
	}

	companionMode := normalizePRFCompanionMode(opts.PRFCompanionMode)
	if companionMode != "" {
		if prfGroupRounds <= 0 {
			prfGroupRounds = 1
		}
		key, kerr := extractIntGenISISPRFKeyElemsFromSemanticM(ringQ, pub.BoundB, []*ring.Poly{cn.M})
		if kerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("extract IntGenISIS PRF key from M: %w", kerr)
		}
		if len(key) != prfParamsLenKey {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("semantic key length=%d want %d", len(key), prfParamsLenKey)
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
		keySourceSlots := []CoeffSlot(nil)
		keySourceDecodeLanes := []int(nil)
		var kserr error
		if mseCompressionDesc.Level > 0 {
			keySourceSlots, keySourceDecodeLanes, kserr = intGenISISKeySourceCarrierSlots(mCarrierStart, len(packed.KeySlots), ncols, int(ringQ.N), mseCompressionDesc.PackWidth)
			if kserr != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("IntGenISIS compressed PRF key source slots: %w", kserr)
			}
		} else {
			keySourceSlots, kserr = intGenISISKeySourceViewSlots(mViewStart, len(packed.KeySlots), ncols, int(ringQ.N))
			if kserr != nil {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("IntGenISIS PRF key source slots: %w", kserr)
			}
		}
		prfCompanionLayout = &PRFCompanionLayout{
			StartRow:             companionStart,
			PackWidth:            ncols,
			KeySource:            KeySourceIndependentWitness,
			KeySlots:             packed.KeySlots,
			KeySourceSlots:       keySourceSlots,
			KeySourceDecodeLanes: keySourceDecodeLanes,
			CheckpointSlots:      packed.CheckpointSlots,
			FinalTagSlots:        packed.FinalTagSlots,
			HelperFamilies:       []string{"final_tag_state"},
			ReplayRows:           len(packed.Rows),
			PackedRows:           len(packed.Rows),
			PackedLogicalCount:   packed.TotalLogicalScalars,
			HelperRowCount:       helperRows,
			DataRows:             dataRows,
			HelperRows:           helperRows,
			KeyCount:             len(packed.KeySlots),
			CheckpointCount:      len(packed.CheckpointSlots),
			TagCount:             len(pub.Tag),
			RowSemantics:         rowSemantics,
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
		X0Len:              x0Len,
		HasExplicitBaseIdx: true,
		IntGenISISShowing: &IntGenISISShowingRowLayout{
			LayoutVersion:              layoutVersion,
			ReplayProjection:           layoutReplayProjection,
			UStart:                     uStart,
			UCount:                     len(cn.Sig),
			MStart:                     mStart,
			MCount:                     1,
			MAttrStart:                 mAttrStart,
			MAttrCount:                 1,
			KStart:                     kStart,
			KCount:                     1,
			SStart:                     sStart,
			SCount:                     len(cn.S),
			EStart:                     eStart,
			ECount:                     len(cn.E),
			MuSigStart:                 muSigStart,
			MuSigCount:                 len(cn.MuSig),
			X0Start:                    x0Start,
			X0Count:                    len(cn.X0),
			X1Start:                    x1Start,
			X1Count:                    1,
			ZStart:                     zStart,
			ZCount:                     1,
			BoundViewStart:             boundViewStart,
			BoundViewCount:             boundViewCount,
			MSECompressionLevel:        mseCompressionDesc.Level,
			MSECompressionPackWidth:    mseCompressionDesc.PackWidth,
			MSECompressionAlphabet:     mseCompressionDesc.Alphabet,
			MSECompressionDecodeDegree: mseCompressionDesc.DecodeDegree,
			MCarrierStart:              mCarrierStart,
			MCarrierCount:              mCarrierCount,
			SCarrierStart:              sCarrierStart,
			SCarrierCount:              sCarrierCount,
			ECarrierStart:              eCarrierStart,
			ECarrierCount:              eCarrierCount,
			MSECarrierCount:            mCarrierCount + sCarrierCount + eCarrierCount,
			UViewStart:                 uViewStart,
			UShortnessStart:            uShortnessStart,
			UShortnessGroupCount:       len(cn.Sig) * viewRowsPerPoly,
			UShortnessRowsPerGroup:     shortSpec.L,
			UShortnessRadix:            int(shortSpec.R),
			UShortnessDigits:           shortSpec.L,
			UShortnessSourceViewStart:  uViewStart,
			UShortnessSourceViewRows:   len(cn.Sig) * viewRowsPerPoly,
			UShortnessCapacity:         int64(shortSpec.MaxAbs),
			UShortnessProofMode:        intGenISISUShortnessMode,
			MViewStart:                 mViewStart,
			MAttrViewStart:             mAttrStart,
			KViewStart:                 kStart,
			SViewStart:                 sViewStart,
			EViewStart:                 eViewStart,
			YViewStart:                 yViewStart,
			YViewCount:                 len(yViewRows),
			MuSigViewStart:             muSigStart,
			X0ViewStart:                x0Start,
			X1ViewStart:                x1Start,
			ZViewStart:                 zStart,
			UHatStart:                  uHatStart,
			UHatCount:                  uHatCount,
			MHatStart:                  -1,
			MHatCount:                  0,
			SHatStart:                  -1,
			SHatCount:                  0,
			EHatStart:                  -1,
			EHatCount:                  0,
			YHatStart:                  yHatStart,
			YHatCount:                  yHatCount,
			MuSigHatStart:              muSigHatStart,
			MuSigHatCount:              muSigHatCount,
			X0HatStart:                 x0HatStart,
			X0HatCount:                 x0HatCount,
			X1HatStart:                 x1HatStart,
			X1HatCount:                 x1HatCount,
			ZHatStart:                  zHatStart,
			ZHatCount:                  zHatCount,
			HatRowsPerPoly:             viewRowsPerPoly,
			ViewRowsPerPoly:            viewRowsPerPoly,
			CoreRowCount:               coreRowCount,
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

func intGenISISUShortnessLayoutSpec(ringQ *ring.Ring, l *IntGenISISShowingRowLayout, sigBound int64) (LinfSpec, error) {
	if l == nil {
		return LinfSpec{}, fmt.Errorf("missing IntGenISIS showing layout")
	}
	spec, err := intGenISISUShortnessSpecForOpts(ringQ.Modulus[0], sigBound, SimOpts{SigShortnessRadix: l.UShortnessRadix, SigShortnessL: l.UShortnessDigits})
	if err != nil {
		return LinfSpec{}, err
	}
	expectedGroups := l.UCount * l.ViewRowsPerPoly
	if expectedGroups <= 0 {
		return LinfSpec{}, fmt.Errorf("invalid IntGenISIS u shortness group count %d", expectedGroups)
	}
	if l.UShortnessStart <= 0 {
		return LinfSpec{}, fmt.Errorf("missing IntGenISIS u shortness rows")
	}
	if l.UShortnessGroupCount != expectedGroups {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness groups=%d want %d", l.UShortnessGroupCount, expectedGroups)
	}
	if l.UShortnessRowsPerGroup != spec.L {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness rows/group=%d want %d", l.UShortnessRowsPerGroup, spec.L)
	}
	if l.UShortnessRadix != int(spec.R) || l.UShortnessDigits != spec.L {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness metadata R=%d L=%d want R=%d L=%d", l.UShortnessRadix, l.UShortnessDigits, spec.R, spec.L)
	}
	if l.UShortnessSourceViewStart != l.UViewStart || l.UShortnessSourceViewRows != expectedGroups {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness source views start=%d rows=%d want start=%d rows=%d", l.UShortnessSourceViewStart, l.UShortnessSourceViewRows, l.UViewStart, expectedGroups)
	}
	if l.UShortnessCapacity != int64(spec.MaxAbs) {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness capacity=%d want %d", l.UShortnessCapacity, spec.MaxAbs)
	}
	if l.UShortnessProofMode != intGenISISUShortnessMode {
		return LinfSpec{}, fmt.Errorf("IntGenISIS u shortness mode=%q want %q", l.UShortnessProofMode, intGenISISUShortnessMode)
	}
	if l.BoundViewStart < l.UShortnessStart+l.UShortnessGroupCount*l.UShortnessRowsPerGroup {
		return LinfSpec{}, fmt.Errorf("IntGenISIS bound views overlap u shortness rows")
	}
	return spec, nil
}

func intGenISISUShortnessConstraintRows(ringQ *ring.Ring, rowsNTT []*ring.Poly, l *IntGenISISShowingRowLayout, spec LinfSpec) ([]*ring.Poly, [][]uint64, error) {
	if l == nil {
		return nil, nil, fmt.Errorf("missing IntGenISIS showing layout")
	}
	sourceCount := l.UShortnessSourceViewRows
	if sourceCount <= 0 {
		return nil, nil, fmt.Errorf("missing IntGenISIS u shortness source rows")
	}
	packedSourceRows := make([]*ring.Poly, sourceCount)
	packedRows := make([][]*ring.Poly, sourceCount)
	for group := 0; group < sourceCount; group++ {
		srcIdx := l.UShortnessSourceViewStart + group
		if srcIdx < 0 || srcIdx >= len(rowsNTT) || rowsNTT[srcIdx] == nil {
			return nil, nil, fmt.Errorf("invalid IntGenISIS u shortness source row %d", srcIdx)
		}
		packedSourceRows[group] = rowsNTT[srcIdx]
		packedRows[group] = make([]*ring.Poly, l.UShortnessRowsPerGroup)
		for lane := 0; lane < l.UShortnessRowsPerGroup; lane++ {
			idx := l.UShortnessStart + group*l.UShortnessRowsPerGroup + lane
			if idx < 0 || idx >= len(rowsNTT) || rowsNTT[idx] == nil {
				return nil, nil, fmt.Errorf("invalid IntGenISIS u shortness digit row %d", idx)
			}
			packedRows[group][lane] = rowsNTT[idx]
		}
	}
	return buildSigShortnessPackedMembershipFormalCoeffs(ringQ, packedSourceRows, packedRows, spec)
}

func intGenISISCommitmentLinearYCoeff(ringQ *ring.Ring, pub PublicInputs, cn *CoeffNativeShowingWitness) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if cn == nil {
		return nil, fmt.Errorf("nil showing witness")
	}
	if len(pub.CM) != 1 || len(pub.CM[0]) != 1 {
		return nil, fmt.Errorf("C_M dimensions=%dx? want 1x1", len(pub.CM))
	}
	if len(pub.AS) != 1 || len(pub.AS[0]) != len(cn.S) {
		return nil, fmt.Errorf("A_s dimensions mismatch rows=%d s=%d", len(pub.AS), len(cn.S))
	}
	if len(cn.E) != 1 {
		return nil, fmt.Errorf("e rows=%d want 1", len(cn.E))
	}
	yNTT := ringQ.NewPoly()
	tmpNTT := ringQ.NewPoly()
	sourceNTT := ringQ.NewPoly()
	addProduct := func(label string, publicNTT, sourceCoeff *ring.Poly) error {
		if publicNTT == nil || sourceCoeff == nil {
			return fmt.Errorf("nil %s term", label)
		}
		ring.Copy(sourceCoeff, sourceNTT)
		ringQ.NTT(sourceNTT, sourceNTT)
		ringQ.MulCoeffs(publicNTT, sourceNTT, tmpNTT)
		ringQ.Add(yNTT, tmpNTT, yNTT)
		return nil
	}
	if err := addProduct("C_M*M", pub.CM[0][0], cn.M); err != nil {
		return nil, err
	}
	for i := range cn.S {
		if err := addProduct(fmt.Sprintf("A_s[%d]*s[%d]", i, i), pub.AS[0][i], cn.S[i]); err != nil {
			return nil, err
		}
	}
	ring.Copy(cn.E[0], sourceNTT)
	ringQ.NTT(sourceNTT, sourceNTT)
	ringQ.Add(yNTT, sourceNTT, yNTT)
	yCoeff := ringQ.NewPoly()
	ringQ.InvNTT(yNTT, yCoeff)
	return yCoeff, nil
}

func intGenISISThetaBlockCoeff(ringQ *ring.Ring, p *ring.Poly, omega []uint64, block, blocks int, name string) ([]uint64, error) {
	theta, err := thetaPolyFromNTTBlock(ringQ, p, omega, block, blocks)
	if err != nil {
		return nil, fmt.Errorf("theta block %s[%d]: %w", name, block, err)
	}
	coeff, err := coeffFromNTTPoly(ringQ, theta)
	if err != nil {
		return nil, fmt.Errorf("theta block %s[%d] coeffs: %w", name, block, err)
	}
	return trimPoly(coeff, ringQ.Modulus[0]), nil
}

func validateIntGenISISShowingPackedLayout(l *IntGenISISShowingRowLayout, rowCount int) error {
	if l == nil {
		return fmt.Errorf("missing IntGenISIS showing layout")
	}
	projectionMode := intGenISISProjectionModeFromLayout(l)
	switch l.LayoutVersion {
	case intGenISISShowingLayoutVersionYLinearV1:
		if projectionMode != IntGenISISReplayProjectionNone {
			return fmt.Errorf("IntGenISIS showing layout version %q cannot use replay projection %q", l.LayoutVersion, projectionMode)
		}
	case intGenISISShowingLayoutVersionProjectionUYHatV1:
		if projectionMode != IntGenISISReplayProjectionProjectUYHatV1 {
			return fmt.Errorf("IntGenISIS showing projection layout requires replay projection %q, got %q", IntGenISISReplayProjectionProjectUYHatV1, projectionMode)
		}
	case intGenISISShowingLayoutVersionProjectionUYHatYViewV2:
		if projectionMode != IntGenISISReplayProjectionProjectUYHatYViewV2 {
			return fmt.Errorf("IntGenISIS showing projection layout requires replay projection %q, got %q", IntGenISISReplayProjectionProjectUYHatYViewV2, projectionMode)
		}
	default:
		return fmt.Errorf("unsupported IntGenISIS showing layout version %q", l.LayoutVersion)
	}
	projectedUY := projectionMode == IntGenISISReplayProjectionProjectUYHatV1 || projectionMode == IntGenISISReplayProjectionProjectUYHatYViewV2
	derivedYView := projectionMode == IntGenISISReplayProjectionProjectUYHatYViewV2
	if l.CoreRowCount != 0 {
		return fmt.Errorf("IntGenISIS packed showing requires core_row_count=0, got %d", l.CoreRowCount)
	}
	if l.UCount <= 0 || l.MCount != 1 || l.MAttrCount != 1 || l.KCount != 1 || l.MuSigCount != 1 || l.X0Count <= 0 || l.X1Count != 1 || l.ZCount != 1 {
		return fmt.Errorf("invalid IntGenISIS showing row counts")
	}
	if l.ViewRowsPerPoly <= 0 {
		return fmt.Errorf("invalid IntGenISIS view rows/poly=%d", l.ViewRowsPerPoly)
	}
	if l.HatRowsPerPoly != l.ViewRowsPerPoly {
		return fmt.Errorf("IntGenISIS hat rows/poly=%d want %d", l.HatRowsPerPoly, l.ViewRowsPerPoly)
	}
	rpp := l.ViewRowsPerPoly
	compressed := l.MSECompressionLevel > 0
	if compressed {
		desc, err := intGenISISMSECompressionDescriptorForBound(l.MSECompressionLevel, intGenISISTernaryBound)
		if err != nil {
			return err
		}
		if l.MSECompressionPackWidth != desc.PackWidth || l.MSECompressionAlphabet != desc.Alphabet || l.MSECompressionDecodeDegree != desc.DecodeDegree {
			return fmt.Errorf("IntGenISIS M/s/e compression metadata mismatch level=%d pack=%d alphabet=%d decode_degree=%d",
				l.MSECompressionLevel, l.MSECompressionPackWidth, l.MSECompressionAlphabet, l.MSECompressionDecodeDegree)
		}
		if l.MCarrierCount != intGenISISCompressedCarrierCount(l.MCount*rpp, desc.PackWidth) ||
			l.SCarrierCount != intGenISISCompressedCarrierCount(l.SCount*rpp, desc.PackWidth) ||
			l.ECarrierCount != intGenISISCompressedCarrierCount(l.ECount*rpp, desc.PackWidth) {
			return fmt.Errorf("IntGenISIS compressed carrier counts mismatch")
		}
		if l.MSECarrierCount != l.MCarrierCount+l.SCarrierCount+l.ECarrierCount {
			return fmt.Errorf("IntGenISIS mse carrier count=%d want %d", l.MSECarrierCount, l.MCarrierCount+l.SCarrierCount+l.ECarrierCount)
		}
	} else if l.MSECompressionPackWidth > 0 && l.MSECompressionPackWidth != 1 {
		return fmt.Errorf("IntGenISIS uncompressed M/s/e has pack width %d", l.MSECompressionPackWidth)
	}
	check := func(name string, start, count int) error {
		if start < 0 || count <= 0 {
			return fmt.Errorf("missing IntGenISIS %s rows start=%d count=%d", name, start, count)
		}
		if start+count > rowCount {
			return fmt.Errorf("IntGenISIS %s rows [%d,%d) exceed rows=%d", name, start, start+count, rowCount)
		}
		return nil
	}
	required := []struct {
		name  string
		start int
		count int
	}{
		{"u coefficient-view", l.UViewStart, l.UCount * rpp},
		{"mu_sig hat", l.MuSigHatStart, l.MuSigHatCount},
		{"x0 hat", l.X0HatStart, l.X0HatCount},
		{"x1 hat", l.X1HatStart, l.X1HatCount},
		{"Z hat", l.ZHatStart, l.ZHatCount},
	}
	if derivedYView {
		if l.YViewStart >= 0 || l.YViewCount != 0 {
			return fmt.Errorf("IntGenISIS V2 projected showing must not commit Y coefficient-view rows start=%d count=%d", l.YViewStart, l.YViewCount)
		}
	} else {
		required = append(required, struct {
			name  string
			start int
			count int
		}{"Y coefficient-view", l.YViewStart, l.YViewCount})
	}
	if projectedUY {
		for _, part := range []struct {
			name  string
			start int
			count int
		}{
			{"u hat", l.UHatStart, l.UHatCount},
			{"Y hat", l.YHatStart, l.YHatCount},
		} {
			if part.start >= 0 || part.count != 0 {
				return fmt.Errorf("IntGenISIS projected showing must not commit %s rows start=%d count=%d", part.name, part.start, part.count)
			}
		}
	} else {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"u hat", l.UHatStart, l.UHatCount},
			struct {
				name  string
				start int
				count int
			}{"Y hat", l.YHatStart, l.YHatCount},
		)
	}
	for _, part := range []struct {
		name  string
		start int
		count int
	}{
		{"M hat", l.MHatStart, l.MHatCount},
		{"s hat", l.SHatStart, l.SHatCount},
		{"e hat", l.EHatStart, l.EHatCount},
	} {
		if part.start >= 0 || part.count != 0 {
			return fmt.Errorf("IntGenISIS Y-linear showing must not use %s rows start=%d count=%d", part.name, part.start, part.count)
		}
	}
	if compressed {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"M compressed carrier", l.MCarrierStart, l.MCarrierCount},
			struct {
				name  string
				start int
				count int
			}{"s compressed carrier", l.SCarrierStart, l.SCarrierCount},
			struct {
				name  string
				start int
				count int
			}{"e compressed carrier", l.ECarrierStart, l.ECarrierCount},
		)
	} else {
		required = append(required,
			struct {
				name  string
				start int
				count int
			}{"M coefficient-view", l.MViewStart, l.MCount * rpp},
			struct {
				name  string
				start int
				count int
			}{"s coefficient-view", l.SViewStart, l.SCount * rpp},
			struct {
				name  string
				start int
				count int
			}{"e coefficient-view", l.EViewStart, l.ECount * rpp},
		)
	}
	for _, part := range required {
		if err := check(part.name, part.start, part.count); err != nil {
			return err
		}
	}
	for _, part := range []struct {
		name  string
		start int
	}{
		{"m coefficient-view", l.MAttrViewStart},
		{"k coefficient-view", l.KViewStart},
		{"mu_sig coefficient-view", l.MuSigViewStart},
		{"x0 coefficient-view", l.X0ViewStart},
		{"x1 coefficient-view", l.X1ViewStart},
		{"Z coefficient-view", l.ZViewStart},
	} {
		if part.start >= 0 {
			return fmt.Errorf("IntGenISIS compact showing does not use %s rows, got start=%d", part.name, part.start)
		}
	}
	if compressed {
		for _, part := range []struct {
			name  string
			start int
		}{
			{"M coefficient-view", l.MViewStart},
			{"s coefficient-view", l.SViewStart},
			{"e coefficient-view", l.EViewStart},
		} {
			if part.start >= 0 {
				return fmt.Errorf("IntGenISIS compressed showing does not use raw %s rows, got start=%d", part.name, part.start)
			}
		}
	}
	expectedHatCounts := map[string][2]int{
		"mu_sig": {l.MuSigHatCount, l.MuSigCount * rpp},
		"x0":     {l.X0HatCount, l.X0Count * rpp},
		"x1":     {l.X1HatCount, l.X1Count * rpp},
		"Z":      {l.ZHatCount, l.ZCount * rpp},
	}
	if !projectedUY {
		expectedHatCounts["u"] = [2]int{l.UHatCount, l.UCount * rpp}
		expectedHatCounts["Y"] = [2]int{l.YHatCount, rpp}
	}
	for name, counts := range expectedHatCounts {
		if counts[0] != counts[1] {
			return fmt.Errorf("IntGenISIS %s hat rows=%d want %d", name, counts[0], counts[1])
		}
	}
	if !derivedYView && l.YViewCount != rpp {
		return fmt.Errorf("IntGenISIS Y coefficient-view rows=%d want %d", l.YViewCount, rpp)
	}
	return nil
}

type intGenISISYLinearTermCache struct {
	Name       string
	Source     int
	Components int
	Compressed bool
	H          [][][][]uint64
}

type intGenISISYLinearMapCache struct {
	Lagrange [][]uint64
	Terms    []intGenISISYLinearTermCache
}

var intGenISISYLinearGlobalCache struct {
	sync.RWMutex
	key   [32]byte
	value *intGenISISYLinearMapCache
	ok    bool
}

func intGenISISPublicCoeffFromNTT(ringQ *ring.Ring, pNTT *ring.Poly, name string) ([]uint64, error) {
	if pNTT == nil {
		return nil, fmt.Errorf("nil %s", name)
	}
	coeff, err := coeffFromNTTPoly(ringQ, pNTT)
	if err != nil {
		return nil, fmt.Errorf("%s coeffs: %w", name, err)
	}
	return trimCoeffsCopy(coeff, ringQ.Modulus[0]), nil
}

type intGenISISRowCoeffCache struct {
	ringQ *ring.Ring
	q     uint64
	rows  []*ring.Poly
	coeff [][]uint64
}

func newIntGenISISRowCoeffCache(ringQ *ring.Ring, rowsNTT []*ring.Poly) (*intGenISISRowCoeffCache, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	q := ringQ.Modulus[0]
	cache := &intGenISISRowCoeffCache{
		ringQ: ringQ,
		q:     q,
		rows:  rowsNTT,
		coeff: make([][]uint64, len(rowsNTT)),
	}
	for i := range rowsNTT {
		if rowsNTT[i] == nil {
			return nil, fmt.Errorf("nil row index %d", i)
		}
		tmp := ringQ.NewPoly()
		ringQ.InvNTT(rowsNTT[i], tmp)
		cache.coeff[i] = trimCoeffsCopy(tmp.Coeffs[0], q)
	}
	return cache, nil
}

func (c *intGenISISRowCoeffCache) Row(idx int) ([]uint64, error) {
	if c == nil {
		return nil, fmt.Errorf("missing row coefficient cache")
	}
	if idx < 0 || idx >= len(c.coeff) || c.rows[idx] == nil {
		return nil, fmt.Errorf("invalid row index %d", idx)
	}
	return c.coeff[idx], nil
}

func intGenISISNegacyclicWeight(multCoeff []uint64, outIdx, srcIdx, n int, q uint64) uint64 {
	if n <= 0 || outIdx < 0 || outIdx >= n || srcIdx < 0 || srcIdx >= n || len(multCoeff) == 0 {
		return 0
	}
	diff := outIdx - srcIdx
	if diff >= 0 {
		if diff >= len(multCoeff) {
			return 0
		}
		return multCoeff[diff] % q
	}
	idx := diff + n
	if idx >= len(multCoeff) {
		return 0
	}
	v := multCoeff[idx] % q
	if v == 0 {
		return 0
	}
	return q - v
}

func intGenISISLinearHForMultiplier(ringQ *ring.Ring, omega []uint64, multCoeff []uint64, rowsPerPoly int, name string) ([][][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 || rowsPerPoly <= 0 {
		return nil, fmt.Errorf("invalid %s linear map omega=%d rowsPerPoly=%d", name, len(omega), rowsPerPoly)
	}
	ncols := len(omega)
	n := int(ringQ.N)
	if rowsPerPoly*ncols != n {
		return nil, fmt.Errorf("%s linear map rowsPerPoly*ncols=%d want ringN=%d", name, rowsPerPoly*ncols, n)
	}
	q := ringQ.Modulus[0]
	out := make([][][]uint64, n)
	for outIdx := 0; outIdx < n; outIdx++ {
		out[outIdx] = make([][]uint64, rowsPerPoly)
		for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
			head := make([]uint64, ncols)
			for lane := 0; lane < ncols; lane++ {
				srcIdx := srcBlock*ncols + lane
				head[lane] = intGenISISNegacyclicWeight(multCoeff, outIdx, srcIdx, n, q)
			}
			out[outIdx][srcBlock] = trimPoly(Interpolate(omega, head, q), q)
		}
	}
	return out, nil
}

func intGenISISYLinearCacheKey(ringQ *ring.Ring, pub PublicInputs, l *IntGenISISShowingRowLayout, omega []uint64) ([32]byte, bool) {
	if ringQ == nil || l == nil || len(ringQ.Modulus) == 0 {
		return [32]byte{}, false
	}
	h := sha256.New()
	var buf [8]byte
	writeU64 := func(v uint64) {
		binary.LittleEndian.PutUint64(buf[:], v)
		_, _ = h.Write(buf[:])
	}
	writeInt := func(v int) {
		writeU64(uint64(v))
	}
	writePoly := func(p *ring.Poly) {
		if p == nil {
			writeU64(^uint64(0))
			return
		}
		writeInt(len(p.Coeffs))
		for i := range p.Coeffs {
			writeInt(len(p.Coeffs[i]))
			for _, v := range p.Coeffs[i] {
				writeU64(v)
			}
		}
	}
	_, _ = h.Write([]byte("intgenisis-y-linear-map-cache-v1"))
	writeU64(ringQ.Modulus[0])
	writeInt(int(ringQ.N))
	writeInt(len(omega))
	for _, v := range omega {
		writeU64(v)
	}
	writeInt(l.ViewRowsPerPoly)
	writeInt(l.MSECompressionLevel)
	writeInt(l.MViewStart)
	writeInt(l.SViewStart)
	writeInt(l.EViewStart)
	writeInt(l.MCarrierStart)
	writeInt(l.SCarrierStart)
	writeInt(l.ECarrierStart)
	writeInt(l.MCount)
	writeInt(l.SCount)
	writeInt(l.ECount)
	writeInt(len(pub.CM))
	for i := range pub.CM {
		writeInt(len(pub.CM[i]))
		for j := range pub.CM[i] {
			writePoly(pub.CM[i][j])
		}
	}
	writeInt(len(pub.AS))
	for i := range pub.AS {
		writeInt(len(pub.AS[i]))
		for j := range pub.AS[i] {
			writePoly(pub.AS[i][j])
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, true
}

func loadIntGenISISYLinearGlobalCache(key [32]byte) (*intGenISISYLinearMapCache, bool) {
	intGenISISYLinearGlobalCache.RLock()
	defer intGenISISYLinearGlobalCache.RUnlock()
	if intGenISISYLinearGlobalCache.ok && intGenISISYLinearGlobalCache.key == key && intGenISISYLinearGlobalCache.value != nil {
		return intGenISISYLinearGlobalCache.value, true
	}
	return nil, false
}

func storeIntGenISISYLinearGlobalCache(key [32]byte, value *intGenISISYLinearMapCache) {
	if value == nil {
		return
	}
	intGenISISYLinearGlobalCache.Lock()
	intGenISISYLinearGlobalCache.key = key
	intGenISISYLinearGlobalCache.value = value
	intGenISISYLinearGlobalCache.ok = true
	intGenISISYLinearGlobalCache.Unlock()
}

func newIntGenISISYLinearMapCache(ringQ *ring.Ring, pub PublicInputs, l *IntGenISISShowingRowLayout, omega []uint64) (*intGenISISYLinearMapCache, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if l == nil {
		return nil, fmt.Errorf("missing IntGenISIS showing layout")
	}
	cacheKey, cacheable := intGenISISYLinearCacheKey(ringQ, pub, l, omega)
	if cacheable {
		if cached, ok := loadIntGenISISYLinearGlobalCache(cacheKey); ok {
			return cached, nil
		}
	}
	lagrange, err := buildLagrangeBasisCoeffs(omega, ringQ.Modulus[0])
	if err != nil {
		return nil, fmt.Errorf("Y linear lagrange basis: %w", err)
	}
	compressed := l.MSECompressionLevel > 0
	buildTerm := func(name string, source, components int, publicNTT []*ring.Poly) (intGenISISYLinearTermCache, error) {
		if source < 0 || components <= 0 || len(publicNTT) != components {
			return intGenISISYLinearTermCache{}, fmt.Errorf("invalid %s Y-linear term source=%d components=%d public=%d", name, source, components, len(publicNTT))
		}
		h := make([][][][]uint64, components)
		for comp := 0; comp < components; comp++ {
			coeff, err := intGenISISPublicCoeffFromNTT(ringQ, publicNTT[comp], fmt.Sprintf("%s[%d]", name, comp))
			if err != nil {
				return intGenISISYLinearTermCache{}, err
			}
			h[comp], err = intGenISISLinearHForMultiplier(ringQ, omega, coeff, l.ViewRowsPerPoly, fmt.Sprintf("%s[%d]", name, comp))
			if err != nil {
				return intGenISISYLinearTermCache{}, err
			}
		}
		return intGenISISYLinearTermCache{Name: name, Source: source, Components: components, Compressed: compressed, H: h}, nil
	}
	mSource := l.MViewStart
	sSource := l.SViewStart
	eSource := l.EViewStart
	if compressed {
		mSource = l.MCarrierStart
		sSource = l.SCarrierStart
		eSource = l.ECarrierStart
	}
	if len(pub.CM) != 1 || len(pub.CM[0]) != l.MCount {
		return nil, fmt.Errorf("C_M dimensions mismatch")
	}
	if len(pub.AS) != 1 || len(pub.AS[0]) != l.SCount {
		return nil, fmt.Errorf("A_s dimensions mismatch")
	}
	identity := ringQ.NewPoly()
	identity.Coeffs[0][0] = 1
	ringQ.NTT(identity, identity)
	mTerm, err := buildTerm("M", mSource, l.MCount, pub.CM[0])
	if err != nil {
		return nil, err
	}
	sTerm, err := buildTerm("s", sSource, l.SCount, pub.AS[0])
	if err != nil {
		return nil, err
	}
	eTerm, err := buildTerm("e", eSource, l.ECount, []*ring.Poly{identity})
	if err != nil {
		return nil, err
	}
	out := &intGenISISYLinearMapCache{
		Lagrange: lagrange,
		Terms:    []intGenISISYLinearTermCache{mTerm, sTerm, eTerm},
	}
	if cacheable {
		storeIntGenISISYLinearGlobalCache(cacheKey, out)
	}
	return out, nil
}

func intGenISISYLinearSourceFormalCoeffs(ringQ *ring.Ring, rowsNTT []*ring.Poly, rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, cache *intGenISISYLinearMapCache, compressionSpec intGenISISMSECompressionSpec) ([][][][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if l == nil || cache == nil {
		return nil, fmt.Errorf("missing IntGenISIS Y-linear metadata")
	}
	sourceCoeffs := make([][][][]uint64, len(cache.Terms))
	for ti, term := range cache.Terms {
		sourceCoeffs[ti] = make([][][]uint64, term.Components)
		if term.Compressed {
			decoded, err := intGenISISCompressedSourceFormalCoeffs(ringQ, rowsNTT, term.Source, term.Components*l.ViewRowsPerPoly, l.MSECompressionPackWidth, compressionSpec.DecodePolys, term.Name)
			if err != nil {
				return nil, err
			}
			for comp := 0; comp < term.Components; comp++ {
				sourceCoeffs[ti][comp] = make([][]uint64, l.ViewRowsPerPoly)
				for block := 0; block < l.ViewRowsPerPoly; block++ {
					sourceCoeffs[ti][comp][block] = decoded[comp*l.ViewRowsPerPoly+block]
				}
			}
			continue
		}
		for comp := 0; comp < term.Components; comp++ {
			sourceCoeffs[ti][comp] = make([][]uint64, l.ViewRowsPerPoly)
			for block := 0; block < l.ViewRowsPerPoly; block++ {
				coeff, err := rowCache.Row(term.Source + comp*l.ViewRowsPerPoly + block)
				if err != nil {
					return nil, err
				}
				sourceCoeffs[ti][comp][block] = coeff
			}
		}
	}
	return sourceCoeffs, nil
}

func intGenISISYLinearConstraintFormalCoeffs(ringQ *ring.Ring, rowsNTT []*ring.Poly, rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, cache *intGenISISYLinearMapCache, compressionSpec intGenISISMSECompressionSpec) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if l == nil || cache == nil {
		return nil, nil, fmt.Errorf("missing IntGenISIS Y-linear metadata")
	}
	q := ringQ.Modulus[0]
	sourceCoeffs, err := intGenISISYLinearSourceFormalCoeffs(ringQ, rowsNTT, rowCache, l, cache, compressionSpec)
	if err != nil {
		return nil, nil, err
	}
	ncols := len(cache.Lagrange)
	fagg := make([]*ring.Poly, 0, l.ViewRowsPerPoly*ncols)
	coeffs := make([][]uint64, 0, l.ViewRowsPerPoly*ncols)
	for block := 0; block < l.ViewRowsPerPoly; block++ {
		yCoeff, err := rowCache.Row(l.YViewStart + block)
		if err != nil {
			return nil, nil, err
		}
		for lane := 0; lane < ncols; lane++ {
			outIdx := block*ncols + lane
			leftCoeff := make([]uint64, int(ringQ.N))
			for ti, term := range cache.Terms {
				for comp := 0; comp < term.Components; comp++ {
					for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
						addMulModXN1Into(leftCoeff, term.H[comp][outIdx][srcBlock], sourceCoeffs[ti][comp][srcBlock], 1, q)
					}
				}
			}
			rightCoeff := make([]uint64, int(ringQ.N))
			mulModXN1(rightCoeff, cache.Lagrange[lane], yCoeff, q)
			res := append([]uint64(nil), leftCoeff...)
			subInto(res, rightCoeff, q)
			res = trimPoly(res, q)
			coeffs = append(coeffs, res)
			fagg = append(fagg, nttPolyFromFormalCoeffsIfFits(ringQ, res))
		}
	}
	return fagg, coeffs, nil
}

func intGenISISCoeffToHatBridgeFormalCoeffs(ringQ *ring.Ring, rowCache *intGenISISRowCoeffCache, omega []uint64, sourceStart, components, hatStart, rowsPerPoly int, name string) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega for %s bridge", name)
	}
	if sourceStart < 0 || hatStart < 0 || components <= 0 || rowsPerPoly <= 0 {
		return nil, nil, fmt.Errorf("invalid %s bridge layout source=%d hat=%d components=%d rowsPerPoly=%d", name, sourceStart, hatStart, components, rowsPerPoly)
	}
	ncols := len(omega)
	basis, err := newTransformBridgeBasisCache(ringQ, omega, rowsPerPoly*ncols, rowsPerPoly)
	if err != nil {
		return nil, nil, fmt.Errorf("%s bridge basis: %w", name, err)
	}
	q := ringQ.Modulus[0]
	fagg := make([]*ring.Poly, 0, components*rowsPerPoly*ncols)
	coeffs := make([][]uint64, 0, components*rowsPerPoly*ncols)
	for comp := 0; comp < components; comp++ {
		sourceCoeffs := make([][]uint64, rowsPerPoly)
		for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
			coeff, err := rowCache.Row(sourceStart + comp*rowsPerPoly + srcBlock)
			if err != nil {
				return nil, nil, err
			}
			sourceCoeffs[srcBlock] = coeff
		}
		for block := 0; block < rowsPerPoly; block++ {
			hatCoeff, err := rowCache.Row(hatStart + comp*rowsPerPoly + block)
			if err != nil {
				return nil, nil, err
			}
			for lane := 0; lane < ncols; lane++ {
				t := block*ncols + lane
				leftCoeff := make([]uint64, int(ringQ.N))
				for srcBlock := 0; srcBlock < rowsPerPoly; srcBlock++ {
					scale := basis.BlockFactors[t][srcBlock] % q
					addMulModXN1Into(leftCoeff, basis.TransformH[t], sourceCoeffs[srcBlock], scale, q)
				}
				rightCoeff := make([]uint64, int(ringQ.N))
				mulModXN1(rightCoeff, basis.LagrangeBasis[lane], hatCoeff, q)
				bridgeCoeff := append([]uint64(nil), leftCoeff...)
				subInto(bridgeCoeff, rightCoeff, q)
				bridgeCoeff = trimPoly(bridgeCoeff, q)
				coeffs = append(coeffs, bridgeCoeff)
				fagg = append(fagg, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
			}
		}
	}
	return fagg, coeffs, nil
}

type intGenISISProjectedSignaturePlan struct {
	n      int
	ncols  int
	blocks int
	omega  []uint64
	basis  *transformBridgeBasisCache

	aBlockCoeff  [][][]uint64
	aAtOmega     [][][]uint64
	bBlockCoeff  [][][]uint64
	cmBlockCoeff [][]uint64
	cmAtOmega    [][]uint64
	asBlockCoeff [][][]uint64
	asAtOmega    [][][]uint64
}

func newIntGenISISProjectedSignaturePlan(ringQ *ring.Ring, pub PublicInputs, l *IntGenISISShowingRowLayout, basis *transformBridgeBasisCache, omega []uint64) (*intGenISISProjectedSignaturePlan, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if l == nil || basis == nil {
		return nil, fmt.Errorf("missing IntGenISIS projected signature metadata")
	}
	q := ringQ.Modulus[0]
	n := int(ringQ.N)
	ncols := len(omega)
	blocks := l.ViewRowsPerPoly
	if blocks*ncols != n {
		return nil, fmt.Errorf("IntGenISIS projected signature rows/poly*ncols=%d want ringN=%d", blocks*ncols, n)
	}
	out := &intGenISISProjectedSignaturePlan{
		n:            n,
		ncols:        ncols,
		blocks:       blocks,
		omega:        omega,
		basis:        basis,
		aBlockCoeff:  make([][][]uint64, l.UCount),
		aAtOmega:     make([][][]uint64, l.UCount),
		bBlockCoeff:  make([][][]uint64, len(pub.B)),
		cmBlockCoeff: nil,
		cmAtOmega:    nil,
		asBlockCoeff: nil,
		asAtOmega:    nil,
	}
	for i := 0; i < l.UCount; i++ {
		out.aBlockCoeff[i] = make([][]uint64, blocks)
		out.aAtOmega[i] = make([][]uint64, blocks)
		for block := 0; block < blocks; block++ {
			coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.A[0][i], omega, block, blocks, fmt.Sprintf("A[0][%d]", i))
			if err != nil {
				return nil, err
			}
			out.aBlockCoeff[i][block] = coeff
			out.aAtOmega[i][block] = evalCoeffOnOmega(coeff, omega, q)
		}
	}
	for j := range pub.B {
		out.bBlockCoeff[j] = make([][]uint64, blocks)
		for block := 0; block < blocks; block++ {
			coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.B[j], omega, block, blocks, fmt.Sprintf("B[%d]", j))
			if err != nil {
				return nil, err
			}
			out.bBlockCoeff[j][block] = coeff
		}
	}
	if intGenISISProjectionDerivesYView(l) {
		out.cmBlockCoeff = make([][]uint64, blocks)
		out.cmAtOmega = make([][]uint64, blocks)
		for block := 0; block < blocks; block++ {
			coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.CM[0][0], omega, block, blocks, "C_M[0][0]")
			if err != nil {
				return nil, err
			}
			out.cmBlockCoeff[block] = coeff
			out.cmAtOmega[block] = evalCoeffOnOmega(coeff, omega, q)
		}
		out.asBlockCoeff = make([][][]uint64, l.SCount)
		out.asAtOmega = make([][][]uint64, l.SCount)
		for i := 0; i < l.SCount; i++ {
			out.asBlockCoeff[i] = make([][]uint64, blocks)
			out.asAtOmega[i] = make([][]uint64, blocks)
			for block := 0; block < blocks; block++ {
				coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.AS[0][i], omega, block, blocks, fmt.Sprintf("A_s[0][%d]", i))
				if err != nil {
					return nil, err
				}
				out.asBlockCoeff[i][block] = coeff
				out.asAtOmega[i][block] = evalCoeffOnOmega(coeff, omega, q)
			}
		}
	}
	return out, nil
}

func evalCoeffOnOmega(coeff, omega []uint64, q uint64) []uint64 {
	out := make([]uint64, len(omega))
	for i := range omega {
		out[i] = EvalPoly(coeff, omega[i]%q, q) % q
	}
	return out
}

// intGenISISProjectedSignatureFormalCoeffs substitutes the aggregate packed-coeff
// transform into the signature equation. The transform bridge is an Ω-sum
// identity, so public A terms are bound as lane scalars rather than as
// pointwise row polynomials.
func intGenISISProjectedSignatureFormalCoeffs(ringQ *ring.Ring, pub PublicInputs, rowsNTT []*ring.Poly, rowCache *intGenISISRowCoeffCache, l *IntGenISISShowingRowLayout, basis *transformBridgeBasisCache, omega []uint64, yLinearCache *intGenISISYLinearMapCache, compressionSpec intGenISISMSECompressionSpec, phase *PhaseRecorder) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if l == nil || basis == nil {
		return nil, nil, fmt.Errorf("missing IntGenISIS projected signature metadata")
	}
	if len(omega) == 0 || len(basis.LagrangeBasis) != len(omega) {
		return nil, nil, fmt.Errorf("invalid IntGenISIS projected signature omega=%d lagrange=%d", len(omega), len(basis.LagrangeBasis))
	}
	if len(pub.A) != 1 || len(pub.A[0]) != l.UCount || len(pub.B) != 3+l.X0Count {
		return nil, nil, fmt.Errorf("IntGenISIS projected signature public dimensions mismatch")
	}
	q := ringQ.Modulus[0]
	n := int(ringQ.N)
	ncols := len(omega)
	if l.ViewRowsPerPoly*ncols != n {
		return nil, nil, fmt.Errorf("IntGenISIS projected signature rows/poly*ncols=%d want ringN=%d", l.ViewRowsPerPoly*ncols, n)
	}
	stage := func(label string, fn func() error) error {
		start := time.Now()
		err := fn()
		if phase != nil {
			phase.RecordDuration(label, time.Since(start))
		}
		return err
	}
	plan, err := newIntGenISISProjectedSignaturePlan(ringQ, pub, l, basis, omega)
	if err != nil {
		return nil, nil, err
	}
	buildSourceTransform := func(sourceCoeffs [][]uint64, t int) ([]uint64, error) {
		if t < 0 || t >= len(basis.TransformH) || t >= len(basis.BlockFactors) {
			return nil, fmt.Errorf("projected signature transform lane t=%d out of range", t)
		}
		if len(sourceCoeffs) != l.ViewRowsPerPoly {
			return nil, fmt.Errorf("projected signature source blocks=%d want %d", len(sourceCoeffs), l.ViewRowsPerPoly)
		}
		left := make([]uint64, n)
		for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
			scale := basis.BlockFactors[t][srcBlock] % q
			addMulModXN1Into(left, basis.TransformH[t], sourceCoeffs[srcBlock], scale, q)
		}
		return trimPoly(left, q), nil
	}
	buildFlatTransforms := func(sourceCoeffs [][][]uint64) ([][][]uint64, error) {
		out := make([][][]uint64, len(sourceCoeffs))
		for comp := range sourceCoeffs {
			out[comp] = make([][]uint64, l.ViewRowsPerPoly*ncols)
			for t := range out[comp] {
				coeff, err := buildSourceTransform(sourceCoeffs[comp], t)
				if err != nil {
					return nil, err
				}
				out[comp][t] = coeff
			}
		}
		return out, nil
	}
	var ySourceCoeffs [][][][]uint64
	if intGenISISProjectionDerivesYView(l) {
		var yerr error
		ySourceCoeffs, yerr = intGenISISYLinearSourceFormalCoeffs(ringQ, rowsNTT, rowCache, l, yLinearCache, compressionSpec)
		if yerr != nil {
			return nil, nil, yerr
		}
	}
	var uTrans [][][]uint64
	var yTrans [][][][]uint64
	var yViewTrans [][][]uint64
	if err := stage("showing.constraints.projected.transform_cache", func() error {
		uSourceCoeffs := make([][][]uint64, l.UCount)
		for comp := 0; comp < l.UCount; comp++ {
			uSourceCoeffs[comp] = make([][]uint64, l.ViewRowsPerPoly)
			for block := 0; block < l.ViewRowsPerPoly; block++ {
				coeff, err := rowCache.Row(l.UViewStart + comp*l.ViewRowsPerPoly + block)
				if err != nil {
					return err
				}
				uSourceCoeffs[comp][block] = coeff
			}
		}
		var terr error
		uTrans, terr = buildFlatTransforms(uSourceCoeffs)
		if terr != nil {
			return terr
		}
		if intGenISISProjectionDerivesYView(l) {
			yTrans = make([][][][]uint64, len(ySourceCoeffs))
			for ti := range ySourceCoeffs {
				yTrans[ti], terr = buildFlatTransforms(ySourceCoeffs[ti])
				if terr != nil {
					return terr
				}
			}
		} else {
			ySource := [][][]uint64{make([][]uint64, l.ViewRowsPerPoly)}
			for block := 0; block < l.ViewRowsPerPoly; block++ {
				coeff, err := rowCache.Row(l.YViewStart + block)
				if err != nil {
					return err
				}
				ySource[0][block] = coeff
			}
			yViewTrans, terr = buildFlatTransforms(ySource)
			if terr != nil {
				return terr
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	derivedYHatLaneCoeff := func(block, lane int) ([]uint64, error) {
		if len(ySourceCoeffs) != 3 {
			return nil, fmt.Errorf("projected Y source terms=%d want 3", len(ySourceCoeffs))
		}
		t := block*ncols + lane
		left := make([]uint64, n)
		cmVal := plan.cmAtOmega[block][lane]
		addScaledInto(left, yTrans[0][0][t], cmVal, q)
		for i := 0; i < l.SCount; i++ {
			asVal := plan.asAtOmega[i][block][lane]
			addScaledInto(left, yTrans[1][i][t], asVal, q)
		}
		addScaledInto(left, yTrans[2][0][t], 1, q)
		return trimPoly(left, q), nil
	}
	fagg := make([]*ring.Poly, 0, l.ViewRowsPerPoly*ncols)
	coeffs := make([][]uint64, 0, l.ViewRowsPerPoly*ncols)
	if err := stage("showing.constraints.projected.emit", func() error {
		for block := 0; block < l.ViewRowsPerPoly; block++ {
			muCoeff, err := rowCache.Row(l.MuSigHatStart + block)
			if err != nil {
				return err
			}
			x0Coeff := make([][]uint64, l.X0Count)
			for i := 0; i < l.X0Count; i++ {
				x0Coeff[i], err = rowCache.Row(l.X0HatStart + i*l.ViewRowsPerPoly + block)
				if err != nil {
					return err
				}
			}
			zCoeff, err := rowCache.Row(l.ZHatStart + block)
			if err != nil {
				return err
			}
			rhs := make([]uint64, n)
			addScaledInto(rhs, plan.bBlockCoeff[0][block], 1, q)
			addMulModXN1Into(rhs, plan.bBlockCoeff[1][block], muCoeff, 1, q)
			for i := 0; i < l.X0Count; i++ {
				addMulModXN1Into(rhs, plan.bBlockCoeff[2+i][block], x0Coeff[i], 1, q)
			}
			addScaledInto(rhs, zCoeff, 1, q)
			for lane := 0; lane < ncols; lane++ {
				t := block*ncols + lane
				res := make([]uint64, n)
				for i := 0; i < l.UCount; i++ {
					aVal := plan.aAtOmega[i][block][lane]
					addScaledInto(res, uTrans[i][t], aVal, q)
				}
				laneRHS := make([]uint64, n)
				mulModXN1(laneRHS, basis.LagrangeBasis[lane], rhs, q)
				subInto(res, laneRHS, q)
				var yLaneCoeff []uint64
				if intGenISISProjectionDerivesYView(l) {
					var yerr error
					yLaneCoeff, yerr = derivedYHatLaneCoeff(block, lane)
					if yerr != nil {
						return yerr
					}
				} else {
					yLaneCoeff = yViewTrans[0][t]
				}
				subInto(res, yLaneCoeff, q)
				res = trimPoly(res, q)
				coeffs = append(coeffs, res)
				fagg = append(fagg, nttPolyFromFormalCoeffsIfFits(ringQ, res))
			}
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	return fagg, coeffs, nil
}

func buildIntGenISISShowingConstraintSetFromRows(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, prfCompanionLayout *PRFCompanionLayout, phase *PhaseRecorder) (ConstraintSet, error) {
	constraintsStart := time.Now()
	if phase != nil {
		defer func() {
			phase.RecordDuration("showing.constraints.total", time.Since(constraintsStart))
		}()
	}
	stage := func(label string, fn func() error) error {
		start := time.Now()
		err := fn()
		if phase != nil {
			phase.RecordDuration(label, time.Since(start))
		}
		return err
	}
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
	if err := validateIntGenISISShowingPackedLayout(l, len(rowsNTT)); err != nil {
		return ConstraintSet{}, err
	}
	if len(pub.A) != 1 || len(pub.A[0]) != l.UCount {
		return ConstraintSet{}, fmt.Errorf("A dimensions=%dx? want 1x%d", len(pub.A), l.UCount)
	}
	if len(pub.B) != 3+l.X0Count {
		return ConstraintSet{}, fmt.Errorf("B length=%d want %d", len(pub.B), 3+l.X0Count)
	}
	if len(pub.CM) != l.ECount || len(pub.CM[0]) != l.MCount || len(pub.AS) != l.ECount || len(pub.AS[0]) != l.SCount {
		return ConstraintSet{}, fmt.Errorf("commitment public dimensions mismatch")
	}
	q := ringQ.Modulus[0]
	projectedUY := intGenISISProjectionUsesProjectedUYHat(l)
	derivedYView := intGenISISProjectionDerivesYView(l)
	compressedMSE := l.MSECompressionLevel > 0
	compressionSpec := intGenISISMSECompressionSpec{}
	if compressedMSE {
		var cerr error
		compressionSpec, cerr = newIntGenISISMSECompressionSpecForBound(q, l.MSECompressionLevel, pub.BoundB)
		if cerr != nil {
			return ConstraintSet{}, cerr
		}
	}
	var yLinearCache *intGenISISYLinearMapCache
	if err := stage("showing.constraints.y_linear_plan", func() error {
		var yerr error
		yLinearCache, yerr = newIntGenISISYLinearMapCache(ringQ, pub, l, omega)
		return yerr
	}); err != nil {
		return ConstraintSet{}, err
	}
	var rowCache *intGenISISRowCoeffCache
	if err := stage("showing.constraints.projected.row_coeff_cache", func() error {
		var rerr error
		rowCache, rerr = newIntGenISISRowCoeffCache(ringQ, rowsNTT)
		return rerr
	}); err != nil {
		return ConstraintSet{}, err
	}
	coeffs := make([][]uint64, 0, 2*l.ViewRowsPerPoly)
	for block := 0; block < l.ViewRowsPerPoly; block++ {
		zCoeff, err := rowCache.Row(l.ZHatStart + block)
		if err != nil {
			return ConstraintSet{}, err
		}
		if !projectedUY {
			sig := []uint64{0}
			for i := 0; i < l.UCount; i++ {
				aCoeff, err := intGenISISThetaBlockCoeff(ringQ, pub.A[0][i], omega, block, l.ViewRowsPerPoly, fmt.Sprintf("A[0][%d]", i))
				if err != nil {
					return ConstraintSet{}, err
				}
				uCoeff, err := rowCache.Row(l.UHatStart + i*l.ViewRowsPerPoly + block)
				if err != nil {
					return ConstraintSet{}, err
				}
				sig = polyAdd(sig, polyMul(aCoeff, uCoeff, q), q)
			}
			b0, err := intGenISISThetaBlockCoeff(ringQ, pub.B[0], omega, block, l.ViewRowsPerPoly, "B[0]")
			if err != nil {
				return ConstraintSet{}, err
			}
			sig = polySub(sig, b0, q)
			b1, err := intGenISISThetaBlockCoeff(ringQ, pub.B[1], omega, block, l.ViewRowsPerPoly, "B[1]")
			if err != nil {
				return ConstraintSet{}, err
			}
			muCoeff, err := rowCache.Row(l.MuSigHatStart + block)
			if err != nil {
				return ConstraintSet{}, err
			}
			sig = polySub(sig, polyMul(b1, muCoeff, q), q)
			for i := 0; i < l.X0Count; i++ {
				bCoeff, err := intGenISISThetaBlockCoeff(ringQ, pub.B[2+i], omega, block, l.ViewRowsPerPoly, fmt.Sprintf("B[%d]", 2+i))
				if err != nil {
					return ConstraintSet{}, err
				}
				x0Coeff, err := rowCache.Row(l.X0HatStart + i*l.ViewRowsPerPoly + block)
				if err != nil {
					return ConstraintSet{}, err
				}
				sig = polySub(sig, polyMul(bCoeff, x0Coeff, q), q)
			}
			sig = polySub(sig, zCoeff, q)
			yHatCoeff, err := rowCache.Row(l.YHatStart + block)
			if err != nil {
				return ConstraintSet{}, err
			}
			sig = polySub(sig, yHatCoeff, q)
			coeffs = append(coeffs, trimPoly(sig, q))
		}

		b3Coeff, err := intGenISISThetaBlockCoeff(ringQ, pub.B[len(pub.B)-1], omega, block, l.ViewRowsPerPoly, fmt.Sprintf("B[%d]", len(pub.B)-1))
		if err != nil {
			return ConstraintSet{}, err
		}
		x1Coeff, err := rowCache.Row(l.X1HatStart + block)
		if err != nil {
			return ConstraintSet{}, err
		}
		inv := polySub(polyMul(polySub(b3Coeff, x1Coeff, q), zCoeff, q), []uint64{1 % q}, q)
		coeffs = append(coeffs, trimPoly(inv, q))

	}
	keyBindCoeffs := make([][]uint64, 0)
	keyBindPolys := make([]*ring.Poly, 0)
	if err := stage("showing.constraints.key_bind", func() error {
		if prfCompanionLayout != nil && prfCompanionLayout.KeyCount > 0 {
			_, selectorCoeff, err := buildOmegaDeltaSelectors(ringQ, omega)
			if err != nil {
				return fmt.Errorf("key source selectors: %w", err)
			}
			if len(prfCompanionLayout.KeySourceSlots) != len(prfCompanionLayout.KeySlots) {
				return fmt.Errorf("PRF key source slots=%d want key slots=%d", len(prfCompanionLayout.KeySourceSlots), len(prfCompanionLayout.KeySlots))
			}
			for i := 0; i < prfCompanionLayout.KeyCount; i++ {
				if i >= len(prfCompanionLayout.KeySlots) || i >= len(prfCompanionLayout.KeySourceSlots) {
					return fmt.Errorf("PRF key slot %d out of range", i)
				}
				keySlot := prfCompanionLayout.KeySlots[i]
				srcSlot := prfCompanionLayout.KeySourceSlots[i]
				if keySlot.Coeff < 0 || keySlot.Coeff >= len(selectorCoeff) || srcSlot.Coeff < 0 || srcSlot.Coeff >= len(selectorCoeff) {
					return fmt.Errorf("PRF key binding slot out of range")
				}
				keyCoeff, err := rowCache.Row(keySlot.Row)
				if err != nil {
					return fmt.Errorf("PRF key row: %w", err)
				}
				var srcCoeff []uint64
				if len(prfCompanionLayout.KeySourceDecodeLanes) > 0 {
					if i >= len(prfCompanionLayout.KeySourceDecodeLanes) {
						return fmt.Errorf("missing PRF key source decode lane %d", i)
					}
					srcCoeff, err = intGenISISCompressedCarrierLaneFormalCoeff(ringQ, rowsNTT, srcSlot.Row, prfCompanionLayout.KeySourceDecodeLanes[i], compressionSpec.DecodePolys, "PRF key source")
					if err != nil {
						return err
					}
				} else {
					srcCoeff, err = rowCache.Row(srcSlot.Row)
					if err != nil {
						return fmt.Errorf("PRF key source row: %w", err)
					}
				}
				res := make([]uint64, int(ringQ.N))
				addMulModXN1Into(res, selectorCoeff[keySlot.Coeff], keyCoeff, 1, q)
				addMulModXN1Into(res, selectorCoeff[srcSlot.Coeff], srcCoeff, q-1, q)
				res = trimPoly(res, q)
				keyBindCoeffs = append(keyBindCoeffs, res)
				keyBindPolys = append(keyBindPolys, nttPolyFromFormalCoeffsIfFits(ringQ, res))
			}
		}
		return nil
	}); err != nil {
		return ConstraintSet{}, err
	}
	fpar := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		if len(coeffs[i]) <= int(ringQ.N) {
			fpar[i] = nttPolyFromFormalCoeffsIfFits(ringQ, coeffs[i])
		}
	}
	var sigBound int64
	var shortSpec LinfSpec
	nonSigRows := intGenISISViewRowIndices(l.BoundViewStart, l.BoundViewCount)
	var shortPolys []*ring.Poly
	var shortCoeffs [][]uint64
	var boundPolys []*ring.Poly
	var boundCoeffs [][]uint64
	var radixPolys []*ring.Poly
	var radixCoeffs [][]uint64
	if err := stage("showing.constraints.bounds", func() error {
		var berr error
		sigBound, berr = intGenISISSignatureBoundFromPublic(pub)
		if berr != nil {
			return berr
		}
		shortSpec, berr = intGenISISUShortnessLayoutSpec(ringQ, l, sigBound)
		if berr != nil {
			return berr
		}
		if intGenISISUseDirectSignatureRange(sigBound) {
			shortRows := intGenISISViewRowIndices(l.UViewStart, l.UCount*l.ViewRowsPerPoly)
			shortPolys, shortCoeffs, berr = intGenISISRangeMembershipRows(ringQ, rowsNTT, shortRows, sigBound)
			if berr != nil {
				return berr
			}
		}
		if compressedMSE {
			boundPolys, boundCoeffs, berr = intGenISISCompressedCarrierMembershipRows(ringQ, rowsNTT, nonSigRows, compressionSpec)
			if berr != nil {
				return berr
			}
		} else {
			boundPolys, boundCoeffs, berr = intGenISISLiveMembershipRows(ringQ, rowsNTT, nonSigRows, pub.BoundB)
			if berr != nil {
				return berr
			}
		}
		radixPolys, radixCoeffs, berr = intGenISISUShortnessConstraintRows(ringQ, rowsNTT, l, shortSpec)
		return berr
	}); err != nil {
		return ConstraintSet{}, err
	}
	boundPolys = append(shortPolys, boundPolys...)
	boundCoeffs = append(shortCoeffs, boundCoeffs...)
	boundPolys = append(boundPolys, radixPolys...)
	boundCoeffs = append(boundCoeffs, radixCoeffs...)

	bridgePolys := append([]*ring.Poly{}, keyBindPolys...)
	bridgeCoeffs := append([][]uint64{}, keyBindCoeffs...)
	if !derivedYView {
		yPolys, yCoeffs, err := intGenISISYLinearConstraintFormalCoeffs(ringQ, rowsNTT, rowCache, l, yLinearCache, compressionSpec)
		if err != nil {
			return ConstraintSet{}, err
		}
		bridgePolys = append(bridgePolys, yPolys...)
		bridgeCoeffs = append(bridgeCoeffs, yCoeffs...)
	}
	if projectedUY {
		var projectedPolys []*ring.Poly
		var projectedCoeffs [][]uint64
		if err := stage("showing.constraints.projected_signature", func() error {
			basis, berr := newTransformBridgeBasisCache(ringQ, omega, l.ViewRowsPerPoly*len(omega), l.ViewRowsPerPoly)
			if berr != nil {
				return fmt.Errorf("IntGenISIS projected signature bridge basis: %w", berr)
			}
			var perr error
			projectedPolys, projectedCoeffs, perr = intGenISISProjectedSignatureFormalCoeffs(ringQ, pub, rowsNTT, rowCache, l, basis, omega, yLinearCache, compressionSpec, phase)
			return perr
		}); err != nil {
			return ConstraintSet{}, err
		}
		bridgePolys = append(bridgePolys, projectedPolys...)
		bridgeCoeffs = append(bridgeCoeffs, projectedCoeffs...)
	} else {
		for _, bridge := range []struct {
			name       string
			source     int
			components int
			hat        int
			compressed bool
		}{
			{"u", l.UViewStart, l.UCount, l.UHatStart, false},
			{"Y", l.YViewStart, 1, l.YHatStart, false},
		} {
			source := bridge.source
			if bridge.compressed {
				switch bridge.name {
				case "M":
					source = l.MCarrierStart
				case "s":
					source = l.SCarrierStart
				case "e":
					source = l.ECarrierStart
				}
			}
			var polys []*ring.Poly
			var coeffs [][]uint64
			var berr error
			if bridge.compressed {
				polys, coeffs, berr = intGenISISCompressedCoeffToHatBridgeFormalCoeffs(ringQ, rowsNTT, omega, source, bridge.components, bridge.hat, l.ViewRowsPerPoly, l.MSECompressionPackWidth, compressionSpec.DecodePolys, bridge.name)
			} else {
				polys, coeffs, berr = intGenISISCoeffToHatBridgeFormalCoeffs(ringQ, rowCache, omega, source, bridge.components, bridge.hat, l.ViewRowsPerPoly, bridge.name)
			}
			if berr != nil {
				return ConstraintSet{}, berr
			}
			bridgePolys = append(bridgePolys, polys...)
			bridgeCoeffs = append(bridgeCoeffs, coeffs...)
		}
	}
	shortDegree, err := signatureShortnessMaxDegree(shortSpec, SimOpts{})
	if err != nil {
		return ConstraintSet{}, err
	}
	shortDegree = maxInt(shortDegree, intGenISISDirectSignatureRangeDegree(sigBound))
	return ConstraintSet{
		FparInt:          fpar,
		FparIntCoeffs:    coeffs,
		FparNorm:         boundPolys,
		FparNormCoeffs:   boundCoeffs,
		FaggNorm:         bridgePolys,
		FaggNormCoeffs:   bridgeCoeffs,
		ParallelAlgDeg:   maxInt(maxInt(2, intGenISISMembershipDegree(pub.BoundB)), maxInt(shortDegree, compressionSpec.Descriptor.MembershipDeg)),
		AggregatedAlgDeg: maxInt(2, compressionSpec.Descriptor.DecodeDegree),
	}, nil
}

func rejectIntGenISISUnsafeSigLookup(opts SimOpts) error {
	if sigLookupShadowR121L2EnabledForOpts(opts) {
		return fmt.Errorf("IntGenISIS showing does not support unsafe R121/L2 signature lookup shadow mode")
	}
	if opts.SigShortnessRadix == sigLookupShadowR121L2Radix && opts.SigShortnessL == sigLookupShadowR121L2Digits {
		return fmt.Errorf("IntGenISIS showing does not support R121/L2 signature shortness overrides")
	}
	return nil
}

func BuildIntGenISISShowingCombined(pub PublicInputs, wit WitnessInputs, opts SimOpts) (*Proof, error) {
	opts.applyDefaults()
	if err := rejectIntGenISISUnsafeSigLookup(opts); err != nil {
		return nil, err
	}
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
		pub, err = bindIntGenISISPublicExtrasWithOpts(pub, int(ringQ.N), opts)
		if err != nil {
			return nil, err
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
		rowsStart := time.Now()
		rows, rowInputs, layout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, builtNCols, err := BuildCredentialRowsShowingIntGenISIS(ringQ, pub, wit, params.LenKey, params.LenNonce, params.RF, params.RP, groupRounds, opts)
		if opts.PhaseRecorder != nil {
			opts.PhaseRecorder.RecordDuration("showing.rows", time.Since(rowsStart))
		}
		if err != nil {
			return nil, fmt.Errorf("build IntGenISIS showing rows: %w", err)
		}
		requiredPCSNCols := requiredExplicitPCSNColsForRows(ringQ, rowInputs, opts.Ell)
		if requiredPCSNCols > pcsNCols {
			opts = bumpExplicitPCSNCols(opts, requiredPCSNCols)
			continue
		}
		rowsNTTStart := time.Now()
		rowsNTT := make([]*ring.Poly, len(rows))
		for i := range rows {
			rowsNTT[i] = ringQ.NewPoly()
			ring.Copy(rows[i], rowsNTT[i])
			ringQ.NTT(rowsNTT[i], rowsNTT[i])
		}
		if opts.PhaseRecorder != nil {
			opts.PhaseRecorder.RecordDuration("showing.rows_ntt", time.Since(rowsNTTStart))
		}
		postSet, err := buildIntGenISISShowingConstraintSetFromRows(ringQ, pub, layout, rowsNTT, omega[:builtNCols], prfCompanionLayout, opts.PhaseRecorder)
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
			omegaWitness:          append([]uint64(nil), omega[:builtNCols]...),
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
	opts.applyDefaults()
	if err := rejectIntGenISISUnsafeSigLookup(opts); err != nil {
		return false, err
	}
	pub.IntGenISIS = true
	ringN := pub.RingDegree
	if ringN == 0 && proof.RowLayout.RingDegree > 0 {
		ringN = proof.RowLayout.RingDegree
	}
	var err error
	pub, err = bindIntGenISISPublicExtrasWithOpts(pub, ringN, opts)
	if err != nil {
		return false, err
	}
	if err := validateIntGenISISProofDegreeMetadata(proof, pub, opts); err != nil {
		return false, err
	}
	verifySet := ConstraintSet{}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	return VerifyWithConstraints(proof, verifySet, pub, opts, FSModeCredential)
}
