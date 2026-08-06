package PIOP

import (
	"fmt"
	"reflect"

	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// validateIntGenISISVerifierOptionsV2 rejects underspecified verifier
// configuration. A v2 verifier is configured by trusted public parameters and
// a preset; no proof field is allowed to fill in a missing option.
func validateIntGenISISVerifierOptionsV2(pub PublicInputs, opts SimOpts) error {
	if err := validateIntGenISISV2TranscriptOpts(opts); err != nil {
		return err
	}
	if pub.RingDegree <= 0 {
		return fmt.Errorf("PIOP: missing trusted IntGenISIS public ring degree")
	}
	if opts.RingDegree != pub.RingDegree {
		return fmt.Errorf("PIOP: verifier ring_degree=%d want trusted public ring_degree=%d", opts.RingDegree, pub.RingDegree)
	}
	if opts.NCols <= 0 || opts.LVCSNCols <= 0 || opts.NLeaves <= 0 {
		return fmt.Errorf("PIOP: verifier requires explicit ncols, lvcs_ncols, and nleaves")
	}
	if opts.PCSNCols > 0 && opts.PCSNCols != opts.LVCSNCols {
		return fmt.Errorf("PIOP: verifier pcs_ncols=%d differs from lvcs_ncols=%d", opts.PCSNCols, opts.LVCSNCols)
	}
	if opts.LVCSNCols < opts.NCols {
		return fmt.Errorf("PIOP: verifier lvcs_ncols=%d below witness ncols=%d", opts.LVCSNCols, opts.NCols)
	}
	if opts.DomainMode != DomainModeExplicit {
		return fmt.Errorf("PIOP: verifier requires the explicit v2 domain")
	}
	if opts.Theta <= 1 || opts.Rho != 1 || opts.EllPrime != 1 || opts.Ell <= 0 || opts.Eta <= 0 {
		return fmt.Errorf("PIOP: invalid v2 SmallWood geometry theta=%d rho=%d ell_prime=%d ell=%d eta=%d", opts.Theta, opts.Rho, opts.EllPrime, opts.Ell, opts.Eta)
	}
	if opts.NCols > pub.RingDegree || pub.RingDegree%opts.NCols != 0 {
		return fmt.Errorf("PIOP: witness ncols=%d does not divide ring degree=%d", opts.NCols, pub.RingDegree)
	}
	return nil
}

func expectedIntGenISISPreSignLayoutV2(ringQ *ring.Ring, pub PublicInputs, opts SimOpts) (RowLayout, error) {
	if ringQ == nil {
		return RowLayout{}, fmt.Errorf("PIOP: nil ring")
	}
	if intGenISISOptsUseStructuralV3(opts) {
		return expectedIntGenISISPreSignSourceOnlyLayoutV3(ringQ, pub, opts)
	}
	if len(pub.Com) == 0 || len(pub.CM) != len(pub.Com) || len(pub.AS) != len(pub.Com) {
		return RowLayout{}, fmt.Errorf("PIOP: malformed trusted commitment geometry")
	}
	mCount := len(pub.CM[0])
	sCount := len(pub.AS[0])
	if mCount <= 0 || sCount <= 0 {
		return RowLayout{}, fmt.Errorf("PIOP: empty trusted commitment matrix row")
	}
	for i := range pub.Com {
		if len(pub.CM[i]) != mCount || len(pub.AS[i]) != sCount {
			return RowLayout{}, fmt.Errorf("PIOP: ragged trusted commitment matrix row %d", i)
		}
	}
	x0Len, err := intGenISISX0LenFromPublic(pub)
	if err != nil {
		return RowLayout{}, err
	}
	rpp := int(ringQ.N) / opts.NCols
	eCount := len(pub.Com)
	coreRows := 3*mCount + sCount + eCount
	cursor := coreRows
	mViewStart := cursor
	cursor += mCount * rpp
	mAttrViewStart := cursor
	cursor += mCount * rpp
	kViewStart := cursor
	cursor += mCount * rpp
	sViewStart := cursor
	cursor += sCount * rpp
	eViewStart := cursor
	cursor += eCount * rpp

	return RowLayout{
		RingDegree: int(ringQ.N),
		SigCount:   cursor,
		X0Len:      x0Len,
		IntGenISISPreSign: &IntGenISISPreSignRowLayout{
			MStart:          0,
			MCount:          mCount,
			MAttrStart:      mCount,
			MAttrCount:      mCount,
			KStart:          2 * mCount,
			KCount:          mCount,
			SStart:          3 * mCount,
			SCount:          sCount,
			EStart:          3*mCount + sCount,
			ECount:          eCount,
			CoreRowCount:    coreRows,
			BoundViewStart:  mViewStart,
			BoundViewCount:  cursor - mViewStart,
			MViewStart:      mViewStart,
			MAttrViewStart:  mAttrViewStart,
			KViewStart:      kViewStart,
			SViewStart:      sViewStart,
			EViewStart:      eViewStart,
			ViewRowsPerPoly: rpp,
			CommitmentRows:  eCount,
		},
	}, nil
}

func expectedIntGenISISShowingLayoutsV2(ringQ *ring.Ring, pub PublicInputs, opts SimOpts) (RowLayout, *PRFCompanionLayout, error) {
	if ringQ == nil {
		return RowLayout{}, nil, fmt.Errorf("PIOP: nil ring")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 || len(pub.CM) == 0 || len(pub.AS) != len(pub.CM) {
		return RowLayout{}, nil, fmt.Errorf("PIOP: malformed trusted showing matrices")
	}
	uCount := len(pub.A[0])
	mCount := len(pub.CM[0])
	sCount := len(pub.AS[0])
	eCount := len(pub.CM)
	if mCount != 1 || sCount <= 0 || eCount <= 0 {
		return RowLayout{}, nil, fmt.Errorf("PIOP: unsupported trusted showing dimensions m=%d s=%d e=%d", mCount, sCount, eCount)
	}
	for i := range pub.CM {
		if len(pub.CM[i]) != mCount || len(pub.AS[i]) != sCount {
			return RowLayout{}, nil, fmt.Errorf("PIOP: ragged trusted showing matrix row %d", i)
		}
	}
	x0Count, err := intGenISISX0LenFromPublic(pub)
	if err != nil {
		return RowLayout{}, nil, err
	}
	if len(pub.B) != 3+x0Count {
		return RowLayout{}, nil, fmt.Errorf("PIOP: trusted B length=%d want=%d", len(pub.B), 3+x0Count)
	}
	sigBound, err := intGenISISSignatureBoundFromPublic(pub)
	if err != nil {
		return RowLayout{}, nil, err
	}
	shortSpec, err := intGenISISUShortnessSpecForOpts(ringQ.Modulus[0], sigBound, opts)
	if err != nil {
		return RowLayout{}, nil, err
	}
	compression, err := intGenISISMSECompressionDescriptorForBound(opts.IntGenISISMSECompression, pub.BoundB)
	if err != nil {
		return RowLayout{}, nil, err
	}
	rpp := int(ringQ.N) / opts.NCols
	structuralV3 := intGenISISOptsUseStructuralV3(opts)
	if structuralV3 && opts.NCols != prfInputTraceV3PackWidth {
		return RowLayout{}, nil, fmt.Errorf("PIOP: strict v3 showing requires ncols=%d", prfInputTraceV3PackWidth)
	}
	projection := normalizeIntGenISISReplayProjection(opts.IntGenISISReplayProjection)
	digitOnlyU := projection == IntGenISISReplayProjectionProjectUDigitsYViewV3 || projection == IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
	projectedUY := digitOnlyU
	derivedYView := digitOnlyU
	layoutVersion := intGenISISShowingLayoutVersionYLinearBoundedV2
	layoutProjection := ""
	switch projection {
	case IntGenISISReplayProjectionNone:
	case IntGenISISReplayProjectionProjectUDigitsYViewV3:
		layoutVersion = intGenISISShowingLayoutVersionProjectionUDigitsYViewBoundedV4
		layoutProjection = projection
	case IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6:
		layoutVersion = intGenISISShowingLayoutVersionProjectionUDigitsYBoundedSourcesV6
		layoutProjection = projection
	default:
		return RowLayout{}, nil, fmt.Errorf("PIOP: unsupported verifier replay projection %q", projection)
	}
	if structuralV3 {
		if projection != IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6 {
			return RowLayout{}, nil, fmt.Errorf("PIOP: strict v3 showing requires replay projection %q", IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6)
		}
		layoutVersion = intGenISISShowingLayoutVersionInputTraceCarrierV3
	}

	cursor := 0
	uViewStart := -1
	uShortnessSourceRows := 0
	if !digitOnlyU {
		uViewStart = cursor
		uShortnessSourceRows = uCount * rpp
		cursor += uShortnessSourceRows
	}
	uShortnessStart := cursor
	cursor += uCount * rpp * shortSpec.L
	boundViewStart := cursor

	mViewStart, sViewStart, eViewStart := -1, -1, -1
	mCarrierStart, sCarrierStart, eCarrierStart := -1, -1, -1
	mCarrierCount, sCarrierCount, eCarrierCount := 0, 0, 0
	mCompressedSourceRows, mSeedViewStart, mSeedViewCount := 0, -1, 0
	if compression.Level > 0 {
		ordinaryRows := (int(ringQ.N) - credential.IntGenISISPRFSeedTailReserve) / opts.NCols
		if ordinaryRows <= 0 || ordinaryRows >= rpp || ordinaryRows*opts.NCols != int(ringQ.N)-credential.IntGenISISPRFSeedTailReserve {
			return RowLayout{}, nil, fmt.Errorf("PIOP: invalid verifier Pack9 seed-tail geometry")
		}
		mCompressedSourceRows = ordinaryRows
		mCarrierStart = cursor
		mCarrierCount = intGenISISCompressedCarrierCount(ordinaryRows, compression.PackWidth)
		cursor += mCarrierCount
		mSeedViewStart = cursor
		mSeedViewCount = rpp - ordinaryRows
		cursor += mSeedViewCount
		sCarrierStart = cursor
		sCarrierCount = intGenISISCompressedCarrierCount(sCount*rpp, compression.PackWidth)
		cursor += sCarrierCount
		eCarrierStart = cursor
		eCarrierCount = intGenISISCompressedCarrierCount(eCount*rpp, compression.PackWidth)
		cursor += eCarrierCount
	} else {
		mViewStart = cursor
		cursor += rpp
		sViewStart = cursor
		cursor += sCount * rpp
		eViewStart = cursor
		cursor += eCount * rpp
	}
	muSigViewStart, x0ViewStart, x1ViewStart := -1, -1, -1
	muSigCarrierStart, x0CarrierStart, x1CarrierStart := -1, -1, -1
	muSigCarrierCount, x0CarrierCount, x1CarrierCount := 0, 0, 0
	if structuralV3 {
		if rpp%ternaryCarrierV3PackWidth != 0 || x0Count*rpp%ternaryCarrierV3PackWidth != 0 {
			return RowLayout{}, nil, fmt.Errorf("PIOP: strict v3 hash source rows are not pair-packable")
		}
		muSigCarrierStart = cursor
		muSigCarrierCount = rpp / ternaryCarrierV3PackWidth
		cursor += muSigCarrierCount
		x0CarrierStart = cursor
		x0CarrierCount = x0Count * rpp / ternaryCarrierV3PackWidth
		cursor += x0CarrierCount
		x1CarrierStart = cursor
		x1CarrierCount = rpp / ternaryCarrierV3PackWidth
		cursor += x1CarrierCount
	} else {
		muSigViewStart = cursor
		cursor += rpp
		x0ViewStart = cursor
		cursor += x0Count * rpp
		x1ViewStart = cursor
		cursor += rpp
	}
	boundViewCount := cursor - boundViewStart

	yViewStart, yViewCount := -1, 0
	if !derivedYView {
		yViewStart = cursor
		yViewCount = rpp
		cursor += rpp
	}
	uHatStart, uHatCount, yHatStart, yHatCount := -1, 0, -1, 0
	if !projectedUY {
		uHatStart = cursor
		uHatCount = uCount * rpp
		cursor += uHatCount
		yHatStart = cursor
		yHatCount = rpp
		cursor += yHatCount
	}
	muSigHatStart, muSigHatCount := -1, 0
	x0HatStart, x0HatCount := -1, 0
	if !structuralV3 {
		muSigHatStart = cursor
		muSigHatCount = rpp
		cursor += muSigHatCount
		x0HatStart = cursor
		x0HatCount = x0Count * rpp
		cursor += x0HatCount
	}
	x1HatStart := cursor
	x1HatCount := rpp
	cursor += x1HatCount
	zHatStart := cursor
	zHatCount := rpp
	cursor += zHatCount

	var companion *PRFCompanionLayout
	prfInputTraceStart, prfInputTraceRows := -1, 0
	prfInputTraceLogical, prfInputTracePadding, prfInputTraceTagCount := 0, 0, 0
	if structuralV3 {
		prfInputTraceStart = cursor
		payload, perr := canonicalPRFInputTraceV3Layout(cursor, len(pub.Tag))
		if perr != nil {
			return RowLayout{}, nil, perr
		}
		prfInputTraceRows = payload.PackedRows
		prfInputTraceLogical = payload.LogicalScalars
		prfInputTracePadding = payload.PaddingScalars
		prfInputTraceTagCount = len(pub.Tag)
		cursor += payload.PackedRows
	} else {
		var companionRows int
		companion, companionRows, err = expectedPRFCompanionLayoutV2(ringQ, pub, opts, cursor, mViewStart, mSeedViewStart, compression.Level > 0)
		if err != nil {
			return RowLayout{}, nil, err
		}
		cursor += companionRows
	}
	l := &IntGenISISShowingRowLayout{
		LayoutVersion:    layoutVersion,
		ReplayProjection: layoutProjection,
		LinearHatSourceMode: func() string {
			if structuralV3 {
				return intGenISISLinearHatSourceMuX0AggregateFused
			}
			return ""
		}(),
		UStart:     -1,
		UCount:     uCount,
		MStart:     -1,
		MCount:     1,
		MAttrStart: -1,
		MAttrCount: 1,
		KStart:     -1,
		KCount:     1,
		SStart:     -1,
		SCount:     sCount,
		EStart:     -1,
		ECount:     eCount,
		MuSigStart: func() int {
			if structuralV3 {
				return muSigCarrierStart
			}
			return muSigViewStart
		}(),
		MuSigCount: 1,
		X0Start: func() int {
			if structuralV3 {
				return x0CarrierStart
			}
			return x0ViewStart
		}(),
		X0Count: x0Count,
		X1Start: func() int {
			if structuralV3 {
				return x1CarrierStart
			}
			return x1ViewStart
		}(),
		X1Count:                    1,
		ZStart:                     -1,
		ZCount:                     1,
		BoundViewStart:             boundViewStart,
		BoundViewCount:             boundViewCount,
		MSECompressionLevel:        compression.Level,
		MSECompressionPackWidth:    compression.PackWidth,
		MSECompressionAlphabet:     compression.Alphabet,
		MSECompressionDecodeDegree: compression.DecodeDegree,
		MCarrierStart:              mCarrierStart,
		MCarrierCount:              mCarrierCount,
		MCompressedSourceRows:      mCompressedSourceRows,
		MSeedViewStart:             mSeedViewStart,
		MSeedViewCount:             mSeedViewCount,
		SCarrierStart:              sCarrierStart,
		SCarrierCount:              sCarrierCount,
		ECarrierStart:              eCarrierStart,
		ECarrierCount:              eCarrierCount,
		MSECarrierCount:            mCarrierCount + sCarrierCount + eCarrierCount,
		HashSourceCarrierV3:        structuralV3,
		HashCarrierPackWidth: func() int {
			if structuralV3 {
				return ternaryCarrierV3PackWidth
			}
			return 0
		}(),
		HashCarrierDecodeDegree: func() int {
			if structuralV3 {
				return ternaryCarrierV3Alphabet - 1
			}
			return 0
		}(),
		HashCarrierMembershipDegree: func() int {
			if structuralV3 {
				return ternaryCarrierV3Alphabet
			}
			return 0
		}(),
		MuSigCarrierStart:         muSigCarrierStart,
		MuSigCarrierCount:         muSigCarrierCount,
		X0CarrierStart:            x0CarrierStart,
		X0CarrierCount:            x0CarrierCount,
		X1CarrierStart:            x1CarrierStart,
		X1CarrierCount:            x1CarrierCount,
		UViewStart:                uViewStart,
		UShortnessStart:           uShortnessStart,
		UShortnessGroupCount:      uCount * rpp,
		UShortnessRowsPerGroup:    shortSpec.L,
		UShortnessRadix:           int(shortSpec.R),
		UShortnessDigits:          shortSpec.L,
		UShortnessSourceViewStart: uViewStart,
		UShortnessSourceViewRows:  uShortnessSourceRows,
		UShortnessCapacity:        int64(shortSpec.MaxAbs),
		UShortnessProofMode:       intGenISISUShortnessMode,
		MViewStart:                mViewStart,
		MAttrViewStart:            -1,
		KViewStart:                -1,
		SViewStart:                sViewStart,
		EViewStart:                eViewStart,
		YViewStart:                yViewStart,
		YViewCount:                yViewCount,
		MuSigViewStart:            muSigViewStart,
		X0ViewStart:               x0ViewStart,
		X1ViewStart:               x1ViewStart,
		ZViewStart:                -1,
		UHatStart:                 uHatStart,
		UHatCount:                 uHatCount,
		MHatStart:                 -1,
		SHatStart:                 -1,
		EHatStart:                 -1,
		YHatStart:                 yHatStart,
		YHatCount:                 yHatCount,
		MuSigHatStart:             muSigHatStart,
		MuSigHatCount:             muSigHatCount,
		X0HatStart:                x0HatStart,
		X0HatCount:                x0HatCount,
		WHatStart:                 -1,
		X1HatStart:                x1HatStart,
		X1HatCount:                x1HatCount,
		ZHatStart:                 zHatStart,
		ZHatCount:                 zHatCount,
		PRFInputTraceV3Start:      prfInputTraceStart,
		PRFInputTraceV3Rows:       prfInputTraceRows,
		PRFInputTraceV3Logical:    prfInputTraceLogical,
		PRFInputTraceV3Padding:    prfInputTracePadding,
		PRFInputTraceV3TagCount:   prfInputTraceTagCount,
		HatRowsPerPoly:            rpp,
		ViewRowsPerPoly:           rpp,
		CoreRowCount:              0,
	}
	return RowLayout{
		RingDegree:         int(ringQ.N),
		SigCount:           cursor,
		X0Len:              x0Count,
		HasExplicitBaseIdx: true,
		IntGenISISShowing:  l,
	}, companion, nil
}

func expectedPRFCompanionLayoutV2(ringQ *ring.Ring, pub PublicInputs, opts SimOpts, startRow, mViewStart, mSeedViewStart int, compressed bool) (*PRFCompanionLayout, int, error) {
	mode := normalizePRFCompanionMode(opts.PRFCompanionMode)
	if mode != PRFCompanionModeDirectFull {
		return nil, 0, fmt.Errorf("PIOP: verifier requires PRF companion mode %q, got %q", PRFCompanionModeDirectFull, mode)
	}
	params, err := loadBoundPRFParamsForOpts(opts)
	if err != nil {
		return nil, 0, fmt.Errorf("PIOP: load PRF params: %w", err)
	}
	if len(pub.Context) != prf.ContextLaneCountV2 || len(pub.ContextDigest) != 32 || len(pub.Tag) != params.LenTag {
		return nil, 0, fmt.Errorf("PIOP: invalid trusted v2 context/tag shape")
	}
	groupRounds := opts.PRFGroupRounds
	if groupRounds <= 0 {
		return nil, 0, fmt.Errorf("PIOP: missing verifier PRF group-round count")
	}
	zeroKey := make([]prf.Elem, params.LenKey)
	zeroContext := make([]prf.Elem, prf.ContextLaneCountV2)
	grouped, err := prf.TraceGroupedWitnessContextSlot(zeroKey, zeroContext, 0, params, groupRounds)
	if err != nil {
		return nil, 0, fmt.Errorf("PIOP: derive verifier PRF layout: %w", err)
	}
	packed, err := packPRFCompanionWitnessRows(
		ringQ,
		opts.NCols,
		startRow,
		mode,
		true,
		zeroKey,
		0,
		[4]prf.Elem{},
		grouped,
		func([]uint64) *ring.Poly { return ringQ.NewPoly() },
	)
	if err != nil {
		return nil, 0, err
	}
	var keySourceSlots []CoeffSlot
	if compressed {
		keySourceSlots, err = intGenISISSeedSourceTailViewSlots(mSeedViewStart, opts.NCols, int(ringQ.N))
	} else {
		keySourceSlots, err = intGenISISSeedSourceViewSlots(mViewStart, opts.NCols, int(ringQ.N))
	}
	if err != nil {
		return nil, 0, err
	}
	dataSlots := append([]CoeffSlot(nil), packed.KeySlots...)
	dataSlots = append(dataSlots, packed.HiddenSlotSlot)
	dataSlots = append(dataSlots, packed.HiddenSlotBitSlots[:]...)
	dataSlots = append(dataSlots, packed.CheckpointSlots...)
	dataSlots = append(dataSlots, packed.FinalRoundOutputSlots...)
	dataRows := len(uniqueRowsFromCoeffSlots(dataSlots))
	helperRows := maxInt(len(packed.Rows)-dataRows, 0)
	semantics := make([]RowSemantics, len(packed.Rows))
	for i := range semantics {
		semantics[i] = CoeffPackedRow
	}
	return &PRFCompanionLayout{
		StartRow:              startRow,
		PackWidth:             opts.NCols,
		GroupRounds:           groupRounds,
		KeySource:             KeySourceIndependentWitness,
		KeySourceMode:         PRFKeySourceModePack9Seed,
		KeySlots:              packed.KeySlots,
		HiddenSlotSlot:        packed.HiddenSlotSlot,
		HiddenSlotBitSlots:    packed.HiddenSlotBitSlots,
		KeySourceSlots:        keySourceSlots,
		CheckpointSlots:       packed.CheckpointSlots,
		FinalRoundOutputSlots: packed.FinalRoundOutputSlots,
		FinalTagSlots:         packed.FinalTagSlots,
		HelperFamilies:        []string{"final_tag_state"},
		ReplayRows:            len(packed.Rows),
		PackedRows:            len(packed.Rows),
		PackedLogicalCount:    packed.TotalLogicalScalars,
		HelperRowCount:        helperRows,
		DataRows:              dataRows,
		HelperRows:            helperRows,
		KeyCount:              len(packed.KeySlots),
		HiddenSlotCount:       1,
		HiddenSlotBitCount:    len(packed.HiddenSlotBitSlots),
		CheckpointCount:       len(packed.CheckpointSlots),
		FinalRoundOutputCount: len(packed.FinalRoundOutputSlots),
		TagCount:              len(pub.Tag),
		RelationVersion:       prfCompanionRelationVersion(mode),
		RowSemantics:          semantics,
	}, len(packed.Rows), nil
}

func validateIntGenISISProofEnvelopeV2(proof *Proof, expectedLayout RowLayout, expectedCompanion *PRFCompanionLayout, pub PublicInputs, opts SimOpts) error {
	if proof == nil {
		return fmt.Errorf("PIOP: nil proof")
	}
	expectedSchema := proofSchemaVersionForTranscript(opts.TranscriptVersion)
	if proof.SchemaVersion != expectedSchema {
		return fmt.Errorf("PIOP: proof schema=%d want=%d; no migration, rerun setup and issuance", proof.SchemaVersion, expectedSchema)
	}
	if proof.RingDegree != pub.RingDegree || proof.RowLayout.RingDegree != pub.RingDegree {
		return fmt.Errorf("PIOP: proof ring geometry does not match trusted ring degree %d", pub.RingDegree)
	}
	if proof.HashRelation != pub.HashRelation || proof.HashRelation != credential.HashRelationBBTran {
		return fmt.Errorf("PIOP: proof hash relation %q does not match trusted BB-tran relation", proof.HashRelation)
	}
	if proof.TranscriptVersion != opts.TranscriptVersion || proof.TranscriptProtocolMode != opts.TranscriptProtocolMode ||
		!transcriptUsesStrictSmallField2025(proof.TranscriptVersion, proof.TranscriptProtocolMode) {
		return fmt.Errorf("PIOP: proof transcript tuple does not match the verifier-selected strict tuple")
	}
	if proof.FixedTranscriptSize != opts.FixedTranscriptSize {
		return fmt.Errorf("PIOP: proof fixed-transcript flag does not match verifier options")
	}
	if proof.Lambda != opts.Lambda || proof.Kappa != opts.Kappa || proof.Theta != opts.Theta {
		return fmt.Errorf("PIOP: proof Fiat-Shamir parameters do not match verifier options")
	}
	wantFSOutputBits, err := ResolveFSOutputBits(opts)
	if err != nil {
		return fmt.Errorf("PIOP: verifier Fiat-Shamir policy: %w", err)
	}
	if err := ValidatePublicationV4Widths(opts); err != nil {
		return fmt.Errorf("PIOP: verifier Fiat-Shamir policy: %w", err)
	}
	if err := ValidateAggregateROQueryBudget(opts); err != nil {
		return fmt.Errorf("PIOP: verifier Fiat-Shamir policy: %w", err)
	}
	if transcriptUsesPublicationV4(opts.TranscriptVersion) && proof.FSOutputBits != wantFSOutputBits {
		return fmt.Errorf("PIOP: proof FS output bits=%d want manifest-bound %d", proof.FSOutputBits, wantFSOutputBits)
	}
	if !transcriptUsesPublicationV4(opts.TranscriptVersion) && proof.FSOutputBits != 0 && proof.FSOutputBits != wantFSOutputBits {
		return fmt.Errorf("PIOP: historical proof FS output bits=%d want zero or %d", proof.FSOutputBits, wantFSOutputBits)
	}
	if transcriptUsesPublicationV4(opts.TranscriptVersion) {
		if err := validateProofFSDigestWidths(proof); err != nil {
			return fmt.Errorf("PIOP: %w", err)
		}
	}
	if len(proof.Salt) != fsSaltBytesForOpts(opts) {
		return fmt.Errorf("PIOP: proof salt width=%d want=%d", len(proof.Salt), fsSaltBytesForOpts(opts))
	}
	if proof.NColsUsed != opts.NCols || proof.PCSNColsUsed != opts.LVCSNCols || proof.LVCSNColsUsed != opts.LVCSNCols ||
		proof.NLeavesUsed != opts.NLeaves || proof.DomainMode != opts.DomainMode {
		return fmt.Errorf("PIOP: proof PCS/domain tuple does not match verifier options")
	}
	if len(proof.Tail) != opts.Ell {
		return fmt.Errorf("PIOP: proof tail count=%d want ell=%d", len(proof.Tail), opts.Ell)
	}
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		if proof.PRFCompanion != nil || proof.SourceProductBridge != nil {
			return fmt.Errorf("PIOP: v3 proof carries forbidden PRF/source-product bridge auxiliary")
		}
		if len(proof.LabelsDigest) != 0 {
			return fmt.Errorf("PIOP: v3 proof carries forbidden labels digest")
		}
		if len(proof.Chi) != 0 || len(proof.Zeta) != 0 || len(proof.QCoeffDebug) != 0 ||
			len(proof.MaskCoeffDebug) != 0 || len(proof.FparCoeffDebug) != 0 ||
			len(proof.FaggCoeffDebug) != 0 || len(proof.MKData) != 0 || len(proof.QKData) != 0 {
			return fmt.Errorf("PIOP: v3 proof carries forbidden field/debug polynomial material")
		}
		expectedRowDegree := opts.LVCSNCols + opts.Ell - 1
		if proof.RowDegreeBound != expectedRowDegree {
			return fmt.Errorf("PIOP: proof row_degree_bound=%d want verifier-derived %d", proof.RowDegreeBound, expectedRowDegree)
		}
	} else if len(proof.LabelsDigest) != 32 {
		return fmt.Errorf("PIOP: proof labels digest width=%d want=32", len(proof.LabelsDigest))
	}
	if !reflect.DeepEqual(proof.RowLayout, expectedLayout) {
		return fmt.Errorf("PIOP: proof row layout does not match the verifier-derived v2 relation layout")
	}
	if proof.PRFLayout != nil {
		return fmt.Errorf("PIOP: retired PRF layout is not accepted in v2")
	}
	if expectedCompanion == nil {
		if proof.PRFCompanion != nil {
			return fmt.Errorf("PIOP: pre-sign proof contains an unexpected PRF companion")
		}
	} else {
		if proof.PRFCompanion == nil || proof.PRFCompanion.Layout == nil {
			return fmt.Errorf("PIOP: showing proof is missing the required v2 PRF companion")
		}
		if proof.PRFCompanion.Mode != PRFCompanionModeDirectFull || !proof.PRFCompanion.BridgeInQ ||
			proof.PRFCompanion.CheckpointSamples != opts.PRFCheckpointSamples {
			return fmt.Errorf("PIOP: proof PRF companion mode does not match verifier options")
		}
		if !reflect.DeepEqual(proof.PRFCompanion.Layout, expectedCompanion) {
			return fmt.Errorf("PIOP: proof PRF companion layout does not match the verifier-derived v2 layout")
		}
	}
	if proof.PCSOpening == nil {
		return fmt.Errorf("PIOP: proof is missing its authoritative v2 PCS opening")
	}
	if proof.RowOpening == nil || !reflect.DeepEqual(proof.RowOpening, proof.PCSOpening) {
		return fmt.Errorf("PIOP: proof PCS opening aliases disagree")
	}
	if err := validateOpeningRoleV2(proof.PCSOpening, "main"); err != nil {
		return err
	}
	if proof.PCSOpening.Eta != opts.Eta || proof.PCSOpening.TapeBytes != DECSTapeBitsForOpts(opts)/8 {
		return fmt.Errorf("PIOP: proof opening parameters do not match verifier options")
	}
	if len(proof.RootHash) != DECSHashBitsForOpts(opts)/8 {
		return fmt.Errorf("PIOP: proof root width=%d want=%d", len(proof.RootHash), DECSHashBitsForOpts(opts)/8)
	}
	if proof.Root != [16]byte{} || proof.QRoot != [16]byte{} || len(proof.QRootHash) != 0 || proof.QOpening != nil || len(proof.QR) != 0 || len(proof.QRBits) != 0 {
		return fmt.Errorf("PIOP: proof contains retired v1 root or Q-opening material")
	}
	if err := validateExpectedPCSGeometryV2(proof, expectedLayout.SigCount, opts); err != nil {
		return err
	}
	return nil
}

func validateExpectedPCSGeometryV2(proof *Proof, logicalRows int, opts SimOpts) error {
	blocks := ceilDiv(logicalRows, opts.LVCSNCols)
	replayRows := blocks * (opts.NCols + opts.Theta)
	maskRows := opts.Rho * (proof.MaskDegreeBound/opts.LVCSNCols + 1) * opts.Theta
	if transcriptUsesSmallWood2025V3(proof.TranscriptVersion) {
		shape, err := deriveSmallFieldMaskShapeV3(proof.MaskDegreeBound, opts.LVCSNCols, opts.Theta)
		if err != nil {
			return fmt.Errorf("PIOP: derive verifier v3 mask geometry: %w", err)
		}
		maskRows = opts.Rho * shape.RowsPerMask
	}
	g := proof.PCSGeometry
	if g.Kind != PCSGeometryKindSmallFieldMatrixV2 || g.SmallFieldSource != PCSGeometrySmallFieldSourceLiteralRowsV2 ||
		g.WitnessPackingCols != opts.NCols || g.PCSNCols != opts.LVCSNCols || g.Theta != opts.Theta || g.Ell != opts.Ell ||
		g.BlockCount != blocks || g.LogicalWitnessPolys != logicalRows || g.WitnessRows != replayRows ||
		g.ReplayWitnessRows != replayRows || g.MaskRows != maskRows || g.ShortnessTailOffset != 0 || g.ShortnessTailRows != 0 {
		return fmt.Errorf("PIOP: proof PCS geometry does not match the verifier-derived v2 geometry")
	}
	if proof.MaskRowOffset != replayRows || proof.MaskRowCount != maskRows ||
		g.OracleLayout.Witness.Offset != 0 || g.OracleLayout.Witness.Count != replayRows ||
		g.OracleLayout.Mask.Offset != replayRows || g.OracleLayout.Mask.Count != maskRows {
		return fmt.Errorf("PIOP: proof oracle layout does not match the verifier-derived v2 geometry")
	}
	return nil
}
