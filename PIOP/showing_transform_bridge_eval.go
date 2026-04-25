package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type prfKeyBindingLayout struct {
	KeyCount int
	Packed   bool
	KeySlots []CoeffSlot
	StartIdx int
}

type transformBridgePostSignConfig struct {
	Ring               *ring.Ring
	Layout             RowLayout
	Omega              []uint64
	DomainPoints       []uint64
	HashRelation       string
	X0Len              int
	DirectTargetReplay bool
	InlineTargetReplay bool

	ThetaAHeads                 [][][]uint64
	ThetaBBlocks                [][][]uint64
	PackingSelCoeff             []uint64
	LagrangeBasis               [][]uint64
	TransformH                  [][]uint64
	TransformHEval              [][]uint64
	BlockFactors                [][]uint64
	ComponentCount              int
	SourceBlocks                int
	MsgDecode1                  []uint64
	MsgDecode2                  []uint64
	X0Decode1                   []uint64
	ScalarDecode1               []uint64
	MsgMembershipPoly           []uint64
	X0MembershipPoly            []uint64
	ScalarMembershipPoly        []uint64
	KeyBindLayout               prfKeyBindingLayout
	PRFConstRows                []int
	PRFBridgeStripeSourceRows   []int
	PRFBridgeStripePhysicalRows []int
}

func newTransformBridgePostSignConfig(ringQ *ring.Ring, proof *Proof, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64, bound int64, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout, opts SimOpts) (*transformBridgePostSignConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesTransformBridge(layout) {
		return nil, fmt.Errorf("transform-bridge config requires transform-bridge coeff-native layout")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return nil, fmt.Errorf("direct T-hat replay expects one public A row, got %d", len(pub.A))
	}
	if len(pub.B) < 4 {
		return nil, fmt.Errorf("transform-bridge replay requires B rows, got %d", len(pub.B))
	}
	useBBTran := publicUsesBBTran(pub)
	inlineTargetReplay := (proof != nil && proof.SigShortness != nil && proof.SigShortness.Version == sigShortnessProofVersionV18) ||
		sigShortnessV18EnabledForOpts(opts) ||
		rowLayoutLooksInlineTargetReplay(layout)
	directTargetReplay := (proof != nil && proof.SigShortness != nil && proof.SigShortness.Version == sigShortnessProofVersionV18) || inlineTargetReplay || rowLayoutPostSignTargetMR0HatIndex(layout, 0) >= 0
	if useBBTran && rowLayoutPostSignZHatIndex(layout, 0) < 0 {
		return nil, fmt.Errorf("bb_tran transform-bridge replay requires Z hats")
	}
	if len(omegaWitness) == 0 {
		return nil, fmt.Errorf("empty omega witness")
	}
	if len(domainPoints) == 0 {
		return nil, fmt.Errorf("missing explicit domain points")
	}
	if bound <= 0 {
		return nil, fmt.Errorf("transform-bridge requires positive bound")
	}
	x0Len := pub.X0Len
	if x0Len <= 0 {
		x0Len = rowLayoutX0Len(layout)
	}
	if x0Len <= 0 {
		return nil, fmt.Errorf("invalid x0 length %d", x0Len)
	}
	q := ringQ.Modulus[0]
	sourceBlocks := layout.SigBlocks
	if sourceBlocks <= 0 {
		sourceBlocks = 1
	}
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	if replayTHatCount <= 0 && !directTargetReplay {
		replayTHatCount = 1
	}
	replayBlockCount := rowLayoutReplayBlockCount(layout)
	if replayBlockCount <= 0 {
		replayBlockCount = replayTHatCount
	}
	if !directTargetReplay && replayTHatCount != replayBlockCount {
		return nil, fmt.Errorf("replay family mismatch: T-hat count=%d replay blocks=%d", replayTHatCount, replayBlockCount)
	}
	if inlineTargetReplay && len(rowLayoutPostSignTargetMR0HatRows(layout)) != 0 {
		return nil, fmt.Errorf("inline-target replay must not carry target-MR0 rows")
	}
	if replayBlockCount > sourceBlocks {
		return nil, fmt.Errorf("replay blocks=%d exceed source blocks=%d", replayBlockCount, sourceBlocks)
	}
	componentCount := layout.CoeffNativeSig.SigComponentCount
	if componentCount <= 0 {
		componentCount = len(pub.A[0])
	}
	if componentCount != len(pub.A[0]) {
		return nil, fmt.Errorf("signature component mismatch: layout=%d want %d", componentCount, len(pub.A[0]))
	}
	outputBlocks := replayTHatCount
	if directTargetReplay {
		outputBlocks = replayBlockCount
	}
	thetaAHeads := make([][][]uint64, outputBlocks)
	for b := 0; b < outputBlocks; b++ {
		thetaAHeads[b] = make([][]uint64, componentCount)
		for comp := 0; comp < componentCount; comp++ {
			head, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, b, sourceBlocks)
			if err != nil {
				return nil, fmt.Errorf("theta A head block %d comp %d: %w", b, comp, err)
			}
			thetaAHeads[b][comp] = head
		}
	}

	thetaBBlocks := make([][][]uint64, replayBlockCount)
	for b := 0; b < replayBlockCount; b++ {
		thetaBBlocks[b] = make([][]uint64, len(pub.B))
		for i := range pub.B {
			var theta *ring.Poly
			var err error
			if replayBlockCount == 1 {
				theta, err = thetaPolyFromNTT(ringQ, pub.B[i], omegaWitness)
			} else {
				theta, err = thetaPolyFromNTTBlock(ringQ, pub.B[i], omegaWitness, b, sourceBlocks)
			}
			if err != nil {
				return nil, fmt.Errorf("theta B[%d] block %d: %w", i, b, err)
			}
			coeff, err := coeffFromNTTPoly(ringQ, theta)
			if err != nil {
				return nil, fmt.Errorf("theta B[%d] block %d coeffs: %w", i, b, err)
			}
			thetaBBlocks[b][i] = coeff
		}
	}

	packingSelCoeff, err := buildPackingSelectorCoeff(ringQ, omegaWitness)
	if err != nil {
		return nil, fmt.Errorf("packing selector coeffs: %w", err)
	}
	bridgeBasis, err := newRowTransformBridgeBasisCache(ringQ, omegaWitness, outputBlocks*len(omegaWitness))
	if err != nil {
		return nil, fmt.Errorf("transform-bridge basis: %w", err)
	}
	msgDecode1, msgDecode2, err := buildPackedMessageCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, fmt.Errorf("message carrier decode polys: %w", err)
	}
	x0Decode1, err := buildSingletonCarrierDecodePoly(pub.X0CoeffBound, q)
	if err != nil {
		return nil, fmt.Errorf("x0 carrier decode polys: %w", err)
	}
	scalarDecode1, _, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, fmt.Errorf("scalar carrier decode polys: %w", err)
	}
	msgMembershipPoly, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		return nil, fmt.Errorf("message carrier membership poly: %w", err)
	}
	x0MembershipPoly, err := buildSingletonCarrierMembershipPoly(pub.X0CoeffBound, q)
	if err != nil {
		return nil, fmt.Errorf("x0 carrier membership poly: %w", err)
	}
	scalarMembershipPoly, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return nil, fmt.Errorf("scalar carrier membership poly: %w", err)
	}

	keyBindLayout := prfKeyBindingLayout{}
	if prfCompanionLayout != nil {
		keyBindLayout.KeyCount = prfCompanionLayout.KeyCount
		keyBindLayout.Packed = true
		keyBindLayout.KeySlots = append([]CoeffSlot(nil), prfCompanionLayout.KeySlots...)
	}
	if keyBindLayout.KeyCount > 0 {
		if len(omegaWitness)/2 < keyBindLayout.KeyCount {
			return nil, fmt.Errorf("key binding requires ncols/2 >= lenkey; got ncols=%d lenkey=%d", len(omegaWitness), keyBindLayout.KeyCount)
		}
		if keyBindLayout.Packed && len(keyBindLayout.KeySlots) < keyBindLayout.KeyCount {
			return nil, fmt.Errorf("key binding requires %d key slots, have %d", keyBindLayout.KeyCount, len(keyBindLayout.KeySlots))
		}
	}

	_ = prfLayout
	var prfConstRows []int
	var prfBridgeStripeSourceRows []int
	var prfBridgeStripePhysicalRows []int
	if normalizePRFCompanionMode(opts.PRFCompanionMode) == PRFCompanionModeAuxInstance && prfCompanionLayout != nil && prfCompanionLayout.BridgeStripe != nil {
		prfBridgeStripeSourceRows = append([]int(nil), prfCompanionLayout.BridgeStripe.SourceRows...)
		prfBridgeStripePhysicalRows = append([]int(nil), prfCompanionLayout.BridgeStripe.PhysicalRows...)
		if len(prfBridgeStripeSourceRows) != len(prfBridgeStripePhysicalRows) {
			return nil, fmt.Errorf("prf bridge stripe source rows=%d want physical rows=%d", len(prfBridgeStripeSourceRows), len(prfBridgeStripePhysicalRows))
		}
	}
	return &transformBridgePostSignConfig{
		Ring:                        ringQ,
		Layout:                      layout,
		Omega:                       append([]uint64(nil), omegaWitness...),
		DomainPoints:                append([]uint64(nil), domainPoints...),
		HashRelation:                pub.HashRelation,
		X0Len:                       x0Len,
		DirectTargetReplay:          directTargetReplay,
		InlineTargetReplay:          inlineTargetReplay,
		ThetaAHeads:                 thetaAHeads,
		ThetaBBlocks:                thetaBBlocks,
		PackingSelCoeff:             packingSelCoeff,
		LagrangeBasis:               bridgeBasis.LagrangeBasis,
		TransformH:                  bridgeBasis.TransformH,
		TransformHEval:              bridgeBasis.TransformHEval,
		BlockFactors:                bridgeBasis.BlockFactors,
		ComponentCount:              componentCount,
		SourceBlocks:                sourceBlocks,
		MsgDecode1:                  msgDecode1,
		MsgDecode2:                  msgDecode2,
		X0Decode1:                   x0Decode1,
		ScalarDecode1:               scalarDecode1,
		MsgMembershipPoly:           msgMembershipPoly,
		X0MembershipPoly:            x0MembershipPoly,
		ScalarMembershipPoly:        scalarMembershipPoly,
		KeyBindLayout:               keyBindLayout,
		PRFConstRows:                prfConstRows,
		PRFBridgeStripeSourceRows:   prfBridgeStripeSourceRows,
		PRFBridgeStripePhysicalRows: prfBridgeStripePhysicalRows,
	}, nil
}

func (cfg *transformBridgePostSignConfig) CoreEvaluator() ConstraintEvaluator {
	return cfg.evaluator()
}

func (cfg *transformBridgePostSignConfig) CoreKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil transform-bridge replay config")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	return cfg.kEvaluator(K), nil
}

func (cfg *transformBridgePostSignConfig) PRFBridgeStripeEqualityEvaluator() ConstraintEvaluator {
	return rowEqualityConstraintEvaluator(cfg.Ring, cfg.PRFBridgeStripeSourceRows, cfg.PRFBridgeStripePhysicalRows)
}

func (cfg *transformBridgePostSignConfig) PRFBridgeStripeEqualityKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil transform-bridge replay config")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	return rowEqualityKConstraintEvaluator(K, cfg.PRFBridgeStripeSourceRows, cfg.PRFBridgeStripePhysicalRows), nil
}

func rowEqualityConstraintEvaluator(ringQ *ring.Ring, sourceRows, physicalRows []int) ConstraintEvaluator {
	if ringQ == nil || len(sourceRows) == 0 || len(physicalRows) == 0 {
		return nil
	}
	if len(sourceRows) != len(physicalRows) {
		return func(uint64, []uint64) ([]uint64, []uint64, error) {
			return nil, nil, fmt.Errorf("row equality source rows=%d want physical rows=%d", len(sourceRows), len(physicalRows))
		}
	}
	q := ringQ.Modulus[0]
	return func(_ uint64, rows []uint64) ([]uint64, []uint64, error) {
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		fpar := make([]uint64, 0, len(sourceRows))
		for i, sourceRow := range sourceRows {
			sourceVal, err := getRow(sourceRow)
			if err != nil {
				return nil, nil, err
			}
			physicalVal, err := getRow(physicalRows[i])
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar, modSub(sourceVal, physicalVal, q))
		}
		return fpar, nil, nil
	}
}

func rowEqualityKConstraintEvaluator(K *kf.Field, sourceRows, physicalRows []int) KConstraintEvaluator {
	if K == nil || len(sourceRows) == 0 || len(physicalRows) == 0 {
		return nil
	}
	if len(sourceRows) != len(physicalRows) {
		return func(kf.Elem, []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
			return nil, nil, fmt.Errorf("row equality source rows=%d want physical rows=%d", len(sourceRows), len(physicalRows))
		}
	}
	return func(_ kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		fpar := make([]kf.Elem, 0, len(sourceRows))
		for i, sourceRow := range sourceRows {
			sourceVal, err := getRow(sourceRow)
			if err != nil {
				return nil, nil, err
			}
			physicalVal, err := getRow(physicalRows[i])
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar, K.Sub(sourceVal, physicalVal))
		}
		return fpar, nil, nil
	}
}

func (cfg *transformBridgePostSignConfig) evaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil transform-bridge replay config")
		}
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return nil, nil, fmt.Errorf("transform-bridge eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
		}
		q := cfg.Ring.Modulus[0]
		x := cfg.DomainPoints[ptIdx] % q
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}

		layout := cfg.Layout
		replayBlocks := len(cfg.ThetaAHeads)
		useBBTran := relationUsesBBTran(cfg.HashRelation)
		aggregateR0Replay := rowLayoutPostSignR0B2HatIndex(layout, 0) >= 0
		directTargetReplay := cfg.DirectTargetReplay
		inlineTargetReplay := cfg.InlineTargetReplay
		fpar := make([]uint64, 0, replayBlocks*(cfg.X0Len+1)+3+cfg.X0Len+cfg.KeyBindLayout.KeyCount)
		for b := 0; b < replayBlocks; b++ {
			rHat1, err := getRow(rowLayoutPostSignRHat1Index(layout, b))
			if err != nil {
				return nil, nil, err
			}
			zHat := uint64(0)
			if useBBTran {
				zHat, err = getRow(rowLayoutPostSignZHatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
			}
			if directTargetReplay {
				if !useBBTran {
					return nil, nil, fmt.Errorf("direct-target replay requires bb_tran")
				}
				fpar = append(fpar, transformInverseResidualEval(q, x, cfg.HashRelation, cfg.ThetaBBlocks[b], rHat1, zHat))
				continue
			}
			mHatSigma, err := getRow(rowLayoutPostSignMHatSigmaIndex(layout, b))
			if err != nil {
				return nil, nil, err
			}
			tHat, err := getRow(rowLayoutPostSignTHatIndex(layout, b))
			if err != nil {
				return nil, nil, err
			}
			if useBBTran {
				if aggregateR0Replay {
					r0B2Hat, err := getRow(rowLayoutPostSignR0B2HatIndex(layout, b))
					if err != nil {
						return nil, nil, err
					}
					fpar = append(fpar,
						transformTargetResidualCombinedEvalAggregate(q, x, cfg.HashRelation, cfg.ThetaBBlocks[b], mHatSigma, r0B2Hat, zHat, tHat),
						transformInverseResidualEval(q, x, cfg.HashRelation, cfg.ThetaBBlocks[b], rHat1, zHat),
					)
					continue
				}
				rHat0Vals := make([]uint64, cfg.X0Len)
				for i := 0; i < cfg.X0Len; i++ {
					rHat0Vals[i], err = getRow(rowLayoutPostSignRHat0ComponentIndex(layout, b, i))
					if err != nil {
						return nil, nil, err
					}
				}
				fpar = append(fpar,
					transformTargetResidualCombinedEvalVector(q, x, cfg.HashRelation, cfg.ThetaBBlocks[b], mHatSigma, rHat0Vals, zHat, tHat),
					transformInverseResidualEval(q, x, cfg.HashRelation, cfg.ThetaBBlocks[b], rHat1, zHat),
				)
				continue
			}
			rHat0Vals := make([]uint64, cfg.X0Len)
			for i := 0; i < cfg.X0Len; i++ {
				rHat0Vals[i], err = getRow(rowLayoutPostSignRHat0ComponentIndex(layout, b, i))
				if err != nil {
					return nil, nil, err
				}
			}
			fpar = append(fpar, transformHashResidualCombinedEval(q, x, cfg.HashRelation, cfg.ThetaBBlocks[b], mHatSigma, rHat0Vals[0], rHat1, tHat, 0, 0))
		}

		cM, err := getRow(layout.IdxCarrierM)
		if err != nil {
			return nil, nil, err
		}
		cR1, err := getRow(layout.IdxCarrierR1)
		if err != nil {
			return nil, nil, err
		}
		m1, err := getRow(layout.IdxM1)
		if err != nil {
			return nil, nil, err
		}
		m2, err := getRow(layout.IdxM2)
		if err != nil {
			return nil, nil, err
		}
		r1, err := getRow(layout.IdxR1)
		if err != nil {
			return nil, nil, err
		}
		r0Vals := make([]uint64, cfg.X0Len)
		for i, idx := range rowLayoutPostSignR0Rows(layout) {
			r0Val, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			r0Vals[i] = r0Val
		}
		sel := EvalPoly(cfg.PackingSelCoeff, x, q) % q
		fpar = append(fpar, modMul(sel, m1, q))
		fpar = append(fpar, modMul((1+q-sel)%q, m2, q))
		fpar = append(fpar, EvalPoly(cfg.MsgMembershipPoly, cM, q)%q)
		for _, idx := range rowLayoutPostSignCarrierR0Rows(layout) {
			cR0, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar, EvalPoly(cfg.X0MembershipPoly, cR0, q)%q)
		}
		fpar = append(fpar, EvalPoly(cfg.ScalarMembershipPoly, cR1, q)%q)

		if cfg.KeyBindLayout.KeyCount > 0 {
			ncols := len(cfg.Omega)
			half := ncols / 2
			lagrangeVals := make([]uint64, ncols)
			for j := 0; j < ncols; j++ {
				lagrangeVals[j] = EvalPoly(cfg.LagrangeBasis[j], x, q) % q
			}
			for i := 0; i < cfg.KeyBindLayout.KeyCount; i++ {
				col := half + i
				if col < 0 || col >= ncols {
					return nil, nil, fmt.Errorf("key binding col=%d out of range", col)
				}
				sel := lagrangeVals[col]
				m2Extract := modMul(sel, m2, q)
				if cfg.KeyBindLayout.Packed {
					slot := cfg.KeyBindLayout.KeySlots[i]
					keyVal, err := getRow(slot.Row)
					if err != nil {
						return nil, nil, err
					}
					if slot.Coeff < 0 || slot.Coeff >= ncols {
						return nil, nil, fmt.Errorf("key slot col=%d out of range", slot.Coeff)
					}
					keyExtract := modMul(keyVal, lagrangeVals[slot.Coeff], q)
					fpar = append(fpar, modSub(keyExtract, m2Extract, q))
					continue
				}
				rowIdx := cfg.KeyBindLayout.StartIdx + i
				keyVal, err := getRow(rowIdx)
				if err != nil {
					return nil, nil, err
				}
				fpar = append(fpar, modMul(sel, modSub(keyVal, m2, q), q))
			}
		}
		lagrangeVals := make([]uint64, len(cfg.LagrangeBasis))
		hVals := make([]uint64, len(cfg.TransformH))
		for j := 0; j < len(cfg.LagrangeBasis); j++ {
			lagrangeVals[j] = EvalPoly(cfg.LagrangeBasis[j], x, q) % q
		}
		for j := 0; j < len(cfg.TransformH); j++ {
			hVals[j] = EvalPoly(cfg.TransformH[j], x, q) % q
		}

		r0BridgeFamilies := cfg.X0Len
		if aggregateR0Replay {
			r0BridgeFamilies = 1
		}
		if directTargetReplay {
			r0BridgeFamilies = 1
		}
		fagg := make([]uint64, 0, (r0BridgeFamilies+2)*replayBlocks*len(lagrangeVals))
		mSigma := modAdd(m1, m2, q)
		bridgePairs := []struct {
			val   uint64
			hatAt func(int) int
		}{}
		bridgePairs = append(bridgePairs, struct {
			val   uint64
			hatAt func(int) int
		}{val: r1, hatAt: func(block int) int { return rowLayoutPostSignRHat1Index(layout, block) }})
		if !directTargetReplay {
			bridgePairs = append([]struct {
				val   uint64
				hatAt func(int) int
			}{
				{val: mSigma, hatAt: func(block int) int { return rowLayoutPostSignMHatSigmaIndex(layout, block) }},
			}, bridgePairs...)
		}
		for _, pair := range bridgePairs {
			for b := 0; b < replayBlocks; b++ {
				hat, err := getRow(pair.hatAt(b))
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < len(lagrangeVals); j++ {
					t := b*len(lagrangeVals) + j
					if t < 0 || t >= len(hVals) {
						return nil, nil, fmt.Errorf("non-sign bridge index t=%d out of range", t)
					}
					left := modMul(pair.val, hVals[t], q)
					right := modMul(hat, lagrangeVals[j], q)
					fagg = append(fagg, modSub(left, right, q))
				}
			}
		}
		if directTargetReplay && !inlineTargetReplay {
			for b := 0; b < replayBlocks; b++ {
				hat, err := getRow(rowLayoutPostSignTargetMR0HatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < len(lagrangeVals); j++ {
					t := b*len(lagrangeVals) + j
					b1 := EvalPoly(cfg.ThetaBBlocks[b][1], cfg.Omega[j]%q, q) % q
					left := modMul(b1, modMul(mSigma, hVals[t], q), q)
					for i := 0; i < cfg.X0Len; i++ {
						b2 := EvalPoly(cfg.ThetaBBlocks[b][2+i], cfg.Omega[j]%q, q) % q
						left = modAdd(left, modMul(b2, modMul(r0Vals[i], hVals[t], q), q), q)
					}
					right := modMul(hat, lagrangeVals[j], q)
					fagg = append(fagg, modSub(left, right, q))
				}
			}
		} else if !directTargetReplay && aggregateR0Replay {
			for b := 0; b < replayBlocks; b++ {
				hat, err := getRow(rowLayoutPostSignR0B2HatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < len(lagrangeVals); j++ {
					t := b*len(lagrangeVals) + j
					left := uint64(0)
					for i := 0; i < cfg.X0Len; i++ {
						b2 := EvalPoly(cfg.ThetaBBlocks[b][2+i], cfg.Omega[j]%q, q) % q
						left = modAdd(left, modMul(b2, modMul(r0Vals[i], hVals[t], q), q), q)
					}
					right := modMul(hat, lagrangeVals[j], q)
					fagg = append(fagg, modSub(left, right, q))
				}
			}
		} else if !directTargetReplay {
			for i := 0; i < cfg.X0Len; i++ {
				for b := 0; b < replayBlocks; b++ {
					hat, err := getRow(rowLayoutPostSignRHat0ComponentIndex(layout, b, i))
					if err != nil {
						return nil, nil, err
					}
					for j := 0; j < len(lagrangeVals); j++ {
						t := b*len(lagrangeVals) + j
						left := modMul(r0Vals[i], hVals[t], q)
						right := modMul(hat, lagrangeVals[j], q)
						fagg = append(fagg, modSub(left, right, q))
					}
				}
			}
		}
		if len(cfg.PRFConstRows) > 0 {
			for _, idx := range cfg.PRFConstRows {
				rowVal, err := getRow(idx)
				if err != nil {
					return nil, nil, err
				}
				base := lagrangeVals[0]
				for j := 1; j < len(lagrangeVals); j++ {
					fagg = append(fagg, modMul(rowVal, modSub(lagrangeVals[j], base, q), q))
				}
			}
		}

		return fpar, fagg, nil
	}
}

func (cfg *transformBridgePostSignConfig) kEvaluator(K *kf.Field) KConstraintEvaluator {
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil transform-bridge replay config")
		}
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}

		layout := cfg.Layout
		replayBlocks := len(cfg.ThetaAHeads)
		useBBTran := relationUsesBBTran(cfg.HashRelation)
		aggregateR0Replay := rowLayoutPostSignR0B2HatIndex(layout, 0) >= 0
		directTargetReplay := cfg.DirectTargetReplay
		inlineTargetReplay := cfg.InlineTargetReplay
		fpar := make([]kf.Elem, 0, replayBlocks*(cfg.X0Len+1)+3+cfg.X0Len+cfg.KeyBindLayout.KeyCount)
		for b := 0; b < replayBlocks; b++ {
			rHat1, err := getRow(rowLayoutPostSignRHat1Index(layout, b))
			if err != nil {
				return nil, nil, err
			}
			zHat := K.Zero()
			if useBBTran {
				zHat, err = getRow(rowLayoutPostSignZHatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
			}
			if directTargetReplay {
				if !useBBTran {
					return nil, nil, fmt.Errorf("direct-target replay requires bb_tran")
				}
				fpar = append(fpar, transformInverseResidualKEval(K, e, cfg.HashRelation, cfg.ThetaBBlocks[b], rHat1, zHat))
				continue
			}
			mHatSigma, err := getRow(rowLayoutPostSignMHatSigmaIndex(layout, b))
			if err != nil {
				return nil, nil, err
			}
			tHat, err := getRow(rowLayoutPostSignTHatIndex(layout, b))
			if err != nil {
				return nil, nil, err
			}
			if useBBTran {
				if aggregateR0Replay {
					r0B2Hat, err := getRow(rowLayoutPostSignR0B2HatIndex(layout, b))
					if err != nil {
						return nil, nil, err
					}
					fpar = append(fpar,
						transformTargetResidualCombinedKEvalAggregate(K, e, cfg.HashRelation, cfg.ThetaBBlocks[b], mHatSigma, r0B2Hat, zHat, tHat),
						transformInverseResidualKEval(K, e, cfg.HashRelation, cfg.ThetaBBlocks[b], rHat1, zHat),
					)
					continue
				}
				rHat0Vals := make([]kf.Elem, cfg.X0Len)
				for i := 0; i < cfg.X0Len; i++ {
					rHat0Vals[i], err = getRow(rowLayoutPostSignRHat0ComponentIndex(layout, b, i))
					if err != nil {
						return nil, nil, err
					}
				}
				fpar = append(fpar,
					transformTargetResidualCombinedKEvalVector(K, e, cfg.HashRelation, cfg.ThetaBBlocks[b], mHatSigma, rHat0Vals, zHat, tHat),
					transformInverseResidualKEval(K, e, cfg.HashRelation, cfg.ThetaBBlocks[b], rHat1, zHat),
				)
				continue
			}
			rHat0Vals := make([]kf.Elem, cfg.X0Len)
			for i := 0; i < cfg.X0Len; i++ {
				rHat0Vals[i], err = getRow(rowLayoutPostSignRHat0ComponentIndex(layout, b, i))
				if err != nil {
					return nil, nil, err
				}
			}
			fpar = append(fpar, transformHashResidualCombinedKEval(K, e, cfg.HashRelation, cfg.ThetaBBlocks[b], mHatSigma, rHat0Vals[0], rHat1, tHat, K.Zero(), K.Zero()))
		}

		cM, err := getRow(layout.IdxCarrierM)
		if err != nil {
			return nil, nil, err
		}
		cR1, err := getRow(layout.IdxCarrierR1)
		if err != nil {
			return nil, nil, err
		}
		m1, err := getRow(layout.IdxM1)
		if err != nil {
			return nil, nil, err
		}
		m2, err := getRow(layout.IdxM2)
		if err != nil {
			return nil, nil, err
		}
		r1, err := getRow(layout.IdxR1)
		if err != nil {
			return nil, nil, err
		}
		r0Vals := make([]kf.Elem, cfg.X0Len)
		for i, idx := range rowLayoutPostSignR0Rows(layout) {
			r0Val, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			r0Vals[i] = r0Val
		}
		sel := K.EvalFPolyAtK(cfg.PackingSelCoeff, e)
		fpar = append(fpar, K.Mul(sel, m1))
		fpar = append(fpar, K.Mul(K.Sub(K.One(), sel), m2))
		fpar = append(fpar, K.EvalFPolyAtK(cfg.MsgMembershipPoly, cM))
		for _, idx := range rowLayoutPostSignCarrierR0Rows(layout) {
			cR0, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar, K.EvalFPolyAtK(cfg.X0MembershipPoly, cR0))
		}
		fpar = append(fpar, K.EvalFPolyAtK(cfg.ScalarMembershipPoly, cR1))

		if cfg.KeyBindLayout.KeyCount > 0 {
			ncols := len(cfg.Omega)
			half := ncols / 2
			lagrangeVals := make([]kf.Elem, ncols)
			for j := 0; j < ncols; j++ {
				lagrangeVals[j] = K.EvalFPolyAtK(cfg.LagrangeBasis[j], e)
			}
			for i := 0; i < cfg.KeyBindLayout.KeyCount; i++ {
				col := half + i
				if col < 0 || col >= ncols {
					return nil, nil, fmt.Errorf("key binding col=%d out of range", col)
				}
				sel := lagrangeVals[col]
				m2Extract := K.Mul(sel, m2)
				if cfg.KeyBindLayout.Packed {
					slot := cfg.KeyBindLayout.KeySlots[i]
					keyVal, err := getRow(slot.Row)
					if err != nil {
						return nil, nil, err
					}
					if slot.Coeff < 0 || slot.Coeff >= ncols {
						return nil, nil, fmt.Errorf("key slot col=%d out of range", slot.Coeff)
					}
					keyExtract := K.Mul(keyVal, lagrangeVals[slot.Coeff])
					fpar = append(fpar, K.Sub(keyExtract, m2Extract))
					continue
				}
				rowIdx := cfg.KeyBindLayout.StartIdx + i
				keyVal, err := getRow(rowIdx)
				if err != nil {
					return nil, nil, err
				}
				fpar = append(fpar, K.Mul(sel, K.Sub(keyVal, m2)))
			}
		}
		lagrangeVals := make([]kf.Elem, len(cfg.LagrangeBasis))
		hVals := make([]kf.Elem, len(cfg.TransformH))
		for j := 0; j < len(cfg.LagrangeBasis); j++ {
			lagrangeVals[j] = K.EvalFPolyAtK(cfg.LagrangeBasis[j], e)
		}
		for j := 0; j < len(cfg.TransformH); j++ {
			hVals[j] = K.EvalFPolyAtK(cfg.TransformH[j], e)
		}

		r0BridgeFamilies := cfg.X0Len
		if aggregateR0Replay {
			r0BridgeFamilies = 1
		}
		if directTargetReplay {
			r0BridgeFamilies = 1
		}
		fagg := make([]kf.Elem, 0, (r0BridgeFamilies+2)*replayBlocks*len(lagrangeVals))
		mSigma := K.Add(m1, m2)
		bridgePairs := []struct {
			val   kf.Elem
			hatAt func(int) int
		}{}
		bridgePairs = append(bridgePairs, struct {
			val   kf.Elem
			hatAt func(int) int
		}{val: r1, hatAt: func(block int) int { return rowLayoutPostSignRHat1Index(layout, block) }})
		if !directTargetReplay {
			bridgePairs = append([]struct {
				val   kf.Elem
				hatAt func(int) int
			}{
				{val: mSigma, hatAt: func(block int) int { return rowLayoutPostSignMHatSigmaIndex(layout, block) }},
			}, bridgePairs...)
		}
		for _, pair := range bridgePairs {
			for b := 0; b < replayBlocks; b++ {
				hat, err := getRow(pair.hatAt(b))
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < len(lagrangeVals); j++ {
					t := b*len(lagrangeVals) + j
					if t < 0 || t >= len(hVals) {
						return nil, nil, fmt.Errorf("non-sign bridge index t=%d out of range", t)
					}
					left := K.Mul(pair.val, hVals[t])
					right := K.Mul(hat, lagrangeVals[j])
					fagg = append(fagg, K.Sub(left, right))
				}
			}
		}
		if directTargetReplay && !inlineTargetReplay {
			for b := 0; b < replayBlocks; b++ {
				hat, err := getRow(rowLayoutPostSignTargetMR0HatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < len(lagrangeVals); j++ {
					t := b*len(lagrangeVals) + j
					b1 := K.EmbedF(EvalPoly(cfg.ThetaBBlocks[b][1], cfg.Omega[j]%K.Q, K.Q) % K.Q)
					left := K.Mul(b1, K.Mul(mSigma, hVals[t]))
					for i := 0; i < cfg.X0Len; i++ {
						b2 := K.EmbedF(EvalPoly(cfg.ThetaBBlocks[b][2+i], cfg.Omega[j]%K.Q, K.Q) % K.Q)
						left = K.Add(left, K.Mul(b2, K.Mul(r0Vals[i], hVals[t])))
					}
					right := K.Mul(hat, lagrangeVals[j])
					fagg = append(fagg, K.Sub(left, right))
				}
			}
		} else if !directTargetReplay && aggregateR0Replay {
			for b := 0; b < replayBlocks; b++ {
				hat, err := getRow(rowLayoutPostSignR0B2HatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < len(lagrangeVals); j++ {
					t := b*len(lagrangeVals) + j
					left := K.Zero()
					for i := 0; i < cfg.X0Len; i++ {
						b2 := K.EmbedF(EvalPoly(cfg.ThetaBBlocks[b][2+i], cfg.Omega[j]%K.Q, K.Q) % K.Q)
						left = K.Add(left, K.Mul(b2, K.Mul(r0Vals[i], hVals[t])))
					}
					right := K.Mul(hat, lagrangeVals[j])
					fagg = append(fagg, K.Sub(left, right))
				}
			}
		} else if !directTargetReplay {
			for i := 0; i < cfg.X0Len; i++ {
				for b := 0; b < replayBlocks; b++ {
					hat, err := getRow(rowLayoutPostSignRHat0ComponentIndex(layout, b, i))
					if err != nil {
						return nil, nil, err
					}
					for j := 0; j < len(lagrangeVals); j++ {
						t := b*len(lagrangeVals) + j
						left := K.Mul(r0Vals[i], hVals[t])
						right := K.Mul(hat, lagrangeVals[j])
						fagg = append(fagg, K.Sub(left, right))
					}
				}
			}
		}
		if len(cfg.PRFConstRows) > 0 {
			for _, idx := range cfg.PRFConstRows {
				rowVal, err := getRow(idx)
				if err != nil {
					return nil, nil, err
				}
				base := lagrangeVals[0]
				for j := 1; j < len(lagrangeVals); j++ {
					fagg = append(fagg, K.Mul(rowVal, K.Sub(lagrangeVals[j], base)))
				}
			}
		}

		return fpar, fagg, nil
	}
}
