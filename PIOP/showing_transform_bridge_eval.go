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
	Ring         *ring.Ring
	Layout       RowLayout
	Omega        []uint64
	DomainPoints []uint64
	HashRelation string

	ThetaAHeads     [][][]uint64
	ThetaBBlocks    [][][]uint64
	PackingSelCoeff []uint64
	LagrangeBasis   [][]uint64
	TransformH      [][]uint64
	TransformHEval  [][]uint64
	BlockFactors    [][]uint64
	RPows           []uint64
	ComponentCount  int
	SourceBlocks    int

	MsgDecode1        []uint64
	MsgDecode2        []uint64
	CtrDecode1        []uint64
	CtrDecode2        []uint64
	MsgMembershipPoly []uint64
	CtrMembershipPoly []uint64
	KeyBindLayout     prfKeyBindingLayout
	PRFConstRows      []int
}

func newTransformBridgePostSignConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64, bound int64, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout, opts SimOpts) (*transformBridgePostSignConfig, error) {
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
		return nil, fmt.Errorf("transform-bridge replay requires 4 B rows, got %d", len(pub.B))
	}
	if rowLayoutPostSignTSource(layout) < 0 {
		return nil, fmt.Errorf("transform-bridge replay requires a committed T source row")
	}
	if publicUsesBBTran(pub) && (layout.IdxMSigmaR1 < 0 || layout.IdxR0R1 < 0 || layout.IdxMSigmaR1Hat < 0 || layout.IdxR0R1Hat < 0) {
		return nil, fmt.Errorf("bb_tran transform-bridge replay requires product rows and hats")
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
	q := ringQ.Modulus[0]
	sourceBlocks := layout.SigBlocks
	if sourceBlocks <= 0 {
		sourceBlocks = 1
	}
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	if replayTHatCount <= 0 {
		replayTHatCount = 1
	}
	replayBlockCount := rowLayoutReplayBlockCount(layout)
	if replayBlockCount <= 0 {
		replayBlockCount = replayTHatCount
	}
	if replayTHatCount != replayBlockCount {
		return nil, fmt.Errorf("replay family mismatch: T-hat count=%d replay blocks=%d", replayTHatCount, replayBlockCount)
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
	spec, err := signatureChainSpecForLayoutAndOpts(q, layout, opts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}

	thetaAHeads := make([][][]uint64, replayTHatCount)
	for b := 0; b < replayTHatCount; b++ {
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
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, replayTHatCount*len(omegaWitness), sourceBlocks)
	if err != nil {
		return nil, fmt.Errorf("transform-bridge basis: %w", err)
	}
	msgDecode1, msgDecode2, err := buildPackedMessageCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, fmt.Errorf("message carrier decode polys: %w", err)
	}
	ctrDecode1, ctrDecode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, fmt.Errorf("carrier decode polys: %w", err)
	}
	msgMembershipPoly, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		return nil, fmt.Errorf("message carrier membership poly: %w", err)
	}
	ctrMembershipPoly, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return nil, fmt.Errorf("carrier membership poly: %w", err)
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

	return &transformBridgePostSignConfig{
		Ring:              ringQ,
		Layout:            layout,
		Omega:             append([]uint64(nil), omegaWitness...),
		DomainPoints:      append([]uint64(nil), domainPoints...),
		HashRelation:      pub.HashRelation,
		ThetaAHeads:       thetaAHeads,
		ThetaBBlocks:      thetaBBlocks,
		PackingSelCoeff:   packingSelCoeff,
		LagrangeBasis:     bridgeBasis.LagrangeBasis,
		TransformH:        bridgeBasis.TransformH,
		TransformHEval:    bridgeBasis.TransformHEval,
		BlockFactors:      bridgeBasis.BlockFactors,
		RPows:             append([]uint64(nil), spec.RPows...),
		ComponentCount:    componentCount,
		SourceBlocks:      sourceBlocks,
		MsgDecode1:        msgDecode1,
		MsgDecode2:        msgDecode2,
		CtrDecode1:        ctrDecode1,
		CtrDecode2:        ctrDecode2,
		MsgMembershipPoly: msgMembershipPoly,
		CtrMembershipPoly: ctrMembershipPoly,
		KeyBindLayout:     keyBindLayout,
		PRFConstRows:      prfConstRows,
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
		tSourceBlocks := rowLayoutPostSignTSourceCount(layout)
		if tSourceBlocks <= 0 {
			tSourceBlocks = cfg.SourceBlocks
		}
		useBBTran := relationUsesBBTran(cfg.HashRelation)
		fpar := make([]uint64, 0, replayBlocks+4+cfg.KeyBindLayout.KeyCount)
		for b := 0; b < replayBlocks; b++ {
			mHatSigma, err := getRow(rowLayoutPostSignMHatSigmaIndex(layout, b))
			if err != nil {
				return nil, nil, err
			}
			rHat0, err := getRow(rowLayoutPostSignRHat0Index(layout, b))
			if err != nil {
				return nil, nil, err
			}
			rHat1, err := getRow(rowLayoutPostSignRHat1Index(layout, b))
			if err != nil {
				return nil, nil, err
			}
			tHat, err := getRow(rowLayoutPostSignTHatIndex(layout, b))
			if err != nil {
				return nil, nil, err
			}
			mSigmaR1Hat := uint64(0)
			r0R1Hat := uint64(0)
			if useBBTran {
				mSigmaR1Hat, err = getRow(rowLayoutPostSignMSigmaR1HatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
				r0R1Hat, err = getRow(rowLayoutPostSignR0R1HatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
			}
			fpar = append(fpar, transformHashResidualCombinedEval(q, x, cfg.HashRelation, cfg.ThetaBBlocks[b], mHatSigma, rHat0, rHat1, tHat, mSigmaR1Hat, r0R1Hat))
		}

		cM, err := getRow(layout.IdxCarrierM)
		if err != nil {
			return nil, nil, err
		}
		cCtr, err := getRow(layout.IdxCarrierCtr)
		if err != nil {
			return nil, nil, err
		}
		m1 := EvalPoly(cfg.MsgDecode1, cM, q) % q
		m2 := EvalPoly(cfg.MsgDecode2, cM, q) % q
		r0 := EvalPoly(cfg.CtrDecode1, cCtr, q) % q
		r1 := EvalPoly(cfg.CtrDecode2, cCtr, q) % q
		mSigmaR1 := uint64(0)
		r0R1 := uint64(0)
		if useBBTran {
			mSigmaR1, err = getRow(layout.IdxMSigmaR1)
			if err != nil {
				return nil, nil, err
			}
			r0R1, err = getRow(layout.IdxR0R1)
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar,
				modSub(mSigmaR1, modMul(modAdd(m1, m2, q), r1, q), q),
				modSub(r0R1, modMul(r0, r1, q), q),
			)
		}

		sel := EvalPoly(cfg.PackingSelCoeff, x, q) % q
		fpar = append(fpar, modMul(sel, m1, q))
		fpar = append(fpar, modMul((1+q-sel)%q, m2, q))
		fpar = append(fpar, EvalPoly(cfg.MsgMembershipPoly, cM, q)%q)
		fpar = append(fpar, EvalPoly(cfg.CtrMembershipPoly, cCtr, q)%q)

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

		fagg := make([]uint64, 0, 2*replayBlocks*len(lagrangeVals)+3*replayBlocks*len(lagrangeVals))
		for b := 0; b < replayBlocks; b++ {
			tVal, err := getRow(layout.IdxTHatBase + b)
			if err != nil {
				return nil, nil, err
			}
			for j := 0; j < len(lagrangeVals); j++ {
				t := b*len(lagrangeVals) + j
				if t < 0 || t >= len(cfg.BlockFactors) || t >= len(hVals) {
					return nil, nil, fmt.Errorf("signature bridge index t=%d out of range", t)
				}
				inner := uint64(0)
				for comp := 0; comp < cfg.ComponentCount; comp++ {
					aScale := cfg.ThetaAHeads[b][comp][j] % q
					if aScale == 0 {
						continue
					}
					for bSrc := 0; bSrc < cfg.SourceBlocks; bSrc++ {
						blockScale := cfg.BlockFactors[t][bSrc] % q
						for lane := 0; lane < len(cfg.RPows); lane++ {
							limbIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, bSrc, lane)
							limbVal, err := getRow(limbIdx)
							if err != nil {
								return nil, nil, err
							}
							scale := modMul(aScale, modMul(blockScale, cfg.RPows[lane]%q, q), q)
							inner = modAdd(inner, modMul(scale, limbVal, q), q)
						}
					}
				}
				left := modMul(hVals[t], inner, q)
				right := modMul(tVal, lagrangeVals[j], q)
				fagg = append(fagg, modSub(left, right, q))
			}
		}
		for b := 0; b < replayBlocks; b++ {
			tVal, err := getRow(layout.IdxTHatBase + b)
			if err != nil {
				return nil, nil, err
			}
			for j := 0; j < len(lagrangeVals); j++ {
				t := b*len(lagrangeVals) + j
				if t < 0 || t >= len(cfg.BlockFactors) || t >= len(hVals) {
					return nil, nil, fmt.Errorf("T source bridge index t=%d out of range", t)
				}
				inner := uint64(0)
				for bSrc := 0; bSrc < tSourceBlocks; bSrc++ {
					tSourceVal, err := getRow(layout.IdxTSource + bSrc)
					if err != nil {
						return nil, nil, err
					}
					scale := cfg.BlockFactors[t][bSrc] % q
					inner = modAdd(inner, modMul(scale, tSourceVal, q), q)
				}
				left := modMul(hVals[t], inner, q)
				right := modMul(tVal, lagrangeVals[j], q)
				fagg = append(fagg, modSub(left, right, q))
			}
		}

		mSigma := modAdd(m1, m2, q)
		for _, pair := range []struct {
			val uint64
			hatBase int
		}{
			{val: mSigma, hatBase: layout.IdxMHatSigma},
			{val: r0, hatBase: layout.IdxRHat0},
			{val: r1, hatBase: layout.IdxRHat1},
		} {
			for b := 0; b < replayBlocks; b++ {
				hat, err := getRow(pair.hatBase + b)
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
		if useBBTran {
			for _, pair := range []struct {
				val     uint64
				hatBase int
			}{
				{val: mSigmaR1, hatBase: layout.IdxMSigmaR1Hat},
				{val: r0R1, hatBase: layout.IdxR0R1Hat},
			} {
				for b := 0; b < replayBlocks; b++ {
					hat, err := getRow(pair.hatBase + b)
					if err != nil {
						return nil, nil, err
					}
					for j := 0; j < len(lagrangeVals); j++ {
						t := b*len(lagrangeVals) + j
						if t < 0 || t >= len(hVals) {
							return nil, nil, fmt.Errorf("bb_tran non-sign bridge index t=%d out of range", t)
						}
						left := modMul(pair.val, hVals[t], q)
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
		tSourceBlocks := rowLayoutPostSignTSourceCount(layout)
		if tSourceBlocks <= 0 {
			tSourceBlocks = cfg.SourceBlocks
		}
		useBBTran := relationUsesBBTran(cfg.HashRelation)
		fpar := make([]kf.Elem, 0, replayBlocks+4+cfg.KeyBindLayout.KeyCount)
		for b := 0; b < replayBlocks; b++ {
			mHatSigma, err := getRow(rowLayoutPostSignMHatSigmaIndex(layout, b))
			if err != nil {
				return nil, nil, err
			}
			rHat0, err := getRow(rowLayoutPostSignRHat0Index(layout, b))
			if err != nil {
				return nil, nil, err
			}
			rHat1, err := getRow(rowLayoutPostSignRHat1Index(layout, b))
			if err != nil {
				return nil, nil, err
			}
			tHat, err := getRow(rowLayoutPostSignTHatIndex(layout, b))
			if err != nil {
				return nil, nil, err
			}
			mSigmaR1Hat := K.Zero()
			r0R1Hat := K.Zero()
			if useBBTran {
				mSigmaR1Hat, err = getRow(rowLayoutPostSignMSigmaR1HatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
				r0R1Hat, err = getRow(rowLayoutPostSignR0R1HatIndex(layout, b))
				if err != nil {
					return nil, nil, err
				}
			}
			fpar = append(fpar, transformHashResidualCombinedKEval(K, e, cfg.HashRelation, cfg.ThetaBBlocks[b], mHatSigma, rHat0, rHat1, tHat, mSigmaR1Hat, r0R1Hat))
		}

		cM, err := getRow(layout.IdxCarrierM)
		if err != nil {
			return nil, nil, err
		}
		cCtr, err := getRow(layout.IdxCarrierCtr)
		if err != nil {
			return nil, nil, err
		}
		m1 := K.EvalFPolyAtK(cfg.MsgDecode1, cM)
		m2 := K.EvalFPolyAtK(cfg.MsgDecode2, cM)
		r0 := K.EvalFPolyAtK(cfg.CtrDecode1, cCtr)
		r1 := K.EvalFPolyAtK(cfg.CtrDecode2, cCtr)
		mSigmaR1 := K.Zero()
		r0R1 := K.Zero()
		if useBBTran {
			mSigmaR1, err = getRow(layout.IdxMSigmaR1)
			if err != nil {
				return nil, nil, err
			}
			r0R1, err = getRow(layout.IdxR0R1)
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar,
				K.Sub(mSigmaR1, K.Mul(K.Add(m1, m2), r1)),
				K.Sub(r0R1, K.Mul(r0, r1)),
			)
		}

		sel := K.EvalFPolyAtK(cfg.PackingSelCoeff, e)
		fpar = append(fpar, K.Mul(sel, m1))
		fpar = append(fpar, K.Mul(K.Sub(K.One(), sel), m2))
		fpar = append(fpar, K.EvalFPolyAtK(cfg.MsgMembershipPoly, cM))
		fpar = append(fpar, K.EvalFPolyAtK(cfg.CtrMembershipPoly, cCtr))

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

		fagg := make([]kf.Elem, 0, 2*replayBlocks*len(lagrangeVals)+3*replayBlocks*len(lagrangeVals))
		for b := 0; b < replayBlocks; b++ {
			tVal, err := getRow(layout.IdxTHatBase + b)
			if err != nil {
				return nil, nil, err
			}
			for j := 0; j < len(lagrangeVals); j++ {
				t := b*len(lagrangeVals) + j
				if t < 0 || t >= len(cfg.BlockFactors) || t >= len(hVals) {
					return nil, nil, fmt.Errorf("signature bridge index t=%d out of range", t)
				}
				inner := K.Zero()
				for comp := 0; comp < cfg.ComponentCount; comp++ {
					aScale := cfg.ThetaAHeads[b][comp][j] % K.Q
					if aScale == 0 {
						continue
					}
					aElem := K.EmbedF(aScale)
					for bSrc := 0; bSrc < cfg.SourceBlocks; bSrc++ {
						blockElem := K.EmbedF(cfg.BlockFactors[t][bSrc] % K.Q)
						for lane := 0; lane < len(cfg.RPows); lane++ {
							limbIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, bSrc, lane)
							limbVal, err := getRow(limbIdx)
							if err != nil {
								return nil, nil, err
							}
							weight := K.Mul(aElem, K.Mul(blockElem, K.EmbedF(cfg.RPows[lane]%K.Q)))
							inner = K.Add(inner, K.Mul(weight, limbVal))
						}
					}
				}
				left := K.Mul(hVals[t], inner)
				right := K.Mul(tVal, lagrangeVals[j])
				fagg = append(fagg, K.Sub(left, right))
			}
		}
		for b := 0; b < replayBlocks; b++ {
			tVal, err := getRow(layout.IdxTHatBase + b)
			if err != nil {
				return nil, nil, err
			}
			for j := 0; j < len(lagrangeVals); j++ {
				t := b*len(lagrangeVals) + j
				if t < 0 || t >= len(cfg.BlockFactors) || t >= len(hVals) {
					return nil, nil, fmt.Errorf("T source bridge index t=%d out of range", t)
				}
				inner := K.Zero()
				for bSrc := 0; bSrc < tSourceBlocks; bSrc++ {
					tSourceVal, err := getRow(layout.IdxTSource + bSrc)
					if err != nil {
						return nil, nil, err
					}
					inner = K.Add(inner, K.Mul(K.EmbedF(cfg.BlockFactors[t][bSrc]%K.Q), tSourceVal))
				}
				left := K.Mul(hVals[t], inner)
				right := K.Mul(tVal, lagrangeVals[j])
				fagg = append(fagg, K.Sub(left, right))
			}
		}

		mSigma := K.Add(m1, m2)
		for _, pair := range []struct {
			val kf.Elem
			hatBase int
		}{
			{val: mSigma, hatBase: layout.IdxMHatSigma},
			{val: r0, hatBase: layout.IdxRHat0},
			{val: r1, hatBase: layout.IdxRHat1},
		} {
			for b := 0; b < replayBlocks; b++ {
				hat, err := getRow(pair.hatBase + b)
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
		if useBBTran {
			for _, pair := range []struct {
				val     kf.Elem
				hatBase int
			}{
				{val: mSigmaR1, hatBase: layout.IdxMSigmaR1Hat},
				{val: r0R1, hatBase: layout.IdxR0R1Hat},
			} {
				for b := 0; b < replayBlocks; b++ {
					hat, err := getRow(pair.hatBase + b)
					if err != nil {
						return nil, nil, err
					}
					for j := 0; j < len(lagrangeVals); j++ {
						t := b*len(lagrangeVals) + j
						if t < 0 || t >= len(hVals) {
							return nil, nil, fmt.Errorf("bb_tran non-sign bridge index t=%d out of range", t)
						}
						left := K.Mul(pair.val, hVals[t])
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
