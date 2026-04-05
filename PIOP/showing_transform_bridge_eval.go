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

	ThetaABlocks [][][][]uint64
	ThetaB       [][]uint64

	PackingSelCoeff []uint64
	LagrangeBasis   [][]uint64
	TransformH      [][]uint64
	TransformHEval  [][]uint64
	NTTPoints       []uint64

	Decode1        []uint64
	Decode2        []uint64
	MembershipPoly []uint64
	KeyBindLayout  prfKeyBindingLayout
	PRFConstRows   []int
}

func newTransformBridgePostSignConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64, bound int64, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout) (*transformBridgePostSignConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesTransformBridge(layout) {
		return nil, fmt.Errorf("transform-bridge config requires transform-bridge coeff-native layout")
	}
	if len(pub.A) == 0 || len(pub.A[0]) == 0 {
		return nil, fmt.Errorf("missing A for transform-bridge replay")
	}
	if len(pub.B) < 4 {
		return nil, fmt.Errorf("transform-bridge replay requires 4 B rows, got %d", len(pub.B))
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
	blocks := layout.SigBlocks
	if blocks <= 0 {
		blocks = 1
	}

	thetaABlocks := make([][][][]uint64, blocks)
	for b := 0; b < blocks; b++ {
		thetaABlocks[b] = make([][][]uint64, len(pub.A))
		for i := range pub.A {
			thetaABlocks[b][i] = make([][]uint64, len(pub.A[i]))
			for j := range pub.A[i] {
				theta, err := thetaPolyFromNTTBlock(ringQ, pub.A[i][j], omegaWitness, b, blocks)
				if err != nil {
					return nil, fmt.Errorf("theta A[%d][%d] block %d: %w", i, j, b, err)
				}
				coeff, err := coeffFromNTTPoly(ringQ, theta)
				if err != nil {
					return nil, fmt.Errorf("theta A[%d][%d] block %d coeffs: %w", i, j, b, err)
				}
				thetaABlocks[b][i][j] = coeff
			}
		}
	}

	thetaB := make([][]uint64, len(pub.B))
	for i := range pub.B {
		theta, err := thetaPolyFromNTT(ringQ, pub.B[i], omegaWitness)
		if err != nil {
			return nil, fmt.Errorf("theta B[%d]: %w", i, err)
		}
		coeff, err := coeffFromNTTPoly(ringQ, theta)
		if err != nil {
			return nil, fmt.Errorf("theta B[%d] coeffs: %w", i, err)
		}
		thetaB[i] = coeff
	}

	packingSelCoeff, err := buildPackingSelectorCoeff(ringQ, omegaWitness)
	if err != nil {
		return nil, fmt.Errorf("packing selector coeffs: %w", err)
	}
	lagrangeBasis, err := buildLagrangeBasisCoeffs(omegaWitness, q)
	if err != nil {
		return nil, fmt.Errorf("lagrange basis: %w", err)
	}
	nttPoints, err := nttDomainPoints(ringQ)
	if err != nil {
		return nil, fmt.Errorf("ntt points: %w", err)
	}
	required := blocks * len(omegaWitness)
	if len(nttPoints) < required {
		return nil, fmt.Errorf("ntt points len=%d < required=%d", len(nttPoints), required)
	}
	nttPoints = nttPoints[:required]
	transformHCoeff, err := buildTransformBridgeHFromCoeffs(omegaWitness, nttPoints, q)
	if err != nil {
		return nil, fmt.Errorf("transform H coeff: %w", err)
	}
	transformHEval, err := buildTransformBridgeHFromEvals(omegaWitness, nttPoints[:len(omegaWitness)], q)
	if err != nil {
		return nil, fmt.Errorf("transform H eval: %w", err)
	}
	decode1, decode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, fmt.Errorf("carrier decode polys: %w", err)
	}
	membershipPoly, err := buildCarrierMembershipPoly(bound, q)
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
		Ring:            ringQ,
		Layout:          layout,
		Omega:           append([]uint64(nil), omegaWitness...),
		DomainPoints:    append([]uint64(nil), domainPoints...),
		ThetaABlocks:    thetaABlocks,
		ThetaB:          thetaB,
		PackingSelCoeff: packingSelCoeff,
		LagrangeBasis:   lagrangeBasis,
		TransformH:      transformHCoeff,
		TransformHEval:  transformHEval,
		NTTPoints:       append([]uint64(nil), nttPoints...),
		Decode1:         decode1,
		Decode2:         decode2,
		MembershipPoly:  membershipPoly,
		KeyBindLayout:   keyBindLayout,
		PRFConstRows:    prfConstRows,
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
		blocks := len(cfg.ThetaABlocks)
		uCount := len(cfg.ThetaABlocks[0][0])
		fpar := make([]uint64, 0, blocks*len(cfg.ThetaABlocks[0])+6+cfg.KeyBindLayout.KeyCount)

		for b := 0; b < blocks; b++ {
			tRow := layout.IdxTHatBase + b
			tVal, err := getRow(tRow)
			if err != nil {
				return nil, nil, err
			}
			for i := range cfg.ThetaABlocks[b] {
				acc := uint64(0)
				for j := 0; j < len(cfg.ThetaABlocks[b][i]); j++ {
					idx := layout.IdxSigHatBase + j
					if b > 0 {
						idx = layout.SigHatExtraBase + (b-1)*uCount + j
					}
					uVal, err := getRow(idx)
					if err != nil {
						return nil, nil, err
					}
					aVal := EvalPoly(cfg.ThetaABlocks[b][i][j], x, q) % q
					acc = modAdd(acc, modMul(aVal, uVal, q), q)
				}
				fpar = append(fpar, modSub(acc, tVal, q))
			}
		}

		mHat1, err := getRow(layout.IdxMHat1)
		if err != nil {
			return nil, nil, err
		}
		mHat2, err := getRow(layout.IdxMHat2)
		if err != nil {
			return nil, nil, err
		}
		rHat0, err := getRow(layout.IdxRHat0)
		if err != nil {
			return nil, nil, err
		}
		rHat1, err := getRow(layout.IdxRHat1)
		if err != nil {
			return nil, nil, err
		}
		tHat0, err := getRow(layout.IdxTHatBase)
		if err != nil {
			return nil, nil, err
		}
		b0 := EvalPoly(cfg.ThetaB[0], x, q) % q
		b1 := EvalPoly(cfg.ThetaB[1], x, q) % q
		b2 := EvalPoly(cfg.ThetaB[2], x, q) % q
		b3 := EvalPoly(cfg.ThetaB[3], x, q) % q
		hashNum := modAdd(b0, modMul(b1, modAdd(mHat1, mHat2, q), q), q)
		hashNum = modAdd(hashNum, modMul(b2, rHat0, q), q)
		hashDen := modSub(b3, rHat1, q)
		fpar = append(fpar, modSub(modMul(hashDen, tHat0, q), hashNum, q))

		cM, err := getRow(layout.IdxCarrierM)
		if err != nil {
			return nil, nil, err
		}
		cCtr, err := getRow(layout.IdxCarrierCtr)
		if err != nil {
			return nil, nil, err
		}
		m1 := EvalPoly(cfg.Decode1, cM, q) % q
		m2 := EvalPoly(cfg.Decode2, cM, q) % q
		r0 := EvalPoly(cfg.Decode1, cCtr, q) % q
		r1 := EvalPoly(cfg.Decode2, cCtr, q) % q

		sel := EvalPoly(cfg.PackingSelCoeff, x, q) % q
		fpar = append(fpar, modMul(sel, m1, q))
		fpar = append(fpar, modMul((1+q-sel)%q, m2, q))
		fpar = append(fpar, EvalPoly(cfg.MembershipPoly, cM, q)%q)
		fpar = append(fpar, EvalPoly(cfg.MembershipPoly, cCtr, q)%q)

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
		hEvalVals := make([]uint64, len(cfg.TransformHEval))
		for j := 0; j < len(cfg.LagrangeBasis); j++ {
			lagrangeVals[j] = EvalPoly(cfg.LagrangeBasis[j], x, q) % q
		}
		for j := 0; j < len(cfg.TransformH); j++ {
			hVals[j] = EvalPoly(cfg.TransformH[j], x, q) % q
		}
		for j := 0; j < len(cfg.TransformHEval); j++ {
			hEvalVals[j] = EvalPoly(cfg.TransformHEval[j], x, q) % q
		}
		fagg := make([]uint64, 0)
		for b := 0; b < blocks; b++ {
			for comp := 0; comp < uCount; comp++ {
				hatIdx := cfg.Layout.IdxSigHatBase + comp
				if b > 0 {
					hatIdx = cfg.Layout.SigHatExtraBase + (b-1)*uCount + comp
				}
				hatVal, err := getRow(hatIdx)
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < len(lagrangeVals); j++ {
					t := b*len(lagrangeVals) + j
					if t < 0 || t >= len(cfg.NTTPoints) || t >= len(hVals) {
						return nil, nil, fmt.Errorf("signature bridge index t=%d out of range", t)
					}
					w := cfg.NTTPoints[t] % q
					wBlock := uint64(1)
					for i := 0; i < len(lagrangeVals); i++ {
						wBlock = modMul(wBlock, w, q)
					}
					factor := uint64(1)
					left := uint64(0)
					for bSrc := 0; bSrc < blocks; bSrc++ {
						srcIdx := cfg.Layout.CoeffNativeSig.PackedSigBase + bSrc*cfg.Layout.CoeffNativeSig.PackedSigComponents + comp
						srcVal, err := getRow(srcIdx)
						if err != nil {
							return nil, nil, err
						}
						term := modMul(srcVal, hVals[t], q)
						if factor != 1 {
							term = modMul(term, factor, q)
						}
						left = modAdd(left, term, q)
						factor = modMul(factor, wBlock, q)
					}
					right := modMul(hatVal, lagrangeVals[j], q)
					fagg = append(fagg, modSub(left, right, q))
				}
			}
		}
		for _, pair := range []struct {
			val uint64
			hat uint64
		}{
			{val: m1, hat: mHat1},
			{val: m2, hat: mHat2},
			{val: r0, hat: rHat0},
			{val: r1, hat: rHat1},
		} {
			for j := 0; j < len(lagrangeVals); j++ {
				if j >= len(hEvalVals) {
					return nil, nil, fmt.Errorf("non-sign bridge index j=%d out of range", j)
				}
				left := modMul(pair.val, hEvalVals[j], q)
				right := modMul(pair.hat, lagrangeVals[j], q)
				fagg = append(fagg, modSub(left, right, q))
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
		blocks := len(cfg.ThetaABlocks)
		uCount := len(cfg.ThetaABlocks[0][0])
		fpar := make([]kf.Elem, 0, blocks*len(cfg.ThetaABlocks[0])+6+cfg.KeyBindLayout.KeyCount)

		for b := 0; b < blocks; b++ {
			tRow := cfg.Layout.IdxTHatBase + b
			tVal, err := getRow(tRow)
			if err != nil {
				return nil, nil, err
			}
			for i := range cfg.ThetaABlocks[b] {
				acc := K.Zero()
				for j := 0; j < len(cfg.ThetaABlocks[b][i]); j++ {
					idx := cfg.Layout.IdxSigHatBase + j
					if b > 0 {
						idx = cfg.Layout.SigHatExtraBase + (b-1)*uCount + j
					}
					uVal, err := getRow(idx)
					if err != nil {
						return nil, nil, err
					}
					aVal := K.EvalFPolyAtK(cfg.ThetaABlocks[b][i][j], e)
					acc = K.Add(acc, K.Mul(aVal, uVal))
				}
				fpar = append(fpar, K.Sub(acc, tVal))
			}
		}

		mHat1, err := getRow(cfg.Layout.IdxMHat1)
		if err != nil {
			return nil, nil, err
		}
		mHat2, err := getRow(cfg.Layout.IdxMHat2)
		if err != nil {
			return nil, nil, err
		}
		rHat0, err := getRow(cfg.Layout.IdxRHat0)
		if err != nil {
			return nil, nil, err
		}
		rHat1, err := getRow(cfg.Layout.IdxRHat1)
		if err != nil {
			return nil, nil, err
		}
		tHat0, err := getRow(cfg.Layout.IdxTHatBase)
		if err != nil {
			return nil, nil, err
		}
		b0 := K.EvalFPolyAtK(cfg.ThetaB[0], e)
		b1 := K.EvalFPolyAtK(cfg.ThetaB[1], e)
		b2 := K.EvalFPolyAtK(cfg.ThetaB[2], e)
		b3 := K.EvalFPolyAtK(cfg.ThetaB[3], e)
		hashNum := K.Add(b0, K.Mul(b1, K.Add(mHat1, mHat2)))
		hashNum = K.Add(hashNum, K.Mul(b2, rHat0))
		hashDen := K.Sub(b3, rHat1)
		fpar = append(fpar, K.Sub(K.Mul(hashDen, tHat0), hashNum))

		cM, err := getRow(cfg.Layout.IdxCarrierM)
		if err != nil {
			return nil, nil, err
		}
		cCtr, err := getRow(cfg.Layout.IdxCarrierCtr)
		if err != nil {
			return nil, nil, err
		}
		m1 := K.EvalFPolyAtK(cfg.Decode1, cM)
		m2 := K.EvalFPolyAtK(cfg.Decode2, cM)
		r0 := K.EvalFPolyAtK(cfg.Decode1, cCtr)
		r1 := K.EvalFPolyAtK(cfg.Decode2, cCtr)

		sel := K.EvalFPolyAtK(cfg.PackingSelCoeff, e)
		fpar = append(fpar, K.Mul(sel, m1))
		fpar = append(fpar, K.Mul(K.Sub(K.One(), sel), m2))
		fpar = append(fpar, K.EvalFPolyAtK(cfg.MembershipPoly, cM))
		fpar = append(fpar, K.EvalFPolyAtK(cfg.MembershipPoly, cCtr))

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
		hEvalVals := make([]kf.Elem, len(cfg.TransformHEval))
		for j := 0; j < len(cfg.LagrangeBasis); j++ {
			lagrangeVals[j] = K.EvalFPolyAtK(cfg.LagrangeBasis[j], e)
		}
		for j := 0; j < len(cfg.TransformH); j++ {
			hVals[j] = K.EvalFPolyAtK(cfg.TransformH[j], e)
		}
		for j := 0; j < len(cfg.TransformHEval); j++ {
			hEvalVals[j] = K.EvalFPolyAtK(cfg.TransformHEval[j], e)
		}
		fagg := make([]kf.Elem, 0)
		for b := 0; b < blocks; b++ {
			for comp := 0; comp < uCount; comp++ {
				hatIdx := cfg.Layout.IdxSigHatBase + comp
				if b > 0 {
					hatIdx = cfg.Layout.SigHatExtraBase + (b-1)*uCount + comp
				}
				hatVal, err := getRow(hatIdx)
				if err != nil {
					return nil, nil, err
				}
				for j := 0; j < len(lagrangeVals); j++ {
					t := b*len(lagrangeVals) + j
					if t < 0 || t >= len(cfg.NTTPoints) || t >= len(hVals) {
						return nil, nil, fmt.Errorf("signature bridge index t=%d out of range", t)
					}
					w := cfg.NTTPoints[t] % cfg.Ring.Modulus[0]
					wElem := K.EmbedF(w)
					wBlock := K.One()
					for i := 0; i < len(lagrangeVals); i++ {
						wBlock = K.Mul(wBlock, wElem)
					}
					factor := K.One()
					left := K.Zero()
					for bSrc := 0; bSrc < blocks; bSrc++ {
						srcIdx := cfg.Layout.CoeffNativeSig.PackedSigBase + bSrc*cfg.Layout.CoeffNativeSig.PackedSigComponents + comp
						srcVal, err := getRow(srcIdx)
						if err != nil {
							return nil, nil, err
						}
						term := K.Mul(srcVal, hVals[t])
						if !elemEqual(K, factor, K.One()) {
							term = K.Mul(term, factor)
						}
						left = K.Add(left, term)
						factor = K.Mul(factor, wBlock)
					}
					right := K.Mul(hatVal, lagrangeVals[j])
					fagg = append(fagg, K.Sub(left, right))
				}
			}
		}
		for _, pair := range []struct {
			val kf.Elem
			hat kf.Elem
		}{
			{val: m1, hat: mHat1},
			{val: m2, hat: mHat2},
			{val: r0, hat: rHat0},
			{val: r1, hat: rHat1},
		} {
			for j := 0; j < len(lagrangeVals); j++ {
				if j >= len(hEvalVals) {
					return nil, nil, fmt.Errorf("non-sign bridge index j=%d out of range", j)
				}
				left := K.Mul(pair.val, hEvalVals[j])
				right := K.Mul(pair.hat, lagrangeVals[j])
				fagg = append(fagg, K.Sub(left, right))
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
