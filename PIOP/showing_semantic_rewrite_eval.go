package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type semanticRewritePostSignConfig struct {
	Ring            *ring.Ring
	Layout          RowLayout
	Bound           int64
	Omega           []uint64
	DomainPoints    []uint64
	ThetaABlocks    [][][][]uint64
	ThetaB          [][]uint64
	ThetaTPublic    [][]uint64
	PackingSelCoeff []uint64
}

func newSemanticRewritePostSignConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64, bound int64) (*semanticRewritePostSignConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesSemanticRewrite(layout) {
		return nil, fmt.Errorf("semantic rewrite config requires semantic rewrite coeff-native layout")
	}
	if len(pub.A) == 0 || len(pub.A[0]) == 0 {
		return nil, fmt.Errorf("missing A for semantic rewrite replay")
	}
	if len(pub.B) < 4 {
		return nil, fmt.Errorf("semantic rewrite replay requires 4 B rows, got %d", len(pub.B))
	}
	if len(omegaWitness) == 0 {
		return nil, fmt.Errorf("empty omega witness")
	}
	ncols := len(omegaWitness)
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

	var thetaTPublic [][]uint64
	if blocks > 1 && layout.SigDerivedT {
		if len(pub.T) < blocks*ncols {
			return nil, fmt.Errorf("public T length %d too small for %d signature blocks of size %d", len(pub.T), blocks, ncols)
		}
		thetaTPublic = make([][]uint64, blocks)
		for b := 0; b < blocks; b++ {
			start := b * ncols
			end := start + ncols
			vals := append([]int64(nil), pub.T[start:end]...)
			theta, err := thetaPolyFromValues(ringQ, vals, omegaWitness)
			if err != nil {
				return nil, fmt.Errorf("theta T block %d: %w", b, err)
			}
			coeff, err := coeffFromNTTPoly(ringQ, theta)
			if err != nil {
				return nil, fmt.Errorf("theta T block %d coeffs: %w", b, err)
			}
			thetaTPublic[b] = coeff
		}
	}

	packingSelCoeff, err := buildPackingSelectorCoeff(ringQ, omegaWitness)
	if err != nil {
		return nil, fmt.Errorf("packing selector coeffs: %w", err)
	}

	return &semanticRewritePostSignConfig{
		Ring:            ringQ,
		Layout:          layout,
		Bound:           bound,
		Omega:           append([]uint64(nil), omegaWitness...),
		DomainPoints:    append([]uint64(nil), domainPoints...),
		ThetaABlocks:    thetaABlocks,
		ThetaB:          thetaB,
		ThetaTPublic:    thetaTPublic,
		PackingSelCoeff: packingSelCoeff,
	}, nil
}

func (cfg *semanticRewritePostSignConfig) nonSigBoundChainConfig() (NonSigBoundChainConfig, bool, error) {
	if cfg == nil || cfg.Ring == nil || cfg.Bound <= 0 {
		return NonSigBoundChainConfig{}, false, nil
	}
	rowsPer := inferNonSigBoundRowsPer(cfg.Layout)
	if rowsPer <= 0 || cfg.Layout.MsgChainBase < 0 || cfg.Layout.RndChainBase < 0 {
		return NonSigBoundChainConfig{}, false, nil
	}
	specBound, err := nonSigBoundLinfSpec(cfg.Ring.Modulus[0], cfg.Bound)
	if err != nil {
		return NonSigBoundChainConfig{}, false, fmt.Errorf("semantic rewrite non-sign bound chain spec: %w", err)
	}
	postBoundRows := postSignBoundRowIndices(cfg.Layout)
	if len(postBoundRows) != 4 {
		return NonSigBoundChainConfig{}, false, fmt.Errorf("semantic rewrite non-sign bound rows=%d want 4", len(postBoundRows))
	}
	return NonSigBoundChainConfig{
		Ring:         cfg.Ring,
		Spec:         specBound,
		SourceRows:   append([]int(nil), postBoundRows...),
		ChainBases:   []int{cfg.Layout.MsgChainBase, cfg.Layout.MsgChainBase + rowsPer, cfg.Layout.RndChainBase, cfg.Layout.RndChainBase + rowsPer},
		Omega:        append([]uint64(nil), cfg.Omega...),
		DomainPoints: append([]uint64(nil), cfg.DomainPoints...),
	}, true, nil
}

func (cfg *semanticRewritePostSignConfig) Evaluator() ConstraintEvaluator {
	return cfg.evaluator(true)
}

func (cfg *semanticRewritePostSignConfig) CoreEvaluator() ConstraintEvaluator {
	return cfg.evaluator(false)
}

func (cfg *semanticRewritePostSignConfig) evaluator(includeBounds bool) ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil semantic rewrite replay config")
		}
		if len(cfg.DomainPoints) == 0 {
			return nil, nil, fmt.Errorf("semantic rewrite replay requires explicit domain points")
		}
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return nil, nil, fmt.Errorf("semantic rewrite eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
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
		uCount := len(cfg.ThetaABlocks[0][0])
		blocks := len(cfg.ThetaABlocks)
		fparCap := blocks*len(cfg.ThetaABlocks[0]) + 3
		if includeBounds {
			fparCap += len(rowLayoutPostSignBoundRows(layout))
		}
		fpar := make([]uint64, 0, fparCap)

		for b := 0; b < blocks; b++ {
			tVal, err := getRow(rowLayoutPostSignT(layout))
			if err != nil {
				return nil, nil, err
			}
			if layout.SigExtraTBase >= 0 {
				tRow := layout.SigExtraTBase + b
				tVal, err = getRow(tRow)
				if err != nil {
					return nil, nil, err
				}
			} else if b > 0 && layout.SigDerivedT {
				if b >= len(cfg.ThetaTPublic) || len(cfg.ThetaTPublic[b]) == 0 {
					return nil, nil, fmt.Errorf("missing public T block %d", b)
				}
				tVal = EvalPoly(cfg.ThetaTPublic[b], x, q) % q
			}
			for i := range cfg.ThetaABlocks[b] {
				acc := uint64(0)
				for j := 0; j < len(cfg.ThetaABlocks[b][i]); j++ {
					uIdx := rowLayoutPostSignUBase(layout) + j
					if b > 0 {
						uIdx = layout.SigExtraUBase + (b-1)*uCount + j
					}
					uVal, err := getRow(uIdx)
					if err != nil {
						return nil, nil, err
					}
					aVal := EvalPoly(cfg.ThetaABlocks[b][i][j], x, q) % q
					acc = modAdd(acc, modMul(aVal, uVal, q), q)
				}
				fpar = append(fpar, modSub(acc, tVal, q))
			}
		}

		m1, err := getRow(rowLayoutPostSignM1(layout))
		if err != nil {
			return nil, nil, err
		}
		m2, err := getRow(rowLayoutPostSignM2(layout))
		if err != nil {
			return nil, nil, err
		}
		r0, err := getRow(rowLayoutPostSignR0(layout))
		if err != nil {
			return nil, nil, err
		}
		r1, err := getRow(rowLayoutPostSignR1(layout))
		if err != nil {
			return nil, nil, err
		}
		tVal, err := getRow(rowLayoutPostSignT(layout))
		if err != nil {
			return nil, nil, err
		}
		b0 := EvalPoly(cfg.ThetaB[0], x, q) % q
		b1 := EvalPoly(cfg.ThetaB[1], x, q) % q
		b2 := EvalPoly(cfg.ThetaB[2], x, q) % q
		b3 := EvalPoly(cfg.ThetaB[3], x, q) % q
		hashNum := modAdd(b0, modMul(b1, modAdd(m1, m2, q), q), q)
		hashNum = modAdd(hashNum, modMul(b2, r0, q), q)
		hashDen := modSub(b3, r1, q)
		fpar = append(fpar, modSub(modMul(hashDen, tVal, q), hashNum, q))

		sel := EvalPoly(cfg.PackingSelCoeff, x, q) % q
		fpar = append(fpar, modMul(sel, m1, q))
		fpar = append(fpar, modMul((1+q-sel)%q, m2, q))

		if includeBounds {
			for _, idx := range rowLayoutPostSignBoundRows(layout) {
				v, err := getRow(idx)
				if err != nil {
					return nil, nil, err
				}
				fpar = append(fpar, boundPoly(int64(v), cfg.Bound, int64(q))%q)
			}
		}
		return fpar, nil, nil
	}
}

func (cfg *semanticRewritePostSignConfig) KEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	return cfg.kEvaluator(K, true)
}

func (cfg *semanticRewritePostSignConfig) CoreKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	return cfg.kEvaluator(K, false)
}

func (cfg *semanticRewritePostSignConfig) kEvaluator(K *kf.Field, includeBounds bool) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil semantic rewrite replay config")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}

		layout := cfg.Layout
		uCount := len(cfg.ThetaABlocks[0][0])
		blocks := len(cfg.ThetaABlocks)
		fparCap := blocks*len(cfg.ThetaABlocks[0]) + 3
		if includeBounds {
			fparCap += len(rowLayoutPostSignBoundRows(layout))
		}
		fpar := make([]kf.Elem, 0, fparCap)

		for b := 0; b < blocks; b++ {
			tVal, err := getRow(rowLayoutPostSignT(layout))
			if err != nil {
				return nil, nil, err
			}
			if layout.SigExtraTBase >= 0 {
				tRow := layout.SigExtraTBase + b
				tVal, err = getRow(tRow)
				if err != nil {
					return nil, nil, err
				}
			} else if b > 0 && layout.SigDerivedT {
				if b >= len(cfg.ThetaTPublic) || len(cfg.ThetaTPublic[b]) == 0 {
					return nil, nil, fmt.Errorf("missing public T block %d", b)
				}
				tVal = K.EvalFPolyAtK(cfg.ThetaTPublic[b], e)
			}
			for i := range cfg.ThetaABlocks[b] {
				acc := K.Zero()
				for j := 0; j < len(cfg.ThetaABlocks[b][i]); j++ {
					uIdx := rowLayoutPostSignUBase(layout) + j
					if b > 0 {
						uIdx = layout.SigExtraUBase + (b-1)*uCount + j
					}
					uVal, err := getRow(uIdx)
					if err != nil {
						return nil, nil, err
					}
					aVal := K.EvalFPolyAtK(cfg.ThetaABlocks[b][i][j], e)
					acc = K.Add(acc, K.Mul(aVal, uVal))
				}
				fpar = append(fpar, K.Sub(acc, tVal))
			}
		}

		m1, err := getRow(rowLayoutPostSignM1(layout))
		if err != nil {
			return nil, nil, err
		}
		m2, err := getRow(rowLayoutPostSignM2(layout))
		if err != nil {
			return nil, nil, err
		}
		r0, err := getRow(rowLayoutPostSignR0(layout))
		if err != nil {
			return nil, nil, err
		}
		r1, err := getRow(rowLayoutPostSignR1(layout))
		if err != nil {
			return nil, nil, err
		}
		tVal, err := getRow(rowLayoutPostSignT(layout))
		if err != nil {
			return nil, nil, err
		}
		b0 := K.EvalFPolyAtK(cfg.ThetaB[0], e)
		b1 := K.EvalFPolyAtK(cfg.ThetaB[1], e)
		b2 := K.EvalFPolyAtK(cfg.ThetaB[2], e)
		b3 := K.EvalFPolyAtK(cfg.ThetaB[3], e)
		hashNum := K.Add(b0, K.Mul(b1, K.Add(m1, m2)))
		hashNum = K.Add(hashNum, K.Mul(b2, r0))
		hashDen := K.Sub(b3, r1)
		fpar = append(fpar, K.Sub(K.Mul(hashDen, tVal), hashNum))

		sel := K.EvalFPolyAtK(cfg.PackingSelCoeff, e)
		fpar = append(fpar, K.Mul(sel, m1))
		fpar = append(fpar, K.Mul(K.Sub(K.One(), sel), m2))

		if includeBounds {
			for _, idx := range rowLayoutPostSignBoundRows(layout) {
				v, err := getRow(idx)
				if err != nil {
					return nil, nil, err
				}
				fpar = append(fpar, boundPolyK(K, v, cfg.Bound))
			}
		}
		return fpar, nil, nil
	}, nil
}

func (cfg *semanticRewritePostSignConfig) BoundsEvaluator() ConstraintEvaluator {
	if chainCfg, ok, err := cfg.nonSigBoundChainConfig(); err != nil {
		return func(uint64, []uint64) ([]uint64, []uint64, error) {
			return nil, nil, err
		}
	} else if ok {
		return chainCfg.NonSigBoundChainEvaluator()
	}
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil semantic rewrite replay config")
		}
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		fpar := make([]uint64, 0, len(rowLayoutPostSignBoundRows(cfg.Layout)))
		for _, idx := range rowLayoutPostSignBoundRows(cfg.Layout) {
			v, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar, boundPoly(int64(v), cfg.Bound, int64(q))%q)
		}
		return fpar, nil, nil
	}
}

func (cfg *semanticRewritePostSignConfig) BoundsKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil semantic rewrite replay config")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if chainCfg, ok, err := cfg.nonSigBoundChainConfig(); err != nil {
		return nil, err
	} else if ok {
		return chainCfg.NonSigBoundChainKEvaluator(K)
	}
	return func(_ kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		fpar := make([]kf.Elem, 0, len(rowLayoutPostSignBoundRows(cfg.Layout)))
		for _, idx := range rowLayoutPostSignBoundRows(cfg.Layout) {
			v, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			fpar = append(fpar, boundPolyK(K, v, cfg.Bound))
		}
		return fpar, nil, nil
	}, nil
}
