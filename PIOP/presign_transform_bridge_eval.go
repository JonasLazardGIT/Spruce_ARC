package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type preSignTransformBridgeConfig struct {
	Ring         *ring.Ring
	Layout       RowLayout
	Omega        []uint64
	DomainPoints []uint64
	Bound        int64

	AcCoeff      [][][]uint64
	ComCoeff     [][]uint64
	RI0Coeff     []uint64
	RI1Coeff     []uint64
	ThetaB       [][]uint64
	TPublicTheta []uint64

	PackingSelCoeff []uint64
	MsgDecode1      []uint64
	MsgDecode2      []uint64
	PairDecode1     []uint64
	PairDecode2     []uint64
	Decode1K        []uint64
	Decode2K        []uint64
	MemMsg          []uint64
	MemBound        []uint64
	MemCarry        []uint64
	LagrangeBasis   [][]uint64
	TransformHEval  [][]uint64
}

func newPreSignTransformBridgeConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64, bound int64) (*preSignTransformBridgeConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omegaWitness) == 0 {
		return nil, fmt.Errorf("empty omega witness")
	}
	if len(domainPoints) == 0 {
		return nil, fmt.Errorf("missing explicit domain points")
	}
	if bound <= 0 {
		return nil, fmt.Errorf("invalid pre-sign bound %d", bound)
	}
	for _, idx := range []int{
		layout.IdxCarrierM, layout.IdxCarrierPreRU, layout.IdxCarrierPreR, layout.IdxCarrierCtr, layout.IdxCarrierK,
		layout.IdxM1, layout.IdxM2, layout.IdxRU0, layout.IdxRU1, layout.IdxR, layout.IdxR0, layout.IdxR1, layout.IdxK0, layout.IdxK1,
		layout.IdxMHat1, layout.IdxMHat2, layout.IdxRHat0, layout.IdxRHat1,
	} {
		if idx < 0 {
			return nil, fmt.Errorf("pre-sign transform-bridge config requires explicit carrier/alias/hat indices")
		}
	}
	if len(pub.Ac) == 0 || len(pub.Com) == 0 || len(pub.RI0) == 0 || len(pub.RI1) == 0 || len(pub.B) < 4 || len(pub.T) == 0 {
		return nil, fmt.Errorf("missing public pre-sign inputs for transform-bridge replay")
	}
	q := ringQ.Modulus[0]
	toThetaCoeff := func(p *ring.Poly, name string) ([]uint64, error) {
		coeff, err := coeffFromNTTPoly(ringQ, p)
		if err != nil {
			return nil, fmt.Errorf("%s coeffs: %w", name, err)
		}
		return trimPoly(coeff, q), nil
	}

	acCoeff := make([][][]uint64, len(pub.Ac))
	for i := range pub.Ac {
		acCoeff[i] = make([][]uint64, len(pub.Ac[i]))
		for j := range pub.Ac[i] {
			theta, err := thetaPolyFromNTT(ringQ, pub.Ac[i][j], omegaWitness)
			if err != nil {
				return nil, fmt.Errorf("theta Ac[%d][%d]: %w", i, j, err)
			}
			coeff, err := toThetaCoeff(theta, fmt.Sprintf("theta Ac[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			acCoeff[i][j] = coeff
		}
	}
	comCoeff := make([][]uint64, len(pub.Com))
	for i := range pub.Com {
		theta, err := thetaPolyFromNTT(ringQ, pub.Com[i], omegaWitness)
		if err != nil {
			return nil, fmt.Errorf("theta Com[%d]: %w", i, err)
		}
		coeff, err := toThetaCoeff(theta, fmt.Sprintf("theta Com[%d]", i))
		if err != nil {
			return nil, err
		}
		comCoeff[i] = coeff
	}
	thetaRI0, err := thetaPolyFromNTT(ringQ, pub.RI0[0], omegaWitness)
	if err != nil {
		return nil, fmt.Errorf("theta RI0: %w", err)
	}
	ri0Coeff, err := toThetaCoeff(thetaRI0, "theta RI0")
	if err != nil {
		return nil, err
	}
	thetaRI1, err := thetaPolyFromNTT(ringQ, pub.RI1[0], omegaWitness)
	if err != nil {
		return nil, fmt.Errorf("theta RI1: %w", err)
	}
	ri1Coeff, err := toThetaCoeff(thetaRI1, "theta RI1")
	if err != nil {
		return nil, err
	}
	thetaB := make([][]uint64, 4)
	for i := 0; i < 4; i++ {
		theta, err := thetaPolyFromNTT(ringQ, pub.B[i], omegaWitness)
		if err != nil {
			return nil, fmt.Errorf("theta B[%d]: %w", i, err)
		}
		coeff, err := toThetaCoeff(theta, fmt.Sprintf("theta B[%d]", i))
		if err != nil {
			return nil, err
		}
		thetaB[i] = coeff
	}
	publicTTheta, err := thetaPolyFromCoeff(ringQ, pub.T, omegaWitness)
	if err != nil {
		return nil, fmt.Errorf("theta public T: %w", err)
	}
	tPublicCoeff, err := toThetaCoeff(publicTTheta, "theta public T")
	if err != nil {
		return nil, err
	}
	packingSelCoeff, err := buildPackingSelectorCoeff(ringQ, omegaWitness)
	if err != nil {
		return nil, fmt.Errorf("packing selector coeffs: %w", err)
	}
	msgDecode1, msgDecode2, err := buildPackedMessageCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, fmt.Errorf("message carrier decode polys: %w", err)
	}
	decode1, decode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, fmt.Errorf("carrier decode polys: %w", err)
	}
	decode1K, decode2K, err := buildCarrierDecodePolys(1, q)
	if err != nil {
		return nil, fmt.Errorf("carrier K decode polys: %w", err)
	}
	memMsg, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		return nil, fmt.Errorf("message carrier membership poly: %w", err)
	}
	memBound, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return nil, fmt.Errorf("carrier membership poly: %w", err)
	}
	memCarry, err := buildCarrierMembershipPoly(1, q)
	if err != nil {
		return nil, fmt.Errorf("carrier K membership poly: %w", err)
	}
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, len(omegaWitness), 1)
	if err != nil {
		return nil, fmt.Errorf("transform-bridge basis: %w", err)
	}

	return &preSignTransformBridgeConfig{
		Ring:            ringQ,
		Layout:          layout,
		Omega:           append([]uint64(nil), omegaWitness...),
		DomainPoints:    append([]uint64(nil), domainPoints...),
		Bound:           bound,
		AcCoeff:         acCoeff,
		ComCoeff:        comCoeff,
		RI0Coeff:        ri0Coeff,
		RI1Coeff:        ri1Coeff,
		ThetaB:          thetaB,
		TPublicTheta:    tPublicCoeff,
		PackingSelCoeff: packingSelCoeff,
		MsgDecode1:      msgDecode1,
		MsgDecode2:      msgDecode2,
		PairDecode1:     decode1,
		PairDecode2:     decode2,
		Decode1K:        decode1K,
		Decode2K:        decode2K,
		MemMsg:          memMsg,
		MemBound:        memBound,
		MemCarry:        memCarry,
		LagrangeBasis:   bridgeBasis.LagrangeBasis,
		TransformHEval:  bridgeBasis.TransformHEval,
	}, nil
}

func (cfg *preSignTransformBridgeConfig) CoreEvaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil pre-sign transform-bridge replay config")
		}
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return nil, nil, fmt.Errorf("pre-sign eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
		}
		q := cfg.Ring.Modulus[0]
		x := cfg.DomainPoints[ptIdx] % q
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		decodeVal := func(coeff []uint64, code uint64) uint64 {
			return EvalPoly(coeff, code%q, q) % q
		}

		layout := cfg.Layout
		carrierM, err := getRow(layout.IdxCarrierM)
		if err != nil {
			return nil, nil, err
		}
		carrierRU, err := getRow(layout.IdxCarrierPreRU)
		if err != nil {
			return nil, nil, err
		}
		carrierR, err := getRow(layout.IdxCarrierPreR)
		if err != nil {
			return nil, nil, err
		}
		carrierCtr, err := getRow(layout.IdxCarrierCtr)
		if err != nil {
			return nil, nil, err
		}
		carrierK, err := getRow(layout.IdxCarrierK)
		if err != nil {
			return nil, nil, err
		}
		m1Dec := decodeVal(cfg.MsgDecode1, carrierM)
		m2Dec := decodeVal(cfg.MsgDecode2, carrierM)
		ru0Dec := decodeVal(cfg.PairDecode1, carrierRU)
		ru1Dec := decodeVal(cfg.PairDecode2, carrierRU)
		rDec := decodeVal(cfg.PairDecode1, carrierR)
		r0Dec := decodeVal(cfg.PairDecode1, carrierCtr)
		r1Dec := decodeVal(cfg.PairDecode2, carrierCtr)
		k0Dec := decodeVal(cfg.Decode1K, carrierK)
		k1Dec := decodeVal(cfg.Decode2K, carrierK)

		m1, err := getRow(layout.IdxM1)
		if err != nil {
			return nil, nil, err
		}
		m2, err := getRow(layout.IdxM2)
		if err != nil {
			return nil, nil, err
		}
		ru0, err := getRow(layout.IdxRU0)
		if err != nil {
			return nil, nil, err
		}
		ru1, err := getRow(layout.IdxRU1)
		if err != nil {
			return nil, nil, err
		}
		rVal, err := getRow(layout.IdxR)
		if err != nil {
			return nil, nil, err
		}
		r0v, err := getRow(layout.IdxR0)
		if err != nil {
			return nil, nil, err
		}
		r1v, err := getRow(layout.IdxR1)
		if err != nil {
			return nil, nil, err
		}
		k0, err := getRow(layout.IdxK0)
		if err != nil {
			return nil, nil, err
		}
		k1, err := getRow(layout.IdxK1)
		if err != nil {
			return nil, nil, err
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

		fpar := []uint64{
			modSub(m1, m1Dec, q),
			modSub(m2, m2Dec, q),
			modSub(ru0, ru0Dec, q),
			modSub(ru1, ru1Dec, q),
			modSub(rVal, rDec, q),
			modSub(r0v, r0Dec, q),
			modSub(r1v, r1Dec, q),
			modSub(k0, k0Dec, q),
			modSub(k1, k1Dec, q),
		}
		for i := range cfg.AcCoeff {
			sum := uint64(0)
			if i < len(cfg.ComCoeff) {
				sum = modSub(sum, EvalPoly(cfg.ComCoeff[i], x, q)%q, q)
			}
			for j := 0; j < len(cfg.AcCoeff[i]); j++ {
				aVal := EvalPoly(cfg.AcCoeff[i][j], x, q) % q
				switch j {
				case 0:
					sum = modAdd(sum, modMul(aVal, m1, q), q)
				case 1:
					sum = modAdd(sum, modMul(aVal, m2, q), q)
				case 2:
					sum = modAdd(sum, modMul(aVal, ru0, q), q)
				case 3:
					sum = modAdd(sum, modMul(aVal, ru1, q), q)
				case 4:
					sum = modAdd(sum, modMul(aVal, rVal, q), q)
				}
			}
			fpar = append(fpar, sum)
		}

		delta := uint64(2*cfg.Bound + 1)
		ri0 := EvalPoly(cfg.RI0Coeff, x, q) % q
		ri1 := EvalPoly(cfg.RI1Coeff, x, q) % q
		res0 := modSub(modSub(modAdd(ru0, ri0, q), r0v, q), modMul(delta%q, k0, q), q)
		res1 := modSub(modSub(modAdd(ru1, ri1, q), r1v, q), modMul(delta%q, k1, q), q)
		fpar = append(fpar, res0, res1)

		tTheta := EvalPoly(cfg.TPublicTheta, x, q) % q
		fpar = append(fpar, transformHashResidualEval(q, x, cfg.ThetaB, mHat1, mHat2, rHat0, rHat1, tTheta))

		sel := EvalPoly(cfg.PackingSelCoeff, x, q) % q
		fpar = append(fpar, modMul(sel, m1, q))
		fpar = append(fpar, modMul((1+q-sel)%q, m2, q))

		fpar = append(fpar,
			EvalPoly(cfg.MemMsg, carrierM, q)%q,
			EvalPoly(cfg.MemBound, carrierRU, q)%q,
			EvalPoly(cfg.MemBound, carrierR, q)%q,
			EvalPoly(cfg.MemBound, carrierCtr, q)%q,
			EvalPoly(cfg.MemCarry, carrierK, q)%q,
		)

		lagrangeVals := make([]uint64, len(cfg.LagrangeBasis))
		hVals := make([]uint64, len(cfg.TransformHEval))
		for j := range cfg.LagrangeBasis {
			lagrangeVals[j] = EvalPoly(cfg.LagrangeBasis[j], x, q) % q
			hVals[j] = EvalPoly(cfg.TransformHEval[j], x, q) % q
		}
		fagg := make([]uint64, 0, 4*len(cfg.LagrangeBasis))
		for _, pair := range []struct {
			src uint64
			hat uint64
		}{
			{src: m1, hat: mHat1},
			{src: m2, hat: mHat2},
			{src: r0v, hat: rHat0},
			{src: r1v, hat: rHat1},
		} {
			for j := 0; j < len(cfg.LagrangeBasis); j++ {
				fagg = append(fagg, modSub(modMul(pair.src, hVals[j], q), modMul(pair.hat, lagrangeVals[j], q), q))
			}
		}
		return fpar, fagg, nil
	}
}

func (cfg *preSignTransformBridgeConfig) CoreKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil pre-sign transform-bridge replay config")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	deltaK := K.EmbedF(uint64(2*cfg.Bound+1) % cfg.Ring.Modulus[0])
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		decodeVal := func(coeff []uint64, code kf.Elem) kf.Elem {
			return K.EvalFPolyAtK(coeff, code)
		}
		layout := cfg.Layout
		carrierM, err := getRow(layout.IdxCarrierM)
		if err != nil {
			return nil, nil, err
		}
		carrierRU, err := getRow(layout.IdxCarrierPreRU)
		if err != nil {
			return nil, nil, err
		}
		carrierR, err := getRow(layout.IdxCarrierPreR)
		if err != nil {
			return nil, nil, err
		}
		carrierCtr, err := getRow(layout.IdxCarrierCtr)
		if err != nil {
			return nil, nil, err
		}
		carrierK, err := getRow(layout.IdxCarrierK)
		if err != nil {
			return nil, nil, err
		}
		m1Dec := decodeVal(cfg.MsgDecode1, carrierM)
		m2Dec := decodeVal(cfg.MsgDecode2, carrierM)
		ru0Dec := decodeVal(cfg.PairDecode1, carrierRU)
		ru1Dec := decodeVal(cfg.PairDecode2, carrierRU)
		rDec := decodeVal(cfg.PairDecode1, carrierR)
		r0Dec := decodeVal(cfg.PairDecode1, carrierCtr)
		r1Dec := decodeVal(cfg.PairDecode2, carrierCtr)
		k0Dec := decodeVal(cfg.Decode1K, carrierK)
		k1Dec := decodeVal(cfg.Decode2K, carrierK)

		m1, err := getRow(layout.IdxM1)
		if err != nil {
			return nil, nil, err
		}
		m2, err := getRow(layout.IdxM2)
		if err != nil {
			return nil, nil, err
		}
		ru0, err := getRow(layout.IdxRU0)
		if err != nil {
			return nil, nil, err
		}
		ru1, err := getRow(layout.IdxRU1)
		if err != nil {
			return nil, nil, err
		}
		rVal, err := getRow(layout.IdxR)
		if err != nil {
			return nil, nil, err
		}
		r0v, err := getRow(layout.IdxR0)
		if err != nil {
			return nil, nil, err
		}
		r1v, err := getRow(layout.IdxR1)
		if err != nil {
			return nil, nil, err
		}
		k0, err := getRow(layout.IdxK0)
		if err != nil {
			return nil, nil, err
		}
		k1, err := getRow(layout.IdxK1)
		if err != nil {
			return nil, nil, err
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

		fpar := []kf.Elem{
			K.Sub(m1, m1Dec),
			K.Sub(m2, m2Dec),
			K.Sub(ru0, ru0Dec),
			K.Sub(ru1, ru1Dec),
			K.Sub(rVal, rDec),
			K.Sub(r0v, r0Dec),
			K.Sub(r1v, r1Dec),
			K.Sub(k0, k0Dec),
			K.Sub(k1, k1Dec),
		}
		for i := range cfg.AcCoeff {
			sum := K.Zero()
			if i < len(cfg.ComCoeff) {
				sum = K.Sub(sum, K.EvalFPolyAtK(cfg.ComCoeff[i], e))
			}
			for j := 0; j < len(cfg.AcCoeff[i]); j++ {
				aVal := K.EvalFPolyAtK(cfg.AcCoeff[i][j], e)
				switch j {
				case 0:
					sum = K.Add(sum, K.Mul(aVal, m1))
				case 1:
					sum = K.Add(sum, K.Mul(aVal, m2))
				case 2:
					sum = K.Add(sum, K.Mul(aVal, ru0))
				case 3:
					sum = K.Add(sum, K.Mul(aVal, ru1))
				case 4:
					sum = K.Add(sum, K.Mul(aVal, rVal))
				}
			}
			fpar = append(fpar, sum)
		}
		ri0 := K.EvalFPolyAtK(cfg.RI0Coeff, e)
		ri1 := K.EvalFPolyAtK(cfg.RI1Coeff, e)
		fpar = append(fpar,
			K.Sub(K.Sub(K.Add(ru0, ri0), r0v), K.Mul(deltaK, k0)),
			K.Sub(K.Sub(K.Add(ru1, ri1), r1v), K.Mul(deltaK, k1)),
		)
		tTheta := K.EvalFPolyAtK(cfg.TPublicTheta, e)
		fpar = append(fpar, transformHashResidualKEval(K, e, cfg.ThetaB, mHat1, mHat2, rHat0, rHat1, tTheta))
		sel := K.EvalFPolyAtK(cfg.PackingSelCoeff, e)
		fpar = append(fpar, K.Mul(sel, m1), K.Mul(K.Sub(K.One(), sel), m2))
		fpar = append(fpar,
			K.EvalFPolyAtK(cfg.MemMsg, carrierM),
			K.EvalFPolyAtK(cfg.MemBound, carrierRU),
			K.EvalFPolyAtK(cfg.MemBound, carrierR),
			K.EvalFPolyAtK(cfg.MemBound, carrierCtr),
			K.EvalFPolyAtK(cfg.MemCarry, carrierK),
		)

		lagrangeVals := make([]kf.Elem, len(cfg.LagrangeBasis))
		hVals := make([]kf.Elem, len(cfg.TransformHEval))
		for j := range cfg.LagrangeBasis {
			lagrangeVals[j] = K.EvalFPolyAtK(cfg.LagrangeBasis[j], e)
			hVals[j] = K.EvalFPolyAtK(cfg.TransformHEval[j], e)
		}
		fagg := make([]kf.Elem, 0, 4*len(cfg.LagrangeBasis))
		for _, pair := range []struct {
			src kf.Elem
			hat kf.Elem
		}{
			{src: m1, hat: mHat1},
			{src: m2, hat: mHat2},
			{src: r0v, hat: rHat0},
			{src: r1v, hat: rHat1},
		} {
			for j := 0; j < len(cfg.LagrangeBasis); j++ {
				fagg = append(fagg, K.Sub(K.Mul(pair.src, hVals[j]), K.Mul(pair.hat, lagrangeVals[j])))
			}
		}
		return fpar, fagg, nil
	}, nil
}
