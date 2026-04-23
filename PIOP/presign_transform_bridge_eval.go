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
	BoundB       int64
	X0Bound      int64
	X0Len        int
	HashRelation string

	AcCoeff      [][][]uint64
	ComCoeff     [][]uint64
	RI0Coeff     [][]uint64
	RI1Coeff     []uint64
	ThetaB       [][]uint64
	TPublicTheta []uint64

	PackingSelCoeff []uint64
	MsgDecode1      []uint64
	MsgDecode2      []uint64
	X0Decode1       []uint64
	X0CarryDecode   []uint64
	ScalarDecode1   []uint64
	ScalarDecode2   []uint64
	Decode1K        []uint64
	Decode2K        []uint64
	MemMsg          []uint64
	MemX0           []uint64
	MemX0Carry      []uint64
	MemScalar       []uint64
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
	x0Len := pub.X0Len
	if x0Len <= 0 {
		x0Len = rowLayoutX0Len(layout)
	}
	if x0Len <= 0 {
		return nil, fmt.Errorf("invalid pre-sign x0 length %d", x0Len)
	}
	if pub.X0CoeffBound <= 0 {
		return nil, fmt.Errorf("invalid pre-sign x0 bound %d", pub.X0CoeffBound)
	}
	requiredScalar := []int{
		layout.IdxCarrierM,
		layout.IdxCarrierRU1,
		layout.IdxCarrierPreR,
		layout.IdxCarrierR1,
		layout.IdxCarrierK1,
		layout.IdxM1,
		layout.IdxM2,
		layout.IdxRU1,
		layout.IdxR,
		layout.IdxR1,
		layout.IdxK1,
		layout.IdxMHat1,
		layout.IdxMHat2,
		layout.IdxRHat1,
	}
	if publicUsesBBTran(pub) {
		requiredScalar = append(requiredScalar, layout.IdxZHat)
	}
	for _, idx := range requiredScalar {
		if idx < 0 {
			return nil, fmt.Errorf("pre-sign transform-bridge config requires explicit scalar carrier/alias/hat indices")
		}
	}
	if len(rowLayoutPreSignCarrierRU0Rows(layout)) != x0Len || len(rowLayoutPostSignCarrierR0Rows(layout)) != x0Len || len(rowLayoutPreSignCarrierK0Rows(layout)) != x0Len {
		return nil, fmt.Errorf("pre-sign transform-bridge config missing x0 carrier blocks: ru0=%d r0=%d k0=%d want %d", len(rowLayoutPreSignCarrierRU0Rows(layout)), len(rowLayoutPostSignCarrierR0Rows(layout)), len(rowLayoutPreSignCarrierK0Rows(layout)), x0Len)
	}
	if len(rowLayoutPreSignRU0Rows(layout)) != x0Len || len(rowLayoutPostSignR0Rows(layout)) != x0Len || len(rowLayoutPreSignK0Rows(layout)) != x0Len {
		return nil, fmt.Errorf("pre-sign transform-bridge config missing x0 alias blocks: ru0=%d r0=%d k0=%d want %d", len(rowLayoutPreSignRU0Rows(layout)), len(rowLayoutPostSignR0Rows(layout)), len(rowLayoutPreSignK0Rows(layout)), x0Len)
	}
	if len(rowLayoutPostSignRHat0Rows(layout)) != x0Len {
		return nil, fmt.Errorf("pre-sign transform-bridge config missing x0 replay hats: got %d want %d", len(rowLayoutPostSignRHat0Rows(layout)), x0Len)
	}
	if len(pub.Ac) == 0 || len(pub.Com) == 0 || len(pub.RI0) == 0 || len(pub.RI1) == 0 || len(pub.B) < 4 || len(pub.T) == 0 {
		return nil, fmt.Errorf("missing public pre-sign inputs for transform-bridge replay")
	}
	if len(pub.RI0) != x0Len {
		return nil, fmt.Errorf("RI0 length=%d want %d", len(pub.RI0), x0Len)
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
	ri0Coeff := make([][]uint64, x0Len)
	for i := 0; i < x0Len; i++ {
		thetaRI0, err := thetaPolyFromNTT(ringQ, pub.RI0[i], omegaWitness)
		if err != nil {
			return nil, fmt.Errorf("theta RI0[%d]: %w", i, err)
		}
		coeff, err := toThetaCoeff(thetaRI0, fmt.Sprintf("theta RI0[%d]", i))
		if err != nil {
			return nil, err
		}
		ri0Coeff[i] = coeff
	}
	thetaRI1, err := thetaPolyFromNTT(ringQ, pub.RI1[0], omegaWitness)
	if err != nil {
		return nil, fmt.Errorf("theta RI1: %w", err)
	}
	ri1Coeff, err := toThetaCoeff(thetaRI1, "theta RI1")
	if err != nil {
		return nil, err
	}
	thetaB := make([][]uint64, len(pub.B))
	for i := range pub.B {
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
	x0Decode1, err := buildSingletonCarrierDecodePoly(pub.X0CoeffBound, q)
	if err != nil {
		return nil, fmt.Errorf("x0 carrier decode polys: %w", err)
	}
	x0CarryDecode, err := buildSingletonCarrierDecodePoly(1, q)
	if err != nil {
		return nil, fmt.Errorf("x0 carry decode polys: %w", err)
	}
	scalarDecode1, scalarDecode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, fmt.Errorf("scalar carrier decode polys: %w", err)
	}
	decode1K, decode2K, err := buildCarrierDecodePolys(1, q)
	if err != nil {
		return nil, fmt.Errorf("carrier K decode polys: %w", err)
	}
	memMsg, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		return nil, fmt.Errorf("message carrier membership poly: %w", err)
	}
	memX0, err := buildSingletonCarrierMembershipPoly(pub.X0CoeffBound, q)
	if err != nil {
		return nil, fmt.Errorf("x0 carrier membership poly: %w", err)
	}
	memX0Carry, err := buildSingletonCarrierMembershipPoly(1, q)
	if err != nil {
		return nil, fmt.Errorf("x0 carry membership poly: %w", err)
	}
	memScalar, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		return nil, fmt.Errorf("scalar carrier membership poly: %w", err)
	}
	memCarry, err := buildCarrierMembershipPoly(1, q)
	if err != nil {
		return nil, fmt.Errorf("carrier K membership poly: %w", err)
	}
	bridgeBasis, err := newRowTransformBridgeBasisCache(ringQ, omegaWitness, len(omegaWitness))
	if err != nil {
		return nil, fmt.Errorf("transform-bridge basis: %w", err)
	}

	return &preSignTransformBridgeConfig{
		Ring:            ringQ,
		Layout:          layout,
		Omega:           append([]uint64(nil), omegaWitness...),
		DomainPoints:    append([]uint64(nil), domainPoints...),
		BoundB:          bound,
		X0Bound:         pub.X0CoeffBound,
		X0Len:           x0Len,
		HashRelation:    pub.HashRelation,
		AcCoeff:         acCoeff,
		ComCoeff:        comCoeff,
		RI0Coeff:        ri0Coeff,
		RI1Coeff:        ri1Coeff,
		ThetaB:          thetaB,
		TPublicTheta:    tPublicCoeff,
		PackingSelCoeff: packingSelCoeff,
		MsgDecode1:      msgDecode1,
		MsgDecode2:      msgDecode2,
		X0Decode1:       x0Decode1,
		X0CarryDecode:   x0CarryDecode,
		ScalarDecode1:   scalarDecode1,
		ScalarDecode2:   scalarDecode2,
		Decode1K:        decode1K,
		Decode2K:        decode2K,
		MemMsg:          memMsg,
		MemX0:           memX0,
		MemX0Carry:      memX0Carry,
		MemScalar:       memScalar,
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
		carrierRU1, err := getRow(layout.IdxCarrierRU1)
		if err != nil {
			return nil, nil, err
		}
		carrierR, err := getRow(layout.IdxCarrierPreR)
		if err != nil {
			return nil, nil, err
		}
		carrierR1, err := getRow(layout.IdxCarrierR1)
		if err != nil {
			return nil, nil, err
		}
		carrierK1, err := getRow(layout.IdxCarrierK1)
		if err != nil {
			return nil, nil, err
		}
		m1Dec := decodeVal(cfg.MsgDecode1, carrierM)
		m2Dec := decodeVal(cfg.MsgDecode2, carrierM)
		ru1Dec := decodeVal(cfg.ScalarDecode1, carrierRU1)
		rDec := decodeVal(cfg.ScalarDecode1, carrierR)
		r1Dec := decodeVal(cfg.ScalarDecode1, carrierR1)
		k1Dec := decodeVal(cfg.Decode1K, carrierK1)

		carrierRU0Rows := rowLayoutPreSignCarrierRU0Rows(layout)
		carrierR0Rows := rowLayoutPostSignCarrierR0Rows(layout)
		carrierK0Rows := rowLayoutPreSignCarrierK0Rows(layout)
		aliasRU0Rows := rowLayoutPreSignRU0Rows(layout)
		aliasR0Rows := rowLayoutPostSignR0Rows(layout)
		aliasK0Rows := rowLayoutPreSignK0Rows(layout)
		rHat0Rows := rowLayoutPostSignRHat0Rows(layout)
		ru0Decs := make([]uint64, cfg.X0Len)
		r0Decs := make([]uint64, cfg.X0Len)
		k0Decs := make([]uint64, cfg.X0Len)
		ru0Vals := make([]uint64, cfg.X0Len)
		r0Vals := make([]uint64, cfg.X0Len)
		k0Vals := make([]uint64, cfg.X0Len)
		rHat0Vals := make([]uint64, cfg.X0Len)
		for i := 0; i < cfg.X0Len; i++ {
			cRU0, err := getRow(carrierRU0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			cR0, err := getRow(carrierR0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			cK0, err := getRow(carrierK0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			ru0Decs[i] = decodeVal(cfg.X0Decode1, cRU0)
			r0Decs[i] = decodeVal(cfg.X0Decode1, cR0)
			k0Decs[i] = decodeVal(cfg.X0CarryDecode, cK0)
			ru0Vals[i], err = getRow(aliasRU0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			r0Vals[i], err = getRow(aliasR0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			k0Vals[i], err = getRow(aliasK0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			rHat0Vals[i], err = getRow(rHat0Rows[i])
			if err != nil {
				return nil, nil, err
			}
		}

		m1, err := getRow(layout.IdxM1)
		if err != nil {
			return nil, nil, err
		}
		m2, err := getRow(layout.IdxM2)
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
		r1v, err := getRow(layout.IdxR1)
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
		rHat1, err := getRow(layout.IdxRHat1)
		if err != nil {
			return nil, nil, err
		}
		useBBTran := relationUsesBBTran(cfg.HashRelation)
		zHat := uint64(0)
		if useBBTran {
			zHat, err = getRow(layout.IdxZHat)
			if err != nil {
				return nil, nil, err
			}
		}

		fpar := []uint64{
			modSub(m1, m1Dec, q),
			modSub(m2, m2Dec, q),
			modSub(ru1, ru1Dec, q),
			modSub(rVal, rDec, q),
			modSub(r1v, r1Dec, q),
			modSub(k1, k1Dec, q),
		}
		for i := 0; i < cfg.X0Len; i++ {
			fpar = append(fpar, modSub(ru0Vals[i], ru0Decs[i], q))
		}
		for i := 0; i < cfg.X0Len; i++ {
			fpar = append(fpar, modSub(r0Vals[i], r0Decs[i], q))
		}
		for i := 0; i < cfg.X0Len; i++ {
			fpar = append(fpar, modSub(k0Vals[i], k0Decs[i], q))
		}
		for i := range cfg.AcCoeff {
			sum := uint64(0)
			if i < len(cfg.ComCoeff) {
				sum = modSub(sum, EvalPoly(cfg.ComCoeff[i], x, q)%q, q)
			}
			for j := 0; j < len(cfg.AcCoeff[i]); j++ {
				aVal := EvalPoly(cfg.AcCoeff[i][j], x, q) % q
				switch {
				case j == 0:
					sum = modAdd(sum, modMul(aVal, m1, q), q)
				case j == 1:
					sum = modAdd(sum, modMul(aVal, m2, q), q)
				case j >= 2 && j < 2+cfg.X0Len:
					sum = modAdd(sum, modMul(aVal, ru0Vals[j-2], q), q)
				case j == 2+cfg.X0Len:
					sum = modAdd(sum, modMul(aVal, ru1, q), q)
				case j == 3+cfg.X0Len:
					sum = modAdd(sum, modMul(aVal, rVal, q), q)
				}
			}
			fpar = append(fpar, sum)
		}

		delta0 := uint64(2*cfg.X0Bound + 1)
		for i := 0; i < cfg.X0Len; i++ {
			ri0 := EvalPoly(cfg.RI0Coeff[i], x, q) % q
			res0 := modSub(modSub(modAdd(ru0Vals[i], ri0, q), r0Vals[i], q), modMul(delta0%q, k0Vals[i], q), q)
			fpar = append(fpar, res0)
		}
		delta1 := uint64(2*cfg.BoundB + 1)
		ri1 := EvalPoly(cfg.RI1Coeff, x, q) % q
		res1 := modSub(modSub(modAdd(ru1, ri1, q), r1v, q), modMul(delta1%q, k1, q), q)
		fpar = append(fpar, res1)

		tTheta := EvalPoly(cfg.TPublicTheta, x, q) % q
		if useBBTran {
			fpar = append(fpar,
				transformTargetResidualCombinedEvalVector(q, x, cfg.HashRelation, cfg.ThetaB, modAdd(mHat1, mHat2, q), rHat0Vals, zHat, tTheta),
				transformInverseResidualEval(q, x, cfg.HashRelation, cfg.ThetaB, rHat1, zHat),
			)
		} else {
			fpar = append(fpar, transformHashResidualEval(q, x, cfg.HashRelation, cfg.ThetaB, mHat1, mHat2, rHat0Vals[0], rHat1, tTheta, 0, 0))
		}

		sel := EvalPoly(cfg.PackingSelCoeff, x, q) % q
		fpar = append(fpar, modMul(sel, m1, q))
		fpar = append(fpar, modMul((1+q-sel)%q, m2, q))

		fpar = append(fpar,
			EvalPoly(cfg.MemMsg, carrierM, q)%q,
			EvalPoly(cfg.MemScalar, carrierRU1, q)%q,
			EvalPoly(cfg.MemScalar, carrierR, q)%q,
			EvalPoly(cfg.MemScalar, carrierR1, q)%q,
			EvalPoly(cfg.MemCarry, carrierK1, q)%q,
		)
		for i := 0; i < cfg.X0Len; i++ {
			cRU0, _ := getRow(carrierRU0Rows[i])
			cR0, _ := getRow(carrierR0Rows[i])
			cK0, _ := getRow(carrierK0Rows[i])
			fpar = append(fpar,
				EvalPoly(cfg.MemX0, cRU0, q)%q,
				EvalPoly(cfg.MemX0, cR0, q)%q,
				EvalPoly(cfg.MemX0Carry, cK0, q)%q,
			)
		}

		lagrangeVals := make([]uint64, len(cfg.LagrangeBasis))
		hVals := make([]uint64, len(cfg.TransformHEval))
		for j := range cfg.LagrangeBasis {
			lagrangeVals[j] = EvalPoly(cfg.LagrangeBasis[j], x, q) % q
			hVals[j] = EvalPoly(cfg.TransformHEval[j], x, q) % q
		}
		fagg := make([]uint64, 0, (cfg.X0Len+3)*len(cfg.LagrangeBasis))
		for _, pair := range []struct {
			src uint64
			hat uint64
		}{
			{src: m1, hat: mHat1},
			{src: m2, hat: mHat2},
			{src: r1v, hat: rHat1},
		} {
			for j := 0; j < len(cfg.LagrangeBasis); j++ {
				fagg = append(fagg, modSub(modMul(pair.src, hVals[j], q), modMul(pair.hat, lagrangeVals[j], q), q))
			}
		}
		for i := 0; i < cfg.X0Len; i++ {
			for j := 0; j < len(cfg.LagrangeBasis); j++ {
				fagg = append(fagg, modSub(modMul(r0Vals[i], hVals[j], q), modMul(rHat0Vals[i], lagrangeVals[j], q), q))
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
	deltaX0K := K.EmbedF(uint64(2*cfg.X0Bound+1) % cfg.Ring.Modulus[0])
	deltaScalarK := K.EmbedF(uint64(2*cfg.BoundB+1) % cfg.Ring.Modulus[0])
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
		carrierRU1, err := getRow(layout.IdxCarrierRU1)
		if err != nil {
			return nil, nil, err
		}
		carrierR, err := getRow(layout.IdxCarrierPreR)
		if err != nil {
			return nil, nil, err
		}
		carrierR1, err := getRow(layout.IdxCarrierR1)
		if err != nil {
			return nil, nil, err
		}
		carrierK1, err := getRow(layout.IdxCarrierK1)
		if err != nil {
			return nil, nil, err
		}
		m1Dec := decodeVal(cfg.MsgDecode1, carrierM)
		m2Dec := decodeVal(cfg.MsgDecode2, carrierM)
		ru1Dec := decodeVal(cfg.ScalarDecode1, carrierRU1)
		rDec := decodeVal(cfg.ScalarDecode1, carrierR)
		r1Dec := decodeVal(cfg.ScalarDecode1, carrierR1)
		k1Dec := decodeVal(cfg.Decode1K, carrierK1)

		carrierRU0Rows := rowLayoutPreSignCarrierRU0Rows(layout)
		carrierR0Rows := rowLayoutPostSignCarrierR0Rows(layout)
		carrierK0Rows := rowLayoutPreSignCarrierK0Rows(layout)
		aliasRU0Rows := rowLayoutPreSignRU0Rows(layout)
		aliasR0Rows := rowLayoutPostSignR0Rows(layout)
		aliasK0Rows := rowLayoutPreSignK0Rows(layout)
		rHat0Rows := rowLayoutPostSignRHat0Rows(layout)
		ru0Decs := make([]kf.Elem, cfg.X0Len)
		r0Decs := make([]kf.Elem, cfg.X0Len)
		k0Decs := make([]kf.Elem, cfg.X0Len)
		ru0Vals := make([]kf.Elem, cfg.X0Len)
		r0Vals := make([]kf.Elem, cfg.X0Len)
		k0Vals := make([]kf.Elem, cfg.X0Len)
		rHat0Vals := make([]kf.Elem, cfg.X0Len)
		for i := 0; i < cfg.X0Len; i++ {
			cRU0, err := getRow(carrierRU0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			cR0, err := getRow(carrierR0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			cK0, err := getRow(carrierK0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			ru0Decs[i] = decodeVal(cfg.X0Decode1, cRU0)
			r0Decs[i] = decodeVal(cfg.X0Decode1, cR0)
			k0Decs[i] = decodeVal(cfg.X0CarryDecode, cK0)
			ru0Vals[i], err = getRow(aliasRU0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			r0Vals[i], err = getRow(aliasR0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			k0Vals[i], err = getRow(aliasK0Rows[i])
			if err != nil {
				return nil, nil, err
			}
			rHat0Vals[i], err = getRow(rHat0Rows[i])
			if err != nil {
				return nil, nil, err
			}
		}

		m1, err := getRow(layout.IdxM1)
		if err != nil {
			return nil, nil, err
		}
		m2, err := getRow(layout.IdxM2)
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
		r1v, err := getRow(layout.IdxR1)
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
		rHat1, err := getRow(layout.IdxRHat1)
		if err != nil {
			return nil, nil, err
		}
		useBBTran := relationUsesBBTran(cfg.HashRelation)
		zHat := K.Zero()
		if useBBTran {
			zHat, err = getRow(layout.IdxZHat)
			if err != nil {
				return nil, nil, err
			}
		}

		fpar := []kf.Elem{
			K.Sub(m1, m1Dec),
			K.Sub(m2, m2Dec),
			K.Sub(ru1, ru1Dec),
			K.Sub(rVal, rDec),
			K.Sub(r1v, r1Dec),
			K.Sub(k1, k1Dec),
		}
		for i := 0; i < cfg.X0Len; i++ {
			fpar = append(fpar, K.Sub(ru0Vals[i], ru0Decs[i]))
		}
		for i := 0; i < cfg.X0Len; i++ {
			fpar = append(fpar, K.Sub(r0Vals[i], r0Decs[i]))
		}
		for i := 0; i < cfg.X0Len; i++ {
			fpar = append(fpar, K.Sub(k0Vals[i], k0Decs[i]))
		}
		for i := range cfg.AcCoeff {
			sum := K.Zero()
			if i < len(cfg.ComCoeff) {
				sum = K.Sub(sum, K.EvalFPolyAtK(cfg.ComCoeff[i], e))
			}
			for j := 0; j < len(cfg.AcCoeff[i]); j++ {
				aVal := K.EvalFPolyAtK(cfg.AcCoeff[i][j], e)
				switch {
				case j == 0:
					sum = K.Add(sum, K.Mul(aVal, m1))
				case j == 1:
					sum = K.Add(sum, K.Mul(aVal, m2))
				case j >= 2 && j < 2+cfg.X0Len:
					sum = K.Add(sum, K.Mul(aVal, ru0Vals[j-2]))
				case j == 2+cfg.X0Len:
					sum = K.Add(sum, K.Mul(aVal, ru1))
				case j == 3+cfg.X0Len:
					sum = K.Add(sum, K.Mul(aVal, rVal))
				}
			}
			fpar = append(fpar, sum)
		}
		for i := 0; i < cfg.X0Len; i++ {
			ri0 := K.EvalFPolyAtK(cfg.RI0Coeff[i], e)
			fpar = append(fpar, K.Sub(K.Sub(K.Add(ru0Vals[i], ri0), r0Vals[i]), K.Mul(deltaX0K, k0Vals[i])))
		}
		ri1 := K.EvalFPolyAtK(cfg.RI1Coeff, e)
		fpar = append(fpar, K.Sub(K.Sub(K.Add(ru1, ri1), r1v), K.Mul(deltaScalarK, k1)))
		tTheta := K.EvalFPolyAtK(cfg.TPublicTheta, e)
		if useBBTran {
			fpar = append(fpar,
				transformTargetResidualCombinedKEvalVector(K, e, cfg.HashRelation, cfg.ThetaB, K.Add(mHat1, mHat2), rHat0Vals, zHat, tTheta),
				transformInverseResidualKEval(K, e, cfg.HashRelation, cfg.ThetaB, rHat1, zHat),
			)
		} else {
			fpar = append(fpar, transformHashResidualKEval(K, e, cfg.HashRelation, cfg.ThetaB, mHat1, mHat2, rHat0Vals[0], rHat1, tTheta, K.Zero(), K.Zero()))
		}
		sel := K.EvalFPolyAtK(cfg.PackingSelCoeff, e)
		fpar = append(fpar, K.Mul(sel, m1), K.Mul(K.Sub(K.One(), sel), m2))
		fpar = append(fpar,
			K.EvalFPolyAtK(cfg.MemMsg, carrierM),
			K.EvalFPolyAtK(cfg.MemScalar, carrierRU1),
			K.EvalFPolyAtK(cfg.MemScalar, carrierR),
			K.EvalFPolyAtK(cfg.MemScalar, carrierR1),
			K.EvalFPolyAtK(cfg.MemCarry, carrierK1),
		)
		for i := 0; i < cfg.X0Len; i++ {
			cRU0, _ := getRow(carrierRU0Rows[i])
			cR0, _ := getRow(carrierR0Rows[i])
			cK0, _ := getRow(carrierK0Rows[i])
			fpar = append(fpar,
				K.EvalFPolyAtK(cfg.MemX0, cRU0),
				K.EvalFPolyAtK(cfg.MemX0, cR0),
				K.EvalFPolyAtK(cfg.MemX0Carry, cK0),
			)
		}

		lagrangeVals := make([]kf.Elem, len(cfg.LagrangeBasis))
		hVals := make([]kf.Elem, len(cfg.TransformHEval))
		for j := range cfg.LagrangeBasis {
			lagrangeVals[j] = K.EvalFPolyAtK(cfg.LagrangeBasis[j], e)
			hVals[j] = K.EvalFPolyAtK(cfg.TransformHEval[j], e)
		}
		fagg := make([]kf.Elem, 0, (cfg.X0Len+3)*len(cfg.LagrangeBasis))
		for _, pair := range []struct {
			src kf.Elem
			hat kf.Elem
		}{
			{src: m1, hat: mHat1},
			{src: m2, hat: mHat2},
			{src: r1v, hat: rHat1},
		} {
			for j := 0; j < len(cfg.LagrangeBasis); j++ {
				fagg = append(fagg, K.Sub(K.Mul(pair.src, hVals[j]), K.Mul(pair.hat, lagrangeVals[j])))
			}
		}
		for i := 0; i < cfg.X0Len; i++ {
			for j := 0; j < len(cfg.LagrangeBasis); j++ {
				fagg = append(fagg, K.Sub(K.Mul(r0Vals[i], hVals[j]), K.Mul(rHat0Vals[i], lagrangeVals[j])))
			}
		}
		return fpar, fagg, nil
	}, nil
}
