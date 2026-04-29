package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type intGenISISShowingReplayConfig struct {
	Ring                 *ring.Ring
	Layout               IntGenISISShowingRowLayout
	DomainPoints         []uint64
	ACoeff               [][][][]uint64
	BCoeff               [][][]uint64
	CMCoeff              [][][][]uint64
	ASCoeff              [][][][]uint64
	BoundRows            []int
	BoundPolys           [][]uint64
	Shortness            LinfSpec
	KeySlots             []CoeffSlot
	KeySource            []CoeffSlot
	KeySourceDecodeLanes []int
	Lagrange             [][]uint64
	BridgeBasis          *transformBridgeBasisCache
	YLinear              *intGenISISYLinearMapCache
	MSECompression       intGenISISMSECompressionSpec
}

func newIntGenISISShowingReplayConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64, prfCompanionLayout *PRFCompanionLayout) (*intGenISISShowingReplayConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !pub.IntGenISIS {
		return nil, fmt.Errorf("IntGenISIS showing replay requires IntGenISIS public inputs")
	}
	if len(pub.Com) > 0 || len(pub.Ac) > 0 || len(pub.RI0) > 0 || len(pub.RI1) > 0 || len(pub.T) > 0 {
		return nil, fmt.Errorf("IntGenISIS showing public inputs must not include c/Ac/RI0/RI1/T")
	}
	l := layout.IntGenISISShowing
	if err := validateIntGenISISShowingPackedLayout(l, layout.SigCount); err != nil {
		return nil, err
	}
	if len(pub.A) != 1 || len(pub.A[0]) != l.UCount {
		return nil, fmt.Errorf("A dimensions=%dx? want 1x%d", len(pub.A), l.UCount)
	}
	if len(pub.B) != 3+l.X0Count {
		return nil, fmt.Errorf("B length=%d want %d", len(pub.B), 3+l.X0Count)
	}
	if len(pub.CM) != l.ECount || len(pub.CM[0]) != l.MCount {
		return nil, fmt.Errorf("C_M dimensions mismatch")
	}
	if len(pub.AS) != l.ECount || len(pub.AS[0]) != l.SCount {
		return nil, fmt.Errorf("A_s dimensions mismatch")
	}
	if len(omegaWitness) == 0 || len(domainPoints) == 0 {
		return nil, fmt.Errorf("missing replay domains")
	}
	toThetaBlocks := func(p *ring.Poly, name string) ([][]uint64, error) {
		if p == nil {
			return nil, fmt.Errorf("nil %s", name)
		}
		out := make([][]uint64, l.ViewRowsPerPoly)
		for block := 0; block < l.ViewRowsPerPoly; block++ {
			coeff, err := intGenISISThetaBlockCoeff(ringQ, p, omegaWitness, block, l.ViewRowsPerPoly, name)
			if err != nil {
				return nil, err
			}
			out[block] = coeff
		}
		return out, nil
	}
	aCoeff := make([][][][]uint64, len(pub.A))
	for i := range pub.A {
		aCoeff[i] = make([][][]uint64, len(pub.A[i]))
		for j := range pub.A[i] {
			coeff, err := toThetaBlocks(pub.A[i][j], fmt.Sprintf("A[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			aCoeff[i][j] = coeff
		}
	}
	bCoeff := make([][][]uint64, len(pub.B))
	for i := range pub.B {
		coeff, err := toThetaBlocks(pub.B[i], fmt.Sprintf("B[%d]", i))
		if err != nil {
			return nil, err
		}
		bCoeff[i] = coeff
	}
	cmCoeff := make([][][][]uint64, len(pub.CM))
	for i := range pub.CM {
		cmCoeff[i] = make([][][]uint64, len(pub.CM[i]))
		for j := range pub.CM[i] {
			coeff, err := toThetaBlocks(pub.CM[i][j], fmt.Sprintf("C_M[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			cmCoeff[i][j] = coeff
		}
	}
	asCoeff := make([][][][]uint64, len(pub.AS))
	for i := range pub.AS {
		asCoeff[i] = make([][][]uint64, len(pub.AS[i]))
		for j := range pub.AS[i] {
			coeff, err := toThetaBlocks(pub.AS[i][j], fmt.Sprintf("A_s[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			asCoeff[i][j] = coeff
		}
	}
	sigBound, err := intGenISISSignatureBoundFromPublic(pub)
	if err != nil {
		return nil, err
	}
	shortSpec, err := intGenISISUShortnessLayoutSpec(ringQ, l, sigBound)
	if err != nil {
		return nil, err
	}
	nonSigRows := intGenISISViewRowIndices(l.BoundViewStart, l.BoundViewCount)
	var boundRows []int
	var boundPolys [][]uint64
	if intGenISISUseDirectSignatureRange(sigBound) {
		shortRows := intGenISISViewRowIndices(l.UViewStart, l.UCount*l.ViewRowsPerPoly)
		boundRows = append(boundRows, shortRows...)
		shortSpec := NewRangeMembershipSpec(ringQ.Modulus[0], int(sigBound)).Coeffs
		for range shortRows {
			boundPolys = append(boundPolys, shortSpec)
		}
	}
	boundRows = append(boundRows, nonSigRows...)
	msgSpec := NewRangeMembershipSpec(ringQ.Modulus[0], intGenISISTernaryBound).Coeffs
	for range nonSigRows {
		boundPolys = append(boundPolys, msgSpec)
	}
	var keySlots, keySource []CoeffSlot
	if prfCompanionLayout != nil && prfCompanionLayout.KeyCount > 0 {
		if len(prfCompanionLayout.KeySourceSlots) != len(prfCompanionLayout.KeySlots) {
			return nil, fmt.Errorf("PRF key source slots=%d want key slots=%d", len(prfCompanionLayout.KeySourceSlots), len(prfCompanionLayout.KeySlots))
		}
		keySlots = append([]CoeffSlot(nil), prfCompanionLayout.KeySlots...)
		keySource = append([]CoeffSlot(nil), prfCompanionLayout.KeySourceSlots...)
	}
	keySourceDecodeLanes := []int(nil)
	if prfCompanionLayout != nil && len(prfCompanionLayout.KeySourceDecodeLanes) > 0 {
		keySourceDecodeLanes = append([]int(nil), prfCompanionLayout.KeySourceDecodeLanes...)
	}
	compressionSpec := intGenISISMSECompressionSpec{}
	if l.MSECompressionLevel > 0 {
		compressionSpec, err = newIntGenISISMSECompressionSpec(ringQ.Modulus[0], l.MSECompressionLevel)
		if err != nil {
			return nil, err
		}
		msgSpec := compressionSpec.MembershipPoly
		boundPolys = boundPolys[:len(boundPolys)-len(nonSigRows)]
		for range nonSigRows {
			boundPolys = append(boundPolys, msgSpec)
		}
	}
	lagrange, err := buildLagrangeBasisCoeffs(omegaWitness, ringQ.Modulus[0])
	if err != nil {
		return nil, fmt.Errorf("lagrange basis: %w", err)
	}
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, l.ViewRowsPerPoly*len(omegaWitness), l.ViewRowsPerPoly)
	if err != nil {
		return nil, fmt.Errorf("IntGenISIS coeff-to-hat bridge basis: %w", err)
	}
	yLinear, err := newIntGenISISYLinearMapCache(ringQ, pub, l, omegaWitness)
	if err != nil {
		return nil, err
	}
	return &intGenISISShowingReplayConfig{
		Ring:                 ringQ,
		Layout:               *l,
		DomainPoints:         append([]uint64(nil), domainPoints...),
		ACoeff:               aCoeff,
		BCoeff:               bCoeff,
		CMCoeff:              cmCoeff,
		ASCoeff:              asCoeff,
		BoundRows:            boundRows,
		BoundPolys:           boundPolys,
		Shortness:            shortSpec,
		KeySlots:             keySlots,
		KeySource:            keySource,
		KeySourceDecodeLanes: keySourceDecodeLanes,
		Lagrange:             lagrange,
		BridgeBasis:          bridgeBasis,
		YLinear:              yLinear,
		MSECompression:       compressionSpec,
	}, nil
}

func (cfg *intGenISISShowingReplayConfig) bridgeSpecs() []struct {
	name       string
	source     int
	components int
	hat        int
	compressed bool
} {
	l := cfg.Layout
	return []struct {
		name       string
		source     int
		components int
		hat        int
		compressed bool
	}{
		{"u", l.UViewStart, l.UCount, l.UHatStart, false},
		{"Y", l.YViewStart, 1, l.YHatStart, false},
	}
}

func (cfg *intGenISISShowingReplayConfig) evalYLinearF(x uint64, getRow func(int) (uint64, error)) ([]uint64, error) {
	if cfg == nil || cfg.YLinear == nil {
		return nil, fmt.Errorf("missing IntGenISIS Y-linear replay cache")
	}
	q := cfg.Ring.Modulus[0]
	l := cfg.Layout
	sourceValue := func(term intGenISISYLinearTermCache, comp, srcBlock int) (uint64, error) {
		if term.Compressed {
			pack := l.MSECompressionPackWidth
			local := comp*l.ViewRowsPerPoly + srcBlock
			carrier, err := getRow(term.Source + local/pack)
			if err != nil {
				return 0, err
			}
			lane := local % pack
			if lane < 0 || lane >= len(cfg.MSECompression.DecodePolys) {
				return 0, fmt.Errorf("compressed %s decode lane=%d outside lanes=%d", term.Name, lane, len(cfg.MSECompression.DecodePolys))
			}
			return EvalPoly(cfg.MSECompression.DecodePolys[lane], carrier, q) % q, nil
		}
		return getRow(term.Source + comp*l.ViewRowsPerPoly + srcBlock)
	}
	out := make([]uint64, 0, l.ViewRowsPerPoly*len(cfg.YLinear.Lagrange))
	for block := 0; block < l.ViewRowsPerPoly; block++ {
		y, err := getRow(l.YViewStart + block)
		if err != nil {
			return nil, err
		}
		for lane := 0; lane < len(cfg.YLinear.Lagrange); lane++ {
			outIdx := block*len(cfg.YLinear.Lagrange) + lane
			left := uint64(0)
			for _, term := range cfg.YLinear.Terms {
				for comp := 0; comp < term.Components; comp++ {
					for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
						src, err := sourceValue(term, comp, srcBlock)
						if err != nil {
							return nil, err
						}
						h := EvalPoly(term.H[comp][outIdx][srcBlock], x, q) % q
						left = modAdd(left, modMul(h, src, q), q)
					}
				}
			}
			right := modMul(EvalPoly(cfg.YLinear.Lagrange[lane], x, q)%q, y, q)
			out = append(out, modSub(left, right, q))
		}
	}
	return out, nil
}

func (cfg *intGenISISShowingReplayConfig) evalYLinearK(K *kf.Field, e kf.Elem, getRow func(int) (kf.Elem, error)) ([]kf.Elem, error) {
	if cfg == nil || cfg.YLinear == nil {
		return nil, fmt.Errorf("missing IntGenISIS Y-linear replay cache")
	}
	l := cfg.Layout
	sourceValue := func(term intGenISISYLinearTermCache, comp, srcBlock int) (kf.Elem, error) {
		if term.Compressed {
			pack := l.MSECompressionPackWidth
			local := comp*l.ViewRowsPerPoly + srcBlock
			carrier, err := getRow(term.Source + local/pack)
			if err != nil {
				return K.Zero(), err
			}
			lane := local % pack
			if lane < 0 || lane >= len(cfg.MSECompression.DecodePolys) {
				return K.Zero(), fmt.Errorf("compressed %s decode lane=%d outside lanes=%d", term.Name, lane, len(cfg.MSECompression.DecodePolys))
			}
			return K.EvalFPolyAtK(cfg.MSECompression.DecodePolys[lane], carrier), nil
		}
		return getRow(term.Source + comp*l.ViewRowsPerPoly + srcBlock)
	}
	out := make([]kf.Elem, 0, l.ViewRowsPerPoly*len(cfg.YLinear.Lagrange))
	for block := 0; block < l.ViewRowsPerPoly; block++ {
		y, err := getRow(l.YViewStart + block)
		if err != nil {
			return nil, err
		}
		for lane := 0; lane < len(cfg.YLinear.Lagrange); lane++ {
			outIdx := block*len(cfg.YLinear.Lagrange) + lane
			left := K.Zero()
			for _, term := range cfg.YLinear.Terms {
				for comp := 0; comp < term.Components; comp++ {
					for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
						src, err := sourceValue(term, comp, srcBlock)
						if err != nil {
							return nil, err
						}
						h := K.EvalFPolyAtK(term.H[comp][outIdx][srcBlock], e)
						left = K.Add(left, K.Mul(h, src))
					}
				}
			}
			right := K.Mul(K.EvalFPolyAtK(cfg.YLinear.Lagrange[lane], e), y)
			out = append(out, K.Sub(left, right))
		}
	}
	return out, nil
}

func (cfg *intGenISISShowingReplayConfig) CoreEvaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil IntGenISIS showing replay config")
		}
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return nil, nil, fmt.Errorf("IntGenISIS showing eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
		}
		q := cfg.Ring.Modulus[0]
		x := cfg.DomainPoints[ptIdx] % q
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		evalTheta := func(coeff []uint64) uint64 {
			if len(coeff) == 0 {
				return 0
			}
			return EvalPoly(coeff, x, q) % q
		}
		l := cfg.Layout
		fpar := make([]uint64, 0, 2*l.ViewRowsPerPoly+len(cfg.KeySlots)+len(cfg.BoundRows)+l.UShortnessSourceViewRows*(1+cfg.Shortness.L))
		for block := 0; block < l.ViewRowsPerPoly; block++ {
			sig := uint64(0)
			for i := 0; i < l.UCount; i++ {
				row, err := getRow(l.UHatStart + i*l.ViewRowsPerPoly + block)
				if err != nil {
					return nil, nil, err
				}
				sig = modAdd(sig, modMul(evalTheta(cfg.ACoeff[0][i][block]), row, q), q)
			}
			sig = modSub(sig, evalTheta(cfg.BCoeff[0][block]), q)
			muSig, err := getRow(l.MuSigHatStart + block)
			if err != nil {
				return nil, nil, err
			}
			sig = modSub(sig, modMul(evalTheta(cfg.BCoeff[1][block]), muSig, q), q)
			for i := 0; i < l.X0Count; i++ {
				x0, err := getRow(l.X0HatStart + i*l.ViewRowsPerPoly + block)
				if err != nil {
					return nil, nil, err
				}
				sig = modSub(sig, modMul(evalTheta(cfg.BCoeff[2+i][block]), x0, q), q)
			}
			z, err := getRow(l.ZHatStart + block)
			if err != nil {
				return nil, nil, err
			}
			sig = modSub(sig, z, q)
			y, err := getRow(l.YHatStart + block)
			if err != nil {
				return nil, nil, err
			}
			sig = modSub(sig, y, q)
			fpar = append(fpar, sig)

			x1, err := getRow(l.X1HatStart + block)
			if err != nil {
				return nil, nil, err
			}
			inv := modSub(evalTheta(cfg.BCoeff[len(cfg.BCoeff)-1][block]), x1, q)
			inv = modMul(inv, z, q)
			inv = modSub(inv, 1%q, q)
			fpar = append(fpar, inv)

		}
		for i, idx := range cfg.BoundRows {
			row, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			if i >= len(cfg.BoundPolys) {
				return nil, nil, fmt.Errorf("missing IntGenISIS bound polynomial %d", i)
			}
			fpar = append(fpar, intGenISISEvalMembership(q, cfg.BoundPolys[i], row))
		}
		for group := 0; group < l.UShortnessSourceViewRows; group++ {
			source, err := getRow(l.UShortnessSourceViewStart + group)
			if err != nil {
				return nil, nil, err
			}
			recon := uint64(0)
			digits := make([]uint64, cfg.Shortness.L)
			for lane := 0; lane < cfg.Shortness.L; lane++ {
				digit, err := getRow(l.UShortnessStart + group*l.UShortnessRowsPerGroup + lane)
				if err != nil {
					return nil, nil, err
				}
				digits[lane] = digit
				recon = modAdd(recon, modMul(cfg.Shortness.RPows[lane]%q, digit, q), q)
			}
			fpar = append(fpar, modSub(source, recon, q))
			for lane := 0; lane < cfg.Shortness.L; lane++ {
				fpar = append(fpar, intGenISISEvalMembership(q, cfg.Shortness.PDi[lane], digits[lane]))
			}
		}
		fagg := make([]uint64, 0)
		if len(cfg.KeySlots) > 0 {
			for i := range cfg.KeySlots {
				key := cfg.KeySlots[i]
				src := cfg.KeySource[i]
				if key.Coeff < 0 || key.Coeff >= len(cfg.Lagrange) || src.Coeff < 0 || src.Coeff >= len(cfg.Lagrange) {
					return nil, nil, fmt.Errorf("PRF key binding slot out of range")
				}
				keyVal, err := getRow(key.Row)
				if err != nil {
					return nil, nil, err
				}
				srcVal, err := getRow(src.Row)
				if err != nil {
					return nil, nil, err
				}
				if len(cfg.KeySourceDecodeLanes) > 0 {
					if i >= len(cfg.KeySourceDecodeLanes) {
						return nil, nil, fmt.Errorf("missing PRF key source decode lane %d", i)
					}
					lane := cfg.KeySourceDecodeLanes[i]
					if lane < 0 || lane >= len(cfg.MSECompression.DecodePolys) {
						return nil, nil, fmt.Errorf("PRF key source decode lane=%d outside lanes=%d", lane, len(cfg.MSECompression.DecodePolys))
					}
					srcVal = EvalPoly(cfg.MSECompression.DecodePolys[lane], srcVal, q) % q
				}
				left := modMul(EvalPoly(cfg.Lagrange[key.Coeff], x, q), keyVal, q)
				right := modMul(EvalPoly(cfg.Lagrange[src.Coeff], x, q), srcVal, q)
				fagg = append(fagg, modSub(left, right, q))
			}
		}
		yVals, err := cfg.evalYLinearF(x, getRow)
		if err != nil {
			return nil, nil, err
		}
		fagg = append(fagg, yVals...)
		for _, bridge := range cfg.bridgeSpecs() {
			for comp := 0; comp < bridge.components; comp++ {
				for block := 0; block < l.ViewRowsPerPoly; block++ {
					hat, err := getRow(bridge.hat + comp*l.ViewRowsPerPoly + block)
					if err != nil {
						return nil, nil, err
					}
					for lane := 0; lane < len(cfg.BridgeBasis.LagrangeBasis); lane++ {
						t := block*len(cfg.BridgeBasis.LagrangeBasis) + lane
						left := uint64(0)
						for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
							var source uint64
							if bridge.compressed {
								pack := l.MSECompressionPackWidth
								local := comp*l.ViewRowsPerPoly + srcBlock
								carrier, err := getRow(bridge.source + local/pack)
								if err != nil {
									return nil, nil, err
								}
								lane := local % pack
								if lane < 0 || lane >= len(cfg.MSECompression.DecodePolys) {
									return nil, nil, fmt.Errorf("compressed %s decode lane=%d outside lanes=%d", bridge.name, lane, len(cfg.MSECompression.DecodePolys))
								}
								source = EvalPoly(cfg.MSECompression.DecodePolys[lane], carrier, q) % q
							} else {
								var err error
								source, err = getRow(bridge.source + comp*l.ViewRowsPerPoly + srcBlock)
								if err != nil {
									return nil, nil, err
								}
							}
							h := EvalPoly(cfg.BridgeBasis.TransformH[t], x, q) % q
							scale := cfg.BridgeBasis.BlockFactors[t][srcBlock] % q
							left = modAdd(left, modMul(scale, modMul(h, source, q), q), q)
						}
						right := modMul(EvalPoly(cfg.BridgeBasis.LagrangeBasis[lane], x, q), hat, q)
						fagg = append(fagg, modSub(left, right, q))
					}
				}
			}
		}
		return fpar, fagg, nil
	}
}

func (cfg *intGenISISShowingReplayConfig) CoreKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil IntGenISIS showing replay config")
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
		evalTheta := func(coeff []uint64) kf.Elem {
			if len(coeff) == 0 {
				return K.Zero()
			}
			return K.EvalFPolyAtK(coeff, e)
		}
		l := cfg.Layout
		fpar := make([]kf.Elem, 0, 2*l.ViewRowsPerPoly+len(cfg.KeySlots)+len(cfg.BoundRows)+l.UShortnessSourceViewRows*(1+cfg.Shortness.L))
		for block := 0; block < l.ViewRowsPerPoly; block++ {
			sig := K.Zero()
			for i := 0; i < l.UCount; i++ {
				row, err := getRow(l.UHatStart + i*l.ViewRowsPerPoly + block)
				if err != nil {
					return nil, nil, err
				}
				sig = K.Add(sig, K.Mul(evalTheta(cfg.ACoeff[0][i][block]), row))
			}
			sig = K.Sub(sig, evalTheta(cfg.BCoeff[0][block]))
			muSig, err := getRow(l.MuSigHatStart + block)
			if err != nil {
				return nil, nil, err
			}
			sig = K.Sub(sig, K.Mul(evalTheta(cfg.BCoeff[1][block]), muSig))
			for i := 0; i < l.X0Count; i++ {
				x0, err := getRow(l.X0HatStart + i*l.ViewRowsPerPoly + block)
				if err != nil {
					return nil, nil, err
				}
				sig = K.Sub(sig, K.Mul(evalTheta(cfg.BCoeff[2+i][block]), x0))
			}
			z, err := getRow(l.ZHatStart + block)
			if err != nil {
				return nil, nil, err
			}
			sig = K.Sub(sig, z)
			y, err := getRow(l.YHatStart + block)
			if err != nil {
				return nil, nil, err
			}
			sig = K.Sub(sig, y)
			fpar = append(fpar, sig)

			x1, err := getRow(l.X1HatStart + block)
			if err != nil {
				return nil, nil, err
			}
			inv := K.Sub(evalTheta(cfg.BCoeff[len(cfg.BCoeff)-1][block]), x1)
			inv = K.Mul(inv, z)
			inv = K.Sub(inv, K.EmbedF(1%cfg.Ring.Modulus[0]))
			fpar = append(fpar, inv)

		}
		for i, idx := range cfg.BoundRows {
			row, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			if i >= len(cfg.BoundPolys) {
				return nil, nil, fmt.Errorf("missing IntGenISIS bound polynomial %d", i)
			}
			fpar = append(fpar, intGenISISEvalKPolyAtElem(K, cfg.BoundPolys[i], row))
		}
		for group := 0; group < l.UShortnessSourceViewRows; group++ {
			source, err := getRow(l.UShortnessSourceViewStart + group)
			if err != nil {
				return nil, nil, err
			}
			recon := K.Zero()
			digits := make([]kf.Elem, cfg.Shortness.L)
			for lane := 0; lane < cfg.Shortness.L; lane++ {
				digit, err := getRow(l.UShortnessStart + group*l.UShortnessRowsPerGroup + lane)
				if err != nil {
					return nil, nil, err
				}
				digits[lane] = digit
				recon = K.Add(recon, K.Mul(K.EmbedF(cfg.Shortness.RPows[lane]%cfg.Ring.Modulus[0]), digit))
			}
			fpar = append(fpar, K.Sub(source, recon))
			for lane := 0; lane < cfg.Shortness.L; lane++ {
				fpar = append(fpar, intGenISISEvalKPolyAtElem(K, cfg.Shortness.PDi[lane], digits[lane]))
			}
		}
		fagg := make([]kf.Elem, 0)
		if len(cfg.KeySlots) > 0 {
			for i := range cfg.KeySlots {
				key := cfg.KeySlots[i]
				src := cfg.KeySource[i]
				if key.Coeff < 0 || key.Coeff >= len(cfg.Lagrange) || src.Coeff < 0 || src.Coeff >= len(cfg.Lagrange) {
					return nil, nil, fmt.Errorf("PRF key binding slot out of range")
				}
				keyVal, err := getRow(key.Row)
				if err != nil {
					return nil, nil, err
				}
				srcVal, err := getRow(src.Row)
				if err != nil {
					return nil, nil, err
				}
				if len(cfg.KeySourceDecodeLanes) > 0 {
					if i >= len(cfg.KeySourceDecodeLanes) {
						return nil, nil, fmt.Errorf("missing PRF key source decode lane %d", i)
					}
					lane := cfg.KeySourceDecodeLanes[i]
					if lane < 0 || lane >= len(cfg.MSECompression.DecodePolys) {
						return nil, nil, fmt.Errorf("PRF key source decode lane=%d outside lanes=%d", lane, len(cfg.MSECompression.DecodePolys))
					}
					srcVal = K.EvalFPolyAtK(cfg.MSECompression.DecodePolys[lane], srcVal)
				}
				left := K.Mul(K.EvalFPolyAtK(cfg.Lagrange[key.Coeff], e), keyVal)
				right := K.Mul(K.EvalFPolyAtK(cfg.Lagrange[src.Coeff], e), srcVal)
				fagg = append(fagg, K.Sub(left, right))
			}
		}
		yVals, err := cfg.evalYLinearK(K, e, getRow)
		if err != nil {
			return nil, nil, err
		}
		fagg = append(fagg, yVals...)
		for _, bridge := range cfg.bridgeSpecs() {
			for comp := 0; comp < bridge.components; comp++ {
				for block := 0; block < l.ViewRowsPerPoly; block++ {
					hat, err := getRow(bridge.hat + comp*l.ViewRowsPerPoly + block)
					if err != nil {
						return nil, nil, err
					}
					for lane := 0; lane < len(cfg.BridgeBasis.LagrangeBasis); lane++ {
						t := block*len(cfg.BridgeBasis.LagrangeBasis) + lane
						left := K.Zero()
						for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
							var source kf.Elem
							if bridge.compressed {
								pack := l.MSECompressionPackWidth
								local := comp*l.ViewRowsPerPoly + srcBlock
								carrier, err := getRow(bridge.source + local/pack)
								if err != nil {
									return nil, nil, err
								}
								lane := local % pack
								if lane < 0 || lane >= len(cfg.MSECompression.DecodePolys) {
									return nil, nil, fmt.Errorf("compressed %s decode lane=%d outside lanes=%d", bridge.name, lane, len(cfg.MSECompression.DecodePolys))
								}
								source = K.EvalFPolyAtK(cfg.MSECompression.DecodePolys[lane], carrier)
							} else {
								var err error
								source, err = getRow(bridge.source + comp*l.ViewRowsPerPoly + srcBlock)
								if err != nil {
									return nil, nil, err
								}
							}
							h := K.EvalFPolyAtK(cfg.BridgeBasis.TransformH[t], e)
							scale := K.EmbedF(cfg.BridgeBasis.BlockFactors[t][srcBlock] % cfg.Ring.Modulus[0])
							left = K.Add(left, K.Mul(scale, K.Mul(h, source)))
						}
						right := K.Mul(K.EvalFPolyAtK(cfg.BridgeBasis.LagrangeBasis[lane], e), hat)
						fagg = append(fagg, K.Sub(left, right))
					}
				}
			}
		}
		return fpar, fagg, nil
	}, nil
}
