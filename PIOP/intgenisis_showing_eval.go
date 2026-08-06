package PIOP

import (
	"fmt"

	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type intGenISISShowingReplayConfig struct {
	Ring                 *ring.Ring
	Layout               IntGenISISShowingRowLayout
	Omega                []uint64
	DomainPoints         []uint64
	ACoeff               [][][][]uint64
	AAtOmega             [][][]uint64
	BCoeff               [][][]uint64
	BAtOmega             [][][]uint64
	CMCoeff              [][][][]uint64
	CMAtOmega            [][]uint64
	ASCoeff              [][][][]uint64
	ASAtOmega            [][][]uint64
	BoundRows            []int
	BoundPolys           [][]uint64
	Shortness            LinfSpec
	KeySlots             []CoeffSlot
	KeySource            []CoeffSlot
	KeySourceMode        string
	KeySourceDecodeLanes []int
	PRFDirectFullStart   int
	PRFDirectFullCount   int
	Lagrange             [][]uint64
	BridgeBasis          *transformBridgeBasisCache
	YLinear              *intGenISISYLinearMapCache
	MSECompression       intGenISISMSECompressionSpec
	HashCompressionV3    intGenISISMSECompressionSpec
	PRFInputTraceV3      *prfInputTraceV3Relation
}

func newIntGenISISShowingReplayConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64, prfCompanionLayout *PRFCompanionLayout) (*intGenISISShowingReplayConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !pub.IntGenISIS {
		return nil, fmt.Errorf("IntGenISIS showing replay requires IntGenISIS public inputs")
	}
	if pub.HashInputBound != credential.IntGenISISHashInputBound {
		return nil, fmt.Errorf("hash_input_bound=%d want %d", pub.HashInputBound, credential.IntGenISISHashInputBound)
	}
	if len(pub.Com) > 0 || len(pub.Ac) > 0 || len(pub.RI0) > 0 || len(pub.RI1) > 0 || len(pub.T) > 0 {
		return nil, fmt.Errorf("IntGenISIS showing public inputs must not include c/Ac/RI0/RI1/T")
	}
	l := layout.IntGenISISShowing
	if err := validateIntGenISISShowingPackedLayout(l, layout.SigCount); err != nil {
		return nil, err
	}
	if len(pub.A) != 1 || len(pub.A[0]) != l.UCount {
		return nil, fmt.Errorf("a dimensions=%dx? want 1x%d", len(pub.A), l.UCount)
	}
	if len(pub.B) != 3+l.X0Count {
		return nil, fmt.Errorf("b length=%d want %d", len(pub.B), 3+l.X0Count)
	}
	if len(pub.CM) != l.ECount || len(pub.CM[0]) != l.MCount {
		return nil, fmt.Errorf("c_m dimensions mismatch")
	}
	if len(pub.AS) != l.ECount || len(pub.AS[0]) != l.SCount {
		return nil, fmt.Errorf("a_s dimensions mismatch")
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
	aAtOmega := make([][][]uint64, l.UCount)
	for i := range pub.A {
		aCoeff[i] = make([][][]uint64, len(pub.A[i]))
		for j := range pub.A[i] {
			coeff, err := toThetaBlocks(pub.A[i][j], fmt.Sprintf("A[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			aCoeff[i][j] = coeff
			if i == 0 {
				aAtOmega[j] = make([][]uint64, l.ViewRowsPerPoly)
				for block := 0; block < l.ViewRowsPerPoly; block++ {
					aAtOmega[j][block] = evalCoeffOnOmega(coeff[block], omegaWitness, ringQ.Modulus[0])
				}
			}
		}
	}
	bCoeff := make([][][]uint64, len(pub.B))
	bAtOmega := make([][][]uint64, len(pub.B))
	for i := range pub.B {
		coeff, err := toThetaBlocks(pub.B[i], fmt.Sprintf("B[%d]", i))
		if err != nil {
			return nil, err
		}
		bCoeff[i] = coeff
		bAtOmega[i] = make([][]uint64, l.ViewRowsPerPoly)
		for block := 0; block < l.ViewRowsPerPoly; block++ {
			bAtOmega[i][block] = evalCoeffOnOmega(coeff[block], omegaWitness, ringQ.Modulus[0])
		}
	}
	cmCoeff := make([][][][]uint64, len(pub.CM))
	cmAtOmega := make([][]uint64, l.ViewRowsPerPoly)
	for i := range pub.CM {
		cmCoeff[i] = make([][][]uint64, len(pub.CM[i]))
		for j := range pub.CM[i] {
			coeff, err := toThetaBlocks(pub.CM[i][j], fmt.Sprintf("C_M[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			cmCoeff[i][j] = coeff
			if i == 0 && j == 0 {
				for block := 0; block < l.ViewRowsPerPoly; block++ {
					cmAtOmega[block] = evalCoeffOnOmega(coeff[block], omegaWitness, ringQ.Modulus[0])
				}
			}
		}
	}
	asCoeff := make([][][][]uint64, len(pub.AS))
	asAtOmega := make([][][]uint64, l.SCount)
	for i := range pub.AS {
		asCoeff[i] = make([][][]uint64, len(pub.AS[i]))
		for j := range pub.AS[i] {
			coeff, err := toThetaBlocks(pub.AS[i][j], fmt.Sprintf("A_s[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			asCoeff[i][j] = coeff
			if i == 0 {
				asAtOmega[j] = make([][]uint64, l.ViewRowsPerPoly)
				for block := 0; block < l.ViewRowsPerPoly; block++ {
					asAtOmega[j][block] = evalCoeffOnOmega(coeff[block], omegaWitness, ringQ.Modulus[0])
				}
			}
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
	var boundRows []int
	var boundPolys [][]uint64
	compressionSpec := intGenISISMSECompressionSpec{}
	if l.MSECompressionLevel > 0 {
		compressionSpec, err = newIntGenISISMSECompressionSpecForBound(ringQ.Modulus[0], l.MSECompressionLevel, pub.BoundB)
		if err != nil {
			return nil, err
		}
	}
	structuralV3 := l.LayoutVersion == intGenISISShowingLayoutVersionInputTraceCarrierV3
	hashCompressionSpec := intGenISISMSECompressionSpec{}
	if structuralV3 {
		hashCompressionSpec, err = newIntGenISISMSECompressionSpecForBound(ringQ.Modulus[0], 1, pub.HashInputBound)
		if err != nil {
			return nil, err
		}
	}
	if intGenISISUseDirectSignatureRange(sigBound) {
		if intGenISISProjectionUsesDigitOnlyU(l) {
			return nil, fmt.Errorf("IntGenISIS digit-only U does not support direct signature range constraints")
		}
		shortRows := intGenISISViewRowIndices(l.UViewStart, l.UCount*l.ViewRowsPerPoly)
		boundRows = append(boundRows, shortRows...)
		shortSpec := NewRangeMembershipSpec(ringQ.Modulus[0], int(sigBound)).Coeffs
		for range shortRows {
			boundPolys = append(boundPolys, shortSpec)
		}
	}
	if l.MSECompressionLevel > 0 {
		carrierRows := make([]int, 0, l.MCarrierCount+l.SCarrierCount+l.ECarrierCount)
		carrierRows = append(carrierRows, intGenISISViewRowIndices(l.MCarrierStart, l.MCarrierCount)...)
		carrierRows = append(carrierRows, intGenISISViewRowIndices(l.SCarrierStart, l.SCarrierCount)...)
		carrierRows = append(carrierRows, intGenISISViewRowIndices(l.ECarrierStart, l.ECarrierCount)...)
		boundRows = append(boundRows, carrierRows...)
		for range carrierRows {
			boundPolys = append(boundPolys, compressionSpec.MembershipPoly)
		}
		seedRows := intGenISISViewRowIndices(l.MSeedViewStart, l.MSeedViewCount)
		boundRows = append(boundRows, seedRows...)
		seedSpec := NewRangeMembershipSpec(ringQ.Modulus[0], int(intGenISISSeedBound)).Coeffs
		for range seedRows {
			boundPolys = append(boundPolys, seedSpec)
		}
	} else {
		mOrdinaryRows, mSeedRows, serr := intGenISISSplitMViewRowIndicesForPack9Tail(l.MViewStart, int(ringQ.N), len(omegaWitness))
		if serr != nil {
			return nil, serr
		}
		ordinaryRows := make([]int, 0, len(mOrdinaryRows)+l.SCount*l.ViewRowsPerPoly+l.ECount*l.ViewRowsPerPoly)
		ordinaryRows = append(ordinaryRows, mOrdinaryRows...)
		ordinaryRows = append(ordinaryRows, intGenISISViewRowIndices(l.SViewStart, l.SCount*l.ViewRowsPerPoly)...)
		ordinaryRows = append(ordinaryRows, intGenISISViewRowIndices(l.EViewStart, l.ECount*l.ViewRowsPerPoly)...)
		boundRows = append(boundRows, ordinaryRows...)
		msgSpec := NewRangeMembershipSpec(ringQ.Modulus[0], int(pub.BoundB)).Coeffs
		for range ordinaryRows {
			boundPolys = append(boundPolys, msgSpec)
		}
		boundRows = append(boundRows, mSeedRows...)
		seedSpec := NewRangeMembershipSpec(ringQ.Modulus[0], int(intGenISISSeedBound)).Coeffs
		for range mSeedRows {
			boundPolys = append(boundPolys, seedSpec)
		}
	}
	hashRows := make([]int, 0, (l.MuSigCount+l.X0Count+l.X1Count)*l.ViewRowsPerPoly)
	if structuralV3 {
		hashRows = append(hashRows, intGenISISViewRowIndices(l.MuSigCarrierStart, l.MuSigCarrierCount)...)
		hashRows = append(hashRows, intGenISISViewRowIndices(l.X0CarrierStart, l.X0CarrierCount)...)
		hashRows = append(hashRows, intGenISISViewRowIndices(l.X1CarrierStart, l.X1CarrierCount)...)
	} else {
		hashRows = append(hashRows, intGenISISViewRowIndices(l.MuSigViewStart, l.MuSigCount*l.ViewRowsPerPoly)...)
		hashRows = append(hashRows, intGenISISViewRowIndices(l.X0ViewStart, l.X0Count*l.ViewRowsPerPoly)...)
		hashRows = append(hashRows, intGenISISViewRowIndices(l.X1ViewStart, l.X1Count*l.ViewRowsPerPoly)...)
	}
	boundRows = append(boundRows, hashRows...)
	if structuralV3 {
		for range hashRows {
			boundPolys = append(boundPolys, hashCompressionSpec.MembershipPoly)
		}
	} else {
		hashSpec := NewRangeMembershipSpec(ringQ.Modulus[0], int(pub.HashInputBound)).Coeffs
		for range hashRows {
			boundPolys = append(boundPolys, hashSpec)
		}
	}
	var keySlots, keySource []CoeffSlot
	keySourceMode := ""
	if prfCompanionLayout != nil && prfCompanionLayout.KeyCount > 0 {
		keySourceMode = prfCompanionLayout.KeySourceMode
		if keySourceMode == "" {
			keySourceMode = PRFKeySourceModeDirect
		}
		wantSources := len(prfCompanionLayout.KeySlots)
		if keySourceMode == PRFKeySourceModePack9Seed {
			wantSources *= intGenISISPRFSeedDigitsPerLane
		} else if keySourceMode != PRFKeySourceModeDirect {
			return nil, fmt.Errorf("unsupported PRF key source mode %q", keySourceMode)
		}
		if len(prfCompanionLayout.KeySourceSlots) != wantSources {
			return nil, fmt.Errorf("PRF key source slots=%d want %d", len(prfCompanionLayout.KeySourceSlots), wantSources)
		}
		keySlots = append([]CoeffSlot(nil), prfCompanionLayout.KeySlots...)
		keySource = append([]CoeffSlot(nil), prfCompanionLayout.KeySourceSlots...)
	}
	keySourceDecodeLanes := []int(nil)
	if prfCompanionLayout != nil && len(prfCompanionLayout.KeySourceDecodeLanes) > 0 {
		keySourceDecodeLanes = append([]int(nil), prfCompanionLayout.KeySourceDecodeLanes...)
	}
	prfDirectFullCount := 0
	if prfCompanionLayout != nil && prfCompanionLayout.RelationVersion == 2 {
		// The v2 relation also contains four Boolean slot-bit constraints and
		// one slot reconstruction constraint before the PRF trace constraints.
		prfDirectFullCount = len(prfCompanionLayout.HiddenSlotBitSlots) + 1 +
			len(prfCompanionLayout.CheckpointSlots) +
			len(prfCompanionLayout.FinalRoundOutputSlots) +
			2*len(prfCompanionLayout.FinalTagSlots)
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
	prfDirectFullStart := 0
	if prfDirectFullCount > 0 {
		prfDirectFullStart = len(keySlots)
		if !intGenISISProjectionDerivesYView(l) {
			prfDirectFullStart += l.ViewRowsPerPoly * len(yLinear.Lagrange)
		}
	}
	var prfInputTraceRelation *prfInputTraceV3Relation
	if structuralV3 {
		prfInputTraceRelation, err = newPRFInputTraceV3RelationForShowing(ringQ, pub, l, omegaWitness, nil, layout.SigCount)
		if err != nil {
			return nil, err
		}
	}
	return &intGenISISShowingReplayConfig{
		Ring:                 ringQ,
		Layout:               *l,
		Omega:                append([]uint64(nil), omegaWitness...),
		DomainPoints:         append([]uint64(nil), domainPoints...),
		ACoeff:               aCoeff,
		AAtOmega:             aAtOmega,
		BCoeff:               bCoeff,
		BAtOmega:             bAtOmega,
		CMCoeff:              cmCoeff,
		CMAtOmega:            cmAtOmega,
		ASCoeff:              asCoeff,
		ASAtOmega:            asAtOmega,
		BoundRows:            boundRows,
		BoundPolys:           boundPolys,
		Shortness:            shortSpec,
		KeySlots:             keySlots,
		KeySource:            keySource,
		KeySourceMode:        keySourceMode,
		KeySourceDecodeLanes: keySourceDecodeLanes,
		PRFDirectFullStart:   prfDirectFullStart,
		PRFDirectFullCount:   prfDirectFullCount,
		Lagrange:             lagrange,
		BridgeBasis:          bridgeBasis,
		YLinear:              yLinear,
		MSECompression:       compressionSpec,
		HashCompressionV3:    hashCompressionSpec,
		PRFInputTraceV3:      prfInputTraceRelation,
	}, nil
}

func (cfg *intGenISISShowingReplayConfig) PRFDirectFullFaggOverrideIdxs() []int {
	if cfg == nil || cfg.PRFDirectFullCount <= 0 {
		return nil
	}
	out := make([]int, cfg.PRFDirectFullCount)
	for i := range out {
		out[i] = cfg.PRFDirectFullStart + i
	}
	return out
}

// semanticConstraintShapeV3 derives the exact CoreEvaluator family sizes from
// the immutable relation plan.  Its additions deliberately mirror the append
// order in CoreEvaluator: signature/inversion, membership and shortness for
// Fpar; then key binding, Y, input-trace, legacy placeholders, projected
// signature and coefficient-to-hat bridges for Fagg.  Keeping this structural
// prevents metadata construction from executing the relation on a dummy row.
func (cfg *intGenISISShowingReplayConfig) semanticConstraintShapeV3() (fpar, fagg int, err error) {
	if cfg == nil || cfg.Ring == nil {
		return 0, 0, fmt.Errorf("nil IntGenISIS showing replay config")
	}
	l := &cfg.Layout
	if l.ViewRowsPerPoly <= 0 || cfg.Shortness.L < 0 || l.UShortnessGroupCount < 0 {
		return 0, 0, fmt.Errorf("invalid IntGenISIS showing replay shape")
	}
	if intGenISISProjectionUsesProjectedUYHat(l) {
		fpar = l.ViewRowsPerPoly
	} else {
		fpar = 2 * l.ViewRowsPerPoly
	}
	fpar += len(cfg.BoundRows)
	shortnessPerGroup := cfg.Shortness.L
	if !intGenISISProjectionUsesDigitOnlyU(l) {
		shortnessPerGroup++
	}
	fpar += l.UShortnessGroupCount * shortnessPerGroup

	fagg = len(cfg.KeySlots)
	if !intGenISISProjectionDerivesYView(l) {
		if cfg.YLinear == nil {
			return 0, 0, fmt.Errorf("missing IntGenISIS Y-linear replay shape")
		}
		fagg += l.ViewRowsPerPoly * len(cfg.YLinear.Lagrange)
	}
	if cfg.PRFInputTraceV3 != nil {
		fagg += len(cfg.PRFInputTraceV3.BooleanBitSlots) + len(cfg.PRFInputTraceV3.Constraints)
	}
	fagg += cfg.PRFDirectFullCount
	if intGenISISProjectionUsesProjectedUYHat(l) {
		if cfg.BridgeBasis == nil {
			return 0, 0, fmt.Errorf("missing IntGenISIS projected-signature replay shape")
		}
		fagg += l.ViewRowsPerPoly * len(cfg.BridgeBasis.LagrangeBasis)
	}
	if cfg.BridgeBasis == nil {
		return 0, 0, fmt.Errorf("missing IntGenISIS bridge replay shape")
	}
	for _, bridge := range cfg.bridgeSpecs() {
		if bridge.components < 0 {
			return 0, 0, fmt.Errorf("invalid IntGenISIS bridge component count")
		}
		fagg += bridge.components * l.ViewRowsPerPoly * len(cfg.BridgeBasis.LagrangeBasis)
	}
	return fpar, fagg, nil
}

func (cfg *intGenISISShowingReplayConfig) bridgeSpecs() []struct {
	name       string
	source     int
	components int
	hat        int
	compressed bool
} {
	l := cfg.Layout
	out := make([]struct {
		name       string
		source     int
		components int
		hat        int
		compressed bool
	}, 0, 5)
	if !intGenISISProjectionUsesProjectedUYHat(&l) {
		out = append(out,
			struct {
				name       string
				source     int
				components int
				hat        int
				compressed bool
			}{"u", l.UViewStart, l.UCount, l.UHatStart, false},
			struct {
				name       string
				source     int
				components int
				hat        int
				compressed bool
			}{"Y", l.YViewStart, 1, l.YHatStart, false},
		)
	}
	linearHatBridges := []struct {
		name       string
		source     int
		components int
		hat        int
		compressed bool
	}{
		struct {
			name       string
			source     int
			components int
			hat        int
			compressed bool
		}{"x1", func() int {
			if l.HashSourceCarrierV3 {
				return l.X1CarrierStart
			}
			return l.X1ViewStart
		}(), l.X1Count, l.X1HatStart, l.HashSourceCarrierV3},
	}
	if intGenISISLinearHatSourceMode(&l) == intGenISISLinearHatSourceMaterialized {
		linearHatBridges = append([]struct {
			name       string
			source     int
			components int
			hat        int
			compressed bool
		}{
			{"mu_sig", func() int {
				if l.HashSourceCarrierV3 {
					return l.MuSigCarrierStart
				}
				return l.MuSigViewStart
			}(), l.MuSigCount, l.MuSigHatStart, l.HashSourceCarrierV3},
			{"x0", func() int {
				if l.HashSourceCarrierV3 {
					return l.X0CarrierStart
				}
				return l.X0ViewStart
			}(), l.X0Count, l.X0HatStart, l.HashSourceCarrierV3},
		}, linearHatBridges...)
	}
	return append(out, linearHatBridges...)
}

func (cfg *intGenISISShowingReplayConfig) evalProjectedTransformLaneF(x uint64, getRow func(int) (uint64, error), sourceStart, comp, block, lane int) (uint64, error) {
	if cfg == nil || cfg.BridgeBasis == nil {
		return 0, fmt.Errorf("missing IntGenISIS projected transform basis")
	}
	q := cfg.Ring.Modulus[0]
	l := cfg.Layout
	ncols := len(cfg.BridgeBasis.LagrangeBasis)
	t := block*ncols + lane
	if t < 0 || t >= len(cfg.BridgeBasis.TransformH) || t >= len(cfg.BridgeBasis.BlockFactors) {
		return 0, fmt.Errorf("projected transform lane t=%d out of range", t)
	}
	left := uint64(0)
	for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
		source, err := getRow(sourceStart + comp*l.ViewRowsPerPoly + srcBlock)
		if err != nil {
			return 0, err
		}
		h := EvalPoly(cfg.BridgeBasis.TransformH[t], x, q) % q
		scale := cfg.BridgeBasis.BlockFactors[t][srcBlock] % q
		left = modAdd(left, modMul(scale, modMul(h, source, q), q), q)
	}
	return left, nil
}

func (cfg *intGenISISShowingReplayConfig) evalProjectedUDigitTransformLaneF(x uint64, getRow func(int) (uint64, error), comp, block, lane int) (uint64, error) {
	if cfg == nil || cfg.BridgeBasis == nil {
		return 0, fmt.Errorf("missing IntGenISIS projected U digit transform basis")
	}
	q := cfg.Ring.Modulus[0]
	l := cfg.Layout
	ncols := len(cfg.BridgeBasis.LagrangeBasis)
	t := block*ncols + lane
	if t < 0 || t >= len(cfg.BridgeBasis.TransformH) || t >= len(cfg.BridgeBasis.BlockFactors) {
		return 0, fmt.Errorf("projected U digit transform lane t=%d out of range", t)
	}
	h := EvalPoly(cfg.BridgeBasis.TransformH[t], x, q) % q
	left := uint64(0)
	for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
		group := comp*l.ViewRowsPerPoly + srcBlock
		source := uint64(0)
		for digit := 0; digit < l.UShortnessRowsPerGroup; digit++ {
			row, err := getRow(l.UShortnessStart + group*l.UShortnessRowsPerGroup + digit)
			if err != nil {
				return 0, err
			}
			source = modAdd(source, modMul(cfg.Shortness.RPows[digit]%q, row, q), q)
		}
		scale := cfg.BridgeBasis.BlockFactors[t][srcBlock] % q
		left = modAdd(left, modMul(scale, modMul(h, source, q), q), q)
	}
	return left, nil
}

// evalProjectedHashCarrierTransformLaneF evaluates the public-linear NTT
// image of one decoded strict-v3 hash-source component.  It is used only by
// the mu/x0 aggregate-fusion mode: x1 continues through its materialized hat
// because it is multiplied by the witness-dependent Z hat.
func (cfg *intGenISISShowingReplayConfig) evalProjectedHashCarrierTransformLaneF(x uint64, getRow func(int) (uint64, error), sourceStart, comp, block, lane int) (uint64, error) {
	if cfg == nil || cfg.BridgeBasis == nil {
		return 0, fmt.Errorf("missing IntGenISIS projected hash-source transform basis")
	}
	l := cfg.Layout
	if !l.HashSourceCarrierV3 || l.HashCarrierPackWidth <= 1 || len(cfg.HashCompressionV3.DecodePolys) < l.HashCarrierPackWidth {
		return 0, fmt.Errorf("missing strict-v3 hash carrier decoder")
	}
	q := cfg.Ring.Modulus[0]
	ncols := len(cfg.BridgeBasis.LagrangeBasis)
	t := block*ncols + lane
	if t < 0 || t >= len(cfg.BridgeBasis.TransformH) || t >= len(cfg.BridgeBasis.BlockFactors) {
		return 0, fmt.Errorf("projected hash-source transform lane t=%d out of range", t)
	}
	h := EvalPoly(cfg.BridgeBasis.TransformH[t], x, q) % q
	left := uint64(0)
	for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
		local := comp*l.ViewRowsPerPoly + srcBlock
		carrier, err := getRow(sourceStart + local/l.HashCarrierPackWidth)
		if err != nil {
			return 0, err
		}
		decodeLane := local % l.HashCarrierPackWidth
		source := EvalPoly(cfg.HashCompressionV3.DecodePolys[decodeLane], carrier, q) % q
		scale := cfg.BridgeBasis.BlockFactors[t][srcBlock] % q
		left = modAdd(left, modMul(scale, modMul(h, source, q), q), q)
	}
	return left, nil
}

func (cfg *intGenISISShowingReplayConfig) evalYLinearSourceF(term intGenISISYLinearTermCache, comp, srcBlock int, getRow func(int) (uint64, error)) (uint64, error) {
	if cfg == nil || cfg.Ring == nil {
		return 0, fmt.Errorf("nil IntGenISIS showing replay config")
	}
	q := cfg.Ring.Modulus[0]
	l := cfg.Layout
	if term.Compressed {
		pack := l.MSECompressionPackWidth
		local := comp*l.ViewRowsPerPoly + srcBlock
		if term.Name == "M" && l.MSeedViewCount > 0 && local >= l.MCompressedSourceRows {
			seedBlock := local - l.MCompressedSourceRows
			if seedBlock < 0 || seedBlock >= l.MSeedViewCount {
				return 0, fmt.Errorf("m seed-tail block=%d outside count=%d", seedBlock, l.MSeedViewCount)
			}
			return getRow(l.MSeedViewStart + seedBlock)
		}
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

func (cfg *intGenISISShowingReplayConfig) evalProjectedSourceTransformLaneF(x uint64, getRow func(int) (uint64, error), term intGenISISYLinearTermCache, comp, block, lane int) (uint64, error) {
	if cfg == nil || cfg.BridgeBasis == nil {
		return 0, fmt.Errorf("missing IntGenISIS projected source transform basis")
	}
	q := cfg.Ring.Modulus[0]
	l := cfg.Layout
	ncols := len(cfg.BridgeBasis.LagrangeBasis)
	t := block*ncols + lane
	if t < 0 || t >= len(cfg.BridgeBasis.TransformH) || t >= len(cfg.BridgeBasis.BlockFactors) {
		return 0, fmt.Errorf("projected source transform lane t=%d out of range", t)
	}
	h := EvalPoly(cfg.BridgeBasis.TransformH[t], x, q) % q
	left := uint64(0)
	for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
		source, err := cfg.evalYLinearSourceF(term, comp, srcBlock, getRow)
		if err != nil {
			return 0, err
		}
		scale := cfg.BridgeBasis.BlockFactors[t][srcBlock] % q
		left = modAdd(left, modMul(scale, modMul(h, source, q), q), q)
	}
	return left, nil
}

func (cfg *intGenISISShowingReplayConfig) evalProjectedYHatLaneF(x uint64, getRow func(int) (uint64, error), block, lane int) (uint64, error) {
	if cfg == nil || cfg.YLinear == nil || len(cfg.YLinear.Terms) != 3 {
		return 0, fmt.Errorf("missing IntGenISIS projected Y replay cache")
	}
	q := cfg.Ring.Modulus[0]
	l := cfg.Layout
	mLane, err := cfg.evalProjectedSourceTransformLaneF(x, getRow, cfg.YLinear.Terms[0], 0, block, lane)
	if err != nil {
		return 0, err
	}
	cmVal := EvalPoly(cfg.CMCoeff[0][0][block], cfg.Omega[lane]%q, q) % q
	left := modMul(cmVal, mLane, q)
	for i := 0; i < l.SCount; i++ {
		sLane, err := cfg.evalProjectedSourceTransformLaneF(x, getRow, cfg.YLinear.Terms[1], i, block, lane)
		if err != nil {
			return 0, err
		}
		asVal := EvalPoly(cfg.ASCoeff[0][i][block], cfg.Omega[lane]%q, q) % q
		left = modAdd(left, modMul(asVal, sLane, q), q)
	}
	eLane, err := cfg.evalProjectedSourceTransformLaneF(x, getRow, cfg.YLinear.Terms[2], 0, block, lane)
	if err != nil {
		return 0, err
	}
	return modAdd(left, eLane, q), nil
}

func (cfg *intGenISISShowingReplayConfig) evalLinearHatF(_ uint64, getRow func(int) (uint64, error), kind intGenISISLinearHatKind, component, block int) (uint64, error) {
	if cfg == nil {
		return 0, fmt.Errorf("nil IntGenISIS showing replay config")
	}
	switch mode := intGenISISLinearHatSourceMode(&cfg.Layout); mode {
	case intGenISISLinearHatSourceMaterialized:
		row, err := intGenISISLinearHatMaterializedRow(&cfg.Layout, kind, component, block)
		if err != nil {
			return 0, err
		}
		return getRow(row)
	case intGenISISLinearHatSourceMuX0AggregateFused:
		if kind != intGenISISLinearHatX1 {
			return 0, fmt.Errorf("IntGenISIS %s hat is fused into the projected signature aggregate", kind)
		}
		row, err := intGenISISLinearHatMaterializedRow(&cfg.Layout, kind, component, block)
		if err != nil {
			return 0, err
		}
		return getRow(row)
	default:
		return 0, fmt.Errorf("unsupported IntGenISIS linear hat source mode %q", mode)
	}
}

func (cfg *intGenISISShowingReplayConfig) evalProjectedSignatureF(x uint64, getRow func(int) (uint64, error)) ([]uint64, error) {
	if cfg == nil || cfg.BridgeBasis == nil {
		return nil, fmt.Errorf("missing IntGenISIS projected signature metadata")
	}
	q := cfg.Ring.Modulus[0]
	l := cfg.Layout
	ncols := len(cfg.BridgeBasis.LagrangeBasis)
	evalTheta := func(coeff []uint64) uint64 {
		if len(coeff) == 0 {
			return 0
		}
		return EvalPoly(coeff, x, q) % q
	}
	out := make([]uint64, 0, l.ViewRowsPerPoly*ncols)
	fusedMuX0 := intGenISISLinearHatSourceMode(&l) == intGenISISLinearHatSourceMuX0AggregateFused
	for block := 0; block < l.ViewRowsPerPoly; block++ {
		z, err := getRow(l.ZHatStart + block)
		if err != nil {
			return nil, err
		}
		rhs := evalTheta(cfg.BCoeff[0][block])
		if !fusedMuX0 {
			muSig, err := cfg.evalLinearHatF(x, getRow, intGenISISLinearHatMuSig, 0, block)
			if err != nil {
				return nil, err
			}
			rhs = modAdd(rhs, modMul(evalTheta(cfg.BCoeff[1][block]), muSig, q), q)
			for i := 0; i < l.X0Count; i++ {
				x0, err := cfg.evalLinearHatF(x, getRow, intGenISISLinearHatX0, i, block)
				if err != nil {
					return nil, err
				}
				rhs = modAdd(rhs, modMul(evalTheta(cfg.BCoeff[2+i][block]), x0, q), q)
			}
		}
		rhs = modAdd(rhs, z, q)
		for lane := 0; lane < ncols; lane++ {
			res := uint64(0)
			for i := 0; i < l.UCount; i++ {
				var uLane uint64
				var err error
				if intGenISISProjectionUsesDigitOnlyU(&l) {
					uLane, err = cfg.evalProjectedUDigitTransformLaneF(x, getRow, i, block, lane)
				} else {
					uLane, err = cfg.evalProjectedTransformLaneF(x, getRow, l.UViewStart, i, block, lane)
				}
				if err != nil {
					return nil, err
				}
				// The packed-coeff transform is enforced in the aggregate
				// family, so A is evaluated as the public lane scalar.
				aLane := EvalPoly(cfg.ACoeff[0][i][block], cfg.Omega[lane]%q, q) % q
				res = modAdd(res, modMul(aLane, uLane, q), q)
			}
			lag := EvalPoly(cfg.BridgeBasis.LagrangeBasis[lane], x, q) % q
			res = modSub(res, modMul(lag, rhs, q), q)
			if fusedMuX0 {
				muSig, err := cfg.evalProjectedHashCarrierTransformLaneF(x, getRow, l.MuSigCarrierStart, 0, block, lane)
				if err != nil {
					return nil, err
				}
				res = modSub(res, modMul(cfg.BAtOmega[1][block][lane], muSig, q), q)
				for i := 0; i < l.X0Count; i++ {
					x0, err := cfg.evalProjectedHashCarrierTransformLaneF(x, getRow, l.X0CarrierStart, i, block, lane)
					if err != nil {
						return nil, err
					}
					res = modSub(res, modMul(cfg.BAtOmega[2+i][block][lane], x0, q), q)
				}
			}
			var yLane uint64
			if intGenISISProjectionDerivesYView(&l) {
				yLane, err = cfg.evalProjectedYHatLaneF(x, getRow, block, lane)
				if err != nil {
					return nil, err
				}
			} else {
				yLane, err = cfg.evalProjectedTransformLaneF(x, getRow, l.YViewStart, 0, block, lane)
				if err != nil {
					return nil, err
				}
			}
			res = modSub(res, yLane, q)
			out = append(out, res)
		}
	}
	return out, nil
}

func (cfg *intGenISISShowingReplayConfig) evalYLinearSourceK(K *kf.Field, term intGenISISYLinearTermCache, comp, srcBlock int, getRow func(int) (kf.Elem, error)) (kf.Elem, error) {
	if cfg == nil {
		return K.Zero(), fmt.Errorf("nil IntGenISIS showing replay config")
	}
	l := cfg.Layout
	if term.Compressed {
		pack := l.MSECompressionPackWidth
		local := comp*l.ViewRowsPerPoly + srcBlock
		if term.Name == "M" && l.MSeedViewCount > 0 && local >= l.MCompressedSourceRows {
			seedBlock := local - l.MCompressedSourceRows
			if seedBlock < 0 || seedBlock >= l.MSeedViewCount {
				return K.Zero(), fmt.Errorf("m seed-tail block=%d outside count=%d", seedBlock, l.MSeedViewCount)
			}
			return getRow(l.MSeedViewStart + seedBlock)
		}
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

func (cfg *intGenISISShowingReplayConfig) evalYLinearSourceKInto(K *kf.Field, dst *kf.Elem, term intGenISISYLinearTermCache, comp, srcBlock int, getRow func(int) (kf.Elem, error)) error {
	if cfg == nil {
		return fmt.Errorf("nil IntGenISIS showing replay config")
	}
	l := cfg.Layout
	if term.Compressed {
		pack := l.MSECompressionPackWidth
		local := comp*l.ViewRowsPerPoly + srcBlock
		if term.Name == "M" && l.MSeedViewCount > 0 && local >= l.MCompressedSourceRows {
			seedBlock := local - l.MCompressedSourceRows
			if seedBlock < 0 || seedBlock >= l.MSeedViewCount {
				return fmt.Errorf("m seed-tail block=%d outside count=%d", seedBlock, l.MSeedViewCount)
			}
			row, err := getRow(l.MSeedViewStart + seedBlock)
			if err != nil {
				return err
			}
			K.SetInto(dst, row)
			return nil
		}
		carrier, err := getRow(term.Source + local/pack)
		if err != nil {
			return err
		}
		lane := local % pack
		if lane < 0 || lane >= len(cfg.MSECompression.DecodePolys) {
			return fmt.Errorf("compressed %s decode lane=%d outside lanes=%d", term.Name, lane, len(cfg.MSECompression.DecodePolys))
		}
		K.EvalFPolyAtKInto(dst, cfg.MSECompression.DecodePolys[lane], carrier)
		return nil
	}
	row, err := getRow(term.Source + comp*l.ViewRowsPerPoly + srcBlock)
	if err != nil {
		return err
	}
	K.SetInto(dst, row)
	return nil
}

func (cfg *intGenISISShowingReplayConfig) evalLinearHatK(K *kf.Field, _ kf.Elem, getRow func(int) (kf.Elem, error), kind intGenISISLinearHatKind, component, block int) (kf.Elem, error) {
	if cfg == nil {
		return K.Zero(), fmt.Errorf("nil IntGenISIS showing replay config")
	}
	switch mode := intGenISISLinearHatSourceMode(&cfg.Layout); mode {
	case intGenISISLinearHatSourceMaterialized:
		row, err := intGenISISLinearHatMaterializedRow(&cfg.Layout, kind, component, block)
		if err != nil {
			return K.Zero(), err
		}
		return getRow(row)
	case intGenISISLinearHatSourceMuX0AggregateFused:
		if kind != intGenISISLinearHatX1 {
			return K.Zero(), fmt.Errorf("IntGenISIS %s hat is fused into the projected signature aggregate", kind)
		}
		row, err := intGenISISLinearHatMaterializedRow(&cfg.Layout, kind, component, block)
		if err != nil {
			return K.Zero(), err
		}
		return getRow(row)
	default:
		return K.Zero(), fmt.Errorf("unsupported IntGenISIS linear hat source mode %q", mode)
	}
}

func (cfg *intGenISISShowingReplayConfig) evalProjectedSignatureK(K *kf.Field, e kf.Elem, getRow func(int) (kf.Elem, error)) ([]kf.Elem, error) {
	if cfg == nil || cfg.BridgeBasis == nil {
		return nil, fmt.Errorf("missing IntGenISIS projected signature metadata")
	}
	l := cfg.Layout
	ncols := len(cfg.BridgeBasis.LagrangeBasis)
	total := l.ViewRowsPerPoly * ncols
	basePoint, embeddedPoint := embeddedFqValueV3(K, e)
	evalThetaInto := func(dst *kf.Elem, coeff []uint64) {
		if len(coeff) == 0 {
			K.ZeroInto(dst)
			return
		}
		if embeddedPoint {
			K.EmbedFInto(dst, EvalPoly(coeff, basePoint, K.Q))
			return
		}
		K.EvalFPolyAtKInto(dst, coeff, e)
	}
	transformAtE := make([]kf.Elem, 0)
	lagrangeAtE := make([]kf.Elem, 0)
	transformAtF := make([]uint64, 0)
	lagrangeAtF := make([]uint64, 0)
	if embeddedPoint {
		transformAtF = make([]uint64, total)
		for t := 0; t < total; t++ {
			transformAtF[t] = EvalPoly(cfg.BridgeBasis.TransformH[t], basePoint, K.Q)
		}
		lagrangeAtF = make([]uint64, ncols)
		for lane := 0; lane < ncols; lane++ {
			lagrangeAtF[lane] = EvalPoly(cfg.BridgeBasis.LagrangeBasis[lane], basePoint, K.Q)
		}
	} else {
		transformAtE = makeKElementBuffer(total, K.Theta)
		for t := 0; t < total; t++ {
			K.EvalFPolyAtKInto(&transformAtE[t], cfg.BridgeBasis.TransformH[t], e)
		}
		lagrangeAtE = makeKElementBuffer(ncols, K.Theta)
		for lane := 0; lane < ncols; lane++ {
			K.EvalFPolyAtKInto(&lagrangeAtE[lane], cfg.BridgeBasis.LagrangeBasis[lane], e)
		}
	}
	loadSources := func(start, components int) ([][]kf.Elem, error) {
		out := make([][]kf.Elem, components)
		for comp := 0; comp < components; comp++ {
			out[comp] = make([]kf.Elem, l.ViewRowsPerPoly)
			for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
				row, err := getRow(start + comp*l.ViewRowsPerPoly + srcBlock)
				if err != nil {
					return nil, err
				}
				out[comp][srcBlock] = row
			}
		}
		return out, nil
	}
	loadUSources := func() ([][]kf.Elem, error) {
		if !intGenISISProjectionUsesDigitOnlyU(&l) {
			return loadSources(l.UViewStart, l.UCount)
		}
		out := makeKElementMatrixBuffer(l.UCount, l.ViewRowsPerPoly, K.Theta)
		for comp := 0; comp < l.UCount; comp++ {
			for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
				group := comp*l.ViewRowsPerPoly + srcBlock
				sum := &out[comp][srcBlock]
				K.ZeroInto(sum)
				for digit := 0; digit < l.UShortnessRowsPerGroup; digit++ {
					row, err := getRow(l.UShortnessStart + group*l.UShortnessRowsPerGroup + digit)
					if err != nil {
						return nil, err
					}
					K.AddMulBaseInto(sum, row, cfg.Shortness.RPows[digit]%cfg.Ring.Modulus[0])
				}
			}
		}
		return out, nil
	}
	loadHashCarrierSources := func(sourceStart, components int) ([][]kf.Elem, error) {
		if !l.HashSourceCarrierV3 || l.HashCarrierPackWidth <= 1 || len(cfg.HashCompressionV3.DecodePolys) < l.HashCarrierPackWidth {
			return nil, fmt.Errorf("missing strict-v3 hash carrier decoder")
		}
		out := makeKElementMatrixBuffer(components, l.ViewRowsPerPoly, K.Theta)
		for comp := 0; comp < components; comp++ {
			for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
				local := comp*l.ViewRowsPerPoly + srcBlock
				carrier, err := getRow(sourceStart + local/l.HashCarrierPackWidth)
				if err != nil {
					return nil, err
				}
				decodeLane := local % l.HashCarrierPackWidth
				K.EvalFPolyAtKInto(&out[comp][srcBlock], cfg.HashCompressionV3.DecodePolys[decodeLane], carrier)
			}
		}
		return out, nil
	}
	loadYLinearSources := func(term intGenISISYLinearTermCache, components int) ([][]kf.Elem, error) {
		out := makeKElementMatrixBuffer(components, l.ViewRowsPerPoly, K.Theta)
		for comp := 0; comp < components; comp++ {
			for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
				if err := cfg.evalYLinearSourceKInto(K, &out[comp][srcBlock], term, comp, srcBlock, getRow); err != nil {
					return nil, err
				}
			}
		}
		return out, nil
	}
	uSources, err := loadUSources()
	if err != nil {
		return nil, err
	}
	fusedMuX0 := intGenISISLinearHatSourceMode(&l) == intGenISISLinearHatSourceMuX0AggregateFused
	var muSigSources, x0Sources [][]kf.Elem
	if fusedMuX0 {
		muSigSources, err = loadHashCarrierSources(l.MuSigCarrierStart, l.MuSigCount)
		if err != nil {
			return nil, err
		}
		x0Sources, err = loadHashCarrierSources(l.X0CarrierStart, l.X0Count)
		if err != nil {
			return nil, err
		}
	}
	var ySources [][][]kf.Elem
	derivedYView := intGenISISProjectionDerivesYView(&l)
	if derivedYView {
		if cfg.YLinear == nil || len(cfg.YLinear.Terms) != 3 {
			return nil, fmt.Errorf("missing IntGenISIS projected Y replay cache")
		}
		ySources = make([][][]kf.Elem, 3)
		ySources[0], err = loadYLinearSources(cfg.YLinear.Terms[0], 1)
		if err != nil {
			return nil, err
		}
		ySources[1], err = loadYLinearSources(cfg.YLinear.Terms[1], l.SCount)
		if err != nil {
			return nil, err
		}
		ySources[2], err = loadYLinearSources(cfg.YLinear.Terms[2], 1)
		if err != nil {
			return nil, err
		}
	} else {
		y, yerr := loadSources(l.YViewStart, 1)
		if yerr != nil {
			return nil, yerr
		}
		ySources = [][][]kf.Elem{y}
	}
	temps := makeKElementBuffer(7, K.Theta)
	transformLaneInto := func(dst *kf.Elem, t int, sources []kf.Elem, sum *kf.Elem) {
		K.ZeroInto(sum)
		for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
			scale := cfg.BridgeBasis.BlockFactors[t][srcBlock] % cfg.Ring.Modulus[0]
			K.AddMulBaseInto(sum, sources[srcBlock], scale)
		}
		if embeddedPoint {
			K.ScaleBaseInto(dst, *sum, transformAtF[t])
			return
		}
		K.MulInto(dst, transformAtE[t], *sum)
	}
	addThetaProduct := func(acc *kf.Elem, coeff []uint64, value kf.Elem) {
		if embeddedPoint {
			K.AddMulBaseInto(acc, value, EvalPoly(coeff, basePoint, K.Q))
			return
		}
		evalThetaInto(&temps[5], coeff)
		K.AddMulInto(acc, temps[5], value)
	}
	out := makeKElementBuffer(total, K.Theta)
	for block := 0; block < l.ViewRowsPerPoly; block++ {
		z, err := getRow(l.ZHatStart + block)
		if err != nil {
			return nil, err
		}
		rhs := &temps[4]
		evalThetaInto(rhs, cfg.BCoeff[0][block])
		if !fusedMuX0 {
			muSig, err := cfg.evalLinearHatK(K, e, getRow, intGenISISLinearHatMuSig, 0, block)
			if err != nil {
				return nil, err
			}
			addThetaProduct(rhs, cfg.BCoeff[1][block], muSig)
			for i := 0; i < l.X0Count; i++ {
				x0, err := cfg.evalLinearHatK(K, e, getRow, intGenISISLinearHatX0, i, block)
				if err != nil {
					return nil, err
				}
				addThetaProduct(rhs, cfg.BCoeff[2+i][block], x0)
			}
		}
		K.AddInto(rhs, *rhs, z)
		for lane := 0; lane < ncols; lane++ {
			t := block*ncols + lane
			res := &out[t]
			K.ZeroInto(res)
			for i := 0; i < l.UCount; i++ {
				aLane := cfg.AAtOmega[i][block][lane]
				transformLaneInto(&temps[0], t, uSources[i], &temps[1])
				K.AddMulBaseInto(res, temps[0], aLane)
			}
			if embeddedPoint {
				K.AddMulBaseInto(res, *rhs, (K.Q-lagrangeAtF[lane])%K.Q)
			} else {
				K.SubMulInto(res, lagrangeAtE[lane], *rhs)
			}
			if fusedMuX0 {
				transformLaneInto(&temps[0], t, muSigSources[0], &temps[1])
				K.AddMulBaseInto(res, temps[0], (K.Q-cfg.BAtOmega[1][block][lane])%K.Q)
				for i := 0; i < l.X0Count; i++ {
					transformLaneInto(&temps[0], t, x0Sources[i], &temps[1])
					K.AddMulBaseInto(res, temps[0], (K.Q-cfg.BAtOmega[2+i][block][lane])%K.Q)
				}
			}
			yLane := &temps[2]
			if derivedYView {
				K.ZeroInto(yLane)
				transformLaneInto(&temps[0], t, ySources[0][0], &temps[1])
				K.AddMulBaseInto(yLane, temps[0], cfg.CMAtOmega[block][lane])
				for i := 0; i < l.SCount; i++ {
					transformLaneInto(&temps[0], t, ySources[1][i], &temps[1])
					K.AddMulBaseInto(yLane, temps[0], cfg.ASAtOmega[i][block][lane])
				}
				transformLaneInto(&temps[0], t, ySources[2][0], &temps[1])
				K.AddInto(yLane, *yLane, temps[0])
			} else {
				transformLaneInto(yLane, t, ySources[0][0], &temps[1])
			}
			K.SubInto(res, *res, *yLane)
		}
	}
	return out, nil
}

func (cfg *intGenISISShowingReplayConfig) evalYLinearF(x uint64, getRow func(int) (uint64, error)) ([]uint64, error) {
	if cfg == nil || cfg.YLinear == nil {
		return nil, fmt.Errorf("missing IntGenISIS Y-linear replay cache")
	}
	q := cfg.Ring.Modulus[0]
	l := cfg.Layout
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
						src, err := cfg.evalYLinearSourceF(term, comp, srcBlock, getRow)
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
						src, err := cfg.evalYLinearSourceK(K, term, comp, srcBlock, getRow)
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
		projectedUY := intGenISISProjectionUsesProjectedUYHat(&l)
		derivedYView := intGenISISProjectionDerivesYView(&l)
		fpar := make([]uint64, 0, 2*l.ViewRowsPerPoly+len(cfg.KeySlots)+len(cfg.BoundRows)+l.UShortnessGroupCount*(1+cfg.Shortness.L))
		for block := 0; block < l.ViewRowsPerPoly; block++ {
			var z uint64
			var err error
			if !projectedUY {
				sig := uint64(0)
				for i := 0; i < l.UCount; i++ {
					row, err := getRow(l.UHatStart + i*l.ViewRowsPerPoly + block)
					if err != nil {
						return nil, nil, err
					}
					sig = modAdd(sig, modMul(evalTheta(cfg.ACoeff[0][i][block]), row, q), q)
				}
				sig = modSub(sig, evalTheta(cfg.BCoeff[0][block]), q)
				muSig, err := cfg.evalLinearHatF(x, getRow, intGenISISLinearHatMuSig, 0, block)
				if err != nil {
					return nil, nil, err
				}
				sig = modSub(sig, modMul(evalTheta(cfg.BCoeff[1][block]), muSig, q), q)
				for i := 0; i < l.X0Count; i++ {
					x0, err := cfg.evalLinearHatF(x, getRow, intGenISISLinearHatX0, i, block)
					if err != nil {
						return nil, nil, err
					}
					sig = modSub(sig, modMul(evalTheta(cfg.BCoeff[2+i][block]), x0, q), q)
				}
				z, err = getRow(l.ZHatStart + block)
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
			}
			z, err = getRow(l.ZHatStart + block)
			if err != nil {
				return nil, nil, err
			}

			x1, err := cfg.evalLinearHatF(x, getRow, intGenISISLinearHatX1, 0, block)
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
		for group := 0; group < l.UShortnessGroupCount; group++ {
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
			if !intGenISISProjectionUsesDigitOnlyU(&l) {
				source, err := getRow(l.UShortnessSourceViewStart + group)
				if err != nil {
					return nil, nil, err
				}
				fpar = append(fpar, modSub(source, recon, q))
			}
			for lane := 0; lane < cfg.Shortness.L; lane++ {
				fpar = append(fpar, intGenISISEvalMembership(q, cfg.Shortness.PDi[lane], digits[lane]))
			}
		}
		fagg := make([]uint64, 0)
		if len(cfg.KeySlots) > 0 {
			keySourceMode := cfg.KeySourceMode
			if keySourceMode == "" {
				keySourceMode = PRFKeySourceModeDirect
			}
			if keySourceMode == PRFKeySourceModePack9Seed {
				for i := range cfg.KeySlots {
					key := cfg.KeySlots[i]
					if key.Coeff < 0 || key.Coeff >= len(cfg.Lagrange) {
						return nil, nil, fmt.Errorf("PRF key binding slot out of range")
					}
					keyVal, err := getRow(key.Row)
					if err != nil {
						return nil, nil, err
					}
					val := modMul(EvalPoly(cfg.Lagrange[key.Coeff], x, q), keyVal, q)
					pow := uint64(1)
					constant := uint64(0)
					for j := 0; j < intGenISISPRFSeedDigitsPerLane; j++ {
						src := cfg.KeySource[i*intGenISISPRFSeedDigitsPerLane+j]
						if src.Coeff < 0 || src.Coeff >= len(cfg.Lagrange) {
							return nil, nil, fmt.Errorf("PRF seed binding slot out of range")
						}
						srcVal, err := getRow(src.Row)
						if err != nil {
							return nil, nil, err
						}
						term := modMul(EvalPoly(cfg.Lagrange[src.Coeff], x, q), modMul(pow, srcVal, q), q)
						val = modSub(val, term, q)
						constant = (constant + (uint64(credential.IntGenISISPRFSeedBound)%q)*pow) % q
						pow = (pow * uint64(credential.IntGenISISPRFSeedPackBase)) % q
					}
					if constant != 0 {
						val = modSub(val, modMul(EvalPoly(cfg.Lagrange[key.Coeff], x, q), constant, q), q)
					}
					fagg = append(fagg, val)
				}
			} else if keySourceMode != PRFKeySourceModeDirect {
				return nil, nil, fmt.Errorf("unsupported PRF key source mode %q", keySourceMode)
			} else {
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
		}
		if !derivedYView {
			yVals, err := cfg.evalYLinearF(x, getRow)
			if err != nil {
				return nil, nil, err
			}
			fagg = append(fagg, yVals...)
		}
		if cfg.PRFInputTraceV3 != nil {
			_, prfVals, err := cfg.PRFInputTraceV3.Evaluator(cfg.DomainPoints)(evalIdx, rows)
			if err != nil {
				return nil, nil, err
			}
			fagg = append(fagg, prfVals...)
		}
		for i := 0; i < cfg.PRFDirectFullCount; i++ {
			fagg = append(fagg, 0)
		}
		if projectedUY {
			projectedVals, err := cfg.evalProjectedSignatureF(x, getRow)
			if err != nil {
				return nil, nil, err
			}
			fagg = append(fagg, projectedVals...)
		}
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
								decodePolys := cfg.MSECompression.DecodePolys
								if l.HashSourceCarrierV3 && (bridge.name == "mu_sig" || bridge.name == "x0" || bridge.name == "x1") {
									pack = l.HashCarrierPackWidth
									decodePolys = cfg.HashCompressionV3.DecodePolys
								}
								local := comp*l.ViewRowsPerPoly + srcBlock
								carrier, err := getRow(bridge.source + local/pack)
								if err != nil {
									return nil, nil, err
								}
								lane := local % pack
								if lane < 0 || lane >= len(decodePolys) {
									return nil, nil, fmt.Errorf("compressed %s decode lane=%d outside lanes=%d", bridge.name, lane, len(decodePolys))
								}
								source = EvalPoly(decodePolys[lane], carrier, q) % q
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

func (cfg *intGenISISShowingReplayConfig) coreKEvaluatorV3(K *kf.Field, preparedFpar, preparedFagg []kf.Elem) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil IntGenISIS showing replay config")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	var prfEval KConstraintEvaluator
	if cfg.PRFInputTraceV3 != nil {
		var err error
		prfEval, err = cfg.PRFInputTraceV3.KEvaluator(K)
		if err != nil {
			return nil, err
		}
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		l := cfg.Layout
		projectedUY := intGenISISProjectionUsesProjectedUYHat(&l)
		derivedYView := intGenISISProjectionDerivesYView(&l)
		basePoint, embeddedPoint := embeddedFqValueV3(K, e)
		fparCapacity := 2*l.ViewRowsPerPoly + len(cfg.KeySlots) + len(cfg.BoundRows) + l.UShortnessGroupCount*(1+cfg.Shortness.L)
		fparStorage := preparedFpar
		if len(fparStorage) == 0 {
			fparStorage = makeKElementBuffer(fparCapacity, K.Theta)
		}
		fparCount := 0
		temps := makeKElementBuffer(3, K.Theta)
		evalThetaInto := func(dst *kf.Elem, coeff []uint64) {
			if len(coeff) == 0 {
				K.ZeroInto(dst)
				return
			}
			if embeddedPoint {
				K.EmbedFInto(dst, EvalPoly(coeff, basePoint, K.Q))
				return
			}
			K.EvalFPolyAtKInto(dst, coeff, e)
		}
		evalThetaBase := func(coeff []uint64) uint64 {
			if len(coeff) == 0 {
				return 0
			}
			return EvalPoly(coeff, basePoint, K.Q) % K.Q
		}
		for block := 0; block < l.ViewRowsPerPoly; block++ {
			var z kf.Elem
			var err error
			if !projectedUY {
				sig := &fparStorage[fparCount]
				fparCount++
				K.ZeroInto(sig)
				for i := 0; i < l.UCount; i++ {
					row, err := getRow(l.UHatStart + i*l.ViewRowsPerPoly + block)
					if err != nil {
						return nil, nil, err
					}
					if embeddedPoint {
						K.AddMulBaseInto(sig, row, evalThetaBase(cfg.ACoeff[0][i][block]))
					} else {
						evalThetaInto(&temps[0], cfg.ACoeff[0][i][block])
						K.MulInto(&temps[1], temps[0], row)
						K.AddInto(sig, *sig, temps[1])
					}
				}
				if embeddedPoint {
					sig.Limb[0] = modSub(sig.Limb[0], evalThetaBase(cfg.BCoeff[0][block]), K.Q)
				} else {
					evalThetaInto(&temps[0], cfg.BCoeff[0][block])
					K.SubInto(sig, *sig, temps[0])
				}
				muSig, err := cfg.evalLinearHatK(K, e, getRow, intGenISISLinearHatMuSig, 0, block)
				if err != nil {
					return nil, nil, err
				}
				if embeddedPoint {
					K.SubMulBaseInto(sig, muSig, evalThetaBase(cfg.BCoeff[1][block]))
				} else {
					evalThetaInto(&temps[0], cfg.BCoeff[1][block])
					K.MulInto(&temps[1], temps[0], muSig)
					K.SubInto(sig, *sig, temps[1])
				}
				for i := 0; i < l.X0Count; i++ {
					x0, err := cfg.evalLinearHatK(K, e, getRow, intGenISISLinearHatX0, i, block)
					if err != nil {
						return nil, nil, err
					}
					if embeddedPoint {
						K.SubMulBaseInto(sig, x0, evalThetaBase(cfg.BCoeff[2+i][block]))
					} else {
						evalThetaInto(&temps[0], cfg.BCoeff[2+i][block])
						K.MulInto(&temps[1], temps[0], x0)
						K.SubInto(sig, *sig, temps[1])
					}
				}
				z, err = getRow(l.ZHatStart + block)
				if err != nil {
					return nil, nil, err
				}
				K.SubInto(sig, *sig, z)
				y, err := getRow(l.YHatStart + block)
				if err != nil {
					return nil, nil, err
				}
				K.SubInto(sig, *sig, y)
			}
			z, err = getRow(l.ZHatStart + block)
			if err != nil {
				return nil, nil, err
			}

			x1, err := cfg.evalLinearHatK(K, e, getRow, intGenISISLinearHatX1, 0, block)
			if err != nil {
				return nil, nil, err
			}
			inv := &fparStorage[fparCount]
			fparCount++
			evalThetaInto(inv, cfg.BCoeff[len(cfg.BCoeff)-1][block])
			K.SubInto(inv, *inv, x1)
			K.MulInto(inv, *inv, z)
			inv.Limb[0] = modSub(inv.Limb[0], 1%cfg.Ring.Modulus[0], K.Q)

		}
		for i, idx := range cfg.BoundRows {
			row, err := getRow(idx)
			if err != nil {
				return nil, nil, err
			}
			if i >= len(cfg.BoundPolys) {
				return nil, nil, fmt.Errorf("missing IntGenISIS bound polynomial %d", i)
			}
			value := &fparStorage[fparCount]
			fparCount++
			K.EvalFPolyAtKInto(value, cfg.BoundPolys[i], row)
		}
		for group := 0; group < l.UShortnessGroupCount; group++ {
			recon := &temps[2]
			K.ZeroInto(recon)
			for lane := 0; lane < cfg.Shortness.L; lane++ {
				digit, err := getRow(l.UShortnessStart + group*l.UShortnessRowsPerGroup + lane)
				if err != nil {
					return nil, nil, err
				}
				K.AddMulBaseInto(recon, digit, cfg.Shortness.RPows[lane]%cfg.Ring.Modulus[0])
			}
			if !intGenISISProjectionUsesDigitOnlyU(&l) {
				source, err := getRow(l.UShortnessSourceViewStart + group)
				if err != nil {
					return nil, nil, err
				}
				value := &fparStorage[fparCount]
				fparCount++
				K.SubInto(value, source, *recon)
			}
			for lane := 0; lane < cfg.Shortness.L; lane++ {
				digit, err := getRow(l.UShortnessStart + group*l.UShortnessRowsPerGroup + lane)
				if err != nil {
					return nil, nil, err
				}
				value := &fparStorage[fparCount]
				fparCount++
				K.EvalFPolyAtKInto(value, cfg.Shortness.PDi[lane], digit)
			}
		}
		fpar := fparStorage[:fparCount]
		fagg := preparedFagg[:0]
		appendFagg := func(value kf.Elem) {
			if len(preparedFagg) == 0 {
				fagg = append(fagg, value)
				return
			}
			if len(fagg) >= cap(fagg) {
				panic("IntGenISIS prepared aggregate constraint storage exhausted")
			}
			fagg = fagg[:len(fagg)+1]
			K.SetInto(&fagg[len(fagg)-1], value)
		}
		if len(cfg.KeySlots) > 0 {
			keySourceMode := cfg.KeySourceMode
			if keySourceMode == "" {
				keySourceMode = PRFKeySourceModeDirect
			}
			if keySourceMode == PRFKeySourceModePack9Seed {
				for i := range cfg.KeySlots {
					key := cfg.KeySlots[i]
					if key.Coeff < 0 || key.Coeff >= len(cfg.Lagrange) {
						return nil, nil, fmt.Errorf("PRF key binding slot out of range")
					}
					keyVal, err := getRow(key.Row)
					if err != nil {
						return nil, nil, err
					}
					val := K.Zero()
					if embeddedPoint {
						K.ScaleBaseInto(&val, keyVal, evalThetaBase(cfg.Lagrange[key.Coeff]))
					} else {
						val = K.Mul(K.EvalFPolyAtK(cfg.Lagrange[key.Coeff], e), keyVal)
					}
					pow := uint64(1)
					constant := uint64(0)
					for j := 0; j < intGenISISPRFSeedDigitsPerLane; j++ {
						src := cfg.KeySource[i*intGenISISPRFSeedDigitsPerLane+j]
						if src.Coeff < 0 || src.Coeff >= len(cfg.Lagrange) {
							return nil, nil, fmt.Errorf("PRF seed binding slot out of range")
						}
						srcVal, err := getRow(src.Row)
						if err != nil {
							return nil, nil, err
						}
						if embeddedPoint {
							scale := modMul(evalThetaBase(cfg.Lagrange[src.Coeff]), pow%cfg.Ring.Modulus[0], K.Q)
							K.SubMulBaseInto(&val, srcVal, scale)
						} else {
							term := K.Mul(K.EvalFPolyAtK(cfg.Lagrange[src.Coeff], e), K.Mul(K.EmbedF(pow%cfg.Ring.Modulus[0]), srcVal))
							val = K.Sub(val, term)
						}
						constant = (constant + (uint64(credential.IntGenISISPRFSeedBound)%cfg.Ring.Modulus[0])*pow) % cfg.Ring.Modulus[0]
						pow = (pow * uint64(credential.IntGenISISPRFSeedPackBase)) % cfg.Ring.Modulus[0]
					}
					if constant != 0 {
						if embeddedPoint {
							val.Limb[0] = modSub(val.Limb[0], modMul(evalThetaBase(cfg.Lagrange[key.Coeff]), constant, K.Q), K.Q)
						} else {
							val = K.Sub(val, K.Mul(K.EvalFPolyAtK(cfg.Lagrange[key.Coeff], e), K.EmbedF(constant)))
						}
					}
					appendFagg(val)
				}
			} else if keySourceMode != PRFKeySourceModeDirect {
				return nil, nil, fmt.Errorf("unsupported PRF key source mode %q", keySourceMode)
			} else {
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
					if embeddedPoint {
						left := K.Zero()
						K.ScaleBaseInto(&left, keyVal, evalThetaBase(cfg.Lagrange[key.Coeff]))
						K.SubMulBaseInto(&left, srcVal, evalThetaBase(cfg.Lagrange[src.Coeff]))
						appendFagg(left)
					} else {
						left := K.Mul(K.EvalFPolyAtK(cfg.Lagrange[key.Coeff], e), keyVal)
						right := K.Mul(K.EvalFPolyAtK(cfg.Lagrange[src.Coeff], e), srcVal)
						appendFagg(K.Sub(left, right))
					}
				}
			}
		}
		if !derivedYView {
			yVals, err := cfg.evalYLinearK(K, e, getRow)
			if err != nil {
				return nil, nil, err
			}
			for i := range yVals {
				appendFagg(yVals[i])
			}
		}
		if prfEval != nil {
			_, prfVals, err := prfEval(e, rows)
			if err != nil {
				return nil, nil, err
			}
			for i := range prfVals {
				appendFagg(prfVals[i])
			}
		}
		for i := 0; i < cfg.PRFDirectFullCount; i++ {
			appendFagg(K.Zero())
		}
		if projectedUY {
			projectedVals, err := cfg.evalProjectedSignatureK(K, e, getRow)
			if err != nil {
				return nil, nil, err
			}
			for i := range projectedVals {
				appendFagg(projectedVals[i])
			}
		}
		bridgeSpecs := cfg.bridgeSpecs()
		bridgeLanes := len(cfg.BridgeBasis.LagrangeBasis)
		bridgeTotal := l.ViewRowsPerPoly * bridgeLanes
		var bridgeTransformK, bridgeLagrangeK []kf.Elem
		var bridgeTransformF, bridgeLagrangeF []uint64
		if embeddedPoint {
			bridgeTransformF = make([]uint64, bridgeTotal)
			bridgeLagrangeF = make([]uint64, bridgeLanes)
			for i := range bridgeTransformF {
				bridgeTransformF[i] = EvalPoly(cfg.BridgeBasis.TransformH[i], basePoint, K.Q) % K.Q
			}
			for i := range bridgeLagrangeF {
				bridgeLagrangeF[i] = EvalPoly(cfg.BridgeBasis.LagrangeBasis[i], basePoint, K.Q) % K.Q
			}
		} else {
			bridgeTransformK = makeKElementBuffer(bridgeTotal, K.Theta)
			bridgeLagrangeK = makeKElementBuffer(bridgeLanes, K.Theta)
			for i := range bridgeTransformK {
				K.EvalFPolyAtKInto(&bridgeTransformK[i], cfg.BridgeBasis.TransformH[i], e)
			}
			for i := range bridgeLagrangeK {
				K.EvalFPolyAtKInto(&bridgeLagrangeK[i], cfg.BridgeBasis.LagrangeBasis[i], e)
			}
		}
		bridgeValueCount := 0
		for _, bridge := range bridgeSpecs {
			bridgeValueCount += bridge.components * l.ViewRowsPerPoly * bridgeLanes
		}
		bridgeValues := makeKElementBuffer(bridgeValueCount, K.Theta)
		if len(preparedFagg) > 0 {
			if len(fagg)+bridgeValueCount > cap(fagg) {
				return nil, nil, fmt.Errorf("prepared aggregate storage=%d smaller than required=%d", cap(fagg), len(fagg)+bridgeValueCount)
			}
			bridgeValues = preparedFagg[len(fagg) : len(fagg)+bridgeValueCount]
		}
		bridgeValuePos := 0
		for _, bridge := range bridgeSpecs {
			// A source lane depends on this K point but not on the output
			// block/lane. Decode it once instead of once per bridge equation.
			sources := makeKElementMatrixBuffer(bridge.components, l.ViewRowsPerPoly, K.Theta)
			for comp := 0; comp < bridge.components; comp++ {
				for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
					if bridge.compressed {
						pack := l.MSECompressionPackWidth
						decodePolys := cfg.MSECompression.DecodePolys
						if l.HashSourceCarrierV3 && (bridge.name == "mu_sig" || bridge.name == "x0" || bridge.name == "x1") {
							pack = l.HashCarrierPackWidth
							decodePolys = cfg.HashCompressionV3.DecodePolys
						}
						local := comp*l.ViewRowsPerPoly + srcBlock
						carrier, err := getRow(bridge.source + local/pack)
						if err != nil {
							return nil, nil, err
						}
						lane := local % pack
						if lane < 0 || lane >= len(decodePolys) {
							return nil, nil, fmt.Errorf("compressed %s decode lane=%d outside lanes=%d", bridge.name, lane, len(decodePolys))
						}
						K.EvalFPolyAtKInto(&sources[comp][srcBlock], decodePolys[lane], carrier)
					} else {
						source, err := getRow(bridge.source + comp*l.ViewRowsPerPoly + srcBlock)
						if err != nil {
							return nil, nil, err
						}
						K.SetInto(&sources[comp][srcBlock], source)
					}
				}
			}
			for comp := 0; comp < bridge.components; comp++ {
				for block := 0; block < l.ViewRowsPerPoly; block++ {
					hat, err := getRow(bridge.hat + comp*l.ViewRowsPerPoly + block)
					if err != nil {
						return nil, nil, err
					}
					for lane := 0; lane < bridgeLanes; lane++ {
						t := block*bridgeLanes + lane
						weighted := &temps[0]
						K.ZeroInto(weighted)
						for srcBlock := 0; srcBlock < l.ViewRowsPerPoly; srcBlock++ {
							K.AddMulBaseInto(weighted, sources[comp][srcBlock], cfg.BridgeBasis.BlockFactors[t][srcBlock]%cfg.Ring.Modulus[0])
						}
						left := &bridgeValues[bridgeValuePos]
						bridgeValuePos++
						right := &temps[1]
						if embeddedPoint {
							K.ScaleBaseInto(left, *weighted, bridgeTransformF[t])
							K.ScaleBaseInto(right, hat, bridgeLagrangeF[lane])
						} else {
							K.MulInto(left, bridgeTransformK[t], *weighted)
							K.MulInto(right, bridgeLagrangeK[lane], hat)
						}
						K.SubInto(left, *left, *right)
					}
				}
			}
		}
		if len(preparedFagg) > 0 {
			fagg = preparedFagg[:len(fagg)+len(bridgeValues)]
		} else {
			fagg = append(fagg, bridgeValues...)
		}
		return fpar, fagg, nil
	}, nil
}

// CoreKEvaluator preserves the compatibility evaluator. Strict-v3 prover
// execution may instead use CoreKIntoEvaluator so each semantic worker owns
// and reuses its output storage.
func (cfg *intGenISISShowingReplayConfig) CoreKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	return cfg.coreKEvaluatorV3(K, nil, nil)
}

type intGenISISShowingKIntoScratchV3 struct {
	evaluator KConstraintEvaluator
	fparBase  *uint64
	faggBase  *uint64
}

func kElementBufferBaseV3(values []kf.Elem) *uint64 {
	if len(values) == 0 || len(values[0].Limb) == 0 {
		return nil
	}
	return &values[0].Limb[0]
}

// CoreKIntoEvaluator is the strict-v3 allocation-aware showing evaluator. Its
// output buffers are owned by one semantic worker and are bound on first use;
// reusing the scratch object with different buffers fails closed.
func (cfg *intGenISISShowingReplayConfig) CoreKIntoEvaluator(K *kf.Field) (*semanticKConstraintIntoV3, error) {
	if _, err := cfg.CoreKEvaluator(K); err != nil {
		return nil, err
	}
	fparCount, faggCount, err := cfg.semanticConstraintShapeV3()
	if err != nil {
		return nil, err
	}
	return &semanticKConstraintIntoV3{
		ParallelCount:  fparCount,
		AggregateCount: faggCount,
		NewScratch: func() any {
			return &intGenISISShowingKIntoScratchV3{}
		},
		EvalInto: func(e kf.Elem, rows, fpar, fagg []kf.Elem, rawScratch any) error {
			if len(fpar) != fparCount || len(fagg) != faggCount {
				return fmt.Errorf("showing K Into output shape=(%d,%d) want (%d,%d)", len(fpar), len(fagg), fparCount, faggCount)
			}
			scratch, ok := rawScratch.(*intGenISISShowingKIntoScratchV3)
			if !ok || scratch == nil {
				return fmt.Errorf("showing K Into scratch has unexpected type %T", rawScratch)
			}
			fparBase := kElementBufferBaseV3(fpar)
			faggBase := kElementBufferBaseV3(fagg)
			if scratch.evaluator == nil {
				scratch.evaluator, err = cfg.coreKEvaluatorV3(K, fpar, fagg)
				if err != nil {
					return err
				}
				scratch.fparBase = fparBase
				scratch.faggBase = faggBase
			} else if scratch.fparBase != fparBase || scratch.faggBase != faggBase {
				return fmt.Errorf("showing K Into scratch reused with different output storage")
			}
			gotFpar, gotFagg, err := scratch.evaluator(e, rows)
			if err != nil {
				return err
			}
			if len(gotFpar) != fparCount || len(gotFagg) != faggCount || kElementBufferBaseV3(gotFpar) != fparBase || kElementBufferBaseV3(gotFagg) != faggBase {
				return fmt.Errorf("showing K Into evaluator escaped prepared output storage")
			}
			return nil
		},
	}, nil
}
