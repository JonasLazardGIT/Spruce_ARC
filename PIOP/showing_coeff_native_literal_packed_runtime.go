package PIOP

import (
	"fmt"
	"path/filepath"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type literalPackedPolyWitness struct {
	Sig      [][]*ring.Poly
	SigLimbs [][][]*ring.Poly
}

func buildLiteralPackedPolyWitness(ringQ *ring.Ring, cn *CoeffNativeShowingWitness, omega []uint64, ncols int, model string, opts SimOpts) (*literalPackedPolyWitness, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if cn == nil {
		return nil, fmt.Errorf("nil coeff-native showing witness")
	}
	if ncols <= 0 || int(ringQ.N)%ncols != 0 {
		return nil, fmt.Errorf("invalid ncols=%d for ringN=%d", ncols, ringQ.N)
	}
	if len(omega) != ncols {
		return nil, fmt.Errorf("omega len=%d want ncols=%d", len(omega), ncols)
	}
	if model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return nil, fmt.Errorf("unsupported coeff-native showing model %q", model)
	}
	q := ringQ.Modulus[0]
	blocks := int(ringQ.N) / ncols
	out := &literalPackedPolyWitness{
		Sig:      make([][]*ring.Poly, len(cn.Sig)),
		SigLimbs: make([][][]*ring.Poly, len(cn.Sig)),
	}
	opts.CoeffNativeSigModel = model
	spec, err := signatureChainSpecForOpts(q, opts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	for comp := range cn.Sig {
		if cn.Sig[comp] == nil || len(cn.Sig[comp].Coeffs) == 0 || len(cn.Sig[comp].Coeffs[0]) < int(ringQ.N) {
			return nil, fmt.Errorf("signature component %d width=%d want ringN=%d", comp, len(cn.Sig[comp].Coeffs[0]), ringQ.N)
		}
		out.Sig[comp] = make([]*ring.Poly, blocks)
		out.SigLimbs[comp] = make([][]*ring.Poly, blocks)
		for block := 0; block < blocks; block++ {
			start := block * ncols
			end := start + ncols
			sigHead := append([]uint64(nil), cn.Sig[comp].Coeffs[0][start:end]...)
			for i := range sigHead {
				sigHead[i] %= q
			}
			out.Sig[comp][block] = BuildThetaPrime(ringQ, sigHead, omega)
			out.SigLimbs[comp][block] = make([]*ring.Poly, spec.L)
			limbHeads := make([][]uint64, spec.L)
			for lane := 0; lane < spec.L; lane++ {
				limbHeads[lane] = make([]uint64, ncols)
			}
			for i := range sigHead {
				av := centeredLift(sigHead[i], q)
				digits, derr := decomposeLinfDigitsSigned(av, spec)
				if derr != nil {
					return nil, fmt.Errorf("v3 signature limb decomposition (comp=%d block=%d col=%d): %w", comp, block, i, derr)
				}
				for lane := 0; lane < spec.L; lane++ {
					limbHeads[lane][i] = liftToField(q, digits[lane])
				}
			}
			for lane := 0; lane < spec.L; lane++ {
				out.SigLimbs[comp][block][lane] = BuildThetaPrime(ringQ, limbHeads[lane], omega)
			}
		}
	}
	return out, nil
}

func repeatFieldValue(v uint64, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func centeredLift(v, q uint64) int64 {
	out := int64(v % q)
	if out > int64(q)/2 {
		out -= int64(q)
	}
	return out
}

func polyAddMod(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	if n == 0 {
		return []uint64{0}
	}
	out := make([]uint64, n)
	copy(out, a)
	for i := 0; i < len(b); i++ {
		out[i] = modAdd(out[i], b[i]%q, q)
	}
	return trimPoly(out, q)
}

func polyScale(a []uint64, c uint64, q uint64) []uint64 {
	if len(a) == 0 || c%q == 0 {
		return []uint64{0}
	}
	out := make([]uint64, len(a))
	for i := range a {
		out[i] = modMul(a[i]%q, c%q, q)
	}
	return trimPoly(out, q)
}

func polySubMod(a, b []uint64, q uint64) []uint64 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	if n == 0 {
		return []uint64{0}
	}
	out := make([]uint64, n)
	copy(out, a)
	for i := 0; i < len(b); i++ {
		out[i] = modSub(out[i], b[i]%q, q)
	}
	return trimPoly(out, q)
}

func coeffsToNTTIfFits(ringQ *ring.Ring, coeffs []uint64) *ring.Poly {
	if ringQ == nil {
		return nil
	}
	if len(coeffs) == 0 {
		coeffs = []uint64{0}
	}
	if len(coeffs) > int(ringQ.N) {
		return nil
	}
	p := ringQ.NewPoly()
	copy(p.Coeffs[0], coeffs)
	ringQ.NTT(p, p)
	return p
}

func literalPackedPostSignReplayRowCount(layout RowLayout) int {
	if layout.SigCount > 0 {
		return layout.SigCount
	}
	cfg := layout.CoeffNativeSig
	rowCount := 0
	if cfg.PackedSigBase >= 0 {
		if end := cfg.PackedSigBase + cfg.PackedSigCount; end > rowCount {
			rowCount = end
		}
	}
	if idx := rowLayoutPostSignSigHatBase(layout); idx >= 0 && layout.SigBlocks > 0 && layout.SigUCount > 0 {
		if end := idx + layout.SigBlocks*layout.SigUCount; end > rowCount {
			rowCount = end
		}
	}
	if idx := rowLayoutPostSignCarrierM(layout); idx >= 0 && idx+1 > rowCount {
		rowCount = idx + 1
	}
	if idx := rowLayoutPostSignCarrierCtr(layout); idx >= 0 && idx+1 > rowCount {
		rowCount = idx + 1
	}
	for _, idx := range []int{rowLayoutPostSignMHat1(layout), rowLayoutPostSignMHat2(layout), rowLayoutPostSignRHat0(layout), rowLayoutPostSignRHat1(layout)} {
		if idx >= 0 && idx+1 > rowCount {
			rowCount = idx + 1
		}
	}
	if idx := rowLayoutPostSignTHatBase(layout); idx >= 0 && layout.SigBlocks > 0 {
		if end := idx + layout.SigBlocks; end > rowCount {
			rowCount = end
		}
	}
	if layout.PackedSigChainBase >= 0 && layout.PackedSigChainRowsPerGroup > 0 {
		if end := layout.PackedSigChainBase + layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup; end > rowCount {
			rowCount = end
		}
	}
	return rowCount
}

func buildCredentialRowsShowingCoeffNativeLiteralPacked(
	ringQ *ring.Ring,
	pub PublicInputs,
	wit WitnessInputs,
	prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds int,
	opts SimOpts,
) (rows []*ring.Poly, rowInputs []lvcs.RowInput, layout RowLayout, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols int, err error) {
	if ringQ == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	if opts.DomainMode != DomainModeExplicit {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed aggregated mode requires explicit domain mode")
	}
	if opts.NCols <= 0 {
		opts.NCols = int(ringQ.N)
	}
	ncols = opts.NCols
	if ncols <= 0 || ringQ.N%ncols != 0 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires ringN %% ncols == 0 (ringN=%d ncols=%d)", ringQ.N, ncols)
	}
	if wit.CoeffNativeShowing == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires WitnessInputs.CoeffNativeShowing")
	}
	model := resolveCoeffNativeSigModel(opts)
	if !coeffNativeSigModelUsesLiteralPacked(model) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("unsupported literal packed coeff-native model %q", model)
	}
	cn := wit.CoeffNativeShowing
	if err := cn.Validate(int(ringQ.N)); err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("invalid coeff-native witness: %w", err)
	}
	if len(pub.A) == 0 || len(pub.A[0]) == 0 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed showing requires non-empty A")
	}
	if len(cn.Sig) != len(pub.A[0]) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed signature witness rows=%d want %d", len(cn.Sig), len(pub.A[0]))
	}
	blocks := int(ringQ.N) / ncols
	var explicitOmega []uint64
	if opts.DomainMode == DomainModeExplicit {
		nLeaves := opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		derivedOmega, derr := deriveExplicitWitnessOmega(ringQ.Modulus[0], nLeaves, ncols, opts.LVCSNCols, opts.Ell)
		if derr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed explicit omega: %w", derr)
		}
		explicitOmega = derivedOmega
	}
	makeRowFromHead := func(head []uint64) *ring.Poly {
		if opts.DomainMode == DomainModeExplicit {
			pNTT := BuildThetaPrime(ringQ, head, explicitOmega)
			coeff := ringQ.NewPoly()
			ringQ.InvNTT(pNTT, coeff)
			return coeff
		}
		pNTT := ringQ.NewPoly()
		q := ringQ.Modulus[0]
		for i := 0; i < ncols && i < len(head); i++ {
			pNTT.Coeffs[0][i] = head[i] % q
		}
		out := ringQ.NewPoly()
		ringQ.InvNTT(pNTT, out)
		return out
	}
	packedWitness, err := buildLiteralPackedPolyWitness(ringQ, cn, explicitOmega, ncols, model, opts)
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("literal packed witness: %w", err)
	}
	packedSigBase, packedSigCount := -1, 0
	if model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("unsupported literal packed coeff-native model %q", model)
	}
	if cn.PackedNCols != ncols {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native packed ncols=%d want %d", cn.PackedNCols, ncols)
	}

	packedSigBase = len(rows)
	for block := 0; block < blocks; block++ {
		for comp := 0; comp < len(packedWitness.Sig); comp++ {
			coeff := ringQ.NewPoly()
			ringQ.InvNTT(packedWitness.Sig[comp][block], coeff)
			rows = append(rows, coeff)
		}
	}
	packedSigCount = blocks * len(cn.Sig)

	// Transform-domain signature alias rows Ŝ (one per block/component).
	sigHatBase := len(rows)
	sigEvalNTT := make([]*ring.Poly, len(cn.Sig))
	for comp := range cn.Sig {
		sigEvalNTT[comp] = ringQ.NewPoly()
		ring.Copy(cn.Sig[comp], sigEvalNTT[comp])
		ringQ.NTT(sigEvalNTT[comp], sigEvalNTT[comp])
	}
	sigHatHeads := make([][][]uint64, blocks)
	for block := 0; block < blocks; block++ {
		sigHatHeads[block] = make([][]uint64, len(cn.Sig))
		start := block * ncols
		end := start + ncols
		for comp := 0; comp < len(cn.Sig); comp++ {
			head := append([]uint64(nil), sigEvalNTT[comp].Coeffs[0][start:end]...)
			sigHatHeads[block][comp] = head
			rows = append(rows, makeRowFromHead(head))
		}
	}

	nttHead := func(src *ring.Poly) ([]uint64, error) {
		if src == nil {
			return nil, fmt.Errorf("nil NTT source row")
		}
		fullNTT := ringQ.NewPoly()
		ring.Copy(src, fullNTT)
		ringQ.NTT(fullNTT, fullNTT)
		if ncols > len(fullNTT.Coeffs[0]) {
			return nil, fmt.Errorf("NTT source row ncols=%d exceeds row width=%d", ncols, len(fullNTT.Coeffs[0]))
		}
		head0 := append([]uint64(nil), fullNTT.Coeffs[0][:ncols]...)
		return head0, nil
	}

	if pub.BoundB <= 0 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("transform-bridge showing requires positive BoundB")
	}
	q := ringQ.Modulus[0]
	var m1Head []uint64
	var berr error
	if opts.DomainMode == DomainModeExplicit {
		if len(cn.M1.Coeffs) == 0 || len(cn.M1.Coeffs[0]) < ncols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M1 head width=%d want >=%d", len(cn.M1.Coeffs[0]), ncols)
		}
		m1Head = append([]uint64(nil), cn.M1.Coeffs[0][:ncols]...)
		for i := range m1Head {
			m1Head[i] %= q
		}
	} else {
		m1Head, berr = nttHead(cn.M1)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M1 head: %w", berr)
	}
	var m2Head []uint64
	if opts.DomainMode == DomainModeExplicit {
		if len(cn.M2.Coeffs) == 0 || len(cn.M2.Coeffs[0]) < ncols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M2 head width=%d want >=%d", len(cn.M2.Coeffs[0]), ncols)
		}
		m2Head = append([]uint64(nil), cn.M2.Coeffs[0][:ncols]...)
		for i := range m2Head {
			m2Head[i] %= q
		}
	} else {
		m2Head, berr = nttHead(cn.M2)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M2 head: %w", berr)
	}
	var r0Head []uint64
	if opts.DomainMode == DomainModeExplicit {
		if len(cn.R0.Coeffs) == 0 || len(cn.R0.Coeffs[0]) < ncols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0 head width=%d want >=%d", len(cn.R0.Coeffs[0]), ncols)
		}
		r0Head = append([]uint64(nil), cn.R0.Coeffs[0][:ncols]...)
		for i := range r0Head {
			r0Head[i] %= q
		}
	} else {
		r0Head, berr = nttHead(cn.R0)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0 head: %w", berr)
	}
	var r1Head []uint64
	if opts.DomainMode == DomainModeExplicit {
		if len(cn.R1.Coeffs) == 0 || len(cn.R1.Coeffs[0]) < ncols {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R1 head width=%d want >=%d", len(cn.R1.Coeffs[0]), ncols)
		}
		r1Head = append([]uint64(nil), cn.R1.Coeffs[0][:ncols]...)
		for i := range r1Head {
			r1Head[i] %= q
		}
	} else {
		r1Head, berr = nttHead(cn.R1)
	}
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R1 head: %w", berr)
	}
	carrierMHead := make([]uint64, ncols)
	carrierCtrHead := make([]uint64, ncols)
	for col := 0; col < ncols; col++ {
		m1 := centeredLift(m1Head[col], q)
		m2 := centeredLift(m2Head[col], q)
		code, err := encodeCarrierPair(m1, m2, pub.BoundB)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("encode carrier M col=%d: %w", col, err)
		}
		carrierMHead[col] = liftToField(q, int64(code))
		r0 := centeredLift(r0Head[col], q)
		r1 := centeredLift(r1Head[col], q)
		code, err = encodeCarrierPair(r0, r1, pub.BoundB)
		if err != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("encode carrier ctr col=%d: %w", col, err)
		}
		carrierCtrHead[col] = liftToField(q, int64(code))
	}
	idxCarrierM := len(rows)
	rows = append(rows, makeRowFromHead(carrierMHead))
	idxCarrierCtr := len(rows)
	rows = append(rows, makeRowFromHead(carrierCtrHead))

	idxMHat1 := len(rows)
	m1HatHead, berr := nttHead(cn.M1)
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M1 hat: %w", berr)
	}
	rows = append(rows, makeRowFromHead(m1HatHead))
	idxMHat2 := len(rows)
	m2HatHead, berr := nttHead(cn.M2)
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native M2 hat: %w", berr)
	}
	rows = append(rows, makeRowFromHead(m2HatHead))
	idxRHat0 := len(rows)
	r0HatHead, berr := nttHead(cn.R0)
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R0 hat: %w", berr)
	}
	rows = append(rows, makeRowFromHead(r0HatHead))
	idxRHat1 := len(rows)
	r1HatHead, berr := nttHead(cn.R1)
	if berr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("coeff-native R1 hat: %w", berr)
	}
	rows = append(rows, makeRowFromHead(r1HatHead))

	idxTHatBase := len(rows)
	if opts.DomainMode == DomainModeExplicit {
		if len(pub.A) == 0 || len(pub.A[0]) == 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("explicit T-hat requires non-empty A")
		}
		if len(pub.A) != 1 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("explicit T-hat expects single-row A, got %d", len(pub.A))
		}
		if sigHatHeads == nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("explicit T-hat requires sig hat heads")
		}
		q := ringQ.Modulus[0]
		for block := 0; block < blocks; block++ {
			tHead := make([]uint64, ncols)
			for comp := 0; comp < len(cn.Sig); comp++ {
				aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], explicitOmega, block, blocks)
				if err != nil {
					return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("theta A head block %d comp %d: %w", block, comp, err)
				}
				for k := 0; k < ncols; k++ {
					tHead[k] = modAdd(tHead[k], modMul(aHead[k]%q, sigHatHeads[block][comp][k]%q, q), q)
				}
			}
			rows = append(rows, makeRowFromHead(tHead))
		}
	} else {
		tNTT := ringQ.NewPoly()
		ring.Copy(cn.T, tNTT)
		ringQ.NTT(tNTT, tNTT)
		for block := 0; block < blocks; block++ {
			start := block * ncols
			end := start + ncols
			head := append([]uint64(nil), tNTT.Coeffs[0][start:end]...)
			rows = append(rows, makeRowFromHead(head))
		}
	}

	packedSigChainBase := -1
	packedSigChainGroupCount := 0
	packedSigChainGroupSize := 0
	packedSigChainRowsPerGroup := 0
	sigSignedChain := false
	spec, serr := signatureChainSpecForOpts(ringQ.Modulus[0], opts)
	if serr != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature chain spec: %w", serr)
	}
	if !signatureSpecNoWrapOK(spec) {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("signature chain spec violates no-wrap bound: maxAbs=%d q=%d", spec.MaxAbs, spec.Q)
	}
	packedSigChainBase = len(rows)
	for block := 0; block < blocks; block++ {
		for comp := 0; comp < len(packedWitness.SigLimbs); comp++ {
			for lane := 0; lane < len(packedWitness.SigLimbs[comp][block]); lane++ {
				coeff := ringQ.NewPoly()
				ringQ.InvNTT(packedWitness.SigLimbs[comp][block][lane], coeff)
				rows = append(rows, coeff)
			}
		}
	}
	packedSigChainGroupCount = len(cn.Sig) * blocks
	packedSigChainGroupSize = ncols
	packedSigChainRowsPerGroup = spec.L
	sigSignedChain = true

	if prfGroupRounds <= 0 {
		prfGroupRounds = 1
	}
	var keyScalars []int64
	if opts.DomainMode == DomainModeExplicit {
		if len(explicitOmega) == 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("explicit omega missing for carrier key extraction")
		}
		keyScalars, err = ExtractSignedPRFKeyScalarsFromCarrierOnOmega(ringQ, rows[idxCarrierM], explicitOmega, cn.PackedNCols, prfParamsLenKey, pub.BoundB)
	} else {
		keyScalars, err = ExtractSignedPRFKeyScalarsFromCarrier(ringQ, rows[idxCarrierM], cn.PackedNCols, prfParamsLenKey, pub.BoundB)
	}
	if err != nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("extract signed prf key: %w", err)
	}
	startIdx = len(rows)
	companionMode := normalizePRFCompanionMode(opts.PRFCompanionMode)
	if companionMode == "" {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("showing requires PRF companion mode")
	}

	layout.HasExplicitBaseIdx = true
	layout.IdxM1 = -1
	layout.IdxM2 = -1
	layout.IdxRU0 = -1
	layout.IdxRU1 = -1
	layout.IdxR = -1
	layout.IdxR0 = -1
	layout.IdxR1 = -1
	layout.IdxK0 = -1
	layout.IdxK1 = -1
	layout.IdxCarrierM = idxCarrierM
	layout.IdxCarrierCtr = idxCarrierCtr
	layout.IdxSigHatBase = sigHatBase
	layout.SigHatExtraBase = -1
	if blocks > 1 {
		layout.SigHatExtraBase = sigHatBase + len(cn.Sig)
	}
	layout.IdxTHatBase = idxTHatBase
	layout.IdxMHat1 = idxMHat1
	layout.IdxMHat2 = idxMHat2
	layout.IdxRHat0 = idxRHat0
	layout.IdxRHat1 = idxRHat1
	layout.SigBlocks = blocks
	layout.SigUCount = len(cn.Sig)
	layout.SigCoeffBase = -1
	layout.ChainBase = -1
	layout.ChainRowsPerSig = 0
	layout.PackedSigChainBase = packedSigChainBase
	layout.PackedSigChainGroupCount = packedSigChainGroupCount
	layout.PackedSigChainGroupSize = packedSigChainGroupSize
	layout.PackedSigChainRowsPerGroup = packedSigChainRowsPerGroup
	layout.SigSignedChain = sigSignedChain
	layout.MsgChainBase = -1
	layout.RndChainBase = -1
	layout.MsgRangeBase = -1
	layout.RndRangeBase = -1
	layout.X1RangeBase = -1
	layout.NonSigBoundRowsPer = 0
	layout.SigPrimaryLimbRows = packedSigChainGroupCount * packedSigChainRowsPerGroup
	layout.ScalarBundleRows = 0
	layout.SigBoundSliceRows = layout.SigPrimaryLimbRows
	layout.PostSignScalarProjectionRows = 0
	layout.PostSignScalarCertificateRows = 0
	layout.PRFScalarBundleRows = len(rows) - startIdx
	layout.PRFGroupedNonlinearRows = 0
	layout.SigCount = len(rows)
	layout.NonSigBlocks = blocks
	layout.MsgCompCount = 0
	layout.MsgExtraNTTBase = -1
	layout.MsgCoeffBase = -1
	layout.RndCompCount = 0
	layout.RndExtraNTTBase = -1
	layout.RndCoeffBase = -1
	layout.X1CompCount = 0
	layout.X1ExtraNTTBase = -1
	layout.X1CoeffBase = -1
	layout.CoeffNativeSig = CoeffNativeSigLayout{
		Enabled:             true,
		Model:               model,
		SigBase:             packedSigBase,
		SigCount:            packedSigCount,
		SigBlocks:           blocks,
		SigUCount:           len(cn.Sig),
		SigComponentCount:   len(cn.Sig),
		SigCoeffCount:       int(ringQ.N),
		OutputBlocks:        blocks,
		OutputBlockWidth:    ncols,
		W1SigBase:           packedSigBase,
		W1SigCount:          packedSigCount,
		PackedSigBase:       packedSigBase,
		PackedSigCount:      packedSigCount,
		PackedSigBlocks:     blocks,
		PackedSigComponents: len(cn.Sig),
		PackedSigBlockWidth: ncols,
		ScalarBundleBase:    -1,
		ScalarBundleCount:   0,
	}
	if companionMode != "" {
		companionStart := len(rows)
		keyElems := make([]prf.Elem, len(keyScalars))
		for i := range keyScalars {
			keyElems[i] = prf.Elem(liftToField(ringQ.Modulus[0], keyScalars[i]))
		}
		nonceElems := make([]prf.Elem, len(pub.Nonce))
		for i := range pub.Nonce {
			if len(pub.Nonce[i]) == 0 {
				return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("public nonce lane %d is empty", i)
			}
			nonceElems[i] = prf.Elem(liftToField(ringQ.Modulus[0], pub.Nonce[i][0]))
		}
		params, perr := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("load prf params for companion witness: %w", perr)
		}
		groupedWitness, gwerr := prf.TraceGroupedWitness(keyElems, nonceElems, params, prfGroupRounds)
		if gwerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("trace grouped prf witness: %w", gwerr)
		}
		packed, perr := packPRFCompanionWitnessRows(ringQ, ncols, companionStart, companionMode, keyElems, groupedWitness, makeRowFromHead)
		if perr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("pack prf companion rows: %w", perr)
		}
		rows = append(rows, packed.Rows...)
		if len(packed.KeySlots) == 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("prf companion missing key slots for independent-key showing")
		}
		rowSemantics := make([]RowSemantics, len(packed.Rows))
		for i := range rowSemantics {
			rowSemantics[i] = CoeffPackedRow
		}
		dataRows := ceilDiv(len(packed.KeySlots)+len(packed.CheckpointSlots), ncols)
		helperRows := maxInt(len(packed.Rows)-dataRows, 0)
		helperFamilies := []string{"final_tag_state"}
		prfCompanionLayout = &PRFCompanionLayout{
			StartRow:           companionStart,
			PackWidth:          ncols,
			KeySource:          KeySourceIndependentWitness,
			KeySlots:           packed.KeySlots,
			CheckpointSlots:    packed.CheckpointSlots,
			FinalTagSlots:      packed.FinalTagSlots,
			HelperFamilies:     helperFamilies,
			PackedRows:         len(packed.Rows),
			PackedLogicalCount: packed.TotalLogicalScalars,
			HelperRowCount:     helperRows,
			DataRows:           dataRows,
			HelperRows:         helperRows,
			KeyCount:           len(packed.KeySlots),
			CheckpointCount:    len(packed.CheckpointSlots),
			TagCount:           len(pub.Tag),
			RowSemantics:       rowSemantics,
		}
	}
	layout.PRFScalarBundleRows = len(rows) - startIdx
	layout.SigCount = len(rows)

	witnessCount = len(rows)
	if opts.DomainMode == DomainModeExplicit {
		if len(explicitOmega) == 0 {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("explicit omega missing for row inputs")
		}
		var rerr error
		rowInputs, rerr = buildRowInputsExplicit(ringQ, rows, explicitOmega, ncols)
		if rerr != nil {
			return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, rerr
		}
	} else {
		rowInputs = buildRowInputs(ringQ, rows, ncols)
	}
	maskRowOffset = len(rows)
	maskRowCount = opts.Rho
	if maskRowCount > 0 {
		zeroHead := make([]uint64, ncols)
		for i := 0; i < maskRowCount; i++ {
			rows = append(rows, ringQ.NewPoly())
			rowInputs = append(rowInputs, lvcs.RowInput{Head: zeroHead})
		}
	}
	maxDegree := opts.DQOverride
	if maxDegree <= 0 {
		maxDegree = ncols + opts.Ell - 1
	}
	decsParams = decs.Params{Degree: maxDegree, Eta: opts.Eta, NonceBytes: 16}
	return rows, rowInputs, layout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols, nil
}

func buildCredentialConstraintSetPostCoeffNativeLiteralPacked(ringQ *ring.Ring, bound int64, pub PublicInputs, layout RowLayout, rowsNTT []*ring.Poly, omega []uint64, domainMode DomainMode, opts SimOpts, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout) (ConstraintSet, error) {
	opts.applyDefaults()
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return ConstraintSet{}, fmt.Errorf("literal packed coeff-native compiler requires literal packed layout")
	}
	if domainMode != DomainModeExplicit {
		return ConstraintSet{}, fmt.Errorf("literal packed aggregated mode requires explicit domain mode")
	}
	var baseSet ConstraintSet
	if rowLayoutCoeffNativeUsesTransformBridge(layout) {
		var err error
		baseSet, err = buildCredentialConstraintSetPostCoeffNativeTransformBridge(ringQ, bound, pub, layout, rowsNTT, omega, domainMode, opts, prfLayout, prfCompanionLayout)
		if err != nil {
			return ConstraintSet{}, err
		}
	} else {
		return ConstraintSet{}, fmt.Errorf("literal packed coeff-native showing requires transform-bridge layout")
	}
	q := ringQ.Modulus[0]
	if cfg.Model != CoeffNativeSigModelLiteralPackedAggregatedV3 {
		return ConstraintSet{}, fmt.Errorf("unsupported literal packed coeff-native model %q", cfg.Model)
	}
	if layout.PackedSigChainBase >= 0 && layout.PackedSigChainRowsPerGroup > 0 {
		specSig, serr := signatureChainSpecForLayoutAndOpts(q, layout, opts)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("signature chain spec: %w", serr)
		}
		wantRowsPer, serr := signaturePackedChainRowsPerGroupForOpts(specSig, opts, layout.PackedSigChainGroupSize)
		if serr != nil {
			return ConstraintSet{}, fmt.Errorf("signature shortness rows-per-group: %w", serr)
		}
		if layout.PackedSigChainRowsPerGroup != wantRowsPer {
			return ConstraintSet{}, fmt.Errorf("signature shortness rows/group=%d want %d", layout.PackedSigChainRowsPerGroup, wantRowsPer)
		}
		wantGroupCount := cfg.PackedSigComponents * cfg.PackedSigBlocks
		if layout.PackedSigChainGroupCount != wantGroupCount {
			return ConstraintSet{}, fmt.Errorf("signature shortness group count=%d want %d", layout.PackedSigChainGroupCount, wantGroupCount)
		}
		if cfg.PackedSigBase+cfg.PackedSigCount > len(rowsNTT) {
			return ConstraintSet{}, fmt.Errorf("packed signature source rows [%d,%d) out of range (rows=%d)", cfg.PackedSigBase, cfg.PackedSigBase+cfg.PackedSigCount, len(rowsNTT))
		}
		if layout.PackedSigChainBase+layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup > len(rowsNTT) {
			return ConstraintSet{}, fmt.Errorf("signature shortness rows [%d,%d) out of range (rows=%d)", layout.PackedSigChainBase, layout.PackedSigChainBase+layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup, len(rowsNTT))
		}
		packedSourceRows := make([]*ring.Poly, layout.PackedSigChainGroupCount)
		for g := 0; g < layout.PackedSigChainGroupCount; g++ {
			packedSourceRows[g] = rowsNTT[cfg.PackedSigBase+g]
		}
		packedRows := make([][]*ring.Poly, layout.PackedSigChainGroupCount)
		for g := 0; g < layout.PackedSigChainGroupCount; g++ {
			packedRows[g] = make([]*ring.Poly, layout.PackedSigChainRowsPerGroup)
			for i := 0; i < layout.PackedSigChainRowsPerGroup; i++ {
				packedRows[g][i] = rowsNTT[layout.PackedSigChainBase+g*layout.PackedSigChainRowsPerGroup+i]
			}
		}
		chainPolys, chainCoeffs, err := buildSigShortnessPackedMembershipFormalCoeffs(ringQ, packedSourceRows, packedRows, specSig)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("literal packed signature shortness: %w", err)
		}
		baseSet.FparNorm = append(baseSet.FparNorm, chainPolys...)
		baseSet.FparNormCoeffs = append(baseSet.FparNormCoeffs, chainCoeffs...)
		deg, derr := signatureShortnessMaxDegree(specSig, opts)
		if derr != nil {
			return ConstraintSet{}, fmt.Errorf("signature shortness degree: %w", derr)
		}
		if deg > baseSet.ParallelAlgDeg {
			baseSet.ParallelAlgDeg = deg
		}
	}
	return baseSet, nil
}
