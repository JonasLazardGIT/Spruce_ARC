package PIOP

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/internal/fpoly"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	sigShortnessProofVersionV18 = 18

	sigShortnessV18ModeReplayCompact uint8 = 1
)

func appendSigShortnessUvarint(dst []byte, v int) []byte {
	if v < 0 {
		v = 0
	}
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(v))
	return append(dst, buf[:n]...)
}

func resolveRowLayoutRingDegree(layout RowLayout) int {
	if layout.RingDegree > 0 {
		return layout.RingDegree
	}
	if layout.CoeffNativeSig.SigCoeffCount > 0 {
		return layout.CoeffNativeSig.SigCoeffCount
	}
	if layout.CoeffNativeSig.PackedSigBlocks > 0 && layout.CoeffNativeSig.PackedSigBlockWidth > 0 {
		return layout.CoeffNativeSig.PackedSigBlocks * layout.CoeffNativeSig.PackedSigBlockWidth
	}
	if layout.SigBlocks > 0 && layout.CoeffNativeSig.PackedSigBlockWidth > 0 {
		return layout.SigBlocks * layout.CoeffNativeSig.PackedSigBlockWidth
	}
	return 0
}

func buildSigShortnessV18LayoutDigest(layout RowLayout) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, []byte("spruce.sig_shortness.v18/replay_compact_inline_layout_v1")...)
	appendInt := func(v int) {
		buf = appendSigShortnessUvarint(buf, v)
	}
	appendInt(resolveRowLayoutRingDegree(layout))
	appendInt(rowLayoutX0Len(layout))
	appendInt(layout.CoeffNativeSig.PackedSigComponents)
	appendInt(layout.CoeffNativeSig.PackedSigBlocks)
	appendInt(layout.CoeffNativeSig.PackedSigBlockWidth)
	appendInt(layout.PackedSigChainBase)
	appendInt(layout.PackedSigChainGroupCount)
	appendInt(layout.PackedSigChainGroupSize)
	appendInt(layout.PackedSigChainRowsPerGroup)
	appendInt(layout.PackedSigChainBlockWidth)
	appendInt(layout.PackedSigChainEffectiveBlocks)
	appendInt(layout.PackedSigChainSourceBlockWidth)
	appendInt(rowLayoutReplayBlockCount(layout))
	appendInt(rowLayoutPostSignM1(layout))
	appendInt(rowLayoutPostSignM2(layout))
	for _, row := range rowLayoutPostSignR0Rows(layout) {
		appendInt(row)
	}
	appendInt(rowLayoutPostSignCarrierM(layout))
	for _, row := range rowLayoutPostSignCarrierR0Rows(layout) {
		appendInt(row)
	}
	appendInt(rowLayoutPostSignCarrierR1(layout))
	for _, row := range rowLayoutPostSignRHat1Rows(layout) {
		appendInt(row)
	}
	for _, row := range rowLayoutPostSignZHatRows(layout) {
		appendInt(row)
	}
	buf = append(buf, buildSigShortnessV18ReplayCompactDigest(layout)...)
	buf = append(buf, buildSigShortnessV18PRFCompactDigest()...)
	sum := sha256.Sum256(buf)
	return append([]byte(nil), sum[:]...)
}

func buildSigShortnessV18ReplayCompactDigest(layout RowLayout) []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, []byte("spruce.sig_shortness.v18/replay_compact_schedule_v1")...)
	appendInt := func(v int) {
		buf = appendSigShortnessUvarint(buf, v)
	}
	appendInt(rowLayoutPostSignCarrierM(layout))
	for _, row := range rowLayoutPostSignCarrierR0Rows(layout) {
		appendInt(row)
	}
	appendInt(rowLayoutPostSignCarrierR1(layout))
	appendInt(rowLayoutReplayBlockCount(layout))
	appendInt(rowLayoutPostSignRHat1(layout))
	appendInt(rowLayoutPostSignZHat(layout))
	sum := sha256.Sum256(buf)
	return append([]byte(nil), sum[:]...)
}

func buildSigShortnessV18PRFCompactDigest() []byte {
	sum := sha256.Sum256([]byte("spruce.sig_shortness.v18/dense_prf_companion_key_packing_v1"))
	return append([]byte(nil), sum[:]...)
}

func buildSigShortnessV18BindingDigest(sig *SigShortnessProof, layout RowLayout, witnessNCols int) ([]byte, error) {
	if sig == nil || sig.Version != sigShortnessProofVersionV18 || sig.V18 == nil {
		return nil, nil
	}
	_ = witnessNCols
	if len(sig.SupportSlots) != 0 || sig.Opening != nil {
		return nil, fmt.Errorf("sig shortness V18 must not populate legacy or other version payload fields")
	}
	v18 := sig.V18
	ringDegree := resolveRowLayoutRingDegree(layout)
	if ringDegree <= 0 {
		return nil, fmt.Errorf("missing ring degree for sig shortness V18 binding")
	}
	if v18.RingDegree != ringDegree {
		return nil, fmt.Errorf("sig shortness V18 ring_degree=%d want %d", v18.RingDegree, ringDegree)
	}
	layoutDigest := buildSigShortnessV18LayoutDigest(layout)
	if !bytes.Equal(v18.LayoutDigest, layoutDigest) {
		return nil, fmt.Errorf("sig shortness V18 layout digest mismatch")
	}
	replayDigest := buildSigShortnessV18ReplayCompactDigest(layout)
	if len(v18.ReplayCompactDigest) > 0 && !bytes.Equal(v18.ReplayCompactDigest, replayDigest) {
		return nil, fmt.Errorf("sig shortness V18 replay compact digest mismatch")
	}
	prfDigest := buildSigShortnessV18PRFCompactDigest()
	if len(v18.PRFCompactDigest) > 0 && !bytes.Equal(v18.PRFCompactDigest, prfDigest) {
		return nil, fmt.Errorf("sig shortness V18 PRF compact digest mismatch")
	}
	buf := make([]byte, 0, 224)
	buf = append(buf, []byte("spruce.sig_shortness.v18/replay_compact_inline_target_v1")...)
	buf = appendSigShortnessUvarint(buf, int(v18.Mode))
	buf = appendSigShortnessUvarint(buf, v18.RingDegree)
	buf = appendSigShortnessUvarint(buf, v18.Radix)
	buf = appendSigShortnessUvarint(buf, v18.Digits)
	buf = appendSigShortnessUvarint(buf, v18.GroupSize)
	buf = appendSigShortnessUvarint(buf, v18.BlockWidth)
	buf = append(buf, v18.LayoutDigest...)
	sum := sha256.Sum256(buf)
	return append([]byte(nil), sum[:]...), nil
}

func buildSigShortnessBindingDigest(sig *SigShortnessProof, layout RowLayout, witnessNCols int) ([]byte, error) {
	if sig == nil {
		return nil, nil
	}
	switch sig.Version {
	case sigShortnessProofVersionV18:
		return buildSigShortnessV18BindingDigest(sig, layout, witnessNCols)
	default:
		return nil, fmt.Errorf("unsupported sig shortness version %d", sig.Version)
	}
}

func deriveMainPCSSubsetParams(proof *Proof) (decs.Params, int, error) {
	if proof == nil {
		return decs.Params{}, 0, fmt.Errorf("nil proof")
	}
	pcsOpening := resolveProofPCSOpening(proof)
	if pcsOpening == nil {
		return decs.Params{}, 0, fmt.Errorf("missing PCS opening")
	}
	rowDegBound := proof.RowDegreeBound
	if rowDegBound <= 0 {
		rowDegBound = proof.MaskDegreeBound
	}
	if rowDegBound <= 0 {
		return decs.Params{}, 0, fmt.Errorf("missing row degree bound")
	}
	nonceBytes := 16
	if pcsOpening.NonceBytes > 0 {
		nonceBytes = pcsOpening.NonceBytes
	} else if len(pcsOpening.Nonces) > 0 && len(pcsOpening.Nonces[0]) > 0 {
		nonceBytes = len(pcsOpening.Nonces[0])
	}
	if pcsOpening.Eta <= 0 {
		return decs.Params{}, 0, fmt.Errorf("missing PCS eta")
	}
	if pcsOpening.R <= 0 {
		return decs.Params{}, 0, fmt.Errorf("missing PCS row count")
	}
	return decs.Params{
		Degree:     rowDegBound,
		Eta:        pcsOpening.Eta,
		NonceBytes: nonceBytes,
	}, pcsOpening.R, nil
}

func deriveMainPCSSubsetGamma(proof *Proof, rowCount int, q uint64) ([][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if rowCount <= 0 {
		return nil, fmt.Errorf("invalid row count %d", rowCount)
	}
	lambda := proof.Lambda
	if lambda <= 0 {
		lambda = 256
	}
	fs := NewFS(NewShake256XOF(fsDigestBytes), proof.Salt, FSParams{Lambda: lambda, Kappa: proof.Kappa, TranscriptVersion: proof.TranscriptVersion})
	material0 := [][]byte{append([]byte(nil), proof.Root[:]...)}
	if len(proof.LabelsDigest) > 0 {
		material0 = append(material0, proof.LabelsDigest)
	}
	if digest, err := buildSigShortnessBindingDigest(proof.SigShortness, proof.RowLayout, proof.NColsUsed); err != nil {
		return nil, err
	} else if len(digest) > 0 {
		material0 = append(material0, digest)
	}
	seed, err := verifyRoundDigest(fs, 0, proof.Ctr[0], material0, proof.Digests[0], proof.Kappa[0])
	if err != nil {
		return nil, fmt.Errorf("main FS round 0: %w", err)
	}
	pcsOpening := resolveProofPCSOpening(proof)
	return sampleFSMatrix(pcsOpening.Eta, rowCount, q, newFSRNG("Gamma", seed)), nil
}

func buildSigShortnessProofV18Metadata(
	ringQ *ring.Ring,
	layout RowLayout,
	opts SimOpts,
) (*SigShortnessProof, error) {
	if !sigShortnessInlinedTargetHidingEnabledForOpts(opts) {
		return nil, nil
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return nil, fmt.Errorf("sig shortness V18 requires literal packed v3 layout")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], layout, opts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	if sigShortnessV18EnabledForOpts(opts) {
		return &SigShortnessProof{
			Version: sigShortnessProofVersionV18,
			V18: &SigShortnessProofV18{
				Mode:         sigShortnessV18ModeReplayCompact,
				RingDegree:   int(ringQ.N),
				Radix:        int(spec.R),
				Digits:       spec.L,
				GroupSize:    layout.PackedSigChainGroupSize,
				BlockWidth:   layout.CoeffNativeSig.PackedSigBlockWidth,
				LayoutDigest: buildSigShortnessV18LayoutDigest(layout),
			},
		}, nil
	}
	return nil, fmt.Errorf("inline-target replay-compact shortness is not enabled")
}

func buildSigShortnessDirectTargetFormalCoeffs(
	ringQ *ring.Ring,
	layout RowLayout,
	pub PublicInputs,
	omegaWitness []uint64,
	rowsNTT []*ring.Poly,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return nil, nil, fmt.Errorf("sig shortness direct target expects one public A row")
	}
	if !publicUsesBBTran(pub) {
		return nil, nil, fmt.Errorf("sig shortness direct target requires bb_tran relation")
	}
	if len(pub.B) < 4 {
		return nil, nil, fmt.Errorf("sig shortness direct target requires B rows")
	}
	cfg := layout.CoeffNativeSig
	replayBlockCount := rowLayoutReplayBlockCount(layout)
	sourceBlocks := cfg.PackedSigBlocks
	if sourceBlocks <= 0 {
		return nil, nil, fmt.Errorf("invalid source blocks=%d", sourceBlocks)
	}
	if replayBlockCount <= 0 {
		return nil, nil, fmt.Errorf("invalid replay blocks=%d", replayBlockCount)
	}
	ncols := len(omegaWitness)
	if ncols <= 0 {
		return nil, nil, fmt.Errorf("empty witness omega")
	}
	bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omegaWitness, replayBlockCount*ncols, sourceBlocks)
	if err != nil {
		return nil, nil, fmt.Errorf("sig shortness direct-target transform bridge basis: %w", err)
	}
	var inlineTargetBridgeBasis *transformBridgeBasisCache
	if rowLayoutPostSignTargetMR0HatIndex(layout, 0) < 0 {
		inlineTargetBridgeBasis, err = newRowTransformBridgeBasisCache(ringQ, omegaWitness, replayBlockCount*ncols)
		if err != nil {
			return nil, nil, fmt.Errorf("sig shortness inline target bridge basis: %w", err)
		}
	}
	var fullMuInlineBridgeBasis *transformBridgeBasisCache
	q := ringQ.Modulus[0]
	getRowCoeff := func(idx int) ([]uint64, error) {
		if idx < 0 || idx >= len(rowsNTT) {
			return nil, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		coeff, err := coeffFromNTTPoly(ringQ, rowsNTT[idx])
		if err != nil {
			return nil, err
		}
		return trimPoly(coeff, q), nil
	}
	inlineTarget := rowLayoutPostSignTargetMR0HatIndex(layout, 0) < 0
	var mSigmaCompCoeffs []uint64
	var fullMuSourceCoeffs [][]uint64
	var r0CompCoeffs [][]uint64
	highDegreePackedMu := false
	if inlineTarget {
		x0Len := pub.X0Len
		if x0Len <= 0 {
			x0Len = rowLayoutX0Len(layout)
		}
		if x0Len <= 0 {
			return nil, nil, fmt.Errorf("sig shortness inline target invalid x0 length=%d", x0Len)
		}
		carrierMIdx := rowLayoutPostSignCarrierM(layout)
		carrierR0Idxs := rowLayoutPostSignCarrierR0Rows(layout)
		if carrierMIdx < 0 || len(carrierR0Idxs) != x0Len {
			return nil, nil, fmt.Errorf("sig shortness inline target missing carrier rows (M=%d R0=%d want %d)", carrierMIdx, len(carrierR0Idxs), x0Len)
		}
		carrierMCoeff, err := getRowCoeff(carrierMIdx)
		if err != nil {
			return nil, nil, fmt.Errorf("inline target carrier M coeffs: %w", err)
		}
		muMode := rowLayoutUsesMu(layout)
		fullMuMode := rowLayoutUsesFullMu(layout)
		packedMuMode := rowLayoutUsesPackedMuCarrier(layout)
		muPackWidth := rowLayoutMuCarrierPackWidth(layout)
		muVirtualBlocks := rowLayoutMuVirtualBlockCount(layout)
		highDegreePackedMu = packedMuMode && muPackWidth > 2
		var msgDecode1, msgDecode2 []uint64
		var muDecodePolys [][]uint64
		if muMode {
			muDecodePolys, _, err = buildMuCarrierDecodePolys(pub.BoundB, muPackWidth, q)
			if err != nil {
				return nil, nil, fmt.Errorf("inline target mu carrier decode poly: %w", err)
			}
			msgDecode1 = muDecodePolys[0]
			msgDecode2 = []uint64{0}
		} else {
			msgDecode1, msgDecode2, err = buildPackedMessageCarrierDecodePolys(pub.BoundB, q)
			if err != nil {
				return nil, nil, fmt.Errorf("inline target message carrier decode polys: %w", err)
			}
		}
		x0Decode1, err := buildSingletonCarrierDecodePoly(pub.X0CoeffBound, q)
		if err != nil {
			return nil, nil, fmt.Errorf("inline target x0 carrier decode polys: %w", err)
		}
		composeOnOmega := func(carrierCoeff []uint64, decodeCoeff []uint64) []uint64 {
			head := make([]uint64, ncols)
			for i, w := range omegaWitness {
				code := EvalPoly(carrierCoeff, w%q, q) % q
				head[i] = EvalPoly(decodeCoeff, code, q) % q
			}
			return trimPoly(Interpolate(omegaWitness, head, q), q)
		}
		composeFormal := func(carrierCoeff []uint64, decodeCoeff []uint64) []uint64 {
			out := trimPoly(fpoly.New(q, decodeCoeff).Compose(fpoly.New(q, carrierCoeff)).Coeffs, q)
			if muPackWidth > 2 {
				return out
			}
			return reducePolyModXN1(out, int(ringQ.N), q)
		}
		m1CompCoeffs := composeOnOmega(carrierMCoeff, msgDecode1)
		m2CompCoeffs := composeOnOmega(carrierMCoeff, msgDecode2)
		mSigmaCompCoeffs = m1CompCoeffs
		if !muMode {
			mSigmaCompCoeffs = polyAdd(m1CompCoeffs, m2CompCoeffs, q)
		} else if fullMuMode {
			if packedMuMode {
				carrierMuIdxs := rowLayoutCarrierMuBlockRows(layout)
				carrierMuCoeffs := make([][]uint64, len(carrierMuIdxs))
				for i, row := range carrierMuIdxs {
					carrierMuCoeffs[i], err = getRowCoeff(row)
					if err != nil {
						return nil, nil, fmt.Errorf("inline target carrier Mu[%d] coeffs: %w", i, err)
					}
				}
				fullMuSourceCoeffs = make([][]uint64, muVirtualBlocks)
				for block := 0; block < muVirtualBlocks; block++ {
					carrierBlock := block / muPackWidth
					lane := block % muPackWidth
					if carrierBlock < 0 || carrierBlock >= len(carrierMuCoeffs) || lane >= len(muDecodePolys) {
						return nil, nil, fmt.Errorf("inline target mu virtual block=%d maps outside carrier rows=%d lanes=%d", block, len(carrierMuCoeffs), len(muDecodePolys))
					}
					fullMuSourceCoeffs[block] = composeFormal(carrierMuCoeffs[carrierBlock], muDecodePolys[lane])
				}
			} else {
				aliasMuIdxs := rowLayoutAliasMuBlockRows(layout)
				if len(aliasMuIdxs) == 0 {
					return nil, nil, fmt.Errorf("full mu inline target missing alias mu block rows")
				}
				fullMuSourceCoeffs = make([][]uint64, len(aliasMuIdxs))
				for i, row := range aliasMuIdxs {
					fullMuSourceCoeffs[i], err = getRowCoeff(row)
					if err != nil {
						return nil, nil, fmt.Errorf("inline target alias Mu[%d] coeffs: %w", i, err)
					}
				}
			}
			fullMuInlineBridgeBasis, err = newTransformBridgeBasisCache(ringQ, omegaWitness, replayBlockCount*ncols, len(fullMuSourceCoeffs))
			if err != nil {
				return nil, nil, fmt.Errorf("full mu inline target bridge basis: %w", err)
			}
		}
		r0CompCoeffs = make([][]uint64, x0Len)
		for i, row := range carrierR0Idxs {
			coeff, err := getRowCoeff(row)
			if err != nil {
				return nil, nil, fmt.Errorf("inline target carrier R0[%d] coeffs: %w", i, err)
			}
			r0CompCoeffs[i] = composeOnOmega(coeff, x0Decode1)
		}
	}
	targetMR0Coeffs := make([][]uint64, replayBlockCount)
	zHatCoeffs := make([][]uint64, replayBlockCount)
	thetaB0Coeffs := make([][]uint64, replayBlockCount)
	thetaBHeads := make([][][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
		if !inlineTarget {
			targetCoeff, err := getRowCoeff(rowLayoutPostSignTargetMR0HatIndex(layout, block))
			if err != nil {
				return nil, nil, fmt.Errorf("target-MR0 coeffs block %d: %w", block, err)
			}
			targetMR0Coeffs[block] = targetCoeff
		}
		zCoeff, err := getRowCoeff(rowLayoutPostSignZHatIndex(layout, block))
		if err != nil {
			return nil, nil, fmt.Errorf("z-hat coeffs block %d: %w", block, err)
		}
		thetaB0, err := thetaPolyFromNTTBlock(ringQ, pub.B[0], omegaWitness, block, sourceBlocks)
		if err != nil {
			return nil, nil, fmt.Errorf("theta B0 block %d: %w", block, err)
		}
		b0Coeff, err := coeffFromNTTPoly(ringQ, thetaB0)
		if err != nil {
			return nil, nil, fmt.Errorf("theta B0 coeffs block %d: %w", block, err)
		}
		zHatCoeffs[block] = zCoeff
		thetaB0Coeffs[block] = trimPoly(b0Coeff, q)
		if inlineTarget {
			thetaBHeads[block] = make([][]uint64, len(pub.B))
			for i := range pub.B {
				head, err := thetaHeadFromNTTBlock(ringQ, pub.B[i], omegaWitness, block, sourceBlocks)
				if err != nil {
					return nil, nil, fmt.Errorf("inline target theta B[%d] block %d: %w", i, block, err)
				}
				thetaBHeads[block][i] = head
			}
		}
	}
	digitCoeffs := make(map[[3]int][]uint64, cfg.PackedSigBlocks*cfg.PackedSigComponents*spec.L)
	for block := 0; block < cfg.PackedSigBlocks; block++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			for lane := 0; lane < spec.L; lane++ {
				var coeff []uint64
				if layout.PairLookupExtractRowsPerLane > 0 {
					groupSize := layout.PackedSigChainGroupSize
					if groupSize <= 0 {
						return nil, nil, fmt.Errorf("invalid pair-lookup group size=%d", groupSize)
					}
					pairGroup := block / groupSize
					parity := block % groupSize
					if parity >= 2 {
						return nil, nil, fmt.Errorf("invalid pair-lookup parity=%d for block=%d", parity, block)
					}
					loCoeff, err := getRowCoeff(rowLayoutPairLookupExtractIndex(layout, comp, pairGroup, lane, parity, 0))
					if err != nil {
						return nil, nil, fmt.Errorf("pair-lookup lo digit coeffs comp=%d block=%d lane=%d: %w", comp, block, lane, err)
					}
					hiCoeff, err := getRowCoeff(rowLayoutPairLookupExtractIndex(layout, comp, pairGroup, lane, parity, 1))
					if err != nil {
						return nil, nil, fmt.Errorf("pair-lookup hi digit coeffs comp=%d block=%d lane=%d: %w", comp, block, lane, err)
					}
					coeff = polyAdd(loCoeff, scalePoly(hiCoeff, uint64(layout.PairLookupRangeLoWidth), q), q)
					if len(coeff) == 0 {
						coeff = []uint64{0}
					}
					coeff[0] = modAdd(coeff[0], liftToField(q, int64(spec.DigitLo[lane])), q)
				} else {
					rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
					if rowIdx < 0 || rowIdx >= len(rowsNTT) {
						return nil, nil, fmt.Errorf("digit row idx out of range for comp=%d block=%d lane=%d", comp, block, lane)
					}
					var err error
					coeff, err = coeffFromNTTPoly(ringQ, rowsNTT[rowIdx])
					if err != nil {
						return nil, nil, fmt.Errorf("digit coeffs comp=%d block=%d lane=%d: %w", comp, block, lane, err)
					}
				}
				digitCoeffs[[3]int{comp, block, lane}] = trimPoly(coeff, q)
			}
		}
	}
	outPolys := make([]*ring.Poly, 0, replayBlockCount*ncols)
	outCoeffs := make([][]uint64, 0, replayBlockCount*ncols)
	for bOut := 0; bOut < replayBlockCount; bOut++ {
		thetaAHeads := make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			aHead, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, nil, fmt.Errorf("theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			thetaAHeads[comp] = aHead
		}
		rhsCoeff := polyAdd(thetaB0Coeffs[bOut], zHatCoeffs[bOut], q)
		if !inlineTarget {
			rhsCoeff = polyAdd(rhsCoeff, targetMR0Coeffs[bOut], q)
		}
		for j := 0; j < ncols; j++ {
			t := bOut*ncols + j
			leftCoeff := []uint64{0}
			for comp := 0; comp < cfg.PackedSigComponents; comp++ {
				aScale := thetaAHeads[comp][j] % q
				if aScale == 0 {
					continue
				}
				for block := 0; block < cfg.PackedSigBlocks; block++ {
					blockScale := bridgeBasis.BlockFactors[t][block] % q
					if blockScale == 0 {
						continue
					}
					for lane := 0; lane < spec.L; lane++ {
						scale := modMul(aScale, modMul(spec.RPows[lane]%q, blockScale, q), q)
						term := reducePolyModXN1(polyMul(bridgeBasis.TransformH[t], digitCoeffs[[3]int{comp, block, lane}], q), int(ringQ.N), q)
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						leftCoeff = polyAdd(leftCoeff, term, q)
					}
				}
			}
			rightCoeff := reducePolyModXN1(polyMul(bridgeBasis.LagrangeBasis[j], rhsCoeff, q), int(ringQ.N), q)
			if inlineTarget {
				var targetCoeff []uint64
				if fullMuInlineBridgeBasis != nil {
					targetCoeff = []uint64{0}
					for block := range fullMuSourceCoeffs {
						term := polyMul(fullMuInlineBridgeBasis.TransformH[t], fullMuSourceCoeffs[block], q)
						if highDegreePackedMu {
							term = trimPoly(term, q)
						} else {
							term = reducePolyModXN1(term, int(ringQ.N), q)
						}
						scale := fullMuInlineBridgeBasis.BlockFactors[t][block] % q
						if scale != 1 {
							term = scalePoly(term, scale, q)
						}
						targetCoeff = polyAdd(targetCoeff, term, q)
					}
				} else {
					targetCoeff = reducePolyModXN1(polyMul(inlineTargetBridgeBasis.TransformH[t], mSigmaCompCoeffs, q), int(ringQ.N), q)
				}
				b1Scale := thetaBHeads[bOut][1][j] % q
				if b1Scale != 1 {
					targetCoeff = scalePoly(targetCoeff, b1Scale, q)
				}
				for i := 0; i < len(r0CompCoeffs); i++ {
					scale := thetaBHeads[bOut][2+i][j] % q
					term := reducePolyModXN1(polyMul(inlineTargetBridgeBasis.TransformH[t], r0CompCoeffs[i], q), int(ringQ.N), q)
					if scale != 1 {
						term = scalePoly(term, scale, q)
					}
					targetCoeff = polyAdd(targetCoeff, term, q)
				}
				rightCoeff = polyAdd(rightCoeff, targetCoeff, q)
			}
			bridgeCoeff := polySub(leftCoeff, rightCoeff, q)
			if highDegreePackedMu {
				bridgeCoeff = trimPoly(bridgeCoeff, q)
			} else {
				bridgeCoeff = reducePolyModXN1(bridgeCoeff, int(ringQ.N), q)
			}
			outCoeffs = append(outCoeffs, bridgeCoeff)
			outPolys = append(outPolys, nttPolyFromFormalCoeffsIfFits(ringQ, bridgeCoeff))
		}
	}
	return outPolys, outCoeffs, nil
}

func buildSigShortnessV18ConstraintSet(
	ringQ *ring.Ring,
	layout RowLayout,
	pub PublicInputs,
	omegaWitness []uint64,
	rowsNTT []*ring.Poly,
	opts SimOpts,
) (ConstraintSet, error) {
	if !sigShortnessInlinedTargetHidingEnabledForOpts(opts) {
		return ConstraintSet{}, nil
	}
	shortSet := ConstraintSet{}
	var err error
	shortSet, err = buildLiteralPackedSignatureShortnessConstraintSet(ringQ, layout, rowsNTT, opts)
	if err != nil {
		return ConstraintSet{}, err
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], layout, opts)
	if err != nil {
		return ConstraintSet{}, err
	}
	faggNorm, faggNormCoeffs, err := buildSigShortnessDirectTargetFormalCoeffs(ringQ, layout, pub, omegaWitness, rowsNTT, spec)
	if err != nil {
		return ConstraintSet{}, err
	}
	shortSet.FaggNorm = append(shortSet.FaggNorm, faggNorm...)
	shortSet.FaggNormCoeffs = append(shortSet.FaggNormCoeffs, faggNormCoeffs...)
	if len(faggNorm) > 0 && shortSet.AggregatedAlgDeg < 1 {
		shortSet.AggregatedAlgDeg = 1
	}
	return shortSet, nil
}

func buildSigShortnessV18Replay(
	ringQ *ring.Ring,
	proof *Proof,
	pub PublicInputs,
	omegaWitness []uint64,
	domainPoints []uint64,
	opts SimOpts,
) (*ConstraintReplay, error) {
	if proof == nil || proof.SigShortness == nil {
		return nil, fmt.Errorf("missing inlined sig shortness proof metadata")
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if proof.SigShortness.Version != sigShortnessProofVersionV18 {
		return nil, fmt.Errorf("unsupported sig shortness version %d", proof.SigShortness.Version)
	}
	if proof.SigShortness.V18 == nil {
		return nil, fmt.Errorf("missing V18 sig shortness proof metadata")
	}
	radix := proof.SigShortness.V18.Radix
	digits := proof.SigShortness.V18.Digits
	coeffLookup := false
	inlineTargetMode := true
	directTarget := true
	groupedSigDomain := false
	pairLookup := false
	freeSigLookupShadow := sigLookupShadowR121L2FreeForOpts(opts)
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	var err error
	logicalRows := proof.PCSGeometry.LogicalWitnessPolys
	if logicalRows <= 0 {
		logicalRows = layout.SigCount
	}
	if logicalRows <= 0 {
		return nil, fmt.Errorf("missing logical witness row count")
	}
	ncols := len(omegaWitness)
	if ncols <= 0 {
		return nil, fmt.Errorf("empty witness omega")
	}
	if len(domainPoints) == 0 {
		return nil, fmt.Errorf("empty domain points")
	}
	if len(pub.A) != 1 || len(pub.A[0]) == 0 {
		return nil, fmt.Errorf("sig shortness V7 expects one public A row")
	}
	sourceBlocks := cfg.PackedSigBlocks
	if sourceBlocks <= 0 {
		return nil, fmt.Errorf("invalid source blocks=%d", sourceBlocks)
	}
	var spec LinfSpec
	if !coeffLookup {
		specOpts := opts
		specOpts.CoeffNativeSigModel = layout.CoeffNativeSig.Model
		specOpts.SigShortnessProfile = ""
		specOpts.SigShortnessRadix = radix
		specOpts.SigShortnessL = digits
		spec, err = signatureChainSpecForOpts(ringQ.Modulus[0], specOpts)
		if err != nil {
			return nil, fmt.Errorf("signature chain spec: %w", err)
		}
	}
	replayOutputBlocks := rowLayoutReplayTHatCount(layout)
	if directTarget {
		replayOutputBlocks = rowLayoutReplayBlockCount(layout)
	}
	if replayOutputBlocks <= 0 {
		return nil, fmt.Errorf("invalid inlined shortness replay output blocks=%d", replayOutputBlocks)
	}
	var bridgeBasis *transformBridgeBasisCache
	var mainLagrange [][]uint64
	var sigLagrange [][]uint64
	bridgeBasis, err = newTransformBridgeBasisCache(ringQ, omegaWitness, replayOutputBlocks*ncols, sourceBlocks)
	if err != nil {
		return nil, fmt.Errorf("sig shortness V18 transform bridge basis: %w", err)
	}
	var inlineTargetBridgeBasis *transformBridgeBasisCache
	if inlineTargetMode {
		inlineTargetBridgeBasis, err = newRowTransformBridgeBasisCache(ringQ, omegaWitness, replayOutputBlocks*ncols)
		if err != nil {
			return nil, fmt.Errorf("sig shortness inline target bridge basis: %w", err)
		}
	}
	fullMuInlineTarget := inlineTargetMode && rowLayoutUsesFullMu(layout)
	packedMuInlineTarget := fullMuInlineTarget && rowLayoutUsesPackedMuCarrier(layout)
	muPackWidth := rowLayoutMuCarrierPackWidth(layout)
	muVirtualBlocks := rowLayoutMuVirtualBlockCount(layout)
	aliasMuRows := rowLayoutAliasMuBlockRows(layout)
	carrierMuRows := rowLayoutCarrierMuBlockRows(layout)
	var muDecodePolys [][]uint64
	var fullMuInlineBridgeBasis *transformBridgeBasisCache
	if fullMuInlineTarget {
		if !packedMuInlineTarget && len(aliasMuRows) == 0 {
			return nil, fmt.Errorf("sig shortness V18 full mu inline target missing alias mu rows")
		}
		if packedMuInlineTarget {
			muDecodePolys, _, err = buildMuCarrierDecodePolys(pub.BoundB, muPackWidth, ringQ.Modulus[0])
			if err != nil {
				return nil, fmt.Errorf("sig shortness V18 packed mu decode polys: %w", err)
			}
		}
		fullMuInlineBridgeBasis, err = newTransformBridgeBasisCache(ringQ, omegaWitness, replayOutputBlocks*ncols, muVirtualBlocks)
		if err != nil {
			return nil, fmt.Errorf("sig shortness V18 full mu inline target bridge basis: %w", err)
		}
	}
	aHeads := make([][][]uint64, replayOutputBlocks)
	for bOut := 0; bOut < replayOutputBlocks; bOut++ {
		aHeads[bOut] = make([][]uint64, cfg.PackedSigComponents)
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			head, err := thetaHeadFromNTTBlock(ringQ, pub.A[0][comp], omegaWitness, bOut, sourceBlocks)
			if err != nil {
				return nil, fmt.Errorf("theta A comp=%d block=%d: %w", comp, bOut, err)
			}
			aHeads[bOut][comp] = head
		}
	}
	var b0Coeffs [][]uint64
	var thetaBHeads [][][]uint64
	if directTarget {
		b0Coeffs = make([][]uint64, replayOutputBlocks)
		if inlineTargetMode {
			thetaBHeads = make([][][]uint64, replayOutputBlocks)
		}
		for block := 0; block < replayOutputBlocks; block++ {
			thetaB0, err := thetaPolyFromNTTBlock(ringQ, pub.B[0], omegaWitness, block, sourceBlocks)
			if err != nil {
				return nil, fmt.Errorf("theta B0 block %d: %w", block, err)
			}
			coeff, err := coeffFromNTTPoly(ringQ, thetaB0)
			if err != nil {
				return nil, fmt.Errorf("theta B0 coeff block %d: %w", block, err)
			}
			b0Coeffs[block] = trimPoly(coeff, ringQ.Modulus[0])
			if inlineTargetMode {
				thetaBHeads[block] = make([][]uint64, len(pub.B))
				for i := range pub.B {
					head, err := thetaHeadFromNTTBlock(ringQ, pub.B[i], omegaWitness, block, sourceBlocks)
					if err != nil {
						return nil, fmt.Errorf("inline target theta B[%d] block %d: %w", i, block, err)
					}
					thetaBHeads[block][i] = head
				}
			}
		}
	}
	eval := func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if len(rows) < logicalRows {
			return nil, nil, fmt.Errorf("row value count=%d want >=%d", len(rows), logicalRows)
		}
		if int(evalIdx) >= len(domainPoints) {
			return nil, nil, fmt.Errorf("eval idx %d out of range (|E|=%d)", evalIdx, len(domainPoints))
		}
		q := ringQ.Modulus[0]
		fparGroups := cfg.PackedSigBlocks * cfg.PackedSigComponents
		if groupedSigDomain {
			fparGroups = layout.PackedSigChainGroupCount
		}
		if pairLookup {
			fparGroups = layout.PackedSigChainGroupCount
		}
		if freeSigLookupShadow {
			fparGroups = 0
			if cfg.PackedSigBase >= 0 && cfg.PackedSigCount >= layout.PackedSigChainGroupCount {
				fparGroups = layout.PackedSigChainGroupCount
			}
		}
		if coeffLookup {
			fparGroups = 0
		}
		fparCap := fparGroups * spec.L
		if coeffLookup {
			// Coefficient lookup modes move interval membership into an
			// auxiliary proof, so the main replay has no digit Fpar bucket.
		} else if freeSigLookupShadow {
			// Unsafe R121/L2 free-shadow mode measures the best-case fixed-table
			// lookup savings by retaining only linear source recomposition.
			fparCap = fparGroups
		} else if pairLookup {
			fparCap *= 5
		}
		fpar := make([]uint64, 0, fparCap)
		if pairLookup {
			rangeLoPoly := buildBalancedMembershipPoly(q, 0, layout.PairLookupRangeLoWidth-1)
			rangeHiPoly := buildBalancedMembershipPoly(q, 0, layout.PairLookupRangeHiWidth-1)
			for pairGroup := 0; pairGroup < rowLayoutPackedSigChainEffectiveBlocks(layout); pairGroup++ {
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					for lane := 0; lane < spec.L; lane++ {
						packedIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, pairGroup*layout.PackedSigChainGroupSize, lane)
						if packedIdx < 0 || packedIdx >= len(rows) {
							return nil, nil, fmt.Errorf("pair-lookup packed row idx out of range for comp=%d group=%d lane=%d", comp, pairGroup, lane)
						}
						extract := make([]uint64, 4)
						pos := 0
						for parity := 0; parity < 2; parity++ {
							for part := 0; part < 2; part++ {
								rowIdx := rowLayoutPairLookupExtractIndex(layout, comp, pairGroup, lane, parity, part)
								if rowIdx < 0 || rowIdx >= len(rows) {
									return nil, nil, fmt.Errorf("pair-lookup extract row idx out of range for comp=%d group=%d lane=%d parity=%d part=%d", comp, pairGroup, lane, parity, part)
								}
								extract[pos] = rows[rowIdx] % q
								pos++
							}
						}
						fpar = append(fpar, EvalPoly(rangeLoPoly, extract[0], q)%q)
						fpar = append(fpar, EvalPoly(rangeHiPoly, extract[1], q)%q)
						fpar = append(fpar, EvalPoly(rangeLoPoly, extract[2], q)%q)
						fpar = append(fpar, EvalPoly(rangeHiPoly, extract[3], q)%q)
						residual := rows[packedIdx] % q
						residual = modSub(residual, extract[0], q)
						residual = modSub(residual, modMul(uint64(layout.PairLookupRangeLoWidth), extract[1], q), q)
						residual = modSub(residual, modMul(uint64(layout.PairLookupBase), extract[2], q), q)
						residual = modSub(residual, modMul(uint64(layout.PairLookupBase*layout.PairLookupRangeLoWidth), extract[3], q), q)
						residual = modAdd(residual, liftToField(q, -int64(spec.DigitLo[lane])*int64(1+layout.PairLookupBase)), q)
						fpar = append(fpar, residual)
					}
				}
			}
		} else if freeSigLookupShadow {
			for group := 0; group < fparGroups; group++ {
				sourceIdx := cfg.PackedSigBase + group
				if sourceIdx < 0 || sourceIdx >= len(rows) {
					return nil, nil, fmt.Errorf("R121/L2 free-shadow source row idx out of range for group=%d", group)
				}
				residual := rows[sourceIdx] % q
				for lane := 0; lane < spec.L; lane++ {
					rowIdx := rowLayoutCoeffNativePackedSigChainIndex(layout, group, lane)
					if rowIdx < 0 || rowIdx >= len(rows) {
						return nil, nil, fmt.Errorf("R121/L2 free-shadow packed row idx out of range for group=%d lane=%d", group, lane)
					}
					residual = modSub(residual, modMul(spec.RPows[lane]%q, rows[rowIdx]%q, q), q)
				}
				fpar = append(fpar, residual)
			}
		} else if groupedSigDomain {
			for group := 0; group < layout.PackedSigChainGroupCount; group++ {
				for lane := 0; lane < spec.L; lane++ {
					rowIdx := rowLayoutCoeffNativePackedSigChainIndex(layout, group, lane)
					fpar = append(fpar, EvalPoly(spec.PDi[lane], rows[rowIdx]%q, q)%q)
				}
			}
		} else {
			for block := 0; block < cfg.PackedSigBlocks; block++ {
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					for lane := 0; lane < spec.L; lane++ {
						rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
						fpar = append(fpar, EvalPoly(spec.PDi[lane], rows[rowIdx]%q, q)%q)
					}
				}
			}
		}
		digitValue := func(comp, block, lane int) (uint64, error) {
			if pairLookup {
				groupSize := layout.PackedSigChainGroupSize
				pairGroup := block / groupSize
				parity := block % groupSize
				loIdx := rowLayoutPairLookupExtractIndex(layout, comp, pairGroup, lane, parity, 0)
				hiIdx := rowLayoutPairLookupExtractIndex(layout, comp, pairGroup, lane, parity, 1)
				if loIdx < 0 || loIdx >= len(rows) || hiIdx < 0 || hiIdx >= len(rows) {
					return 0, fmt.Errorf("pair-lookup digit extract idx out of range for comp=%d block=%d lane=%d", comp, block, lane)
				}
				value := modAdd(rows[loIdx]%q, modMul(uint64(layout.PairLookupRangeLoWidth), rows[hiIdx]%q, q), q)
				value = modAdd(value, liftToField(q, int64(spec.DigitLo[lane])), q)
				return value, nil
			}
			rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
			if rowIdx < 0 || rowIdx >= len(rows) {
				return 0, fmt.Errorf("digit row idx out of range for comp=%d block=%d lane=%d", comp, block, lane)
			}
			return rows[rowIdx] % q, nil
		}
		x := domainPoints[int(evalIdx)] % q
		var mSigma uint64
		var r0Vals []uint64
		if inlineTargetMode {
			if !fullMuInlineTarget {
				m1Idx := rowLayoutPostSignM1(layout)
				m2Idx := rowLayoutPostSignM2(layout)
				if m1Idx < 0 || m1Idx >= len(rows) || m2Idx < 0 || m2Idx >= len(rows) {
					return nil, nil, fmt.Errorf("inline target message rows out of range")
				}
				mSigma = modAdd(rows[m1Idx]%q, rows[m2Idx]%q, q)
			}
			r0Rows := rowLayoutPostSignR0Rows(layout)
			r0Vals = make([]uint64, len(r0Rows))
			for i, rowIdx := range r0Rows {
				if rowIdx < 0 || rowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("inline target R0 row idx out of range for component=%d", i)
				}
				r0Vals[i] = rows[rowIdx] % q
			}
		}
		fagg := make([]uint64, 0, replayOutputBlocks*ncols)
		var mainLagrangeVals []uint64
		var sigLagrangeVals []uint64
		if groupedSigDomain {
			mainLagrangeVals = make([]uint64, len(mainLagrange))
			for j := range mainLagrange {
				mainLagrangeVals[j] = EvalPoly(mainLagrange[j], x, q) % q
			}
			sigLagrangeVals = make([]uint64, len(sigLagrange))
			for j := range sigLagrange {
				sigLagrangeVals[j] = EvalPoly(sigLagrange[j], x, q) % q
			}
		}
		for bOut := 0; bOut < replayOutputBlocks; bOut++ {
			var rhsBase uint64
			if directTarget {
				zHatRowIdx := rowLayoutPostSignZHatIndex(layout, bOut)
				if zHatRowIdx < 0 || zHatRowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("z-hat row idx out of range for block=%d", bOut)
				}
				rhsBase = EvalPoly(b0Coeffs[bOut], x, q) % q
				if !inlineTargetMode {
					targetRowIdx := rowLayoutPostSignTargetMR0HatIndex(layout, bOut)
					if targetRowIdx < 0 || targetRowIdx >= len(rows) {
						return nil, nil, fmt.Errorf("target-MR0 row idx out of range for block=%d", bOut)
					}
					rhsBase = modAdd(rhsBase, rows[targetRowIdx]%q, q)
				}
				rhsBase = modAdd(rhsBase, rows[zHatRowIdx]%q, q)
			} else {
				tHatRowIdx := rowLayoutPostSignTHatIndex(layout, bOut)
				if tHatRowIdx < 0 || tHatRowIdx >= len(rows) {
					return nil, nil, fmt.Errorf("t-hat row idx out of range for block=%d", bOut)
				}
				rhsBase = rows[tHatRowIdx] % q
			}
			for j := 0; j < ncols; j++ {
				lhs := uint64(0)
				if coeffLookup {
					lambda := EvalPoly(bridgeBasis.LagrangeBasis[j], x, q) % q
					for comp := 0; comp < layout.CoeffLookupComponents; comp++ {
						rowIdx := rowLayoutCoeffLookupIndex(layout, comp, bOut)
						if rowIdx < 0 || rowIdx >= len(rows) {
							return nil, nil, fmt.Errorf("coefficient lookup row idx out of range for comp=%d block=%d", comp, bOut)
						}
						aScale := aHeads[bOut][comp][j] % q
						if aScale == 0 {
							continue
						}
						term := modMul(aScale, modMul(lambda, rows[rowIdx]%q, q), q)
						lhs = modAdd(lhs, term, q)
					}
					rhs := modMul(lambda, rhsBase, q)
					fagg = append(fagg, modSub(lhs, rhs, q))
					continue
				}
				if groupedSigDomain {
					groupSize := layout.PackedSigChainGroupSize
					sigCol := (bOut%groupSize)*ncols + j
					lambdaSig := sigLagrangeVals[sigCol]
					for comp := 0; comp < cfg.PackedSigComponents; comp++ {
						aScale := aHeads[bOut][comp][j] % q
						if aScale == 0 {
							continue
						}
						for lane := 0; lane < spec.L; lane++ {
							digit, err := digitValue(comp, bOut, lane)
							if err != nil {
								return nil, nil, err
							}
							scale := modMul(aScale, spec.RPows[lane]%q, q)
							term := modMul(scale, modMul(lambdaSig, digit, q), q)
							lhs = modAdd(lhs, term, q)
						}
					}
					rhs := modMul(mainLagrangeVals[j], rhsBase, q)
					fagg = append(fagg, modSub(lhs, rhs, q))
					continue
				}
				t := bOut*ncols + j
				hVal := EvalPoly(bridgeBasis.TransformH[t], x, q) % q
				for comp := 0; comp < cfg.PackedSigComponents; comp++ {
					aScale := aHeads[bOut][comp][j] % q
					if aScale == 0 {
						continue
					}
					for block := 0; block < cfg.PackedSigBlocks; block++ {
						blockScale := bridgeBasis.BlockFactors[t][block] % q
						if blockScale == 0 {
							continue
						}
						for lane := 0; lane < spec.L; lane++ {
							digit, err := digitValue(comp, block, lane)
							if err != nil {
								return nil, nil, err
							}
							scale := modMul(aScale, modMul(spec.RPows[lane]%q, blockScale, q), q)
							term := modMul(scale, modMul(hVal, digit, q), q)
							lhs = modAdd(lhs, term, q)
						}
					}
				}
				lambda := EvalPoly(bridgeBasis.LagrangeBasis[j], x, q) % q
				rhs := modMul(lambda, rhsBase, q)
				if inlineTargetMode {
					inlineHVal := EvalPoly(inlineTargetBridgeBasis.TransformH[t], x, q) % q
					inlineTarget := uint64(0)
					if fullMuInlineTarget {
						fullMuHVal := EvalPoly(fullMuInlineBridgeBasis.TransformH[t], x, q) % q
						for block := 0; block < muVirtualBlocks; block++ {
							var srcVal uint64
							if packedMuInlineTarget {
								carrierBlock := block / muPackWidth
								lane := block % muPackWidth
								if carrierBlock < 0 || carrierBlock >= len(carrierMuRows) || lane >= len(muDecodePolys) {
									return nil, nil, fmt.Errorf("V18 mu virtual block=%d maps outside carrier rows=%d lanes=%d", block, len(carrierMuRows), len(muDecodePolys))
								}
								rowIdx := carrierMuRows[carrierBlock]
								if rowIdx < 0 || rowIdx >= len(rows) {
									return nil, nil, fmt.Errorf("V18 carrier mu row idx out of range for block=%d", block)
								}
								srcVal = EvalPoly(muDecodePolys[lane], rows[rowIdx]%q, q) % q
							} else {
								rowIdx := aliasMuRows[block]
								if rowIdx < 0 || rowIdx >= len(rows) {
									return nil, nil, fmt.Errorf("V18 alias mu row idx out of range for block=%d", block)
								}
								srcVal = rows[rowIdx] % q
							}
							scale := fullMuInlineBridgeBasis.BlockFactors[t][block] % q
							inlineTarget = modAdd(inlineTarget, modMul(scale, modMul(fullMuHVal, srcVal, q), q), q)
						}
						inlineTarget = modMul(thetaBHeads[bOut][1][j]%q, inlineTarget, q)
					} else {
						inlineTarget = modMul(thetaBHeads[bOut][1][j]%q, mSigma, q)
						inlineTarget = modMul(inlineHVal, inlineTarget, q)
					}
					for i := 0; i < len(r0Vals); i++ {
						term := modMul(thetaBHeads[bOut][2+i][j]%q, r0Vals[i], q)
						inlineTarget = modAdd(inlineTarget, modMul(inlineHVal, term, q), q)
					}
					rhs = modAdd(rhs, inlineTarget, q)
				}
				fagg = append(fagg, modSub(lhs, rhs, q))
			}
		}
		return fpar, fagg, nil
	}
	var evalK KConstraintEvaluator
	if proof.Theta > 1 {
		K, err := kf.New(ringQ.Modulus[0], proof.Theta, proof.Chi)
		if err != nil {
			return nil, err
		}
		evalK = func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
			if len(rows) < logicalRows {
				return nil, nil, fmt.Errorf("k row value count=%d want >=%d", len(rows), logicalRows)
			}
			fparGroups := cfg.PackedSigBlocks * cfg.PackedSigComponents
			if groupedSigDomain {
				fparGroups = layout.PackedSigChainGroupCount
			}
			if pairLookup {
				fparGroups = layout.PackedSigChainGroupCount
			}
			if freeSigLookupShadow {
				fparGroups = 0
				if cfg.PackedSigBase >= 0 && cfg.PackedSigCount >= layout.PackedSigChainGroupCount {
					fparGroups = layout.PackedSigChainGroupCount
				}
			}
			if coeffLookup {
				fparGroups = 0
			}
			fparCap := fparGroups * spec.L
			if coeffLookup {
				// Lookup membership is verified by the auxiliary proof.
			} else if freeSigLookupShadow {
				// Unsafe free-shadow mode keeps only linear source recomposition.
				fparCap = fparGroups
			} else if pairLookup {
				fparCap *= 5
			}
			fpar := make([]kf.Elem, 0, fparCap)
			if pairLookup {
				rangeLoPoly := buildBalancedMembershipPoly(K.Q, 0, layout.PairLookupRangeLoWidth-1)
				rangeHiPoly := buildBalancedMembershipPoly(K.Q, 0, layout.PairLookupRangeHiWidth-1)
				for pairGroup := 0; pairGroup < rowLayoutPackedSigChainEffectiveBlocks(layout); pairGroup++ {
					for comp := 0; comp < cfg.PackedSigComponents; comp++ {
						for lane := 0; lane < spec.L; lane++ {
							packedIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, pairGroup*layout.PackedSigChainGroupSize, lane)
							if packedIdx < 0 || packedIdx >= len(rows) {
								return nil, nil, fmt.Errorf("pair-lookup K packed row idx out of range for comp=%d group=%d lane=%d", comp, pairGroup, lane)
							}
							extract := make([]kf.Elem, 4)
							pos := 0
							for parity := 0; parity < 2; parity++ {
								for part := 0; part < 2; part++ {
									rowIdx := rowLayoutPairLookupExtractIndex(layout, comp, pairGroup, lane, parity, part)
									if rowIdx < 0 || rowIdx >= len(rows) {
										return nil, nil, fmt.Errorf("pair-lookup K extract row idx out of range for comp=%d group=%d lane=%d parity=%d part=%d", comp, pairGroup, lane, parity, part)
									}
									extract[pos] = rows[rowIdx]
									pos++
								}
							}
							fpar = append(fpar, K.EvalFPolyAtK(rangeLoPoly, extract[0]))
							fpar = append(fpar, K.EvalFPolyAtK(rangeHiPoly, extract[1]))
							fpar = append(fpar, K.EvalFPolyAtK(rangeLoPoly, extract[2]))
							fpar = append(fpar, K.EvalFPolyAtK(rangeHiPoly, extract[3]))
							residual := rows[packedIdx]
							residual = K.Sub(residual, extract[0])
							residual = K.Sub(residual, K.Mul(K.EmbedF(uint64(layout.PairLookupRangeLoWidth)%K.Q), extract[1]))
							residual = K.Sub(residual, K.Mul(K.EmbedF(uint64(layout.PairLookupBase)%K.Q), extract[2]))
							residual = K.Sub(residual, K.Mul(K.EmbedF(uint64(layout.PairLookupBase*layout.PairLookupRangeLoWidth)%K.Q), extract[3]))
							residual = K.Add(residual, K.EmbedF(liftToField(K.Q, -int64(spec.DigitLo[lane])*int64(1+layout.PairLookupBase))))
							fpar = append(fpar, residual)
						}
					}
				}
			} else if freeSigLookupShadow {
				for group := 0; group < fparGroups; group++ {
					sourceIdx := cfg.PackedSigBase + group
					if sourceIdx < 0 || sourceIdx >= len(rows) {
						return nil, nil, fmt.Errorf("R121/L2 free-shadow K source row idx out of range for group=%d", group)
					}
					residual := rows[sourceIdx]
					for lane := 0; lane < spec.L; lane++ {
						rowIdx := rowLayoutCoeffNativePackedSigChainIndex(layout, group, lane)
						if rowIdx < 0 || rowIdx >= len(rows) {
							return nil, nil, fmt.Errorf("R121/L2 free-shadow K packed row idx out of range for group=%d lane=%d", group, lane)
						}
						residual = K.Sub(residual, K.Mul(K.EmbedF(spec.RPows[lane]%K.Q), rows[rowIdx]))
					}
					fpar = append(fpar, residual)
				}
			} else if groupedSigDomain {
				for group := 0; group < layout.PackedSigChainGroupCount; group++ {
					for lane := 0; lane < spec.L; lane++ {
						rowIdx := rowLayoutCoeffNativePackedSigChainIndex(layout, group, lane)
						fpar = append(fpar, K.EvalFPolyAtK(spec.PDi[lane], rows[rowIdx]))
					}
				}
			} else {
				for block := 0; block < cfg.PackedSigBlocks; block++ {
					for comp := 0; comp < cfg.PackedSigComponents; comp++ {
						for lane := 0; lane < spec.L; lane++ {
							rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
							fpar = append(fpar, K.EvalFPolyAtK(spec.PDi[lane], rows[rowIdx]))
						}
					}
				}
			}
			digitValueK := func(comp, block, lane int) (kf.Elem, error) {
				if pairLookup {
					groupSize := layout.PackedSigChainGroupSize
					pairGroup := block / groupSize
					parity := block % groupSize
					loIdx := rowLayoutPairLookupExtractIndex(layout, comp, pairGroup, lane, parity, 0)
					hiIdx := rowLayoutPairLookupExtractIndex(layout, comp, pairGroup, lane, parity, 1)
					if loIdx < 0 || loIdx >= len(rows) || hiIdx < 0 || hiIdx >= len(rows) {
						return kf.Elem{}, fmt.Errorf("pair-lookup K digit extract idx out of range for comp=%d block=%d lane=%d", comp, block, lane)
					}
					value := K.Add(rows[loIdx], K.Mul(K.EmbedF(uint64(layout.PairLookupRangeLoWidth)%K.Q), rows[hiIdx]))
					value = K.Add(value, K.EmbedF(liftToField(K.Q, int64(spec.DigitLo[lane]))))
					return value, nil
				}
				rowIdx := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
				if rowIdx < 0 || rowIdx >= len(rows) {
					return kf.Elem{}, fmt.Errorf("digit K row idx out of range for comp=%d block=%d lane=%d", comp, block, lane)
				}
				return rows[rowIdx], nil
			}
			var mainLagrangeVals []kf.Elem
			var sigLagrangeVals []kf.Elem
			if groupedSigDomain {
				mainLagrangeVals = make([]kf.Elem, len(mainLagrange))
				for j := range mainLagrange {
					mainLagrangeVals[j] = K.EvalFPolyAtK(mainLagrange[j], e)
				}
				sigLagrangeVals = make([]kf.Elem, len(sigLagrange))
				for j := range sigLagrange {
					sigLagrangeVals[j] = K.EvalFPolyAtK(sigLagrange[j], e)
				}
			}
			var mSigmaK kf.Elem
			var r0ValsK []kf.Elem
			if inlineTargetMode {
				if !fullMuInlineTarget {
					m1Idx := rowLayoutPostSignM1(layout)
					m2Idx := rowLayoutPostSignM2(layout)
					if m1Idx < 0 || m1Idx >= len(rows) || m2Idx < 0 || m2Idx >= len(rows) {
						return nil, nil, fmt.Errorf("inline target K message rows out of range")
					}
					mSigmaK = K.Add(rows[m1Idx], rows[m2Idx])
				}
				r0Rows := rowLayoutPostSignR0Rows(layout)
				r0ValsK = make([]kf.Elem, len(r0Rows))
				for i, rowIdx := range r0Rows {
					if rowIdx < 0 || rowIdx >= len(rows) {
						return nil, nil, fmt.Errorf("inline target K R0 row idx out of range for component=%d", i)
					}
					r0ValsK[i] = rows[rowIdx]
				}
			}
			fagg := make([]kf.Elem, 0, replayOutputBlocks*ncols)
			for bOut := 0; bOut < replayOutputBlocks; bOut++ {
				var rhsBase kf.Elem
				if directTarget {
					zHatRowIdx := rowLayoutPostSignZHatIndex(layout, bOut)
					if zHatRowIdx < 0 || zHatRowIdx >= len(rows) {
						return nil, nil, fmt.Errorf("z-hat k row idx out of range for block=%d", bOut)
					}
					rhsBase = K.EvalFPolyAtK(b0Coeffs[bOut], e)
					if !inlineTargetMode {
						targetRowIdx := rowLayoutPostSignTargetMR0HatIndex(layout, bOut)
						if targetRowIdx < 0 || targetRowIdx >= len(rows) {
							return nil, nil, fmt.Errorf("target-MR0 k row idx out of range for block=%d", bOut)
						}
						rhsBase = K.Add(rhsBase, rows[targetRowIdx])
					}
					rhsBase = K.Add(rhsBase, rows[zHatRowIdx])
				} else {
					tHatRowIdx := rowLayoutPostSignTHatIndex(layout, bOut)
					if tHatRowIdx < 0 || tHatRowIdx >= len(rows) {
						return nil, nil, fmt.Errorf("t-hat k row idx out of range for block=%d", bOut)
					}
					rhsBase = rows[tHatRowIdx]
				}
				for j := 0; j < ncols; j++ {
					lhs := K.Zero()
					if coeffLookup {
						lambda := K.EvalFPolyAtK(bridgeBasis.LagrangeBasis[j], e)
						for comp := 0; comp < layout.CoeffLookupComponents; comp++ {
							rowIdx := rowLayoutCoeffLookupIndex(layout, comp, bOut)
							if rowIdx < 0 || rowIdx >= len(rows) {
								return nil, nil, fmt.Errorf("coefficient lookup K row idx out of range for comp=%d block=%d", comp, bOut)
							}
							aScale := K.EmbedF(aHeads[bOut][comp][j] % K.Q)
							if K.IsZero(aScale) {
								continue
							}
							term := K.Mul(aScale, K.Mul(lambda, rows[rowIdx]))
							lhs = K.Add(lhs, term)
						}
						rhs := K.Mul(lambda, rhsBase)
						fagg = append(fagg, K.Sub(lhs, rhs))
						continue
					}
					if groupedSigDomain {
						groupSize := layout.PackedSigChainGroupSize
						sigCol := (bOut%groupSize)*ncols + j
						lambdaSig := sigLagrangeVals[sigCol]
						for comp := 0; comp < cfg.PackedSigComponents; comp++ {
							aScale := K.EmbedF(aHeads[bOut][comp][j] % K.Q)
							if K.IsZero(aScale) {
								continue
							}
							for lane := 0; lane < spec.L; lane++ {
								digit, err := digitValueK(comp, bOut, lane)
								if err != nil {
									return nil, nil, err
								}
								scale := K.Mul(aScale, K.EmbedF(spec.RPows[lane]%K.Q))
								term := K.Mul(scale, K.Mul(lambdaSig, digit))
								lhs = K.Add(lhs, term)
							}
						}
						rhs := K.Mul(mainLagrangeVals[j], rhsBase)
						fagg = append(fagg, K.Sub(lhs, rhs))
						continue
					}
					t := bOut*ncols + j
					hVal := K.EvalFPolyAtK(bridgeBasis.TransformH[t], e)
					for comp := 0; comp < cfg.PackedSigComponents; comp++ {
						aScale := K.EmbedF(aHeads[bOut][comp][j] % K.Q)
						if K.IsZero(aScale) {
							continue
						}
						for block := 0; block < cfg.PackedSigBlocks; block++ {
							blockScale := K.EmbedF(bridgeBasis.BlockFactors[t][block] % K.Q)
							if K.IsZero(blockScale) {
								continue
							}
							for lane := 0; lane < spec.L; lane++ {
								digit, err := digitValueK(comp, block, lane)
								if err != nil {
									return nil, nil, err
								}
								scale := K.Mul(aScale, K.Mul(K.EmbedF(spec.RPows[lane]%K.Q), blockScale))
								term := K.Mul(scale, K.Mul(hVal, digit))
								lhs = K.Add(lhs, term)
							}
						}
					}
					lambda := K.EvalFPolyAtK(bridgeBasis.LagrangeBasis[j], e)
					rhs := K.Mul(lambda, rhsBase)
					if inlineTargetMode {
						inlineHVal := K.EvalFPolyAtK(inlineTargetBridgeBasis.TransformH[t], e)
						inlineTarget := K.Zero()
						if fullMuInlineTarget {
							fullMuHVal := K.EvalFPolyAtK(fullMuInlineBridgeBasis.TransformH[t], e)
							for block := 0; block < muVirtualBlocks; block++ {
								var srcVal kf.Elem
								if packedMuInlineTarget {
									carrierBlock := block / muPackWidth
									lane := block % muPackWidth
									if carrierBlock < 0 || carrierBlock >= len(carrierMuRows) || lane >= len(muDecodePolys) {
										return nil, nil, fmt.Errorf("V18 K mu virtual block=%d maps outside carrier rows=%d lanes=%d", block, len(carrierMuRows), len(muDecodePolys))
									}
									rowIdx := carrierMuRows[carrierBlock]
									if rowIdx < 0 || rowIdx >= len(rows) {
										return nil, nil, fmt.Errorf("V18 K carrier mu row idx out of range for block=%d", block)
									}
									srcVal = K.EvalFPolyAtK(muDecodePolys[lane], rows[rowIdx])
								} else {
									rowIdx := aliasMuRows[block]
									if rowIdx < 0 || rowIdx >= len(rows) {
										return nil, nil, fmt.Errorf("V18 K alias mu row idx out of range for block=%d", block)
									}
									srcVal = rows[rowIdx]
								}
								scale := K.EmbedF(fullMuInlineBridgeBasis.BlockFactors[t][block] % K.Q)
								inlineTarget = K.Add(inlineTarget, K.Mul(scale, K.Mul(fullMuHVal, srcVal)))
							}
							inlineTarget = K.Mul(K.EmbedF(thetaBHeads[bOut][1][j]%K.Q), inlineTarget)
						} else {
							inlineTarget = K.Mul(K.EmbedF(thetaBHeads[bOut][1][j]%K.Q), mSigmaK)
							inlineTarget = K.Mul(inlineHVal, inlineTarget)
						}
						for i := 0; i < len(r0ValsK); i++ {
							term := K.Mul(K.EmbedF(thetaBHeads[bOut][2+i][j]%K.Q), r0ValsK[i])
							inlineTarget = K.Add(inlineTarget, K.Mul(inlineHVal, term))
						}
						rhs = K.Add(rhs, inlineTarget)
					}
					fagg = append(fagg, K.Sub(lhs, rhs))
				}
			}
			return fpar, fagg, nil
		}
	}
	return &ConstraintReplay{
		Eval:     eval,
		EvalK:    evalK,
		RowCount: logicalRows,
	}, nil
}

func VerifySigShortnessProof(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	switch proof.SigShortness.Version {
	case sigShortnessProofVersionV18:
		return VerifySigShortnessProofV18(proof, ringQ, omegaWitness, pub, opts)
	default:
		return fmt.Errorf("unsupported sig shortness proof version %d", proof.SigShortness.Version)
	}
}

func validateSigShortnessV18Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV18 {
		return nil
	}
	if sig.V18 == nil {
		return fmt.Errorf("missing sig shortness V18 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil {
		return fmt.Errorf("sig shortness V18 must not populate legacy or unrelated payload fields")
	}
	v18 := sig.V18
	if v18.Mode != sigShortnessV18ModeReplayCompact {
		return fmt.Errorf("unsupported sig shortness V18 mode %d", v18.Mode)
	}
	if v18.RingDegree <= 0 {
		return fmt.Errorf("missing sig shortness V18 ring_degree")
	}
	if proof.RowLayout.PackedSigChainBase < 0 || proof.RowLayout.PackedSigChainGroupCount <= 0 || proof.RowLayout.PackedSigChainRowsPerGroup <= 0 {
		return fmt.Errorf("missing replay-compact packed shortness layout")
	}
	if rowLayoutReplayTHatCount(proof.RowLayout) != 0 || len(rowLayoutPostSignTHatRows(proof.RowLayout)) != 0 || rowLayoutPostSignTHatBase(proof.RowLayout) >= 0 {
		return fmt.Errorf("sig shortness V18 must not materialize replay T-hat rows")
	}
	replayBlocks := rowLayoutReplayBlockCount(proof.RowLayout)
	if replayBlocks <= 0 {
		return fmt.Errorf("sig shortness V18 requires replay blocks")
	}
	if len(rowLayoutPostSignTargetMR0HatRows(proof.RowLayout)) != 0 || rowLayoutPostSignTargetMR0Hat(proof.RowLayout) >= 0 {
		return fmt.Errorf("sig shortness V18 must not materialize target-MR0 replay rows")
	}
	if len(rowLayoutPostSignRHat1Rows(proof.RowLayout)) != replayBlocks || len(rowLayoutPostSignZHatRows(proof.RowLayout)) != replayBlocks {
		return fmt.Errorf("sig shortness V18 requires one RHat1 and one ZHat row per block")
	}
	if proof.RowLayout.PairLookupExtractBase >= 0 || proof.RowLayout.PairLookupExtractGroupCount != 0 || proof.RowLayout.PairLookupExtractRowsPerLane != 0 {
		return fmt.Errorf("sig shortness V18 must not carry pair extraction rows")
	}
	if proof.RowLayout.CoeffLookupBase >= 0 || proof.RowLayout.CoeffLookupRowCount != 0 {
		return fmt.Errorf("sig shortness V18 must not carry coefficient lookup rows")
	}
	if v18.GroupSize != proof.RowLayout.PackedSigChainGroupSize {
		return fmt.Errorf("V18 group_size=%d want %d", v18.GroupSize, proof.RowLayout.PackedSigChainGroupSize)
	}
	if v18.BlockWidth != proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth {
		return fmt.Errorf("V18 block_width=%d want %d", v18.BlockWidth, proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth)
	}
	if !bytes.Equal(v18.LayoutDigest, buildSigShortnessV18LayoutDigest(proof.RowLayout)) {
		return fmt.Errorf("sig shortness V18 layout digest mismatch")
	}
	if len(v18.ReplayCompactDigest) > 0 && !bytes.Equal(v18.ReplayCompactDigest, buildSigShortnessV18ReplayCompactDigest(proof.RowLayout)) {
		return fmt.Errorf("sig shortness V18 replay compact digest mismatch")
	}
	if len(v18.PRFCompactDigest) > 0 && !bytes.Equal(v18.PRFCompactDigest, buildSigShortnessV18PRFCompactDigest()) {
		return fmt.Errorf("sig shortness V18 PRF compact digest mismatch")
	}
	return nil
}

func VerifySigShortnessProofV18(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	_ = omegaWitness
	if err := validateSigShortnessV18Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if proof.RingDegree > 0 && proof.RingDegree != int(ringQ.N) {
		return fmt.Errorf("proof ring_degree=%d does not match verifier ring degree %d", proof.RingDegree, ringQ.N)
	}
	if proof.RowLayout.RingDegree > 0 && proof.RowLayout.RingDegree != int(ringQ.N) {
		return fmt.Errorf("row layout ring_degree=%d does not match verifier ring degree %d", proof.RowLayout.RingDegree, ringQ.N)
	}
	if v18 := proof.SigShortness.V18; v18 != nil && v18.RingDegree != int(ringQ.N) {
		return fmt.Errorf("V18 ring_degree=%d want %d", v18.RingDegree, ringQ.N)
	}
	if pub.X0Len > 0 {
		layoutX0Len := rowLayoutX0Len(proof.RowLayout)
		if layoutX0Len > 0 && layoutX0Len != pub.X0Len {
			return fmt.Errorf("row layout x0_len=%d does not match public x0_len=%d", layoutX0Len, pub.X0Len)
		}
	}
	if !sigShortnessV18EnabledForOpts(opts) {
		return fmt.Errorf("sig shortness V18 not enabled for opts")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
	if err != nil {
		return fmt.Errorf("sig shortness V18 spec: %w", err)
	}
	v18 := proof.SigShortness.V18
	if v18.Radix != int(spec.R) {
		return fmt.Errorf("sig shortness V18 radix=%d want %d", v18.Radix, spec.R)
	}
	if v18.Digits != spec.L {
		return fmt.Errorf("sig shortness V18 digits=%d want %d", v18.Digits, spec.L)
	}
	if _, err := buildSigShortnessV18BindingDigest(proof.SigShortness, proof.RowLayout, proof.NColsUsed); err != nil {
		return err
	}
	return nil
}
