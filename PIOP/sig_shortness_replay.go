package PIOP

import (
	"fmt"
	"sort"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	sigShortnessProofVersionV2 = 2
	sigShortnessProofVersionV3 = 3
	sigShortnessProofVersionV4 = 4
)

func buildSigShortnessWitnessPolyIndices(layout RowLayout) []int {
	return buildSigShortnessWitnessPolyIndicesForVersion(layout, sigShortnessProofVersionV2)
}

func buildSigShortnessWitnessPolyIndicesForVersion(layout RowLayout, version int) []int {
	rows := make([]int, 0, rowLayoutReplayTHatCount(layout)+layout.CoeffNativeSig.PackedSigCount+layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup)
	if version >= sigShortnessProofVersionV3 {
		tHatBase := rowLayoutPostSignTHatBase(layout)
		tHatCount := rowLayoutReplayTHatCount(layout)
		if tHatBase >= 0 && tHatCount > 0 {
			for i := 0; i < tHatCount; i++ {
				rows = append(rows, tHatBase+i)
			}
		}
	}
	if version < sigShortnessProofVersionV4 && layout.CoeffNativeSig.PackedSigBase >= 0 && layout.CoeffNativeSig.PackedSigCount > 0 {
		for i := 0; i < layout.CoeffNativeSig.PackedSigCount; i++ {
			rows = append(rows, layout.CoeffNativeSig.PackedSigBase+i)
		}
	}
	if layout.PackedSigChainBase >= 0 && layout.PackedSigChainRowsPerGroup > 0 {
		chainRows := layout.PackedSigChainGroupCount * layout.PackedSigChainRowsPerGroup
		for i := 0; i < chainRows; i++ {
			rows = append(rows, layout.PackedSigChainBase+i)
		}
	}
	return rows
}

func buildSigShortnessSupportSlotsForRows(rows []int, pcsNCols int) ([]int, error) {
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	seen := make(map[int]struct{}, len(rows))
	for _, row := range rows {
		if row < 0 {
			return nil, fmt.Errorf("invalid shortness witness index %d", row)
		}
		seen[row%pcsNCols] = struct{}{}
	}
	slots := make([]int, 0, len(seen))
	for slot := range seen {
		slots = append(slots, slot)
	}
	sort.Ints(slots)
	return slots, nil
}

func buildSigShortnessSupportSlots(layout RowLayout, pcsNCols int) ([]int, error) {
	return buildSigShortnessSupportSlotsForVersion(layout, pcsNCols, sigShortnessProofVersionV2)
}

func buildSigShortnessSupportSlotsForVersion(layout RowLayout, pcsNCols int, version int) ([]int, error) {
	return buildSigShortnessSupportSlotsForRows(buildSigShortnessWitnessPolyIndicesForVersion(layout, version), pcsNCols)
}

func validateSortedUniqueIndices(label string, values []int) error {
	for i, v := range values {
		if v < 0 {
			return fmt.Errorf("%s[%d]=%d is negative", label, i, v)
		}
		if i == 0 {
			continue
		}
		if values[i-1] >= v {
			return fmt.Errorf("%s is not strictly increasing at %d (%d >= %d)", label, i, values[i-1], v)
		}
	}
	return nil
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
	fs := NewFS(NewShake256XOF(fsDigestBytes), proof.Salt, FSParams{Lambda: lambda, Kappa: proof.Kappa})
	material0 := [][]byte{append([]byte(nil), proof.Root[:]...)}
	if len(proof.LabelsDigest) > 0 {
		material0 = append(material0, proof.LabelsDigest)
	}
	seed, err := verifyRoundDigest(fs, 0, proof.Ctr[0], material0, proof.Digests[0], proof.Kappa[0])
	if err != nil {
		return nil, fmt.Errorf("main FS round 0: %w", err)
	}
	pcsOpening := resolveProofPCSOpening(proof)
	return sampleFSMatrix(pcsOpening.Eta, rowCount, q, newFSRNG("Gamma", seed)), nil
}

func deriveProofExplicitDomainPoints(proof *Proof, q uint64, witnessNCols, pcsNCols int) ([]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if proof.DomainMode != DomainModeExplicit {
		return nil, fmt.Errorf("unsupported domain mode %d", proof.DomainMode)
	}
	ell := len(proof.Tail)
	if ell <= 0 {
		return nil, fmt.Errorf("missing proof tail for explicit domain derivation")
	}
	nLeaves := proof.NLeavesUsed
	if nLeaves <= 0 {
		return nil, fmt.Errorf("missing proof nleaves")
	}
	_, domainPoints, err := deriveExplicitDomainForRelation(q, nLeaves, witnessNCols, pcsNCols, ell, proof.HashRelation)
	if err != nil {
		return nil, err
	}
	return domainPoints, nil
}

func prepareSigShortnessOpeningForVerify(
	opening *decs.DECSOpening,
	gamma [][]uint64,
	rPolys []*ring.Poly,
	domainPoints []uint64,
	ringQ *ring.Ring,
) (*decs.DECSOpening, error) {
	if opening == nil {
		return nil, fmt.Errorf("missing sig shortness opening")
	}
	open := expandPackedOpening(opening)
	if open.FormatVersion == 1 {
		return nil, fmt.Errorf("sig shortness P compression is not supported")
	}
	if open.MFormatVersion == 1 {
		if err := reconstructRowOpeningMvals(open, gamma, rPolys, domainPoints, ringQ); err != nil {
			return nil, fmt.Errorf("reconstruct sig shortness M values: %w", err)
		}
	}
	return open, nil
}

func restoreExplicitMerklePaths(dst, src *decs.DECSOpening) {
	if dst == nil || src == nil {
		return
	}
	// Frontier round-tripping is not yet stable for this sparse support-slot
	// opening shape. Keep the residue packing wins while retaining the original
	// explicit Merkle paths for verifier compatibility.
	dst.Nodes = nil
	if len(src.Nodes) > 0 {
		dst.Nodes = make([][]byte, len(src.Nodes))
		for i := range src.Nodes {
			dst.Nodes[i] = append([]byte(nil), src.Nodes[i]...)
		}
	}
	dst.PathIndex = nil
	if len(src.PathIndex) > 0 {
		dst.PathIndex = make([][]int, len(src.PathIndex))
		for i := range src.PathIndex {
			dst.PathIndex[i] = append([]int(nil), src.PathIndex[i]...)
		}
	}
	dst.PathBits = nil
	dst.PathBitWidth = 0
	if len(dst.PathIndex) > 0 {
		dst.PathDepth = len(dst.PathIndex[0])
	} else {
		dst.PathDepth = 0
	}
	dst.FrontierNodes = nil
	dst.FrontierProof = nil
	dst.FrontierLR = nil
	dst.FrontierDepth = 0
	dst.FrontierRefsBits = nil
	dst.FrontierRefWidth = 0
	dst.FrontierRefCount = 0
}

type sigShortnessSupportView struct {
	opening           *decs.DECSOpening
	slotPos           map[int]int
	q                 uint64
	pcsNCols          int
	witnessNCols      int
	rowsPerBlock      int
	replayWitnessRows int
}

func newSigShortnessSupportView(proof *Proof, opening *decs.DECSOpening, supportSlots []int, witnessNCols, pcsNCols, theta int, q uint64) (*sigShortnessSupportView, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if opening == nil {
		return nil, fmt.Errorf("missing shortness opening")
	}
	if err := validateSortedUniqueIndices("sig shortness support slots", supportSlots); err != nil {
		return nil, err
	}
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("invalid witness ncols=%d", witnessNCols)
	}
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	if theta <= 1 {
		return nil, fmt.Errorf("compressed-row sig shortness requires theta>1, got %d", theta)
	}
	replayWitnessRows := proof.PCSGeometry.ReplayWitnessRows
	if replayWitnessRows <= 0 {
		replayWitnessRows = proof.MaskRowOffset
	}
	if replayWitnessRows <= 0 {
		return nil, fmt.Errorf("missing replay witness row count")
	}
	rowsPerBlock := witnessNCols + theta
	if rowsPerBlock <= 0 {
		return nil, fmt.Errorf("invalid rows/block=%d", rowsPerBlock)
	}
	if replayWitnessRows%rowsPerBlock != 0 {
		return nil, fmt.Errorf("replay witness rows=%d not divisible by rows/block=%d", replayWitnessRows, rowsPerBlock)
	}
	open := expandPackedOpening(opening)
	if open.EntryCount() != len(supportSlots) {
		return nil, fmt.Errorf("shortness opening entry count=%d want %d", open.EntryCount(), len(supportSlots))
	}
	openSlots := open.AllIndices()
	if !equalIntSlices(openSlots, supportSlots) {
		return nil, fmt.Errorf("shortness opening slots mismatch")
	}
	if open.R < replayWitnessRows {
		return nil, fmt.Errorf("shortness opening row count=%d want >=%d", open.R, replayWitnessRows)
	}
	slotPos := make(map[int]int, len(supportSlots))
	for i, slot := range supportSlots {
		slotPos[slot] = i
	}
	return &sigShortnessSupportView{
		opening:           open,
		slotPos:           slotPos,
		q:                 q,
		pcsNCols:          pcsNCols,
		witnessNCols:      witnessNCols,
		rowsPerBlock:      rowsPerBlock,
		replayWitnessRows: replayWitnessRows,
	}, nil
}

func (v *sigShortnessSupportView) witnessValue(witnessPolyIdx, omegaRow int) (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("nil shortness support view")
	}
	if witnessPolyIdx < 0 {
		return 0, fmt.Errorf("invalid witness polynomial index %d", witnessPolyIdx)
	}
	if omegaRow < 0 || omegaRow >= v.witnessNCols {
		return 0, fmt.Errorf("invalid omega row %d", omegaRow)
	}
	block := witnessPolyIdx / v.pcsNCols
	slot := witnessPolyIdx % v.pcsNCols
	pos, ok := v.slotPos[slot]
	if !ok {
		return 0, fmt.Errorf("missing support slot %d", slot)
	}
	rowIdx := block*v.rowsPerBlock + omegaRow
	if rowIdx < 0 || rowIdx >= v.replayWitnessRows {
		return 0, fmt.Errorf("witness row overflow for poly=%d block=%d row=%d limit=%d", witnessPolyIdx, block, rowIdx, v.replayWitnessRows)
	}
	return decs.GetOpeningPval(v.opening, pos, rowIdx) % v.q, nil
}

func collectSigShortnessDigitHeads(proof *Proof, view *sigShortnessSupportView, spec LinfSpec) ([][][][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if view == nil {
		return nil, fmt.Errorf("nil support view")
	}
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	if cfg.PackedSigComponents <= 0 || cfg.PackedSigBlocks <= 0 {
		return nil, fmt.Errorf("invalid packed signature layout: comps=%d blocks=%d", cfg.PackedSigComponents, cfg.PackedSigBlocks)
	}
	if spec.L <= 0 {
		return nil, fmt.Errorf("invalid shortness digit count=%d", spec.L)
	}
	out := make([][][][]uint64, cfg.PackedSigComponents)
	for comp := 0; comp < cfg.PackedSigComponents; comp++ {
		out[comp] = make([][][]uint64, cfg.PackedSigBlocks)
		for block := 0; block < cfg.PackedSigBlocks; block++ {
			out[comp][block] = make([][]uint64, spec.L)
			for lane := 0; lane < spec.L; lane++ {
				digitRow := rowLayoutCoeffNativePackedSigLimbIndex(layout, comp, block, lane)
				if digitRow < 0 {
					return nil, fmt.Errorf("invalid packed digit row for comp=%d block=%d lane=%d", comp, block, lane)
				}
				head := make([]uint64, view.witnessNCols)
				for omegaRow := 0; omegaRow < view.witnessNCols; omegaRow++ {
					digitField, err := view.witnessValue(digitRow, omegaRow)
					if err != nil {
						return nil, fmt.Errorf("digit[%d,%d,%d,%d]: %w", comp, block, lane, omegaRow, err)
					}
					head[omegaRow] = digitField % view.q
				}
				out[comp][block][lane] = head
			}
		}
	}
	return out, nil
}

func verifySigShortnessDigitHeads(proof *Proof, spec LinfSpec, sigLimbHeads [][][][]uint64, q uint64) error {
	if proof == nil {
		return fmt.Errorf("nil proof")
	}
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return fmt.Errorf("sig shortness requires literal packed v3 layout")
	}
	if spec.UsesAbsRow {
		return fmt.Errorf("packed raw signature shortness requires signed chain mode")
	}
	wantRowsPer, err := signaturePackedChainRowsPerGroupForOpts(spec, SimOpts{}, layout.PackedSigChainGroupSize)
	if err != nil {
		return fmt.Errorf("rows/group: %w", err)
	}
	if layout.PackedSigChainRowsPerGroup != wantRowsPer {
		return fmt.Errorf("packed shortness rows/group=%d want %d", layout.PackedSigChainRowsPerGroup, wantRowsPer)
	}
	wantGroups := cfg.PackedSigComponents * cfg.PackedSigBlocks
	if layout.PackedSigChainGroupCount != wantGroups {
		return fmt.Errorf("packed shortness group count=%d want %d", layout.PackedSigChainGroupCount, wantGroups)
	}
	for block := 0; block < cfg.PackedSigBlocks; block++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			for omegaRow := 0; omegaRow < len(sigLimbHeads[comp][block][0]); omegaRow++ {
				digits := make([]int64, spec.L)
				rhs := uint64(0)
				for lane := 0; lane < spec.L; lane++ {
					if comp >= len(sigLimbHeads) || block >= len(sigLimbHeads[comp]) || lane >= len(sigLimbHeads[comp][block]) || omegaRow >= len(sigLimbHeads[comp][block][lane]) {
						return fmt.Errorf("missing digit head for comp=%d block=%d lane=%d omega=%d", comp, block, lane, omegaRow)
					}
					digitField := sigLimbHeads[comp][block][lane][omegaRow] % q
					digit := centeredLift(digitField, q)
					if digit < int64(spec.DigitLo[lane]) || digit > int64(spec.DigitHi[lane]) {
						return fmt.Errorf("digit[%d,%d,%d,%d]=%d outside [%d,%d]", comp, block, lane, omegaRow, digit, spec.DigitLo[lane], spec.DigitHi[lane])
					}
					if EvalPoly(spec.PDi[lane], digitField%q, q) != 0 {
						return fmt.Errorf("digit membership failed at comp=%d block=%d lane=%d omega=%d", comp, block, lane, omegaRow)
					}
					digits[lane] = digit
					rhs = lvcs.MulAddMod64(rhs, spec.RPows[lane]%q, digitField%q, q)
				}
				if recomposeLinfDigits(digits, spec) != centeredLift(rhs, q) {
					return fmt.Errorf("signed reconstruction mismatch at comp=%d block=%d omega=%d", comp, block, omegaRow)
				}
			}
		}
	}
	return nil
}

func verifySigShortnessPackedSourceValues(proof *Proof, view *sigShortnessSupportView, spec LinfSpec, sigLimbHeads [][][][]uint64) error {
	if proof == nil {
		return fmt.Errorf("nil proof")
	}
	if view == nil {
		return fmt.Errorf("nil support view")
	}
	if err := verifySigShortnessDigitHeads(proof, spec, sigLimbHeads, view.q); err != nil {
		return err
	}
	layout := proof.RowLayout
	cfg := layout.CoeffNativeSig
	wantGroups := cfg.PackedSigComponents * cfg.PackedSigBlocks
	if cfg.PackedSigCount <= 0 || cfg.PackedSigBase < 0 {
		return nil
	}
	if cfg.PackedSigCount != wantGroups {
		return fmt.Errorf("packed signature source rows=%d want %d", cfg.PackedSigCount, wantGroups)
	}
	for block := 0; block < cfg.PackedSigBlocks; block++ {
		for comp := 0; comp < cfg.PackedSigComponents; comp++ {
			sourceRow := rowLayoutCoeffNativePackedSigIndex(layout, comp, block)
			if sourceRow < 0 {
				return fmt.Errorf("invalid packed source row for comp=%d block=%d", comp, block)
			}
			for omegaRow := 0; omegaRow < view.witnessNCols; omegaRow++ {
				sourceField, err := view.witnessValue(sourceRow, omegaRow)
				if err != nil {
					return fmt.Errorf("source[%d,%d,%d]: %w", comp, block, omegaRow, err)
				}
				rhs := uint64(0)
				for lane := 0; lane < spec.L; lane++ {
					rhs = lvcs.MulAddMod64(rhs, spec.RPows[lane]%view.q, sigLimbHeads[comp][block][lane][omegaRow]%view.q, view.q)
				}
				if rhs%view.q != sourceField%view.q {
					return fmt.Errorf("packed reconstruction failed at comp=%d block=%d omega=%d", comp, block, omegaRow)
				}
			}
		}
	}
	return nil
}

func deriveSigShortnessExpectedTHatHeads(proof *Proof, ringQ *ring.Ring, pub PublicInputs, omegaWitness []uint64, spec LinfSpec, sigLimbHeads [][][][]uint64) ([][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(sigLimbHeads) == 0 || len(sigLimbHeads[0]) == 0 || len(sigLimbHeads[0][0]) == 0 {
		return nil, fmt.Errorf("empty shortness digit heads")
	}
	ncols := len(sigLimbHeads[0][0][0])
	if ncols <= 0 {
		return nil, fmt.Errorf("invalid shortness support width")
	}
	if len(omegaWitness) < ncols {
		return nil, fmt.Errorf("omega witness len=%d < support width=%d", len(omegaWitness), ncols)
	}
	layout := proof.RowLayout
	sourceBlocks := layout.CoeffNativeSig.PackedSigBlocks
	if sourceBlocks <= 0 {
		return nil, fmt.Errorf("invalid packed signature block count=%d", sourceBlocks)
	}
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	if replayTHatCount <= 0 {
		return nil, fmt.Errorf("missing replay T-hat count")
	}
	packedSigHeads := reconstructPackedSigHeadsFromLimbHeads(sigLimbHeads, spec, ringQ.Modulus[0])
	sigHatHeads, err := buildSigHatHeadsFromPackedSigHeads(ringQ, packedSigHeads, ncols)
	if err != nil {
		return nil, fmt.Errorf("build signature hats from digit-backed source heads: %w", err)
	}
	tHatHeads, err := buildTHatHeadsFromSigHatHeads(ringQ, pub, omegaWitness[:ncols], sigHatHeads, replayTHatCount, sourceBlocks)
	if err != nil {
		return nil, fmt.Errorf("build T-hat heads from shortness digits: %w", err)
	}
	return tHatHeads, nil
}

func verifySigShortnessTHatSupportValues(proof *Proof, view *sigShortnessSupportView, expectedTHatHeads [][]uint64) error {
	if proof == nil {
		return fmt.Errorf("nil proof")
	}
	if view == nil {
		return fmt.Errorf("nil support view")
	}
	layout := proof.RowLayout
	replayTHatCount := rowLayoutReplayTHatCount(layout)
	if replayTHatCount <= 0 {
		return fmt.Errorf("missing replay T-hat count")
	}
	if len(expectedTHatHeads) != replayTHatCount {
		return fmt.Errorf("expected T-hat block count=%d want %d", len(expectedTHatHeads), replayTHatCount)
	}
	for block := 0; block < replayTHatCount; block++ {
		tHatRow := rowLayoutPostSignTHatIndex(layout, block)
		if tHatRow < 0 {
			return fmt.Errorf("invalid T-hat row for block %d", block)
		}
		if len(expectedTHatHeads[block]) != view.witnessNCols {
			return fmt.Errorf("expected T-hat width=%d want %d for block %d", len(expectedTHatHeads[block]), view.witnessNCols, block)
		}
		for omegaRow := 0; omegaRow < view.witnessNCols; omegaRow++ {
			got, err := view.witnessValue(tHatRow, omegaRow)
			if err != nil {
				return fmt.Errorf("T-hat[%d,%d]: %w", block, omegaRow, err)
			}
			want := expectedTHatHeads[block][omegaRow] % view.q
			if got%view.q != want {
				return fmt.Errorf("T-hat mismatch at block=%d omega=%d", block, omegaRow)
			}
		}
	}
	return nil
}

func verifySigShortnessSupportValues(proof *Proof, view *sigShortnessSupportView, spec LinfSpec) ([][][][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if view == nil {
		return nil, fmt.Errorf("nil support view")
	}
	sigLimbHeads, err := collectSigShortnessDigitHeads(proof, view, spec)
	if err != nil {
		return nil, err
	}
	if err := verifySigShortnessPackedSourceValues(proof, view, spec, sigLimbHeads); err != nil {
		return nil, err
	}
	return sigLimbHeads, nil
}

func verifySigShortnessDigitOnlySupportValues(proof *Proof, view *sigShortnessSupportView, spec LinfSpec) ([][][][]uint64, error) {
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if view == nil {
		return nil, fmt.Errorf("nil support view")
	}
	sigLimbHeads, err := collectSigShortnessDigitHeads(proof, view, spec)
	if err != nil {
		return nil, err
	}
	if err := verifySigShortnessDigitHeads(proof, spec, sigLimbHeads, view.q); err != nil {
		return nil, err
	}
	return sigLimbHeads, nil
}

func buildSigShortnessProofBase(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	proof *Proof,
	opts SimOpts,
	version int,
) (*SigShortnessProof, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(proof.RowLayout) {
		return nil, nil
	}
	if proof.Theta <= 1 || proof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV1 {
		return nil, nil
	}
	if pk == nil {
		return nil, fmt.Errorf("nil prover key")
	}
	spec, err := signatureChainSpecForLayoutAndOpts(ringQ.Modulus[0], proof.RowLayout, opts)
	if err != nil {
		return nil, fmt.Errorf("signature chain spec: %w", err)
	}
	if _, err := signaturePackedChainRowsPerGroupForOpts(spec, opts, proof.RowLayout.PackedSigChainGroupSize); err != nil {
		return nil, fmt.Errorf("rows/group: %w", err)
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("missing pcs ncols")
	}
	supportSlots, err := buildSigShortnessSupportSlotsForVersion(proof.RowLayout, pcsNCols, version)
	if err != nil {
		return nil, err
	}
	if len(supportSlots) == 0 {
		return nil, nil
	}
	opening := cloneDECSOpening(lvcs.EvalFinish(pk, supportSlots).DECSOpen)
	originalOpening := cloneDECSOpening(opening)
	omitAllRowOpeningMvals(opening)
	decs.PackOpening(opening)
	restoreExplicitMerklePaths(opening, originalOpening)
	return &SigShortnessProof{
		Version:      version,
		SupportSlots: append([]int(nil), supportSlots...),
		Opening:      opening,
	}, nil
}

func buildSigShortnessProofV2(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	proof *Proof,
	omegaWitness []uint64,
	opts SimOpts,
) (*SigShortnessProof, error) {
	sig, err := buildSigShortnessProofBase(ringQ, pk, proof, opts, sigShortnessProofVersionV2)
	if err != nil || sig == nil {
		return sig, err
	}
	proofWithSig := *proof
	proofWithSig.SigShortness = sig
	if err := VerifySigShortnessProofV2(&proofWithSig, ringQ, omegaWitness, opts); err != nil {
		return nil, fmt.Errorf("compressed-row sig shortness verification failed: %w", err)
	}
	return sig, nil
}

func buildSigShortnessProofV3(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	proof *Proof,
	pub PublicInputs,
	omegaWitness []uint64,
	opts SimOpts,
) (*SigShortnessProof, error) {
	sig, err := buildSigShortnessProofBase(ringQ, pk, proof, opts, sigShortnessProofVersionV3)
	if err != nil || sig == nil {
		return sig, err
	}
	proofWithSig := *proof
	proofWithSig.SigShortness = sig
	if err := VerifySigShortnessProof(&proofWithSig, ringQ, omegaWitness, pub, opts); err != nil {
		return nil, fmt.Errorf("compressed-row sig shortness verification failed: %w", err)
	}
	return sig, nil
}

func buildSigShortnessProofV4(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	proof *Proof,
	pub PublicInputs,
	omegaWitness []uint64,
	opts SimOpts,
) (*SigShortnessProof, error) {
	sig, err := buildSigShortnessProofBase(ringQ, pk, proof, opts, sigShortnessProofVersionV4)
	if err != nil || sig == nil {
		return sig, err
	}
	proofWithSig := *proof
	proofWithSig.SigShortness = sig
	if err := VerifySigShortnessProof(&proofWithSig, ringQ, omegaWitness, pub, opts); err != nil {
		return nil, fmt.Errorf("compressed-row sig shortness verification failed: %w", err)
	}
	return sig, nil
}

func prepareSigShortnessVerifyBase(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, opts SimOpts, version int) (*sigShortnessSupportView, LinfSpec, error) {
	if proof == nil || proof.SigShortness == nil {
		return nil, LinfSpec{}, nil
	}
	sig := proof.SigShortness
	if sig.Version != version {
		return nil, LinfSpec{}, fmt.Errorf("unsupported sig shortness version %d", sig.Version)
	}
	if ringQ == nil {
		return nil, LinfSpec{}, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(proof.RowLayout) {
		return nil, LinfSpec{}, fmt.Errorf("sig shortness V%d requires literal packed v3 layout", version)
	}
	if proof.Theta <= 1 || proof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV1 {
		return nil, LinfSpec{}, fmt.Errorf("sig shortness V%d requires compressed-row small-field geometry", version)
	}
	if sig.Opening == nil {
		return nil, LinfSpec{}, fmt.Errorf("missing sig shortness opening")
	}
	if err := validateSortedUniqueIndices("sig shortness support slots", sig.SupportSlots); err != nil {
		return nil, LinfSpec{}, err
	}
	q := ringQ.Modulus[0]
	spec, err := signatureChainSpecForLayoutAndOpts(q, proof.RowLayout, opts)
	if err != nil {
		return nil, LinfSpec{}, fmt.Errorf("signature chain spec: %w", err)
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		return nil, LinfSpec{}, fmt.Errorf("missing pcs ncols")
	}
	expectedSlots, err := buildSigShortnessSupportSlotsForVersion(proof.RowLayout, pcsNCols, version)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	if !equalIntSlices(expectedSlots, sig.SupportSlots) {
		return nil, LinfSpec{}, fmt.Errorf("sig shortness support slots mismatch")
	}
	witnessNCols := proof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = len(omegaWitness)
	}
	if witnessNCols <= 0 {
		return nil, LinfSpec{}, fmt.Errorf("missing witness support width")
	}
	params, rowCount, err := deriveMainPCSSubsetParams(proof)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	gamma, err := deriveMainPCSSubsetGamma(proof, rowCount, q)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	domainPoints, err := deriveProofExplicitDomainPoints(proof, q, witnessNCols, pcsNCols)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	rPolys := make([]*ring.Poly, len(proof.R))
	for i := range proof.R {
		rPolys[i] = coeffsToNTTIfFits(ringQ, proof.R[i])
		if rPolys[i] == nil {
			return nil, LinfSpec{}, fmt.Errorf("R polynomial %d too large to materialize", i)
		}
	}
	opening, err := prepareSigShortnessOpeningForVerify(sig.Opening, gamma, rPolys, domainPoints, ringQ)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	if err := verifyDECSSubset(ringQ, proof.Root, params, gamma, rPolys, opening, sig.SupportSlots, domainPoints); err != nil {
		return nil, LinfSpec{}, fmt.Errorf("sig shortness opening rejected: %w", err)
	}
	theta := proof.Theta
	if theta <= 1 {
		theta = proof.PCSGeometry.Theta
	}
	view, err := newSigShortnessSupportView(proof, opening, sig.SupportSlots, witnessNCols, pcsNCols, theta, q)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	return view, spec, nil
}

func VerifySigShortnessProof(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	switch proof.SigShortness.Version {
	case sigShortnessProofVersionV2:
		return VerifySigShortnessProofV2(proof, ringQ, omegaWitness, opts)
	case sigShortnessProofVersionV3:
		return VerifySigShortnessProofV3(proof, ringQ, omegaWitness, pub, opts)
	case sigShortnessProofVersionV4:
		return VerifySigShortnessProofV4(proof, ringQ, omegaWitness, pub, opts)
	default:
		return fmt.Errorf("unsupported sig shortness version %d", proof.SigShortness.Version)
	}
}

func VerifySigShortnessProofV2(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, opts SimOpts) error {
	view, spec, err := prepareSigShortnessVerifyBase(proof, ringQ, omegaWitness, opts, sigShortnessProofVersionV2)
	if err != nil {
		return err
	}
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	if _, err := verifySigShortnessSupportValues(proof, view, spec); err != nil {
		return fmt.Errorf("sig shortness values rejected: %w", err)
	}
	return nil
}

func VerifySigShortnessProofV3(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	view, spec, err := prepareSigShortnessVerifyBase(proof, ringQ, omegaWitness, opts, sigShortnessProofVersionV3)
	if err != nil {
		return err
	}
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sigLimbHeads, err := verifySigShortnessSupportValues(proof, view, spec)
	if err != nil {
		return fmt.Errorf("sig shortness values rejected: %w", err)
	}
	expectedTHatHeads, err := deriveSigShortnessExpectedTHatHeads(proof, ringQ, pub, omegaWitness, spec, sigLimbHeads)
	if err != nil {
		return fmt.Errorf("sig shortness T-hat derivation failed: %w", err)
	}
	if err := verifySigShortnessTHatSupportValues(proof, view, expectedTHatHeads); err != nil {
		return fmt.Errorf("sig shortness T-hat values rejected: %w", err)
	}
	return nil
}

func VerifySigShortnessProofV4(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	view, spec, err := prepareSigShortnessVerifyBase(proof, ringQ, omegaWitness, opts, sigShortnessProofVersionV4)
	if err != nil {
		return err
	}
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sigLimbHeads, err := verifySigShortnessDigitOnlySupportValues(proof, view, spec)
	if err != nil {
		return fmt.Errorf("sig shortness values rejected: %w", err)
	}
	expectedTHatHeads, err := deriveSigShortnessExpectedTHatHeads(proof, ringQ, pub, omegaWitness, spec, sigLimbHeads)
	if err != nil {
		return fmt.Errorf("sig shortness T-hat derivation failed: %w", err)
	}
	if err := verifySigShortnessTHatSupportValues(proof, view, expectedTHatHeads); err != nil {
		return fmt.Errorf("sig shortness T-hat values rejected: %w", err)
	}
	return nil
}
