package PIOP

import (
	"crypto/sha256"
	"encoding/binary"
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
	sigShortnessProofVersionV5 = 5

	sigShortnessV5ModeExactSigHeads uint8 = 1
)

func buildSigShortnessWitnessPolyIndices(layout RowLayout) []int {
	return buildSigShortnessWitnessPolyIndicesForVersion(layout, sigShortnessProofVersionV2)
}

func buildSigShortnessWitnessPolyIndicesForVersion(layout RowLayout, version int) []int {
	rows := make([]int, 0, rowLayoutReplayTHatCount(layout)+layout.CoeffNativeSig.PackedSigCount+layout.PackedSigChainGroupCount*layout.PackedSigChainRowsPerGroup)
	if version >= sigShortnessProofVersionV3 {
		rows = append(rows, buildSigShortnessTHatWitnessRows(layout)...)
	}
	if version < sigShortnessProofVersionV4 && layout.CoeffNativeSig.PackedSigBase >= 0 && layout.CoeffNativeSig.PackedSigCount > 0 {
		for i := 0; i < layout.CoeffNativeSig.PackedSigCount; i++ {
			rows = append(rows, layout.CoeffNativeSig.PackedSigBase+i)
		}
	}
	if version < sigShortnessProofVersionV5 && layout.PackedSigChainBase >= 0 && layout.PackedSigChainRowsPerGroup > 0 {
		chainRows := layout.PackedSigChainGroupCount * layout.PackedSigChainRowsPerGroup
		for i := 0; i < chainRows; i++ {
			rows = append(rows, layout.PackedSigChainBase+i)
		}
	}
	return rows
}

func buildSigShortnessTHatWitnessRows(layout RowLayout) []int {
	tHatBase := rowLayoutPostSignTHatBase(layout)
	tHatCount := rowLayoutReplayTHatCount(layout)
	if tHatBase < 0 || tHatCount <= 0 {
		return nil
	}
	rows := make([]int, tHatCount)
	for i := range rows {
		rows[i] = tHatBase + i
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

func appendSigShortnessUvarint(dst []byte, v int) []byte {
	if v < 0 {
		v = 0
	}
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(v))
	return append(dst, buf[:n]...)
}

func sigShortnessV5WitnessNColsFromProof(proof *Proof) int {
	if proof == nil {
		return 0
	}
	if proof.NColsUsed > 0 {
		return proof.NColsUsed
	}
	return proof.RowLayout.CoeffNativeSig.PackedSigBlockWidth
}

func buildSigShortnessV5BindingDigest(sig *SigShortnessProof, layout RowLayout, witnessNCols int) ([]byte, error) {
	if sig == nil || sig.Version != sigShortnessProofVersionV5 || sig.V5 == nil {
		return nil, nil
	}
	if sig.SupportSlots != nil || sig.Opening != nil {
		return nil, fmt.Errorf("sig shortness V5 must not populate legacy opening fields")
	}
	cfg := layout.CoeffNativeSig
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("missing witness ncols for sig shortness V5 binding")
	}
	if cfg.PackedSigComponents <= 0 || cfg.PackedSigBlocks <= 0 || cfg.PackedSigBlockWidth <= 0 {
		return nil, fmt.Errorf("invalid literal packed coeff-native layout: comps=%d blocks=%d width=%d", cfg.PackedSigComponents, cfg.PackedSigBlocks, cfg.PackedSigBlockWidth)
	}
	buf := make([]byte, 0, len(sig.V5.ExactHeads.Bits)+128)
	buf = append(buf, []byte("spruce.sig_shortness.v5/exact_sig_heads_v1")...)
	buf = appendSigShortnessUvarint(buf, int(sig.V5.Mode))
	buf = appendSigShortnessUvarint(buf, sig.V5.Radix)
	buf = appendSigShortnessUvarint(buf, sig.V5.Digits)
	buf = appendSigShortnessUvarint(buf, witnessNCols)
	buf = appendSigShortnessUvarint(buf, cfg.PackedSigComponents)
	buf = appendSigShortnessUvarint(buf, cfg.PackedSigBlocks)
	buf = appendSigShortnessUvarint(buf, cfg.PackedSigBlockWidth)
	buf = appendSigShortnessUvarint(buf, rowLayoutReplayTHatCount(layout))
	buf = append(buf, sig.V5.ExactHeads.BitWidth)
	buf = appendSigShortnessUvarint(buf, len(sig.V5.ExactHeads.Bits))
	buf = append(buf, sig.V5.ExactHeads.Bits...)
	sum := sha256.Sum256(buf)
	return append([]byte(nil), sum[:]...), nil
}

func packSigShortnessV5ExactHeads(sigHeads [][][]uint64) (SigShortnessPackedMatrix, error) {
	if len(sigHeads) == 0 {
		return SigShortnessPackedMatrix{}, fmt.Errorf("empty signature heads")
	}
	rows := make([][]uint64, 0, len(sigHeads)*len(sigHeads[0]))
	for comp := range sigHeads {
		for block := range sigHeads[comp] {
			rows = append(rows, append([]uint64(nil), sigHeads[comp][block]...))
		}
	}
	bits, _, _, width := decs.PackUintMatrix(rows)
	return SigShortnessPackedMatrix{
		Bits:     bits,
		BitWidth: uint8(width),
	}, nil
}

func unpackSigShortnessV5ExactHeads(layout RowLayout, packed SigShortnessPackedMatrix) ([][][]uint64, error) {
	cfg := layout.CoeffNativeSig
	if cfg.PackedSigComponents <= 0 || cfg.PackedSigBlocks <= 0 || cfg.PackedSigBlockWidth <= 0 {
		return nil, fmt.Errorf("invalid packed signature layout: comps=%d blocks=%d width=%d", cfg.PackedSigComponents, cfg.PackedSigBlocks, cfg.PackedSigBlockWidth)
	}
	rows, gotRows, gotCols, gotWidth, err := decs.UnpackUintMatrix(packed.Bits)
	if err != nil {
		return nil, fmt.Errorf("unpack exact sig heads: %w", err)
	}
	wantRows := cfg.PackedSigComponents * cfg.PackedSigBlocks
	wantCols := cfg.PackedSigBlockWidth
	if gotRows != wantRows || gotCols != wantCols {
		return nil, fmt.Errorf("exact sig heads dims=%dx%d want %dx%d", gotRows, gotCols, wantRows, wantCols)
	}
	if packed.BitWidth != 0 && uint8(gotWidth) != packed.BitWidth {
		return nil, fmt.Errorf("exact sig heads bit width=%d want %d", gotWidth, packed.BitWidth)
	}
	out := make([][][]uint64, cfg.PackedSigComponents)
	row := 0
	for comp := 0; comp < cfg.PackedSigComponents; comp++ {
		out[comp] = make([][]uint64, cfg.PackedSigBlocks)
		for block := 0; block < cfg.PackedSigBlocks; block++ {
			out[comp][block] = append([]uint64(nil), rows[row]...)
			row++
		}
	}
	return out, nil
}

func buildSigShortnessV5THatOpening(
	pk *lvcs.ProverKey,
	root [16]byte,
	layout RowLayout,
	pcsNCols int,
) ([]int, *decs.DECSOpening, error) {
	if pk == nil {
		return nil, nil, fmt.Errorf("nil prover key")
	}
	rows := buildSigShortnessTHatWitnessRows(layout)
	if len(rows) == 0 {
		return nil, nil, fmt.Errorf("missing replay T-hat rows")
	}
	slots, err := buildSigShortnessSupportSlotsForRows(rows, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	opening := cloneDECSOpening(lvcs.EvalFinish(pk, slots).DECSOpen)
	omitAllRowOpeningMvals(opening)
	decs.PackOpening(opening)
	return slots, opening, nil
}

func validateSigShortnessV5Shape(proof *Proof) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	sig := proof.SigShortness
	if sig.Version != sigShortnessProofVersionV5 {
		return nil
	}
	if sig.V5 == nil {
		return fmt.Errorf("missing sig shortness V5 payload")
	}
	if len(sig.SupportSlots) != 0 || sig.Opening != nil {
		return fmt.Errorf("sig shortness V5 must not populate legacy opening fields")
	}
	if sig.V5.Mode != sigShortnessV5ModeExactSigHeads {
		return fmt.Errorf("unsupported sig shortness V5 mode %d", sig.V5.Mode)
	}
	if sig.V5.THatOpening == nil {
		return fmt.Errorf("missing sig shortness V5 T-hat opening")
	}
	return nil
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
	if digest, err := buildSigShortnessV5BindingDigest(proof.SigShortness, proof.RowLayout, sigShortnessV5WitnessNColsFromProof(proof)); err != nil {
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
	replayWitnessRows int,
) (*decs.DECSOpening, error) {
	if opening == nil {
		return nil, fmt.Errorf("missing sig shortness opening")
	}
	open := expandPackedOpening(opening)
	if open.FormatVersion == 1 {
		if err := reconstructSigShortnessOpeningPvals(open, replayWitnessRows); err != nil {
			return nil, fmt.Errorf("reconstruct sig shortness P values: %w", err)
		}
	}
	if open.MFormatVersion == 1 {
		if err := reconstructRowOpeningMvals(open, gamma, rPolys, domainPoints, ringQ); err != nil {
			return nil, fmt.Errorf("reconstruct sig shortness M values: %w", err)
		}
	}
	return open, nil
}

func sigShortnessReplayWitnessRows(proof *Proof) (int, error) {
	if proof == nil {
		return 0, fmt.Errorf("nil proof")
	}
	replayWitnessRows := proof.PCSGeometry.ReplayWitnessRows
	if replayWitnessRows <= 0 {
		replayWitnessRows = proof.MaskRowOffset
	}
	if replayWitnessRows <= 0 {
		return 0, fmt.Errorf("missing replay witness row count")
	}
	return replayWitnessRows, nil
}

func maybeCompressSigShortnessOpeningPvals(open *decs.DECSOpening, replayWitnessRows int) error {
	if open == nil || len(open.Pvals) == 0 {
		return nil
	}
	if open.R <= 0 {
		return fmt.Errorf("invalid shortness opening row count R=%d", open.R)
	}
	if replayWitnessRows <= 0 || replayWitnessRows >= open.R {
		return nil
	}
	omitCols := make([]int, open.R-replayWitnessRows)
	for i := range omitCols {
		omitCols[i] = replayWitnessRows + i
	}
	compressed := make([][]uint64, len(open.Pvals))
	canCompress := true
	for t := range open.Pvals {
		if len(open.Pvals[t]) != open.R {
			return fmt.Errorf("shortness opening P row %d width=%d want=%d", t, len(open.Pvals[t]), open.R)
		}
		for _, col := range omitCols {
			if open.Pvals[t][col] != 0 {
				canCompress = false
				break
			}
		}
		if !canCompress {
			break
		}
		compressed[t] = append([]uint64(nil), open.Pvals[t][:replayWitnessRows]...)
	}
	if !canCompress {
		return nil
	}
	open.FormatVersion = 1
	open.PColsEncoded = replayWitnessRows
	open.POmitCols = omitCols
	open.Pvals = compressed
	return nil
}

func reconstructSigShortnessOpeningPvals(open *decs.DECSOpening, replayWitnessRows int) error {
	if open == nil {
		return fmt.Errorf("nil opening")
	}
	if open.FormatVersion != 1 {
		return nil
	}
	if open.R <= 0 {
		return fmt.Errorf("invalid shortness opening row count R=%d", open.R)
	}
	if replayWitnessRows <= 0 || replayWitnessRows >= open.R {
		return fmt.Errorf("invalid shortness replay witness rows=%d for R=%d", replayWitnessRows, open.R)
	}
	expectedOmit := make([]int, open.R-replayWitnessRows)
	for i := range expectedOmit {
		expectedOmit[i] = replayWitnessRows + i
	}
	if !equalIntSlices(open.POmitCols, expectedOmit) {
		return fmt.Errorf("shortness opening POmitCols=%v want %v", open.POmitCols, expectedOmit)
	}
	if open.PColsEncoded != replayWitnessRows {
		return fmt.Errorf("shortness opening PColsEncoded=%d want %d", open.PColsEncoded, replayWitnessRows)
	}
	if len(open.Pvals) != open.EntryCount() {
		return fmt.Errorf("shortness opening P row count=%d want=%d", len(open.Pvals), open.EntryCount())
	}
	fullRows := make([][]uint64, open.EntryCount())
	for t := range open.Pvals {
		if len(open.Pvals[t]) != replayWitnessRows {
			return fmt.Errorf("shortness opening P row %d width=%d want=%d", t, len(open.Pvals[t]), replayWitnessRows)
		}
		full := make([]uint64, open.R)
		copy(full, open.Pvals[t])
		fullRows[t] = full
	}
	open.Pvals = fullRows
	open.PvalsBits = nil
	open.PvalsBitWidth = 0
	open.FormatVersion = 0
	open.PColsEncoded = 0
	open.POmitCols = nil
	return nil
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
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, err
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
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, err
	}
	if err := maybeCompressSigShortnessOpeningPvals(opening, replayWitnessRows); err != nil {
		return nil, err
	}
	omitAllRowOpeningMvals(opening)
	decs.PackOpening(opening)
	restoreExplicitMerklePaths(opening, originalOpening)
	return &SigShortnessProof{
		Version:      version,
		SupportSlots: append([]int(nil), supportSlots...),
		Opening:      opening,
	}, nil
}

func restoreExplicitMerklePaths(dst, src *decs.DECSOpening) {
	if dst == nil || src == nil {
		return
	}
	if len(src.Nodes) == 0 || len(src.PathIndex) == 0 {
		return
	}
	dst.Nodes = make([][]byte, len(src.Nodes))
	for i := range src.Nodes {
		dst.Nodes[i] = append([]byte(nil), src.Nodes[i]...)
	}
	dst.PathIndex = make([][]int, len(src.PathIndex))
	for i := range src.PathIndex {
		dst.PathIndex[i] = append([]int(nil), src.PathIndex[i]...)
	}
	dst.PathBits = nil
	dst.PathBitWidth = 0
	dst.PathDepth = 0
	dst.FrontierNodes = nil
	dst.FrontierProof = nil
	dst.FrontierLR = nil
	dst.FrontierDepth = 0
	dst.FrontierRefsBits = nil
	dst.FrontierRefWidth = 0
	dst.FrontierRefCount = 0
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

func buildSigShortnessProofV5(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	root [16]byte,
	layout RowLayout,
	cn *CoeffNativeShowingWitness,
	omegaWitness []uint64,
	witnessNCols int,
	pcsNCols int,
	opts SimOpts,
) (*SigShortnessProof, []byte, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if pk == nil {
		return nil, nil, fmt.Errorf("nil prover key")
	}
	if cn == nil {
		return nil, nil, fmt.Errorf("nil coeff-native showing witness")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(layout) {
		return nil, nil, fmt.Errorf("sig shortness V5 requires literal packed v3 layout")
	}
	if witnessNCols <= 0 {
		return nil, nil, fmt.Errorf("invalid witness ncols=%d", witnessNCols)
	}
	if len(omegaWitness) != witnessNCols {
		return nil, nil, fmt.Errorf("omega witness len=%d want %d", len(omegaWitness), witnessNCols)
	}
	if pcsNCols <= 0 {
		return nil, nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	model := layout.CoeffNativeSig.Model
	if model == "" {
		model = resolveCoeffNativeSigModel(opts)
	}
	packedWitness, err := buildLiteralPackedPolyWitness(ringQ, cn, omegaWitness, witnessNCols, model, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("literal packed witness: %w", err)
	}
	exactHeads, err := packSigShortnessV5ExactHeads(packedWitness.SigHeads)
	if err != nil {
		return nil, nil, err
	}
	radix, digits, _, _, err := ResolveSignatureShortnessMetricsForOpts(ringQ.Modulus[0], opts)
	if err != nil {
		return nil, nil, fmt.Errorf("signature shortness metrics: %w", err)
	}
	_, tHatOpening, err := buildSigShortnessV5THatOpening(pk, root, layout, pcsNCols)
	if err != nil {
		return nil, nil, fmt.Errorf("build sig shortness V5 T-hat opening: %w", err)
	}
	sig := &SigShortnessProof{
		Version: sigShortnessProofVersionV5,
		V5: &SigShortnessProofV5{
			Mode:        sigShortnessV5ModeExactSigHeads,
			Radix:       radix,
			Digits:      digits,
			ExactHeads:  exactHeads,
			THatOpening: tHatOpening,
		},
	}
	digest, err := buildSigShortnessV5BindingDigest(sig, layout, witnessNCols)
	if err != nil {
		return nil, nil, err
	}
	return sig, digest, nil
}

func prepareSigShortnessV5THatView(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64) (*sigShortnessSupportView, error) {
	if proof == nil || proof.SigShortness == nil {
		return nil, nil
	}
	if err := validateSigShortnessV5Shape(proof); err != nil {
		return nil, err
	}
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !rowLayoutCoeffNativeUsesLiteralPackedV3(proof.RowLayout) {
		return nil, fmt.Errorf("sig shortness V5 requires literal packed v3 layout")
	}
	if proof.Theta <= 1 || proof.PCSGeometry.Kind != PCSGeometryKindSmallFieldMatrixV1 {
		return nil, fmt.Errorf("sig shortness V5 requires compressed-row small-field geometry")
	}
	witnessNCols := proof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = len(omegaWitness)
	}
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("missing witness support width")
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("missing pcs ncols")
	}
	slots, err := buildSigShortnessSupportSlotsForRows(buildSigShortnessTHatWitnessRows(proof.RowLayout), pcsNCols)
	if err != nil {
		return nil, err
	}
	params, rowCount, err := deriveMainPCSSubsetParams(proof)
	if err != nil {
		return nil, err
	}
	gamma, err := deriveMainPCSSubsetGamma(proof, rowCount, ringQ.Modulus[0])
	if err != nil {
		return nil, err
	}
	domainPoints, err := deriveProofExplicitDomainPoints(proof, ringQ.Modulus[0], witnessNCols, pcsNCols)
	if err != nil {
		return nil, err
	}
	rPolys := make([]*ring.Poly, len(proof.R))
	for i := range proof.R {
		rPolys[i] = coeffsToNTTIfFits(ringQ, proof.R[i])
		if rPolys[i] == nil {
			return nil, fmt.Errorf("R polynomial %d too large to materialize", i)
		}
	}
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, err
	}
	opening, err := prepareSigShortnessOpeningForVerify(proof.SigShortness.V5.THatOpening, gamma, rPolys, domainPoints, ringQ, replayWitnessRows)
	if err != nil {
		return nil, err
	}
	if err := verifyDECSSubset(ringQ, proof.Root, params, gamma, rPolys, opening, slots, domainPoints); err != nil {
		return nil, fmt.Errorf("sig shortness V5 T-hat opening rejected: %w", err)
	}
	theta := proof.Theta
	if theta <= 1 {
		theta = proof.PCSGeometry.Theta
	}
	return newSigShortnessSupportView(proof, opening, slots, witnessNCols, pcsNCols, theta, ringQ.Modulus[0])
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
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, LinfSpec{}, err
	}
	opening, err := prepareSigShortnessOpeningForVerify(sig.Opening, gamma, rPolys, domainPoints, ringQ, replayWitnessRows)
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
	case sigShortnessProofVersionV5:
		return VerifySigShortnessProofV5(proof, ringQ, omegaWitness, pub, opts)
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

func VerifySigShortnessProofV5(proof *Proof, ringQ *ring.Ring, omegaWitness []uint64, pub PublicInputs, opts SimOpts) error {
	if proof == nil || proof.SigShortness == nil {
		return nil
	}
	if err := validateSigShortnessV5Shape(proof); err != nil {
		return err
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	q := ringQ.Modulus[0]
	spec, err := signatureChainSpecForLayoutAndOpts(q, proof.RowLayout, opts)
	if err != nil {
		return fmt.Errorf("signature chain spec: %w", err)
	}
	v5 := proof.SigShortness.V5
	if v5.Radix != int(spec.R) {
		return fmt.Errorf("sig shortness V5 radix=%d want %d", v5.Radix, spec.R)
	}
	if v5.Digits != spec.L {
		return fmt.Errorf("sig shortness V5 digits=%d want %d", v5.Digits, spec.L)
	}
	sigHeads, err := unpackSigShortnessV5ExactHeads(proof.RowLayout, v5.ExactHeads)
	if err != nil {
		return err
	}
	for comp := range sigHeads {
		for block := range sigHeads[comp] {
			for col, value := range sigHeads[comp][block] {
				if _, err := decomposeLinfDigitsSigned(centeredLift(value, q), spec); err != nil {
					return fmt.Errorf("sig shortness V5 exact head[%d,%d,%d] rejected: %w", comp, block, col, err)
				}
			}
		}
	}
	view, err := prepareSigShortnessV5THatView(proof, ringQ, omegaWitness)
	if err != nil {
		return err
	}
	if view == nil {
		return nil
	}
	if len(omegaWitness) < view.witnessNCols {
		return fmt.Errorf("omega witness len=%d want >=%d", len(omegaWitness), view.witnessNCols)
	}
	sigHatHeads, err := buildSigHatHeadsFromPackedSigHeads(ringQ, sigHeads, view.witnessNCols)
	if err != nil {
		return fmt.Errorf("sig shortness V5 sig-hat derivation failed: %w", err)
	}
	sourceBlocks := proof.RowLayout.CoeffNativeSig.PackedSigBlocks
	expectedTHatHeads, err := buildTHatHeadsFromSigHatHeads(ringQ, pub, omegaWitness[:view.witnessNCols], sigHatHeads, rowLayoutReplayTHatCount(proof.RowLayout), sourceBlocks)
	if err != nil {
		return fmt.Errorf("sig shortness V5 T-hat derivation failed: %w", err)
	}
	for block := 0; block < len(expectedTHatHeads); block++ {
		tHatRow := rowLayoutPostSignTHatIndex(proof.RowLayout, block)
		if tHatRow < 0 {
			return fmt.Errorf("invalid replay T-hat row for block %d", block)
		}
		for omegaRow := 0; omegaRow < view.witnessNCols; omegaRow++ {
			got, err := view.witnessValue(tHatRow, omegaRow)
			if err != nil {
				return fmt.Errorf("sig shortness V5 T-hat[%d,%d]: %w", block, omegaRow, err)
			}
			want := expectedTHatHeads[block][omegaRow] % q
			if got != want {
				return fmt.Errorf("sig shortness V5 T-hat[%d,%d]=%d want %d", block, omegaRow, got, want)
			}
		}
	}
	return nil
}
