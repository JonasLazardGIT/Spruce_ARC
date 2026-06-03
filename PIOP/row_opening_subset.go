package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Research helper for reconstructing witness rows from the main PCS opening.
// The stable baseline verifier uses it only for retained PRF control paths and
// study work, not as a generic extraction mechanism.
type maskSubsetRowRecovery struct {
	Opening     *decs.DECSOpening
	MaskBase    int
	MaskIndices []int
	MaskPoints  []uint64
}

type maskSubsetWitnessView struct {
	q                 uint64
	pcsOmega          []uint64
	pcsNCols          int
	witnessNCols      int
	rowsPerBlock      int
	replayWitnessRows int
	rowCoeffs         map[int][]uint64
}

func prepareMaskSubsetRowRecovery(
	ringQ *ring.Ring,
	proof *Proof,
	omegaWitness []uint64,
	domainPoints []uint64,
) (*maskSubsetRowRecovery, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	baseOpening := resolveProofPCSOpening(proof)
	if baseOpening == nil {
		return nil, fmt.Errorf("missing row opening for direct-auth verification")
	}
	maskBase := baseOpening.MaskBase
	maskCount := baseOpening.MaskCount
	ncols := proof.NColsUsed
	if ncols <= 0 {
		ncols = len(omegaWitness)
	}
	if maskCount <= 0 {
		maskBase = ncols
		if maskBase <= 0 {
			maskBase = len(omegaWitness)
		}
		maskCount = len(proof.Tail)
	}
	if maskBase <= 0 {
		return nil, fmt.Errorf("missing witness width for direct-auth verification")
	}
	if maskCount <= 0 {
		return nil, fmt.Errorf("missing mask count for direct-auth verification")
	}
	maskIdx := make([]int, maskCount)
	for i := 0; i < maskCount; i++ {
		maskIdx[i] = maskBase + i
	}
	params, rowCount, err := deriveMainPCSSubsetParams(proof)
	if err != nil {
		return nil, err
	}
	gamma, err := deriveMainPCSSubsetGamma(proof, rowCount, ringQ.Modulus[0])
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
	coeffMatrix := proof.CoeffMatrix
	if len(coeffMatrix) == 0 {
		return nil, fmt.Errorf("missing coefficient matrix for direct-auth verification")
	}
	barSets := proof.BarSetsMatrix()
	if len(barSets) == 0 {
		return nil, fmt.Errorf("missing bar sets for direct-auth verification")
	}
	vTargets := proof.VTargetsMatrix()
	if len(vTargets) == 0 {
		return nil, fmt.Errorf("missing vtargets for direct-auth verification")
	}
	qVals, err := interpolateReplayQRows(ringQ, vTargets, barSets, ncols)
	if err != nil {
		return nil, fmt.Errorf("replay Q rows for direct-auth verification: %w", err)
	}
	opening, err := prepareRowOpeningForVerify(baseOpening, gamma, rPolys, coeffMatrix, qVals, barSets, maskIdx, proof.Tail, ncols, domainPoints, ringQ)
	if err != nil {
		return nil, err
	}
	subsetIdx := append(append([]int(nil), maskIdx...), proof.Tail...)
	opening, err = buildSubsetOpening(opening, subsetIdx, rowCount, params.Eta)
	if err != nil {
		return nil, fmt.Errorf("direct-auth subset opening: %w", err)
	}
	q := ringQ.Modulus[0]
	maskPoints := make([]uint64, opening.EntryCount())
	indexPos := make(map[int]int, opening.EntryCount())
	for pos := 0; pos < opening.EntryCount(); pos++ {
		indexPos[opening.IndexAt(pos)] = pos
	}
	for i, idx := range opening.AllIndices() {
		if idx < 0 || idx >= len(domainPoints) {
			return nil, fmt.Errorf("mask domain index %d out of range", idx)
		}
		if _, ok := indexPos[idx]; !ok {
			return nil, fmt.Errorf("row opening missing mask index %d", idx)
		}
		maskPoints[i] = domainPoints[idx] % q
	}
	return &maskSubsetRowRecovery{
		Opening:     opening,
		MaskBase:    maskBase,
		MaskIndices: opening.AllIndices(),
		MaskPoints:  maskPoints,
	}, nil
}

func recoverLowDegreeRowsFromMaskSubset(
	ringQ *ring.Ring,
	proof *Proof,
	rowIndices []int,
	omegaWitness []uint64,
	domainPoints []uint64,
) (map[int][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	rowIndices = sortedUniqueInts(rowIndices)
	if len(rowIndices) == 0 {
		return map[int][]uint64{}, nil
	}
	prepared, err := prepareMaskSubsetRowRecovery(ringQ, proof, omegaWitness, domainPoints)
	if err != nil {
		return nil, err
	}
	if len(prepared.MaskPoints) == 0 {
		return nil, fmt.Errorf("empty mask point set for direct-auth verification")
	}
	indexPos := make(map[int]int, prepared.Opening.EntryCount())
	for pos := 0; pos < prepared.Opening.EntryCount(); pos++ {
		indexPos[prepared.Opening.IndexAt(pos)] = pos
	}
	entryWidth := 0
	if len(prepared.Opening.Pvals) > 0 {
		entryWidth = len(prepared.Opening.Pvals[0])
	}
	q := ringQ.Modulus[0]
	out := make(map[int][]uint64, len(rowIndices))
	for _, rowIdx := range rowIndices {
		if rowIdx < 0 {
			return nil, fmt.Errorf("direct-auth recovery row index %d is negative", rowIdx)
		}
		if rowIdx >= entryWidth {
			return nil, fmt.Errorf("direct-auth recovery row idx %d out of range for opening width=%d", rowIdx, entryWidth)
		}
		values := make([]uint64, len(prepared.MaskIndices))
		for i, maskIdx := range prepared.MaskIndices {
			pos := indexPos[maskIdx]
			values[i] = prepared.Opening.Pvals[pos][rowIdx] % q
		}
		out[rowIdx] = trimPoly(Interpolate(prepared.MaskPoints, values, q), q)
	}
	return out, nil
}

func prepareMaskSubsetWitnessView(
	ringQ *ring.Ring,
	proof *Proof,
	witnessPolyIndices []int,
	omegaWitness []uint64,
	domainPoints []uint64,
) (*maskSubsetWitnessView, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if proof == nil {
		return nil, fmt.Errorf("nil proof")
	}
	witnessNCols := proof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = len(omegaWitness)
	}
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("missing witness ncols for direct-auth witness view")
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("missing pcs ncols for direct-auth witness view")
	}
	if len(domainPoints) < pcsNCols {
		return nil, fmt.Errorf("direct-auth witness view domain width=%d < pcs ncols=%d", len(domainPoints), pcsNCols)
	}
	theta := proof.Theta
	if theta <= 1 {
		theta = proof.PCSGeometry.Theta
	}
	if theta <= 1 {
		return nil, fmt.Errorf("direct-auth witness view requires theta>1")
	}
	replayWitnessRows := proof.PCSGeometry.ReplayWitnessRows
	if replayWitnessRows <= 0 {
		replayWitnessRows = proof.MaskRowOffset
	}
	if replayWitnessRows <= 0 {
		return nil, fmt.Errorf("missing replay witness row count for direct-auth witness view")
	}
	rowsPerBlock := witnessNCols + theta
	if rowsPerBlock <= 0 || replayWitnessRows%rowsPerBlock != 0 {
		return nil, fmt.Errorf("invalid replay witness geometry rows=%d rowsPerBlock=%d", replayWitnessRows, rowsPerBlock)
	}
	smallFieldRows := make([]int, 0, len(witnessPolyIndices)*witnessNCols)
	for _, witnessPolyIdx := range sortedUniqueInts(witnessPolyIndices) {
		if witnessPolyIdx < 0 {
			return nil, fmt.Errorf("invalid witness polynomial index %d", witnessPolyIdx)
		}
		block := witnessPolyIdx / pcsNCols
		for omegaRow := 0; omegaRow < witnessNCols; omegaRow++ {
			rowIdx := block*rowsPerBlock + omegaRow
			if rowIdx < 0 || rowIdx >= replayWitnessRows {
				return nil, fmt.Errorf("direct-auth witness row overflow for poly=%d block=%d row=%d limit=%d", witnessPolyIdx, block, rowIdx, replayWitnessRows)
			}
			smallFieldRows = append(smallFieldRows, rowIdx)
		}
	}
	rowCoeffs, err := recoverLowDegreeRowsFromMaskSubset(ringQ, proof, smallFieldRows, omegaWitness, domainPoints)
	if err != nil {
		return nil, err
	}
	return &maskSubsetWitnessView{
		q:                 ringQ.Modulus[0],
		pcsOmega:          append([]uint64(nil), domainPoints[:pcsNCols]...),
		pcsNCols:          pcsNCols,
		witnessNCols:      witnessNCols,
		rowsPerBlock:      rowsPerBlock,
		replayWitnessRows: replayWitnessRows,
		rowCoeffs:         rowCoeffs,
	}, nil
}

func (v *maskSubsetWitnessView) witnessHead(witnessPolyIdx int) ([]uint64, error) {
	if v == nil {
		return nil, fmt.Errorf("nil direct-auth witness view")
	}
	if witnessPolyIdx < 0 {
		return nil, fmt.Errorf("invalid witness polynomial index %d", witnessPolyIdx)
	}
	block := witnessPolyIdx / v.pcsNCols
	slot := witnessPolyIdx % v.pcsNCols
	if slot < 0 || slot >= len(v.pcsOmega) {
		return nil, fmt.Errorf("direct-auth witness slot %d out of range for pcs omega width=%d", slot, len(v.pcsOmega))
	}
	x := v.pcsOmega[slot] % v.q
	head := make([]uint64, v.witnessNCols)
	for omegaRow := 0; omegaRow < v.witnessNCols; omegaRow++ {
		rowIdx := block*v.rowsPerBlock + omegaRow
		if rowIdx < 0 || rowIdx >= v.replayWitnessRows {
			return nil, fmt.Errorf("direct-auth witness row overflow for poly=%d row=%d limit=%d", witnessPolyIdx, rowIdx, v.replayWitnessRows)
		}
		coeffs, ok := v.rowCoeffs[rowIdx]
		if !ok {
			return nil, fmt.Errorf("missing recovered direct-auth row coeffs for row %d", rowIdx)
		}
		head[omegaRow] = EvalPoly(coeffs, x, v.q) % v.q
	}
	return head, nil
}
