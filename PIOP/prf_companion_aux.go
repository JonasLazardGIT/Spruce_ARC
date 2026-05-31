package PIOP

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	// This file supports the non-maintained PRF companion aux-instance path.
	// Maintained IntGenISIS presets use direct_full and do not invoke this
	// module.
	prfAuxMainRootExtraKey     = "prf_aux_main_root"
	prfAuxCoordDigestExtraKey  = "prf_aux_coord_digest"
	prfAuxBridgeDigestExtraKey = "prf_aux_bridge_digest"
	prfAuxBridgeChecksExtraKey = "prf_aux_bridge_checks"
	prfAuxSpecExtraKey         = "prf_aux_spec"
	prfWitnessOmegaBridgeV1    = 1
)

func encodePRFCompanionAuxSpec(mode PRFCompanionMode, checkpointSamples int, layout *PRFCompanionLayout) []byte {
	mode = prfCompanionModeDefault(mode)
	buf := make([]byte, 0, 128)
	buf = append(buf, []byte(mode)...)
	buf = append(buf, 0)
	buf = appendSigShortnessUvarint(buf, checkpointSamples)
	buf = append(buf, prfCompanionLayoutDigest(layout)...)
	return buf
}

func encodeIntSlice(vals []int) []byte {
	buf := make([]byte, 0, 16+len(vals)*8)
	var tmp [8]byte
	buf = appendSigShortnessUvarint(buf, len(vals))
	for _, v := range vals {
		binary.LittleEndian.PutUint64(tmp[:], uint64(v))
		buf = append(buf, tmp[:]...)
	}
	return buf
}

func encodePRFPublicMatrix(vals [][]int64) []byte {
	out := make([]byte, 0, len(vals)*32)
	var buf [8]byte
	out = appendSigShortnessUvarint(out, len(vals))
	for _, row := range vals {
		out = appendSigShortnessUvarint(out, len(row))
		for _, v := range row {
			binary.LittleEndian.PutUint64(buf[:], uint64(v))
			out = append(out, buf[:]...)
		}
	}
	return out
}

func buildPRFWitnessOmegaGeometryDigest(layout *PRFCompanionLayout, rowIndices, physicalRows, supportSlots []int) []byte {
	h := sha256.New()
	h.Write(prfCompanionLayoutDigest(layout))
	h.Write(encodeIntSlice(rowIndices))
	h.Write(encodeIntSlice(physicalRows))
	h.Write(encodeIntSlice(supportSlots))
	sum := h.Sum(nil)
	return append([]byte(nil), sum...)
}

func buildPRFWitnessOmegaPackedDigest(packedHeads [][]uint64) []byte {
	h := sha256.New()
	h.Write(bytesFromUint64Matrix(packedHeads))
	sum := h.Sum(nil)
	return append([]byte(nil), sum...)
}

func buildPRFWitnessOmegaBridgeDigest(mainRoot [16]byte, mainPub PublicInputs, companion *PRFCompanionProof, bridge *PRFWitnessOmegaBridge) []byte {
	h := sha256.New()
	h.Write(mainRoot[:])
	if companion != nil {
		h.Write(encodePRFCompanionAuxSpec(companion.Mode, companion.CheckpointSamples, companion.Layout))
		h.Write(bytesFromUint64Matrix(companion.BridgeChecks))
	}
	if bridge != nil {
		h.Write(bridge.GeometryDigest)
		h.Write(bridge.PackedDigest)
		h.Write(bridge.CoordDigest)
	}
	h.Write(encodePRFPublicMatrix(mainPub.Tag))
	h.Write(encodePRFPublicMatrix(mainPub.Nonce))
	sum := h.Sum(nil)
	return append([]byte(nil), sum...)
}

func buildPRFCompanionAuxPublicInputs(mainPub PublicInputs, mainRoot [16]byte, companion *PRFCompanionProof, bridge *PRFWitnessOmegaBridge) PublicInputs {
	bridgeDigest := []byte(nil)
	if bridge != nil {
		bridgeDigest = append([]byte(nil), bridge.BridgeDigest...)
	}
	extras := map[string]interface{}{
		prfAuxMainRootExtraKey:     append([]byte(nil), mainRoot[:]...),
		prfAuxCoordDigestExtraKey:  append([]byte(nil), companion.CoordDigest...),
		prfAuxBridgeDigestExtraKey: bridgeDigest,
		prfAuxBridgeChecksExtraKey: bytesFromUint64Matrix(companion.BridgeChecks),
		prfAuxSpecExtraKey:         encodePRFCompanionAuxSpec(companion.Mode, companion.CheckpointSamples, companion.Layout),
	}
	return PublicInputs{
		Tag:          mainPub.Tag,
		Nonce:        mainPub.Nonce,
		HashRelation: mainPub.HashRelation,
		Extras:       extras,
	}
}

func prfCompanionBridgeLayout(companion *PRFCompanionProof) (*PRFCompanionLayout, error) {
	if companion == nil {
		return nil, fmt.Errorf("nil prf companion proof")
	}
	return resolvePRFCompanionBridgeLayout(companion.Layout, companion.Mode)
}

func buildPRFCompanionAuxOpts(baseOpts SimOpts, witnessNCols int, relation string) (SimOpts, error) {
	if witnessNCols <= 0 {
		return SimOpts{}, fmt.Errorf("invalid prf aux witness width=%d", witnessNCols)
	}
	baseOpts.applyDefaults()
	auxNLeaves := baseOpts.PRFNLeaves
	if auxNLeaves <= 0 {
		auxNLeaves = baseOpts.NLeaves
	}
	auxLVCSNCols := baseOpts.PRFLVCSNCols
	if auxLVCSNCols <= 0 {
		auxLVCSNCols = baseOpts.LVCSNCols
	}
	if auxLVCSNCols < witnessNCols {
		auxLVCSNCols = witnessNCols
	}
	aux := SimOpts{
		Credential:           true,
		DomainMode:           DomainModeExplicit,
		CoeffNativeSigModel:  CoeffNativeSigModelLiteralPackedAggregatedV3,
		NCols:                witnessNCols,
		PCSNCols:             auxLVCSNCols,
		LVCSNCols:            auxLVCSNCols,
		Theta:                1,
		Rho:                  1,
		Ell:                  maxInt(baseOpts.Ell, 1),
		EllPrime:             maxInt(baseOpts.EllPrime, 1),
		Eta:                  8,
		NLeaves:              auxNLeaves,
		PRFCompanionMode:     PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: baseOpts.PRFCheckpointSamples,
		Lambda:               baseOpts.Lambda,
		Kappa:                baseOpts.Kappa,
	}
	aux.applyDefaults()
	return aux, nil
}

func rebasePRFCompanionLayout(layout *PRFCompanionLayout) *PRFCompanionLayout {
	if layout == nil {
		return nil
	}
	out := clonePRFCompanionLayout(layout)
	shift := out.StartRow
	out.StartRow = 0
	adjust := func(slots []CoeffSlot) {
		for i := range slots {
			slots[i].Row -= shift
		}
	}
	adjust(out.KeySlots)
	adjust(out.KeySourceSlots)
	adjust(out.CheckpointSlots)
	adjust(out.FinalRoundOutputSlots)
	adjust(out.FinalTagSlots)
	return out
}

func buildPRFCompanionSupportSlots(rowIndices []int, pcsNCols int) ([]int, error) {
	return buildSigShortnessSupportSlotsForRows(rowIndices, pcsNCols)
}

func buildPRFCompanionRowsOpening(pk *lvcs.ProverKey, rowIndices []int, pcsNCols int) ([]int, *decs.DECSOpening, error) {
	if pk == nil {
		return nil, nil, fmt.Errorf("nil prover key")
	}
	slots, err := buildPRFCompanionSupportSlots(rowIndices, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	opening := cloneDECSOpening(lvcs.EvalFinish(pk, slots).DECSOpen)
	return slots, opening, nil
}

func buildPRFWitnessOmegaBridge(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	root [16]byte,
	mainPub PublicInputs,
	companion *PRFCompanionProof,
	mainProofGeometry PCSGeometry,
) (*PRFWitnessOmegaBridge, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if companion == nil || companion.Layout == nil {
		return nil, nil, fmt.Errorf("missing prf companion layout")
	}
	bridgeLayout, err := prfCompanionBridgeLayout(companion)
	if err != nil {
		return nil, nil, err
	}
	rowIndices := prfCompanionBridgeStripeSourceRows(companion.Layout)
	if len(rowIndices) == 0 {
		return nil, nil, fmt.Errorf("missing prf companion packed rows")
	}
	physicalRows := append([]int(nil), rowIndices...)
	if companion.Layout.BridgeStripe != nil && len(companion.Layout.BridgeStripe.PhysicalRows) > 0 {
		physicalRows = append([]int(nil), companion.Layout.BridgeStripe.PhysicalRows...)
	}
	if len(physicalRows) != len(rowIndices) {
		return nil, nil, fmt.Errorf("prf witness omega bridge physical rows=%d want source rows=%d", len(physicalRows), len(rowIndices))
	}
	pcsNCols := mainProofGeometry.PCSNCols
	if pcsNCols <= 0 {
		pcsNCols = mainProofGeometry.WitnessPackingCols
	}
	if pcsNCols <= 0 {
		pcsNCols = companion.Layout.PackWidth
	}
	slots, opening, err := buildPRFCompanionRowsOpening(pk, physicalRows, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	packedHeads, err := extractPRFCompanionPackedHeadsFromWitnessOpening(mainProofGeometry, bridgeLayout.PackWidth, physicalRows, opening, slots, ringQ.Modulus[0])
	if err != nil {
		return nil, nil, err
	}
	bridge := &PRFWitnessOmegaBridge{
		Version:        prfWitnessOmegaBridgeV1,
		RowIndices:     append([]int(nil), rowIndices...),
		PhysicalRows:   append([]int(nil), physicalRows...),
		SupportSlots:   append([]int(nil), slots...),
		RowsOpening:    opening,
		PackedDigest:   buildPRFWitnessOmegaPackedDigest(packedHeads),
		CoordDigest:    append([]byte(nil), companion.CoordDigest...),
		GeometryDigest: buildPRFWitnessOmegaGeometryDigest(bridgeLayout, rowIndices, physicalRows, slots),
	}
	bridge.BridgeDigest = buildPRFWitnessOmegaBridgeDigest(root, mainPub, companion, bridge)
	return bridge, packedHeads, nil
}

func extractPRFCompanionPackedHeadsFromWitnessOpening(geom PCSGeometry, witnessNCols int, rowIndices []int, opening *decs.DECSOpening, supportSlots []int, q uint64) ([][]uint64, error) {
	if opening == nil {
		return nil, fmt.Errorf("nil prf companion opening")
	}
	if err := validateSortedUniqueIndices("prf companion support slots", supportSlots); err != nil {
		return nil, err
	}
	if witnessNCols <= 0 {
		witnessNCols = geom.WitnessPackingCols
	}
	pcsNCols := geom.PCSNCols
	if pcsNCols <= 0 {
		pcsNCols = witnessNCols
	}
	theta := geom.Theta
	if theta <= 1 {
		return nil, fmt.Errorf("prf witness omega bridge requires theta>1, got %d", theta)
	}
	replayWitnessRows := geom.ReplayWitnessRows
	if replayWitnessRows <= 0 {
		replayWitnessRows = geom.WitnessRows
	}
	if replayWitnessRows <= 0 {
		return nil, fmt.Errorf("missing replay witness row count for prf witness omega bridge")
	}
	rowsPerBlock := witnessNCols + theta
	if rowsPerBlock <= 0 || replayWitnessRows%rowsPerBlock != 0 {
		return nil, fmt.Errorf("invalid prf witness omega bridge geometry rows=%d rowsPerBlock=%d", replayWitnessRows, rowsPerBlock)
	}
	open := expandPackedOpening(opening)
	if open.EntryCount() != len(supportSlots) {
		return nil, fmt.Errorf("prf companion opening entries=%d want %d", open.EntryCount(), len(supportSlots))
	}
	if !equalIntSlices(open.AllIndices(), supportSlots) {
		return nil, fmt.Errorf("prf companion opening slots mismatch")
	}
	slotPos := make(map[int]int, len(supportSlots))
	for i, slot := range supportSlots {
		slotPos[slot] = i
	}
	out := make([][]uint64, len(rowIndices))
	for rel, witnessPolyIdx := range rowIndices {
		block := witnessPolyIdx / pcsNCols
		slot := witnessPolyIdx % pcsNCols
		pos, ok := slotPos[slot]
		if !ok {
			return nil, fmt.Errorf("missing prf witness omega bridge slot %d", slot)
		}
		head := make([]uint64, witnessNCols)
		for omegaRow := 0; omegaRow < witnessNCols; omegaRow++ {
			rowIdx := block*rowsPerBlock + omegaRow
			if rowIdx < 0 || rowIdx >= replayWitnessRows {
				return nil, fmt.Errorf("prf witness omega bridge row overflow for poly=%d row=%d limit=%d", witnessPolyIdx, rowIdx, replayWitnessRows)
			}
			head[omegaRow] = decs.GetOpeningPval(open, pos, rowIdx) % q
		}
		out[rel] = head
	}
	return out, nil
}

func companionLayoutRowsAsPolys(rows []*ring.Poly, layout *PRFCompanionLayout) ([]*ring.Poly, error) {
	if layout == nil {
		return nil, fmt.Errorf("nil prf companion layout")
	}
	if layout.StartRow < 0 || layout.StartRow+layout.PackedRows > len(rows) {
		return nil, fmt.Errorf("prf companion row window [%d,%d) out of range for rows=%d", layout.StartRow, layout.StartRow+layout.PackedRows, len(rows))
	}
	return clonePolys(rows[layout.StartRow : layout.StartRow+layout.PackedRows]), nil
}

func packedHeadsFromRowsOnOmegaAtRows(ringQ *ring.Ring, omegaWitness []uint64, rows []*ring.Poly, rowIndices []int, packWidth int) ([][]uint64, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if packWidth <= 0 {
		return nil, nil, fmt.Errorf("invalid pack width=%d", packWidth)
	}
	if len(omegaWitness) != packWidth {
		return nil, nil, fmt.Errorf("omega witness len=%d want pack width=%d", len(omegaWitness), packWidth)
	}
	q := ringQ.Modulus[0]
	heads := make([][]uint64, len(rowIndices))
	coeffs := make([][]uint64, len(rowIndices))
	for i, rowIdx := range rowIndices {
		if rowIdx < 0 || rowIdx >= len(rows) {
			return nil, nil, fmt.Errorf("packed head row idx=%d out of range for rows=%d", rowIdx, len(rows))
		}
		rowPoly := rows[rowIdx]
		if rowPoly == nil {
			return nil, nil, fmt.Errorf("nil packed row polynomial at witness row %d", rowIdx)
		}
		rowCoeff := trimPoly(append([]uint64(nil), rowPoly.Coeffs[0]...), q)
		head := make([]uint64, packWidth)
		for col := 0; col < packWidth; col++ {
			head[col] = EvalPoly(rowCoeff, omegaWitness[col]%q, q)
		}
		heads[i] = head
		coeffs[i] = rowCoeff
	}
	return heads, coeffs, nil
}

func buildPRFCompanionAuxRowsFromHeads(ringQ *ring.Ring, packedHeads [][]uint64, omegaWitness []uint64) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(packedHeads) == 0 {
		return nil, fmt.Errorf("empty prf companion packed heads")
	}
	rows := make([]*ring.Poly, len(packedHeads))
	for rel, head := range packedHeads {
		if len(head) != len(omegaWitness) {
			return nil, fmt.Errorf("prf companion head %d width=%d want=%d", rel, len(head), len(omegaWitness))
		}
		pNTT := BuildThetaPrime(ringQ, head, omegaWitness)
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(pNTT, coeff)
		rows[rel] = coeff
	}
	return rows, nil
}

func buildPRFCompanionAuxPrepared(ringQ *ring.Ring, rows []*ring.Poly, pub PublicInputs, opts SimOpts, witnessOmega []uint64) (*preparedCredentialBuild, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty prf aux rows")
	}
	opts.applyDefaults()
	pcsNCols := resolvePCSNCols(opts, opts.NCols)
	if pcsNCols <= 0 {
		pcsNCols = opts.NCols
	}
	var (
		omega        []uint64
		domainPoints []uint64
		omegaWitness []uint64
		err          error
	)
	if relationUsesBBTran(pub.HashRelation) {
		if len(witnessOmega) != opts.NCols {
			return nil, fmt.Errorf("prf aux witness omega len=%d want=%d", len(witnessOmega), opts.NCols)
		}
		omegaWitness = append([]uint64(nil), witnessOmega...)
		omega, domainPoints, err = deriveExplicitDomainWithWitnessPrefix(ringQ.Modulus[0], opts.NLeaves, opts.NCols, pcsNCols, opts.Ell, omegaWitness)
		if err != nil {
			return nil, fmt.Errorf("prf aux explicit domain with witness prefix: %w", err)
		}
	} else {
		omega, domainPoints, err = deriveExplicitDomainForRelation(ringQ.Modulus[0], opts.NLeaves, opts.NCols, pcsNCols, opts.Ell, pub.HashRelation)
		if err != nil {
			return nil, fmt.Errorf("prf aux explicit domain: %w", err)
		}
		omegaWitness, err = deriveRelationWitnessOmega(ringQ.Modulus[0], opts.NLeaves, opts.NCols, pcsNCols, opts.Ell, pub.HashRelation)
		if err != nil {
			return nil, fmt.Errorf("prf aux explicit witness omega: %w", err)
		}
	}
	witnessRows := clonePolys(rows)
	maskRowCount := opts.Rho
	if maskRowCount <= 0 {
		maskRowCount = 1
	}
	preparedRows := append([]*ring.Poly{}, witnessRows...)
	for i := 0; i < maskRowCount; i++ {
		preparedRows = append(preparedRows, ringQ.NewPoly())
	}
	rowInputs, err := buildRowInputsExplicit(ringQ, preparedRows, omega, pcsNCols)
	if err != nil {
		return nil, fmt.Errorf("prf aux row inputs: %w", err)
	}
	return &preparedCredentialBuild{
		rows:          preparedRows,
		rowInputs:     rowInputs,
		rowLayout:     RowLayout{SigCount: len(witnessRows)},
		witnessCount:  len(witnessRows),
		witnessNCols:  opts.NCols,
		omega:         omega,
		omegaWitness:  append([]uint64(nil), omegaWitness...),
		domainPoints:  domainPoints,
		decsParams:    decs.Params{},
		maskRowOffset: len(witnessRows),
		maskRowCount:  maskRowCount,
	}, nil
}

func buildPRFCompanionAuxConstraintSet(
	ringQ *ring.Ring,
	layout *PRFCompanionLayout,
	omegaWitness []uint64,
	rows []*ring.Poly,
	seed2 []byte,
	checks [][]uint64,
	mode PRFCompanionMode,
	checkpointSamples int,
) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if layout == nil {
		return ConstraintSet{}, fmt.Errorf("nil prf companion layout")
	}
	build, err := buildPRFCompanionBridgeFamiliesFormal(
		ringQ,
		omegaWitness,
		layout,
		nil,
		rows,
		seed2,
		len(checks),
		mode,
		checkpointSamples,
	)
	if err != nil {
		return ConstraintSet{}, err
	}
	if build == nil {
		return ConstraintSet{}, fmt.Errorf("nil prf companion aux bridge build")
	}
	zero := ringQ.NewPoly()
	return ConstraintSet{
		FparNorm:         []*ring.Poly{zero},
		FparNormCoeffs:   [][]uint64{{0}},
		FaggNorm:         append([]*ring.Poly{}, build.Families...),
		FaggNormCoeffs:   append([][]uint64{}, build.Coeffs...),
		ParallelAlgDeg:   1,
		AggregatedAlgDeg: 1,
	}, nil
}

func buildPRFCompanionAuxBlockMap(layout *PRFCompanionLayout, pcsNCols int) (map[int]int, []int, error) {
	if layout == nil {
		return nil, nil, fmt.Errorf("nil prf companion layout")
	}
	if pcsNCols <= 0 {
		return nil, nil, fmt.Errorf("invalid aux pcs width=%d", pcsNCols)
	}
	blockMap := make(map[int]int)
	blocks := make([]int, 0, 2)
	for rel := 0; rel < layout.PackedRows; rel++ {
		mainBlock := (layout.StartRow + rel) / pcsNCols
		if _, ok := blockMap[mainBlock]; ok {
			continue
		}
		blockMap[mainBlock] = mainBlock
		blocks = append(blocks, mainBlock)
	}
	return blockMap, blocks, nil
}

func buildPRFCompanionAuxPhysicalIndices(layout *PRFCompanionLayout, pcsNCols int) ([]int, error) {
	blockMap, _, err := buildPRFCompanionAuxBlockMap(layout, pcsNCols)
	if err != nil {
		return nil, err
	}
	indices := make([]int, layout.PackedRows)
	for rel := 0; rel < layout.PackedRows; rel++ {
		mainIdx := layout.StartRow + rel
		mainBlock := mainIdx / pcsNCols
		auxBlock, ok := blockMap[mainBlock]
		if !ok {
			return nil, fmt.Errorf("missing aux block mapping for main block %d", mainBlock)
		}
		indices[rel] = auxBlock*pcsNCols + (mainIdx % pcsNCols)
	}
	return indices, nil
}

func schedulePRFCompanionAuxRows(ringQ *ring.Ring, rows []*ring.Poly, layout *PRFCompanionLayout, pcsNCols int) ([]*ring.Poly, []int, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if layout == nil {
		return nil, nil, fmt.Errorf("nil prf companion layout")
	}
	blockMap, blocks, err := buildPRFCompanionAuxBlockMap(layout, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	if len(blocks) == 0 {
		return nil, nil, fmt.Errorf("empty aux row schedule")
	}
	maxBlock := blocks[len(blocks)-1]
	scheduled := make([]*ring.Poly, (maxBlock+1)*pcsNCols)
	for i := range scheduled {
		scheduled[i] = ringQ.NewPoly()
	}
	for _, mainBlock := range blocks {
		auxBlock := blockMap[mainBlock]
		for slot := 0; slot < pcsNCols; slot++ {
			mainIdx := mainBlock*pcsNCols + slot
			auxIdx := auxBlock*pcsNCols + slot
			if mainIdx >= 0 && mainIdx < len(rows) && rows[mainIdx] != nil {
				scheduled[auxIdx] = rows[mainIdx].CopyNew()
			}
		}
	}
	indices, err := buildPRFCompanionAuxPhysicalIndices(layout, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	return scheduled, indices, nil
}

func buildPRFCompanionAuxInstance(
	ringQ *ring.Ring,
	root [16]byte,
	mainPub PublicInputs,
	companion *PRFCompanionProof,
	mainRows []*ring.Poly,
	companionRows []lvcs.RowInput,
	omegaWitness []uint64,
	mainProofGeometry PCSGeometry,
	mainPK *lvcs.ProverKey,
	seed2 []byte,
	opts SimOpts,
) (*PRFWitnessOmegaBridge, *PRFCompanionAuxInstance, error) {
	if companion == nil || companion.Layout == nil {
		return nil, nil, nil
	}
	bridgeLayout, err := prfCompanionBridgeLayout(companion)
	if err != nil {
		return nil, nil, err
	}
	auxOpts, err := buildPRFCompanionAuxOpts(opts, companion.Layout.PackWidth, mainPub.HashRelation)
	if err != nil {
		return nil, nil, err
	}
	bridge, bridgeHeads, err := buildPRFWitnessOmegaBridge(ringQ, mainPK, root, mainPub, companion, mainProofGeometry)
	if err != nil {
		return nil, nil, err
	}
	if len(companionRows) > 0 {
		for rel, rowIdx := range bridge.RowIndices {
			head := companionRows[rowIdx].Head
			if len(head) < bridgeLayout.PackWidth {
				return nil, nil, fmt.Errorf("prf witness omega bridge row input %d width=%d want >=%d", rel, len(head), bridgeLayout.PackWidth)
			}
			if !equalU64SliceTrimmed(head[:bridgeLayout.PackWidth], bridgeHeads[rel]) {
				pos, got, want, _ := firstU64Mismatch(bridgeHeads[rel], head[:bridgeLayout.PackWidth])
				return nil, nil, fmt.Errorf("prf witness omega bridge row input %d mismatch: first_diff_col=%d bridge=%d row_input=%d", rel, pos, got, want)
			}
		}
	}
	if len(mainRows) > 0 {
		directHeads, _, derr := packedHeadsFromRowsOnOmegaAtRows(ringQ, omegaWitness, mainRows, bridge.RowIndices, bridgeLayout.PackWidth)
		if derr != nil {
			return nil, nil, derr
		}
		if len(directHeads) != len(bridgeHeads) {
			return nil, nil, fmt.Errorf("prf witness omega bridge row count=%d want %d", len(bridgeHeads), len(directHeads))
		}
		for i := range directHeads {
			if !equalU64SliceTrimmed(directHeads[i], bridgeHeads[i]) {
				pos, got, want, _ := firstU64Mismatch(bridgeHeads[i], directHeads[i])
				return nil, nil, fmt.Errorf(
					"prf witness omega bridge packed row %d mismatch at prover: first_diff_col=%d bridge=%d direct=%d bridge_prefix=%v direct_prefix=%v",
					i,
					pos,
					got,
					want,
					shortU64Prefix(bridgeHeads[i], 4),
					shortU64Prefix(directHeads[i], 4),
				)
			}
		}
	}
	auxRows, err := buildPRFCompanionAuxRowsFromHeads(ringQ, bridgeHeads, omegaWitness)
	if err != nil {
		return nil, nil, err
	}
	auxPrepared, err := buildPRFCompanionAuxPrepared(ringQ, auxRows, mainPub, auxOpts, omegaWitness)
	if err != nil {
		return nil, nil, err
	}
	auxPub := buildPRFCompanionAuxPublicInputs(mainPub, root, companion, bridge)
	auxLayout := rebasePRFCompanionLayout(bridgeLayout)
	auxSet, err := buildPRFCompanionAuxConstraintSet(
		ringQ,
		auxLayout,
		omegaWitness,
		auxRows,
		seed2,
		companion.BridgeChecks,
		companion.Mode,
		companion.CheckpointSamples,
	)
	if err != nil {
		return nil, nil, err
	}
	auxProof, err := buildWithConstraintsPrepared(auxPub, WitnessInputs{}, auxSet, auxOpts, FSModeCredential, auxPrepared)
	if err != nil {
		return nil, nil, fmt.Errorf("build prf aux proof: %w", err)
	}
	ok, err := VerifyWithConstraints(auxProof, auxSet, auxPub, auxOpts, FSModeCredential)
	if err != nil {
		return nil, nil, fmt.Errorf("verify prf aux proof: %w", err)
	}
	if !ok {
		return nil, nil, fmt.Errorf("verify prf aux proof returned ok=false")
	}
	return bridge, &PRFCompanionAuxInstance{Proof: auxProof}, nil
}

type prfWitnessOmegaBridgeView struct {
	Opening      *decs.DECSOpening
	PackedHeads  [][]uint64
	WitnessOmega []uint64
}

func preparePRFWitnessOmegaBridgeOpeningForVerify(ringQ *ring.Ring, proof *Proof, opening *decs.DECSOpening, supportSlots []int) (*decs.DECSOpening, []uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if proof == nil {
		return nil, nil, fmt.Errorf("nil proof")
	}
	params, _, err := deriveMainPCSSubsetParams(proof)
	if err != nil {
		return nil, nil, err
	}
	witnessNCols := proof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = proof.PCSGeometry.WitnessPackingCols
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		pcsNCols = proof.PCSGeometry.WitnessPackingCols
	}
	domainPoints, err := deriveProofExplicitDomainPoints(proof, ringQ.Modulus[0], witnessNCols, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	gamma, err := deriveMainPCSSubsetGamma(proof, resolveProofPCSOpening(proof).R, ringQ.Modulus[0])
	if err != nil {
		return nil, nil, err
	}
	rCoeffRows := make([][]uint64, len(proof.R))
	for i := range proof.R {
		rCoeffRows[i] = trimPoly(append([]uint64(nil), proof.R[i]...), ringQ.Modulus[0])
	}
	replayWitnessRows, err := sigShortnessReplayWitnessRows(proof)
	if err != nil {
		return nil, nil, err
	}
	prepared, err := prepareSigShortnessOpeningForVerify(opening, gamma, rCoeffRows, domainPoints, ringQ, replayWitnessRows)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyDECSSubsetFormal(proof.Root, params, gamma, rCoeffRows, prepared, supportSlots, domainPoints, ringQ.Modulus[0]); err != nil {
		return nil, nil, err
	}
	return prepared, domainPoints, nil
}

func preparePRFWitnessOmegaBridgeView(
	ringQ *ring.Ring,
	mainProof *Proof,
	pub PublicInputs,
) (*prfWitnessOmegaBridgeView, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if mainProof == nil || mainProof.PRFCompanion == nil || mainProof.PRFCompanion.Bridge == nil {
		return nil, fmt.Errorf("missing prf witness omega bridge")
	}
	companion := mainProof.PRFCompanion
	bridge := companion.Bridge
	if companion.Layout == nil {
		return nil, fmt.Errorf("missing prf companion layout")
	}
	bridgeLayout, err := prfCompanionBridgeLayout(companion)
	if err != nil {
		return nil, err
	}
	if bridge.Version != prfWitnessOmegaBridgeV1 {
		return nil, fmt.Errorf("unsupported prf witness omega bridge version %d", bridge.Version)
	}
	wantRows := prfCompanionBridgeStripeSourceRows(companion.Layout)
	if !equalIntSlices(bridge.RowIndices, wantRows) {
		return nil, fmt.Errorf("prf witness omega bridge row indices mismatch")
	}
	wantPhysical := append([]int(nil), wantRows...)
	if companion.Layout.BridgeStripe != nil && len(companion.Layout.BridgeStripe.PhysicalRows) > 0 {
		wantPhysical = append([]int(nil), companion.Layout.BridgeStripe.PhysicalRows...)
	}
	if !equalIntSlices(bridge.PhysicalRows, wantPhysical) {
		return nil, fmt.Errorf("prf witness omega bridge physical rows mismatch")
	}
	wantGeom := buildPRFWitnessOmegaGeometryDigest(bridgeLayout, wantRows, wantPhysical, bridge.SupportSlots)
	if !bytes.Equal(bridge.GeometryDigest, wantGeom) {
		return nil, fmt.Errorf("prf witness omega bridge geometry digest mismatch")
	}
	if !bytes.Equal(bridge.CoordDigest, companion.CoordDigest) {
		return nil, fmt.Errorf("prf witness omega bridge coord digest mismatch")
	}
	opening, _, err := preparePRFWitnessOmegaBridgeOpeningForVerify(ringQ, mainProof, bridge.RowsOpening, bridge.SupportSlots)
	if err != nil {
		return nil, err
	}
	packedHeads, err := extractPRFCompanionPackedHeadsFromWitnessOpening(mainProof.PCSGeometry, bridgeLayout.PackWidth, bridge.PhysicalRows, opening, bridge.SupportSlots, ringQ.Modulus[0])
	if err != nil {
		return nil, err
	}
	wantPacked := buildPRFWitnessOmegaPackedDigest(packedHeads)
	if !bytes.Equal(bridge.PackedDigest, wantPacked) {
		return nil, fmt.Errorf("prf witness omega bridge packed digest mismatch")
	}
	wantBridge := buildPRFWitnessOmegaBridgeDigest(mainProof.Root, pub, companion, &PRFWitnessOmegaBridge{
		Version:        bridge.Version,
		RowIndices:     append([]int(nil), bridge.RowIndices...),
		PhysicalRows:   append([]int(nil), bridge.PhysicalRows...),
		SupportSlots:   append([]int(nil), bridge.SupportSlots...),
		PackedDigest:   append([]byte(nil), bridge.PackedDigest...),
		CoordDigest:    append([]byte(nil), bridge.CoordDigest...),
		GeometryDigest: append([]byte(nil), bridge.GeometryDigest...),
	})
	if !bytes.Equal(bridge.BridgeDigest, wantBridge) {
		return nil, fmt.Errorf("prf witness omega bridge digest mismatch")
	}
	witnessNCols := mainProof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = companion.Layout.PackWidth
	}
	pcsNCols := resolveProofPCSNCols(mainProof, witnessNCols)
	ell := mainProof.PCSGeometry.Ell
	if ell <= 0 {
		ell = len(mainProof.Tail)
	}
	domainPoints, err := deriveProofExplicitDomainPoints(mainProof, ringQ.Modulus[0], witnessNCols, pcsNCols)
	if err != nil {
		return nil, fmt.Errorf("derive prf witness omega domain points from main proof: %w", err)
	}
	if len(domainPoints) < witnessNCols {
		return nil, fmt.Errorf("main proof domain points=%d want >= witness ncols=%d", len(domainPoints), witnessNCols)
	}
	witnessOmega := append([]uint64(nil), domainPoints[:witnessNCols]...)
	if len(witnessOmega) == 0 {
		return nil, fmt.Errorf("empty prf witness omega")
	}
	if len(witnessOmega) != witnessNCols {
		return nil, fmt.Errorf("prf witness omega len=%d want %d", len(witnessOmega), witnessNCols)
	}
	if _, _, err = deriveExplicitDomainWithWitnessPrefix(ringQ.Modulus[0], mainProof.NLeavesUsed, witnessNCols, pcsNCols, ell, witnessOmega); err != nil {
		return nil, fmt.Errorf("reconstruct explicit domain with recovered witness omega: %w", err)
	}
	if len(domainPoints) < pcsNCols {
		return nil, fmt.Errorf("main proof domain width=%d want >= pcs ncols=%d", len(domainPoints), pcsNCols)
	}
	return &prfWitnessOmegaBridgeView{
		Opening:      opening,
		PackedHeads:  packedHeads,
		WitnessOmega: witnessOmega,
	}, nil
}

func evalPRFCompanionDescriptorByRowHeads(desc prfCompanionOpeningDescriptor, rowHeads map[int][]uint64, q uint64) (uint64, error) {
	acc := desc.Constant % q
	for _, term := range desc.Terms {
		if term.Source != prfCompanionPackedSource {
			return 0, fmt.Errorf("descriptor %s has unknown source %d", desc.Label, term.Source)
		}
		head, ok := rowHeads[term.Row]
		if !ok {
			return 0, fmt.Errorf("descriptor %s missing row head for row %d", desc.Label, term.Row)
		}
		scale := term.RowMixCoeff % q
		if len(term.CoordinateWeights) > len(head) {
			return 0, fmt.Errorf("descriptor %s weights=%d exceed head width=%d", desc.Label, len(term.CoordinateWeights), len(head))
		}
		for col, weight := range term.CoordinateWeights {
			if weight%q == 0 {
				continue
			}
			acc = modAdd(acc, modMul(scale, modMul(weight%q, head[col]%q, q), q), q)
		}
	}
	return acc % q, nil
}

func verifyPRFCompanionOpeningsFromRowHeads(
	layout *PRFCompanionLayout,
	companion *PRFCompanionProof,
	params *prf.Params,
	rowHeads map[int][]uint64,
	tagPublic [][]int64,
	noncePublic [][]int64,
	seed3 []byte,
) error {
	if layout == nil || companion == nil {
		return nil
	}
	plan, err := buildPRFCompanionOpeningPlan(
		layout,
		params,
		companion.Mode,
		companion.CheckpointSamples,
		seed3,
		companion.CoordDigest,
		tagPublic,
		noncePublic,
	)
	if err != nil {
		return err
	}
	if len(companion.CheckpointAudits) != len(plan.Audits) {
		return fmt.Errorf("checkpoint audit count=%d want %d", len(companion.CheckpointAudits), len(plan.Audits))
	}
	openings := make(map[string]PRFCompanionOpening, len(plan.Descriptors))
	for i := range plan.Audits {
		openings[plan.Audits[i].ZLabel] = companion.CheckpointAudits[i].Z
		openings[plan.Audits[i].WireLabel] = companion.CheckpointAudits[i].Wire
	}
	openings["tag_final"] = companion.TagFinal
	openings["key_trunc"] = companion.KeyTrunc
	for i, desc := range plan.Descriptors {
		want, err := evalPRFCompanionDescriptorByRowHeads(desc, rowHeads, plan.Q)
		if err != nil {
			return err
		}
		opening, ok := openings[desc.Label]
		if !ok {
			return fmt.Errorf("missing prf companion opening %q", desc.Label)
		}
		got, err := recoverPRFCompanionOpening(desc.Label, opening, plan.Masks[i], plan.Q)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("prf companion opening %s mismatch: got=%d want=%d", desc.Label, got, want)
		}
	}
	return nil
}

func verifyPRFCompanionOpeningsFromHeads(
	layout *PRFCompanionLayout,
	companion *PRFCompanionProof,
	params *prf.Params,
	rowHeads [][]uint64,
	tagPublic [][]int64,
	noncePublic [][]int64,
	seed3 []byte,
) error {
	rowHeadsByRow := make(map[int][]uint64, len(rowHeads))
	for i := range rowHeads {
		rowHeadsByRow[layout.StartRow+i] = append([]uint64(nil), rowHeads[i]...)
	}
	return verifyPRFCompanionOpeningsFromRowHeads(layout, companion, params, rowHeadsByRow, tagPublic, noncePublic, seed3)
}

func shortU64Prefix(vals []uint64, limit int) []uint64 {
	if len(vals) <= limit {
		return append([]uint64(nil), vals...)
	}
	return append([]uint64(nil), vals[:limit]...)
}

func firstU64Mismatch(a, b []uint64) (int, uint64, uint64, bool) {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] != b[i] {
			return i, a[i], b[i], true
		}
	}
	if len(a) != len(b) {
		return limit, 0, 0, true
	}
	return 0, 0, 0, false
}

func equalU64SliceTrimmed(a, b []uint64) bool {
	a = trimTrailingZeros(append([]uint64(nil), a...))
	b = trimTrailingZeros(append([]uint64(nil), b...))
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func trimTrailingZeros(coeffs []uint64) []uint64 {
	n := len(coeffs)
	for n > 1 && coeffs[n-1] == 0 {
		n--
	}
	return coeffs[:n]
}

func verifyPRFCompanionAuxInstance(
	ringQ *ring.Ring,
	mainProof *Proof,
	pub PublicInputs,
	opts SimOpts,
	params *prf.Params,
) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if mainProof == nil || mainProof.PRFCompanion == nil || mainProof.PRFCompanion.AuxInstance == nil {
		return nil
	}
	companion := mainProof.PRFCompanion
	aux := companion.AuxInstance
	if companion.Layout == nil {
		return fmt.Errorf("missing main prf companion layout")
	}
	if companion.Bridge == nil {
		return fmt.Errorf("missing prf witness omega bridge")
	}
	if aux.Proof == nil {
		return fmt.Errorf("missing prf aux proof")
	}
	bridgeLayout, err := prfCompanionBridgeLayout(companion)
	if err != nil {
		return err
	}
	bridgeView, err := preparePRFWitnessOmegaBridgeView(ringQ, mainProof, pub)
	if err != nil {
		return err
	}
	auxOpts, err := buildPRFCompanionAuxOpts(opts, companion.Layout.PackWidth, pub.HashRelation)
	if err != nil {
		return err
	}
	auxPub := buildPRFCompanionAuxPublicInputs(pub, mainProof.Root, companion, companion.Bridge)
	auxLayout := rebasePRFCompanionLayout(bridgeLayout)
	auxRows, err := buildPRFCompanionAuxRowsFromHeads(ringQ, bridgeView.PackedHeads, bridgeView.WitnessOmega)
	if err != nil {
		return err
	}
	auxSet, err := buildPRFCompanionAuxConstraintSet(
		ringQ,
		auxLayout,
		bridgeView.WitnessOmega,
		auxRows,
		append([]byte(nil), mainProof.Digests[1]...),
		companion.BridgeChecks,
		companion.Mode,
		companion.CheckpointSamples,
	)
	if err != nil {
		return err
	}
	ok, err := VerifyWithConstraints(aux.Proof, auxSet, auxPub, auxOpts, FSModeCredential)
	if err != nil {
		return fmt.Errorf("verify prf aux instance: %w", err)
	}
	if !ok {
		return fmt.Errorf("verify prf aux instance returned ok=false")
	}
	rowHeads := make(map[int][]uint64, len(bridgeView.PackedHeads))
	for i, rowIdx := range companion.Bridge.RowIndices {
		rowHeads[rowIdx] = append([]uint64(nil), bridgeView.PackedHeads[i]...)
	}
	if err := verifyPRFCompanionOpeningsFromRowHeads(companion.Layout, companion, params, rowHeads, pub.Tag, pub.Nonce, mainProof.Digests[2]); err != nil {
		return err
	}
	return nil
}
