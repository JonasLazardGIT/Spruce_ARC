package PIOP

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const sourceProductBridgeV1 = 1

type SourceProductBridge struct {
	Version        int
	RowIndices     []int
	PhysicalRows   []int
	SupportSlots   []int
	RowsOpening    *decs.DECSOpening
	PackedDigest   []byte
	GeometryDigest []byte
	BridgeDigest   []byte
}

type sourceProductAliasStripeLayout struct {
	SourceRows   []int
	PhysicalRows []int
	SupportSlots []int
	PaddingRows  int
}

type sourceProductBridgeView struct {
	Opening      *decs.DECSOpening
	PackedHeads  [][]uint64
	OmegaS1Limbs [][]uint64
	Coeffs       [][]uint64
	WitnessOmega []uint64
}

type sourceProductCarrierWitnessView struct {
	q                 uint64
	pcsOmega          []uint64
	pcsNCols          int
	witnessNCols      int
	rowsPerBlock      int
	replayWitnessRows int
	rowCoeffs         map[int][]uint64
}

func sourceProductAliasStripeRequested(pub PublicInputs, opts SimOpts) bool {
	return false
}

func sourceProductBridgePhysicalRows(layout RowLayout) []int {
	return rowLayoutSourceProductAliasRows(layout)
}

func sourceProductBridgeEnabled(pub PublicInputs, opts SimOpts, layout RowLayout) bool {
	if !sourceProductAliasStripeRequested(pub, opts) {
		return false
	}
	if len(sourceProductBridgeRowIndices(layout)) != 2 {
		return false
	}
	return len(sourceProductBridgePhysicalRows(layout)) == 2
}

func sourceProductBridgeEnabledForProof(proof *Proof) bool {
	return proof != nil && proof.SourceProductBridge != nil
}

func sourceProductBridgeRowIndices(layout RowLayout) []int {
	rows := []int{}
	for _, idx := range []int{layout.IdxMSigmaR1, layout.IdxR0R1} {
		if idx >= 0 {
			rows = append(rows, idx)
		}
	}
	return rows
}

func buildSourceProductAliasStripeLayout(layout RowLayout, currentWitnessRows, pcsNCols int) (*sourceProductAliasStripeLayout, error) {
	if currentWitnessRows < 0 {
		return nil, fmt.Errorf("invalid current witness rows=%d", currentWitnessRows)
	}
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	sourceRows := sourceProductBridgeRowIndices(layout)
	if len(sourceRows) != 2 {
		return nil, fmt.Errorf("source-product alias stripe requires 2 source rows, got %d", len(sourceRows))
	}
	if pcsNCols < len(sourceRows) {
		return nil, fmt.Errorf("source-product alias stripe requires pcs ncols >= %d, got %d", len(sourceRows), pcsNCols)
	}
	start := currentWitnessRows
	if rem := currentWitnessRows % pcsNCols; rem != 0 {
		slotsLeft := pcsNCols - rem
		if slotsLeft < len(sourceRows) {
			start += slotsLeft
		}
	}
	physicalRows := make([]int, len(sourceRows))
	for i := range sourceRows {
		physicalRows[i] = start + i
	}
	supportSlots, err := buildSigShortnessSupportSlotsForRows(physicalRows, pcsNCols)
	if err != nil {
		return nil, err
	}
	return &sourceProductAliasStripeLayout{
		SourceRows:   append([]int(nil), sourceRows...),
		PhysicalRows: physicalRows,
		SupportSlots: supportSlots,
		PaddingRows:  start - currentWitnessRows,
	}, nil
}

func appendSourceProductAliasStripeRows(ringQ *ring.Ring, rows []*ring.Poly, stripe *sourceProductAliasStripeLayout) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if stripe == nil {
		return rows, nil
	}
	if len(stripe.SourceRows) != len(stripe.PhysicalRows) {
		return nil, fmt.Errorf("source-product alias stripe source rows=%d want physical rows=%d", len(stripe.SourceRows), len(stripe.PhysicalRows))
	}
	for i, sourceRow := range stripe.SourceRows {
		targetRow := stripe.PhysicalRows[i]
		for len(rows) < targetRow {
			rows = append(rows, ringQ.NewPoly())
		}
		if len(rows) != targetRow {
			return nil, fmt.Errorf("source-product alias stripe target row=%d current rows=%d", targetRow, len(rows))
		}
		if sourceRow < 0 || sourceRow >= len(rows) {
			return nil, fmt.Errorf("source-product alias stripe source row=%d out of range for rows=%d", sourceRow, len(rows))
		}
		if rows[sourceRow] == nil {
			return nil, fmt.Errorf("nil source-product alias stripe source row %d", sourceRow)
		}
		rows = append(rows, rows[sourceRow].CopyNew())
	}
	return rows, nil
}

func buildSourceProductAliasStripeEqualityConstraints(ringQ *ring.Ring, rowsNTT []*ring.Poly, layout RowLayout) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	sourceRows := sourceProductBridgeRowIndices(layout)
	physicalRows := sourceProductBridgePhysicalRows(layout)
	if len(sourceRows) == 0 || len(physicalRows) == 0 {
		return nil, nil, nil
	}
	if len(sourceRows) != len(physicalRows) {
		return nil, nil, fmt.Errorf("source-product alias stripe source rows=%d want physical rows=%d", len(sourceRows), len(physicalRows))
	}
	q := ringQ.Modulus[0]
	families := make([]*ring.Poly, 0, len(sourceRows))
	coeffs := make([][]uint64, 0, len(sourceRows))
	for i, sourceRow := range sourceRows {
		physicalRow := physicalRows[i]
		if sourceRow < 0 || sourceRow >= len(rowsNTT) || physicalRow < 0 || physicalRow >= len(rowsNTT) {
			return nil, nil, fmt.Errorf("source-product alias equality rows source=%d physical=%d out of range (rows=%d)", sourceRow, physicalRow, len(rowsNTT))
		}
		sourceCoeff, err := coeffFromNTTPoly(ringQ, rowsNTT[sourceRow])
		if err != nil {
			return nil, nil, fmt.Errorf("source-product alias source coeff row %d: %w", sourceRow, err)
		}
		physicalCoeff, err := coeffFromNTTPoly(ringQ, rowsNTT[physicalRow])
		if err != nil {
			return nil, nil, fmt.Errorf("source-product alias physical coeff row %d: %w", physicalRow, err)
		}
		diff := trimPoly(polySub(sourceCoeff, physicalCoeff, q), q)
		families = append(families, nttPolyFromFormalCoeffsIfFits(ringQ, diff))
		coeffs = append(coeffs, diff)
	}
	return families, coeffs, nil
}

func buildSourceProductBridgeGeometryDigest(rowIndices, physicalRows, supportSlots []int, witnessNCols, pcsNCols int) []byte {
	h := sha256.New()
	h.Write(encodeIntSlice([]int{sourceProductBridgeV1, witnessNCols, pcsNCols}))
	h.Write(encodeIntSlice(rowIndices))
	h.Write(encodeIntSlice(physicalRows))
	h.Write(encodeIntSlice(supportSlots))
	sum := h.Sum(nil)
	return append([]byte(nil), sum...)
}

func buildSourceProductBridgePackedDigest(packedHeads [][]uint64) []byte {
	h := sha256.New()
	h.Write(bytesFromUint64Matrix(packedHeads))
	sum := h.Sum(nil)
	return append([]byte(nil), sum...)
}

func buildReplayHeadsFromSourceHead(ringQ *ring.Ring, sourceHead, omega []uint64, replayBlockCount int, name string) ([][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(sourceHead) == 0 {
		return nil, fmt.Errorf("empty source head for %s", name)
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega for %s", name)
	}
	if len(sourceHead) != len(omega) {
		return nil, fmt.Errorf("source head width=%d want omega width=%d for %s", len(sourceHead), len(omega), name)
	}
	if replayBlockCount <= 0 {
		return nil, fmt.Errorf("invalid replay block count=%d", replayBlockCount)
	}
	ncols := len(omega)
	basis, err := newTransformBridgeBasisCache(ringQ, omega, replayBlockCount*ncols, 1)
	if err != nil {
		return nil, fmt.Errorf("transform basis for %s: %w", name, err)
	}
	q := ringQ.Modulus[0]
	out := make([][]uint64, replayBlockCount)
	for block := 0; block < replayBlockCount; block++ {
		head := make([]uint64, ncols)
		for j := 0; j < ncols; j++ {
			t := block*ncols + j
			acc := uint64(0)
			for k := 0; k < ncols; k++ {
				weight := EvalPoly(basis.TransformH[t], omega[k]%q, q) % q
				acc = modAdd(acc, modMul(weight, sourceHead[k]%q, q), q)
			}
			head[j] = acc
		}
		out[block] = head
	}
	return out, nil
}

func buildSourceProductBridgeDigest(mainRoot [16]byte, mainPub PublicInputs, bridge *SourceProductBridge) []byte {
	h := sha256.New()
	h.Write(mainRoot[:])
	h.Write(computeLabelsDigest(BuildPublicLabels(mainPub)))
	if bridge != nil {
		h.Write(bridge.GeometryDigest)
		h.Write(bridge.PackedDigest)
	}
	sum := h.Sum(nil)
	return append([]byte(nil), sum...)
}

func buildSourceProductBridgeRowsOpening(pk *lvcs.ProverKey, rowIndices []int, pcsNCols int) ([]int, *decs.DECSOpening, error) {
	if pk == nil {
		return nil, nil, fmt.Errorf("nil prover key")
	}
	slots, err := buildSigShortnessSupportSlotsForRows(rowIndices, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	opening := cloneDECSOpening(lvcs.EvalFinish(pk, slots).DECSOpen)
	return slots, opening, nil
}

func extractSourceProductHeadsFromWitnessOpening(geom PCSGeometry, witnessNCols int, rowIndices []int, opening *decs.DECSOpening, supportSlots []int, q uint64) ([][]uint64, error) {
	if opening == nil {
		return nil, fmt.Errorf("nil source-product opening")
	}
	if err := validateSortedUniqueIndices("source-product support slots", supportSlots); err != nil {
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
		return nil, fmt.Errorf("source-product bridge requires theta>1, got %d", theta)
	}
	replayWitnessRows := geom.ReplayWitnessRows
	if replayWitnessRows <= 0 {
		replayWitnessRows = geom.WitnessRows
	}
	if replayWitnessRows <= 0 {
		return nil, fmt.Errorf("missing replay witness row count for source-product bridge")
	}
	rowsPerBlock := witnessNCols + theta
	if rowsPerBlock <= 0 || replayWitnessRows%rowsPerBlock != 0 {
		return nil, fmt.Errorf("invalid source-product bridge geometry rows=%d rowsPerBlock=%d", replayWitnessRows, rowsPerBlock)
	}
	open := expandPackedOpening(opening)
	if open.EntryCount() != len(supportSlots) {
		return nil, fmt.Errorf("source-product opening entries=%d want %d", open.EntryCount(), len(supportSlots))
	}
	if !equalIntSlices(open.AllIndices(), supportSlots) {
		return nil, fmt.Errorf("source-product opening slots mismatch")
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
			return nil, fmt.Errorf("missing source-product support slot %d", slot)
		}
		head := make([]uint64, witnessNCols)
		for omegaRow := 0; omegaRow < witnessNCols; omegaRow++ {
			rowIdx := block*rowsPerBlock + omegaRow
			if rowIdx < 0 || rowIdx >= replayWitnessRows {
				return nil, fmt.Errorf("source-product bridge row overflow for poly=%d row=%d limit=%d", witnessPolyIdx, rowIdx, replayWitnessRows)
			}
			head[omegaRow] = decs.GetOpeningPval(open, pos, rowIdx) % q
		}
		out[rel] = head
	}
	return out, nil
}

func extractSourceProductOmegaS1LimbsFromWitnessOpening(geom PCSGeometry, witnessNCols int, rowIndices []int, opening *decs.DECSOpening, supportSlots []int, q uint64) ([][]uint64, error) {
	if opening == nil {
		return nil, fmt.Errorf("nil source-product opening")
	}
	pcsNCols := geom.PCSNCols
	if pcsNCols <= 0 {
		pcsNCols = witnessNCols
	}
	theta := geom.Theta
	if theta <= 1 {
		return nil, fmt.Errorf("source-product omegaS1 extraction requires theta>1, got %d", theta)
	}
	replayWitnessRows := geom.ReplayWitnessRows
	if replayWitnessRows <= 0 {
		replayWitnessRows = geom.WitnessRows
	}
	rowsPerBlock := witnessNCols + theta
	if rowsPerBlock <= 0 || replayWitnessRows%rowsPerBlock != 0 {
		return nil, fmt.Errorf("invalid source-product omegaS1 geometry rows=%d rowsPerBlock=%d", replayWitnessRows, rowsPerBlock)
	}
	open := expandPackedOpening(opening)
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
			return nil, fmt.Errorf("missing source-product support slot %d", slot)
		}
		limbs := make([]uint64, theta)
		for coord := 0; coord < theta; coord++ {
			rowIdx := block*rowsPerBlock + witnessNCols + coord
			if rowIdx < 0 || rowIdx >= replayWitnessRows {
				return nil, fmt.Errorf("source-product omegaS1 row overflow for poly=%d row=%d limit=%d", witnessPolyIdx, rowIdx, replayWitnessRows)
			}
			limbs[coord] = decs.GetOpeningPval(open, pos, rowIdx) % q
		}
		out[rel] = limbs
	}
	return out, nil
}

func buildSourceProductBridge(
	ringQ *ring.Ring,
	pk *lvcs.ProverKey,
	root [16]byte,
	mainPub PublicInputs,
	layout RowLayout,
	omegaWitness []uint64,
	mainProofGeometry PCSGeometry,
) (*SourceProductBridge, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	rowIndices := sourceProductBridgeRowIndices(layout)
	if len(rowIndices) != 2 {
		return nil, nil, fmt.Errorf("source-product bridge requires 2 source rows, got %d", len(rowIndices))
	}
	physicalRows := sourceProductBridgePhysicalRows(layout)
	if len(physicalRows) != 2 {
		return nil, nil, fmt.Errorf("source-product bridge requires 2 physical rows, got %d", len(physicalRows))
	}
	pcsNCols := mainProofGeometry.PCSNCols
	if pcsNCols <= 0 {
		pcsNCols = mainProofGeometry.WitnessPackingCols
	}
	if pcsNCols <= 0 {
		pcsNCols = len(omegaWitness)
	}
	slots, opening, err := buildSourceProductBridgeRowsOpening(pk, physicalRows, pcsNCols)
	if err != nil {
		return nil, nil, err
	}
	packedHeads, err := extractSourceProductHeadsFromWitnessOpening(mainProofGeometry, len(omegaWitness), physicalRows, opening, slots, ringQ.Modulus[0])
	if err != nil {
		return nil, nil, err
	}
	bridge := &SourceProductBridge{
		Version:        sourceProductBridgeV1,
		RowIndices:     append([]int(nil), rowIndices...),
		PhysicalRows:   append([]int(nil), physicalRows...),
		SupportSlots:   append([]int(nil), slots...),
		RowsOpening:    opening,
		PackedDigest:   buildSourceProductBridgePackedDigest(packedHeads),
		GeometryDigest: buildSourceProductBridgeGeometryDigest(rowIndices, physicalRows, slots, len(omegaWitness), pcsNCols),
	}
	bridge.BridgeDigest = buildSourceProductBridgeDigest(root, mainPub, bridge)
	return bridge, packedHeads, nil
}

func prepareSourceProductBridgeOpeningForVerify(ringQ *ring.Ring, proof *Proof, opening *decs.DECSOpening, supportSlots []int) (*decs.DECSOpening, []uint64, error) {
	return preparePRFWitnessOmegaBridgeOpeningForVerify(ringQ, proof, opening, supportSlots)
}

func prepareSourceProductBridgeView(ringQ *ring.Ring, proof *Proof, pub PublicInputs) (*sourceProductBridgeView, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if proof == nil || proof.SourceProductBridge == nil {
		return nil, fmt.Errorf("missing source-product bridge")
	}
	bridge := proof.SourceProductBridge
	if bridge.Version != sourceProductBridgeV1 {
		return nil, fmt.Errorf("unsupported source-product bridge version %d", bridge.Version)
	}
	wantRows := sourceProductBridgeRowIndices(proof.RowLayout)
	if !equalIntSlices(bridge.RowIndices, wantRows) {
		return nil, fmt.Errorf("source-product bridge row indices mismatch")
	}
	wantPhysical := sourceProductBridgePhysicalRows(proof.RowLayout)
	if len(wantPhysical) != len(wantRows) {
		return nil, fmt.Errorf("source-product bridge physical rows missing from row layout")
	}
	if !equalIntSlices(bridge.PhysicalRows, wantPhysical) {
		return nil, fmt.Errorf("source-product bridge physical rows mismatch")
	}
	witnessNCols := proof.NColsUsed
	if witnessNCols <= 0 {
		witnessNCols = proof.PCSGeometry.WitnessPackingCols
	}
	pcsNCols := resolveProofPCSNCols(proof, witnessNCols)
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("missing pcs ncols for source-product bridge")
	}
	wantGeom := buildSourceProductBridgeGeometryDigest(wantRows, wantPhysical, bridge.SupportSlots, witnessNCols, pcsNCols)
	if !bytes.Equal(bridge.GeometryDigest, wantGeom) {
		return nil, fmt.Errorf("source-product bridge geometry digest mismatch")
	}
	opening, domainPoints, err := prepareSourceProductBridgeOpeningForVerify(ringQ, proof, bridge.RowsOpening, bridge.SupportSlots)
	if err != nil {
		return nil, err
	}
	if len(domainPoints) < witnessNCols {
		return nil, fmt.Errorf("source-product bridge domain width=%d want >= witness ncols=%d", len(domainPoints), witnessNCols)
	}
	witnessOmega := append([]uint64(nil), domainPoints[:witnessNCols]...)
	packedHeads, err := extractSourceProductHeadsFromWitnessOpening(proof.PCSGeometry, witnessNCols, bridge.PhysicalRows, opening, bridge.SupportSlots, ringQ.Modulus[0])
	if err != nil {
		return nil, err
	}
	omegaS1Limbs, err := extractSourceProductOmegaS1LimbsFromWitnessOpening(proof.PCSGeometry, witnessNCols, bridge.PhysicalRows, opening, bridge.SupportSlots, ringQ.Modulus[0])
	if err != nil {
		return nil, err
	}
	wantPacked := buildSourceProductBridgePackedDigest(packedHeads)
	if !bytes.Equal(bridge.PackedDigest, wantPacked) {
		return nil, fmt.Errorf("source-product bridge packed digest mismatch")
	}
	wantBridge := buildSourceProductBridgeDigest(proof.Root, pub, &SourceProductBridge{
		Version:        bridge.Version,
		RowIndices:     append([]int(nil), bridge.RowIndices...),
		PhysicalRows:   append([]int(nil), bridge.PhysicalRows...),
		SupportSlots:   append([]int(nil), bridge.SupportSlots...),
		PackedDigest:   append([]byte(nil), bridge.PackedDigest...),
		GeometryDigest: append([]byte(nil), bridge.GeometryDigest...),
	})
	if !bytes.Equal(bridge.BridgeDigest, wantBridge) {
		return nil, fmt.Errorf("source-product bridge digest mismatch")
	}
	coeffs := make([][]uint64, len(packedHeads))
	for i, head := range packedHeads {
		coeff, err := coeffRowFromHeadOnOmega(ringQ, head, witnessOmega, fmt.Sprintf("source-product[%d]", i))
		if err != nil {
			return nil, err
		}
		coeffs[i] = coeff
	}
	return &sourceProductBridgeView{
		Opening:      opening,
		PackedHeads:  packedHeads,
		OmegaS1Limbs: omegaS1Limbs,
		Coeffs:       coeffs,
		WitnessOmega: witnessOmega,
	}, nil
}

func evalSourceProductBridgeValueAtK(K *kf.Field, omega []uint64, omegaS1 kf.Elem, head []uint64, omegaS1Limbs []uint64, e kf.Elem) (kf.Elem, error) {
	if K == nil {
		return kf.Elem{}, fmt.Errorf("nil K field")
	}
	if len(head) != len(omega) {
		return kf.Elem{}, fmt.Errorf("source-product head width=%d want omega width=%d", len(head), len(omega))
	}
	if len(omegaS1Limbs) != K.Theta {
		return kf.Elem{}, fmt.Errorf("source-product omegaS1 limbs=%d want theta=%d", len(omegaS1Limbs), K.Theta)
	}
	q := K.Q
	s := len(omega)
	lagNum := make([][]uint64, s)
	lagDenInv := make([]uint64, s)
	for k := 0; k < s; k++ {
		lagNum[k] = lagrangeBasisNumerator(omega, k, q)
		den := uint64(1)
		for j := 0; j < s; j++ {
			if j == k {
				continue
			}
			den = modMul(den, modSub(omega[k]%q, omega[j]%q, q), q)
		}
		lagDenInv[k] = modInv(den, q)
	}
	acc := K.Zero()
	accAtOmegaS1 := K.Zero()
	for k := 0; k < s; k++ {
		headVal := K.EmbedF(head[k] % q)
		lambda := K.Mul(K.EvalFPolyAtK(lagNum[k], e), K.EmbedF(lagDenInv[k]))
		acc = K.Add(acc, K.Mul(lambda, headVal))
		lambdaAtOmegaS1 := K.Mul(K.EvalFPolyAtK(lagNum[k], omegaS1), K.EmbedF(lagDenInv[k]))
		accAtOmegaS1 = K.Add(accAtOmegaS1, K.Mul(lambdaAtOmegaS1, headVal))
	}
	yS1 := K.Phi(omegaS1Limbs)
	prod := K.One()
	denom := K.One()
	for _, w := range omega {
		prod = K.Mul(prod, K.Sub(e, K.EmbedF(w%q)))
		denom = K.Mul(denom, K.Sub(omegaS1, K.EmbedF(w%q)))
	}
	mu := K.Mul(prod, K.Inv(denom))
	return K.Add(acc, K.Mul(mu, K.Sub(yS1, accAtOmegaS1))), nil
}

func prepareSourceProductMaskSubsetRecovery(
	ringQ *ring.Ring,
	proof *Proof,
	domainPoints []uint64,
) (*decs.DECSOpening, []int, []uint64, error) {
	if ringQ == nil {
		return nil, nil, nil, fmt.Errorf("nil ring")
	}
	if proof == nil {
		return nil, nil, nil, fmt.Errorf("nil proof")
	}
	baseOpening := resolveProofPCSOpening(proof)
	if baseOpening == nil {
		return nil, nil, nil, fmt.Errorf("missing row opening for source-product recovery")
	}
	maskBase := baseOpening.MaskBase
	maskCount := baseOpening.MaskCount
	ncols := proof.NColsUsed
	if maskCount <= 0 {
		maskBase = ncols
		if maskBase <= 0 {
			maskBase = proof.PCSGeometry.WitnessPackingCols
		}
		maskCount = len(proof.Tail)
	}
	if maskBase <= 0 {
		return nil, nil, nil, fmt.Errorf("missing witness width for source-product recovery")
	}
	if maskCount <= 0 {
		return nil, nil, nil, fmt.Errorf("missing mask count for source-product recovery")
	}
	maskIdx := make([]int, maskCount)
	for i := 0; i < maskCount; i++ {
		maskIdx[i] = maskBase + i
	}
	params, rowCount, err := deriveMainPCSSubsetParams(proof)
	if err != nil {
		return nil, nil, nil, err
	}
	gamma, err := deriveMainPCSSubsetGamma(proof, rowCount, ringQ.Modulus[0])
	if err != nil {
		return nil, nil, nil, err
	}
	rPolys := make([]*ring.Poly, len(proof.R))
	for i := range proof.R {
		rPolys[i] = coeffsToNTTIfFits(ringQ, proof.R[i])
		if rPolys[i] == nil {
			return nil, nil, nil, fmt.Errorf("R polynomial %d too large to materialize", i)
		}
	}
	coeffMatrix := proof.CoeffMatrix
	if len(coeffMatrix) == 0 {
		return nil, nil, nil, fmt.Errorf("missing coefficient matrix for source-product recovery")
	}
	barSets := proof.BarSetsMatrix()
	if len(barSets) == 0 {
		return nil, nil, nil, fmt.Errorf("missing bar sets for source-product recovery")
	}
	vTargets := proof.VTargetsMatrix()
	if len(vTargets) == 0 {
		return nil, nil, nil, fmt.Errorf("missing vtargets for source-product recovery")
	}
	qVals, err := interpolateReplayQRows(ringQ, vTargets, barSets, ncols)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("replay Q rows for source-product recovery: %w", err)
	}
	opening, err := prepareRowOpeningForVerify(baseOpening, gamma, rPolys, coeffMatrix, qVals, barSets, maskIdx, proof.Tail, ncols, domainPoints, ringQ)
	if err != nil {
		return nil, nil, nil, err
	}
	subsetIdx := append(append([]int(nil), maskIdx...), proof.Tail...)
	opening, err = buildSubsetOpening(opening, subsetIdx, rowCount, params.Eta)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("source-product subset opening: %w", err)
	}
	q := ringQ.Modulus[0]
	maskPoints := make([]uint64, opening.EntryCount())
	indexPos := make(map[int]int, opening.EntryCount())
	for pos := 0; pos < opening.EntryCount(); pos++ {
		indexPos[opening.IndexAt(pos)] = pos
	}
	for i, idx := range opening.AllIndices() {
		if idx < 0 || idx >= len(domainPoints) {
			return nil, nil, nil, fmt.Errorf("source-product recovery index %d out of range", idx)
		}
		if _, ok := indexPos[idx]; !ok {
			return nil, nil, nil, fmt.Errorf("source-product recovery opening missing index %d", idx)
		}
		maskPoints[i] = domainPoints[idx] % q
	}
	return opening, opening.AllIndices(), maskPoints, nil
}

func recoverSourceProductLowDegreeRowsFromMainPCS(
	ringQ *ring.Ring,
	proof *Proof,
	rowIndices []int,
	domainPoints []uint64,
) (map[int][]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	rowIndices = sortedUniqueInts(rowIndices)
	if len(rowIndices) == 0 {
		return map[int][]uint64{}, nil
	}
	opening, maskIndices, maskPoints, err := prepareSourceProductMaskSubsetRecovery(ringQ, proof, domainPoints)
	if err != nil {
		return nil, err
	}
	if len(maskPoints) == 0 {
		return nil, fmt.Errorf("empty source-product recovery point set")
	}
	indexPos := make(map[int]int, opening.EntryCount())
	for pos := 0; pos < opening.EntryCount(); pos++ {
		indexPos[opening.IndexAt(pos)] = pos
	}
	entryWidth := 0
	if len(opening.Pvals) > 0 {
		entryWidth = len(opening.Pvals[0])
	}
	q := ringQ.Modulus[0]
	out := make(map[int][]uint64, len(rowIndices))
	for _, rowIdx := range rowIndices {
		if rowIdx < 0 || rowIdx >= entryWidth {
			return nil, fmt.Errorf("source-product recovery row idx %d out of range for width=%d", rowIdx, entryWidth)
		}
		values := make([]uint64, len(maskIndices))
		for i, maskIdx := range maskIndices {
			pos := indexPos[maskIdx]
			values[i] = opening.Pvals[pos][rowIdx] % q
		}
		out[rowIdx] = trimPoly(Interpolate(maskPoints, values, q), q)
	}
	return out, nil
}

func prepareSourceProductCarrierWitnessView(
	ringQ *ring.Ring,
	proof *Proof,
	witnessPolyIndices []int,
	omegaWitness []uint64,
	domainPoints []uint64,
) (*sourceProductCarrierWitnessView, error) {
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
		return nil, fmt.Errorf("missing witness ncols for source-product carrier view")
	}
	pcsNCols := resolveProofPCSNCols(proof, 0)
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("missing pcs ncols for source-product carrier view")
	}
	if len(domainPoints) < pcsNCols {
		return nil, fmt.Errorf("source-product carrier view domain width=%d < pcs ncols=%d", len(domainPoints), pcsNCols)
	}
	theta := proof.Theta
	if theta <= 1 {
		theta = proof.PCSGeometry.Theta
	}
	if theta <= 1 {
		return nil, fmt.Errorf("source-product carrier view requires theta>1")
	}
	replayWitnessRows := proof.PCSGeometry.ReplayWitnessRows
	if replayWitnessRows <= 0 {
		replayWitnessRows = proof.MaskRowOffset
	}
	if replayWitnessRows <= 0 {
		return nil, fmt.Errorf("missing replay witness row count for source-product carrier view")
	}
	rowsPerBlock := witnessNCols + theta
	if rowsPerBlock <= 0 || replayWitnessRows%rowsPerBlock != 0 {
		return nil, fmt.Errorf("invalid source-product carrier geometry rows=%d rowsPerBlock=%d", replayWitnessRows, rowsPerBlock)
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
				return nil, fmt.Errorf("source-product carrier row overflow for poly=%d row=%d limit=%d", witnessPolyIdx, rowIdx, replayWitnessRows)
			}
			smallFieldRows = append(smallFieldRows, rowIdx)
		}
	}
	rowCoeffs, err := recoverSourceProductLowDegreeRowsFromMainPCS(ringQ, proof, smallFieldRows, domainPoints)
	if err != nil {
		return nil, err
	}
	return &sourceProductCarrierWitnessView{
		q:                 ringQ.Modulus[0],
		pcsOmega:          append([]uint64(nil), domainPoints[:pcsNCols]...),
		pcsNCols:          pcsNCols,
		witnessNCols:      witnessNCols,
		rowsPerBlock:      rowsPerBlock,
		replayWitnessRows: replayWitnessRows,
		rowCoeffs:         rowCoeffs,
	}, nil
}

func (v *sourceProductCarrierWitnessView) witnessHead(witnessPolyIdx int) ([]uint64, error) {
	if v == nil {
		return nil, fmt.Errorf("nil source-product carrier witness view")
	}
	if witnessPolyIdx < 0 {
		return nil, fmt.Errorf("invalid witness polynomial index %d", witnessPolyIdx)
	}
	block := witnessPolyIdx / v.pcsNCols
	slot := witnessPolyIdx % v.pcsNCols
	if slot < 0 || slot >= len(v.pcsOmega) {
		return nil, fmt.Errorf("source-product carrier slot %d out of range for pcs omega width=%d", slot, len(v.pcsOmega))
	}
	x := v.pcsOmega[slot] % v.q
	head := make([]uint64, v.witnessNCols)
	for omegaRow := 0; omegaRow < v.witnessNCols; omegaRow++ {
		rowIdx := block*v.rowsPerBlock + omegaRow
		if rowIdx < 0 || rowIdx >= v.replayWitnessRows {
			return nil, fmt.Errorf("source-product carrier row overflow for poly=%d row=%d limit=%d", witnessPolyIdx, rowIdx, v.replayWitnessRows)
		}
		coeffs, ok := v.rowCoeffs[rowIdx]
		if !ok {
			return nil, fmt.Errorf("missing recovered source-product carrier coeffs for row %d", rowIdx)
		}
		head[omegaRow] = EvalPoly(coeffs, x, v.q) % v.q
	}
	return head, nil
}
