package PIOP

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	decs "vSIS-Signature/DECS"
)

type RowSemantics uint8

const (
	EvalDomainRow RowSemantics = iota
	CoeffPackedRow
)

type KeySource uint8

const (
	KeySourceIndependentWitness KeySource = iota
)

type CoeffSlot struct {
	Row   int
	Coeff int
}

type PRFCompanionLayout struct {
	StartRow              int
	PackWidth             int
	GroupRounds           int
	KeySource             KeySource
	KeySlots              []CoeffSlot
	KeySourceSlots        []CoeffSlot
	KeySourceDecodeLanes  []int
	CheckpointSlots       []CoeffSlot
	FinalRoundOutputSlots []CoeffSlot
	FinalTagSlots         []CoeffSlot
	HelperFamilies        []string
	ReplayRows            int
	PackedRows            int
	PackedLogicalCount    int
	HelperRowCount        int
	DataRows              int
	HelperRows            int
	KeyCount              int
	CheckpointCount       int
	FinalRoundOutputCount int
	TagCount              int
	RelationVersion       uint8
	RowSemantics          []RowSemantics
	BridgeStripe          *PRFBridgeStripeLayout
}

type PRFCompanionOpening struct {
	Masked []uint64
	Mask   []uint64
}

type PRFCheckpointAuditOpening struct {
	Z    PRFCompanionOpening
	Wire PRFCompanionOpening
}

type PRFCompanionProof struct {
	Mode              PRFCompanionMode
	CheckpointSamples int
	BridgeInQ         bool
	Layout            *PRFCompanionLayout
	BridgeChecks      [][]uint64
	BridgeChecksBits  []byte
	CheckpointAudits  []PRFCheckpointAuditOpening
	TagFinal          PRFCompanionOpening
	KeyTrunc          PRFCompanionOpening
	CoordDigest       []byte
	Bridge            *PRFWitnessOmegaBridge
	AuxInstance       *PRFCompanionAuxInstance
}

type PRFWitnessOmegaBridge struct {
	Version        int
	RowIndices     []int
	PhysicalRows   []int
	SupportSlots   []int
	RowsOpening    *decs.DECSOpening
	PackedDigest   []byte
	CoordDigest    []byte
	GeometryDigest []byte
	BridgeDigest   []byte
}

type PRFBridgeStripeLayout struct {
	Version      int
	SourceRows   []int
	PhysicalRows []int
	SupportSlots []int
	PackWidth    int
}

type PRFCompanionAuxInstance struct {
	Proof *Proof
}

func cloneProofForPRFAux(src *Proof) *Proof {
	if src == nil {
		return nil
	}
	out := *src
	if src.PRFCompanion != nil {
		out.PRFCompanion = clonePRFCompanionProof(src.PRFCompanion)
	}
	if src.SourceProductBridge != nil {
		out.SourceProductBridge = cloneSourceProductBridge(src.SourceProductBridge)
	}
	if src.SigShortness != nil {
		out.SigShortness = &SigShortnessProof{
			Version:      src.SigShortness.Version,
			SupportSlots: append([]int(nil), src.SigShortness.SupportSlots...),
			Opening:      cloneDECSOpening(src.SigShortness.Opening),
		}
		if src.SigShortness.V5 != nil {
			v5 := *src.SigShortness.V5
			v5.THatOpening = cloneDECSOpening(src.SigShortness.V5.THatOpening)
			out.SigShortness.V5 = &v5
		}
		if src.SigShortness.V6 != nil {
			v6 := *src.SigShortness.V6
			v6.HiddenProof = cloneProofForPRFAux(src.SigShortness.V6.HiddenProof)
			v6.THatOpening = cloneDECSOpening(src.SigShortness.V6.THatOpening)
			out.SigShortness.V6 = &v6
		}
		if src.SigShortness.V7 != nil {
			v7 := *src.SigShortness.V7
			out.SigShortness.V7 = &v7
		}
		if src.SigShortness.V8 != nil {
			v8 := *src.SigShortness.V8
			v8.HiddenProof = cloneProofForPRFAux(src.SigShortness.V8.HiddenProof)
			v8.THatHeads = SigShortnessPackedMatrix{
				Bits:     append([]byte(nil), src.SigShortness.V8.THatHeads.Bits...),
				BitWidth: src.SigShortness.V8.THatHeads.BitWidth,
			}
			out.SigShortness.V8 = &v8
		}
		if src.SigShortness.V9 != nil {
			v9 := *src.SigShortness.V9
			v9.HiddenProof = cloneProofForPRFAux(src.SigShortness.V9.HiddenProof)
			v9.THatCommitment.Heads = SigShortnessPackedMatrix{
				Bits:     append([]byte(nil), src.SigShortness.V9.THatCommitment.Heads.Bits...),
				BitWidth: src.SigShortness.V9.THatCommitment.Heads.BitWidth,
			}
			v9.CommitmentParamsDigest = append([]byte(nil), src.SigShortness.V9.CommitmentParamsDigest...)
			v9.MainOpeningDigest = append([]byte(nil), src.SigShortness.V9.MainOpeningDigest...)
			v9.HiddenOpeningDigest = append([]byte(nil), src.SigShortness.V9.HiddenOpeningDigest...)
			out.SigShortness.V9 = &v9
		}
		if src.SigShortness.V10 != nil {
			v10 := *src.SigShortness.V10
			out.SigShortness.V10 = &v10
		}
		if src.SigShortness.V12 != nil {
			v12 := *src.SigShortness.V12
			out.SigShortness.V12 = &v12
		}
		if src.SigShortness.V13 != nil {
			v13 := *src.SigShortness.V13
			v13.LookupTableDigest = append([]byte(nil), src.SigShortness.V13.LookupTableDigest...)
			out.SigShortness.V13 = &v13
		}
		if src.SigShortness.V18 != nil {
			v18 := *src.SigShortness.V18
			v18.LayoutDigest = append([]byte(nil), src.SigShortness.V18.LayoutDigest...)
			v18.ReplayCompactDigest = append([]byte(nil), src.SigShortness.V18.ReplayCompactDigest...)
			v18.PRFCompactDigest = append([]byte(nil), src.SigShortness.V18.PRFCompactDigest...)
			out.SigShortness.V18 = &v18
		}
	}
	return &out
}

func cloneSourceProductBridge(src *SourceProductBridge) *SourceProductBridge {
	if src == nil {
		return nil
	}
	return &SourceProductBridge{
		Version:        src.Version,
		RowIndices:     append([]int(nil), src.RowIndices...),
		PhysicalRows:   append([]int(nil), src.PhysicalRows...),
		SupportSlots:   append([]int(nil), src.SupportSlots...),
		RowsOpening:    cloneDECSOpening(src.RowsOpening),
		PackedDigest:   append([]byte(nil), src.PackedDigest...),
		GeometryDigest: append([]byte(nil), src.GeometryDigest...),
		BridgeDigest:   append([]byte(nil), src.BridgeDigest...),
	}
}

func clonePRFCompanionOpening(src PRFCompanionOpening) PRFCompanionOpening {
	return PRFCompanionOpening{
		Masked: append([]uint64(nil), src.Masked...),
		Mask:   append([]uint64(nil), src.Mask...),
	}
}

func cloneCoeffSlots(src []CoeffSlot) []CoeffSlot {
	if len(src) == 0 {
		return nil
	}
	out := make([]CoeffSlot, len(src))
	copy(out, src)
	return out
}

func clonePRFCompanionLayout(src *PRFCompanionLayout) *PRFCompanionLayout {
	if src == nil {
		return nil
	}
	out := *src
	out.KeySlots = cloneCoeffSlots(src.KeySlots)
	out.KeySourceSlots = cloneCoeffSlots(src.KeySourceSlots)
	if len(src.KeySourceDecodeLanes) > 0 {
		out.KeySourceDecodeLanes = append([]int(nil), src.KeySourceDecodeLanes...)
	}
	out.CheckpointSlots = cloneCoeffSlots(src.CheckpointSlots)
	out.FinalRoundOutputSlots = cloneCoeffSlots(src.FinalRoundOutputSlots)
	out.FinalTagSlots = cloneCoeffSlots(src.FinalTagSlots)
	if len(src.HelperFamilies) > 0 {
		out.HelperFamilies = append([]string(nil), src.HelperFamilies...)
	}
	if len(src.RowSemantics) > 0 {
		out.RowSemantics = append([]RowSemantics(nil), src.RowSemantics...)
	}
	if src.BridgeStripe != nil {
		out.BridgeStripe = &PRFBridgeStripeLayout{
			Version:      src.BridgeStripe.Version,
			SourceRows:   append([]int(nil), src.BridgeStripe.SourceRows...),
			PhysicalRows: append([]int(nil), src.BridgeStripe.PhysicalRows...),
			SupportSlots: append([]int(nil), src.BridgeStripe.SupportSlots...),
			PackWidth:    src.BridgeStripe.PackWidth,
		}
	}
	return &out
}

func clonePRFCheckpointAuditOpenings(src []PRFCheckpointAuditOpening) []PRFCheckpointAuditOpening {
	if len(src) == 0 {
		return nil
	}
	out := make([]PRFCheckpointAuditOpening, len(src))
	for i := range src {
		out[i] = PRFCheckpointAuditOpening{
			Z:    clonePRFCompanionOpening(src[i].Z),
			Wire: clonePRFCompanionOpening(src[i].Wire),
		}
	}
	return out
}

func clonePRFCompanionProof(src *PRFCompanionProof) *PRFCompanionProof {
	if src == nil {
		return nil
	}
	out := *src
	out.Layout = clonePRFCompanionLayout(src.Layout)
	out.BridgeChecks = copyMatrix(src.BridgeChecks)
	out.BridgeChecksBits = append([]byte(nil), src.BridgeChecksBits...)
	out.CheckpointAudits = clonePRFCheckpointAuditOpenings(src.CheckpointAudits)
	out.TagFinal = clonePRFCompanionOpening(src.TagFinal)
	out.KeyTrunc = clonePRFCompanionOpening(src.KeyTrunc)
	out.CoordDigest = append([]byte(nil), src.CoordDigest...)
	if src.Bridge != nil {
		out.Bridge = &PRFWitnessOmegaBridge{
			Version:        src.Bridge.Version,
			RowIndices:     append([]int(nil), src.Bridge.RowIndices...),
			PhysicalRows:   append([]int(nil), src.Bridge.PhysicalRows...),
			SupportSlots:   append([]int(nil), src.Bridge.SupportSlots...),
			RowsOpening:    cloneDECSOpening(src.Bridge.RowsOpening),
			PackedDigest:   append([]byte(nil), src.Bridge.PackedDigest...),
			CoordDigest:    append([]byte(nil), src.Bridge.CoordDigest...),
			GeometryDigest: append([]byte(nil), src.Bridge.GeometryDigest...),
			BridgeDigest:   append([]byte(nil), src.Bridge.BridgeDigest...),
		}
	}
	if src.AuxInstance != nil {
		out.AuxInstance = &PRFCompanionAuxInstance{
			Proof: cloneProofForPRFAux(src.AuxInstance.Proof),
		}
	}
	return &out
}

// ClonePRFCompanionProofForTest exposes the internal deep-clone helper to
// cross-package integration tests.
func ClonePRFCompanionProofForTest(src *PRFCompanionProof) *PRFCompanionProof {
	return clonePRFCompanionProof(src)
}

func prfCompanionOrderedOpenings(proof *PRFCompanionProof) []*PRFCompanionOpening {
	if proof == nil {
		return nil
	}
	openings := make([]*PRFCompanionOpening, 0)
	for i := range proof.CheckpointAudits {
		openings = append(openings, &proof.CheckpointAudits[i].Z, &proof.CheckpointAudits[i].Wire)
	}
	openings = append(openings, &proof.TagFinal, &proof.KeyTrunc)
	return openings
}

func prfCompanionHasOpeningPayload(proof *PRFCompanionProof) bool {
	for _, opening := range prfCompanionOrderedOpenings(proof) {
		if opening != nil && (len(opening.Masked) > 0 || len(opening.Mask) > 0) {
			return true
		}
	}
	return false
}

func prfCompanionOpeningPayloadMatrix(proof *PRFCompanionProof) [][]uint64 {
	if proof == nil {
		return nil
	}
	openings := prfCompanionOrderedOpenings(proof)
	if len(openings) == 0 {
		return nil
	}
	out := make([][]uint64, 0, len(openings)*2)
	for _, opening := range openings {
		if opening == nil {
			out = append(out, nil, nil)
			continue
		}
		out = append(out, append([]uint64(nil), opening.Masked...))
		out = append(out, append([]uint64(nil), opening.Mask...))
	}
	return out
}

func prfCompanionOpeningPayloadBytes(proof *PRFCompanionProof) []byte {
	mat := prfCompanionOpeningPayloadMatrix(proof)
	if len(mat) == 0 {
		return nil
	}
	return bytesFromUint64Matrix(mat)
}

func prfCompanionPackedRowIndices(layout *PRFCompanionLayout) []int {
	if layout == nil || layout.PackedRows <= 0 || layout.StartRow < 0 {
		return nil
	}
	out := make([]int, layout.PackedRows)
	for i := 0; i < layout.PackedRows; i++ {
		out[i] = layout.StartRow + i
	}
	return out
}

func companionRowsFromWitnessRows(rows [][]uint64, layout *PRFCompanionLayout) ([][]uint64, error) {
	if layout == nil {
		return nil, nil
	}
	if layout.PackedRows <= 0 {
		return nil, fmt.Errorf("invalid companion packed rows=%d", layout.PackedRows)
	}
	if layout.StartRow < 0 || layout.StartRow+layout.PackedRows > len(rows) {
		return nil, fmt.Errorf("companion row window [%d,%d) out of range for rows=%d", layout.StartRow, layout.StartRow+layout.PackedRows, len(rows))
	}
	out := make([][]uint64, layout.PackedRows)
	for i := 0; i < layout.PackedRows; i++ {
		head := append([]uint64(nil), rows[layout.StartRow+i]...)
		out[i] = head
	}
	return out, nil
}

func ValidatePRFCompanionLayout(layout *PRFCompanionLayout, witnessRows int) error {
	if layout == nil {
		return nil
	}
	if witnessRows < 0 {
		return fmt.Errorf("invalid witness row count %d", witnessRows)
	}
	if layout.StartRow < 0 {
		return fmt.Errorf("invalid companion start row %d", layout.StartRow)
	}
	if layout.PackWidth <= 0 {
		return fmt.Errorf("invalid companion pack width %d", layout.PackWidth)
	}
	if layout.GroupRounds < 0 {
		return fmt.Errorf("invalid companion group rounds %d", layout.GroupRounds)
	}
	if layout.PackedRows <= 0 {
		return fmt.Errorf("invalid companion packed rows %d", layout.PackedRows)
	}
	if layout.ReplayRows < 0 || layout.ReplayRows > layout.PackedRows {
		return fmt.Errorf("invalid companion replay rows %d for packed rows %d", layout.ReplayRows, layout.PackedRows)
	}
	if layout.StartRow+layout.PackedRows > witnessRows {
		return fmt.Errorf("companion packed rows [%d,%d) exceed witness rows=%d", layout.StartRow, layout.StartRow+layout.PackedRows, witnessRows)
	}
	if len(layout.RowSemantics) != layout.PackedRows {
		return fmt.Errorf("companion row semantics len=%d want packed rows=%d", len(layout.RowSemantics), layout.PackedRows)
	}
	for i, sem := range layout.RowSemantics {
		if sem != CoeffPackedRow {
			return fmt.Errorf("unexpected companion row semantics[%d]=%d", i, sem)
		}
	}
	checkSlot := func(kind string, slot CoeffSlot) error {
		if slot.Row < layout.StartRow || slot.Row >= layout.StartRow+layout.PackedRows {
			return fmt.Errorf("%s slot row=%d outside packed row window [%d,%d)", kind, slot.Row, layout.StartRow, layout.StartRow+layout.PackedRows)
		}
		if slot.Coeff < 0 || slot.Coeff >= layout.PackWidth {
			return fmt.Errorf("%s slot coeff=%d outside [0,%d)", kind, slot.Coeff, layout.PackWidth)
		}
		return nil
	}
	for _, slot := range layout.KeySlots {
		if err := checkSlot("key", slot); err != nil {
			return err
		}
	}
	for _, slot := range layout.KeySourceSlots {
		if slot.Row < 0 || slot.Row >= witnessRows {
			return fmt.Errorf("key source slot row=%d outside witness rows=%d", slot.Row, witnessRows)
		}
		if slot.Coeff < 0 || slot.Coeff >= layout.PackWidth {
			return fmt.Errorf("key source slot coeff=%d outside [0,%d)", slot.Coeff, layout.PackWidth)
		}
	}
	if len(layout.KeySourceSlots) > 0 && len(layout.KeySourceSlots) != len(layout.KeySlots) {
		return fmt.Errorf("key source slots=%d want key slots=%d", len(layout.KeySourceSlots), len(layout.KeySlots))
	}
	if len(layout.KeySourceDecodeLanes) > 0 {
		if len(layout.KeySourceDecodeLanes) != len(layout.KeySourceSlots) {
			return fmt.Errorf("key source decode lanes=%d want key source slots=%d", len(layout.KeySourceDecodeLanes), len(layout.KeySourceSlots))
		}
		for i, lane := range layout.KeySourceDecodeLanes {
			if lane < 0 {
				return fmt.Errorf("key source decode lane[%d]=%d is negative", i, lane)
			}
		}
	}
	for _, slot := range layout.CheckpointSlots {
		if err := checkSlot("checkpoint", slot); err != nil {
			return err
		}
	}
	for _, slot := range layout.FinalRoundOutputSlots {
		if err := checkSlot("final_round_output", slot); err != nil {
			return err
		}
	}
	for _, slot := range layout.FinalTagSlots {
		if err := checkSlot("final_tag", slot); err != nil {
			return err
		}
	}
	wantLogical := len(layout.KeySlots) + len(layout.CheckpointSlots) + len(layout.FinalRoundOutputSlots) + len(layout.FinalTagSlots)
	if layout.PackedLogicalCount != wantLogical {
		return fmt.Errorf("companion packed logical count=%d want %d", layout.PackedLogicalCount, wantLogical)
	}
	if layout.HelperRowCount < 0 {
		return fmt.Errorf("invalid companion helper row count %d", layout.HelperRowCount)
	}
	if layout.DataRows < 0 {
		return fmt.Errorf("invalid companion data rows %d", layout.DataRows)
	}
	if layout.HelperRows < 0 {
		return fmt.Errorf("invalid companion helper rows %d", layout.HelperRows)
	}
	if layout.KeyCount != len(layout.KeySlots) {
		return fmt.Errorf("companion key count=%d want %d", layout.KeyCount, len(layout.KeySlots))
	}
	if layout.CheckpointCount != len(layout.CheckpointSlots) {
		return fmt.Errorf("companion checkpoint count=%d want %d", layout.CheckpointCount, len(layout.CheckpointSlots))
	}
	if layout.FinalRoundOutputCount != len(layout.FinalRoundOutputSlots) {
		return fmt.Errorf("companion final round output count=%d want %d", layout.FinalRoundOutputCount, len(layout.FinalRoundOutputSlots))
	}
	switch layout.RelationVersion {
	case 0:
		if layout.FinalRoundOutputCount != 0 || len(layout.FinalRoundOutputSlots) != 0 {
			return fmt.Errorf("legacy companion relation carries final-round output slots")
		}
	case 1:
		if layout.FinalRoundOutputCount <= 0 {
			return fmt.Errorf("direct_full companion relation requires final-round output slots")
		}
	default:
		return fmt.Errorf("unsupported companion relation version %d", layout.RelationVersion)
	}
	if layout.BridgeStripe != nil {
		if layout.BridgeStripe.Version <= 0 {
			return fmt.Errorf("invalid bridge stripe version %d", layout.BridgeStripe.Version)
		}
		if layout.BridgeStripe.PackWidth != layout.PackWidth {
			return fmt.Errorf("bridge stripe pack width=%d want %d", layout.BridgeStripe.PackWidth, layout.PackWidth)
		}
		if len(layout.BridgeStripe.SourceRows) != len(layout.BridgeStripe.PhysicalRows) {
			return fmt.Errorf("bridge stripe source rows=%d want physical rows=%d", len(layout.BridgeStripe.SourceRows), len(layout.BridgeStripe.PhysicalRows))
		}
		if err := validateSortedUniqueIndices("prf bridge stripe source rows", layout.BridgeStripe.SourceRows); err != nil {
			return err
		}
		if err := validateSortedUniqueIndices("prf bridge stripe physical rows", layout.BridgeStripe.PhysicalRows); err != nil {
			return err
		}
		if err := validateSortedUniqueIndices("prf bridge stripe support slots", layout.BridgeStripe.SupportSlots); err != nil {
			return err
		}
		for _, row := range layout.BridgeStripe.SourceRows {
			if row < layout.StartRow || row >= layout.StartRow+layout.PackedRows {
				return fmt.Errorf("bridge stripe source row=%d outside packed row window [%d,%d)", row, layout.StartRow, layout.StartRow+layout.PackedRows)
			}
		}
		for _, row := range layout.BridgeStripe.PhysicalRows {
			if row < 0 || row >= witnessRows {
				return fmt.Errorf("bridge stripe physical row=%d outside witness rows=%d", row, witnessRows)
			}
		}
		for _, slot := range layout.BridgeStripe.SupportSlots {
			if slot < 0 || slot >= layout.BridgeStripe.PackWidth {
				return fmt.Errorf("bridge stripe support slot=%d outside [0,%d)", slot, layout.BridgeStripe.PackWidth)
			}
		}
	}
	return nil
}

func prfCompanionLayoutDigest(layout *PRFCompanionLayout) []byte {
	if layout == nil {
		return nil
	}
	var buf bytes.Buffer
	writeInt := func(v int) {
		_ = binary.Write(&buf, binary.LittleEndian, int64(v))
	}
	writeUint8 := func(v uint8) {
		_ = buf.WriteByte(v)
	}
	writeString := func(v string) {
		writeInt(len(v))
		_, _ = buf.WriteString(v)
	}
	writeInt(layout.StartRow)
	writeInt(layout.PackWidth)
	writeUint8(uint8(layout.KeySource))
	writeInt(layout.PackedRows)
	writeInt(layout.PackedLogicalCount)
	writeInt(layout.HelperRowCount)
	writeInt(len(layout.KeySlots))
	for _, slot := range layout.KeySlots {
		writeInt(slot.Row)
		writeInt(slot.Coeff)
	}
	writeInt(len(layout.KeySourceSlots))
	for _, slot := range layout.KeySourceSlots {
		writeInt(slot.Row)
		writeInt(slot.Coeff)
	}
	writeInt(len(layout.KeySourceDecodeLanes))
	for _, lane := range layout.KeySourceDecodeLanes {
		writeInt(lane)
	}
	writeInt(len(layout.CheckpointSlots))
	for _, slot := range layout.CheckpointSlots {
		writeInt(slot.Row)
		writeInt(slot.Coeff)
	}
	if layout.RelationVersion != 0 {
		writeInt(layout.GroupRounds)
		writeInt(len(layout.FinalRoundOutputSlots))
		for _, slot := range layout.FinalRoundOutputSlots {
			writeInt(slot.Row)
			writeInt(slot.Coeff)
		}
	}
	writeInt(len(layout.FinalTagSlots))
	for _, slot := range layout.FinalTagSlots {
		writeInt(slot.Row)
		writeInt(slot.Coeff)
	}
	writeInt(layout.DataRows)
	writeInt(layout.HelperRows)
	writeInt(layout.KeyCount)
	writeInt(layout.CheckpointCount)
	if layout.RelationVersion != 0 {
		writeInt(layout.FinalRoundOutputCount)
		writeUint8(layout.RelationVersion)
	}
	writeInt(layout.TagCount)
	writeInt(len(layout.HelperFamilies))
	for _, fam := range layout.HelperFamilies {
		writeString(fam)
	}
	writeInt(len(layout.RowSemantics))
	for _, sem := range layout.RowSemantics {
		writeUint8(uint8(sem))
	}
	if layout.BridgeStripe != nil {
		writeInt(layout.BridgeStripe.Version)
		writeInt(layout.BridgeStripe.PackWidth)
		writeInt(len(layout.BridgeStripe.SourceRows))
		for _, row := range layout.BridgeStripe.SourceRows {
			writeInt(row)
		}
		writeInt(len(layout.BridgeStripe.PhysicalRows))
		for _, row := range layout.BridgeStripe.PhysicalRows {
			writeInt(row)
		}
		writeInt(len(layout.BridgeStripe.SupportSlots))
		for _, slot := range layout.BridgeStripe.SupportSlots {
			writeInt(slot)
		}
	} else {
		writeInt(0)
	}
	sum := sha256.Sum256(buf.Bytes())
	return append([]byte(nil), sum[:]...)
}

func prfCompanionSourceRowSet(rows []int) map[int]struct{} {
	out := make(map[int]struct{}, len(rows))
	for _, row := range rows {
		out[row] = struct{}{}
	}
	return out
}

func prfCompanionBridgeStripeSourceRows(layout *PRFCompanionLayout) []int {
	if layout == nil {
		return nil
	}
	if layout.BridgeStripe != nil && len(layout.BridgeStripe.SourceRows) > 0 {
		return append([]int(nil), layout.BridgeStripe.SourceRows...)
	}
	rows := append([]int(nil), prfCompanionKeyRowIndices(layout)...)
	rows = append(rows, prfCompanionDirectAuthRowIndices(layout)...)
	return sortedUniqueInts(rows)
}
