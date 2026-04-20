package PIOP

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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
	StartRow           int
	PackWidth          int
	KeySource          KeySource
	KeySlots           []CoeffSlot
	CheckpointSlots    []CoeffSlot
	FinalTagSlots      []CoeffSlot
	HelperFamilies     []string
	ReplayRows         int
	PackedRows         int
	PackedLogicalCount int
	HelperRowCount     int
	DataRows           int
	HelperRows         int
	KeyCount           int
	CheckpointCount    int
	TagCount           int
	RowSemantics       []RowSemantics
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
	out.CheckpointSlots = cloneCoeffSlots(src.CheckpointSlots)
	out.FinalTagSlots = cloneCoeffSlots(src.FinalTagSlots)
	if len(src.HelperFamilies) > 0 {
		out.HelperFamilies = append([]string(nil), src.HelperFamilies...)
	}
	if len(src.RowSemantics) > 0 {
		out.RowSemantics = append([]RowSemantics(nil), src.RowSemantics...)
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
	for _, slot := range layout.CheckpointSlots {
		if err := checkSlot("checkpoint", slot); err != nil {
			return err
		}
	}
	for _, slot := range layout.FinalTagSlots {
		if err := checkSlot("final_tag", slot); err != nil {
			return err
		}
	}
	wantLogical := len(layout.KeySlots) + len(layout.CheckpointSlots) + len(layout.FinalTagSlots)
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
	writeInt(len(layout.CheckpointSlots))
	for _, slot := range layout.CheckpointSlots {
		writeInt(slot.Row)
		writeInt(slot.Coeff)
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
	writeInt(layout.TagCount)
	writeInt(len(layout.HelperFamilies))
	for _, fam := range layout.HelperFamilies {
		writeString(fam)
	}
	writeInt(len(layout.RowSemantics))
	for _, sem := range layout.RowSemantics {
		writeUint8(uint8(sem))
	}
	sum := sha256.Sum256(buf.Bytes())
	return append([]byte(nil), sum[:]...)
}
