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

const (
	PRFKeySourceModeDirect    = "direct_v1"
	PRFKeySourceModePack9Seed = "pack9_seed_v1"
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
	KeySourceMode         string
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
	keySourceMode := layout.KeySourceMode
	if keySourceMode == "" {
		keySourceMode = PRFKeySourceModeDirect
	}
	wantKeySourceSlots := len(layout.KeySlots)
	if keySourceMode == PRFKeySourceModePack9Seed {
		wantKeySourceSlots = len(layout.KeySlots) * intGenISISPRFSeedDigitsPerLane
	} else if keySourceMode != PRFKeySourceModeDirect {
		return fmt.Errorf("unsupported PRF key source mode %q", keySourceMode)
	}
	if len(layout.KeySourceSlots) > 0 && len(layout.KeySourceSlots) != wantKeySourceSlots {
		return fmt.Errorf("key source slots=%d want %d for mode %s", len(layout.KeySourceSlots), wantKeySourceSlots, keySourceMode)
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
	writeString(layout.KeySourceMode)
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
	writeInt(0)
	sum := sha256.Sum256(buf.Bytes())
	return append([]byte(nil), sum[:]...)
}
