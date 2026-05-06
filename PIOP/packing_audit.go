package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	"vSIS-Signature/internal/packedwidth"
)

// PackedMatrixAudit describes one packed field-valued matrix in the proof.
type PackedMatrixAudit struct {
	Component string `json:"component"`
	Rows      int    `json:"rows"`
	Cols      int    `json:"cols"`
	MaxValue  uint64 `json:"max_value"`
	BitWidth  int    `json:"bit_width"`
	Bytes     int    `json:"bytes"`
}

// PackedOpeningResidueAudit describes one residue stream inside a DECS opening.
type PackedOpeningResidueAudit struct {
	MaxValue    uint64 `json:"max_value"`
	BitWidth    int    `json:"bit_width"`
	Bytes       int    `json:"bytes"`
	EncodedCols int    `json:"encoded_cols"`
	OmittedCols int    `json:"omitted_cols"`
}

// PackedOpeningAudit describes the packed field-valued residue streams in a DECS opening.
type PackedOpeningAudit struct {
	Component  string                    `json:"component"`
	EntryCount int                       `json:"entry_count"`
	TotalBytes int                       `json:"total_bytes"`
	Pvals      PackedOpeningResidueAudit `json:"pvals"`
	Mvals      PackedOpeningResidueAudit `json:"mvals"`
}

// ProofPackingAudit records the packed field-valued proof objects relevant to the
// retained proof serializer.
type ProofPackingAudit struct {
	ModulusCeilingBits int                `json:"modulus_ceiling_bits"`
	MaxFieldBitWidth   int                `json:"max_field_bit_width"`
	VTargets           PackedMatrixAudit  `json:"vtargets"`
	QPayload           PackedMatrixAudit  `json:"q_payload"`
	QR                 PackedMatrixAudit  `json:"qr"`
	BarSets            PackedMatrixAudit  `json:"barsets"`
	RowOpening         PackedOpeningAudit `json:"row_opening"`
	QOpening           PackedOpeningAudit `json:"q_opening"`
	PCSOpening         PackedOpeningAudit `json:"pcs_opening"`
}

// BuildProofPackingAudit reports the encoded widths and maxima of the proof's packed
// field-valued components.
func BuildProofPackingAudit(proof *Proof, q uint64) (ProofPackingAudit, error) {
	if proof == nil {
		return ProofPackingAudit{}, fmt.Errorf("nil proof")
	}
	proof.syncPCSCompat()
	proof.ensureQPayloadPacked()
	if !proofUsesPaperQPayloadOnly(proof) {
		proof.ensureQRPacked()
	}
	proof.ensureVTargetsPacked()
	proof.ensureBarSetsPacked()
	audit := ProofPackingAudit{
		ModulusCeilingBits: packedwidth.ModulusCeiling(q),
	}
	audit.VTargets = buildPackedMatrixAudit("VTargets", proof.VTargetsMatrix(), proof.VTargetsBits, proof.VTargetsRows, proof.VTargetsCols, proof.VTargetsBitWidth)
	audit.QPayload = buildPackedMatrixAudit("QPayload", proof.QPayloadMatrix(), proof.QPayloadBits, proof.QPayloadRows, proof.QPayloadCols, proof.QPayloadBitWidth)
	audit.BarSets = buildPackedMatrixAudit("BarSets", proof.BarSetsMatrix(), proof.BarSetsBits, proof.BarSetsRows, proof.BarSetsCols, proof.BarSetsBitWidth)
	audit.RowOpening = buildPackedOpeningAudit("RowOpening", resolveProofPCSOpening(proof))
	audit.PCSOpening = buildPackedOpeningAudit("PCSOpening", proof.PCSOpening)
	if !proofUsesPaperQPayloadOnly(proof) {
		audit.QR = buildPackedMatrixAudit("QR", proof.QRMatrix(), proof.QRBits, proof.QRRows, proof.QRCols, proof.QRBitWidth)
		audit.QOpening = buildPackedOpeningAudit("QOpening", proof.QOpening)
	}
	audit.MaxFieldBitWidth = maxPackingWidth(
		audit.VTargets.BitWidth,
		audit.QPayload.BitWidth,
		audit.QR.BitWidth,
		audit.BarSets.BitWidth,
		audit.RowOpening.Pvals.BitWidth,
		audit.RowOpening.Mvals.BitWidth,
		audit.QOpening.Pvals.BitWidth,
		audit.QOpening.Mvals.BitWidth,
		audit.PCSOpening.Pvals.BitWidth,
		audit.PCSOpening.Mvals.BitWidth,
	)
	return audit, nil
}

func buildPackedMatrixAudit(component string, mat [][]uint64, bits []byte, rows, cols int, width uint8) PackedMatrixAudit {
	if rows <= 0 {
		rows = len(mat)
	}
	if cols <= 0 {
		cols = matrixAuditCols(mat)
	}
	maxValue := matrixAuditMaxValue(mat)
	bitWidth := int(width)
	if bitWidth == 0 && (len(bits) > 0 || len(mat) > 0) {
		bitWidth = packedwidth.ExactForMax(maxValue)
	}
	return PackedMatrixAudit{
		Component: component,
		Rows:      rows,
		Cols:      cols,
		MaxValue:  maxValue,
		BitWidth:  bitWidth,
		Bytes:     len(bits),
	}
}

func buildPackedOpeningAudit(component string, open *decs.DECSOpening) PackedOpeningAudit {
	if open == nil {
		return PackedOpeningAudit{Component: component}
	}
	return PackedOpeningAudit{
		Component:  component,
		EntryCount: open.EntryCount(),
		TotalBytes: sizeDECSOpening(open),
		Pvals: PackedOpeningResidueAudit{
			MaxValue:    openingAuditMaxPValue(open),
			BitWidth:    openingAuditPBitWidth(open),
			Bytes:       openingAuditResidueBytes(open.Pvals, open.PvalsBits, open.PvalsColumnWidths),
			EncodedCols: openingAuditPCols(open),
			OmittedCols: len(open.POmitCols),
		},
		Mvals: PackedOpeningResidueAudit{
			MaxValue:    openingAuditMaxMValue(open),
			BitWidth:    openingAuditMBitWidth(open),
			Bytes:       openingAuditResidueBytes(open.Mvals, open.MvalsBits, open.MvalsColumnWidths),
			EncodedCols: openingAuditMCols(open),
			OmittedCols: len(open.MOmitCols),
		},
	}
}

func matrixAuditCols(mat [][]uint64) int {
	cols := 0
	for _, row := range mat {
		if len(row) > cols {
			cols = len(row)
		}
	}
	return cols
}

func matrixAuditMaxValue(mat [][]uint64) uint64 {
	var max uint64
	for _, row := range mat {
		for _, v := range row {
			if v > max {
				max = v
			}
		}
	}
	return max
}

func openingAuditPCols(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	if open.FormatVersion != decs.OpeningFormatPlain {
		if open.PColsEncoded > 0 {
			return open.PColsEncoded
		}
		if len(open.PvalsColumnWidths) > 0 {
			return len(open.PvalsColumnWidths)
		}
		return 0
	}
	if open.R > 0 {
		return open.R
	}
	if len(open.Pvals) > 0 {
		return len(open.Pvals[0])
	}
	return 0
}

func openingAuditMCols(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	if open.MFormatVersion != decs.OpeningFormatPlain {
		if open.MColsEncoded > 0 {
			return open.MColsEncoded
		}
		if len(open.MvalsColumnWidths) > 0 {
			return len(open.MvalsColumnWidths)
		}
		return 0
	}
	if open.Eta > 0 {
		return open.Eta
	}
	if len(open.Mvals) > 0 {
		return len(open.Mvals[0])
	}
	return 0
}

func openingAuditPBitWidth(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	if open.PvalsBitWidth != 0 {
		return int(open.PvalsBitWidth)
	}
	if len(open.PvalsColumnWidths) > 0 {
		return maxUint8(open.PvalsColumnWidths)
	}
	if len(open.PvalsBits) > 0 || len(open.Pvals) > 0 {
		return 20
	}
	return 0
}

func openingAuditMBitWidth(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	if open.MvalsBitWidth != 0 {
		return int(open.MvalsBitWidth)
	}
	if len(open.MvalsColumnWidths) > 0 {
		return maxUint8(open.MvalsColumnWidths)
	}
	if len(open.MvalsBits) > 0 || len(open.Mvals) > 0 {
		return 20
	}
	return 0
}

func openingAuditMaxPValue(open *decs.DECSOpening) uint64 {
	cols := openingAuditPCols(open)
	if open == nil || cols <= 0 {
		return 0
	}
	var max uint64
	for t := 0; t < open.EntryCount(); t++ {
		for k := 0; k < cols; k++ {
			if v := decs.GetOpeningPval(open, t, k); v > max {
				max = v
			}
		}
	}
	return max
}

func openingAuditMaxMValue(open *decs.DECSOpening) uint64 {
	cols := openingAuditMCols(open)
	if open == nil || cols <= 0 {
		return 0
	}
	var max uint64
	for t := 0; t < open.EntryCount(); t++ {
		for k := 0; k < cols; k++ {
			if v := decs.GetOpeningMval(open, t, k); v > max {
				max = v
			}
		}
	}
	return max
}

func openingAuditResidueBytes(rows [][]uint64, bits []byte, columnWidths []uint8) int {
	if len(bits) > 0 {
		return len(bits) + len(columnWidths)
	}
	return sizeUint64Matrix(rows)
}

func maxUint8(vals []uint8) int {
	max := 0
	for _, v := range vals {
		if int(v) > max {
			max = int(v)
		}
	}
	return max
}

func maxPackingWidth(widths ...int) int {
	max := 0
	for _, width := range widths {
		if width > max {
			max = width
		}
	}
	return max
}
