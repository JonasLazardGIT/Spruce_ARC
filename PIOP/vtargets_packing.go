package PIOP

import (
	"encoding/binary"
	"fmt"

	"vSIS-Signature/internal/packedwidth"
)

const (
	vTargetsFormatDense  = byte(1)
	vTargetsFormatRagged = byte(2)
	vTargetsHeaderSize   = 10
)

func (p *Proof) setVTargets(mat [][]uint64) {
	if len(mat) == 0 {
		p.VTargets = nil
		p.VTargetsBits = nil
		p.VTargetsRows = 0
		p.VTargetsCols = 0
		p.VTargetsBitWidth = 0
		return
	}
	bits, rows, cols, width := packProofVTargets(p, mat)
	p.VTargetsBits = bits
	p.VTargetsRows = rows
	p.VTargetsCols = cols
	p.VTargetsBitWidth = uint8(width)
	p.VTargets = nil
}

func (p *Proof) ensureVTargetsPacked() {
	if len(p.VTargetsBits) == 0 && len(p.VTargets) > 0 {
		p.setVTargets(p.VTargets)
	}
}

func (p *Proof) VTargetsMatrix() [][]uint64 {
	if len(p.VTargets) > 0 {
		return p.VTargets
	}
	if len(p.VTargetsBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := unpackProofVTargets(p, p.VTargetsBits)
	if err != nil {
		return nil
	}
	p.VTargets = mat
	p.VTargetsRows = rows
	p.VTargetsCols = cols
	p.VTargetsBitWidth = uint8(width)
	return mat
}

func packProofVTargets(p *Proof, mat [][]uint64) ([]byte, int, int, int) {
	rows := len(mat)
	cols := matrixEqualWidth(mat)
	if rows == 0 || cols == 0 {
		return nil, 0, 0, 0
	}
	width := packedwidth.ExactForMax(matrixAuditMaxValue(mat))
	format := vTargetsFormatDense
	rowWidths := make([]int, rows)
	for i := range rowWidths {
		rowWidths[i] = cols
	}
	if ragged := deriveVTargetsRaggedWidths(p, rows, cols); len(ragged) == rows && raggedWidthsUsable(mat, ragged) {
		rowWidths = ragged
		format = vTargetsFormatRagged
	}
	payload := packVariableWidthUintRows(mat, rowWidths, width)
	bits := make([]byte, vTargetsHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(bits[0:4], uint32(rows))
	binary.LittleEndian.PutUint32(bits[4:8], uint32(cols))
	bits[8] = byte(width)
	bits[9] = format
	copy(bits[vTargetsHeaderSize:], payload)
	return bits, rows, cols, width
}

func unpackProofVTargets(p *Proof, bits []byte) ([][]uint64, int, int, int, error) {
	if len(bits) < vTargetsHeaderSize {
		return nil, 0, 0, 0, fmt.Errorf("proof: VTargets too short")
	}
	rows := int(binary.LittleEndian.Uint32(bits[0:4]))
	cols := int(binary.LittleEndian.Uint32(bits[4:8]))
	width := int(bits[8])
	format := bits[9]
	if rows <= 0 || cols <= 0 {
		return nil, 0, 0, 0, fmt.Errorf("proof: invalid VTargets dimensions rows=%d cols=%d", rows, cols)
	}
	if width <= 0 || width > 64 {
		return nil, 0, 0, 0, fmt.Errorf("proof: invalid VTargets bit width %d", width)
	}
	rowWidths := make([]int, rows)
	for i := range rowWidths {
		rowWidths[i] = cols
	}
	switch format {
	case vTargetsFormatDense:
		// keep dense widths
	case vTargetsFormatRagged:
		ragged := deriveVTargetsRaggedWidths(p, rows, cols)
		if len(ragged) != rows {
			return nil, 0, 0, 0, fmt.Errorf("proof: ragged VTargets geometry unavailable")
		}
		rowWidths = ragged
	default:
		return nil, 0, 0, 0, fmt.Errorf("proof: unknown VTargets format %d", format)
	}
	mat, err := unpackVariableWidthUintRows(bits[vTargetsHeaderSize:], rows, cols, rowWidths, width)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	return mat, rows, cols, width, nil
}

func deriveVTargetsRaggedWidths(p *Proof, rows, cols int) []int {
	if p == nil || rows <= 0 || cols <= 0 || p.Theta <= 1 {
		return nil
	}
	witnessRows := p.MaskRowOffset
	if witnessRows <= 0 {
		return nil
	}
	rowsBlock := ceilDiv(witnessRows, cols)
	if rowsBlock <= 1 {
		return nil
	}
	if rows%rowsBlock != 0 {
		return nil
	}
	finalCols := witnessRows - (rowsBlock-1)*cols
	if finalCols <= 0 || finalCols >= cols {
		return nil
	}
	perBlockRows := rows / rowsBlock
	if perBlockRows <= 0 || perBlockRows >= rows {
		return nil
	}
	out := make([]int, rows)
	for i := range out {
		out[i] = cols
	}
	for i := rows - perBlockRows; i < rows; i++ {
		out[i] = finalCols
	}
	return out
}

func raggedWidthsUsable(mat [][]uint64, widths []int) bool {
	if len(mat) != len(widths) {
		return false
	}
	for i := range mat {
		if widths[i] <= 0 || widths[i] > len(mat[i]) {
			return false
		}
		for j := widths[i]; j < len(mat[i]); j++ {
			if mat[i][j] != 0 {
				return false
			}
		}
	}
	return true
}

func packVariableWidthUintRows(rows [][]uint64, rowWidths []int, width int) []byte {
	if width <= 0 || len(rows) == 0 || len(rowWidths) != len(rows) {
		return nil
	}
	totalVals := 0
	for _, rowWidth := range rowWidths {
		if rowWidth > 0 {
			totalVals += rowWidth
		}
	}
	totalBits := totalVals * width
	out := make([]byte, (totalBits+7)/8)
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << width) - 1
	}
	bitPos := 0
	for i, row := range rows {
		rowWidth := rowWidths[i]
		for j := 0; j < rowWidth; j++ {
			val := row[j] & mask
			bytePos := bitPos >> 3
			shift := uint(bitPos & 7)
			chunk := val << shift
			bytesNeeded := (width + int(shift) + 7) / 8
			for k := 0; k < bytesNeeded && (bytePos+k) < len(out); k++ {
				out[bytePos+k] |= byte(chunk & 0xFF)
				chunk >>= 8
			}
			bitPos += width
		}
	}
	return out
}

func unpackVariableWidthUintRows(bits []byte, rows, cols int, rowWidths []int, width int) ([][]uint64, error) {
	if rows <= 0 || cols <= 0 || width <= 0 || len(rowWidths) != rows {
		return nil, fmt.Errorf("proof: invalid variable-width matrix shape")
	}
	totalVals := 0
	for _, rowWidth := range rowWidths {
		if rowWidth < 0 || rowWidth > cols {
			return nil, fmt.Errorf("proof: invalid row width %d for cols=%d", rowWidth, cols)
		}
		totalVals += rowWidth
	}
	expectedBits := totalVals * width
	if len(bits)*8 < expectedBits {
		return nil, fmt.Errorf("proof: truncated variable-width matrix payload")
	}
	out := make([][]uint64, rows)
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << width) - 1
	}
	bitPos := 0
	for r := 0; r < rows; r++ {
		row := make([]uint64, cols)
		for c := 0; c < rowWidths[r]; c++ {
			bytePos := bitPos >> 3
			shift := uint(bitPos & 7)
			var chunk uint64
			bytesNeeded := (width + int(shift) + 7) / 8
			for k := 0; k < bytesNeeded && (bytePos+k) < len(bits); k++ {
				chunk |= uint64(bits[bytePos+k]) << (8 * k)
			}
			row[c] = (chunk >> shift) & mask
			bitPos += width
		}
		out[r] = row
	}
	return out, nil
}

func matrixEqualWidth(rows [][]uint64) int {
	if len(rows) == 0 {
		return 0
	}
	width := len(rows[0])
	for i := 1; i < len(rows); i++ {
		if len(rows[i]) > width {
			width = len(rows[i])
		}
	}
	return width
}
