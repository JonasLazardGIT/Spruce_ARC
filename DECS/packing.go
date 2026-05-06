package decs

import (
	"encoding/binary"
	"errors"

	"vSIS-Signature/internal/packedwidth"
)

const packedMatrixHeaderSize = 10

// PackUintMatrix encodes a matrix into a bitstream prefixed with a 10-byte header:
// 4 bytes rows, 4 bytes cols, 1 byte bit width, 1 reserved byte. The bit width
// is chosen automatically as the exact width of the largest entry.
// The returned slice contains the header followed by the packed payload.
func PackUintMatrix(rows [][]uint64) ([]byte, int, int, int) {
	if len(rows) == 0 {
		return nil, 0, 0, 0
	}
	rowLen := maxRowLen(rows)
	if rowLen == 0 {
		return nil, 0, 0, 0
	}
	width := selectBitWidth(maxMatrixValue(rows))
	payload := packUintMatrixBody(rows, rowLen, width)
	buf := make([]byte, packedMatrixHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(rows)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(rowLen))
	buf[8] = byte(width)
	buf[9] = 0
	copy(buf[packedMatrixHeaderSize:], payload)
	return buf, len(rows), rowLen, width
}

// UnpackUintMatrix parses the header emitted by PackUintMatrix and reconstructs
// the original matrix together with its dimensions and bit width.
func UnpackUintMatrix(bits []byte) ([][]uint64, int, int, int, error) {
	rows, cols, width, payload, err := parsePackedMatrix(bits)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	mat := unpackUintMatrixBody(payload, rows, cols, width)
	return mat, rows, cols, width, nil
}

func parsePackedMatrix(bits []byte) (int, int, int, []byte, error) {
	if len(bits) < packedMatrixHeaderSize {
		return 0, 0, 0, nil, errors.New("decs: packed matrix too short")
	}
	rows := int(binary.LittleEndian.Uint32(bits[0:4]))
	cols := int(binary.LittleEndian.Uint32(bits[4:8]))
	width := int(bits[8])
	if rows < 0 || cols < 0 {
		return 0, 0, 0, nil, errors.New("decs: invalid matrix dimensions")
	}
	if width <= 0 || width > 64 {
		return 0, 0, 0, nil, errors.New("decs: invalid matrix bit width")
	}
	payload := bits[packedMatrixHeaderSize:]
	expectedBits := rows * cols * width
	if len(payload)*8 < expectedBits {
		return 0, 0, 0, nil, errors.New("decs: truncated packed matrix payload")
	}
	return rows, cols, width, payload, nil
}

func packUintMatrixBody(rows [][]uint64, rowLen, width int) []byte {
	if rowLen <= 0 || width <= 0 {
		return nil
	}
	totalVals := len(rows) * rowLen
	totalBits := totalVals * width
	out := make([]byte, (totalBits+7)/8)
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << width) - 1
	}
	bitPos := 0
	for _, row := range rows {
		for j := 0; j < rowLen; j++ {
			val := uint64(0)
			if j < len(row) {
				val = row[j] & mask
			}
			bytePos := bitPos >> 3
			shift := uint(bitPos & 7)
			chunk := uint64(val) << shift
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

func packFlatUintMatrix(rows [][]uint64, rowLen, width int) []byte {
	return packUintMatrixBody(rows, rowLen, width)
}

func packColumnWidthUintMatrix(rows [][]uint64, rowLen int, widths []uint8) []byte {
	if rowLen <= 0 || len(widths) != rowLen || len(rows) == 0 {
		return nil
	}
	totalBits := 0
	for _, width := range widths {
		if width == 0 || width > 64 {
			return nil
		}
		totalBits += int(width) * len(rows)
	}
	out := make([]byte, (totalBits+7)/8)
	bitPos := 0
	for _, row := range rows {
		for j := 0; j < rowLen; j++ {
			width := int(widths[j])
			val := uint64(0)
			if j < len(row) {
				val = row[j]
			}
			packUintAt(out, bitPos, width, val)
			bitPos += width
		}
	}
	return out
}

func columnWidthsForMatrix(rows [][]uint64, rowLen int) []uint8 {
	if rowLen <= 0 || len(rows) == 0 {
		return nil
	}
	maxVals := make([]uint64, rowLen)
	for _, row := range rows {
		for j := 0; j < rowLen && j < len(row); j++ {
			if row[j] > maxVals[j] {
				maxVals[j] = row[j]
			}
		}
	}
	widths := make([]uint8, rowLen)
	for j, max := range maxVals {
		widths[j] = uint8(selectBitWidth(max))
	}
	return widths
}

func unpackFlatUint(bits []byte, index, width int) uint64 {
	if index < 0 || width <= 0 {
		return 0
	}
	off := index * width
	bytePos := off >> 3
	bitOff := uint(off & 7)
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << width) - 1
	}
	var chunk uint64
	bytesNeeded := (width + int(bitOff) + 7) / 8
	for i := 0; i < bytesNeeded && (bytePos+i) < len(bits); i++ {
		chunk |= uint64(bits[bytePos+i]) << (8 * i)
	}
	chunk >>= bitOff
	return chunk & mask
}

func unpackColumnWidthUint(bits []byte, row, col, rowLen int, widths []uint8) uint64 {
	if row < 0 || col < 0 || rowLen <= 0 || col >= rowLen || len(widths) != rowLen {
		return 0
	}
	bitPos := 0
	rowBits := 0
	for _, width := range widths {
		if width == 0 || width > 64 {
			return 0
		}
		rowBits += int(width)
	}
	bitPos += row * rowBits
	for j := 0; j < col; j++ {
		bitPos += int(widths[j])
	}
	return unpackUintAt(bits, bitPos, int(widths[col]))
}

func unpackUintMatrixBody(bits []byte, rows, rowLen, width int) [][]uint64 {
	if rows <= 0 || rowLen <= 0 || width <= 0 {
		return nil
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
		row := make([]uint64, rowLen)
		for c := 0; c < rowLen; c++ {
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
	return out
}

func packUintAt(out []byte, bitPos, width int, val uint64) {
	if width <= 0 {
		return
	}
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << width) - 1
	}
	bytePos := bitPos >> 3
	shift := uint(bitPos & 7)
	chunk := (val & mask) << shift
	bytesNeeded := (width + int(shift) + 7) / 8
	for k := 0; k < bytesNeeded && (bytePos+k) < len(out); k++ {
		out[bytePos+k] |= byte(chunk & 0xFF)
		chunk >>= 8
	}
}

func unpackUintAt(bits []byte, bitPos, width int) uint64 {
	if width <= 0 {
		return 0
	}
	bytePos := bitPos >> 3
	shift := uint(bitPos & 7)
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << width) - 1
	}
	var chunk uint64
	bytesNeeded := (width + int(shift) + 7) / 8
	for k := 0; k < bytesNeeded && (bytePos+k) < len(bits); k++ {
		chunk |= uint64(bits[bytePos+k]) << (8 * k)
	}
	return (chunk >> shift) & mask
}

func maxMatrixValue(rows [][]uint64) uint64 {
	var max uint64
	for _, row := range rows {
		for _, v := range row {
			if v > max {
				max = v
			}
		}
	}
	return max
}

func maxRowLen(rows [][]uint64) int {
	rowLen := 0
	for _, row := range rows {
		if len(row) > rowLen {
			rowLen = len(row)
		}
	}
	return rowLen
}

func selectBitWidth(max uint64) int {
	return packedwidth.ExactForMax(max)
}
