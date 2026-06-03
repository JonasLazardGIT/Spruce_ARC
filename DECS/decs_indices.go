package decs

const indexBitsPerValue = 13
const indexBitsMask = (1 << indexBitsPerValue) - 1

func (op *DECSOpening) tailLen() int {
	if op == nil {
		return 0
	}
	if len(op.Indices) > 0 {
		return len(op.Indices)
	}
	if op.TailCount > 0 {
		return op.TailCount
	}
	return 0
}

func (op *DECSOpening) packTailIndices() {
	if op == nil {
		return
	}
	if len(op.IndexBits) > 0 && len(op.Indices) == 0 && op.TailCount > 0 {
		// already packed
		return
	}
	tailLen := len(op.Indices)
	if tailLen == 0 {
		op.IndexBits = nil
		op.TailCount = 0
		return
	}
	maxIdx := 0
	for _, idx := range op.Indices {
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	op.TailCount = tailLen
	if maxIdx >= 1<<indexBitsPerValue {
		// fallback: keep explicit indices if values overflow 13 bits
		return
	}
	op.IndexBits = packIndexBits13(op.Indices)
	op.IndexBitWidth = 0
	op.Indices = nil
}

func (op *DECSOpening) packTailIndicesFixed(width int) {
	if op == nil {
		return
	}
	if width <= 0 {
		op.packTailIndices()
		return
	}
	if width > 63 {
		width = 63
	}
	if len(op.IndexBits) > 0 && len(op.Indices) == 0 && op.TailCount > 0 && int(op.IndexBitWidth) == width {
		return
	}
	tailLen := len(op.Indices)
	if tailLen == 0 {
		op.IndexBits = nil
		op.TailCount = 0
		op.IndexBitWidth = 0
		return
	}
	op.TailCount = tailLen
	op.IndexBits = packIndexBitsWidth(op.Indices, width)
	op.IndexBitWidth = uint8(width)
	op.Indices = nil
}

func (op *DECSOpening) tailIndexAt(pos int) int {
	if op == nil || pos < 0 || pos >= op.TailCount || len(op.IndexBits) == 0 {
		return -1
	}
	v, ok := unpackIndexAtWidth(op.IndexBits, pos, op.tailIndexBitWidth())
	if !ok {
		return -1
	}
	return v
}

func (op *DECSOpening) decodeTailInto(dst []int) {
	if op == nil || len(dst) == 0 {
		return
	}
	if len(op.Indices) > 0 {
		n := len(dst)
		if n > len(op.Indices) {
			n = len(op.Indices)
		}
		copy(dst, op.Indices[:n])
		return
	}
	if op.TailCount == 0 || len(op.IndexBits) == 0 {
		for i := range dst {
			dst[i] = 0
		}
		return
	}
	for i := 0; i < len(dst) && i < op.TailCount; i++ {
		if val, ok := unpackIndexAtWidth(op.IndexBits, i, op.tailIndexBitWidth()); ok {
			dst[i] = val
		} else {
			dst[i] = 0
		}
	}
}

func (op *DECSOpening) tailIndexBitWidth() int {
	if op != nil && op.IndexBitWidth > 0 {
		return int(op.IndexBitWidth)
	}
	return indexBitsPerValue
}

func packIndexBits13(values []int) []byte {
	return packIndexBitsWidth(values, indexBitsPerValue)
}

func packIndexBitsWidth(values []int, width int) []byte {
	if len(values) == 0 {
		return nil
	}
	if width <= 0 {
		return nil
	}
	if width > 63 {
		width = 63
	}
	mask := uint64(1<<uint(width)) - 1
	if width == 63 {
		mask = (uint64(1) << 63) - 1
	}
	totalBits := len(values) * width
	out := make([]byte, (totalBits+7)/8)
	bitPos := 0
	for _, v := range values {
		val := uint64(v) & mask
		packIndexUintAt(out, bitPos, width, val)
		bitPos += width
	}
	return out
}

func unpackIndexAt(bits []byte, pos int) (int, bool) {
	return unpackIndexAtWidth(bits, pos, indexBitsPerValue)
}

func unpackIndexAtWidth(bits []byte, pos int, width int) (int, bool) {
	if pos < 0 {
		return 0, false
	}
	if width <= 0 {
		return 0, false
	}
	if width > 63 {
		width = 63
	}
	bitPos := pos * width
	bytePos := bitPos >> 3
	if bytePos >= len(bits) {
		return 0, false
	}
	shift := uint(bitPos & 7)
	var chunk uint64
	bytesNeeded := (width + int(shift) + 7) / 8
	for i := 0; i < bytesNeeded && (bytePos+i) < len(bits); i++ {
		chunk |= uint64(bits[bytePos+i]) << (8 * i)
	}
	chunk >>= shift
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << uint(width)) - 1
	}
	value := int(chunk & mask)
	if bytePos*8+int(shift)+width > len(bits)*8 {
		return 0, false
	}
	return value, true
}

func packIndexUintAt(out []byte, bitPos, width int, val uint64) {
	if width <= 0 {
		return
	}
	bytePos := bitPos >> 3
	shift := uint(bitPos & 7)
	chunk := val << shift
	bytesNeeded := (width + int(shift) + 7) / 8
	for i := 0; i < bytesNeeded && (bytePos+i) < len(out); i++ {
		out[bytePos+i] |= byte(chunk & 0xFF)
		chunk >>= 8
	}
}
