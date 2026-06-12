package decs

const (
	OpeningFormatPlain        uint8 = 0
	OpeningFormatOmitCols     uint8 = 1
	OpeningFormatColumnWidths uint8 = 2

	DefaultHashBytes = 18
	WideHashBytes    = 32
)

// IsSupportedHashBytes reports whether hashBytes is one of the maintained
// byte-aligned Merkle/tape widths.
func IsSupportedHashBytes(hashBytes int) bool {
	return hashBytes >= 16 && hashBytes <= 32
}

func SupportedHashBytesList() string {
	return "16..32"
}

// DECSOpening holds the DECS opening data sent by the prover.
type DECSOpening struct {
	// FormatVersion selects the P-value encoding.
	FormatVersion uint8
	// PColsEncoded is the number of transmitted P columns per opened index.
	PColsEncoded int
	POmitCols    []int
	// MFormatVersion selects the M-value encoding.
	MFormatVersion uint8
	// MColsEncoded is the number of transmitted M columns per opened index.
	MColsEncoded int
	MOmitCols    []int

	MaskBase  int
	MaskCount int
	Indices   []int  // explicit indices after the mask segment (optional)
	TailCount int    // number of tail indices when Indices is packed
	IndexBits []byte // packed tail indices (13-bit compatibility or IndexBitWidth per entry; optional)
	// IndexBitWidth selects the packed tail-index width. Zero means the
	// compatibility 13-bit encoding used by compact openings.
	IndexBitWidth uint8
	Pvals         [][]uint64 // optional: P_j(e) for each e∈E, j∈[0..r)
	Mvals         [][]uint64 // optional: M_k(e) for each e∈E, k∈[0..η)
	// Width 0 keeps the full residue encoding.
	PvalsBits         []byte
	MvalsBits         []byte
	PvalsBitWidth     uint8
	MvalsBitWidth     uint8
	PvalsColumnWidths []uint8
	MvalsColumnWidths []uint8
	R                 int // number of P columns (rows committed)
	Eta               int // number of mask polys (η)
	Nodes             [][]byte
	PathIndex         [][]int // optional: explicit indices
	PathBits          []byte  // packed path indices (row-major t×depth), optional
	PathBitWidth      uint8   // bit width per path entry when PathBits is set
	PathDepth         int     // path length when PathBits is set
	Nonces            [][]byte
	NonceSeed         []byte
	NonceBytes        int
}

// EntryCount returns the total number of opened indices.
func (op *DECSOpening) EntryCount() int {
	if op == nil {
		return 0
	}
	return op.MaskCount + op.tailLen()
}

// IndexAt returns the logical index at position i within the opening.
func (op *DECSOpening) IndexAt(i int) int {
	if op == nil || i < 0 || i >= op.EntryCount() {
		return -1
	}
	if i < op.MaskCount {
		return op.MaskBase + i
	}
	tailPos := i - op.MaskCount
	if tailPos < len(op.Indices) {
		return op.Indices[tailPos]
	}
	if tailPos < op.TailCount {
		return op.tailIndexAt(tailPos)
	}
	return -1
}

// AllIndices materialises the full index set (mask prefix + explicit tail).
func (op *DECSOpening) AllIndices() []int {
	if op == nil {
		return nil
	}
	total := op.EntryCount()
	if total == 0 {
		return nil
	}
	out := make([]int, total)
	for i := 0; i < op.MaskCount; i++ {
		out[i] = op.MaskBase + i
	}
	switch {
	case len(op.Indices) > 0:
		copy(out[op.MaskCount:], op.Indices)
	case op.TailCount > 0 && len(op.IndexBits) > 0:
		op.decodeTailInto(out[op.MaskCount:])
	}
	return out
}

// Params bundles the protocol parameters for DECS.
type Params struct {
	Degree     int // max polynomial degree d
	Eta        int // number of mask polynomials η
	NonceBytes int // size of each nonce ρ_e in bytes
	HashBytes  int // size of Merkle hashes in bytes; zero keeps DefaultHashBytes
}

// DefaultParams provides the maintained DECS parameters.
var DefaultParams = Params{Degree: 4095, Eta: 2, NonceBytes: 24}
