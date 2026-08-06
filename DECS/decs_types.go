package decs

const (
	OpeningFormatPlain        uint8 = 0
	OpeningFormatOmitCols     uint8 = 1
	OpeningFormatColumnWidths uint8 = 2

	// OpeningAuthPaths is the legacy DECS representation: Nodes together with
	// PathIndex/PathBits (or row-major Nodes) describe one path per leaf.
	OpeningAuthPaths uint8 = 0
	// OpeningAuthPositionalFrontierV3 is an in-memory marker reconstructed by
	// the schema-3 proof decoder. Nodes then contains the canonical bottom-up
	// Merkle frontier; positions are derived from AllIndices() and are never
	// accepted from the proof wire.
	OpeningAuthPositionalFrontierV3 uint8 = 1

	DefaultHashBytes = 18
	WideHashBytes    = 32

	// OpeningVersionV2 is the paper-aligned DECS opening format. V2 commits
	// independently sampled tapes and is always verified with an explicit
	// CommitmentContext.
	OpeningVersionV2 uint16 = 2
)

// IsSupportedHashBytes reports whether hashBytes is one of the maintained
// byte-aligned Merkle widths.
func IsSupportedHashBytes(hashBytes int) bool {
	return hashBytes >= 16 && hashBytes <= 64
}

func IsSupportedTapeBytes(tapeBytes int) bool {
	return tapeBytes >= 12 && tapeBytes <= 64
}

func SupportedHashBytesList() string {
	return "16..64"
}

func SupportedTapeBytesList() string {
	return "12..64"
}

// DECSOpening holds the DECS opening data sent by the prover.
type DECSOpening struct {
	// Version and Role identify the v2 commitment that this opening belongs to.
	// The maintained verifier accepts only OpeningVersionV2.
	Version uint16
	Role    CommitmentRole
	// Tapes contains exactly one independently sampled tape per logical opened
	// leaf, in the same order as Pvals, Mvals, paths, and AllIndices().
	Tapes     [][]byte
	TapeBytes int

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
	// AuthFormat selects how Nodes is interpreted. The zero value preserves
	// every legacy opening. The positional frontier value is only installed by
	// the strict schema-3 canonical decoder and is batch-verified after the
	// opened leaf hashes have been reconstructed.
	AuthFormat uint8
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
	Degree int // max polynomial degree d
	Eta    int // number of mask polynomials η
	// TapeBytes is the width of each independent v2 tape.
	TapeBytes int
	HashBytes int // size of Merkle hashes in bytes
}

// DefaultParams provides the maintained DECS parameters.
var DefaultParams = Params{Degree: 4095, Eta: 2, TapeBytes: 24, HashBytes: DefaultHashBytes}
