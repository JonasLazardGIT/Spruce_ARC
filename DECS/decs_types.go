package decs

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
	Indices   []int      // explicit indices after the mask segment (optional)
	TailCount int        // number of tail indices when Indices is packed
	IndexBits []byte     // packed tail indices (13-bit per entry; optional)
	Pvals     [][]uint64 // optional: P_j(e) for each e∈E, j∈[0..r)
	Mvals     [][]uint64 // optional: M_k(e) for each e∈E, k∈[0..η)
	// Width 0 keeps the full residue encoding.
	PvalsBits        []byte
	MvalsBits        []byte
	PvalsBitWidth    uint8
	MvalsBitWidth    uint8
	R                int // number of P columns (rows committed)
	Eta              int // number of mask polys (η)
	Nodes            [][]byte
	PathIndex        [][]int // optional: explicit indices
	PathBits         []byte  // packed path indices (row-major t×depth), optional
	PathBitWidth     uint8   // bit width per path entry when PathBits is set
	PathDepth        int     // path length when PathBits is set
	FrontierRefsBits []byte  // packed indices into FrontierNodes (union)
	FrontierRefWidth uint8   // bit width for FrontierRefsBits entries
	FrontierRefCount int     // number of references encoded in FrontierRefsBits
	Nonces           [][]byte
	NonceSeed        []byte
	NonceBytes       int

	// Frontier-based openings can be expanded with EnsureMerkleDecoded.
	FrontierNodes [][]byte
	FrontierProof []byte
	FrontierLR    []byte
	FrontierDepth int
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
}

// DefaultParams provides the baseline DECS parameters.
var DefaultParams = Params{Degree: 4095, Eta: 2, NonceBytes: 24}
