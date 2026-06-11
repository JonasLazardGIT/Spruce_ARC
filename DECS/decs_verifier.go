package decs

import (
	"encoding/binary"
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Verifier holds DECS verification parameters.
type Verifier struct {
	ringQ   *ring.Ring
	r       int
	params  Params
	points  []uint64 // explicit evaluation domain points E[i]
	nLeaves int
}

// NewVerifierWithParamsAndPointsChecked is the error-returning variant of
// NewVerifierWithParamsAndPoints for library callers.
func NewVerifierWithParamsAndPointsChecked(ringQ *ring.Ring, r int, params Params, points []uint64) (*Verifier, error) {
	if points == nil {
		return nil, fmt.Errorf("decs: explicit points are required")
	}
	if err := validateVerifierParams(params); err != nil {
		return nil, err
	}
	if params.Eta <= 0 {
		return nil, fmt.Errorf("decs: invalid eta (must be > 0)")
	}
	if params.NonceBytes <= 0 {
		return nil, fmt.Errorf("decs: invalid NonceBytes (must be > 0)")
	}
	if len(ringQ.Modulus) != 1 {
		return nil, fmt.Errorf("decs: only single-modulus rings are supported (len(Modulus) must be 1)")
	}
	if err := validatePoints(points, ringQ.Modulus[0]); err != nil {
		return nil, err
	}
	return &Verifier{ringQ: ringQ, r: r, params: params, points: points, nLeaves: len(points)}, nil
}

// VerifyEvalFormal runs DECS.Eval checks with formal coefficient rows for R.
func (v *Verifier) VerifyEvalFormal(
	root [16]byte, Gamma [][]uint64, R [][]uint64,
	open *DECSOpening,
) bool {
	return v.VerifyEvalFormalHash(root[:], Gamma, R, open)
}

func (v *Verifier) VerifyEvalFormalHash(
	rootHash []byte, Gamma [][]uint64, R [][]uint64,
	open *DECSOpening,
) bool {
	if open == nil {
		return false
	}
	if openingPRequiresReconstruction(open) {
		if len(open.Pvals) == 0 {
			// Compressed openings must be reconstructed before DECS verification.
			return false
		}
		if open.R <= 0 {
			return false
		}
		for i := 0; i < len(open.Pvals); i++ {
			if len(open.Pvals[i]) != open.R {
				return false
			}
		}
	}
	if openingMRequiresReconstruction(open) {
		if len(open.Mvals) == 0 {
			// Compressed M openings must be reconstructed before DECS verification.
			return false
		}
		for i := 0; i < len(open.Mvals); i++ {
			if len(open.Mvals[i]) != open.Eta {
				return false
			}
		}
	}
	n := open.EntryCount()
	if len(open.Pvals) > 0 && len(open.Pvals) != n {
		return false
	}
	if len(open.Pvals) == 0 && openingPCols(open) < v.r {
		return false
	}
	if len(open.Mvals) > 0 && len(open.Mvals) != n {
		return false
	}
	if len(open.Mvals) == 0 && openingMCols(open) < v.params.Eta {
		return false
	}
	if len(open.Nonces) > 0 && len(open.Nonces) != n {
		return false
	}
	if len(Gamma) != v.params.Eta || len(R) != v.params.Eta {
		return false
	}
	for k := 0; k < v.params.Eta; k++ {
		if len(Gamma[k]) != v.r {
			return false
		}
	}

	mod := v.ringQ.Modulus[0]

	for t := 0; t < n; t++ {
		idx := open.IndexAt(t)
		if idx < 0 || idx >= v.nLeaves {
			return false
		}
		if len(open.Pvals) > 0 && len(open.Pvals[t]) != v.r {
			return false
		}
		if len(open.Mvals) > 0 && len(open.Mvals[t]) != v.params.Eta {
			return false
		}
		var nonce []byte
		if len(open.Nonces) > t && len(open.Nonces[t]) > 0 {
			nonce = open.Nonces[t]
		} else if len(open.NonceSeed) > 0 && open.NonceBytes > 0 {
			nonce = deriveNonce(open.NonceSeed, idx, open.NonceBytes)
		}
		if len(nonce) != v.params.NonceBytes {
			return false
		}

		// pack field elements as uint32 and index as uint16 (matching prover)
		buf := make([]byte, 4*(v.r+v.params.Eta)+2+v.params.NonceBytes)
		off := 0
		for j := 0; j < v.r; j++ {
			pv := getPval(open, t, j)
			binary.LittleEndian.PutUint32(buf[off:], uint32(pv))
			off += 4
		}
		for k := 0; k < v.params.Eta; k++ {
			mv := getMval(open, t, k)
			binary.LittleEndian.PutUint32(buf[off:], uint32(mv))
			off += 4
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(idx))
		off += 2
		copy(buf[off:], nonce[:v.params.NonceBytes])
		// Reconstruct per-index path from union
		ids, ok := pathRowIndices(open, t)
		if !ok {
			return false
		}
		path := make([][]byte, len(ids))
		for lvl, id := range ids {
			if id < 0 || id >= len(open.Nodes) {
				return false
			}
			path[lvl] = open.Nodes[id]
		}
		if !VerifyPathHash(buf, path, rootHash, idx) {
			return false
		}

		for k := 0; k < v.params.Eta; k++ {
			x := v.points[idx] % mod
			lhs := evalPoly(R[k], x, mod)
			rhs := getMval(open, t, k) % mod
			for j := 0; j < v.r; j++ {
				mul := mulMod64(getPval(open, t, j), Gamma[k][j], mod)
				rhs = addMod64(rhs, mul, mod)
			}
			if lhs != rhs {
				return false
			}
		}
	}
	return true
}

// getPval returns Pvals[t][j], reading from packed form if necessary.
func getPval(open *DECSOpening, t, j int) uint64 {
	if open.Pvals != nil {
		return open.Pvals[t][j]
	}
	rowCols := openingPCols(open)
	if rowCols <= 0 {
		return 0
	}
	if j >= rowCols {
		return 0
	}
	if len(open.PvalsColumnWidths) == rowCols {
		return unpackColumnWidthUint(open.PvalsBits, t, j, rowCols, open.PvalsColumnWidths)
	}
	idx := t*rowCols + j
	return unpackFlatUint(open.PvalsBits, idx, openingPBitWidth(open))
}

func getMval(open *DECSOpening, t, k int) uint64 {
	if open.Mvals != nil {
		return open.Mvals[t][k]
	}
	rowCols := openingMCols(open)
	if len(open.MvalsColumnWidths) == rowCols {
		return unpackColumnWidthUint(open.MvalsBits, t, k, rowCols, open.MvalsColumnWidths)
	}
	idx := t*rowCols + k
	return unpackFlatUint(open.MvalsBits, idx, openingMBitWidth(open))
}

// GetOpeningPval returns the P value at (t,j) from the opening, reading from
// the packed residue stream if the plain matrix is nil.
func GetOpeningPval(open *DECSOpening, t, j int) uint64 {
	if open == nil || t < 0 || j < 0 {
		return 0
	}
	if open.Pvals != nil {
		if t >= len(open.Pvals) || j >= len(open.Pvals[t]) {
			return 0
		}
		return open.Pvals[t][j]
	}
	rowCols := openingPCols(open)
	if rowCols <= 0 || j >= rowCols {
		return 0
	}
	if len(open.PvalsColumnWidths) == rowCols {
		return unpackColumnWidthUint(open.PvalsBits, t, j, rowCols, open.PvalsColumnWidths)
	}
	idx := t*rowCols + j
	return unpackFlatUint(open.PvalsBits, idx, openingPBitWidth(open))
}

func openingPCols(open *DECSOpening) int {
	if open == nil {
		return 0
	}
	if open.FormatVersion == OpeningFormatOmitCols || open.FormatVersion == OpeningFormatColumnWidths {
		if open.PColsEncoded > 0 {
			return open.PColsEncoded
		}
		if open.FormatVersion == OpeningFormatColumnWidths && len(open.PvalsColumnWidths) > 0 {
			return len(open.PvalsColumnWidths)
		}
		return 0
	}
	return open.R
}

// GetOpeningMval returns the M value at (t,k) from the opening, reading from
// the packed residue stream if the plain matrix is nil.
func GetOpeningMval(open *DECSOpening, t, k int) uint64 {
	if open == nil || t < 0 || k < 0 {
		return 0
	}
	if open.Mvals != nil {
		if t >= len(open.Mvals) || k >= len(open.Mvals[t]) {
			return 0
		}
		return open.Mvals[t][k]
	}
	rowCols := openingMCols(open)
	if rowCols <= 0 || k >= rowCols {
		return 0
	}
	if len(open.MvalsColumnWidths) == rowCols {
		return unpackColumnWidthUint(open.MvalsBits, t, k, rowCols, open.MvalsColumnWidths)
	}
	idx := t*rowCols + k
	return unpackFlatUint(open.MvalsBits, idx, openingMBitWidth(open))
}

func openingMCols(open *DECSOpening) int {
	if open == nil {
		return 0
	}
	if open.MFormatVersion == OpeningFormatOmitCols || open.MFormatVersion == OpeningFormatColumnWidths {
		if open.MColsEncoded > 0 {
			return open.MColsEncoded
		}
		if open.MFormatVersion == OpeningFormatColumnWidths && len(open.MvalsColumnWidths) > 0 {
			return len(open.MvalsColumnWidths)
		}
		return 0
	}
	return open.Eta
}

func openingPBitWidth(open *DECSOpening) int {
	if open == nil || open.PvalsBitWidth == 0 {
		return 20
	}
	return int(open.PvalsBitWidth)
}

func openingMBitWidth(open *DECSOpening) int {
	if open == nil || open.MvalsBitWidth == 0 {
		return 20
	}
	return int(open.MvalsBitWidth)
}

func openingPRequiresReconstruction(open *DECSOpening) bool {
	return open != nil && len(open.POmitCols) > 0 && (open.FormatVersion == OpeningFormatOmitCols || open.FormatVersion == OpeningFormatColumnWidths)
}

func openingMRequiresReconstruction(open *DECSOpening) bool {
	return open != nil && len(open.MOmitCols) > 0 && (open.MFormatVersion == OpeningFormatOmitCols || open.MFormatVersion == OpeningFormatColumnWidths)
}

func pathRowIndices(open *DECSOpening, row int) ([]int, bool) {
	if open == nil || row < 0 || row >= open.EntryCount() {
		return nil, false
	}
	if len(open.PathIndex) > row && open.PathIndex[row] != nil {
		return open.PathIndex[row], true
	}
	if open.PathDepth > 0 && len(open.PathIndex) == 0 && len(open.PathBits) == 0 && len(open.Nodes) == open.EntryCount()*open.PathDepth {
		start := row * open.PathDepth
		out := make([]int, open.PathDepth)
		for i := range out {
			out[i] = start + i
		}
		return out, true
	}
	if open.PathDepth <= 0 || open.PathBitWidth == 0 || len(open.PathBits) == 0 {
		return nil, false
	}
	rowVals, err := unpackPathRow(open.PathBits, row, open.EntryCount(), open.PathDepth, int(open.PathBitWidth))
	if err != nil {
		return nil, false
	}
	return rowVals, true
}

// VerifyEvalAt enforces that the prover opened exactly the challenged set E,
// then runs the standard DECS checks.
func (v *Verifier) VerifyEvalAt(
	root [16]byte, Gamma [][]uint64, R []*ring.Poly,
	open *DECSOpening, E []int,
) bool {
	return v.VerifyEvalAtFormal(root, Gamma, ringRowsToFormal(R, v.ringQ.Modulus[0]), open, E)
}

func (v *Verifier) VerifyEvalAtHash(
	rootHash []byte, Gamma [][]uint64, R []*ring.Poly,
	open *DECSOpening, E []int,
) bool {
	return v.VerifyEvalAtFormalHash(rootHash, Gamma, ringRowsToFormal(R, v.ringQ.Modulus[0]), open, E)
}

// VerifyEvalAtFormal enforces that the prover opened exactly E, then runs
// VerifyEvalFormal.
func (v *Verifier) VerifyEvalAtFormal(
	root [16]byte, Gamma [][]uint64, R [][]uint64,
	open *DECSOpening, E []int,
) bool {
	return v.VerifyEvalAtFormalHash(root[:], Gamma, R, open, E)
}

func (v *Verifier) VerifyEvalAtFormalHash(
	rootHash []byte, Gamma [][]uint64, R [][]uint64,
	open *DECSOpening, E []int,
) bool {
	if open == nil {
		return false
	}
	indices := open.AllIndices()
	if len(indices) != len(E) {
		return false
	}
	seen := make(map[int]struct{}, len(E))
	for _, x := range E {
		if x < 0 || x >= v.nLeaves {
			return false
		}
		if _, dup := seen[x]; dup {
			return false
		}
		seen[x] = struct{}{}
	}
	for _, y := range indices {
		if _, ok := seen[y]; !ok {
			return false
		}
		delete(seen, y)
	}
	if len(seen) != 0 {
		return false
	}
	return v.VerifyEvalFormalHash(rootHash, Gamma, R, open)
}

func validateVerifierParams(params Params) error {
	if params.Degree < 0 {
		return fmt.Errorf("decs: invalid degree parameter")
	}
	if params.HashBytes != 0 && !IsSupportedHashBytes(params.HashBytes) {
		return fmt.Errorf("decs: invalid HashBytes (supported: %s)", SupportedHashBytesList())
	}
	return nil
}
