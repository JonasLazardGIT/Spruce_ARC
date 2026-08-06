package decs

import (
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
	context CommitmentContext
}

// NewVerifierWithParamsAndPointsV2Checked constructs a verifier that accepts
// only canonical v2 openings under ctx and a full declared-width root.
func NewVerifierWithParamsAndPointsV2Checked(ringQ *ring.Ring, r int, params Params, points []uint64, ctx CommitmentContext) (*Verifier, error) {
	return newVerifierWithParamsAndPointsV2Checked(ringQ, r, params, points, ctx, true)
}

func newVerifierWithParamsAndPointsV2Checked(ringQ *ring.Ring, r int, params Params, points []uint64, ctx CommitmentContext, validateDomain bool) (*Verifier, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if _, err := v2TapeBytes(params); err != nil {
		return nil, err
	}
	if !IsSupportedHashBytes(params.HashBytes) {
		return nil, fmt.Errorf("decs: v2 requires explicit HashBytes (got %d)", params.HashBytes)
	}
	if points == nil {
		return nil, fmt.Errorf("decs: explicit points are required")
	}
	if params.Eta <= 0 {
		return nil, fmt.Errorf("decs: invalid eta (must be > 0)")
	}
	if ringQ == nil || len(ringQ.Modulus) != 1 {
		return nil, fmt.Errorf("decs: only single-modulus rings are supported (len(Modulus) must be 1)")
	}
	if validateDomain {
		if err := validatePoints(points, ringQ.Modulus[0]); err != nil {
			return nil, err
		}
	}
	return &Verifier{
		ringQ: ringQ, r: r, params: params,
		points: append([]uint64(nil), points...), nLeaves: len(points),
		context: cloneCommitmentContext(ctx),
	}, nil
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
