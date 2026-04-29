package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	PCSGeometryKindLiteralRows        = "literal_rows_v1"
	PCSGeometryKindSmallFieldMatrixV1 = "smallfield_matrix_v1"

	PCSGeometrySmallFieldSourceLiteralRows = "literal_row_heads_v1"
)

// PCSGeometry describes the committed PCS row geometry independently of the
// statement-facing witness packing width s = NCols.
type PCSGeometry struct {
	Kind                string
	SmallFieldSource    string
	WitnessPackingCols  int
	PCSNCols            int
	Theta               int
	Ell                 int
	BlockCount          int
	LogicalWitnessPolys int
	WitnessRows         int
	ReplayWitnessRows   int
	MaskRows            int
	ShortnessTailOffset int
	ShortnessTailRows   int
	OracleLayout        lvcs.OracleLayout
}

type builtPCSRows struct {
	RowInputs     []lvcs.RowInput
	WitnessCount  int
	MaskRowOffset int
	MaskRowCount  int
	PCSGeometry   PCSGeometry
}

func resolvePCSNCols(opts SimOpts, witnessNCols int) int {
	if opts.PCSNCols > 0 {
		return opts.PCSNCols
	}
	if opts.LVCSNCols > 0 {
		return opts.LVCSNCols
	}
	if witnessNCols > 0 {
		return witnessNCols
	}
	if opts.NCols > 0 {
		return opts.NCols
	}
	return 0
}

func resolveProofPCSNCols(proof *Proof, fallback int) int {
	if proof != nil {
		if proof.PCSNColsUsed > 0 {
			return proof.PCSNColsUsed
		}
		if proof.LVCSNColsUsed > 0 {
			return proof.LVCSNColsUsed
		}
		if proof.PCSGeometry.PCSNCols > 0 {
			return proof.PCSGeometry.PCSNCols
		}
		if proof.NColsUsed > 0 {
			return proof.NColsUsed
		}
	}
	return fallback
}

func resolveProofPCSOpening(proof *Proof) *decs.DECSOpening {
	if proof == nil {
		return nil
	}
	if proof.PCSOpening != nil {
		return proof.PCSOpening
	}
	return proof.RowOpening
}

func (p *Proof) syncPCSCompat() {
	if p == nil {
		return
	}
	if p.PCSOpening == nil {
		p.PCSOpening = p.RowOpening
	}
	if p.RowOpening == nil {
		p.RowOpening = p.PCSOpening
	}
	if p.PCSNColsUsed <= 0 {
		switch {
		case p.LVCSNColsUsed > 0:
			p.PCSNColsUsed = p.LVCSNColsUsed
		case p.PCSGeometry.PCSNCols > 0:
			p.PCSNColsUsed = p.PCSGeometry.PCSNCols
		default:
			p.PCSNColsUsed = p.NColsUsed
		}
	}
	if p.LVCSNColsUsed <= 0 {
		p.LVCSNColsUsed = p.PCSNColsUsed
	}
	if p.PCSGeometry.PCSNCols <= 0 {
		p.PCSGeometry.PCSNCols = p.PCSNColsUsed
	}
	if p.PCSGeometry.WitnessPackingCols <= 0 {
		p.PCSGeometry.WitnessPackingCols = p.NColsUsed
	}
}

func makeLegacyPCSGeometry(witnessPackingCols, pcsNCols, theta, ell, logicalWitnessPolys, witnessRows, maskRowOffset, maskRowCount int) PCSGeometry {
	return PCSGeometry{
		Kind:                PCSGeometryKindLiteralRows,
		WitnessPackingCols:  witnessPackingCols,
		PCSNCols:            pcsNCols,
		Theta:               theta,
		Ell:                 ell,
		BlockCount:          witnessRows,
		LogicalWitnessPolys: logicalWitnessPolys,
		WitnessRows:         witnessRows,
		ReplayWitnessRows:   witnessRows,
		MaskRows:            maskRowCount,
		OracleLayout: lvcs.OracleLayout{
			Witness: lvcs.LayoutSegment{Offset: 0, Count: witnessRows},
			Mask:    lvcs.LayoutSegment{Offset: maskRowOffset, Count: maskRowCount},
		},
	}
}

func buildSmallFieldPCSRows(
	ringQ *ring.Ring,
	omegaWitness []uint64,
	pcsNCols int,
	ell int,
	K *kf.Field,
	omegaS1 kf.Elem,
	witnessPolys []*ring.Poly,
	maskPolysK []*KPoly,
	maskDegreeBound int,
) (*builtPCSRows, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	if len(omegaWitness) == 0 {
		return nil, fmt.Errorf("empty witness omega")
	}
	if len(witnessPolys) == 0 {
		return nil, fmt.Errorf("empty witness polynomial set")
	}
	witnessRows, err := buildSmallFieldWitnessRows(ringQ, omegaWitness, pcsNCols, K, omegaS1, witnessPolys)
	if err != nil {
		return nil, err
	}
	maskRows, err := buildSmallFieldMaskLayerRows(K, maskPolysK, pcsNCols, maskDegreeBound)
	if err != nil {
		return nil, err
	}
	if len(maskRows) == 0 {
		return nil, fmt.Errorf("empty small-field PCS mask rows")
	}
	rowInputs := make([]lvcs.RowInput, 0, len(witnessRows)+len(maskRows))
	for i := range witnessRows {
		rowInputs = append(rowInputs, lvcs.RowInput{Head: append([]uint64(nil), witnessRows[i]...)})
	}
	maskRowOffset := len(rowInputs)
	for i := range maskRows {
		rowInputs = append(rowInputs, lvcs.RowInput{Head: append([]uint64(nil), maskRows[i]...)})
	}
	blocks := ceilDiv(len(witnessPolys), pcsNCols)
	if blocks <= 0 {
		blocks = 1
	}
	return &builtPCSRows{
		RowInputs:     rowInputs,
		WitnessCount:  maskRowOffset,
		MaskRowOffset: maskRowOffset,
		MaskRowCount:  len(maskRows),
		PCSGeometry: PCSGeometry{
			Kind:                PCSGeometryKindSmallFieldMatrixV1,
			WitnessPackingCols:  len(omegaWitness),
			PCSNCols:            pcsNCols,
			Theta:               K.Theta,
			Ell:                 ell,
			BlockCount:          blocks,
			LogicalWitnessPolys: len(witnessPolys),
			WitnessRows:         maskRowOffset,
			ReplayWitnessRows:   len(witnessRows),
			MaskRows:            len(maskRows),
			OracleLayout: lvcs.OracleLayout{
				Witness: lvcs.LayoutSegment{Offset: 0, Count: maskRowOffset},
				Mask:    lvcs.LayoutSegment{Offset: maskRowOffset, Count: len(maskRows)},
			},
		},
	}, nil
}

func buildSmallFieldPCSRowsFromLiteralInputs(
	ringQ *ring.Ring,
	omegaWitness []uint64,
	pcsNCols int,
	ell int,
	K *kf.Field,
	omegaS1 kf.Elem,
	logicalRows []lvcs.RowInput,
	maskPolysK []*KPoly,
	maskDegreeBound int,
) (*builtPCSRows, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if pcsNCols <= 0 {
		return nil, fmt.Errorf("invalid pcs ncols=%d", pcsNCols)
	}
	if len(omegaWitness) == 0 {
		return nil, fmt.Errorf("empty witness omega")
	}
	if len(logicalRows) == 0 {
		return nil, fmt.Errorf("empty logical row set")
	}
	witnessRows, err := buildSmallFieldWitnessRowsFromLiteralInputs(ringQ, omegaWitness, pcsNCols, K, omegaS1, logicalRows)
	if err != nil {
		return nil, err
	}
	maskRows, err := buildSmallFieldMaskLayerRows(K, maskPolysK, pcsNCols, maskDegreeBound)
	if err != nil {
		return nil, err
	}
	if len(maskRows) == 0 {
		return nil, fmt.Errorf("empty small-field PCS mask rows")
	}
	rowInputs := make([]lvcs.RowInput, 0, len(witnessRows)+len(maskRows))
	for i := range witnessRows {
		rowInputs = append(rowInputs, lvcs.RowInput{Head: append([]uint64(nil), witnessRows[i]...)})
	}
	maskRowOffset := len(rowInputs)
	for i := range maskRows {
		rowInputs = append(rowInputs, lvcs.RowInput{Head: append([]uint64(nil), maskRows[i]...)})
	}
	blocks := ceilDiv(len(logicalRows), pcsNCols)
	if blocks <= 0 {
		blocks = 1
	}
	return &builtPCSRows{
		RowInputs:     rowInputs,
		WitnessCount:  maskRowOffset,
		MaskRowOffset: maskRowOffset,
		MaskRowCount:  len(maskRows),
		PCSGeometry: PCSGeometry{
			Kind:                PCSGeometryKindSmallFieldMatrixV1,
			SmallFieldSource:    PCSGeometrySmallFieldSourceLiteralRows,
			WitnessPackingCols:  len(omegaWitness),
			PCSNCols:            pcsNCols,
			Theta:               K.Theta,
			Ell:                 ell,
			BlockCount:          blocks,
			LogicalWitnessPolys: len(logicalRows),
			WitnessRows:         maskRowOffset,
			ReplayWitnessRows:   len(witnessRows),
			MaskRows:            len(maskRows),
			OracleLayout: lvcs.OracleLayout{
				Witness: lvcs.LayoutSegment{Offset: 0, Count: maskRowOffset},
				Mask:    lvcs.LayoutSegment{Offset: maskRowOffset, Count: len(maskRows)},
			},
		},
	}, nil
}
