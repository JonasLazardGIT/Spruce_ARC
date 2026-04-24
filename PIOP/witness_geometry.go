package PIOP

import "math"

func maxGeometryInt(a, b int) int {
	if a >= b {
		return a
	}
	return b
}

// CommittedWitnessBreakdown reports the committed witness-row allocation under
// the current one-root PCS/LVCS layout.
type CommittedWitnessBreakdown struct {
	CoeffNativeRows int `json:"coeff_native_rows"`
	SharedRows      int `json:"shared_rows"`
	PRFRows         int `json:"prf_rows"`
	TotalRows       int `json:"total_rows"`
}

// LogicalWitnessBreakdown reports the replay-facing witness families used by
// the current showing verifier surface.
type LogicalWitnessBreakdown struct {
	SigCoreRows             int `json:"sig_core_rows"`
	SigProductRows          int `json:"sig_product_rows"`
	SigReplayRows           int `json:"sig_replay_rows"`
	SigShortnessRows        int `json:"sig_shortness_rows"`
	PostSignProjectionRows  int `json:"post_sign_scalar_projection_rows"`
	PostSignCertificateRows int `json:"post_sign_scalar_certificate_rows"`
	NonSigRows              int `json:"non_sig_rows"`
	PRFRows                 int `json:"prf_rows"`
	TotalRows               int `json:"total_rows"`
}

// WitnessGeometrySnapshot reports the exact one-root small-field witness
// geometry. This is intentionally separate from replay-family reporting:
// replay rows and actual witness polynomials are not the same object.
type WitnessGeometrySnapshot struct {
	WitnessSupportCols         int     `json:"witness_support_cols"`
	CommittedCols              int     `json:"committed_cols"`
	LeafCount                  int     `json:"leaf_count"`
	ActualWitnessPolys         int     `json:"actual_witness_polys"`
	ActualPostSignWitnessPolys int     `json:"actual_post_sign_witness_polys"`
	ActualPRFWitnessPolys      int     `json:"actual_prf_witness_polys"`
	ReplayPostSignRows         int     `json:"replay_post_sign_rows"`
	ReplayPRFRows              int     `json:"replay_prf_rows"`
	PCSBlockCount              int     `json:"pcs_block_count"`
	RowsPerBlock               int     `json:"rows_per_block"`
	WitnessRowsCommitted       int     `json:"witness_rows_committed"`
	MaskRowsCommitted          int     `json:"mask_rows_committed"`
	TotalRowsCommitted         int     `json:"total_rows_committed"`
	BlockCapacity              int     `json:"block_capacity"`
	FinalBlockSlack            int     `json:"final_block_slack"`
	PostSignPrefixSlack        int     `json:"post_sign_prefix_slack"`
	OccupancyPct               float64 `json:"occupancy_pct"`
	ReplayToWitnessExpansion   float64 `json:"replay_to_witness_expansion"`
}

func replayPRFRowCount(layout *PRFLayout, companion *PRFCompanionLayout, mode PRFCompanionMode) int {
	if companion != nil {
		return len(prfCompanionSelectedReplayRows(companion, mode))
	}
	if layout == nil {
		return 0
	}
	if layout.PackedRows {
		seen := map[int]struct{}{}
		for _, slot := range layout.KeySlots {
			if slot.Row >= 0 {
				seen[slot.Row] = struct{}{}
			}
		}
		for _, slot := range layout.SBoxSlots {
			if slot.Row >= 0 {
				seen[slot.Row] = struct{}{}
			}
		}
		return len(seen)
	}
	if layout.WitnessRows > 0 {
		return layout.WitnessRows
	}
	return layout.LenKey + len(layout.SBoxSlots)
}

func inferNonSigBoundRowsPerForWitnessGeometry(layout RowLayout) int {
	if layout.NonSigBoundRowsPer > 0 {
		return layout.NonSigBoundRowsPer
	}
	if layout.MsgChainBase < 0 || layout.RndChainBase < 0 {
		return 0
	}
	delta := layout.RndChainBase - layout.MsgChainBase
	if delta <= 0 || delta%2 != 0 {
		return 0
	}
	rowsPer := delta / 2
	if rowsPer <= 0 {
		return 0
	}
	return rowsPer
}

// LogicalWitnessBreakdownFromLayout reports the replay-facing logical witness
// families implied by the given row/prf layout.
func LogicalWitnessBreakdownFromLayout(layout RowLayout, prfLayout *PRFLayout, prfCompanionLayout *PRFCompanionLayout) LogicalWitnessBreakdown {
	out := LogicalWitnessBreakdown{}
	if layout.CoeffNativeSig.Enabled {
		cfg := layout.CoeffNativeSig
		if rowLayoutCoeffNativeUsesTransformBridge(layout) {
			out.SigCoreRows = rowLayoutReplayTHatCount(layout)
			out.SigReplayRows = out.SigCoreRows
			out.NonSigRows = 0
			if layout.IdxCarrierM >= 0 {
				out.NonSigRows++
			}
			if rowLayoutPostSignCarrierR1(layout) >= 0 {
				out.NonSigRows++
			}
			out.NonSigRows += len(rowLayoutPostSignCarrierR0Rows(layout))
			if out.NonSigRows > 0 && layout.IdxCarrierCtr >= 0 && len(rowLayoutPostSignCarrierR0Rows(layout)) == 0 {
				out.NonSigRows++
			}
			if layout.IdxTSource >= 0 {
				out.NonSigRows += rowLayoutPostSignTSourceCount(layout)
			}
			replayBlocks := rowLayoutReplayBlockCount(layout)
			type replayFamily struct {
				rows []int
				idx  int
			}
			for _, family := range []replayFamily{
				{rows: rowLayoutPostSignMHatSigmaRows(layout), idx: rowLayoutPostSignMHatSigma(layout)},
				{rows: rowLayoutPostSignRHat0Rows(layout), idx: rowLayoutPostSignRHat0(layout)},
				{rows: rowLayoutPostSignR0B2HatRows(layout), idx: rowLayoutPostSignR0B2Hat(layout)},
				{rows: rowLayoutPostSignTargetMR0HatRows(layout), idx: rowLayoutPostSignTargetMR0Hat(layout)},
				{rows: rowLayoutPostSignRHat1Rows(layout), idx: rowLayoutPostSignRHat1(layout)},
				{rows: rowLayoutPostSignZHatRows(layout), idx: rowLayoutPostSignZHat(layout)},
			} {
				if len(family.rows) > 0 {
					out.NonSigRows += len(family.rows)
				} else if family.idx >= 0 {
					if replayBlocks > 0 {
						out.NonSigRows += replayBlocks
					} else {
						out.NonSigRows++
					}
				}
			}
			for _, idx := range []int{layout.IdxMSigmaR1, layout.IdxR0R1} {
				if idx >= 0 {
					out.NonSigRows++
				}
			}
			for _, family := range []replayFamily{
				{rows: rowLayoutPostSignMSigmaR1HatRows(layout), idx: rowLayoutPostSignMSigmaR1Hat(layout)},
				{rows: rowLayoutPostSignR0R1HatRows(layout), idx: rowLayoutPostSignR0R1Hat(layout)},
			} {
				if len(family.rows) > 0 {
					out.NonSigRows += len(family.rows)
				} else if family.idx >= 0 {
					if replayBlocks > 0 {
						out.NonSigRows += replayBlocks
					} else {
						out.NonSigRows++
					}
				}
			}
		}
		if layout.ChainRowsPerSig > 0 && cfg.W1SigCount > 0 {
			out.SigShortnessRows = layout.ChainRowsPerSig * cfg.W1SigCount
		}
		if layout.PackedSigChainBase >= 0 && layout.PackedSigChainGroupCount > 0 && layout.PackedSigChainRowsPerGroup > 0 {
			out.SigShortnessRows += layout.PackedSigChainGroupCount * layout.PackedSigChainRowsPerGroup
		}
	}
	out.PRFRows = replayPRFRowCount(prfLayout, prfCompanionLayout, PRFCompanionMode(""))
	out.TotalRows = out.SigReplayRows + out.SigShortnessRows + out.NonSigRows + out.PRFRows
	return out
}

// LogicalWitnessRowBreakdownFromProof reports the replay-facing witness
// families for a built proof.
func LogicalWitnessRowBreakdownFromProof(proof *Proof) LogicalWitnessBreakdown {
	if proof == nil {
		return LogicalWitnessBreakdown{}
	}
	var companionLayout *PRFCompanionLayout
	if proof.PRFCompanion != nil {
		companionLayout = proof.PRFCompanion.Layout
	}
	out := LogicalWitnessBreakdownFromLayout(proof.RowLayout, proof.PRFLayout, companionLayout)
	if out.TotalRows == 0 && proof.MaskRowOffset > 0 {
		out.TotalRows = proof.MaskRowOffset
	}
	return out
}

func replayPostSignRowCount(layout RowLayout, witnessCount int) int {
	if rowLayoutCoeffNativeUsesLiteralPacked(layout) {
		return literalPackedPostSignReplayRowCount(layout)
	}
	if witnessCount > 0 {
		return witnessCount
	}
	return layout.SigCount
}

func slackFor(count, width int) int {
	if count <= 0 || width <= 0 {
		return 0
	}
	return ceilDiv(count, width)*width - count
}

// BuildWitnessGeometrySnapshotFromLayout derives the exact one-root witness
// geometry from the actual row builder output plus the small-field block
// formula. Under smallfield_matrix_v1, row order within a fixed witness set
// does not change block count or committed witness rows; only total witness
// polynomial count and the chosen widths do.
func BuildWitnessGeometrySnapshotFromLayout(
	layout RowLayout,
	prfLayout *PRFLayout,
	prfCompanionLayout *PRFCompanionLayout,
	pcsGeometry PCSGeometry,
	witnessCount int,
	maskRowsCommitted int,
	witnessSupportCols int,
	committedCols int,
	leafCount int,
	theta int,
) WitnessGeometrySnapshot {
	out := WitnessGeometrySnapshot{
		WitnessSupportCols: witnessSupportCols,
		CommittedCols:      committedCols,
		LeafCount:          leafCount,
	}
	actualWitness := witnessCount
	if pcsGeometry.LogicalWitnessPolys > 0 {
		actualWitness = pcsGeometry.LogicalWitnessPolys
	}
	if actualWitness < 0 {
		actualWitness = 0
	}
	prfWitness := 0
	if layout.PRFScalarBundleRows > 0 {
		prfWitness = layout.PRFScalarBundleRows
	} else if prfCompanionLayout != nil {
		if prfCompanionLayout.PackedRows > 0 {
			prfWitness = prfCompanionLayout.PackedRows
		}
	} else if prfLayout != nil {
		if prfLayout.WitnessRows > 0 {
			prfWitness = prfLayout.WitnessRows
		}
	}
	if prfWitness < 0 {
		prfWitness = 0
	}
	if prfWitness > actualWitness {
		prfWitness = actualWitness
	}
	postSignWitness := actualWitness - prfWitness
	if postSignWitness < 0 {
		postSignWitness = 0
	}
	blockCount := 0
	if pcsGeometry.BlockCount > 0 {
		blockCount = pcsGeometry.BlockCount
	} else if committedCols > 0 {
		blockCount = ceilDiv(actualWitness, committedCols)
	}
	rowsPerBlock := 0
	if theta > 1 && witnessSupportCols > 0 {
		rowsPerBlock = witnessSupportCols + theta
	}
	witnessRowsCommitted := 0
	if pcsGeometry.WitnessRows > 0 {
		witnessRowsCommitted = pcsGeometry.WitnessRows
	} else if blockCount > 0 && rowsPerBlock > 0 {
		witnessRowsCommitted = blockCount * rowsPerBlock
	} else {
		witnessRowsCommitted = actualWitness
	}
	maskRows := maskRowsCommitted
	if pcsGeometry.MaskRows > 0 {
		maskRows = pcsGeometry.MaskRows
	}
	blockCapacity := 0
	if blockCount > 0 && committedCols > 0 {
		blockCapacity = blockCount * committedCols
	}
	replayPRF := replayPRFRowCount(prfLayout, prfCompanionLayout, PRFCompanionMode(""))
	out.ActualWitnessPolys = actualWitness
	out.ActualPostSignWitnessPolys = postSignWitness
	out.ActualPRFWitnessPolys = prfWitness
	out.ReplayPostSignRows = replayPostSignRowCount(layout, postSignWitness)
	out.ReplayPRFRows = replayPRF
	out.PCSBlockCount = blockCount
	out.RowsPerBlock = rowsPerBlock
	out.WitnessRowsCommitted = witnessRowsCommitted
	out.MaskRowsCommitted = maskRows
	out.TotalRowsCommitted = witnessRowsCommitted + maskRows
	out.BlockCapacity = blockCapacity
	out.FinalBlockSlack = slackFor(actualWitness, committedCols)
	out.PostSignPrefixSlack = slackFor(postSignWitness, committedCols)
	if blockCapacity > 0 {
		out.OccupancyPct = 100.0 * float64(actualWitness) / float64(blockCapacity)
	}
	if replayPRF > 0 {
		out.ReplayToWitnessExpansion = float64(prfWitness) / float64(replayPRF)
	} else if prfWitness > 0 {
		out.ReplayToWitnessExpansion = math.Inf(1)
	}
	return out
}

// BuildWitnessGeometrySnapshotFromProof derives the exact one-root witness
// geometry for a built proof.
func BuildWitnessGeometrySnapshotFromProof(proof *Proof) WitnessGeometrySnapshot {
	if proof == nil {
		return WitnessGeometrySnapshot{}
	}
	committedCols := resolveProofPCSNCols(proof, proof.LVCSNColsUsed)
	return BuildWitnessGeometrySnapshotFromLayout(
		proof.RowLayout,
		proof.PRFLayout,
		func() *PRFCompanionLayout {
			if proof.PRFCompanion != nil {
				return proof.PRFCompanion.Layout
			}
			return nil
		}(),
		proof.PCSGeometry,
		proof.MaskRowOffset,
		proof.MaskRowCount,
		proof.NColsUsed,
		committedCols,
		proof.NLeavesUsed,
		proof.Theta,
	)
}

// CommittedWitnessBreakdownFromGeometry derives the committed row allocation
// from an exact one-root geometry snapshot.
func CommittedWitnessBreakdownFromGeometry(geom WitnessGeometrySnapshot) CommittedWitnessBreakdown {
	out := CommittedWitnessBreakdown{TotalRows: geom.WitnessRowsCommitted}
	if geom.TotalRowsCommitted <= 0 {
		return out
	}
	out.TotalRows = geom.WitnessRowsCommitted
	if geom.CommittedCols <= 0 || geom.RowsPerBlock <= 0 {
		out.CoeffNativeRows = geom.WitnessRowsCommitted
		return out
	}
	fullCoeffBlocks := geom.ActualPostSignWitnessPolys / geom.CommittedCols
	out.CoeffNativeRows = fullCoeffBlocks * geom.RowsPerBlock
	if geom.ActualPostSignWitnessPolys%geom.CommittedCols != 0 {
		out.SharedRows = geom.RowsPerBlock
	}
	if out.CoeffNativeRows+out.SharedRows > geom.WitnessRowsCommitted {
		out.SharedRows = geom.WitnessRowsCommitted - out.CoeffNativeRows
		if out.SharedRows < 0 {
			out.SharedRows = 0
		}
	}
	out.PRFRows = geom.WitnessRowsCommitted - out.CoeffNativeRows - out.SharedRows
	if out.PRFRows < 0 {
		out.PRFRows = 0
	}
	return out
}

// CommittedWitnessRowBreakdownFromProof reports the committed witness rows of a
// built proof under the current one-root PCS/LVCS layout.
func CommittedWitnessRowBreakdownFromProof(proof *Proof) CommittedWitnessBreakdown {
	return CommittedWitnessBreakdownFromGeometry(BuildWitnessGeometrySnapshotFromProof(proof))
}
