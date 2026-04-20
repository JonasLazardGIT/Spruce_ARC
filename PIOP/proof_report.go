package PIOP

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// ProofReport captures proof size and soundness metrics for a built proof.
type ProofReport struct {
	ProofBytes      int
	ProofKB         float64
	Soundness       SoundnessBudget
	PaperTranscript PaperTranscriptReport
	TranscriptFocus TranscriptOptimizationReport
	Packing         ProofPackingAudit
	ReplayAudit     ReplayFamilyAuditReport
	SigShortness    SigShortnessReport
	Geometry        WitnessGeometrySnapshot
	NCols           int
	PCSNCols        int
	LVCSNCols       int
	Ell             int
	EllPrime        int
	Rho             int
	Theta           int
	Eta             int
	DQ              int
	NLeaves         int
	FieldModulus    uint64
	Lambda          int
	Kappa           [4]int
}

type SigShortnessReport struct {
	Enabled          bool `json:"enabled"`
	Version          int  `json:"version"`
	SupportSlotCount int  `json:"support_slot_count"`
	OpenedBlockCount int  `json:"opened_block_count"`
	OpeningBytes     int  `json:"opening_bytes"`
	ProofBytes       int  `json:"proof_bytes"`
}

// TranscriptOptimizationReport surfaces the geometry and bucket counters that
// dominate the current paper transcript optimization pass.
type TranscriptOptimizationReport struct {
	ShowingPreset       string `json:"showing_preset"`
	PRFPacked           bool   `json:"prf_packed"`
	PRFMode             string `json:"prf_mode"`
	PRFAuditSamples     int    `json:"prf_audit_samples"`
	PRFBridgeInQ        bool   `json:"prf_bridge_in_q"`
	PRFLogicalScalars   int    `json:"prf_logical_scalars"`
	PRFPackedRows       int    `json:"prf_packed_rows"`
	PRFDataRows         int    `json:"prf_data_rows"`
	PRFHelperRows       int    `json:"prf_helper_rows"`
	PRFTotalRows        int    `json:"prf_total_rows"`
	SigShortnessProfile string `json:"sig_shortness_profile"`
	SigShortnessRadix   int    `json:"sig_shortness_radix"`
	SigShortnessDigits  int    `json:"sig_shortness_digits"`
	SigShortnessDegree  int    `json:"sig_shortness_degree"`
	ReplayMode          string `json:"replay_mode"`
	ReplayBlocks        int    `json:"replay_blocks"`
	LVCSNCols           int    `json:"lvcs_ncols"`
	NLeaves             int    `json:"nleaves"`
	WitnessRows         int    `json:"witness_rows"`
	RowsBlock           int    `json:"rows_block"`
	MaskChunks          int    `json:"mask_chunks"`
	NRows               int    `json:"nrows"`
	M                   int    `json:"m"`
	PCols               int    `json:"pcols"`
	OmitP               int    `json:"omit_p"`
	RowOpeningEntries   int    `json:"row_opening_entries"`
	PdecsBytes          int    `json:"pdecs_bytes"`
	VTargetsBytes       int    `json:"vtargets_bytes"`
	BarSetsBytes        int    `json:"barsets_bytes"`
	QBytes              int    `json:"q_bytes"`
}

// BuildProofReport derives proof size + soundness metrics for a given proof/options.
// This is intended for credential issuance/showing runs.
func BuildProofReport(proof *Proof, opts SimOpts, ringQ *ring.Ring) (ProofReport, error) {
	if proof == nil {
		return ProofReport{}, fmt.Errorf("nil proof")
	}
	if ringQ == nil {
		return ProofReport{}, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	reportOpts := opts
	if proof.Lambda > 0 {
		reportOpts.Lambda = proof.Lambda
	}
	reportOpts.Kappa = proof.Kappa
	if proof.Theta > 0 {
		reportOpts.Theta = proof.Theta
	}

	ncols := proof.NColsUsed
	if ncols <= 0 {
		ncols = reportOpts.NCols
	}
	if ncols <= 0 {
		ncols = int(ringQ.N)
	}
	lvcsNCols := resolveProofPCSNCols(proof, reportOpts.PCSNCols)
	if lvcsNCols <= 0 {
		lvcsNCols = reportOpts.LVCSNCols
	}
	if lvcsNCols <= 0 {
		lvcsNCols = ncols
	}
	ell := reportOpts.Ell
	ellPrime := reportOpts.EllPrime
	rho := reportOpts.Rho
	eta := reportOpts.Eta
	theta := reportOpts.Theta

	dQ := proof.QDegreeBound
	if dQ <= 0 {
		dQ = proof.MaskDegreeBound
	}
	if dQ <= 0 {
		dQ = reportOpts.DQOverride
	}
	if dQ <= 0 {
		return ProofReport{}, fmt.Errorf("missing dQ/QDegreeBound in proof")
	}

	geometry := BuildWitnessGeometrySnapshotFromProof(proof)
	witnessPolys := geometry.ActualWitnessPolys
	if witnessPolys <= 0 {
		witnessPolys = proof.MaskRowOffset
	}
	if witnessPolys <= 0 {
		if proof.RowLayout.SigCount > 0 {
			witnessPolys = proof.RowLayout.SigCount
		} else {
			witnessPolys = ncols
		}
	}

	nLeaves := proof.NLeavesUsed
	if nLeaves <= 0 {
		nLeaves = reportOpts.NLeaves
	}
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}

	q := ringQ.Modulus[0]
	fieldSize := float64(q)
	if theta > 1 {
		fieldSize = math.Pow(float64(q), float64(theta))
	}
	sb := computeSoundnessBudget(reportOpts, q, fieldSize, fsCollisionSpaceBits(reportOpts.Lambda, len(proof.Salt)), dQ, ncols, lvcsNCols, ell, ellPrime, eta, nLeaves, witnessPolys)
	size := MeasureProofSize(proof)
	packing, err := BuildProofPackingAudit(proof, q)
	if err != nil {
		return ProofReport{}, fmt.Errorf("packing audit: %w", err)
	}
	replayAudit, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		return ProofReport{}, fmt.Errorf("replay audit: %w", err)
	}
	sigShortness := buildSigShortnessReport(proof)
	paperTranscript := buildPaperTranscriptReportLeaf(proof, q, paperTranscriptParams{
		Lambda:   reportOpts.Lambda,
		Eta:      eta,
		Ell:      ell,
		EllPrime: ellPrime,
		Rho:      rho,
		Theta:    theta,
		DQ:       dQ,
		DDECS:    lvcsNCols + ell - 1,
	})
	return ProofReport{
		ProofBytes:      size.Total,
		ProofKB:         float64(size.Total) / 1024.0,
		Soundness:       sb,
		PaperTranscript: paperTranscript,
		Packing:         packing,
		ReplayAudit:     replayAudit,
		SigShortness:    sigShortness,
		Geometry:        geometry,
		TranscriptFocus: buildTranscriptOptimizationReport(proof, paperTranscript, packing, sb, geometry, lvcsNCols, dQ, reportOpts, q),
		NCols:           ncols,
		PCSNCols:        lvcsNCols,
		LVCSNCols:       lvcsNCols,
		Ell:             ell,
		EllPrime:        ellPrime,
		Rho:             rho,
		Theta:           theta,
		Eta:             eta,
		DQ:              dQ,
		NLeaves:         nLeaves,
		FieldModulus:    q,
		Lambda:          reportOpts.Lambda,
		Kappa:           reportOpts.Kappa,
	}, nil
}

func buildSigShortnessReport(proof *Proof) SigShortnessReport {
	if proof == nil || proof.SigShortness == nil {
		return SigShortnessReport{}
	}
	sig := proof.SigShortness
	pcsNCols := resolveProofPCSNCols(proof, 0)
	openBlocks := 0
	if pcsNCols > 0 {
		rows := buildSigShortnessWitnessPolyIndicesForVersion(proof.RowLayout, sig.Version)
		seen := make(map[int]struct{}, len(rows))
		for _, row := range rows {
			if row < 0 {
				continue
			}
			seen[row/pcsNCols] = struct{}{}
		}
		openBlocks = len(seen)
	}
	supportSlotCount := len(sig.SupportSlots)
	openingBytes := sizeDECSOpening(sig.Opening)
	if sig.Version == sigShortnessProofVersionV5 && sig.V5 != nil {
		if sig.V5.THatOpening != nil {
			supportSlotCount = len(expandPackedOpening(sig.V5.THatOpening).AllIndices())
		} else {
			supportSlotCount = 0
		}
		openingBytes = sizeDECSOpening(sig.V5.THatOpening)
	}
	return SigShortnessReport{
		Enabled:          true,
		Version:          sig.Version,
		SupportSlotCount: supportSlotCount,
		OpenedBlockCount: openBlocks,
		OpeningBytes:     openingBytes,
		ProofBytes:       sizeSigShortnessProof(sig),
	}
}

func buildTranscriptOptimizationReport(proof *Proof, paper PaperTranscriptReport, packing ProofPackingAudit, sb SoundnessBudget, geometry WitnessGeometrySnapshot, lvcsNCols int, dQ int, opts SimOpts, q uint64) TranscriptOptimizationReport {
	out := TranscriptOptimizationReport{
		NRows:             sb.NRows,
		M:                 sb.M,
		PCols:             packing.RowOpening.Pvals.EncodedCols,
		OmitP:             packing.RowOpening.Pvals.OmittedCols,
		RowOpeningEntries: packing.RowOpening.EntryCount,
		PdecsBytes:        paper.Pdecs.OptimizedBytes,
		VTargetsBytes:     paper.VTargets.OptimizedBytes,
		BarSetsBytes:      paper.BarSets.OptimizedBytes,
		QBytes:            paper.Q.OptimizedBytes,
	}
	out.LVCSNCols = lvcsNCols
	out.ReplayMode = string(normalizeShowingReplayMode(opts.ShowingReplayMode))
	out.ReplayBlocks = rowLayoutReplayBlockCount(proof.RowLayout)
	if out.ReplayBlocks <= 0 {
		out.ReplayBlocks = rowLayoutReplayTHatCount(proof.RowLayout)
	}
	out.NLeaves = proof.NLeavesUsed
	if out.NLeaves <= 0 {
		out.NLeaves = opts.NLeaves
	}
	out.WitnessRows = geometry.ActualWitnessPolys
	out.ShowingPreset = ResolveShowingPresetLabelForOpts(opts)
	if out.LVCSNCols > 0 {
		out.RowsBlock = ceilDiv(out.WitnessRows, out.LVCSNCols)
		if dQ > 0 {
			out.MaskChunks = dQ/out.LVCSNCols + 1
		}
	}
	out.SigShortnessProfile = ResolveSignatureShortnessProfileLabelForOpts(opts)
	if base, L, _, degree, err := ResolveSignatureShortnessMetricsForOpts(q, opts); err == nil {
		out.SigShortnessRadix = base
		out.SigShortnessDigits = L
		out.SigShortnessDegree = degree
	}
	if out.PCols == 0 && packing.PCSOpening.Pvals.EncodedCols > 0 {
		out.PCols = packing.PCSOpening.Pvals.EncodedCols
		out.OmitP = packing.PCSOpening.Pvals.OmittedCols
		out.RowOpeningEntries = packing.PCSOpening.EntryCount
	}
	if proof == nil {
		return out
	}
	if proof.PRFCompanion != nil && proof.PRFCompanion.Layout != nil {
		out.PRFPacked = true
		out.PRFMode = string(prfCompanionModeDefault(proof.PRFCompanion.Mode))
		out.PRFAuditSamples = proof.PRFCompanion.CheckpointSamples
		out.PRFBridgeInQ = proof.PRFCompanion.BridgeInQ
		out.PRFLogicalScalars = proof.PRFCompanion.Layout.PackedLogicalCount
		out.PRFPackedRows = proof.PRFCompanion.Layout.PackedRows
		out.PRFDataRows = proof.PRFCompanion.Layout.DataRows
		out.PRFHelperRows = proof.PRFCompanion.Layout.HelperRows
		out.PRFTotalRows = proof.PRFCompanion.Layout.PackedRows
		return out
	}
	if proof.PRFLayout == nil {
		return out
	}
	out.PRFPacked = proof.PRFLayout.PackedRows
	out.PRFLogicalScalars = prfLogicalScalarCount(proof.PRFLayout)
	out.PRFPackedRows = proof.PRFLayout.WitnessRows
	out.PRFTotalRows = proof.PRFLayout.WitnessRows
	return out
}
