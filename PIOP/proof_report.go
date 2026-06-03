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
	RingDegree      int
	X0Len           int
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
	Enabled          bool   `json:"enabled"`
	Mode             string `json:"mode"`
	Version          int    `json:"version"`
	SupportSlotCount int    `json:"support_slot_count"`
	OpenedBlockCount int    `json:"opened_block_count"`
	OpeningBytes     int    `json:"opening_bytes"`
	HiddenProofBytes int    `json:"hidden_proof_bytes"`
	BindingBytes     int    `json:"binding_bytes"`
	ProofBytes       int    `json:"proof_bytes"`
	HiddenProfile    string `json:"hidden_profile"`
	HiddenRadix      int    `json:"hidden_radix"`
	HiddenDigits     int    `json:"hidden_digits"`
}

// TranscriptOptimizationReport surfaces the geometry and bucket counters that
// dominate the current paper transcript optimization pass.
type TranscriptOptimizationReport struct {
	RingDegree                      int    `json:"ring_degree"`
	X0Len                           int    `json:"x0_len"`
	ShowingPreset                   string `json:"showing_preset"`
	PRFPacked                       bool   `json:"prf_packed"`
	PRFMode                         string `json:"prf_mode"`
	PRFAuditSamples                 int    `json:"prf_audit_samples"`
	PRFBridgeInQ                    bool   `json:"prf_bridge_in_q"`
	PRFLogicalScalars               int    `json:"prf_logical_scalars"`
	PRFPackedRows                   int    `json:"prf_packed_rows"`
	PRFDataRows                     int    `json:"prf_data_rows"`
	PRFHelperRows                   int    `json:"prf_helper_rows"`
	PRFTotalRows                    int    `json:"prf_total_rows"`
	MuPackWidth                     int    `json:"mu_pack_width"`
	MuCarrierRows                   int    `json:"mu_carrier_rows"`
	MuVirtualBlocks                 int    `json:"mu_virtual_blocks"`
	SigShortnessProfile             string `json:"sig_shortness_profile"`
	SigShortnessRadix               int    `json:"sig_shortness_radix"`
	SigShortnessDigits              int    `json:"sig_shortness_digits"`
	SigShortnessDegree              int    `json:"sig_shortness_degree"`
	UDigitOnly                      bool   `json:"u_digit_only,omitempty"`
	LinearHatSourceMode             string `json:"linear_hat_source_mode,omitempty"`
	OmittedLinearHatRows            int    `json:"omitted_linear_hat_rows,omitempty"`
	ShortnessMembershipBackend      string `json:"shortness_membership_backend,omitempty"`
	SigLookupShadowMode             string `json:"sig_lookup_shadow_mode"`
	SigLookupCells                  int    `json:"sig_lookup_cells"`
	SigLookupTableSize              int    `json:"sig_lookup_table_size"`
	SigRowsBefore                   int    `json:"sig_rows_before"`
	SigRowsAfter                    int    `json:"sig_rows_after"`
	FreeLookupUpperBoundBytes       int    `json:"free_lookup_upper_bound_bytes"`
	MaxLookupBudgetFor35500         int    `json:"max_lookup_budget_for_35500"`
	ReplayMode                      string `json:"replay_mode"`
	StatementClass                  string `json:"statement_class"`
	ShortnessMode                   string `json:"shortness_mode"`
	SigShortnessSupportSlots        int    `json:"sig_shortness_support_slots"`
	ReplayBlocks                    int    `json:"replay_blocks"`
	ReplayMHatSigmaRows             int    `json:"replay_mhat_sigma_rows"`
	ReplayRHat0Rows                 int    `json:"replay_rhat0_rows"`
	ReplayR0B2HatRows               int    `json:"replay_r0_b2_hat_rows"`
	ReplayTargetMR0HatRows          int    `json:"replay_target_mr0_hat_rows"`
	ReplayRHat1Rows                 int    `json:"replay_rhat1_rows"`
	ReplayZHatRows                  int    `json:"replay_zhat_rows"`
	ReplayTHatRows                  int    `json:"replay_that_rows"`
	InlinedShortnessRows            int    `json:"inlined_shortness_rows"`
	PackedSigChainGroupSize         int    `json:"packed_sig_chain_group_size"`
	PackedSigBlockWidth             int    `json:"packed_sig_block_width"`
	PackedSigEffectiveBlocks        int    `json:"packed_sig_effective_blocks"`
	PackedSigShortnessRows          int    `json:"packed_sig_shortness_rows"`
	MaskRows                        int    `json:"mask_rows"`
	AggregateR0Replay               bool   `json:"aggregate_r0_replay"`
	MainLVCSNCols                   int    `json:"main_lvcs_ncols"`
	MainNLeaves                     int    `json:"main_nleaves"`
	PRFLVCSNCols                    int    `json:"prf_lvcs_ncols"`
	PRFNLeaves                      int    `json:"prf_nleaves"`
	HiddenShortnessProfile          string `json:"hidden_shortness_profile"`
	HiddenShortnessRadix            int    `json:"hidden_shortness_radix"`
	HiddenShortnessDigits           int    `json:"hidden_shortness_digits"`
	HiddenShortnessLVCSNCols        int    `json:"hidden_shortness_lvcs_ncols"`
	HiddenShortnessNLeaves          int    `json:"hidden_shortness_nleaves"`
	FixedTranscriptSize             bool   `json:"fixed_transcript_size"`
	TranscriptSizeMode              string `json:"transcript_size_mode"`
	SourceProductBridgeBytes        int    `json:"source_product_bridge_bytes"`
	SourceProductBridgeSupportSlots int    `json:"source_product_bridge_support_slots"`
	SourceProductBridgeOpenedBlocks int    `json:"source_product_bridge_opened_blocks"`
	CarrierSelectedRows             int    `json:"carrier_selected_rows"`
	SourceProductSelectedRows       int    `json:"source_product_selected_rows"`
	PRFCompanionSelectedRows        int    `json:"prf_companion_selected_rows"`
	LVCSNCols                       int    `json:"lvcs_ncols"`
	NLeaves                         int    `json:"nleaves"`
	WitnessRows                     int    `json:"witness_rows"`
	RowsBlock                       int    `json:"rows_block"`
	AuditRows                       int    `json:"audit_rows"`
	OpeningCols                     int    `json:"opening_cols"`
	SmallFieldReplayRows            int    `json:"smallfield_replay_rows"`
	MaskChunks                      int    `json:"mask_chunks"`
	NRows                           int    `json:"nrows"`
	M                               int    `json:"m"`
	PCols                           int    `json:"pcols"`
	OmitP                           int    `json:"omit_p"`
	RowOpeningEntries               int    `json:"row_opening_entries"`
	PdecsBytes                      int    `json:"pdecs_bytes"`
	VTargetsBytes                   int    `json:"vtargets_bytes"`
	BarSetsBytes                    int    `json:"barsets_bytes"`
	QBytes                          int    `json:"q_bytes"`
	PDecsBitWidth                   int    `json:"pdecs_bit_width"`
	VTargetsBitWidth                int    `json:"vtargets_bit_width"`
	TranscriptSecurityStatus        string `json:"transcript_security_status,omitempty"`
	SmallField2025Status            string `json:"smallfield_2025_status,omitempty"`
	SmallField2025ReductionEnabled  bool   `json:"smallfield_2025_reduction_enabled,omitempty"`
	SmallField2025QueryCount        int    `json:"smallfield_2025_query_count,omitempty"`
	SmallField2025VHeadRows         int    `json:"smallfield_2025_vhead_rows,omitempty"`
	SmallField2025VHeadCols         int    `json:"smallfield_2025_vhead_cols,omitempty"`
	SmallField2025VBarRows          int    `json:"smallfield_2025_vbar_rows,omitempty"`
	SmallField2025VBarCols          int    `json:"smallfield_2025_vbar_cols,omitempty"`
	SmallField2025Notes             string `json:"smallfield_2025_notes,omitempty"`
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
	if err := validateProofRingDegree(proof, int(ringQ.N)); err != nil {
		return ProofReport{}, err
	}
	reportOpts := opts
	reportOpts.RingDegree = int(ringQ.N)
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
	x0Len := rowLayoutX0Len(proof.RowLayout)
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
		Lambda:     reportOpts.Lambda,
		RingDegree: int(ringQ.N),
		X0Len:      x0Len,
		Eta:        eta,
		Ell:        ell,
		EllPrime:   ellPrime,
		Rho:        rho,
		Theta:      theta,
		DQ:         dQ,
		DDECS:      lvcsNCols + ell - 1,
	})
	if proof.SourceProductBridge != nil {
		openingRep := BuildOpeningPaperReport(proof.SourceProductBridge.RowsOpening)
		paperTranscript.Pdecs.NaiveBits += openingRep.PdecsBits
		paperTranscript.Pdecs.OptimizedBits += openingRep.PdecsBits
		paperTranscript.Mdecs.NaiveBits += openingRep.MdecsBits
		paperTranscript.Mdecs.OptimizedBits += openingRep.MdecsBits
		paperTranscript.Auth.NaiveBits += openingRep.AuthBits
		paperTranscript.Auth.OptimizedBits += openingRep.AuthBits
		paperTranscript.Tapes.NaiveBits += openingRep.TapeBits
		paperTranscript.Tapes.OptimizedBits += openingRep.TapeBits
		finalizePaperTranscriptReport(&paperTranscript)
	}
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
		RingDegree:      int(ringQ.N),
		X0Len:           x0Len,
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
	if pcsNCols > 0 && sig.Version != sigShortnessProofVersionV18 {
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
	if sig.Version == sigShortnessProofVersionV18 && sig.V18 != nil {
		supportSlotCount = 0
		openingBytes = 0
		openBlocks = 0
	}
	if sig.Version == sigShortnessProofVersionV6 && sig.V6 != nil {
		if sig.V6.THatOpening != nil {
			supportSlotCount = len(expandPackedOpening(sig.V6.THatOpening).AllIndices())
		} else {
			supportSlotCount = 0
		}
		openingBytes = sizeDECSOpening(sig.V6.THatOpening)
	}
	if sig.Version == sigShortnessProofVersionV5 && sig.V5 != nil {
		if sig.V5.THatOpening != nil {
			supportSlotCount = len(expandPackedOpening(sig.V5.THatOpening).AllIndices())
		} else {
			supportSlotCount = 0
		}
		openingBytes = sizeDECSOpening(sig.V5.THatOpening)
	}
	proofBytes := sizeSigShortnessProof(sig)
	hiddenBytes := 0
	hiddenProfile := ""
	hiddenRadix := 0
	hiddenDigits := 0
	if sig.Version == sigShortnessProofVersionV6 && sig.V6 != nil && sig.V6.HiddenProof != nil {
		_, hiddenBytes = proofSizeBreakdown(sig.V6.HiddenProof)
		hiddenRadix = sig.V6.Radix
		hiddenDigits = sig.V6.Digits
		hiddenProfile = signatureShortnessProfileLabelFromMetrics(hiddenRadix, hiddenDigits)
	}
	return SigShortnessReport{
		Enabled:          true,
		Mode:             ResolveSigShortnessMode(proof),
		Version:          sig.Version,
		SupportSlotCount: supportSlotCount,
		OpenedBlockCount: openBlocks,
		OpeningBytes:     openingBytes,
		HiddenProofBytes: hiddenBytes,
		BindingBytes:     maxInt(proofBytes-openingBytes-hiddenBytes, 0),
		ProofBytes:       proofBytes,
		HiddenProfile:    hiddenProfile,
		HiddenRadix:      hiddenRadix,
		HiddenDigits:     hiddenDigits,
	}
}

func buildTranscriptOptimizationReport(proof *Proof, paper PaperTranscriptReport, packing ProofPackingAudit, sb SoundnessBudget, geometry WitnessGeometrySnapshot, lvcsNCols int, dQ int, opts SimOpts, q uint64) TranscriptOptimizationReport {
	out := TranscriptOptimizationReport{
		RingDegree:          resolvedProofRingDegree(proof, opts.RingDegree),
		X0Len:               rowLayoutX0Len(proof.RowLayout),
		NRows:               sb.NRows,
		M:                   sb.M,
		PCols:               packing.RowOpening.Pvals.EncodedCols,
		OmitP:               packing.RowOpening.Pvals.OmittedCols,
		RowOpeningEntries:   packing.RowOpening.EntryCount,
		PdecsBytes:          paper.Pdecs.OptimizedBytes,
		VTargetsBytes:       paper.VTargets.OptimizedBytes,
		BarSetsBytes:        paper.BarSets.OptimizedBytes,
		QBytes:              paper.Q.OptimizedBytes,
		PDecsBitWidth:       packing.RowOpening.Pvals.BitWidth,
		VTargetsBitWidth:    packing.VTargets.BitWidth,
		FixedTranscriptSize: opts.FixedTranscriptSize || proof.FixedTranscriptSize,
	}
	if out.FixedTranscriptSize {
		out.TranscriptSizeMode = "fixed"
	} else {
		out.TranscriptSizeMode = "compact"
	}
	out.LVCSNCols = lvcsNCols
	out.MainLVCSNCols = lvcsNCols
	out.ReplayMode = string(normalizeShowingReplayMode(opts.ShowingReplayMode))
	out.StatementClass = ResolveShowingStatementClass(proof, opts)
	out.ShortnessMode = ResolveSigShortnessMode(proof)
	out.SigShortnessSupportSlots = buildSigShortnessReport(proof).SupportSlotCount
	out.ReplayBlocks = rowLayoutReplayBlockCount(proof.RowLayout)
	if out.ReplayBlocks <= 0 {
		out.ReplayBlocks = rowLayoutReplayTHatCount(proof.RowLayout)
	}
	out.ReplayMHatSigmaRows = len(rowLayoutPostSignMHatSigmaRows(proof.RowLayout))
	out.ReplayRHat0Rows = len(rowLayoutPostSignRHat0Rows(proof.RowLayout))
	out.ReplayR0B2HatRows = len(rowLayoutPostSignR0B2HatRows(proof.RowLayout))
	out.ReplayTargetMR0HatRows = len(rowLayoutPostSignTargetMR0HatRows(proof.RowLayout))
	out.ReplayRHat1Rows = len(rowLayoutPostSignRHat1Rows(proof.RowLayout))
	out.ReplayZHatRows = len(rowLayoutPostSignZHatRows(proof.RowLayout))
	out.ReplayTHatRows = len(rowLayoutPostSignTHatRows(proof.RowLayout))
	out.MuPackWidth = rowLayoutMuCarrierPackWidth(proof.RowLayout)
	out.MuCarrierRows = len(rowLayoutCarrierMuBlockRows(proof.RowLayout))
	out.MuVirtualBlocks = rowLayoutMuVirtualBlockCount(proof.RowLayout)
	inlinedShortnessRows := proof.RowLayout.PackedSigChainGroupCount * proof.RowLayout.PackedSigChainRowsPerGroup
	out.InlinedShortnessRows = inlinedShortnessRows
	if proof.SigShortness != nil && proof.SigShortness.Version == sigShortnessProofVersionV18 {
		out.PackedSigChainGroupSize = proof.RowLayout.PackedSigChainGroupSize
		out.PackedSigBlockWidth = rowLayoutPackedSigChainBlockWidth(proof.RowLayout)
		out.PackedSigEffectiveBlocks = rowLayoutPackedSigChainEffectiveBlocks(proof.RowLayout)
		out.PackedSigShortnessRows = inlinedShortnessRows
	}
	out.SigLookupShadowMode = NormalizeSigLookupShadowR121L2Mode(opts.UnsafeSigLookupShadowR121L2)
	if out.SigLookupShadowMode != SigLookupShadowR121L2None {
		out.SigRowsBefore = proof.RowLayout.PackedSigChainGroupCount * signaturePackedProductionL
		out.SigRowsAfter = inlinedShortnessRows
		out.SigLookupCells = out.SigRowsAfter * maxInt(out.PackedSigBlockWidth, opts.NCols)
		out.SigLookupTableSize = sigLookupShadowR121L2TableSize
		if out.SigLookupShadowMode == SigLookupShadowR121L2Free {
			out.FreeLookupUpperBoundBytes = paper.OptimizedBytes
			out.MaxLookupBudgetFor35500 = sigLookupShadowR121L2TargetBudget - out.FreeLookupUpperBoundBytes
		}
	}
	out.MaskRows = geometry.MaskRowsCommitted
	out.SmallFieldReplayRows = proof.PCSGeometry.ReplayWitnessRows
	if out.SmallFieldReplayRows <= 0 {
		out.SmallFieldReplayRows = proof.MaskRowOffset
	}
	out.AggregateR0Replay = opts.AggregateR0Replay || out.ReplayR0B2HatRows > 0 || out.ReplayTargetMR0HatRows > 0
	out.NLeaves = proof.NLeavesUsed
	if out.NLeaves <= 0 {
		out.NLeaves = opts.NLeaves
	}
	out.MainNLeaves = out.NLeaves
	out.PRFLVCSNCols = opts.PRFLVCSNCols
	if out.PRFLVCSNCols <= 0 {
		out.PRFLVCSNCols = opts.LVCSNCols
	}
	out.PRFNLeaves = opts.PRFNLeaves
	if out.PRFNLeaves <= 0 {
		out.PRFNLeaves = opts.NLeaves
	}
	out.WitnessRows = geometry.ActualWitnessPolys
	out.ShowingPreset = ResolveShowingPresetLabelForOpts(opts)
	if out.LVCSNCols > 0 {
		out.RowsBlock = ceilDiv(out.WitnessRows, out.LVCSNCols)
		if dQ > 0 {
			out.MaskChunks = dQ/out.LVCSNCols + 1
		}
	}
	if opts.EllPrime > 0 {
		out.AuditRows = out.RowsBlock * opts.EllPrime
		if opts.Theta > 1 {
			out.AuditRows *= opts.Theta
		}
	}
	if opts.Theta > 1 {
		out.OpeningCols = out.SmallFieldReplayRows + out.MaskRows - out.AuditRows
	} else {
		out.OpeningCols = out.WitnessRows + maxInt(opts.Rho, 1)
	}
	if out.OpeningCols < 0 {
		out.OpeningCols = 0
	}
	out.SigShortnessProfile = ResolveSignatureShortnessProfileLabelForOpts(opts)
	if base, L, _, degree, err := ResolveSignatureShortnessMetricsForOpts(q, opts); err == nil {
		out.SigShortnessRadix = base
		out.SigShortnessDigits = L
		out.SigShortnessDegree = degree
	}
	out.ShortnessMembershipBackend = string(intGenISISShortnessMembershipBackendForOpts(opts))
	if out.PCols == 0 && packing.PCSOpening.Pvals.EncodedCols > 0 {
		out.PCols = packing.PCSOpening.Pvals.EncodedCols
		out.OmitP = packing.PCSOpening.Pvals.OmittedCols
		out.RowOpeningEntries = packing.PCSOpening.EntryCount
	}
	if proof == nil {
		return out
	}
	if proof.RowLayout.IntGenISISShowing != nil {
		l := proof.RowLayout.IntGenISISShowing
		out.UDigitOnly = intGenISISProjectionUsesDigitOnlyU(l)
		out.LinearHatSourceMode = intGenISISLinearHatSourceMode(l)
		if intGenISISProjectionUsesSourceLinearHats(l) {
			out.OmittedLinearHatRows = l.MuSigCount*l.ViewRowsPerPoly + l.X0Count*l.ViewRowsPerPoly + l.X1Count*l.ViewRowsPerPoly - (l.MuSigHatCount + l.X0HatCount + l.X1HatCount)
			if out.OmittedLinearHatRows < 0 {
				out.OmittedLinearHatRows = 0
			}
		} else if intGenISISProjectionUsesBBTranWResidual(l) {
			out.OmittedLinearHatRows = l.MuSigCount*l.ViewRowsPerPoly + l.X0Count*l.ViewRowsPerPoly - l.WHatCount
			if out.OmittedLinearHatRows < 0 {
				out.OmittedLinearHatRows = 0
			}
		}
	}
	out.TranscriptSecurityStatus = "maintained_live"
	if normalizeTranscriptVersion(proof.TranscriptVersion) == TranscriptVersionSmallWood2025 {
		out.TranscriptSecurityStatus = "smallwood_2025_1085_live"
	}
	if opts.TranscriptCodec != "" {
		out.TranscriptSecurityStatus = "serialization_live"
	}
	if proof.SmallField2025 != nil {
		out.TranscriptSecurityStatus = proof.SmallField2025.Status
		out.SmallField2025Status = proof.SmallField2025.Status
		out.SmallField2025ReductionEnabled = proof.SmallField2025.ReductionEnabled
		out.SmallField2025QueryCount = proof.SmallField2025.QueryCount
		out.SmallField2025VHeadRows = proof.SmallField2025.VHeadRows
		out.SmallField2025VHeadCols = proof.SmallField2025.VHeadCols
		out.SmallField2025VBarRows = proof.SmallField2025.VBarRows
		out.SmallField2025VBarCols = proof.SmallField2025.VBarCols
		out.SmallField2025Notes = proof.SmallField2025.Notes
		if proof.SmallField2025.ReductionEnabled {
			out.AuditRows = proof.SmallField2025.QueryCount
			out.MaskRows = proof.SmallField2025.MaskRows
			if out.PCols > 0 {
				out.OpeningCols = out.PCols
			}
		}
	}
	if proof.SigShortness != nil && proof.SigShortness.V6 != nil && proof.SigShortness.V6.HiddenProof != nil {
		out.HiddenShortnessProfile = signatureShortnessProfileLabelFromMetrics(proof.SigShortness.V6.Radix, proof.SigShortness.V6.Digits)
		out.HiddenShortnessRadix = proof.SigShortness.V6.Radix
		out.HiddenShortnessDigits = proof.SigShortness.V6.Digits
		out.HiddenShortnessLVCSNCols = resolveProofPCSNCols(proof.SigShortness.V6.HiddenProof, 0)
		out.HiddenShortnessNLeaves = proof.SigShortness.V6.HiddenProof.NLeavesUsed
	}
	if proof.SourceProductBridge != nil {
		out.SourceProductBridgeBytes = sizeSourceProductBridge(proof.SourceProductBridge)
		out.SourceProductBridgeSupportSlots = len(proof.SourceProductBridge.SupportSlots)
		pcsNCols := resolveProofPCSNCols(proof, 0)
		if pcsNCols > 0 {
			seen := make(map[int]struct{}, len(proof.SourceProductBridge.PhysicalRows))
			for _, row := range proof.SourceProductBridge.PhysicalRows {
				seen[row/pcsNCols] = struct{}{}
			}
			out.SourceProductBridgeOpenedBlocks = len(seen)
		}
	}
	for _, count := range buildReplayFamilySelectedCounts(proof) {
		switch count.kind {
		case ReplayFamilyCarrier:
			out.CarrierSelectedRows = count.count
		case ReplayFamilySourceProduct:
			out.SourceProductSelectedRows = count.count
		case ReplayFamilyPRFCompanion:
			out.PRFCompanionSelectedRows = count.count
		}
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

type replayFamilySelectedCount struct {
	kind  ReplayFamilyKind
	count int
}

func buildReplayFamilySelectedCounts(proof *Proof) []replayFamilySelectedCount {
	if proof == nil {
		return nil
	}
	report, err := BuildReplayFamilyAuditReport(proof)
	if err != nil {
		return nil
	}
	out := make([]replayFamilySelectedCount, 0, len(report.Families))
	for _, family := range report.Families {
		out = append(out, replayFamilySelectedCount{
			kind:  family.Family,
			count: family.SelectedRowCount,
		})
	}
	return out
}
