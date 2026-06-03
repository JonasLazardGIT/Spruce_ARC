package main

import (
	"fmt"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/prf"
)

const (
	sweepTranscriptModeBaseline       = "baseline"
	sweepTranscriptModeColumnWidths   = "column_widths_v1"
	sweepTranscriptModeSmallField2025 = "smallfield_2025_1085_v1"
)

type benchmarkIntGenISISMetrics struct {
	ProofSizeBytes                int                `json:"proof_size_bytes"`
	PaperTranscriptBytes          int                `json:"paper_transcript_bytes"`
	PaperTranscriptKB             float64            `json:"paper_transcript_kb"`
	QBytes                        int                `json:"q_bytes"`
	RBytes                        int                `json:"r_bytes"`
	PdecsBytes                    int                `json:"pdecs_bytes"`
	MdecsBytes                    int                `json:"mdecs_bytes,omitempty"`
	AuthBytes                     int                `json:"auth_bytes"`
	TapesBytes                    int                `json:"tapes_bytes,omitempty"`
	SigShortnessBytes             int                `json:"sig_shortness_bytes"`
	VTargetsBytes                 int                `json:"vtargets_bytes"`
	BarSetsBytes                  int                `json:"barsets_bytes"`
	ProvingMS                     float64            `json:"proving_ms"`
	VerificationMS                float64            `json:"verification_ms"`
	PhaseTimings                  []PIOP.PhaseTiming `json:"phase_timings,omitempty"`
	TotalRows                     int                `json:"total_rows"`
	RowsBlock                     int                `json:"rows_block,omitempty"`
	AuditRows                     int                `json:"audit_rows,omitempty"`
	OpeningCols                   int                `json:"opening_cols,omitempty"`
	PRFRows                       int                `json:"prf_rows"`
	CoefficientViewRows           int                `json:"coefficient_view_rows"`
	UCoefficientViewRows          int                `json:"u_coefficient_view_rows,omitempty"`
	UDigitOnly                    bool               `json:"u_digit_only,omitempty"`
	SemanticViewRows              int                `json:"semantic_view_rows,omitempty"`
	CommitmentViewRows            int                `json:"commitment_view_rows,omitempty"`
	YCoefficientViewRows          int                `json:"y_coefficient_view_rows,omitempty"`
	IssuerViewRows                int                `json:"issuer_view_rows,omitempty"`
	BoundRows                     int                `json:"bound_rows"`
	ShortnessRows                 int                `json:"shortness_rows"`
	ShortnessConstraints          int                `json:"shortness_constraints,omitempty"`
	HatRows                       int                `json:"hat_rows"`
	YHatRows                      int                `json:"y_hat_rows,omitempty"`
	SourceBridgeConstraints       int                `json:"source_bridge_constraints"`
	UBridgeConstraints            int                `json:"u_bridge_constraints,omitempty"`
	CommitmentBridgeConstraints   int                `json:"commitment_bridge_constraints,omitempty"`
	YLinearConstraints            int                `json:"y_linear_constraints,omitempty"`
	ProjectedSignatureConstraints int                `json:"projected_signature_constraints,omitempty"`
	ReplayProjection              string             `json:"replay_projection,omitempty"`
	IssuerBridgeConstraints       int                `json:"issuer_bridge_constraints,omitempty"`
	PRFKeyBridgeConstraints       int                `json:"prf_key_bridge_constraints,omitempty"`
	FparIntConstraints            int                `json:"fpar_int_constraints,omitempty"`
	RangeConstraints              int                `json:"range_constraints,omitempty"`
	ParallelDegree                int                `json:"parallel_degree"`
	AggregatedDegree              int                `json:"aggregated_degree"`
	ParallelAlgDegree             int                `json:"parallel_alg_degree,omitempty"`
	AggregatedAlgDegree           int                `json:"aggregated_alg_degree,omitempty"`
	PaperConservativeDQ           int                `json:"paper_conservative_dq,omitempty"`
	MaskDegreeBound               int                `json:"mask_degree_bound,omitempty"`
	DominantDegreeSource          string             `json:"dominant_degree_source,omitempty"`
	TernaryRows                   int                `json:"ternary_rows,omitempty"`
	CompressedRows                int                `json:"compressed_rows"`
	MSECompressionLevel           int                `json:"mse_compression_level,omitempty"`
	MSECompressionPackWidth       int                `json:"mse_compression_pack_width,omitempty"`
	MSECompressionDegree          int                `json:"mse_compression_degree,omitempty"`
	RoundBits                     [4]float64         `json:"round_bits"`
	RawRoundBits                  [4]float64         `json:"raw_round_bits"`
	TheoremBits                   [4]float64         `json:"theorem_bits"`
	TheoremTotalBits              float64            `json:"theorem_total_bits"`
	CollisionBits                 float64            `json:"collision_bits"`
	Clamped                       [4]bool            `json:"clamped"`
	SoundnessEq8Bits              float64            `json:"soundness_eq8_bits"`
	DQ                            int                `json:"dq"`
	DDECS                         int                `json:"ddecs"`
	WitnessSupportCols            int                `json:"witness_support_cols"`
	CommittedCols                 int                `json:"committed_cols"`
	ProofReportBuckets            int                `json:"proof_report_buckets"`
	Theta                         int                `json:"theta"`
	Rho                           int                `json:"rho"`
	EllPrime                      int                `json:"ell_prime"`
	SmallFieldReplayRows          int                `json:"smallfield_replay_rows,omitempty"`
	MaskRows                      int                `json:"mask_rows,omitempty"`
	QSplitRows                    int                `json:"q_split_rows,omitempty"`
	QLimbRows                     int                `json:"q_limb_rows,omitempty"`
	PDecsBitWidth                 int                `json:"pdecs_bit_width,omitempty"`
	VTargetsBitWidth              int                `json:"vtargets_bit_width,omitempty"`
	PaperShapeNRows               int                `json:"paper_shape_nrows,omitempty"`
	PaperShapeQueries             int                `json:"paper_shape_queries,omitempty"`
	PaperShapeWitnessLayers       int                `json:"paper_shape_witness_layers,omitempty"`
	PaperShapeMaskRows            int                `json:"paper_shape_mask_rows,omitempty"`
	PaperShapeVHeadBytes          int                `json:"paper_shape_vhead_bytes,omitempty"`
	PaperShapeVBarBytes           int                `json:"paper_shape_vbar_bytes,omitempty"`
	PaperShapeOpeningOmitEntries  int                `json:"paper_shape_opening_omit_entries,omitempty"`
	PaperShapeCanonical           bool               `json:"paper_shape_canonical,omitempty"`
	FixedTranscriptSize           bool               `json:"fixed_transcript_size"`
	TranscriptSizeMode            string             `json:"transcript_size_mode"`
	TranscriptSecurityStatus      string             `json:"transcript_security_status,omitempty"`
	MeasurementStatus             string             `json:"measurement_status"`
}

func normalizeSweepTranscriptMode(mode string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "", sweepTranscriptModeBaseline:
		return sweepTranscriptModeBaseline, nil
	case sweepTranscriptModeColumnWidths, "column-widths", "column_widths":
		return sweepTranscriptModeColumnWidths, nil
	case sweepTranscriptModeSmallField2025, "smallfield-2025-1085-v1", "smallwood-2025-1085-smallfield", "paper-smallfield":
		return sweepTranscriptModeSmallField2025, nil
	default:
		return "", fmt.Errorf("unknown transcript mode %q (supported: baseline, column_widths_v1, smallfield_2025_1085_v1)", mode)
	}
}

func intGenISISMetricsFromProof(proof *PIOP.Proof, report PIOP.ProofReport, pub PIOP.PublicInputs, opts PIOP.SimOpts, proveDur, verifyDur time.Duration, status string) benchmarkIntGenISISMetrics {
	metrics := benchmarkIntGenISISMetrics{
		ProofSizeBytes:           report.ProofBytes,
		PaperTranscriptBytes:     report.PaperTranscript.OptimizedBytes,
		PaperTranscriptKB:        float64(report.PaperTranscript.OptimizedBytes) / 1024.0,
		QBytes:                   report.PaperTranscript.Q.OptimizedBytes,
		RBytes:                   report.PaperTranscript.R.OptimizedBytes,
		PdecsBytes:               report.PaperTranscript.Pdecs.OptimizedBytes,
		AuthBytes:                report.PaperTranscript.Auth.OptimizedBytes,
		SigShortnessBytes:        report.PaperTranscript.SigShortness.OptimizedBytes,
		VTargetsBytes:            report.PaperTranscript.VTargets.OptimizedBytes,
		BarSetsBytes:             report.PaperTranscript.BarSets.OptimizedBytes,
		ProvingMS:                float64(proveDur.Microseconds()) / 1000.0,
		VerificationMS:           float64(verifyDur.Microseconds()) / 1000.0,
		PhaseTimings:             opts.PhaseRecorder.Snapshot(),
		TotalRows:                proof.RowLayout.SigCount,
		RowsBlock:                report.TranscriptFocus.RowsBlock,
		AuditRows:                report.TranscriptFocus.AuditRows,
		OpeningCols:              report.TranscriptFocus.OpeningCols,
		ParallelDegree:           proof.QDegreeBound,
		AggregatedDegree:         proof.QDegreeBound,
		RoundBits:                report.Soundness.Bits,
		RawRoundBits:             report.Soundness.RawBits,
		TheoremBits:              report.Soundness.TheoremBits,
		TheoremTotalBits:         report.Soundness.TotalBits,
		CollisionBits:            report.Soundness.CollisionBits,
		Clamped:                  report.Soundness.Clamped,
		SoundnessEq8Bits:         report.Soundness.Eq8TotalBits,
		DQ:                       report.DQ,
		DDECS:                    report.Soundness.DDECS,
		WitnessSupportCols:       report.Soundness.WitnessSupportCols,
		CommittedCols:            report.Soundness.CommittedCols,
		ProofReportBuckets:       intGenISISProofSizeBucketCount(proof),
		PDecsBitWidth:            report.TranscriptFocus.PDecsBitWidth,
		VTargetsBitWidth:         report.TranscriptFocus.VTargetsBitWidth,
		FixedTranscriptSize:      opts.FixedTranscriptSize || proof.FixedTranscriptSize,
		TranscriptSizeMode:       transcriptSizeModeLabel(opts.FixedTranscriptSize || proof.FixedTranscriptSize),
		TranscriptSecurityStatus: report.TranscriptFocus.TranscriptSecurityStatus,
		MeasurementStatus:        status,
	}
	metrics.Theta = proof.Theta
	if metrics.Theta <= 0 {
		metrics.Theta = 1
	}
	if proof.Theta > 1 {
		metrics.Rho = len(proof.GammaPrimeK)
		metrics.EllPrime = len(proof.KPoint)
		metrics.SmallFieldReplayRows = proof.PCSGeometry.ReplayWitnessRows
		metrics.MaskRows = proof.PCSGeometry.MaskRows
		metrics.QLimbRows = proof.Theta
	} else {
		metrics.Rho = len(proof.GammaPrime)
		metrics.EllPrime = len(proof.EvalPoints)
	}
	if qPayloadRows := len(proof.QPayloadMatrix()); qPayloadRows > 0 {
		metrics.QSplitRows = qPayloadRows
		if metrics.Rho <= 0 {
			metrics.Rho = qPayloadRows
			if proof.Theta > 1 && proof.Theta > 0 {
				metrics.Rho = qPayloadRows / proof.Theta
			}
		}
	}
	if metrics.Rho <= 0 && proof.QOpening != nil {
		metrics.Rho = proof.QOpening.R
		if proof.Theta > 1 && proof.Theta > 0 {
			metrics.Rho = proof.QOpening.R / proof.Theta
		}
	}
	if proof.QOpening != nil {
		metrics.QSplitRows = proof.QOpening.R
	}
	if proof.RowLayout.IntGenISISPreSign != nil {
		l := proof.RowLayout.IntGenISISPreSign
		metrics.BoundRows = l.BoundViewCount
		metrics.TernaryRows = l.BoundViewCount
		metrics.ParallelAlgDegree = 9
		metrics.AggregatedAlgDegree = 1
		metrics.DominantDegreeSource = "bounded_range"
		metrics.ParallelDegree = metrics.ParallelAlgDegree
		metrics.AggregatedDegree = metrics.AggregatedAlgDegree
	}
	if proof.RowLayout.IntGenISISShowing != nil {
		l := proof.RowLayout.IntGenISISShowing
		countViews := func(start, components int) int {
			if start < 0 || components <= 0 || l.ViewRowsPerPoly <= 0 {
				return 0
			}
			return components * l.ViewRowsPerPoly
		}
		metrics.UCoefficientViewRows = countViews(l.UViewStart, l.UCount)
		metrics.SemanticViewRows = countViews(l.MViewStart, l.MCount) + countViews(l.MAttrViewStart, l.MAttrCount) + countViews(l.KViewStart, l.KCount)
		metrics.CommitmentViewRows = countViews(l.SViewStart, l.SCount) + countViews(l.EViewStart, l.ECount)
		metrics.YCoefficientViewRows = l.YViewCount
		metrics.IssuerViewRows = countViews(l.MuSigViewStart, l.MuSigCount) + countViews(l.X0ViewStart, l.X0Count) + countViews(l.X1ViewStart, l.X1Count) + countViews(l.ZViewStart, l.ZCount)
		metrics.CoefficientViewRows = metrics.UCoefficientViewRows + metrics.SemanticViewRows + metrics.CommitmentViewRows + metrics.YCoefficientViewRows + metrics.IssuerViewRows
		metrics.BoundRows = l.BoundViewCount
		metrics.TernaryRows = l.BoundViewCount
		metrics.CompressedRows = l.MSECarrierCount
		metrics.MSECompressionLevel = l.MSECompressionLevel
		metrics.MSECompressionPackWidth = l.MSECompressionPackWidth
		metrics.MSECompressionDegree = l.MSECompressionDecodeDegree
		metrics.RangeConstraints = l.BoundViewCount
		metrics.ShortnessRows = l.UShortnessGroupCount * l.UShortnessRowsPerGroup
		metrics.UDigitOnly = l.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || l.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 || l.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5
		metrics.ShortnessConstraints = l.UShortnessGroupCount * l.UShortnessRowsPerGroup
		if !metrics.UDigitOnly {
			metrics.ShortnessConstraints += l.UShortnessGroupCount
		}
		metrics.YHatRows = l.YHatCount
		metrics.HatRows = l.UHatCount + l.MHatCount + l.SHatCount + l.EHatCount + l.YHatCount + l.MuSigHatCount + l.X0HatCount + l.WHatCount + l.X1HatCount + l.ZHatCount
		metrics.ReplayProjection = l.ReplayProjection
		if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_y_hat_v1" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUYHatV1
		} else if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_y_hat_y_view_v2" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2
		} else if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_digits_y_view_v3" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3
		} else if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_digits_y_source_linear_v4" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4
		} else if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_digits_y_w_residual_v5" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5
		}
		metrics.UDigitOnly = metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5
		if l.ViewRowsPerPoly > 0 {
			ncols := proof.RowLayout.RingDegree / l.ViewRowsPerPoly
			bridgeRows := func(viewStart, hatCount int) int {
				if viewStart < 0 || hatCount <= 0 {
					return 0
				}
				return hatCount * ncols
			}
			metrics.UBridgeConstraints = bridgeRows(l.UViewStart, l.UHatCount)
			metrics.CommitmentBridgeConstraints = bridgeRows(l.YViewStart, l.YHatCount)
			metrics.YLinearConstraints = l.YViewCount * ncols
			metrics.IssuerBridgeConstraints = bridgeRows(l.MuSigViewStart, l.MuSigHatCount) + bridgeRows(l.X0ViewStart, l.X0HatCount) + bridgeRows(l.X1ViewStart, l.X1HatCount) + bridgeRows(l.ZViewStart, l.ZHatCount)
			if metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUYHatV1 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5 {
				metrics.ProjectedSignatureConstraints = l.ViewRowsPerPoly * ncols
			}
			metrics.SourceBridgeConstraints = metrics.UBridgeConstraints + metrics.CommitmentBridgeConstraints + metrics.YLinearConstraints + metrics.ProjectedSignatureConstraints + metrics.IssuerBridgeConstraints
		}
		semanticConstraints := 0
		if l.MViewStart >= 0 && l.MAttrViewStart >= 0 && l.KViewStart >= 0 {
			semanticConstraints = l.ViewRowsPerPoly
		}
		if metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUYHatV1 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5 {
			metrics.FparIntConstraints = l.ViewRowsPerPoly + semanticConstraints
		} else {
			metrics.FparIntConstraints = 2*l.ViewRowsPerPoly + semanticConstraints
		}
	}
	if proof.RowLayout.IntGenISISPreSign != nil || proof.RowLayout.IntGenISISShowing != nil {
		if meta, err := PIOP.IntGenISISDegreeMetadataForProof(proof, pub, opts); err == nil {
			metrics.ParallelAlgDegree = meta.ParallelAlgDegree
			metrics.AggregatedAlgDegree = meta.AggregatedAlgDegree
			metrics.DominantDegreeSource = meta.DominantDegreeSource
			metrics.ParallelDegree = meta.ParallelAlgDegree
			metrics.AggregatedDegree = meta.AggregatedAlgDegree
			metrics.MSECompressionLevel = meta.CompressionLevel
			metrics.MSECompressionPackWidth = meta.CompressionPackWidth
			metrics.MSECompressionDegree = meta.CompressionDegree
		}
		metrics.MaskDegreeBound = proof.MaskDegreeBound
		metrics.PaperConservativeDQ = proof.QDegreeBound
	}
	if proof.PRFCompanion != nil && proof.PRFCompanion.Layout != nil {
		metrics.PRFRows = proof.PRFCompanion.Layout.PackedRows
		metrics.PRFKeyBridgeConstraints = proof.PRFCompanion.Layout.KeyCount
	}
	if metrics.ProofReportBuckets == 0 {
		metrics.ProofReportBuckets = report.TranscriptFocus.RowOpeningEntries
	}
	return metrics
}

func transcriptSizeModeLabel(fixed bool) string {
	if fixed {
		return "fixed"
	}
	return "compact"
}

func intGenISISProofSizeBucketCount(proof *PIOP.Proof) int {
	size := PIOP.MeasureProofSize(proof)
	count := 0
	for _, v := range size.Parts {
		if v > 0 {
			count++
		}
	}
	return count
}

func intGenISISBenchmarkElemFromSigned(v int64, q uint64) prf.Elem {
	mod := v % int64(q)
	if mod < 0 {
		mod += int64(q)
	}
	return prf.Elem(uint64(mod))
}

func intGenISISBenchmarkNonce(lenNonce, ncols int, q uint64) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lenNonce)
	public := make([][]int64, lenNonce)
	for i := 0; i < lenNonce; i++ {
		v := uint64(i+1) % q
		nonce[i] = prf.Elem(v)
		public[i] = intGenISISBenchmarkConstLane(ncols, int64(v))
	}
	return nonce, public
}

func intGenISISBenchmarkConstLane(ncols int, v int64) []int64 {
	out := make([]int64, ncols)
	for i := range out {
		out[i] = v
	}
	return out
}

func intGenISISBenchmarkLanesFromElems(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = intGenISISBenchmarkConstLane(ncols, int64(v))
	}
	return out
}
