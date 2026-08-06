package main

import (
	"fmt"
	"math"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"
)

const intGenISISTranscriptModeSmallField2025 = credential.IntGenISISTranscriptProtocolV2
const intGenISISTranscriptModeSmallField2025V3 = credential.IntGenISISTranscriptProtocolV3

type benchmarkIntGenISISMetrics struct {
	// ProofSizeBytes is retained for historical v2 result compatibility. For
	// strict v3 target reports it is the actual canonical proof wire length.
	ProofSizeBytes                 int                               `json:"proof_size_bytes"`
	ModeledVerifierMessageBytes    int                               `json:"modeled_verifier_message_bytes"`
	CanonicalProofWireBytes        int                               `json:"canonical_proof_wire_bytes,omitempty"`
	CanonicalPresentationWireBytes int                               `json:"canonical_presentation_wire_bytes,omitempty"`
	CanonicalWireAudit             *PIOP.CanonicalProofWireAuditV6   `json:"canonical_wire_audit,omitempty"`
	ProofSchemaVersion             int                               `json:"proof_schema_version,omitempty"`
	CanonicalProofKind             string                            `json:"canonical_proof_kind,omitempty"`
	CanonicalProofCodecVersion     int                               `json:"canonical_proof_codec_version,omitempty"`
	CanonicalProofCodecProfile     string                            `json:"canonical_proof_codec_profile,omitempty"`
	CanonicalProofFieldEncoding    string                            `json:"canonical_proof_field_encoding,omitempty"`
	CanonicalProofQKernelEncoding  string                            `json:"canonical_proof_q_kernel_encoding,omitempty"`
	CanonicalProofRadixQGroupSize  int                               `json:"canonical_proof_radix_q_group_elements,omitempty"`
	CanonicalProofMerkleTopology   string                            `json:"canonical_proof_merkle_topology,omitempty"`
	PreparedContextDigest          string                            `json:"prepared_context_digest,omitempty"`
	CanonicalTamperRejected        bool                              `json:"canonical_tamper_rejected"`
	PaperTranscriptBytes           int                               `json:"paper_transcript_bytes"`
	PaperTranscriptKB              float64                           `json:"paper_transcript_kb"`
	QBytes                         int                               `json:"q_bytes"`
	RBytes                         int                               `json:"r_bytes"`
	PdecsBytes                     int                               `json:"pdecs_bytes"`
	MdecsBytes                     int                               `json:"mdecs_bytes,omitempty"`
	AuthBytes                      int                               `json:"auth_bytes"`
	TapesBytes                     int                               `json:"tapes_bytes,omitempty"`
	TapeBytes                      int                               `json:"tape_bytes"`
	TapeCount                      int                               `json:"tape_count"`
	TapeWidthBytes                 int                               `json:"tape_width_bytes"`
	TapeDisclosureMode             string                            `json:"tape_disclosure_mode"`
	LeafEncodingVersion            int                               `json:"leaf_encoding_version"`
	RootWidthBytes                 int                               `json:"root_width_bytes"`
	ZeroKnowledgeEligible          bool                              `json:"zero_knowledge_eligible"`
	SigShortnessBytes              int                               `json:"sig_shortness_bytes"`
	VTargetsBytes                  int                               `json:"vtargets_bytes"`
	BarSetsBytes                   int                               `json:"barsets_bytes"`
	TranscriptAudit                PIOP.PaperTranscriptAudit         `json:"transcript_audit,omitempty"`
	ValidPrefixCost                credential.ValidPrefixCostReport  `json:"valid_prefix_cost,omitempty"`
	ProvingMS                      float64                           `json:"proving_ms"`
	VerificationMS                 float64                           `json:"verification_ms"`
	PhaseTimings                   []PIOP.PhaseTiming                `json:"phase_timings,omitempty"`
	FSCounters                     [4]uint64                         `json:"fs_counters"`
	TotalRows                      int                               `json:"total_rows"`
	RowsBlock                      int                               `json:"rows_block,omitempty"`
	AuditRows                      int                               `json:"audit_rows,omitempty"`
	OpeningCols                    int                               `json:"opening_cols,omitempty"`
	PRFRows                        int                               `json:"prf_rows"`
	CoefficientViewRows            int                               `json:"coefficient_view_rows"`
	UCoefficientViewRows           int                               `json:"u_coefficient_view_rows,omitempty"`
	UDigitOnly                     bool                              `json:"u_digit_only,omitempty"`
	SemanticViewRows               int                               `json:"semantic_view_rows,omitempty"`
	CommitmentViewRows             int                               `json:"commitment_view_rows,omitempty"`
	YCoefficientViewRows           int                               `json:"y_coefficient_view_rows,omitempty"`
	IssuerViewRows                 int                               `json:"issuer_view_rows,omitempty"`
	BoundRows                      int                               `json:"bound_rows"`
	ShortnessRows                  int                               `json:"shortness_rows"`
	ShortnessConstraints           int                               `json:"shortness_constraints,omitempty"`
	HatRows                        int                               `json:"hat_rows"`
	YHatRows                       int                               `json:"y_hat_rows,omitempty"`
	SourceBridgeConstraints        int                               `json:"source_bridge_constraints,omitempty"`
	UBridgeConstraints             int                               `json:"u_bridge_constraints,omitempty"`
	CommitmentBridgeConstraints    int                               `json:"commitment_bridge_constraints,omitempty"`
	YLinearConstraints             int                               `json:"y_linear_constraints,omitempty"`
	ProjectedSignatureConstraints  int                               `json:"projected_signature_constraints,omitempty"`
	ReplayProjection               string                            `json:"replay_projection,omitempty"`
	LayoutVersion                  string                            `json:"layout_version,omitempty"`
	RelationVersion                string                            `json:"relation_version,omitempty"`
	PRFCompanionRelationVersion    int                               `json:"prf_companion_relation_version,omitempty"`
	PRFInputTraceRelationVersion   int                               `json:"prf_input_trace_relation_version,omitempty"`
	IssuerBridgeConstraints        int                               `json:"issuer_bridge_constraints,omitempty"`
	PRFKeyBridgeConstraints        int                               `json:"prf_key_bridge_constraints,omitempty"`
	FparIntConstraints             int                               `json:"fpar_int_constraints,omitempty"`
	RangeConstraints               int                               `json:"range_constraints,omitempty"`
	ParallelDegree                 int                               `json:"parallel_degree"`
	AggregatedDegree               int                               `json:"aggregated_degree"`
	ParallelAlgDegree              int                               `json:"parallel_alg_degree,omitempty"`
	AggregatedAlgDegree            int                               `json:"aggregated_alg_degree,omitempty"`
	PaperConservativeDQ            int                               `json:"paper_conservative_dq,omitempty"`
	MaskDegreeBound                int                               `json:"mask_degree_bound,omitempty"`
	DominantDegreeSource           string                            `json:"dominant_degree_source,omitempty"`
	TernaryRows                    int                               `json:"ternary_rows,omitempty"`
	CompressedRows                 int                               `json:"compressed_rows,omitempty"`
	MSECompressionLevel            int                               `json:"mse_compression_level,omitempty"`
	MSECompressionPackWidth        int                               `json:"mse_compression_pack_width,omitempty"`
	MSECompressionDegree           int                               `json:"mse_compression_degree,omitempty"`
	RoundBits                      [4]float64                        `json:"round_bits"`
	RawRoundBits                   [4]float64                        `json:"raw_round_bits"`
	TheoremBits                    [4]float64                        `json:"theorem_bits"`
	TheoremTotalBits               float64                           `json:"theorem_total_bits"`
	ROQueryCaps                    [5]int                            `json:"ro_query_caps"`
	ROQueryCapsSet                 bool                              `json:"-"`
	ROQueryCapBits                 [5]float64                        `json:"ro_query_cap_bits,omitempty"`
	ROQueryCapBitsSet              bool                              `json:"-"`
	CollisionSpaceBits             int                               `json:"collision_space_bits"`
	FSLambdaBits                   int                               `json:"fs_lambda_bits"`
	FSOutputBits                   int                               `json:"fs_output_bits"`
	ObservedFSDigestBits           [4]int                            `json:"observed_fs_digest_bits"`
	AggregateQueryBudget           bool                              `json:"aggregate_query_budget,omitempty"`
	AggregateQueryCapLog2          float64                           `json:"aggregate_query_cap_log2,omitempty"`
	WorkFactorMode                 bool                              `json:"work_factor_mode,omitempty"`
	WorkFactorBits                 float64                           `json:"work_factor_bits,omitempty"`
	WorkFactorComponents           [6]float64                        `json:"work_factor_components,omitempty"`
	NativeAlgebraicTerms           [4]float64                        `json:"native_algebraic_terms,omitempty"`
	NativeAlgebraicBits            [4]float64                        `json:"native_algebraic_bits,omitempty"`
	EffectiveLambdaBits            int                               `json:"effective_lambda_bits"`
	DECSHashBits                   int                               `json:"decs_hash_bits"`
	DECSTapeBits                   int                               `json:"decs_tape_bits"`
	SaltBits                       int                               `json:"salt_bits"`
	TranscriptMode                 string                            `json:"transcript_mode,omitempty"`
	AlgebraicTerms                 [4]float64                        `json:"algebraic_terms"`
	AlgebraicBits                  [4]float64                        `json:"algebraic_bits"`
	AlgebraicTotal                 float64                           `json:"algebraic_total"`
	AlgebraicTotalBits             float64                           `json:"algebraic_total_bits"`
	Collision                      float64                           `json:"collision"`
	CollisionBits                  float64                           `json:"collision_bits"`
	OneProofTotal                  float64                           `json:"one_proof_total"`
	OneProofTotalBits              float64                           `json:"one_proof_total_bits"`
	Clamped                        [4]bool                           `json:"clamped"`
	SoundnessEq8Bits               float64                           `json:"soundness_eq8_bits"`
	DQ                             int                               `json:"dq"`
	DDECS                          int                               `json:"ddecs"`
	WitnessSupportCols             int                               `json:"witness_support_cols"`
	CommittedCols                  int                               `json:"committed_cols"`
	ProofReportBuckets             int                               `json:"proof_report_buckets"`
	LVCSNCols                      int                               `json:"lvcs_ncols,omitempty"`
	NLeaves                        int                               `json:"nleaves,omitempty"`
	Eta                            int                               `json:"eta,omitempty"`
	Ell                            int                               `json:"ell,omitempty"`
	Theta                          int                               `json:"theta"`
	Rho                            int                               `json:"rho"`
	EllPrime                       int                               `json:"ell_prime"`
	SmallFieldReplayRows           int                               `json:"smallfield_replay_rows,omitempty"`
	MaskRows                       int                               `json:"mask_rows,omitempty"`
	QSplitRows                     int                               `json:"q_split_rows,omitempty"`
	QLimbRows                      int                               `json:"q_limb_rows,omitempty"`
	PDecsBitWidth                  int                               `json:"pdecs_bit_width,omitempty"`
	VTargetsBitWidth               int                               `json:"vtargets_bit_width,omitempty"`
	PaperShapeNRows                int                               `json:"paper_shape_nrows,omitempty"`
	PaperShapeQueries              int                               `json:"paper_shape_queries,omitempty"`
	PaperShapeWitnessLayers        int                               `json:"paper_shape_witness_layers,omitempty"`
	PaperShapeMaskRows             int                               `json:"paper_shape_mask_rows,omitempty"`
	PaperShapeVHeadBytes           int                               `json:"paper_shape_vhead_bytes,omitempty"`
	PaperShapeVBarBytes            int                               `json:"paper_shape_vbar_bytes,omitempty"`
	PaperShapeOpeningOmitEntries   int                               `json:"paper_shape_opening_omit_entries,omitempty"`
	PaperShapeCanonical            bool                              `json:"paper_shape_canonical,omitempty"`
	FixedTranscriptSize            bool                              `json:"fixed_transcript_size"`
	TranscriptSizeMode             string                            `json:"transcript_size_mode"`
	TranscriptSecurityStatus       string                            `json:"transcript_security_status,omitempty"`
	MeasurementStatus              string                            `json:"measurement_status"`
	RelationCandidate              benchmarkIntGenISISRelationReport `json:"relation_candidate,omitempty"`
	Soundness                      PIOP.SoundnessBudget              `json:"-"`
}

type benchmarkIntGenISISRelationReport struct {
	LogicalRows          int            `json:"logical_rows,omitempty"`
	ParallelDegree       int            `json:"parallel_degree,omitempty"`
	AggregatedDegree     int            `json:"aggregated_degree,omitempty"`
	DQParallel           int            `json:"dq_parallel,omitempty"`
	DQAggregate          int            `json:"dq_aggregate,omitempty"`
	DQ                   int            `json:"dq,omitempty"`
	MaskDegreeBound      int            `json:"mask_degree_bound,omitempty"`
	RowCounts            map[string]int `json:"row_counts,omitempty"`
	ConstraintCounts     map[string]int `json:"constraint_counts,omitempty"`
	DominantDegreeSource string         `json:"dominant_degree_source,omitempty"`
	DominantDQBranch     string         `json:"dominant_dq_branch,omitempty"`
}

func intGenISISMetricsFromProof(proof *PIOP.Proof, report PIOP.ProofReport, pub PIOP.PublicInputs, opts PIOP.SimOpts, proveDur, verifyDur time.Duration, status string) benchmarkIntGenISISMetrics {
	metrics := benchmarkIntGenISISMetrics{
		ProofSizeBytes:              report.ProofBytes,
		ModeledVerifierMessageBytes: report.ProofBytes,
		ProofSchemaVersion:          proof.SchemaVersion,
		PaperTranscriptBytes:        report.PaperTranscript.OptimizedBytes,
		PaperTranscriptKB:           float64(report.PaperTranscript.OptimizedBytes) / 1024.0,
		QBytes:                      report.PaperTranscript.Q.OptimizedBytes,
		RBytes:                      report.PaperTranscript.R.OptimizedBytes,
		PdecsBytes:                  report.PaperTranscript.Pdecs.OptimizedBytes,
		MdecsBytes:                  report.PaperTranscript.Mdecs.OptimizedBytes,
		AuthBytes:                   report.PaperTranscript.Auth.OptimizedBytes,
		TapesBytes:                  report.PaperTranscript.Tapes.OptimizedBytes,
		TapeBytes:                   report.TapeBytes,
		TapeCount:                   report.TapeCount,
		TapeWidthBytes:              report.TapeWidthBytes,
		TapeDisclosureMode:          report.TapeDisclosureMode,
		LeafEncodingVersion:         report.LeafEncodingVersion,
		RootWidthBytes:              report.RootWidthBytes,
		ZeroKnowledgeEligible:       report.ZeroKnowledgeEligible,
		SigShortnessBytes:           report.PaperTranscript.SigShortness.OptimizedBytes,
		VTargetsBytes:               report.PaperTranscript.VTargets.OptimizedBytes,
		BarSetsBytes:                report.PaperTranscript.BarSets.OptimizedBytes,
		TranscriptAudit:             report.PaperTranscript.Audit,
		ProvingMS:                   float64(proveDur.Microseconds()) / 1000.0,
		VerificationMS:              float64(verifyDur.Microseconds()) / 1000.0,
		PhaseTimings:                nonZeroPhaseTimings(opts.PhaseRecorder.Snapshot()),
		FSCounters:                  proof.Ctr,
		TotalRows:                   proof.RowLayout.SigCount,
		RowsBlock:                   report.TranscriptFocus.RowsBlock,
		AuditRows:                   report.TranscriptFocus.AuditRows,
		OpeningCols:                 report.TranscriptFocus.OpeningCols,
		ParallelDegree:              proof.QDegreeBound,
		AggregatedDegree:            proof.QDegreeBound,
		RoundBits:                   report.Soundness.Bits,
		RawRoundBits:                report.Soundness.RawBits,
		TheoremBits:                 report.Soundness.TheoremBits,
		TheoremTotalBits:            report.Soundness.TotalBits,
		ROQueryCaps:                 report.Soundness.QueryCaps,
		ROQueryCapsSet:              opts.ROQueryCapsSet,
		ROQueryCapBits:              report.Soundness.QueryCapBits,
		ROQueryCapBitsSet:           opts.ROQueryCapBitsSet,
		CollisionSpaceBits:          report.Soundness.CollisionSpaceBits,
		FSLambdaBits:                report.Soundness.FSLambdaBits,
		FSOutputBits:                report.Soundness.FSOutputBits,
		ObservedFSDigestBits:        report.Soundness.ObservedFSDigestBits,
		AggregateQueryBudget:        report.Soundness.AggregateQueryBudget,
		AggregateQueryCapLog2:       report.Soundness.AggregateQueryCapBits,
		EffectiveLambdaBits:         report.Soundness.EffectiveLambdaBits,
		DECSHashBits:                report.Soundness.DECSHashBits,
		DECSTapeBits:                report.Soundness.DECSTapeBits,
		SaltBits:                    len(proof.Salt) * 8,
		TranscriptMode:              benchmarkTranscriptModeFromProof(proof),
		AlgebraicTerms:              report.Soundness.AlgebraicTerms,
		AlgebraicBits:               report.Soundness.AlgebraicBits,
		AlgebraicTotal:              report.Soundness.AlgebraicTotal,
		AlgebraicTotalBits:          report.Soundness.AlgebraicTotalBits,
		Collision:                   report.Soundness.Collision,
		CollisionBits:               report.Soundness.CollisionBits,
		OneProofTotal:               report.Soundness.OneProofTotal,
		OneProofTotalBits:           report.Soundness.OneProofTotalBits,
		Clamped:                     report.Soundness.Clamped,
		SoundnessEq8Bits:            report.Soundness.Eq8TotalBits,
		DQ:                          report.DQ,
		DDECS:                       report.Soundness.DDECS,
		WitnessSupportCols:          report.Soundness.WitnessSupportCols,
		CommittedCols:               report.Soundness.CommittedCols,
		ProofReportBuckets:          intGenISISProofSizeBucketCount(proof),
		LVCSNCols:                   report.LVCSNCols,
		NLeaves:                     report.NLeaves,
		Eta:                         report.Eta,
		Ell:                         report.Ell,
		PDecsBitWidth:               report.TranscriptFocus.PDecsBitWidth,
		VTargetsBitWidth:            report.TranscriptFocus.VTargetsBitWidth,
		FixedTranscriptSize:         opts.FixedTranscriptSize || proof.FixedTranscriptSize,
		TranscriptSizeMode:          transcriptSizeModeLabel(opts.FixedTranscriptSize || proof.FixedTranscriptSize),
		TranscriptSecurityStatus:    report.TranscriptFocus.TranscriptSecurityStatus,
		MeasurementStatus:           status,
		Soundness:                   report.Soundness,
	}
	metrics.Theta = proof.Theta
	benchmarkProjectPublicationV4QueryCaps(&metrics, proof)
	benchmarkProjectWorkFactorMetrics(&metrics, report.Soundness)
	if metrics.Theta <= 0 {
		metrics.Theta = 1
	}
	if metrics.LVCSNCols <= 0 {
		metrics.LVCSNCols = opts.LVCSNCols
	}
	if metrics.NLeaves <= 0 {
		metrics.NLeaves = opts.NLeaves
	}
	if metrics.Eta <= 0 {
		metrics.Eta = opts.Eta
	}
	if metrics.Ell <= 0 {
		metrics.Ell = opts.Ell
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
		metrics.CompressedRows = l.MCarrierCount + l.SCarrierCount + l.ECarrierCount
		metrics.MSECompressionLevel = l.MSECompressionLevel
		metrics.MSECompressionPackWidth = l.MSECompressionPackWidth
		metrics.MSECompressionDegree = l.MSECompressionDecodeDegree
		metrics.LayoutVersion = l.LayoutVersion
		metrics.RelationVersion = l.RelationVersion
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
		metrics.UDigitOnly = l.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || l.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
		metrics.ShortnessConstraints = l.UShortnessGroupCount * l.UShortnessRowsPerGroup
		if !metrics.UDigitOnly {
			metrics.ShortnessConstraints += l.UShortnessGroupCount
		}
		metrics.YHatRows = l.YHatCount
		metrics.HatRows = l.UHatCount + l.MHatCount + l.SHatCount + l.EHatCount + l.YHatCount + l.MuSigHatCount + l.X0HatCount + l.WHatCount + l.X1HatCount + l.ZHatCount
		metrics.ReplayProjection = l.ReplayProjection
		metrics.LayoutVersion = l.LayoutVersion
		if l.PRFInputTraceV3Rows > 0 {
			// This is reconstructed from the committed row layout, not copied
			// from preset metadata. It distinguishes the strict input-trace
			// relation from the retired output-trace/companion relation.
			metrics.PRFInputTraceRelationVersion = int(prf.InputTraceRelationVersionV3)
		}
		if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_digits_y_view_v3" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3
		} else if metrics.ReplayProjection == "" && l.LayoutVersion == "intgenisis_showing_project_u_digits_y_bounded_sources_v6" {
			metrics.ReplayProjection = PIOP.IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
		}
		metrics.UDigitOnly = metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
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
			if metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6 {
				metrics.ProjectedSignatureConstraints = l.ViewRowsPerPoly * ncols
			}
			metrics.SourceBridgeConstraints = metrics.UBridgeConstraints + metrics.CommitmentBridgeConstraints + metrics.YLinearConstraints + metrics.ProjectedSignatureConstraints + metrics.IssuerBridgeConstraints
		}
		semanticConstraints := 0
		if l.MViewStart >= 0 && l.MAttrViewStart >= 0 && l.KViewStart >= 0 {
			semanticConstraints = l.ViewRowsPerPoly
		}
		if metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || metrics.ReplayProjection == PIOP.IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6 {
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
		metrics.PRFCompanionRelationVersion = int(proof.PRFCompanion.Layout.RelationVersion)
	}
	if smallField := proof.SmallField2025; smallField != nil {
		metrics.PaperShapeNRows = smallField.NRows
		metrics.PaperShapeQueries = smallField.QueryCount
		metrics.PaperShapeWitnessLayers = smallField.WitnessLayers
		metrics.PaperShapeMaskRows = smallField.MaskRows
		metrics.PaperShapeVHeadBytes = report.PaperTranscript.VTargets.OptimizedBytes
		metrics.PaperShapeVBarBytes = report.PaperTranscript.BarSets.OptimizedBytes
		metrics.PaperShapeOpeningOmitEntries = len(smallField.POmitCols) + len(smallField.MOmitCols)
		v2Canonical := smallField.Version == 2 &&
			smallField.Mode == credential.IntGenISISTranscriptProtocolV2 &&
			smallField.Status == credential.IntGenISISSecurityGateV2 &&
			smallField.ReductionEnabled &&
			proof.PCSGeometry.Kind == PIOP.PCSGeometryKindSmallFieldMatrixV2 &&
			smallField.TranscriptOmission != nil &&
			smallField.TranscriptOmission.Version == 2 &&
			smallField.TranscriptOmission.Mode == PIOP.SmallField2025TranscriptOmissionModeDigestBoundV2
		v3Canonical := benchmarkStrictTranscriptStatusMatchesProof(proof, report.TranscriptFocus.TranscriptSecurityStatus) &&
			smallField.Version == 2 &&
			smallField.Mode == proof.TranscriptProtocolMode &&
			smallField.ReductionEnabled &&
			proof.PCSGeometry.Kind == PIOP.PCSGeometryKindSmallFieldMatrixV2 &&
			smallField.TranscriptOmission != nil &&
			smallField.TranscriptOmission.Version == 3 &&
			smallField.TranscriptOmission.Mode == PIOP.SmallField2025TranscriptOmissionModeCanonicalV3
		if v3Canonical {
			// SmallField2025.MaskRows is the VBar width (ell). The strict-v3
			// paper shape reports the physical Eq. (2) mask rows instead.
			metrics.PaperShapeMaskRows = report.Geometry.MaskRowsCommitted
		}
		metrics.PaperShapeCanonical = v2Canonical || v3Canonical
	}
	if metrics.ProofReportBuckets == 0 {
		metrics.ProofReportBuckets = report.TranscriptFocus.RowOpeningEntries
	}
	if metrics.ParallelAlgDegree > 0 || metrics.AggregatedAlgDegree > 0 {
		metrics.RelationCandidate = benchmarkIntGenISISRelationReportFromMetrics(proof, metrics, opts)
	}
	return metrics
}

// benchmarkProjectPublicationV4QueryCaps converts publication-v4's internal
// -Inf non-applicable query-cap markers into the finite JSON sentinel. The
// integer slots remain zero; bounded-query lanes expose their one aggregate Q
// separately, and WF128 exposes no query-budget scalar.
func benchmarkProjectPublicationV4QueryCaps(metrics *benchmarkIntGenISISMetrics, proof *PIOP.Proof) {
	if metrics == nil || proof == nil ||
		proof.TranscriptVersion != PIOP.TranscriptVersionSmallWood2025V4 ||
		proof.TranscriptProtocolMode != PIOP.TranscriptProtocolSmallField2025V4 {
		return
	}
	for i := range metrics.ROQueryCapBits {
		metrics.ROQueryCapBits[i] = benchmarkFiniteBits(metrics.ROQueryCapBits[i])
	}
}

// benchmarkProjectWorkFactorMetrics maps the WF128 lane's native attack-work
// exponents into the existing finite phase-report schema. Internally, an
// absent query cap correctly produces +/-Inf in the query-adjusted probability
// fields. JSON has no representation for infinities, and those values are not
// the WF128 claim: its exact gate is the minimum native algebraic, collision,
// and tape work factor. Keep the internal SoundnessBudget untouched while
// emitting the native curve coefficients under separately named fields and
// the established -1 non-applicable sentinel for query-adjusted bit fields.
func benchmarkProjectWorkFactorMetrics(metrics *benchmarkIntGenISISMetrics, sb PIOP.SoundnessBudget) {
	if metrics == nil || !sb.WorkFactorMode {
		return
	}
	metrics.WorkFactorMode = true
	metrics.WorkFactorBits = sb.WorkFactorBits
	metrics.WorkFactorComponents = sb.WorkFactorComponents
	metrics.NativeAlgebraicTerms = sb.NativeAlgebraicTerms
	metrics.NativeAlgebraicBits = sb.NativeAlgebraicBits
	for i, bits := range sb.NativeAlgebraicBits {
		if math.IsNaN(bits) || math.IsInf(bits, 0) {
			metrics.NativeAlgebraicBits[i] = -1
			metrics.NativeAlgebraicTerms[i] = 0
		}
		metrics.RawRoundBits[i] = benchmarkFiniteBits(metrics.RawRoundBits[i])
		metrics.RoundBits[i] = benchmarkFiniteBits(metrics.RoundBits[i])
		metrics.TheoremBits[i] = -1
		metrics.AlgebraicBits[i] = -1
		metrics.AlgebraicTerms[i] = 0
	}
	metrics.TheoremTotalBits = -1
	metrics.AlgebraicTotal = 0
	metrics.AlgebraicTotalBits = -1
	metrics.Collision = 0
	metrics.CollisionBits = -1
	metrics.OneProofTotal = 0
	metrics.OneProofTotalBits = -1
	for i := range metrics.ROQueryCapBits {
		metrics.ROQueryCapBits[i] = -1
	}
}

func benchmarkFiniteBits(bits float64) float64 {
	if math.IsNaN(bits) || math.IsInf(bits, 0) {
		return -1
	}
	return bits
}

func benchmarkStrictTranscriptStatusMatchesProof(proof *PIOP.Proof, status string) bool {
	if proof == nil {
		return false
	}
	return (proof.TranscriptVersion == PIOP.TranscriptVersionSmallWood2025V3 &&
		proof.TranscriptProtocolMode == PIOP.TranscriptProtocolSmallField2025V3 &&
		status == credential.IntGenISISSecurityGateV3) ||
		(proof.TranscriptVersion == PIOP.TranscriptVersionSmallWood2025V4 &&
			proof.TranscriptProtocolMode == PIOP.TranscriptProtocolSmallField2025V4 &&
			status == credential.IntGenISISSecurityGateV4)
}

// attachCanonicalProofIdentity records the independently versioned in-memory
// proof and physical codec epochs. The audit is produced by serializing the
// actual proof with the production codec, so these fields cannot silently
// inherit preset labels that disagree with the emitted bytes.
func attachCanonicalProofIdentity(metrics *benchmarkIntGenISISMetrics, kind string, audit PIOP.CanonicalProofWireAuditV6) error {
	if metrics == nil {
		return fmt.Errorf("nil benchmark metrics")
	}
	if kind != "presign" && kind != "showing" {
		return fmt.Errorf("unsupported canonical proof kind %q", kind)
	}
	if metrics.ProofSchemaVersion != PIOP.ProofSchemaVersionV3 || metrics.ProofSchemaVersion != audit.ProofSchemaVersion ||
		audit.CodecVersion != PIOP.CanonicalProofCodecVersionV6 ||
		audit.CodecProfile != PIOP.CanonicalProofCodecProfileV6 ||
		audit.FieldEncoding != PIOP.CanonicalProofFieldEncodingV6 ||
		audit.QKernelEncoding != PIOP.CanonicalProofQKernelEncodingV6 ||
		audit.RadixQGroupElements != PIOP.CanonicalProofRadixQGroupElementsV6 {
		return fmt.Errorf("canonical proof identity disagrees with production v6 codec audit")
	}
	if metrics.CanonicalProofWireBytes > 0 && audit.TotalBytes != metrics.CanonicalProofWireBytes {
		return fmt.Errorf("canonical proof audit bytes=%d want=%d", audit.TotalBytes, metrics.CanonicalProofWireBytes)
	}
	metrics.CanonicalProofKind = kind
	metrics.CanonicalProofCodecVersion = audit.CodecVersion
	metrics.CanonicalProofCodecProfile = audit.CodecProfile
	metrics.CanonicalProofFieldEncoding = audit.FieldEncoding
	metrics.CanonicalProofQKernelEncoding = audit.QKernelEncoding
	metrics.CanonicalProofRadixQGroupSize = audit.RadixQGroupElements
	metrics.CanonicalProofMerkleTopology = audit.MerkleTopology
	metrics.CanonicalWireAudit = &audit
	return nil
}

func benchmarkTranscriptModeFromProof(proof *PIOP.Proof) string {
	if proof == nil {
		return ""
	}
	if proof.TranscriptVersion == PIOP.TranscriptVersionSmallWood2025V2 && proof.TranscriptProtocolMode == PIOP.TranscriptProtocolSmallField2025V2 {
		return intGenISISTranscriptModeSmallField2025
	}
	if proof.TranscriptVersion == PIOP.TranscriptVersionSmallWood2025V3 && proof.TranscriptProtocolMode == PIOP.TranscriptProtocolSmallField2025V3 {
		return intGenISISTranscriptModeSmallField2025V3
	}
	if proof.TranscriptVersion == PIOP.TranscriptVersionSmallWood2025V4 && proof.TranscriptProtocolMode == PIOP.TranscriptProtocolSmallField2025V4 {
		return credential.IntGenISISTranscriptProtocolV4
	}
	return ""
}

func benchmarkIntGenISISRelationReportFromMetrics(proof *PIOP.Proof, metrics benchmarkIntGenISISMetrics, opts PIOP.SimOpts) benchmarkIntGenISISRelationReport {
	dqParallel, dqAggregate, dq := PIOP.ComputeDQBranchBounds(metrics.ParallelAlgDegree, metrics.AggregatedAlgDegree, opts.NCols, opts.Ell)
	dominantDQ := "parallel"
	if dqAggregate > dqParallel {
		dominantDQ = "aggregate"
	}
	if opts.DQOverride > dq {
		dq = opts.DQOverride
		dominantDQ = "override"
	}
	if metrics.MaskDegreeBound > dq {
		dq = metrics.MaskDegreeBound
		dominantDQ = "measured_mask"
	}
	rowCounts := map[string]int{
		"total":            metrics.TotalRows,
		"coefficient_view": metrics.CoefficientViewRows,
		"prf":              metrics.PRFRows,
		"bound":            metrics.BoundRows,
		"shortness":        metrics.ShortnessRows,
		"mask":             reportPositiveInt(metrics.MaskRows, proof.MaskRowCount),
	}
	constraintCounts := map[string]int{
		"range":               metrics.RangeConstraints,
		"shortness":           metrics.ShortnessConstraints,
		"source_bridge":       metrics.SourceBridgeConstraints,
		"u_bridge":            metrics.UBridgeConstraints,
		"commitment_bridge":   metrics.CommitmentBridgeConstraints,
		"projected_signature": metrics.ProjectedSignatureConstraints,
		"issuer_bridge":       metrics.IssuerBridgeConstraints,
		"prf_key_bridge":      metrics.PRFKeyBridgeConstraints,
		"fpar_int":            metrics.FparIntConstraints,
	}
	return benchmarkIntGenISISRelationReport{
		LogicalRows:          metrics.TotalRows,
		ParallelDegree:       metrics.ParallelAlgDegree,
		AggregatedDegree:     metrics.AggregatedAlgDegree,
		DQParallel:           dqParallel,
		DQAggregate:          dqAggregate,
		DQ:                   dq,
		MaskDegreeBound:      metrics.MaskDegreeBound,
		RowCounts:            pruneZeroIntMap(rowCounts),
		ConstraintCounts:     pruneZeroIntMap(constraintCounts),
		DominantDegreeSource: metrics.DominantDegreeSource,
		DominantDQBranch:     dominantDQ,
	}
}

func pruneZeroIntMap(in map[string]int) map[string]int {
	for k, v := range in {
		if v == 0 {
			delete(in, k)
		}
	}
	if len(in) == 0 {
		return nil
	}
	return in
}

func reportPositiveInt(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

func nonZeroPhaseTimings(in []PIOP.PhaseTiming) []PIOP.PhaseTiming {
	out := in[:0]
	for _, ph := range in {
		if ph.Label != "" && ph.Milliseconds > 0 {
			out = append(out, ph)
		}
	}
	return out
}

func transcriptSizeModeLabel(fixed bool) string {
	if fixed {
		return "fixed"
	}
	return "compact"
}

func intGenISISProofSizeBucketCount(proof *PIOP.Proof) int {
	size := PIOP.EstimateVerifierMessageSize(proof)
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

func intGenISISBenchmarkScalarsFromElems(vals []prf.Elem) []int64 {
	out := make([]int64, len(vals))
	for i, v := range vals {
		out[i] = int64(v)
	}
	return out
}
