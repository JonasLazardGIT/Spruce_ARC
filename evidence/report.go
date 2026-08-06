package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

// benchmarkReportWire mirrors the v2 benchmark's persisted schema so
// DisallowUnknownFields applies recursively rather than accepting a report
// object from another epoch.
type benchmarkReportWire struct {
	Version                    int                                         `json:"version"`
	Generated                  string                                      `json:"generated_at"`
	Preset                     string                                      `json:"preset,omitempty"`
	CanonicalPresetID          string                                      `json:"canonical_preset_id,omitempty"`
	PresetVersion              int                                         `json:"preset_version,omitempty"`
	PresetLifecycle            credential.PresetLifecycle                  `json:"preset_lifecycle,omitempty"`
	ClaimScope                 credential.ClaimScope                       `json:"claim_scope,omitempty"`
	PrimitiveProfileID         string                                      `json:"primitive_profile_id,omitempty"`
	PresetManifestDigest       string                                      `json:"preset_manifest_digest,omitempty"`
	ThreatModel                credential.PresetThreatModel                `json:"threat_model"`
	Profile                    string                                      `json:"profile"`
	SecurityProfile            string                                      `json:"security_profile,omitempty"`
	SecurityMode               string                                      `json:"security_mode,omitempty"`
	CompleteSystemClaim        bool                                        `json:"complete_system_claim,omitempty"`
	CoreBitsRequired           float64                                     `json:"core_required_bits,omitempty"`
	CoreAvailableBits          float64                                     `json:"core_available_bits,omitempty"`
	PRFProfile                 string                                      `json:"prf_profile,omitempty"`
	PRFParamsPath              string                                      `json:"prf_params_path,omitempty"`
	PRFParamsDigest            string                                      `json:"prf_params_digest,omitempty"`
	LedgerStatus               string                                      `json:"ledger_status,omitempty"`
	LedgerReasons              []string                                    `json:"ledger_rejection_reasons,omitempty"`
	LedgerTerms                []credential.SystemSecurityLedgerTerm       `json:"ledger_terms,omitempty"`
	SoundnessBits              float64                                     `json:"soundness_bits,omitempty"`
	UnlinkabilityBits          float64                                     `json:"unlinkability_bits,omitempty"`
	CorrectnessBits            float64                                     `json:"correctness_bits,omitempty"`
	PrimitiveBits              float64                                     `json:"primitive_bits,omitempty"`
	CompositionBits            float64                                     `json:"composition_bits,omitempty"`
	ZeroKnowledgeBits          float64                                     `json:"zero_knowledge_bits,omitempty"`
	RequiredPhaseAlgebraicBits float64                                     `json:"required_phase_algebraic_bits,omitempty"`
	PhaseAlgebraicSlackBits    float64                                     `json:"phase_algebraic_slack_bits,omitempty"`
	DominantSoundnessLimiter   string                                      `json:"dominant_soundness_limiter,omitempty"`
	TagCollisionBits           float64                                     `json:"tag_collision_bits,omitempty"`
	SaltCollisionBits          float64                                     `json:"salt_collision_bits,omitempty"`
	TapeGuessingBits           float64                                     `json:"tape_guessing_bits,omitempty"`
	ProgrammingBits            float64                                     `json:"programming_conflict_bits,omitempty"`
	ChallengeBiasBits          float64                                     `json:"challenge_bias_bits,omitempty"`
	Modulus                    uint64                                      `json:"q,omitempty"`
	ProfileBound               int64                                       `json:"profile_bound,omitempty"`
	ArtifactDir                string                                      `json:"artifact_dir"`
	MaxNLeaves                 int                                         `json:"max_nleaves,omitempty"`
	Options                    benchmarkOptionsWire                        `json:"options"`
	Environment                benchmarkEnvironmentWire                    `json:"environment"`
	Timings                    benchmarkTimingsWire                        `json:"timings"`
	Resources                  benchmarkResourcesWire                      `json:"resources"`
	Issuance                   benchmarkPhaseWire                          `json:"issuance"`
	Showing                    benchmarkPhaseWire                          `json:"showing"`
	FullGame                   PIOP.FullGameSoundnessReport                `json:"full_game"`
	FullGameAccountingStatus   string                                      `json:"full_game_accounting_status,omitempty"`
	SecurityLedger             credential.SystemSecurityLedger             `json:"security_ledger"`
	ParameterAudit             credential.IntGenISISSecurityParameterAudit `json:"parameter_audit"`
	ValidPrefixCost            credential.ValidPrefixCostReport            `json:"valid_prefix_cost,omitempty"`
	Artifacts                  benchmarkArtifactsWire                      `json:"artifacts"`
	CanonicalSizes             *benchmarkCanonicalSizesWire                `json:"canonical_sizes,omitempty"`
	ReplayRejected             bool                                        `json:"replay_rejected"`
	TamperRejected             bool                                        `json:"tamper_rejected,omitempty"`
	ArtifactHashesVerified     bool                                        `json:"artifact_hashes_verified,omitempty"`
	ArtifactSHA256             map[string]string                           `json:"artifact_sha256,omitempty"`
	Notes                      []string                                    `json:"notes"`
}

type benchmarkEnvironmentWire struct {
	GoVersion           string `json:"go_version"`
	GOOS                string `json:"goos"`
	GOARCH              string `json:"goarch"`
	NumCPU              int    `json:"num_cpu"`
	GOMAXPROCS          int    `json:"gomaxprocs"`
	VCS                 string `json:"vcs,omitempty"`
	Commit              string `json:"commit,omitempty"`
	CommitTime          string `json:"commit_time,omitempty"`
	Modified            *bool  `json:"modified,omitempty"`
	SourceTreeAlgorithm string `json:"source_tree_algorithm,omitempty"`
	SourceTreeDigest    string `json:"source_tree_digest,omitempty"`
	SourceTreeFileCount int    `json:"source_tree_file_count,omitempty"`
	BuildSHA256         string `json:"build_sha256,omitempty"`
	CPUModel            string `json:"cpu_model,omitempty"`
	CPUFeatures         string `json:"cpu_features,omitempty"`
	MachineDigest       string `json:"machine_digest,omitempty"`
}

type benchmarkResourcesWire struct {
	AllocatedBytes uint64 `json:"allocated_bytes"`
	Allocations    uint64 `json:"allocations"`
	PeakRSSBytes   uint64 `json:"peak_rss_bytes,omitempty"`
}

type benchmarkCanonicalSizesWire struct {
	CredentialStateBytes   int `json:"persistent_credential_state_bytes"`
	IssuanceProofWireBytes int `json:"issuance_proof_wire_bytes"`
	ShowingProofWireBytes  int `json:"showing_proof_wire_bytes"`
	PresentationWireBytes  int `json:"presentation_wire_bytes"`
	IssuancePaperBytes     int `json:"issuance_paper_transcript_bytes"`
	ShowingPaperBytes      int `json:"showing_paper_transcript_bytes"`
}

type benchmarkArtifactsWire struct {
	PublicParams     string `json:"public_params"`
	BMatrix          string `json:"b_matrix"`
	HolderSecret     string `json:"holder_secret"`
	CommitRequest    string `json:"commit_request"`
	Submission       string `json:"presign_submission"`
	Response         string `json:"issue_response"`
	State            string `json:"state"`
	VerifierKey      string `json:"verifier_key"`
	Presentation     string `json:"presentation"`
	HolderUsageState string `json:"holder_usage_state"`
	VerifierState    string `json:"verifier_state"`
	NTRUParams       string `json:"ntru_params"`
	NTRUPublic       string `json:"ntru_public"`
	NTRUPrivate      string `json:"ntru_private"`
	NTRUSignature    string `json:"ntru_signature"`
}

type benchmarkTimingsWire struct {
	SetupPublicMS    float64 `json:"setup_public_ms,omitempty"`
	SetupNTRUKeysMS  float64 `json:"setup_ntru_keys_ms,omitempty"`
	HolderCommitMS   float64 `json:"holder_commit_ms,omitempty"`
	HolderProveMS    float64 `json:"holder_prove_ms,omitempty"`
	IssuerSignMS     float64 `json:"issuer_verify_sign_ms,omitempty"`
	HolderFinalizeMS float64 `json:"holder_finalize_ms,omitempty"`
}

type benchmarkOptionsWire struct {
	Issuance benchmarkTuningWire `json:"issuance"`
	Showing  benchmarkTuningWire `json:"showing"`
}

type benchmarkTuningWire struct {
	PresetID                string     `json:"preset_id,omitempty"`
	NCols                   int        `json:"ncols"`
	LVCSNCols               int        `json:"lvcs_ncols"`
	NLeaves                 int        `json:"nleaves"`
	Eta                     int        `json:"eta"`
	Theta                   int        `json:"theta"`
	Rho                     int        `json:"rho"`
	Ell                     int        `json:"ell"`
	EllPrime                int        `json:"ell_prime"`
	DQOverride              int        `json:"dq_override,omitempty"`
	Kappa                   [4]int     `json:"kappa"`
	ROQueryCaps             [5]int     `json:"ro_query_caps,omitempty"`
	ROQueryCapBits          [5]float64 `json:"ro_query_cap_bits,omitempty"`
	AggregateROQueryCapLog2 float64    `json:"aggregate_ro_query_cap_log2,omitempty"`
	DECSCollisionBits       int        `json:"decs_collision_bits,omitempty"`
	DECSHashBits            int        `json:"decs_hash_bits,omitempty"`
	DECSTapeBits            int        `json:"decs_tape_bits,omitempty"`
	FSCollisionBits         int        `json:"fs_collision_bits,omitempty"`
	FSOutputBits            int        `json:"fs_output_bits,omitempty"`
	SaltBits                int        `json:"salt_bits,omitempty"`
	PRFProfile              string     `json:"prf_profile,omitempty"`
	PRFParamsPath           string     `json:"prf_params_path,omitempty"`
	PRFCompanionMode        string     `json:"prf_companion_mode,omitempty"`
	PRFGroupRounds          int        `json:"prf_group_rounds,omitempty"`
	CheckpointSamples       int        `json:"prf_checkpoint_samples,omitempty"`
	SigShortnessRadix       int        `json:"sig_shortness_radix,omitempty"`
	SigShortnessDigits      int        `json:"sig_shortness_digits,omitempty"`
	CompressedRows          int        `json:"compressed_rows,omitempty"`
	ReplayProjection        string     `json:"replay_projection,omitempty"`
	TranscriptMode          string     `json:"transcript_mode,omitempty"`
	TranscriptOmissionMode  string     `json:"transcript_omission_mode,omitempty"`
	FixedTranscriptSize     bool       `json:"fixed_transcript_size,omitempty"`
}

// benchmarkPhaseWire names the complete v2 metric object. Large diagnostic
// subobjects are retained as RawMessage; their containing schema is strict.
type benchmarkPhaseWire struct {
	ProofSizeBytes                int                              `json:"proof_size_bytes"`
	ModeledVerifierMessageBytes   int                              `json:"modeled_verifier_message_bytes"`
	CanonicalProofWireBytes       int                              `json:"canonical_proof_wire_bytes,omitempty"`
	CanonicalPresentationBytes    int                              `json:"canonical_presentation_wire_bytes,omitempty"`
	CanonicalWireAudit            *PIOP.CanonicalProofWireAuditV6  `json:"canonical_wire_audit,omitempty"`
	ProofSchemaVersion            int                              `json:"proof_schema_version,omitempty"`
	CanonicalProofKind            string                           `json:"canonical_proof_kind,omitempty"`
	CanonicalProofCodecVersion    int                              `json:"canonical_proof_codec_version,omitempty"`
	CanonicalProofCodecProfile    string                           `json:"canonical_proof_codec_profile,omitempty"`
	CanonicalProofFieldEncoding   string                           `json:"canonical_proof_field_encoding,omitempty"`
	CanonicalProofQKernelEncoding string                           `json:"canonical_proof_q_kernel_encoding,omitempty"`
	CanonicalProofRadixQGroupSize int                              `json:"canonical_proof_radix_q_group_elements,omitempty"`
	CanonicalProofMerkleTopology  string                           `json:"canonical_proof_merkle_topology,omitempty"`
	CanonicalTamperRejected       bool                             `json:"canonical_tamper_rejected"`
	PaperTranscriptBytes          int                              `json:"paper_transcript_bytes"`
	PaperTranscriptKB             float64                          `json:"paper_transcript_kb"`
	QBytes                        int                              `json:"q_bytes"`
	RBytes                        int                              `json:"r_bytes"`
	PdecsBytes                    int                              `json:"pdecs_bytes"`
	MdecsBytes                    int                              `json:"mdecs_bytes,omitempty"`
	AuthBytes                     int                              `json:"auth_bytes"`
	TapesBytes                    int                              `json:"tapes_bytes,omitempty"`
	TapeBytes                     int                              `json:"tape_bytes"`
	TapeCount                     int                              `json:"tape_count"`
	TapeWidthBytes                int                              `json:"tape_width_bytes"`
	TapeDisclosureMode            string                           `json:"tape_disclosure_mode"`
	LeafEncodingVersion           int                              `json:"leaf_encoding_version"`
	RootWidthBytes                int                              `json:"root_width_bytes"`
	ZeroKnowledgeEligible         bool                             `json:"zero_knowledge_eligible"`
	SigShortnessBytes             int                              `json:"sig_shortness_bytes"`
	VTargetsBytes                 int                              `json:"vtargets_bytes"`
	BarSetsBytes                  int                              `json:"barsets_bytes"`
	TranscriptAudit               PIOP.PaperTranscriptAudit        `json:"transcript_audit,omitempty"`
	ValidPrefixCost               credential.ValidPrefixCostReport `json:"valid_prefix_cost,omitempty"`
	ProvingMS                     float64                          `json:"proving_ms"`
	VerificationMS                float64                          `json:"verification_ms"`
	PhaseTimings                  []PIOP.PhaseTiming               `json:"phase_timings,omitempty"`
	FSCounters                    [4]uint64                        `json:"fs_counters"`
	TotalRows                     int                              `json:"total_rows"`
	RowsBlock                     int                              `json:"rows_block,omitempty"`
	AuditRows                     int                              `json:"audit_rows,omitempty"`
	OpeningCols                   int                              `json:"opening_cols,omitempty"`
	PRFRows                       int                              `json:"prf_rows"`
	CoefficientViewRows           int                              `json:"coefficient_view_rows"`
	UCoefficientViewRows          int                              `json:"u_coefficient_view_rows,omitempty"`
	UDigitOnly                    bool                             `json:"u_digit_only,omitempty"`
	SemanticViewRows              int                              `json:"semantic_view_rows,omitempty"`
	CommitmentViewRows            int                              `json:"commitment_view_rows,omitempty"`
	YCoefficientViewRows          int                              `json:"y_coefficient_view_rows,omitempty"`
	IssuerViewRows                int                              `json:"issuer_view_rows,omitempty"`
	BoundRows                     int                              `json:"bound_rows"`
	ShortnessRows                 int                              `json:"shortness_rows"`
	ShortnessConstraints          int                              `json:"shortness_constraints,omitempty"`
	HatRows                       int                              `json:"hat_rows"`
	YHatRows                      int                              `json:"y_hat_rows,omitempty"`
	SourceBridgeConstraints       int                              `json:"source_bridge_constraints,omitempty"`
	UBridgeConstraints            int                              `json:"u_bridge_constraints,omitempty"`
	CommitmentBridgeConstraints   int                              `json:"commitment_bridge_constraints,omitempty"`
	YLinearConstraints            int                              `json:"y_linear_constraints,omitempty"`
	ProjectedSignatureConstraints int                              `json:"projected_signature_constraints,omitempty"`
	ReplayProjection              string                           `json:"replay_projection,omitempty"`
	LayoutVersion                 string                           `json:"layout_version,omitempty"`
	RelationVersion               string                           `json:"relation_version,omitempty"`
	PRFCompanionRelationVersion   int                              `json:"prf_companion_relation_version,omitempty"`
	PRFInputTraceRelationVersion  int                              `json:"prf_input_trace_relation_version,omitempty"`
	IssuerBridgeConstraints       int                              `json:"issuer_bridge_constraints,omitempty"`
	PRFKeyBridgeConstraints       int                              `json:"prf_key_bridge_constraints,omitempty"`
	FparIntConstraints            int                              `json:"fpar_int_constraints,omitempty"`
	RangeConstraints              int                              `json:"range_constraints,omitempty"`
	ParallelDegree                int                              `json:"parallel_degree"`
	AggregatedDegree              int                              `json:"aggregated_degree"`
	ParallelAlgDegree             int                              `json:"parallel_alg_degree,omitempty"`
	AggregatedAlgDegree           int                              `json:"aggregated_alg_degree,omitempty"`
	PaperConservativeDQ           int                              `json:"paper_conservative_dq,omitempty"`
	MaskDegreeBound               int                              `json:"mask_degree_bound,omitempty"`
	DominantDegreeSource          string                           `json:"dominant_degree_source,omitempty"`
	TernaryRows                   int                              `json:"ternary_rows,omitempty"`
	CompressedRows                int                              `json:"compressed_rows,omitempty"`
	MSECompressionLevel           int                              `json:"mse_compression_level,omitempty"`
	MSECompressionPackWidth       int                              `json:"mse_compression_pack_width,omitempty"`
	MSECompressionDegree          int                              `json:"mse_compression_degree,omitempty"`
	RoundBits                     [4]float64                       `json:"round_bits"`
	RawRoundBits                  [4]float64                       `json:"raw_round_bits"`
	TheoremBits                   [4]float64                       `json:"theorem_bits"`
	TheoremTotalBits              float64                          `json:"theorem_total_bits"`
	ROQueryCaps                   [5]int                           `json:"ro_query_caps"`
	ROQueryCapBits                [5]float64                       `json:"ro_query_cap_bits,omitempty"`
	CollisionSpaceBits            int                              `json:"collision_space_bits"`
	FSLambdaBits                  int                              `json:"fs_lambda_bits"`
	FSOutputBits                  int                              `json:"fs_output_bits"`
	ObservedFSDigestBits          [4]int                           `json:"observed_fs_digest_bits"`
	AggregateQueryBudget          bool                             `json:"aggregate_query_budget,omitempty"`
	AggregateQueryCapLog2         float64                          `json:"aggregate_query_cap_log2,omitempty"`
	WorkFactorMode                bool                             `json:"work_factor_mode,omitempty"`
	WorkFactorBits                float64                          `json:"work_factor_bits,omitempty"`
	WorkFactorComponents          [6]float64                       `json:"work_factor_components,omitempty"`
	NativeAlgebraicTerms          [4]float64                       `json:"native_algebraic_terms,omitempty"`
	NativeAlgebraicBits           [4]float64                       `json:"native_algebraic_bits,omitempty"`
	EffectiveLambdaBits           int                              `json:"effective_lambda_bits"`
	DECSHashBits                  int                              `json:"decs_hash_bits"`
	DECSTapeBits                  int                              `json:"decs_tape_bits"`
	SaltBits                      int                              `json:"salt_bits"`
	TranscriptMode                string                           `json:"transcript_mode,omitempty"`
	AlgebraicTerms                [4]float64                       `json:"algebraic_terms"`
	AlgebraicBits                 [4]float64                       `json:"algebraic_bits"`
	AlgebraicTotal                float64                          `json:"algebraic_total"`
	AlgebraicTotalBits            float64                          `json:"algebraic_total_bits"`
	Collision                     float64                          `json:"collision"`
	CollisionBits                 float64                          `json:"collision_bits"`
	OneProofTotal                 float64                          `json:"one_proof_total"`
	OneProofTotalBits             float64                          `json:"one_proof_total_bits"`
	Clamped                       [4]bool                          `json:"clamped"`
	SoundnessEq8Bits              float64                          `json:"soundness_eq8_bits"`
	DQ                            int                              `json:"dq"`
	DDECS                         int                              `json:"ddecs"`
	WitnessSupportCols            int                              `json:"witness_support_cols"`
	CommittedCols                 int                              `json:"committed_cols"`
	ProofReportBuckets            int                              `json:"proof_report_buckets"`
	LVCSNCols                     int                              `json:"lvcs_ncols,omitempty"`
	NLeaves                       int                              `json:"nleaves,omitempty"`
	Eta                           int                              `json:"eta,omitempty"`
	Ell                           int                              `json:"ell,omitempty"`
	Theta                         int                              `json:"theta"`
	Rho                           int                              `json:"rho"`
	EllPrime                      int                              `json:"ell_prime"`
	SmallFieldReplayRows          int                              `json:"smallfield_replay_rows,omitempty"`
	MaskRows                      int                              `json:"mask_rows,omitempty"`
	QSplitRows                    int                              `json:"q_split_rows,omitempty"`
	QLimbRows                     int                              `json:"q_limb_rows,omitempty"`
	PDecsBitWidth                 int                              `json:"pdecs_bit_width,omitempty"`
	VTargetsBitWidth              int                              `json:"vtargets_bit_width,omitempty"`
	PaperShapeNRows               int                              `json:"paper_shape_nrows,omitempty"`
	PaperShapeQueries             int                              `json:"paper_shape_queries,omitempty"`
	PaperShapeWitnessLayers       int                              `json:"paper_shape_witness_layers,omitempty"`
	PaperShapeMaskRows            int                              `json:"paper_shape_mask_rows,omitempty"`
	PaperShapeVHeadBytes          int                              `json:"paper_shape_vhead_bytes,omitempty"`
	PaperShapeVBarBytes           int                              `json:"paper_shape_vbar_bytes,omitempty"`
	PaperShapeOpeningOmitEntries  int                              `json:"paper_shape_opening_omit_entries,omitempty"`
	PaperShapeCanonical           bool                             `json:"paper_shape_canonical,omitempty"`
	FixedTranscriptSize           bool                             `json:"fixed_transcript_size"`
	TranscriptSizeMode            string                           `json:"transcript_size_mode"`
	TranscriptSecurityStatus      string                           `json:"transcript_security_status,omitempty"`
	MeasurementStatus             string                           `json:"measurement_status"`
	RelationCandidate             relationCandidateWire            `json:"relation_candidate,omitempty"`
}

type relationCandidateWire struct {
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

func decodeBenchmarkReport(path string) (benchmarkReportWire, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return benchmarkReportWire{}, nil, err
	}
	if err := requireBenchmarkReportVersionV2(data); err != nil {
		return benchmarkReportWire{}, nil, err
	}
	var report benchmarkReportWire
	if err := decodeStrictJSON(data, &report); err != nil {
		return benchmarkReportWire{}, nil, fmt.Errorf("decode benchmark report: %w", err)
	}
	return report, data, nil
}

// requireBenchmarkReportVersionV2 establishes the outer epoch before the
// strict full-schema decode. In particular, an old report with coincidentally
// familiar fields is never promoted into the v2 evidence model.
func requireBenchmarkReportVersionV2(data []byte) error {
	var identity struct {
		Version int `json:"version"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&identity); err != nil {
		return fmt.Errorf("decode benchmark report identity: %w", err)
	}
	want := ArtifactSchemasV2().E2EReport
	if identity.Version != want {
		return fmt.Errorf("benchmark report schema version %d; want %d (no migration; rerun setup, issuance, and the v2 benchmark)", identity.Version, want)
	}
	return nil
}

func validateBenchmarkReport(report benchmarkReportWire, preset credential.IntGenISISPreset) error {
	if report.Version != ArtifactSchemasV2().E2EReport {
		return fmt.Errorf("report schema version %d; want %d (no migration; rerun setup, issuance, and benchmark)", report.Version, ArtifactSchemasV2().E2EReport)
	}
	if report.CanonicalPresetID != preset.CanonicalID || report.PresetVersion != preset.PresetVersion {
		return fmt.Errorf("report preset tuple (%q,v%d) does not match (%q,v%d)", report.CanonicalPresetID, report.PresetVersion, preset.CanonicalID, preset.PresetVersion)
	}
	wantManifest := credential.IntGenISISPresetManifestDigest(preset)
	if report.PresetManifestDigest != wantManifest {
		return fmt.Errorf("report manifest digest %q does not match %q", report.PresetManifestDigest, wantManifest)
	}
	if report.PresetLifecycle != preset.Lifecycle || report.ClaimScope != credential.ClaimProofOnly || report.ClaimScope != preset.ClaimScope || report.CompleteSystemClaim {
		return fmt.Errorf("report lifecycle/claim tuple is not the proof-only preset tuple")
	}
	if report.Profile != preset.Profile || report.PrimitiveProfileID != preset.PrimitiveProfileID || report.SecurityProfile != preset.SecurityProfile || report.SecurityMode != preset.SecurityMode {
		return fmt.Errorf("report profile tuple does not match preset")
	}
	if !reflect.DeepEqual(report.ThreatModel, preset.ThreatModel) || report.MaxNLeaves != preset.MaxNLeaves {
		return fmt.Errorf("report threat model or leaf cap does not match preset")
	}
	if report.PRFProfile != preset.PRFProfile || report.PRFParamsDigest != preset.PRFParamsDigest {
		return fmt.Errorf("report PRF tuple does not match preset")
	}
	if report.ProfileBound != 1 {
		return fmt.Errorf("report hash-input bound=%d; want 1", report.ProfileBound)
	}
	if report.Modulus == 0 || strings.TrimSpace(report.Generated) == "" || strings.TrimSpace(report.LedgerStatus) == "" {
		return fmt.Errorf("report is missing modulus, generated_at, or ledger status")
	}
	if _, err := time.Parse(time.RFC3339, report.Generated); err != nil {
		return fmt.Errorf("report generated_at is not RFC3339: %w", err)
	}
	if report.ParameterAudit.Status != "pass" {
		return fmt.Errorf("report parameter audit status=%q; want pass", report.ParameterAudit.Status)
	}
	securitySpec, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	if !ok {
		return fmt.Errorf("preset security profile %q is not registered", preset.SecurityProfile)
	}
	if report.LedgerStatus != report.SecurityLedger.LedgerStatus || report.SecurityLedger.CompleteSystemClaim || report.SecurityLedger.SecurityProfile != preset.SecurityProfile || report.SecurityLedger.SecurityMode != preset.SecurityMode {
		return fmt.Errorf("report security-ledger tuple is inconsistent with its proof-only preset")
	}
	if report.LedgerStatus != string(securitySpec.Status) {
		return fmt.Errorf("report ledger status=%q does not match security profile status=%q", report.LedgerStatus, securitySpec.Status)
	}
	if !reflect.DeepEqual(report.LedgerReasons, report.SecurityLedger.RejectionReasons) || !reflect.DeepEqual(report.LedgerTerms, report.SecurityLedger.Terms) {
		return fmt.Errorf("report flattened security ledger does not match the nested ledger")
	}
	if report.FullGame.AcceptedIssuance != preset.ThreatModel.AcceptedIssuance || report.FullGame.AcceptedShowing != preset.ThreatModel.AcceptedShowing {
		return fmt.Errorf("report full-game accepted-proof counts do not match preset")
	}
	if !finitePositive(report.SoundnessBits) || !finitePositive(report.SecurityLedger.TargetBits) || !finitePositive(report.SecurityLedger.FullGameBits) || !finitePositive(report.CoreBitsRequired) || !finitePositive(report.CoreAvailableBits) {
		return fmt.Errorf("report has invalid soundness accounting")
	}
	if !report.ReplayRejected {
		return fmt.Errorf("report did not demonstrate replay rejection")
	}
	if err := validateTuning("issuance", report.Options.Issuance, preset.Issuance); err != nil {
		return err
	}
	if err := validateTuning("showing", report.Options.Showing, preset.Showing); err != nil {
		return err
	}
	if err := validatePhase("issuance", report.Issuance, preset.Issuance, false); err != nil {
		return err
	}
	if err := validatePhase("showing", report.Showing, preset.Showing, true); err != nil {
		return err
	}
	if report.Issuance.AlgebraicTotalBits < preset.TargetTheoremBits || report.Showing.AlgebraicTotalBits < preset.TargetTheoremBits {
		return fmt.Errorf("measured algebraic targets issuance=%.2f showing=%.2f fall below %.2f", report.Issuance.AlgebraicTotalBits, report.Showing.AlgebraicTotalBits, preset.TargetTheoremBits)
	}
	if err := validateFiniteNonnegativeTimings(report.Timings); err != nil {
		return err
	}
	return nil
}

func validateTuning(label string, got benchmarkTuningWire, want credential.IntGenISISTuningPreset) error {
	if got.NCols != want.NCols || got.LVCSNCols != want.LVCSNCols || got.NLeaves != want.NLeaves || got.Eta != want.Eta || got.Theta != want.Theta || got.Rho != want.Rho || got.Ell != want.Ell || got.EllPrime != want.EllPrime || got.Kappa != want.Kappa {
		return fmt.Errorf("%s report tuning geometry does not match preset", label)
	}
	if got.TranscriptMode != ProtocolModeV2 || got.TranscriptMode != want.TranscriptMode || !got.FixedTranscriptSize || !want.FixedTranscriptSize {
		return fmt.Errorf("%s report transcript tuple does not match v2 preset", label)
	}
	if got.TranscriptOmissionMode != OmissionDescriptorV2 || got.TranscriptOmissionMode != want.TranscriptOmissionMode {
		return fmt.Errorf("%s report transcript omission mode=%q does not match the v2 preset", label, got.TranscriptOmissionMode)
	}
	if got.DECSHashBits != want.DECSHashBits || got.DECSTapeBits != want.DECSTapeBits || got.SaltBits != want.SaltBits || got.DECSCollisionBits != want.DECSCollisionBits || got.FSCollisionBits != want.FSCollisionBits {
		return fmt.Errorf("%s report hash/tape/salt widths do not match preset", label)
	}
	if got.PRFProfile != want.PRFProfile || got.PRFCompanionMode != want.PRFCompanionMode || got.PRFGroupRounds != want.PRFGroupRounds || got.CheckpointSamples != want.CheckpointSamples || got.SigShortnessRadix != want.SigShortnessRadix || got.SigShortnessDigits != want.SigShortnessDigits || got.CompressedRows != want.CompressedRows || got.ReplayProjection != want.ReplayProjection {
		return fmt.Errorf("%s report relation tuning does not match preset", label)
	}
	if got.ROQueryCaps != want.ROQueryCaps || !equalFloatArray(got.ROQueryCapBits, want.ROQueryCapBits) {
		return fmt.Errorf("%s report random-oracle budget does not match preset", label)
	}
	return nil
}

func validatePhase(label string, phase benchmarkPhaseWire, tuning credential.IntGenISISTuningPreset, showing bool) error {
	if phase.TranscriptMode != ProtocolModeV2 || phase.TranscriptSecurityStatus != SecurityStatusV2 {
		return fmt.Errorf("%s phase transcript tuple (%q,%q) is not v2", label, phase.TranscriptMode, phase.TranscriptSecurityStatus)
	}
	if !phase.FixedTranscriptSize || phase.TranscriptSizeMode != "fixed" || phase.MeasurementStatus == "" {
		return fmt.Errorf("%s phase is missing fixed transcript or measurement status", label)
	}
	if !phase.PaperShapeCanonical || phase.PaperShapeNRows <= 0 || phase.PaperShapeQueries <= 0 || phase.PaperShapeWitnessLayers <= 0 {
		return fmt.Errorf("%s phase does not report canonical smallfield_matrix_v2 geometry", label)
	}
	if phase.TotalRows <= 0 || phase.ParallelDegree <= 0 || phase.AggregatedDegree <= 0 || phase.DQ <= 0 || phase.DDECS <= 0 {
		return fmt.Errorf("%s phase has invalid rows or degree metadata", label)
	}
	formal := phase.RelationCandidate
	if formal.LogicalRows != phase.TotalRows || formal.RowCounts["total"] != phase.TotalRows ||
		formal.ParallelDegree != phase.ParallelAlgDegree || formal.AggregatedDegree != phase.AggregatedAlgDegree ||
		formal.DQ != phase.DQ || formal.ParallelDegree <= 0 || formal.AggregatedDegree <= 0 ||
		strings.TrimSpace(formal.DominantDegreeSource) == "" || strings.TrimSpace(formal.DominantDQBranch) == "" {
		return fmt.Errorf("%s phase formal relation report is missing or inconsistent", label)
	}
	if showing && formal.ParallelDegree < 3 {
		return fmt.Errorf("showing phase formal degree=%d; hidden-slot PRF relation is at least cubic", formal.ParallelDegree)
	}
	if phase.ProofSizeBytes <= 0 || phase.PaperTranscriptBytes <= 0 || phase.DECSHashBits <= 0 || phase.DECSTapeBits <= 0 || phase.SaltBits <= 0 {
		return fmt.Errorf("%s phase has invalid wire-size or transcript-width metadata", label)
	}
	wireValues := []int{phase.QBytes, phase.RBytes, phase.PdecsBytes, phase.MdecsBytes, phase.AuthBytes, phase.TapesBytes, phase.SigShortnessBytes, phase.VTargetsBytes, phase.BarSetsBytes}
	for _, value := range wireValues {
		if value < 0 {
			return fmt.Errorf("%s phase has a negative wire-size bucket", label)
		}
	}
	if phase.TapesBytes <= 0 || phase.TapeBytes <= 0 || phase.TapeCount <= 0 || phase.TapeWidthBytes <= 0 || phase.RootWidthBytes <= 0 || phase.TranscriptAudit.Tapes.TapeCount <= 0 || phase.TranscriptAudit.Tapes.TapeBytes <= 0 {
		return fmt.Errorf("%s phase does not account for independent selective tapes", label)
	}
	if phase.TapeDisclosureMode != TapeDisclosureModeV2 || phase.LeafEncodingVersion != LeafEncodingVersionV2 || !phase.ZeroKnowledgeEligible {
		return fmt.Errorf("%s phase tape disclosure/leaf encoding tuple is not v2", label)
	}
	if phase.TranscriptAudit.Tapes.TapeBytes < phase.TapeBytes || phase.TranscriptAudit.Tapes.TapeCount < phase.TapeCount ||
		phase.TapeBytes != phase.TapeCount*phase.TapeWidthBytes || phase.TapeWidthBytes*8 != phase.DECSTapeBits ||
		phase.RootWidthBytes*8 != phase.DECSHashBits || phase.TapesBytes < phase.TapeBytes {
		return fmt.Errorf("%s phase tape count/width accounting is inconsistent", label)
	}
	if phase.LVCSNCols != tuning.LVCSNCols || phase.NLeaves != tuning.NLeaves || phase.Eta != tuning.Eta || phase.Theta != tuning.Theta || phase.Rho != tuning.Rho || phase.Ell != tuning.Ell || phase.EllPrime != tuning.EllPrime {
		return fmt.Errorf("%s measured geometry does not match preset", label)
	}
	if (tuning.DECSHashBits > 0 && phase.DECSHashBits != tuning.DECSHashBits) ||
		(tuning.DECSTapeBits > 0 && phase.DECSTapeBits != tuning.DECSTapeBits) ||
		(tuning.SaltBits > 0 && phase.SaltBits != tuning.SaltBits) {
		return fmt.Errorf("%s measured hash/tape/salt widths do not match preset", label)
	}
	if showing && phase.ReplayProjection != ShowingRelationV2 {
		return fmt.Errorf("showing phase relation %q; want %q", phase.ReplayProjection, ShowingRelationV2)
	}
	if showing && (phase.LayoutVersion != ShowingLayoutV2 || phase.PRFCompanionRelationVersion != PRFCompanionRelationV2) {
		return fmt.Errorf("showing phase layout/PRF companion relation is not v2")
	}
	if !finiteNonnegative(phase.ProvingMS) || !finiteNonnegative(phase.VerificationMS) || !finitePositive(phase.TheoremTotalBits) || !finitePositive(phase.SoundnessEq8Bits) {
		return fmt.Errorf("%s phase has invalid timing or security values", label)
	}
	return nil
}

func validateFiniteNonnegativeTimings(t benchmarkTimingsWire) error {
	values := []float64{t.SetupPublicMS, t.SetupNTRUKeysMS, t.HolderCommitMS, t.HolderProveMS, t.IssuerSignMS, t.HolderFinalizeMS}
	for _, value := range values {
		if !finiteNonnegative(value) {
			return fmt.Errorf("report contains invalid setup timing %v", value)
		}
	}
	return nil
}

func benchmarkEvidenceFromReport(report benchmarkReportWire, raw []byte, canonicalID string) BenchmarkEvidence {
	digest := sha256.Sum256(raw)
	return BenchmarkEvidence{
		File:          canonicalID + "/" + DefaultBenchmarkFileName,
		Digest:        hex.EncodeToString(digest[:]),
		SchemaVersion: report.Version,
		GeneratedAt:   report.Generated,
		Modulus:       report.Modulus,
		ProfileBound:  report.ProfileBound,
		SetupTimings: SetupTimings{
			SetupPublicMS: report.Timings.SetupPublicMS, SetupNTRUKeysMS: report.Timings.SetupNTRUKeysMS,
			HolderCommitMS: report.Timings.HolderCommitMS, HolderProveMS: report.Timings.HolderProveMS,
			IssuerSignMS: report.Timings.IssuerSignMS, HolderFinalizeMS: report.Timings.HolderFinalizeMS,
		},
		Issuance: phaseEvidenceFromReport(report.Issuance, report.Options.Issuance, false),
		Showing:  phaseEvidenceFromReport(report.Showing, report.Options.Showing, true),
		Security: ReportSecurityEvidence{
			LedgerStatus: report.LedgerStatus, LedgerRejectionReasons: append([]string(nil), report.LedgerReasons...),
			TargetBits: report.SecurityLedger.TargetBits, CoreRequiredBits: report.CoreBitsRequired,
			CoreAvailableBits: report.CoreAvailableBits, SoundnessBits: report.SoundnessBits,
			UnlinkabilityBits: report.UnlinkabilityBits, CorrectnessBits: report.CorrectnessBits,
			ZeroKnowledgeBits: report.ZeroKnowledgeBits, PrimitiveBits: report.PrimitiveBits,
			CompositionBits: report.CompositionBits, TagCollisionBits: report.TagCollisionBits,
			FullGameBits: report.SecurityLedger.FullGameBits, GlobalCollisionBits: report.FullGame.GlobalCollisionBits,
			GlobalCollisionFullGameBits: report.FullGame.GlobalCollisionFullGameBits,
			AcceptedIssuance:            report.FullGame.AcceptedIssuance, AcceptedShowing: report.FullGame.AcceptedShowing,
			SaltCollisionBits: report.SaltCollisionBits, TapeGuessingBits: report.TapeGuessingBits,
			ProgrammingConflictBits: report.ProgrammingBits, ChallengeBiasBits: report.ChallengeBiasBits,
			RequiredPhaseAlgebraicBits: report.RequiredPhaseAlgebraicBits,
			PhaseAlgebraicSlackBits:    report.PhaseAlgebraicSlackBits,
			DominantSoundnessLimiter:   report.DominantSoundnessLimiter,
		},
		ReplayRejected: report.ReplayRejected,
	}
}

func phaseEvidenceFromReport(phase benchmarkPhaseWire, tuning benchmarkTuningWire, showing bool) PhaseEvidence {
	relation, layout := "bounded_bb_tran_ternary_sources_v2", "intgenisis_presign_bounded_sources_v2"
	if showing {
		relation, layout = phase.ReplayProjection, phase.LayoutVersion
	}
	return PhaseEvidence{
		Relation: relation, Layout: layout, PRFCompanionRelationVersion: phase.PRFCompanionRelationVersion,
		TranscriptMode: phase.TranscriptMode, PCSGeometry: PCSGeometryV2,
		PCSRows: phase.PaperShapeNRows, PCSQueries: phase.PaperShapeQueries,
		PCSWitnessLayers: phase.PaperShapeWitnessLayers, PCSMaskRows: phase.PaperShapeMaskRows,
		Rows: PhaseRows{
			Total: phase.TotalRows, Logical: phase.RelationCandidate.LogicalRows, PRF: phase.PRFRows,
			CoefficientViews: phase.CoefficientViewRows, SemanticViews: phase.SemanticViewRows,
			CommitmentViews: phase.CommitmentViewRows, Bound: phase.BoundRows,
			Shortness: phase.ShortnessRows, Hat: phase.HatRows, Ternary: phase.TernaryRows,
			SmallFieldReplay:  phase.SmallFieldReplayRows,
			RelationRowCounts: cloneIntMap(phase.RelationCandidate.RowCounts),
			ConstraintCounts:  cloneIntMap(phase.RelationCandidate.ConstraintCounts),
		},
		Degrees: PhaseDegrees{
			Parallel: phase.ParallelDegree, Aggregated: phase.AggregatedDegree,
			ParallelAlgebraic: phase.ParallelAlgDegree, AggregatedAlgebraic: phase.AggregatedAlgDegree,
			Quotient: phase.DQ, DECS: phase.DDECS, MaskBound: phase.MaskDegreeBound,
			DominantSource:       phase.DominantDegreeSource,
			DominantQuotientPath: phase.RelationCandidate.DominantDQBranch,
		},
		Security: PhaseSecurity{
			TheoremBits: phase.TheoremTotalBits, SoundnessEq8Bits: phase.SoundnessEq8Bits,
			AlgebraicBits: phase.AlgebraicTotalBits, CollisionBits: phase.CollisionBits,
			OneProofBits: phase.OneProofTotalBits, RoundTheoremBits: phase.TheoremBits,
			ROQueryCapBits: phase.ROQueryCapBits, CollisionSpaceBits: phase.CollisionSpaceBits,
			DECSHashBits: phase.DECSHashBits, DECSTapeBits: phase.DECSTapeBits,
			SaltBits: phase.SaltBits, TranscriptStatus: phase.TranscriptSecurityStatus,
			MeasurementStatus: phase.MeasurementStatus, ZeroKnowledgeEligible: phase.ZeroKnowledgeEligible,
		},
		WireSizes: PhaseWireSizes{
			Proof: phase.ProofSizeBytes, PaperTranscript: phase.PaperTranscriptBytes,
			Q: phase.QBytes, R: phase.RBytes, PDECS: phase.PdecsBytes, MDECS: phase.MdecsBytes,
			Authentication: phase.AuthBytes, Tapes: phase.TapesBytes,
			SignatureShortness: phase.SigShortnessBytes, VTargets: phase.VTargetsBytes,
			BarSets: phase.BarSetsBytes,
		},
		Timings: PhaseTimings{ProvingMS: phase.ProvingMS, VerificationMS: phase.VerificationMS},
		NCols:   tuning.NCols, LVCSNCols: phase.LVCSNCols, NLeaves: phase.NLeaves,
		Eta: phase.Eta, Theta: phase.Theta, Rho: phase.Rho, Ell: phase.Ell, EllPrime: phase.EllPrime,
		TapeBytes: phase.TapeBytes, RootWidthBits: phase.DECSHashBits, RootWidthBytes: phase.RootWidthBytes,
		TapeCount: phase.TapeCount, TapeWidthBits: phase.DECSTapeBits, TapeWidthBytes: phase.TapeWidthBytes,
		TapeDisclosureMode: phase.TapeDisclosureMode, LeafEncodingVersion: phase.LeafEncodingVersion,
	}
}

func decodeStrictJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func equalFloatArray(left, right [5]float64) bool {
	return reflect.DeepEqual(left, right)
}

func finiteNonnegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func finitePositive(value float64) bool {
	return finiteNonnegative(value) && value > 0
}

func cloneIntMap(src map[string]int) map[string]int {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]int, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}
