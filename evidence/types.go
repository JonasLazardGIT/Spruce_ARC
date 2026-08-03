// Package evidence exports and validates the stable, paper-facing SPRUCE v2
// evidence lock.  It deliberately consumes benchmark artifacts instead of
// running benchmarks: producing measurements and freezing measurements are
// separate operations.
package evidence

import "vSIS-Signature/credential"

const (
	LockSchemaV2             = "spruce.paper-artifact-lock.v2"
	LockVersionV2            = 2
	ManifestSchemaV2         = "spruce.intgenisis.preset.v2"
	ProtocolModeV2           = "smallfield_2025_1085_salted_tapes_v2"
	TranscriptVersionV2      = "smallwood_2025_1085_salted_decs_v2"
	SecurityStatusV2         = "smallwood_2025_1085_salted_tapes_v2_live"
	PresentationSchemaV2     = "intgenisis_presentation_v2"
	PCSGeometryV2            = "smallfield_matrix_v2"
	OmissionDescriptorV2     = "digest_bound_payload_v2"
	LeafEncodingVersionV2    = 2
	TapeDisclosureModeV2     = "independent_selective"
	ShowingRelationV2        = "project_u_digits_y_bounded_sources_v6"
	ShowingLayoutV2          = "intgenisis_showing_project_u_digits_y_bounded_sources_v6"
	PRFCompanionRelationV2   = 2
	DefaultBenchmarkFileName = "benchmark-intgenisis-e2e.json"
	DefaultBaselineFileName  = "benchmark-intgenisis-e2e-baseline.json"
	DefaultArtifactSubdir    = "artifacts/smallwood-salted-v2"
	DefaultLockFileName      = "spruce-paper-v2.lock.json"
	GeneratedMacrosFileName  = "v2_macros.tex"
	GeneratedTableFileName   = "v2_tables.tex"
)

const (
	BaselineSchemaV2      = "spruce.intgenisis.three-run-baseline.v2"
	BaselineVersionV2     = 2
	BaselineAggregationV2 = "independent_scalar_median_of_three_v2"
	BaselineRunCountV2    = 3
	BaselineCanonicalRun  = 2
)

// ArtifactSchemas records every incompatible persisted v2 boundary used by
// the executable artifact.  Keeping these values in one lock makes accidental
// mixed-epoch paper evidence visible.
type ArtifactSchemas struct {
	PIOPProof             int    `json:"piop_proof"`
	DECSOpening           int    `json:"decs_opening"`
	PublicParameters      int    `json:"public_parameters"`
	IssuanceRequest       int    `json:"issuance_request"`
	PresignSubmission     int    `json:"presign_submission"`
	IssuanceResponse      int    `json:"issuance_response"`
	HolderSecret          int    `json:"holder_secret"`
	CredentialState       int    `json:"credential_state"`
	HolderUsageState      int    `json:"holder_usage_state"`
	VerifierKey           int    `json:"verifier_key"`
	Presentation          int    `json:"presentation"`
	VerifierState         int    `json:"verifier_state"`
	E2EReport             int    `json:"e2e_report"`
	BMatrix               int    `json:"b_matrix"`
	NTRUParameters        int    `json:"ntru_parameters"`
	NTRUParameterIdentity string `json:"ntru_parameter_identity"`
	NTRUKeyIdentity       string `json:"ntru_key_identity"`
	NTRUSignatureIdentity string `json:"ntru_signature_identity"`
	SmallFieldMetadata    int    `json:"small_field_metadata"`
	OmissionDescriptor    int    `json:"omission_descriptor"`
}

func ArtifactSchemasV2() ArtifactSchemas {
	return ArtifactSchemas{
		PIOPProof:             2,
		DECSOpening:           2,
		PublicParameters:      8,
		IssuanceRequest:       3,
		PresignSubmission:     3,
		IssuanceResponse:      3,
		HolderSecret:          3,
		CredentialState:       7,
		HolderUsageState:      2,
		VerifierKey:           2,
		Presentation:          2,
		VerifierState:         2,
		E2EReport:             2,
		BMatrix:               3,
		NTRUParameters:        2,
		NTRUParameterIdentity: "ntru-params-v2",
		NTRUKeyIdentity:       "ntru-key-v2",
		NTRUSignatureIdentity: "ntru-signature-v2",
		SmallFieldMetadata:    2,
		OmissionDescriptor:    2,
	}
}

type ProtocolIdentities struct {
	ProtocolMode        string          `json:"protocol_mode"`
	TranscriptVersion   string          `json:"transcript_version"`
	SecurityStatus      string          `json:"security_status"`
	ManifestSchema      string          `json:"manifest_schema"`
	PresentationSchema  string          `json:"presentation_schema"`
	PCSGeometry         string          `json:"pcs_geometry"`
	OmissionDescriptor  string          `json:"omission_descriptor"`
	LeafEncodingVersion int             `json:"leaf_encoding_version"`
	TapeDisclosureMode  string          `json:"tape_disclosure_mode"`
	Schemas             ArtifactSchemas `json:"schemas"`
}

func ProtocolIdentitiesV2() ProtocolIdentities {
	return ProtocolIdentities{
		ProtocolMode:        ProtocolModeV2,
		TranscriptVersion:   TranscriptVersionV2,
		SecurityStatus:      SecurityStatusV2,
		ManifestSchema:      ManifestSchemaV2,
		PresentationSchema:  PresentationSchemaV2,
		PCSGeometry:         PCSGeometryV2,
		OmissionDescriptor:  OmissionDescriptorV2,
		LeafEncodingVersion: LeafEncodingVersionV2,
		TapeDisclosureMode:  TapeDisclosureModeV2,
		Schemas:             ArtifactSchemasV2(),
	}
}

type SourceTreeEvidence struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	FileCount int    `json:"file_count"`
}

type GitEvidence struct {
	Revision string `json:"revision"`
}

type PhaseRows struct {
	Total             int            `json:"total"`
	Logical           int            `json:"logical,omitempty"`
	PRF               int            `json:"prf,omitempty"`
	CoefficientViews  int            `json:"coefficient_views,omitempty"`
	SemanticViews     int            `json:"semantic_views,omitempty"`
	CommitmentViews   int            `json:"commitment_views,omitempty"`
	Bound             int            `json:"bound,omitempty"`
	Shortness         int            `json:"shortness,omitempty"`
	Hat               int            `json:"hat,omitempty"`
	Ternary           int            `json:"ternary,omitempty"`
	SmallFieldReplay  int            `json:"small_field_replay,omitempty"`
	RelationRowCounts map[string]int `json:"relation_row_counts,omitempty"`
	ConstraintCounts  map[string]int `json:"constraint_counts,omitempty"`
}

type PhaseDegrees struct {
	Parallel             int    `json:"parallel"`
	Aggregated           int    `json:"aggregated"`
	ParallelAlgebraic    int    `json:"parallel_algebraic,omitempty"`
	AggregatedAlgebraic  int    `json:"aggregated_algebraic,omitempty"`
	Quotient             int    `json:"quotient"`
	DECS                 int    `json:"decs"`
	MaskBound            int    `json:"mask_bound,omitempty"`
	DominantSource       string `json:"dominant_source,omitempty"`
	DominantQuotientPath string `json:"dominant_quotient_path,omitempty"`
}

type PhaseSecurity struct {
	TheoremBits           float64    `json:"theorem_bits"`
	SoundnessEq8Bits      float64    `json:"soundness_eq8_bits"`
	AlgebraicBits         float64    `json:"algebraic_bits"`
	CollisionBits         float64    `json:"collision_bits"`
	OneProofBits          float64    `json:"one_proof_bits"`
	RoundTheoremBits      [4]float64 `json:"round_theorem_bits"`
	ROQueryCapBits        [5]float64 `json:"ro_query_cap_bits"`
	CollisionSpaceBits    int        `json:"collision_space_bits"`
	DECSHashBits          int        `json:"decs_hash_bits"`
	DECSTapeBits          int        `json:"decs_tape_bits"`
	SaltBits              int        `json:"salt_bits"`
	TranscriptStatus      string     `json:"transcript_status"`
	MeasurementStatus     string     `json:"measurement_status"`
	ZeroKnowledgeEligible bool       `json:"zero_knowledge_eligible"`
}

type PhaseWireSizes struct {
	Proof              int `json:"proof"`
	PaperTranscript    int `json:"paper_transcript"`
	Q                  int `json:"q"`
	R                  int `json:"r"`
	PDECS              int `json:"pdecs"`
	MDECS              int `json:"mdecs,omitempty"`
	Authentication     int `json:"authentication"`
	Tapes              int `json:"tapes"`
	SignatureShortness int `json:"signature_shortness"`
	VTargets           int `json:"v_targets"`
	BarSets            int `json:"bar_sets"`
}

type PhaseTimings struct {
	ProvingMS      float64 `json:"proving_ms"`
	VerificationMS float64 `json:"verification_ms"`
}

type PhaseEvidence struct {
	Relation                    string         `json:"relation"`
	Layout                      string         `json:"layout"`
	PRFCompanionRelationVersion int            `json:"prf_companion_relation_version,omitempty"`
	TranscriptMode              string         `json:"transcript_mode"`
	PCSGeometry                 string         `json:"pcs_geometry"`
	PCSRows                     int            `json:"pcs_rows"`
	PCSQueries                  int            `json:"pcs_queries"`
	PCSWitnessLayers            int            `json:"pcs_witness_layers"`
	PCSMaskRows                 int            `json:"pcs_mask_rows"`
	Rows                        PhaseRows      `json:"rows"`
	Degrees                     PhaseDegrees   `json:"degrees"`
	Security                    PhaseSecurity  `json:"security"`
	WireSizes                   PhaseWireSizes `json:"wire_sizes"`
	Timings                     PhaseTimings   `json:"timings"`
	NCols                       int            `json:"ncols"`
	LVCSNCols                   int            `json:"lvcs_ncols"`
	NLeaves                     int            `json:"nleaves"`
	Eta                         int            `json:"eta"`
	Theta                       int            `json:"theta"`
	Rho                         int            `json:"rho"`
	Ell                         int            `json:"ell"`
	EllPrime                    int            `json:"ell_prime"`
	TapeBytes                   int            `json:"tape_bytes"`
	RootWidthBits               int            `json:"root_width_bits"`
	RootWidthBytes              int            `json:"root_width_bytes"`
	TapeCount                   int            `json:"tape_count"`
	TapeWidthBits               int            `json:"tape_width_bits"`
	TapeWidthBytes              int            `json:"tape_width_bytes"`
	TapeDisclosureMode          string         `json:"tape_disclosure_mode"`
	LeafEncodingVersion         int            `json:"leaf_encoding_version"`
}

type SetupTimings struct {
	SetupPublicMS    float64 `json:"setup_public_ms"`
	SetupNTRUKeysMS  float64 `json:"setup_ntru_keys_ms"`
	HolderCommitMS   float64 `json:"holder_commit_ms"`
	HolderProveMS    float64 `json:"holder_prove_ms"`
	IssuerSignMS     float64 `json:"issuer_verify_sign_ms"`
	HolderFinalizeMS float64 `json:"holder_finalize_ms"`
}

// BaselineTimings contains independent scalar medians. Each field is sorted
// and selected independently from the three benchmark runs; the values are
// not presented as if they came from one synthetic benchmark execution.
type BaselineTimings struct {
	Setup    SetupTimings `json:"setup"`
	Issuance PhaseTimings `json:"issuance"`
	Showing  PhaseTimings `json:"showing"`
}

type BaselineRunEvidence struct {
	Run         int    `json:"run"`
	File        string `json:"file"`
	Digest      string `json:"sha256"`
	GeneratedAt string `json:"generated_at"`
}

type BaselineStability struct {
	Bytes       bool   `json:"bytes"`
	Geometry    bool   `json:"geometry"`
	Security    bool   `json:"security"`
	Environment bool   `json:"environment"`
	Digest      string `json:"projection_digest"`
}

// BaselineDocument is the strict persisted sidecar produced from exactly
// three independently generated v2 benchmark reports.
type BaselineDocument struct {
	Schema                string                `json:"schema"`
	Version               int                   `json:"version"`
	Aggregation           string                `json:"aggregation"`
	CanonicalPresetID     string                `json:"canonical_preset_id"`
	PresetManifestDigest  string                `json:"preset_manifest_digest"`
	RunCount              int                   `json:"run_count"`
	Runs                  []BaselineRunEvidence `json:"runs"`
	CanonicalRun          int                   `json:"canonical_run"`
	CanonicalReportFile   string                `json:"canonical_report_file"`
	CanonicalReportDigest string                `json:"canonical_report_sha256"`
	Stability             BaselineStability     `json:"stability"`
	MedianTimings         BaselineTimings       `json:"median_timings"`
}

// BaselineEvidence embeds a validated sidecar in the paper lock and also
// binds the exact sidecar bytes.
type BaselineEvidence struct {
	File   string `json:"file"`
	Digest string `json:"sha256"`
	BaselineDocument
}

type ReportSecurityEvidence struct {
	LedgerStatus                string   `json:"ledger_status"`
	LedgerRejectionReasons      []string `json:"ledger_rejection_reasons,omitempty"`
	TargetBits                  float64  `json:"target_bits"`
	CoreRequiredBits            float64  `json:"core_required_bits"`
	CoreAvailableBits           float64  `json:"core_available_bits"`
	SoundnessBits               float64  `json:"soundness_bits"`
	UnlinkabilityBits           float64  `json:"unlinkability_bits"`
	CorrectnessBits             float64  `json:"correctness_bits"`
	ZeroKnowledgeBits           float64  `json:"zero_knowledge_bits"`
	PrimitiveBits               float64  `json:"primitive_bits"`
	CompositionBits             float64  `json:"composition_bits"`
	FullGameBits                float64  `json:"full_game_bits"`
	GlobalCollisionBits         float64  `json:"global_collision_bits"`
	GlobalCollisionFullGameBits float64  `json:"global_collision_full_game_bits"`
	AcceptedIssuance            int      `json:"accepted_issuance"`
	AcceptedShowing             int      `json:"accepted_showing"`
	TagCollisionBits            float64  `json:"tag_collision_bits"`
	SaltCollisionBits           float64  `json:"salt_collision_bits"`
	TapeGuessingBits            float64  `json:"tape_guessing_bits"`
	ProgrammingConflictBits     float64  `json:"programming_conflict_bits"`
	ChallengeBiasBits           float64  `json:"challenge_bias_bits"`
	RequiredPhaseAlgebraicBits  float64  `json:"required_phase_algebraic_bits"`
	PhaseAlgebraicSlackBits     float64  `json:"phase_algebraic_slack_bits"`
	DominantSoundnessLimiter    string   `json:"dominant_soundness_limiter,omitempty"`
}

type BenchmarkEvidence struct {
	File           string                 `json:"file"`
	Digest         string                 `json:"digest"`
	SchemaVersion  int                    `json:"schema_version"`
	GeneratedAt    string                 `json:"generated_at"`
	Modulus        uint64                 `json:"modulus"`
	ProfileBound   int64                  `json:"hash_input_bound"`
	SetupTimings   SetupTimings           `json:"setup_timings"`
	Issuance       PhaseEvidence          `json:"issuance"`
	Showing        PhaseEvidence          `json:"showing"`
	Security       ReportSecurityEvidence `json:"security"`
	ReplayRejected bool                   `json:"replay_rejected"`
}

type PresetEvidence struct {
	CanonicalID          string                     `json:"canonical_id"`
	Selector             string                     `json:"selector"`
	PresetVersion        int                        `json:"preset_version"`
	ManifestDigest       string                     `json:"manifest_digest"`
	PrimitiveProfileID   string                     `json:"primitive_profile_id"`
	SecurityProfile      string                     `json:"security_profile"`
	SecurityMode         string                     `json:"security_mode"`
	Lifecycle            credential.PresetLifecycle `json:"lifecycle"`
	ClaimScope           credential.ClaimScope      `json:"claim_scope"`
	CompleteSystemClaim  bool                       `json:"complete_system_claim"`
	TargetTheoremBits    float64                    `json:"target_theorem_bits"`
	RateLimitPolicy      credential.RateLimitPolicy `json:"rate_limit_policy"`
	ShowingRelation      string                     `json:"showing_relation"`
	ShowingLayout        string                     `json:"showing_layout"`
	PRFCompanionRelation int                        `json:"prf_companion_relation"`
	Benchmark            *BenchmarkEvidence         `json:"benchmark,omitempty"`
	Baseline             *BaselineEvidence          `json:"baseline,omitempty"`
	PendingReason        string                     `json:"pending_reason,omitempty"`
}

// ArtifactLock is stable for the same source tree and benchmark report bytes:
// it intentionally contains no exporter wall-clock timestamp or host path.
type ArtifactLock struct {
	Schema           string             `json:"schema"`
	Version          int                `json:"version"`
	Status           string             `json:"status"`
	Identities       ProtocolIdentities `json:"identities"`
	SourceTree       SourceTreeEvidence `json:"source_tree"`
	Git              *GitEvidence       `json:"git,omitempty"`
	PresetCount      int                `json:"preset_count"`
	Aggregation      string             `json:"aggregation"`
	RunCount         int                `json:"run_count"`
	RunDigestCount   int                `json:"run_digest_count"`
	Presets          []PresetEvidence   `json:"presets"`
	ReportsDigest    string             `json:"reports_digest"`
	RunReportsDigest string             `json:"run_reports_digest"`
	EvidenceDigest   string             `json:"evidence_digest"`
}

type BuildOptions struct {
	SPRUCE_DIR   string
	ReportsDir   string
	AllowPending bool
}

type ValidationOptions struct {
	SPRUCE_DIR      string
	ReportsDir      string
	GeneratedTeXDir string
	AllowPending    bool
}

type BaselineOptions struct {
	SPRUCE_DIR        string
	ReportsDir        string
	CanonicalPresetID string
}
