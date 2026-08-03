package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func baselineRunFileName(run int) string {
	return fmt.Sprintf("run-%02d.json", run)
}

// GenerateThreeRunBaselines validates and freezes exactly three benchmark
// runs for every selected preset. The canonical report is an exact copy of run
// 02; independently aggregated scalar medians live in the sidecar and lock.
func GenerateThreeRunBaselines(opts BaselineOptions) ([]BaselineEvidence, error) {
	root, err := ResolveSPRUCE_DIR(opts.SPRUCE_DIR)
	if err != nil {
		return nil, err
	}
	reportsDir, err := ResolveReportsDir(root, opts.ReportsDir)
	if err != nil {
		return nil, err
	}
	if err := validatePresetRegistryV2(); err != nil {
		return nil, err
	}
	ids := CanonicalV2PresetIDs()
	if requested := strings.TrimSpace(opts.CanonicalPresetID); requested != "" {
		if !isCanonicalV2PresetID(requested) {
			return nil, fmt.Errorf("baseline preset %q is not a maintained canonical v2 identity", requested)
		}
		ids = []string{requested}
	}

	result := make([]BaselineEvidence, 0, len(ids))
	for _, canonicalID := range ids {
		preset, ok := credential.LookupIntGenISISPreset(canonicalID)
		if !ok {
			return nil, fmt.Errorf("canonical v2 preset %q is not registered", canonicalID)
		}
		document, canonicalRaw, err := aggregateThreeRunBaseline(reportsDir, preset)
		if err != nil {
			return nil, fmt.Errorf("baseline %s: %w", canonicalID, err)
		}
		encoded, err := marshalBaselineDocument(document)
		if err != nil {
			return nil, err
		}
		presetDir := filepath.Join(reportsDir, canonicalID)
		// Installing either file without the other cannot be accepted: final
		// ingestion rechecks the canonical bytes, sidecar, and all three runs.
		if err := writeFileAtomic(filepath.Join(presetDir, DefaultBenchmarkFileName), canonicalRaw, 0o644); err != nil {
			return nil, fmt.Errorf("install canonical report for %s: %w", canonicalID, err)
		}
		if err := writeFileAtomic(filepath.Join(presetDir, DefaultBaselineFileName), encoded, 0o644); err != nil {
			return nil, fmt.Errorf("install baseline sidecar for %s: %w", canonicalID, err)
		}
		result = append(result, baselineEvidenceFromDocument(document, encoded, canonicalID))
	}
	return result, nil
}

func isCanonicalV2PresetID(id string) bool {
	for _, candidate := range canonicalV2PresetIDs {
		if id == candidate {
			return true
		}
	}
	return false
}

func aggregateThreeRunBaseline(reportsDir string, preset credential.IntGenISISPreset) (BaselineDocument, []byte, error) {
	runsDir := filepath.Join(reportsDir, preset.CanonicalID, "runs")
	if err := validateBaselineRunDirectory(runsDir); err != nil {
		return BaselineDocument{}, nil, err
	}
	var reports [BaselineRunCountV2]benchmarkReportWire
	var raw [BaselineRunCountV2][]byte
	runs := make([]BaselineRunEvidence, 0, BaselineRunCountV2)
	for offset := 0; offset < BaselineRunCountV2; offset++ {
		run := offset + 1
		rel := filepath.ToSlash(filepath.Join(preset.CanonicalID, "runs", baselineRunFileName(run)))
		path := filepath.Join(reportsDir, filepath.FromSlash(rel))
		report, encoded, err := decodeBenchmarkReport(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return BaselineDocument{}, nil, fmt.Errorf("missing run %d at %s", run, path)
			}
			return BaselineDocument{}, nil, fmt.Errorf("read run %d: %w", run, err)
		}
		if err := validateBenchmarkReport(report, preset); err != nil {
			return BaselineDocument{}, nil, fmt.Errorf("invalid run %d: %w", run, err)
		}
		digest := sha256.Sum256(encoded)
		reports[offset], raw[offset] = report, encoded
		runs = append(runs, BaselineRunEvidence{
			Run: run, File: rel, Digest: hex.EncodeToString(digest[:]), GeneratedAt: report.Generated,
		})
	}
	stability, err := validateThreeRunStability(reports)
	if err != nil {
		return BaselineDocument{}, nil, err
	}
	canonicalDigest := sha256.Sum256(raw[BaselineCanonicalRun-1])
	return BaselineDocument{
		Schema: BaselineSchemaV2, Version: BaselineVersionV2, Aggregation: BaselineAggregationV2,
		CanonicalPresetID: preset.CanonicalID, PresetManifestDigest: credential.IntGenISISPresetManifestDigest(preset),
		RunCount: BaselineRunCountV2, Runs: runs, CanonicalRun: BaselineCanonicalRun,
		CanonicalReportFile:   filepath.ToSlash(filepath.Join(preset.CanonicalID, DefaultBenchmarkFileName)),
		CanonicalReportDigest: hex.EncodeToString(canonicalDigest[:]), Stability: stability,
		MedianTimings: medianBaselineTimings(reports),
	}, append([]byte(nil), raw[BaselineCanonicalRun-1]...), nil
}

func validateBaselineRunDirectory(runsDir string) error {
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		return fmt.Errorf("read runs directory %s: %w", runsDir, err)
	}
	expected := make(map[string]bool, BaselineRunCountV2)
	for run := 1; run <= BaselineRunCountV2; run++ {
		expected[baselineRunFileName(run)] = false
	}
	for _, entry := range entries {
		if _, ok := expected[entry.Name()]; ok {
			if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return fmt.Errorf("run report %s is not a regular file", filepath.Join(runsDir, entry.Name()))
			}
			expected[entry.Name()] = true
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			return fmt.Errorf("unexpected JSON run report %s; exactly run-01.json through run-03.json are allowed", filepath.Join(runsDir, entry.Name()))
		}
	}
	for run := 1; run <= BaselineRunCountV2; run++ {
		name := baselineRunFileName(run)
		if !expected[name] {
			return fmt.Errorf("missing run report %s", filepath.Join(runsDir, name))
		}
	}
	return nil
}

func marshalBaselineDocument(document BaselineDocument) ([]byte, error) {
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode three-run baseline: %w", err)
	}
	return append(encoded, '\n'), nil
}

func decodeBaselineDocument(path string) (BaselineDocument, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BaselineDocument{}, nil, err
	}
	if err := requireBaselineIdentityV2(data); err != nil {
		return BaselineDocument{}, nil, err
	}
	var document BaselineDocument
	if err := decodeStrictJSON(data, &document); err != nil {
		return BaselineDocument{}, nil, fmt.Errorf("decode baseline sidecar: %w", err)
	}
	return document, data, nil
}

func requireBaselineIdentityV2(data []byte) error {
	var identity struct {
		Schema  string `json:"schema"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&identity); err != nil {
		return fmt.Errorf("decode baseline identity: %w", err)
	}
	if identity.Schema != BaselineSchemaV2 || identity.Version != BaselineVersionV2 {
		return fmt.Errorf("baseline schema (%q,v%d) is not (%q,v%d); no migration; rerun all three v2 measurements", identity.Schema, identity.Version, BaselineSchemaV2, BaselineVersionV2)
	}
	return nil
}

func readAndValidateBaseline(reportsDir string, preset credential.IntGenISISPreset) (BaselineEvidence, error) {
	path := filepath.Join(reportsDir, preset.CanonicalID, DefaultBaselineFileName)
	document, raw, err := decodeBaselineDocument(path)
	if err != nil {
		return BaselineEvidence{}, err
	}
	expected, canonicalRaw, err := aggregateThreeRunBaseline(reportsDir, preset)
	if err != nil {
		return BaselineEvidence{}, err
	}
	if !reflect.DeepEqual(document, expected) {
		return BaselineEvidence{}, fmt.Errorf("baseline sidecar does not match the three run reports; regenerate it")
	}
	canonicalPath := filepath.Join(reportsDir, preset.CanonicalID, DefaultBenchmarkFileName)
	installed, err := os.ReadFile(canonicalPath)
	if err != nil {
		return BaselineEvidence{}, fmt.Errorf("read canonical report: %w", err)
	}
	if !bytes.Equal(installed, canonicalRaw) {
		return BaselineEvidence{}, fmt.Errorf("canonical report is not an exact copy of run %02d; regenerate the baseline", BaselineCanonicalRun)
	}
	return baselineEvidenceFromDocument(document, raw, preset.CanonicalID), nil
}

func baselineEvidenceFromDocument(document BaselineDocument, raw []byte, canonicalID string) BaselineEvidence {
	digest := sha256.Sum256(raw)
	document.Runs = append([]BaselineRunEvidence(nil), document.Runs...)
	return BaselineEvidence{
		File:   filepath.ToSlash(filepath.Join(canonicalID, DefaultBaselineFileName)),
		Digest: hex.EncodeToString(digest[:]), BaselineDocument: document,
	}
}

type baselineBytesProjection struct {
	Issuance baselinePhaseBytes `json:"issuance"`
	Showing  baselinePhaseBytes `json:"showing"`
}

type baselinePhaseBytes struct {
	WireSizes            PhaseWireSizes            `json:"wire_sizes"`
	PaperTranscriptKB    float64                   `json:"paper_transcript_kb"`
	TapeBytes            int                       `json:"tape_bytes"`
	TapeCount            int                       `json:"tape_count"`
	TapeWidthBytes       int                       `json:"tape_width_bytes"`
	RootWidthBytes       int                       `json:"root_width_bytes"`
	TranscriptAudit      PIOP.PaperTranscriptAudit `json:"transcript_audit"`
	PaperShapeVHeadBytes int                       `json:"paper_shape_vhead_bytes"`
	PaperShapeVBarBytes  int                       `json:"paper_shape_vbar_bytes"`
}

type baselineGeometryProjection struct {
	CanonicalPresetID string               `json:"canonical_preset_id"`
	PresetVersion     int                  `json:"preset_version"`
	ManifestDigest    string               `json:"manifest_digest"`
	Profile           string               `json:"profile"`
	PrimitiveProfile  string               `json:"primitive_profile"`
	Modulus           uint64               `json:"modulus"`
	ProfileBound      int64                `json:"profile_bound"`
	MaxNLeaves        int                  `json:"max_nleaves"`
	Options           benchmarkOptionsWire `json:"options"`
	Issuance          PhaseEvidence        `json:"issuance"`
	Showing           PhaseEvidence        `json:"showing"`
}

type baselineSecurityProjection struct {
	ThreatModel                credential.PresetThreatModel                `json:"threat_model"`
	LedgerStatus               string                                      `json:"ledger_status"`
	LedgerReasons              []string                                    `json:"ledger_reasons"`
	LedgerTerms                []credential.SystemSecurityLedgerTerm       `json:"ledger_terms"`
	CoreBitsRequired           float64                                     `json:"core_bits_required"`
	CoreBitsAvailable          float64                                     `json:"core_bits_available"`
	SoundnessBits              float64                                     `json:"soundness_bits"`
	UnlinkabilityBits          float64                                     `json:"unlinkability_bits"`
	CorrectnessBits            float64                                     `json:"correctness_bits"`
	PrimitiveBits              float64                                     `json:"primitive_bits"`
	CompositionBits            float64                                     `json:"composition_bits"`
	ZeroKnowledgeBits          float64                                     `json:"zero_knowledge_bits"`
	RequiredPhaseAlgebraicBits float64                                     `json:"required_phase_algebraic_bits"`
	PhaseAlgebraicSlackBits    float64                                     `json:"phase_algebraic_slack_bits"`
	DominantSoundnessLimiter   string                                      `json:"dominant_soundness_limiter"`
	TagCollisionBits           float64                                     `json:"tag_collision_bits"`
	SaltCollisionBits          float64                                     `json:"salt_collision_bits"`
	TapeGuessingBits           float64                                     `json:"tape_guessing_bits"`
	ProgrammingBits            float64                                     `json:"programming_bits"`
	ChallengeBiasBits          float64                                     `json:"challenge_bias_bits"`
	FullGame                   PIOP.FullGameSoundnessReport                `json:"full_game"`
	SecurityLedger             credential.SystemSecurityLedger             `json:"security_ledger"`
	ParameterAudit             credential.IntGenISISSecurityParameterAudit `json:"parameter_audit"`
	ValidPrefixCost            credential.ValidPrefixCostReport            `json:"valid_prefix_cost"`
	Issuance                   baselinePhaseSecurity                       `json:"issuance"`
	Showing                    baselinePhaseSecurity                       `json:"showing"`
}

type baselinePhaseSecurity struct {
	RoundBits                [4]float64 `json:"round_bits"`
	RawRoundBits             [4]float64 `json:"raw_round_bits"`
	TheoremBits              [4]float64 `json:"theorem_bits"`
	TheoremTotalBits         float64    `json:"theorem_total_bits"`
	ROQueryCaps              [5]int     `json:"ro_query_caps"`
	ROQueryCapBits           [5]float64 `json:"ro_query_cap_bits"`
	CollisionSpaceBits       int        `json:"collision_space_bits"`
	FSLambdaBits             int        `json:"fs_lambda_bits"`
	EffectiveLambdaBits      int        `json:"effective_lambda_bits"`
	DECSHashBits             int        `json:"decs_hash_bits"`
	DECSTapeBits             int        `json:"decs_tape_bits"`
	SaltBits                 int        `json:"salt_bits"`
	AlgebraicTerms           [4]float64 `json:"algebraic_terms"`
	AlgebraicBits            [4]float64 `json:"algebraic_bits"`
	AlgebraicTotal           float64    `json:"algebraic_total"`
	AlgebraicTotalBits       float64    `json:"algebraic_total_bits"`
	Collision                float64    `json:"collision"`
	CollisionBits            float64    `json:"collision_bits"`
	OneProofTotal            float64    `json:"one_proof_total"`
	OneProofTotalBits        float64    `json:"one_proof_total_bits"`
	Clamped                  [4]bool    `json:"clamped"`
	SoundnessEq8Bits         float64    `json:"soundness_eq8_bits"`
	TranscriptSecurityStatus string     `json:"transcript_security_status"`
	MeasurementStatus        string     `json:"measurement_status"`
	ZeroKnowledgeEligible    bool       `json:"zero_knowledge_eligible"`
}

type baselineStabilityProjection struct {
	Bytes       baselineBytesProjection    `json:"bytes"`
	Geometry    baselineGeometryProjection `json:"geometry"`
	Security    baselineSecurityProjection `json:"security"`
	Environment benchmarkEnvironmentWire   `json:"environment"`
}

func validateThreeRunStability(reports [BaselineRunCountV2]benchmarkReportWire) (BaselineStability, error) {
	projections := [BaselineRunCountV2]baselineStabilityProjection{}
	for i := range reports {
		projections[i] = makeBaselineStabilityProjection(reports[i])
	}
	for i := 1; i < len(projections); i++ {
		if !reflect.DeepEqual(projections[0].Bytes, projections[i].Bytes) {
			return BaselineStability{}, fmt.Errorf("byte accounting differs between runs 1 and %d", i+1)
		}
		if !reflect.DeepEqual(projections[0].Geometry, projections[i].Geometry) {
			return BaselineStability{}, fmt.Errorf("geometry/relation accounting differs between runs 1 and %d", i+1)
		}
		if !reflect.DeepEqual(projections[0].Security, projections[i].Security) {
			return BaselineStability{}, fmt.Errorf("security accounting differs between runs 1 and %d", i+1)
		}
		if !reflect.DeepEqual(projections[0].Environment, projections[i].Environment) {
			return BaselineStability{}, fmt.Errorf("benchmark environment differs between runs 1 and %d", i+1)
		}
	}
	encoded, err := json.Marshal(projections[0])
	if err != nil {
		return BaselineStability{}, fmt.Errorf("encode stability projection: %w", err)
	}
	digest := sha256.Sum256(append([]byte("spruce-three-run-stability-v2\x00"), encoded...))
	return BaselineStability{
		Bytes: true, Geometry: true, Security: true, Environment: true,
		Digest: hex.EncodeToString(digest[:]),
	}, nil
}

func makeBaselineStabilityProjection(report benchmarkReportWire) baselineStabilityProjection {
	return baselineStabilityProjection{
		Bytes: baselineBytesProjection{
			Issuance: makeBaselinePhaseBytes(report.Issuance, report.Options.Issuance, false),
			Showing:  makeBaselinePhaseBytes(report.Showing, report.Options.Showing, true),
		},
		Geometry:    makeBaselineGeometryProjection(report),
		Security:    makeBaselineSecurityProjection(report),
		Environment: report.Environment,
	}
}

func makeBaselinePhaseBytes(phase benchmarkPhaseWire, tuning benchmarkTuningWire, showing bool) baselinePhaseBytes {
	evidence := phaseEvidenceFromReport(phase, tuning, showing)
	return baselinePhaseBytes{
		WireSizes: evidence.WireSizes, PaperTranscriptKB: phase.PaperTranscriptKB,
		TapeBytes: phase.TapeBytes, TapeCount: phase.TapeCount, TapeWidthBytes: phase.TapeWidthBytes,
		RootWidthBytes: phase.RootWidthBytes, TranscriptAudit: phase.TranscriptAudit,
		PaperShapeVHeadBytes: phase.PaperShapeVHeadBytes, PaperShapeVBarBytes: phase.PaperShapeVBarBytes,
	}
}

func makeBaselineGeometryProjection(report benchmarkReportWire) baselineGeometryProjection {
	issuance := phaseEvidenceFromReport(report.Issuance, report.Options.Issuance, false)
	showing := phaseEvidenceFromReport(report.Showing, report.Options.Showing, true)
	for _, phase := range []*PhaseEvidence{&issuance, &showing} {
		phase.Security = PhaseSecurity{}
		phase.WireSizes = PhaseWireSizes{}
		phase.Timings = PhaseTimings{}
	}
	return baselineGeometryProjection{
		CanonicalPresetID: report.CanonicalPresetID, PresetVersion: report.PresetVersion,
		ManifestDigest: report.PresetManifestDigest, Profile: report.Profile,
		PrimitiveProfile: report.PrimitiveProfileID, Modulus: report.Modulus,
		ProfileBound: report.ProfileBound, MaxNLeaves: report.MaxNLeaves,
		Options: report.Options, Issuance: issuance, Showing: showing,
	}
}

func makeBaselineSecurityProjection(report benchmarkReportWire) baselineSecurityProjection {
	return baselineSecurityProjection{
		ThreatModel: report.ThreatModel, LedgerStatus: report.LedgerStatus,
		LedgerReasons:    append([]string(nil), report.LedgerReasons...),
		LedgerTerms:      append([]credential.SystemSecurityLedgerTerm(nil), report.LedgerTerms...),
		CoreBitsRequired: report.CoreBitsRequired, CoreBitsAvailable: report.CoreAvailableBits,
		SoundnessBits: report.SoundnessBits, UnlinkabilityBits: report.UnlinkabilityBits,
		CorrectnessBits: report.CorrectnessBits, PrimitiveBits: report.PrimitiveBits,
		CompositionBits: report.CompositionBits, ZeroKnowledgeBits: report.ZeroKnowledgeBits,
		RequiredPhaseAlgebraicBits: report.RequiredPhaseAlgebraicBits,
		PhaseAlgebraicSlackBits:    report.PhaseAlgebraicSlackBits,
		DominantSoundnessLimiter:   report.DominantSoundnessLimiter,
		TagCollisionBits:           report.TagCollisionBits, SaltCollisionBits: report.SaltCollisionBits,
		TapeGuessingBits: report.TapeGuessingBits, ProgrammingBits: report.ProgrammingBits,
		ChallengeBiasBits: report.ChallengeBiasBits, FullGame: report.FullGame,
		SecurityLedger: report.SecurityLedger, ParameterAudit: report.ParameterAudit,
		ValidPrefixCost: stableValidPrefixCost(report.ValidPrefixCost),
		Issuance:        makeBaselinePhaseSecurity(report.Issuance),
		Showing:         makeBaselinePhaseSecurity(report.Showing),
	}
}

// Valid-prefix measurements deliberately contain wall-clock-derived cost
// estimates.  They belong with the independently aggregated timings, not in
// the invariant security projection.  Preserve every structural and theorem
// accounting field while removing only the two measured scalars from each
// round before comparing the three runs.
func stableValidPrefixCost(report credential.ValidPrefixCostReport) credential.ValidPrefixCostReport {
	stable := report
	stable.Rounds = append([]credential.ValidPrefixRoundCost(nil), report.Rounds...)
	stable.Notes = append([]string(nil), report.Notes...)
	for i := range stable.Rounds {
		stable.Rounds[i].StructuralPrerequisites = append([]string(nil), report.Rounds[i].StructuralPrerequisites...)
		stable.Rounds[i].MeasuredCumulativeMS = 0
		stable.Rounds[i].EstimatedHashEquivalentLog2 = 0
	}
	return stable
}

func makeBaselinePhaseSecurity(phase benchmarkPhaseWire) baselinePhaseSecurity {
	return baselinePhaseSecurity{
		RoundBits: phase.RoundBits, RawRoundBits: phase.RawRoundBits, TheoremBits: phase.TheoremBits,
		TheoremTotalBits: phase.TheoremTotalBits, ROQueryCaps: phase.ROQueryCaps,
		ROQueryCapBits: phase.ROQueryCapBits, CollisionSpaceBits: phase.CollisionSpaceBits,
		FSLambdaBits: phase.FSLambdaBits, EffectiveLambdaBits: phase.EffectiveLambdaBits,
		DECSHashBits: phase.DECSHashBits, DECSTapeBits: phase.DECSTapeBits, SaltBits: phase.SaltBits,
		AlgebraicTerms: phase.AlgebraicTerms, AlgebraicBits: phase.AlgebraicBits,
		AlgebraicTotal: phase.AlgebraicTotal, AlgebraicTotalBits: phase.AlgebraicTotalBits,
		Collision: phase.Collision, CollisionBits: phase.CollisionBits,
		OneProofTotal: phase.OneProofTotal, OneProofTotalBits: phase.OneProofTotalBits,
		Clamped: phase.Clamped, SoundnessEq8Bits: phase.SoundnessEq8Bits,
		TranscriptSecurityStatus: phase.TranscriptSecurityStatus,
		MeasurementStatus:        phase.MeasurementStatus, ZeroKnowledgeEligible: phase.ZeroKnowledgeEligible,
	}
}

func medianBaselineTimings(reports [BaselineRunCountV2]benchmarkReportWire) BaselineTimings {
	return BaselineTimings{
		Setup: SetupTimings{
			SetupPublicMS:    median3(reports[0].Timings.SetupPublicMS, reports[1].Timings.SetupPublicMS, reports[2].Timings.SetupPublicMS),
			SetupNTRUKeysMS:  median3(reports[0].Timings.SetupNTRUKeysMS, reports[1].Timings.SetupNTRUKeysMS, reports[2].Timings.SetupNTRUKeysMS),
			HolderCommitMS:   median3(reports[0].Timings.HolderCommitMS, reports[1].Timings.HolderCommitMS, reports[2].Timings.HolderCommitMS),
			HolderProveMS:    median3(reports[0].Timings.HolderProveMS, reports[1].Timings.HolderProveMS, reports[2].Timings.HolderProveMS),
			IssuerSignMS:     median3(reports[0].Timings.IssuerSignMS, reports[1].Timings.IssuerSignMS, reports[2].Timings.IssuerSignMS),
			HolderFinalizeMS: median3(reports[0].Timings.HolderFinalizeMS, reports[1].Timings.HolderFinalizeMS, reports[2].Timings.HolderFinalizeMS),
		},
		Issuance: PhaseTimings{
			ProvingMS:      median3(reports[0].Issuance.ProvingMS, reports[1].Issuance.ProvingMS, reports[2].Issuance.ProvingMS),
			VerificationMS: median3(reports[0].Issuance.VerificationMS, reports[1].Issuance.VerificationMS, reports[2].Issuance.VerificationMS),
		},
		Showing: PhaseTimings{
			ProvingMS:      median3(reports[0].Showing.ProvingMS, reports[1].Showing.ProvingMS, reports[2].Showing.ProvingMS),
			VerificationMS: median3(reports[0].Showing.VerificationMS, reports[1].Showing.VerificationMS, reports[2].Showing.VerificationMS),
		},
	}
}

func median3(a, b, c float64) float64 {
	values := []float64{a, b, c}
	sort.Float64s(values)
	return values[1]
}
