package main

import (
	"encoding/json"
	"math"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func TestPublicationSmallFieldMetadataProjectionMatchesStrictAccounting(t *testing.T) {
	if got := publicationSmallFieldMetadataBytes(); got != 476 {
		t.Fatalf("small-field metadata bytes=%d want 476", got)
	}
	if publicationLambdaBits != 256 {
		t.Fatalf("paper lambda=%d want 256", publicationLambdaBits)
	}
}

func TestPublicationPaperProjectionIncludesPackedBarFrame(t *testing.T) {
	preset, ok := credential.LookupIntGenISISPublicationPreset(credential.IntGenISISPublicationPresetBQ96Q32V4)
	if !ok {
		t.Fatal("missing BQ96-32 publication preset")
	}
	tuning := preset.Showing
	tuning.LVCSNCols, tuning.NLeaves, tuning.Eta = 43, 987291, 47
	tuning.Theta, tuning.Ell, tuning.Kappa = 7, 8, [4]int{0, 0, 0, 13}
	tuning.SigShortnessRadix, tuning.SigShortnessDigits = 11, 4
	geometry, err := publicationGeometry(tuning.LVCSNCols, tuning.Theta, tuning.Ell, 423, 11)
	if err != nil {
		t.Fatal(err)
	}
	_, paper, _, err := publicationPhaseProjection(newPublicationSearchCache(), tuning, geometry)
	if err != nil {
		t.Fatal(err)
	}
	// This is the exact strict-accounting total observed by serialization for
	// this geometry: 35,749 payload/fixed bytes plus BarSets' 10-byte frame.
	if paper != 35759 {
		t.Fatalf("paper projection=%d want 35759", paper)
	}
}

func TestPublicationRankingPlacesSlackBeforeLexicographicNLeaves(t *testing.T) {
	base := publicationCandidateBinding{Projection: &publicationCandidateProjection{ShowingProofMaxBytes: 1}}
	lowSlackSmallN := base
	lowSlackSmallN.Showing.NLeaves = 100
	lowSlackSmallN.Projection = &publicationCandidateProjection{ShowingProofMaxBytes: 1, MinimumSecuritySlack: 0.1}
	highSlackLargeN := base
	highSlackLargeN.Showing.NLeaves = 200
	highSlackLargeN.Projection = &publicationCandidateProjection{ShowingProofMaxBytes: 1, MinimumSecuritySlack: 0.2}
	if !publicationBindingLess(highSlackLargeN, lowSlackSmallN) {
		t.Fatal("security slack must precede NLeaves in the publication ordering")
	}
}

func TestPublicationEnvelopeExpansionUsesPrescribedSteps(t *testing.T) {
	base := publicationInitialEnvelope()
	got, ok := publicationExpandEnvelope(base, map[string]bool{
		"l_issuance_upper": true, "l_showing_upper": true, "theta_upper": true, "ell_upper": true,
	})
	if !ok || got.LIssuanceMax != base.LIssuanceMax+16 || got.LShowingMax != base.LShowingMax+16 ||
		got.ThetaMax != base.ThetaMax+2 || got.EllMax != base.EllMax+4 {
		t.Fatalf("unexpected expanded envelope: %+v", got)
	}
}

func TestPublicationCertifiedLowerFloorDoesNotBlockUpperExpansion(t *testing.T) {
	base := publicationInitialEnvelope()
	binding := publicationCandidateBinding{}
	binding.Issuance.LVCSNCols = base.LIssuanceMin
	binding.Showing.LVCSNCols = base.LShowingMin + 1
	binding.Showing.Theta = base.ThetaMin
	binding.Showing.Ell = base.EllMin
	if !publicationBindingInterior(binding, base) {
		t.Fatal("a tuple on certified lower support floors must be interior with respect to expandable boundaries")
	}
	support, expandable := publicationSplitBoundaryHits([]string{"l_issuance_lower", "theta_lower", "l_showing_upper"})
	if len(support) != 2 || len(expandable) != 1 || expandable[0] != "l_showing_upper" {
		t.Fatalf("unexpected boundary partition support=%v expandable=%v", support, expandable)
	}
	next, expanded := publicationExpandEnvelope(base, map[string]bool{expandable[0]: true})
	if !expanded || next.LShowingMax != base.LShowingMax+16 || next.LIssuanceMax != base.LIssuanceMax {
		t.Fatalf("lower support hit blocked or distorted upper expansion: %+v", next)
	}
}

func TestPublicationBenchmarkConfigExactlyMatchesManifestTunings(t *testing.T) {
	for _, preset := range credential.IntGenISISPublicationPresetsV4() {
		preset := preset
		t.Run(preset.PublicationLabel, func(t *testing.T) {
			cfg, err := parseBenchmarkIntGenISISE2EConfig([]string{"-preset", preset.CanonicalID})
			if err != nil {
				t.Fatal(err)
			}
			wantIssuance := intGenISISTuningFromPresetSpec(preset.Issuance)
			wantShowing := intGenISISTuningFromPresetSpec(preset.Showing)
			if cfg.Issuance != wantIssuance || cfg.Showing != wantShowing {
				t.Fatalf("benchmark tuning differs from manifest\nissuance got=%+v want=%+v\nshowing got=%+v want=%+v", cfg.Issuance, wantIssuance, cfg.Showing, wantShowing)
			}
			if cfg.Issuance.PresetID != preset.CanonicalID || cfg.Showing.PresetID != preset.CanonicalID {
				t.Fatalf("phase preset IDs=%q/%q want %q", cfg.Issuance.PresetID, cfg.Showing.PresetID, preset.CanonicalID)
			}
		})
	}
}

func TestPublicationIssuanceOverridesClearInheritedLegacyQueryCaps(t *testing.T) {
	legacy := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{})
	if legacy.ROQueryCaps == [5]int{} {
		t.Fatal("test precondition: historical defaults have no query caps")
	}
	for _, presetID := range []string{
		credential.IntGenISISPublicationPresetBQ96Q32V4,
		credential.IntGenISISPublicationPresetWF128V4,
	} {
		preset, ok := credential.LookupIntGenISISPublicationPreset(presetID)
		if !ok {
			t.Fatalf("missing publication preset %s", presetID)
		}
		got := applyIssuanceRuntimeOverrides(legacy, intGenISISTuningToIssuanceOverrides(intGenISISTuningFromPresetSpec(preset.Issuance), credential.Ternary1024IntGenISISProfile().N))
		if got.ROQueryCaps != [5]int{} || got.ROQueryCapsSet || got.ROQueryCapBits != [5]float64{} || got.ROQueryCapBitsSet {
			t.Fatalf("%s retained inherited legacy query caps: %+v", presetID, got)
		}
		if preset.ThreatModel.AggregateROQueryCapLog2Set {
			if !got.AggregateROQueryCapLog2Set || got.AggregateROQueryCapLog2 != preset.ThreatModel.AggregateROQueryCapLog2 {
				t.Fatalf("%s lost its sole aggregate Q scalar: %+v", presetID, got)
			}
		} else if got.AggregateROQueryCapLog2Set || got.AggregateROQueryCapLog2 != 0 {
			t.Fatalf("%s materialized an aggregate Q scalar: %+v", presetID, got)
		}
	}
}

func TestPublicationLiveExplicitSeedPreservesBothPhaseTuples(t *testing.T) {
	for _, preset := range credential.IntGenISISPublicationPresetsV4() {
		preset := preset
		t.Run(preset.PublicationLabel, func(t *testing.T) {
			seeds := publicationSeedTunings(preset)
			if len(seeds) == 0 {
				t.Fatal("publication search omitted the live incumbent seed")
			}
			if seeds[0].Issuance != preset.Issuance || seeds[0].Showing != preset.Showing {
				t.Fatalf("live seed flattened phase-specific tuning\nissuance got=%+v want=%+v\nshowing got=%+v want=%+v", seeds[0].Issuance, preset.Issuance, seeds[0].Showing, preset.Showing)
			}
			binding, err := publicationProjectExplicitSeed(newPublicationSearchCache(), preset, seeds[0])
			if err != nil {
				t.Fatalf("project live incumbent: %v", err)
			}
			if binding.Issuance != preset.Issuance || binding.Showing != preset.Showing {
				t.Fatalf("projected live seed changed a phase tuple\nissuance got=%+v want=%+v\nshowing got=%+v want=%+v", binding.Issuance, preset.Issuance, binding.Showing, preset.Showing)
			}
			if binding.SelectionStatus != "adopted_manifest_measurement_pending" {
				t.Fatalf("live incumbent selection status=%q", binding.SelectionStatus)
			}
		})
	}
}

func TestPublicationSecurityParameterAuditActualsPassAllFive(t *testing.T) {
	for _, preset := range credential.IntGenISISPublicationPresetsV4() {
		preset := preset
		t.Run(preset.PublicationLabel, func(t *testing.T) {
			cfg, err := parseBenchmarkIntGenISISE2EConfig([]string{"-preset", preset.CanonicalID})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ClaimScope != credential.ClaimProofOnly || cfg.CompleteSystemClaim {
				t.Fatalf("publication preset escaped proof-only scope: claim=%q complete=%v", cfg.ClaimScope, cfg.CompleteSystemClaim)
			}
			tagElements, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
			if !ok {
				t.Fatal("unknown PRF profile")
			}
			actual := credential.IntGenISISSecurityParameterActuals{
				DECSHashBits: preset.Showing.DECSHashBits, DECSTapeBits: preset.Showing.DECSTapeBits,
				FSCollisionBits: preset.Showing.FSCollisionBits, SaltBits: preset.Showing.SaltBits,
				PRFTagElements: tagElements, PRFProfile: preset.PRFProfile, TranscriptMode: credential.IntGenISISTranscriptProtocolV4,
				Evidence: map[string]string{
					"decs_hash_bits": credential.SecurityEvidenceMeasured, "decs_tape_bits": credential.SecurityEvidenceMeasured,
					"fs_collision_bits": credential.SecurityEvidenceMeasured, "salt_bits": credential.SecurityEvidenceMeasured,
					"prf_tag_elements": credential.SecurityEvidenceLoadedParams, "prf_profile": credential.SecurityEvidenceLoadedParams,
					"transcript_mode": credential.SecurityEvidenceMeasured,
				},
			}
			issuance := benchmarkIntGenISISMetrics{FSOutputBits: preset.Issuance.FSOutputBits, AggregateQueryBudget: preset.Issuance.AggregateROQueryCapLog2Set, AggregateQueryCapLog2: preset.Issuance.AggregateROQueryCapLog2}
			showing := benchmarkIntGenISISMetrics{FSOutputBits: preset.Showing.FSOutputBits, AggregateQueryBudget: preset.Showing.AggregateROQueryCapLog2Set, AggregateQueryCapLog2: preset.Showing.AggregateROQueryCapLog2}
			benchmarkPopulatePublicationV4AuditActuals(cfg, issuance, showing, &actual)
			spec, ok := credential.LookupIntGenISISSecurityProfile(preset.SecurityProfile)
			if !ok {
				t.Fatal("missing publication security profile")
			}
			audit := credential.AuditIntGenISISSecurityParameters(spec, actual)
			if audit.Status != "pass" || len(audit.MissingActual) != 0 || len(audit.MissingEvidence) != 0 || len(audit.Mismatches) != 0 {
				t.Fatalf("publication parameter audit rejected measured tuple: %+v", audit)
			}
		})
	}
}

func TestPublicationBenchmarkTranscriptModeUsesExactProofTuple(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		protocol string
		want     string
	}{
		{"v2", PIOP.TranscriptVersionSmallWood2025V2, PIOP.TranscriptProtocolSmallField2025V2, credential.IntGenISISTranscriptProtocolV2},
		{"v3", PIOP.TranscriptVersionSmallWood2025V3, PIOP.TranscriptProtocolSmallField2025V3, credential.IntGenISISTranscriptProtocolV3},
		{"v4", PIOP.TranscriptVersionSmallWood2025V4, PIOP.TranscriptProtocolSmallField2025V4, credential.IntGenISISTranscriptProtocolV4},
		{"cross-version-mutation", PIOP.TranscriptVersionSmallWood2025V4, PIOP.TranscriptProtocolSmallField2025V3, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof := &PIOP.Proof{TranscriptVersion: tc.version, TranscriptProtocolMode: tc.protocol}
			if got := benchmarkTranscriptModeFromProof(proof); got != tc.want {
				t.Fatalf("reported transcript mode=%q want %q", got, tc.want)
			}
		})
	}
	if got := benchmarkTranscriptModeFromProof(nil); got != "" {
		t.Fatalf("nil proof reported transcript mode %q", got)
	}
}

func TestPublicationRawReportSerializesMeasuredV4TranscriptMode(t *testing.T) {
	proof := &PIOP.Proof{
		TranscriptVersion:      PIOP.TranscriptVersionSmallWood2025V4,
		TranscriptProtocolMode: PIOP.TranscriptProtocolSmallField2025V4,
	}
	mode := benchmarkTranscriptModeFromProof(proof)
	report := benchmarkIntGenISISE2EReport{
		Issuance: benchmarkIntGenISISMetrics{TranscriptMode: mode},
		Showing:  benchmarkIntGenISISMetrics{TranscriptMode: mode},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Issuance struct {
			TranscriptMode string `json:"transcript_mode"`
		} `json:"issuance"`
		Showing struct {
			TranscriptMode string `json:"transcript_mode"`
		} `json:"showing"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Issuance.TranscriptMode != credential.IntGenISISTranscriptProtocolV4 || decoded.Showing.TranscriptMode != credential.IntGenISISTranscriptProtocolV4 {
		t.Fatalf("raw report transcript modes=%q/%q want V4", decoded.Issuance.TranscriptMode, decoded.Showing.TranscriptMode)
	}
}

func TestPublicationCanonicalShapeRequiresMatchingVersionStatus(t *testing.T) {
	v3 := &PIOP.Proof{TranscriptVersion: PIOP.TranscriptVersionSmallWood2025V3, TranscriptProtocolMode: PIOP.TranscriptProtocolSmallField2025V3}
	v4 := &PIOP.Proof{TranscriptVersion: PIOP.TranscriptVersionSmallWood2025V4, TranscriptProtocolMode: PIOP.TranscriptProtocolSmallField2025V4}
	if PIOP.SmallField2025StatusLiveV4 != credential.IntGenISISSecurityGateV4 {
		t.Fatalf("PIOP V4 status=%q disagrees with manifest gate %q", PIOP.SmallField2025StatusLiveV4, credential.IntGenISISSecurityGateV4)
	}
	if !benchmarkStrictTranscriptStatusMatchesProof(v3, credential.IntGenISISSecurityGateV3) || !benchmarkStrictTranscriptStatusMatchesProof(v4, credential.IntGenISISSecurityGateV4) {
		t.Fatal("exact V3/V4 version-status tuples were rejected")
	}
	if benchmarkStrictTranscriptStatusMatchesProof(v3, credential.IntGenISISSecurityGateV4) || benchmarkStrictTranscriptStatusMatchesProof(v4, credential.IntGenISISSecurityGateV3) {
		t.Fatal("cross-version transcript status was accepted as canonical")
	}
}

func TestPublicationBenchmarkScheduleHasExactFunnel(t *testing.T) {
	lock := publicationCandidateLock{}
	for _, preset := range credential.IntGenISISPublicationPresetsV4() {
		result := publicationPresetSearchResult{CanonicalID: preset.CanonicalID}
		for rank := 1; rank <= publicationFinalistCount; rank++ {
			result.Finalists = append(result.Finalists, publicationCandidateBinding{CandidateDigest: preset.CanonicalID + string(rune(rank))})
		}
		lock.Presets = append(lock.Presets, result)
	}
	schedule, err := publicationBenchmarkSchedule(lock, publicationDefaultRuns)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(schedule), publicationPresetCount*(publicationFinalistCount+2*3+publicationDefaultRuns); got != want {
		t.Fatalf("schedule entries=%d want %d", got, want)
	}
	stages := map[string]int{}
	for i, entry := range schedule {
		if entry.Sequence != i+1 {
			t.Fatalf("sequence[%d]=%d", i, entry.Sequence)
		}
		stages[entry.Stage]++
	}
	if stages["screening"] != 60 || stages["confirmation"] != 30 || stages["final"] != 35 {
		t.Fatalf("stage counts=%v", stages)
	}
}

func TestBenchmarkFiniteFullGameReportReplacesOnlyNonFiniteSentinels(t *testing.T) {
	report := PIOP.FullGameSoundnessReport{
		IssuanceQueryCapBits: [5]float64{math.Inf(-1), 1, 2, 3, 4},
		ShowingQueryCapBits:  [5]float64{5, math.Inf(1), 6, 7, 8},
		GlobalQueryCapBits:   [5]float64{64, math.Inf(-1), -1, math.NaN(), 0},
	}
	got := benchmarkFiniteFullGameReport(report)
	if got.GlobalQueryCapBits != [5]float64{64, -1, -1, -1, 0} {
		t.Fatalf("finite full-game cap vector=%v", got.GlobalQueryCapBits)
	}
	if got.IssuanceQueryCapBits != [5]float64{-1, 1, 2, 3, 4} || got.ShowingQueryCapBits != [5]float64{5, -1, 6, 7, 8} {
		t.Fatalf("finite phase cap vectors=%v/%v", got.IssuanceQueryCapBits, got.ShowingQueryCapBits)
	}
}

func TestBenchmarkWorkFactorProjectionUsesFiniteNativeBits(t *testing.T) {
	sb := PIOP.SoundnessBudget{
		WorkFactorMode:       true,
		WorkFactorBits:       128,
		CollisionSpaceBits:   256,
		DECSTapeBits:         136,
		WorkFactorComponents: [6]float64{128, 129, 130, 131, 132, 136},
		NativeAlgebraicBits:  [4]float64{129, 130, 131, 132},
		NativeAlgebraicTerms: [4]float64{math.Exp2(-129), math.Exp2(-130), math.Exp2(-131), math.Exp2(-132)},
	}
	metrics := benchmarkIntGenISISMetrics{
		RawRoundBits:       [4]float64{129, 130, math.Inf(1), 132},
		RoundBits:          [4]float64{129, 130, math.Inf(1), 132},
		TheoremBits:        [4]float64{math.Inf(1), math.Inf(1), math.Inf(1), math.Inf(1)},
		AlgebraicBits:      [4]float64{math.Inf(1), math.Inf(1), math.Inf(1), math.Inf(1)},
		AlgebraicTotalBits: math.Inf(1),
		CollisionBits:      math.Inf(1),
		ROQueryCapBits:     [5]float64{math.Inf(-1), math.Inf(-1), math.Inf(-1), math.Inf(-1), math.Inf(-1)},
	}
	benchmarkProjectWorkFactorMetrics(&metrics, sb)
	if !metrics.WorkFactorMode || metrics.WorkFactorBits != 128 || metrics.WorkFactorComponents != sb.WorkFactorComponents || metrics.NativeAlgebraicBits != sb.NativeAlgebraicBits || metrics.NativeAlgebraicTerms != sb.NativeAlgebraicTerms {
		t.Fatalf("unexpected work-factor projection: %+v", metrics)
	}
	if metrics.TheoremBits != [4]float64{-1, -1, -1, -1} || metrics.AlgebraicBits != [4]float64{-1, -1, -1, -1} || metrics.AlgebraicTotalBits != -1 || metrics.TheoremTotalBits != -1 || metrics.CollisionBits != -1 || metrics.OneProofTotalBits != -1 {
		t.Fatalf("query-adjusted WF quantities were relabeled instead of marked inapplicable: %+v", metrics)
	}
	if metrics.RawRoundBits[2] != -1 || metrics.RoundBits[2] != -1 || metrics.ROQueryCapBits != [5]float64{-1, -1, -1, -1, -1} {
		t.Fatalf("non-finite sentinels were not normalized: raw=%v round=%v caps=%v", metrics.RawRoundBits, metrics.RoundBits, metrics.ROQueryCapBits)
	}
	if _, err := json.Marshal(metrics); err != nil {
		t.Fatalf("finite work-factor metrics did not serialize: %v", err)
	}
}

func TestBenchmarkPublicationV4QueryCapsUseOnlyFiniteNonApplicableSentinels(t *testing.T) {
	metrics := benchmarkIntGenISISMetrics{
		ROQueryCapBits: [5]float64{math.Inf(-1), math.Inf(-1), math.Inf(-1), math.Inf(-1), math.Inf(-1)},
	}
	proof := &PIOP.Proof{
		TranscriptVersion:      PIOP.TranscriptVersionSmallWood2025V4,
		TranscriptProtocolMode: PIOP.TranscriptProtocolSmallField2025V4,
	}
	benchmarkProjectPublicationV4QueryCaps(&metrics, proof)
	if metrics.ROQueryCaps != [5]int{} || metrics.ROQueryCapBits != [5]float64{-1, -1, -1, -1, -1} {
		t.Fatalf("publication-v4 query-cap projection=%v/%v", metrics.ROQueryCaps, metrics.ROQueryCapBits)
	}
	if _, err := json.Marshal(metrics); err != nil {
		t.Fatalf("publication-v4 query-cap projection is not finite JSON: %v", err)
	}
}

func TestBenchmarkDarwinCPUIdentityHasNormalizedFeatureBaseline(t *testing.T) {
	model, features := benchmarkNormalizeDarwinCPUIdentity(
		"arm64",
		"  Apple   M5 Pro ",
		"",
		"",
		"hw.optional.arm.FEAT_SHA3: 1\nhw.optional.arm.FEAT_AES: 1\nhw.optional.arm.FEAT_MTE3: 0\n",
	)
	if model != "Apple M5 Pro" || features != "hw.optional.arm.feat_aes hw.optional.arm.feat_sha3 isa=arm64" {
		t.Fatalf("normalized Darwin CPU identity=%q/%q", model, features)
	}
	_, baseline := benchmarkNormalizeDarwinCPUIdentity("arm64", "", "", "", "")
	if baseline != "isa=arm64" {
		t.Fatalf("Darwin CPU feature fallback=%q want arm64 ISA baseline", baseline)
	}
}

func TestBenchmarkMachineDigestBindsCPUFeatures(t *testing.T) {
	base := benchmarkIntGenISISE2EEnvironment{
		GoVersion: "go-test", GOOS: "darwin", GOARCH: "arm64", CPUModel: "Apple M5 Pro", CPUFeatures: "isa=arm64",
		NumCPU: 12, GOMAXPROCS: 12,
	}
	first, err := benchmarkMachineDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	base.CPUFeatures += " hw.optional.arm.feat_sha3"
	second, err := benchmarkMachineDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first == "" || second == "" {
		t.Fatalf("machine digest did not bind normalized CPU features: %q/%q", first, second)
	}
}
