package credential

import (
	"math"
	"reflect"
	"testing"
)

func TestPublicationPresetNamesV4AreExactAndOrdered(t *testing.T) {
	want := []string{
		"publication-n1024-bq-r96-q32-v4",
		"publication-n1024-bq-r96-q96-v4",
		"publication-n1024-wf128-v4",
		"publication-n1024-bq-r128-q64-v4",
		"publication-n1024-bq-r128-q128-v4",
	}
	got := IntGenISISPublicationPresetNamesV4()
	if len(got) != len(want) {
		t.Fatalf("publication presets=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("publication presets=%v want %v", got, want)
		}
		preset, ok := LookupIntGenISISPublicationPreset(got[i])
		if !ok || preset.CanonicalID != want[i] || preset.Name != want[i] {
			t.Fatalf("publication lookup %q=(%+v,%v)", got[i], preset, ok)
		}
	}
	got[0] = "mutated"
	if IntGenISISPublicationPresetNamesV4()[0] != want[0] {
		t.Fatal("publication preset-name API exposed mutable shared storage")
	}
	if _, ok := LookupIntGenISISPublicationPreset(IntGenISISPresetPilotN1024BQ32R96V2); ok {
		t.Fatal("historical preset resolved through the exact publication-v4 API")
	}
}

func TestPublicationPresetManifestDigestsV4AreFrozen(t *testing.T) {
	want := map[string]string{
		IntGenISISPublicationPresetBQ96Q32V4:   "a3a894f478ebde1394b5ff359c9660650d75cf883fba7724f0c5d2aa5b9d5d16",
		IntGenISISPublicationPresetBQ96Q96V4:   "6bc98e6635f4cfbecce47aceaa3b535f812baaa392fd401a3dbf7262ac9d7682",
		IntGenISISPublicationPresetWF128V4:     "d7fde513c629ff80f1ed35c859da3b021c3a90c8ccd9a609709e5935e204d17a",
		IntGenISISPublicationPresetBQ128Q64V4:  "01e6077bb1f0346c8e0e0d4f0e48c2ccc5bad63334e5c45f959df3b7b23f2689",
		IntGenISISPublicationPresetBQ128Q128V4: "1a35ce0e355e8a0eb3045bef60a7b5d0799e95b7d9a0ad7bc88ddea7673afb58",
	}
	for id, digest := range want {
		preset, ok := LookupIntGenISISPublicationPreset(id)
		if !ok {
			t.Fatalf("missing publication preset %s", id)
		}
		if got := IntGenISISPresetManifestDigest(preset); got != digest {
			t.Fatalf("%s manifest digest=%s want %s", id, got, digest)
		}
	}
}

func TestPublicationPresetsV4BindExactSecurityPolicy(t *testing.T) {
	tests := []struct {
		id         string
		label      string
		target     float64
		querySet   bool
		queryLog2  float64
		hashBits   int
		tapeBits   int
		saltBits   int
		tagProfile string
		issueGeom  [5]int
		showGeom   [5]int
		issueKappa [4]int
		showKappa  [4]int
	}{
		{IntGenISISPublicationPresetBQ96Q32V4, IntGenISISPublicationLabelBQ96Q32, IntGenISISPublicationNativeTargetBQ96Q32V4, true, 32, 168, 136, 160, IntGenISISPRFProfileTag9, [5]int{32, 753080, 38, 7, 8}, [5]int{43, 987291, 47, 7, 8}, [4]int{6, 0, 0, 13}, [4]int{0, 0, 0, 13}},
		{IntGenISISPublicationPresetBQ96Q96V4, IntGenISISPublicationLabelBQ96Q96, IntGenISISPublicationNativeTargetBQ96Q96V4, true, 96, 296, 200, 160, IntGenISISPRFProfileTag9, [5]int{33, 542171, 44, 10, 13}, [5]int{47, 738371, 55, 10, 13}, [4]int{12, 0, 2, 13}, [4]int{6, 0, 2, 13}},
		{IntGenISISPublicationPresetWF128V4, IntGenISISPublicationLabelWF128, 128, false, 0, 256, 136, 256, IntGenISISPRFProfileTag13, [5]int{32, 752712, 38, 7, 8}, [5]int{39, 901705, 44, 7, 8}, [4]int{6, 0, 0, 13}, [4]int{0, 0, 0, 13}},
		{IntGenISISPublicationPresetBQ128Q64V4, IntGenISISPublicationLabelBQ128Q64, IntGenISISPublicationNativeTargetBQ128Q64V4, true, 64, 264, 200, 192, IntGenISISPRFProfileTag10, [5]int{33, 542171, 44, 10, 13}, [5]int{47, 738371, 55, 10, 13}, [4]int{12, 0, 2, 13}, [4]int{6, 0, 2, 13}},
		{IntGenISISPublicationPresetBQ128Q128V4, IntGenISISPublicationLabelBQ128Q128, IntGenISISPublicationNativeTargetBQ128Q128V4, true, 128, 392, 264, 192, IntGenISISPRFProfileTag10, [5]int{34, 488783, 51, 13, 18}, [5]int{53, 710108, 66, 13, 18}, [4]int{9, 0, 6, 13}, [4]int{0, 0, 6, 13}},
	}
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			preset, ok := LookupIntGenISISPublicationPreset(tc.id)
			if !ok {
				t.Fatalf("missing publication preset %s", tc.id)
			}
			if err := ValidateIntGenISISPresetManifest(preset); err != nil {
				t.Fatalf("valid publication manifest rejected: %v", err)
			}
			if preset.PublicationLabel != tc.label || preset.PresetVersion != IntGenISISPresetManifestVersionV4 ||
				preset.ProofSchemaVersion != IntGenISISProofSchemaVersionV3 || preset.RelationVersion != 3 || preset.LayoutVersion != 3 ||
				preset.ClaimScope != ClaimProofOnly || preset.CompleteSystemClaim || preset.ThreatModel.ROM != ROMModelCROM {
				t.Fatalf("publication identity/versions=%+v", preset)
			}
			if preset.ThreatModel.ROQueryCapScope != ROQueryCapAggregateComposedGame || preset.ThreatModel.ROQueryCapLog2 != [5]float64{} ||
				preset.ThreatModel.AggregateROQueryCapLog2Set != tc.querySet || preset.ThreatModel.AggregateROQueryCapLog2 != tc.queryLog2 {
				t.Fatalf("aggregate query scope=%+v", preset.ThreatModel)
			}
			issueGeom := [5]int{preset.Issuance.LVCSNCols, preset.Issuance.NLeaves, preset.Issuance.Eta, preset.Issuance.Theta, preset.Issuance.Ell}
			showGeom := [5]int{preset.Showing.LVCSNCols, preset.Showing.NLeaves, preset.Showing.Eta, preset.Showing.Theta, preset.Showing.Ell}
			if preset.PRFProfile != tc.tagProfile || issueGeom != tc.issueGeom || showGeom != tc.showGeom ||
				preset.Issuance.Kappa != tc.issueKappa || preset.Showing.Kappa != tc.showKappa ||
				preset.Showing.SigShortnessRadix != 11 || preset.Showing.SigShortnessDigits != 4 {
				t.Fatalf("adopted primitive/geometry tuple=(%s,%v,%v,%v,%v,r%d/l%d)", preset.PRFProfile, issueGeom, showGeom, preset.Issuance.Kappa, preset.Showing.Kappa, preset.Showing.SigShortnessRadix, preset.Showing.SigShortnessDigits)
			}
			for phase, tuning := range map[string]IntGenISISTuningPreset{"issuance": preset.Issuance, "showing": preset.Showing} {
				if tuning.TargetTheoremBits != tc.target || tuning.DECSHashBits != tc.hashBits || tuning.DECSCollisionBits != tc.hashBits ||
					tuning.FSCollisionBits != tc.hashBits || tuning.FSOutputBits != tc.hashBits || tuning.DECSTapeBits != tc.tapeBits || tuning.SaltBits != tc.saltBits {
					t.Fatalf("%s exact security tuple=%+v", phase, tuning)
				}
				if tuning.ROQueryCapsSet || tuning.ROQueryCapBitsSet || tuning.ROQueryCaps != [5]int{} || tuning.ROQueryCapBits != [5]float64{} {
					t.Fatalf("%s retained legacy vector query caps: %+v", phase, tuning)
				}
			}
		})
	}
}

func TestPublicationNativeTargetsDeriveFromOneByteBoundary(t *testing.T) {
	correction := -math.Log2(1 - math.Exp2(-8))
	for name, tc := range map[string]struct {
		base float64
		got  float64
	}{
		"BQ96-32":   {128, IntGenISISPublicationNativeTargetBQ96Q32V4},
		"BQ96-96":   {192, IntGenISISPublicationNativeTargetBQ96Q96V4},
		"BQ128-64":  {192, IntGenISISPublicationNativeTargetBQ128Q64V4},
		"BQ128-128": {256, IntGenISISPublicationNativeTargetBQ128Q128V4},
	} {
		if math.Abs(tc.got-(tc.base+correction)) > 5e-14 {
			t.Fatalf("%s native target=%.17g want %.17g", name, tc.got, tc.base+correction)
		}
	}
}

func TestPublicationManifestV4WidthsFailClosed(t *testing.T) {
	for _, id := range IntGenISISPublicationPresetNamesV4() {
		preset, _ := LookupIntGenISISPublicationPreset(id)
		for name, mutate := range map[string]func(*IntGenISISTuningPreset){
			"hash": func(tuning *IntGenISISTuningPreset) {
				tuning.DECSCollisionBits -= 8
				tuning.DECSHashBits -= 8
				tuning.FSCollisionBits -= 8
				tuning.FSOutputBits -= 8
			},
			"tape":      func(tuning *IntGenISISTuningPreset) { tuning.DECSTapeBits -= 8 },
			"salt":      func(tuning *IntGenISISTuningPreset) { tuning.SaltBits -= 8 },
			"zero_fs":   func(tuning *IntGenISISTuningPreset) { tuning.FSOutputBits = 0 },
			"unaligned": func(tuning *IntGenISISTuningPreset) { tuning.FSOutputBits-- },
		} {
			t.Run(preset.PublicationLabel+"/"+name, func(t *testing.T) {
				mutated := preset
				mutate(&mutated.Showing)
				if err := ValidateIntGenISISPresetManifest(mutated); err == nil {
					t.Fatal("undersized, absent, divergent, or non-byte-aligned width was accepted")
				}
			})
		}
	}
}

func TestPublicationManifestV4RejectsLegacyVectorAndCrossPresetContext(t *testing.T) {
	preset, _ := LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetBQ96Q32V4)
	preset.Issuance.ROQueryCapBitsSet = true
	preset.Issuance.ROQueryCapBits = [5]float64{32, 32, 32, 32, 32}
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("publication-v4 manifest accepted a legacy per-domain vector")
	}

	preset, _ = LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetBQ96Q32V4)
	preset.PublicationLabel = IntGenISISPublicationLabelBQ96Q96
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("publication-v4 manifest accepted a cross-preset paper label")
	}

	preset, _ = LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetBQ96Q32V4)
	preset.FieldProfileDigest = "different"
	if err := ValidateIntGenISISPresetManifest(preset); err == nil {
		t.Fatal("publication-v4 manifest accepted a cross-field context")
	}
}

func TestPublicationSecurityAuditBindsAggregateQueryAndActualFSOutput(t *testing.T) {
	preset, _ := LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetBQ128Q64V4)
	spec, _ := LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	actual := IntGenISISSecurityParameterActuals{
		ROQueryCapScope:            ROQueryCapAggregateComposedGame,
		AggregateROQueryCapLog2Set: true,
		AggregateROQueryCapLog2:    64,
		DECSHashBits:               264,
		DECSTapeBits:               200,
		FSCollisionBits:            264,
		FSOutputBits:               264,
		SaltBits:                   192,
		PRFTagElements:             10,
		PRFProfile:                 IntGenISISPRFProfileTag10,
		TranscriptMode:             IntGenISISTranscriptProtocolV4,
		Evidence: map[string]string{
			"ro_query_cap_scope":          SecurityEvidenceExecutedPreset,
			"aggregate_ro_query_cap_log2": SecurityEvidenceExecutedPreset,
			"decs_hash_bits":              SecurityEvidenceExecutedPreset,
			"decs_tape_bits":              SecurityEvidenceExecutedPreset,
			"fs_collision_bits":           SecurityEvidenceExecutedPreset,
			"fs_output_bits":              SecurityEvidenceMeasured,
			"salt_bits":                   SecurityEvidenceExecutedPreset,
			"prf_tag_elements":            SecurityEvidenceLoadedParams,
			"prf_profile":                 SecurityEvidenceLoadedParams,
			"transcript_mode":             SecurityEvidenceMeasured,
		},
	}
	if audit := AuditIntGenISISSecurityParameters(spec, actual); audit.Status != "pass" {
		t.Fatalf("valid publication-v4 actuals rejected: %+v", audit)
	}
	actual.FSOutputBits = 256
	if audit := AuditIntGenISISSecurityParameters(spec, actual); audit.Status != "rejected" {
		t.Fatalf("undersized actual FS output accepted: %+v", audit)
	}
	actual.FSOutputBits = 264
	actual.ROQueryCapLog2Set = true
	actual.ROQueryCapLog2 = []float64{64, 64, 64, 64, 64}
	if audit := AuditIntGenISISSecurityParameters(spec, actual); audit.Status != "rejected" {
		t.Fatalf("legacy query vector accepted alongside aggregate scalar: %+v", audit)
	}
}

func TestPublicationWF128AuditRequiresNoAggregateCap(t *testing.T) {
	preset, _ := LookupIntGenISISPublicationPreset(IntGenISISPublicationPresetWF128V4)
	spec, _ := LookupIntGenISISSecurityProfile(preset.SecurityProfile)
	actual := IntGenISISSecurityParameterActuals{
		ROQueryCapScope: ROQueryCapAggregateComposedGame,
		DECSHashBits:    256,
		DECSTapeBits:    136,
		FSCollisionBits: 256,
		FSOutputBits:    256,
		SaltBits:        256,
		PRFTagElements:  13,
		PRFProfile:      IntGenISISPRFProfileTag13,
		TranscriptMode:  IntGenISISTranscriptProtocolV4,
		Evidence: map[string]string{
			"ro_query_cap_scope": SecurityEvidenceExecutedPreset,
			"decs_hash_bits":     SecurityEvidenceExecutedPreset,
			"decs_tape_bits":     SecurityEvidenceExecutedPreset,
			"fs_collision_bits":  SecurityEvidenceExecutedPreset,
			"fs_output_bits":     SecurityEvidenceMeasured,
			"salt_bits":          SecurityEvidenceExecutedPreset,
			"prf_tag_elements":   SecurityEvidenceLoadedParams,
			"prf_profile":        SecurityEvidenceLoadedParams,
			"transcript_mode":    SecurityEvidenceMeasured,
		},
	}
	if audit := AuditIntGenISISSecurityParameters(spec, actual); audit.Status != "pass" {
		t.Fatalf("WF128 audit with unset aggregate cap rejected: %+v", audit)
	}
	actual.AggregateROQueryCapLog2Set = true
	actual.AggregateROQueryCapLog2 = 64
	actual.Evidence["aggregate_ro_query_cap_log2"] = SecurityEvidenceExecutedPreset
	if audit := AuditIntGenISISSecurityParameters(spec, actual); audit.Status != "rejected" {
		t.Fatalf("WF128 audit accepted an invented bounded-query scalar: %+v", audit)
	}
}

func TestPublicationV4StrictStateAndPresentationContexts(t *testing.T) {
	for _, id := range IntGenISISPublicationPresetNamesV4() {
		t.Run(id, func(t *testing.T) {
			state, stateCtx := testStateV8Artifacts(t, id)
			stateWire, err := MarshalIntGenISISStateV8(state, stateCtx)
			if err != nil {
				t.Fatal(err)
			}
			decodedState, err := UnmarshalIntGenISISStateV8(stateWire, stateCtx)
			if err != nil || !reflect.DeepEqual(decodedState, state) {
				t.Fatalf("publication state-v8 round trip=(%v,%v)", reflect.DeepEqual(decodedState, state), err)
			}
			preset, _ := LookupIntGenISISPublicationPreset(id)
			_, _, width, err := validateIntGenISISStateV8Context(stateCtx)
			if err != nil {
				t.Fatal(err)
			}
			wantWidth := maxInt(preset.Issuance.FSOutputBits, preset.Showing.FSOutputBits) / 8
			if width != wantWidth {
				t.Fatalf("state binding width=%d want exact FS output width %d", width, wantWidth)
			}

			presentation, presentationCtx := testPresentationV3Artifacts(t, id)
			presentationWire, err := MarshalIntGenISISPresentationV3(presentation, presentationCtx)
			if err != nil {
				t.Fatal(err)
			}
			decodedPresentation, err := UnmarshalIntGenISISPresentationV3(presentationWire, presentationCtx)
			if err != nil || !reflect.DeepEqual(decodedPresentation, presentation) {
				t.Fatalf("publication presentation-v3 round trip=(%v,%v)", reflect.DeepEqual(decodedPresentation, presentation), err)
			}
		})
	}

	state, leftCtx := testStateV8Artifacts(t, IntGenISISPublicationPresetBQ96Q32V4)
	stateWire, err := MarshalIntGenISISStateV8(state, leftCtx)
	if err != nil {
		t.Fatal(err)
	}
	_, rightCtx := testStateV8Artifacts(t, IntGenISISPublicationPresetBQ96Q96V4)
	if _, err := UnmarshalIntGenISISStateV8(stateWire, rightCtx); err == nil {
		t.Fatal("publication state-v8 accepted a different manifest-bound public/key context")
	}

	presentation, presentationCtx := testPresentationV3Artifacts(t, IntGenISISPublicationPresetBQ96Q32V4)
	presentationWire, err := MarshalIntGenISISPresentationV3(presentation, presentationCtx)
	if err != nil {
		t.Fatal(err)
	}
	presentationCtx.VerifierKey = rightCtx.VerifierKey
	if _, err := UnmarshalIntGenISISPresentationV3(presentationWire, presentationCtx); err == nil {
		t.Fatal("publication presentation-v3 accepted a verifier key from a different preset context")
	}
}
