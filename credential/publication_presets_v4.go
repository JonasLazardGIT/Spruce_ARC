package credential

import (
	"fmt"
	"math"

	kf "vSIS-Signature/internal/kfield"
)

const (
	IntGenISISPublicationNativeTargetBQ96Q32V4   = 128.00564656314114
	IntGenISISPublicationNativeTargetBQ96Q96V4   = 192.00564656314114
	IntGenISISPublicationNativeTargetBQ128Q64V4  = 192.00564656314114
	IntGenISISPublicationNativeTargetBQ128Q128V4 = 256.00564656314117
	// This is the content digest of the pre-adoption lock whose 60 finalists
	// were each executed once and whose top three were each executed three
	// times before the five rank-1 tuples below were adopted.
	IntGenISISPublicationAdoptionLockDigestV4 = "703d091317838b251711f5b656e31b6e18bc3fe019d24bec1c4f92ccaafb67cf"
)

func intGenISISPublicationPresetRegistryV4(
	bq96q32Seed IntGenISISTuningPreset,
	bq128q64Seed IntGenISISTuningPreset,
	wf128Seed IntGenISISTuningPreset,
	bq128q128Seed IntGenISISTuningPreset,
) map[string]IntGenISISPreset {
	bq96q32Show := intGenISISPublicationBoundedTuningV4(
		bq96q32Seed, 32, IntGenISISPublicationNativeTargetBQ96Q32V4,
		168, 136, 160, [4]int{0, 0, 0, 10},
	)
	intGenISISPublicationSetTuningPRF(&bq96q32Show, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
	bq96q32Show = intGenISISPublicationAdoptShowingTuningV4(bq96q32Show, 43, 987291, 47, 7, 8, [4]int{0, 0, 0, 13})
	bq96q32Issuance := intGenISISStrictV4Tuning(intGenISISIssuanceTuning(bq96q32Show))
	bq96q32Issuance = intGenISISPublicationAdoptPhaseTuningV4(bq96q32Issuance, 32, 753080, 38, 7, 8, [4]int{6, 0, 0, 13})

	// The first BQ96-96 executable seed intentionally starts from the current
	// BQ64-R128 incumbent geometry. The publication tuner may replace it only
	// through an explicit candidate-lock adoption.
	bq96q96Show := intGenISISPublicationBoundedTuningV4(
		bq128q64Seed, 96, IntGenISISPublicationNativeTargetBQ96Q96V4,
		296, 200, 160, [4]int{2, 0, 2, 10},
	)
	intGenISISPublicationSetTuningPRF(&bq96q96Show, IntGenISISPRFProfileTag9, IntGenISISPRFParamsTag9)
	bq96q96Show = intGenISISPublicationAdoptShowingTuningV4(bq96q96Show, 47, 738371, 55, 10, 13, [4]int{6, 0, 2, 13})
	bq96q96Issuance := intGenISISStrictV4Tuning(intGenISISIssuanceTuning(bq96q96Show))
	bq96q96Issuance = intGenISISPublicationAdoptPhaseTuningV4(bq96q96Issuance, 33, 542171, 44, 10, 13, [4]int{12, 0, 2, 13})

	wf128Show := intGenISISPublicationWorkFactorTuningV4(wf128Seed)
	intGenISISPublicationSetTuningPRF(&wf128Show, IntGenISISPRFProfileTag13, IntGenISISPRFParamsTag13)
	wf128Show = intGenISISPublicationAdoptShowingTuningV4(wf128Show, 39, 901705, 44, 7, 8, [4]int{0, 0, 0, 13})
	wf128Issuance := intGenISISStrictV4Tuning(intGenISISIssuanceTuning(wf128Show))
	wf128Issuance = intGenISISPublicationAdoptPhaseTuningV4(wf128Issuance, 32, 752712, 38, 7, 8, [4]int{6, 0, 0, 13})

	bq128q64Show := intGenISISPublicationBoundedTuningV4(
		bq128q64Seed, 64, IntGenISISPublicationNativeTargetBQ128Q64V4,
		264, 200, 192, [4]int{2, 0, 2, 10},
	)
	intGenISISPublicationSetTuningPRF(&bq128q64Show, IntGenISISPRFProfileTag10, IntGenISISPRFParamsTag10)
	bq128q64Show = intGenISISPublicationAdoptShowingTuningV4(bq128q64Show, 47, 738371, 55, 10, 13, [4]int{6, 0, 2, 13})
	bq128q64Issuance := intGenISISStrictV4Tuning(intGenISISIssuanceTuning(bq128q64Show))
	bq128q64Issuance = intGenISISPublicationAdoptPhaseTuningV4(bq128q64Issuance, 33, 542171, 44, 10, 13, [4]int{12, 0, 2, 13})

	bq128q128Show := intGenISISPublicationBoundedTuningV4(
		bq128q128Seed, 128, IntGenISISPublicationNativeTargetBQ128Q128V4,
		392, 264, 192, [4]int{0, 0, 6, 10},
	)
	intGenISISPublicationSetTuningPRF(&bq128q128Show, IntGenISISPRFProfileTag10, IntGenISISPRFParamsTag10)
	bq128q128Show = intGenISISPublicationAdoptShowingTuningV4(bq128q128Show, 53, 710108, 66, 13, 18, [4]int{0, 0, 6, 13})
	bq128q128Issuance := intGenISISStrictV4Tuning(intGenISISIssuanceTuning(bq128q128Show))
	bq128q128Issuance = intGenISISPublicationAdoptPhaseTuningV4(bq128q128Issuance, 34, 488783, 51, 13, 18, [4]int{9, 0, 6, 13})

	return map[string]IntGenISISPreset{
		IntGenISISPublicationPresetBQ96Q32V4: intGenISISPublicationPresetV4(
			IntGenISISPublicationPresetBQ96Q32V4,
			IntGenISISPublicationLabelBQ96Q32,
			"N=1024 publication BQ96-32 proof-only CROM preset",
			IntGenISISPublicationNativeTargetBQ96Q32V4,
			bq96q32Issuance,
			bq96q32Show,
		),
		IntGenISISPublicationPresetBQ96Q96V4: intGenISISPublicationPresetV4(
			IntGenISISPublicationPresetBQ96Q96V4,
			IntGenISISPublicationLabelBQ96Q96,
			"N=1024 publication BQ96-96 proof-only CROM preset",
			IntGenISISPublicationNativeTargetBQ96Q96V4,
			bq96q96Issuance,
			bq96q96Show,
		),
		IntGenISISPublicationPresetWF128V4: intGenISISPublicationPresetV4(
			IntGenISISPublicationPresetWF128V4,
			IntGenISISPublicationLabelWF128,
			"N=1024 publication WF128 proof-only CROM preset",
			128,
			wf128Issuance,
			wf128Show,
		),
		IntGenISISPublicationPresetBQ128Q64V4: intGenISISPublicationPresetV4(
			IntGenISISPublicationPresetBQ128Q64V4,
			IntGenISISPublicationLabelBQ128Q64,
			"N=1024 publication BQ128-64 proof-only CROM preset",
			IntGenISISPublicationNativeTargetBQ128Q64V4,
			bq128q64Issuance,
			bq128q64Show,
		),
		IntGenISISPublicationPresetBQ128Q128V4: intGenISISPublicationPresetV4(
			IntGenISISPublicationPresetBQ128Q128V4,
			IntGenISISPublicationLabelBQ128Q128,
			"N=1024 publication BQ128-128 proof-only CROM preset",
			IntGenISISPublicationNativeTargetBQ128Q128V4,
			bq128q128Issuance,
			bq128q128Show,
		),
	}
}

func intGenISISPublicationPresetV4(
	canonicalID, label, description string,
	target float64,
	issuance, showing IntGenISISTuningPreset,
) IntGenISISPreset {
	issuance.PresetID = canonicalID
	showing.PresetID = canonicalID
	return IntGenISISPreset{
		Name:              canonicalID,
		CanonicalID:       canonicalID,
		PublicationLabel:  label,
		Description:       description,
		Profile:           ProfileIntGenISISC,
		TargetTheoremBits: target,
		SoundnessGate:     IntGenISISSecurityGateV4,
		LVCSNCols:         showing.LVCSNCols,
		MaxNLeaves:        maxIntGenISISPublicationLeaves(issuance.NLeaves, showing.NLeaves),
		Issuance:          issuance,
		Showing:           showing,
		Notes: []string{
			"Publication-v4 proof-only CROM preset; no complete-system or QROM claim.",
			"The bounded-query lanes use one aggregate oracle budget across the complete one-issuance-plus-one-showing game.",
			"Geometry was explicitly adopted from publication-v4 candidate lock " + IntGenISISPublicationAdoptionLockDigestV4 + " after complete finalist execution.",
			"The optimization claim is restricted to the recorded, boundary-expanded supported search envelope.",
		},
	}
}

func intGenISISPublicationAdoptPhaseTuningV4(
	tuning IntGenISISTuningPreset,
	lvcsNCols, nLeaves, eta, theta, ell int,
	kappa [4]int,
) IntGenISISTuningPreset {
	tuning.NCols = 32
	tuning.LVCSNCols = lvcsNCols
	tuning.NLeaves = nLeaves
	tuning.Eta = eta
	tuning.Theta = theta
	tuning.Rho = 1
	tuning.Ell = ell
	tuning.EllPrime = 1
	tuning.Kappa = kappa
	return intGenISISStrictV4Tuning(tuning)
}

func intGenISISPublicationAdoptShowingTuningV4(
	tuning IntGenISISTuningPreset,
	lvcsNCols, nLeaves, eta, theta, ell int,
	kappa [4]int,
) IntGenISISTuningPreset {
	tuning = intGenISISPublicationAdoptPhaseTuningV4(tuning, lvcsNCols, nLeaves, eta, theta, ell, kappa)
	tuning.SigShortnessRadix = 11
	tuning.SigShortnessDigits = 4
	tuning.CompressedRows = 1
	return tuning
}

func intGenISISPublicationBoundedTuningV4(
	seed IntGenISISTuningPreset,
	queryLog2 float64,
	target float64,
	hashBits, tapeBits, saltBits int,
	kappa [4]int,
) IntGenISISTuningPreset {
	seed.ROQueryCaps = [5]int{}
	seed.ROQueryCapsSet = false
	seed.ROQueryCapBits = [5]float64{}
	seed.ROQueryCapBitsSet = false
	seed.AggregateROQueryCapLog2 = queryLog2
	seed.AggregateROQueryCapLog2Set = true
	seed.DECSCollisionBits = hashBits
	seed.DECSHashBits = hashBits
	seed.DECSTapeBits = tapeBits
	seed.FSCollisionBits = hashBits
	seed.FSOutputBits = hashBits
	seed.SaltBits = saltBits
	seed.Kappa = kappa
	seed.TargetTheoremBits = target
	return intGenISISStrictV4Tuning(seed)
}

func intGenISISPublicationWorkFactorTuningV4(seed IntGenISISTuningPreset) IntGenISISTuningPreset {
	seed.ROQueryCaps = [5]int{}
	seed.ROQueryCapsSet = false
	seed.ROQueryCapBits = [5]float64{}
	seed.ROQueryCapBitsSet = false
	seed.AggregateROQueryCapLog2 = 0
	seed.AggregateROQueryCapLog2Set = false
	seed.DECSCollisionBits = 256
	seed.DECSHashBits = 256
	seed.DECSTapeBits = 136
	seed.FSCollisionBits = 256
	seed.FSOutputBits = 256
	seed.SaltBits = 256
	seed.TargetTheoremBits = 128
	return intGenISISStrictV4Tuning(seed)
}

func maxIntGenISISPublicationLeaves(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func intGenISISPublicationSetTuningPRF(tuning *IntGenISISTuningPreset, profile, paramsPath string) {
	tuning.PRFProfile = profile
	tuning.PRFParamsPath = paramsPath
}

func isIntGenISISPublicationPresetV4ID(name string) bool {
	switch name {
	case IntGenISISPublicationPresetBQ96Q32V4,
		IntGenISISPublicationPresetBQ96Q96V4,
		IntGenISISPublicationPresetWF128V4,
		IntGenISISPublicationPresetBQ128Q64V4,
		IntGenISISPublicationPresetBQ128Q128V4:
		return true
	default:
		return false
	}
}

func validateIntGenISISPublicationPresetManifestV4(preset IntGenISISPreset, spec IntGenISISSecurityProfileSpec) error {
	if !isIntGenISISPublicationPresetV4ID(preset.CanonicalID) || preset.Name != preset.CanonicalID {
		return fmt.Errorf("manifest v4 is restricted to exact publication-v4 canonical IDs")
	}
	wantLabel, wantTarget, ok := intGenISISPublicationIdentityV4(preset.CanonicalID)
	if !ok || preset.PublicationLabel != wantLabel || math.Abs(preset.TargetTheoremBits-wantTarget) > 1e-9 {
		return fmt.Errorf("publication-v4 identity, label, or native theorem target mismatch")
	}
	if preset.Profile != ProfileIntGenISISC || preset.ClaimScope != ClaimProofOnly || preset.Lifecycle != PresetCandidate || preset.CompleteSystemClaim {
		return fmt.Errorf("publication-v4 preset must remain an N=1024 proof-only CROM candidate")
	}
	if preset.ThreatModel.ROM != ROMModelCROM || preset.ThreatModel.ROQueryCapScope != ROQueryCapAggregateComposedGame ||
		preset.ThreatModel.AcceptedIssuance != 1 || preset.ThreatModel.AcceptedShowing != 1 {
		return fmt.Errorf("publication-v4 preset must bind the one-issuance-plus-one-showing aggregate CROM game")
	}
	if preset.ProofSchemaVersion != IntGenISISProofSchemaVersionV3 || preset.RelationVersion != 3 || preset.LayoutVersion != 3 ||
		preset.StateFormatVersion != IntGenISISStateFormatVersionV8 || preset.PresentationVersion != IntGenISISPresentationFormatVersionV3 ||
		preset.IssuanceVersion != IntGenISISIssuanceArtifactFormatVersionV4 || preset.HolderUsageVersion != IntGenISISHolderUsageFormatVersionV3 {
		return fmt.Errorf("publication-v4 preset does not retain the strict structural version tuple")
	}
	if preset.Issuance.Theta != preset.Showing.Theta || preset.MaxNLeaves != maxIntGenISISPublicationLeaves(preset.Issuance.NLeaves, preset.Showing.NLeaves) {
		return fmt.Errorf("publication-v4 phases disagree on field degree or domain ceiling")
	}
	profile, ok := kf.LookupSmallWoodFieldProfileV3(IntGenISISSharedModulusQ, preset.Showing.Theta)
	if !ok {
		return fmt.Errorf("publication-v4 preset is missing a pinned extension-field profile")
	}
	digest, err := profile.DigestHex(32)
	if err != nil || preset.FieldProfileID != profile.ID || preset.FieldProfileDigest != digest {
		return fmt.Errorf("publication-v4 field profile binding mismatch")
	}
	tagElements, ok := IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok || tagElements != spec.MinPRFTagElements {
		return fmt.Errorf("publication-v4 PRF tag width=%d want exactly %d", tagElements, spec.MinPRFTagElements)
	}
	for phase, tuning := range map[string]IntGenISISTuningPreset{"issuance": preset.Issuance, "showing": preset.Showing} {
		if tuning.PresetID != preset.CanonicalID {
			return fmt.Errorf("%s preset identity %q does not match canonical manifest %q", phase, tuning.PresetID, preset.CanonicalID)
		}
		if tuning.TranscriptMode != IntGenISISTranscriptProtocolV4 || tuning.TranscriptOmissionMode != IntGenISISTranscriptOmissionModeV3 ||
			tuning.SoundnessGate != IntGenISISSecurityGateV4 || tuning.RelationVersion != 3 || tuning.LayoutVersion != 3 {
			return fmt.Errorf("%s does not select the publication-v4 transcript on the strict proof path", phase)
		}
		if tuning.NCols != 32 || tuning.Rho != 1 || tuning.EllPrime != 1 || tuning.NLeaves <= 0 || tuning.NLeaves > preset.MaxNLeaves {
			return fmt.Errorf("%s violates frozen publication-v4 ring/column/domain invariants", phase)
		}
		if !tuning.FixedTranscriptSize || math.Abs(tuning.TargetTheoremBits-preset.TargetTheoremBits) > 1e-9 {
			return fmt.Errorf("%s transcript policy or theorem target is not manifest bound", phase)
		}
		if tuning.DECSCollisionBits != tuning.DECSHashBits || tuning.DECSHashBits != tuning.FSCollisionBits || tuning.FSCollisionBits != tuning.FSOutputBits {
			return fmt.Errorf("%s DECS/hash/Fiat--Shamir widths must be equal in publication v4", phase)
		}
		widths := []struct {
			name string
			got  int
			want int
		}{
			{"decs_hash_bits", tuning.DECSHashBits, spec.MinDECSHashBits},
			{"decs_tape_bits", tuning.DECSTapeBits, spec.MinDECSTapeBits},
			{"fs_collision_bits", tuning.FSCollisionBits, spec.MinFSCollisionBits},
			{"fs_output_bits", tuning.FSOutputBits, spec.MinFSOutputBits},
			{"salt_bits", tuning.SaltBits, spec.MinSaltBits},
		}
		for _, width := range widths {
			if width.got <= 0 || width.got%8 != 0 || width.got != width.want {
				return fmt.Errorf("%s %s=%d want exact supported byte-aligned width %d", phase, width.name, width.got, width.want)
			}
		}
	}
	return nil
}

func intGenISISPublicationIdentityV4(canonicalID string) (label string, target float64, ok bool) {
	switch canonicalID {
	case IntGenISISPublicationPresetBQ96Q32V4:
		return IntGenISISPublicationLabelBQ96Q32, IntGenISISPublicationNativeTargetBQ96Q32V4, true
	case IntGenISISPublicationPresetBQ96Q96V4:
		return IntGenISISPublicationLabelBQ96Q96, IntGenISISPublicationNativeTargetBQ96Q96V4, true
	case IntGenISISPublicationPresetWF128V4:
		return IntGenISISPublicationLabelWF128, 128, true
	case IntGenISISPublicationPresetBQ128Q64V4:
		return IntGenISISPublicationLabelBQ128Q64, IntGenISISPublicationNativeTargetBQ128Q64V4, true
	case IntGenISISPublicationPresetBQ128Q128V4:
		return IntGenISISPublicationLabelBQ128Q128, IntGenISISPublicationNativeTargetBQ128Q128V4, true
	default:
		return "", 0, false
	}
}
