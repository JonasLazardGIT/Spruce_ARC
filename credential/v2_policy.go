package credential

import "fmt"

const (
	IntGenISISRateLimitModeV2                        = "public_context_hidden_slot_v2"
	IntGenISISContextEncodingV2                      = "shake256_reject11_v2"
	IntGenISISHolderCounterModeV2                    = "monotonic_burn_v2"
	IntGenISISVerifierStateModeV2                    = "atomic_context_tag_set_v2"
	IntGenISISContextLaneCount                       = 11
	IntGenISISHiddenSlotLaneCount                    = 1
	IntGenISISQuotaSlots                      uint32 = 16
	IntGenISISSlotBits                        uint32 = 4
	IntGenISISTranscriptProtocolV2                   = "smallfield_2025_1085_salted_tapes_v2"
	IntGenISISTranscriptVersionV2                    = "smallwood_2025_1085_salted_decs_v2"
	IntGenISISTranscriptOmissionModeV2               = "digest_bound_payload_v2"
	IntGenISISSecurityGateV2                         = "smallwood_2025_1085_salted_tapes_v2_live"
	IntGenISISPresentationSchemaV2                   = "intgenisis_presentation_v2"
	IntGenISISProofSchemaVersionV2                   = 2
	IntGenISISTranscriptProtocolV3                   = "smallfield_2025_1085_salted_tapes_v3"
	IntGenISISTranscriptVersionV3                    = "smallwood_2025_1085_salted_decs_v3"
	IntGenISISTranscriptOmissionModeV3               = "canonical_reconstruction_v3"
	IntGenISISSecurityGateV3                         = "smallwood_2025_1085_salted_tapes_v3_live"
	IntGenISISPresentationSchemaV3                   = "intgenisis_presentation_v3"
	IntGenISISProofSchemaVersionV3                   = 3
	IntGenISISPresetManifestVersionV3                = 3
	IntGenISISStateFormatVersionV8                   = 8
	IntGenISISPresentationFormatVersionV3            = 3
	IntGenISISIssuanceArtifactFormatVersionV4        = 4
	IntGenISISHolderUsageFormatVersionV3             = 3
	// Publication-v4 changes the Fiat--Shamir domain and output policy while
	// deliberately retaining the strict-v3 proof/relation/layout formats.
	IntGenISISTranscriptProtocolV4    = "smallfield_2025_1085_salted_tapes_v4"
	IntGenISISTranscriptVersionV4     = "smallwood_2025_1085_salted_decs_v4"
	IntGenISISSecurityGateV4          = "smallwood_2025_1085_aggregate_q_v4_live"
	IntGenISISPresetManifestVersionV4 = 4
)

// RateLimitPolicy is part of the canonical preset and public-parameter
// identity.  It is deliberately not configurable at presentation time.
type RateLimitPolicy struct {
	Mode              string `json:"mode"`
	ContextLanes      uint32 `json:"context_lanes"`
	HiddenSlotLanes   uint32 `json:"hidden_slot_lanes"`
	QuotaSlots        uint32 `json:"quota_slots"`
	SlotBits          uint32 `json:"slot_bits"`
	ContextEncoding   string `json:"context_encoding"`
	HolderCounterMode string `json:"holder_counter_mode"`
	VerifierStateMode string `json:"verifier_state_mode"`
}

func IntGenISISRateLimitPolicyV2() RateLimitPolicy {
	return RateLimitPolicy{
		Mode:              IntGenISISRateLimitModeV2,
		ContextLanes:      IntGenISISContextLaneCount,
		HiddenSlotLanes:   IntGenISISHiddenSlotLaneCount,
		QuotaSlots:        IntGenISISQuotaSlots,
		SlotBits:          IntGenISISSlotBits,
		ContextEncoding:   IntGenISISContextEncodingV2,
		HolderCounterMode: IntGenISISHolderCounterModeV2,
		VerifierStateMode: IntGenISISVerifierStateModeV2,
	}
}

func (p RateLimitPolicy) ValidateV2() error {
	want := IntGenISISRateLimitPolicyV2()
	if p != want {
		return fmt.Errorf("unsupported IntGenISIS rate-limit policy %+v; want %+v", p, want)
	}
	return nil
}

// ResolveIntGenISISTranscript is the single persisted-mode resolver shared by
// issuance, showing, benchmarking, and verification. There are no aliases.
func ResolveIntGenISISTranscript(mode string) (protocol, version string, err error) {
	switch mode {
	case IntGenISISTranscriptProtocolV2:
		return IntGenISISTranscriptProtocolV2, IntGenISISTranscriptVersionV2, nil
	case IntGenISISTranscriptProtocolV3:
		return IntGenISISTranscriptProtocolV3, IntGenISISTranscriptVersionV3, nil
	case IntGenISISTranscriptProtocolV4:
		return IntGenISISTranscriptProtocolV4, IntGenISISTranscriptVersionV4, nil
	default:
		return "", "", fmt.Errorf("unsupported IntGenISIS transcript mode %q", mode)
	}
}

// ResolveIntGenISISTranscriptOmission accepts only the omission descriptor
// implemented by the v2 transcript. There are no aliases or implicit legacy
// defaults at the persisted credential boundary.
func ResolveIntGenISISTranscriptOmission(mode string) (string, error) {
	switch mode {
	case IntGenISISTranscriptOmissionModeV2, IntGenISISTranscriptOmissionModeV3:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported IntGenISIS transcript omission mode %q", mode)
	}
}
