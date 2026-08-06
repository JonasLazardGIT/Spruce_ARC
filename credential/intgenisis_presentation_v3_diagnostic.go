package credential

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const presentationV3DiagnosticDigestDomain = "ARC-SPRUCE/intgenisis-presentation-v3/binary-digest"

// IntGenISISPresentationV3Diagnostic is deliberately not a proof format. It
// contains only an identifier for the canonical binary, its exact length, and
// a caller-supplied non-verifying report. In particular it has no tag or proof
// field and cannot be loaded by the verifier.
type IntGenISISPresentationV3Diagnostic struct {
	FormatVersion     int             `json:"format_version"`
	BinarySHAKEDigest string          `json:"binary_shake_digest"`
	BinaryBytes       int             `json:"binary_bytes"`
	ProofReport       json.RawMessage `json:"proof_report"`
}

func NewIntGenISISPresentationV3Diagnostic(wire []byte, proofReport json.RawMessage, ctx IntGenISISPresentationCodecContext) (IntGenISISPresentationV3Diagnostic, error) {
	var zero IntGenISISPresentationV3Diagnostic
	_, _, bindingWidth, err := validateIntGenISISPresentationV3Context(ctx)
	if err != nil {
		return zero, err
	}
	if _, err := UnmarshalIntGenISISPresentationV3(wire, ctx); err != nil {
		return zero, fmt.Errorf("diagnostic requires canonical presentation-v3 envelope: %w", err)
	}
	if err := validatePresentationV3DiagnosticReport(proofReport); err != nil {
		return zero, err
	}
	digest, err := shakeConfiguredBinding(presentationV3DiagnosticDigestDomain, wire, bindingWidth)
	if err != nil {
		return zero, err
	}
	return IntGenISISPresentationV3Diagnostic{
		FormatVersion:     IntGenISISPresentationFormatVersionV3,
		BinarySHAKEDigest: hex.EncodeToString(digest),
		BinaryBytes:       len(wire),
		ProofReport:       append(json.RawMessage(nil), proofReport...),
	}, nil
}

func SaveIntGenISISPresentationV3Diagnostic(path string, diagnostic IntGenISISPresentationV3Diagnostic) error {
	if diagnostic.FormatVersion != IntGenISISPresentationFormatVersionV3 {
		return fmt.Errorf("presentation-v3 diagnostic format_version=%d want %d", diagnostic.FormatVersion, IntGenISISPresentationFormatVersionV3)
	}
	// BQ128 uses a 392-bit configured digest and WF128 a 264-bit digest, so
	// the legacy fixed-32-byte digest validator is intentionally not used.
	decoded, decodeErr := hex.DecodeString(diagnostic.BinarySHAKEDigest)
	if decodeErr != nil || (len(decoded) != 33 && len(decoded) != 49) || hex.EncodeToString(decoded) != diagnostic.BinarySHAKEDigest {
		return fmt.Errorf("presentation-v3 binary SHAKE digest is not a canonical configured-width hex string")
	}
	if diagnostic.BinaryBytes <= 0 {
		return fmt.Errorf("presentation-v3 diagnostic binary_bytes=%d must be positive", diagnostic.BinaryBytes)
	}
	if err := validatePresentationV3DiagnosticReport(diagnostic.ProofReport); err != nil {
		return err
	}
	data, err := json.MarshalIndent(diagnostic, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal presentation-v3 diagnostic: %w", err)
	}
	if err := atomicWriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write presentation-v3 diagnostic: %w", err)
	}
	return nil
}

func validatePresentationV3DiagnosticReport(report json.RawMessage) error {
	if len(report) == 0 || !json.Valid(report) || string(report) == "null" {
		return fmt.Errorf("presentation-v3 diagnostic proof report must be a non-null JSON object")
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(report, &shape); err != nil || shape == nil {
		return fmt.Errorf("presentation-v3 diagnostic proof report must be a JSON object")
	}
	for _, forbidden := range []string{"proof", "canonical_proof", "tag", "presentation"} {
		if _, exists := shape[forbidden]; exists {
			return fmt.Errorf("presentation-v3 diagnostic proof report contains forbidden lossless field %q", forbidden)
		}
	}
	return nil
}
