package credential

import (
	"encoding/json"
	"fmt"
	"slices"
)

// IntGenISISPresentationProver builds the cryptographic tag and proof after a
// slot has been durably burned. The slot is witness-only and must not be
// copied into either returned value.
type IntGenISISPresentationProver func(context PresentationContextBinding, slot uint8) (tag []int64, proof json.RawMessage, err error)

// IntGenISISProofVerifier performs the expensive proof-system verification.
// The public envelope and independently supplied context are checked before
// this callback is invoked.
type IntGenISISProofVerifier func(presentation IntGenISISPresentation) (bool, error)

// CreatePresentation derives the public service context, durably reserves the
// next hidden slot, and invokes prove. A prover or transport failure never
// rolls back the reservation.
func CreatePresentation(public PublicParams, key IntGenISISVerifierKey, state IntGenISISState, context []byte, holderUsageStore string, prove IntGenISISPresentationProver) (IntGenISISPresentation, error) {
	if holderUsageStore == "" {
		return IntGenISISPresentation{}, fmt.Errorf("holder usage state path is required")
	}
	if prove == nil {
		return IntGenISISPresentation{}, fmt.Errorf("presentation prover is required")
	}
	if err := state.ValidateAgainst(public, key); err != nil {
		return IntGenISISPresentation{}, fmt.Errorf("validate credential presentation bindings: %w", err)
	}
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		return IntGenISISPresentation{}, err
	}
	keyDigest, err := key.Digest()
	if err != nil {
		return IntGenISISPresentation{}, err
	}
	binding, err := DerivePresentationContext(context, public.Modulus, public.PresetManifestDigest, publicDigest, keyDigest)
	if err != nil {
		return IntGenISISPresentation{}, fmt.Errorf("derive presentation context: %w", err)
	}
	fingerprint, err := IntGenISISCredentialFingerprint(state)
	if err != nil {
		return IntGenISISPresentation{}, err
	}
	slot, err := ReserveIntGenISISSlot(holderUsageStore, publicDigest, public.PresetManifestDigest, fingerprint, binding.Digest)
	if err != nil {
		return IntGenISISPresentation{}, err
	}
	tag, proof, err := prove(binding, slot)
	if err != nil {
		return IntGenISISPresentation{}, fmt.Errorf("create presentation proof after burning slot %d: %w", slot, err)
	}
	presentation := IntGenISISPresentation{
		Version:              IntGenISISPresentationVersion,
		PresetManifestDigest: public.PresetManifestDigest,
		PublicParamsDigest:   publicDigest,
		VerifierKeyDigest:    keyDigest,
		ContextDigest:        binding.Digest,
		Context:              append([]int64(nil), binding.Lanes...),
		Tag:                  append([]int64(nil), tag...),
		Proof:                append(json.RawMessage(nil), proof...),
	}
	if err := presentation.ValidateAgainst(public, key); err != nil {
		return IntGenISISPresentation{}, fmt.Errorf("validate generated presentation: %w", err)
	}
	return presentation, nil
}

// VerifyProof verifies the immutable public envelope against an independently
// supplied service context before invoking the proof-system verifier. It does
// not evaluate or mutate rate-limit state.
func VerifyProof(presentation IntGenISISPresentation, public PublicParams, key IntGenISISVerifierKey, expectedContext []byte, verify IntGenISISProofVerifier) (bool, error) {
	if verify == nil {
		return false, fmt.Errorf("presentation proof verifier is required")
	}
	if err := presentation.ValidateAgainst(public, key); err != nil {
		return false, err
	}
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		return false, err
	}
	keyDigest, err := key.Digest()
	if err != nil {
		return false, err
	}
	expected, err := DerivePresentationContext(expectedContext, public.Modulus, public.PresetManifestDigest, publicDigest, keyDigest)
	if err != nil {
		return false, fmt.Errorf("derive expected presentation context: %w", err)
	}
	if presentation.ContextDigest != expected.Digest || !slices.Equal(presentation.Context, expected.Lanes) {
		return false, fmt.Errorf("presentation context does not match independently supplied context")
	}
	return verify(presentation)
}

// VerifyAndAccept first verifies the proof and expected service context, then
// atomically inserts the tag into the durable per-context replay set.
func VerifyAndAccept(presentation IntGenISISPresentation, public PublicParams, key IntGenISISVerifierKey, expectedContext []byte, verifierStore string, verify IntGenISISProofVerifier) (bool, error) {
	if verifierStore == "" {
		return false, fmt.Errorf("verifier state path is required")
	}
	ok, err := VerifyProof(presentation, public, key, expectedContext, verify)
	if err != nil || !ok {
		return false, err
	}
	if err := CheckAndMarkIntGenISISPresentation(verifierStore, presentation); err != nil {
		return false, err
	}
	return true, nil
}
