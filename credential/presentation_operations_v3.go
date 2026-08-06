package credential

import (
	"fmt"
	"slices"
)

// IntGenISISPresentationProverV3 builds the tag and canonical schema-3
// showing proof after a hidden slot has been durably burned.  Neither the
// slot nor the public context is serialized by the presentation envelope.
type IntGenISISPresentationProverV3 func(context PresentationContextBinding, slot uint8) (tag []int64, canonicalProof []byte, err error)

// IntGenISISProofVerifierV3 must canonical-decode and cryptographically verify
// CanonicalProof against the supplied trusted codec context.  Merely checking
// the presentation envelope or canonical-proof header is not verification.
type IntGenISISProofVerifierV3 func(presentation IntGenISISPresentationV3, context IntGenISISPresentationCodecContext) (bool, error)

func validateIntGenISISV3OperationBindings(public PublicParams, key IntGenISISVerifierKey, credential IntGenISISState, stateCtx IntGenISISStateCodecContext) error {
	if _, _, _, err := validateIntGenISISV3PublicKeyContext(public, key); err != nil {
		return err
	}
	if err := credential.ValidateAgainst(public, key); err != nil {
		return fmt.Errorf("validate credential presentation-v3 bindings: %w", err)
	}
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		return err
	}
	statePublicDigest, err := PublicParamsDigest(stateCtx.Public)
	if err != nil {
		return fmt.Errorf("digest state-v8 codec public parameters: %w", err)
	}
	keyDigest, err := key.Digest()
	if err != nil {
		return err
	}
	stateKeyDigest, err := stateCtx.VerifierKey.Digest()
	if err != nil {
		return fmt.Errorf("digest state-v8 codec verifier key: %w", err)
	}
	if publicDigest != statePublicDigest || keyDigest != stateKeyDigest {
		return fmt.Errorf("presentation-v3 and state-v8 codec public/key binding mismatch")
	}
	// This also checks the canonical state's routing path and all target-only
	// manifest gates before a holder slot can be consumed.
	if _, err := MarshalIntGenISISStateV8(credential, stateCtx); err != nil {
		return fmt.Errorf("validate canonical state-v8 operation source: %w", err)
	}
	return nil
}

func deriveIntGenISISPresentationCodecContextV3(public PublicParams, key IntGenISISVerifierKey, rawContext []byte) (PresentationContextBinding, IntGenISISPresentationCodecContext, error) {
	if _, _, _, err := validateIntGenISISV3PublicKeyContext(public, key); err != nil {
		return PresentationContextBinding{}, IntGenISISPresentationCodecContext{}, err
	}
	publicDigest, err := PublicParamsDigest(public)
	if err != nil {
		return PresentationContextBinding{}, IntGenISISPresentationCodecContext{}, err
	}
	keyDigest, err := key.Digest()
	if err != nil {
		return PresentationContextBinding{}, IntGenISISPresentationCodecContext{}, err
	}
	binding, err := DerivePresentationContext(rawContext, public.Modulus, public.PresetManifestDigest, publicDigest, keyDigest)
	if err != nil {
		return PresentationContextBinding{}, IntGenISISPresentationCodecContext{}, fmt.Errorf("derive presentation-v3 context: %w", err)
	}
	codecCtx := IntGenISISPresentationCodecContext{
		Public:      public,
		VerifierKey: key,
		Context:     append([]int64(nil), binding.Lanes...),
	}
	if _, _, _, err := validateIntGenISISPresentationV3Context(codecCtx); err != nil {
		return PresentationContextBinding{}, IntGenISISPresentationCodecContext{}, err
	}
	return binding, codecCtx, nil
}

// DeriveIntGenISISPresentationV3Context exposes the one canonical derivation
// used by creation, binary serialization, proof verification, and replay
// acceptance.  rawContext remains service-controlled input and is never
// included in the presentation wire.
func DeriveIntGenISISPresentationV3Context(public PublicParams, key IntGenISISVerifierKey, rawContext []byte) (PresentationContextBinding, IntGenISISPresentationCodecContext, error) {
	return deriveIntGenISISPresentationCodecContextV3(public, key, rawContext)
}

// CreatePresentationV3 derives the service-controlled context, atomically
// reserves the next target holder slot using state-v8 bindings, and invokes
// prove.  Prover or transport failure never rolls the reservation back.
func CreatePresentationV3(public PublicParams, key IntGenISISVerifierKey, credential IntGenISISState, stateCtx IntGenISISStateCodecContext, rawContext []byte, holderUsageStore string, prove IntGenISISPresentationProverV3) (IntGenISISPresentationV3, error) {
	if holderUsageStore == "" {
		return IntGenISISPresentationV3{}, fmt.Errorf("holder usage state-v3 path is required")
	}
	if prove == nil {
		return IntGenISISPresentationV3{}, fmt.Errorf("presentation-v3 prover is required")
	}
	if err := validateIntGenISISV3OperationBindings(public, key, credential, stateCtx); err != nil {
		return IntGenISISPresentationV3{}, err
	}
	binding, codecCtx, err := deriveIntGenISISPresentationCodecContextV3(public, key, rawContext)
	if err != nil {
		return IntGenISISPresentationV3{}, err
	}
	slot, err := ReserveIntGenISISSlotV3(holderUsageStore, credential, stateCtx, binding)
	if err != nil {
		return IntGenISISPresentationV3{}, err
	}
	proverBinding := PresentationContextBinding{Digest: binding.Digest, Lanes: append([]int64(nil), binding.Lanes...)}
	tag, canonicalProof, err := prove(proverBinding, slot)
	if err != nil {
		return IntGenISISPresentationV3{}, fmt.Errorf("create presentation-v3 proof after burning slot %d: %w", slot, err)
	}
	presentation := IntGenISISPresentationV3{
		Tag:            append([]int64(nil), tag...),
		CanonicalProof: append([]byte(nil), canonicalProof...),
	}
	if _, err := MarshalIntGenISISPresentationV3(presentation, codecCtx); err != nil {
		return IntGenISISPresentationV3{}, fmt.Errorf("validate generated presentation-v3 after burning slot %d: %w", slot, err)
	}
	return presentation, nil
}

func cloneIntGenISISPresentationV3(pres IntGenISISPresentationV3) IntGenISISPresentationV3 {
	return IntGenISISPresentationV3{
		Tag:            append([]int64(nil), pres.Tag...),
		CanonicalProof: append([]byte(nil), pres.CanonicalProof...),
	}
}

func verifyProofV3WithContext(presentation IntGenISISPresentationV3, public PublicParams, key IntGenISISVerifierKey, expectedContext []byte, verify IntGenISISProofVerifierV3) (bool, IntGenISISPresentationCodecContext, error) {
	if verify == nil {
		return false, IntGenISISPresentationCodecContext{}, fmt.Errorf("presentation-v3 proof verifier is required")
	}
	derived, codecCtx, err := deriveIntGenISISPresentationCodecContextV3(public, key, expectedContext)
	if err != nil {
		return false, IntGenISISPresentationCodecContext{}, err
	}
	if !slices.Equal(codecCtx.Context, derived.Lanes) {
		return false, IntGenISISPresentationCodecContext{}, fmt.Errorf("internal presentation-v3 context derivation mismatch")
	}
	// Enforce the canonical target envelope before entering the expensive proof
	// verifier.  The proof callback remains responsible for every proof-level
	// check and for binding these independently derived context lanes.
	if _, err := MarshalIntGenISISPresentationV3(presentation, codecCtx); err != nil {
		return false, IntGenISISPresentationCodecContext{}, err
	}
	callbackCtx := codecCtx
	callbackCtx.Context = append([]int64(nil), codecCtx.Context...)
	ok, err := verify(cloneIntGenISISPresentationV3(presentation), callbackCtx)
	if err != nil {
		return false, IntGenISISPresentationCodecContext{}, err
	}
	return ok, codecCtx, nil
}

// VerifyProofV3 performs proof-only verification with an independently
// derived context.  It neither reads nor mutates a replay store.
func VerifyProofV3(presentation IntGenISISPresentationV3, public PublicParams, key IntGenISISVerifierKey, expectedContext []byte, verify IntGenISISProofVerifierV3) (bool, error) {
	ok, _, err := verifyProofV3WithContext(presentation, public, key, expectedContext, verify)
	return ok, err
}

// VerifyAndAcceptV3 verifies the canonical proof and only then atomically
// records its tag in the target-only durable replay set.  Concurrent duplicate
// accepts have exactly one successful state transition.
func VerifyAndAcceptV3(presentation IntGenISISPresentationV3, public PublicParams, key IntGenISISVerifierKey, expectedContext []byte, verifierStore string, verify IntGenISISProofVerifierV3) (bool, error) {
	if verifierStore == "" {
		return false, fmt.Errorf("verifier state-v3 path is required")
	}
	ok, codecCtx, err := verifyProofV3WithContext(presentation, public, key, expectedContext, verify)
	if err != nil || !ok {
		return false, err
	}
	if err := CheckAndMarkIntGenISISPresentationV3(verifierStore, presentation, codecCtx); err != nil {
		return false, err
	}
	return true, nil
}
