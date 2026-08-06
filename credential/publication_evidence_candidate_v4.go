package credential

import (
	"fmt"
	"sync/atomic"
)

// publicationEvidenceCandidate is a process-local, serialized registry shadow
// used only by the publication tuner. It lets one compiled source execute and
// verify several manifest-bound finalist tuples without mutating the live
// exact-five registry or mislabelling a projected tuple with an incumbent
// manifest digest.
var publicationEvidenceCandidate atomic.Pointer[IntGenISISPreset]
var publicationEvidenceCandidateActive atomic.Bool

// WithIntGenISISPublicationEvidenceCandidate executes fn while candidate is
// the trusted manifest returned for its exact publication-v4 canonical ID.
//
// The override is deliberately scoped to one callback, rejects nesting and
// concurrent use, and accepts only a fully valid exact-five publication-v4
// manifest. It is evidence machinery, not a deployment configuration API.
func WithIntGenISISPublicationEvidenceCandidate(candidate IntGenISISPreset, fn func() error) error {
	if fn == nil {
		return fmt.Errorf("publication evidence candidate callback is nil")
	}
	if !isIntGenISISPublicationPresetV4ID(candidate.CanonicalID) || candidate.Name != candidate.CanonicalID || candidate.PresetVersion != IntGenISISPresetManifestVersionV4 {
		return fmt.Errorf("publication evidence candidate is not an exact-five manifest-v4 identity")
	}
	base, ok := intGenISISPresetRegistry()[candidate.CanonicalID]
	if !ok || base.PresetVersion != IntGenISISPresetManifestVersionV4 {
		return fmt.Errorf("publication evidence candidate base %q is unavailable", candidate.CanonicalID)
	}
	if candidate.PublicationLabel != base.PublicationLabel || candidate.Profile != base.Profile ||
		candidate.SecurityProfile != base.SecurityProfile || candidate.SecurityMode != base.SecurityMode ||
		candidate.PRFProfile != base.PRFProfile || candidate.PRFParamsDigest != base.PRFParamsDigest ||
		candidate.ClaimScope != base.ClaimScope || candidate.CompleteSystemClaim != base.CompleteSystemClaim ||
		candidate.ThreatModel != base.ThreatModel || candidate.RateLimitPolicy != base.RateLimitPolicy {
		return fmt.Errorf("publication evidence candidate changes a frozen identity, primitive, or security-policy binding")
	}
	if err := ValidateIntGenISISPresetManifest(candidate); err != nil {
		return fmt.Errorf("invalid publication evidence candidate: %w", err)
	}
	if !publicationEvidenceCandidateActive.CompareAndSwap(false, true) {
		return fmt.Errorf("publication evidence candidate session is already active")
	}
	copyCandidate := candidate
	publicationEvidenceCandidate.Store(&copyCandidate)
	defer func() {
		publicationEvidenceCandidate.Store(nil)
		publicationEvidenceCandidateActive.Store(false)
	}()
	return fn()
}

func lookupIntGenISISPublicationEvidenceCandidate(canonicalID string) (IntGenISISPreset, bool) {
	candidate := publicationEvidenceCandidate.Load()
	if candidate == nil || candidate.CanonicalID != canonicalID {
		return IntGenISISPreset{}, false
	}
	return *candidate, true
}
