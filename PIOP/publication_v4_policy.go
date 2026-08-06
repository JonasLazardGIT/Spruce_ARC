package PIOP

import (
	"fmt"
	"strings"

	"vSIS-Signature/credential"
)

type PublicationV4WidthPolicy struct {
	FSOutputBits     int
	HashBits         int
	TapeBits         int
	SaltBits         int
	NativeTargetBits float64
	WorkFactor       bool
}

func PublicationV4WidthPolicyForPreset(presetID string) (PublicationV4WidthPolicy, bool) {
	preset, ok := credential.LookupIntGenISISPublicationPreset(strings.TrimSpace(presetID))
	if !ok || credential.ValidateIntGenISISPresetManifest(preset) != nil {
		return PublicationV4WidthPolicy{}, false
	}
	tuning := preset.Showing
	return PublicationV4WidthPolicy{
		FSOutputBits:     tuning.FSOutputBits,
		HashBits:         tuning.DECSHashBits,
		TapeBits:         tuning.DECSTapeBits,
		SaltBits:         tuning.SaltBits,
		NativeTargetBits: preset.TargetTheoremBits,
		WorkFactor:       preset.SecurityMode == string(credential.SecurityModeQueryWorkFactor),
	}, true
}

func publicationV4UsesWorkFactor(opts SimOpts) bool {
	policy, ok := PublicationV4WidthPolicyForPreset(opts.PresetID)
	return ok && policy.WorkFactor
}

// ValidatePublicationV4Widths rejects every unset, fallback, non-byte-aligned,
// unsupported, or undersized cryptographic width before proof construction or
// verification. The exact-five policy is intentionally keyed by trusted
// manifest identity, not by theta or another shared geometry parameter.
func ValidatePublicationV4Widths(opts SimOpts) error {
	if !transcriptUsesPublicationV4(opts.TranscriptVersion) {
		return nil
	}
	policy, ok := PublicationV4WidthPolicyForPreset(opts.PresetID)
	if !ok {
		return fmt.Errorf("publication-v4 has no width policy for trusted preset %q", opts.PresetID)
	}
	for name, bits := range map[string]int{
		"FSOutputBits":      opts.FSOutputBits,
		"FSCollisionBits":   opts.FSCollisionBits,
		"DECSCollisionBits": opts.DECSCollisionBits,
		"DECSHashBits":      opts.DECSHashBits,
		"DECSTapeBits":      opts.DECSTapeBits,
		"SaltBits":          opts.SaltBits,
	} {
		if bits <= 0 || bits%8 != 0 {
			return fmt.Errorf("publication-v4 %s=%d must be positive and byte-aligned", name, bits)
		}
	}
	if opts.FSOutputBits != policy.FSOutputBits || opts.FSCollisionBits != policy.HashBits ||
		opts.DECSCollisionBits != policy.HashBits || opts.DECSHashBits != policy.HashBits ||
		opts.DECSTapeBits != policy.TapeBits || opts.SaltBits != policy.SaltBits {
		return fmt.Errorf(
			"publication-v4 preset %q widths (fs,fs_collision,decs_collision,decs_hash,tape,salt)=(%d,%d,%d,%d,%d,%d), want (%d,%d,%d,%d,%d,%d)",
			opts.PresetID,
			opts.FSOutputBits, opts.FSCollisionBits, opts.DECSCollisionBits, opts.DECSHashBits, opts.DECSTapeBits, opts.SaltBits,
			policy.FSOutputBits, policy.HashBits, policy.HashBits, policy.HashBits, policy.TapeBits, policy.SaltBits,
		)
	}
	if _, err := ResolveFSOutputBits(opts); err != nil {
		return err
	}
	return nil
}

func validatePublicationV4SoundnessBudget(opts SimOpts, sb SoundnessBudget) error {
	if !transcriptUsesPublicationV4(opts.TranscriptVersion) {
		return nil
	}
	policy, ok := PublicationV4WidthPolicyForPreset(opts.PresetID)
	if !ok {
		return fmt.Errorf("publication-v4 has no soundness policy for trusted preset %q", opts.PresetID)
	}
	if !policy.WorkFactor {
		for i, bits := range sb.NativeAlgebraicBits {
			if bits+1e-9 < policy.NativeTargetBits {
				return fmt.Errorf("publication-v4 preset %q native algebraic branch %d=%g bits want at least %g", opts.PresetID, i, bits, policy.NativeTargetBits)
			}
		}
		return nil
	}
	if sb.CollisionSpaceBits/2 < 128 {
		return fmt.Errorf("WF128 collision work factor=%d bits want at least 128", sb.CollisionSpaceBits/2)
	}
	for i, bits := range sb.NativeAlgebraicBits {
		if bits < 128 {
			return fmt.Errorf("WF128 native algebraic branch %d=%g bits want at least 128", i, bits)
		}
	}
	if sb.DECSTapeBits < 136 {
		return fmt.Errorf("WF128 tape/ZK gate=%d bits want at least 136", sb.DECSTapeBits)
	}
	return nil
}
