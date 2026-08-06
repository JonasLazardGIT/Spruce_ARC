package PIOP

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"vSIS-Signature/credential"
	"vSIS-Signature/prf"
)

func loadPRFParamsForOpts(opts SimOpts) (*prf.Params, error) {
	path := opts.PRFParamsPath
	if path == "" {
		return prf.LoadLocalOrDefaultParams("prf/prf_params.json")
	}
	return prf.LoadLocalOrBundledParams(path)
}

func optsWithTrustedPresetID(opts SimOpts, pub PublicInputs) (SimOpts, error) {
	fromOpts := strings.TrimSpace(opts.PresetID)
	fromPublic := ""
	if pub.Extras != nil {
		if raw, ok := pub.Extras["IntGenISIS.preset_id"].([]byte); ok {
			fromPublic = strings.TrimSpace(string(raw))
		}
	}
	if fromOpts != "" && fromPublic != "" && fromOpts != fromPublic {
		return SimOpts{}, fmt.Errorf("trusted preset ID mismatch: options=%q public=%q", fromOpts, fromPublic)
	}
	if fromOpts == "" {
		fromOpts = fromPublic
	}
	if transcriptUsesPublicationV4(opts.TranscriptVersion) && fromOpts == "" {
		return SimOpts{}, fmt.Errorf("publication-v4 requires manifest-bound IntGenISIS.preset_id")
	}
	opts.PresetID = fromOpts
	return opts, nil
}

// loadTargetPRFParamsForPresetV3 resolves a strict-v3 PRF profile against the
// build-time embedded target. A runtime path is operational only: if present,
// its complete decoded relation constants must equal the fixed profile.
func loadTargetPRFParamsForPresetV3(preset credential.IntGenISISPreset, opts SimOpts) (*prf.Params, []byte, error) {
	expected, expectedCanonical, err := prf.LoadEmbeddedTargetParamsV3(preset.PRFParamsPath)
	if err != nil {
		return nil, nil, err
	}
	embeddedDigest, err := prf.EmbeddedTargetParamsFileDigestV3(preset.PRFParamsPath)
	if err != nil || embeddedDigest != preset.PRFParamsDigest {
		return nil, nil, fmt.Errorf("strict-v3 embedded PRF source does not match pinned profile digest for %q", preset.PRFProfile)
	}
	wantTag, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok || expected.Q != credential.IntGenISISSharedModulusQ || expected.LenTag != wantTag {
		return nil, nil, fmt.Errorf("strict-v3 embedded PRF profile %q does not match preset %q", preset.PRFProfile, preset.CanonicalID)
	}

	path := strings.TrimSpace(opts.PRFParamsPath)
	if path == "" {
		return expected, expectedCanonical, nil
	}
	actual, actualCanonical, err := prf.LoadParamsFileWithCanonicalBytesV3(path)
	if err != nil {
		// The canonical preset path is a relocatable installation hint. When
		// it is absent from the process working directory, use the embedded
		// profile. Arbitrary explicit paths never receive such a fallback.
		if errors.Is(err, os.ErrNotExist) && filepath.Clean(path) == filepath.Clean(preset.PRFParamsPath) {
			return expected, expectedCanonical, nil
		}
		return nil, nil, fmt.Errorf("load strict-v3 PRF params %q: %w", path, err)
	}
	if !bytes.Equal(actualCanonical, expectedCanonical) {
		return nil, nil, fmt.Errorf("strict-v3 PRF params %q do not match fixed profile %q", path, preset.PRFProfile)
	}
	return actual, expectedCanonical, nil
}

func targetPresetForPRFOptsV3(opts SimOpts) (credential.IntGenISISPreset, error) {
	presetID := strings.TrimSpace(opts.PresetID)
	if presetID == "" {
		// Historical v3 callers predate the explicit identity field. Preserve
		// replay only for the two frozen v3 tuples; publication v4 always fails
		// closed rather than inferring a preset from theta.
		if transcriptUsesPublicationV4(opts.TranscriptVersion) {
			return credential.IntGenISISPreset{}, fmt.Errorf("publication-v4 requires a trusted preset ID")
		}
		switch opts.Theta {
		case 7:
			presetID = credential.IntGenISISPresetSystemN1024WF128CROMV2
		case 13:
			presetID = credential.IntGenISISPresetPoCN1024BQ128R128V3
		default:
			return credential.IntGenISISPreset{}, fmt.Errorf("historical strict-v3 unsupported theta=%d PRF profile", opts.Theta)
		}
	}
	preset, ok := credential.LookupIntGenISISPreset(presetID)
	if !ok {
		return credential.IntGenISISPreset{}, fmt.Errorf("missing strict target preset %q", presetID)
	}
	if preset.CanonicalID != presetID {
		return credential.IntGenISISPreset{}, fmt.Errorf("preset lookup %q returned canonical ID %q", presetID, preset.CanonicalID)
	}
	return preset, nil
}

func loadTargetPRFParamsForOptsV3(opts SimOpts) (*prf.Params, []byte, error) {
	preset, err := targetPresetForPRFOptsV3(opts)
	if err != nil {
		return nil, nil, err
	}
	return loadTargetPRFParamsForPresetV3(preset, opts)
}

// loadBoundPRFParamsForOpts is the common relation-loader boundary. Legacy
// transcripts retain their historical file policy; strict v3 always resolves
// and checks the fixed embedded profile before any relation code executes.
func loadBoundPRFParamsForOpts(opts SimOpts) (*prf.Params, error) {
	if transcriptUsesSmallWood2025V3(opts.TranscriptVersion) {
		params, _, err := loadTargetPRFParamsForOptsV3(opts)
		return params, err
	}
	return loadPRFParamsForOpts(opts)
}
