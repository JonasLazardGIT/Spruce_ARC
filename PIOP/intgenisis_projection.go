package PIOP

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	IntGenISISReplayProjectionNone                            = "none"
	IntGenISISReplayProjectionProjectUDigitsYViewV3           = "project_u_digits_and_y_view_v3"
	IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6 = "project_u_digits_y_bounded_sources_v6"
)

type intGenISISReplayProjectionDescriptor struct {
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

func normalizeIntGenISISReplayProjection(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", IntGenISISReplayProjectionNone:
		return IntGenISISReplayProjectionNone
	case IntGenISISReplayProjectionProjectUDigitsYViewV3:
		return IntGenISISReplayProjectionProjectUDigitsYViewV3
	case IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6:
		return IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func validateIntGenISISReplayProjection(mode string) error {
	switch normalizeIntGenISISReplayProjection(mode) {
	case IntGenISISReplayProjectionNone, IntGenISISReplayProjectionProjectUDigitsYViewV3, IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6:
		return nil
	default:
		return fmt.Errorf("unsupported IntGenISIS replay projection mode %q", mode)
	}
}

func intGenISISReplayProjectionDescriptorBytes(mode string) ([]byte, error) {
	mode = normalizeIntGenISISReplayProjection(mode)
	if err := validateIntGenISISReplayProjection(mode); err != nil {
		return nil, err
	}
	return json.Marshal(intGenISISReplayProjectionDescriptor{
		Version: "intgenisis_replay_projection_v2",
		Mode:    mode,
	})
}

func intGenISISProjectionModeFromLayout(l *IntGenISISShowingRowLayout) string {
	if l == nil {
		return IntGenISISReplayProjectionNone
	}
	mode := normalizeIntGenISISReplayProjection(l.ReplayProjection)
	if mode != IntGenISISReplayProjectionNone {
		return mode
	}
	if l.LayoutVersion == intGenISISShowingLayoutVersionProjectionUDigitsYViewBoundedV4 {
		return IntGenISISReplayProjectionProjectUDigitsYViewV3
	}
	if l.LayoutVersion == intGenISISShowingLayoutVersionProjectionUDigitsYBoundedSourcesV6 {
		return IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
	}
	return IntGenISISReplayProjectionNone
}

func intGenISISProjectionUsesProjectedUYHat(l *IntGenISISShowingRowLayout) bool {
	mode := intGenISISProjectionModeFromLayout(l)
	return mode == IntGenISISReplayProjectionProjectUDigitsYViewV3 || mode == IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
}

func intGenISISProjectionDerivesYView(l *IntGenISISShowingRowLayout) bool {
	mode := intGenISISProjectionModeFromLayout(l)
	return mode == IntGenISISReplayProjectionProjectUDigitsYViewV3 || mode == IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
}

func intGenISISProjectionUsesDigitOnlyU(l *IntGenISISShowingRowLayout) bool {
	mode := intGenISISProjectionModeFromLayout(l)
	return mode == IntGenISISReplayProjectionProjectUDigitsYViewV3 || mode == IntGenISISReplayProjectionProjectUDigitsYBoundedSourcesV6
}

func intGenISISProjectionUsesBBTranWResidual(l *IntGenISISShowingRowLayout) bool {
	// Bounded BB-tran v2 always retains the individual bounded sources. The W
	// full-image projection is not a supported proof relation.
	return false
}
