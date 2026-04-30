package PIOP

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	IntGenISISReplayProjectionNone                = "none"
	IntGenISISReplayProjectionProjectUYHatV1      = "project_u_y_hat_v1"
	IntGenISISReplayProjectionProjectUYHatYViewV2 = "project_u_y_hat_and_y_view_v2"
)

type intGenISISReplayProjectionDescriptor struct {
	Version string `json:"version"`
	Mode    string `json:"mode"`
}

func normalizeIntGenISISReplayProjection(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", IntGenISISReplayProjectionNone:
		return IntGenISISReplayProjectionNone
	case IntGenISISReplayProjectionProjectUYHatV1:
		return IntGenISISReplayProjectionProjectUYHatV1
	case IntGenISISReplayProjectionProjectUYHatYViewV2:
		return IntGenISISReplayProjectionProjectUYHatYViewV2
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func validateIntGenISISReplayProjection(mode string) error {
	switch normalizeIntGenISISReplayProjection(mode) {
	case IntGenISISReplayProjectionNone, IntGenISISReplayProjectionProjectUYHatV1, IntGenISISReplayProjectionProjectUYHatYViewV2:
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
		Version: "intgenisis_replay_projection_v1",
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
	if l.LayoutVersion == intGenISISShowingLayoutVersionProjectionUYHatV1 {
		return IntGenISISReplayProjectionProjectUYHatV1
	}
	if l.LayoutVersion == intGenISISShowingLayoutVersionProjectionUYHatYViewV2 {
		return IntGenISISReplayProjectionProjectUYHatYViewV2
	}
	return IntGenISISReplayProjectionNone
}

func intGenISISProjectionUsesProjectedUYHat(l *IntGenISISShowingRowLayout) bool {
	mode := intGenISISProjectionModeFromLayout(l)
	return mode == IntGenISISReplayProjectionProjectUYHatV1 || mode == IntGenISISReplayProjectionProjectUYHatYViewV2
}

func intGenISISProjectionDerivesYView(l *IntGenISISShowingRowLayout) bool {
	return intGenISISProjectionModeFromLayout(l) == IntGenISISReplayProjectionProjectUYHatYViewV2
}
