package PIOP

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	IntGenISISReplayProjectionNone                          = "none"
	IntGenISISReplayProjectionProjectUYHatV1                = "project_u_y_hat_v1"
	IntGenISISReplayProjectionProjectUYHatYViewV2           = "project_u_y_hat_and_y_view_v2"
	IntGenISISReplayProjectionProjectUDigitsYViewV3         = "project_u_digits_and_y_view_v3"
	IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 = "project_u_digits_y_source_linear_v4"
	IntGenISISReplayProjectionProjectUDigitsYWResidualV5    = "project_u_digits_y_w_residual_v5"
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
	case IntGenISISReplayProjectionProjectUDigitsYViewV3:
		return IntGenISISReplayProjectionProjectUDigitsYViewV3
	case IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4:
		return IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4
	case IntGenISISReplayProjectionProjectUDigitsYWResidualV5:
		return IntGenISISReplayProjectionProjectUDigitsYWResidualV5
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func validateIntGenISISReplayProjection(mode string) error {
	switch normalizeIntGenISISReplayProjection(mode) {
	case IntGenISISReplayProjectionNone, IntGenISISReplayProjectionProjectUYHatV1, IntGenISISReplayProjectionProjectUYHatYViewV2, IntGenISISReplayProjectionProjectUDigitsYViewV3, IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4, IntGenISISReplayProjectionProjectUDigitsYWResidualV5:
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
	if l.LayoutVersion == intGenISISShowingLayoutVersionProjectionUDigitsYViewV3 {
		return IntGenISISReplayProjectionProjectUDigitsYViewV3
	}
	if l.LayoutVersion == intGenISISShowingLayoutVersionProjectionUDigitsYSourceLinearV4 {
		return IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4
	}
	if l.LayoutVersion == intGenISISShowingLayoutVersionProjectionUDigitsYWResidualV5 {
		return IntGenISISReplayProjectionProjectUDigitsYWResidualV5
	}
	return IntGenISISReplayProjectionNone
}

func intGenISISProjectionUsesProjectedUYHat(l *IntGenISISShowingRowLayout) bool {
	mode := intGenISISProjectionModeFromLayout(l)
	return mode == IntGenISISReplayProjectionProjectUYHatV1 || mode == IntGenISISReplayProjectionProjectUYHatYViewV2 || mode == IntGenISISReplayProjectionProjectUDigitsYViewV3 || mode == IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 || mode == IntGenISISReplayProjectionProjectUDigitsYWResidualV5
}

func intGenISISProjectionDerivesYView(l *IntGenISISShowingRowLayout) bool {
	mode := intGenISISProjectionModeFromLayout(l)
	return mode == IntGenISISReplayProjectionProjectUYHatYViewV2 || mode == IntGenISISReplayProjectionProjectUDigitsYViewV3 || mode == IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 || mode == IntGenISISReplayProjectionProjectUDigitsYWResidualV5
}

func intGenISISProjectionUsesDigitOnlyU(l *IntGenISISShowingRowLayout) bool {
	mode := intGenISISProjectionModeFromLayout(l)
	return mode == IntGenISISReplayProjectionProjectUDigitsYViewV3 || mode == IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 || mode == IntGenISISReplayProjectionProjectUDigitsYWResidualV5
}

func intGenISISProjectionUsesSourceLinearHats(l *IntGenISISShowingRowLayout) bool {
	return intGenISISProjectionModeFromLayout(l) == IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4
}

func intGenISISProjectionUsesBBTranWResidual(l *IntGenISISShowingRowLayout) bool {
	return intGenISISProjectionModeFromLayout(l) == IntGenISISReplayProjectionProjectUDigitsYWResidualV5
}
