package main

import (
	"vSIS-Signature/credential"
	"vSIS-Signature/ntru/signverify"
)

// SignatureBoundAuditReport compares the persisted showing-state signature norm
// against the deterministic production beta calibration policy.
type SignatureBoundAuditReport struct {
	ProductionBeta       uint64  `json:"production_beta"`
	StateMaxS1           int64   `json:"state_max_s1"`
	StateMaxS2           int64   `json:"state_max_s2"`
	StateMax             int64   `json:"state_max"`
	CalibrationSamples   int     `json:"calibration_samples"`
	CalibrationAlpha     float64 `json:"calibration_alpha"`
	CalibrationBatchMax  int64   `json:"calibration_batch_max"`
	CalibrationMaxSample int     `json:"calibration_max_sample"`
	SlackRatio           float64 `json:"slack_ratio"`
}

func buildSignatureBoundAuditReport(st credential.State, beta uint64, calibration *signverify.BetaCalibrationReport) SignatureBoundAuditReport {
	maxS1, maxS2, maxSig := st.SignatureCoordLinf()
	out := SignatureBoundAuditReport{
		ProductionBeta: beta,
		StateMaxS1:     maxS1,
		StateMaxS2:     maxS2,
		StateMax:       maxSig,
	}
	if calibration != nil {
		out.CalibrationSamples = calibration.Samples
		out.CalibrationAlpha = calibration.Alpha
		out.CalibrationBatchMax = calibration.BatchMax
		out.CalibrationMaxSample = calibration.BatchMaxIndex
	}
	if maxSig > 0 {
		out.SlackRatio = float64(beta) / float64(maxSig)
	}
	return out
}
