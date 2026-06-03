package main

import (
	"flag"
	"fmt"
	"strings"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

func visitedFlagNames(fs *flag.FlagSet) map[string]bool {
	out := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		out[f.Name] = true
	})
	return out
}

func intGenISISTuningFromPresetSpec(spec credential.IntGenISISTuningPreset) intGenISISTuning {
	return intGenISISTuning{
		NCols:                  spec.NCols,
		LVCSNCols:              spec.LVCSNCols,
		NLeaves:                spec.NLeaves,
		Eta:                    spec.Eta,
		Theta:                  spec.Theta,
		Rho:                    spec.Rho,
		Ell:                    spec.Ell,
		EllPrime:               spec.EllPrime,
		Kappa:                  spec.Kappa,
		PRFCompanionMode:       PIOP.PRFCompanionMode(spec.PRFCompanionMode),
		PRFGroupRounds:         spec.PRFGroupRounds,
		CheckpointSamples:      spec.CheckpointSamples,
		SigShortnessRadix:      spec.SigShortnessRadix,
		SigShortnessDigits:     spec.SigShortnessDigits,
		CompressedRows:         spec.CompressedRows,
		ReplayProjection:       spec.ReplayProjection,
		TranscriptMode:         spec.TranscriptMode,
		FixedTranscriptSize:    spec.FixedTranscriptSize,
		FixedTranscriptSizeSet: spec.FixedTranscriptSize,
	}
}

func applyCommonTuningFlagOverrides(t *intGenISISTuning, set map[string]bool, ncols, lvcsNCols, nLeaves, eta, theta, rho, ell, ellPrime int, kappa [4]int) {
	if set["ncols"] {
		t.NCols = ncols
	}
	if set["lvcs-ncols"] {
		t.LVCSNCols = lvcsNCols
	}
	if set["nleaves"] {
		t.NLeaves = nLeaves
	}
	if set["eta"] {
		t.Eta = eta
	}
	if set["theta"] {
		t.Theta = theta
	}
	if set["rho"] {
		t.Rho = rho
	}
	if set["ell"] {
		t.Ell = ell
	}
	if set["ell-prime"] {
		t.EllPrime = ellPrime
	}
	if set["kappa1"] || set["kappa2"] || set["kappa3"] || set["kappa4"] {
		t.Kappa = kappa
	}
}

func applyPrefixedTuningFlagOverrides(t *intGenISISTuning, set map[string]bool, prefix string, ncols, lvcsNCols, nLeaves, eta, theta, rho, ell, ellPrime int) {
	if set[prefix+"ncols"] {
		t.NCols = ncols
	}
	if set[prefix+"lvcs-ncols"] {
		t.LVCSNCols = lvcsNCols
	}
	if set[prefix+"nleaves"] {
		t.NLeaves = nLeaves
	}
	if set[prefix+"eta"] {
		t.Eta = eta
	}
	if set[prefix+"theta"] {
		t.Theta = theta
	}
	if set[prefix+"rho"] {
		t.Rho = rho
	}
	if set[prefix+"ell"] {
		t.Ell = ell
	}
	if set[prefix+"ell-prime"] {
		t.EllPrime = ellPrime
	}
}

func applyShowingSpecificFlagOverrides(t *intGenISISTuning, set map[string]bool, companionMode PIOP.PRFCompanionMode, prfGroupRounds, checkpointSamples, shortnessRadix, shortnessDigits, compressedRows int, replayProjection, transcriptMode string) {
	if set["prf-companion-mode"] {
		t.PRFCompanionMode = companionMode
	}
	if set["prf-group-rounds"] {
		t.PRFGroupRounds = prfGroupRounds
	}
	if set["prf-checkpoint-samples"] {
		t.CheckpointSamples = checkpointSamples
	}
	if set["showing-sig-shortness-radix"] {
		t.SigShortnessRadix = shortnessRadix
	}
	if set["showing-sig-shortness-digits"] {
		t.SigShortnessDigits = shortnessDigits
	}
	if set["showing-compressed-rows"] {
		t.CompressedRows = compressedRows
	}
	if set["showing-replay-projection"] {
		t.ReplayProjection = replayProjection
	}
	if set["showing-transcript-mode"] {
		t.TranscriptMode = transcriptMode
	}
}

func applyIssuanceSpecificFlagOverrides(t *intGenISISTuning, set map[string]bool, transcriptMode string) {
	if set["issuance-transcript-mode"] {
		t.TranscriptMode = transcriptMode
	}
}

func applyTranscriptSizeFlag(t *intGenISISTuning, mode string) error {
	value, ok, err := parseTranscriptSizeFlag(mode)
	if err != nil || !ok {
		return err
	}
	t.FixedTranscriptSize = value
	t.FixedTranscriptSizeSet = true
	return nil
}

func applyTranscriptSizeFlagOverrides(issuance, showing *intGenISISTuning, set map[string]bool, sharedMode, issuanceMode, showingMode string) error {
	if set["fixed-transcript-size"] {
		if err := applyTranscriptSizeFlag(issuance, sharedMode); err != nil {
			return err
		}
		if err := applyTranscriptSizeFlag(showing, sharedMode); err != nil {
			return err
		}
	}
	if set["issuance-fixed-transcript-size"] {
		if err := applyTranscriptSizeFlag(issuance, issuanceMode); err != nil {
			return err
		}
	}
	if set["showing-fixed-transcript-size"] {
		if err := applyTranscriptSizeFlag(showing, showingMode); err != nil {
			return err
		}
	}
	return nil
}

func parseTranscriptSizeFlag(mode string) (value bool, ok bool, err error) {
	mode = strings.TrimSpace(strings.ToLower(mode))
	switch mode {
	case "", "auto":
		return false, false, nil
	case "on", "true", "1", "fixed", "fixed_size":
		return true, true, nil
	case "off", "false", "0", "compact", "legacy":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("unknown transcript size mode %q (supported: auto, on, off)", mode)
	}
}
