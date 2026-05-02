package main

import (
	"flag"

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
		NCols:              spec.NCols,
		LVCSNCols:          spec.LVCSNCols,
		NLeaves:            spec.NLeaves,
		Eta:                spec.Eta,
		Theta:              spec.Theta,
		Rho:                spec.Rho,
		Ell:                spec.Ell,
		EllPrime:           spec.EllPrime,
		Kappa:              spec.Kappa,
		PRFCompanionMode:   PIOP.PRFCompanionMode(spec.PRFCompanionMode),
		PRFGroupRounds:     spec.PRFGroupRounds,
		CheckpointSamples:  spec.CheckpointSamples,
		SigShortnessRadix:  spec.SigShortnessRadix,
		SigShortnessDigits: spec.SigShortnessDigits,
		CompressedRows:     spec.CompressedRows,
		ReplayProjection:   spec.ReplayProjection,
	}
}

func intGenISISTuningPresetFromTuning(t intGenISISTuning, target float64) credential.IntGenISISTuningPreset {
	return credential.IntGenISISTuningPreset{
		NCols:              t.NCols,
		LVCSNCols:          t.LVCSNCols,
		NLeaves:            t.NLeaves,
		Eta:                t.Eta,
		Theta:              t.Theta,
		Rho:                t.Rho,
		Ell:                t.Ell,
		EllPrime:           t.EllPrime,
		Kappa:              t.Kappa,
		PRFCompanionMode:   string(t.PRFCompanionMode),
		PRFGroupRounds:     t.PRFGroupRounds,
		CheckpointSamples:  t.CheckpointSamples,
		SigShortnessRadix:  t.SigShortnessRadix,
		SigShortnessDigits: t.SigShortnessDigits,
		CompressedRows:     t.CompressedRows,
		ReplayProjection:   t.ReplayProjection,
		TargetEq8Bits:      target,
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

func applyShowingSpecificFlagOverrides(t *intGenISISTuning, set map[string]bool, companionMode PIOP.PRFCompanionMode, prfGroupRounds, checkpointSamples, shortnessRadix, shortnessDigits, compressedRows int, replayProjection string) {
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
}
