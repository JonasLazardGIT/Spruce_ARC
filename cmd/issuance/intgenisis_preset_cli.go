package main

import (
	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
)

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
		ROQueryCaps:            spec.ROQueryCaps,
		ROQueryCapsSet:         spec.ROQueryCapsSet,
		ROQueryCapBits:         spec.ROQueryCapBits,
		ROQueryCapBitsSet:      spec.ROQueryCapBitsSet,
		DECSCollisionBits:      spec.DECSCollisionBits,
		DECSHashBits:           spec.DECSHashBits,
		DECSTapeBits:           spec.DECSTapeBits,
		FSCollisionBits:        spec.FSCollisionBits,
		SaltBits:               spec.SaltBits,
		PRFProfile:             spec.PRFProfile,
		PRFParamsPath:          spec.PRFParamsPath,
		PRFCompanionMode:       PIOP.PRFCompanionMode(spec.PRFCompanionMode),
		PRFGroupRounds:         spec.PRFGroupRounds,
		CheckpointSamples:      spec.CheckpointSamples,
		SigShortnessRadix:      spec.SigShortnessRadix,
		SigShortnessDigits:     spec.SigShortnessDigits,
		CompressedRows:         spec.CompressedRows,
		ReplayProjection:       spec.ReplayProjection,
		TranscriptMode:         spec.TranscriptMode,
		TranscriptOmissionMode: spec.TranscriptOmissionMode,
		FixedTranscriptSize:    spec.FixedTranscriptSize,
		FixedTranscriptSizeSet: spec.FixedTranscriptSize,
	}
}
