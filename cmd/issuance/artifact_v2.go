package main

import (
	"fmt"
	"slices"

	"vSIS-Signature/credential"
)

func validatePersistedSmallWoodV2(kind string, ncols, lvcsNCols, nLeaves int, omega []uint64, spec *smallWoodTuningSpec) error {
	if spec == nil {
		return fmt.Errorf("%s is missing the v2 SmallWood transcript tuple; no migration is supported; rerun setup and issuance", kind)
	}
	if ncols <= 0 || lvcsNCols < ncols || nLeaves <= 0 {
		return fmt.Errorf("%s has invalid outer SmallWood geometry ncols=%d lvcs_ncols=%d nleaves=%d", kind, ncols, lvcsNCols, nLeaves)
	}
	if spec.NCols != ncols || spec.LVCSNCols != lvcsNCols || spec.NLeaves != nLeaves {
		return fmt.Errorf("%s outer and nested SmallWood geometry differ", kind)
	}
	if len(omega) != ncols {
		return fmt.Errorf("%s omega length=%d want exact ncols=%d", kind, len(omega), ncols)
	}
	if spec.Ell <= 0 || spec.EllPrime <= 0 || spec.Eta <= 0 || spec.Theta <= 0 || spec.Rho <= 0 {
		return fmt.Errorf("%s has incomplete SmallWood relation geometry", kind)
	}
	if _, _, err := credential.ResolveIntGenISISTranscript(spec.TranscriptMode); err != nil {
		return fmt.Errorf("%s transcript tuple: %w", kind, err)
	}
	if _, err := credential.ResolveIntGenISISTranscriptOmission(spec.TranscriptOmissionMode); err != nil {
		return fmt.Errorf("%s transcript omission tuple: %w", kind, err)
	}
	if !spec.FixedTranscriptSize {
		return fmt.Errorf("%s must use the fixed v2 transcript shape", kind)
	}
	return nil
}

func validatePersistedOmegaV2(kind string, persisted, expected []uint64) error {
	if !slices.Equal(persisted, expected) {
		return fmt.Errorf("%s omega does not match the independently resolved preset transcript", kind)
	}
	return nil
}

func validateMatchingSmallWoodV2(leftKind string, left *smallWoodTuningSpec, rightKind string, right *smallWoodTuningSpec) error {
	if left == nil || right == nil || *left != *right {
		return fmt.Errorf("%s and %s SmallWood transcript tuples differ", leftKind, rightKind)
	}
	return nil
}
