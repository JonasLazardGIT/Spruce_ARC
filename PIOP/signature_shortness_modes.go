package PIOP

import "fmt"

type sigShortnessPackedRawSpec struct {
	Base      LinfSpec
	GroupSize int
}

func signaturePackedChainRowsPerGroupForOpts(spec LinfSpec, _ SimOpts, groupSize int) (int, error) {
	if _, err := buildSigShortnessPackedRawSpec(spec, groupSize); err != nil {
		return 0, err
	}
	return spec.L, nil
}

func signatureShortnessMaxDegree(spec LinfSpec, _ SimOpts) (int, error) {
	maxDeg := 1
	for i := 0; i < spec.L; i++ {
		if deg := maxDegreeFromCoeffs(spec.PDi[i]); deg > maxDeg {
			maxDeg = deg
		}
	}
	return maxDeg, nil
}

func buildSigShortnessPackedRawSpec(spec LinfSpec, groupSize int) (sigShortnessPackedRawSpec, error) {
	if spec.UsesAbsRow {
		return sigShortnessPackedRawSpec{}, fmt.Errorf("packed raw signature shortness requires signed chain mode")
	}
	if groupSize <= 0 {
		return sigShortnessPackedRawSpec{}, fmt.Errorf("packed raw signature shortness requires positive group size, got %d", groupSize)
	}
	return sigShortnessPackedRawSpec{Base: spec, GroupSize: groupSize}, nil
}
