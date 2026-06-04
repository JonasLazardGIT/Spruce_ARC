package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildCredentialRowsShowing builds the retained showing witness surface.
func BuildCredentialRowsShowing(
	ringQ *ring.Ring,
	pub PublicInputs,
	wit WitnessInputs,
	prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds int,
	opts SimOpts,
) (
	rows []*ring.Poly,
	rowInputs []lvcs.RowInput,
	layout RowLayout,
	prfLayout *PRFLayout,
	prfCompanionLayout *PRFCompanionLayout,
	decsParams decs.Params,
	maskRowOffset, maskRowCount, witnessCount, startIdx, ncols int,
	err error,
) {
	if ringQ == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()
	if !opts.CoeffPacking {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("showing requires coeff packing")
	}
	if wit.CoeffNativeShowing == nil {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("showing requires WitnessInputs.CoeffNativeShowing")
	}
	if len(pub.A) == 0 || len(pub.B) == 0 {
		return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("showing requires non-empty post-sign public inputs A and B")
	}
	if pub.IntGenISIS {
		return BuildCredentialRowsShowingIntGenISIS(
			ringQ, pub, wit, prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds, opts,
		)
	}
	return nil, nil, RowLayout{}, nil, nil, decs.Params{}, 0, 0, 0, 0, 0, fmt.Errorf("non-IntGenISIS showing rows are no longer supported")
}
