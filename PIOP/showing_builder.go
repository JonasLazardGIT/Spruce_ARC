package PIOP

import (
	"fmt"
	"path/filepath"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/prf"

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
	return buildCredentialRowsShowingCoeffNativeLiteralPacked(
		ringQ, pub, wit, prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP, prfGroupRounds, opts,
	)
}

// BuildShowingCombined constructs the one supported showing statement:
// the coeff-native literal-packed post-sign proof with grouped PRF rows.
func BuildShowingCombined(pub PublicInputs, wit WitnessInputs, opts SimOpts) (*Proof, error) {
	opts.applyDefaults()
	if !opts.Credential || !opts.CoeffPacking {
		return nil, fmt.Errorf("showing requires credential coeff-packing mode")
	}
	if wit.CoeffNativeShowing == nil {
		return nil, fmt.Errorf("showing requires WitnessInputs.CoeffNativeShowing")
	}
	if pub.IntGenISIS {
		return BuildIntGenISISShowingCombined(pub, wit, opts)
	}
	// The live one-root showing path is the PRF companion route. The legacy
	// one-root PRF replay is no longer selectable here.
	opts.EnablePackedPRFWitnessRows = true
	opts.EnablePRFCompanion = true
	if normalizePRFCompanionMode(opts.PRFCompanionMode) == "" {
		opts.PRFCompanionMode = PRFCompanionModeOutputAudit
	}
	for attempt := 0; attempt < 4; attempt++ {
		ringQ, omega, pcsNCols, err := loadParamsAndOmegaForRelation(opts, pub.HashRelation)
		if err != nil {
			return nil, fmt.Errorf("load params: %w", err)
		}
		witnessNCols := opts.NCols
		if witnessNCols <= 0 {
			witnessNCols = pcsNCols
		}
		if pcsNCols < witnessNCols {
			return nil, fmt.Errorf("invalid lvcs ncols=%d (must be >= witness ncols=%d)", pcsNCols, witnessNCols)
		}
		if opts.DomainMode == DomainModeExplicit {
			nLeaves := opts.NLeaves
			if nLeaves <= 0 {
				nLeaves = int(ringQ.N)
			}
			ell := opts.Ell
			if pcsNCols+ell > int(ringQ.N) {
				return nil, fmt.Errorf("explicit domain: need ncols+ell <= ring dimension (ncols=%d ell=%d ringN=%d)", pcsNCols, ell, ringQ.N)
			}
			derivedOmega, _, derr := deriveExplicitDomainForRelation(ringQ.Modulus[0], nLeaves, witnessNCols, pcsNCols, ell, pub.HashRelation)
			if derr != nil {
				return nil, fmt.Errorf("explicit domain: %w", derr)
			}
			omega = derivedOmega
			pcsNCols = len(omega)
		}
		omegaWitness := omega
		if len(omegaWitness) < witnessNCols {
			return nil, fmt.Errorf("omega len=%d < witness ncols=%d", len(omegaWitness), witnessNCols)
		}
		if opts.DomainMode == DomainModeExplicit {
			nLeaves := opts.NLeaves
			if nLeaves <= 0 {
				nLeaves = int(ringQ.N)
			}
			omegaWitness, err = deriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, witnessNCols, pcsNCols, opts.Ell, pub.HashRelation)
			if err != nil {
				return nil, fmt.Errorf("explicit witness omega: %w", err)
			}
		} else if len(omegaWitness) > witnessNCols {
			omegaWitness = append([]uint64(nil), omegaWitness[:witnessNCols]...)
		}
		params, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
		if err != nil {
			return nil, fmt.Errorf("load prf params: %w", err)
		}
		if len(pub.A) == 0 {
			return nil, fmt.Errorf("missing A for post-sign constraints")
		}
		if len(pub.B) == 0 {
			return nil, fmt.Errorf("missing B for post-sign hash")
		}
		if len(pub.Tag) == 0 || len(pub.Nonce) == 0 {
			return nil, fmt.Errorf("missing tag/nonce publics")
		}
		groupRounds := opts.PRFGroupRounds
		if groupRounds <= 0 {
			groupRounds = 1
		}
		rows, rowInputs, layout, prfLayout, prfCompanionLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, builtNCols, err := BuildCredentialRowsShowing(ringQ, pub, wit, params.LenKey, params.LenNonce, params.RF, params.RP, groupRounds, opts)
		if err != nil {
			return nil, fmt.Errorf("build showing rows: %w", err)
		}
		if prfLayout != nil {
			return nil, fmt.Errorf("legacy PRF layout is no longer supported for showing")
		}
		requiredPCSNCols := requiredExplicitPCSNColsForRows(ringQ, rowInputs, opts.Ell)
		if requiredPCSNCols > pcsNCols {
			opts = bumpExplicitPCSNCols(opts, requiredPCSNCols)
			continue
		}
		if builtNCols != witnessNCols {
			witnessNCols = builtNCols
			if len(omega) < witnessNCols {
				return nil, fmt.Errorf("omega len=%d < witness ncols=%d", len(omega), witnessNCols)
			}
			omegaWitness = append([]uint64(nil), omega[:witnessNCols]...)
		}
		rowsNTT := make([]*ring.Poly, len(rows))
		for i := range rows {
			rowsNTT[i] = ringQ.NewPoly()
			ring.Copy(rows[i], rowsNTT[i])
			ringQ.NTT(rowsNTT[i], rowsNTT[i])
		}
		postSet, err := buildCredentialConstraintSetPostFromRows(ringQ, pub.BoundB, pub, layout, rowsNTT, omegaWitness, opts.DomainMode, opts, prfLayout, prfCompanionLayout)
		if err != nil {
			return nil, fmt.Errorf("build post-sign constraint set: %w", err)
		}
		if prfCompanionLayout == nil {
			return nil, fmt.Errorf("missing showing PRF companion metadata")
		}
		prfSet := ConstraintSet{PRFCompanionLayout: prfCompanionLayout}
		parDeg := postSet.ParallelAlgDeg
		if prfSet.ParallelAlgDeg > parDeg {
			parDeg = prfSet.ParallelAlgDeg
		}
		aggDeg := postSet.AggregatedAlgDeg
		if prfSet.AggregatedAlgDeg > aggDeg {
			aggDeg = prfSet.AggregatedAlgDeg
		}
		set := ConstraintSet{
			FparInt:            append(append([]*ring.Poly{}, postSet.FparInt...), prfSet.FparInt...),
			FparIntCoeffs:      append(append([][]uint64{}, postSet.FparIntCoeffs...), prfSet.FparIntCoeffs...),
			FparNorm:           postSet.FparNorm,
			FparNormCoeffs:     postSet.FparNormCoeffs,
			FaggInt:            postSet.FaggInt,
			FaggIntCoeffs:      postSet.FaggIntCoeffs,
			FaggNorm:           postSet.FaggNorm,
			FaggNormCoeffs:     postSet.FaggNormCoeffs,
			ParallelAlgDeg:     parDeg,
			AggregatedAlgDeg:   aggDeg,
			PRFLayout:          prfLayout,
			PRFCompanionLayout: prfCompanionLayout,
		}
		prepared := &preparedCredentialBuild{
			rows:                  rows,
			rowInputs:             rowInputs,
			rowLayout:             layout,
			decsParams:            decsParams,
			maskRowOffset:         maskRowOffset,
			maskRowCount:          maskRowCount,
			witnessCount:          witnessCount,
			witnessNCols:          witnessNCols,
			skipConstraintRebuild: true,
		}
		opts.Credential = true
		proof, err := buildWithConstraintsPrepared(pub, wit, set, opts, FSModeCredential, prepared)
		if err != nil {
			return nil, err
		}
		return proof, nil
	}
	return nil, fmt.Errorf("could not stabilize explicit PCS width for showing rows")
}
