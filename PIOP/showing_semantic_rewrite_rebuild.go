package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func groupedPRFWitnessScalarCount(lenKey, lenNonce, rf, rp, groupRounds int) (int, error) {
	if lenKey <= 0 || lenNonce <= 0 {
		return 0, fmt.Errorf("invalid grouped PRF shape lenKey=%d lenNonce=%d", lenKey, lenNonce)
	}
	if rf <= 0 || rf%2 != 0 {
		return 0, fmt.Errorf("invalid grouped PRF RF=%d", rf)
	}
	if rp <= 0 {
		return 0, fmt.Errorf("invalid grouped PRF RP=%d", rp)
	}
	if groupRounds <= 0 {
		return 0, fmt.Errorf("invalid grouped PRF groupRounds=%d", groupRounds)
	}
	t := lenKey + lenNonce
	count := 0
	totalRounds := rf + rp
	for round := 0; round < totalRounds; round++ {
		checkpoint := true
		fullRound := round < rf/2 || round >= rf/2+rp
		if groupRounds > 1 && fullRound {
			fullIdx := round
			if round >= rf/2+rp {
				fullIdx = round - rp
			}
			checkpoint = fullIdx != rf-1
		}
		if !checkpoint {
			continue
		}
		if fullRound {
			count += t
		} else {
			count++
		}
	}
	return count, nil
}

func expectedPRFFparCount(layout *PRFLayout) (int, error) {
	if layout == nil {
		return 0, nil
	}
	mode := layout.Mode
	if mode == "" {
		mode = PRFLayoutModeSBox
	}
	if mode != PRFLayoutModeSBox {
		return 0, fmt.Errorf("unsupported PRF layout mode %q", mode)
	}
	groupRounds := layout.GroupRounds
	if groupRounds <= 0 {
		groupRounds = 1
	}
	sboxCount, err := groupedPRFWitnessScalarCount(layout.LenKey, layout.LenNonce, layout.RF, layout.RP, groupRounds)
	if err != nil {
		return 0, err
	}
	total := sboxCount + layout.LenTag
	if layout.KeyBind {
		total += layout.LenKey
	}
	return total, nil
}

func expectedShowingPRFSuffixCount(set *ConstraintSet) (int, error) {
	if set == nil {
		return 0, fmt.Errorf("nil constraint set")
	}
	return expectedPRFFparCount(set.PRFLayout)
}

func exactConstraintCoeffOverrides(polys []*ring.Poly, coeffs [][]uint64) [][]uint64 {
	if len(polys) == 0 {
		return nil
	}
	out := make([][]uint64, len(polys))
	limit := len(coeffs)
	if limit > len(polys) {
		limit = len(polys)
	}
	for i := 0; i < limit; i++ {
		if len(coeffs[i]) == 0 {
			continue
		}
		out[i] = append([]uint64(nil), coeffs[i]...)
	}
	return out
}

func replaceShowingPostSignPrefix(set *ConstraintSet, rebuilt ConstraintSet) error {
	if set == nil {
		return fmt.Errorf("nil constraint set")
	}
	suffixCount, err := expectedShowingPRFSuffixCount(set)
	if err != nil {
		return fmt.Errorf("expected PRF suffix count: %w", err)
	}
	if suffixCount > len(set.FparInt) {
		return fmt.Errorf("expected PRF suffix=%d exceeds FparInt len=%d", suffixCount, len(set.FparInt))
	}
	oldPrefixLen := len(set.FparInt) - suffixCount
	if len(rebuilt.FparInt) != oldPrefixLen {
		return fmt.Errorf("rebuilt post-sign prefix len=%d want %d (total=%d prf_suffix=%d)", len(rebuilt.FparInt), oldPrefixLen, len(set.FparInt), suffixCount)
	}

	var prfSuffix []*ring.Poly
	var prfSuffixCoeffs [][]uint64
	if suffixCount > 0 {
		prfSuffix = append([]*ring.Poly{}, set.FparInt[oldPrefixLen:]...)
		start := oldPrefixLen
		if start > len(set.FparIntCoeffs) {
			start = len(set.FparIntCoeffs)
		}
		prfSuffixCoeffs = exactConstraintCoeffOverrides(prfSuffix, set.FparIntCoeffs[start:])
	}

	set.FparInt = append(append([]*ring.Poly{}, rebuilt.FparInt...), prfSuffix...)
	set.FparIntCoeffs = append(exactConstraintCoeffOverrides(rebuilt.FparInt, rebuilt.FparIntCoeffs), prfSuffixCoeffs...)
	return nil
}

func rebuildPostSignConstraintSetWithBridges(
	ringQ *ring.Ring,
	pub PublicInputs,
	rowLayout RowLayout,
	constraintRows []*ring.Poly,
	omegaWitness []uint64,
	opts SimOpts,
	root [16]byte,
) (ConstraintSet, error) {
	postRows, err := buildCredentialConstraintSetPostFromRows(ringQ, pub.BoundB, pub, rowLayout, constraintRows, omegaWitness, opts.DomainMode, opts)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("rebuild post-sign constraints from rows: %w", err)
	}

	if !rowLayoutHasCoeffNativeSig(rowLayout) || rowLayoutCoeffNativeUsesSemanticRewrite(rowLayout) {
		if rowLayoutCoeffNativeUsesSemanticRewrite(rowLayout) {
			return postRows, nil
		}
		nonSigBridge, nonSigBridgeCoeffs, nonSigErr := buildPostSignNonSigBridgeConstraintsFormal(
			ringQ,
			constraintRows,
			omegaWitness,
			rowLayout,
			root,
			signatureNTTBridgeChecks,
		)
		if nonSigErr != nil {
			return ConstraintSet{}, fmt.Errorf("post-sign non-signature bridge: %w", nonSigErr)
		}
		if len(nonSigBridge) > 0 {
			// The semantic-rewrite non-signature bridge is replayed through its
			// aggregated bridge polynomials. Keep the formal coefficient channel
			// disabled here so QK uses the same projected bridge objects as the
			// verifier-side evaluator.
			if rowLayoutCoeffNativeUsesSemanticRewrite(rowLayout) || opts.DomainMode != DomainModeExplicit {
				nonSigBridgeCoeffs = make([][]uint64, len(nonSigBridge))
			}
			postRows.FaggNorm = append(postRows.FaggNorm, nonSigBridge...)
			postRows.FaggNormCoeffs = append(exactConstraintCoeffOverrides(postRows.FaggNorm[:len(postRows.FaggNorm)-len(nonSigBridge)], postRows.FaggNormCoeffs), exactConstraintCoeffOverrides(nonSigBridge, nonSigBridgeCoeffs)...)
			if postRows.AggregatedAlgDeg < 2 {
				postRows.AggregatedAlgDeg = 2
			}
		}
		if !rowLayoutHasCoeffNativeSig(rowLayout) {
			var (
				bridge       []*ring.Poly
				bridgeCoeffs [][]uint64
				berr         error
			)
			if opts.DomainMode == DomainModeExplicit {
				bridge, bridgeCoeffs, berr = buildSignatureNTTBridgeConstraintsFormal(ringQ, constraintRows, omegaWitness, rowLayout, root, signatureNTTBridgeChecks)
			} else {
				bridge, berr = buildSignatureNTTBridgeConstraints(ringQ, constraintRows, omegaWitness, rowLayout, root, signatureNTTBridgeChecks)
				if len(bridge) > 0 {
					bridgeCoeffs = make([][]uint64, len(bridge))
				}
			}
			if berr != nil {
				return ConstraintSet{}, fmt.Errorf("signature NTT bridge: %w", berr)
			}
			if len(bridge) > 0 {
				postRows.FaggNorm = append(postRows.FaggNorm, bridge...)
				postRows.FaggNormCoeffs = append(exactConstraintCoeffOverrides(postRows.FaggNorm[:len(postRows.FaggNorm)-len(bridge)], postRows.FaggNormCoeffs), exactConstraintCoeffOverrides(bridge, bridgeCoeffs)...)
				if postRows.AggregatedAlgDeg < 2 {
					postRows.AggregatedAlgDeg = 2
				}
			}
		}
	}
	postRows.FparIntCoeffs = exactConstraintCoeffOverrides(postRows.FparInt, postRows.FparIntCoeffs)
	postRows.FparNormCoeffs = exactConstraintCoeffOverrides(postRows.FparNorm, postRows.FparNormCoeffs)
	postRows.FaggIntCoeffs = exactConstraintCoeffOverrides(postRows.FaggInt, postRows.FaggIntCoeffs)
	postRows.FaggNormCoeffs = exactConstraintCoeffOverrides(postRows.FaggNorm, postRows.FaggNormCoeffs)
	return postRows, nil
}
