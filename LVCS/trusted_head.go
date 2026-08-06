package lvcs

import (
	"fmt"

	swdomain "vSIS-Signature/internal/domain"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// directHeadProvenance is deliberately unexported and binds a checked head to
// its canonical polynomial and exact prepared-domain layout. Callers cannot
// forge it by setting RowInput.TrustedHead.
type directHeadProvenance struct {
	binding swdomain.Binding
	head    []uint64
	coeffs  []uint64
}

// NewAuthenticatedDirectRowInput derives the canonical Omega head directly
// from a polynomial and attaches opaque provenance in the same pass. It is the
// preferred strict-row constructor because it avoids computing the head once
// in a caller and then checking it again here.
func NewAuthenticatedDirectRowInput(
	ringQ *ring.Ring,
	prepared *swdomain.Prepared,
	poly *ring.Poly,
	polyCoeffs []uint64,
	tail []uint64,
) (RowInput, error) {
	q, binding, coefficients, err := directRowAuthenticationInputs(ringQ, prepared, poly, polyCoeffs)
	if err != nil {
		return RowInput{}, err
	}
	head := make([]uint64, binding.OmegaSize)
	for pointIndex := range head {
		head[pointIndex] = evalPolyCoeffs(coefficients, prepared.At(pointIndex), q)
	}
	return rowInputWithDirectHeadProvenance(poly, polyCoeffs, tail, binding, head, coefficients), nil
}

// AuthenticateDirectRowHead checks a direct-polynomial row at every Omega
// point and returns an owned RowInput carrying opaque provenance. A subsequent
// prepared-domain commit may skip only that same repeated evaluation. Mutation
// of the returned row invalidates the provenance and restores the full check.
func AuthenticateDirectRowHead(ringQ *ring.Ring, prepared *swdomain.Prepared, input RowInput) (RowInput, error) {
	q, binding, coefficients, err := directRowAuthenticationInputs(ringQ, prepared, input.Poly, input.PolyCoeffs)
	if err != nil {
		return RowInput{}, err
	}
	if len(input.Head) != binding.OmegaSize {
		return RowInput{}, fmt.Errorf("AuthenticateDirectRowHead: head length=%d want=%d", len(input.Head), binding.OmegaSize)
	}
	canonicalHead := make([]uint64, len(input.Head))
	for pointIndex, claimed := range input.Head {
		if claimed >= q {
			return RowInput{}, fmt.Errorf("AuthenticateDirectRowHead: head[%d]=%d is not canonical (q=%d)", pointIndex, claimed, q)
		}
		want := evalPolyCoeffs(coefficients, prepared.At(pointIndex), q)
		if claimed != want {
			return RowInput{}, fmt.Errorf("AuthenticateDirectRowHead: head[%d]=%d want=%d", pointIndex, claimed, want)
		}
		canonicalHead[pointIndex] = claimed
	}
	return rowInputWithDirectHeadProvenance(input.Poly, input.PolyCoeffs, input.Tail, binding, canonicalHead, coefficients), nil
}

func directRowAuthenticationInputs(ringQ *ring.Ring, prepared *swdomain.Prepared, poly *ring.Poly, polyCoeffs []uint64) (uint64, swdomain.Binding, []uint64, error) {
	if ringQ == nil || len(ringQ.Modulus) != 1 {
		return 0, swdomain.Binding{}, nil, fmt.Errorf("AuthenticateDirectRowHead: expected a single-modulus ring")
	}
	if prepared == nil {
		return 0, swdomain.Binding{}, nil, fmt.Errorf("AuthenticateDirectRowHead: nil prepared domain")
	}
	binding := prepared.Binding()
	q := ringQ.Modulus[0]
	if binding.Q != q {
		return 0, swdomain.Binding{}, nil, fmt.Errorf("AuthenticateDirectRowHead: prepared modulus=%d want=%d", binding.Q, q)
	}
	if poly == nil && len(polyCoeffs) == 0 {
		return 0, swdomain.Binding{}, nil, fmt.Errorf("AuthenticateDirectRowHead: direct polynomial is required")
	}
	if len(polyCoeffs) > 0 {
		return q, binding, trimCoeffsMod(polyCoeffs, q), nil
	}
	return q, binding, trimCoeffsMod(poly.Coeffs[0], q), nil
}

func rowInputWithDirectHeadProvenance(poly *ring.Poly, polyCoeffs, tail []uint64, binding swdomain.Binding, head, normalizedCoefficients []uint64) RowInput {
	return RowInput{
		Head:       append([]uint64(nil), head...),
		Tail:       append([]uint64(nil), tail...),
		Poly:       poly,
		PolyCoeffs: append([]uint64(nil), polyCoeffs...),
		headProvenance: &directHeadProvenance{
			binding: binding,
			head:    append([]uint64(nil), head...),
			coeffs:  append([]uint64(nil), normalizedCoefficients...),
		},
	}
}

func directHeadProvenanceMatches(input RowInput, normalizedCoefficients []uint64, prepared *swdomain.Prepared, ncols int) bool {
	provenance := input.headProvenance
	if provenance == nil || prepared == nil || ncols <= 0 {
		return false
	}
	binding := prepared.Binding()
	if provenance.binding != binding || binding.OmegaSize != ncols {
		return false
	}
	if !equalUint64Slices(input.Head, provenance.head) || !equalUint64Slices(normalizedCoefficients, provenance.coeffs) {
		return false
	}
	return true
}

func equalUint64Slices(left, right []uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
