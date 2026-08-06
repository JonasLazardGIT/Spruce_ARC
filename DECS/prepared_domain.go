package decs

import (
	"fmt"

	swdomain "vSIS-Signature/internal/domain"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// NewProverWithParamsAndPreparedDomainFormalChecked constructs a formal DECS
// prover from an immutable domain that has already passed range and
// distinctness validation. The prover retains its own point copy so its state
// cannot be affected by another layer.
func NewProverWithParamsAndPreparedDomainFormalChecked(
	ringQ *ring.Ring,
	coeffs [][]uint64,
	params Params,
	prepared *swdomain.Prepared,
) (*Prover, error) {
	points, err := pointsFromPrepared(ringQ, prepared)
	if err != nil {
		return nil, err
	}
	return newProverWithParamsAndPointsFormalChecked(ringQ, coeffs, params, points, false)
}

// NewVerifierWithParamsAndPreparedDomainV2Checked is the prepared-domain
// counterpart of NewVerifierWithParamsAndPointsV2Checked.
func NewVerifierWithParamsAndPreparedDomainV2Checked(
	ringQ *ring.Ring,
	r int,
	params Params,
	prepared *swdomain.Prepared,
	ctx CommitmentContext,
) (*Verifier, error) {
	points, err := pointsFromPrepared(ringQ, prepared)
	if err != nil {
		return nil, err
	}
	return newVerifierWithParamsAndPointsV2Checked(ringQ, r, params, points, ctx, false)
}

func pointsFromPrepared(ringQ *ring.Ring, prepared *swdomain.Prepared) ([]uint64, error) {
	if ringQ == nil || len(ringQ.Modulus) != 1 {
		return nil, fmt.Errorf("decs: only single-modulus rings are supported (len(Modulus) must be 1)")
	}
	if prepared == nil {
		return nil, fmt.Errorf("decs: nil prepared domain")
	}
	binding := prepared.Binding()
	if binding.Q != ringQ.Modulus[0] {
		return nil, fmt.Errorf("decs: prepared domain modulus=%d want=%d", binding.Q, ringQ.Modulus[0])
	}
	if binding.NLeaves != prepared.Len() {
		return nil, fmt.Errorf("decs: prepared domain length=%d binding=%d", prepared.Len(), binding.NLeaves)
	}
	return prepared.CopyPoints(), nil
}

// ValidateFormalRowsDegree verifies that all coefficients above degree vanish
// in F_q. It is shared by prover-side preflight checks and the retained
// verifier; it does not normalize or mutate the supplied rows.
func ValidateFormalRowsDegree(rows [][]uint64, degree int, modulus uint64) error {
	if degree < 0 {
		return fmt.Errorf("decs: negative formal degree bound %d", degree)
	}
	if modulus == 0 {
		return fmt.Errorf("decs: zero formal-row modulus")
	}
	for rowIndex, row := range rows {
		if degree >= len(row)-1 {
			continue
		}
		start := degree + 1
		for coefficientIndex := start; coefficientIndex < len(row); coefficientIndex++ {
			if row[coefficientIndex]%modulus != 0 {
				return fmt.Errorf("decs: formal row %d coefficient %d exceeds degree bound %d", rowIndex, coefficientIndex, degree)
			}
		}
	}
	return nil
}
