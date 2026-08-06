package PIOP

import (
	"errors"
	"fmt"
)

// canonicalQKernelCompactFromFullV5 omits only the constant coefficient of
// each split-coordinate Q polynomial.  The omitted value is uniquely fixed by
//
//	sum_{omega in Omega} Q(omega) = 0,
//
// so it is reconstructed from q_1,...,q_d alone.  In particular, compact Q
// binds every free coordinate before Fiat--Shamir samples e; no coefficient is
// recovered from the later Eq. (4) target.
func canonicalQKernelCompactFromFullV5(full [][]uint64, omega []uint64, q uint64) ([][]uint64, error) {
	if len(full) == 0 || len(full[0]) < 2 {
		return nil, errors.New("PIOP: canonical Q kernel: empty full polynomial")
	}
	degree := len(full[0]) - 1
	compact := make([][]uint64, len(full))
	for coord, row := range full {
		if len(row) != degree+1 {
			return nil, fmt.Errorf("PIOP: canonical Q kernel: ragged full row %d", coord)
		}
		for j, value := range row {
			if value >= q {
				return nil, fmt.Errorf("PIOP: canonical Q kernel: noncanonical full coefficient (%d,%d)", coord, j)
			}
		}
		constant, err := canonicalQConstantFromTailV3(row[1:], omega, q)
		if err != nil {
			return nil, err
		}
		if row[0] != constant {
			return nil, fmt.Errorf("PIOP: canonical Q kernel: row %d violates sum-over-Omega identity", coord)
		}
		compact[coord] = append([]uint64(nil), row[1:]...)
	}
	return compact, nil
}

func canonicalQKernelTranscriptFromFullV5(full [][]uint64, omega []uint64, q uint64) ([]byte, error) {
	compact, err := canonicalQKernelCompactFromFullV5(full, omega, q)
	if err != nil {
		return nil, err
	}
	return canonicalQKernelTranscriptBytesV6(compact, omega, q)
}

// canonicalQKernelReconstructV5 restores q_0 from the support-sum identity.
// It deliberately has no evaluation point or Eq. (4) target argument: the
// full Q polynomial is fixed before round 3 derives e.
func canonicalQKernelReconstructV5(compact [][]uint64, omega []uint64, degree int, q uint64) ([][]uint64, error) {
	if len(compact) == 0 || degree <= 0 || q <= 2 {
		return nil, errors.New("PIOP: canonical Q kernel: invalid reconstruction context")
	}
	full := make([][]uint64, len(compact))
	for coord, tail := range compact {
		if len(tail) != degree {
			return nil, fmt.Errorf("PIOP: canonical Q kernel: compact row %d width=%d want=%d", coord, len(tail), degree)
		}
		constant, err := canonicalQConstantFromTailV3(tail, omega, q)
		if err != nil {
			return nil, fmt.Errorf("PIOP: canonical Q kernel: reconstruct row %d: %w", coord, err)
		}
		full[coord] = make([]uint64, degree+1)
		full[coord][0] = constant
		copy(full[coord][1:], tail)
	}
	return full, nil
}
