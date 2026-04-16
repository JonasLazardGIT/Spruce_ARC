package PIOP

import (
	"fmt"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func relationUsesBBTran(relation string) bool {
	return credential.NormalizeHashRelation(relation) == credential.HashRelationBBTran
}

func coeffPolyFromFormalCoeffs(ringQ *ring.Ring, coeffs []uint64, name string) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	p := nttPolyFromFormalCoeffsIfFits(ringQ, coeffs)
	if p == nil {
		return nil, fmt.Errorf("%s degree=%d exceeds ring dimension %d", name, len(trimPoly(coeffs, ringQ.Modulus[0]))-1, ringQ.N)
	}
	out := ringQ.NewPoly()
	ring.Copy(p, out)
	ringQ.InvNTT(out, out)
	return out, nil
}

func buildBBTranProductInterpCoeffs(q uint64, omega []uint64, m1Coeff, m2Coeff, r0Coeff, r1Coeff []uint64) (mSigmaR1Coeff, r0R1Coeff []uint64, err error) {
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	mSigmaR1Head := make([]uint64, len(omega))
	r0R1Head := make([]uint64, len(omega))
	for i, w := range omega {
		x := w % q
		m1 := EvalPoly(m1Coeff, x, q) % q
		m2 := EvalPoly(m2Coeff, x, q) % q
		r0 := EvalPoly(r0Coeff, x, q) % q
		r1 := EvalPoly(r1Coeff, x, q) % q
		mSigmaR1Head[i] = modMul(modAdd(m1, m2, q), r1, q)
		r0R1Head[i] = modMul(r0, r1, q)
	}
	return trimPoly(Interpolate(omega, mSigmaR1Head, q), q), trimPoly(Interpolate(omega, r0R1Head, q), q), nil
}

func deriveTransformAliasRowFromSource(ringQ *ring.Ring, omega []uint64, domainMode DomainMode, src *ring.Poly, name string) (*ring.Poly, []uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if src == nil {
		return nil, nil, fmt.Errorf("nil transform alias source %s", name)
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega for %s", name)
	}
	ncols := len(omega)
	q := ringQ.Modulus[0]
	var head []uint64
	if domainMode == DomainModeExplicit {
		bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omega, ncols, 1)
		if err != nil {
			return nil, nil, fmt.Errorf("transform bridge basis for %s: %w", name, err)
		}
		srcHead, err := rowHeadOnOmega(ringQ, omega, src, ncols)
		if err != nil {
			return nil, nil, fmt.Errorf("source head for %s: %w", name, err)
		}
		head = make([]uint64, ncols)
		for j := 0; j < ncols; j++ {
			acc := uint64(0)
			for k := 0; k < ncols; k++ {
				weight := EvalPoly(bridgeBasis.TransformHEval[j], omega[k]%q, q)
				acc = modAdd(acc, modMul(weight, srcHead[k]%q, q), q)
			}
			head[j] = acc
		}
	} else {
		var err error
		head, err = nttHeadFromCoeffPoly(ringQ, src, ncols)
		if err != nil {
			return nil, nil, fmt.Errorf("ntt head for %s: %w", name, err)
		}
	}
	row, err := buildCommittedRowFromHead(ringQ, head, omega, domainMode)
	if err != nil {
		return nil, nil, fmt.Errorf("build transform alias %s: %w", name, err)
	}
	rowNTT := ringQ.NewPoly()
	ring.Copy(row, rowNTT)
	ringQ.NTT(rowNTT, rowNTT)
	coeff, err := coeffFromNTTPoly(ringQ, rowNTT)
	if err != nil {
		return nil, nil, fmt.Errorf("transform alias coeffs %s: %w", name, err)
	}
	return row, trimPoly(coeff, q), nil
}

func coeffOrZero(coeffs [][]uint64, idx int) []uint64 {
	if idx < 0 || idx >= len(coeffs) || coeffs[idx] == nil {
		return []uint64{0}
	}
	return coeffs[idx]
}
