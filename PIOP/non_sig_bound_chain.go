package PIOP

import "fmt"

const nonSigBoundChainWindowBits = 2
const (
	v3NonSigCertRadix    = uint64(5)
	v3NonSigCertDigits   = 2
	v3NonSigCertMaxBound = int64(12)
)

func nonSigBoundShape(beta uint64) (W int, L int, caps []int, err error) {
	W = nonSigBoundChainWindowBits
	L, err = minimalChainDigits(beta, W)
	if err != nil {
		return 0, 0, nil, err
	}
	return W, L, nil, nil
}

func ResolveNonSigBoundShape(bound int64) (W int, L int, caps []int, err error) {
	if bound < 0 {
		return 0, 0, nil, fmt.Errorf("invalid bound %d", bound)
	}
	return nonSigBoundShape(uint64(bound))
}

func nonSigBoundLinfSpec(q uint64, bound int64) (spec LinfSpec, err error) {
	if q == 0 {
		return LinfSpec{}, fmt.Errorf("invalid modulus q=0")
	}
	if bound < 0 {
		return LinfSpec{}, fmt.Errorf("invalid bound %d", bound)
	}
	beta := uint64(bound)
	W, L, caps, err := nonSigBoundShape(beta)
	if err != nil {
		return LinfSpec{}, err
	}
	if len(caps) == 0 {
		defer func() {
			if rec := recover(); rec != nil {
				err = fmt.Errorf("non-signature bound chain spec: %v", rec)
				spec = LinfSpec{}
			}
		}()
		spec = NewLinfChainSpec(q, W, L, 1, beta)
		return spec, nil
	}
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("non-signature bound chain spec: %v", rec)
			spec = LinfSpec{}
		}
	}()
	spec = NewLinfChainSpecCapped(q, W, L, 1, beta, caps)
	return spec, nil
}

func v3NonSigScalarCertEnabled(bound int64) bool {
	return bound > 0 && bound <= v3NonSigCertMaxBound
}

func v3NonSigScalarCertSpec(q uint64, bound int64) (spec LinfSpec, err error) {
	if q == 0 {
		return LinfSpec{}, fmt.Errorf("invalid modulus q=0")
	}
	if !v3NonSigScalarCertEnabled(bound) {
		return LinfSpec{}, fmt.Errorf("v3 non-sign scalar cert unsupported for bound=%d", bound)
	}
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("v3 non-sign scalar cert spec: %v", rec)
		}
	}()
	spec = NewSignedLinfChainSpecRadix(q, v3NonSigCertRadix, v3NonSigCertDigits, 1, uint64(bound), nil)
	return spec, nil
}
