package PIOP

import (
	"fmt"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// ResolvePackedNCols selects the issuance/showing packing width. Production
// state persists PackedNCols directly; older credential-state files may still
// carry only the legacy coeff-native ncols field.
func ResolvePackedNCols(packedNCols, legacyNCols, ringN int) (int, error) {
	ncols := packedNCols
	if ncols <= 0 {
		ncols = legacyNCols
	}
	if ncols <= 0 {
		ncols = 16
	}
	if ringN > 0 {
		if ncols > ringN {
			return 0, fmt.Errorf("packed ncols=%d exceeds ringN=%d", ncols, ringN)
		}
		if ringN%ncols != 0 {
			return 0, fmt.Errorf("packed ncols=%d does not divide ringN=%d", ncols, ringN)
		}
	}
	if ncols%2 != 0 {
		return 0, fmt.Errorf("packed ncols=%d must be even", ncols)
	}
	return ncols, nil
}

// ExtractSignedPRFKeyScalars derives the logical PRF key lanes from the signed
// M2 witness row by reading the upper half of the issuance packing domain.
func ExtractSignedPRFKeyScalars(ringQ *ring.Ring, m2 *ring.Poly, packedNCols, lenKey int) ([]int64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if m2 == nil {
		return nil, fmt.Errorf("nil signed M2 row")
	}
	if lenKey <= 0 {
		return nil, fmt.Errorf("invalid lenKey=%d", lenKey)
	}
	ncols, err := ResolvePackedNCols(packedNCols, 0, int(ringQ.N))
	if err != nil {
		return nil, err
	}
	half := ncols / 2
	if half < lenKey {
		return nil, fmt.Errorf("packed ncols=%d leaves only %d upper-half lanes for lenKey=%d", ncols, half, lenKey)
	}
	m2NTT := ringQ.NewPoly()
	ring.Copy(m2, m2NTT)
	ringQ.NTT(m2NTT, m2NTT)
	out := make([]int64, lenKey)
	for i := 0; i < lenKey; i++ {
		out[i] = int64(m2NTT.Coeffs[0][half+i] % ringQ.Modulus[0])
	}
	return out, nil
}

// ExtractSignedPRFKeyElems is the canonical production helper for showing-time
// ARC PRF tag generation from the signed M2 witness row.
func ExtractSignedPRFKeyElems(ringQ *ring.Ring, m2 *ring.Poly, packedNCols, lenKey int) ([]prf.Elem, error) {
	scalars, err := ExtractSignedPRFKeyScalars(ringQ, m2, packedNCols, lenKey)
	if err != nil {
		return nil, err
	}
	out := make([]prf.Elem, len(scalars))
	for i := range scalars {
		out[i] = prf.Elem(scalars[i])
	}
	return out, nil
}
