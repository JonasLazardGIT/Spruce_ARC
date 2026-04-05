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

// ExtractSignedPRFKeyScalarsFromCarrier derives the logical PRF key lanes from
// the compressed carrier row by decoding the upper-half coordinates.
func ExtractSignedPRFKeyScalarsFromCarrier(ringQ *ring.Ring, carrier *ring.Poly, packedNCols, lenKey int, bound int64) ([]int64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if carrier == nil {
		return nil, fmt.Errorf("nil carrier row")
	}
	if lenKey <= 0 {
		return nil, fmt.Errorf("invalid lenKey=%d", lenKey)
	}
	if bound <= 0 {
		return nil, fmt.Errorf("invalid bound=%d for carrier decode", bound)
	}
	ncols, err := ResolvePackedNCols(packedNCols, 0, int(ringQ.N))
	if err != nil {
		return nil, err
	}
	half := ncols / 2
	if half < lenKey {
		return nil, fmt.Errorf("packed ncols=%d leaves only %d upper-half lanes for lenKey=%d", ncols, half, lenKey)
	}
	carrierNTT := ringQ.NewPoly()
	ring.Copy(carrier, carrierNTT)
	ringQ.NTT(carrierNTT, carrierNTT)
	out := make([]int64, lenKey)
	for i := 0; i < lenKey; i++ {
		code := carrierNTT.Coeffs[0][half+i] % ringQ.Modulus[0]
		_, m2, err := decodeCarrierPair(code, bound)
		if err != nil {
			return nil, fmt.Errorf("carrier decode col=%d: %w", half+i, err)
		}
		out[i] = m2
	}
	return out, nil
}

// ExtractSignedPRFKeyScalarsFromCarrierOnOmega decodes the logical PRF key lanes
// from the carrier row values evaluated on the provided Ω witness set.
func ExtractSignedPRFKeyScalarsFromCarrierOnOmega(ringQ *ring.Ring, carrier *ring.Poly, omega []uint64, packedNCols, lenKey int, bound int64) ([]int64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if carrier == nil {
		return nil, fmt.Errorf("nil carrier row")
	}
	if lenKey <= 0 {
		return nil, fmt.Errorf("invalid lenKey=%d", lenKey)
	}
	if bound <= 0 {
		return nil, fmt.Errorf("invalid bound=%d for carrier decode", bound)
	}
	ncols, err := ResolvePackedNCols(packedNCols, 0, int(ringQ.N))
	if err != nil {
		return nil, err
	}
	half := ncols / 2
	if half < lenKey {
		return nil, fmt.Errorf("packed ncols=%d leaves only %d upper-half lanes for lenKey=%d", ncols, half, lenKey)
	}
	head, err := rowHeadOnOmega(ringQ, omega, carrier, ncols)
	if err != nil {
		return nil, fmt.Errorf("carrier head on omega: %w", err)
	}
	out := make([]int64, lenKey)
	q := ringQ.Modulus[0]
	for i := 0; i < lenKey; i++ {
		code := head[half+i] % q
		_, m2, err := decodeCarrierPair(code, bound)
		if err != nil {
			return nil, fmt.Errorf("carrier decode col=%d: %w", half+i, err)
		}
		out[i] = m2
	}
	return out, nil
}

// ExtractSignedPRFKeyScalarsFromM2OnOmega derives the logical PRF key lanes
// directly from the signed M2 row values on Ω.
func ExtractSignedPRFKeyScalarsFromM2OnOmega(ringQ *ring.Ring, m2 *ring.Poly, omega []uint64, packedNCols, lenKey int) ([]int64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if m2 == nil {
		return nil, fmt.Errorf("nil signed M2 row")
	}
	if lenKey <= 0 {
		return nil, fmt.Errorf("invalid lenKey=%d", lenKey)
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	ncols, err := ResolvePackedNCols(packedNCols, 0, int(ringQ.N))
	if err != nil {
		return nil, err
	}
	half := ncols / 2
	if half < lenKey {
		return nil, fmt.Errorf("packed ncols=%d leaves only %d upper-half lanes for lenKey=%d", ncols, half, lenKey)
	}
	head, err := rowHeadOnOmega(ringQ, omega, m2, ncols)
	if err != nil {
		return nil, fmt.Errorf("m2 head on omega: %w", err)
	}
	out := make([]int64, lenKey)
	q := ringQ.Modulus[0]
	for i := 0; i < lenKey; i++ {
		out[i] = int64(head[half+i] % q)
	}
	return out, nil
}

// ExtractSignedPRFKeyElemsFromM2OnOmega derives the PRF key elements directly
// from the signed M2 row values on Ω.
func ExtractSignedPRFKeyElemsFromM2OnOmega(ringQ *ring.Ring, m2 *ring.Poly, omega []uint64, packedNCols, lenKey int) ([]prf.Elem, error) {
	scalars, err := ExtractSignedPRFKeyScalarsFromM2OnOmega(ringQ, m2, omega, packedNCols, lenKey)
	if err != nil {
		return nil, err
	}
	out := make([]prf.Elem, len(scalars))
	q := ringQ.Modulus[0]
	for i := range scalars {
		out[i] = prf.Elem(liftToField(q, scalars[i]))
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
