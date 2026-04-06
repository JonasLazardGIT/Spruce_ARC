package PIOP

import (
	"fmt"

	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func carrierBase(bound int64) (int64, error) {
	if bound < 0 {
		return 0, fmt.Errorf("invalid carrier bound %d", bound)
	}
	base := 2*bound + 1
	if base <= 0 {
		return 0, fmt.Errorf("invalid carrier base for bound %d", bound)
	}
	return base, nil
}

func carrierAlphabetSize(bound int64) (int64, error) {
	base, err := carrierBase(bound)
	if err != nil {
		return 0, err
	}
	if base > 0 && base > (1<<62) {
		return 0, fmt.Errorf("carrier base %d too large", base)
	}
	if base != 0 && base > (1<<31) && base > (int64(^uint64(0)>>1))/base {
		return 0, fmt.Errorf("carrier alphabet overflows for base %d", base)
	}
	size := base * base
	if size <= 0 {
		return 0, fmt.Errorf("invalid carrier alphabet size for base %d", base)
	}
	return size, nil
}

func encodeCarrierPair(m1, m2, bound int64) (uint64, error) {
	base, err := carrierBase(bound)
	if err != nil {
		return 0, err
	}
	lo := int64(0)
	hi := base - 1
	m1v := m1 + bound
	m2v := m2 + bound
	if m1v < lo || m1v > hi {
		return 0, fmt.Errorf("carrier m1=%d outside [-%d,%d]", m1, bound, bound)
	}
	if m2v < lo || m2v > hi {
		return 0, fmt.Errorf("carrier m2=%d outside [-%d,%d]", m2, bound, bound)
	}
	code := m1v + base*m2v
	if code < 0 {
		return 0, fmt.Errorf("invalid carrier code %d", code)
	}
	return uint64(code), nil
}

// EncodeCarrierPair is the exported form of the pair codec used by issuance
// and tests when they need to derive the same committed carrier surface as the
// constraint builder.
func EncodeCarrierPair(m1, m2, bound int64) (uint64, error) {
	return encodeCarrierPair(m1, m2, bound)
}

func packedMessageCarrierAlphabetSize(bound int64) (int64, error) {
	if bound < 0 {
		return 0, fmt.Errorf("invalid packed-message bound %d", bound)
	}
	size := 4*bound + 1
	if size <= 0 {
		return 0, fmt.Errorf("invalid packed-message alphabet size for bound %d", bound)
	}
	return size, nil
}

func encodePackedMessageCarrier(m1, m2, bound int64) (uint64, error) {
	if bound < 0 {
		return 0, fmt.Errorf("invalid packed-message bound %d", bound)
	}
	if m1 < -bound || m1 > bound {
		return 0, fmt.Errorf("carrier m1=%d outside [-%d,%d]", m1, bound, bound)
	}
	if m2 < -bound || m2 > bound {
		return 0, fmt.Errorf("carrier m2=%d outside [-%d,%d]", m2, bound, bound)
	}
	if m1 != 0 && m2 != 0 {
		return 0, fmt.Errorf("packed-message carrier forbids mixed nonzero pair (%d,%d)", m1, m2)
	}
	if m1 == 0 && m2 == 0 {
		return 0, nil
	}
	encodeNonzero := func(v int64) uint64 {
		if v < 0 {
			return uint64(v + bound + 1)
		}
		return uint64(bound + v)
	}
	if m1 != 0 {
		return encodeNonzero(m1), nil
	}
	return uint64(2*bound) + encodeNonzero(m2), nil
}

func decodePackedMessageCarrier(code uint64, bound int64) (int64, int64, error) {
	size, err := packedMessageCarrierAlphabetSize(bound)
	if err != nil {
		return 0, 0, err
	}
	if int64(code) < 0 || int64(code) >= size {
		return 0, 0, fmt.Errorf("packed-message carrier code %d outside [0,%d)", code, size)
	}
	if code == 0 {
		return 0, 0, nil
	}
	decodeNonzero := func(offset uint64) (int64, error) {
		if offset == 0 || offset > uint64(2*bound) {
			return 0, fmt.Errorf("invalid packed-message nonzero offset %d for bound %d", offset, bound)
		}
		if offset <= uint64(bound) {
			return int64(offset) - bound - 1, nil
		}
		return int64(offset) - bound, nil
	}
	if code <= uint64(2*bound) {
		m1, err := decodeNonzero(code)
		if err != nil {
			return 0, 0, err
		}
		return m1, 0, nil
	}
	m2, err := decodeNonzero(code - uint64(2*bound))
	if err != nil {
		return 0, 0, err
	}
	return 0, m2, nil
}

func buildPackedMessageCarrierDecodePolys(bound int64, q uint64) ([]uint64, []uint64, error) {
	size, err := packedMessageCarrierAlphabetSize(bound)
	if err != nil {
		return nil, nil, err
	}
	if size <= 0 {
		return nil, nil, fmt.Errorf("invalid packed-message alphabet size %d", size)
	}
	xs := make([]uint64, size)
	ys1 := make([]uint64, size)
	ys2 := make([]uint64, size)
	for i := int64(0); i < size; i++ {
		xs[i] = uint64(i) % q
		m1, m2, err := decodePackedMessageCarrier(uint64(i), bound)
		if err != nil {
			return nil, nil, err
		}
		ys1[i] = liftToField(q, m1)
		ys2[i] = liftToField(q, m2)
	}
	return Interpolate(xs, ys1, q), Interpolate(xs, ys2, q), nil
}

func buildPackedMessageCarrierMembershipPoly(bound int64, q uint64) ([]uint64, error) {
	size, err := packedMessageCarrierAlphabetSize(bound)
	if err != nil {
		return nil, err
	}
	coeffs := make([]uint64, size+1)
	coeffs[0] = 1
	for a := int64(0); a < size; a++ {
		av := uint64(a) % q
		for k := a + 1; k >= 1; k-- {
			coeffs[k] = modSubReduced(coeffs[k-1], modMulReduced(av, coeffs[k], q), q)
		}
		coeffs[0] = modSubReduced(0, modMulReduced(av, coeffs[0], q), q)
	}
	return trimPoly(coeffs, q), nil
}

func decodeCarrierPair(code uint64, bound int64) (int64, int64, error) {
	size, err := carrierAlphabetSize(bound)
	if err != nil {
		return 0, 0, err
	}
	if int64(code) < 0 || int64(code) >= size {
		return 0, 0, fmt.Errorf("carrier code %d outside [0,%d)", code, size)
	}
	base, _ := carrierBase(bound)
	m1v := int64(code % uint64(base))
	m2v := int64(code / uint64(base))
	return m1v - bound, m2v - bound, nil
}

func buildCarrierDecodePolys(bound int64, q uint64) ([]uint64, []uint64, error) {
	size, err := carrierAlphabetSize(bound)
	if err != nil {
		return nil, nil, err
	}
	if size <= 0 {
		return nil, nil, fmt.Errorf("invalid carrier alphabet size %d", size)
	}
	const maxCarrierAlphabetSize = 1 << 20
	if size > maxCarrierAlphabetSize {
		return nil, nil, fmt.Errorf("carrier alphabet size %d exceeds limit %d", size, maxCarrierAlphabetSize)
	}
	xs := make([]uint64, size)
	ys1 := make([]uint64, size)
	ys2 := make([]uint64, size)
	base, _ := carrierBase(bound)
	for i := int64(0); i < size; i++ {
		xs[i] = uint64(i) % q
		m1 := (i % base) - bound
		m2 := (i / base) - bound
		ys1[i] = liftToField(q, m1)
		ys2[i] = liftToField(q, m2)
	}
	c1 := Interpolate(xs, ys1, q)
	c2 := Interpolate(xs, ys2, q)
	return c1, c2, nil
}

func buildCarrierMembershipPoly(bound int64, q uint64) ([]uint64, error) {
	size, err := carrierAlphabetSize(bound)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("invalid carrier alphabet size %d", size)
	}
	const maxCarrierAlphabetSize = 1 << 20
	if size > maxCarrierAlphabetSize {
		return nil, fmt.Errorf("carrier alphabet size %d exceeds limit %d", size, maxCarrierAlphabetSize)
	}
	// Build ∏_{a=0}^{size-1} (X - a).
	coeffs := make([]uint64, size+1)
	coeffs[0] = 1
	for a := int64(0); a < size; a++ {
		av := uint64(a) % q
		for k := a + 1; k >= 1; k-- {
			coeffs[k] = modSubReduced(coeffs[k-1], modMulReduced(av, coeffs[k], q), q)
		}
		coeffs[0] = modSubReduced(0, modMulReduced(av, coeffs[0], q), q)
	}
	return trimPoly(coeffs, q), nil
}

// DecodeCarrierHeadToFormalPair interpolates the carrier head over Ω,
// composes the public decode polynomials with that committed carrier
// polynomial, and returns the formal coefficient vectors of the two decoded
// coordinates. This matches the exact pre-sign/showing virtual-row semantics
// used by the explicit-domain constraint builders.
func DecodeCarrierHeadToFormalPair(ringQ *ring.Ring, bound int64, carrierHead, omega []uint64) ([]uint64, []uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	if len(carrierHead) < len(omega) {
		return nil, nil, fmt.Errorf("carrier head len=%d < omega len=%d", len(carrierHead), len(omega))
	}
	q := ringQ.Modulus[0]
	decode1, decode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, nil, err
	}
	carrierTheta := BuildThetaPrime(ringQ, carrierHead[:len(omega)], omega)
	carrierCoeff := ringQ.NewPoly()
	ringQ.InvNTT(carrierTheta, carrierCoeff)
	carrierPoly := fpoly.New(q, trimPoly(carrierCoeff.Coeffs[0], q))
	left := fpoly.New(q, decode1).Compose(carrierPoly)
	right := fpoly.New(q, decode2).Compose(carrierPoly)
	return trimPoly(left.Coeffs, q), trimPoly(right.Coeffs, q), nil
}

const (
	PreSignCarrierM = iota
	PreSignCarrierPreRU
	PreSignCarrierPreR
	PreSignCarrierCtr
	PreSignCarrierK
	preSignCarrierCount
)

const (
	PreSignAliasM1 = iota
	PreSignAliasM2
	PreSignAliasRU0
	PreSignAliasRU1
	PreSignAliasR
	PreSignAliasR0
	PreSignAliasR1
	PreSignAliasK0
	PreSignAliasK1
	preSignAliasCount
)

const (
	PreSignTransformAliasMHat1 = iota
	PreSignTransformAliasMHat2
	PreSignTransformAliasRHat0
	PreSignTransformAliasRHat1
	preSignTransformAliasCount
)

// PreSignRawRows carries the raw coefficient-domain witness rows used to derive
// the canonical committed pre-sign carrier and alias surface.
type PreSignRawRows struct {
	M1  *ring.Poly
	M2  *ring.Poly
	RU0 *ring.Poly
	RU1 *ring.Poly
	R   *ring.Poly
	R0  *ring.Poly
	R1  *ring.Poly
	K0  *ring.Poly
	K1  *ring.Poly
}

// PreSignCarrierAliasSurface returns the canonical committed pre-sign rows.
//
// CarrierRows order:
//
//	0: C^M
//	1: C^preRU
//	2: C^preR
//	3: C^ctr
//	4: C^K
//
// AliasRows / AliasCoeffs order:
//
//	0: M1
//	1: M2
//	2: RU0
//	3: RU1
//	4: R
//	5: R0
//	6: R1
//	7: K0
//	8: K1
//
// Missing inputs leave the corresponding carrier / alias entries nil.
type PreSignCarrierAliasSurface struct {
	CarrierRows []*ring.Poly
	AliasRows   []*ring.Poly
	AliasCoeffs [][]uint64
}

// PreSignTransformAliasSurface records the replay-facing pre-sign hats used by
// the transform-domain hash relation.
type PreSignTransformAliasSurface struct {
	Rows   []*ring.Poly
	Coeffs [][]uint64
}

func buildCommittedRowFromHead(ringQ *ring.Ring, head, omega []uint64, domainMode DomainMode) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(head) == 0 {
		return nil, fmt.Errorf("empty head")
	}
	q := ringQ.Modulus[0]
	if domainMode == DomainModeExplicit {
		if len(omega) != len(head) {
			return nil, fmt.Errorf("explicit row head len=%d want |omega|=%d", len(head), len(omega))
		}
		pNTT := BuildThetaPrime(ringQ, head, omega)
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(pNTT, coeff)
		return coeff, nil
	}
	pNTT := ringQ.NewPoly()
	for i := 0; i < len(head) && i < len(pNTT.Coeffs[0]); i++ {
		pNTT.Coeffs[0][i] = head[i] % q
	}
	coeff := ringQ.NewPoly()
	ringQ.InvNTT(pNTT, coeff)
	return coeff, nil
}

func nttHeadFromCoeffPoly(ringQ *ring.Ring, p *ring.Poly, ncols int) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if p == nil {
		return nil, fmt.Errorf("nil coeff poly")
	}
	if ncols <= 0 || ncols > len(p.Coeffs[0]) {
		return nil, fmt.Errorf("invalid ncols=%d for row width=%d", ncols, len(p.Coeffs[0]))
	}
	fullNTT := ringQ.NewPoly()
	ring.Copy(p, fullNTT)
	ringQ.NTT(fullNTT, fullNTT)
	head := append([]uint64(nil), fullNTT.Coeffs[0][:ncols]...)
	q := ringQ.Modulus[0]
	for i := range head {
		head[i] %= q
	}
	return head, nil
}

// DerivePreSignCarrierAndAliasRows builds the canonical pre-sign witness
// surface from raw witness rows. Carrier rows are first committed, then alias
// rows are derived by composing the public decode polynomials with those
// committed carrier polynomials. This is the exact surface replayed at E'.
func DerivePreSignCarrierAndAliasRows(ringQ *ring.Ring, bound int64, omega []uint64, domainMode DomainMode, raw PreSignRawRows) (*PreSignCarrierAliasSurface, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if bound <= 0 {
		return nil, fmt.Errorf("invalid carrier bound %d", bound)
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return nil, fmt.Errorf("|Omega|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	q := ringQ.Modulus[0]

	headFromPoly := func(p *ring.Poly, name string) ([]uint64, error) {
		if p == nil {
			return nil, nil
		}
		if domainMode == DomainModeExplicit {
			if len(p.Coeffs) == 0 || len(p.Coeffs[0]) < ncols {
				return nil, fmt.Errorf("%s head width=%d want >=%d", name, len(p.Coeffs[0]), ncols)
			}
			head := append([]uint64(nil), p.Coeffs[0][:ncols]...)
			for i := range head {
				head[i] %= q
			}
			return head, nil
		}
		pNTT := ringQ.NewPoly()
		ring.Copy(p, pNTT)
		ringQ.NTT(pNTT, pNTT)
		head := append([]uint64(nil), pNTT.Coeffs[0][:ncols]...)
		for i := range head {
			head[i] %= q
		}
		return head, nil
	}

	makeCarrierRowFromHead := func(head []uint64) (*ring.Poly, error) {
		if head == nil {
			return nil, nil
		}
		if len(head) != ncols {
			return nil, fmt.Errorf("carrier head len=%d want %d", len(head), ncols)
		}
		return buildCommittedRowFromHead(ringQ, head, omega, domainMode)
	}

	m1Head, err := headFromPoly(raw.M1, "M1")
	if err != nil {
		return nil, err
	}
	m2Head, err := headFromPoly(raw.M2, "M2")
	if err != nil {
		return nil, err
	}
	ru0Head, err := headFromPoly(raw.RU0, "RU0")
	if err != nil {
		return nil, err
	}
	ru1Head, err := headFromPoly(raw.RU1, "RU1")
	if err != nil {
		return nil, err
	}
	rHead, err := headFromPoly(raw.R, "R")
	if err != nil {
		return nil, err
	}
	r0Head, err := headFromPoly(raw.R0, "R0")
	if err != nil {
		return nil, err
	}
	r1Head, err := headFromPoly(raw.R1, "R1")
	if err != nil {
		return nil, err
	}
	k0Head, err := headFromPoly(raw.K0, "K0")
	if err != nil {
		return nil, err
	}
	k1Head, err := headFromPoly(raw.K1, "K1")
	if err != nil {
		return nil, err
	}

	carrierRows := make([]*ring.Poly, preSignCarrierCount)
	buildCarrierPairRow := func(leftHead, rightHead []uint64, pairBound int64, name string) (*ring.Poly, error) {
		if leftHead == nil || rightHead == nil {
			return nil, nil
		}
		head := make([]uint64, ncols)
		for col := 0; col < ncols; col++ {
			code, err := encodeCarrierPair(centeredLift(leftHead[col], q), centeredLift(rightHead[col], q), pairBound)
			if err != nil {
				return nil, fmt.Errorf("encode carrier %s col=%d: %w", name, col, err)
			}
			head[col] = liftToField(q, int64(code))
		}
		return makeCarrierRowFromHead(head)
	}
	buildPackedMessageCarrierRow := func(leftHead, rightHead []uint64, name string) (*ring.Poly, error) {
		if leftHead == nil || rightHead == nil {
			return nil, nil
		}
		head := make([]uint64, ncols)
		for col := 0; col < ncols; col++ {
			code, err := encodePackedMessageCarrier(centeredLift(leftHead[col], q), centeredLift(rightHead[col], q), bound)
			if err != nil {
				return nil, fmt.Errorf("encode carrier %s col=%d: %w", name, col, err)
			}
			head[col] = liftToField(q, int64(code))
		}
		return makeCarrierRowFromHead(head)
	}

	carrierRows[PreSignCarrierM], err = buildPackedMessageCarrierRow(m1Head, m2Head, "M")
	if err != nil {
		return nil, err
	}
	carrierRows[PreSignCarrierPreRU], err = buildCarrierPairRow(ru0Head, ru1Head, bound, "preRU")
	if err != nil {
		return nil, err
	}
	if rHead != nil {
		zeroHead := make([]uint64, ncols)
		carrierRows[PreSignCarrierPreR], err = buildCarrierPairRow(rHead, zeroHead, bound, "preR")
		if err != nil {
			return nil, err
		}
	}
	carrierRows[PreSignCarrierCtr], err = buildCarrierPairRow(r0Head, r1Head, bound, "ctr")
	if err != nil {
		return nil, err
	}
	carrierRows[PreSignCarrierK], err = buildCarrierPairRow(k0Head, k1Head, 1, "K")
	if err != nil {
		return nil, err
	}

	msgDecode1, msgDecode2, err := buildPackedMessageCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, err
	}
	decode1, decode2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		return nil, err
	}
	decode1K, decode2K, err := buildCarrierDecodePolys(1, q)
	if err != nil {
		return nil, err
	}
	buildAliasPair := func(carrier *ring.Poly, leftDecode, rightDecode []uint64) ([]uint64, []uint64, error) {
		if carrier == nil {
			return nil, nil, nil
		}
		carrierPoly := fpoly.New(q, trimPoly(append([]uint64(nil), carrier.Coeffs[0]...), q))
		left := trimPoly(fpoly.New(q, leftDecode).Compose(carrierPoly).Coeffs, q)
		right := trimPoly(fpoly.New(q, rightDecode).Compose(carrierPoly).Coeffs, q)
		if domainMode != DomainModeExplicit {
			left = reducePolyModXN1(left, int(ringQ.N), q)
			right = reducePolyModXN1(right, int(ringQ.N), q)
		}
		return left, right, nil
	}

	aliasCoeffs := make([][]uint64, preSignAliasCount)
	aliasRows := make([]*ring.Poly, preSignAliasCount)
	assignAlias := func(idx int, coeffs []uint64) error {
		if coeffs == nil {
			return nil
		}
		trimmed := trimPoly(append([]uint64(nil), coeffs...), q)
		if len(trimmed) == 0 {
			trimmed = []uint64{0}
		}
		if len(trimmed) > int(ringQ.N) {
			return fmt.Errorf("alias row %d degree=%d exceeds ring dimension %d", idx, len(trimmed)-1, ringQ.N)
		}
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], trimmed)
		aliasCoeffs[idx] = trimmed
		aliasRows[idx] = p
		return nil
	}

	left, right, err := buildAliasPair(carrierRows[PreSignCarrierM], msgDecode1, msgDecode2)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasM1, left); err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasM2, right); err != nil {
		return nil, err
	}
	left, right, err = buildAliasPair(carrierRows[PreSignCarrierPreRU], decode1, decode2)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasRU0, left); err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasRU1, right); err != nil {
		return nil, err
	}
	left, _, err = buildAliasPair(carrierRows[PreSignCarrierPreR], decode1, decode2)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasR, left); err != nil {
		return nil, err
	}
	left, right, err = buildAliasPair(carrierRows[PreSignCarrierCtr], decode1, decode2)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasR0, left); err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasR1, right); err != nil {
		return nil, err
	}
	left, right, err = buildAliasPair(carrierRows[PreSignCarrierK], decode1K, decode2K)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasK0, left); err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasK1, right); err != nil {
		return nil, err
	}

	return &PreSignCarrierAliasSurface{
		CarrierRows: carrierRows,
		AliasRows:   aliasRows,
		AliasCoeffs: aliasCoeffs,
	}, nil
}

// DerivePreSignTransformAliases builds the pre-sign replay-facing transform
// aliases from the committed decoded alias rows. The resulting rows follow the
// same theta-lifted NTT-head convention as the showing path.
func DerivePreSignTransformAliases(ringQ *ring.Ring, omega []uint64, domainMode DomainMode, aliases *PreSignCarrierAliasSurface) (*PreSignTransformAliasSurface, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if aliases == nil {
		return nil, fmt.Errorf("nil alias surface")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	q := ringQ.Modulus[0]
	rows := make([]*ring.Poly, preSignTransformAliasCount)
	coeffs := make([][]uint64, preSignTransformAliasCount)
	var transformHeadWeights [][]uint64
	if domainMode == DomainModeExplicit {
		bridgeBasis, err := newTransformBridgeBasisCache(ringQ, omega, ncols, 1)
		if err != nil {
			return nil, fmt.Errorf("pre-sign transform-bridge basis: %w", err)
		}
		transformHeadWeights = make([][]uint64, ncols)
		for j := 0; j < ncols; j++ {
			transformHeadWeights[j] = make([]uint64, ncols)
			for k := 0; k < ncols; k++ {
				transformHeadWeights[j][k] = EvalPoly(bridgeBasis.TransformHEval[j], omega[k]%q, q)
			}
		}
	}
	type srcSpec struct {
		out int
		in  int
	}
	for _, spec := range []srcSpec{
		{PreSignTransformAliasMHat1, PreSignAliasM1},
		{PreSignTransformAliasMHat2, PreSignAliasM2},
		{PreSignTransformAliasRHat0, PreSignAliasR0},
		{PreSignTransformAliasRHat1, PreSignAliasR1},
	} {
		if spec.in < 0 || spec.in >= len(aliases.AliasRows) || aliases.AliasRows[spec.in] == nil {
			return nil, fmt.Errorf("missing pre-sign alias row %d", spec.in)
		}
		var head []uint64
		if domainMode == DomainModeExplicit {
			srcHead, err := rowHeadOnOmega(ringQ, omega, aliases.AliasRows[spec.in], ncols)
			if err != nil {
				return nil, fmt.Errorf("pre-sign transform alias %d source head: %w", spec.out, err)
			}
			head = make([]uint64, ncols)
			for j := 0; j < ncols; j++ {
				acc := uint64(0)
				for k := 0; k < ncols; k++ {
					acc = modAdd(acc, modMul(transformHeadWeights[j][k]%q, srcHead[k]%q, q), q)
				}
				head[j] = acc
			}
		} else {
			var err error
			head, err = nttHeadFromCoeffPoly(ringQ, aliases.AliasRows[spec.in], ncols)
			if err != nil {
				return nil, fmt.Errorf("pre-sign transform alias %d head: %w", spec.out, err)
			}
		}
		row, err := buildCommittedRowFromHead(ringQ, head, omega, domainMode)
		if err != nil {
			return nil, fmt.Errorf("pre-sign transform alias %d row: %w", spec.out, err)
		}
		rowCoeffs, err := coeffFromNTTPoly(ringQ, func() *ring.Poly {
			p := ringQ.NewPoly()
			ring.Copy(row, p)
			ringQ.NTT(p, p)
			return p
		}())
		if err != nil {
			return nil, fmt.Errorf("pre-sign transform alias %d coeffs: %w", spec.out, err)
		}
		rows[spec.out] = row
		coeffs[spec.out] = trimPoly(rowCoeffs, q)
	}
	return &PreSignTransformAliasSurface{Rows: rows, Coeffs: coeffs}, nil
}
