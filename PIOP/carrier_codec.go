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

func singletonCarrierAlphabetSize(bound int64) (int64, error) {
	return carrierBase(bound)
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

func encodeSingletonCarrier(m, bound int64) (uint64, error) {
	base, err := carrierBase(bound)
	if err != nil {
		return 0, err
	}
	mv := m + bound
	if mv < 0 || mv >= base {
		return 0, fmt.Errorf("singleton carrier m=%d outside [-%d,%d]", m, bound, bound)
	}
	return uint64(mv), nil
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

func decodeSingletonCarrier(code uint64, bound int64) (int64, error) {
	size, err := singletonCarrierAlphabetSize(bound)
	if err != nil {
		return 0, err
	}
	if int64(code) < 0 || int64(code) >= size {
		return 0, fmt.Errorf("singleton carrier code %d outside [0,%d)", code, size)
	}
	return int64(code) - bound, nil
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

func buildSingletonCarrierDecodePoly(bound int64, q uint64) ([]uint64, error) {
	size, err := singletonCarrierAlphabetSize(bound)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("invalid singleton carrier alphabet size %d", size)
	}
	const maxCarrierAlphabetSize = 1 << 20
	if size > maxCarrierAlphabetSize {
		return nil, fmt.Errorf("singleton carrier alphabet size %d exceeds limit %d", size, maxCarrierAlphabetSize)
	}
	xs := make([]uint64, size)
	ys := make([]uint64, size)
	for i := int64(0); i < size; i++ {
		xs[i] = uint64(i) % q
		ys[i] = liftToField(q, i-bound)
	}
	return Interpolate(xs, ys, q), nil
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

func buildSingletonCarrierMembershipPoly(bound int64, q uint64) ([]uint64, error) {
	size, err := singletonCarrierAlphabetSize(bound)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("invalid singleton carrier alphabet size %d", size)
	}
	const maxCarrierAlphabetSize = 1 << 20
	if size > maxCarrierAlphabetSize {
		return nil, fmt.Errorf("singleton carrier alphabet size %d exceeds limit %d", size, maxCarrierAlphabetSize)
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

func firstPoly(polys []*ring.Poly) *ring.Poly {
	if len(polys) == 0 {
		return nil
	}
	return polys[0]
}

func firstCoeff(coeffs [][]uint64) []uint64 {
	if len(coeffs) == 0 {
		return nil
	}
	return coeffs[0]
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
	RU0 []*ring.Poly
	RU1 *ring.Poly
	R   *ring.Poly
	R0  []*ring.Poly
	R1  *ring.Poly
	K0  []*ring.Poly
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
	CarrierM       *ring.Poly
	CarrierRU0Rows []*ring.Poly
	CarrierRU1     *ring.Poly
	CarrierRBar    *ring.Poly
	CarrierR0Rows  []*ring.Poly
	CarrierR1      *ring.Poly
	CarrierK0Rows  []*ring.Poly
	CarrierK1      *ring.Poly

	AliasM1      *ring.Poly
	AliasM2      *ring.Poly
	AliasRU0Rows []*ring.Poly
	AliasRU1     *ring.Poly
	AliasRBar    *ring.Poly
	AliasR0Rows  []*ring.Poly
	AliasR1      *ring.Poly
	AliasK0Rows  []*ring.Poly
	AliasK1      *ring.Poly

	AliasM1Coeff   []uint64
	AliasM2Coeff   []uint64
	AliasRU0Coeffs [][]uint64
	AliasRU1Coeff  []uint64
	AliasRBarCoeff []uint64
	AliasR0Coeffs  [][]uint64
	AliasR1Coeff   []uint64
	AliasK0Coeffs  [][]uint64
	AliasK1Coeff   []uint64

	// Legacy scalar compatibility surface. Live vector code should use the
	// explicit block fields above.
	CarrierRows []*ring.Poly
	AliasRows   []*ring.Poly
	AliasCoeffs [][]uint64
}

// PreSignTransformAliasSurface records the replay-facing pre-sign hats used by
// the transform-domain hash relation.
type PreSignTransformAliasSurface struct {
	MHat1       *ring.Poly
	MHat2       *ring.Poly
	RHat0Rows   []*ring.Poly
	RHat1       *ring.Poly
	MHat1Coeff  []uint64
	MHat2Coeff  []uint64
	RHat0Coeffs [][]uint64
	RHat1Coeff  []uint64

	// Legacy scalar compatibility surface. Live vector code should use the
	// explicit block fields above.
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
func DerivePreSignCarrierAndAliasRows(ringQ *ring.Ring, boundB int64, x0Bound int64, omega []uint64, domainMode DomainMode, raw PreSignRawRows) (*PreSignCarrierAliasSurface, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if boundB <= 0 {
		return nil, fmt.Errorf("invalid bounded scalar carrier bound %d", boundB)
	}
	if x0Bound <= 0 {
		return nil, fmt.Errorf("invalid x0 carrier bound %d", x0Bound)
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
			head, err := rowHeadOnOmega(ringQ, omega, p, ncols)
			if err != nil {
				return nil, fmt.Errorf("%s head on omega: %w", name, err)
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

	headVecFromPolys := func(polys []*ring.Poly, name string) ([][]uint64, error) {
		if len(polys) == 0 {
			return nil, nil
		}
		out := make([][]uint64, len(polys))
		for i := range polys {
			head, err := headFromPoly(polys[i], fmt.Sprintf("%s[%d]", name, i))
			if err != nil {
				return nil, err
			}
			out[i] = head
		}
		return out, nil
	}

	m1Head, err := headFromPoly(raw.M1, "M1")
	if err != nil {
		return nil, err
	}
	m2Head, err := headFromPoly(raw.M2, "M2")
	if err != nil {
		return nil, err
	}
	ru0Heads, err := headVecFromPolys(raw.RU0, "RU0")
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
	r0Heads, err := headVecFromPolys(raw.R0, "R0")
	if err != nil {
		return nil, err
	}
	r1Head, err := headFromPoly(raw.R1, "R1")
	if err != nil {
		return nil, err
	}
	k0Heads, err := headVecFromPolys(raw.K0, "K0")
	if err != nil {
		return nil, err
	}
	k1Head, err := headFromPoly(raw.K1, "K1")
	if err != nil {
		return nil, err
	}

	x0Len := 0
	for _, n := range []int{len(ru0Heads), len(r0Heads), len(k0Heads)} {
		if n > x0Len {
			x0Len = n
		}
	}
	for _, pair := range []struct {
		name string
		got  int
	}{
		{name: "RU0", got: len(ru0Heads)},
		{name: "R0", got: len(r0Heads)},
		{name: "K0", got: len(k0Heads)},
	} {
		if pair.got != 0 && pair.got != x0Len {
			return nil, fmt.Errorf("%s block length=%d mismatches x0Len=%d", pair.name, pair.got, x0Len)
		}
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
			code, err := encodePackedMessageCarrier(centeredLift(leftHead[col], q), centeredLift(rightHead[col], q), boundB)
			if err != nil {
				return nil, fmt.Errorf("encode carrier %s col=%d: %w", name, col, err)
			}
			head[col] = liftToField(q, int64(code))
		}
		return makeCarrierRowFromHead(head)
	}
	buildSingletonCarrierRows := func(heads [][]uint64, singletonBound int64, name string) ([]*ring.Poly, error) {
		if len(heads) == 0 {
			return nil, nil
		}
		out := make([]*ring.Poly, len(heads))
		for i := range heads {
			head := make([]uint64, ncols)
			for col := 0; col < ncols; col++ {
				code, err := encodeSingletonCarrier(centeredLift(heads[i][col], q), singletonBound)
				if err != nil {
					return nil, fmt.Errorf("encode singleton carrier %s[%d] col=%d: %w", name, i, col, err)
				}
				head[col] = liftToField(q, int64(code))
			}
			row, err := makeCarrierRowFromHead(head)
			if err != nil {
				return nil, err
			}
			out[i] = row
		}
		return out, nil
	}
	buildScalarPairSingletonRow := func(head []uint64, pairBound int64, name string) (*ring.Poly, error) {
		if head == nil {
			return nil, nil
		}
		zeroHead := make([]uint64, ncols)
		return buildCarrierPairRow(head, zeroHead, pairBound, name)
	}

	carrierRows[PreSignCarrierM], err = buildPackedMessageCarrierRow(m1Head, m2Head, "M")
	if err != nil {
		return nil, err
	}
	carrierRU0Rows, err := buildSingletonCarrierRows(ru0Heads, x0Bound, "preRU")
	if err != nil {
		return nil, err
	}
	carrierRows[PreSignCarrierPreRU] = firstPoly(carrierRU0Rows)
	if rHead != nil {
		carrierRows[PreSignCarrierPreR], err = buildScalarPairSingletonRow(rHead, boundB, "preR")
		if err != nil {
			return nil, err
		}
	}
	carrierR0Rows, err := buildSingletonCarrierRows(r0Heads, x0Bound, "ctr")
	if err != nil {
		return nil, err
	}
	carrierRows[PreSignCarrierCtr] = firstPoly(carrierR0Rows)
	carrierR1, err := buildScalarPairSingletonRow(r1Head, boundB, "r1")
	if err != nil {
		return nil, err
	}
	carrierK0Rows, err := buildSingletonCarrierRows(k0Heads, 1, "K")
	if err != nil {
		return nil, err
	}
	carrierRows[PreSignCarrierK] = firstPoly(carrierK0Rows)
	carrierRU1, err := buildScalarPairSingletonRow(ru1Head, boundB, "ru1")
	if err != nil {
		return nil, err
	}
	carrierK1, err := buildScalarPairSingletonRow(k1Head, 1, "k1")
	if err != nil {
		return nil, err
	}

	msgDecode1, msgDecode2, err := buildPackedMessageCarrierDecodePolys(boundB, q)
	if err != nil {
		return nil, err
	}
	x0Decode1, err := buildSingletonCarrierDecodePoly(x0Bound, q)
	if err != nil {
		return nil, err
	}
	scalarDecode1, scalarDecode2, err := buildCarrierDecodePolys(boundB, q)
	if err != nil {
		return nil, err
	}
	x0CarryDecode, err := buildSingletonCarrierDecodePoly(1, q)
	if err != nil {
		return nil, err
	}
	decode1K, decode2K, err := buildCarrierDecodePolys(1, q)
	if err != nil {
		return nil, err
	}
	buildAliasPair := func(carrier *ring.Poly, leftDecode, rightDecode []uint64) ([]uint64, []uint64, *ring.Poly, *ring.Poly, error) {
		if carrier == nil {
			return nil, nil, nil, nil, nil
		}
		if domainMode == DomainModeExplicit {
			carrierHead, err := rowHeadOnOmega(ringQ, omega, carrier, ncols)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			leftHead := make([]uint64, ncols)
			rightHead := make([]uint64, ncols)
			for col := 0; col < ncols; col++ {
				leftHead[col] = EvalPoly(leftDecode, carrierHead[col]%q, q) % q
				rightHead[col] = EvalPoly(rightDecode, carrierHead[col]%q, q) % q
			}
			leftRow, err := buildCommittedRowFromHead(ringQ, leftHead, omega, domainMode)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			rightRow, err := buildCommittedRowFromHead(ringQ, rightHead, omega, domainMode)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			left := trimPoly(append([]uint64(nil), leftRow.Coeffs[0]...), q)
			right := trimPoly(append([]uint64(nil), rightRow.Coeffs[0]...), q)
			return left, right, leftRow, rightRow, nil
		}
		carrierPoly := fpoly.New(q, trimPoly(append([]uint64(nil), carrier.Coeffs[0]...), q))
		left := trimPoly(fpoly.New(q, leftDecode).Compose(carrierPoly).Coeffs, q)
		right := trimPoly(fpoly.New(q, rightDecode).Compose(carrierPoly).Coeffs, q)
		left = reducePolyModXN1(left, int(ringQ.N), q)
		right = reducePolyModXN1(right, int(ringQ.N), q)
		leftRow := ringQ.NewPoly()
		copy(leftRow.Coeffs[0], left)
		rightRow := ringQ.NewPoly()
		copy(rightRow.Coeffs[0], right)
		return left, right, leftRow, rightRow, nil
	}
	buildAliasSingle := func(carrier *ring.Poly, decode []uint64) ([]uint64, *ring.Poly, error) {
		if carrier == nil {
			return nil, nil, nil
		}
		if domainMode == DomainModeExplicit {
			carrierHead, err := rowHeadOnOmega(ringQ, omega, carrier, ncols)
			if err != nil {
				return nil, nil, err
			}
			head := make([]uint64, ncols)
			for col := 0; col < ncols; col++ {
				head[col] = EvalPoly(decode, carrierHead[col]%q, q) % q
			}
			row, err := buildCommittedRowFromHead(ringQ, head, omega, domainMode)
			if err != nil {
				return nil, nil, err
			}
			coeff := trimPoly(append([]uint64(nil), row.Coeffs[0]...), q)
			return coeff, row, nil
		}
		carrierPoly := fpoly.New(q, trimPoly(append([]uint64(nil), carrier.Coeffs[0]...), q))
		coeff := trimPoly(fpoly.New(q, decode).Compose(carrierPoly).Coeffs, q)
		coeff = reducePolyModXN1(coeff, int(ringQ.N), q)
		row := ringQ.NewPoly()
		copy(row.Coeffs[0], coeff)
		return coeff, row, nil
	}
	buildAliasLeftRows := func(carriers []*ring.Poly, decode []uint64) ([][]uint64, []*ring.Poly, error) {
		if len(carriers) == 0 {
			return nil, nil, nil
		}
		outCoeffs := make([][]uint64, len(carriers))
		outRows := make([]*ring.Poly, len(carriers))
		for i := range carriers {
			left, leftRow, err := buildAliasSingle(carriers[i], decode)
			if err != nil {
				return nil, nil, err
			}
			outCoeffs[i] = left
			if leftRow == nil {
				continue
			}
			outRows[i] = leftRow
		}
		return outCoeffs, outRows, nil
	}

	aliasCoeffs := make([][]uint64, preSignAliasCount)
	aliasRows := make([]*ring.Poly, preSignAliasCount)
	assignAlias := func(idx int, coeffs []uint64, row *ring.Poly) error {
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
		aliasCoeffs[idx] = trimmed
		if row == nil {
			row = ringQ.NewPoly()
			copy(row.Coeffs[0], trimmed)
		}
		aliasRows[idx] = row
		return nil
	}

	left, right, leftRow, rightRow, err := buildAliasPair(carrierRows[PreSignCarrierM], msgDecode1, msgDecode2)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasM1, left, leftRow); err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasM2, right, rightRow); err != nil {
		return nil, err
	}
	left, right, leftRow, rightRow, err = buildAliasPair(carrierRU1, scalarDecode1, scalarDecode2)
	if err != nil {
		return nil, err
	}
	ru0AliasCoeffs, ru0AliasRows, err := buildAliasLeftRows(carrierRU0Rows, x0Decode1)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasRU0, firstCoeff(ru0AliasCoeffs), firstPoly(ru0AliasRows)); err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasRU1, left, leftRow); err != nil {
		return nil, err
	}
	left, _, leftRow, _, err = buildAliasPair(carrierRows[PreSignCarrierPreR], scalarDecode1, scalarDecode2)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasR, left, leftRow); err != nil {
		return nil, err
	}
	left, right, leftRow, rightRow, err = buildAliasPair(carrierR1, scalarDecode1, scalarDecode2)
	if err != nil {
		return nil, err
	}
	r0AliasCoeffs, r0AliasRows, err := buildAliasLeftRows(carrierR0Rows, x0Decode1)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasR0, firstCoeff(r0AliasCoeffs), firstPoly(r0AliasRows)); err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasR1, left, leftRow); err != nil {
		return nil, err
	}
	left, right, leftRow, rightRow, err = buildAliasPair(carrierK1, decode1K, decode2K)
	if err != nil {
		return nil, err
	}
	k0AliasCoeffs, k0AliasRows, err := buildAliasLeftRows(carrierK0Rows, x0CarryDecode)
	if err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasK0, firstCoeff(k0AliasCoeffs), firstPoly(k0AliasRows)); err != nil {
		return nil, err
	}
	if err := assignAlias(PreSignAliasK1, left, leftRow); err != nil {
		return nil, err
	}

	return &PreSignCarrierAliasSurface{
		CarrierM:       carrierRows[PreSignCarrierM],
		CarrierRU0Rows: carrierRU0Rows,
		CarrierRU1:     carrierRU1,
		CarrierRBar:    carrierRows[PreSignCarrierPreR],
		CarrierR0Rows:  carrierR0Rows,
		CarrierR1:      carrierR1,
		CarrierK0Rows:  carrierK0Rows,
		CarrierK1:      carrierK1,
		AliasM1:        aliasRows[PreSignAliasM1],
		AliasM2:        aliasRows[PreSignAliasM2],
		AliasRU0Rows:   ru0AliasRows,
		AliasRU1:       aliasRows[PreSignAliasRU1],
		AliasRBar:      aliasRows[PreSignAliasR],
		AliasR0Rows:    r0AliasRows,
		AliasR1:        aliasRows[PreSignAliasR1],
		AliasK0Rows:    k0AliasRows,
		AliasK1:        aliasRows[PreSignAliasK1],
		AliasM1Coeff:   aliasCoeffs[PreSignAliasM1],
		AliasM2Coeff:   aliasCoeffs[PreSignAliasM2],
		AliasRU0Coeffs: ru0AliasCoeffs,
		AliasRU1Coeff:  aliasCoeffs[PreSignAliasRU1],
		AliasRBarCoeff: aliasCoeffs[PreSignAliasR],
		AliasR0Coeffs:  r0AliasCoeffs,
		AliasR1Coeff:   aliasCoeffs[PreSignAliasR1],
		AliasK0Coeffs:  k0AliasCoeffs,
		AliasK1Coeff:   aliasCoeffs[PreSignAliasK1],
		CarrierRows:    carrierRows,
		AliasRows:      aliasRows,
		AliasCoeffs:    aliasCoeffs,
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
	rHat0Rows := make([]*ring.Poly, len(aliases.AliasR0Rows))
	rHat0Coeffs := make([][]uint64, len(aliases.AliasR0Rows))
	type scalarSrcSpec struct {
		out  int
		name string
		row  *ring.Poly
	}
	for _, spec := range []scalarSrcSpec{
		{PreSignTransformAliasMHat1, "M1", aliases.AliasM1},
		{PreSignTransformAliasMHat2, "M2", aliases.AliasM2},
		{PreSignTransformAliasRHat1, "R1", aliases.AliasR1},
	} {
		if spec.row == nil {
			return nil, fmt.Errorf("missing pre-sign alias row %s", spec.name)
		}
		head, err := nttHeadFromCoeffPoly(ringQ, spec.row, ncols)
		if err != nil {
			return nil, fmt.Errorf("pre-sign transform alias %d head: %w", spec.out, err)
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
	for i := range aliases.AliasR0Rows {
		if aliases.AliasR0Rows[i] == nil {
			return nil, fmt.Errorf("missing pre-sign alias row R0[%d]", i)
		}
		head, err := nttHeadFromCoeffPoly(ringQ, aliases.AliasR0Rows[i], ncols)
		if err != nil {
			return nil, fmt.Errorf("pre-sign transform alias R0[%d] head: %w", i, err)
		}
		row, err := buildCommittedRowFromHead(ringQ, head, omega, domainMode)
		if err != nil {
			return nil, fmt.Errorf("pre-sign transform alias R0[%d] row: %w", i, err)
		}
		rowCoeffs, err := coeffFromNTTPoly(ringQ, func() *ring.Poly {
			p := ringQ.NewPoly()
			ring.Copy(row, p)
			ringQ.NTT(p, p)
			return p
		}())
		if err != nil {
			return nil, fmt.Errorf("pre-sign transform alias R0[%d] coeffs: %w", i, err)
		}
		rHat0Rows[i] = row
		rHat0Coeffs[i] = trimPoly(rowCoeffs, q)
	}
	rows[PreSignTransformAliasRHat0] = firstPoly(rHat0Rows)
	coeffs[PreSignTransformAliasRHat0] = firstCoeff(rHat0Coeffs)
	return &PreSignTransformAliasSurface{
		MHat1:       rows[PreSignTransformAliasMHat1],
		MHat2:       rows[PreSignTransformAliasMHat2],
		RHat0Rows:   rHat0Rows,
		RHat1:       rows[PreSignTransformAliasRHat1],
		MHat1Coeff:  coeffs[PreSignTransformAliasMHat1],
		MHat2Coeff:  coeffs[PreSignTransformAliasMHat2],
		RHat0Coeffs: rHat0Coeffs,
		RHat1Coeff:  coeffs[PreSignTransformAliasRHat1],
		Rows:        rows,
		Coeffs:      coeffs,
	}, nil
}
