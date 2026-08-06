package PIOP

import "testing"

func TestTernaryCarrierV3ExhaustiveEncodingAndDecoding(t *testing.T) {
	seen := make(map[uint64]bool, ternaryCarrierV3Alphabet)
	for b := int64(-1); b <= 1; b++ {
		for a := int64(-1); a <= 1; a++ {
			code, err := encodeTernaryCarrierV3(a, b)
			if err != nil {
				t.Fatalf("encode (%d,%d): %v", a, b, err)
			}
			want := uint64((a + 1) + 3*(b+1))
			if code != want {
				t.Fatalf("Enc(%d,%d)=%d want %d", a, b, code, want)
			}
			if seen[code] {
				t.Fatalf("duplicate code %d", code)
			}
			seen[code] = true
			gotA, gotB, err := decodeTernaryCarrierV3(code)
			if err != nil {
				t.Fatalf("decode %d: %v", code, err)
			}
			if gotA != a || gotB != b {
				t.Fatalf("decode %d=(%d,%d) want (%d,%d)", code, gotA, gotB, a, b)
			}
		}
	}
	if len(seen) != ternaryCarrierV3Alphabet {
		t.Fatalf("codes=%d want %d", len(seen), ternaryCarrierV3Alphabet)
	}
	for _, bad := range []uint64{9, 10, 255, 1017856} {
		if _, _, err := decodeTernaryCarrierV3(bad); err == nil {
			t.Fatalf("invalid carrier %d accepted", bad)
		}
	}
	for _, pair := range [][2]int64{{-2, 0}, {2, 0}, {0, -2}, {0, 2}} {
		if _, err := encodeTernaryCarrierV3(pair[0], pair[1]); err == nil {
			t.Fatalf("invalid pair %v accepted", pair)
		}
	}
}

func TestTernaryCarrierV3Polynomials(t *testing.T) {
	const q = uint64(1017857)
	decode, err := buildTernaryCarrierV3DecodePolys(q)
	if err != nil {
		t.Fatalf("decode polys: %v", err)
	}
	member, err := buildTernaryCarrierV3MembershipPoly(q)
	if err != nil {
		t.Fatalf("membership poly: %v", err)
	}
	if got := degreeOfPoly(member, q); got != 9 {
		t.Fatalf("membership degree=%d want 9", got)
	}
	for lane := range decode {
		if got := degreeOfPoly(decode[lane], q); got > 8 {
			t.Fatalf("decode lane %d degree=%d want <=8", lane, got)
		}
	}
	for code := uint64(0); code < 9; code++ {
		if got := EvalPoly(member, code, q); got != 0 {
			t.Fatalf("member(%d)=%d want 0", code, got)
		}
		a, b, _ := decodeTernaryCarrierV3(code)
		if got := EvalPoly(decode[0], code, q); got != liftToField(q, a) {
			t.Fatalf("decode0(%d)=%d want %d", code, got, liftToField(q, a))
		}
		if got := EvalPoly(decode[1], code, q); got != liftToField(q, b) {
			t.Fatalf("decode1(%d)=%d want %d", code, got, liftToField(q, b))
		}
	}
	for _, bad := range []uint64{9, 10, 11, 101} {
		if got := EvalPoly(member, bad, q); got == 0 {
			t.Fatalf("invalid carrier %d passed membership", bad)
		}
	}
	// A one-unit carrier mutation either changes at least one decoded lane or
	// leaves the valid alphabet, so it cannot preserve both authenticated
	// source lanes.
	for code := uint64(0); code < 9; code++ {
		for _, mutated := range []uint64{(code + 1) % 9, (code + 8) % 9} {
			a0, b0, _ := decodeTernaryCarrierV3(code)
			a1, b1, _ := decodeTernaryCarrierV3(mutated)
			if a0 == a1 && b0 == b1 {
				t.Fatalf("carrier tamper %d->%d preserved both lanes", code, mutated)
			}
		}
	}
}

func TestCarrierEncodeMatchesPairAlphabet(t *testing.T) {
	bound := int64(2)
	base, err := carrierBase(bound)
	if err != nil {
		t.Fatalf("carrier base: %v", err)
	}
	for m1 := -bound; m1 <= bound; m1++ {
		for m2 := -bound; m2 <= bound; m2++ {
			code, err := encodeCarrierPair(m1, m2, bound)
			if err != nil {
				t.Fatalf("encode m1=%d m2=%d: %v", m1, m2, err)
			}
			want := uint64((m2+bound)*base + (m1 + bound))
			if code != want {
				t.Fatalf("code mismatch for (%d,%d): got %d want %d", m1, m2, code, want)
			}
		}
	}
}

func TestCarrierDecodePolys(t *testing.T) {
	bound := int64(2)
	q := uint64(12289)
	d1, d2, err := buildCarrierDecodePolys(bound, q)
	if err != nil {
		t.Fatalf("decode polys: %v", err)
	}
	size, err := carrierAlphabetSize(bound)
	if err != nil {
		t.Fatalf("alphabet size: %v", err)
	}
	base, err := carrierBase(bound)
	if err != nil {
		t.Fatalf("carrier base: %v", err)
	}
	for code := int64(0); code < size; code++ {
		m1 := code%base - bound
		m2 := code/base - bound
		got1 := EvalPoly(d1, uint64(code)%q, q) % q
		got2 := EvalPoly(d2, uint64(code)%q, q) % q
		want1 := liftToField(q, m1) % q
		want2 := liftToField(q, m2) % q
		if got1 != want1 || got2 != want2 {
			t.Fatalf("decode poly mismatch code=%d got=(%d,%d) want=(%d,%d)", code, got1, got2, want1, want2)
		}
	}
}

func TestCarrierMembershipPoly(t *testing.T) {
	bound := int64(2)
	q := uint64(12289)
	p, err := buildCarrierMembershipPoly(bound, q)
	if err != nil {
		t.Fatalf("membership poly: %v", err)
	}
	size, err := carrierAlphabetSize(bound)
	if err != nil {
		t.Fatalf("alphabet size: %v", err)
	}
	for code := int64(0); code < size; code++ {
		val := EvalPoly(p, uint64(code)%q, q) % q
		if val != 0 {
			t.Fatalf("membership nonzero for code=%d val=%d", code, val)
		}
	}
	val := EvalPoly(p, uint64(size)%q, q) % q
	if val == 0 {
		t.Fatalf("membership unexpectedly zero for out-of-range code=%d", size)
	}
}

func TestSingletonCarrierEncodeMatchesAlphabet(t *testing.T) {
	for _, bound := range []int64{1, 5, 8} {
		for m := -bound; m <= bound; m++ {
			code, err := encodeSingletonCarrier(m, bound)
			if err != nil {
				t.Fatalf("bound=%d encode m=%d: %v", bound, m, err)
			}
			want := uint64(m + bound)
			if code != want {
				t.Fatalf("bound=%d code mismatch: got %d want %d", bound, code, want)
			}
		}
	}
}

func TestSingletonCarrierDecodePoly(t *testing.T) {
	bound := int64(5)
	q := uint64(12289)
	decode, err := buildSingletonCarrierDecodePoly(bound, q)
	if err != nil {
		t.Fatalf("singleton decode poly: %v", err)
	}
	size, err := singletonCarrierAlphabetSize(bound)
	if err != nil {
		t.Fatalf("singleton alphabet size: %v", err)
	}
	for code := int64(0); code < size; code++ {
		got := EvalPoly(decode, uint64(code)%q, q) % q
		want := liftToField(q, code-bound) % q
		if got != want {
			t.Fatalf("singleton decode mismatch code=%d got=%d want=%d", code, got, want)
		}
	}
}

func TestSingletonCarrierMembershipPoly(t *testing.T) {
	bound := int64(8)
	q := uint64(12289)
	p, err := buildSingletonCarrierMembershipPoly(bound, q)
	if err != nil {
		t.Fatalf("singleton membership poly: %v", err)
	}
	size, err := singletonCarrierAlphabetSize(bound)
	if err != nil {
		t.Fatalf("singleton alphabet size: %v", err)
	}
	for code := int64(0); code < size; code++ {
		if got := EvalPoly(p, uint64(code)%q, q) % q; got != 0 {
			t.Fatalf("singleton membership nonzero for code=%d val=%d", code, got)
		}
	}
	for _, code := range []uint64{uint64(size), uint64(size + 1)} {
		if got := EvalPoly(p, code%q, q) % q; got == 0 {
			t.Fatalf("singleton membership unexpectedly zero for out-of-range code=%d", code)
		}
	}
}

func TestSingletonCarrierAlphabetAndMembershipDegreeAreSmallerThanPair(t *testing.T) {
	for _, bound := range []int64{1, 5, 8} {
		pairSize, err := carrierAlphabetSize(bound)
		if err != nil {
			t.Fatalf("pair alphabet size bound=%d: %v", bound, err)
		}
		singletonSize, err := singletonCarrierAlphabetSize(bound)
		if err != nil {
			t.Fatalf("singleton alphabet size bound=%d: %v", bound, err)
		}
		if singletonSize >= pairSize {
			t.Fatalf("bound=%d singleton alphabet=%d want < pair alphabet=%d", bound, singletonSize, pairSize)
		}
		q := uint64(12289)
		pairMem, err := buildCarrierMembershipPoly(bound, q)
		if err != nil {
			t.Fatalf("pair membership poly bound=%d: %v", bound, err)
		}
		singletonMem, err := buildSingletonCarrierMembershipPoly(bound, q)
		if err != nil {
			t.Fatalf("singleton membership poly bound=%d: %v", bound, err)
		}
		if len(singletonMem) >= len(pairMem) {
			t.Fatalf("bound=%d singleton membership degree=%d want < pair degree=%d", bound, len(singletonMem)-1, len(pairMem)-1)
		}
	}
}

func TestPackedMessageCarrierEncodeDecodeRoundTrip(t *testing.T) {
	bound := int64(2)
	for m1 := -bound; m1 <= bound; m1++ {
		for m2 := -bound; m2 <= bound; m2++ {
			code, err := encodePackedMessageCarrier(m1, m2, bound)
			if m1 != 0 && m2 != 0 {
				if err == nil {
					t.Fatalf("mixed nonzero pair (%d,%d) unexpectedly encoded as %d", m1, m2, code)
				}
				continue
			}
			if err != nil {
				t.Fatalf("encode packed message (%d,%d): %v", m1, m2, err)
			}
			d1, d2, err := decodePackedMessageCarrier(code, bound)
			if err != nil {
				t.Fatalf("decode packed message code=%d: %v", code, err)
			}
			if d1 != m1 || d2 != m2 {
				t.Fatalf("packed-message round-trip mismatch: got (%d,%d) want (%d,%d)", d1, d2, m1, m2)
			}
		}
	}
}

func TestPackedMessageCarrierDecodePolys(t *testing.T) {
	bound := int64(2)
	q := uint64(12289)
	d1, d2, err := buildPackedMessageCarrierDecodePolys(bound, q)
	if err != nil {
		t.Fatalf("packed-message decode polys: %v", err)
	}
	size, err := packedMessageCarrierAlphabetSize(bound)
	if err != nil {
		t.Fatalf("packed-message alphabet size: %v", err)
	}
	for code := int64(0); code < size; code++ {
		m1, m2, err := decodePackedMessageCarrier(uint64(code), bound)
		if err != nil {
			t.Fatalf("decode packed-message code=%d: %v", code, err)
		}
		got1 := EvalPoly(d1, uint64(code)%q, q) % q
		got2 := EvalPoly(d2, uint64(code)%q, q) % q
		want1 := liftToField(q, m1) % q
		want2 := liftToField(q, m2) % q
		if got1 != want1 || got2 != want2 {
			t.Fatalf("packed-message decode poly mismatch code=%d got=(%d,%d) want=(%d,%d)", code, got1, got2, want1, want2)
		}
	}
}

func TestPackedMessageCarrierMembershipPoly(t *testing.T) {
	bound := int64(2)
	q := uint64(12289)
	p, err := buildPackedMessageCarrierMembershipPoly(bound, q)
	if err != nil {
		t.Fatalf("packed-message membership poly: %v", err)
	}
	size, err := packedMessageCarrierAlphabetSize(bound)
	if err != nil {
		t.Fatalf("packed-message alphabet size: %v", err)
	}
	for code := int64(0); code < size; code++ {
		val := EvalPoly(p, uint64(code)%q, q) % q
		if val != 0 {
			t.Fatalf("packed-message membership nonzero for code=%d val=%d", code, val)
		}
	}
	for _, code := range []uint64{uint64(size), uint64(size + 1)} {
		val := EvalPoly(p, code%q, q) % q
		if val == 0 {
			t.Fatalf("packed-message membership unexpectedly zero for out-of-range code=%d", code)
		}
	}
}

func TestPackedMuCarrierEncodeDecodeRoundTrip(t *testing.T) {
	bound := int64(1)
	for _, packWidth := range []int{2, 4} {
		size, err := packedMuCarrierAlphabetSize(bound, packWidth)
		if err != nil {
			t.Fatalf("packed mu alphabet size width=%d: %v", packWidth, err)
		}
		for code := int64(0); code < size; code++ {
			vals := make([]int64, packWidth)
			for lane := 0; lane < packWidth; lane++ {
				got, err := decodePackedMuCarrierLane(uint64(code), bound, packWidth, lane)
				if err != nil {
					t.Fatalf("decode packed mu width=%d lane=%d code=%d: %v", packWidth, lane, code, err)
				}
				vals[lane] = got
			}
			encoded, err := encodePackedMuCarrier(vals, bound)
			if err != nil {
				t.Fatalf("encode packed mu width=%d vals=%v: %v", packWidth, vals, err)
			}
			if encoded != uint64(code) {
				t.Fatalf("packed mu round-trip width=%d got code=%d want %d vals=%v", packWidth, encoded, code, vals)
			}
		}
	}
}

func TestPackedMuCarrierDecodePolys(t *testing.T) {
	bound := int64(1)
	q := uint64(12289)
	for _, packWidth := range []int{2, 4} {
		decode, err := buildPackedMuCarrierDecodePolys(bound, packWidth, q)
		if err != nil {
			t.Fatalf("packed mu decode polys width=%d: %v", packWidth, err)
		}
		if len(decode) != packWidth {
			t.Fatalf("decode polys=%d want %d", len(decode), packWidth)
		}
		size, err := packedMuCarrierAlphabetSize(bound, packWidth)
		if err != nil {
			t.Fatalf("packed mu alphabet size width=%d: %v", packWidth, err)
		}
		for code := int64(0); code < size; code++ {
			for lane := 0; lane < packWidth; lane++ {
				got := EvalPoly(decode[lane], uint64(code)%q, q) % q
				wantSigned, err := decodePackedMuCarrierLane(uint64(code), bound, packWidth, lane)
				if err != nil {
					t.Fatalf("decode packed mu width=%d code=%d lane=%d: %v", packWidth, code, lane, err)
				}
				want := liftToField(q, wantSigned) % q
				if got != want {
					t.Fatalf("decode poly mismatch width=%d code=%d lane=%d got=%d want=%d", packWidth, code, lane, got, want)
				}
			}
		}
	}
}

func TestPackedMuCarrierMembershipPoly(t *testing.T) {
	bound := int64(1)
	q := uint64(12289)
	for _, packWidth := range []int{2, 4} {
		p, err := buildPackedMuCarrierMembershipPoly(bound, packWidth, q)
		if err != nil {
			t.Fatalf("packed mu membership poly width=%d: %v", packWidth, err)
		}
		size, err := packedMuCarrierAlphabetSize(bound, packWidth)
		if err != nil {
			t.Fatalf("packed mu alphabet size width=%d: %v", packWidth, err)
		}
		for code := int64(0); code < size; code++ {
			if got := EvalPoly(p, uint64(code)%q, q) % q; got != 0 {
				t.Fatalf("membership nonzero width=%d code=%d: %d", packWidth, code, got)
			}
		}
		if got := EvalPoly(p, uint64(size)%q, q) % q; got == 0 {
			t.Fatalf("membership unexpectedly zero width=%d for out-of-set code=%d", packWidth, size)
		}
	}
}
