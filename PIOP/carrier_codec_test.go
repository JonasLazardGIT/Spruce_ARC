package PIOP

import "testing"

func TestCarrierEncodeDecodeRoundTrip(t *testing.T) {
	bound := int64(2)
	for m1 := -bound; m1 <= bound; m1++ {
		for m2 := -bound; m2 <= bound; m2++ {
			code, err := encodeCarrierPair(m1, m2, bound)
			if err != nil {
				t.Fatalf("encode m1=%d m2=%d: %v", m1, m2, err)
			}
			d1, d2, err := decodeCarrierPair(code, bound)
			if err != nil {
				t.Fatalf("decode code=%d: %v", code, err)
			}
			if d1 != m1 || d2 != m2 {
				t.Fatalf("round-trip mismatch: got (%d,%d) want (%d,%d)", d1, d2, m1, m2)
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
	for code := int64(0); code < size; code++ {
		m1, m2, err := decodeCarrierPair(uint64(code), bound)
		if err != nil {
			t.Fatalf("decode pair code=%d: %v", code, err)
		}
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

func TestSingletonCarrierEncodeDecodeRoundTrip(t *testing.T) {
	for _, bound := range []int64{1, 5, 8} {
		for m := -bound; m <= bound; m++ {
			code, err := encodeSingletonCarrier(m, bound)
			if err != nil {
				t.Fatalf("bound=%d encode m=%d: %v", bound, m, err)
			}
			got, err := decodeSingletonCarrier(code, bound)
			if err != nil {
				t.Fatalf("bound=%d decode code=%d: %v", bound, code, err)
			}
			if got != m {
				t.Fatalf("bound=%d round-trip mismatch: got %d want %d", bound, got, m)
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
