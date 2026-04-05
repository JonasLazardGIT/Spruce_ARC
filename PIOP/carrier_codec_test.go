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
