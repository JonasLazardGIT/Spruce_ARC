package credential

import "testing"

func TestSemanticMessageRingTailKeyRoundTrip(t *testing.T) {
	for _, profile := range []IntGenISISProfile{PrimaryIntGenISISProfile(), Ternary1024IntGenISISProfile()} {
		t.Run(profile.Name, func(t *testing.T) {
			layout, err := DefaultSemanticMessageLayout(profile, 8)
			if err != nil {
				t.Fatalf("layout: %v", err)
			}
			if layout.Name != IntGenISISMessageLayoutRingTailKeyV1 || layout.Version != 4 {
				t.Fatalf("layout version/name=%d/%q", layout.Version, layout.Name)
			}
			if layout.MSEDomain != layoutDomainForProfile(profile) || layout.KeyDomain != layoutDomainForProfile(profile) || layout.Bound != profile.B {
				t.Fatalf("layout domain/bound mse=%q key=%q bound=%d", layout.MSEDomain, layout.KeyDomain, layout.Bound)
			}
			if len(layout.Attribute) != profile.N-8 || len(layout.Key) != 8 {
				t.Fatalf("layout slots attr=%d key=%d want %d/8", len(layout.Attribute), len(layout.Key), profile.N-8)
			}
			if layout.Key[0].Coeff != profile.N-8 || layout.Key[len(layout.Key)-1].Coeff != profile.N-1 {
				t.Fatalf("key slots=%+v", layout.Key)
			}
			attrs := ZeroSemanticAttributes(layout)
			for i := 0; i < len(layout.Attribute); i++ {
				attrs[0][layout.Attribute[i].Coeff] = sampleValueForBound(profile.B, i)
			}
			key := make([]int64, 8)
			for i := range key {
				key[i] = sampleValueForBound(profile.B, i+len(layout.Attribute))
			}
			msg, err := EncodeSemanticMessage(layout, attrs, key)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if err := ValidateSemanticMessage(layout, msg); err != nil {
				t.Fatalf("validate: %v", err)
			}
			gotKey, err := PRFKeyFromSemanticMessage(layout, msg.M)
			if err != nil {
				t.Fatalf("extract key: %v", err)
			}
			for i := range key {
				if gotKey[i] != key[i] {
					t.Fatalf("key[%d]=%d want %d", i, gotKey[i], key[i])
				}
			}
			decoded, err := DecodeSemanticMessage(layout, msg.M)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := ValidateSemanticMessage(layout, decoded); err != nil {
				t.Fatalf("decoded validate: %v", err)
			}
		})
	}
}

func layoutDomainForProfile(profile IntGenISISProfile) string {
	if profile.B == 1 {
		return IntGenISISDomainTernaryV1
	}
	return IntGenISISDomainBoundedRangeV1
}

func sampleValueForBound(bound int64, i int) int64 {
	if bound == 1 {
		return int64((i % 3) - 1)
	}
	return int64((i % int(2*bound+1)) - int(bound))
}

func TestSemanticMessageTernary1024Defaults(t *testing.T) {
	profile := Ternary1024IntGenISISProfile()
	layout, err := DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		t.Fatalf("layout: %v", err)
	}
	if layout.Bound != 1 || layout.MSEDomain != IntGenISISDomainTernaryV1 || layout.KeyDomain != IntGenISISDomainTernaryV1 {
		t.Fatalf("profile C layout domain/bound mse=%q key=%q bound=%d", layout.MSEDomain, layout.KeyDomain, layout.Bound)
	}
	attrs := ZeroSemanticAttributes(layout)
	for i, slot := range layout.Attribute {
		attrs[slot.Poly][slot.Coeff] = int64((i % 3) - 1)
	}
	if _, err := EncodeSemanticMessage(layout, attrs, []int64{-1, 0, 1, -1, 0, 1, -1, 0}); err != nil {
		t.Fatalf("ternary encode rejected: %v", err)
	}
	if _, err := EncodeSemanticMessage(layout, attrs, []int64{2, 0, 1, -1, 0, 1, -1, 0}); err == nil {
		t.Fatal("ternary profile accepted key value 2")
	}
}

func TestSemanticMessageProfileDigestsDiffer(t *testing.T) {
	a, err := DefaultSemanticMessageLayout(PrimaryIntGenISISProfile(), 8)
	if err != nil {
		t.Fatalf("profile B layout: %v", err)
	}
	b, err := DefaultSemanticMessageLayout(Ternary1024IntGenISISProfile(), 8)
	if err != nil {
		t.Fatalf("profile C layout: %v", err)
	}
	if string(a.Digest()) == string(b.Digest()) {
		t.Fatal("profile B and C semantic layout digests match")
	}
}

func TestSemanticMessageRejectsSplitMutations(t *testing.T) {
	profile := PrimaryIntGenISISProfile()
	layout, err := DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		t.Fatalf("layout: %v", err)
	}
	msg, err := EncodeSemanticMessage(layout, nil, []int64{1, 0, -1, 1, 0, -1, 1, 0})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg.MAttr[0][layout.Key[0].Coeff] = 1
	if err := ValidateSemanticMessage(layout, msg); err == nil {
		t.Fatal("m mutation in key region accepted")
	}
	msg, err = EncodeSemanticMessage(layout, nil, []int64{1, 0, -1, 1, 0, -1, 1, 0})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg.K[0][layout.Attribute[0].Coeff] = 1
	if err := ValidateSemanticMessage(layout, msg); err == nil {
		t.Fatal("k mutation in attribute region accepted")
	}
}

func TestSemanticMessageRejectsKeyAndBindingMutations(t *testing.T) {
	profile := PrimaryIntGenISISProfile()
	layout, err := DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		t.Fatalf("layout: %v", err)
	}
	msg, err := EncodeSemanticMessage(layout, nil, []int64{1, 0, -1, 1, 0, -1, 1, 0})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg.K[0][layout.Key[0].Coeff] = 5
	if err := ValidateSemanticMessage(layout, msg); err == nil {
		t.Fatal("out-of-bound key mutation accepted")
	}
	msg, err = EncodeSemanticMessage(layout, nil, []int64{1, 0, -1, 1, 0, -1, 1, 0})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg.M[0][layout.Key[0].Coeff]++
	if err := ValidateSemanticMessage(layout, msg); err == nil {
		t.Fatal("M/key binding mutation accepted")
	}
}
