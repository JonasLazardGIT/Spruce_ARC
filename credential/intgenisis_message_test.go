package credential

import "testing"

func TestSemanticMessageProfileBRoundTrip(t *testing.T) {
	profile := PrimaryIntGenISISProfile()
	layout, err := DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		t.Fatalf("layout: %v", err)
	}
	if layout.Name != IntGenISISMessageLayoutProfileBV3 || layout.Version != 3 {
		t.Fatalf("layout version/name=%d/%q", layout.Version, layout.Name)
	}
	if layout.MSEDomain != IntGenISISDomainTernaryV1 || layout.KeyDomain != IntGenISISDomainTernaryV1 || layout.Bound != 1 {
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
		attrs[0][layout.Attribute[i].Coeff] = int64((i % 3) - 1)
	}
	key := []int64{1, -1, 0, 1, -1, 0, 1, -1}
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
	msg.K[0][layout.Key[0].Coeff] = 2
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
