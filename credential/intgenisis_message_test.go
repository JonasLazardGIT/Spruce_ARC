package credential

import "testing"

func TestSemanticMessagePack9SeedRoundTrip(t *testing.T) {
	for _, profile := range []IntGenISISProfile{PrimaryIntGenISISProfile(), Ternary1024IntGenISISProfile()} {
		t.Run(profile.Name, func(t *testing.T) {
			layout, err := DefaultSemanticMessageLayout(profile, 8)
			if err != nil {
				t.Fatalf("layout: %v", err)
			}
			if layout.Name != IntGenISISMessageLayoutPack9SeedV1 || layout.Version != IntGenISISMessageLayoutVersion {
				t.Fatalf("layout version/name=%d/%q", layout.Version, layout.Name)
			}
			if layout.MSEDomain != IntGenISISDomainTernaryV1 || layout.KeyDomain != IntGenISISDomainBoundedRangeB4V1 || layout.Bound != IntGenISISLiveBound || layout.SeedBound != IntGenISISPRFSeedBound {
				t.Fatalf("layout domain/bounds mse=%q key=%q bound=%d seed=%d", layout.MSEDomain, layout.KeyDomain, layout.Bound, layout.SeedBound)
			}
			if len(layout.Attribute) != profile.N-IntGenISISPRFSeedTailReserve || len(layout.Key) != IntGenISISPRFSeedLen {
				t.Fatalf("layout slots attr=%d key=%d want %d/%d", len(layout.Attribute), len(layout.Key), profile.N-IntGenISISPRFSeedTailReserve, IntGenISISPRFSeedLen)
			}
			if layout.Key[0].Coeff != profile.N-IntGenISISPRFSeedLen || layout.Key[len(layout.Key)-1].Coeff != profile.N-1 {
				t.Fatalf("seed slots=%+v", layout.Key)
			}
			attrs := ZeroSemanticAttributes(layout)
			for i := 0; i < len(layout.Attribute); i++ {
				attrs[0][layout.Attribute[i].Coeff] = sampleValueForBound(IntGenISISLiveBound, i)
			}
			seed := makeSeedForTest()
			msg, err := EncodeSemanticMessage(layout, attrs, seed)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if err := ValidateSemanticMessage(layout, msg); err != nil {
				t.Fatalf("validate: %v", err)
			}
			gotSeed, err := PRFSeedFromSemanticMessage(layout, msg.M)
			if err != nil {
				t.Fatalf("extract seed: %v", err)
			}
			for i := range seed {
				if gotSeed[i] != seed[i] {
					t.Fatalf("seed[%d]=%d want %d", i, gotSeed[i], seed[i])
				}
			}
			gotKey, err := PRFKeyFromSemanticMessage(layout, msg.M)
			if err != nil {
				t.Fatalf("extract key: %v", err)
			}
			wantKey, err := PackPRFSeed(seed)
			if err != nil {
				t.Fatalf("pack seed: %v", err)
			}
			for i := range wantKey {
				if gotKey[i] != wantKey[i] {
					t.Fatalf("packed key[%d]=%d want %d", i, gotKey[i], wantKey[i])
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

func sampleValueForBound(bound int64, i int) int64 {
	if bound == 1 {
		return int64((i % 3) - 1)
	}
	return int64((i % int(2*bound+1)) - int(bound))
}

func makeSeedForTest() []int64 {
	seed := make([]int64, IntGenISISPRFSeedLen)
	for i := range seed {
		seed[i] = sampleValueForBound(IntGenISISPRFSeedBound, i)
	}
	return seed
}

func TestSemanticMessagePack9SeedDefaults(t *testing.T) {
	profile := Ternary1024IntGenISISProfile()
	layout, err := DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		t.Fatalf("layout: %v", err)
	}
	if layout.Bound != 1 || layout.MSEDomain != IntGenISISDomainTernaryV1 || layout.KeyDomain != IntGenISISDomainBoundedRangeB4V1 || layout.SeedBound != 4 {
		t.Fatalf("profile C layout domain/bound mse=%q key=%q bound=%d", layout.MSEDomain, layout.KeyDomain, layout.Bound)
	}
	attrs := ZeroSemanticAttributes(layout)
	for i, slot := range layout.Attribute {
		attrs[slot.Poly][slot.Coeff] = int64((i % 3) - 1)
	}
	seed := makeSeedForTest()
	seed[0] = 4
	if _, err := EncodeSemanticMessage(layout, attrs, seed); err != nil {
		t.Fatalf("B4 seed encode rejected: %v", err)
	}
	seed[0] = 5
	if _, err := EncodeSemanticMessage(layout, attrs, seed); err == nil {
		t.Fatal("semantic layout accepted seed value 5")
	}
	if _, err := EncodeSemanticMessage(layout, attrs, []int64{-1, 0, 1, -1, 0, 1, -1, 0}); err == nil {
		t.Fatal("semantic layout accepted old 8-coefficient key")
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
	seed := makeSeedForTest()
	msg, err := EncodeSemanticMessage(layout, nil, seed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg.MAttr[0][layout.Key[0].Coeff] = 1
	if err := ValidateSemanticMessage(layout, msg); err == nil {
		t.Fatal("m mutation in key region accepted")
	}
	msg, err = EncodeSemanticMessage(layout, nil, seed)
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
	seed := makeSeedForTest()
	msg, err := EncodeSemanticMessage(layout, nil, seed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg.K[0][layout.Key[0].Coeff] = 5
	if err := ValidateSemanticMessage(layout, msg); err == nil {
		t.Fatal("out-of-bound key mutation accepted")
	}
	msg, err = EncodeSemanticMessage(layout, nil, seed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	msg.M[0][layout.Key[0].Coeff]++
	if err := ValidateSemanticMessage(layout, msg); err == nil {
		t.Fatal("M/key binding mutation accepted")
	}
}
