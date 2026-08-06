package kfield

import (
	"encoding/hex"
	"strconv"
	"testing"
)

func TestMaintainedSmallWoodFieldProfilesV3(t *testing.T) {
	omega := make([]uint64, 32)
	for i := range omega {
		omega[i] = uint64(i + 1)
	}
	for theta := 5; theta <= 16; theta++ {
		p, ok := LookupSmallWoodFieldProfileV3(1017857, theta)
		if !ok {
			t.Fatalf("missing theta=%d profile", theta)
		}
		field, extra, err := p.Validate(omega)
		if err != nil {
			t.Fatalf("theta=%d validate: %v", theta, err)
		}
		if len(extra.Limb) != theta || extra.Limb[1] != 1 {
			t.Fatalf("theta=%d omega-extra=%v", theta, extra.Limb)
		}
		if field.Q != p.Q || field.Theta != p.Theta || len(field.Chi) != theta+1 || field.Chi[theta] != 1 {
			t.Fatalf("theta=%d incompatible checked field: q=%d degree=%d chi=%v", theta, field.Q, field.Theta, field.Chi)
		}
		for _, w := range omega {
			if equalElem(field, extra, field.EmbedF(w)) {
				t.Fatalf("theta=%d omega-extra collided with %d", theta, w)
			}
		}
		if got, err := p.DigestHex((theta + 7) / 2); err != nil || got == "" {
			t.Fatalf("theta=%d digest=%q err=%v", theta, got, err)
		}
	}
}

func TestSmallWoodFieldProfilesTheta5Through16IDsAndDigestsPinned(t *testing.T) {
	for _, tc := range []struct {
		theta       int
		id          string
		digest32Hex string
	}{
		{5, "spruce-smallwood-kfield-q1017857-theta5-v4", "f5cce09c0155a508463ed292effc440ba822e010115e6370c6a1dab31fa404e4"},
		{6, "spruce-smallwood-kfield-q1017857-theta6-v4", "da25e0df018ea0e961cf567544e6319a3a8051f3941534d43f5048d1c7169659"},
		{7, "spruce-smallwood-kfield-q1017857-theta7-v3", "ba72a24ef2a544ceccbaf63ef821c034c2ca939bb131c35c456840f69422e95a"},
		{8, "spruce-smallwood-kfield-q1017857-theta8-v4", "fa4716ff12c777e93dd1ba3c91f5f61cf1360cfb21df7b62199e7930b3fb61a1"},
		{9, "spruce-smallwood-kfield-q1017857-theta9-v4", "f443bd8ec50c36be8707fc9a7a8e25310309f3ffa3bfda4a180a1f9cba76a1d1"},
		{10, "spruce-smallwood-kfield-q1017857-theta10-v4", "29653cf4c1eefe8552f7f956b84f85e0c8d9024593be64f8d92a4a0fd2525d6d"},
		{11, "spruce-smallwood-kfield-q1017857-theta11-v4", "7bcf8917df35cba73aa1c29deb2b54f4cbcc190d7e193188c1ab346e2fb659a7"},
		{12, "spruce-smallwood-kfield-q1017857-theta12-v4", "b33395dad7428d599725cd093bc0ff6302a1e9492358b98adb45d4724c299b9e"},
		{13, "spruce-smallwood-kfield-q1017857-theta13-v3", "67bf7f5d49ef1485a05dd2313cc789096f7dc6befb24b0c7bb0e05f7bbde1462"},
		{14, "spruce-smallwood-kfield-q1017857-theta14-v4", "c66be6cdfb5989c9309b133dd1de3465cf8e42e6e10bbacc3faa08bbd69f137a"},
		{15, "spruce-smallwood-kfield-q1017857-theta15-v4", "a4d699b352d63f5afa8325d57ff7fd80e22fcda8fb21602f9cae26a6c5de97a0"},
		{16, "spruce-smallwood-kfield-q1017857-theta16-v4", "5eed27bc588a42c45be8be68eb2514bd7f0be4b0c357e732bf74a3dfd5663ad7"},
	} {
		t.Run("theta-"+strconv.Itoa(tc.theta), func(t *testing.T) {
			profile, ok := LookupSmallWoodFieldProfileV3(1017857, tc.theta)
			if !ok {
				t.Fatalf("missing theta=%d profile", tc.theta)
			}
			if profile.ID != tc.id {
				t.Fatalf("theta=%d id=%q want=%q", tc.theta, profile.ID, tc.id)
			}
			gotDigest, err := profile.DigestHex(32)
			if err != nil {
				t.Fatalf("theta=%d digest: %v", tc.theta, err)
			}
			if gotDigest != tc.digest32Hex {
				t.Fatalf("theta=%d digest=%s want=%s", tc.theta, gotDigest, tc.digest32Hex)
			}
		})
	}
}

func TestSmallWoodFieldProfileDefensiveCopies(t *testing.T) {
	p, ok := LookupSmallWoodFieldProfileV3(1017857, 7)
	if !ok {
		t.Fatal("missing profile")
	}
	p.Chi[0] = 0
	p.OmegaExtra[1] = 0
	again, _ := LookupSmallWoodFieldProfileV3(1017857, 7)
	if again.Chi[0] == 0 || again.OmegaExtra[1] != 1 {
		t.Fatal("profile registry was mutated through returned slices")
	}
}

func TestSmallWoodFieldProfilesV3CanonicalEncodingAndDigestPinned(t *testing.T) {
	for _, tc := range []struct {
		theta        int
		canonicalHex string
		digest32Hex  string
	}{
		{
			theta:        7,
			canonicalHex: "03000000000000002a000000000000007370727563652d736d616c6c776f6f642d6b6669656c642d71313031373835372d7468657461372d763301880f00000000000700000000000000080000000000000067c1000000000000663e0900000000008e6d0f0000000000b58c040000000000a3f60b000000000054da040000000000fc150f0000000000010000000000000007000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			digest32Hex:  "ba72a24ef2a544ceccbaf63ef821c034c2ca939bb131c35c456840f69422e95a",
		},
		{
			theta:        10,
			canonicalHex: "03000000000000002b000000000000007370727563652d736d616c6c776f6f642d6b6669656c642d71313031373835372d746865746131302d763401880f00000000000a000000000000000b0000000000000031960e000000000097090f0000000000db06010000000000fa1101000000000056590d0000000000bd0204000000000084bc0b0000000000a5520b000000000035490d000000000026d400000000000001000000000000000a000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			digest32Hex:  "29653cf4c1eefe8552f7f956b84f85e0c8d9024593be64f8d92a4a0fd2525d6d",
		},
		{
			theta:        13,
			canonicalHex: "03000000000000002b000000000000007370727563652d736d616c6c776f6f642d6b6669656c642d71313031373835372d746865746131332d763301880f00000000000d000000000000000e000000000000005fdb0b0000000000ed59040000000000ccf20800000000007a71020000000000655b0b00000000006d860700000000008dce0000000000007601000000000000bc7e0400000000007e650a000000000039e10d000000000041460f0000000000a2f407000000000001000000000000000d000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			digest32Hex:  "67bf7f5d49ef1485a05dd2313cc789096f7dc6befb24b0c7bb0e05f7bbde1462",
		},
	} {
		t.Run("theta-"+strconv.Itoa(tc.theta), func(t *testing.T) {
			profile, ok := LookupSmallWoodFieldProfileV3(1017857, tc.theta)
			if !ok {
				t.Fatalf("missing theta=%d profile", tc.theta)
			}
			if got := hex.EncodeToString(profile.CanonicalBytes()); got != tc.canonicalHex {
				t.Fatalf("theta=%d canonical profile bytes changed:\n got %s\nwant %s", tc.theta, got, tc.canonicalHex)
			}
			gotDigest, err := profile.DigestHex(32)
			if err != nil {
				t.Fatalf("theta=%d digest: %v", tc.theta, err)
			}
			if gotDigest != tc.digest32Hex {
				t.Fatalf("theta=%d digest=%s want=%s", tc.theta, gotDigest, tc.digest32Hex)
			}
		})
	}
}
