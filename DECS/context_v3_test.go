package decs

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/sha3"
)

func TestV3CommitmentDomainsAreSeparatedFromV2(t *testing.T) {
	salt := bytes.Repeat([]byte{0x39}, MinSaltBytes)
	v2 := CommitmentContext{TranscriptVersion: TranscriptVersionV2, Role: CommitmentRoleMain, Salt: salt}
	v3 := CommitmentContext{TranscriptVersion: TranscriptVersionV3, Role: CommitmentRoleMain, Salt: salt}
	if err := v2.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := v3.Validate(); err != nil {
		t.Fatal(err)
	}
	pvals := []uint64{1, 2, 3}
	mvals := []uint64{4, 5}
	tape := bytes.Repeat([]byte{0xa7}, 16)
	h2 := hashLeafV2With(sha3.NewShake256(), v2, 7, 19, 1017857, pvals, mvals, tape, 32)
	h3 := hashLeafV2With(sha3.NewShake256(), v3, 7, 19, 1017857, pvals, mvals, tape, 32)
	if bytes.Equal(h2, h3) {
		t.Fatal("v2 and v3 leaf commitments collided for identical payload")
	}
	g2, err := DeriveGammaV2(v2, h2, 2, 3, 1017857)
	if err != nil {
		t.Fatal(err)
	}
	g3, err := DeriveGammaV2(v3, h2, 2, 3, 1017857)
	if err != nil {
		t.Fatal(err)
	}
	if len(g2) == len(g3) && bytes.Equal(uint64MatrixBytes(g2), uint64MatrixBytes(g3)) {
		t.Fatal("v2 and v3 gamma domains produced the same matrix")
	}
}

func TestCommitmentContextRejectsUnknownVersion(t *testing.T) {
	ctx := CommitmentContext{
		TranscriptVersion: "smallwood-unknown",
		Role:              CommitmentRoleMain,
		Salt:              bytes.Repeat([]byte{1}, MinSaltBytes),
	}
	if err := ctx.Validate(); err == nil {
		t.Fatal("unknown transcript version accepted")
	}
}

func uint64MatrixBytes(in [][]uint64) []byte {
	out := make([]byte, 0, len(in)*len(in[0])*8)
	for _, row := range in {
		for _, v := range row {
			out = append(out,
				byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
				byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
		}
	}
	return out
}
