package signverify

import (
	"path/filepath"
	"strings"
	"testing"

	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
)

func TestVerifyRejectsSignatureFromDifferentParamsDigest(t *testing.T) {
	paramsPath := filepath.Join(t.TempDir(), "params.json")
	if err := ntrurio.SaveParams(paramsPath, ntrurio.SystemParams{N: 2, Q: 17, Beta: 3}); err != nil {
		t.Fatal(err)
	}
	pk := &keys.PublicKey{
		Version:      keys.KeyVersionV2,
		ParamsDigest: strings.Repeat("ab", 32),
		N:            2,
		Q:            "11",
		HCoeffs:      []int64{0, 0},
	}
	if err := keys.BindPublicKey(pk); err != nil {
		t.Fatal(err)
	}
	sig := keys.NewSignature()
	sig.Params.N = 2
	sig.Params.Q = "11"
	sig.Params.ParamsDigest = pk.ParamsDigest
	sig.Hash.TCoeffs = []int64{0, 0}
	sig.PublicKey.KeyID = pk.KeyID
	sig.PublicKey.HCoeffs = pk.HCoeffs
	sig.Signature.S0 = []int64{0, 0}
	sig.Signature.S1 = []int64{0, 0}
	sig.Signature.S2 = []int64{0, 0}
	sig.Signature.Norm.Passed = true
	sig.Signature.TrialsUsed = 1
	sig.Signature.MaxTrials = 1
	if err := keys.BindSignature(sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWithParamsPath(sig, paramsPath); err == nil {
		t.Fatal("verified signature under a different params digest")
	}
}
