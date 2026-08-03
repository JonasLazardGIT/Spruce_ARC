package keys

import (
	"path/filepath"
	"strings"
	"testing"
)

func testPublicKey(t *testing.T) *PublicKey {
	t.Helper()
	pk := &PublicKey{
		Version:      KeyVersionV2,
		ParamsDigest: strings.Repeat("ab", 32),
		N:            2,
		Q:            "11",
		HCoeffs:      []int64{-1, 2},
	}
	if err := BindPublicKey(pk); err != nil {
		t.Fatal(err)
	}
	if pk.KeyID != "95e61af365c70cfcb23642ed8a6bad2d141142bea85372247188935248710857" {
		t.Fatalf("canonical public key ID=%s", pk.KeyID)
	}
	return pk
}

func TestPublicKeyV2RoundTripAndTamperRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public.json")
	pk := testPublicKey(t)
	if err := SavePublicFile(path, pk); err != nil {
		t.Fatalf("save public key: %v", err)
	}
	got, err := LoadPublicFile(path)
	if err != nil {
		t.Fatalf("load public key: %v", err)
	}
	if got.KeyID != pk.KeyID || got.ParamsDigest != pk.ParamsDigest {
		t.Fatalf("lost public key bindings: %+v", got)
	}

	got.HCoeffs[0]++
	if err := writeJSON(path, got); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicFile(path); err == nil {
		t.Fatal("accepted public key coefficients under stale key ID")
	}
}

func TestPrivateKeyV2RejectsLegacyAndMissingPairBinding(t *testing.T) {
	pk := testPublicKey(t)
	sk := &PrivateKey{
		Version:      KeyVersionV2,
		ParamsDigest: pk.ParamsDigest,
		PublicKeyID:  pk.KeyID,
		N:            2,
		Q:            "11",
		F:            []int64{1, 0},
		G:            []int64{0, 1},
		Fsmall:       []int64{1, 0},
		Gsmall:       []int64{0, 1},
	}
	if err := ValidatePrivateKey(sk); err != nil {
		t.Fatalf("valid private artifact: %v", err)
	}
	sk.Version = "ntru-key-v1"
	if err := ValidatePrivateKey(sk); err == nil {
		t.Fatal("accepted legacy private-key identity")
	}
	sk.Version = KeyVersionV2
	sk.PublicKeyID = ""
	if err := ValidatePrivateKey(sk); err == nil {
		t.Fatal("accepted private key without public-key binding")
	}
}

func testSignature(t *testing.T) *Signature {
	t.Helper()
	pk := testPublicKey(t)
	sig := NewSignature()
	sig.Params.N = pk.N
	sig.Params.Q = pk.Q
	sig.Params.ParamsDigest = pk.ParamsDigest
	sig.Hash.TCoeffs = []int64{1, -1}
	sig.PublicKey.KeyID = pk.KeyID
	sig.PublicKey.HCoeffs = append([]int64(nil), pk.HCoeffs...)
	sig.Signature.S0 = []int64{1, 0}
	sig.Signature.S1 = []int64{0, -1}
	sig.Signature.S2 = []int64{1, 1}
	sig.Signature.Norm.Passed = true
	sig.Signature.Norm.L2Est = 3
	sig.Signature.Norm.ResidualLinf = 1
	sig.Signature.TrialsUsed = 1
	sig.Signature.MaxTrials = 4
	if err := BindSignature(sig); err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestSignatureV2RoundTripAndParameterBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signature.json")
	sig := testSignature(t)
	if err := SaveSignatureFile(path, sig); err != nil {
		t.Fatalf("save signature: %v", err)
	}
	got, err := LoadSignatureFile(path)
	if err != nil {
		t.Fatalf("load signature: %v", err)
	}
	if got.Version != SignatureVersionV2 || got.SignatureID != sig.SignatureID || got.PublicKey.KeyID != sig.PublicKey.KeyID {
		t.Fatalf("lost signature identity: %+v", got)
	}
	got.Signature.Norm.L2Est++
	if err := writeJSON(path, got); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignatureFile(path); err == nil {
		t.Fatal("accepted signature metadata tampering under stale signature ID")
	}

	got = testSignature(t)
	got.Params.ParamsDigest = strings.Repeat("cd", 32)
	if err := writeJSON(path, got); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignatureFile(path); err == nil {
		t.Fatal("accepted signature params tampering under stale public-key ID")
	}
}

func TestSignatureV2RejectsLegacyIdentity(t *testing.T) {
	sig := testSignature(t)
	sig.Version = "ntru-signature-v1"
	if err := ValidateSignature(sig); err == nil {
		t.Fatal("accepted legacy signature identity")
	}
}
