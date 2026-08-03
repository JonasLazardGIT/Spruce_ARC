package PIOP

import (
	"bytes"
	"strings"
	"testing"
)

func TestFiatShamirDomainSeparationChangesChallenges(t *testing.T) {
	material := [][]byte{[]byte("same transcript material")}
	fsA := NewFS(NewShake256XOF(32), []byte("salt"), FSParams{Lambda: 128})
	_, _, chalA := fsA.GrindAndDerive(0, material, func(h []byte) []byte { return append([]byte(nil), h...) })

	fsB := NewFS(NewShake256XOF(32), []byte("salt"), FSParams{Lambda: 128})
	_, _, chalB := fsB.GrindAndDerive(1, material, func(h []byte) []byte { return append([]byte(nil), h...) })

	if bytes.Equal(chalA, chalB) {
		t.Fatal("Fiat-Shamir challenges matched across distinct round domains")
	}
}

func TestFSInitializationLengthBindsTranscriptTuple(t *testing.T) {
	salt := []byte("same salt")
	base := fsInitializationInput("v2", "protocol-a", salt)
	if bytes.Equal(base, fsInitializationInput("v2", "protocol-b", salt)) {
		t.Fatal("FS initialization did not bind transcript protocol")
	}
	if bytes.Equal(base, fsInitializationInput("v3", "protocol-a", salt)) {
		t.Fatal("FS initialization did not bind transcript version")
	}
	if bytes.Equal(
		fsInitializationInput("ab", "c", salt),
		fsInitializationInput("a", "bc", salt),
	) {
		t.Fatal("FS transcript tuple framing is ambiguous")
	}
	if bytes.Equal(base, salt) || !bytes.Contains(base, []byte(fsInitializationDomainV2)) {
		t.Fatal("FS initialization is not domain separated from the raw salt")
	}
}

func TestFSSaltBytesUsesExplicitSplitWidth(t *testing.T) {
	opts := SimOpts{Lambda: 256, SaltBits: 168}
	if got := fsSaltBytesForOpts(opts); got != 21 {
		t.Fatalf("explicit salt bytes=%d want 21", got)
	}
	opts.SaltBits = 0
	if got := fsSaltBytesForOpts(opts); got != 64 {
		t.Fatalf("legacy salt bytes=%d want 64", got)
	}
}

func TestVerifierRejectsSaltWidthOutsideBoundManifest(t *testing.T) {
	opts := SimOpts{SaltBits: 168}
	proof := &Proof{Salt: make([]byte, 20)}
	if _, err := VerifyWithConstraints(proof, ConstraintSet{}, PublicInputs{}, opts, ""); err == nil || !strings.Contains(err.Error(), "salt length") {
		t.Fatalf("unexpected verifier result for 160-bit salt under 168-bit options: %v", err)
	}
}

func TestPaperTranscriptUsesExplicitSaltAndRootWidths(t *testing.T) {
	report := buildPaperTranscriptReportLeaf(&Proof{}, 1048193, paperTranscriptParams{
		Lambda:       128,
		SaltBits:     168,
		DECSHashBits: 168,
	})
	if report.SaltRoot.OptimizedBits != 336 || report.SaltRoot.OptimizedBytes != 42 {
		t.Fatalf("explicit salt/root bucket=%+v", report.SaltRoot)
	}
}
