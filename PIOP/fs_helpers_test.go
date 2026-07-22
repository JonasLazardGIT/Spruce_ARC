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
