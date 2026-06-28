package PIOP

import (
	"bytes"
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
