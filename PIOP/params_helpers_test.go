package PIOP

import (
	"reflect"
	"testing"

	"vSIS-Signature/credential"
)

func TestBBTranWitnessOmegaStableAcrossNLeaves(t *testing.T) {
	const (
		q            = uint64(1054721)
		witnessNCols = 16
		lvcsNCols    = 96
		ell          = 18
	)
	omega4096, err := deriveRelationWitnessOmega(q, 4096, witnessNCols, lvcsNCols, ell, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("deriveRelationWitnessOmega(4096): %v", err)
	}
	omega8192, err := deriveRelationWitnessOmega(q, 8192, witnessNCols, lvcsNCols, ell, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("deriveRelationWitnessOmega(8192): %v", err)
	}
	if !reflect.DeepEqual(omega4096, omega8192) {
		t.Fatalf("bb_tran witness omega should be stable across nLeaves: 4096=%v 8192=%v", omega4096, omega8192)
	}
}

func TestBBTranExplicitDomainPrefixStableAcrossNLeaves(t *testing.T) {
	const (
		q            = uint64(1054721)
		witnessNCols = 16
		lvcsNCols    = 96
		ell          = 18
	)
	omega4096, points4096, err := deriveExplicitDomainForRelation(q, 4096, witnessNCols, lvcsNCols, ell, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("deriveExplicitDomainForRelation(4096): %v", err)
	}
	omega8192, points8192, err := deriveExplicitDomainForRelation(q, 8192, witnessNCols, lvcsNCols, ell, credential.HashRelationBBTran)
	if err != nil {
		t.Fatalf("deriveExplicitDomainForRelation(8192): %v", err)
	}
	if !reflect.DeepEqual(omega4096, omega8192) {
		t.Fatalf("bb_tran explicit omega should be stable across nLeaves")
	}
	prefixLen := lvcsNCols + ell
	if len(points4096) < prefixLen || len(points8192) < prefixLen {
		t.Fatalf("domain prefix too short: len4096=%d len8192=%d want >= %d", len(points4096), len(points8192), prefixLen)
	}
	if !reflect.DeepEqual(points4096[:prefixLen], points8192[:prefixLen]) {
		t.Fatalf("bb_tran explicit prefix should be stable across nLeaves")
	}
}

func TestGenericExplicitWitnessOmegaStillTracksNLeaves(t *testing.T) {
	const (
		q            = uint64(1054721)
		witnessNCols = 16
		lvcsNCols    = 32
		ell          = 18
	)
	omega2048, err := deriveRelationWitnessOmega(q, 2048, witnessNCols, lvcsNCols, ell, "legacy_scalar_relation")
	if err != nil {
		t.Fatalf("deriveRelationWitnessOmega(2048): %v", err)
	}
	omega4096, err := deriveRelationWitnessOmega(q, 4096, witnessNCols, lvcsNCols, ell, "legacy_scalar_relation")
	if err != nil {
		t.Fatalf("deriveRelationWitnessOmega(4096): %v", err)
	}
	if reflect.DeepEqual(omega2048, omega4096) {
		t.Fatalf("non-bb_tran witness omega should keep explicit-domain behavior")
	}
}
