package PIOP

import (
	"fmt"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func normalizePublicHashRelation(pub PublicInputs) string {
	return credential.NormalizeHashRelation(pub.HashRelation)
}

func publicUsesBBTran(pub PublicInputs) bool {
	return normalizePublicHashRelation(pub) == credential.HashRelationBBTran
}

func validateHashRelationPublicInputs(pub PublicInputs) error {
	relation := normalizePublicHashRelation(pub)
	if relation == "" {
		return fmt.Errorf("missing or invalid hash relation %q", pub.HashRelation)
	}
	if relation != credential.HashRelationBBTran {
		return nil
	}
	if len(pub.B) == 0 {
		return nil
	}
	if len(pub.B) != 4 {
		return fmt.Errorf("bb_tran requires 4 B rows, got %d", len(pub.B))
	}
	if !polyIsZero(pub.B[0]) {
		return fmt.Errorf("bb_tran requires B[0] = 0")
	}
	return nil
}

func polyIsZero(p *ring.Poly) bool {
	if p == nil {
		return false
	}
	for _, c := range p.Coeffs[0] {
		if c != 0 {
			return false
		}
	}
	return true
}
