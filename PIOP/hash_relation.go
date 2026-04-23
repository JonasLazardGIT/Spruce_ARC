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
	x0Len := pub.X0Len
	if x0Len <= 0 {
		x0Len = 1
	}
	if pub.TargetDim <= 0 {
		pub.TargetDim = 1
	}
	if pub.TargetDim != 1 {
		return fmt.Errorf("bb_tran only supports TargetDim=1, got %d", pub.TargetDim)
	}
	if len(pub.B) != 3+x0Len {
		return fmt.Errorf("bb_tran requires %d B rows for X0Len=%d, got %d", 3+x0Len, x0Len, len(pub.B))
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
