package PIOP

import "vSIS-Signature/credential"

func normalizePublicHashRelation(pub PublicInputs) string {
	return credential.NormalizeHashRelation(pub.HashRelation)
}

func publicUsesBBTran(pub PublicInputs) bool {
	return normalizePublicHashRelation(pub) == credential.HashRelationBBTran
}

func relationUsesBBTran(relation string) bool {
	return credential.NormalizeHashRelation(relation) == credential.HashRelationBBTran
}
