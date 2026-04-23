package credential

import "fmt"

const (
	HashRelationBBS    = "bbs"
	HashRelationBBTran = "bb_tran"
)

func NormalizeHashRelation(relation string) string {
	switch relation {
	case HashRelationBBS:
		return HashRelationBBS
	case HashRelationBBTran:
		return HashRelationBBTran
	default:
		return ""
	}
}

func ValidateHashRelation(relation string) error {
	if NormalizeHashRelation(relation) == "" {
		return fmt.Errorf("invalid hash_relation %q", relation)
	}
	return nil
}

func ValidateLiveHashRelation(relation string) error {
	if NormalizeHashRelation(relation) != HashRelationBBTran {
		return fmt.Errorf("unsupported live hash_relation %q: only %q is allowed", relation, HashRelationBBTran)
	}
	return nil
}
