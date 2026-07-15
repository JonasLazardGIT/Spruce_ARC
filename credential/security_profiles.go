package credential

import "strings"

type SecurityMode string

const (
	SecurityModeSingleCandidate  SecurityMode = "single_candidate"
	SecurityModeQueryWorkFactor  SecurityMode = "query_work_factor"
	SecurityModeResidualAtBudget SecurityMode = "residual_at_budget"
)

type ROMModel string

const (
	ROMModelCROM ROMModel = "crom"
)

type SecurityProfileStatus string

const (
	SecurityProfileCompleteLive          SecurityProfileStatus = "complete_live"
	SecurityProfileProofOnly             SecurityProfileStatus = "proof_only"
	SecurityProfileCandidate             SecurityProfileStatus = "candidate"
	SecurityProfileRequiresNewPrimitives SecurityProfileStatus = "requires_new_primitives"
	SecurityProfileRequiresTheory        SecurityProfileStatus = "requires_theorem_accounting"
)

type IntGenISISSecurityProfileSpec struct {
	Label            string                `json:"label"`
	Mode             SecurityMode          `json:"mode"`
	ROM              ROMModel              `json:"rom"`
	TargetBits       float64               `json:"target_bits"`
	CoreBitsRequired float64               `json:"core_bits_required"`
	ROQueryCaps      []uint64              `json:"ro_query_caps,omitempty"`
	ROQueryCapBits   []float64             `json:"ro_query_cap_bits,omitempty"`
	DECSHashBits     int                   `json:"decs_hash_bits,omitempty"`
	DECSTapeBits     int                   `json:"decs_tape_bits,omitempty"`
	FSCollisionBits  int                   `json:"fs_collision_bits,omitempty"`
	SaltBits         int                   `json:"salt_bits,omitempty"`
	PRFTagElements   int                   `json:"prf_tag_elements,omitempty"`
	SeedSlots        int                   `json:"seed_slots,omitempty"`
	PackedKeyCoords  int                   `json:"packed_key_coords,omitempty"`
	Status           SecurityProfileStatus `json:"status"`
	Notes            string                `json:"notes,omitempty"`
}

func LookupIntGenISISSecurityProfile(label string) (IntGenISISSecurityProfileSpec, bool) {
	profile, ok := intGenISISSecurityProfileRegistry()[normalizeIntGenISISSecurityProfileLabel(label)]
	if !ok {
		return IntGenISISSecurityProfileSpec{}, false
	}
	return cloneIntGenISISSecurityProfileSpec(profile), true
}

func normalizeIntGenISISSecurityProfileLabel(label string) string {
	return strings.ToUpper(strings.TrimSpace(label))
}

func intGenISISSecurityProfileRegistry() map[string]IntGenISISSecurityProfileSpec {
	profiles := intGenISISSecurityProfileSpecs()
	reg := make(map[string]IntGenISISSecurityProfileSpec, len(profiles))
	for _, profile := range profiles {
		reg[normalizeIntGenISISSecurityProfileLabel(profile.Label)] = profile
	}
	return reg
}

func intGenISISSecurityProfileSpecs() []IntGenISISSecurityProfileSpec {
	return []IntGenISISSecurityProfileSpec{
		{
			Label:            "SC-96",
			Mode:             SecurityModeSingleCandidate,
			ROM:              ROMModelCROM,
			TargetBits:       96,
			CoreBitsRequired: 96,
			PRFTagElements:   7,
			SeedSlots:        IntGenISISPRFSeedLen,
			PackedKeyCoords:  IntGenISISPRFPoseidonKeyLen,
			Status:           SecurityProfileProofOnly,
			Notes:            "Single-candidate 96-bit baseline for current compact presets.",
		},
		{
			Label:            "SC-125",
			Mode:             SecurityModeSingleCandidate,
			ROM:              ROMModelCROM,
			TargetBits:       125,
			CoreBitsRequired: 125,
			PRFTagElements:   7,
			SeedSlots:        IntGenISISPRFSeedLen,
			PackedKeyCoords:  IntGenISISPRFPoseidonKeyLen,
			Status:           SecurityProfileProofOnly,
			Notes:            "Single-candidate 125+ baseline; not a full 128-bit residual-budget claim.",
		},
		{
			Label:            "WF-128",
			Mode:             SecurityModeQueryWorkFactor,
			ROM:              ROMModelCROM,
			TargetBits:       128,
			CoreBitsRequired: 128,
			DECSHashBits:     264,
			DECSTapeBits:     128,
			FSCollisionBits:  264,
			SaltBits:         128,
			PRFTagElements:   7,
			SeedSlots:        IntGenISISPRFSeedLen,
			PackedKeyCoords:  IntGenISISPRFPoseidonKeyLen,
			Status:           SecurityProfileCandidate,
			Notes:            "Query work-factor target in CROM; blocked from live use until width split and ledger pass.",
		},
		{
			Label:            "BQ32-96",
			Mode:             SecurityModeResidualAtBudget,
			ROM:              ROMModelCROM,
			TargetBits:       96,
			CoreBitsRequired: 128,
			ROQueryCaps:      intGenISISSecurityProfileROQueryCaps(32),
			ROQueryCapBits:   intGenISISSecurityProfileROQueryCapBits(32),
			DECSHashBits:     168,
			DECSTapeBits:     128,
			FSCollisionBits:  168,
			SaltBits:         128,
			PRFTagElements:   9,
			SeedSlots:        IntGenISISPRFSeedLen,
			PackedKeyCoords:  IntGenISISPRFPoseidonKeyLen,
			Status:           SecurityProfileCandidate,
			Notes:            "First bounded-budget target; requires ledger, tag-9 PRF plumbing, and width split before promotion.",
		},
		{
			Label:            "BQ32-128",
			Mode:             SecurityModeResidualAtBudget,
			ROM:              ROMModelCROM,
			TargetBits:       128,
			CoreBitsRequired: 160,
			ROQueryCaps:      intGenISISSecurityProfileROQueryCaps(32),
			ROQueryCapBits:   intGenISISSecurityProfileROQueryCapBits(32),
			DECSHashBits:     200,
			DECSTapeBits:     160,
			FSCollisionBits:  200,
			SaltBits:         192,
			PRFTagElements:   10,
			SeedSlots:        IntGenISISPRFSeedLen,
			PackedKeyCoords:  IntGenISISPRFPoseidonKeyLen,
			Status:           SecurityProfileRequiresNewPrimitives,
			Notes:            "Requires about 160-bit lattice and PRF primitive families.",
		},
		{
			Label:            "BQ64-96",
			Mode:             SecurityModeResidualAtBudget,
			ROM:              ROMModelCROM,
			TargetBits:       96,
			CoreBitsRequired: 160,
			ROQueryCaps:      intGenISISSecurityProfileROQueryCaps(64),
			ROQueryCapBits:   intGenISISSecurityProfileROQueryCapBits(64),
			DECSHashBits:     232,
			DECSTapeBits:     160,
			FSCollisionBits:  232,
			SaltBits:         224,
			PRFTagElements:   12,
			SeedSlots:        IntGenISISPRFSeedLen,
			PackedKeyCoords:  IntGenISISPRFPoseidonKeyLen,
			Status:           SecurityProfileRequiresNewPrimitives,
			Notes:            "Requires about 160-bit lattice and PRF primitive families; 224-bit salt is the bare PDF target and 256-bit salt is the practical engineering lane.",
		},
		{
			Label:            "BQ64-128",
			Mode:             SecurityModeResidualAtBudget,
			ROM:              ROMModelCROM,
			TargetBits:       128,
			CoreBitsRequired: 192,
			ROQueryCaps:      intGenISISSecurityProfileROQueryCaps(64),
			ROQueryCapBits:   intGenISISSecurityProfileROQueryCapBits(64),
			DECSHashBits:     320,
			DECSTapeBits:     192,
			FSCollisionBits:  320,
			SaltBits:         256,
			PRFTagElements:   13,
			SeedSlots:        IntGenISISPRFSeedLen,
			PackedKeyCoords:  IntGenISISPRFPoseidonKeyLen,
			Status:           SecurityProfileRequiresNewPrimitives,
			Notes:            "Requires about 192-bit lattice and PRF primitive families.",
		},
		{
			Label:            "BQ128-128",
			Mode:             SecurityModeResidualAtBudget,
			ROM:              ROMModelCROM,
			TargetBits:       128,
			CoreBitsRequired: 256,
			ROQueryCaps:      intGenISISSecurityProfileROQueryCaps(128),
			ROQueryCapBits:   intGenISISSecurityProfileROQueryCapBits(128),
			DECSHashBits:     512,
			DECSTapeBits:     256,
			FSCollisionBits:  512,
			SaltBits:         384,
			PRFTagElements:   20,
			SeedSlots:        IntGenISISPRFSeedLen,
			PackedKeyCoords:  IntGenISISPRFPoseidonKeyLen,
			Status:           SecurityProfileRequiresNewPrimitives,
			Notes:            "Requires a 256-bit primitive redesign.",
		},
	}
}

func intGenISISSecurityProfileROQueryCaps(exp uint) []uint64 {
	if exp >= 64 {
		return nil
	}
	cap := uint64(1) << exp
	return []uint64{cap, cap, cap, cap, cap}
}

func intGenISISSecurityProfileROQueryCapBits(exp uint) []float64 {
	bits := float64(exp)
	return []float64{bits, bits, bits, bits, bits}
}

func cloneIntGenISISSecurityProfileSpec(profile IntGenISISSecurityProfileSpec) IntGenISISSecurityProfileSpec {
	if profile.ROQueryCaps != nil {
		profile.ROQueryCaps = append([]uint64(nil), profile.ROQueryCaps...)
	}
	if profile.ROQueryCapBits != nil {
		profile.ROQueryCapBits = append([]float64(nil), profile.ROQueryCapBits...)
	}
	return profile
}
