package credential

import (
	"fmt"
	"math"
	"strings"
)

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
	Label              string                `json:"label"`
	Mode               SecurityMode          `json:"mode"`
	ROM                ROMModel              `json:"rom"`
	TargetBits         float64               `json:"target_bits"`
	CoreBitsRequired   float64               `json:"core_bits_required"`
	ROQueryCaps        []uint64              `json:"ro_query_caps,omitempty"`
	ROQueryCapBits     []float64             `json:"ro_query_cap_bits,omitempty"`
	MinDECSHashBits    int                   `json:"min_decs_hash_bits,omitempty"`
	MinDECSTapeBits    int                   `json:"min_decs_tape_bits,omitempty"`
	MinFSCollisionBits int                   `json:"min_fs_collision_bits,omitempty"`
	MinSaltBits        int                   `json:"min_salt_bits,omitempty"`
	MinPRFTagElements  int                   `json:"min_prf_tag_elements,omitempty"`
	SeedSlots          int                   `json:"seed_slots,omitempty"`
	PackedKeyCoords    int                   `json:"packed_key_coords,omitempty"`
	Status             SecurityProfileStatus `json:"status"`
	Notes              string                `json:"notes,omitempty"`
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
		if err := validateIntGenISISSecurityProfileSpec(profile); err != nil {
			panic(fmt.Sprintf("invalid IntGenISIS security profile %q: %v", profile.Label, err))
		}
		label := normalizeIntGenISISSecurityProfileLabel(profile.Label)
		if _, exists := reg[label]; exists {
			panic("duplicate IntGenISIS security profile " + profile.Label)
		}
		reg[label] = profile
	}
	return reg
}

func validateIntGenISISSecurityProfileSpec(profile IntGenISISSecurityProfileSpec) error {
	if strings.TrimSpace(profile.Label) == "" || !finitePositive(profile.TargetBits) || !finitePositive(profile.CoreBitsRequired) || profile.CoreBitsRequired < profile.TargetBits {
		return fmt.Errorf("invalid label or target/core bits")
	}
	if profile.ROM != ROMModelCROM {
		return fmt.Errorf("unsupported ROM model %q", profile.ROM)
	}
	switch profile.Mode {
	case SecurityModeSingleCandidate, SecurityModeQueryWorkFactor:
		if len(profile.ROQueryCaps) != 0 || len(profile.ROQueryCapBits) != 0 {
			return fmt.Errorf("mode %q must not carry bounded-query caps", profile.Mode)
		}
	case SecurityModeResidualAtBudget:
		if len(profile.ROQueryCapBits) != 5 {
			return fmt.Errorf("residual-budget profile must carry five logarithmic caps")
		}
		for i, bits := range profile.ROQueryCapBits {
			if bits <= 0 || math.IsNaN(bits) || math.IsInf(bits, 0) {
				return fmt.Errorf("invalid logarithmic query cap %d=%v", i, bits)
			}
		}
		if len(profile.ROQueryCaps) != 0 {
			if len(profile.ROQueryCaps) != 5 {
				return fmt.Errorf("integer query caps must contain five entries")
			}
			for i, cap := range profile.ROQueryCaps {
				if cap == 0 || math.Abs(math.Log2(float64(cap))-profile.ROQueryCapBits[i]) > 1e-9 {
					return fmt.Errorf("integer/log query cap mismatch at %d", i)
				}
			}
		}
	default:
		return fmt.Errorf("unsupported security mode %q", profile.Mode)
	}
	switch profile.Status {
	case SecurityProfileCompleteLive, SecurityProfileProofOnly, SecurityProfileCandidate, SecurityProfileRequiresNewPrimitives, SecurityProfileRequiresTheory:
	default:
		return fmt.Errorf("unsupported profile status %q", profile.Status)
	}
	if profile.MinDECSHashBits < 0 || profile.MinDECSTapeBits < 0 || profile.MinFSCollisionBits < 0 || profile.MinSaltBits < 0 || profile.MinPRFTagElements <= 0 {
		return fmt.Errorf("invalid minimum security parameters")
	}
	if profile.SeedSlots != IntGenISISPRFSeedLen || profile.PackedKeyCoords != IntGenISISPRFPoseidonKeyLen {
		return fmt.Errorf("invalid semantic PRF seed/key shape")
	}
	return nil
}

func finitePositive(value float64) bool {
	return value > 0 && !math.IsNaN(value) && !math.IsInf(value, 0)
}

func intGenISISSecurityProfileSpecs() []IntGenISISSecurityProfileSpec {
	return []IntGenISISSecurityProfileSpec{
		{
			Label:             "SC-96",
			Mode:              SecurityModeSingleCandidate,
			ROM:               ROMModelCROM,
			TargetBits:        96,
			CoreBitsRequired:  96,
			MinPRFTagElements: 7,
			SeedSlots:         IntGenISISPRFSeedLen,
			PackedKeyCoords:   IntGenISISPRFPoseidonKeyLen,
			Status:            SecurityProfileProofOnly,
			Notes:             "Single-candidate 96-bit baseline for current compact presets.",
		},
		{
			Label:             "SC-125",
			Mode:              SecurityModeSingleCandidate,
			ROM:               ROMModelCROM,
			TargetBits:        125,
			CoreBitsRequired:  125,
			MinPRFTagElements: 7,
			SeedSlots:         IntGenISISPRFSeedLen,
			PackedKeyCoords:   IntGenISISPRFPoseidonKeyLen,
			Status:            SecurityProfileProofOnly,
			Notes:             "Single-candidate 125+ baseline; not a full 128-bit residual-budget claim.",
		},
		{
			Label:              "WF-128",
			Mode:               SecurityModeQueryWorkFactor,
			ROM:                ROMModelCROM,
			TargetBits:         128,
			CoreBitsRequired:   128,
			MinDECSHashBits:    264,
			MinDECSTapeBits:    128,
			MinFSCollisionBits: 264,
			MinSaltBits:        256,
			MinPRFTagElements:  13,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileCandidate,
			Notes:              "CROM work-factor candidate; the executable preset remains unavailable until a matching primitive/PRF family and complete ledger exist.",
		},
		{
			Label:              "WF-128-ENG",
			Mode:               SecurityModeQueryWorkFactor,
			ROM:                ROMModelCROM,
			TargetBits:         128,
			CoreBitsRequired:   128,
			MinDECSHashBits:    272,
			MinDECSTapeBits:    136,
			MinFSCollisionBits: 272,
			MinSaltBits:        264,
			MinPRFTagElements:  14,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileCandidate,
			Notes:              "Engineering-margin CROM work-factor lane; no executable preset or reviewed primitive/PRF family exists yet.",
		},
		{
			Label:              "BQ10-96",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         96,
			CoreBitsRequired:   106,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(10),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(10),
			MinDECSHashBits:    120,
			MinDECSTapeBits:    106,
			MinFSCollisionBits: 120,
			MinSaltBits:        120,
			MinPRFTagElements:  7,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileProofOnly,
			Notes:              "Historical proof-layer profile for raw 2^10 CROM query caps.",
		},
		{
			Label:              "BQ16-96",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         96,
			CoreBitsRequired:   112,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(16),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(16),
			MinDECSHashBits:    136,
			MinDECSTapeBits:    112,
			MinFSCollisionBits: 136,
			MinSaltBits:        136,
			MinPRFTagElements:  7,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileProofOnly,
			Notes:              "Historical proof-layer profile for raw 2^16 CROM query caps.",
		},
		{
			Label:              "BQ10-128",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         128,
			CoreBitsRequired:   138,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(10),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(10),
			MinDECSHashBits:    152,
			MinDECSTapeBits:    138,
			MinFSCollisionBits: 152,
			MinSaltBits:        152,
			MinPRFTagElements:  8,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileRequiresNewPrimitives,
			Notes:              "Historical proof-theorem point for raw 2^10 CROM query caps; the executable tag-7 PRF does not meet the system requirement.",
		},
		{
			Label:              "BQ16-128",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         128,
			CoreBitsRequired:   144,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(16),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(16),
			MinDECSHashBits:    168,
			MinDECSTapeBits:    144,
			MinFSCollisionBits: 168,
			MinSaltBits:        168,
			MinPRFTagElements:  8,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileRequiresNewPrimitives,
			Notes:              "Historical proof-theorem point for raw 2^16 CROM query caps; the executable tag-7 PRF does not meet the system requirement.",
		},
		{
			Label:              "BQ32-96",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         96,
			CoreBitsRequired:   128,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(32),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(32),
			MinDECSHashBits:    168,
			MinDECSTapeBits:    136,
			MinFSCollisionBits: 168,
			MinSaltBits:        168,
			MinPRFTagElements:  9,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileCandidate,
			Notes:              "Controlled-pilot CROM target with raw 2^32 query caps; requires measured composition and reviewed primitive accounting before promotion.",
		},
		{
			Label:              "BQ32-128",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         128,
			CoreBitsRequired:   160,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(32),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(32),
			MinDECSHashBits:    200,
			MinDECSTapeBits:    160,
			MinFSCollisionBits: 200,
			MinSaltBits:        192,
			MinPRFTagElements:  10,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileRequiresNewPrimitives,
			Notes:              "Requires about 160-bit lattice and PRF primitive families.",
		},
		{
			Label:              "BQ64-96",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         96,
			CoreBitsRequired:   160,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(64),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(64),
			MinDECSHashBits:    232,
			MinDECSTapeBits:    160,
			MinFSCollisionBits: 232,
			MinSaltBits:        224,
			MinPRFTagElements:  12,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileRequiresNewPrimitives,
			Notes:              "Requires about 160-bit lattice and PRF primitive families; 224-bit salt is the bare PDF target and 256-bit salt is the practical engineering lane.",
		},
		{
			Label:              "BQ64-128",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         128,
			CoreBitsRequired:   192,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(64),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(64),
			MinDECSHashBits:    320,
			MinDECSTapeBits:    192,
			MinFSCollisionBits: 320,
			MinSaltBits:        256,
			MinPRFTagElements:  13,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileRequiresNewPrimitives,
			Notes:              "Requires about 192-bit lattice and PRF primitive families.",
		},
		{
			Label:              "BQ128-128",
			Mode:               SecurityModeResidualAtBudget,
			ROM:                ROMModelCROM,
			TargetBits:         128,
			CoreBitsRequired:   256,
			ROQueryCaps:        intGenISISSecurityProfileROQueryCaps(128),
			ROQueryCapBits:     intGenISISSecurityProfileROQueryCapBits(128),
			MinDECSHashBits:    512,
			MinDECSTapeBits:    256,
			MinFSCollisionBits: 512,
			MinSaltBits:        384,
			MinPRFTagElements:  20,
			SeedSlots:          IntGenISISPRFSeedLen,
			PackedKeyCoords:    IntGenISISPRFPoseidonKeyLen,
			Status:             SecurityProfileRequiresNewPrimitives,
			Notes:              "Requires a 256-bit primitive redesign.",
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
