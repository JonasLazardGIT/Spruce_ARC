package kfield

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const SmallWoodFieldProfileVersionV3 = 3

// SmallWoodFieldProfile fixes the public extension-field representation used by
// a maintained SmallWood v3 preset. Chi and OmegaExtra are public parameters,
// not prover messages.
type SmallWoodFieldProfile struct {
	Version    int
	ID         string
	Q          uint64
	Theta      int
	Chi        []uint64
	OmegaExtra []uint64
}

// The publication-v4 profiles added for theta 5..16 were derived once by
// feeding FindIrreducible with SHAKE-256 seeded by
//
//	SPRUCE/SmallWood/field-profile/v4/irreducible/q1017857/theta<theta>
//
// and are pinned here so production and replay never depend on a runtime
// polynomial search. The pre-existing theta 7, 10, and 13 profiles are kept
// byte-for-byte for compatibility.
var maintainedSmallWoodFieldProfilesV3 = map[int]SmallWoodFieldProfile{
	5: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta5-v4",
		Q:          1017857,
		Theta:      5,
		Chi:        []uint64{427311, 319530, 595293, 829711, 240319, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0},
	},
	6: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta6-v4",
		Q:          1017857,
		Theta:      6,
		Chi:        []uint64{663400, 832985, 260110, 757556, 343454, 973663, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0},
	},
	7: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta7-v3",
		Q:          1017857,
		Theta:      7,
		Chi:        []uint64{49511, 605798, 1011086, 298165, 784035, 318036, 988668, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0},
	},
	8: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta8-v4",
		Q:          1017857,
		Theta:      8,
		Chi:        []uint64{286920, 900547, 499350, 705608, 610917, 684252, 600096, 258321, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0},
	},
	9: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta9-v4",
		Q:          1017857,
		Theta:      9,
		Chi:        []uint64{365698, 597340, 651699, 84010, 647358, 15162, 937939, 306649, 907196, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0, 0},
	},
	10: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta10-v4",
		Q:          1017857,
		Theta:      10,
		Chi:        []uint64{955953, 985495, 67291, 70138, 874838, 262845, 769156, 742053, 870709, 54310, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0, 0, 0},
	},
	11: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta11-v4",
		Q:          1017857,
		Theta:      11,
		Chi:        []uint64{49089, 103027, 115597, 517377, 822722, 503884, 838139, 501531, 66495, 413756, 356615, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	},
	12: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta12-v4",
		Q:          1017857,
		Theta:      12,
		Chi:        []uint64{624336, 817012, 771074, 499493, 712971, 437729, 212258, 550505, 431378, 954375, 225458, 766316, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	},
	13: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta13-v3",
		Q:          1017857,
		Theta:      13,
		Chi:        []uint64{777055, 285165, 586444, 160122, 744293, 493165, 52877, 374, 294588, 681342, 909625, 1001025, 521378, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	},
	14: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta14-v4",
		Q:          1017857,
		Theta:      14,
		Chi:        []uint64{359811, 767830, 734430, 380351, 963208, 13301, 521041, 258128, 434260, 274510, 303283, 830023, 821998, 23902, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	},
	15: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta15-v4",
		Q:          1017857,
		Theta:      15,
		Chi:        []uint64{407488, 924438, 551890, 365504, 74296, 164271, 751152, 1011271, 626958, 804080, 184906, 578361, 157000, 557433, 643520, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	},
	16: {
		Version:    SmallWoodFieldProfileVersionV3,
		ID:         "spruce-smallwood-kfield-q1017857-theta16-v4",
		Q:          1017857,
		Theta:      16,
		Chi:        []uint64{605030, 925447, 274680, 651321, 237992, 626739, 664142, 985373, 964154, 260465, 632005, 432860, 508778, 921592, 914004, 600087, 1},
		OmegaExtra: []uint64{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	},
}

// LookupSmallWoodFieldProfileV3 returns a defensive copy of a maintained
// public field profile.
func LookupSmallWoodFieldProfileV3(q uint64, theta int) (SmallWoodFieldProfile, bool) {
	p, ok := maintainedSmallWoodFieldProfilesV3[theta]
	if !ok || p.Q != q {
		return SmallWoodFieldProfile{}, false
	}
	p.Chi = append([]uint64(nil), p.Chi...)
	p.OmegaExtra = append([]uint64(nil), p.OmegaExtra...)
	return p, true
}

// Validate checks the public field, the fixed extra support point, and its
// separation from the witness support. It returns the checked field so callers
// do not need to repeat the irreducibility test.
func (p SmallWoodFieldProfile) Validate(omega []uint64) (*Field, Elem, error) {
	if p.Version != SmallWoodFieldProfileVersionV3 || p.ID == "" {
		return nil, Elem{}, fmt.Errorf("kfield: invalid v3 field profile header")
	}
	if p.Q == 0 || p.Theta <= 1 || len(p.Chi) != p.Theta+1 || len(p.OmegaExtra) != p.Theta {
		return nil, Elem{}, fmt.Errorf("kfield: invalid v3 field profile dimensions")
	}
	field, err := New(p.Q, p.Theta, p.Chi)
	if err != nil {
		return nil, Elem{}, fmt.Errorf("kfield: validate v3 profile chi: %w", err)
	}
	extra := field.Phi(p.OmegaExtra)
	for _, w := range omega {
		if equalElem(field, extra, field.EmbedF(w%p.Q)) {
			return nil, Elem{}, fmt.Errorf("kfield: v3 omega-extra collides with witness support")
		}
	}
	return field, extra, nil
}

func equalElem(f *Field, a, b Elem) bool {
	if f == nil || len(a.Limb) != f.Theta || len(b.Limb) != f.Theta {
		return false
	}
	for i := 0; i < f.Theta; i++ {
		if a.Limb[i]%f.Q != b.Limb[i]%f.Q {
			return false
		}
	}
	return true
}

// CanonicalBytes is the unique manifest/transcript encoding of the profile.
func (p SmallWoodFieldProfile) CanonicalBytes() []byte {
	out := make([]byte, 0, 64+8*(len(p.Chi)+len(p.OmegaExtra)))
	appendU64 := func(v uint64) {
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], v)
		out = append(out, buf[:]...)
	}
	appendU64(uint64(p.Version))
	appendU64(uint64(len(p.ID)))
	out = append(out, p.ID...)
	appendU64(p.Q)
	appendU64(uint64(p.Theta))
	appendU64(uint64(len(p.Chi)))
	for _, v := range p.Chi {
		appendU64(v)
	}
	appendU64(uint64(len(p.OmegaExtra)))
	for _, v := range p.OmegaExtra {
		appendU64(v)
	}
	return out
}

// DigestHex returns a domain-separated SHAKE-256 digest of CanonicalBytes.
func (p SmallWoodFieldProfile) DigestHex(outLen int) (string, error) {
	if outLen <= 0 {
		return "", fmt.Errorf("kfield: invalid profile digest width %d", outLen)
	}
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("SPRUCE/SmallWood/field-profile/v3"))
	_, _ = h.Write(p.CanonicalBytes())
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return hex.EncodeToString(out), nil
}
