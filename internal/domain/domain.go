package domain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"

	"golang.org/x/crypto/sha3"
)

// Domain describes the explicit evaluation domain and its Ω / Ω' split.
type Domain struct {
	Q uint64

	// E is the full evaluation domain, indexed by Merkle leaf index.
	E []uint64

	// Omega is the witness support (|Omega| == s).
	Omega []uint64

	// OmegaPrime is the mask support (|OmegaPrime| == ell).
	OmegaPrime []uint64

	// Tail is E \\ (Omega ∪ OmegaPrime), i.e. E[TailStart:].
	Tail []uint64

	// TailStart == len(Omega)+len(OmegaPrime).
	TailStart int

	// NLeaves == len(E).
	NLeaves int
}

// NewDomain samples an explicit evaluation domain and partitions it as
// (Omega, OmegaPrime, Tail).
func NewDomain(q uint64, nLeaves, s, ell int, seed []byte) (Domain, error) {
	if q == 0 {
		return Domain{}, errors.New("q must be > 0")
	}
	if nLeaves <= 0 {
		return Domain{}, fmt.Errorf("nLeaves must be > 0 (got %d)", nLeaves)
	}
	if s <= 0 {
		return Domain{}, fmt.Errorf("s must be > 0 (got %d)", s)
	}
	if ell < 0 {
		return Domain{}, fmt.Errorf("ell must be >= 0 (got %d)", ell)
	}
	if s+ell >= nLeaves {
		return Domain{}, fmt.Errorf("need s+ell < nLeaves (got s=%d, ell=%d, nLeaves=%d)", s, ell, nLeaves)
	}
	if uint64(nLeaves) >= q {
		return Domain{}, fmt.Errorf("need nLeaves < q to sample distinct points (got nLeaves=%d, q=%d)", nLeaves, q)
	}

	xof := sha3.NewShake256()
	_, _ = xof.Write([]byte("SmallWood:E"))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], q)
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(nLeaves))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(s))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(ell))
	_, _ = xof.Write(buf[:])
	if len(seed) > 0 {
		_, _ = xof.Write(seed)
	}

	E := make([]uint64, 0, nLeaves)
	seen := make(map[uint64]struct{}, nLeaves)
	for len(E) < nLeaves {
		v, err := sampleUniformMod(xof, q)
		if err != nil {
			return Domain{}, err
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		E = append(E, v)
	}

	d := Domain{
		Q:          q,
		E:          E,
		Omega:      E[:s],
		OmegaPrime: E[s : s+ell],
		Tail:       E[s+ell:],
		TailStart:  s + ell,
		NLeaves:    nLeaves,
	}
	return d, d.Validate()
}

// NewDomainWithPrefix fixes the first s+ell points before sampling the rest of E.
func NewDomainWithPrefix(q uint64, nLeaves, s, ell int, prefix []uint64, seed []byte) (Domain, error) {
	if q == 0 {
		return Domain{}, errors.New("q must be > 0")
	}
	if nLeaves <= 0 {
		return Domain{}, fmt.Errorf("nLeaves must be > 0 (got %d)", nLeaves)
	}
	if s <= 0 {
		return Domain{}, fmt.Errorf("s must be > 0 (got %d)", s)
	}
	if ell < 0 {
		return Domain{}, fmt.Errorf("ell must be >= 0 (got %d)", ell)
	}
	if s+ell >= nLeaves {
		return Domain{}, fmt.Errorf("need s+ell < nLeaves (got s=%d, ell=%d, nLeaves=%d)", s, ell, nLeaves)
	}
	if uint64(nLeaves) >= q {
		return Domain{}, fmt.Errorf("need nLeaves < q to sample distinct points (got nLeaves=%d, q=%d)", nLeaves, q)
	}
	if len(prefix) != s+ell {
		return Domain{}, fmt.Errorf("prefix length must equal s+ell (got %d, want %d)", len(prefix), s+ell)
	}

	E := make([]uint64, 0, nLeaves)
	seen := make(map[uint64]struct{}, nLeaves)
	for i, v := range prefix {
		v %= q
		if _, ok := seen[v]; ok {
			return Domain{}, fmt.Errorf("prefix has duplicate element %d (at index %d)", v, i)
		}
		seen[v] = struct{}{}
		E = append(E, v)
	}

	xof := sha3.NewShake256()
	_, _ = xof.Write([]byte("SmallWood:E:prefixed"))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], q)
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(nLeaves))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(s))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(ell))
	_, _ = xof.Write(buf[:])
	for _, v := range prefix {
		binary.LittleEndian.PutUint64(buf[:], v%q)
		_, _ = xof.Write(buf[:])
	}
	if len(seed) > 0 {
		_, _ = xof.Write(seed)
	}

	for len(E) < nLeaves {
		v, err := sampleUniformMod(xof, q)
		if err != nil {
			return Domain{}, err
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		E = append(E, v)
	}

	d := Domain{
		Q:          q,
		E:          E,
		Omega:      E[:s],
		OmegaPrime: E[s : s+ell],
		Tail:       E[s+ell:],
		TailStart:  s + ell,
		NLeaves:    nLeaves,
	}
	return d, d.Validate()
}

func sampleUniformMod(xof sha3.ShakeHash, q uint64) (uint64, error) {
	if q == 0 {
		return 0, errors.New("q must be > 0")
	}
	max := ^uint64(0)
	limit := max - (max % q)
	var buf [8]byte
	for {
		if _, err := xof.Read(buf[:]); err != nil {
			return 0, err
		}
		x := binary.LittleEndian.Uint64(buf[:])
		if x < limit {
			return x % q, nil
		}
	}
}

func (d Domain) Validate() error {
	if d.Q == 0 {
		return errors.New("domain.Q must be > 0")
	}
	if d.NLeaves <= 0 {
		return fmt.Errorf("domain.NLeaves must be > 0 (got %d)", d.NLeaves)
	}
	if len(d.E) != d.NLeaves {
		return fmt.Errorf("domain.E length mismatch: len(E)=%d, NLeaves=%d", len(d.E), d.NLeaves)
	}
	if d.TailStart != len(d.Omega)+len(d.OmegaPrime) {
		return fmt.Errorf("domain.TailStart mismatch: TailStart=%d, len(Omega)+len(OmegaPrime)=%d", d.TailStart, len(d.Omega)+len(d.OmegaPrime))
	}
	if d.TailStart > len(d.E) {
		return fmt.Errorf("domain.TailStart out of range: TailStart=%d, len(E)=%d", d.TailStart, len(d.E))
	}

	seen := make(map[uint64]struct{}, len(d.E))
	for i, v := range d.E {
		if v >= d.Q {
			return fmt.Errorf("domain.E[%d]=%d out of field range (q=%d)", i, v, d.Q)
		}
		if _, ok := seen[v]; ok {
			return fmt.Errorf("domain.E has duplicate element %d", v)
		}
		seen[v] = struct{}{}
	}

	// Ensure (Omega, OmegaPrime, Tail) are a partition of E (by value equality).
	if len(d.Omega) == 0 {
		return errors.New("|Omega| must be > 0")
	}
	if got := append(append(append([]uint64{}, d.Omega...), d.OmegaPrime...), d.Tail...); len(got) != len(d.E) {
		return errors.New("domain partition does not cover E")
	} else {
		for i := range got {
			if got[i] != d.E[i] {
				return errors.New("domain partition is not aligned with E ordering")
			}
		}
	}
	return nil
}

func (d Domain) PointAtIndex(i int) (uint64, error) {
	if i < 0 || i >= len(d.E) {
		return 0, fmt.Errorf("index %d out of range (len(E)=%d)", i, len(d.E))
	}
	return d.E[i], nil
}

// SampleTailIndices returns distinct indices in [TailStart, NLeaves).
func (d Domain) SampleTailIndices(count int, rng *rand.Rand) ([]int, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if count < 0 {
		return nil, fmt.Errorf("count must be >= 0 (got %d)", count)
	}
	if rng == nil {
		return nil, errors.New("rng must be non-nil")
	}
	tailLen := d.NLeaves - d.TailStart
	if count > tailLen {
		return nil, fmt.Errorf("count=%d exceeds tail length %d", count, tailLen)
	}
	if count == 0 {
		return nil, nil
	}

	perm := rng.Perm(tailLen)
	out := make([]int, count)
	for i := 0; i < count; i++ {
		out[i] = d.TailStart + perm[i]
	}
	return out, nil
}
