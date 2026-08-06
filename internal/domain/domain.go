package domain

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const maxDistinctBitsetBytes = 8 << 20

// Binding is the public structural identity of an explicit evaluation domain.
// It deliberately contains no seed or mutable point storage.
type Binding struct {
	Q         uint64
	NLeaves   int
	OmegaSize int
	Ell       int
}

// Validate checks the structural requirements shared by sampled and imported
// explicit domains.
func (b Binding) Validate() error {
	if b.Q == 0 {
		return errors.New("q must be > 0")
	}
	if b.NLeaves <= 0 {
		return fmt.Errorf("nLeaves must be > 0 (got %d)", b.NLeaves)
	}
	if b.OmegaSize <= 0 {
		return fmt.Errorf("s must be > 0 (got %d)", b.OmegaSize)
	}
	if b.Ell < 0 {
		return fmt.Errorf("ell must be >= 0 (got %d)", b.Ell)
	}
	if b.Ell >= b.NLeaves || b.OmegaSize >= b.NLeaves-b.Ell {
		return fmt.Errorf("need s+ell < nLeaves (got s=%d, ell=%d, nLeaves=%d)", b.OmegaSize, b.Ell, b.NLeaves)
	}
	if uint64(b.NLeaves) >= b.Q {
		return fmt.Errorf("need nLeaves < q to sample distinct points (got nLeaves=%d, q=%d)", b.NLeaves, b.Q)
	}
	return nil
}

// Prepared is an immutable, validated explicit evaluation domain. Its backing
// point slice is never returned to callers; consumers may index it or request
// an owned copy. This makes validation reusable across protocol layers without
// trusting caller-owned mutable slices.
type Prepared struct {
	binding Binding
	points  []uint64
}

// NewPrepared validates and copies an existing ordered explicit domain.
func NewPrepared(binding Binding, points []uint64) (*Prepared, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	if len(points) != binding.NLeaves {
		return nil, fmt.Errorf("domain points length mismatch: got %d want %d", len(points), binding.NLeaves)
	}
	owned := append([]uint64(nil), points...)
	if err := validateOrderedPoints(owned, binding.Q, "domain points"); err != nil {
		return nil, err
	}
	return &Prepared{binding: binding, points: owned}, nil
}

// SamplePrepared samples an explicit domain with exactly the legacy
// NewDomain transcript and point-consumption order.
func SamplePrepared(binding Binding, seed []byte) (*Prepared, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	xof := sha3.NewShake256()
	_, _ = xof.Write([]byte("SmallWood:E"))
	writeSamplingParameters(xof, binding)
	if len(seed) > 0 {
		_, _ = xof.Write(seed)
	}
	points, err := sampleDistinctSuffix(xof, binding.Q, binding.NLeaves, nil)
	if err != nil {
		return nil, err
	}
	return &Prepared{binding: binding, points: points}, nil
}

// SamplePreparedWithPrefix fixes the first OmegaSize+Ell points before
// sampling the rest with exactly the legacy NewDomainWithPrefix transcript.
func SamplePreparedWithPrefix(binding Binding, prefix []uint64, seed []byte) (*Prepared, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	wantPrefix := binding.OmegaSize + binding.Ell
	if len(prefix) != wantPrefix {
		return nil, fmt.Errorf("prefix length must equal s+ell (got %d, want %d)", len(prefix), wantPrefix)
	}
	normalized := make([]uint64, len(prefix))
	set := newDistinctSet(binding.Q, binding.NLeaves)
	for i, value := range prefix {
		value %= binding.Q
		if !set.add(value) {
			return nil, fmt.Errorf("prefix has duplicate element %d (at index %d)", value, i)
		}
		normalized[i] = value
	}

	xof := sha3.NewShake256()
	_, _ = xof.Write([]byte("SmallWood:E:prefixed"))
	writeSamplingParameters(xof, binding)
	var buf [8]byte
	for _, value := range normalized {
		binary.LittleEndian.PutUint64(buf[:], value)
		_, _ = xof.Write(buf[:])
	}
	if len(seed) > 0 {
		_, _ = xof.Write(seed)
	}

	points := make([]uint64, 0, binding.NLeaves)
	points = append(points, normalized...)
	for len(points) < binding.NLeaves {
		value, err := sampleUniformMod(xof, binding.Q)
		if err != nil {
			return nil, err
		}
		if !set.add(value) {
			continue
		}
		points = append(points, value)
	}
	return &Prepared{binding: binding, points: points}, nil
}

// Binding returns the immutable domain's structural binding by value.
func (p *Prepared) Binding() Binding {
	if p == nil {
		return Binding{}
	}
	return p.binding
}

// Len returns the number of ordered evaluation points.
func (p *Prepared) Len() int {
	if p == nil {
		return 0
	}
	return len(p.points)
}

// At returns the point at index i. It panics on an invalid index in the same
// way as direct slice indexing.
func (p *Prepared) At(i int) uint64 { return p.points[i] }

// CopyPoints returns an independently owned copy of the complete domain.
func (p *Prepared) CopyPoints() []uint64 {
	if p == nil {
		return nil
	}
	return append([]uint64(nil), p.points...)
}

// CopyRange returns an independently owned copy of [start,end).
func (p *Prepared) CopyRange(start, end int) []uint64 {
	if p == nil {
		return nil
	}
	return append([]uint64(nil), p.points[start:end]...)
}

// EqualBinding reports whether p has exactly the requested public structure.
func (p *Prepared) EqualBinding(binding Binding) bool {
	return p != nil && p.binding == binding
}

// ValidateBinding fails closed when a prepared domain is reused for a
// different public structure.
func (p *Prepared) ValidateBinding(binding Binding) error {
	if p == nil {
		return errors.New("nil prepared domain")
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	if p.binding != binding {
		return fmt.Errorf("prepared domain binding mismatch: got %+v want %+v", p.binding, binding)
	}
	return nil
}

// Domain returns the legacy mutable representation backed by a fresh copy.
func (p *Prepared) Domain() Domain {
	if p == nil {
		return Domain{}
	}
	return domainFromOwned(p.binding, p.CopyPoints())
}

// Domain describes the explicit evaluation domain and its Omega / Omega'
// split. It remains mutable for source compatibility; new internal paths
// should retain a Prepared value instead.
type Domain struct {
	Q          uint64
	E          []uint64
	Omega      []uint64
	OmegaPrime []uint64
	Tail       []uint64
	TailStart  int
	NLeaves    int
}

// NewDomain is the legacy mutable wrapper around SamplePrepared.
func NewDomain(q uint64, nLeaves, s, ell int, seed []byte) (Domain, error) {
	prepared, err := SamplePrepared(Binding{Q: q, NLeaves: nLeaves, OmegaSize: s, Ell: ell}, seed)
	if err != nil {
		return Domain{}, err
	}
	return prepared.Domain(), nil
}

// NewDomainWithPrefix is the legacy mutable wrapper around
// SamplePreparedWithPrefix.
func NewDomainWithPrefix(q uint64, nLeaves, s, ell int, prefix []uint64, seed []byte) (Domain, error) {
	prepared, err := SamplePreparedWithPrefix(Binding{Q: q, NLeaves: nLeaves, OmegaSize: s, Ell: ell}, prefix, seed)
	if err != nil {
		return Domain{}, err
	}
	return prepared.Domain(), nil
}

func domainFromOwned(binding Binding, points []uint64) Domain {
	tailStart := binding.OmegaSize + binding.Ell
	return Domain{
		Q: binding.Q, E: points,
		Omega:      points[:binding.OmegaSize],
		OmegaPrime: points[binding.OmegaSize:tailStart],
		Tail:       points[tailStart:], TailStart: tailStart,
		NLeaves: binding.NLeaves,
	}
}

func writeSamplingParameters(xof sha3.ShakeHash, binding Binding) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], binding.Q)
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(binding.NLeaves))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(binding.OmegaSize))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(binding.Ell))
	_, _ = xof.Write(buf[:])
}

func sampleDistinctSuffix(xof sha3.ShakeHash, q uint64, count int, prefix []uint64) ([]uint64, error) {
	points := make([]uint64, 0, count)
	set := newDistinctSet(q, count)
	for _, value := range prefix {
		if !set.add(value) {
			return nil, fmt.Errorf("duplicate prefix point %d", value)
		}
		points = append(points, value)
	}
	for len(points) < count {
		value, err := sampleUniformMod(xof, q)
		if err != nil {
			return nil, err
		}
		if !set.add(value) {
			continue
		}
		points = append(points, value)
	}
	return points, nil
}

type distinctSet interface{ add(uint64) bool }

type bitDistinctSet []byte

func (s bitDistinctSet) add(value uint64) bool {
	byteIndex := value >> 3
	mask := byte(1 << (value & 7))
	if s[byteIndex]&mask != 0 {
		return false
	}
	s[byteIndex] |= mask
	return true
}

type mapDistinctSet map[uint64]struct{}

func (s mapDistinctSet) add(value uint64) bool {
	if _, exists := s[value]; exists {
		return false
	}
	s[value] = struct{}{}
	return true
}

func newDistinctSet(q uint64, expected int) distinctSet {
	if q <= uint64(maxDistinctBitsetBytes)*8 {
		return make(bitDistinctSet, int((q+7)/8))
	}
	return make(mapDistinctSet, expected)
}

func validateOrderedPoints(points []uint64, q uint64, label string) error {
	set := newDistinctSet(q, len(points))
	for i, value := range points {
		if value >= q {
			return fmt.Errorf("%s[%d]=%d out of field range (q=%d)", label, i, value, q)
		}
		if !set.add(value) {
			return fmt.Errorf("%s has duplicate element %d", label, value)
		}
	}
	return nil
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
	binding := Binding{Q: d.Q, NLeaves: d.NLeaves, OmegaSize: len(d.Omega), Ell: len(d.OmegaPrime)}
	if err := binding.Validate(); err != nil {
		return fmt.Errorf("domain: %w", err)
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
	if err := validateOrderedPoints(d.E, d.Q, "domain.E"); err != nil {
		return err
	}
	if len(d.Omega)+len(d.OmegaPrime)+len(d.Tail) != len(d.E) {
		return errors.New("domain partition does not cover E")
	}
	offset := 0
	for _, part := range [][]uint64{d.Omega, d.OmegaPrime, d.Tail} {
		for i, value := range part {
			if value != d.E[offset+i] {
				return errors.New("domain partition is not aligned with E ordering")
			}
		}
		offset += len(part)
	}
	return nil
}
