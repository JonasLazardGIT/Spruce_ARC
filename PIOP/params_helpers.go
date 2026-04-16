package PIOP

import (
	"encoding/binary"
	"fmt"

	swDomain "vSIS-Signature/internal/domain"
	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
	"golang.org/x/crypto/sha3"
)

// DomainMode controls how the PCS/PIOP evaluation domain is derived.
// The retained protocol supports only explicit public-domain evaluation.
type DomainMode uint8

const (
	DomainModeExplicit DomainMode = iota
)

// Shipping mode is repo-root only, so retained flows resolve tracked assets
// directly from the repository root.
func resolve(rel string) string {
	return rel
}

// deriveExplicitDomain builds the public evaluation domain E={e_0,...,e_{N-1}}
// and returns:
//   - omega = Ω = E[:ncols]
//   - domainPoints = E
func deriveExplicitDomain(q uint64, nLeaves, ncols, ell int) (omega []uint64, domainPoints []uint64, err error) {
	if q == 0 {
		return nil, nil, fmt.Errorf("invalid modulus q=0")
	}
	if ncols <= 0 {
		return nil, nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	if ell < 0 {
		return nil, nil, fmt.Errorf("invalid ell %d", ell)
	}
	if nLeaves <= 0 {
		return nil, nil, fmt.Errorf("invalid nLeaves %d", nLeaves)
	}
	d, err := swDomain.NewDomain(q, nLeaves, ncols, ell, nil)
	if err != nil {
		return nil, nil, err
	}
	return append([]uint64(nil), d.Omega...), append([]uint64(nil), d.E...), nil
}

// deriveExplicitWitnessOmega returns the statement-facing witness Ω_s while
// allowing explicit-domain derivation to use a wider LVCS width.
func deriveExplicitWitnessOmega(q uint64, nLeaves, witnessNCols, lvcsNCols, ell int) ([]uint64, error) {
	if witnessNCols <= 0 {
		return nil, fmt.Errorf("invalid witness ncols %d", witnessNCols)
	}
	if lvcsNCols <= 0 {
		lvcsNCols = witnessNCols
	}
	if lvcsNCols < witnessNCols {
		return nil, fmt.Errorf("invalid lvcs ncols %d < witness ncols %d", lvcsNCols, witnessNCols)
	}
	omegaLVCS, _, err := deriveExplicitDomain(q, nLeaves, lvcsNCols, ell)
	if err != nil {
		return nil, err
	}
	if len(omegaLVCS) < witnessNCols {
		return nil, fmt.Errorf("derived lvcs omega len=%d < witness ncols=%d", len(omegaLVCS), witnessNCols)
	}
	return append([]uint64(nil), omegaLVCS[:witnessNCols]...), nil
}

func deriveRelationWitnessOmega(q uint64, nLeaves, witnessNCols, lvcsNCols, ell int, relation string) ([]uint64, error) {
	if relationUsesBBTran(relation) {
		omegaWitness, _, err := deriveExplicitDomain(q, nLeaves, witnessNCols, ell)
		if err != nil {
			return nil, err
		}
		if len(omegaWitness) < witnessNCols {
			return nil, fmt.Errorf("derived witness omega len=%d < witness ncols=%d", len(omegaWitness), witnessNCols)
		}
		return append([]uint64(nil), omegaWitness[:witnessNCols]...), nil
	}
	return deriveExplicitWitnessOmega(q, nLeaves, witnessNCols, lvcsNCols, ell)
}

func sampleUniformModDeterministic(xof sha3.ShakeHash, q uint64) (uint64, error) {
	if q == 0 {
		return 0, fmt.Errorf("q must be > 0")
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

func deriveExplicitDomainWithWitnessPrefix(q uint64, nLeaves, witnessNCols, lvcsNCols, ell int, witnessOmega []uint64) ([]uint64, []uint64, error) {
	if witnessNCols <= 0 {
		return nil, nil, fmt.Errorf("invalid witness ncols %d", witnessNCols)
	}
	if lvcsNCols <= 0 {
		lvcsNCols = witnessNCols
	}
	if lvcsNCols < witnessNCols {
		return nil, nil, fmt.Errorf("invalid lvcs ncols %d < witness ncols %d", lvcsNCols, witnessNCols)
	}
	if len(witnessOmega) != witnessNCols {
		return nil, nil, fmt.Errorf("witness omega len=%d want %d", len(witnessOmega), witnessNCols)
	}
	prefixLen := lvcsNCols + ell
	prefix := make([]uint64, 0, prefixLen)
	seen := make(map[uint64]struct{}, prefixLen)
	for i, v := range witnessOmega {
		v %= q
		if _, dup := seen[v]; dup {
			return nil, nil, fmt.Errorf("duplicate witness omega value %d at index %d", v, i)
		}
		seen[v] = struct{}{}
		prefix = append(prefix, v)
	}
	xof := sha3.NewShake256()
	_, _ = xof.Write([]byte("SmallWood:E:bb_tran:prefix"))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], q)
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(nLeaves))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(witnessNCols))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(lvcsNCols))
	_, _ = xof.Write(buf[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(ell))
	_, _ = xof.Write(buf[:])
	for _, v := range witnessOmega {
		binary.LittleEndian.PutUint64(buf[:], v%q)
		_, _ = xof.Write(buf[:])
	}
	for len(prefix) < prefixLen {
		v, err := sampleUniformModDeterministic(xof, q)
		if err != nil {
			return nil, nil, err
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		prefix = append(prefix, v)
	}
	dom, err := swDomain.NewDomainWithPrefix(q, nLeaves, lvcsNCols, ell, prefix, nil)
	if err != nil {
		return nil, nil, err
	}
	return append([]uint64(nil), dom.Omega...), append([]uint64(nil), dom.E...), nil
}

func deriveExplicitDomainForRelation(q uint64, nLeaves, witnessNCols, lvcsNCols, ell int, relation string) ([]uint64, []uint64, error) {
	if !relationUsesBBTran(relation) {
		return deriveExplicitDomain(q, nLeaves, lvcsNCols, ell)
	}
	witnessOmega, err := deriveRelationWitnessOmega(q, nLeaves, witnessNCols, lvcsNCols, ell, relation)
	if err != nil {
		return nil, nil, err
	}
	return deriveExplicitDomainWithWitnessPrefix(q, nLeaves, witnessNCols, lvcsNCols, ell, witnessOmega)
}

func loadParamsAndOmegaForRelation(opts SimOpts, relation string) (*ring.Ring, []uint64, int, error) {
	opts.applyDefaults()
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("load params: %w", err)
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ring.NewRing: %w", err)
	}
	q := ringQ.Modulus[0]
	sWitness := opts.NCols
	if sWitness <= 0 {
		sWitness = int(ringQ.N)
	}
	pcsNCols := resolvePCSNCols(opts, sWitness)
	ncols := pcsNCols
	if ncols <= 0 {
		ncols = sWitness
	}
	if ncols < sWitness {
		return nil, nil, 0, fmt.Errorf("invalid lvcs ncols=%d (must be >= witness ncols=%d)", ncols, sWitness)
	}
	if opts.DomainMode != DomainModeExplicit {
		return nil, nil, 0, fmt.Errorf("unsupported domain mode %d (only explicit mode is supported)", opts.DomainMode)
	}
	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	ell := opts.Ell
	if ell < 0 {
		ell = 0
	}
	if ncols+ell > int(ringQ.N) {
		return nil, nil, 0, fmt.Errorf("explicit domain: need lvcsNCols+ell <= ring dimension (lvcsNCols=%d, ell=%d, ringN=%d)", ncols, ell, ringQ.N)
	}
	omega, _, derr := deriveExplicitDomainForRelation(q, nLeaves, sWitness, ncols, ell, relation)
	if derr != nil {
		return nil, nil, 0, fmt.Errorf("explicit domain: %w", derr)
	}
	if err := checkOmega(omega, q); err != nil {
		return nil, nil, 0, fmt.Errorf("invalid omega: %w", err)
	}
	return ringQ, omega, ncols, nil
}

// loadParamsAndOmega loads Parameters.json, constructs the ring, and derives
// the explicit evaluation set Ω from the public domain E.
// It returns the ring, omega, and ncols=|Ω| used for LVCS/domain plumbing.
func loadParamsAndOmega(opts SimOpts) (*ring.Ring, []uint64, int, error) {
	opts.applyDefaults()
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("load params: %w", err)
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ring.NewRing: %w", err)
	}
	q := ringQ.Modulus[0]
	sWitness := opts.NCols
	if sWitness <= 0 {
		sWitness = int(ringQ.N)
	}
	pcsNCols := resolvePCSNCols(opts, sWitness)
	ncols := pcsNCols
	if ncols <= 0 {
		ncols = sWitness
	}
	if ncols < sWitness {
		return nil, nil, 0, fmt.Errorf("invalid lvcs ncols=%d (must be >= witness ncols=%d)", ncols, sWitness)
	}
	if opts.DomainMode != DomainModeExplicit {
		return nil, nil, 0, fmt.Errorf("unsupported domain mode %d (only explicit mode is supported)", opts.DomainMode)
	}
	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	ell := opts.Ell
	if ell < 0 {
		ell = 0
	}
	if ncols+ell > int(ringQ.N) {
		return nil, nil, 0, fmt.Errorf("explicit domain: need lvcsNCols+ell <= ring dimension (lvcsNCols=%d, ell=%d, ringN=%d)", ncols, ell, ringQ.N)
	}
	omega, _, derr := deriveExplicitDomain(q, nLeaves, ncols, ell)
	if derr != nil {
		return nil, nil, 0, fmt.Errorf("explicit domain: %w", derr)
	}
	if err := checkOmega(omega, q); err != nil {
		return nil, nil, 0, fmt.Errorf("invalid omega: %w", err)
	}
	return ringQ, omega, ncols, nil
}
