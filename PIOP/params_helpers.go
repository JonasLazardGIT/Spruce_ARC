package PIOP

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

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

// Retained flows refer to tracked assets by repo-root-relative paths. Tests may
// execute from package directories, so resolve searches upward when needed.
func resolve(rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	if _, err := os.Stat(rel); err == nil {
		return rel
	}
	wd, err := os.Getwd()
	if err != nil {
		return rel
	}
	for dir := wd; dir != ""; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
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

const (
	stableBBTranWitnessNLeaves = 4096
	stableBBTranWitnessEll     = 18
)

func resolveSimRingDegree(requested int, defaultN int) (int, error) {
	if defaultN <= 0 {
		return 0, fmt.Errorf("invalid default ring degree %d", defaultN)
	}
	switch requested {
	case 0:
		return defaultN, nil
	case defaultN:
		return defaultN, nil
	case 1024:
		return 1024, nil
	case 512:
		return 512, nil
	default:
		return 0, fmt.Errorf("unsupported ring degree %d (supported: %d, 1024, 512)", requested, defaultN)
	}
}

func loadParamsRingForOpts(opts SimOpts) (*ring.Ring, error) {
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		return nil, fmt.Errorf("load params: %w", err)
	}
	n, err := resolveSimRingDegree(opts.RingDegree, par.N)
	if err != nil {
		return nil, err
	}
	ringQ, err := ring.NewRing(n, []uint64{par.Q})
	if err != nil {
		return nil, fmt.Errorf("ring.NewRing: %w", err)
	}
	return ringQ, nil
}

func validateProofRingDegree(proof *Proof, ringDegree int) error {
	if proof == nil || ringDegree <= 0 {
		return nil
	}
	if proof.RingDegree > 0 && proof.RingDegree != ringDegree {
		return fmt.Errorf("proof ring_degree=%d does not match verifier ring degree %d", proof.RingDegree, ringDegree)
	}
	if proof.RowLayout.RingDegree > 0 && proof.RowLayout.RingDegree != ringDegree {
		return fmt.Errorf("row layout ring_degree=%d does not match verifier ring degree %d", proof.RowLayout.RingDegree, ringDegree)
	}
	if proof.SigShortness != nil && proof.SigShortness.V18 != nil {
		if proof.SigShortness.V18.RingDegree > 0 && proof.SigShortness.V18.RingDegree != ringDegree {
			return fmt.Errorf("sig shortness V18 ring_degree=%d does not match verifier ring degree %d", proof.SigShortness.V18.RingDegree, ringDegree)
		}
	}
	return nil
}

func resolvedProofRingDegree(proof *Proof, fallback int) int {
	if proof != nil {
		if proof.RingDegree > 0 {
			return proof.RingDegree
		}
		if proof.RowLayout.RingDegree > 0 {
			return proof.RowLayout.RingDegree
		}
		if proof.SigShortness != nil && proof.SigShortness.V18 != nil && proof.SigShortness.V18.RingDegree > 0 {
			return proof.SigShortness.V18.RingDegree
		}
		if n := resolveRowLayoutRingDegree(proof.RowLayout); n > 0 {
			return n
		}
	}
	return fallback
}

func deriveStableWitnessOmega(q uint64, witnessNCols, _ int, relation string) ([]uint64, error) {
	if !relationUsesBBTran(relation) {
		return nil, fmt.Errorf("stable witness omega only supports bb_tran, got %q", relation)
	}
	omegaWitness, _, err := deriveExplicitDomain(q, stableBBTranWitnessNLeaves, witnessNCols, stableBBTranWitnessEll)
	if err != nil {
		return nil, err
	}
	if len(omegaWitness) < witnessNCols {
		return nil, fmt.Errorf("derived stable witness omega len=%d < witness ncols=%d", len(omegaWitness), witnessNCols)
	}
	return append([]uint64(nil), omegaWitness[:witnessNCols]...), nil
}

func deriveRelationWitnessOmega(q uint64, nLeaves, witnessNCols, lvcsNCols, ell int, relation string) ([]uint64, error) {
	if relationUsesBBTran(relation) {
		omegaWitness, err := deriveStableWitnessOmega(q, witnessNCols, ell, relation)
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

func DeriveRelationWitnessOmega(q uint64, nLeaves, witnessNCols, lvcsNCols, ell int, relation string) ([]uint64, error) {
	return deriveRelationWitnessOmega(q, nLeaves, witnessNCols, lvcsNCols, ell, relation)
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
	// Keep the full witness+mask prefix stable across NLeaves. Varying NLeaves
	// should only extend the tail of E, not change the witness embedding.
	_, _ = xof.Write([]byte("SmallWood:E:bb_tran:prefix:v2"))
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], q)
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

func DeriveExplicitDomainForRelation(q uint64, nLeaves, witnessNCols, lvcsNCols, ell int, relation string) ([]uint64, []uint64, error) {
	return deriveExplicitDomainForRelation(q, nLeaves, witnessNCols, lvcsNCols, ell, relation)
}

func loadParamsAndOmegaForRelation(opts SimOpts, relation string) (*ring.Ring, []uint64, int, error) {
	opts.applyDefaults()
	ringQ, err := loadParamsRingForOpts(opts)
	if err != nil {
		return nil, nil, 0, err
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
	ringQ, err := loadParamsRingForOpts(opts)
	if err != nil {
		return nil, nil, 0, err
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
