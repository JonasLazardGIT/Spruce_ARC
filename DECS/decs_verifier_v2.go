package decs

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// VerifyEvalFormalHashV2 verifies a canonical v2 opening against the full
// Merkle root. It requires selective tapes and canonical field residues before
// hashing.
func (v *Verifier) VerifyEvalFormalHashV2(rootHash []byte, gamma [][]uint64, rRows [][]uint64, open *DECSOpening) bool {
	return v.verifyEvalFormalHashV2(rootHash, gamma, rRows, open) == nil
}

func (v *Verifier) verifyEvalFormalHashV2(rootHash []byte, gamma [][]uint64, rRows [][]uint64, open *DECSOpening) error {
	if v == nil {
		return fmt.Errorf("decs: v2 verifier context is not configured")
	}
	if err := v.context.Validate(); err != nil {
		return err
	}
	if len(rootHash) != v.params.HashBytes {
		return fmt.Errorf("decs: v2 root width=%d want=%d", len(rootHash), v.params.HashBytes)
	}
	tapeBytes, err := v2TapeBytes(v.params)
	if err != nil {
		return err
	}
	if err := validateOpeningV2(v.context, open, tapeBytes); err != nil {
		return err
	}
	if open.R != v.r || open.Eta != v.params.Eta {
		return fmt.Errorf("decs: v2 opening dimensions R=%d Eta=%d want R=%d Eta=%d", open.R, open.Eta, v.r, v.params.Eta)
	}
	if openingPRequiresReconstruction(open) {
		if len(open.Pvals) != open.EntryCount() {
			return fmt.Errorf("decs: v2 compressed P values were not reconstructed")
		}
		for i := range open.Pvals {
			if len(open.Pvals[i]) != v.r {
				return fmt.Errorf("decs: v2 reconstructed P row width mismatch")
			}
		}
	}
	if openingMRequiresReconstruction(open) {
		if len(open.Mvals) != open.EntryCount() {
			return fmt.Errorf("decs: v2 compressed M values were not reconstructed")
		}
		for i := range open.Mvals {
			if len(open.Mvals[i]) != v.params.Eta {
				return fmt.Errorf("decs: v2 reconstructed M row width mismatch")
			}
		}
	}
	n := open.EntryCount()
	if n == 0 {
		return fmt.Errorf("decs: empty v2 opening")
	}
	if len(open.Pvals) > 0 && len(open.Pvals) != n {
		return fmt.Errorf("decs: v2 P row count mismatch")
	}
	if len(open.Pvals) == 0 && openingPCols(open) < v.r {
		return fmt.Errorf("decs: v2 packed P column count mismatch")
	}
	if len(open.Mvals) > 0 && len(open.Mvals) != n {
		return fmt.Errorf("decs: v2 M row count mismatch")
	}
	if len(open.Mvals) == 0 && openingMCols(open) < v.params.Eta {
		return fmt.Errorf("decs: v2 packed M column count mismatch")
	}
	if len(gamma) != v.params.Eta || len(rRows) != v.params.Eta {
		return fmt.Errorf("decs: v2 gamma/R row count mismatch")
	}
	mod := v.ringQ.Modulus[0]
	for k := 0; k < v.params.Eta; k++ {
		if len(gamma[k]) != v.r {
			return fmt.Errorf("decs: v2 gamma row width mismatch")
		}
		for _, value := range gamma[k] {
			if value >= mod {
				return fmt.Errorf("decs: non-canonical v2 gamma value")
			}
		}
		for _, value := range rRows[k] {
			if value >= mod {
				return fmt.Errorf("decs: non-canonical v2 R coefficient")
			}
		}
	}

	seen := make(map[int]struct{}, n)
	for t := 0; t < n; t++ {
		idx := open.IndexAt(t)
		if idx < 0 || idx >= v.nLeaves {
			return fmt.Errorf("decs: v2 index %d outside domain", idx)
		}
		if _, duplicate := seen[idx]; duplicate {
			return fmt.Errorf("decs: duplicate v2 opening index %d", idx)
		}
		seen[idx] = struct{}{}
		if len(open.Pvals) > 0 && len(open.Pvals[t]) != v.r {
			return fmt.Errorf("decs: v2 P row width mismatch")
		}
		if len(open.Mvals) > 0 && len(open.Mvals[t]) != v.params.Eta {
			return fmt.Errorf("decs: v2 M row width mismatch")
		}
		pvals := make([]uint64, v.r)
		for j := 0; j < v.r; j++ {
			pvals[j] = getPval(open, t, j)
			if pvals[j] >= mod {
				return fmt.Errorf("decs: non-canonical v2 P value")
			}
		}
		mvals := make([]uint64, v.params.Eta)
		for k := 0; k < v.params.Eta; k++ {
			mvals[k] = getMval(open, t, k)
			if mvals[k] >= mod {
				return fmt.Errorf("decs: non-canonical v2 M value")
			}
		}
		leafHash, err := HashLeafV2(v.context, uint64(idx), v.points[idx], mod, pvals, mvals, open.Tapes[t], v.params.HashBytes)
		if err != nil {
			return err
		}
		ids, ok := pathRowIndices(open, t)
		if !ok {
			return fmt.Errorf("decs: malformed v2 authentication path")
		}
		if len(ids) != merkleDepthV2(v.nLeaves) {
			return fmt.Errorf("decs: v2 authentication depth=%d want=%d", len(ids), merkleDepthV2(v.nLeaves))
		}
		path := make([][]byte, len(ids))
		for level, id := range ids {
			if id < 0 || id >= len(open.Nodes) {
				return fmt.Errorf("decs: v2 authentication node index out of range")
			}
			if len(open.Nodes[id]) != v.params.HashBytes {
				return fmt.Errorf("decs: v2 authentication node width mismatch")
			}
			path[level] = open.Nodes[id]
		}
		if !VerifyPathHashV2(v.context, leafHash, path, rootHash, uint64(idx)) {
			return fmt.Errorf("decs: v2 Merkle path rejected")
		}
		x := v.points[idx] % mod
		for k := 0; k < v.params.Eta; k++ {
			lhs := evalPoly(rRows[k], x, mod)
			rhs := mvals[k]
			for j := 0; j < v.r; j++ {
				rhs = addMod64(rhs, mulMod64(pvals[j], gamma[k][j], mod), mod)
			}
			if lhs != rhs {
				return fmt.Errorf("decs: v2 low-degree relation rejected")
			}
		}
	}
	return nil
}

func (v *Verifier) VerifyEvalAtFormalHashV2(rootHash []byte, gamma [][]uint64, rRows [][]uint64, open *DECSOpening, indices []int) bool {
	if v == nil {
		return false
	}
	if !sameDistinctOpeningIndicesV2(open, indices, v.nLeaves) {
		return false
	}
	return v.VerifyEvalFormalHashV2(rootHash, gamma, rRows, open)
}

func merkleDepthV2(nLeaves int) int {
	depth := 0
	for size := 1; size < nLeaves; size <<= 1 {
		depth++
	}
	return depth
}

func (v *Verifier) VerifyEvalAtHashV2(rootHash []byte, gamma [][]uint64, rRows []*ring.Poly, open *DECSOpening, indices []int) bool {
	if v == nil {
		return false
	}
	return v.VerifyEvalAtFormalHashV2(rootHash, gamma, ringRowsToFormal(rRows, v.ringQ.Modulus[0]), open, indices)
}

func sameDistinctOpeningIndicesV2(open *DECSOpening, expected []int, nLeaves int) bool {
	if open == nil || open.EntryCount() != len(expected) || len(expected) == 0 {
		return false
	}
	previous := -1
	for _, idx := range expected {
		if idx < 0 || idx >= nLeaves {
			return false
		}
		if idx <= previous {
			return false
		}
		previous = idx
	}
	for i, idx := range open.AllIndices() {
		if idx != expected[i] {
			return false
		}
	}
	return true
}
