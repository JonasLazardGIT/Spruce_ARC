package decs

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"

	"golang.org/x/crypto/sha3"
)

const merkleParallelLevelThreshold = 4096

// MerkleTree is a full binary Merkle tree of SHAKE-256 truncated hashes.
type MerkleTree struct {
	layers    [][][]byte
	hashBytes int
}

// BuildMerkleTreeFromLeafHashBytesV2 builds the canonical v2 tree. Leaf
// hashes must already be canonical HashLeafV2 outputs. Padding and every
// internal node are separately domain-separated and bind the commitment
// context, full uint64 position, and tree level.
func BuildMerkleTreeFromLeafHashBytesV2(ctx CommitmentContext, leaves [][]byte, hashBytes int) (*MerkleTree, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("decs: cannot build v2 Merkle tree with no leaves")
	}
	if !IsSupportedHashBytes(hashBytes) {
		return nil, fmt.Errorf("decs: invalid v2 Merkle hash width %d", hashBytes)
	}
	size := 1
	for size < len(leaves) {
		if size > int(^uint(0)>>1)/2 {
			return nil, fmt.Errorf("decs: v2 Merkle leaf count overflows tree size")
		}
		size <<= 1
	}
	layer := make([][]byte, size)
	for i := range leaves {
		if len(leaves[i]) != hashBytes {
			return nil, fmt.Errorf("decs: v2 leaf hash[%d] width=%d want=%d", i, len(leaves[i]), hashBytes)
		}
		layer[i] = append([]byte(nil), leaves[i]...)
	}
	h := sha3.NewShake256()
	for i := len(leaves); i < size; i++ {
		layer[i] = hashPaddingV2With(h, ctx, uint64(i), hashBytes)
	}
	layers := [][][]byte{layer}

	for level, sz := uint64(1), size; sz > 1; level, sz = level+1, sz>>1 {
		prev := layers[len(layers)-1]
		pairs := sz / 2
		next := make([][]byte, pairs)
		workers := runtime.GOMAXPROCS(0)
		if pairs < merkleParallelLevelThreshold || workers < 2 {
			for pair := 0; pair < pairs; pair++ {
				next[pair] = hashNodeV2With(h, ctx, level, uint64(pair), prev[2*pair], prev[2*pair+1], hashBytes)
			}
		} else {
			if workers > pairs {
				workers = pairs
			}
			var wg sync.WaitGroup
			wg.Add(workers)
			for worker := 0; worker < workers; worker++ {
				start := worker * pairs / workers
				end := (worker + 1) * pairs / workers
				go func(start, end int) {
					defer wg.Done()
					hw := sha3.NewShake256()
					for pair := start; pair < end; pair++ {
						next[pair] = hashNodeV2With(hw, ctx, level, uint64(pair), prev[2*pair], prev[2*pair+1], hashBytes)
					}
				}(start, end)
			}
			wg.Wait()
		}
		layers = append(layers, next)
	}
	return &MerkleTree{layers: layers, hashBytes: hashBytes}, nil
}

// RootHash returns the full Merkle root hash.
func (mt *MerkleTree) RootHash() []byte {
	if mt == nil || len(mt.layers) == 0 {
		return nil
	}
	return append([]byte(nil), mt.layers[len(mt.layers)-1][0]...)
}

// VerifyPathHashV2 checks a path from an already canonical v2 leaf hash to a
// full-width root. It never truncates or normalizes hashes and has no legacy
// root fallback.
func VerifyPathHashV2(ctx CommitmentContext, leafHash []byte, path [][]byte, root []byte, idx uint64) bool {
	if err := ctx.Validate(); err != nil || !IsSupportedHashBytes(len(root)) {
		return false
	}
	hashBytes := len(root)
	if len(leafHash) != hashBytes {
		return false
	}
	h := append([]byte(nil), leafHash...)
	shake := sha3.NewShake256()
	for level, sibling := range path {
		if len(sibling) != hashBytes {
			return false
		}
		parent := idx >> 1
		if idx&1 == 0 {
			h = hashNodeV2With(shake, ctx, uint64(level+1), parent, h, sibling, hashBytes)
		} else {
			h = hashNodeV2With(shake, ctx, uint64(level+1), parent, sibling, h, hashBytes)
		}
		idx = parent
	}
	return idx == 0 && bytes.Equal(h, root)
}
