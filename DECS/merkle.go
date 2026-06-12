package decs

import (
	"bytes"
	"runtime"
	"sync"

	"golang.org/x/crypto/sha3"
)

const (
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

var (
	leafPrefixBytes = [1]byte{leafPrefix}
	nodePrefixBytes = [1]byte{nodePrefix}
)

const merkleParallelLevelThreshold = 4096

// MerkleTree is a full binary Merkle tree of SHAKE-256 truncated hashes.
type MerkleTree struct {
	layers    [][][]byte
	hashBytes int
}

func BuildMerkleTreeFromLeafHashBytes(leaves [][]byte, hashBytes int) *MerkleTree {
	hashBytes = NormalizeHashBytes(hashBytes)
	n := len(leaves)
	size := 1
	for size < n {
		size <<= 1
	}
	layer := make([][]byte, size)
	for i := 0; i < n; i++ {
		layer[i] = normalizeHashCopy(leaves[i], hashBytes)
	}
	h := sha3.NewShake256()
	emptyLeaf := hashLeafWith(h, nil, hashBytes)
	for i := n; i < size; i++ {
		layer[i] = append([]byte(nil), emptyLeaf...)
	}
	layers := [][][]byte{layer}

	for sz := size; sz > 1; sz >>= 1 {
		prev := layers[len(layers)-1]
		next := make([][]byte, sz/2)
		pairs := sz / 2
		workers := runtime.GOMAXPROCS(0)
		if pairs < merkleParallelLevelThreshold || workers < 2 {
			for i := 0; i < sz; i += 2 {
				next[i/2] = hashNodeWith(h, prev[i], prev[i+1], hashBytes)
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
						i := pair * 2
						next[pair] = hashNodeWith(hw, prev[i], prev[i+1], hashBytes)
					}
				}(start, end)
			}
			wg.Wait()
		}
		layers = append(layers, next)
	}

	return &MerkleTree{layers: layers, hashBytes: hashBytes}
}

// Root returns the root hash.
func (mt *MerkleTree) Root() [16]byte {
	var root [16]byte
	if mt == nil || len(mt.layers) == 0 {
		return root
	}
	copy(root[:], mt.layers[len(mt.layers)-1][0])
	return root
}

// RootHash returns the full Merkle root hash.
func (mt *MerkleTree) RootHash() []byte {
	if mt == nil || len(mt.layers) == 0 {
		return nil
	}
	return append([]byte(nil), mt.layers[len(mt.layers)-1][0]...)
}

// VerifyPathHash checks leaf→root via path using the supplied root hash width.
func VerifyPathHash(leaf []byte, path [][]byte, root []byte, idx int) bool {
	hashBytes := NormalizeHashBytes(len(root))
	shake := sha3.NewShake256()
	h := hashLeafWith(shake, leaf, hashBytes)
	for _, sib := range path {
		sibHash := normalizeHashCopy(sib, hashBytes)
		if idx&1 == 0 {
			h = hashNodeWith(shake, h, sibHash, hashBytes)
		} else {
			h = hashNodeWith(shake, sibHash, h, hashBytes)
		}
		idx >>= 1
	}
	return bytes.Equal(h, normalizeHashCopy(root, hashBytes))
}

func hashLeafWith(h sha3.ShakeHash, leaf []byte, hashBytes int) []byte {
	out := make([]byte, NormalizeHashBytes(hashBytes))
	hashLeafIntoWith(h, leaf, out)
	return out
}

func hashLeafIntoWith(h sha3.ShakeHash, leaf []byte, out []byte) {
	h.Reset()
	_, _ = h.Write(leafPrefixBytes[:])
	_, _ = h.Write(leaf)
	_, _ = h.Read(out)
}

func hashNodeWith(h sha3.ShakeHash, left, right []byte, hashBytes int) []byte {
	out := make([]byte, NormalizeHashBytes(hashBytes))
	hashNodeIntoWith(h, left, right, out)
	return out
}

func hashNodeIntoWith(h sha3.ShakeHash, left, right []byte, out []byte) {
	h.Reset()
	_, _ = h.Write(nodePrefixBytes[:])
	_, _ = h.Write(left)
	_, _ = h.Write(right)
	_, _ = h.Read(out)
}

func NormalizeHashBytes(hashBytes int) int {
	if IsSupportedHashBytes(hashBytes) {
		return hashBytes
	}
	return DefaultHashBytes
}

func normalizeHashCopy(in []byte, hashBytes int) []byte {
	hashBytes = NormalizeHashBytes(hashBytes)
	out := make([]byte, hashBytes)
	copy(out, in)
	return out
}
