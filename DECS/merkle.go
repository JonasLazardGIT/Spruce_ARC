package decs

import (
	"bytes"
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

// MerkleTree is a full binary Merkle tree of 16-byte hashes (SHAKE-256 truncated).
type MerkleTree struct {
	layers [][][16]byte
}

// BuildMerkleTree builds a balanced tree from leaves.
func BuildMerkleTree(leaves [][]byte) *MerkleTree {
	n := len(leaves)
	leafHashes := make([][16]byte, n)
	h := sha3.NewShake256()
	for i := 0; i < n; i++ {
		hashLeafIntoWith(h, leaves[i], &leafHashes[i])
	}
	return BuildMerkleTreeFromLeafHashes(leafHashes)
}

func BuildMerkleTreeFromLeafHashes(leaves [][16]byte) *MerkleTree {
	n := len(leaves)
	size := 1
	for size < n {
		size <<= 1
	}
	layer := make([][16]byte, size)
	copy(layer, leaves)
	h := sha3.NewShake256()
	emptyLeaf := hashLeafWith(h, nil)
	for i := n; i < size; i++ {
		layer[i] = emptyLeaf
	}
	layers := [][][16]byte{layer}

	for sz := size; sz > 1; sz >>= 1 {
		prev := layers[len(layers)-1]
		next := make([][16]byte, sz/2)
		for i := 0; i < sz; i += 2 {
			hashNodeIntoWith(h, &prev[i], &prev[i+1], &next[i/2])
		}
		layers = append(layers, next)
	}

	return &MerkleTree{layers: layers}
}

// Root returns the root hash.
func (mt *MerkleTree) Root() [16]byte {
	return mt.layers[len(mt.layers)-1][0]
}

// VerifyPath checks leaf→root via path.
func VerifyPath(leaf []byte, path [][]byte, root [16]byte, idx int) bool {
	shake := sha3.NewShake256()
	h := hashLeafWith(shake, leaf)
	for _, sib := range path {
		var sibHash [16]byte
		copy(sibHash[:], sib)
		if idx&1 == 0 {
			h = hashNodeWith(shake, h, sibHash)
		} else {
			h = hashNodeWith(shake, sibHash, h)
		}
		idx >>= 1
	}
	return bytes.Equal(h[:], root[:])
}

func hashLeafWith(h sha3.ShakeHash, leaf []byte) [16]byte {
	var out [16]byte
	hashLeafIntoWith(h, leaf, &out)
	return out
}

func hashLeafIntoWith(h sha3.ShakeHash, leaf []byte, out *[16]byte) {
	h.Reset()
	_, _ = h.Write(leafPrefixBytes[:])
	_, _ = h.Write(leaf)
	_, _ = h.Read(out[:])
}

func hashNodeWith(h sha3.ShakeHash, left, right [16]byte) [16]byte {
	var out [16]byte
	hashNodeIntoWith(h, &left, &right, &out)
	return out
}

func hashNodeIntoWith(h sha3.ShakeHash, left, right *[16]byte, out *[16]byte) {
	h.Reset()
	_, _ = h.Write(nodePrefixBytes[:])
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	_, _ = h.Read(out[:])
}

func shake16(data []byte) [16]byte {
	var out [16]byte
	h := sha3.NewShake256()
	_, _ = h.Write(data)
	_, _ = h.Read(out[:])
	return out
}
