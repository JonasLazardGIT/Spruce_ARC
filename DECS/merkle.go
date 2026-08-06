package decs

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

const merkleParallelLevelThreshold = 4096

const (
	// The exact-N domains deliberately differ from the former padded-tree v3
	// domains.  A schema-3 proof made with the padded topology therefore cannot
	// be reinterpreted as an exact-N proof, even when N is a power of two.
	merkleExactLeafDomainV3 = "SPRUCE/SmallWood/DECS/merkle/exact-n/leaf/v3"
	merkleExactNodeDomainV3 = "SPRUCE/SmallWood/DECS/merkle/exact-n/node/v3"
)

type merkleTreeTopology uint8

const (
	merkleTreePaddedV2 merkleTreeTopology = iota
	merkleTreeExactNV3
)

// MerkleTree is a binary Merkle tree of SHAKE-256 truncated hashes. Legacy v2
// contexts retain the complete padded topology. Strict v3 contexts use the
// exact-N largest-lower-power split defined in merkle_frontier_v3.go.
type MerkleTree struct {
	topology merkleTreeTopology
	layers   [][][]byte // legacy padded v2 only
	// exactHashes stores strict-v3 node hashes in canonical preorder. The
	// topology is implicit: for [start,end), left=node+1 and
	// right=node+2*(split-start), where split is exactMerkleSplitV3(start,end).
	// Keeping only the hash arena avoids retaining six machine words and one
	// slice header for every one of the 2*NLeaves-1 nodes.
	exactHashes []byte
	nLeaves     int
	hashBytes   int
}

type exactMerkleWorkV3 struct {
	node  int
	start int
	end   int
}

// exactMerkleBuilderV3 owns the final strict-v3 preorder hash arena and the
// only temporary topology aid: one uint32 node index per logical leaf.
type exactMerkleBuilderV3 struct {
	ctx         CommitmentContext
	nLeaves     int
	hashBytes   int
	nodeCount   int
	hashStorage []byte
	leafNodes   []uint32
}

func newExactMerkleBuilderV3(ctx CommitmentContext, nLeaves, hashBytes int, timings *exactMerklePhaseTimingsV3) (*exactMerkleBuilderV3, error) {
	if ctx.TranscriptVersion != TranscriptVersionV3 {
		return nil, fmt.Errorf("decs: exact-N Merkle topology requires transcript v3")
	}
	maxInt := int(^uint(0) >> 1)
	if nLeaves <= 0 || nLeaves > maxInt/2+1 {
		return nil, fmt.Errorf("decs: exact-N Merkle leaf count %d overflows node count", nLeaves)
	}
	nodeCount := 2*nLeaves - 1
	if uint64(nodeCount) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("decs: exact-N Merkle topology exceeds uint32 node map")
	}
	if hashBytes <= 0 || nodeCount > maxInt/hashBytes {
		return nil, fmt.Errorf("decs: exact-N Merkle hash storage overflows int")
	}
	storageStart := time.Time{}
	if timings != nil {
		storageStart = time.Now()
	}
	builder := &exactMerkleBuilderV3{
		ctx:         cloneCommitmentContext(ctx),
		nLeaves:     nLeaves,
		hashBytes:   hashBytes,
		nodeCount:   nodeCount,
		hashStorage: make([]byte, nodeCount*hashBytes),
		leafNodes:   make([]uint32, nLeaves),
	}
	for i := range builder.leafNodes {
		builder.leafNodes[i] = ^uint32(0)
	}
	visited := 0
	var buildLeafMap func(node, start, end int) error
	buildLeafMap = func(node, start, end int) error {
		if node < 0 || node >= nodeCount || start < 0 || start >= end || end > nLeaves {
			return fmt.Errorf("decs: invalid exact-N Merkle interval [%d,%d) at node %d", start, end, node)
		}
		visited++
		if end-start == 1 {
			builder.leafNodes[start] = uint32(node)
			return nil
		}
		split, err := exactMerkleSplitV3(start, end)
		if err != nil {
			return err
		}
		left := node + 1
		right := node + 2*(split-start)
		if err := buildLeafMap(left, start, split); err != nil {
			return err
		}
		return buildLeafMap(right, split, end)
	}
	if err := buildLeafMap(0, 0, nLeaves); err != nil {
		return nil, err
	}
	if visited != nodeCount {
		return nil, fmt.Errorf("decs: exact-N Merkle topology nodes=%d want=%d", visited, nodeCount)
	}
	if timings != nil {
		timings.storage = time.Since(storageStart)
	}
	return builder, nil
}

func (b *exactMerkleBuilderV3) hashAt(node int) []byte {
	return b.hashStorage[node*b.hashBytes : (node+1)*b.hashBytes]
}

func (b *exactMerkleBuilderV3) leafHashAt(index int) []byte {
	node := int(b.leafNodes[index])
	if node < 0 || node >= b.nodeCount {
		panic("decs: inconsistent exact-N leaf topology")
	}
	return b.hashAt(node)
}

// wrapLeafHashInto applies the independent exact-N positional leaf hash in
// place. The canonical DECS leaf hash already occupies the final leaf arena
// slot; framing copies it to scratch before SHAKE overwrites that slot.
func (b *exactMerkleBuilderV3) wrapLeafHashInto(h sha3.ShakeHash, scratch []byte, index int) []byte {
	leaf := b.leafHashAt(index)
	return hashExactMerkleLeafV3Into(h, scratch, leaf, b.ctx, b.nLeaves, index, leaf)
}

type exactMerklePhaseTimingsV3 struct {
	storage      time.Duration
	leafWrapping time.Duration
	internalHash time.Duration
}

func (t *exactMerklePhaseTimingsV3) record(rec CommitPhaseRecorder) {
	if t == nil || rec == nil {
		return
	}
	rec.RecordDuration("decs.exact_tree_storage", t.storage)
	rec.RecordDuration("decs.exact_leaf_wrapping", t.leafWrapping)
	rec.RecordDuration("decs.internal_node_hashing", t.internalHash)
}

// BuildMerkleTreeFromLeafHashBytesV2 builds the topology selected by the
// commitment context. Legacy v2 uses a padded complete tree. Strict v3 uses
// the exact-N tree and its separate interval-binding domains. Input leaves
// must already be canonical HashLeafV2 outputs for the same context.
func BuildMerkleTreeFromLeafHashBytesV2(ctx CommitmentContext, leaves [][]byte, hashBytes int) (*MerkleTree, error) {
	return buildMerkleTreeFromLeafHashBytesV2(ctx, leaves, hashBytes, nil)
}

func buildMerkleTreeFromLeafHashBytesV2(ctx CommitmentContext, leaves [][]byte, hashBytes int, timings *exactMerklePhaseTimingsV3) (*MerkleTree, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("decs: cannot build v2 Merkle tree with no leaves")
	}
	if !IsSupportedHashBytes(hashBytes) {
		return nil, fmt.Errorf("decs: invalid v2 Merkle hash width %d", hashBytes)
	}
	for i := range leaves {
		if len(leaves[i]) != hashBytes {
			return nil, fmt.Errorf("decs: v2 leaf hash[%d] width=%d want=%d", i, len(leaves[i]), hashBytes)
		}
	}
	if ctx.TranscriptVersion == TranscriptVersionV3 {
		return buildExactNMerkleTreeV3(ctx, leaves, hashBytes, timings)
	}
	return buildPaddedMerkleTreeV2(ctx, leaves, hashBytes)
}

func buildPaddedMerkleTreeV2(ctx CommitmentContext, leaves [][]byte, hashBytes int) (*MerkleTree, error) {
	size := 1
	for size < len(leaves) {
		if size > int(^uint(0)>>1)/2 {
			return nil, fmt.Errorf("decs: v2 Merkle leaf count overflows tree size")
		}
		size <<= 1
	}
	if size > int(^uint(0)>>1)/hashBytes {
		return nil, fmt.Errorf("decs: v2 Merkle layer size overflows int")
	}
	layer := make([][]byte, size)
	layerStorage := make([]byte, size*hashBytes)
	for i := range layer {
		layer[i] = layerStorage[i*hashBytes : (i+1)*hashBytes]
	}
	for i := range leaves {
		copy(layer[i], leaves[i])
	}
	h := sha3.NewShake256()
	var scratch []byte
	for i := len(leaves); i < size; i++ {
		scratch = hashPaddingV2Into(h, scratch, layer[i], ctx, uint64(i))
	}
	layers := [][][]byte{layer}

	for level, sz := uint64(1), size; sz > 1; level, sz = level+1, sz>>1 {
		prev := layers[len(layers)-1]
		pairs := sz / 2
		next := make([][]byte, pairs)
		nextStorage := make([]byte, pairs*hashBytes)
		for pair := range next {
			next[pair] = nextStorage[pair*hashBytes : (pair+1)*hashBytes]
		}
		workers := runtime.GOMAXPROCS(0)
		if pairs < merkleParallelLevelThreshold || workers < 2 {
			for pair := 0; pair < pairs; pair++ {
				scratch = hashNodeV2Into(h, scratch, next[pair], ctx, level, uint64(pair), prev[2*pair], prev[2*pair+1])
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
					var workerScratch []byte
					for pair := start; pair < end; pair++ {
						workerScratch = hashNodeV2Into(hw, workerScratch, next[pair], ctx, level, uint64(pair), prev[2*pair], prev[2*pair+1])
					}
				}(start, end)
			}
			wg.Wait()
		}
		layers = append(layers, next)
	}
	return &MerkleTree{
		topology:  merkleTreePaddedV2,
		layers:    layers,
		nLeaves:   len(leaves),
		hashBytes: hashBytes,
	}, nil
}

func buildExactNMerkleTreeV3(ctx CommitmentContext, leaves [][]byte, hashBytes int, timings *exactMerklePhaseTimingsV3) (*MerkleTree, error) {
	nLeaves := len(leaves)
	builder, err := newExactMerkleBuilderV3(ctx, nLeaves, hashBytes, timings)
	if err != nil {
		return nil, err
	}
	runParallel := func(count int, work func(h sha3.ShakeHash, scratch []byte, index int) []byte) {
		workers := runtime.GOMAXPROCS(0)
		if count < merkleParallelLevelThreshold || workers < 2 {
			h := sha3.NewShake256()
			var scratch []byte
			for index := 0; index < count; index++ {
				scratch = work(h, scratch, index)
			}
			return
		}
		if workers > count {
			workers = count
		}
		var wg sync.WaitGroup
		wg.Add(workers)
		for worker := 0; worker < workers; worker++ {
			start := worker * count / workers
			end := (worker + 1) * count / workers
			go func(start, end int) {
				defer wg.Done()
				h := sha3.NewShake256()
				var scratch []byte
				for index := start; index < end; index++ {
					scratch = work(h, scratch, index)
				}
			}(start, end)
		}
		wg.Wait()
	}
	leafStart := time.Time{}
	if timings != nil {
		leafStart = time.Now()
	}
	runParallel(nLeaves, func(h sha3.ShakeHash, scratch []byte, leafIndex int) []byte {
		out := builder.leafHashAt(leafIndex)
		return hashExactMerkleLeafV3Into(h, scratch, out, ctx, nLeaves, leafIndex, leaves[leafIndex])
	})
	if timings != nil {
		timings.leafWrapping = time.Since(leafStart)
	}

	return builder.finishInternal(timings)
}

func (b *exactMerkleBuilderV3) finishInternal(timings *exactMerklePhaseTimingsV3) (*MerkleTree, error) {
	internalStart := time.Time{}
	if timings != nil {
		internalStart = time.Now()
	}
	nLeaves := b.nLeaves
	hashAt := b.hashAt
	workers := runtime.GOMAXPROCS(0)
	cutDepth := 0
	for tasks := 1; tasks < workers*4; tasks <<= 1 {
		cutDepth++
	}
	tasks := make([]exactMerkleWorkV3, 0, workers*4)
	skeleton := make([]exactMerkleWorkV3, 0, workers*4)
	var cut func(node, start, end, depth int) error
	cut = func(node, start, end, depth int) error {
		if end-start <= 1 {
			return nil
		}
		if depth >= cutDepth {
			tasks = append(tasks, exactMerkleWorkV3{node: node, start: start, end: end})
			return nil
		}
		split, err := exactMerkleSplitV3(start, end)
		if err != nil {
			return err
		}
		left := node + 1
		right := node + 2*(split-start)
		if err := cut(left, start, split, depth+1); err != nil {
			return err
		}
		if err := cut(right, split, end, depth+1); err != nil {
			return err
		}
		skeleton = append(skeleton, exactMerkleWorkV3{node: node, start: start, end: end})
		return nil
	}
	if err := cut(0, 0, nLeaves, 0); err != nil {
		return nil, err
	}
	hashNode := func(h sha3.ShakeHash, scratch []byte, item exactMerkleWorkV3) []byte {
		split, err := exactMerkleSplitV3(item.start, item.end)
		if err != nil {
			panic(err)
		}
		left := item.node + 1
		right := item.node + 2*(split-item.start)
		return hashExactMerkleNodeV3Into(h, scratch, hashAt(item.node), b.ctx, nLeaves, item.start, split, item.end, hashAt(left), hashAt(right))
	}
	var hashSubtree func(h sha3.ShakeHash, scratch []byte, node, start, end int) []byte
	hashSubtree = func(h sha3.ShakeHash, scratch []byte, node, start, end int) []byte {
		if end-start <= 1 {
			return scratch
		}
		split, err := exactMerkleSplitV3(start, end)
		if err != nil {
			panic(err)
		}
		left := node + 1
		right := node + 2*(split-start)
		scratch = hashSubtree(h, scratch, left, start, split)
		scratch = hashSubtree(h, scratch, right, split, end)
		return hashNode(h, scratch, exactMerkleWorkV3{node: node, start: start, end: end})
	}
	if len(tasks) > 0 {
		if workers > len(tasks) {
			workers = len(tasks)
		}
		var next uint64
		var wg sync.WaitGroup
		wg.Add(workers)
		for worker := 0; worker < workers; worker++ {
			go func() {
				defer wg.Done()
				h := sha3.NewShake256()
				var scratch []byte
				for {
					index := int(atomic.AddUint64(&next, 1) - 1)
					if index >= len(tasks) {
						return
					}
					task := tasks[index]
					scratch = hashSubtree(h, scratch, task.node, task.start, task.end)
				}
			}()
		}
		wg.Wait()
	}
	h := sha3.NewShake256()
	var scratch []byte
	for _, item := range skeleton {
		scratch = hashNode(h, scratch, item)
	}
	if timings != nil {
		timings.internalHash = time.Since(internalStart)
	}
	return &MerkleTree{
		topology:    merkleTreeExactNV3,
		exactHashes: b.hashStorage,
		nLeaves:     nLeaves,
		hashBytes:   b.hashBytes,
	}, nil
}

// RootHash returns the full Merkle root hash.
func (mt *MerkleTree) RootHash() []byte {
	if mt == nil {
		return nil
	}
	if mt.topology == merkleTreeExactNV3 {
		if mt.nLeaves <= 0 || mt.hashBytes <= 0 || len(mt.exactHashes) != (2*mt.nLeaves-1)*mt.hashBytes {
			return nil
		}
		return append([]byte(nil), mt.exactHashV3(0)...)
	}
	if len(mt.layers) == 0 {
		return nil
	}
	return append([]byte(nil), mt.layers[len(mt.layers)-1][0]...)
}

func (mt *MerkleTree) exactHashV3(node int) []byte {
	if mt == nil || node < 0 || mt.hashBytes <= 0 || node >= 2*mt.nLeaves-1 {
		return nil
	}
	start := node * mt.hashBytes
	end := start + mt.hashBytes
	if start < 0 || end < start || end > len(mt.exactHashes) {
		return nil
	}
	return mt.exactHashes[start:end]
}

func hashExactMerkleLeafV3Into(h sha3.ShakeHash, scratch, out []byte, ctx CommitmentContext, nLeaves, index int, leafHash []byte) []byte {
	scratch = scratch[:0]
	scratch = appendContextV2(scratch, merkleExactLeafDomainV3, ctx)
	scratch = appendUint64(scratch, uint64(nLeaves))
	scratch = appendUint64(scratch, uint64(index))
	scratch = appendUint64(scratch, uint64(index+1))
	scratch = appendUint32(scratch, uint32(len(out)))
	scratch = appendLengthPrefixed(scratch, leafHash)
	h.Reset()
	_, _ = h.Write(scratch)
	_, _ = h.Read(out)
	return scratch
}

func hashExactMerkleNodeV3Into(h sha3.ShakeHash, scratch, out []byte, ctx CommitmentContext, nLeaves, start, split, end int, left, right []byte) []byte {
	scratch = scratch[:0]
	scratch = appendContextV2(scratch, merkleExactNodeDomainV3, ctx)
	scratch = appendUint64(scratch, uint64(nLeaves))
	scratch = appendUint64(scratch, uint64(start))
	scratch = appendUint64(scratch, uint64(split))
	scratch = appendUint64(scratch, uint64(end))
	scratch = appendUint64(scratch, uint64(split-start))
	scratch = appendUint64(scratch, uint64(end-split))
	scratch = appendUint32(scratch, uint32(len(out)))
	scratch = appendLengthPrefixed(scratch, left)
	scratch = appendLengthPrefixed(scratch, right)
	h.Reset()
	_, _ = h.Write(scratch)
	_, _ = h.Read(out)
	return scratch
}

func (mt *MerkleTree) exactPathNodesV3(index int) ([][]byte, error) {
	if mt == nil || mt.topology != merkleTreeExactNV3 || mt.nLeaves <= 0 || len(mt.exactHashes) != (2*mt.nLeaves-1)*mt.hashBytes {
		return nil, fmt.Errorf("decs: exact-N Merkle path requested from incompatible tree")
	}
	if index < 0 || index >= mt.nLeaves {
		return nil, fmt.Errorf("decs: exact-N Merkle leaf %d outside [0,%d)", index, mt.nLeaves)
	}
	nodeIdx, start, end := 0, 0, mt.nLeaves
	rootDown := make([][]byte, 0, checkedMerkleDepthV3NoError(mt.nLeaves))
	for end-start > 1 {
		split, err := exactMerkleSplitV3(start, end)
		if err != nil {
			return nil, err
		}
		left := nodeIdx + 1
		right := nodeIdx + 2*(split-start)
		if index < split {
			rootDown = append(rootDown, append([]byte(nil), mt.exactHashV3(right)...))
			nodeIdx, end = left, split
		} else {
			rootDown = append(rootDown, append([]byte(nil), mt.exactHashV3(left)...))
			nodeIdx, start = right, split
		}
	}
	path := make([][]byte, len(rootDown))
	for i := range rootDown {
		path[len(rootDown)-1-i] = rootDown[i]
	}
	return path, nil
}

func (mt *MerkleTree) exactNodeHashV3(position MerkleFrontierPositionV3) ([]byte, error) {
	if mt == nil || mt.topology != merkleTreeExactNV3 || len(mt.exactHashes) != (2*mt.nLeaves-1)*mt.hashBytes {
		return nil, fmt.Errorf("decs: exact-N Merkle node requested from incompatible tree")
	}
	idx, start, end := 0, 0, mt.nLeaves
	for idx >= 0 && idx < 2*mt.nLeaves-1 {
		if start == position.Start && end == position.End {
			return append([]byte(nil), mt.exactHashV3(idx)...), nil
		}
		if end-start <= 1 {
			break
		}
		split, err := exactMerkleSplitV3(start, end)
		if err != nil {
			return nil, err
		}
		left := idx + 1
		right := idx + 2*(split-start)
		if position.End <= split {
			idx, end = left, split
			continue
		}
		if position.Start >= split {
			idx, start = right, split
			continue
		}
		break
	}
	return nil, fmt.Errorf("decs: interval [%d,%d) is not an exact-N Merkle node", position.Start, position.End)
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
