package decs

import (
	"bytes"
	"fmt"
	"sort"

	"golang.org/x/crypto/sha3"
)

// MerkleTopologyExactNV3 is the public identity of the strict-v3 tree shape.
// The root additionally binds NLeaves and every exact interval/split.
const MerkleTopologyExactNV3 = "exact-n-largest-lower-power-v3"

// MerkleFrontierPositionV3 identifies the exact half-open leaf interval
// covered by one node in the strict-v3 exact-N Merkle tree. Intervals, rather
// than padded level/index pairs, make the topology unambiguous for every N.
// Positions are public consequences of NLeaves and the Fiat--Shamir indices;
// they are never transmitted.
type MerkleFrontierPositionV3 struct {
	Start int
	End   int
}

// exactMerkleSplitV3 implements the canonical largest-lower-power topology.
// For a non-leaf interval [start,end), its left child has the largest power-of-
// two size strictly below end-start, and its right child contains the residue.
// When the parent size is itself a power of two, this is the usual equal split.
func exactMerkleSplitV3(start, end int) (int, error) {
	if start < 0 || end-start <= 1 {
		return 0, fmt.Errorf("decs: exact-N Merkle interval [%d,%d) is not internal", start, end)
	}
	span := end - start
	leftSize := 1
	for leftSize <= (span-1)/2 {
		leftSize <<= 1
	}
	if leftSize <= 0 || leftSize >= span {
		return 0, fmt.Errorf("decs: cannot split exact-N Merkle interval [%d,%d)", start, end)
	}
	return start + leftSize, nil
}

func exactMerkleHeightV3(span int) int {
	if span <= 1 {
		return 0
	}
	height := 0
	for size := 1; size < span; size <<= 1 {
		height++
	}
	return height
}

func checkedMerkleDepthV3NoError(nLeaves int) int {
	depth, _ := checkedMerkleDepthV3(nLeaves)
	return depth
}

func validateStrictMerkleLeavesV3(indices []int, nLeaves int) error {
	if _, err := checkedMerkleDepthV3(nLeaves); err != nil {
		return err
	}
	if len(indices) == 0 || len(indices) > nLeaves {
		return fmt.Errorf("decs: positional frontier opening count=%d outside [1,%d]", len(indices), nLeaves)
	}
	previous := -1
	for _, index := range indices {
		if index < 0 || index >= nLeaves {
			return fmt.Errorf("decs: positional frontier leaf %d outside [0,%d)", index, nLeaves)
		}
		if index <= previous {
			return fmt.Errorf("decs: positional frontier leaves are not strictly increasing at %d", index)
		}
		previous = index
	}
	return nil
}

// MerkleAuthenticationPathPositionsV3 returns the canonical sibling intervals
// for one leaf, ordered from the leaf towards the root. Path lengths may differ
// between leaves in a non-power-of-two exact-N tree.
func MerkleAuthenticationPathPositionsV3(index, nLeaves int) ([]MerkleFrontierPositionV3, error) {
	if _, err := checkedMerkleDepthV3(nLeaves); err != nil {
		return nil, err
	}
	if index < 0 || index >= nLeaves {
		return nil, fmt.Errorf("decs: exact-N Merkle leaf %d outside [0,%d)", index, nLeaves)
	}
	start, end := 0, nLeaves
	rootDown := make([]MerkleFrontierPositionV3, 0, checkedMerkleDepthV3NoError(nLeaves))
	for end-start > 1 {
		split, err := exactMerkleSplitV3(start, end)
		if err != nil {
			return nil, err
		}
		if index < split {
			rootDown = append(rootDown, MerkleFrontierPositionV3{Start: split, End: end})
			end = split
		} else {
			rootDown = append(rootDown, MerkleFrontierPositionV3{Start: start, End: split})
			start = split
		}
	}
	positions := make([]MerkleFrontierPositionV3, len(rootDown))
	for i := range rootDown {
		positions[len(rootDown)-1-i] = rootDown[i]
	}
	return positions, nil
}

// MerkleFrontierPositionsV3 returns the unique canonical exact-N frontier for
// strictly increasing opened leaf indices. A maximal sibling subtree is
// included exactly when it contains no opened leaf and its parent does.
// Ordering is bottom-up by subtree height, then interval start/end.
func MerkleFrontierPositionsV3(indices []int, nLeaves int) ([]MerkleFrontierPositionV3, error) {
	if err := validateStrictMerkleLeavesV3(indices, nLeaves); err != nil {
		return nil, err
	}
	positions := make([]MerkleFrontierPositionV3, 0, len(indices)*checkedMerkleDepthV3NoError(nLeaves))
	var visit func(start, end, lo, hi int) error
	visit = func(start, end, lo, hi int) error {
		if lo == hi {
			positions = append(positions, MerkleFrontierPositionV3{Start: start, End: end})
			return nil
		}
		if end-start == 1 {
			if hi-lo != 1 || indices[lo] != start {
				return fmt.Errorf("decs: inconsistent exact-N frontier leaf interval [%d,%d)", start, end)
			}
			return nil
		}
		split, err := exactMerkleSplitV3(start, end)
		if err != nil {
			return err
		}
		mid := lo + sort.Search(hi-lo, func(offset int) bool { return indices[lo+offset] >= split })
		if err := visit(start, split, lo, mid); err != nil {
			return err
		}
		return visit(split, end, mid, hi)
	}
	if err := visit(0, nLeaves, 0, len(indices)); err != nil {
		return nil, err
	}
	sort.Slice(positions, func(i, j int) bool {
		hi := exactMerkleHeightV3(positions[i].End - positions[i].Start)
		hj := exactMerkleHeightV3(positions[j].End - positions[j].Start)
		if hi != hj {
			return hi < hj
		}
		if positions[i].Start != positions[j].Start {
			return positions[i].Start < positions[j].Start
		}
		return positions[i].End < positions[j].End
	})
	return positions, nil
}

// MerkleFrontierWorstCaseNodesV3 computes the exact fixed-size frontier bound
// over all choices of opened leaves in the exact-N topology. The dynamic
// program follows the same largest-lower-power split as commitment and
// verification, so no padded node is counted.
func MerkleFrontierWorstCaseNodesV3(nLeaves, opened int) (int, error) {
	depth, err := checkedMerkleDepthV3(nLeaves)
	if err != nil {
		return 0, err
	}
	if opened <= 0 || opened > nLeaves {
		return 0, fmt.Errorf("decs: positional frontier opening count=%d outside [1,%d]", opened, nLeaves)
	}
	type state struct {
		leaves int
		opened int
	}
	const impossible = -1 << 30
	memo := make(map[state]int)
	var solve func(leaves, selected int) int
	solve = func(leaves, selected int) int {
		if selected < 0 || selected > leaves {
			return impossible
		}
		if selected == 0 {
			return 0
		}
		if leaves == 1 {
			if selected == 1 {
				return 0
			}
			return impossible
		}
		key := state{leaves: leaves, opened: selected}
		if value, ok := memo[key]; ok {
			return value
		}
		split, splitErr := exactMerkleSplitV3(0, leaves)
		if splitErr != nil {
			return impossible
		}
		leftLeaves, rightLeaves := split, leaves-split
		minLeft := selected - rightLeaves
		if minLeft < 0 {
			minLeft = 0
		}
		maxLeft := selected
		if maxLeft > leftLeaves {
			maxLeft = leftLeaves
		}
		best := impossible
		for leftSelected := minLeft; leftSelected <= maxLeft; leftSelected++ {
			rightSelected := selected - leftSelected
			leftCost := solve(leftLeaves, leftSelected)
			rightCost := solve(rightLeaves, rightSelected)
			if leftCost == impossible || rightCost == impossible {
				continue
			}
			cost := leftCost + rightCost
			if (leftSelected == 0) != (rightSelected == 0) {
				cost++
			}
			if cost > best {
				best = cost
			}
		}
		memo[key] = best
		return best
	}
	bound := solve(nLeaves, opened)
	if bound < 0 || bound > opened*depth {
		return 0, fmt.Errorf("decs: failed to derive exact-N positional frontier bound")
	}
	return bound, nil
}

// VerifyMerkleFrontierV3 batch-verifies exact-N leaf hashes against the
// canonical positional frontier. The verifier derives every interval from
// NLeaves and leafIndices; duplicate, missing, reordered, or surplus sibling
// data therefore has no alternate representation.
func VerifyMerkleFrontierV3(ctx CommitmentContext, nLeaves int, leafIndices []int, leafHashes, frontier [][]byte, root []byte) error {
	if err := ctx.Validate(); err != nil {
		return err
	}
	if ctx.TranscriptVersion != TranscriptVersionV3 {
		return fmt.Errorf("decs: exact-N positional frontier requires transcript v3")
	}
	if !IsSupportedHashBytes(len(root)) {
		return fmt.Errorf("decs: positional frontier root width=%d is unsupported", len(root))
	}
	if len(leafHashes) != len(leafIndices) {
		return fmt.Errorf("decs: positional frontier leaf hash count=%d want=%d", len(leafHashes), len(leafIndices))
	}
	positions, err := MerkleFrontierPositionsV3(leafIndices, nLeaves)
	if err != nil {
		return err
	}
	if len(frontier) != len(positions) {
		return fmt.Errorf("decs: positional frontier nodes=%d want=%d", len(frontier), len(positions))
	}
	hashBytes := len(root)
	known := make(map[MerkleFrontierPositionV3][]byte, len(leafIndices)+len(frontier))
	shake := sha3.NewShake256()
	var scratch []byte
	for i, index := range leafIndices {
		if len(leafHashes[i]) != hashBytes {
			return fmt.Errorf("decs: positional frontier leaf hash[%d] width=%d want=%d", i, len(leafHashes[i]), hashBytes)
		}
		position := MerkleFrontierPositionV3{Start: index, End: index + 1}
		wrapped := make([]byte, hashBytes)
		scratch = hashExactMerkleLeafV3Into(shake, scratch, wrapped, ctx, nLeaves, index, leafHashes[i])
		if _, duplicate := known[position]; duplicate {
			return fmt.Errorf("decs: duplicate positional frontier leaf interval [%d,%d)", position.Start, position.End)
		}
		known[position] = wrapped
	}
	for i, position := range positions {
		if len(frontier[i]) != hashBytes {
			return fmt.Errorf("decs: positional frontier node[%d] width=%d want=%d", i, len(frontier[i]), hashBytes)
		}
		if _, duplicate := known[position]; duplicate {
			return fmt.Errorf("decs: duplicate positional frontier interval [%d,%d)", position.Start, position.End)
		}
		known[position] = append([]byte(nil), frontier[i]...)
	}
	consumed := make(map[MerkleFrontierPositionV3]struct{}, len(known))
	var reconstruct func(start, end int) ([]byte, error)
	reconstruct = func(start, end int) ([]byte, error) {
		position := MerkleFrontierPositionV3{Start: start, End: end}
		if value, ok := known[position]; ok {
			if _, reused := consumed[position]; reused {
				return nil, fmt.Errorf("decs: duplicate use of positional frontier interval [%d,%d)", start, end)
			}
			consumed[position] = struct{}{}
			return value, nil
		}
		if end-start <= 1 {
			return nil, fmt.Errorf("decs: positional frontier missing leaf interval [%d,%d)", start, end)
		}
		split, splitErr := exactMerkleSplitV3(start, end)
		if splitErr != nil {
			return nil, splitErr
		}
		left, leftErr := reconstruct(start, split)
		if leftErr != nil {
			return nil, leftErr
		}
		right, rightErr := reconstruct(split, end)
		if rightErr != nil {
			return nil, rightErr
		}
		parent := make([]byte, hashBytes)
		scratch = hashExactMerkleNodeV3Into(shake, scratch, parent, ctx, nLeaves, start, split, end, left, right)
		return parent, nil
	}
	computed, err := reconstruct(0, nLeaves)
	if err != nil {
		return err
	}
	if len(consumed) != len(known) {
		return fmt.Errorf("decs: positional frontier contains noncanonical unused sibling")
	}
	if !bytes.Equal(computed, root) {
		return fmt.Errorf("decs: positional Merkle frontier rejected")
	}
	return nil
}

// VerifyPathHashExactNV3 verifies one exact-N path. sibling intervals are
// derived rather than transmitted and every parent hash binds N and the full
// canonical interval split.
func VerifyPathHashExactNV3(ctx CommitmentContext, nLeaves, index int, leafHash []byte, path [][]byte, root []byte) bool {
	if err := ctx.Validate(); err != nil || ctx.TranscriptVersion != TranscriptVersionV3 || !IsSupportedHashBytes(len(root)) {
		return false
	}
	positions, err := MerkleAuthenticationPathPositionsV3(index, nLeaves)
	if err != nil || len(path) != len(positions) || len(leafHash) != len(root) {
		return false
	}
	shake := sha3.NewShake256()
	current := make([]byte, len(root))
	var scratch []byte
	scratch = hashExactMerkleLeafV3Into(shake, scratch, current, ctx, nLeaves, index, leafHash)
	currentStart, currentEnd := index, index+1
	for i, position := range positions {
		if len(path[i]) != len(root) {
			return false
		}
		parentStart, parentSplit, parentEnd := 0, 0, 0
		left, right := []byte(nil), []byte(nil)
		switch {
		case position.End == currentStart:
			parentStart, parentSplit, parentEnd = position.Start, currentStart, currentEnd
			left, right = path[i], current
		case currentEnd == position.Start:
			parentStart, parentSplit, parentEnd = currentStart, position.Start, position.End
			left, right = current, path[i]
		default:
			return false
		}
		expectedSplit, splitErr := exactMerkleSplitV3(parentStart, parentEnd)
		if splitErr != nil || expectedSplit != parentSplit {
			return false
		}
		next := make([]byte, len(root))
		scratch = hashExactMerkleNodeV3Into(shake, scratch, next, ctx, nLeaves, parentStart, parentSplit, parentEnd, left, right)
		current = next
		currentStart, currentEnd = parentStart, parentEnd
	}
	return currentStart == 0 && currentEnd == nLeaves && bytes.Equal(current, root)
}

func checkedMerkleDepthV3(nLeaves int) (int, error) {
	if nLeaves <= 0 {
		return 0, fmt.Errorf("decs: invalid Merkle leaf count %d", nLeaves)
	}
	depth := 0
	for size := uint64(1); size < uint64(nLeaves); size <<= 1 {
		depth++
		if depth >= 63 {
			return 0, fmt.Errorf("decs: Merkle depth overflow")
		}
	}
	return depth, nil
}
