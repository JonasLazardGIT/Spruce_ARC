package decs

import (
	"bytes"
	"fmt"
	"reflect"
)

type openingEntryV2 struct {
	index int
	pvals []uint64
	mvals []uint64
	tape  []byte
	path  [][]byte
}

// MergeOpeningsV2 merges a mask-prefix opening and a tail opening. Entries are
// keyed by their logical leaf index; identical repeats are emitted once and a
// conflicting tape, evaluation row, or authentication path is rejected. The
// resulting order is the mask order followed by first-seen tail order.
func MergeOpeningsV2(ctx CommitmentContext, mask, tail *DECSOpening) (*DECSOpening, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	base := mask
	if base == nil {
		base = tail
	}
	if base == nil {
		return nil, fmt.Errorf("decs: cannot merge two nil v2 openings")
	}
	tapeBytes := base.TapeBytes
	if err := validateOpeningV2(ctx, base, tapeBytes); err != nil {
		return nil, err
	}
	result := &DECSOpening{
		Version:   OpeningVersionV2,
		Role:      ctx.Role,
		TapeBytes: tapeBytes,
		R:         base.R,
		Eta:       base.Eta,
	}
	nodeByHash := make(map[string]int)
	addNode := func(node []byte) int {
		key := string(node)
		if id, exists := nodeByHash[key]; exists {
			return id
		}
		id := len(result.Nodes)
		result.Nodes = append(result.Nodes, append([]byte(nil), node...))
		nodeByHash[key] = id
		return id
	}
	entries := make(map[int]openingEntryV2)
	order := make([]int, 0, base.EntryCount())
	appendOpening := func(source *DECSOpening) error {
		if source == nil {
			return nil
		}
		if err := validateOpeningV2(ctx, source, tapeBytes); err != nil {
			return err
		}
		if source.R != result.R || source.Eta != result.Eta {
			return fmt.Errorf("decs: cannot merge v2 openings with different dimensions")
		}
		if len(source.Pvals) != source.EntryCount() || len(source.Mvals) != source.EntryCount() {
			return fmt.Errorf("decs: MergeOpeningsV2 requires unpacked, fully reconstructed values")
		}
		for row := 0; row < source.EntryCount(); row++ {
			idx := source.IndexAt(row)
			if idx < 0 {
				return fmt.Errorf("decs: malformed v2 merge index at row %d", row)
			}
			if len(source.Pvals[row]) != result.R || len(source.Mvals[row]) != result.Eta {
				return fmt.Errorf("decs: malformed v2 merge value width at index %d", idx)
			}
			pathIDs, ok := pathRowIndices(source, row)
			if !ok {
				return fmt.Errorf("decs: malformed v2 merge path at index %d", idx)
			}
			entry := openingEntryV2{
				index: idx,
				pvals: append([]uint64(nil), source.Pvals[row]...),
				mvals: append([]uint64(nil), source.Mvals[row]...),
				tape:  append([]byte(nil), source.Tapes[row]...),
				path:  make([][]byte, len(pathIDs)),
			}
			for level, id := range pathIDs {
				if id < 0 || id >= len(source.Nodes) {
					return fmt.Errorf("decs: malformed v2 merge node index at leaf %d", idx)
				}
				entry.path[level] = append([]byte(nil), source.Nodes[id]...)
			}
			if previous, exists := entries[idx]; exists {
				if !reflect.DeepEqual(previous.pvals, entry.pvals) ||
					!reflect.DeepEqual(previous.mvals, entry.mvals) ||
					!bytes.Equal(previous.tape, entry.tape) ||
					!reflect.DeepEqual(previous.path, entry.path) {
					return fmt.Errorf("decs: conflicting v2 opening data for leaf %d", idx)
				}
				continue
			}
			entries[idx] = entry
			order = append(order, idx)
		}
		return nil
	}
	if err := appendOpening(mask); err != nil {
		return nil, err
	}
	maskUniqueCount := len(order)
	if maskUniqueCount > 0 {
		result.MaskBase = order[0]
		for i := 1; i < maskUniqueCount; i++ {
			if order[i] != result.MaskBase+i {
				return nil, fmt.Errorf("decs: v2 mask opening is not a contiguous prefix")
			}
		}
		result.MaskCount = maskUniqueCount
	}
	if err := appendOpening(tail); err != nil {
		return nil, err
	}
	result.Indices = append(result.Indices, order[maskUniqueCount:]...)
	for _, idx := range order {
		entry := entries[idx]
		result.Pvals = append(result.Pvals, entry.pvals)
		result.Mvals = append(result.Mvals, entry.mvals)
		result.Tapes = append(result.Tapes, entry.tape)
		pathIDs := make([]int, len(entry.path))
		for level, node := range entry.path {
			pathIDs[level] = addNode(node)
		}
		result.PathIndex = append(result.PathIndex, pathIDs)
	}
	if len(result.PathIndex) > 0 {
		result.PathDepth = len(result.PathIndex[0])
	}
	if err := validateStrictlyIncreasingOpeningIndicesV2(result); err != nil {
		return nil, err
	}
	return result, nil
}
