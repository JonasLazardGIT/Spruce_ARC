package decs

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestMerkleFrontierV3AdjacentAndNonPowerOfTwo(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 0x71)
	ctx.TranscriptVersion = TranscriptVersionV3
	const (
		nLeaves   = 13
		hashBytes = 21
	)
	leaves := make([][]byte, nLeaves)
	for i := range leaves {
		leaves[i] = bytes.Repeat([]byte{byte(i + 1)}, hashBytes)
	}
	tree, err := BuildMerkleTreeFromLeafHashBytesV2(ctx, leaves, hashBytes)
	if err != nil {
		t.Fatal(err)
	}
	indices := []int{2, 3, 12}
	positions, err := MerkleFrontierPositionsV3(indices, nLeaves)
	if err != nil {
		t.Fatal(err)
	}
	wantPositions := []MerkleFrontierPositionV3{
		{Start: 0, End: 2},
		{Start: 4, End: 8},
		{Start: 8, End: 12},
	}
	if !reflect.DeepEqual(positions, wantPositions) {
		t.Fatalf("frontier positions=%v want=%v", positions, wantPositions)
	}
	for _, position := range positions {
		if position.End-position.Start == 1 && (position.Start == 2 || position.Start == 3) {
			t.Fatal("adjacent opened leaf was serialized as its sibling")
		}
	}
	frontier := frontierNodesFromTreeV3(tree, positions)
	openedHashes := [][]byte{leaves[2], leaves[3], leaves[12]}
	if err := VerifyMerkleFrontierV3(ctx, nLeaves, indices, openedHashes, frontier, tree.RootHash()); err != nil {
		t.Fatalf("valid frontier rejected: %v", err)
	}

	t.Run("missing", func(t *testing.T) {
		if err := VerifyMerkleFrontierV3(ctx, nLeaves, indices, openedHashes, frontier[:len(frontier)-1], tree.RootHash()); err == nil {
			t.Fatal("missing frontier node accepted")
		}
	})
	t.Run("duplicate_or_surplus", func(t *testing.T) {
		bad := append(cloneByteRowsV2(frontier), append([]byte(nil), frontier[0]...))
		if err := VerifyMerkleFrontierV3(ctx, nLeaves, indices, openedHashes, bad, tree.RootHash()); err == nil {
			t.Fatal("surplus duplicate frontier node accepted")
		}
	})
	t.Run("tamper", func(t *testing.T) {
		bad := cloneByteRowsV2(frontier)
		bad[0][0] ^= 1
		if err := VerifyMerkleFrontierV3(ctx, nLeaves, indices, openedHashes, bad, tree.RootHash()); err == nil {
			t.Fatal("tampered frontier node accepted")
		}
	})
	t.Run("noncanonical_leaf_order", func(t *testing.T) {
		if _, err := MerkleFrontierPositionsV3([]int{3, 2, 12}, nLeaves); err == nil {
			t.Fatal("noncanonical leaf order accepted")
		}
	})
}

func TestMerkleFrontierV3ExactWorstCaseBound(t *testing.T) {
	for nLeaves := 2; nLeaves <= 13; nLeaves++ {
		maxOpened := 4
		if maxOpened > nLeaves {
			maxOpened = nLeaves
		}
		for opened := 1; opened <= maxOpened; opened++ {
			bound, err := MerkleFrontierWorstCaseNodesV3(nLeaves, opened)
			if err != nil {
				t.Fatalf("n=%d opened=%d: %v", nLeaves, opened, err)
			}
			indices := make([]int, opened)
			actualMax := -1
			var visit func(next, used int)
			visit = func(next, used int) {
				if used == opened {
					positions, posErr := MerkleFrontierPositionsV3(indices, nLeaves)
					if posErr != nil {
						t.Fatalf("n=%d indices=%v: %v", nLeaves, indices, posErr)
					}
					if len(positions) > actualMax {
						actualMax = len(positions)
					}
					return
				}
				remaining := opened - used
				for value := next; value <= nLeaves-remaining; value++ {
					indices[used] = value
					visit(value+1, used+1)
				}
			}
			visit(0, 0)
			if bound != actualMax {
				t.Fatalf("n=%d opened=%d bound=%d exhaustive=%d", nLeaves, opened, bound, actualMax)
			}
		}
	}

	bound, err := MerkleFrontierWorstCaseNodesV3(688128, 18)
	if err != nil {
		t.Fatal(err)
	}
	if bound != 273 {
		t.Fatalf("BQ128 exact-N frontier bound=%d want=273", bound)
	}
	depth := merkleDepthV2(688128)
	if bound >= 18*depth {
		t.Fatalf("derived bound=%d did not improve naive bound=%d", bound, 18*depth)
	}
	wfBound, err := MerkleFrontierWorstCaseNodesV3(327680, 9)
	if err != nil {
		t.Fatal(err)
	}
	if wfBound != 136 {
		t.Fatalf("WF128 exact-N frontier bound=%d want=136", wfBound)
	}
}

func TestExactNMerkleV3SingleLeaf(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 0x74)
	ctx.TranscriptVersion = TranscriptVersionV3
	leaf := bytes.Repeat([]byte{0x5a}, 24)
	tree, err := BuildMerkleTreeFromLeafHashBytesV2(ctx, [][]byte{leaf}, len(leaf))
	if err != nil {
		t.Fatal(err)
	}
	positions, err := MerkleFrontierPositionsV3([]int{0}, 1)
	if err != nil || len(positions) != 0 {
		t.Fatalf("single-leaf frontier=%v err=%v", positions, err)
	}
	bound, err := MerkleFrontierWorstCaseNodesV3(1, 1)
	if err != nil || bound != 0 {
		t.Fatalf("single-leaf bound=%d err=%v", bound, err)
	}
	if err := VerifyMerkleFrontierV3(ctx, 1, []int{0}, [][]byte{leaf}, nil, tree.RootHash()); err != nil {
		t.Fatalf("single-leaf frontier rejected: %v", err)
	}
	if !VerifyPathHashExactNV3(ctx, 1, 0, leaf, nil, tree.RootHash()) {
		t.Fatal("single-leaf path rejected")
	}
	badLeaf := append([]byte(nil), leaf...)
	badLeaf[0] ^= 1
	if VerifyPathHashExactNV3(ctx, 1, 0, badLeaf, nil, tree.RootHash()) {
		t.Fatal("single-leaf path accepted a modified leaf")
	}
}

func TestExactNMerkleV3FusedLeafWrappingMatchesSeparate(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 0x7a)
	ctx.TranscriptVersion = TranscriptVersionV3
	for _, nLeaves := range []int{1, 8, 13, 257} {
		t.Run(fmt.Sprintf("n=%d", nLeaves), func(t *testing.T) {
			const hashBytes = 24
			leaves := make([][]byte, nLeaves)
			for index := range leaves {
				leaves[index] = bytes.Repeat([]byte{byte(index*29 + 7)}, hashBytes)
			}
			separate, err := BuildMerkleTreeFromLeafHashBytesV2(ctx, leaves, hashBytes)
			if err != nil {
				t.Fatal(err)
			}
			targets, err := newLeafHashTargets(ctx, nLeaves, hashBytes, nil)
			if err != nil {
				t.Fatal(err)
			}
			h := nilShake()
			var scratch []byte
			for index := range leaves {
				copy(targets.at(index), leaves[index])
				scratch = targets.wrapExactLeaf(h, scratch, index)
			}
			fused, err := targets.exact.finishInternal(nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(fused.RootHash(), separate.RootHash()) {
				t.Fatal("fused exact-N root differs from separate leaf wrapping")
			}
			for index := range leaves {
				fusedPath, err := fused.exactPathNodesV3(index)
				if err != nil {
					t.Fatal(err)
				}
				separatePath, err := separate.exactPathNodesV3(index)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(fusedPath, separatePath) {
					t.Fatalf("leaf %d path differs", index)
				}
			}
		})
	}
}

func TestExactNMerkleV3PowerOfTwoAndTopologyDomainIsolation(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 0x73)
	ctx.TranscriptVersion = TranscriptVersionV3
	for _, nLeaves := range []int{8, 13} {
		t.Run(fmt.Sprintf("n=%d", nLeaves), func(t *testing.T) {
			const hashBytes = 24
			leaves := make([][]byte, nLeaves)
			for i := range leaves {
				leaves[i] = bytes.Repeat([]byte{byte(0x40 + i)}, hashBytes)
			}
			exact, err := BuildMerkleTreeFromLeafHashBytesV2(ctx, leaves, hashBytes)
			if err != nil {
				t.Fatal(err)
			}
			padded, err := buildPaddedMerkleTreeV2(ctx, leaves, hashBytes)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(exact.RootHash(), padded.RootHash()) {
				t.Fatal("exact-N v3 root reused the former padded-tree domain")
			}
			indices := []int{1, nLeaves - 1}
			positions, err := MerkleFrontierPositionsV3(indices, nLeaves)
			if err != nil {
				t.Fatal(err)
			}
			frontier := frontierNodesFromTreeV3(exact, positions)
			opened := [][]byte{leaves[indices[0]], leaves[indices[1]]}
			if err := VerifyMerkleFrontierV3(ctx, nLeaves, indices, opened, frontier, exact.RootHash()); err != nil {
				t.Fatalf("exact-N frontier rejected: %v", err)
			}
			if err := VerifyMerkleFrontierV3(ctx, nLeaves, indices, opened, frontier, padded.RootHash()); err == nil {
				t.Fatal("former padded-tree root verified under exact-N topology")
			}
			path, err := exact.exactPathNodesV3(indices[1])
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyPathHashExactNV3(ctx, nLeaves, indices[1], leaves[indices[1]], path, exact.RootHash()) {
				t.Fatal("exact-N authentication path rejected")
			}
			if nLeaves > 8 && VerifyPathHashExactNV3(ctx, nLeaves-1, indices[1], leaves[indices[1]], path, exact.RootHash()) {
				t.Fatal("authentication path did not bind NLeaves")
			}
		})
	}
}

func TestExactNMerkleV3UsesImplicitPreorderArena(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 0x75)
	ctx.TranscriptVersion = TranscriptVersionV3
	for _, nLeaves := range []int{1, 2, 8, 13, 65} {
		t.Run(fmt.Sprintf("n=%d", nLeaves), func(t *testing.T) {
			const hashBytes = 24
			leaves := make([][]byte, nLeaves)
			for i := range leaves {
				leaves[i] = bytes.Repeat([]byte{byte(i*17 + 3)}, hashBytes)
			}
			tree, err := BuildMerkleTreeFromLeafHashBytesV2(ctx, leaves, hashBytes)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := len(tree.exactHashes), (2*nLeaves-1)*hashBytes; got != want {
				t.Fatalf("hash arena bytes=%d want=%d", got, want)
			}
			for leaf := range leaves {
				path, pathErr := tree.exactPathNodesV3(leaf)
				if pathErr != nil {
					t.Fatal(pathErr)
				}
				if !VerifyPathHashExactNV3(ctx, nLeaves, leaf, leaves[leaf], path, tree.RootHash()) {
					t.Fatalf("leaf %d path did not verify", leaf)
				}
			}
		})
	}
}

func TestDECSVerifierV3PositionalFrontierAndLegacyIsolation(t *testing.T) {
	ctx := v2TestContext(CommitmentRoleMain, 0x72)
	prover := makeV2FormalProver(t)
	root := commitV2ForTest(t, prover, ctx, CommitOptions{})
	gamma, err := DeriveGammaV2(ctx, root, prover.params.Eta, prover.rowCount(), prover.ringQ.Modulus[0])
	if err != nil {
		t.Fatal(err)
	}
	rRows := prover.CommitStep2Formal(gamma)
	indices := []int{2, 3, 12}
	legacy, err := prover.EvalOpenV2(indices)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifierWithParamsAndPointsV2Checked(prover.ringQ, prover.rowCount(), prover.params, prover.points, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.VerifyEvalAtFormalHashV2(root, gamma, rRows, legacy, indices) {
		t.Fatal("legacy path opening stopped verifying")
	}

	// Recommit the same DECS instance under the strict-v3 exact-N topology.
	ctxV3 := ctx
	ctxV3.TranscriptVersion = TranscriptVersionV3
	rootV3, err := prover.CommitInitV2WithOptions(ctxV3, CommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	gammaV3, err := DeriveGammaV2(ctxV3, rootV3, prover.params.Eta, prover.rowCount(), prover.ringQ.Modulus[0])
	if err != nil {
		t.Fatal(err)
	}
	rRowsV3 := prover.CommitStep2Formal(gammaV3)
	exactPaths, err := prover.EvalOpenV2(indices)
	if err != nil {
		t.Fatal(err)
	}
	verifierV3, err := NewVerifierWithParamsAndPointsV2Checked(prover.ringQ, prover.rowCount(), prover.params, prover.points, ctxV3)
	if err != nil {
		t.Fatal(err)
	}
	if !verifierV3.VerifyEvalAtFormalHashV2(rootV3, gammaV3, rRowsV3, exactPaths, indices) {
		t.Fatal("strict-v3 exact-N authentication paths did not verify")
	}

	positions, err := MerkleFrontierPositionsV3(indices, len(prover.points))
	if err != nil {
		t.Fatal(err)
	}
	frontierNodes := make([][]byte, len(positions))
	for i, position := range positions {
		found := false
		for row, leaf := range indices {
			pathPositions, pathErr := MerkleAuthenticationPathPositionsV3(leaf, len(prover.points))
			if pathErr != nil {
				t.Fatal(pathErr)
			}
			for level, sibling := range pathPositions {
				if sibling != position {
					continue
				}
				id := exactPaths.PathIndex[row][level]
				frontierNodes[i] = append([]byte(nil), exactPaths.Nodes[id]...)
				found = true
				break
			}
			if found {
				break
			}
		}
		if !found {
			t.Fatalf("frontier position %+v was not present in source paths", position)
		}
	}
	frontier := cloneOpeningV2(exactPaths)
	frontier.AuthFormat = OpeningAuthPositionalFrontierV3
	frontier.Nodes = frontierNodes
	frontier.PathIndex = nil
	frontier.PathBits = nil
	frontier.PathBitWidth = 0
	frontier.PathDepth = 0
	if !verifierV3.VerifyEvalAtFormalHashV2(rootV3, gammaV3, rRowsV3, frontier, indices) {
		t.Fatal("canonical positional frontier opening did not verify")
	}
	if verifier.VerifyEvalAtFormalHashV2(root, gamma, rRows, frontier, indices) {
		t.Fatal("legacy v2 verifier accepted exact-N positional frontier")
	}

	unknown := cloneOpeningV2(frontier)
	unknown.AuthFormat = 99
	if verifierV3.VerifyEvalAtFormalHashV2(rootV3, gammaV3, rRowsV3, unknown, indices) {
		t.Fatal("unknown authentication encoding verified")
	}
	mixed := cloneOpeningV2(frontier)
	mixed.PathDepth = 1
	if verifierV3.VerifyEvalAtFormalHashV2(rootV3, gammaV3, rRowsV3, mixed, indices) {
		t.Fatal("frontier mixed with legacy path metadata verified")
	}
}

func frontierNodesFromTreeV3(tree *MerkleTree, positions []MerkleFrontierPositionV3) [][]byte {
	nodes := make([][]byte, len(positions))
	for i, position := range positions {
		node, err := tree.exactNodeHashV3(position)
		if err != nil {
			panic(err)
		}
		nodes[i] = node
	}
	return nodes
}
