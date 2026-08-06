package PIOP

import (
	"bytes"
	"testing"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	swdomain "vSIS-Signature/internal/domain"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestDetailedPhaseRecorderPropagatesDECSSubphases(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatal(err)
	}
	const nLeaves = 257
	points := make([]uint64, nLeaves)
	for i := range points {
		points[i] = uint64(i + 1)
	}
	prepared, err := swdomain.NewPrepared(swdomain.Binding{
		Q: ringQ.Modulus[0], NLeaves: nLeaves, OmegaSize: 3, Ell: 2,
	}, points)
	if err != nil {
		t.Fatal(err)
	}
	rows := []lvcs.RowInput{{Head: []uint64{3, 5, 7}, Tail: []uint64{11, 13}}}
	ctx := decs.CommitmentContext{
		TranscriptVersion: decs.TranscriptVersionV3,
		Role:              decs.CommitmentRoleMain,
		Salt:              bytes.Repeat([]byte{0x42}, 24),
	}
	recorder := NewDetailedPhaseRecorder()
	_, key, _, err := commitRowsPrepared(
		ringQ, rows, 2,
		decs.Params{Degree: 4, Eta: 2, TapeBytes: 16, HashBytes: 21},
		1, 1, 0, nil, prepared, ctx, recorder, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.DecsProver.ReleaseTapes)
	want := map[string]bool{
		"decs.formal_evaluation_cpu":   false,
		"decs.leaf_encoding_cpu":       false,
		"decs.leaf_shake_cpu":          false,
		"decs.exact_leaf_wrapping_cpu": false,
		"decs.internal_node_hashing":   false,
		"decs.exact_tree_storage":      false,
	}
	for _, timing := range recorder.Snapshot() {
		if _, ok := want[timing.Label]; ok {
			want[timing.Label] = true
		}
	}
	for label, found := range want {
		if !found {
			t.Fatalf("detailed recorder missing %s", label)
		}
	}
}
