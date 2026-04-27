package PIOP

import "testing"

func TestBuildPublicLabelsOmitsTWhenEmpty(t *testing.T) {
	labels := BuildPublicLabels(PublicInputs{
		HashRelation: "bbs",
		Tag:          [][]int64{{1, 2}},
		Nonce:        [][]int64{{3, 4}},
	})
	for _, label := range labels {
		if label.Name == "T" {
			t.Fatalf("unexpected T label when public T is empty")
		}
	}
}

func TestBuildPublicLabelsIncludesTWhenPresent(t *testing.T) {
	labels := BuildPublicLabels(PublicInputs{
		HashRelation: "bbs",
		T:            []int64{5, 6},
		Tag:          [][]int64{{1}},
		Nonce:        [][]int64{{2}},
	})
	found := false
	for _, label := range labels {
		if label.Name == "T" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing T label when public T is present")
	}
}

func TestBuildPublicLabelsIncludesX0Len(t *testing.T) {
	labels := BuildPublicLabels(PublicInputs{
		RingDegree:   512,
		X0Len:        70,
		HashRelation: "bb_tran",
	})
	found := false
	for _, label := range labels {
		if label.Name == "X0Len" {
			found = true
			if len(label.Data) != 8 {
				t.Fatalf("X0Len label length=%d want 8", len(label.Data))
			}
			break
		}
	}
	if !found {
		t.Fatal("missing X0Len public label")
	}
}
