package PIOP

import "testing"

func TestBuildPublicLabelsOmitsTWhenEmpty(t *testing.T) {
	labels := BuildPublicLabels(PublicInputs{
		Tag:   [][]int64{{1, 2}},
		Nonce: [][]int64{{3, 4}},
	})
	for _, label := range labels {
		if label.Name == "T" {
			t.Fatalf("unexpected T label when public T is empty")
		}
	}
}

func TestBuildPublicLabelsIncludesTWhenPresent(t *testing.T) {
	labels := BuildPublicLabels(PublicInputs{
		T:     []int64{5, 6},
		Tag:   [][]int64{{1}},
		Nonce: [][]int64{{2}},
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
