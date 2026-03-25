package packedwidth

import "testing"

func TestExactForMax(t *testing.T) {
	cases := []struct {
		max  uint64
		want int
	}{
		{0, 1},
		{1, 1},
		{3, 2},
		{(1 << 14) - 1, 14},
		{(1 << 15) - 1, 15},
		{(1 << 16) - 1, 16},
		{(1 << 18) - 1, 18},
		{(1 << 19) - 1, 19},
		{(1 << 20) - 1, 20},
	}
	for _, tc := range cases {
		if got := ExactForMax(tc.max); got != tc.want {
			t.Fatalf("ExactForMax(%d)=%d want=%d", tc.max, got, tc.want)
		}
	}
}

func TestModulusCeiling(t *testing.T) {
	cases := []struct {
		q    uint64
		want int
	}{
		{3, 2},
		{12289, 14},
		{18433, 15},
		{40961, 16},
		{65537, 17},
	}
	for _, tc := range cases {
		if got := ModulusCeiling(tc.q); got != tc.want {
			t.Fatalf("ModulusCeiling(%d)=%d want=%d", tc.q, got, tc.want)
		}
	}
}
