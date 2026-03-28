package lvcs

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestInterpolateRowExplicitCoeffsMatchesReference(t *testing.T) {
	mod := uint64(12289)
	ncols := 96
	ell := 18
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 16; trial++ {
		row := make([]uint64, ncols)
		mask := make([]uint64, ell)
		xs := make([]uint64, ncols+ell)
		for i := range row {
			row[i] = uint64(rng.Intn(int(mod)))
		}
		for i := range mask {
			mask[i] = uint64(rng.Intn(int(mod)))
		}
		for i := range xs {
			xs[i] = uint64(i + 1 + trial*(ncols+ell))
		}
		got, err := interpolateRowCoeffsWithXs(row, mask, xs, ncols, ell, mod)
		if err != nil {
			t.Fatalf("cached interpolate trial %d: %v", trial, err)
		}
		want, err := interpolateRowCoeffsWithXsReference(row, mask, xs, ncols, ell, mod)
		if err != nil {
			t.Fatalf("reference interpolate trial %d: %v", trial, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("interpolation mismatch on trial %d", trial)
		}
	}
}
