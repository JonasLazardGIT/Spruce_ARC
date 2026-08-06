package PIOP

import (
	"math/rand"
	"sync"
	"testing"
)

func TestInterpolationPlanMatchesReference(t *testing.T) {
	const q = uint64(1017857)
	rng := rand.New(rand.NewSource(0x51504c414e))
	for _, n := range []int{1, 2, 7, 32, 60} {
		xs := make([]uint64, n)
		for i := range xs {
			xs[i] = uint64(3*i + 1)
		}
		plan, err := buildInterpolationPlan(xs, q)
		if err != nil {
			t.Fatalf("n=%d: build plan: %v", n, err)
		}
		for iteration := 0; iteration < 16; iteration++ {
			values := make([]uint64, n)
			for i := range values {
				values[i] = uint64(rng.Int63()) + q*uint64(iteration%3)
			}
			want := Interpolate(xs, values, q)
			got := plan.interpolate(values)
			if len(got) != len(want) {
				t.Fatalf("n=%d iteration=%d: coefficient length=%d want %d", n, iteration, len(got), len(want))
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("n=%d iteration=%d degree=%d: coefficient=%d want %d", n, iteration, i, got[i], want[i])
				}
			}
		}
	}
}

func TestInterpolationPlanIntoDoesNotAllocateAndIsConcurrent(t *testing.T) {
	const q = uint64(1017857)
	xs := make([]uint64, 60)
	values := make([]uint64, len(xs))
	for i := range xs {
		xs[i] = uint64(i)
		values[i] = uint64(7*i + 3)
	}
	plan, err := buildInterpolationPlan(xs, q)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]uint64, len(xs)+8)
	if allocs := testing.AllocsPerRun(1000, func() {
		plan.interpolateInto(dst, values)
	}); allocs != 0 {
		t.Fatalf("interpolateInto allocates %.2f objects/run", allocs)
	}

	want := append([]uint64(nil), dst...)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]uint64, len(dst))
			for iteration := 0; iteration < 20; iteration++ {
				plan.interpolateInto(local, values)
				for i := range want {
					if local[i] != want[i] {
						t.Errorf("concurrent interpolation degree=%d got %d want %d", i, local[i], want[i])
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}
