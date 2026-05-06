package decs

import (
	"math/rand"
	"testing"
)

func TestModReducer64MulReducedMatchesDiv(t *testing.T) {
	mods := []uint64{17, 257, 65537, 1054721, uint64(^uint32(0))}
	for _, mod := range mods {
		red := newModReducer64(mod)
		values := []uint64{0, 1, 2, 3, mod / 2, mod - 2, mod - 1}
		for _, a := range values {
			for _, b := range values {
				got := red.mulReduced(a%mod, b%mod)
				want := mulMod64Reduced(a%mod, b%mod, mod)
				if got != want {
					t.Fatalf("mod=%d a=%d b=%d got=%d want=%d", mod, a, b, got, want)
				}
			}
		}
	}
}

func TestModReducer64ReduceUint64MatchesModulo(t *testing.T) {
	mods := []uint64{17, 257, 65537, 1054721, uint64(^uint32(0))}
	values := []uint64{0, 1, 2, 3, 16, 255, 65536, 1054720, 1 << 32, 1 << 40, ^uint64(0) / 3}
	for _, mod := range mods {
		red := newModReducer64(mod)
		for _, v := range values {
			got := red.reduceUint64(v)
			want := v % mod
			if got != want {
				t.Fatalf("mod=%d v=%d got=%d want=%d", mod, v, got, want)
			}
		}
	}
}

func TestFormalEvalPlanMatchesEvalPoly(t *testing.T) {
	q := uint64(1054721)
	red := newModReducer64(q)
	rng := rand.New(rand.NewSource(31))
	for iter := 0; iter < 80; iter++ {
		rowCount := 1 + rng.Intn(32)
		degree := rng.Intn(64)
		rows := make([][]uint64, rowCount)
		for j := range rows {
			rowDegree := rng.Intn(degree + 1)
			rows[j] = make([]uint64, rowDegree+1+rng.Intn(3))
			for d := 0; d <= rowDegree; d++ {
				if rng.Intn(5) == 0 {
					continue
				}
				rows[j][d] = uint64(rng.Int63n(int64(3 * q)))
			}
		}
		plan := newFormalEvalPlan(rows, q)
		dst := make([]uint64, rowCount)
		powers := make([]uint64, plan.maxDeg+1)
		for trial := 0; trial < 12; trial++ {
			x := uint64(rng.Int63n(int64(q)))
			computeFormalEvalPowers(powers, x, red)
			plan.evalIntoPrepared(dst, x, red, powers)
			for j := range rows {
				want := evalPoly(rows[j], x, q)
				if dst[j] != want {
					t.Fatalf("iter=%d trial=%d row=%d got=%d want=%d", iter, trial, j, dst[j], want)
				}
			}
			plan.evalInto(dst, x, red)
			for j := range rows {
				want := evalPoly(rows[j], x, q)
				if dst[j] != want {
					t.Fatalf("evalInto iter=%d trial=%d row=%d got=%d want=%d", iter, trial, j, dst[j], want)
				}
			}
		}
	}
}
