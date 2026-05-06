package decs

import "testing"

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
