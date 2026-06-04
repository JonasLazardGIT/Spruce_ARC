package PIOP

import "github.com/tuneinsight/lattigo/v4/ring"

// ChainDecomp holds magnitude and digit columns for the membership-chain gadget.
type ChainDecomp struct {
	M []*ring.Poly
	D [][]*ring.Poly
}

func liftToField(q uint64, v int64) uint64 {
	if v >= 0 {
		return uint64(v) % q
	}
	neg := uint64(-v) % q
	if neg == 0 {
		return 0
	}
	return (q - neg) % q
}
