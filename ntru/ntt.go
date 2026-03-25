package ntru

import (
	"os"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func ToNTT(r *ring.Ring, a *ring.Poly) {
	r.NTT(a, a)
}

func FromNTT(r *ring.Ring, a *ring.Poly) {
	r.InvNTT(a, a)
}

func MulNTT(r *ring.Ring, a, b, out *ring.Poly) {
	r.MulCoeffsMontgomery(a, b, out)
}
func ConvolveRNS(a, b ModQPoly, p Params) (ModQPoly, error) {
	dbg(os.Stderr, "[NTT] ConvolveRNS begin N=%d limbs=%d\n", p.N, len(p.Qi))
	rings, err := p.BuildRings()
	if err != nil {
		return ModQPoly{}, err
	}
	limbsA := ToRNS(a, p)
	limbsB := ToRNS(b, p)
	resLimbs := make([]*ring.Poly, len(rings))
	for i, r := range rings {
		r.MForm(limbsA[i], limbsA[i])
		r.MForm(limbsB[i], limbsB[i])
		ToNTT(r, limbsA[i])
		ToNTT(r, limbsB[i])
		res := r.NewPoly()
		MulNTT(r, limbsA[i], limbsB[i], res)
		FromNTT(r, res)
		r.InvMForm(res, res)
		resLimbs[i] = res
	}
	res := FromRNS(resLimbs, p)
	dbg(os.Stderr, "[NTT] ConvolveRNS done\n")
	return res, nil
}
