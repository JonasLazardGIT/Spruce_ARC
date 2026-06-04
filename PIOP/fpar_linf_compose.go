package PIOP

import (
	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildFparLinfChainComposeFormalCoeffs returns formal coefficient vectors for
// the replayable ℓ∞ chain constraints.
func buildFparLinfChainComposeFormalCoeffs(r *ring.Ring, P []*ring.Poly, cd ChainDecomp, spec LinfSpec) (Fpar []*ring.Poly, coeffs [][]uint64) {
	if r == nil {
		return nil, nil
	}
	q := r.Modulus[0]

	toFormal := func(pNTT *ring.Poly) fpoly.Poly {
		if pNTT == nil {
			return fpoly.Zero(q)
		}
		coeff := r.NewPoly()
		r.InvNTT(pNTT, coeff)
		return fpoly.New(q, coeff.Coeffs[0])
	}
	toNTTIfFits := func(c []uint64) *ring.Poly {
		if len(c) == 0 {
			c = []uint64{0}
		}
		if len(c) > int(r.N) {
			return nil
		}
		p := r.NewPoly()
		copy(p.Coeffs[0], c)
		r.NTT(p, p)
		return p
	}

	for t := 0; t < len(P); t++ {
		pf := toFormal(P[t])
		recon := fpoly.Zero(q)
		for i := 0; i < spec.L; i++ {
			di := toFormal(cd.D[t][i])
			recon = recon.Add(di.Scale(spec.RPows[i] % q))
		}
		if spec.UsesAbsRow {
			mf := toFormal(cd.M[t])
			// (1) M_t^2 - P_t^2
			c1 := mf.Mul(mf).Sub(pf.Mul(pf))
			coeffs = append(coeffs, append([]uint64(nil), c1.Coeffs...))
			Fpar = append(Fpar, toNTTIfFits(c1.Coeffs))

			// (2) M_t - Σ_i R^i·D_i
			c2 := mf.Sub(recon)
			coeffs = append(coeffs, append([]uint64(nil), c2.Coeffs...))
			Fpar = append(Fpar, toNTTIfFits(c2.Coeffs))
		} else {
			// (1) P_t - Σ_i R^i·D_i
			c1 := pf.Sub(recon)
			coeffs = append(coeffs, append([]uint64(nil), c1.Coeffs...))
			Fpar = append(Fpar, toNTTIfFits(c1.Coeffs))
		}

		// (3) P_{D_i}(D_i(X))
		for i := 0; i < spec.L; i++ {
			di := toFormal(cd.D[t][i])
			pi := fpoly.New(q, spec.PDi[i]).Compose(di)
			coeffs = append(coeffs, append([]uint64(nil), pi.Coeffs...))
			Fpar = append(Fpar, toNTTIfFits(pi.Coeffs))
		}
	}
	return Fpar, coeffs
}
