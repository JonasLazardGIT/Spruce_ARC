package PIOP

import (
	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildFparLinfChain builds the parallel constraints for the membership chain.
func buildFparLinfChain(r *ring.Ring, P []*ring.Poly, cd ChainDecomp, spec LinfSpec, omega []uint64) (Fpar []*ring.Poly) {
	q := r.Modulus[0]
	for t := 0; t < len(P); t++ {
		msq := r.NewPoly()
		psq := r.NewPoly()
		r.MulCoeffs(cd.M[t], cd.M[t], msq)
		r.MulCoeffs(P[t], P[t], psq)
		r.Sub(msq, psq, msq)
		Fpar = append(Fpar, msq)

		recon := r.NewPoly()
		tmp := r.NewPoly()
		for i := 0; i < spec.L; i++ {
			scalePolyNTT(r, cd.D[t][i], spec.RPows[i]%q, tmp)
			addInto(r, recon, tmp)
		}
		assem := r.NewPoly()
		r.Sub(cd.M[t], recon, assem)
		Fpar = append(Fpar, assem)

		// Evaluate digit membership on Ω and interpolate the residuals.
		for i := 0; i < spec.L; i++ {
			coeff := r.NewPoly()
			r.InvNTT(cd.D[t][i], coeff)
			vals := make([]uint64, len(omega))
			for j, w := range omega {
				dVal := EvalPoly(coeff.Coeffs[0], w%q, q)
				vals[j] = EvalPoly(spec.PDi[i], dVal%q, q)
			}
			Fpar = append(Fpar, BuildThetaPrime(r, vals, omega))
		}
	}
	return
}
