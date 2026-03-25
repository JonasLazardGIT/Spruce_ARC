package PIOP

import (
	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildFparLinfChainPointwise evaluates the membership-chain residuals on Ω.
func buildFparLinfChainPointwise(r *ring.Ring, P []*ring.Poly, cd ChainDecomp, spec LinfSpec, omega []uint64) (Fpar []*ring.Poly) {
	q := r.Modulus[0]
	if len(omega) == 0 {
		return nil
	}
	coeffTmp := r.NewPoly()
	cache := make(map[*ring.Poly][]uint64, len(P)*signatureChainConstraintCountPerSig(spec))
	evalsOnOmega := func(poly *ring.Poly) []uint64 {
		if poly == nil {
			return make([]uint64, len(omega))
		}
		if vals, ok := cache[poly]; ok {
			return vals
		}
		r.InvNTT(poly, coeffTmp)
		vals := make([]uint64, len(omega))
		for k, w := range omega {
			vals[k] = EvalPoly(coeffTmp.Coeffs[0], w%q, q)
		}
		cache[poly] = vals
		return vals
	}

	for t := 0; t < len(P); t++ {
		pVals := evalsOnOmega(P[t])
		dVals := make([][]uint64, spec.L)
		for i := 0; i < spec.L; i++ {
			dVals[i] = evalsOnOmega(cd.D[t][i])
		}

		if spec.UsesAbsRow {
			mVals := evalsOnOmega(cd.M[t])
			res1 := make([]uint64, len(omega))
			for k := range omega {
				res1[k] = modSub(modMul(mVals[k], mVals[k], q), modMul(pVals[k], pVals[k], q), q)
			}
			Fpar = append(Fpar, BuildThetaPrime(r, res1, omega))

			res2 := make([]uint64, len(omega))
			for k := range omega {
				sum := uint64(0)
				for i := 0; i < spec.L; i++ {
					sum = modAdd(sum, modMul(spec.RPows[i]%q, dVals[i][k], q), q)
				}
				res2[k] = modSub(mVals[k], sum, q)
			}
			Fpar = append(Fpar, BuildThetaPrime(r, res2, omega))
		} else {
			res := make([]uint64, len(omega))
			for k := range omega {
				sum := uint64(0)
				for i := 0; i < spec.L; i++ {
					sum = modAdd(sum, modMul(spec.RPows[i]%q, dVals[i][k], q), q)
				}
				res[k] = modSub(pVals[k], sum, q)
			}
			Fpar = append(Fpar, BuildThetaPrime(r, res, omega))
		}

		for i := 0; i < spec.L; i++ {
			res := make([]uint64, len(omega))
			for k := range omega {
				res[k] = EvalPoly(spec.PDi[i], dVals[i][k]%q, q)
			}
			Fpar = append(Fpar, BuildThetaPrime(r, res, omega))
		}
	}
	return
}

// buildFparLinfChainCompose builds the membership-chain residuals with true
// polynomial composition.
func buildFparLinfChainCompose(r *ring.Ring, P []*ring.Poly, cd ChainDecomp, spec LinfSpec) (Fpar []*ring.Poly) {
	q := r.Modulus[0]
	for t := 0; t < len(P); t++ {
		recon := r.NewPoly()
		tmp := r.NewPoly()
		for i := 0; i < spec.L; i++ {
			scalePolyNTT(r, cd.D[t][i], spec.RPows[i]%q, tmp)
			addInto(r, recon, tmp)
		}
		if spec.UsesAbsRow {
			msq := r.NewPoly()
			psq := r.NewPoly()
			r.MulCoeffs(cd.M[t], cd.M[t], msq)
			r.MulCoeffs(P[t], P[t], psq)
			r.Sub(msq, psq, msq)
			Fpar = append(Fpar, msq)

			assem := r.NewPoly()
			r.Sub(cd.M[t], recon, assem)
			Fpar = append(Fpar, assem)
		} else {
			assem := r.NewPoly()
			r.Sub(P[t], recon, assem)
			Fpar = append(Fpar, assem)
		}

		for i := 0; i < spec.L; i++ {
			Fpar = append(Fpar, composeFPolyWithRowNTT(r, cd.D[t][i], spec.PDi[i]))
		}
	}
	return
}

// composeFPolyWithRowNTT returns the NTT-form polynomial for f(row(X)).
func composeFPolyWithRowNTT(r *ring.Ring, rowNTT *ring.Poly, fCoeffs []uint64) *ring.Poly {
	q := r.Modulus[0]
	resCoeff := r.NewPoly()
	tmpNTT := r.NewPoly()
	for i := len(fCoeffs) - 1; i >= 0; i-- {
		r.NTT(resCoeff, tmpNTT)
		r.MulCoeffs(tmpNTT, rowNTT, tmpNTT)
		r.InvNTT(tmpNTT, resCoeff)
		c := fCoeffs[i] % q
		if c != 0 {
			resCoeff.Coeffs[0][0] = (resCoeff.Coeffs[0][0] + c) % q
		}
	}
	resNTT := r.NewPoly()
	r.NTT(resCoeff, resNTT)
	return resNTT
}

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
