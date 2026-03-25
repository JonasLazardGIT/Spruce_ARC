package ntru

import (
	"errors"
	"fmt"
	"os"

	ps "vSIS-Signature/Preimage_Sampler"
)

func (S *Sampler) SamplePreimageTargetOptionB(t ModQPoly, maxTrials int) (s0, s1 *IntPoly, trials int, err error) {
	if S.Opts.ReduceIters <= 0 {
		S.Opts.ReduceIters = 64
	}
	S.Opts.UseCNormalDist = true
	S.Opts.UseExactResidual = true
	S.Opts.BoundShape = "cstyle"
	S.Opts.ApplyDefaults(S.Par)
	if err := S.ReduceTrapdoor(S.Opts.ReduceIters); err != nil {
		return nil, nil, 0, err
	}
	if S.a == nil {
		if err := S.BuildGram(); err != nil {
			return nil, nil, 0, err
		}
	}
	if S.Opts.RSquare <= 0 || S.Opts.Alpha <= 0 {
		return nil, nil, 0, errors.New("OptionB: RSquare and Alpha must be positive")
	}
	if S.Opts.Slack <= 0 {
		return nil, nil, 0, errors.New("OptionB: Slack must be positive")
	}
	if _, _, err := S.ComputeSigmasC(); err != nil {
		return nil, nil, 0, err
	}
	if maxTrials <= 0 {
		maxTrials = 1 << 16
	}
	S.lastS2 = nil
	c0, c1 := S.CentersFromSyndrome(t)
	c1rec := recenterModQ(t, S.Par)
	if debugOn {
		var maxC1 int64
		for _, v := range c1rec {
			if v < 0 {
				v = -v
			}
			if v > maxC1 {
				maxC1 = v
			}
		}
		dbg(os.Stderr, "[OptionB] max|target|=%d\n", maxC1)
	}
	c1Mod := Int64ToModQPoly(c1rec, S.Par)
	h, err := PublicKeyH(Int64ToModQPoly(S.f, S.Par), Int64ToModQPoly(S.g, S.Par), S.Par)
	if err != nil {
		return nil, nil, 0, err
	}
	for trials = 1; trials <= maxTrials; trials++ {
		if trials == 1 || trials%16 == 0 {
			dbg(os.Stderr, "[OptionB] trial=%d\n", trials)
		}
		var z0, z1 []int64
		if debugOn {
			var trace SampleTrace
			var sErr error
			z0, z1, trace, sErr = S.samplePairCExactTrace(c0, c1)
			if sErr != nil {
				continue
			}
			dbg(os.Stderr, "[OptionB] norms: initial=%.4e after1=%.4e after2=%.4e\n", trace.NormInitial, trace.NormAfterStep1, trace.NormAfterStep2)
		} else {
			var sErr error
			z0, z1, sErr = S.samplePairCExact(c0, c1)
			if sErr != nil {
				continue
			}
		}
		z1Coeff := psFromInt64Coeff(z1, S.Prec)
		z0Coeff := psFromInt64Coeff(z0, S.Prec)
		z1Eval := FloatToEvalCFFT(z1Coeff, S.Prec)
		z0Eval := FloatToEvalCFFT(z0Coeff, S.Prec)
		assertSameFlavor("SamplePreimageTargetOptionB:z1", S.b20, z1Eval)
		v1Eval := ps.FieldAddBig(ps.FieldMulBig(S.b10, z0Eval), ps.FieldMulBig(S.b20, z1Eval))
		v2Eval := ps.FieldAddBig(ps.FieldMulBig(S.b11, z0Eval), ps.FieldMulBig(S.b21, z1Eval))
		v1Eval.Domain, v2Eval.Domain = ps.Eval, ps.Eval
		v1Coeff := FloatToCoeffCFFT(v1Eval, S.Prec)
		v2Coeff := FloatToCoeffCFFT(v2Eval, S.Prec)
		n := S.Par.N
		v1Round := make([]int64, n)
		v2Round := make([]int64, n)
		s1i := make([]int64, n)
		for i := 0; i < n; i++ {
			v1, _ := v1Coeff.Coeffs[i].Real.Float64()
			v2, _ := v2Coeff.Coeffs[i].Real.Float64()
			r1 := RoundAwayFromZero(v1)
			r2 := RoundAwayFromZero(v2)
			v1Round[i] = r1
			v2Round[i] = r2
			s1i[i] = -r1
		}
		if debugOn {
			limit := 8
			if n < limit {
				limit = n
			}
			dbg(os.Stderr, "[OptionB] v1Round[0:%d]=%v\n", limit, v1Round[:limit])
			dbg(os.Stderr, "[OptionB] v2Round[0:%d]=%v\n", limit, v2Round[:limit])
		}
		v2Poly := Int64ToModQPoly(v2Round, S.Par)
		residual := c1Mod.Sub(v2Poly)
		s2c := recenterModQ(residual, S.Par)
		S.lastS2 = append(S.lastS2[:0], s2c...)
		if debugOn {
			limit := 8
			if len(s2c) < limit {
				limit = len(s2c)
			}
			dbg(os.Stderr, "[OptionB] s2c[0:%d]=%v\n", limit, s2c[:limit])
		}
		var linf int64
		for _, v := range s2c {
			if v < 0 {
				v = -v
			}
			if v > linf {
				linf = v
			}
		}
		if S.Opts.ResidualLInf > 0 && float64(linf) > S.Opts.ResidualLInf {
			if debugOn {
				dbg(os.Stderr, "[OptionB] reject residual Linf=%d (limit=%.2f)\n", linf, S.Opts.ResidualLInf)
			}
			continue
		}
		sum := normSumBig(v1Round, s2c, S.Par, S.Opts)
		gamma := gammaSqBig(S.Par, S.Opts)
		if ok := sum.Cmp(gamma) <= 0; !ok {
			if debugOn {
				sumF, _ := sum.Float64()
				gammaF, _ := gamma.Float64()
				fmt.Fprintf(os.Stderr, "[OptionB] reject residual (cstyle): sum=%.4g bound=%.4g ratio=%.4f\n", sumF, gammaF, sumF/gammaF)
			}
			continue
		}
		if debugOn {
			sumF, _ := sum.Float64()
			gammaF, _ := gamma.Float64()
			dbg(os.Stderr, "[OptionB] accept residual: sum=%.4g bound=%.4g ratio=%.4f\n", sumF, gammaF, sumF/gammaF)
		}
		s1poly := Int64ToModQPoly(s1i, S.Par)
		hs1, convErr := ConvolveRNS(s1poly, h, S.Par)
		if convErr != nil {
			continue
		}
		s0Q := t.Sub(hs1)
		s0c := recenterModQ(s0Q, S.Par)
		p0 := NewIntPoly(n)
		p1 := NewIntPoly(n)
		for i := 0; i < n; i++ {
			p0.Coeffs[i].SetInt64(s0c[i])
			p1.Coeffs[i].SetInt64(s1i[i])
		}
		return &p0, &p1, trials, nil
	}
	return nil, nil, maxTrials, errors.New("OptionB: too many rejections")
}
