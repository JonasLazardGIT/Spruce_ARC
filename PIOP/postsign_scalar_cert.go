package PIOP

import (
	"fmt"

	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/internal/fpoly"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// PostSignScalarCertConfig replays the compressed v3 post-sign scalar
// certificate. Replay-facing rows carry the public projections U_sum, X0_sum,
// and X1, while the certificate rows carry a fixed signed radix decomposition
// for each bounded scalar.
type PostSignScalarCertConfig struct {
	Ring *ring.Ring
	Spec LinfSpec

	MsgSumRow int
	RndSumRow int
	X1Row     int

	UScalarCertBase   int
	UScalarCertCount  int
	X0ScalarCertBase  int
	X0ScalarCertCount int
	X1ScalarCertBase  int
	X1ScalarCertCount int

	RowsPerScalar int
}

func (cfg PostSignScalarCertConfig) validate() error {
	if cfg.Ring == nil {
		return fmt.Errorf("nil ring")
	}
	if cfg.Spec.L <= 0 {
		return fmt.Errorf("invalid scalar cert spec L=%d", cfg.Spec.L)
	}
	if cfg.RowsPerScalar <= 0 {
		return fmt.Errorf("invalid rows per scalar %d", cfg.RowsPerScalar)
	}
	if cfg.RowsPerScalar != cfg.Spec.L {
		return fmt.Errorf("rows per scalar=%d want spec.L=%d", cfg.RowsPerScalar, cfg.Spec.L)
	}
	return nil
}

func (cfg PostSignScalarCertConfig) familyRecon(rows []uint64, base, count int, q uint64) (uint64, error) {
	acc := uint64(0)
	for ord := 0; ord < count; ord++ {
		for digit := 0; digit < cfg.RowsPerScalar; digit++ {
			idx := base + ord*cfg.RowsPerScalar + digit
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("scalar cert row idx %d out of range (rows=%d)", idx, len(rows))
			}
			acc = lvcs.MulAddMod64(acc, cfg.Spec.RPows[digit]%q, rows[idx]%q, q)
		}
	}
	return acc % q, nil
}

func (cfg PostSignScalarCertConfig) familyReconK(K *kf.Field, rows []kf.Elem, base, count int) (kf.Elem, error) {
	acc := K.Zero()
	for ord := 0; ord < count; ord++ {
		for digit := 0; digit < cfg.RowsPerScalar; digit++ {
			idx := base + ord*cfg.RowsPerScalar + digit
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("scalar cert row idx %d out of range (rows=%d)", idx, len(rows))
			}
			K.AddMulBaseInto(&acc, rows[idx], cfg.Spec.RPows[digit])
		}
	}
	return acc, nil
}

func (cfg PostSignScalarCertConfig) appendMemberships(rows []uint64, out []uint64, base, count int, q uint64) ([]uint64, error) {
	for ord := 0; ord < count; ord++ {
		for digit := 0; digit < cfg.RowsPerScalar; digit++ {
			idx := base + ord*cfg.RowsPerScalar + digit
			if idx < 0 || idx >= len(rows) {
				return nil, fmt.Errorf("scalar cert row idx %d out of range (rows=%d)", idx, len(rows))
			}
			out = append(out, EvalPoly(cfg.Spec.PDi[digit], rows[idx]%q, q))
		}
	}
	return out, nil
}

func (cfg PostSignScalarCertConfig) appendMembershipsK(K *kf.Field, rows []kf.Elem, out []kf.Elem, base, count int) ([]kf.Elem, error) {
	for ord := 0; ord < count; ord++ {
		for digit := 0; digit < cfg.RowsPerScalar; digit++ {
			idx := base + ord*cfg.RowsPerScalar + digit
			if idx < 0 || idx >= len(rows) {
				return nil, fmt.Errorf("scalar cert row idx %d out of range (rows=%d)", idx, len(rows))
			}
			out = append(out, K.EvalFPolyAtK(cfg.Spec.PDi[digit], rows[idx]))
		}
	}
	return out, nil
}

func (cfg PostSignScalarCertConfig) PostSignScalarCertEvaluator() ConstraintEvaluator {
	return func(_ uint64, rows []uint64) ([]uint64, []uint64, error) {
		if err := cfg.validate(); err != nil {
			return nil, nil, err
		}
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		totalDigits := cfg.RowsPerScalar * (cfg.UScalarCertCount + cfg.X0ScalarCertCount + cfg.X1ScalarCertCount)
		out := make([]uint64, 0, 3+totalDigits)
		msgSum, err := getRow(cfg.MsgSumRow)
		if err != nil {
			return nil, nil, err
		}
		msgRecon, err := cfg.familyRecon(rows, cfg.UScalarCertBase, cfg.UScalarCertCount, q)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, modSub(msgSum, msgRecon, q))
		rndSum, err := getRow(cfg.RndSumRow)
		if err != nil {
			return nil, nil, err
		}
		rndRecon, err := cfg.familyRecon(rows, cfg.X0ScalarCertBase, cfg.X0ScalarCertCount, q)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, modSub(rndSum, rndRecon, q))
		x1Val, err := getRow(cfg.X1Row)
		if err != nil {
			return nil, nil, err
		}
		x1Recon, err := cfg.familyRecon(rows, cfg.X1ScalarCertBase, cfg.X1ScalarCertCount, q)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, modSub(x1Val, x1Recon, q))
		out, err = cfg.appendMemberships(rows, out, cfg.UScalarCertBase, cfg.UScalarCertCount, q)
		if err != nil {
			return nil, nil, err
		}
		out, err = cfg.appendMemberships(rows, out, cfg.X0ScalarCertBase, cfg.X0ScalarCertCount, q)
		if err != nil {
			return nil, nil, err
		}
		out, err = cfg.appendMemberships(rows, out, cfg.X1ScalarCertBase, cfg.X1ScalarCertCount, q)
		if err != nil {
			return nil, nil, err
		}
		return out, nil, nil
	}
}

func (cfg PostSignScalarCertConfig) PostSignScalarCertKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return func(_ kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		totalDigits := cfg.RowsPerScalar * (cfg.UScalarCertCount + cfg.X0ScalarCertCount + cfg.X1ScalarCertCount)
		out := make([]kf.Elem, 0, 3+totalDigits)
		msgSum, err := getRow(cfg.MsgSumRow)
		if err != nil {
			return nil, nil, err
		}
		msgRecon, err := cfg.familyReconK(K, rows, cfg.UScalarCertBase, cfg.UScalarCertCount)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, K.Sub(msgSum, msgRecon))
		rndSum, err := getRow(cfg.RndSumRow)
		if err != nil {
			return nil, nil, err
		}
		rndRecon, err := cfg.familyReconK(K, rows, cfg.X0ScalarCertBase, cfg.X0ScalarCertCount)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, K.Sub(rndSum, rndRecon))
		x1Val, err := getRow(cfg.X1Row)
		if err != nil {
			return nil, nil, err
		}
		x1Recon, err := cfg.familyReconK(K, rows, cfg.X1ScalarCertBase, cfg.X1ScalarCertCount)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, K.Sub(x1Val, x1Recon))
		out, err = cfg.appendMembershipsK(K, rows, out, cfg.UScalarCertBase, cfg.UScalarCertCount)
		if err != nil {
			return nil, nil, err
		}
		out, err = cfg.appendMembershipsK(K, rows, out, cfg.X0ScalarCertBase, cfg.X0ScalarCertCount)
		if err != nil {
			return nil, nil, err
		}
		out, err = cfg.appendMembershipsK(K, rows, out, cfg.X1ScalarCertBase, cfg.X1ScalarCertCount)
		if err != nil {
			return nil, nil, err
		}
		return out, nil, nil
	}, nil
}

func buildPostSignScalarCertFormalCoeffs(r *ring.Ring, rowsNTT []*ring.Poly, cfg PostSignScalarCertConfig) ([]*ring.Poly, [][]uint64, error) {
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}
	if r == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	getPoly := func(idx int) (*ring.Poly, error) {
		if idx < 0 || idx >= len(rowsNTT) {
			return nil, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rowsNTT))
		}
		return rowsNTT[idx], nil
	}
	toFormalCoeffs := func(p *ring.Poly) ([]uint64, error) {
		if p == nil {
			return nil, fmt.Errorf("nil row polynomial")
		}
		return coeffFromNTTPoly(r, p)
	}
	toFormal := func(p *ring.Poly) (fpoly.Poly, error) {
		coeff, err := toFormalCoeffs(p)
		if err != nil {
			return fpoly.Poly{}, err
		}
		return fpoly.New(r.Modulus[0], coeff), nil
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
	buildBridge := func(sumRow, base, count int) ([]uint64, *ring.Poly, error) {
		sumPoly, err := getPoly(sumRow)
		if err != nil {
			return nil, nil, err
		}
		sumFormal, err := toFormal(sumPoly)
		if err != nil {
			return nil, nil, err
		}
		recon := fpoly.Zero(r.Modulus[0])
		for ord := 0; ord < count; ord++ {
			for digit := 0; digit < cfg.RowsPerScalar; digit++ {
				p, err := getPoly(base + ord*cfg.RowsPerScalar + digit)
				if err != nil {
					return nil, nil, err
				}
				dFormal, err := toFormal(p)
				if err != nil {
					return nil, nil, err
				}
				recon = recon.Add(dFormal.Scale(cfg.Spec.RPows[digit] % r.Modulus[0]))
			}
		}
		c := append([]uint64(nil), sumFormal.Sub(recon).Coeffs...)
		return c, toNTTIfFits(c), nil
	}
	appendMemberships := func(Fpar []*ring.Poly, coeffs [][]uint64, base, count int) ([]*ring.Poly, [][]uint64, error) {
		for ord := 0; ord < count; ord++ {
			for digit := 0; digit < cfg.RowsPerScalar; digit++ {
				rowPoly, err := getPoly(base + ord*cfg.RowsPerScalar + digit)
				if err != nil {
					return nil, nil, err
				}
				memNTT := composeFPolyWithRowNTT(r, rowPoly, cfg.Spec.PDi[digit])
				memCoeff, err := coeffFromNTTPoly(r, memNTT)
				if err != nil {
					return nil, nil, err
				}
				Fpar = append(Fpar, memNTT)
				coeffs = append(coeffs, memCoeff)
			}
		}
		return Fpar, coeffs, nil
	}

	Fpar := make([]*ring.Poly, 0, 3+cfg.RowsPerScalar*(cfg.UScalarCertCount+cfg.X0ScalarCertCount+cfg.X1ScalarCertCount))
	coeffs := make([][]uint64, 0, cap(Fpar))
	for _, bridge := range []struct {
		sumRow int
		base   int
		count  int
	}{
		{cfg.MsgSumRow, cfg.UScalarCertBase, cfg.UScalarCertCount},
		{cfg.RndSumRow, cfg.X0ScalarCertBase, cfg.X0ScalarCertCount},
		{cfg.X1Row, cfg.X1ScalarCertBase, cfg.X1ScalarCertCount},
	} {
		c, p, err := buildBridge(bridge.sumRow, bridge.base, bridge.count)
		if err != nil {
			return nil, nil, err
		}
		Fpar = append(Fpar, p)
		coeffs = append(coeffs, c)
	}
	var err error
	Fpar, coeffs, err = appendMemberships(Fpar, coeffs, cfg.UScalarCertBase, cfg.UScalarCertCount)
	if err != nil {
		return nil, nil, err
	}
	Fpar, coeffs, err = appendMemberships(Fpar, coeffs, cfg.X0ScalarCertBase, cfg.X0ScalarCertCount)
	if err != nil {
		return nil, nil, err
	}
	Fpar, coeffs, err = appendMemberships(Fpar, coeffs, cfg.X1ScalarCertBase, cfg.X1ScalarCertCount)
	if err != nil {
		return nil, nil, err
	}
	return Fpar, coeffs, nil
}
