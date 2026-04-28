package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type intGenISISPreSignReplayConfig struct {
	Ring         *ring.Ring
	Layout       IntGenISISPreSignRowLayout
	DomainPoints []uint64
	CMCoeff      [][][]uint64
	ASCoeff      [][][]uint64
	ComCoeff     [][]uint64
}

func newIntGenISISPreSignReplayConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64) (*intGenISISPreSignReplayConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !pub.IntGenISIS {
		return nil, fmt.Errorf("IntGenISIS replay requires IntGenISIS public inputs")
	}
	if len(pub.Ac) > 0 || len(pub.RI0) > 0 || len(pub.RI1) > 0 || len(pub.T) > 0 || len(pub.B) > 0 {
		return nil, fmt.Errorf("IntGenISIS pre-sign public inputs must not include legacy Ac/RI0/RI1/T/B data")
	}
	if len(pub.Com) == 0 || len(pub.CM) == 0 || len(pub.AS) == 0 {
		return nil, fmt.Errorf("missing IntGenISIS commitment public inputs")
	}
	if len(omegaWitness) == 0 {
		return nil, fmt.Errorf("empty witness omega")
	}
	if len(domainPoints) == 0 {
		return nil, fmt.Errorf("missing explicit domain points")
	}
	l := layout.IntGenISISPreSign
	if l == nil {
		return nil, fmt.Errorf("missing IntGenISIS pre-sign row layout")
	}
	if l.MStart != 0 || l.SStart != l.MCount || l.EStart != l.MCount+l.SCount {
		return nil, fmt.Errorf("invalid IntGenISIS pre-sign row order")
	}
	if l.MCount <= 0 || l.SCount <= 0 || l.ECount <= 0 || l.CommitmentRows <= 0 {
		return nil, fmt.Errorf("invalid IntGenISIS pre-sign row counts")
	}
	if len(pub.Com) != l.CommitmentRows || len(pub.CM) != l.CommitmentRows || len(pub.AS) != l.CommitmentRows || l.ECount != l.CommitmentRows {
		return nil, fmt.Errorf("IntGenISIS commitment dimension mismatch")
	}
	for i := range pub.CM {
		if len(pub.CM[i]) != l.MCount {
			return nil, fmt.Errorf("C_M row %d cols=%d want %d", i, len(pub.CM[i]), l.MCount)
		}
		if len(pub.AS[i]) != l.SCount {
			return nil, fmt.Errorf("A_s row %d cols=%d want %d", i, len(pub.AS[i]), l.SCount)
		}
	}
	toThetaCoeff := func(p *ring.Poly, name string) ([]uint64, error) {
		if p == nil {
			return nil, fmt.Errorf("nil %s", name)
		}
		theta, err := thetaPolyFromNTT(ringQ, p, omegaWitness)
		if err != nil {
			return nil, fmt.Errorf("theta %s: %w", name, err)
		}
		coeff, err := coeffFromNTTPoly(ringQ, theta)
		if err != nil {
			return nil, fmt.Errorf("theta %s coeffs: %w", name, err)
		}
		return trimPoly(coeff, ringQ.Modulus[0]), nil
	}
	cmCoeff := make([][][]uint64, len(pub.CM))
	for i := range pub.CM {
		cmCoeff[i] = make([][]uint64, len(pub.CM[i]))
		for j := range pub.CM[i] {
			coeff, err := toThetaCoeff(pub.CM[i][j], fmt.Sprintf("C_M[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			cmCoeff[i][j] = coeff
		}
	}
	asCoeff := make([][][]uint64, len(pub.AS))
	for i := range pub.AS {
		asCoeff[i] = make([][]uint64, len(pub.AS[i]))
		for j := range pub.AS[i] {
			coeff, err := toThetaCoeff(pub.AS[i][j], fmt.Sprintf("A_s[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			asCoeff[i][j] = coeff
		}
	}
	comCoeff := make([][]uint64, len(pub.Com))
	for i := range pub.Com {
		coeff, err := toThetaCoeff(pub.Com[i], fmt.Sprintf("Com[%d]", i))
		if err != nil {
			return nil, err
		}
		comCoeff[i] = coeff
	}
	return &intGenISISPreSignReplayConfig{
		Ring:         ringQ,
		Layout:       *l,
		DomainPoints: append([]uint64(nil), domainPoints...),
		CMCoeff:      cmCoeff,
		ASCoeff:      asCoeff,
		ComCoeff:     comCoeff,
	}, nil
}

func (cfg *intGenISISPreSignReplayConfig) CoreEvaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil IntGenISIS pre-sign replay config")
		}
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return nil, nil, fmt.Errorf("IntGenISIS pre-sign eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
		}
		q := cfg.Ring.Modulus[0]
		x := cfg.DomainPoints[ptIdx] % q
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		evalTheta := func(coeff []uint64) uint64 {
			if len(coeff) == 0 {
				return 0
			}
			return EvalPoly(coeff, x, q) % q
		}
		fpar := make([]uint64, cfg.Layout.CommitmentRows)
		for out := 0; out < cfg.Layout.CommitmentRows; out++ {
			sum := modSub(0, evalTheta(cfg.ComCoeff[out]), q)
			for j := 0; j < cfg.Layout.MCount; j++ {
				row, err := getRow(cfg.Layout.MStart + j)
				if err != nil {
					return nil, nil, err
				}
				sum = modAdd(sum, modMul(evalTheta(cfg.CMCoeff[out][j]), row, q), q)
			}
			for j := 0; j < cfg.Layout.SCount; j++ {
				row, err := getRow(cfg.Layout.SStart + j)
				if err != nil {
					return nil, nil, err
				}
				sum = modAdd(sum, modMul(evalTheta(cfg.ASCoeff[out][j]), row, q), q)
			}
			row, err := getRow(cfg.Layout.EStart + out)
			if err != nil {
				return nil, nil, err
			}
			sum = modAdd(sum, row, q)
			fpar[out] = sum
		}
		return fpar, nil, nil
	}
}

func (cfg *intGenISISPreSignReplayConfig) CoreKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil IntGenISIS pre-sign replay config")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		evalTheta := func(coeff []uint64) kf.Elem {
			if len(coeff) == 0 {
				return K.Zero()
			}
			return K.EvalFPolyAtK(coeff, e)
		}
		fpar := make([]kf.Elem, cfg.Layout.CommitmentRows)
		for out := 0; out < cfg.Layout.CommitmentRows; out++ {
			sum := K.Sub(K.Zero(), evalTheta(cfg.ComCoeff[out]))
			for j := 0; j < cfg.Layout.MCount; j++ {
				row, err := getRow(cfg.Layout.MStart + j)
				if err != nil {
					return nil, nil, err
				}
				sum = K.Add(sum, K.Mul(evalTheta(cfg.CMCoeff[out][j]), row))
			}
			for j := 0; j < cfg.Layout.SCount; j++ {
				row, err := getRow(cfg.Layout.SStart + j)
				if err != nil {
					return nil, nil, err
				}
				sum = K.Add(sum, K.Mul(evalTheta(cfg.ASCoeff[out][j]), row))
			}
			row, err := getRow(cfg.Layout.EStart + out)
			if err != nil {
				return nil, nil, err
			}
			sum = K.Add(sum, row)
			fpar[out] = sum
		}
		return fpar, nil, nil
	}, nil
}
