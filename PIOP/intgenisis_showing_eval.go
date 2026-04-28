package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type intGenISISShowingReplayConfig struct {
	Ring         *ring.Ring
	Layout       IntGenISISShowingRowLayout
	DomainPoints []uint64
	ACoeff       [][][]uint64
	BCoeff       [][]uint64
	CMCoeff      [][][]uint64
	ASCoeff      [][][]uint64
}

func newIntGenISISShowingReplayConfig(ringQ *ring.Ring, pub PublicInputs, layout RowLayout, omegaWitness, domainPoints []uint64) (*intGenISISShowingReplayConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if !pub.IntGenISIS {
		return nil, fmt.Errorf("IntGenISIS showing replay requires IntGenISIS public inputs")
	}
	if len(pub.Com) > 0 || len(pub.Ac) > 0 || len(pub.RI0) > 0 || len(pub.RI1) > 0 || len(pub.T) > 0 {
		return nil, fmt.Errorf("IntGenISIS showing public inputs must not include c/Ac/RI0/RI1/T")
	}
	l := layout.IntGenISISShowing
	if l == nil {
		return nil, fmt.Errorf("missing IntGenISIS showing row layout")
	}
	if l.UCount <= 0 || l.MCount != 1 || l.MuSigCount != 1 || l.X0Count != 2 || l.X1Count != 1 || l.ZCount != 1 {
		return nil, fmt.Errorf("invalid IntGenISIS showing row counts")
	}
	if len(pub.A) != 1 || len(pub.A[0]) != l.UCount {
		return nil, fmt.Errorf("A dimensions=%dx? want 1x%d", len(pub.A), l.UCount)
	}
	if len(pub.B) != 3+l.X0Count {
		return nil, fmt.Errorf("B length=%d want %d", len(pub.B), 3+l.X0Count)
	}
	if len(pub.CM) != l.ECount || len(pub.CM[0]) != l.MCount {
		return nil, fmt.Errorf("C_M dimensions mismatch")
	}
	if len(pub.AS) != l.ECount || len(pub.AS[0]) != l.SCount {
		return nil, fmt.Errorf("A_s dimensions mismatch")
	}
	if len(omegaWitness) == 0 || len(domainPoints) == 0 {
		return nil, fmt.Errorf("missing replay domains")
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
	aCoeff := make([][][]uint64, len(pub.A))
	for i := range pub.A {
		aCoeff[i] = make([][]uint64, len(pub.A[i]))
		for j := range pub.A[i] {
			coeff, err := toThetaCoeff(pub.A[i][j], fmt.Sprintf("A[%d][%d]", i, j))
			if err != nil {
				return nil, err
			}
			aCoeff[i][j] = coeff
		}
	}
	bCoeff := make([][]uint64, len(pub.B))
	for i := range pub.B {
		coeff, err := toThetaCoeff(pub.B[i], fmt.Sprintf("B[%d]", i))
		if err != nil {
			return nil, err
		}
		bCoeff[i] = coeff
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
	return &intGenISISShowingReplayConfig{
		Ring:         ringQ,
		Layout:       *l,
		DomainPoints: append([]uint64(nil), domainPoints...),
		ACoeff:       aCoeff,
		BCoeff:       bCoeff,
		CMCoeff:      cmCoeff,
		ASCoeff:      asCoeff,
	}, nil
}

func (cfg *intGenISISShowingReplayConfig) CoreEvaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg == nil || cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil IntGenISIS showing replay config")
		}
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return nil, nil, fmt.Errorf("IntGenISIS showing eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
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
		l := cfg.Layout
		sig := uint64(0)
		for i := 0; i < l.UCount; i++ {
			row, err := getRow(l.UStart + i)
			if err != nil {
				return nil, nil, err
			}
			sig = modAdd(sig, modMul(evalTheta(cfg.ACoeff[0][i]), row, q), q)
		}
		sig = modSub(sig, evalTheta(cfg.BCoeff[0]), q)
		muSig, err := getRow(l.MuSigStart)
		if err != nil {
			return nil, nil, err
		}
		sig = modSub(sig, modMul(evalTheta(cfg.BCoeff[1]), muSig, q), q)
		for i := 0; i < l.X0Count; i++ {
			x0, err := getRow(l.X0Start + i)
			if err != nil {
				return nil, nil, err
			}
			sig = modSub(sig, modMul(evalTheta(cfg.BCoeff[2+i]), x0, q), q)
		}
		z, err := getRow(l.ZStart)
		if err != nil {
			return nil, nil, err
		}
		sig = modSub(sig, z, q)
		m, err := getRow(l.MStart)
		if err != nil {
			return nil, nil, err
		}
		sig = modSub(sig, modMul(evalTheta(cfg.CMCoeff[0][0]), m, q), q)
		for i := 0; i < l.SCount; i++ {
			s, err := getRow(l.SStart + i)
			if err != nil {
				return nil, nil, err
			}
			sig = modSub(sig, modMul(evalTheta(cfg.ASCoeff[0][i]), s, q), q)
		}
		e, err := getRow(l.EStart)
		if err != nil {
			return nil, nil, err
		}
		sig = modSub(sig, e, q)

		x1, err := getRow(l.X1Start)
		if err != nil {
			return nil, nil, err
		}
		inv := modSub(evalTheta(cfg.BCoeff[len(cfg.BCoeff)-1]), x1, q)
		inv = modMul(inv, z, q)
		inv = modSub(inv, 1%q, q)
		return []uint64{sig, inv}, nil, nil
	}
}

func (cfg *intGenISISShowingReplayConfig) CoreKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg == nil || cfg.Ring == nil {
		return nil, fmt.Errorf("nil IntGenISIS showing replay config")
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
		l := cfg.Layout
		sig := K.Zero()
		for i := 0; i < l.UCount; i++ {
			row, err := getRow(l.UStart + i)
			if err != nil {
				return nil, nil, err
			}
			sig = K.Add(sig, K.Mul(evalTheta(cfg.ACoeff[0][i]), row))
		}
		sig = K.Sub(sig, evalTheta(cfg.BCoeff[0]))
		muSig, err := getRow(l.MuSigStart)
		if err != nil {
			return nil, nil, err
		}
		sig = K.Sub(sig, K.Mul(evalTheta(cfg.BCoeff[1]), muSig))
		for i := 0; i < l.X0Count; i++ {
			x0, err := getRow(l.X0Start + i)
			if err != nil {
				return nil, nil, err
			}
			sig = K.Sub(sig, K.Mul(evalTheta(cfg.BCoeff[2+i]), x0))
		}
		z, err := getRow(l.ZStart)
		if err != nil {
			return nil, nil, err
		}
		sig = K.Sub(sig, z)
		m, err := getRow(l.MStart)
		if err != nil {
			return nil, nil, err
		}
		sig = K.Sub(sig, K.Mul(evalTheta(cfg.CMCoeff[0][0]), m))
		for i := 0; i < l.SCount; i++ {
			s, err := getRow(l.SStart + i)
			if err != nil {
				return nil, nil, err
			}
			sig = K.Sub(sig, K.Mul(evalTheta(cfg.ASCoeff[0][i]), s))
		}
		ev, err := getRow(l.EStart)
		if err != nil {
			return nil, nil, err
		}
		sig = K.Sub(sig, ev)

		x1, err := getRow(l.X1Start)
		if err != nil {
			return nil, nil, err
		}
		inv := K.Sub(evalTheta(cfg.BCoeff[len(cfg.BCoeff)-1]), x1)
		inv = K.Mul(inv, z)
		inv = K.Sub(inv, K.EmbedF(1%cfg.Ring.Modulus[0]))
		return []kf.Elem{sig, inv}, nil, nil
	}, nil
}
