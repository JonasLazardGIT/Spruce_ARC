package PIOP

import (
	"fmt"
	"os"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// EvalInput carries explicit-domain data for Eq.(4) replay.
type EvalInput struct {
	EvalPoints []uint64
	Pvals      [][]uint64
	MaskVals   [][]uint64
	Q          []*ring.Poly
	GammaPrime [][][]uint64
	GammaAgg   [][]uint64
	Ring       *ring.Ring
	Omega      []uint64
}

// EvalKInput carries K-point data for Eq.(4) replay.
type EvalKInput struct {
	K                *kf.Field
	KPoints          [][]uint64
	VTargets         [][]uint64
	QK               []*KPoly
	MK               []*KPoly
	GammaPrimeK      [][][]KScalar
	GammaAggK        [][]KScalar
	WitnessCount     int
	Ring             *ring.Ring
	Fpar             []*ring.Poly
	Fagg             []*ring.Poly
	FparOverrideIdxs []int
	BoundRows        []int
	CarryRows        []int
	BoundB           int64
	CarryBound       int64
}

// EvalTailInput carries tail-opening data for Eq.(4) replay.
type EvalTailInput struct {
	Tail       []int
	RowOpen    *decs.DECSOpening
	QOpen      *decs.DECSOpening
	GammaPrime [][][]uint64
	GammaAgg   [][]uint64
	Ring       *ring.Ring
	// DomainPoints is the explicit DECS evaluation domain.
	// When nil, EvaluateConstraintsOnTailOpen treats indices as ring slot indices.
	DomainPoints  []uint64
	RowCount      int
	MaskRowOffset int
	MaskRowCount  int
}

type ConstraintEvaluator func(evalIdx uint64, rowVals []uint64) (fpar []uint64, fagg []uint64, err error)

type KConstraintEvaluator func(e kf.Elem, rowVals []kf.Elem) (fpar []kf.Elem, fagg []kf.Elem, err error)

type ConstraintReplay struct {
	Eval       ConstraintEvaluator
	EvalK      KConstraintEvaluator
	RowCount   int
	BoundRows  []int
	CarryRows  []int
	BoundB     int64
	CarryBound int64
}

func composeEvaluators(a, b ConstraintEvaluator) ConstraintEvaluator {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		fparA, faggA, err := a(evalIdx, rows)
		if err != nil {
			return nil, nil, err
		}
		fparB, faggB, err := b(evalIdx, rows)
		if err != nil {
			return nil, nil, err
		}
		fpar := append(append([]uint64{}, fparA...), fparB...)
		fagg := append(append([]uint64{}, faggA...), faggB...)
		return fpar, fagg, nil
	}
}

func composeKEvaluators(a, b KConstraintEvaluator) KConstraintEvaluator {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		fparA, faggA, err := a(e, rows)
		if err != nil {
			return nil, nil, err
		}
		fparB, faggB, err := b(e, rows)
		if err != nil {
			return nil, nil, err
		}
		fpar := append(append([]kf.Elem{}, fparA...), fparB...)
		fagg := append(append([]kf.Elem{}, faggA...), faggB...)
		return fpar, fagg, nil
	}
}

func ringDomainSlots(r *ring.Ring) ([]uint64, error) {
	if r == nil {
		return nil, fmt.Errorf("nil ring")
	}
	px := r.NewPoly()
	px.Coeffs[0][1] = 1
	pts := r.NewPoly()
	r.NTT(px, pts)
	return pts.Coeffs[0], nil
}

// EvaluateConstraintsOnKPoints replays Eq.(4) at K-points using row values
// reconstructed from VTargets and the provided constraint evaluator.
func EvaluateConstraintsOnKPoints(eval KConstraintEvaluator, in EvalKInput) (bool, error) {
	if eval == nil {
		return false, fmt.Errorf("nil K evaluator")
	}
	if in.K == nil {
		return false, fmt.Errorf("nil K field")
	}
	if len(in.KPoints) == 0 {
		return false, fmt.Errorf("no K points")
	}
	if in.WitnessCount <= 0 {
		return false, fmt.Errorf("invalid witness count")
	}
	if len(in.QK) == 0 || len(in.MK) == 0 {
		return false, fmt.Errorf("missing QK/MK")
	}
	if len(in.VTargets) == 0 || len(in.VTargets[0]) == 0 {
		return false, fmt.Errorf("missing VTargets for K replay")
	}
	if len(in.VTargets)%len(in.KPoints) != 0 {
		return false, fmt.Errorf("invalid VTargets row count %d for |K'|=%d", len(in.VTargets), len(in.KPoints))
	}
	rowsPerPoint := len(in.VTargets) / len(in.KPoints)
	if rowsPerPoint <= 0 {
		return false, fmt.Errorf("invalid rowsPerPoint=%d", rowsPerPoint)
	}
	rho := len(in.QK)
	for kpIdx, limbs := range in.KPoints {
		e := in.K.Phi(limbs)
		rowVals, err := buildRowValsFromVTargets(in.K, in.VTargets, kpIdx, len(in.KPoints), in.WitnessCount)
		if err != nil {
			return false, err
		}
		fpar, fagg, err := eval(e, rowVals)
		if err != nil {
			return false, err
		}
		if len(in.FparOverrideIdxs) > 0 && in.Ring != nil && len(in.Fpar) > 0 {
			tmp := in.Ring.NewPoly()
			for _, idx := range in.FparOverrideIdxs {
				if idx < 0 || idx >= len(fpar) || idx >= len(in.Fpar) || in.Fpar[idx] == nil {
					continue
				}
				in.Ring.InvNTT(in.Fpar[idx], tmp)
				fpar[idx] = in.K.EvalFPolyAtK(tmp.Coeffs[0], e)
			}
		}
		for i := 0; i < rho; i++ {
			if i >= len(in.MK) || in.QK[i] == nil || in.MK[i] == nil {
				return false, fmt.Errorf("missing K polys at row %d", i)
			}
			lhs := evalKPolyAtK(in.K, in.QK[i], e)
			rhs := evalKPolyAtK(in.K, in.MK[i], e)
			if i < len(in.GammaPrimeK) {
				rowGamma := in.GammaPrimeK[i]
				for j, val := range fpar {
					if j >= len(rowGamma) {
						continue
					}
					g := evalKScalarPolyAtK(in.K, rowGamma[j], e)
					rhs = in.K.Add(rhs, in.K.Mul(g, val))
				}
			}
			if i < len(in.GammaAggK) {
				rowGamma := in.GammaAggK[i]
				for j, val := range fagg {
					if j >= len(rowGamma) {
						continue
					}
					g := in.K.Phi(rowGamma[j])
					rhs = in.K.Add(rhs, in.K.Mul(g, val))
				}
			}
			if !elemEqual(in.K, lhs, rhs) {
				if os.Getenv("PIOP_DEBUG_EQ4_K") == "1" && kpIdx == 0 && i == 0 {
					var gammaPrimeLen, gammaAggLen int
					if i < len(in.GammaPrimeK) {
						gammaPrimeLen = len(in.GammaPrimeK[i])
					}
					if i < len(in.GammaAggK) {
						gammaAggLen = len(in.GammaAggK[i])
					}
					fmt.Printf("[PIOP_DEBUG_EQ4_K] mismatch kp=%d row=%d witnessCount=%d theta=%d fpar=%d fagg=%d gammaPrime=%d gammaAgg=%d\n",
						kpIdx, i, in.WitnessCount, in.K.Theta, len(fpar), len(fagg), gammaPrimeLen, gammaAggLen)
					if len(in.Fpar) > 0 {
						limit := len(fpar)
						if limit > len(in.Fpar) {
							limit = len(in.Fpar)
						}
						if limit > gammaPrimeLen {
							limit = gammaPrimeLen
						}
						mism := 0
						for j := 0; j < limit && mism < 8; j++ {
							if in.Fpar[j] == nil || in.Ring == nil {
								continue
							}
							tmp := in.Ring.NewPoly()
							in.Ring.InvNTT(in.Fpar[j], tmp)
							polyVal := in.K.EvalFPolyAtK(tmp.Coeffs[0], e)
							if !elemEqual(in.K, polyVal, fpar[j]) {
								fmt.Printf("[PIOP_DEBUG_EQ4_K] fpar[%d] poly!=eval\n", j)
								mism++
							}
						}
					}
					if len(in.Fagg) > 0 {
						limit := len(fagg)
						if limit > len(in.Fagg) {
							limit = len(in.Fagg)
						}
						if limit > gammaAggLen {
							limit = gammaAggLen
						}
						mism := 0
						for j := 0; j < limit && mism < 8; j++ {
							if in.Fagg[j] == nil || in.Ring == nil {
								continue
							}
							tmp := in.Ring.NewPoly()
							in.Ring.InvNTT(in.Fagg[j], tmp)
							polyVal := in.K.EvalFPolyAtK(tmp.Coeffs[0], e)
							if !elemEqual(in.K, polyVal, fagg[j]) {
								fmt.Printf("[PIOP_DEBUG_EQ4_K] fagg[%d] poly!=eval\n", j)
								mism++
							}
						}
					}
				}
				return false, fmt.Errorf("eq4 K-point mismatch at kp=%d row=%d", kpIdx, i)
			}
		}
	}
	return true, nil
}

// EvaluateConstraintsOnTailOpen replays Eq.(4) at the tail indices using row
// openings and a constraint evaluator. It uses mask evaluations from MaskOpen.
func EvaluateConstraintsOnTailOpen(eval ConstraintEvaluator, in EvalTailInput) (bool, error) {
	if eval == nil {
		return false, fmt.Errorf("nil evaluator")
	}
	if in.Ring == nil {
		return false, fmt.Errorf("nil ring")
	}
	if in.RowOpen == nil {
		return false, fmt.Errorf("nil row opening")
	}
	if len(in.Tail) == 0 {
		return false, fmt.Errorf("no tail indices")
	}
	if in.QOpen == nil {
		return false, fmt.Errorf("missing Q opening")
	}
	q := in.Ring.Modulus[0]
	points := in.DomainPoints
	pointAt := func(idx int) (uint64, error) {
		if idx < 0 {
			return 0, fmt.Errorf("invalid tail index %d", idx)
		}
		if idx >= len(points) {
			return 0, fmt.Errorf("tail idx %d out of range for explicit domain (len=%d)", idx, len(points))
		}
		return points[idx] % q, nil
	}
	if len(points) == 0 {
		ringSlots, lerr := ringDomainSlots(in.Ring)
		if lerr != nil {
			return false, lerr
		}
		pointAt = func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(ringSlots) {
				return 0, fmt.Errorf("invalid ring slot %d", idx)
			}
			return ringSlots[idx] % q, nil
		}
	}
	rowCount := in.RowCount
	if rowCount <= 0 {
		if in.RowOpen.R > 0 {
			rowCount = in.RowOpen.R
		} else if len(in.RowOpen.Pvals) > 0 {
			rowCount = len(in.RowOpen.Pvals[0])
		}
	}
	if rowCount <= 0 {
		return false, fmt.Errorf("invalid row count")
	}
	openRowCount := in.RowOpen.R
	if openRowCount <= 0 && len(in.RowOpen.Pvals) > 0 {
		openRowCount = len(in.RowOpen.Pvals[0])
	}
	if openRowCount <= 0 {
		return false, fmt.Errorf("invalid row opening row count")
	}
	posByIdxRow := make(map[int]int, in.RowOpen.EntryCount())
	for pos := 0; pos < in.RowOpen.EntryCount(); pos++ {
		posByIdxRow[in.RowOpen.IndexAt(pos)] = pos
	}
	posByIdxQ := make(map[int]int, in.QOpen.EntryCount())
	for pos := 0; pos < in.QOpen.EntryCount(); pos++ {
		posByIdxQ[in.QOpen.IndexAt(pos)] = pos
	}
	rho := in.QOpen.R
	if rho <= 0 {
		return false, fmt.Errorf("invalid Q opening row count R=%d", rho)
	}
	maskRowOffset := in.MaskRowOffset
	maskRowCount := in.MaskRowCount
	if maskRowOffset < 0 {
		return false, fmt.Errorf("invalid mask row offset %d", maskRowOffset)
	}
	if maskRowCount < rho {
		return false, fmt.Errorf("mask row count %d < rho=%d", maskRowCount, rho)
	}
	if maskRowOffset+rho > openRowCount {
		return false, fmt.Errorf("mask rows [%d,%d) exceed opening row count %d", maskRowOffset, maskRowOffset+rho, openRowCount)
	}
	for _, idx := range in.Tail {
		posRow, ok := posByIdxRow[idx]
		if !ok {
			return false, fmt.Errorf("row opening missing idx %d", idx)
		}
		posQ, ok := posByIdxQ[idx]
		if !ok {
			return false, fmt.Errorf("Q opening missing idx %d", idx)
		}
		rowVals := make([]uint64, rowCount)
		for j := 0; j < rowCount; j++ {
			rowVals[j] = decs.GetOpeningPval(in.RowOpen, posRow, j) % q
		}
		fpar, fagg, err := eval(uint64(idx), rowVals)
		if err != nil {
			return false, err
		}
		x, xerr := pointAt(idx)
		if xerr != nil {
			return false, xerr
		}
		for i := 0; i < rho; i++ {
			var lhs uint64
			lhs = decs.GetOpeningPval(in.QOpen, posQ, i) % q
			rhs := decs.GetOpeningPval(in.RowOpen, posRow, maskRowOffset+i) % q
			if i < len(in.GammaPrime) {
				rowGamma := in.GammaPrime[i]
				for j, val := range fpar {
					if j >= len(rowGamma) {
						continue
					}
					g := EvalPoly(rowGamma[j], x, q) % q
					rhs = lvcs.MulAddMod64(rhs, g, val%q, q)
				}
			}
			if i < len(in.GammaAgg) {
				rowGamma := in.GammaAgg[i]
				for j, val := range fagg {
					if j >= len(rowGamma) {
						continue
					}
					rhs = lvcs.MulAddMod64(rhs, rowGamma[j]%q, val%q, q)
				}
			}
			if lhs != rhs {
				return false, fmt.Errorf("eq4 tail replay mismatch idx=%d row=%d lhs=%d rhs=%d", idx, i, lhs, rhs)
			}
		}
	}
	return true, nil
}

// CredentialConstraintConfig carries the row indices and public parameters
// needed to recompute the current credential constraints from row evaluations.
type CredentialConstraintConfig struct {
	Ring  *ring.Ring
	Ac    [][]*ring.Poly
	B     []*ring.Poly
	Com   []*ring.Poly
	RI0   []*ring.Poly
	RI1   []*ring.Poly
	Bound int64
	// CarryBound is used for K0/K1 carry rows; defaults to 1 when set.
	CarryBound int64

	TPublicNTT *ring.Poly // optional: public T in NTT domain

	// Packing selector values over the evaluation domain (NTT).
	PackingSelNTT []uint64
	PackingNCols  int

	IdxM1  int
	IdxM2  int
	IdxRU0 int
	IdxRU1 int
	IdxR   int
	IdxR0  int
	IdxR1  int
	IdxK0  int
	IdxK1  int
	IdxT   int // optional: T as witness row

	BoundRows []int
	CarryRows []int

	Omega []uint64
	// DomainPoints is the explicit DECS evaluation domain.
	// When nil, evaluators interpret evalIdx as a ring slot index.
	DomainPoints []uint64
}

func buildLagrangeBasisCoeffs(omega []uint64, q uint64) ([][]uint64, error) {
	plan, err := buildInterpolationPlan(omega, q)
	if err != nil {
		return nil, err
	}
	out := make([][]uint64, len(plan.basis))
	for i := range plan.basis {
		out[i] = append([]uint64(nil), plan.basis[i]...)
	}
	return out, nil
}

// SigCoeffBoundsConfig replays the signature coefficient bound chain and its
// aggregated NTT-to-coefficient bridge.
type SigCoeffBoundsConfig struct {
	Ring *ring.Ring

	Spec       LinfSpec
	Mode       string
	PackedPlan []int

	CoefBase           int
	CoefCount          int
	PackedSourceBase   int
	PackedSourceCount  int
	ChainBase          int
	ChainRowsPer       int
	PackedChainBase    int
	PackedGroupCount   int
	PackedGroupSize    int
	PackedRowsPerGroup int

	Omega        []uint64
	DomainPoints []uint64

	Layout       RowLayout
	Root         [16]byte
	BridgeChecks int
}

type sigNTTBridgeEvalCache struct {
	q              uint64
	ncols          int
	blocks         int
	componentCount int

	alpha  [][]uint64
	rTheta [][][]uint64
	sTheta [][][]uint64
}

func buildRowSetNTTBridgeEvalCache(ringQ *ring.Ring, omega []uint64, root [16]byte, label string, checks int, blocks int, componentCount int) (*sigNTTBridgeEvalCache, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	if checks <= 0 {
		return nil, fmt.Errorf("invalid bridge check count %d", checks)
	}
	if blocks <= 0 || componentCount <= 0 {
		return nil, nil
	}
	if label == "" {
		label = "RowSetNTTBridge"
	}
	q := ringQ.Modulus[0]
	ncols := len(omega)
	rng := newFSRNG(label, root[:], bytesU64Vec([]uint64{uint64(ncols), uint64(blocks), uint64(componentCount)}))

	alpha := make([][]uint64, checks)
	rTheta := make([][][]uint64, checks)
	sTheta := make([][][]uint64, checks)

	sampleVector := func() []uint64 {
		v := make([]uint64, ringQ.N)
		for i := 0; i < int(ringQ.N); i++ {
			v[i] = rng.nextU64() % q
		}
		return v
	}

	for t := 0; t < checks; t++ {
		alpha[t] = make([]uint64, componentCount)
		for j := 0; j < componentCount; j++ {
			alpha[t][j] = rng.nextU64() % q
		}
		rVec := sampleVector()
		sVec, err := TransposeNTTVector(ringQ, rVec)
		if err != nil {
			return nil, fmt.Errorf("transpose NTT: %w", err)
		}
		rTheta[t] = make([][]uint64, blocks)
		sTheta[t] = make([][]uint64, blocks)
		for b := 0; b < blocks; b++ {
			start := b * ncols
			end := start + ncols
			rTheta[t][b] = Interpolate(omega, rVec[start:end], q)
			sTheta[t][b] = Interpolate(omega, sVec[start:end], q)
		}
	}
	return &sigNTTBridgeEvalCache{
		q:              q,
		ncols:          ncols,
		blocks:         blocks,
		componentCount: componentCount,
		alpha:          alpha,
		rTheta:         rTheta,
		sTheta:         sTheta,
	}, nil
}

func (cfg SigCoeffBoundsConfig) SigCoeffBoundsEvaluator() ConstraintEvaluator {
	if len(cfg.DomainPoints) == 0 {
		return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
			return nil, nil, fmt.Errorf("sig-coeff replay config: missing domain points for explicit evaluator")
		}
	}
	return cfg.sigCoeffBoundsEvaluator(func(evalIdx uint64, q uint64) (uint64, error) {
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return 0, fmt.Errorf("bridge eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
		}
		return cfg.DomainPoints[ptIdx] % q, nil
	})
}

func (cfg SigCoeffBoundsConfig) sigCoeffBoundsEvaluator(evalPoint func(evalIdx uint64, q uint64) (uint64, error)) ConstraintEvaluator {
	var lagrangeBasis [][]uint64
	var lagrangeErr error
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil ring")
		}
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}

		if cfg.Spec.L <= 0 {
			return nil, nil, fmt.Errorf("invalid LinfSpec L=%d", cfg.Spec.L)
		}
		wantRowsPer, err := signaturePackedChainRowsPerGroupForOpts(cfg.Spec, SimOpts{}, cfg.PackedGroupSize)
		if err != nil {
			return nil, nil, err
		}
		if cfg.PackedRowsPerGroup != wantRowsPer {
			return nil, nil, fmt.Errorf("invalid packed chain rows-per-group=%d want %d", cfg.PackedRowsPerGroup, wantRowsPer)
		}
		wantConstraints := cfg.Spec.L
		if !rowLayoutCoeffNativeUsesLiteralPackedV3(cfg.Layout) {
			var err error
			wantConstraints, err = signaturePackedChainConstraintCountPerGroupForOpts(cfg.Spec, SimOpts{}, cfg.PackedGroupSize)
			if err != nil {
				return nil, nil, err
			}
		}
		fpar := make([]uint64, 0, cfg.PackedGroupCount*wantConstraints)
		if lagrangeBasis == nil && lagrangeErr == nil {
			lagrangeBasis, lagrangeErr = buildLagrangeBasisCoeffs(cfg.Omega, q)
		}
		if lagrangeErr != nil {
			return nil, nil, lagrangeErr
		}
		x, err := evalPoint(evalIdx, q)
		if err != nil {
			return nil, nil, err
		}
		lambdas := make([]uint64, len(lagrangeBasis))
		for i := range lagrangeBasis {
			lambdas[i] = EvalPoly(lagrangeBasis[i], x%q, q) % q
		}
		_ = lambdas
		for g := 0; g < cfg.PackedGroupCount; g++ {
			base := cfg.PackedChainBase + g*cfg.PackedRowsPerGroup
			if !rowLayoutCoeffNativeUsesLiteralPackedV3(cfg.Layout) {
				if cfg.PackedSourceCount > 0 && g >= cfg.PackedSourceCount {
					return nil, nil, fmt.Errorf("packed source group %d out of range (count=%d)", g, cfg.PackedSourceCount)
				}
				sPack, err := getRow(cfg.PackedSourceBase + g)
				if err != nil {
					return nil, nil, err
				}
				recon := uint64(0)
				for i := 0; i < cfg.Spec.L; i++ {
					dVal, err := getRow(base + i)
					if err != nil {
						return nil, nil, err
					}
					recon = lvcs.MulAddMod64(recon, cfg.Spec.RPows[i], dVal, q)
				}
				if sPack >= recon {
					fpar = append(fpar, (sPack-recon)%q)
				} else {
					fpar = append(fpar, (sPack+q-recon)%q)
				}
			}
			for i := 0; i < cfg.Spec.L; i++ {
				dVal, err := getRow(base + i)
				if err != nil {
					return nil, nil, err
				}
				fpar = append(fpar, EvalPoly(cfg.Spec.PDi[i], dVal%q, q))
			}
		}
		return fpar, nil, nil
	}
}

func (cfg SigCoeffBoundsConfig) SigCoeffBoundsKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if cfg.Spec.L <= 0 {
		return nil, fmt.Errorf("invalid LinfSpec L=%d", cfg.Spec.L)
	}
	var lagrangeBasis [][]uint64
	var lagrangeErr error
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}

		wantRowsPer, err := signaturePackedChainRowsPerGroupForOpts(cfg.Spec, SimOpts{}, cfg.PackedGroupSize)
		if err != nil {
			return nil, nil, err
		}
		if cfg.PackedRowsPerGroup != wantRowsPer {
			return nil, nil, fmt.Errorf("invalid packed chain rows-per-group=%d want %d", cfg.PackedRowsPerGroup, wantRowsPer)
		}
		wantConstraints := cfg.Spec.L
		if !rowLayoutCoeffNativeUsesLiteralPackedV3(cfg.Layout) {
			var err error
			wantConstraints, err = signaturePackedChainConstraintCountPerGroupForOpts(cfg.Spec, SimOpts{}, cfg.PackedGroupSize)
			if err != nil {
				return nil, nil, err
			}
		}
		fpar := make([]kf.Elem, 0, cfg.PackedGroupCount*wantConstraints)
		if lagrangeBasis == nil && lagrangeErr == nil {
			lagrangeBasis, lagrangeErr = buildLagrangeBasisCoeffs(cfg.Omega, cfg.Ring.Modulus[0])
		}
		if lagrangeErr != nil {
			return nil, nil, lagrangeErr
		}
		lambdas := make([]kf.Elem, len(lagrangeBasis))
		for i := range lagrangeBasis {
			lambdas[i] = K.EvalFPolyAtK(lagrangeBasis[i], e)
		}
		_ = lambdas
		for g := 0; g < cfg.PackedGroupCount; g++ {
			base := cfg.PackedChainBase + g*cfg.PackedRowsPerGroup
			if !rowLayoutCoeffNativeUsesLiteralPackedV3(cfg.Layout) {
				if cfg.PackedSourceCount > 0 && g >= cfg.PackedSourceCount {
					return nil, nil, fmt.Errorf("packed source group %d out of range (count=%d)", g, cfg.PackedSourceCount)
				}
				sPack, err := getRow(cfg.PackedSourceBase + g)
				if err != nil {
					return nil, nil, err
				}
				recon := K.Zero()
				for i := 0; i < cfg.Spec.L; i++ {
					dVal, err := getRow(base + i)
					if err != nil {
						return nil, nil, err
					}
					K.AddMulBaseInto(&recon, dVal, cfg.Spec.RPows[i])
				}
				fpar = append(fpar, K.Sub(sPack, recon))
			}
			for i := 0; i < cfg.Spec.L; i++ {
				dVal, err := getRow(base + i)
				if err != nil {
					return nil, nil, err
				}
				fpar = append(fpar, K.EvalFPolyAtK(cfg.Spec.PDi[i], dVal))
			}
		}
		return fpar, nil, nil
	}, nil
}

// NonSigBoundChainConfig replays the low-degree non-signature BoundB chain.
type NonSigBoundChainConfig struct {
	Ring *ring.Ring
	Spec LinfSpec

	SourceRows   []int
	SourceSlots  []PRFSlot
	ChainBases   []int
	MsgChainBase int
	RndChainBase int
	Omega        []uint64
	DomainPoints []uint64
}

func (cfg NonSigBoundChainConfig) sourceRowsAndBases() ([]int, []int, error) {
	if cfg.Spec.L <= 0 {
		return nil, nil, fmt.Errorf("invalid non-sig chain spec L=%d", cfg.Spec.L)
	}
	if len(cfg.SourceRows) == 0 {
		cfg.SourceRows = rowLayoutPostSignBoundRows(RowLayout{})
	}
	if len(cfg.SourceRows) == 0 {
		return nil, nil, fmt.Errorf("empty non-sig chain source rows")
	}
	if len(cfg.ChainBases) > 0 {
		if len(cfg.ChainBases) != len(cfg.SourceRows) {
			return nil, nil, fmt.Errorf("non-sig chain bases len=%d want %d", len(cfg.ChainBases), len(cfg.SourceRows))
		}
		return append([]int(nil), cfg.SourceRows...), append([]int(nil), cfg.ChainBases...), nil
	}
	if cfg.MsgChainBase < 0 || cfg.RndChainBase < 0 {
		return nil, nil, fmt.Errorf("invalid non-sig chain bases (msg=%d rnd=%d)", cfg.MsgChainBase, cfg.RndChainBase)
	}
	rowsPer := 1 + cfg.Spec.L
	switch len(cfg.SourceRows) {
	case 4:
		return append([]int(nil), cfg.SourceRows...), []int{
			cfg.MsgChainBase,
			cfg.MsgChainBase + rowsPer,
			cfg.RndChainBase,
			cfg.RndChainBase + rowsPer,
		}, nil
	default:
		return nil, nil, fmt.Errorf("non-sig chain requires explicit ChainBases for %d source rows", len(cfg.SourceRows))
	}
}

func (cfg NonSigBoundChainConfig) NonSigBoundChainEvaluator() ConstraintEvaluator {
	var lagrangeBasis [][]uint64
	var lagrangeErr error
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil ring")
		}
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		if len(cfg.SourceSlots) > 0 {
			if len(cfg.ChainBases) != len(cfg.SourceSlots) {
				return nil, nil, fmt.Errorf("non-sig source slots len=%d want chain bases len=%d", len(cfg.SourceSlots), len(cfg.ChainBases))
			}
			if len(cfg.DomainPoints) == 0 {
				return nil, nil, fmt.Errorf("non-sig slot bound chain missing domain points")
			}
			if lagrangeBasis == nil && lagrangeErr == nil {
				lagrangeBasis, lagrangeErr = buildLagrangeBasisCoeffs(cfg.Omega, q)
			}
			if lagrangeErr != nil {
				return nil, nil, lagrangeErr
			}
			ptIdx := int(evalIdx)
			if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
				return nil, nil, fmt.Errorf("non-sig slot eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
			}
			x := cfg.DomainPoints[ptIdx] % q
			lambdas := make([]uint64, len(lagrangeBasis))
			for i := range lagrangeBasis {
				lambdas[i] = EvalPoly(lagrangeBasis[i], x, q) % q
			}
			out := make([]uint64, 0, len(cfg.SourceSlots)*(2+cfg.Spec.L))
			for t := 0; t < len(cfg.SourceSlots); t++ {
				slot := cfg.SourceSlots[t]
				if slot.Row < 0 || slot.Row >= len(rows) {
					return nil, nil, fmt.Errorf("non-sig slot row %d out of range (rows=%d)", slot.Row, len(rows))
				}
				if slot.Col < 0 || slot.Col >= len(lambdas) {
					return nil, nil, fmt.Errorf("non-sig slot col %d out of range (lambdas=%d)", slot.Col, len(lambdas))
				}
				p := lvcs.MulMod64(rows[slot.Row]%q, lambdas[slot.Col]%q, q)
				base := cfg.ChainBases[t]
				m, err := getRow(base)
				if err != nil {
					return nil, nil, err
				}
				msq := lvcs.MulMod64(m, m, q)
				psq := lvcs.MulMod64(p, p, q)
				if msq >= psq {
					out = append(out, (msq-psq)%q)
				} else {
					out = append(out, (msq+q-psq)%q)
				}
				var recon uint64
				for i := 0; i < cfg.Spec.L; i++ {
					dVal, derr := getRow(base + 1 + i)
					if derr != nil {
						return nil, nil, derr
					}
					recon = lvcs.MulAddMod64(recon, cfg.Spec.RPows[i]%q, dVal, q)
				}
				if m >= recon {
					out = append(out, (m-recon)%q)
				} else {
					out = append(out, (m+q-recon)%q)
				}
				for i := 0; i < cfg.Spec.L; i++ {
					dVal, derr := getRow(base + 1 + i)
					if derr != nil {
						return nil, nil, derr
					}
					out = append(out, EvalPoly(cfg.Spec.PDi[i], dVal%q, q))
				}
			}
			return out, nil, nil
		}
		srcRows, bases, err := cfg.sourceRowsAndBases()
		if err != nil {
			return nil, nil, err
		}
		out := make([]uint64, 0, len(srcRows)*(2+cfg.Spec.L))
		for t := 0; t < len(srcRows); t++ {
			p, err := getRow(srcRows[t])
			if err != nil {
				return nil, nil, err
			}
			base := bases[t]
			m, err := getRow(base)
			if err != nil {
				return nil, nil, err
			}
			// (1) M^2 - P^2
			msq := lvcs.MulMod64(m, m, q)
			psq := lvcs.MulMod64(p, p, q)
			if msq >= psq {
				out = append(out, (msq-psq)%q)
			} else {
				out = append(out, (msq+q-psq)%q)
			}
			// (2) M - Σ_i R^i·D_i
			var recon uint64
			for i := 0; i < cfg.Spec.L; i++ {
				dVal, derr := getRow(base + 1 + i)
				if derr != nil {
					return nil, nil, derr
				}
				recon = lvcs.MulAddMod64(recon, cfg.Spec.RPows[i]%q, dVal, q)
			}
			if m >= recon {
				out = append(out, (m-recon)%q)
			} else {
				out = append(out, (m+q-recon)%q)
			}
			// (3) Digit memberships P_{D_i}(D_i).
			for i := 0; i < cfg.Spec.L; i++ {
				dVal, derr := getRow(base + 1 + i)
				if derr != nil {
					return nil, nil, derr
				}
				out = append(out, EvalPoly(cfg.Spec.PDi[i], dVal%q, q))
			}
		}
		return out, nil, nil
	}
}

func (cfg NonSigBoundChainConfig) NonSigBoundChainKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	srcRows, bases, err := cfg.sourceRowsAndBases()
	if err != nil && len(cfg.SourceSlots) == 0 {
		return nil, err
	}
	var lagrangeBasis [][]uint64
	var lagrangeErr error
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		if len(cfg.SourceSlots) > 0 {
			if len(cfg.ChainBases) != len(cfg.SourceSlots) {
				return nil, nil, fmt.Errorf("non-sig source slots len=%d want chain bases len=%d", len(cfg.SourceSlots), len(cfg.ChainBases))
			}
			if lagrangeBasis == nil && lagrangeErr == nil {
				lagrangeBasis, lagrangeErr = buildLagrangeBasisCoeffs(cfg.Omega, cfg.Ring.Modulus[0])
			}
			if lagrangeErr != nil {
				return nil, nil, lagrangeErr
			}
			lambdas := make([]kf.Elem, len(lagrangeBasis))
			for i := range lagrangeBasis {
				lambdas[i] = K.EvalFPolyAtK(lagrangeBasis[i], e)
			}
			out := make([]kf.Elem, 0, len(cfg.SourceSlots)*(2+cfg.Spec.L))
			for t := 0; t < len(cfg.SourceSlots); t++ {
				slot := cfg.SourceSlots[t]
				if slot.Row < 0 || slot.Row >= len(rows) {
					return nil, nil, fmt.Errorf("non-sig slot row %d out of range (rows=%d)", slot.Row, len(rows))
				}
				if slot.Col < 0 || slot.Col >= len(lambdas) {
					return nil, nil, fmt.Errorf("non-sig slot col %d out of range (lambdas=%d)", slot.Col, len(lambdas))
				}
				p := K.Mul(rows[slot.Row], lambdas[slot.Col])
				base := cfg.ChainBases[t]
				m, err := getRow(base)
				if err != nil {
					return nil, nil, err
				}
				out = append(out, K.Sub(K.Mul(m, m), K.Mul(p, p)))
				recon := K.Zero()
				for i := 0; i < cfg.Spec.L; i++ {
					dVal, derr := getRow(base + 1 + i)
					if derr != nil {
						return nil, nil, derr
					}
					K.AddMulBaseInto(&recon, dVal, cfg.Spec.RPows[i])
				}
				out = append(out, K.Sub(m, recon))
				for i := 0; i < cfg.Spec.L; i++ {
					dVal, derr := getRow(base + 1 + i)
					if derr != nil {
						return nil, nil, derr
					}
					out = append(out, K.EvalFPolyAtK(cfg.Spec.PDi[i], dVal))
				}
			}
			return out, nil, nil
		}
		out := make([]kf.Elem, 0, len(srcRows)*(2+cfg.Spec.L))
		for t := 0; t < len(srcRows); t++ {
			p, err := getRow(srcRows[t])
			if err != nil {
				return nil, nil, err
			}
			base := bases[t]
			m, err := getRow(base)
			if err != nil {
				return nil, nil, err
			}
			// (1) M^2 - P^2
			out = append(out, K.Sub(K.Mul(m, m), K.Mul(p, p)))
			// (2) M - Σ_i R^i·D_i
			recon := K.Zero()
			for i := 0; i < cfg.Spec.L; i++ {
				dVal, derr := getRow(base + 1 + i)
				if derr != nil {
					return nil, nil, derr
				}
				K.AddMulBaseInto(&recon, dVal, cfg.Spec.RPows[i])
			}
			out = append(out, K.Sub(m, recon))
			// (3) Digit memberships.
			for i := 0; i < cfg.Spec.L; i++ {
				dVal, derr := getRow(base + 1 + i)
				if derr != nil {
					return nil, nil, derr
				}
				out = append(out, K.EvalFPolyAtK(cfg.Spec.PDi[i], dVal))
			}
		}
		return out, nil, nil
	}, nil
}

// NonSigNTTBridgeConfig replays aggregated NTT↔coefficient bridges for
// non-signature showing families (message/randomness/x1-like rows).
type NonSigNTTBridgeConfig struct {
	Ring         *ring.Ring
	Omega        []uint64
	DomainPoints []uint64
	Layout       RowLayout
	Families     []nonSigBridgeFamily
	Root         [16]byte
	BridgeChecks int
}

func (cfg NonSigNTTBridgeConfig) NonSigBridgeEvaluator() ConstraintEvaluator {
	if len(cfg.DomainPoints) == 0 {
		return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
			return nil, nil, fmt.Errorf("non-sig bridge replay config: missing domain points for explicit evaluator")
		}
	}
	return cfg.nonSigBridgeEvaluator(func(evalIdx uint64, q uint64) (uint64, error) {
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return 0, fmt.Errorf("bridge eval idx %d out of range (|E|=%d)", ptIdx, len(cfg.DomainPoints))
		}
		return cfg.DomainPoints[ptIdx] % q, nil
	})
}

func (cfg NonSigNTTBridgeConfig) nonSigBridgeEvaluator(evalPoint func(evalIdx uint64, q uint64) (uint64, error)) ConstraintEvaluator {
	families := cfg.Families
	if len(families) == 0 {
		families = postSignNonSigFamilies(cfg.Layout)
	}
	caches := map[string]*sigNTTBridgeEvalCache{}
	cacheErrs := map[string]error{}
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil ring")
		}
		if cfg.BridgeChecks <= 0 || len(families) == 0 {
			return nil, nil, nil
		}
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) (uint64, error) {
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		x, err := evalPoint(evalIdx, q)
		if err != nil {
			return nil, nil, err
		}

		fagg := make([]uint64, 0, len(families)*cfg.BridgeChecks)
		for _, fam := range families {
			cache := caches[fam.Label]
			if cache == nil && cacheErrs[fam.Label] == nil {
				cache, cacheErrs[fam.Label] = buildRowSetNTTBridgeEvalCache(
					cfg.Ring, cfg.Omega, cfg.Root, fam.Label, cfg.BridgeChecks, fam.Blocks, fam.ComponentCount,
				)
				caches[fam.Label] = cache
			}
			if cacheErr := cacheErrs[fam.Label]; cacheErr != nil {
				return nil, nil, cacheErr
			}
			if cache == nil {
				continue
			}
			for t := 0; t < cfg.BridgeChecks; t++ {
				var acc uint64
				for b := 0; b < cache.blocks; b++ {
					rVal := EvalPoly(cache.rTheta[t][b], x, q) % q
					sVal := EvalPoly(cache.sTheta[t][b], x, q) % q
					var mixNTT, mixCoef uint64
					for j := 0; j < cache.componentCount; j++ {
						a := cache.alpha[t][j] % q
						if a == 0 {
							continue
						}
						nIdx := fam.Block0Base + j
						if b > 0 {
							nIdx = fam.ExtraNTTBase + (b-1)*fam.ComponentCount + j
						}
						nVal, nErr := getRow(nIdx)
						if nErr != nil {
							return nil, nil, nErr
						}
						mixNTT = modAdd(mixNTT, modMul(a, nVal, q), q)

						cIdx := fam.CoeffBase + b*fam.ComponentCount + j
						cVal, cErr := getRow(cIdx)
						if cErr != nil {
							return nil, nil, cErr
						}
						mixCoef = modAdd(mixCoef, modMul(a, cVal, q), q)
					}
					acc = modAdd(acc, modSub(modMul(rVal, mixNTT, q), modMul(sVal, mixCoef, q), q), q)
				}
				fagg = append(fagg, acc%q)
			}
		}
		return nil, fagg, nil
	}
}

func (cfg NonSigNTTBridgeConfig) NonSigBridgeKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	families := cfg.Families
	if len(families) == 0 {
		families = postSignNonSigFamilies(cfg.Layout)
	}
	caches := map[string]*sigNTTBridgeEvalCache{}
	cacheErrs := map[string]error{}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		if cfg.BridgeChecks <= 0 || len(families) == 0 {
			return nil, nil, nil
		}
		getRow := func(idx int) (kf.Elem, error) {
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("row idx %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		fagg := make([]kf.Elem, 0, len(families)*cfg.BridgeChecks)
		for _, fam := range families {
			cache := caches[fam.Label]
			if cache == nil && cacheErrs[fam.Label] == nil {
				cache, cacheErrs[fam.Label] = buildRowSetNTTBridgeEvalCache(
					cfg.Ring, cfg.Omega, cfg.Root, fam.Label, cfg.BridgeChecks, fam.Blocks, fam.ComponentCount,
				)
				caches[fam.Label] = cache
			}
			if cacheErr := cacheErrs[fam.Label]; cacheErr != nil {
				return nil, nil, cacheErr
			}
			if cache == nil {
				continue
			}
			for t := 0; t < cfg.BridgeChecks; t++ {
				acc := K.Zero()
				for b := 0; b < cache.blocks; b++ {
					rVal := K.EvalFPolyAtK(cache.rTheta[t][b], e)
					sVal := K.EvalFPolyAtK(cache.sTheta[t][b], e)
					mixNTT := K.Zero()
					mixCoef := K.Zero()
					for j := 0; j < cache.componentCount; j++ {
						a := cache.alpha[t][j] % cache.q
						if a == 0 {
							continue
						}
						nIdx := fam.Block0Base + j
						if b > 0 {
							nIdx = fam.ExtraNTTBase + (b-1)*fam.ComponentCount + j
						}
						nVal, nErr := getRow(nIdx)
						if nErr != nil {
							return nil, nil, nErr
						}
						K.AddMulBaseInto(&mixNTT, nVal, a)

						cIdx := fam.CoeffBase + b*fam.ComponentCount + j
						cVal, cErr := getRow(cIdx)
						if cErr != nil {
							return nil, nil, cErr
						}
						K.AddMulBaseInto(&mixCoef, cVal, a)
					}
					acc = K.Add(acc, K.Sub(K.Mul(rVal, mixNTT), K.Mul(sVal, mixCoef)))
				}
				fagg = append(fagg, acc)
			}
		}
		return nil, fagg, nil
	}, nil
}

// PRFConstraintConfig carries the row indices and public parameters needed to
// recompute PRF constraints from row evaluations. All PRF parameters are
// treated as public θ-polynomials; ME/MI/CExt/CInt are constant θ's, while
// Tag/Nonce are interpolated over Ω.
type PRFConstraintConfig struct {
	Ring   *ring.Ring
	Params *prf.Params
	// DomainPoints is the explicit DECS evaluation domain E (DomainModeExplicit).
	// When empty/nil, evaluators interpret evalIdx as a row index.
	DomainPoints []uint64

	Mode string

	StartIdx    int
	NCols       int
	M2RowIdx    int
	KeyBind     bool
	GroupRounds int
	PackedRows  bool
	KeySlots    []PRFSlot
	SBoxSlots   []PRFSlot

	TagTheta   []*ring.Poly
	TagCoeff   [][]uint64
	NonceTheta []*ring.Poly
	NonceCoeff [][]uint64

	// KeySel polynomials select the Ω slot used to bind each PRF key lane to M2.
	// When PackedRows is enabled, KeySel selects the packed PRF row slot for the
	// logical key lane. M2Sel selects the corresponding slot in the M2 row.
	KeySelTheta  []*ring.Poly
	KeySelCoeff  [][]uint64
	M2SelTheta   []*ring.Poly
	M2SelCoeff   [][]uint64
	SBoxSelTheta []*ring.Poly
	SBoxSelCoeff [][]uint64
}

// CredentialEvaluator builds a ConstraintEvaluator for the credential
// pre-sign constraints (commit, center, hash, bounds).
func (cfg CredentialConstraintConfig) CredentialEvaluator() ConstraintEvaluator {
	if len(cfg.DomainPoints) == 0 {
		return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
			return nil, nil, fmt.Errorf("credential replay config: missing domain points for explicit evaluator")
		}
	}
	var (
		configErr       error
		acCoeff         [][][]uint64
		comCoeff        [][]uint64
		bCoeff          [][]uint64
		packingSelCoeff []uint64
		ri0Coeff        []uint64
		ri1Coeff        []uint64
		tPublicCoeff    []uint64
	)
	if cfg.Ring == nil {
		configErr = fmt.Errorf("nil ring")
	}
	ncols := cfg.PackingNCols
	if ncols <= 0 {
		if len(cfg.Omega) > 0 {
			ncols = len(cfg.Omega)
		} else if cfg.Ring != nil {
			ncols = int(cfg.Ring.N)
		}
	}
	omega := cfg.Omega
	if len(omega) == 0 {
		configErr = fmt.Errorf("credential replay config: missing omega in explicit-domain mode")
	}
	toCoeffTheta := func(p *ring.Poly) ([]uint64, error) {
		if p == nil {
			return nil, nil
		}
		// cfg carries Θ-polynomials already materialised in NTT form; recover
		// their coefficients directly (do not re-interpolate on Ω).
		return coeffFromNTTPoly(cfg.Ring, p)
	}
	if len(cfg.Ac) > 0 {
		acCoeff = make([][][]uint64, len(cfg.Ac))
		for i := range cfg.Ac {
			acCoeff[i] = make([][]uint64, len(cfg.Ac[i]))
			for j := range cfg.Ac[i] {
				coeff, err := toCoeffTheta(cfg.Ac[i][j])
				if err != nil {
					continue
				}
				acCoeff[i][j] = coeff
			}
		}
	}
	if len(cfg.Com) > 0 {
		comCoeff = make([][]uint64, len(cfg.Com))
		for i := range cfg.Com {
			coeff, err := toCoeffTheta(cfg.Com[i])
			if err != nil {
				continue
			}
			comCoeff[i] = coeff
		}
	}
	if len(cfg.B) > 0 {
		bCoeff = make([][]uint64, len(cfg.B))
		for i := range cfg.B {
			coeff, err := toCoeffTheta(cfg.B[i])
			if err != nil {
				continue
			}
			bCoeff[i] = coeff
		}
	}
	if len(cfg.PackingSelNTT) > 0 && configErr == nil {
		if ncols > len(omega) {
			configErr = fmt.Errorf("credential replay config: omega len=%d < ncols=%d", len(omega), ncols)
		} else {
			selCoeff, err := buildPackingSelectorCoeff(cfg.Ring, omega[:ncols])
			if err != nil {
				configErr = fmt.Errorf("credential replay config: packing selector: %w", err)
			} else {
				packingSelCoeff = selCoeff
			}
		}
	}
	firstCoeff := func(polys []*ring.Poly) []uint64 {
		for _, p := range polys {
			coeff, err := toCoeffTheta(p)
			if err == nil && len(coeff) > 0 {
				return coeff
			}
		}
		return nil
	}
	ri0Coeff = firstCoeff(cfg.RI0)
	ri1Coeff = firstCoeff(cfg.RI1)
	if cfg.TPublicNTT != nil {
		coeff, err := toCoeffTheta(cfg.TPublicNTT)
		if err == nil {
			tPublicCoeff = coeff
		}
	}
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if configErr != nil {
			return nil, nil, configErr
		}
		if cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil ring")
		}
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) uint64 {
			if idx < 0 || idx >= len(rows) {
				return 0
			}
			return rows[idx] % q
		}
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
			return nil, nil, fmt.Errorf("eval idx %d out of range for explicit domain (len=%d)", ptIdx, len(cfg.DomainPoints))
		}
		x := cfg.DomainPoints[ptIdx] % q
		evalTheta := func(coeff []uint64) uint64 {
			if len(coeff) == 0 {
				return 0
			}
			return EvalPoly(coeff, x, q)
		}
		// Commit residuals (parallel, same ordering as BuildCredentialConstraintSetPre).
		var fpar []uint64
		if len(cfg.Ac) > 0 {
			fpar = make([]uint64, len(cfg.Ac))
			for i := range cfg.Ac {
				var sum uint64
				if cfg.Ac[i] == nil || cfg.Com == nil || i >= len(cfg.Com) {
					continue
				}
				if i < len(comCoeff) {
					sum = (q + sum - evalTheta(comCoeff[i])%q) % q
				}
				cols := len(cfg.Ac[i])
				for j := 0; j < cols; j++ {
					if cfg.Ac[i][j] == nil {
						continue
					}
					vecIdx := []int{cfg.IdxM1, cfg.IdxM2, cfg.IdxRU0, cfg.IdxRU1, cfg.IdxR}
					if j < len(vecIdx) {
						var aVal uint64
						if i < len(acCoeff) && j < len(acCoeff[i]) && len(acCoeff[i][j]) > 0 {
							aVal = evalTheta(acCoeff[i][j]) % q
						}
						sum = lvcs.MulAddMod64(sum, aVal%q, getRow(vecIdx[j]), q)
					}
				}
				fpar[i] = sum % q
			}
		}

		// Center constraints.
		if cfg.Bound > 0 {
			delta := uint64(2*cfg.Bound + 1)
			ru0 := getRow(cfg.IdxRU0)
			ru1 := getRow(cfg.IdxRU1)
			r0 := getRow(cfg.IdxR0)
			r1 := getRow(cfg.IdxR1)
			k0 := getRow(cfg.IdxK0)
			k1 := getRow(cfg.IdxK1)
			ri0 := evalTheta(ri0Coeff)
			ri1 := evalTheta(ri1Coeff)
			res0 := (ru0 + ri0 + q - r0) % q
			res0 = (res0 + q - (delta*k0)%q) % q
			res1 := (ru1 + ri1 + q - r1) % q
			res1 = (res1 + q - (delta*k1)%q) % q
			fpar = append(fpar, res0%q, res1%q)
		}

		// Hash residual (cleared denominator form).
		if len(cfg.B) >= 4 {
			var b0, b1, b2, b3 uint64
			if len(bCoeff) >= 4 {
				b0 = evalTheta(bCoeff[0]) % q
				b1 = evalTheta(bCoeff[1]) % q
				b2 = evalTheta(bCoeff[2]) % q
				b3 = evalTheta(bCoeff[3]) % q
			}
			m1 := getRow(cfg.IdxM1)
			m2 := getRow(cfg.IdxM2)
			r0v := getRow(cfg.IdxR0)
			r1v := getRow(cfg.IdxR1)
			t := uint64(0)
			if cfg.IdxT >= 0 && cfg.IdxT < len(rows) {
				t = rows[cfg.IdxT] % q
			} else {
				t = evalTheta(tPublicCoeff)
			}
			// (B3 - R1)*T - (B0 + B1*(M1+M2) + B2*R0)
			res := (q + b3 - r1v) % q
			res = (res * t) % q
			mCombined := (m1 + m2) % q
			lin := b0
			lin = lvcs.MulAddMod64(lin, b1, mCombined, q)
			lin = lvcs.MulAddMod64(lin, b2, r0v, q)
			if res >= lin {
				res = (res - lin) % q
			} else {
				res = (res + q - lin) % q
			}
			fpar = append(fpar, res%q)
		}

		// Packing residuals: enforce lower/upper-half zeroing (evaluation-domain proxy).
		if len(cfg.PackingSelNTT) > 0 {
			var sel uint64
			if len(packingSelCoeff) > 0 {
				sel = evalTheta(packingSelCoeff) % q
			}
			oneMinus := (1 + q - sel) % q
			fpar = append(fpar, lvcs.MulMod64(sel, getRow(cfg.IdxM1), q))
			fpar = append(fpar, lvcs.MulMod64(oneMinus, getRow(cfg.IdxM2), q))
		}

		// Bounds: P_B(row) for configured rows (evaluation-domain).
		for _, idx := range cfg.BoundRows {
			v := int64(getRow(idx))
			pb := boundPoly(v, cfg.Bound, int64(q))
			fpar = append(fpar, pb%q)
		}
		carryBound := cfg.CarryBound
		if carryBound == 0 && len(cfg.CarryRows) > 0 {
			carryBound = 1
		}
		for _, idx := range cfg.CarryRows {
			v := int64(getRow(idx))
			pb := boundPoly(v, carryBound, int64(q))
			fpar = append(fpar, pb%q)
		}

		return fpar, nil, nil
	}
}

// CredentialKEvaluator builds a K-point evaluator for the credential pre-sign constraints.
// It recomputes residuals from K-point row evaluations and public parameters.
func (cfg CredentialConstraintConfig) CredentialKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	cache, err := buildCredentialKEvalCache(cfg, K)
	if err != nil {
		return nil, err
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) kf.Elem {
			if idx < 0 || idx >= len(rows) {
				return K.Zero()
			}
			return rows[idx]
		}

		// Commit residuals.
		var fpar []kf.Elem
		if len(cache.AcCoeff) > 0 {
			fpar = make([]kf.Elem, len(cache.AcCoeff))
			vecIdx := []int{cfg.IdxM1, cfg.IdxM2, cfg.IdxRU0, cfg.IdxRU1, cfg.IdxR}
			for i := range cache.AcCoeff {
				sum := K.Zero()
				if i < len(cache.ComCoeff) {
					comVal := K.EvalFPolyAtK(cache.ComCoeff[i], e)
					sum = K.Sub(sum, comVal)
				}
				for j := 0; j < len(cache.AcCoeff[i]) && j < len(vecIdx); j++ {
					aVal := K.EvalFPolyAtK(cache.AcCoeff[i][j], e)
					sum = K.Add(sum, K.Mul(aVal, getRow(vecIdx[j])))
				}
				fpar[i] = sum
			}
		}

		// Center residuals.
		if cfg.Bound > 0 {
			delta := uint64(2*cfg.Bound + 1)
			deltaK := K.EmbedF(delta % q)
			ru0 := getRow(cfg.IdxRU0)
			ru1 := getRow(cfg.IdxRU1)
			r0 := getRow(cfg.IdxR0)
			r1 := getRow(cfg.IdxR1)
			k0 := getRow(cfg.IdxK0)
			k1 := getRow(cfg.IdxK1)
			ri0 := K.EvalFPolyAtK(cache.RI0Coeff, e)
			ri1 := K.EvalFPolyAtK(cache.RI1Coeff, e)
			res0 := K.Sub(K.Sub(K.Add(ru0, ri0), r0), K.Mul(deltaK, k0))
			res1 := K.Sub(K.Sub(K.Add(ru1, ri1), r1), K.Mul(deltaK, k1))
			fpar = append(fpar, res0, res1)
		}

		// Hash residual.
		if len(cache.BCoeff) >= 4 {
			b0 := K.EvalFPolyAtK(cache.BCoeff[0], e)
			b1 := K.EvalFPolyAtK(cache.BCoeff[1], e)
			b2 := K.EvalFPolyAtK(cache.BCoeff[2], e)
			b3 := K.EvalFPolyAtK(cache.BCoeff[3], e)
			m1 := getRow(cfg.IdxM1)
			m2 := getRow(cfg.IdxM2)
			r0v := getRow(cfg.IdxR0)
			r1v := getRow(cfg.IdxR1)
			var t kf.Elem
			if cfg.IdxT >= 0 && cfg.IdxT < len(rows) {
				t = getRow(cfg.IdxT)
			} else if len(cache.TPublicCoeff) > 0 {
				t = K.EvalFPolyAtK(cache.TPublicCoeff, e)
			} else {
				t = K.Zero()
			}
			res := K.Sub(b3, r1v)
			res = K.Mul(res, t)
			lin := b0
			lin = K.Add(lin, K.Mul(b1, K.Add(m1, m2)))
			lin = K.Add(lin, K.Mul(b2, r0v))
			res = K.Sub(res, lin)
			fpar = append(fpar, res)
		}

		// Packing residuals via selector polynomial on Ω.
		if len(cache.PackingSelCoeff) > 0 {
			sel := K.EvalFPolyAtK(cache.PackingSelCoeff, e)
			oneMinus := K.Sub(K.One(), sel)
			fpar = append(fpar, K.Mul(sel, getRow(cfg.IdxM1)))
			fpar = append(fpar, K.Mul(oneMinus, getRow(cfg.IdxM2)))
		}

		// Bounds: P_B(row) over K.
		for _, idx := range cfg.BoundRows {
			v := getRow(idx)
			pb := boundPolyK(K, v, cfg.Bound)
			fpar = append(fpar, pb)
		}
		carryBound := cfg.CarryBound
		if carryBound == 0 && len(cfg.CarryRows) > 0 {
			carryBound = 1
		}
		for _, idx := range cfg.CarryRows {
			v := getRow(idx)
			pb := boundPolyK(K, v, carryBound)
			fpar = append(fpar, pb)
		}

		return fpar, nil, nil
	}, nil
}

func buildPackingSelectorCoeff(ringQ *ring.Ring, omega []uint64) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return nil, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	if ncols%2 != 0 {
		return nil, fmt.Errorf("ncols %d not even for packing selector", ncols)
	}
	half := ncols / 2
	row := make([]uint64, ncols)
	for i := half; i < ncols; i++ {
		row[i] = 1 % ringQ.Modulus[0]
	}
	q := ringQ.Modulus[0]
	coeffs := Interpolate(omega, row, q)
	out := make([]uint64, ringQ.N)
	copy(out, coeffs)
	for i := range out {
		out[i] %= q
	}
	return out, nil
}

func boundPoly(x, B, q int64) uint64 {
	if B <= 0 {
		return 0
	}
	res := int64(1 % q)
	for i := -B; i <= B; i++ {
		res = (res * ((x - i) % q)) % q
		if res < 0 {
			res += q
		}
	}
	return uint64(res % q)
}

// buildRowValsFromVTargets reconstructs K-point row values from VTargets.
func buildRowValsFromVTargets(K *kf.Field, vTargets [][]uint64, kpIdx int, kPointCount int, witnessCount int) ([]kf.Elem, error) {
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if len(vTargets) == 0 {
		return nil, fmt.Errorf("empty VTargets")
	}
	if kPointCount <= 0 {
		return nil, fmt.Errorf("invalid K-point count %d", kPointCount)
	}
	if len(vTargets)%kPointCount != 0 {
		return nil, fmt.Errorf("vTargets rows %d not divisible by K-point count %d", len(vTargets), kPointCount)
	}
	if kpIdx < 0 || kpIdx >= kPointCount {
		return nil, fmt.Errorf("kpIdx %d out of range (kpoints=%d)", kpIdx, kPointCount)
	}
	theta := K.Theta
	rowsPerPoint := len(vTargets) / kPointCount
	if rowsPerPoint < theta || rowsPerPoint%theta != 0 {
		return nil, fmt.Errorf("invalid rows-per-point %d for theta=%d", rowsPerPoint, theta)
	}
	ncols := len(vTargets[0])
	if ncols == 0 {
		return nil, fmt.Errorf("empty VTargets columns")
	}
	for i := 1; i < len(vTargets); i++ {
		if len(vTargets[i]) != ncols {
			return nil, fmt.Errorf("ragged VTargets row %d: got %d cols want %d", i, len(vTargets[i]), ncols)
		}
	}
	layerCount := rowsPerPoint / theta
	maxRows := layerCount * ncols
	if witnessCount > maxRows {
		return nil, fmt.Errorf("vTargets capacity %d < witness count %d (layers=%d ncols=%d)", maxRows, witnessCount, layerCount, ncols)
	}

	start := kpIdx * rowsPerPoint
	out := make([]kf.Elem, witnessCount)
	for rowIdx := 0; rowIdx < witnessCount; rowIdx++ {
		layer := rowIdx / ncols
		col := rowIdx % ncols
		limbs := make([]uint64, theta)
		for coord := 0; coord < theta; coord++ {
			limbs[coord] = vTargets[start+layer*theta+coord][col]
		}
		out[rowIdx] = K.Phi(limbs)
	}
	return out, nil
}

type credentialKEvalCache struct {
	AcCoeff         [][][]uint64
	ComCoeff        [][]uint64
	BCoeff          [][]uint64
	RI0Coeff        []uint64
	RI1Coeff        []uint64
	TPublicCoeff    []uint64
	PackingSelCoeff []uint64
}

func buildCredentialKEvalCache(cfg CredentialConstraintConfig, K *kf.Field) (*credentialKEvalCache, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(cfg.Omega) == 0 {
		return nil, fmt.Errorf("credential replay config: missing omega")
	}
	ncols := cfg.PackingNCols
	if ncols <= 0 {
		ncols = len(cfg.Omega)
	}
	omega := cfg.Omega
	if ncols > len(omega) {
		return nil, fmt.Errorf("credential replay config: omega len=%d < ncols=%d", len(omega), ncols)
	}
	if len(omega) > ncols {
		omega = omega[:ncols]
	}
	toCoeffTheta := func(p *ring.Poly) ([]uint64, error) {
		if p == nil {
			return nil, nil
		}
		// cfg carries Θ-polynomials already materialised in NTT form.
		return coeffFromNTTPoly(cfg.Ring, p)
	}
	cache := &credentialKEvalCache{}
	if len(cfg.Ac) > 0 {
		cache.AcCoeff = make([][][]uint64, len(cfg.Ac))
		for i := range cfg.Ac {
			if cfg.Ac[i] == nil {
				continue
			}
			cache.AcCoeff[i] = make([][]uint64, len(cfg.Ac[i]))
			for j := range cfg.Ac[i] {
				coeff, err := toCoeffTheta(cfg.Ac[i][j])
				if err != nil {
					return nil, err
				}
				cache.AcCoeff[i][j] = coeff
			}
		}
	}
	if len(cfg.Com) > 0 {
		cache.ComCoeff = make([][]uint64, len(cfg.Com))
		for i := range cfg.Com {
			coeff, err := toCoeffTheta(cfg.Com[i])
			if err != nil {
				return nil, err
			}
			cache.ComCoeff[i] = coeff
		}
	}
	if len(cfg.B) > 0 {
		cache.BCoeff = make([][]uint64, len(cfg.B))
		for i := range cfg.B {
			coeff, err := toCoeffTheta(cfg.B[i])
			if err != nil {
				return nil, err
			}
			cache.BCoeff[i] = coeff
		}
	}
	if len(cfg.RI0) > 0 {
		coeff, err := toCoeffTheta(cfg.RI0[0])
		if err != nil {
			return nil, err
		}
		cache.RI0Coeff = coeff
	}
	if len(cfg.RI1) > 0 {
		coeff, err := toCoeffTheta(cfg.RI1[0])
		if err != nil {
			return nil, err
		}
		cache.RI1Coeff = coeff
	}
	if cfg.TPublicNTT != nil {
		coeff, err := toCoeffTheta(cfg.TPublicNTT)
		if err != nil {
			return nil, err
		}
		cache.TPublicCoeff = coeff
	}
	// Packing selector: interpolate over Ω of length ncols.
	if ncols%2 == 0 {
		selCoeff, err := buildPackingSelectorCoeff(cfg.Ring, omega)
		if err != nil {
			return nil, err
		}
		cache.PackingSelCoeff = selCoeff
	}
	return cache, nil
}

func boundPolyK(K *kf.Field, x kf.Elem, B int64) kf.Elem {
	if B <= 0 {
		return K.Zero()
	}
	q := int64(K.Q)
	res := K.One()
	for i := -B; i <= B; i++ {
		val := i % q
		if val < 0 {
			val += q
		}
		res = K.Mul(res, K.Sub(x, K.EmbedF(uint64(val))))
	}
	return res
}

// buildPRFThetaPolys interpolates public lanes over Ω and returns their Θ data.
func buildPRFThetaPolys(ringQ *ring.Ring, lanes [][]int64, omega []uint64) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(lanes) == 0 {
		return nil, nil, nil
	}
	if len(omega) == 0 {
		return nil, nil, fmt.Errorf("empty omega")
	}
	ncols := len(omega)
	if ncols > int(ringQ.N) {
		return nil, nil, fmt.Errorf("|Ω|=%d exceeds ring dimension %d", ncols, ringQ.N)
	}
	q := int64(ringQ.Modulus[0])
	theta := make([]*ring.Poly, len(lanes))
	coeff := make([][]uint64, len(lanes))
	for i := range lanes {
		if len(lanes[i]) < ncols {
			return nil, nil, fmt.Errorf("lane %d len=%d < ncols=%d", i, len(lanes[i]), ncols)
		}
		vals := make([]uint64, ncols)
		for j := 0; j < ncols; j++ {
			v := lanes[i][j]
			if v < 0 {
				v += q
			}
			vals[j] = uint64(v % q)
		}
		q64 := ringQ.Modulus[0]
		coeffs := Interpolate(omega, vals, q64)
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], coeffs)
		pNTT := ringQ.NewPoly()
		ring.Copy(p, pNTT)
		ringQ.NTT(pNTT, pNTT)
		theta[i] = pNTT
		full := make([]uint64, ringQ.N)
		copy(full, coeffs)
		for j := range full {
			full[j] %= q64
		}
		coeff[i] = full
	}
	return theta, coeff, nil
}

// NewPRFConstraintConfig builds the PRF replay config.
func NewPRFConstraintConfig(ringQ *ring.Ring, params *prf.Params, layout *PRFLayout, tagPublic, noncePublic [][]int64, omega []uint64, domainPoints []uint64) (*PRFConstraintConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if params == nil {
		return nil, fmt.Errorf("nil prf params")
	}
	if layout == nil {
		return nil, fmt.Errorf("nil prf layout")
	}
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("prf params invalid: %w", err)
	}
	if layout.LenKey != params.LenKey || layout.LenNonce != params.LenNonce || layout.RF != params.RF || layout.RP != params.RP || layout.LenTag != params.LenTag {
		return nil, fmt.Errorf("prf layout mismatch with params")
	}
	mode := layout.Mode
	if mode == "" {
		mode = PRFLayoutModeSBox
	}
	if mode != PRFLayoutModeSBox {
		return nil, fmt.Errorf("unsupported prf layout mode %q", mode)
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("prf replay config: missing omega")
	}
	ncols := len(omega)
	groupRounds := layout.GroupRounds
	if groupRounds <= 0 {
		groupRounds = 1
	}
	tagTheta, tagCoeff, err := buildPRFThetaPolys(ringQ, tagPublic, omega)
	if err != nil {
		return nil, fmt.Errorf("tag theta: %w", err)
	}
	nonceTheta, nonceCoeff, err := buildPRFThetaPolys(ringQ, noncePublic, omega)
	if err != nil {
		return nil, fmt.Errorf("nonce theta: %w", err)
	}
	var omegaSelTheta []*ring.Poly
	var omegaSelCoeff [][]uint64
	if layout.PackedRows || layout.KeyBind {
		omegaSelTheta, omegaSelCoeff, err = buildOmegaDeltaSelectors(ringQ, omega)
		if err != nil {
			return nil, fmt.Errorf("delta selectors: %w", err)
		}
	}
	var keySelTheta []*ring.Poly
	var keySelCoeff [][]uint64
	var m2SelTheta []*ring.Poly
	var m2SelCoeff [][]uint64
	var sboxSelTheta []*ring.Poly
	var sboxSelCoeff [][]uint64
	if layout.PackedRows {
		if len(layout.KeySlots) != params.LenKey {
			return nil, fmt.Errorf("packed key slot count=%d want %d", len(layout.KeySlots), params.LenKey)
		}
		groupedSBoxCount, serr := prf.SBoxOutputCountGrouped(params, groupRounds)
		if serr != nil {
			return nil, fmt.Errorf("grouped sbox count: %w", serr)
		}
		if len(layout.SBoxSlots) != groupedSBoxCount {
			return nil, fmt.Errorf("packed sbox slot count=%d want %d", len(layout.SBoxSlots), groupedSBoxCount)
		}
		keySelTheta = make([]*ring.Poly, params.LenKey)
		keySelCoeff = make([][]uint64, params.LenKey)
		for i := range layout.KeySlots {
			col := layout.KeySlots[i].Col
			if col < 0 || col >= len(omegaSelTheta) {
				return nil, fmt.Errorf("packed key slot col %d out of range", col)
			}
			keySelTheta[i] = omegaSelTheta[col]
			keySelCoeff[i] = omegaSelCoeff[col]
		}
		sboxSelTheta = make([]*ring.Poly, len(layout.SBoxSlots))
		sboxSelCoeff = make([][]uint64, len(layout.SBoxSlots))
		for i := range layout.SBoxSlots {
			col := layout.SBoxSlots[i].Col
			if col < 0 || col >= len(omegaSelTheta) {
				return nil, fmt.Errorf("packed sbox slot col %d out of range", col)
			}
			sboxSelTheta[i] = omegaSelTheta[col]
			sboxSelCoeff[i] = omegaSelCoeff[col]
		}
	}
	if layout.KeyBind {
		if layout.M2RowIdx < 0 {
			return nil, fmt.Errorf("keyBind enabled but missing M2RowIdx")
		}
		if ncols%2 != 0 {
			return nil, fmt.Errorf("keyBind requires even ncols, got %d", ncols)
		}
		half := ncols / 2
		if half < params.LenKey {
			return nil, fmt.Errorf("keyBind requires ncols/2 >= lenkey; got ncols=%d lenkey=%d", ncols, params.LenKey)
		}
		m2SelTheta = make([]*ring.Poly, params.LenKey)
		m2SelCoeff = make([][]uint64, params.LenKey)
		for i := 0; i < params.LenKey; i++ {
			col := half + i
			if col < 0 || col >= len(omegaSelTheta) {
				return nil, fmt.Errorf("keyBind selector col %d out of range", col)
			}
			m2SelTheta[i] = omegaSelTheta[col]
			m2SelCoeff[i] = omegaSelCoeff[col]
		}
	}
	return &PRFConstraintConfig{
		Ring:         ringQ,
		Params:       params,
		DomainPoints: domainPoints,
		Mode:         mode,
		StartIdx:     layout.StartIdx,
		NCols:        ncols,
		M2RowIdx:     layout.M2RowIdx,
		KeyBind:      layout.KeyBind,
		GroupRounds:  groupRounds,
		PackedRows:   layout.PackedRows,
		KeySlots:     clonePRFSlots(layout.KeySlots),
		SBoxSlots:    clonePRFSlots(layout.SBoxSlots),
		TagTheta:     tagTheta,
		TagCoeff:     tagCoeff,
		NonceTheta:   nonceTheta,
		NonceCoeff:   nonceCoeff,
		KeySelTheta:  keySelTheta,
		KeySelCoeff:  keySelCoeff,
		M2SelTheta:   m2SelTheta,
		M2SelCoeff:   m2SelCoeff,
		SBoxSelTheta: sboxSelTheta,
		SBoxSelCoeff: sboxSelCoeff,
	}, nil
}

// PRFEvaluator returns a row-indexed evaluator for PRF constraints at eval points.
func (cfg PRFConstraintConfig) PRFEvaluator() ConstraintEvaluator {
	if len(cfg.DomainPoints) == 0 {
		return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
			return nil, nil, fmt.Errorf("prf replay config: missing domain points for explicit evaluator")
		}
	}
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil || cfg.Params == nil {
			return nil, nil, fmt.Errorf("nil prf config")
		}
		q := cfg.Ring.Modulus[0]
		ptIdx := int(evalIdx)
		x := uint64(0)
		t := cfg.Params.T()
		powMod := func(v uint64, exp uint64) uint64 {
			res := uint64(1)
			base := v % q
			for exp > 0 {
				if exp&1 == 1 {
					res = (res * base) % q
				}
				base = (base * base) % q
				exp >>= 1
			}
			return res
		}
		tagAt := func(j int) uint64 { return 0 }
		nonceAt := func(j int) uint64 { return 0 }
		keySelAt := func(i int) (uint64, error) {
			if i >= len(cfg.KeySelTheta) || cfg.KeySelTheta[i] == nil || ptIdx < 0 || ptIdx >= len(cfg.KeySelTheta[i].Coeffs[0]) {
				return 0, fmt.Errorf("missing key selector theta for key lane %d", i)
			}
			return cfg.KeySelTheta[i].Coeffs[0][ptIdx] % q, nil
		}
		sboxSelAt := func(i int) (uint64, error) {
			if i >= len(cfg.SBoxSelTheta) || cfg.SBoxSelTheta[i] == nil || ptIdx < 0 || ptIdx >= len(cfg.SBoxSelTheta[i].Coeffs[0]) {
				return 0, fmt.Errorf("missing sbox selector theta for sbox lane %d", i)
			}
			return cfg.SBoxSelTheta[i].Coeffs[0][ptIdx] % q, nil
		}
		m2SelAt := func(i int) (uint64, error) {
			if i >= len(cfg.M2SelTheta) || cfg.M2SelTheta[i] == nil || ptIdx < 0 || ptIdx >= len(cfg.M2SelTheta[i].Coeffs[0]) {
				return 0, fmt.Errorf("missing m2 selector theta for key lane %d", i)
			}
			return cfg.M2SelTheta[i].Coeffs[0][ptIdx] % q, nil
		}
		if len(cfg.DomainPoints) > 0 {
			if ptIdx < 0 || ptIdx >= len(cfg.DomainPoints) {
				return nil, nil, fmt.Errorf("evalIdx=%d out of range for domain size %d", evalIdx, len(cfg.DomainPoints))
			}
			x = cfg.DomainPoints[ptIdx] % q
			tagAt = func(j int) uint64 {
				if j < 0 || j >= len(cfg.TagCoeff) {
					return 0
				}
				return EvalPoly(cfg.TagCoeff[j], x, q)
			}
			nonceAt = func(j int) uint64 {
				if j < 0 || j >= len(cfg.NonceCoeff) {
					return 0
				}
				return EvalPoly(cfg.NonceCoeff[j], x, q)
			}
			keySelAt = func(i int) (uint64, error) {
				if i >= len(cfg.KeySelCoeff) || cfg.KeySelCoeff[i] == nil {
					return 0, fmt.Errorf("missing key selector coeff for key lane %d", i)
				}
				return EvalPoly(cfg.KeySelCoeff[i], x, q), nil
			}
			sboxSelAt = func(i int) (uint64, error) {
				if i >= len(cfg.SBoxSelCoeff) || cfg.SBoxSelCoeff[i] == nil {
					return 0, fmt.Errorf("missing sbox selector coeff for sbox lane %d", i)
				}
				return EvalPoly(cfg.SBoxSelCoeff[i], x, q), nil
			}
			m2SelAt = func(i int) (uint64, error) {
				if i >= len(cfg.M2SelCoeff) || cfg.M2SelCoeff[i] == nil {
					return 0, fmt.Errorf("missing m2 selector coeff for key lane %d", i)
				}
				return EvalPoly(cfg.M2SelCoeff[i], x, q), nil
			}
		} else {
			tagAt = func(j int) uint64 {
				if j < 0 || j >= len(cfg.TagTheta) || ptIdx < 0 || ptIdx >= len(cfg.TagTheta[j].Coeffs[0]) {
					return 0
				}
				return cfg.TagTheta[j].Coeffs[0][ptIdx] % q
			}
			nonceAt = func(j int) uint64 {
				if j < 0 || j >= len(cfg.NonceTheta) || ptIdx < 0 || ptIdx >= len(cfg.NonceTheta[j].Coeffs[0]) {
					return 0
				}
				return cfg.NonceTheta[j].Coeffs[0][ptIdx] % q
			}
		}
		getKey := func(i int) (uint64, error) {
			if cfg.PackedRows {
				if i < 0 || i >= len(cfg.KeySlots) {
					return 0, fmt.Errorf("packed key slot %d out of range (%d)", i, len(cfg.KeySlots))
				}
				slot := cfg.KeySlots[i]
				if slot.Row < 0 || slot.Row >= len(rows) {
					return 0, fmt.Errorf("packed key row %d out of range (rows=%d)", slot.Row, len(rows))
				}
				sel, err := keySelAt(i)
				if err != nil {
					return 0, err
				}
				return lvcs.MulMod64(sel, rows[slot.Row]%q, q), nil
			}
			idx := cfg.StartIdx + i
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("prf key row %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}
		getZ := func(alpha int) (uint64, error) {
			if cfg.PackedRows {
				if alpha < 0 || alpha >= len(cfg.SBoxSlots) {
					return 0, fmt.Errorf("packed sbox slot %d out of range (%d)", alpha, len(cfg.SBoxSlots))
				}
				slot := cfg.SBoxSlots[alpha]
				if slot.Row < 0 || slot.Row >= len(rows) {
					return 0, fmt.Errorf("packed sbox row %d out of range (rows=%d)", slot.Row, len(rows))
				}
				sel, err := sboxSelAt(alpha)
				if err != nil {
					return 0, err
				}
				return lvcs.MulMod64(sel, rows[slot.Row]%q, q), nil
			}
			idx := cfg.StartIdx + cfg.Params.LenKey + alpha
			if idx < 0 || idx >= len(rows) {
				return 0, fmt.Errorf("prf sbox row %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx] % q, nil
		}

		groupRounds := cfg.GroupRounds
		if groupRounds <= 0 {
			groupRounds = 1
		}
		sboxCount, err := prf.SBoxOutputCountGrouped(cfg.Params, groupRounds)
		if err != nil {
			return nil, nil, fmt.Errorf("grouped sbox count: %w", err)
		}
		need := cfg.StartIdx + cfg.Params.LenKey + sboxCount
		if !cfg.PackedRows && (cfg.StartIdx < 0 || need > len(rows)) {
			return nil, nil, fmt.Errorf("rowVals len=%d too small for prf sbox layout (need %d from %d)", len(rows), need, cfg.StartIdx)
		}
		mdsMul := func(st []uint64, mds [][]uint64) []uint64 {
			out := make([]uint64, len(st))
			for j := 0; j < len(st); j++ {
				var sum uint64
				for i := 0; i < len(st); i++ {
					sum = lvcs.MulAddMod64(sum, mds[j][i]%q, st[i], q)
				}
				out[j] = sum % q
			}
			return out
		}
		state := make([]uint64, t)
		for i := 0; i < t; i++ {
			if i < cfg.Params.LenKey {
				v, err := getKey(i)
				if err != nil {
					return nil, nil, err
				}
				state[i] = v
			} else {
				state[i] = nonceAt(i - cfg.Params.LenKey)
			}
		}
		fpar := make([]uint64, 0, sboxCount+cfg.Params.LenTag)
		alpha := 0
		// External rounds (first half).
		for r := 0; r < cfg.Params.RF/2; r++ {
			checkpoint := prf.ShouldCheckpointRound(cfg.Params, r, groupRounds)
			for lane := 0; lane < t; lane++ {
				u := (state[lane] + cfg.Params.CExt[r][lane]) % q
				pow := powMod(u, cfg.Params.D)
				if checkpoint {
					z, zErr := getZ(alpha)
					if zErr != nil {
						return nil, nil, zErr
					}
					fpar = append(fpar, (pow+q-z)%q) // U^d - Z
					state[lane] = z
					alpha++
				} else {
					state[lane] = pow
				}
			}
			state = mdsMul(state, cfg.Params.ME)
		}
		// Internal rounds.
		for ir := 0; ir < cfg.Params.RP; ir++ {
			globalRound := cfg.Params.RF/2 + ir
			checkpoint := prf.ShouldCheckpointRound(cfg.Params, globalRound, groupRounds)
			u := (state[0] + cfg.Params.CInt[ir]) % q
			pow := powMod(u, cfg.Params.D)
			if checkpoint {
				z, zErr := getZ(alpha)
				if zErr != nil {
					return nil, nil, zErr
				}
				fpar = append(fpar, (pow+q-z)%q)
				state[0] = z
				alpha++
			} else {
				state[0] = pow
			}
			state = mdsMul(state, cfg.Params.MI)
		}
		// External rounds (second half).
		for r := cfg.Params.RF / 2; r < cfg.Params.RF; r++ {
			globalRound := r + cfg.Params.RP
			checkpoint := prf.ShouldCheckpointRound(cfg.Params, globalRound, groupRounds)
			for lane := 0; lane < t; lane++ {
				u := (state[lane] + cfg.Params.CExt[r][lane]) % q
				pow := powMod(u, cfg.Params.D)
				if checkpoint {
					z, zErr := getZ(alpha)
					if zErr != nil {
						return nil, nil, zErr
					}
					fpar = append(fpar, (pow+q-z)%q)
					state[lane] = z
					alpha++
				} else {
					state[lane] = pow
				}
			}
			state = mdsMul(state, cfg.Params.ME)
		}
		if alpha != sboxCount {
			return nil, nil, fmt.Errorf("grouped sbox consumption mismatch: used %d want %d", alpha, sboxCount)
		}
		// Tag binding: y[j] + x0[j] - tag[j] = 0.
		for j := 0; j < cfg.Params.LenTag; j++ {
			x0j := uint64(0)
			if j < cfg.Params.LenKey {
				v, err := getKey(j)
				if err != nil {
					return nil, nil, err
				}
				x0j = v
			} else {
				x0j = nonceAt(j - cfg.Params.LenKey)
			}
			res := (state[j] + x0j + q - tagAt(j)) % q
			fpar = append(fpar, res)
		}
		// Optional key binding: Sel_{half+i}(X)·(Key_i - M2) = 0.
		if cfg.KeyBind {
			if cfg.M2RowIdx < 0 || cfg.M2RowIdx >= len(rows) {
				return nil, nil, fmt.Errorf("keyBind enabled but invalid M2RowIdx=%d (rows=%d)", cfg.M2RowIdx, len(rows))
			}
			for i := 0; i < cfg.Params.LenKey; i++ {
				keyVal, keyErr := getKey(i)
				if keyErr != nil {
					return nil, nil, keyErr
				}
				if cfg.PackedRows {
					m2Sel, selErr := m2SelAt(i)
					if selErr != nil {
						return nil, nil, selErr
					}
					m2Val := lvcs.MulMod64(m2Sel, rows[cfg.M2RowIdx]%q, q)
					fpar = append(fpar, (keyVal+q-m2Val)%q)
					continue
				}
				sel, selErr := m2SelAt(i)
				if selErr != nil {
					return nil, nil, selErr
				}
				diff := (keyVal + q - (rows[cfg.M2RowIdx] % q)) % q
				fpar = append(fpar, lvcs.MulMod64(sel, diff, q))
			}
		}
		return fpar, nil, nil
	}
}

// PRFKEvaluator returns a K-point evaluator for PRF constraints in θ>1 mode.
func (cfg PRFConstraintConfig) PRFKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Params == nil {
		return nil, fmt.Errorf("nil prf params")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		t := cfg.Params.T()
		powK := func(v kf.Elem, exp uint64) kf.Elem {
			res := K.One()
			base := v
			for exp > 0 {
				if exp&1 == 1 {
					res = K.Mul(res, base)
				}
				base = K.Mul(base, base)
				exp >>= 1
			}
			return res
		}
		tagAt := func(j int) kf.Elem {
			if j < 0 || j >= len(cfg.TagCoeff) {
				return K.Zero()
			}
			return K.EvalFPolyAtK(cfg.TagCoeff[j], e)
		}
		nonceAt := func(j int) kf.Elem {
			if j < 0 || j >= len(cfg.NonceCoeff) {
				return K.Zero()
			}
			return K.EvalFPolyAtK(cfg.NonceCoeff[j], e)
		}
		keySelAt := func(i int) (kf.Elem, error) {
			if i >= len(cfg.KeySelCoeff) || cfg.KeySelCoeff[i] == nil {
				return K.Zero(), fmt.Errorf("missing key selector coeff for key lane %d", i)
			}
			return K.EvalFPolyAtK(cfg.KeySelCoeff[i], e), nil
		}
		sboxSelAt := func(i int) (kf.Elem, error) {
			if i >= len(cfg.SBoxSelCoeff) || cfg.SBoxSelCoeff[i] == nil {
				return K.Zero(), fmt.Errorf("missing sbox selector coeff for sbox lane %d", i)
			}
			return K.EvalFPolyAtK(cfg.SBoxSelCoeff[i], e), nil
		}
		m2SelAt := func(i int) (kf.Elem, error) {
			if i >= len(cfg.M2SelCoeff) || cfg.M2SelCoeff[i] == nil {
				return K.Zero(), fmt.Errorf("missing m2 selector coeff for key lane %d", i)
			}
			return K.EvalFPolyAtK(cfg.M2SelCoeff[i], e), nil
		}
		getKey := func(i int) (kf.Elem, error) {
			if cfg.PackedRows {
				if i < 0 || i >= len(cfg.KeySlots) {
					return K.Zero(), fmt.Errorf("packed key slot %d out of range (%d)", i, len(cfg.KeySlots))
				}
				slot := cfg.KeySlots[i]
				if slot.Row < 0 || slot.Row >= len(rows) {
					return K.Zero(), fmt.Errorf("packed key row %d out of range (rows=%d)", slot.Row, len(rows))
				}
				sel, err := keySelAt(i)
				if err != nil {
					return K.Zero(), err
				}
				return K.Mul(sel, rows[slot.Row]), nil
			}
			idx := cfg.StartIdx + i
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("prf key row %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}
		getZ := func(alpha int) (kf.Elem, error) {
			if cfg.PackedRows {
				if alpha < 0 || alpha >= len(cfg.SBoxSlots) {
					return K.Zero(), fmt.Errorf("packed sbox slot %d out of range (%d)", alpha, len(cfg.SBoxSlots))
				}
				slot := cfg.SBoxSlots[alpha]
				if slot.Row < 0 || slot.Row >= len(rows) {
					return K.Zero(), fmt.Errorf("packed sbox row %d out of range (rows=%d)", slot.Row, len(rows))
				}
				sel, err := sboxSelAt(alpha)
				if err != nil {
					return K.Zero(), err
				}
				return K.Mul(sel, rows[slot.Row]), nil
			}
			idx := cfg.StartIdx + cfg.Params.LenKey + alpha
			if idx < 0 || idx >= len(rows) {
				return K.Zero(), fmt.Errorf("prf sbox row %d out of range (rows=%d)", idx, len(rows))
			}
			return rows[idx], nil
		}

		groupRounds := cfg.GroupRounds
		if groupRounds <= 0 {
			groupRounds = 1
		}
		sboxCount, err := prf.SBoxOutputCountGrouped(cfg.Params, groupRounds)
		if err != nil {
			return nil, nil, fmt.Errorf("grouped sbox count: %w", err)
		}
		need := cfg.StartIdx + cfg.Params.LenKey + sboxCount
		if !cfg.PackedRows && (cfg.StartIdx < 0 || need > len(rows)) {
			return nil, nil, fmt.Errorf("rowVals len=%d too small for prf sbox layout (need %d from %d)", len(rows), need, cfg.StartIdx)
		}
		mdsMul := func(st []kf.Elem, mds [][]uint64) []kf.Elem {
			out := make([]kf.Elem, len(st))
			for j := 0; j < len(st); j++ {
				sum := K.Zero()
				for i := 0; i < len(st); i++ {
					K.AddMulBaseInto(&sum, st[i], mds[j][i]%K.Q)
				}
				out[j] = sum
			}
			return out
		}
		state := make([]kf.Elem, t)
		for i := 0; i < t; i++ {
			if i < cfg.Params.LenKey {
				v, err := getKey(i)
				if err != nil {
					return nil, nil, err
				}
				state[i] = v
			} else {
				state[i] = nonceAt(i - cfg.Params.LenKey)
			}
		}
		fpar := make([]kf.Elem, 0, sboxCount+cfg.Params.LenTag)
		alpha := 0
		for r := 0; r < cfg.Params.RF/2; r++ {
			checkpoint := prf.ShouldCheckpointRound(cfg.Params, r, groupRounds)
			for lane := 0; lane < t; lane++ {
				u := K.Add(state[lane], K.EmbedF(cfg.Params.CExt[r][lane]%K.Q))
				pow := powK(u, cfg.Params.D)
				if checkpoint {
					z, zErr := getZ(alpha)
					if zErr != nil {
						return nil, nil, zErr
					}
					fpar = append(fpar, K.Sub(pow, z)) // U^d - Z
					state[lane] = z
					alpha++
				} else {
					state[lane] = pow
				}
			}
			state = mdsMul(state, cfg.Params.ME)
		}
		for ir := 0; ir < cfg.Params.RP; ir++ {
			globalRound := cfg.Params.RF/2 + ir
			checkpoint := prf.ShouldCheckpointRound(cfg.Params, globalRound, groupRounds)
			u := K.Add(state[0], K.EmbedF(cfg.Params.CInt[ir]%K.Q))
			pow := powK(u, cfg.Params.D)
			if checkpoint {
				z, zErr := getZ(alpha)
				if zErr != nil {
					return nil, nil, zErr
				}
				fpar = append(fpar, K.Sub(pow, z))
				state[0] = z
				alpha++
			} else {
				state[0] = pow
			}
			state = mdsMul(state, cfg.Params.MI)
		}
		for r := cfg.Params.RF / 2; r < cfg.Params.RF; r++ {
			globalRound := r + cfg.Params.RP
			checkpoint := prf.ShouldCheckpointRound(cfg.Params, globalRound, groupRounds)
			for lane := 0; lane < t; lane++ {
				u := K.Add(state[lane], K.EmbedF(cfg.Params.CExt[r][lane]%K.Q))
				pow := powK(u, cfg.Params.D)
				if checkpoint {
					z, zErr := getZ(alpha)
					if zErr != nil {
						return nil, nil, zErr
					}
					fpar = append(fpar, K.Sub(pow, z))
					state[lane] = z
					alpha++
				} else {
					state[lane] = pow
				}
			}
			state = mdsMul(state, cfg.Params.ME)
		}
		if alpha != sboxCount {
			return nil, nil, fmt.Errorf("grouped sbox consumption mismatch: used %d want %d", alpha, sboxCount)
		}
		for j := 0; j < cfg.Params.LenTag; j++ {
			x0j := K.Zero()
			if j < cfg.Params.LenKey {
				v, err := getKey(j)
				if err != nil {
					return nil, nil, err
				}
				x0j = v
			} else {
				x0j = nonceAt(j - cfg.Params.LenKey)
			}
			res := K.Add(state[j], x0j)
			res = K.Sub(res, tagAt(j))
			fpar = append(fpar, res)
		}
		// Optional key binding: Sel_{half+i}(X)·(Key_i - M2) = 0.
		if cfg.KeyBind {
			if cfg.M2RowIdx < 0 || cfg.M2RowIdx >= len(rows) {
				return nil, nil, fmt.Errorf("keyBind enabled but invalid M2RowIdx=%d (rows=%d)", cfg.M2RowIdx, len(rows))
			}
			for i := 0; i < cfg.Params.LenKey; i++ {
				keyVal, keyErr := getKey(i)
				if keyErr != nil {
					return nil, nil, keyErr
				}
				if cfg.PackedRows {
					m2Sel, selErr := m2SelAt(i)
					if selErr != nil {
						return nil, nil, selErr
					}
					fpar = append(fpar, K.Sub(keyVal, K.Mul(m2Sel, rows[cfg.M2RowIdx])))
					continue
				}
				m2Sel, selErr := m2SelAt(i)
				if selErr != nil {
					return nil, nil, selErr
				}
				diff := K.Sub(keyVal, rows[cfg.M2RowIdx])
				fpar = append(fpar, K.Mul(m2Sel, diff))
			}
		}
		return fpar, nil, nil
	}, nil
}
