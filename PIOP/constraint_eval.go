package PIOP

import (
	"fmt"
	"os"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

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
	AuxVTargets      [][]uint64
	QK               []*KPoly
	MK               []*KPoly
	GammaPrimeK      [][][]KScalar
	GammaAggK        [][]KScalar
	WitnessCount     int
	AuxWitnessCount  int
	Ring             *ring.Ring
	Fpar             []*ring.Poly
	Fagg             []*ring.Poly
	FparCoeffs       [][]uint64
	FaggCoeffs       [][]uint64
	FparOverrideIdxs []int
	FaggOverrideIdxs []int
	BoundRows        []int
	CarryRows        []int
	BoundB           int64
	CarryBound       int64
}

// EvalTailInput carries tail-opening data for Eq.(4) replay.
type EvalTailInput struct {
	Tail             []int
	SelectedRows     []int
	RowOpen          *decs.DECSOpening
	QOpen            *decs.DECSOpening
	GammaPrime       [][][]uint64
	GammaAgg         [][]uint64
	Ring             *ring.Ring
	FparCoeffs       [][]uint64
	FparOverrideIdxs []int
	FaggCoeffs       [][]uint64
	FaggOverrideIdxs []int
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
	Eval             ConstraintEvaluator
	EvalK            KConstraintEvaluator
	RowCount         int
	BoundRows        []int
	CarryRows        []int
	BoundB           int64
	CarryBound       int64
	Fpar             []*ring.Poly
	Fagg             []*ring.Poly
	FparCoeffs       [][]uint64
	FaggCoeffs       [][]uint64
	FparOverrideIdxs []int
	FaggOverrideIdxs []int
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

func coeffRowsAllZero(rows [][]uint64) bool {
	for _, row := range rows {
		for _, v := range row {
			if v != 0 {
				return false
			}
		}
	}
	return true
}

func zeroConstraintEvaluator(parCount, aggCount int) ConstraintEvaluator {
	if parCount <= 0 && aggCount <= 0 {
		return nil
	}
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		return make([]uint64, parCount), make([]uint64, aggCount), nil
	}
}

func zeroKConstraintEvaluator(K *kf.Field, parCount, aggCount int) KConstraintEvaluator {
	if K == nil || (parCount <= 0 && aggCount <= 0) {
		return nil
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		fpar := make([]kf.Elem, parCount)
		fagg := make([]kf.Elem, aggCount)
		for i := 0; i < parCount; i++ {
			fpar[i] = K.Zero()
		}
		for i := 0; i < aggCount; i++ {
			fagg[i] = K.Zero()
		}
		return fpar, fagg, nil
	}
}

func formalCoeffConstraintEvaluator(domainPoints []uint64, parRows, aggRows [][]uint64, q uint64) ConstraintEvaluator {
	if len(parRows) == 0 && len(aggRows) == 0 {
		return nil
	}
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		ptIdx := int(evalIdx)
		if ptIdx < 0 || ptIdx >= len(domainPoints) {
			return nil, nil, fmt.Errorf("formal coeff evaluator idx %d out of range (|E|=%d)", ptIdx, len(domainPoints))
		}
		x := domainPoints[ptIdx] % q
		fpar := make([]uint64, len(parRows))
		for i, coeffs := range parRows {
			fpar[i] = EvalPoly(coeffs, x, q)
		}
		fagg := make([]uint64, len(aggRows))
		for i, coeffs := range aggRows {
			fagg[i] = EvalPoly(coeffs, x, q)
		}
		return fpar, fagg, nil
	}
}

func formalCoeffKConstraintEvaluator(K *kf.Field, parRows, aggRows [][]uint64) KConstraintEvaluator {
	if K == nil || (len(parRows) == 0 && len(aggRows) == 0) {
		return nil
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		fpar := make([]kf.Elem, len(parRows))
		for i, coeffs := range parRows {
			fpar[i] = K.EvalFPolyAtK(coeffs, e)
		}
		fagg := make([]kf.Elem, len(aggRows))
		for i, coeffs := range aggRows {
			fagg[i] = K.EvalFPolyAtK(coeffs, e)
		}
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
	debugEq4K := os.Getenv("PIOP_DEBUG_EQ4_K") == "1"
	for kpIdx, limbs := range in.KPoints {
		e := in.K.Phi(limbs)
		rowVals, err := buildRowValsFromVTargets(in.K, in.VTargets, kpIdx, len(in.KPoints), in.WitnessCount)
		if err != nil {
			return false, err
		}
		if len(in.AuxVTargets) > 0 || in.AuxWitnessCount > 0 {
			if len(in.AuxVTargets) == 0 || in.AuxWitnessCount <= 0 {
				return false, fmt.Errorf("incomplete aux VTargets replay data")
			}
			auxVals, aerr := buildRowValsFromVTargets(in.K, in.AuxVTargets, kpIdx, len(in.KPoints), in.AuxWitnessCount)
			if aerr != nil {
				return false, aerr
			}
			rowVals = append(rowVals, auxVals...)
		}
		fpar, fagg, err := eval(e, rowVals)
		if err != nil {
			return false, err
		}
		if len(in.FparOverrideIdxs) > 0 {
			tmp := in.Ring.NewPoly()
			for _, idx := range in.FparOverrideIdxs {
				if idx < 0 || idx >= len(fpar) {
					continue
				}
				switch {
				case idx < len(in.FparCoeffs) && len(in.FparCoeffs[idx]) > 0:
					fpar[idx] = in.K.EvalFPolyAtK(in.FparCoeffs[idx], e)
				case in.Ring != nil && idx < len(in.Fpar) && in.Fpar[idx] != nil:
					in.Ring.InvNTT(in.Fpar[idx], tmp)
					fpar[idx] = in.K.EvalFPolyAtK(tmp.Coeffs[0], e)
				}
			}
		}
		if len(in.FaggOverrideIdxs) > 0 {
			tmp := in.Ring.NewPoly()
			for _, idx := range in.FaggOverrideIdxs {
				if idx < 0 || idx >= len(fagg) {
					continue
				}
				switch {
				case idx < len(in.FaggCoeffs) && len(in.FaggCoeffs[idx]) > 0:
					fagg[idx] = in.K.EvalFPolyAtK(in.FaggCoeffs[idx], e)
				case in.Ring != nil && idx < len(in.Fagg) && in.Fagg[idx] != nil:
					in.Ring.InvNTT(in.Fagg[idx], tmp)
					fagg[idx] = in.K.EvalFPolyAtK(tmp.Coeffs[0], e)
				}
			}
		}
		lhs := in.K.Zero()
		rhs := in.K.Zero()
		rhsMask := in.K.Zero()
		rhsPar := in.K.Zero()
		rhsAgg := in.K.Zero()
		g := in.K.Zero()
		term := in.K.Zero()
		for i := 0; i < rho; i++ {
			if i >= len(in.MK) || in.QK[i] == nil || in.MK[i] == nil {
				return false, fmt.Errorf("missing K polys at row %d", i)
			}
			evalKPolyAtKInto(in.K, &lhs, in.QK[i], e)
			evalKPolyAtKInto(in.K, &rhs, in.MK[i], e)
			if debugEq4K {
				copy(rhsMask.Limb, rhs.Limb)
				clear(rhsPar.Limb)
				clear(rhsAgg.Limb)
			}
			if i < len(in.GammaPrimeK) {
				rowGamma := in.GammaPrimeK[i]
				for j, val := range fpar {
					if j >= len(rowGamma) {
						continue
					}
					evalKScalarPolyAtKInto(in.K, &g, rowGamma[j], e)
					in.K.MulInto(&term, g, val)
					if debugEq4K {
						in.K.AddInto(&rhsPar, rhsPar, term)
					}
					in.K.AddInto(&rhs, rhs, term)
				}
			}
			if i < len(in.GammaAggK) {
				rowGamma := in.GammaAggK[i]
				for j, val := range fagg {
					if j >= len(rowGamma) {
						continue
					}
					setKCoords(in.K, &g, rowGamma[j])
					in.K.MulInto(&term, g, val)
					if debugEq4K {
						in.K.AddInto(&rhsAgg, rhsAgg, term)
					}
					in.K.AddInto(&rhs, rhs, term)
				}
			}
			if !elemEqual(in.K, lhs, rhs) {
				if debugEq4K && kpIdx == 0 && i == 0 {
					var gammaPrimeLen, gammaAggLen int
					if i < len(in.GammaPrimeK) {
						gammaPrimeLen = len(in.GammaPrimeK[i])
					}
					if i < len(in.GammaAggK) {
						gammaAggLen = len(in.GammaAggK[i])
					}
					fmt.Printf("[PIOP_DEBUG_EQ4_K] mismatch kp=%d row=%d witnessCount=%d theta=%d fpar=%d fagg=%d gammaPrime=%d gammaAgg=%d\n",
						kpIdx, i, in.WitnessCount, in.K.Theta, len(fpar), len(fagg), gammaPrimeLen, gammaAggLen)
					fmt.Printf("[PIOP_DEBUG_EQ4_K] lhs!=rhs with mask/par/agg components\n")
					if len(in.Fpar) > 0 {
						limit := len(fpar)
						if limit > len(in.Fpar) {
							limit = len(in.Fpar)
						}
						if limit > gammaPrimeLen {
							limit = gammaPrimeLen
						}
						for j := 0; j < limit; j++ {
							if in.Fpar[j] == nil || in.Ring == nil {
								continue
							}
							tmp := in.Ring.NewPoly()
							in.Ring.InvNTT(in.Fpar[j], tmp)
							polyVal := in.K.EvalFPolyAtK(tmp.Coeffs[0], e)
							if !elemEqual(in.K, polyVal, fpar[j]) {
								fmt.Printf("[PIOP_DEBUG_EQ4_K] fpar[%d] poly!=eval\n", j)
								break
							}
						}
					}
					if len(in.FparCoeffs) > 0 {
						limit := len(fpar)
						if limit > len(in.FparCoeffs) {
							limit = len(in.FparCoeffs)
						}
						for j := 0; j < limit; j++ {
							if len(in.FparCoeffs[j]) == 0 {
								continue
							}
							coeffVal := in.K.EvalFPolyAtK(in.FparCoeffs[j], e)
							if !elemEqual(in.K, coeffVal, fpar[j]) {
								fmt.Printf("[PIOP_DEBUG_EQ4_K] fparCoeff[%d] coeff!=eval\n", j)
								break
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
						for j := 0; j < limit; j++ {
							if in.Fagg[j] == nil || in.Ring == nil {
								continue
							}
							tmp := in.Ring.NewPoly()
							in.Ring.InvNTT(in.Fagg[j], tmp)
							polyVal := in.K.EvalFPolyAtK(tmp.Coeffs[0], e)
							if !elemEqual(in.K, polyVal, fagg[j]) {
								fmt.Printf("[PIOP_DEBUG_EQ4_K] fagg[%d] poly!=eval\n", j)
								break
							}
						}
					}
					if len(in.FaggCoeffs) > 0 {
						limit := len(fagg)
						if limit > len(in.FaggCoeffs) {
							limit = len(in.FaggCoeffs)
						}
						for j := 0; j < limit; j++ {
							if len(in.FaggCoeffs[j]) == 0 {
								continue
							}
							coeffVal := in.K.EvalFPolyAtK(in.FaggCoeffs[j], e)
							if !elemEqual(in.K, coeffVal, fagg[j]) {
								fmt.Printf("[PIOP_DEBUG_EQ4_K] faggCoeff[%d] coeff!=eval\n", j)
								break
							}
						}
					}
					fmt.Printf("[PIOP_DEBUG_EQ4_K] lhs=%v rhsMask=%v rhsPar=%v rhsAgg=%v rhs=%v\n", lhs, rhsMask, rhsPar, rhsAgg, rhs)
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
	selectedRows := in.SelectedRows
	if len(selectedRows) > 0 {
		rowCount = len(selectedRows)
	}
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
			return false, fmt.Errorf("q opening missing idx %d", idx)
		}
		rowVals := make([]uint64, rowCount)
		if len(selectedRows) > 0 {
			for j, rowIdx := range selectedRows {
				if rowIdx < 0 || rowIdx >= openRowCount {
					return false, fmt.Errorf("selected row idx %d out of range (rows=%d)", rowIdx, openRowCount)
				}
				rowVals[j] = decs.GetOpeningPval(in.RowOpen, posRow, rowIdx) % q
			}
		} else {
			for j := 0; j < rowCount; j++ {
				rowVals[j] = decs.GetOpeningPval(in.RowOpen, posRow, j) % q
			}
		}
		fpar, fagg, err := eval(uint64(idx), rowVals)
		if err != nil {
			return false, err
		}
		x, xerr := pointAt(idx)
		if xerr != nil {
			return false, xerr
		}
		if len(in.FparOverrideIdxs) > 0 && len(in.FparCoeffs) > 0 {
			for _, familyIdx := range in.FparOverrideIdxs {
				if familyIdx < 0 || familyIdx >= len(fpar) || familyIdx >= len(in.FparCoeffs) {
					continue
				}
				fpar[familyIdx] = EvalPoly(in.FparCoeffs[familyIdx], x, q) % q
			}
		}
		if len(in.FaggOverrideIdxs) > 0 && len(in.FaggCoeffs) > 0 {
			for _, familyIdx := range in.FaggOverrideIdxs {
				if familyIdx < 0 || familyIdx >= len(fagg) || familyIdx >= len(in.FaggCoeffs) {
					continue
				}
				fagg[familyIdx] = EvalPoly(in.FaggCoeffs[familyIdx], x, q) % q
			}
		}
		for i := 0; i < rho; i++ {
			lhs := decs.GetOpeningPval(in.QOpen, posQ, i) % q
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
				if os.Getenv("PIOP_DEBUG_EQ4_TAIL") == "1" {
					fmt.Printf("[PIOP_DEBUG_EQ4_TAIL] idx=%d row=%d lhs=%d rhs=%d overrides=%v fparLen=%d coeffLen=%d\n", idx, i, lhs, rhs, in.FparOverrideIdxs, len(fpar), len(in.FparCoeffs))
					for _, familyIdx := range in.FparOverrideIdxs {
						if familyIdx >= 0 && familyIdx < len(fpar) && familyIdx < len(in.FparCoeffs) {
							fmt.Printf("[PIOP_DEBUG_EQ4_TAIL] fpar[%d]=%d coeffEval=%d\n", familyIdx, fpar[familyIdx], EvalPoly(in.FparCoeffs[familyIdx], x, q)%q)
						}
					}
				}
				return false, fmt.Errorf("eq4 tail replay mismatch idx=%d row=%d lhs=%d rhs=%d", idx, i, lhs, rhs)
			}
		}
	}
	return true, nil
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
