package PIOP

import (
	"fmt"
	"runtime"
	"sync"

	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildSigShortnessPackedMembershipFormalCoeffs(
	ringQ *ring.Ring,
	packedSourceRows []*ring.Poly,
	packedRows [][]*ring.Poly,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(packedRows) == 0 {
		return nil, nil, fmt.Errorf("empty packed signature shortness rows")
	}
	if len(packedSourceRows) > 0 && len(packedRows) != len(packedSourceRows) {
		return nil, nil, fmt.Errorf("packed row groups=%d want %d", len(packedRows), len(packedSourceRows))
	}
	groupCount := len(packedRows)
	cd := ChainDecomp{D: make([][]*ring.Poly, groupCount)}
	if spec.UsesAbsRow {
		cd.M = make([]*ring.Poly, groupCount)
	}
	for g := 0; g < groupCount; g++ {
		rows := packedRows[g]
		if spec.UsesAbsRow {
			if len(rows) != spec.L+1 {
				return nil, nil, fmt.Errorf("packed shortness rows/group=%d want %d", len(rows), spec.L+1)
			}
			cd.M[g] = rows[0]
			cd.D[g] = rows[1:]
		} else {
			if len(rows) != spec.L {
				return nil, nil, fmt.Errorf("packed shortness rows/group=%d want %d", len(rows), spec.L)
			}
			cd.D[g] = rows
		}
	}
	if len(packedSourceRows) == 0 {
		return buildPackedDigitMembershipFormalCoeffs(ringQ, packedRows, spec)
	}
	rows, coeffs := buildFparLinfChainComposeFormalCoeffs(ringQ, packedSourceRows, cd, spec)
	return rows, coeffs, nil
}

func buildSigShortnessPackedRecompositionFormalCoeffs(
	ringQ *ring.Ring,
	packedSourceRows []*ring.Poly,
	packedRows [][]*ring.Poly,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(packedSourceRows) == 0 {
		return nil, nil, fmt.Errorf("packed signature recomposition requires source rows")
	}
	if len(packedRows) != len(packedSourceRows) {
		return nil, nil, fmt.Errorf("packed row groups=%d want %d", len(packedRows), len(packedSourceRows))
	}
	if spec.UsesAbsRow {
		return nil, nil, fmt.Errorf("packed signature recomposition requires signed chain mode")
	}
	q := ringQ.Modulus[0]
	toFormal := func(row *ring.Poly) (fpoly.Poly, error) {
		if row == nil {
			return fpoly.Zero(q), fmt.Errorf("nil packed shortness row")
		}
		coeff, err := coeffFromNTTPoly(ringQ, row)
		if err != nil {
			return fpoly.Zero(q), err
		}
		return fpoly.New(q, trimPoly(coeff, q)), nil
	}
	outPolys := make([]*ring.Poly, 0, len(packedRows))
	outCoeffs := make([][]uint64, 0, len(packedRows))
	for g := range packedRows {
		if len(packedRows[g]) != spec.L {
			return nil, nil, fmt.Errorf("packed shortness rows/group=%d want %d", len(packedRows[g]), spec.L)
		}
		source, err := toFormal(packedSourceRows[g])
		if err != nil {
			return nil, nil, fmt.Errorf("packed source row %d: %w", g, err)
		}
		recon := fpoly.Zero(q)
		for lane := 0; lane < spec.L; lane++ {
			rowFormal, err := toFormal(packedRows[g][lane])
			if err != nil {
				return nil, nil, fmt.Errorf("packed recomposition row %d lane %d: %w", g, lane, err)
			}
			recon = recon.Add(rowFormal.Scale(spec.RPows[lane] % q))
		}
		residual := source.Sub(recon)
		coeff := trimPoly(append([]uint64(nil), residual.Coeffs...), q)
		outCoeffs = append(outCoeffs, coeff)
		outPolys = append(outPolys, nttPolyFromFormalCoeffsIfFits(ringQ, coeff))
	}
	return outPolys, outCoeffs, nil
}

func buildPackedDigitMembershipFormalCoeffs(
	ringQ *ring.Ring,
	packedRows [][]*ring.Poly,
	spec LinfSpec,
) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	q := ringQ.Modulus[0]
	toFormal := func(row *ring.Poly) (fpoly.Poly, error) {
		if row == nil {
			return fpoly.Zero(q), fmt.Errorf("nil packed shortness row")
		}
		coeff, err := coeffFromNTTPoly(ringQ, row)
		if err != nil {
			return fpoly.Zero(q), err
		}
		return fpoly.New(q, trimPoly(coeff, q)), nil
	}
	total := len(packedRows) * spec.L
	outPolys := make([]*ring.Poly, total)
	outCoeffs := make([][]uint64, total)
	for g := range packedRows {
		if len(packedRows[g]) != spec.L {
			return nil, nil, fmt.Errorf("packed shortness rows/group=%d want %d", len(packedRows[g]), spec.L)
		}
	}
	compute := func(idx int) error {
		g := idx / spec.L
		lane := idx % spec.L
		rowFormal, err := toFormal(packedRows[g][lane])
		if err != nil {
			return fmt.Errorf("packed digit membership coeffs: %w", err)
		}
		pi := fpoly.New(q, spec.PDi[lane]).Compose(rowFormal)
		coeff := trimPoly(append([]uint64(nil), pi.Coeffs...), q)
		outCoeffs[idx] = coeff
		outPolys[idx] = nttPolyFromFormalCoeffsIfFits(ringQ, coeff)
		return nil
	}
	workers := minInt(runtime.GOMAXPROCS(0), total)
	if workers <= 1 || total < 16 {
		for idx := 0; idx < total; idx++ {
			if err := compute(idx); err != nil {
				return nil, nil, err
			}
		}
		return outPolys, outCoeffs, nil
	}
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error
	setErr := func(err error) {
		if err != nil {
			errOnce.Do(func() {
				firstErr = err
			})
		}
	}
	for worker := 0; worker < workers; worker++ {
		start := worker * total / workers
		end := (worker + 1) * total / workers
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for idx := start; idx < end; idx++ {
				if err := compute(idx); err != nil {
					setErr(err)
					return
				}
			}
		}(start, end)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, nil, firstErr
	}
	return outPolys, outCoeffs, nil
}
