package PIOP

import (
	"fmt"
	"runtime"
	"sync"

	"vSIS-Signature/internal/fpoly"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildFparRangeMembershipComposeFormalCoeffs returns replayable membership
// constraints as formal coefficient vectors, together with ring-polynomial
// materialisations when the resulting degree fits ringQ.N.
func buildFparRangeMembershipComposeFormalCoeffs(
	r *ring.Ring,
	rows []*ring.Poly,
	spec RangeMembershipSpec,
) (Fpar []*ring.Poly, coeffs [][]uint64, err error) {
	if r == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(spec.Coeffs) == 0 {
		return []*ring.Poly{}, [][]uint64{}, nil
	}
	q := r.Modulus[0]
	memberPoly := fpoly.New(q, spec.Coeffs)

	toFormal := func(row *ring.Poly) (fpoly.Poly, error) {
		if row == nil {
			return fpoly.Zero(q), fmt.Errorf("nil row")
		}
		coeff, cerr := coeffFromNTTPoly(r, row)
		if cerr != nil {
			return fpoly.Zero(q), cerr
		}
		return fpoly.New(q, coeff), nil
	}
	toNTTIfFits := func(c []uint64) *ring.Poly {
		if len(c) == 0 {
			c = []uint64{0}
		}
		if len(c) > int(r.N) {
			return nil
		}
		out := r.NewPoly()
		copy(out.Coeffs[0], c)
		r.NTT(out, out)
		return out
	}

	Fpar = make([]*ring.Poly, len(rows))
	coeffs = make([][]uint64, len(rows))
	compute := func(i int) error {
		rowFormal, ferr := toFormal(rows[i])
		if ferr != nil {
			return fmt.Errorf("row %d: %w", i, ferr)
		}
		composed := memberPoly.Compose(rowFormal)
		coeffCopy := append([]uint64(nil), composed.Coeffs...)
		coeffs[i] = coeffCopy
		Fpar[i] = toNTTIfFits(coeffCopy)
		return nil
	}
	workers := minInt(runtime.GOMAXPROCS(0), len(rows))
	if workers <= 1 || len(rows) < 16 {
		for i := range rows {
			if err := compute(i); err != nil {
				return nil, nil, err
			}
		}
		return Fpar, coeffs, nil
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
		start := worker * len(rows) / workers
		end := (worker + 1) * len(rows) / workers
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				if err := compute(i); err != nil {
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
	return Fpar, coeffs, nil
}
