package lvcs

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type Opening struct {
	DECSOpen *decs.DECSOpening
}

// RowInput specifies one logical LVCS row. If Poly is non-nil, the prover
// commits that polynomial directly and derives the Ω/Ω' evaluations from it.
type RowInput struct {
	Head []uint64
	Tail []uint64
	Poly *ring.Poly // optional: coefficient-form polynomial to commit directly (ring-backed)
	// PolyCoeffs optionally provides a formal coefficient slice to commit directly.
	// When set, it takes precedence over Poly and is valid in explicit-domain mode
	// even when degree exceeds ringQ.N-1.
	PolyCoeffs []uint64
	// TrustedHead skips recomputing Ω values for direct-polynomial rows. It is
	// only an internal prover-side optimization hint; callers that do not set it
	// keep the full consistency check.
	TrustedHead bool
}

// LayoutSegment tracks a contiguous row slice within the global oracle.
type LayoutSegment struct {
	Offset int
	Count  int
}

func (s LayoutSegment) End() int {
	return s.Offset + s.Count
}

// OracleLayout partitions the LVCS oracle rows into witness and mask regions.
type OracleLayout struct {
	Witness LayoutSegment
	Mask    LayoutSegment
}

// EvalRequest encapsulates a single LVCS evaluation query. Point (or KPoint)
// binds the Fiat–Shamir transcript to the evaluation target, while Coeffs
// holds the linear form applied to the committed rows.
type EvalRequest struct {
	Point  uint64   // optional when opening over F
	KPoint []uint64 // optional when opening over K (θ limbs)
	Coeffs []uint64 // linear coefficients over F for this query
}

// OracleResponses mirrors the prover’s oracle evaluations split by layout.
type OracleResponses struct {
	Points  []uint64
	Witness [][]uint64
	Mask    [][]uint64
}

// ProverKey holds everything the prover needs between Commit and Eval.
type ProverKey struct {
	RingQ      *ring.Ring   // so we can grab q later without touching unexported decs.Prover.ringQ
	DecsProver *decs.Prover // underlying DECS prover

	Rows          []RowInput   // materialised rows including tails
	MaskPolys     []*ring.Poly // the η=ℓ′ mask-polynomials  M_i(X)  (NTT domain, optional in explicit/formal mode)
	RowPolys      []*ring.Poly // one polynomial per *row* in NTT form when representable
	RowPolyCoeffs [][]uint64   // formal row coefficients (always populated)
	Gamma         [][]uint64   // gamma values for the prover
	Params        decs.Params  // DECS parameters
	TailLen       int          // ℓ
	Layout        OracleLayout // oracle segmentation metadata

	// Points is the explicit DECS evaluation domain E.
	Points  []uint64
	NLeaves int
}

// CommitOptions carries benchmark-only commit controls. The zero value keeps
// the existing transcript and proof bytes.
type CommitOptions struct {
	PhaseRecorder      decs.CommitPhaseRecorder
	DecsWorkerCount    int
	DecsFormalEvalMode decs.FormalEvalMode
}

// CommitInitWithParamsAndPoints commits rows against an explicit DECS domain E:
//   - points defines the DECS evaluation domain E (E[i] = points[i])
//   - Ω and Ω′ are interpreted as the prefixes:
//     Ω  = points[0:ncols]
//     Ω′ = points[ncols : ncols+ell]
func CommitInitWithParamsAndPoints(
	ringQ *ring.Ring,
	rows []RowInput,
	ell int,
	params decs.Params,
	points []uint64,
) (
	root [16]byte,
	prover *ProverKey,
	err error,
) {
	return CommitInitWithParamsAndPointsWithOptions(ringQ, rows, ell, params, points, CommitOptions{})
}

// CommitInitWithParamsAndPointsWithOptions is CommitInitWithParamsAndPoints
// with benchmark-only controls.
func CommitInitWithParamsAndPointsWithOptions(
	ringQ *ring.Ring,
	rows []RowInput,
	ell int,
	params decs.Params,
	points []uint64,
	opts CommitOptions,
) (
	root [16]byte,
	prover *ProverKey,
	err error,
) {
	if ell <= 0 {
		err = fmt.Errorf("CommitInitWithParams: ell must be > 0")
		return
	}

	nrows := len(rows)
	if nrows == 0 {
		err = fmt.Errorf("CommitInitWithParams: rows must be non-empty")
		return
	}
	q0 := ringQ.Modulus[0]
	if len(points) == 0 {
		err = fmt.Errorf("CommitInitWithParams: points must be non-empty")
		return
	}
	nLeaves := len(points)
	seen := make(map[uint64]struct{}, nLeaves)
	for i, p := range points {
		if p >= q0 {
			err = fmt.Errorf("CommitInitWithParams: points[%d]=%d out of range (q=%d)", i, p, q0)
			return
		}
		if _, ok := seen[p]; ok {
			err = fmt.Errorf("CommitInitWithParams: duplicate domain point %d", p)
			return
		}
		seen[p] = struct{}{}
	}

	normalised := make([]RowInput, nrows)
	rowCoeffPolys := make([][]uint64, nrows)
	ncols := len(rows[0].Head)
	if ncols <= 0 {
		err = fmt.Errorf("CommitInitWithParams: rows must have non-empty head")
		return
	}
	if len(points) < ncols+ell {
		err = fmt.Errorf("CommitInitWithParams: points length %d too small for ncols+ell=%d", len(points), ncols+ell)
		return
	}
	if nLeaves < ncols+2*ell {
		err = fmt.Errorf("CommitInitWithParams: need |E| >= ncols+2*ell for tail sampling (got nLeaves=%d, ncols=%d, ell=%d)", nLeaves, ncols, ell)
		return
	}

	interpPlan, err := getInterpolationPlan(points[:ncols+ell], ncols, ell, q0)
	if err != nil {
		return
	}

	// 1a) ensure tail materialisation ̄r_j ∈ F_q^ℓ
	for j, in := range rows {
		if in.Poly != nil || len(in.PolyCoeffs) > 0 {
			// Commit a provided polynomial directly.
			if params.Degree < 0 {
				err = fmt.Errorf("CommitInitWithParams: invalid degree parameter %d (ring N=%d)", params.Degree, ringQ.N)
				return
			}
			var coeffs []uint64
			if len(in.PolyCoeffs) > 0 {
				coeffs = trimCoeffsMod(in.PolyCoeffs, q0)
			} else {
				coeffs = trimCoeffsMod(in.Poly.Coeffs[0], q0)
			}
			for idx := params.Degree + 1; idx < len(coeffs); idx++ {
				if coeffs[idx] != 0 {
					err = fmt.Errorf("CommitInitWithParams: row %d polynomial exceeds degree bound (idx=%d > %d)", j, idx, params.Degree)
					return
				}
			}
			var headVals []uint64
			if in.TrustedHead && len(in.Head) > 0 {
				if len(in.Head) != ncols {
					err = fmt.Errorf("CommitInitWithParams: inconsistent trusted head length for row %d (got %d want %d)", j, len(in.Head), ncols)
					return
				}
				headVals = append([]uint64(nil), in.Head...)
				for i := range headVals {
					headVals[i] %= q0
				}
			} else {
				headVals = make([]uint64, ncols)
				for i := 0; i < ncols; i++ {
					headVals[i] = evalPolyCoeffs(coeffs, points[i]%q0, q0)
				}
			}
			tailVals := make([]uint64, ell)
			for i := 0; i < ell; i++ {
				tailVals[i] = evalPolyCoeffs(coeffs, points[ncols+i]%q0, q0)
			}
			if len(in.Head) > 0 && !in.TrustedHead {
				if len(in.Head) != ncols {
					err = fmt.Errorf("CommitInitWithParams: inconsistent head length for row %d (got %d want %d)", j, len(in.Head), ncols)
					return
				}
				for i := 0; i < ncols; i++ {
					if in.Head[i]%q0 != headVals[i]%q0 {
						err = fmt.Errorf("CommitInitWithParams: row %d head[%d] mismatch (got %d want %d)", j, i, in.Head[i]%q0, headVals[i]%q0)
						return
					}
				}
			}
			if in.Tail != nil {
				if len(in.Tail) != ell {
					err = fmt.Errorf("CommitInitWithParams: row %d tail length mismatch (got %d want %d)", j, len(in.Tail), ell)
					return
				}
				for i := 0; i < ell; i++ {
					if in.Tail[i]%q0 != tailVals[i]%q0 {
						err = fmt.Errorf("CommitInitWithParams: row %d tail[%d] mismatch (got %d want %d)", j, i, in.Tail[i]%q0, tailVals[i]%q0)
						return
					}
				}
			}
			normalised[j] = RowInput{Head: headVals, Tail: tailVals}
			rowCoeffPolys[j] = coeffs
			continue
		}

		headLen := len(in.Head)
		if headLen == 0 {
			err = fmt.Errorf("CommitInitWithParams: row %d has empty head", j)
			return
		}
		if headLen != ncols {
			err = fmt.Errorf("CommitInitWithParams: inconsistent head length (row %d has %d, expected %d)", j, headLen, ncols)
			return
		}
		headCopy := append([]uint64(nil), in.Head...)
		tailCopy := make([]uint64, ell)
		switch {
		case in.Tail == nil:
			for i := 0; i < ell; i++ {
				x, _ := rand.Int(rand.Reader, big.NewInt(int64(q0)))
				tailCopy[i] = uint64(x.Int64())
			}
		case len(in.Tail) != ell:
			err = fmt.Errorf("CommitInitWithParams: row %d tail length mismatch (got %d want %d)", j, len(in.Tail), ell)
			return
		default:
			copy(tailCopy, in.Tail)
			for i := 0; i < ell; i++ {
				tailCopy[i] %= q0
			}
		}
		normalised[j] = RowInput{
			Head: headCopy,
			Tail: tailCopy,
		}
	}

	// 1b) interpolate each (r_j, mask_j) into P_j(X)
	interpStart := time.Time{}
	if opts.PhaseRecorder != nil {
		interpStart = time.Now()
	}
	for j, row := range normalised {
		if rowCoeffPolys[j] != nil {
			continue
		}
		if len(row.Tail) != ell {
			err = fmt.Errorf("CommitInitWithParams: tail length mismatch for row %d", j)
			return
		}
		rowCoeffPolys[j], err = interpolateRowCoeffsWithPlan(row.Head, row.Tail, interpPlan)
		if err != nil {
			return
		}
	}
	if opts.PhaseRecorder != nil {
		opts.PhaseRecorder.RecordDuration("lvcs.row_interpolation", time.Since(interpStart))
	}

	// 2) DECS.CommitInit  (keeps P_j in coeff-form; we keep a *copy*
	//    in NTT domain for the PACS layer → RowPolys)
	var dprover *decs.Prover
	dprover, err = decs.NewProverWithParamsAndPointsFormalChecked(ringQ, rowCoeffPolys, params, points)
	if err != nil {
		return
	}
	if root, err = dprover.CommitInitWithOptions(decs.CommitOptions{
		PhaseRecorder:  opts.PhaseRecorder,
		WorkerCount:    opts.DecsWorkerCount,
		FormalEvalMode: opts.DecsFormalEvalMode,
	}); err != nil {
		return
	}
	Gamma := decs.DeriveGamma(root, params.Eta, nrows, q0)

	// lift P_j to NTT for later reuse when representable in ringQ.
	rowNTTStart := time.Time{}
	if opts.PhaseRecorder != nil {
		rowNTTStart = time.Now()
	}
	rowsNTT := make([]*ring.Poly, nrows)
	for j := range rowCoeffPolys {
		if len(rowCoeffPolys[j]) == 0 || len(rowCoeffPolys[j]) > int(ringQ.N) {
			continue
		}
		pj := ringQ.NewPoly()
		copy(pj.Coeffs[0], rowCoeffPolys[j])
		rowsNTT[j] = ringQ.NewPoly()
		ringQ.NTT(pj, rowsNTT[j])
	}

	// Export DECS masks in NTT form when representable.
	masksNTT := make([]*ring.Poly, params.Eta)
	if dprover.MFormal != nil {
		for i := 0; i < params.Eta; i++ {
			if i >= len(dprover.MFormal) || len(dprover.MFormal[i]) > int(ringQ.N) {
				continue
			}
			mi := ringQ.NewPoly()
			copy(mi.Coeffs[0], dprover.MFormal[i])
			masksNTT[i] = ringQ.NewPoly()
			ringQ.NTT(mi, masksNTT[i])
		}
	} else {
		for i := 0; i < params.Eta; i++ {
			masksNTT[i] = ringQ.NewPoly()
			ringQ.NTT(dprover.M[i], masksNTT[i])
		}
	}
	if opts.PhaseRecorder != nil {
		opts.PhaseRecorder.RecordDuration("lvcs.row_ntt", time.Since(rowNTTStart))
	}
	prover = &ProverKey{
		RingQ:         ringQ,
		DecsProver:    dprover,
		Rows:          normalised,
		RowPolys:      rowsNTT,
		RowPolyCoeffs: rowCoeffPolys,
		MaskPolys:     masksNTT,
		Gamma:         Gamma,
		Params:        params,
		TailLen:       ell,
		Points:        points,
		NLeaves:       nLeaves,
		Layout: OracleLayout{
			Witness: LayoutSegment{Offset: 0, Count: nrows},
			Mask:    LayoutSegment{Offset: nrows, Count: 0},
		},
	}
	return
}

// EvalInitManyChecked is the error-returning variant of EvalInitMany for
// library callers.
func EvalInitManyChecked(
	ringQ *ring.Ring,
	prover *ProverKey,
	reqs []EvalRequest,
) ([][]uint64, error) {
	if prover == nil {
		return nil, fmt.Errorf("EvalInitMany: nil prover")
	}
	nrows := len(prover.Rows)
	m := len(reqs)
	if nrows == 0 {
		return nil, fmt.Errorf("EvalInitMany: prover has no rows")
	}
	ell := prover.TailLen
	q0 := ringQ.Modulus[0]

	bar := make([][]uint64, m)
	for k := 0; k < m; k++ {
		req := reqs[k]
		if len(req.Coeffs) != nrows {
			return nil, fmt.Errorf("EvalInitMany: coeff length mismatch (got %d want %d)", len(req.Coeffs), nrows)
		}
		bar[k] = make([]uint64, ell)
		for j := 0; j < nrows; j++ {
			cij := req.Coeffs[j] % q0
			row := prover.Rows[j].Tail
			for i := 0; i < ell; i++ {
				bar[k][i] = (bar[k][i] + cij*row[i]) % q0
			}
		}
	}
	return bar, nil
}

// EvalFinish – §4.1 steps 3–4:
// Open the masked positions via DECS.EvalOpen.
func EvalFinish(
	prover *ProverKey,
	E []int,
) *Opening {
	decsOpen := prover.DecsProver.EvalOpen(E)
	return &Opening{DECSOpen: decsOpen}
}

func validateLayout(total int, layout OracleLayout) error {
	if total < 0 {
		return fmt.Errorf("validateLayout: negative total rows")
	}
	if layout.Witness.Offset < 0 || layout.Witness.Count < 0 {
		return fmt.Errorf("validateLayout: invalid witness segment %+v", layout.Witness)
	}
	if layout.Mask.Offset < 0 || layout.Mask.Count < 0 {
		return fmt.Errorf("validateLayout: invalid mask segment %+v", layout.Mask)
	}
	if layout.Witness.End() > total {
		return fmt.Errorf("validateLayout: witness segment exceeds total rows (end=%d total=%d)", layout.Witness.End(), total)
	}
	if layout.Mask.End() > total {
		return fmt.Errorf("validateLayout: mask segment exceeds total rows (end=%d total=%d)", layout.Mask.End(), total)
	}
	if overlap(layout.Witness, layout.Mask) {
		return fmt.Errorf("validateLayout: witness and mask segments overlap")
	}
	return nil
}

func overlap(a, b LayoutSegment) bool {
	if a.Count == 0 || b.Count == 0 {
		return false
	}
	return a.Offset < b.End() && b.Offset < a.End()
}

// SetLayout stores the oracle layout after validating it against the row count.
func (pk *ProverKey) SetLayout(layout OracleLayout) error {
	if pk == nil {
		return fmt.Errorf("SetLayout: nil ProverKey")
	}
	if err := validateLayout(len(pk.Rows), layout); err != nil {
		return err
	}
	pk.Layout = layout
	return nil
}

// EvalOracle evaluates the committed rows at the provided points, partitioning
// the responses according to the requested layout. If layout is the zero value,
// the prover's stored layout is used.
func EvalOracle(
	ringQ *ring.Ring,
	prover *ProverKey,
	points []uint64,
	layout OracleLayout,
) (OracleResponses, error) {
	if ringQ == nil {
		return OracleResponses{}, fmt.Errorf("EvalOracle: nil ring")
	}
	if prover == nil {
		return OracleResponses{}, fmt.Errorf("EvalOracle: nil prover")
	}
	totalRows := len(prover.Rows)
	if totalRows != len(prover.RowPolyCoeffs) {
		return OracleResponses{}, fmt.Errorf("EvalOracle: row/coeff length mismatch (%d vs %d)", totalRows, len(prover.RowPolyCoeffs))
	}
	effective := layout
	if effective == (OracleLayout{}) {
		effective = prover.Layout
	}
	if err := validateLayout(totalRows, effective); err != nil {
		return OracleResponses{}, err
	}

	resp := OracleResponses{
		Points:  append([]uint64(nil), points...),
		Witness: make([][]uint64, effective.Witness.Count),
		Mask:    make([][]uint64, effective.Mask.Count),
	}

	q0 := ringQ.Modulus[0]
	tmp := ringQ.NewPoly()

	evalSegment := func(seg LayoutSegment, dest [][]uint64) {
		if seg.Count == 0 {
			return
		}
		for rowIdx := seg.Offset; rowIdx < seg.End(); rowIdx++ {
			coeffs := prover.RowPolyCoeffs[rowIdx]
			if len(coeffs) == 0 {
				if rowIdx >= len(prover.RowPolys) || prover.RowPolys[rowIdx] == nil {
					dest[rowIdx-seg.Offset] = make([]uint64, len(points))
					continue
				}
				ringQ.InvNTT(prover.RowPolys[rowIdx], tmp)
				coeffs = trimCoeffsMod(tmp.Coeffs[0], q0)
			}
			vals := make([]uint64, len(points))
			for i, pt := range points {
				vals[i] = evalPolyCoeffs(coeffs, pt%q0, q0)
			}
			dest[rowIdx-seg.Offset] = vals
		}
	}

	evalSegment(effective.Witness, resp.Witness)
	evalSegment(effective.Mask, resp.Mask)
	return resp, nil
}

func trimCoeffsMod(coeffs []uint64, mod uint64) []uint64 {
	if len(coeffs) == 0 {
		return []uint64{0}
	}
	out := make([]uint64, len(coeffs))
	for i := range coeffs {
		out[i] = coeffs[i] % mod
	}
	last := len(out) - 1
	for last > 0 && out[last] == 0 {
		last--
	}
	return out[:last+1]
}

func evalPolyCoeffs(coeffs []uint64, x, mod uint64) uint64 {
	res := uint64(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		res = MulMod64(res, x%mod, mod)
		res = AddMod64(res, coeffs[i]%mod, mod)
		if i == 0 {
			break
		}
	}
	return res % mod
}
