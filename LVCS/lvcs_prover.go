package lvcs

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"time"

	decs "vSIS-Signature/DECS"
	swdomain "vSIS-Signature/internal/domain"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type Opening struct {
	DECSOpen *decs.DECSOpening
}

// MergeOpeningsV2 combines LVCS mask and tail openings using DECS's strict
// index-keyed tape merge rules.
func MergeOpeningsV2(ctx decs.CommitmentContext, mask, tail *Opening) (*Opening, error) {
	var maskOpen, tailOpen *decs.DECSOpening
	if mask != nil {
		maskOpen = mask.DECSOpen
	}
	if tail != nil {
		tailOpen = tail.DECSOpen
	}
	merged, err := decs.MergeOpeningsV2(ctx, maskOpen, tailOpen)
	if err != nil {
		return nil, err
	}
	return &Opening{DECSOpen: merged}, nil
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
	TrustedHead    bool
	headProvenance *directHeadProvenance
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
	RootHash      []byte       // full DECS Merkle root hash
	Context       decs.CommitmentContext
	TailLen       int          // ℓ
	Layout        OracleLayout // oracle segmentation metadata

	// Points is the explicit DECS evaluation domain E.
	Points []uint64
	// PreparedDomain is non-nil when this key was constructed through the
	// immutable prepared-domain API. Points remains an owned compatibility copy.
	PreparedDomain *swdomain.Prepared
	NLeaves        int

	nttOnce sync.Once
	nttErr  error
	// headMatchesCommitted records which retained heads were either used to
	// interpolate the committed polynomial or checked against it. Legacy
	// TrustedHead hints deliberately do not qualify for the EvalOracle fast path.
	headMatchesCommitted []bool
}

// CommitOptions carries benchmark-only commit controls. The zero value keeps
// the existing transcript and proof bytes.
type CommitOptions struct {
	PhaseRecorder       decs.CommitPhaseRecorder
	DecsWorkerCount     int
	DecsChunkLeaves     int
	DecsRecordSubphases bool
	DecsFormalEvalMode  decs.FormalEvalMode
	DecsMaxTapeBytes    int
	// DeferNTTMaterialization skips construction of RowPolys and MaskPolys until
	// MaterializeNTTPolys is called. The zero value preserves eager behavior.
	DeferNTTMaterialization bool
	commitmentContext       *decs.CommitmentContext
	preparedDomain          *swdomain.Prepared
}

// CommitInitWithParamsAndPointsV2 commits rows under the explicit v2
// version/role/salt context and returns the full-width DECS root.
func CommitInitWithParamsAndPointsV2(
	ringQ *ring.Ring,
	rows []RowInput,
	ell int,
	params decs.Params,
	points []uint64,
	ctx decs.CommitmentContext,
	opts CommitOptions,
) ([]byte, *ProverKey, error) {
	if err := ctx.Validate(); err != nil {
		return nil, nil, err
	}
	ctxCopy := ctx
	ctxCopy.Salt = append([]byte(nil), ctx.Salt...)
	opts.commitmentContext = &ctxCopy
	prover, err := commitInitWithParamsAndPointsV2(ringQ, rows, ell, params, points, opts)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), prover.RootHash...), prover, nil
}

// CommitInitWithParamsAndPreparedDomainV2 commits against an immutable domain
// whose range and distinctness checks have already succeeded.
func CommitInitWithParamsAndPreparedDomainV2(
	ringQ *ring.Ring,
	rows []RowInput,
	ell int,
	params decs.Params,
	prepared *swdomain.Prepared,
	ctx decs.CommitmentContext,
	opts CommitOptions,
) ([]byte, *ProverKey, error) {
	if err := ctx.Validate(); err != nil {
		return nil, nil, err
	}
	if prepared == nil {
		return nil, nil, fmt.Errorf("CommitInitWithParamsAndPreparedDomainV2: nil prepared domain")
	}
	ctxCopy := ctx
	ctxCopy.Salt = append([]byte(nil), ctx.Salt...)
	opts.commitmentContext = &ctxCopy
	opts.preparedDomain = prepared
	prover, err := commitInitWithParamsAndPointsV2(ringQ, rows, ell, params, nil, opts)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), prover.RootHash...), prover, nil
}

// commitInitWithParamsAndPointsV2 commits rows against an explicit
// DECS domain E with benchmark-only controls:
//   - points defines the DECS evaluation domain E (E[i] = points[i])
//   - Ω and Ω′ are interpreted as the prefixes:
//     Ω  = points[0:ncols]
//     Ω′ = points[ncols : ncols+ell]
func commitInitWithParamsAndPointsV2(
	ringQ *ring.Ring,
	rows []RowInput,
	ell int,
	params decs.Params,
	points []uint64,
	opts CommitOptions,
) (
	prover *ProverKey,
	err error,
) {
	if ringQ == nil || len(ringQ.Modulus) != 1 {
		err = fmt.Errorf("CommitInitWithParams: expected a single-modulus non-nil ring")
		return
	}
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
	if opts.preparedDomain != nil {
		binding := opts.preparedDomain.Binding()
		if binding.Q != q0 {
			err = fmt.Errorf("CommitInitWithParams: prepared domain modulus=%d want=%d", binding.Q, q0)
			return
		}
		if binding.Ell != ell {
			err = fmt.Errorf("CommitInitWithParams: prepared domain ell=%d want=%d", binding.Ell, ell)
			return
		}
		points = opts.preparedDomain.CopyPoints()
	}
	if len(points) == 0 {
		err = fmt.Errorf("CommitInitWithParams: points must be non-empty")
		return
	}
	nLeaves := len(points)
	if opts.preparedDomain == nil {
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
	}

	normalised := make([]RowInput, nrows)
	rowCoeffPolys := make([][]uint64, nrows)
	headMatchesCommitted := make([]bool, nrows)
	ncols := len(rows[0].Head)
	if ncols <= 0 {
		err = fmt.Errorf("CommitInitWithParams: rows must have non-empty head")
		return
	}
	if opts.preparedDomain != nil && opts.preparedDomain.Binding().OmegaSize != ncols {
		err = fmt.Errorf("CommitInitWithParams: prepared domain omega size=%d want=%d", opts.preparedDomain.Binding().OmegaSize, ncols)
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
			authenticatedHead := directHeadProvenanceMatches(in, coeffs, opts.preparedDomain, ncols)
			trustedWithoutCheck := (in.TrustedHead || authenticatedHead) && len(in.Head) > 0
			var headVals []uint64
			if trustedWithoutCheck {
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
			if len(in.Head) > 0 && !trustedWithoutCheck {
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
			headMatchesCommitted[j] = authenticatedHead || !trustedWithoutCheck
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
		headMatchesCommitted[j] = true
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
	if opts.preparedDomain != nil {
		dprover, err = decs.NewProverWithParamsAndPreparedDomainFormalChecked(ringQ, rowCoeffPolys, params, opts.preparedDomain)
	} else {
		dprover, err = decs.NewProverWithParamsAndPointsFormalChecked(ringQ, rowCoeffPolys, params, points)
	}
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			dprover.ReleaseTapes()
		}
	}()
	decsOpts := decs.CommitOptions{
		PhaseRecorder:      opts.PhaseRecorder,
		WorkerCount:        opts.DecsWorkerCount,
		ChunkLeaves:        opts.DecsChunkLeaves,
		RecordSubphases:    opts.DecsRecordSubphases,
		FormalEvalMode:     opts.DecsFormalEvalMode,
		MaxTapeBufferBytes: opts.DecsMaxTapeBytes,
	}
	if opts.commitmentContext == nil {
		err = fmt.Errorf("CommitInitWithParams: missing v2 commitment context")
		return
	}
	rootHash, err := dprover.CommitInitV2WithOptions(*opts.commitmentContext, decsOpts)
	if err != nil {
		return
	}
	Gamma, err := decs.DeriveGammaV2(*opts.commitmentContext, rootHash, params.Eta, nrows, q0)
	if err != nil {
		return
	}

	prover = &ProverKey{
		RingQ:                ringQ,
		DecsProver:           dprover,
		Rows:                 normalised,
		RowPolyCoeffs:        rowCoeffPolys,
		Gamma:                Gamma,
		Params:               params,
		RootHash:             append([]byte(nil), rootHash...),
		TailLen:              ell,
		Points:               append([]uint64(nil), points...),
		PreparedDomain:       opts.preparedDomain,
		NLeaves:              nLeaves,
		headMatchesCommitted: headMatchesCommitted,
		Layout: OracleLayout{
			Witness: LayoutSegment{Offset: 0, Count: nrows},
			Mask:    LayoutSegment{Offset: nrows, Count: 0},
		},
	}
	if opts.commitmentContext != nil {
		prover.Context = *opts.commitmentContext
		prover.Context.Salt = append([]byte(nil), opts.commitmentContext.Salt...)
	}
	if !opts.DeferNTTMaterialization {
		rowNTTStart := time.Time{}
		if opts.PhaseRecorder != nil {
			rowNTTStart = time.Now()
		}
		if err = prover.MaterializeNTTPolys(); err != nil {
			return
		}
		if opts.PhaseRecorder != nil {
			opts.PhaseRecorder.RecordDuration("lvcs.row_ntt", time.Since(rowNTTStart))
		}
	}
	return
}

// MaterializeNTTPolys constructs the compatibility NTT views exactly once.
// It is safe for concurrent callers. Strict prepared proving paths that do not
// rebuild constraints can leave these views deferred for the key's lifetime.
func (pk *ProverKey) MaterializeNTTPolys() error {
	if pk == nil {
		return fmt.Errorf("MaterializeNTTPolys: nil ProverKey")
	}
	pk.nttOnce.Do(func() {
		if pk.RingQ == nil || len(pk.RingQ.Modulus) != 1 {
			pk.nttErr = fmt.Errorf("MaterializeNTTPolys: expected a single-modulus ring")
			return
		}
		if pk.DecsProver == nil {
			pk.nttErr = fmt.Errorf("MaterializeNTTPolys: nil DECS prover")
			return
		}
		rowsNTT := make([]*ring.Poly, len(pk.RowPolyCoeffs))
		for rowIndex, coefficients := range pk.RowPolyCoeffs {
			if len(coefficients) == 0 || len(coefficients) > int(pk.RingQ.N) {
				continue
			}
			coefficientPoly := pk.RingQ.NewPoly()
			copy(coefficientPoly.Coeffs[0], coefficients)
			rowsNTT[rowIndex] = pk.RingQ.NewPoly()
			pk.RingQ.NTT(coefficientPoly, rowsNTT[rowIndex])
		}

		masksNTT := make([]*ring.Poly, pk.Params.Eta)
		if pk.DecsProver.MFormal != nil {
			for maskIndex := 0; maskIndex < pk.Params.Eta; maskIndex++ {
				if maskIndex >= len(pk.DecsProver.MFormal) || len(pk.DecsProver.MFormal[maskIndex]) > int(pk.RingQ.N) {
					continue
				}
				coefficientPoly := pk.RingQ.NewPoly()
				copy(coefficientPoly.Coeffs[0], pk.DecsProver.MFormal[maskIndex])
				masksNTT[maskIndex] = pk.RingQ.NewPoly()
				pk.RingQ.NTT(coefficientPoly, masksNTT[maskIndex])
			}
		} else {
			if len(pk.DecsProver.M) < pk.Params.Eta {
				pk.nttErr = fmt.Errorf("MaterializeNTTPolys: mask polynomial count=%d want=%d", len(pk.DecsProver.M), pk.Params.Eta)
				return
			}
			for maskIndex := 0; maskIndex < pk.Params.Eta; maskIndex++ {
				masksNTT[maskIndex] = pk.RingQ.NewPoly()
				pk.RingQ.NTT(pk.DecsProver.M[maskIndex], masksNTT[maskIndex])
			}
		}
		pk.RowPolys = rowsNTT
		pk.MaskPolys = masksNTT
	})
	return pk.nttErr
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

	for k := 0; k < m; k++ {
		if len(reqs[k].Coeffs) != nrows {
			return nil, fmt.Errorf("EvalInitMany: coeff length mismatch (got %d want %d)", len(reqs[k].Coeffs), nrows)
		}
	}

	// The maintained q0 is a ~20-bit prime, so many reduced products can be
	// accumulated before a Barrett reduction. Keep the generic reduction path
	// for wider moduli, and derive the block size with room for the reduced value
	// carried from the previous block.
	red := NewReducer64(q0)
	maxLazyTerms := red.MaxLazyAccumulationTerms()
	lazy := maxLazyTerms > 0
	safeBlock := nrows
	if lazy && maxLazyTerms < uint64(safeBlock) {
		safeBlock = int(maxLazyTerms)
	}
	// One contiguous backing block instead of m separate allocations.
	backing := make([]uint64, m*ell)
	bar := make([][]uint64, m)
	for k := 0; k < m; k++ {
		bar[k] = backing[k*ell : (k+1)*ell : (k+1)*ell]
	}
	compute := func(k int) {
		acc := bar[k]
		coeffs := reqs[k].Coeffs
		if !lazy {
			for j := 0; j < nrows; j++ {
				row := prover.Rows[j].Tail
				for i := 0; i < ell; i++ {
					acc[i] = MulAddMod64(acc[i], coeffs[j], row[i], q0)
				}
			}
			return
		}
		sinceReduce := 0
		for j := 0; j < nrows; j++ {
			cij := coeffs[j]
			if cij >= q0 {
				cij %= q0
			}
			if cij == 0 {
				continue
			}
			row := prover.Rows[j].Tail
			i := 0
			limit := ell - ell%4
			for ; i < limit; i += 4 {
				r0, r1 := row[i], row[i+1]
				r2, r3 := row[i+2], row[i+3]
				if r0 >= q0 {
					r0 %= q0
				}
				if r1 >= q0 {
					r1 %= q0
				}
				if r2 >= q0 {
					r2 %= q0
				}
				if r3 >= q0 {
					r3 %= q0
				}
				acc[i] += cij * r0
				acc[i+1] += cij * r1
				acc[i+2] += cij * r2
				acc[i+3] += cij * r3
			}
			for ; i < ell; i++ {
				r := row[i]
				if r >= q0 {
					r %= q0
				}
				acc[i] += cij * r
			}
			if sinceReduce++; sinceReduce == safeBlock {
				for i := 0; i < ell; i++ {
					acc[i] = red.Reduce(acc[i])
				}
				sinceReduce = 0
			}
		}
		for i := 0; i < ell; i++ {
			acc[i] = red.Reduce(acc[i])
		}
	}
	// Each request row is independent, so fan out over k; small inputs stay serial.
	workers := runtime.GOMAXPROCS(0)
	if workers > m {
		workers = m
	}
	if workers <= 1 || m < 8 || m*ell < 1<<14 {
		for k := 0; k < m; k++ {
			compute(k)
		}
		return bar, nil
	}
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		start := worker * m / workers
		end := (worker + 1) * m / workers
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for k := start; k < end; k++ {
				compute(k)
			}
		}(start, end)
	}
	wg.Wait()
	return bar, nil
}

// EvalFinishV2 returns a checked selective-tape opening. Duplicate or invalid
// indices are rejected rather than silently producing a malformed proof.
func EvalFinishV2(prover *ProverKey, indices []int) (*Opening, error) {
	if prover == nil || prover.DecsProver == nil {
		return nil, fmt.Errorf("lvcs: EvalFinishV2 requires a v2 prover")
	}
	if err := prover.Context.Validate(); err != nil {
		return nil, fmt.Errorf("lvcs: EvalFinishV2 invalid commitment context: %w", err)
	}
	opening, err := prover.DecsProver.EvalOpenV2(indices)
	if err != nil {
		return nil, err
	}
	return &Opening{DECSOpen: opening}, nil
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

	if len(ringQ.Modulus) != 1 {
		return OracleResponses{}, fmt.Errorf("EvalOracle: expected a single-modulus ring")
	}
	q0 := ringQ.Modulus[0]
	if isExactOmegaHeadRequest(prover, points) {
		copyHeads := func(segment LayoutSegment, destination [][]uint64) error {
			for rowIndex := segment.Offset; rowIndex < segment.End(); rowIndex++ {
				if len(prover.Rows[rowIndex].Head) != len(points) {
					return fmt.Errorf("EvalOracle: row %d head length=%d want=%d", rowIndex, len(prover.Rows[rowIndex].Head), len(points))
				}
				values := make([]uint64, len(points))
				for pointIndex, value := range prover.Rows[rowIndex].Head {
					values[pointIndex] = value % q0
				}
				destination[rowIndex-segment.Offset] = values
			}
			return nil
		}
		if err := copyHeads(effective.Witness, resp.Witness); err != nil {
			return OracleResponses{}, err
		}
		if err := copyHeads(effective.Mask, resp.Mask); err != nil {
			return OracleResponses{}, err
		}
		return resp, nil
	}
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

func isExactOmegaHeadRequest(prover *ProverKey, points []uint64) bool {
	if prover == nil || len(prover.Rows) == 0 {
		return false
	}
	ncols := len(prover.Rows[0].Head)
	if ncols == 0 || len(points) != ncols {
		return false
	}
	if len(prover.headMatchesCommitted) != len(prover.Rows) {
		return false
	}
	for _, matches := range prover.headMatchesCommitted {
		if !matches {
			return false
		}
	}
	if prover.PreparedDomain != nil {
		binding := prover.PreparedDomain.Binding()
		if binding.OmegaSize != ncols || prover.PreparedDomain.Len() < ncols {
			return false
		}
		for pointIndex, point := range points {
			if point != prover.PreparedDomain.At(pointIndex) {
				return false
			}
		}
		return true
	}
	if len(prover.Points) < ncols {
		return false
	}
	for pointIndex, point := range points {
		if point != prover.Points[pointIndex] {
			return false
		}
	}
	return true
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
