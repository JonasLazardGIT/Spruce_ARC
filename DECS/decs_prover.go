package decs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
	"golang.org/x/crypto/sha3"
)

// q32 dense storage is kept behind a local switch because the maintained q20
// profiles benchmark faster with uint64 coefficient rows on current hardware.
const enableFormalEvalUint32 = false

const (
	formalEvalDenseRowMajorMinRows = 512
	formalEvalDenseRowMajorMaxRows = 200
)

type formalEvalPlan struct {
	rowCount    int
	maxDeg      int
	nnz         int
	rowDeg      []int
	coeffs      []uint64
	coeffs32    []uint32
	rowOffsets  []int
	rowCoeffs   []uint64
	denseRows64 []uint64
	denseRows32 []uint32
	dotSafe     bool
	sparseTerms []formalEvalTerm
}

type formalEvalTerm struct {
	degree int
	row    int
	coeff  uint64
}

func newFormalEvalPlan(rows [][]uint64, q uint64) formalEvalPlan {
	// Dense row-major kernels remain an R&D candidate until the required
	// fixed-entropy paired end-to-end adoption gate is available. Production
	// therefore retains the established combined evaluator.
	return newFormalEvalPlanWithDenseRowMajor(rows, q, false)
}

func newFormalEvalPlanWithDenseRowMajor(rows [][]uint64, q uint64, enableDenseRowMajor bool) formalEvalPlan {
	rowCount := len(rows)
	rowDeg := make([]int, rowCount)
	for i := range rowDeg {
		rowDeg[i] = -1
	}
	maxDeg := -1
	nnz := 0
	for j, row := range rows {
		for d := len(row) - 1; d >= 0; d-- {
			c := row[d]
			if c >= q {
				c %= q
			}
			if c == 0 {
				continue
			}
			rowDeg[j] = d
			if d > maxDeg {
				maxDeg = d
			}
			break
		}
		for d := 0; d < len(row); d++ {
			c := row[d]
			if c >= q {
				c %= q
			}
			if c != 0 {
				nnz++
			}
		}
	}
	if maxDeg < 0 {
		maxDeg = 0
	}
	denseSlots := (maxDeg + 1) * rowCount
	rowSlots := 0
	for _, deg := range rowDeg {
		if deg >= 0 {
			rowSlots += deg + 1
		}
	}
	dotSafe := formalEvalDotSafe(maxDeg, q)
	useSparse := dotSafe && nnz*4 < denseSlots
	useUint32 := enableFormalEvalUint32 && dotSafe && q <= uint64(^uint32(0))
	useDenseRow64 := enableDenseRowMajor && dotSafe && nnz == denseSlots && maxDeg <= 64 && rowCount >= formalEvalDenseRowMajorMinRows
	useDenseRow32 := enableDenseRowMajor && dotSafe && nnz == denseSlots && maxDeg <= 64 && rowCount <= formalEvalDenseRowMajorMaxRows && q <= uint64(^uint32(0))
	useRowMajor := dotSafe && !useSparse && !useUint32 && !useDenseRow64 && !useDenseRow32 && rowSlots*4 < denseSlots*3
	var coeffs []uint64
	var coeffs32 []uint32
	var rowOffsets []int
	var rowCoeffs []uint64
	var denseRows64 []uint64
	var denseRows32 []uint32
	if useRowMajor {
		rowOffsets = make([]int, rowCount+1)
		rowCoeffs = make([]uint64, 0, rowSlots)
	} else if useDenseRow64 {
		denseRows64 = make([]uint64, denseSlots)
	} else if useDenseRow32 {
		denseRows32 = make([]uint32, denseSlots)
	} else if useUint32 {
		coeffs32 = make([]uint32, (maxDeg+1)*rowCount)
	} else {
		coeffs = make([]uint64, (maxDeg+1)*rowCount)
	}
	var sparseTerms []formalEvalTerm
	if useSparse {
		sparseTerms = make([]formalEvalTerm, 0, nnz)
	}
	for j, row := range rows {
		limit := rowDeg[j]
		if limit < 0 {
			if useRowMajor {
				rowOffsets[j+1] = len(rowCoeffs)
			}
			continue
		}
		if useRowMajor {
			rowOffsets[j] = len(rowCoeffs)
			for d := 0; d <= limit; d++ {
				c := row[d]
				if c >= q {
					c %= q
				}
				rowCoeffs = append(rowCoeffs, c)
			}
			rowOffsets[j+1] = len(rowCoeffs)
			continue
		}
		for d := 0; d <= limit; d++ {
			c := row[d]
			if c >= q {
				c %= q
			}
			if c == 0 {
				continue
			}
			if useDenseRow64 {
				denseRows64[j*(maxDeg+1)+d] = c
			} else if useDenseRow32 {
				denseRows32[j*(maxDeg+1)+d] = uint32(c)
			} else if useUint32 {
				coeffs32[d*rowCount+j] = uint32(c)
			} else {
				coeffs[d*rowCount+j] = c
			}
			if useSparse {
				sparseTerms = append(sparseTerms, formalEvalTerm{degree: d, row: j, coeff: c})
			}
		}
	}
	return formalEvalPlan{
		rowCount:    rowCount,
		maxDeg:      maxDeg,
		nnz:         nnz,
		rowDeg:      rowDeg,
		coeffs:      coeffs,
		coeffs32:    coeffs32,
		rowOffsets:  rowOffsets,
		rowCoeffs:   rowCoeffs,
		denseRows64: denseRows64,
		denseRows32: denseRows32,
		dotSafe:     dotSafe,
		sparseTerms: sparseTerms,
	}
}

func formalEvalDotSafe(maxDeg int, q uint64) bool {
	if maxDeg < 0 || q <= 1 {
		return true
	}
	v := q - 1
	if v != 0 && v > ^uint64(0)/v {
		return false
	}
	term := v * v
	if term == 0 {
		return true
	}
	return uint64(maxDeg+1) <= ^uint64(0)/term
}

func (p formalEvalPlan) usesPowerEval() bool {
	return p.dotSafe
}

func computeFormalEvalPowers(powers []uint64, x uint64, red modReducer64) {
	if len(powers) == 0 {
		return
	}
	q := red.mod
	if x >= q {
		x %= q
	}
	powers[0] = 1 % q
	for i := 1; i < len(powers); i++ {
		powers[i] = red.mulReduced(powers[i-1], x)
	}
}

func (p formalEvalPlan) evalIntoPrepared(dst []uint64, x uint64, red modReducer64, powers []uint64) {
	if p.usesPowerEval() && len(powers) > p.maxDeg {
		p.evalIntoPowers(dst, red, powers)
		return
	}
	p.evalIntoHorner(dst, x, red)
}

func (p formalEvalPlan) evalIntoHorner(dst []uint64, x uint64, red modReducer64) {
	if p.rowCount == 0 {
		return
	}
	q := red.mod
	if len(p.denseRows64) > 0 || len(p.denseRows32) > 0 {
		width := p.maxDeg + 1
		for rowIndex := 0; rowIndex < p.rowCount; rowIndex++ {
			value := uint64(0)
			for degree := p.maxDeg; degree >= 0; degree-- {
				coefficient := uint64(0)
				if len(p.denseRows32) > 0 {
					coefficient = uint64(p.denseRows32[rowIndex*width+degree])
				} else {
					coefficient = p.denseRows64[rowIndex*width+degree]
				}
				value = addMod64Reduced(red.mulReduced(value, x), coefficient, q)
			}
			dst[rowIndex] = value
		}
		return
	}
	if len(p.coeffs32) > 0 {
		top := p.coeffs32[p.maxDeg*p.rowCount : (p.maxDeg+1)*p.rowCount]
		for j, c := range top {
			dst[j] = uint64(c)
		}
		for d := p.maxDeg - 1; d >= 0; d-- {
			row := p.coeffs32[d*p.rowCount : (d+1)*p.rowCount]
			for j := 0; j < p.rowCount; j++ {
				dst[j] = addMod64Reduced(red.mulReduced(dst[j], x), uint64(row[j]), q)
			}
		}
		return
	}
	top := p.coeffs[p.maxDeg*p.rowCount : (p.maxDeg+1)*p.rowCount]
	copy(dst[:p.rowCount], top)
	for d := p.maxDeg - 1; d >= 0; d-- {
		row := p.coeffs[d*p.rowCount : (d+1)*p.rowCount]
		for j := 0; j < p.rowCount; j++ {
			dst[j] = addMod64Reduced(red.mulReduced(dst[j], x), row[j], q)
		}
	}
}

func (p formalEvalPlan) evalIntoPowers(dst []uint64, red modReducer64, powers []uint64) {
	if p.rowCount == 0 {
		return
	}
	if len(p.rowOffsets) == p.rowCount+1 {
		for j := 0; j < p.rowCount; j++ {
			acc := uint64(0)
			row := p.rowCoeffs[p.rowOffsets[j]:p.rowOffsets[j+1]]
			for d, c := range row {
				acc += c * powers[d]
			}
			dst[j] = red.reduceUint64(acc)
		}
		return
	}
	if len(p.denseRows64) > 0 {
		p.evalDenseRowMajor64Into(dst, red, powers)
		return
	}
	if len(p.denseRows32) > 0 {
		p.evalDenseRowMajor32Into(dst, red, powers)
		return
	}
	denseSlots := (p.maxDeg + 1) * p.rowCount
	if p.nnz == denseSlots && len(p.coeffs) > 0 && p.maxDeg <= 64 {
		p.evalDenseLowDegreeUint64Into(dst, red, powers)
		return
	}
	for j := 0; j < p.rowCount; j++ {
		dst[j] = 0
	}
	if len(p.sparseTerms) > 0 {
		for _, term := range p.sparseTerms {
			dst[term.row] += term.coeff * powers[term.degree]
		}
	} else {
		if p.nnz == denseSlots {
			if len(p.coeffs32) > 0 {
				for d := 0; d <= p.maxDeg; d++ {
					pow := powers[d]
					row := p.coeffs32[d*p.rowCount : (d+1)*p.rowCount]
					for j := 0; j < p.rowCount; j++ {
						dst[j] += uint64(row[j]) * pow
					}
				}
			} else {
				for d := 0; d <= p.maxDeg; d++ {
					pow := powers[d]
					row := p.coeffs[d*p.rowCount : (d+1)*p.rowCount]
					for j := 0; j < p.rowCount; j++ {
						dst[j] += row[j] * pow
					}
				}
			}
			for j := 0; j < p.rowCount; j++ {
				dst[j] = red.reduceUint64(dst[j])
			}
			return
		}
		for d := 0; d <= p.maxDeg; d++ {
			pow := powers[d]
			if pow == 0 {
				continue
			}
			if len(p.coeffs32) > 0 {
				row := p.coeffs32[d*p.rowCount : (d+1)*p.rowCount]
				for j, c := range row {
					if c == 0 {
						continue
					}
					dst[j] += uint64(c) * pow
				}
			} else {
				row := p.coeffs[d*p.rowCount : (d+1)*p.rowCount]
				for j, c := range row {
					if c == 0 {
						continue
					}
					dst[j] += c * pow
				}
			}
		}
	}
	for j := 0; j < p.rowCount; j++ {
		dst[j] = red.reduceUint64(dst[j])
	}
}

func (p formalEvalPlan) evalDenseRowMajor64Into(dst []uint64, red modReducer64, powers []uint64) {
	width := p.maxDeg + 1
	for rowIndex := 0; rowIndex < p.rowCount; rowIndex++ {
		coefficients := p.denseRows64[rowIndex*width : (rowIndex+1)*width]
		var acc0, acc1, acc2, acc3 uint64
		degree := 0
		limit := width - width%4
		for ; degree < limit; degree += 4 {
			acc0 += coefficients[degree] * powers[degree]
			acc1 += coefficients[degree+1] * powers[degree+1]
			acc2 += coefficients[degree+2] * powers[degree+2]
			acc3 += coefficients[degree+3] * powers[degree+3]
		}
		for ; degree < width; degree++ {
			acc0 += coefficients[degree] * powers[degree]
		}
		dst[rowIndex] = red.reduceUint64((acc0 + acc1) + (acc2 + acc3))
	}
}

func (p formalEvalPlan) evalDenseRowMajor32Into(dst []uint64, red modReducer64, powers []uint64) {
	width := p.maxDeg + 1
	for rowIndex := 0; rowIndex < p.rowCount; rowIndex++ {
		coefficients := p.denseRows32[rowIndex*width : (rowIndex+1)*width]
		var acc0, acc1, acc2, acc3 uint64
		degree := 0
		limit := width - width%4
		for ; degree < limit; degree += 4 {
			acc0 += uint64(coefficients[degree]) * powers[degree]
			acc1 += uint64(coefficients[degree+1]) * powers[degree+1]
			acc2 += uint64(coefficients[degree+2]) * powers[degree+2]
			acc3 += uint64(coefficients[degree+3]) * powers[degree+3]
		}
		for ; degree < width; degree++ {
			acc0 += uint64(coefficients[degree]) * powers[degree]
		}
		dst[rowIndex] = red.reduceUint64((acc0 + acc1) + (acc2 + acc3))
	}
}

func (p formalEvalPlan) evalDenseLowDegreeUint64Into(dst []uint64, red modReducer64, powers []uint64) {
	rowCount := p.rowCount
	copy(dst[:rowCount], p.coeffs[:rowCount])
	for d := 1; d <= p.maxDeg; d++ {
		pow := powers[d]
		row := p.coeffs[d*rowCount : (d+1)*rowCount]
		j := 0
		limit := rowCount - rowCount%4
		for ; j < limit; j += 4 {
			dst[j] += row[j] * pow
			dst[j+1] += row[j+1] * pow
			dst[j+2] += row[j+2] * pow
			dst[j+3] += row[j+3] * pow
		}
		for ; j < rowCount; j++ {
			dst[j] += row[j] * pow
		}
	}
	j := 0
	limit := rowCount - rowCount%4
	for ; j < limit; j += 4 {
		dst[j] = red.reduceUint64(dst[j])
		dst[j+1] = red.reduceUint64(dst[j+1])
		dst[j+2] = red.reduceUint64(dst[j+2])
		dst[j+3] = red.reduceUint64(dst[j+3])
	}
	for ; j < rowCount; j++ {
		dst[j] = red.reduceUint64(dst[j])
	}
}

func (p formalEvalPlan) evalTileIntoPrepared(dst []uint64, points []uint64, red modReducer64, powers []uint64) {
	tileLen := len(points)
	if tileLen == 0 || p.rowCount == 0 {
		return
	}
	if !p.usesPowerEval() || len(powers) < tileLen*(p.maxDeg+1) {
		for t, x := range points {
			p.evalIntoPrepared(dst[t*p.rowCount:(t+1)*p.rowCount], x, red, nil)
		}
		return
	}
	powerCount := p.maxDeg + 1
	for t, x := range points {
		computeFormalEvalPowers(powers[t*powerCount:(t+1)*powerCount], x, red)
	}
	for i := range dst[:tileLen*p.rowCount] {
		dst[i] = 0
	}
	if len(p.rowOffsets) == p.rowCount+1 {
		for t := 0; t < tileLen; t++ {
			tPowers := powers[t*powerCount : (t+1)*powerCount]
			tDst := dst[t*p.rowCount : (t+1)*p.rowCount]
			for j := 0; j < p.rowCount; j++ {
				acc := uint64(0)
				row := p.rowCoeffs[p.rowOffsets[j]:p.rowOffsets[j+1]]
				for d, c := range row {
					acc += c * tPowers[d]
				}
				tDst[j] = red.reduceUint64(acc)
			}
		}
		return
	}
	if len(p.denseRows64) > 0 || len(p.denseRows32) > 0 {
		for t := 0; t < tileLen; t++ {
			p.evalIntoPowers(
				dst[t*p.rowCount:(t+1)*p.rowCount],
				red,
				powers[t*powerCount:(t+1)*powerCount],
			)
		}
		return
	}
	if len(p.sparseTerms) > 0 {
		for _, term := range p.sparseTerms {
			coeff := term.coeff
			for t := 0; t < tileLen; t++ {
				dst[t*p.rowCount+term.row] += coeff * powers[t*powerCount+term.degree]
			}
		}
	} else if len(p.coeffs32) > 0 {
		for d := 0; d <= p.maxDeg; d++ {
			row := p.coeffs32[d*p.rowCount : (d+1)*p.rowCount]
			for j, c32 := range row {
				if c32 == 0 {
					continue
				}
				c := uint64(c32)
				for t := 0; t < tileLen; t++ {
					pow := powers[t*powerCount+d]
					if pow != 0 {
						dst[t*p.rowCount+j] += c * pow
					}
				}
			}
		}
	} else {
		for d := 0; d <= p.maxDeg; d++ {
			row := p.coeffs[d*p.rowCount : (d+1)*p.rowCount]
			for j, c := range row {
				if c == 0 {
					continue
				}
				for t := 0; t < tileLen; t++ {
					pow := powers[t*powerCount+d]
					if pow != 0 {
						dst[t*p.rowCount+j] += c * pow
					}
				}
			}
		}
	}
	for i := range dst[:tileLen*p.rowCount] {
		dst[i] = red.reduceUint64(dst[i])
	}
}

// Prover encapsulates the prover state for DECS.
type Prover struct {
	ringQ   *ring.Ring
	P       []*ring.Poly // r input polys (coeff form)
	M       []*ring.Poly // η mask polys (coeff form)
	PFormal [][]uint64   // optional formal coeffs for explicit-domain mode
	MFormal [][]uint64   // optional formal coeffs for explicit-domain mode
	// tapes is the flat prover-private v2 tape buffer. It is never serialized
	// wholesale; EvalOpenV2 copies only challenged slices.
	tapes             []byte
	entropy           io.Reader
	commitmentContext CommitmentContext
	mt                *MerkleTree
	rootHash          []byte
	R                 []*ring.Poly // η output polys in coeff form
	RFormal           [][]uint64   // optional formal coeffs for explicit-domain mode
	params            Params
	points            []uint64 // explicit evaluation domain points E[i]
	nLeaves           int
}

// NewProverWithParamsAndPointsFormalChecked is the error-returning variant of
// NewProverWithParamsAndPointsFormal for library callers.
func NewProverWithParamsAndPointsFormalChecked(ringQ *ring.Ring, coeffs [][]uint64, params Params, points []uint64) (*Prover, error) {
	return newProverWithParamsAndPointsFormalChecked(ringQ, coeffs, params, points, true)
}

func newProverWithParamsAndPointsFormalChecked(ringQ *ring.Ring, coeffs [][]uint64, params Params, points []uint64, validateDomain bool) (*Prover, error) {
	if points == nil {
		return nil, fmt.Errorf("decs: formal constructor requires explicit points")
	}
	if err := validateProverParams(params); err != nil {
		return nil, err
	}
	if params.Eta <= 0 {
		return nil, fmt.Errorf("decs: invalid eta (must be > 0)")
	}
	if !IsSupportedTapeBytes(params.TapeBytes) {
		return nil, fmt.Errorf("decs: invalid TapeBytes (supported: %s)", SupportedTapeBytesList())
	}
	if ringQ == nil || len(ringQ.Modulus) != 1 {
		return nil, fmt.Errorf("decs: only single-modulus rings are supported (len(Modulus) must be 1)")
	}
	if validateDomain {
		if err := validatePoints(points, ringQ.Modulus[0]); err != nil {
			return nil, err
		}
	}
	pFormal := normalizeFormalRows(coeffs, ringQ.Modulus[0])
	return &Prover{
		ringQ:   ringQ,
		PFormal: pFormal,
		params:  params,
		points:  append([]uint64(nil), points...),
		nLeaves: len(points),
	}, nil
}

// CommitPhaseRecorder records opt-in commit phase timings. It is used by
// benchmark/reporting callers only and is not part of the transcript.
type CommitPhaseRecorder interface {
	RecordDuration(label string, d time.Duration)
}

// CommitOptions carries non-transcript-affecting CommitInit controls.
// The zero value preserves the normal proving path.
type CommitOptions struct {
	PhaseRecorder      CommitPhaseRecorder
	WorkerCount        int
	RecordSubphases    bool
	FormalEvalMode     FormalEvalMode
	FormalEvalTileSize int
	// ChunkLeaves enables deterministic dynamic leaf scheduling when positive.
	// Workers keep their scratch buffers while claiming successive chunks, so
	// finer load balancing does not multiply the dominant per-worker allocations.
	// Zero preserves the historical equal contiguous ranges.
	ChunkLeaves int
	// MaxTapeBufferBytes is an operational allocation ceiling for independent
	// v2 tapes. Zero selects DefaultMaxTapeBufferBytes.
	MaxTapeBufferBytes int
}

const DefaultMaxTapeBufferBytes = 64 << 20

// FormalEvalMode selects the internal formal-row evaluator used by CommitInit.
// All modes keep the committed leaf bytes and Merkle tree format; they are
// expected to produce identical roots when masks and tapes are fixed.
type FormalEvalMode uint8

const (
	// FormalEvalScalar preserves the existing per-leaf scalar evaluator.
	FormalEvalScalar FormalEvalMode = iota
	// FormalEvalCombined scans the combined P||M formal plan once per leaf.
	FormalEvalCombined
	// FormalEvalTiled scans the combined P||M formal plan across small leaf tiles.
	FormalEvalTiled
)

type commitInitOptions struct {
	phaseRecorder         CommitPhaseRecorder
	workerCount           int
	tileSize              int
	forceScalarFormalEval bool
	recordSubphases       bool
	maxTapeBufferBytes    int
	chunkLeaves           int
}

type commitInitPhaseTimings struct {
	maskSamplingNs  int64
	formalEvalNs    int64
	leafEncodingNs  int64
	leafHashNs      int64
	exactLeafWrapNs int64
	merkleNs        int64
	evalHashNs      int64
	recordSubphases bool
}

func (t *commitInitPhaseTimings) record(rec CommitPhaseRecorder) {
	if rec == nil || t == nil {
		return
	}
	rec.RecordDuration("decs.mask_sampling", time.Duration(atomic.LoadInt64(&t.maskSamplingNs)))
	rec.RecordDuration("decs.eval_hash", time.Duration(atomic.LoadInt64(&t.evalHashNs)))
	rec.RecordDuration("decs.merkle", time.Duration(atomic.LoadInt64(&t.merkleNs)))
	if !t.recordSubphases {
		return
	}
	rec.RecordDuration("decs.formal_evaluation_cpu", time.Duration(atomic.LoadInt64(&t.formalEvalNs)))
	rec.RecordDuration("decs.leaf_encoding_cpu", time.Duration(atomic.LoadInt64(&t.leafEncodingNs)))
	leafShake := time.Duration(atomic.LoadInt64(&t.leafHashNs))
	rec.RecordDuration("decs.leaf_shake_cpu", leafShake)
	// Compatibility alias for existing profile readers.
	rec.RecordDuration("decs.leaf_hashing_cpu", leafShake)
	rec.RecordDuration("decs.exact_leaf_wrapping_cpu", time.Duration(atomic.LoadInt64(&t.exactLeafWrapNs)))
}

type leafHashTargets struct {
	hashBytes int
	flat      []byte
	exact     *exactMerkleBuilderV3
}

func newLeafHashTargets(ctx CommitmentContext, nLeaves, hashBytes int, exactTimings *exactMerklePhaseTimingsV3) (*leafHashTargets, error) {
	if ctx.TranscriptVersion == TranscriptVersionV3 {
		exact, err := newExactMerkleBuilderV3(ctx, nLeaves, hashBytes, exactTimings)
		if err != nil {
			return nil, err
		}
		return &leafHashTargets{hashBytes: hashBytes, exact: exact}, nil
	}
	if nLeaves > 0 && hashBytes > int(^uint(0)>>1)/nLeaves {
		return nil, fmt.Errorf("decs: leaf hash buffer size overflows int")
	}
	return &leafHashTargets{hashBytes: hashBytes, flat: make([]byte, nLeaves*hashBytes)}, nil
}

func (t *leafHashTargets) at(index int) []byte {
	if t.exact != nil {
		return t.exact.leafHashAt(index)
	}
	start := index * t.hashBytes
	return t.flat[start : start+t.hashBytes]
}

func (t *leafHashTargets) wrapExactLeaf(h sha3.ShakeHash, scratch []byte, index int) []byte {
	if t.exact == nil {
		return scratch
	}
	return t.exact.wrapLeafHashInto(h, scratch, index)
}

func (t *leafHashTargets) legacyViews(nLeaves int) [][]byte {
	views := make([][]byte, nLeaves)
	for index := range views {
		views[index] = t.at(index)
	}
	return views
}

// CommitInitV2WithOptions commits using independent per-leaf tapes and the
// canonical version/role/salt context. It returns the full declared-width
// Merkle root and never exposes or derives a master tape seed.
func (pr *Prover) CommitInitV2WithOptions(ctx CommitmentContext, opts CommitOptions) ([]byte, error) {
	if pr == nil {
		return nil, fmt.Errorf("decs: nil prover")
	}
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if _, err := v2TapeBytes(pr.params); err != nil {
		return nil, err
	}
	if !IsSupportedHashBytes(pr.params.HashBytes) {
		return nil, fmt.Errorf("decs: v2 requires explicit HashBytes (got %d)", pr.params.HashBytes)
	}
	internal, err := normalizeCommitOptions(opts)
	if err != nil {
		return nil, err
	}
	pr.commitmentContext = cloneCommitmentContext(ctx)
	pr.mt = nil
	pr.rootHash = nil
	if err := pr.commitInitWithOptions(internal); err != nil {
		pr.ReleaseTapes()
		return nil, err
	}
	return pr.RootHash(), nil
}

func normalizeCommitOptions(opts CommitOptions) (commitInitOptions, error) {
	internal := commitInitOptions{
		phaseRecorder:         opts.PhaseRecorder,
		workerCount:           opts.WorkerCount,
		forceScalarFormalEval: true,
		recordSubphases:       opts.RecordSubphases,
		maxTapeBufferBytes:    opts.MaxTapeBufferBytes,
		chunkLeaves:           opts.ChunkLeaves,
	}
	if opts.ChunkLeaves < 0 || opts.ChunkLeaves > 1<<20 {
		return commitInitOptions{}, fmt.Errorf("decs: invalid chunk leaf count %d", opts.ChunkLeaves)
	}
	switch opts.FormalEvalMode {
	case FormalEvalScalar:
	case FormalEvalCombined:
		internal.forceScalarFormalEval = false
	case FormalEvalTiled:
		internal.forceScalarFormalEval = false
		internal.tileSize = opts.FormalEvalTileSize
		if internal.tileSize <= 0 {
			internal.tileSize = 8
		}
	default:
		return commitInitOptions{}, fmt.Errorf("decs: unsupported formal eval mode %d", opts.FormalEvalMode)
	}
	if opts.WorkerCount > 0 {
		internal.workerCount = opts.WorkerCount
	}
	return internal, nil
}

func (pr *Prover) commitInitWithOptions(opts commitInitOptions) error {
	r := pr.rowCount()
	N := pr.nLeaves
	q := pr.ringQ.Modulus[0]
	hashBytes := pr.params.HashBytes
	var timings *commitInitPhaseTimings
	if opts.phaseRecorder != nil {
		timings = &commitInitPhaseTimings{recordSubphases: opts.recordSubphases}
	}

	// sampler
	maskStart := time.Time{}
	if timings != nil {
		maskStart = time.Now()
	}
	if pr.PFormal != nil {
		if pr.MFormal == nil {
			pr.MFormal = make([][]uint64, pr.params.Eta)
			for k := 0; k < pr.params.Eta; k++ {
				row := make([]uint64, pr.params.Degree+1)
				for i := range row {
					v, err := randUint64Mod(pr.ringQ.Modulus[0])
					if err != nil {
						return err
					}
					row[i] = v
				}
				pr.MFormal[k] = trimFormalInPlace(row, pr.ringQ.Modulus[0])
			}
		} else if len(pr.MFormal) != pr.params.Eta {
			return fmt.Errorf("decs: formal mask polynomial count mismatch: got=%d want=%d", len(pr.MFormal), pr.params.Eta)
		}
	} else {
		if pr.M == nil {
			prng, err := utils.NewPRNG()
			if err != nil {
				return err
			}
			us := ring.NewUniformSampler(prng, pr.ringQ)
			// 1a) sample η mask polys
			pr.M = make([]*ring.Poly, pr.params.Eta)
			for k := 0; k < pr.params.Eta; k++ {
				pr.M[k] = pr.ringQ.NewPoly()
				us.Read(pr.M[k])
				for i := pr.params.Degree + 1; i < int(pr.ringQ.N); i++ {
					pr.M[k].Coeffs[0][i] = 0
				}
			}
		} else if len(pr.M) != pr.params.Eta {
			return fmt.Errorf("decs: mask polynomial count mismatch: got=%d want=%d", len(pr.M), pr.params.Eta)
		}
	}
	if timings != nil {
		timings.maskSamplingNs = int64(time.Since(maskStart))
	}

	// 1b) explicit-domain path computes evaluations on demand

	// 1c) build leaf hashes
	evalHashStart := time.Time{}
	if timings != nil {
		evalHashStart = time.Now()
	}
	var exactMerkleTimings *exactMerklePhaseTimingsV3
	if timings != nil && timings.recordSubphases && pr.commitmentContext.TranscriptVersion == TranscriptVersionV3 {
		exactMerkleTimings = &exactMerklePhaseTimingsV3{}
	}
	leafTargets, err := newLeafHashTargets(pr.commitmentContext, N, hashBytes, exactMerkleTimings)
	if err != nil {
		return err
	}
	if err := pr.ensureV2Tapes(opts.maxTapeBufferBytes); err != nil {
		return err
	}
	if pr.PFormal != nil {
		if opts.forceScalarFormalEval {
			pr.commitInitFormalScalarLeafHashes(leafTargets, opts, timings)
		} else {
			pr.commitInitFormalOptimizedLeafHashes(leafTargets, opts, timings)
		}
	} else {
		buildLeafHash := func(h sha3.ShakeHash, scratch []byte, i int) []byte {
			x := pr.points[i] % q
			pvals := make([]uint64, r)
			for j := 0; j < r; j++ {
				pvals[j] = evalPoly(pr.P[j].Coeffs[0], x, q)
			}
			mvals := make([]uint64, pr.params.Eta)
			for k := 0; k < pr.params.Eta; k++ {
				mvals[k] = evalPoly(pr.M[k].Coeffs[0], x, q)
			}
			scratch = hashLeafV2Into(h, scratch, leafTargets.at(i), pr.commitmentContext, uint64(i), pr.points[i], q, pvals, mvals, pr.tapeAt(i))
			return leafTargets.wrapExactLeaf(h, scratch, i)
		}
		workers := runtime.GOMAXPROCS(0)
		if workers < 2 || N < 128 {
			h := nilShake()
			var scratch []byte
			for i := 0; i < N; i++ {
				scratch = buildLeafHash(h, scratch, i)
			}
		} else {
			if workers > N {
				workers = N
			}
			var wg sync.WaitGroup
			wg.Add(workers)
			chunk := (N + workers - 1) / workers
			for worker := 0; worker < workers; worker++ {
				start := worker * chunk
				end := start + chunk
				if end > N {
					end = N
				}
				go func(start, end int) {
					defer wg.Done()
					h := nilShake()
					var scratch []byte
					for i := start; i < end; i++ {
						scratch = buildLeafHash(h, scratch, i)
					}
				}(start, end)
			}
			wg.Wait()
		}
	}
	if timings != nil {
		timings.evalHashNs = int64(time.Since(evalHashStart))
	}

	// 1d) Merkle tree
	merkleStart := time.Time{}
	if timings != nil {
		merkleStart = time.Now()
	}
	if exactMerkleTimings != nil {
		exactMerkleTimings.leafWrapping = time.Duration(atomic.LoadInt64(&timings.exactLeafWrapNs))
	}
	if leafTargets.exact != nil {
		pr.mt, err = leafTargets.exact.finishInternal(exactMerkleTimings)
	} else {
		pr.mt, err = buildMerkleTreeFromLeafHashBytesV2(pr.commitmentContext, leafTargets.legacyViews(N), hashBytes, exactMerkleTimings)
	}
	if err != nil {
		return err
	}
	pr.rootHash = pr.mt.RootHash()
	if timings != nil {
		timings.merkleNs = int64(time.Since(merkleStart))
		timings.record(opts.phaseRecorder)
		exactMerkleTimings.record(opts.phaseRecorder)
	}

	return nil
}

func v2TapeBytes(params Params) (int, error) {
	if !IsSupportedTapeBytes(params.TapeBytes) {
		return 0, fmt.Errorf("decs: invalid v2 TapeBytes=%d (supported: %s)", params.TapeBytes, SupportedTapeBytesList())
	}
	return params.TapeBytes, nil
}

func (pr *Prover) ensureV2Tapes(maxBytes int) error {
	tapeBytes, err := v2TapeBytes(pr.params)
	if err != nil {
		return err
	}
	if pr.nLeaves < 0 || (pr.nLeaves > 0 && tapeBytes > int(^uint(0)>>1)/pr.nLeaves) {
		return fmt.Errorf("decs: v2 tape buffer size overflows int")
	}
	total := pr.nLeaves * tapeBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxTapeBufferBytes
	}
	if total > maxBytes {
		return fmt.Errorf("decs: v2 tape buffer=%d exceeds configured limit=%d", total, maxBytes)
	}
	if len(pr.tapes) != 0 {
		if len(pr.tapes) != total {
			return fmt.Errorf("decs: v2 tape buffer width=%d want=%d", len(pr.tapes), total)
		}
		return nil
	}
	pr.tapes = make([]byte, total)
	reader := pr.entropy
	if reader == nil {
		reader = rand.Reader
	}
	if _, err := io.ReadFull(reader, pr.tapes); err != nil {
		for i := range pr.tapes {
			pr.tapes[i] = 0
		}
		pr.tapes = nil
		return fmt.Errorf("decs: sample independent tapes: %w", err)
	}
	return nil
}

func (pr *Prover) tapeAt(index int) []byte {
	tapeBytes := pr.params.TapeBytes
	start := index * tapeBytes
	return pr.tapes[start : start+tapeBytes]
}

// ReleaseTapes zeroes and releases the prover-private v2 tape buffer. Further
// openings fail until a new commitment is created.
func (pr *Prover) ReleaseTapes() {
	if pr == nil {
		return
	}
	for i := range pr.tapes {
		pr.tapes[i] = 0
	}
	pr.tapes = nil
}

type formalScalarWorkerScratch struct {
	pValues     []uint64
	mValues     []uint64
	powers      []uint64
	shake       sha3.ShakeHash
	hashScratch []byte
}

func (pr *Prover) commitInitFormalScalarLeafHashes(leafTargets *leafHashTargets, opts commitInitOptions, timings *commitInitPhaseTimings) {
	r := pr.rowCount()
	N := pr.nLeaves
	q := pr.ringQ.Modulus[0]
	red := newModReducer64(q)
	pPlan := newFormalEvalPlan(pr.PFormal, q)
	mPlan := newFormalEvalPlan(pr.MFormal, q)
	usePowerEval := pPlan.usesPowerEval() || mPlan.usesPowerEval()
	powerCount := pPlan.maxDeg + 1
	if mPlan.maxDeg+1 > powerCount {
		powerCount = mPlan.maxDeg + 1
	}
	workers := runtime.GOMAXPROCS(0)
	if opts.workerCount > 0 {
		workers = opts.workerCount
	}
	if workers < 2 || N < 128 {
		pr.commitInitFormalScalarRange(0, N, leafTargets, r, red, pPlan, mPlan, usePowerEval, powerCount, timings)
		return
	}
	if workers > N {
		workers = N
	}
	scratch := make([]formalScalarWorkerScratch, workers)
	for worker := range scratch {
		scratch[worker] = formalScalarWorkerScratch{
			pValues: make([]uint64, r),
			mValues: make([]uint64, pr.params.Eta),
			shake:   nilShake(),
		}
		if usePowerEval {
			scratch[worker].powers = make([]uint64, powerCount)
		}
	}
	runDECSLeafRanges(workers, N, opts.chunkLeaves, func(worker, start, end int) {
		pr.commitInitFormalScalarRangeWithScratch(start, end, leafTargets, r, red, pPlan, mPlan, usePowerEval, timings, &scratch[worker])
	})
}

func (pr *Prover) commitInitFormalScalarRange(start, end int, leafTargets *leafHashTargets, r int, red modReducer64, pPlan, mPlan formalEvalPlan, usePowerEval bool, powerCount int, timings *commitInitPhaseTimings) {
	scratch := &formalScalarWorkerScratch{
		pValues: make([]uint64, r),
		mValues: make([]uint64, pr.params.Eta),
		shake:   nilShake(),
	}
	if usePowerEval {
		scratch.powers = make([]uint64, powerCount)
	}
	pr.commitInitFormalScalarRangeWithScratch(start, end, leafTargets, r, red, pPlan, mPlan, usePowerEval, timings, scratch)
}

func (pr *Prover) commitInitFormalScalarRangeWithScratch(start, end int, leafTargets *leafHashTargets, r int, red modReducer64, pPlan, mPlan formalEvalPlan, usePowerEval bool, timings *commitInitPhaseTimings, scratch *formalScalarWorkerScratch) {
	record := timings != nil && timings.recordSubphases
	var evalNs, encodingNs, hashNs, wrappingNs int64
	for i := start; i < end; i++ {
		x := pr.points[i] % red.mod
		evalStart := time.Time{}
		if record {
			evalStart = time.Now()
		}
		if usePowerEval {
			computeFormalEvalPowers(scratch.powers, x, red)
		}
		pPlan.evalIntoPrepared(scratch.pValues, x, red, scratch.powers)
		mPlan.evalIntoPrepared(scratch.mValues, x, red, scratch.powers)
		if record {
			evalNs += int64(time.Since(evalStart))
		}
		if record {
			encodingStart := time.Now()
			scratch.hashScratch = frameLeafV2Into(scratch.hashScratch, pr.commitmentContext, uint64(i), pr.points[i], red.mod, scratch.pValues, scratch.mValues, pr.tapeAt(i))
			encodingNs += int64(time.Since(encodingStart))
			hashStart := time.Now()
			shakeFrameV2Into(scratch.shake, leafTargets.at(i), scratch.hashScratch)
			hashNs += int64(time.Since(hashStart))
		} else {
			scratch.hashScratch = hashLeafV2Into(scratch.shake, scratch.hashScratch, leafTargets.at(i), pr.commitmentContext, uint64(i), pr.points[i], red.mod, scratch.pValues, scratch.mValues, pr.tapeAt(i))
		}
		if leafTargets.exact != nil {
			if record {
				wrapStart := time.Now()
				scratch.hashScratch = leafTargets.wrapExactLeaf(scratch.shake, scratch.hashScratch, i)
				wrappingNs += int64(time.Since(wrapStart))
			} else {
				scratch.hashScratch = leafTargets.wrapExactLeaf(scratch.shake, scratch.hashScratch, i)
			}
		}
	}
	if record {
		atomic.AddInt64(&timings.formalEvalNs, evalNs)
		atomic.AddInt64(&timings.leafEncodingNs, encodingNs)
		atomic.AddInt64(&timings.leafHashNs, hashNs)
		atomic.AddInt64(&timings.exactLeafWrapNs, wrappingNs)
	}
}

func (pr *Prover) commitInitFormalTiledLeafHashes(leafTargets *leafHashTargets, opts commitInitOptions, timings *commitInitPhaseTimings) {
	r := pr.rowCount()
	N := pr.nLeaves
	q := pr.ringQ.Modulus[0]
	red := newModReducer64(q)
	combinedRows := make([][]uint64, 0, r+pr.params.Eta)
	combinedRows = append(combinedRows, pr.PFormal...)
	combinedRows = append(combinedRows, pr.MFormal...)
	plan := newFormalEvalPlan(combinedRows, q)
	if !plan.usesPowerEval() {
		pr.commitInitFormalScalarLeafHashes(leafTargets, opts, timings)
		return
	}
	tileSize := opts.tileSize
	if tileSize <= 0 {
		tileSize = 8
	}
	if tileSize > 32 {
		tileSize = 32
	}
	workers := opts.workerCount
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 2 || N < 128 {
		pr.commitInitFormalTiledRange(0, N, tileSize, leafTargets, r, red, plan, timings)
		return
	}
	if workers > N {
		workers = N
	}
	scratch := make([]formalCombinedWorkerScratch, workers)
	for worker := range scratch {
		scratch[worker] = newFormalCombinedWorkerScratch(tileSize*plan.rowCount, tileSize*(plan.maxDeg+1))
	}
	runDECSLeafRanges(workers, N, opts.chunkLeaves, func(worker, start, end int) {
		pr.commitInitFormalTiledRangeWithScratch(start, end, tileSize, leafTargets, r, red, plan, timings, &scratch[worker])
	})
}

func (pr *Prover) commitInitFormalOptimizedLeafHashes(leafTargets *leafHashTargets, opts commitInitOptions, timings *commitInitPhaseTimings) {
	if opts.tileSize > 1 {
		pr.commitInitFormalTiledLeafHashes(leafTargets, opts, timings)
		return
	}
	r := pr.rowCount()
	N := pr.nLeaves
	q := pr.ringQ.Modulus[0]
	red := newModReducer64(q)
	combinedRows := make([][]uint64, 0, r+pr.params.Eta)
	combinedRows = append(combinedRows, pr.PFormal...)
	combinedRows = append(combinedRows, pr.MFormal...)
	plan := newFormalEvalPlan(combinedRows, q)
	if !plan.usesPowerEval() {
		pr.commitInitFormalScalarLeafHashes(leafTargets, opts, timings)
		return
	}
	workers := opts.workerCount
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 2 || N < 128 {
		pr.commitInitFormalOptimizedRange(0, N, leafTargets, r, red, plan, timings)
		return
	}
	if workers > N {
		workers = N
	}
	scratch := make([]formalCombinedWorkerScratch, workers)
	for worker := range scratch {
		scratch[worker] = newFormalCombinedWorkerScratch(plan.rowCount, plan.maxDeg+1)
	}
	runDECSLeafRanges(workers, N, opts.chunkLeaves, func(worker, start, end int) {
		pr.commitInitFormalOptimizedRangeWithScratch(start, end, leafTargets, r, red, plan, timings, &scratch[worker])
	})
}

type formalCombinedWorkerScratch struct {
	values      []uint64
	powers      []uint64
	shake       sha3.ShakeHash
	hashScratch []byte
}

func newFormalCombinedWorkerScratch(valueCount, powerCount int) formalCombinedWorkerScratch {
	return formalCombinedWorkerScratch{
		values: make([]uint64, valueCount),
		powers: make([]uint64, powerCount),
		shake:  nilShake(),
	}
}

func (pr *Prover) commitInitFormalOptimizedRange(start, end int, leafTargets *leafHashTargets, r int, red modReducer64, plan formalEvalPlan, timings *commitInitPhaseTimings) {
	scratch := newFormalCombinedWorkerScratch(plan.rowCount, plan.maxDeg+1)
	pr.commitInitFormalOptimizedRangeWithScratch(start, end, leafTargets, r, red, plan, timings, &scratch)
}

func (pr *Prover) commitInitFormalOptimizedRangeWithScratch(start, end int, leafTargets *leafHashTargets, r int, red modReducer64, plan formalEvalPlan, timings *commitInitPhaseTimings, scratch *formalCombinedWorkerScratch) {
	record := timings != nil && timings.recordSubphases
	var evalNs, encodingNs, hashNs, wrappingNs int64
	for i := start; i < end; i++ {
		x := pr.points[i] % red.mod
		evalStart := time.Time{}
		if record {
			evalStart = time.Now()
		}
		computeFormalEvalPowers(scratch.powers, x, red)
		plan.evalIntoPrepared(scratch.values, x, red, scratch.powers)
		if record {
			evalNs += int64(time.Since(evalStart))
		}
		if record {
			encodingStart := time.Now()
			scratch.hashScratch = frameLeafV2Into(scratch.hashScratch, pr.commitmentContext, uint64(i), pr.points[i], red.mod, scratch.values[:r], scratch.values[r:r+pr.params.Eta], pr.tapeAt(i))
			encodingNs += int64(time.Since(encodingStart))
			hashStart := time.Now()
			shakeFrameV2Into(scratch.shake, leafTargets.at(i), scratch.hashScratch)
			hashNs += int64(time.Since(hashStart))
		} else {
			scratch.hashScratch = hashLeafV2Into(scratch.shake, scratch.hashScratch, leafTargets.at(i), pr.commitmentContext, uint64(i), pr.points[i], red.mod, scratch.values[:r], scratch.values[r:r+pr.params.Eta], pr.tapeAt(i))
		}
		if leafTargets.exact != nil {
			if record {
				wrapStart := time.Now()
				scratch.hashScratch = leafTargets.wrapExactLeaf(scratch.shake, scratch.hashScratch, i)
				wrappingNs += int64(time.Since(wrapStart))
			} else {
				scratch.hashScratch = leafTargets.wrapExactLeaf(scratch.shake, scratch.hashScratch, i)
			}
		}
	}
	if record {
		atomic.AddInt64(&timings.formalEvalNs, evalNs)
		atomic.AddInt64(&timings.leafEncodingNs, encodingNs)
		atomic.AddInt64(&timings.leafHashNs, hashNs)
		atomic.AddInt64(&timings.exactLeafWrapNs, wrappingNs)
	}
}

func (pr *Prover) commitInitFormalTiledRange(start, end, tileSize int, leafTargets *leafHashTargets, r int, red modReducer64, plan formalEvalPlan, timings *commitInitPhaseTimings) {
	scratch := newFormalCombinedWorkerScratch(tileSize*plan.rowCount, tileSize*(plan.maxDeg+1))
	pr.commitInitFormalTiledRangeWithScratch(start, end, tileSize, leafTargets, r, red, plan, timings, &scratch)
}

func (pr *Prover) commitInitFormalTiledRangeWithScratch(start, end, tileSize int, leafTargets *leafHashTargets, r int, red modReducer64, plan formalEvalPlan, timings *commitInitPhaseTimings, scratch *formalCombinedWorkerScratch) {
	rowCount := plan.rowCount
	record := timings != nil && timings.recordSubphases
	var evalNs, encodingNs, hashNs, wrappingNs int64
	for tileStart := start; tileStart < end; tileStart += tileSize {
		tileEnd := tileStart + tileSize
		if tileEnd > end {
			tileEnd = end
		}
		tileLen := tileEnd - tileStart
		points := pr.points[tileStart:tileEnd]
		evalStart := time.Time{}
		if record {
			evalStart = time.Now()
		}
		plan.evalTileIntoPrepared(scratch.values[:tileLen*rowCount], points, red, scratch.powers[:tileLen*(plan.maxDeg+1)])
		if record {
			evalNs += int64(time.Since(evalStart))
		}
		for t := 0; t < tileLen; t++ {
			i := tileStart + t
			rowVals := scratch.values[t*rowCount : (t+1)*rowCount]
			if record {
				encodingStart := time.Now()
				scratch.hashScratch = frameLeafV2Into(scratch.hashScratch, pr.commitmentContext, uint64(i), pr.points[i], red.mod, rowVals[:r], rowVals[r:r+pr.params.Eta], pr.tapeAt(i))
				encodingNs += int64(time.Since(encodingStart))
				hashStart := time.Now()
				shakeFrameV2Into(scratch.shake, leafTargets.at(i), scratch.hashScratch)
				hashNs += int64(time.Since(hashStart))
			} else {
				scratch.hashScratch = hashLeafV2Into(scratch.shake, scratch.hashScratch, leafTargets.at(i), pr.commitmentContext, uint64(i), pr.points[i], red.mod, rowVals[:r], rowVals[r:r+pr.params.Eta], pr.tapeAt(i))
			}
			if leafTargets.exact != nil {
				if record {
					wrapStart := time.Now()
					scratch.hashScratch = leafTargets.wrapExactLeaf(scratch.shake, scratch.hashScratch, i)
					wrappingNs += int64(time.Since(wrapStart))
				} else {
					scratch.hashScratch = leafTargets.wrapExactLeaf(scratch.shake, scratch.hashScratch, i)
				}
			}
		}
	}
	if record {
		atomic.AddInt64(&timings.formalEvalNs, evalNs)
		atomic.AddInt64(&timings.leafEncodingNs, encodingNs)
		atomic.AddInt64(&timings.leafHashNs, hashNs)
		atomic.AddInt64(&timings.exactLeafWrapNs, wrappingNs)
	}
}

// runDECSLeafRanges assigns canonical leaf intervals to a fixed worker pool.
// A positive dynamicChunk enables work stealing through one monotonic counter;
// output locations and entropy have already been fixed by leaf index, so the
// scheduling order cannot affect the commitment. The worker identifier is
// stable and lets callers retain one scratch arena per goroutine.
func runDECSLeafRanges(workers, total, dynamicChunk int, work func(worker, start, end int)) {
	if total <= 0 {
		return
	}
	if workers <= 1 {
		work(0, 0, total)
		return
	}
	if workers > total {
		workers = total
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	if dynamicChunk <= 0 {
		chunk := (total + workers - 1) / workers
		for worker := 0; worker < workers; worker++ {
			start := worker * chunk
			end := start + chunk
			if end > total {
				end = total
			}
			go func(worker, start, end int) {
				defer wg.Done()
				if start < end {
					work(worker, start, end)
				}
			}(worker, start, end)
		}
		wg.Wait()
		return
	}
	if dynamicChunk > total {
		dynamicChunk = total
	}
	var next atomic.Int64
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			defer wg.Done()
			for {
				end := int(next.Add(int64(dynamicChunk)))
				start := end - dynamicChunk
				if start >= total {
					return
				}
				if end > total {
					end = total
				}
				work(worker, start, end)
			}
		}(worker)
	}
	wg.Wait()
}

func nilShake() sha3.ShakeHash {
	return sha3.NewShake256()
}

// CommitStep2Formal computes R_k(X) = M_k(X) + Σ_j Γ[k][j]·P_j(X) as formal
// coefficient slices and returns deep copies.
func (pr *Prover) CommitStep2Formal(Gamma [][]uint64) [][]uint64 {
	if pr.PFormal == nil {
		pr.RFormal = ringRowsToFormal(pr.R, pr.ringQ.Modulus[0])
		return cloneFormalRows(pr.RFormal)
	}
	q := pr.ringQ.Modulus[0]
	r := len(pr.PFormal)
	pr.RFormal = make([][]uint64, pr.params.Eta)
	for k := 0; k < pr.params.Eta; k++ {
		acc := []uint64{0}
		if k < len(pr.MFormal) {
			acc = append([]uint64(nil), pr.MFormal[k]...)
		}
		acc = trimFormalInPlace(acc, q)
		if k < len(Gamma) {
			for j := 0; j < r && j < len(Gamma[k]); j++ {
				gamma := Gamma[k][j]
				if gamma >= q {
					gamma %= q
				}
				if gamma == 0 {
					continue
				}
				acc = addScaledFormalInto(acc, pr.PFormal[j], gamma, q)
			}
		}
		pr.RFormal[k] = trimFormalInPlace(acc, q)
	}
	return cloneFormalRows(pr.RFormal)
}

// EvalOpenV2 opens distinct challenged leaves from a v2 commitment. Exactly
// one independently sampled tape is copied for each index; no seed or other
// state capable of reconstructing unopened tapes is returned.
func (pr *Prover) EvalOpenV2(E []int) (*DECSOpening, error) {
	if pr == nil {
		return nil, fmt.Errorf("decs: EvalOpenV2 requires a completed v2 commitment")
	}
	if pr.mt == nil || len(pr.rootHash) == 0 {
		return nil, fmt.Errorf("decs: EvalOpenV2 called before commitment")
	}
	tapeBytes, err := v2TapeBytes(pr.params)
	if err != nil {
		return nil, err
	}
	if len(pr.tapes) != pr.nLeaves*tapeBytes {
		return nil, fmt.Errorf("decs: v2 private tapes unavailable or malformed")
	}
	if len(E) == 0 {
		return nil, fmt.Errorf("decs: v2 opening index set is empty")
	}
	previous := -1
	for _, idx := range E {
		if idx < 0 || idx >= pr.nLeaves {
			return nil, fmt.Errorf("decs: opening index %d outside [0,%d)", idx, pr.nLeaves)
		}
		if idx <= previous {
			return nil, fmt.Errorf("decs: v2 opening indices are not strictly increasing at %d", idx)
		}
		previous = idx
	}

	r := pr.rowCount()
	open := &DECSOpening{
		Version:   OpeningVersionV2,
		Role:      pr.commitmentContext.Role,
		Indices:   append([]int(nil), E...),
		Pvals:     make([][]uint64, len(E)),
		Mvals:     make([][]uint64, len(E)),
		PathIndex: make([][]int, len(E)),
		Tapes:     make([][]byte, len(E)),
		TapeBytes: tapeBytes,
		R:         r,
		Eta:       pr.params.Eta,
	}
	nodeIdx := make(map[string]int)
	addNode := func(value []byte) int {
		key := string(value)
		if id, ok := nodeIdx[key]; ok {
			return id
		}
		id := len(open.Nodes)
		open.Nodes = append(open.Nodes, append([]byte(nil), value...))
		nodeIdx[key] = id
		return id
	}
	for t, idx := range E {
		open.Pvals[t] = make([]uint64, r)
		for j := 0; j < r; j++ {
			open.Pvals[t][j] = pr.evalP(idx, j)
		}
		open.Mvals[t] = make([]uint64, pr.params.Eta)
		for k := 0; k < pr.params.Eta; k++ {
			open.Mvals[t][k] = pr.evalM(idx, k)
		}
		open.Tapes[t] = append([]byte(nil), pr.tapeAt(idx)...)
		var pathNodes [][]byte
		if pr.commitmentContext.TranscriptVersion == TranscriptVersionV3 {
			pathNodes, err = pr.mt.exactPathNodesV3(idx)
			if err != nil {
				return nil, err
			}
		} else {
			depth := len(pr.mt.layers) - 1
			pathNodes = make([][]byte, depth)
			cur := idx
			for level := 0; level < depth; level++ {
				pathNodes[level] = pr.mt.layers[level][cur^1]
				cur >>= 1
			}
		}
		pathIndices := make([]int, len(pathNodes))
		for level, node := range pathNodes {
			pathIndices[level] = addNode(node)
		}
		open.PathIndex[t] = pathIndices
	}
	return open, nil
}

func (pr *Prover) evalP(idx, j int) uint64 {
	if pr.PFormal != nil {
		q := pr.ringQ.Modulus[0]
		x := pr.points[idx] % q
		return evalPoly(pr.PFormal[j], x, q)
	}
	q := pr.ringQ.Modulus[0]
	x := pr.points[idx] % q
	coeffs := pr.P[j].Coeffs[0]
	return evalPoly(coeffs, x, q)
}

func (pr *Prover) evalM(idx, k int) uint64 {
	if pr.PFormal != nil {
		q := pr.ringQ.Modulus[0]
		x := pr.points[idx] % q
		return evalPoly(pr.MFormal[k], x, q)
	}
	q := pr.ringQ.Modulus[0]
	x := pr.points[idx] % q
	coeffs := pr.M[k].Coeffs[0]
	return evalPoly(coeffs, x, q)
}

func validateProverParams(params Params) error {
	if params.Degree < 0 {
		return fmt.Errorf("decs: invalid degree parameter")
	}
	if !IsSupportedHashBytes(params.HashBytes) {
		return fmt.Errorf("decs: invalid HashBytes (supported: %s)", SupportedHashBytesList())
	}
	if !IsSupportedTapeBytes(params.TapeBytes) {
		return fmt.Errorf("decs: invalid TapeBytes (supported: %s)", SupportedTapeBytesList())
	}
	return nil
}

func (pr *Prover) RootHash() []byte {
	if pr == nil {
		return nil
	}
	return append([]byte(nil), pr.rootHash...)
}

func (pr *Prover) rowCount() int {
	if pr.PFormal != nil {
		return len(pr.PFormal)
	}
	return len(pr.P)
}

func normalizeFormalRows(rows [][]uint64, q uint64) [][]uint64 {
	out := make([][]uint64, len(rows))
	for i := range rows {
		copied := append([]uint64(nil), rows[i]...)
		out[i] = trimFormalInPlace(copied, q)
	}
	return out
}

func trimFormalInPlace(coeffs []uint64, q uint64) []uint64 {
	if len(coeffs) == 0 {
		return []uint64{0}
	}
	last := -1
	for i := len(coeffs) - 1; i >= 0; i-- {
		v := coeffs[i]
		if v >= q {
			v %= q
			coeffs[i] = v
		}
		if last < 0 && v != 0 {
			last = i
		}
	}
	if last < 0 {
		coeffs[0] = 0
		return coeffs[:1]
	}
	for last > 0 && coeffs[last] == 0 {
		last--
	}
	return coeffs[:last+1]
}

func cloneFormalRows(rows [][]uint64) [][]uint64 {
	out := make([][]uint64, len(rows))
	for i := range rows {
		out[i] = append([]uint64(nil), rows[i]...)
	}
	return out
}

func addScaledFormalInto(dst []uint64, src []uint64, scale, q uint64) []uint64 {
	if len(src) == 0 || scale == 0 {
		return dst
	}
	if len(dst) < len(src) {
		grown := make([]uint64, len(src))
		copy(grown, dst)
		dst = grown
	}
	for i := range src {
		v := src[i]
		if v >= q {
			v %= q
		}
		if v == 0 {
			continue
		}
		term := mulMod64Reduced(v, scale, q)
		if dst[i] >= q {
			dst[i] %= q
		}
		dst[i] = addMod64Reduced(dst[i], term, q)
	}
	return dst
}

func ringRowsToFormal(rows []*ring.Poly, q uint64) [][]uint64 {
	out := make([][]uint64, len(rows))
	for i := range rows {
		coeffs := append([]uint64(nil), rows[i].Coeffs[0]...)
		out[i] = trimFormalInPlace(coeffs, q)
	}
	return out
}

// OpeningPackOptions selects the proof payload encoding for DECS openings.
type OpeningPackOptions struct {
	// FixedSize emits fixed-width tail indices plus full row-major Merkle paths.
	FixedSize bool
	// NLeaves is used to derive the fixed index width when FixedSize is true.
	NLeaves int
	// FieldBitWidth fixes P/M residue streams when FixedSize is true. Zero keeps
	// the compact instance-minimum width.
	FieldBitWidth uint8
}

// PackOpening compacts residues and tail indices, then emits row-major Merkle
// paths.
func PackOpening(op *DECSOpening) {
	PackOpeningWithOptions(op, OpeningPackOptions{})
}

// PackOpeningWithOptions compacts an opening using the maintained fixed-size
// mode when requested, otherwise compacting residues and path indices only.
func PackOpeningWithOptions(op *DECSOpening, opts OpeningPackOptions) {
	if op == nil {
		return
	}
	if opts.FixedSize {
		width := int(opts.FieldBitWidth)
		op.packResiduesFixed(width)
		op.packTailIndicesFixed(bitWidthForCount(opts.NLeaves))
		op.packRowMajorPaths()
	} else {
		op.packResidues()
		op.packTailIndices()
		op.packRowMajorPaths()
	}
}

func bitWidthForCount(n int) int {
	if n <= 1 {
		return 1
	}
	return pathBitWidth(n - 1)
}

func (op *DECSOpening) packResiduesFixed(width int) {
	if width <= 0 {
		op.packResidues()
		return
	}
	op.packPvalsFixed(width)
	op.packMvalsFixed(width)
}

func (op *DECSOpening) packPvalsFixed(width int) {
	if op == nil || len(op.Pvals) == 0 {
		return
	}
	if op.R <= 0 {
		op.R = len(op.Pvals[0])
	}
	pCols := op.R
	if op.FormatVersion == OpeningFormatOmitCols || op.FormatVersion == OpeningFormatColumnWidths {
		if op.PColsEncoded > 0 {
			pCols = op.PColsEncoded
		} else {
			pCols = len(op.Pvals[0])
			op.PColsEncoded = pCols
		}
	} else {
		op.FormatVersion = OpeningFormatPlain
		op.PColsEncoded = 0
		op.POmitCols = nil
	}
	if pCols <= 0 {
		pCols = len(op.Pvals[0])
	}
	for i := range op.Pvals {
		if len(op.Pvals[i]) != pCols {
			panic("decs: ragged P matrix in fixed packed opening")
		}
	}
	if min := selectBitWidth(maxMatrixValue(op.Pvals)); min > width {
		width = min
	}
	op.PvalsBits = packFlatUintMatrix(op.Pvals, pCols, width)
	op.PvalsBitWidth = uint8(width)
	op.PvalsColumnWidths = nil
	if op.FormatVersion == OpeningFormatColumnWidths && len(op.POmitCols) == 0 {
		op.FormatVersion = OpeningFormatPlain
		op.PColsEncoded = 0
	} else if op.FormatVersion == OpeningFormatColumnWidths {
		op.FormatVersion = OpeningFormatOmitCols
	}
	op.Pvals = nil
}

func (op *DECSOpening) packMvalsFixed(width int) {
	if op == nil || len(op.Mvals) == 0 {
		return
	}
	if op.Eta <= 0 {
		op.Eta = len(op.Mvals[0])
	}
	mCols := op.Eta
	if op.MFormatVersion == OpeningFormatOmitCols || op.MFormatVersion == OpeningFormatColumnWidths {
		if op.MColsEncoded > 0 {
			mCols = op.MColsEncoded
		} else {
			mCols = len(op.Mvals[0])
			op.MColsEncoded = mCols
		}
	} else {
		op.MFormatVersion = OpeningFormatPlain
		op.MColsEncoded = 0
		op.MOmitCols = nil
	}
	if mCols <= 0 {
		mCols = len(op.Mvals[0])
	}
	for i := range op.Mvals {
		if len(op.Mvals[i]) != mCols {
			panic("decs: ragged M matrix in fixed packed opening")
		}
	}
	if min := selectBitWidth(maxMatrixValue(op.Mvals)); min > width {
		width = min
	}
	op.MvalsBits = packFlatUintMatrix(op.Mvals, mCols, width)
	op.MvalsBitWidth = uint8(width)
	op.MvalsColumnWidths = nil
	if op.MFormatVersion == OpeningFormatColumnWidths && len(op.MOmitCols) == 0 {
		op.MFormatVersion = OpeningFormatPlain
		op.MColsEncoded = 0
	} else if op.MFormatVersion == OpeningFormatColumnWidths {
		op.MFormatVersion = OpeningFormatOmitCols
	}
	op.Mvals = nil
}

func (op *DECSOpening) packRowMajorPaths() {
	if op == nil || op.EntryCount() == 0 {
		op.Nodes = nil
		op.PathIndex = nil
		op.PathBits = nil
		op.PathBitWidth = 0
		op.PathDepth = 0
		return
	}
	pathIdx := op.PathIndex
	if len(pathIdx) == 0 && len(op.PathBits) > 0 && op.PathDepth > 0 && op.PathBitWidth > 0 {
		if matrix, err := unpackPathMatrix(op.PathBits, op.EntryCount(), op.PathDepth, int(op.PathBitWidth)); err == nil {
			pathIdx = matrix
		}
	}
	if len(pathIdx) == 0 || len(op.Nodes) == 0 {
		return
	}
	depth := len(pathIdx[0])
	if depth <= 0 {
		return
	}
	rowMajor := make([][]byte, 0, op.EntryCount()*depth)
	for row := 0; row < op.EntryCount(); row++ {
		if row >= len(pathIdx) || len(pathIdx[row]) != depth {
			return
		}
		for lvl := 0; lvl < depth; lvl++ {
			id := pathIdx[row][lvl]
			if id < 0 || id >= len(op.Nodes) {
				return
			}
			rowMajor = append(rowMajor, append([]byte(nil), op.Nodes[id]...))
		}
	}
	op.Nodes = rowMajor
	op.PathIndex = nil
	op.PathBits = nil
	op.PathBitWidth = 0
	op.PathDepth = depth
}

// packResidues packs Pvals and Mvals into width-tagged row-major bitstreams.
func (op *DECSOpening) packResidues() {
	if len(op.Pvals) > 0 {
		if op.R <= 0 {
			if len(op.Pvals) > 0 {
				op.R = len(op.Pvals[0])
			}
		}
		pCols := op.R
		if op.FormatVersion == OpeningFormatOmitCols || op.FormatVersion == OpeningFormatColumnWidths {
			if op.PColsEncoded > 0 {
				pCols = op.PColsEncoded
			} else if len(op.Pvals) > 0 {
				pCols = len(op.Pvals[0])
				op.PColsEncoded = pCols
			}
		} else {
			op.FormatVersion = OpeningFormatPlain
			op.PColsEncoded = 0
			op.POmitCols = nil
		}
		if pCols < 0 {
			pCols = 0
		}
		if len(op.Pvals) > 0 {
			want := len(op.Pvals[0])
			if pCols == 0 {
				pCols = want
			}
			if want != pCols {
				panic("decs: inconsistent P row width for packed opening")
			}
			for i := 1; i < len(op.Pvals); i++ {
				if len(op.Pvals[i]) != pCols {
					panic("decs: ragged P matrix in packed opening")
				}
			}
		}
		wantColumnWidths := op.FormatVersion == OpeningFormatColumnWidths
		width := selectBitWidth(maxMatrixValue(op.Pvals))
		flat := packFlatUintMatrix(op.Pvals, pCols, width)
		flatCost := len(flat) + 1
		var colWidths []uint8
		var colPacked []byte
		colCost := flatCost
		if wantColumnWidths {
			colWidths = columnWidthsForMatrix(op.Pvals, pCols)
			colPacked = packColumnWidthUintMatrix(op.Pvals, pCols, colWidths)
			colCost = len(colPacked) + len(colWidths)
			if len(op.POmitCols) == 0 {
				colCost++ // format byte needed to signal per-column widths.
			}
		}
		if wantColumnWidths && len(colPacked) > 0 && colCost < flatCost {
			op.PvalsBits = colPacked
			op.PvalsBitWidth = 0
			op.PvalsColumnWidths = colWidths
			op.FormatVersion = OpeningFormatColumnWidths
		} else {
			op.PvalsBits = flat
			op.PvalsBitWidth = uint8(width)
			op.PvalsColumnWidths = nil
			if op.FormatVersion == OpeningFormatColumnWidths && len(op.POmitCols) == 0 {
				op.FormatVersion = OpeningFormatPlain
				op.PColsEncoded = 0
			} else if op.FormatVersion == OpeningFormatColumnWidths {
				op.FormatVersion = OpeningFormatOmitCols
			}
		}
		op.Pvals = nil
	}
	if len(op.Mvals) > 0 {
		if op.Eta <= 0 {
			if len(op.Mvals) > 0 {
				op.Eta = len(op.Mvals[0])
			}
		}
		mCols := op.Eta
		if op.MFormatVersion == OpeningFormatOmitCols || op.MFormatVersion == OpeningFormatColumnWidths {
			if op.MColsEncoded > 0 {
				mCols = op.MColsEncoded
			} else if len(op.Mvals) > 0 {
				mCols = len(op.Mvals[0])
				op.MColsEncoded = mCols
			}
		} else {
			op.MFormatVersion = OpeningFormatPlain
			op.MColsEncoded = 0
			op.MOmitCols = nil
		}
		if mCols < 0 {
			mCols = 0
		}
		if len(op.Mvals) > 0 {
			want := len(op.Mvals[0])
			if mCols == 0 {
				mCols = want
			}
			if want != mCols {
				panic("decs: inconsistent M row width for packed opening")
			}
			for i := 1; i < len(op.Mvals); i++ {
				if len(op.Mvals[i]) != mCols {
					panic("decs: ragged M matrix in packed opening")
				}
			}
		}
		wantColumnWidths := op.MFormatVersion == OpeningFormatColumnWidths
		width := selectBitWidth(maxMatrixValue(op.Mvals))
		flat := packFlatUintMatrix(op.Mvals, mCols, width)
		flatCost := len(flat) + 1
		var colWidths []uint8
		var colPacked []byte
		colCost := flatCost
		if wantColumnWidths {
			colWidths = columnWidthsForMatrix(op.Mvals, mCols)
			colPacked = packColumnWidthUintMatrix(op.Mvals, mCols, colWidths)
			colCost = len(colPacked) + len(colWidths)
			if len(op.MOmitCols) == 0 {
				colCost++
			}
		}
		if wantColumnWidths && len(colPacked) > 0 && colCost < flatCost {
			op.MvalsBits = colPacked
			op.MvalsBitWidth = 0
			op.MvalsColumnWidths = colWidths
			op.MFormatVersion = OpeningFormatColumnWidths
		} else {
			op.MvalsBits = flat
			op.MvalsBitWidth = uint8(width)
			op.MvalsColumnWidths = nil
			if op.MFormatVersion == OpeningFormatColumnWidths && len(op.MOmitCols) == 0 {
				op.MFormatVersion = OpeningFormatPlain
				op.MColsEncoded = 0
			} else if op.MFormatVersion == OpeningFormatColumnWidths {
				op.MFormatVersion = OpeningFormatOmitCols
			}
		}
		op.Mvals = nil
	}
}

// DeriveGammaV2 expands the complete v2 Merkle root into Gamma. It binds the
// same version/role/salt context as the commitment and never truncates a wide
// root to the legacy 16-byte prefix.
func DeriveGammaV2(ctx CommitmentContext, rootHash []byte, eta, r int, q uint64) ([][]uint64, error) {
	if err := ctx.Validate(); err != nil {
		return nil, err
	}
	if !IsSupportedHashBytes(len(rootHash)) {
		return nil, fmt.Errorf("decs: invalid v2 root width %d", len(rootHash))
	}
	if eta <= 0 || r <= 0 || q < 2 {
		return nil, fmt.Errorf("decs: invalid v2 gamma dimensions eta=%d r=%d q=%d", eta, r, q)
	}
	out := make([][]uint64, eta)
	limit := (^uint64(0) / q) * q
	var counter uint64
	for k := 0; k < eta; k++ {
		out[k] = make([]uint64, r)
		for j := 0; j < r; j++ {
			for {
				h := sha3.NewShake256()
				writeContextV2(h, gammaDomain(ctx), ctx)
				writeLengthPrefixed(h, rootHash)
				writeUint64(h, counter)
				var buf [8]byte
				_, _ = h.Read(buf[:])
				counter++
				value := binary.BigEndian.Uint64(buf[:])
				if value < limit {
					out[k][j] = value % q
					break
				}
			}
		}
	}
	return out, nil
}
