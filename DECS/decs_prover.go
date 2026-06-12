package decs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
	"golang.org/x/crypto/sha3"
)

const nonceDeriveLabel = "decs-nonce"

// q32 dense storage is kept behind a local switch because the maintained q20
// profiles benchmark faster with uint64 coefficient rows on current hardware.
const enableFormalEvalUint32 = false

func deriveNonce(seed []byte, idx int, nonceBytes int) []byte {
	scratch := make([]byte, 0, len(nonceDeriveLabel)+len(seed)+5)
	out := make([]byte, nonceBytes)
	_ = deriveNonceInto(out, scratch, seed, idx)
	return out
}

func deriveNonceInto(dst []byte, scratch []byte, seed []byte, idx int) []byte {
	nonceBytes := len(dst)
	if nonceBytes <= 0 {
		return scratch
	}
	scratch = scratch[:0]
	scratch = append(scratch, nonceDeriveLabel...)
	scratch = append(scratch, seed...)
	var idxBuf [4]byte
	binary.LittleEndian.PutUint32(idxBuf[:], uint32(idx))
	scratch = append(scratch, idxBuf[:]...)
	sum := sha256.Sum256(scratch)
	n := copy(dst, sum[:])
	if n < nonceBytes {
		baseLen := len(scratch)
		var counter byte = 1
		for n < nonceBytes {
			scratch = scratch[:baseLen]
			scratch = append(scratch, counter)
			counter++
			chunk := sha256.Sum256(scratch)
			n += copy(dst[n:], chunk[:])
		}
	}
	return scratch
}

type formalEvalPlan struct {
	rowCount    int
	maxDeg      int
	nnz         int
	rowDeg      []int
	coeffs      []uint64
	coeffs32    []uint32
	rowOffsets  []int
	rowCoeffs   []uint64
	dotSafe     bool
	sparseTerms []formalEvalTerm
}

type formalEvalTerm struct {
	degree int
	row    int
	coeff  uint64
}

func newFormalEvalPlan(rows [][]uint64, q uint64) formalEvalPlan {
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
	useRowMajor := dotSafe && !useSparse && !useUint32 && rowSlots*4 < denseSlots*3
	var coeffs []uint64
	var coeffs32 []uint32
	var rowOffsets []int
	var rowCoeffs []uint64
	if useRowMajor {
		rowOffsets = make([]int, rowCount+1)
		rowCoeffs = make([]uint64, 0, rowSlots)
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
			if useUint32 {
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
	ringQ     *ring.Ring
	P         []*ring.Poly // r input polys (coeff form)
	M         []*ring.Poly // η mask polys (coeff form)
	PFormal   [][]uint64   // optional formal coeffs for explicit-domain mode
	MFormal   [][]uint64   // optional formal coeffs for explicit-domain mode
	nonceSeed []byte
	mt        *MerkleTree
	root      [16]byte
	rootHash  []byte
	R         []*ring.Poly // η output polys in coeff form
	RFormal   [][]uint64   // optional formal coeffs for explicit-domain mode
	params    Params
	points    []uint64 // explicit evaluation domain points E[i]
	nLeaves   int
}

// NewProverWithParamsAndPointsFormalChecked is the error-returning variant of
// NewProverWithParamsAndPointsFormal for library callers.
func NewProverWithParamsAndPointsFormalChecked(ringQ *ring.Ring, coeffs [][]uint64, params Params, points []uint64) (*Prover, error) {
	if points == nil {
		return nil, fmt.Errorf("decs: formal constructor requires explicit points")
	}
	if err := validateProverParams(params); err != nil {
		return nil, err
	}
	if params.Eta <= 0 {
		return nil, fmt.Errorf("decs: invalid eta (must be > 0)")
	}
	if params.NonceBytes <= 0 {
		return nil, fmt.Errorf("decs: invalid NonceBytes (must be > 0)")
	}
	if len(ringQ.Modulus) != 1 {
		return nil, fmt.Errorf("decs: only single-modulus rings are supported (len(Modulus) must be 1)")
	}
	if err := validatePoints(points, ringQ.Modulus[0]); err != nil {
		return nil, err
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
}

// FormalEvalMode selects the internal formal-row evaluator used by CommitInit.
// All modes keep the committed leaf bytes and Merkle tree format; they are
// expected to produce identical roots when masks and nonces are fixed.
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
}

type commitInitPhaseTimings struct {
	maskSamplingNs  int64
	formalEvalNs    int64
	leafEncodingNs  int64
	nonceDeriveNs   int64
	leafHashNs      int64
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
	rec.RecordDuration("decs.nonce_derivation_cpu", time.Duration(atomic.LoadInt64(&t.nonceDeriveNs)))
	rec.RecordDuration("decs.leaf_hashing_cpu", time.Duration(atomic.LoadInt64(&t.leafHashNs)))
}

// CommitInitWithOptions is CommitInit with benchmark-only controls. It keeps
// the committed leaf encoding and tree format so roots and proof bytes match
// CommitInit for fixed masks/nonces.
func (pr *Prover) CommitInitWithOptions(opts CommitOptions) ([16]byte, error) {
	internal := commitInitOptions{
		phaseRecorder:         opts.PhaseRecorder,
		workerCount:           opts.WorkerCount,
		forceScalarFormalEval: true,
		recordSubphases:       opts.RecordSubphases,
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
		return [16]byte{}, fmt.Errorf("decs: unsupported formal eval mode %d", opts.FormalEvalMode)
	}
	if opts.WorkerCount > 0 {
		internal.workerCount = opts.WorkerCount
	}
	return pr.commitInitWithOptions(internal)
}

func (pr *Prover) commitInitWithOptions(opts commitInitOptions) ([16]byte, error) {
	r := pr.rowCount()
	N := pr.nLeaves
	q := pr.ringQ.Modulus[0]
	hashBytes := NormalizeHashBytes(pr.params.HashBytes)
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
						return [16]byte{}, err
					}
					row[i] = v
				}
				pr.MFormal[k] = trimFormalInPlace(row, pr.ringQ.Modulus[0])
			}
		} else if len(pr.MFormal) != pr.params.Eta {
			return [16]byte{}, fmt.Errorf("decs: formal mask polynomial count mismatch: got=%d want=%d", len(pr.MFormal), pr.params.Eta)
		}
	} else {
		if pr.M == nil {
			prng, err := utils.NewPRNG()
			if err != nil {
				return [16]byte{}, err
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
			return [16]byte{}, fmt.Errorf("decs: mask polynomial count mismatch: got=%d want=%d", len(pr.M), pr.params.Eta)
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
	leafHashes := make([][]byte, N)
	if len(pr.nonceSeed) == 0 {
		pr.nonceSeed = make([]byte, pr.params.NonceBytes)
		if _, err := rand.Read(pr.nonceSeed); err != nil {
			return [16]byte{}, err
		}
	} else if len(pr.nonceSeed) != pr.params.NonceBytes {
		return [16]byte{}, fmt.Errorf("decs: nonce seed length mismatch: got=%d want=%d", len(pr.nonceSeed), pr.params.NonceBytes)
	}
	leafBytes := 4*(r+pr.params.Eta) + 2 + pr.params.NonceBytes
	if pr.PFormal != nil {
		if opts.forceScalarFormalEval {
			pr.commitInitFormalScalarLeafHashes(leafHashes, leafBytes, timings)
		} else {
			pr.commitInitFormalOptimizedLeafHashes(leafHashes, leafBytes, opts, timings)
		}
	} else {
		buildLeaf := func(i int) []byte {
			buf := make([]byte, leafBytes)
			off := 0
			x := pr.points[i] % q
			for j := 0; j < r; j++ {
				binary.LittleEndian.PutUint32(buf[off:], uint32(evalPoly(pr.P[j].Coeffs[0], x, q)))
				off += 4
			}
			for k := 0; k < pr.params.Eta; k++ {
				binary.LittleEndian.PutUint32(buf[off:], uint32(evalPoly(pr.M[k].Coeffs[0], x, q)))
				off += 4
			}
			binary.LittleEndian.PutUint16(buf[off:], uint16(i))
			off += 2
			rho := deriveNonce(pr.nonceSeed, i, pr.params.NonceBytes)
			copy(buf[off:], rho)
			return buf
		}
		workers := runtime.GOMAXPROCS(0)
		if workers < 2 || N < 128 {
			h := nilShake()
			for i := 0; i < N; i++ {
				leaf := buildLeaf(i)
				leafHashes[i] = make([]byte, hashBytes)
				hashLeafIntoWith(h, leaf, leafHashes[i])
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
				go func() {
					defer wg.Done()
					h := nilShake()
					for i := start; i < end; i++ {
						leaf := buildLeaf(i)
						leafHashes[i] = make([]byte, hashBytes)
						hashLeafIntoWith(h, leaf, leafHashes[i])
					}
				}()
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
	pr.mt = BuildMerkleTreeFromLeafHashBytes(leafHashes, hashBytes)
	pr.root = pr.mt.Root()
	pr.rootHash = pr.mt.RootHash()
	if timings != nil {
		timings.merkleNs = int64(time.Since(merkleStart))
		timings.record(opts.phaseRecorder)
	}

	return pr.root, nil
}

func (pr *Prover) commitInitFormalScalarLeafHashes(leafHashes [][]byte, leafBytes int, timings *commitInitPhaseTimings) {
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
	if workers < 2 || N < 128 {
		pr.commitInitFormalScalarRange(0, N, leafHashes, leafBytes, r, red, pPlan, mPlan, usePowerEval, powerCount, timings)
		return
	}
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
			pr.commitInitFormalScalarRange(start, end, leafHashes, leafBytes, r, red, pPlan, mPlan, usePowerEval, powerCount, timings)
		}(start, end)
	}
	wg.Wait()
}

func (pr *Prover) commitInitFormalScalarRange(start, end int, leafHashes [][]byte, leafBytes, r int, red modReducer64, pPlan, mPlan formalEvalPlan, usePowerEval bool, powerCount int, timings *commitInitPhaseTimings) {
	buf := make([]byte, leafBytes)
	pScratch := make([]uint64, r)
	mScratch := make([]uint64, pr.params.Eta)
	var powerScratch []uint64
	if usePowerEval {
		powerScratch = make([]uint64, powerCount)
	}
	nonceScratch := make([]byte, 0, len(nonceDeriveLabel)+len(pr.nonceSeed)+5)
	shake := nilShake()
	record := timings != nil && timings.recordSubphases
	var evalNs, encodeNs, nonceNs, hashNs int64
	for i := start; i < end; i++ {
		buf = buf[:leafBytes]
		x := pr.points[i] % red.mod
		evalStart := time.Time{}
		if record {
			evalStart = time.Now()
		}
		if usePowerEval {
			computeFormalEvalPowers(powerScratch, x, red)
		}
		pPlan.evalIntoPrepared(pScratch, x, red, powerScratch)
		mPlan.evalIntoPrepared(mScratch, x, red, powerScratch)
		if record {
			evalNs += int64(time.Since(evalStart))
		}
		encodeStart := time.Time{}
		if record {
			encodeStart = time.Now()
		}
		off := 0
		for j := 0; j < r; j++ {
			binary.LittleEndian.PutUint32(buf[off:], uint32(pScratch[j]))
			off += 4
		}
		for k := 0; k < pr.params.Eta; k++ {
			binary.LittleEndian.PutUint32(buf[off:], uint32(mScratch[k]))
			off += 4
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(i))
		off += 2
		if record {
			encodeNs += int64(time.Since(encodeStart))
		}
		nonceStart := time.Time{}
		if record {
			nonceStart = time.Now()
		}
		nonceScratch = deriveNonceInto(buf[off:off+pr.params.NonceBytes], nonceScratch, pr.nonceSeed, i)
		if record {
			nonceNs += int64(time.Since(nonceStart))
		}
		hashStart := time.Time{}
		if record {
			hashStart = time.Now()
		}
		leafHashes[i] = make([]byte, NormalizeHashBytes(pr.params.HashBytes))
		hashLeafIntoWith(shake, buf, leafHashes[i])
		if record {
			hashNs += int64(time.Since(hashStart))
		}
	}
	if record {
		atomic.AddInt64(&timings.formalEvalNs, evalNs)
		atomic.AddInt64(&timings.leafEncodingNs, encodeNs)
		atomic.AddInt64(&timings.nonceDeriveNs, nonceNs)
		atomic.AddInt64(&timings.leafHashNs, hashNs)
	}
}

func (pr *Prover) commitInitFormalTiledLeafHashes(leafHashes [][]byte, leafBytes int, opts commitInitOptions, timings *commitInitPhaseTimings) {
	r := pr.rowCount()
	N := pr.nLeaves
	q := pr.ringQ.Modulus[0]
	red := newModReducer64(q)
	combinedRows := make([][]uint64, 0, r+pr.params.Eta)
	combinedRows = append(combinedRows, pr.PFormal...)
	combinedRows = append(combinedRows, pr.MFormal...)
	plan := newFormalEvalPlan(combinedRows, q)
	if !plan.usesPowerEval() {
		pr.commitInitFormalScalarLeafHashes(leafHashes, leafBytes, timings)
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
		pr.commitInitFormalTiledRange(0, N, tileSize, leafHashes, leafBytes, r, red, plan, timings)
		return
	}
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
			pr.commitInitFormalTiledRange(start, end, tileSize, leafHashes, leafBytes, r, red, plan, timings)
		}(start, end)
	}
	wg.Wait()
}

func (pr *Prover) commitInitFormalOptimizedLeafHashes(leafHashes [][]byte, leafBytes int, opts commitInitOptions, timings *commitInitPhaseTimings) {
	if opts.tileSize > 1 {
		pr.commitInitFormalTiledLeafHashes(leafHashes, leafBytes, opts, timings)
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
		pr.commitInitFormalScalarLeafHashes(leafHashes, leafBytes, timings)
		return
	}
	workers := opts.workerCount
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 2 || N < 128 {
		pr.commitInitFormalOptimizedRange(0, N, leafHashes, leafBytes, r, red, plan, timings)
		return
	}
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
			pr.commitInitFormalOptimizedRange(start, end, leafHashes, leafBytes, r, red, plan, timings)
		}(start, end)
	}
	wg.Wait()
}

func (pr *Prover) commitInitFormalOptimizedRange(start, end int, leafHashes [][]byte, leafBytes, r int, red modReducer64, plan formalEvalPlan, timings *commitInitPhaseTimings) {
	buf := make([]byte, leafBytes)
	values := make([]uint64, plan.rowCount)
	powers := make([]uint64, plan.maxDeg+1)
	nonceScratch := make([]byte, 0, len(nonceDeriveLabel)+len(pr.nonceSeed)+5)
	shake := nilShake()
	record := timings != nil && timings.recordSubphases
	var evalNs, encodeNs, nonceNs, hashNs int64
	for i := start; i < end; i++ {
		buf = buf[:leafBytes]
		x := pr.points[i] % red.mod
		evalStart := time.Time{}
		if record {
			evalStart = time.Now()
		}
		computeFormalEvalPowers(powers, x, red)
		plan.evalIntoPrepared(values, x, red, powers)
		if record {
			evalNs += int64(time.Since(evalStart))
		}
		encodeStart := time.Time{}
		if record {
			encodeStart = time.Now()
		}
		off := 0
		for j := 0; j < r; j++ {
			binary.LittleEndian.PutUint32(buf[off:], uint32(values[j]))
			off += 4
		}
		for k := 0; k < pr.params.Eta; k++ {
			binary.LittleEndian.PutUint32(buf[off:], uint32(values[r+k]))
			off += 4
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(i))
		off += 2
		if record {
			encodeNs += int64(time.Since(encodeStart))
		}
		nonceStart := time.Time{}
		if record {
			nonceStart = time.Now()
		}
		nonceScratch = deriveNonceInto(buf[off:off+pr.params.NonceBytes], nonceScratch, pr.nonceSeed, i)
		if record {
			nonceNs += int64(time.Since(nonceStart))
		}
		hashStart := time.Time{}
		if record {
			hashStart = time.Now()
		}
		leafHashes[i] = make([]byte, NormalizeHashBytes(pr.params.HashBytes))
		hashLeafIntoWith(shake, buf, leafHashes[i])
		if record {
			hashNs += int64(time.Since(hashStart))
		}
	}
	if record {
		atomic.AddInt64(&timings.formalEvalNs, evalNs)
		atomic.AddInt64(&timings.leafEncodingNs, encodeNs)
		atomic.AddInt64(&timings.nonceDeriveNs, nonceNs)
		atomic.AddInt64(&timings.leafHashNs, hashNs)
	}
}

func (pr *Prover) commitInitFormalTiledRange(start, end, tileSize int, leafHashes [][]byte, leafBytes, r int, red modReducer64, plan formalEvalPlan, timings *commitInitPhaseTimings) {
	rowCount := plan.rowCount
	buf := make([]byte, leafBytes)
	values := make([]uint64, tileSize*rowCount)
	powers := make([]uint64, tileSize*(plan.maxDeg+1))
	nonceScratch := make([]byte, 0, len(nonceDeriveLabel)+len(pr.nonceSeed)+5)
	shake := nilShake()
	record := timings != nil && timings.recordSubphases
	var evalNs, encodeNs, nonceNs, hashNs int64
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
		plan.evalTileIntoPrepared(values[:tileLen*rowCount], points, red, powers[:tileLen*(plan.maxDeg+1)])
		if record {
			evalNs += int64(time.Since(evalStart))
		}
		for t := 0; t < tileLen; t++ {
			i := tileStart + t
			rowVals := values[t*rowCount : (t+1)*rowCount]
			buf = buf[:leafBytes]
			encodeStart := time.Time{}
			if record {
				encodeStart = time.Now()
			}
			off := 0
			for j := 0; j < r; j++ {
				binary.LittleEndian.PutUint32(buf[off:], uint32(rowVals[j]))
				off += 4
			}
			for k := 0; k < pr.params.Eta; k++ {
				binary.LittleEndian.PutUint32(buf[off:], uint32(rowVals[r+k]))
				off += 4
			}
			binary.LittleEndian.PutUint16(buf[off:], uint16(i))
			off += 2
			if record {
				encodeNs += int64(time.Since(encodeStart))
			}
			nonceStart := time.Time{}
			if record {
				nonceStart = time.Now()
			}
			nonceScratch = deriveNonceInto(buf[off:off+pr.params.NonceBytes], nonceScratch, pr.nonceSeed, i)
			if record {
				nonceNs += int64(time.Since(nonceStart))
			}
			hashStart := time.Time{}
			if record {
				hashStart = time.Now()
			}
			leafHashes[i] = make([]byte, NormalizeHashBytes(pr.params.HashBytes))
			hashLeafIntoWith(shake, buf, leafHashes[i])
			if record {
				hashNs += int64(time.Since(hashStart))
			}
		}
	}
	if record {
		atomic.AddInt64(&timings.formalEvalNs, evalNs)
		atomic.AddInt64(&timings.leafEncodingNs, encodeNs)
		atomic.AddInt64(&timings.nonceDeriveNs, nonceNs)
		atomic.AddInt64(&timings.leafHashNs, hashNs)
	}
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

// EvalOpen does DECS.Eval step 1: given E, returns Pvals,Mvals,Paths,Nonces.
func (pr *Prover) EvalOpen(E []int) *DECSOpening {
	r := pr.rowCount()
	open := &DECSOpening{
		Indices:    append([]int(nil), E...),
		Pvals:      make([][]uint64, len(E)),
		Mvals:      make([][]uint64, len(E)),
		Nodes:      nil,
		PathIndex:  make([][]int, len(E)),
		R:          r,
		Eta:        pr.params.Eta,
		NonceSeed:  append([]byte(nil), pr.nonceSeed...),
		NonceBytes: pr.params.NonceBytes,
	}
	// Deduplicate sibling nodes across all paths
	nodeIdx := make(map[string]int)
	addNode := func(b []byte) int {
		key := string(b)
		if id, ok := nodeIdx[key]; ok {
			return id
		}
		id := len(open.Nodes)
		// store a copy
		cp := append([]byte(nil), b...)
		open.Nodes = append(open.Nodes, cp)
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
		// Build path and map to indices
		depth := len(pr.mt.layers) - 1
		pi := make([]int, depth)
		cur := idx
		for lvl := 0; lvl < depth; lvl++ {
			sib := cur ^ 1
			h := pr.mt.layers[lvl][sib]
			pi[lvl] = addNode(h)
			cur >>= 1
		}
		open.PathIndex[t] = pi
	}
	// Return unpacked opening; the caller may pack it after combining
	return open
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
	if params.HashBytes != 0 && !IsSupportedHashBytes(params.HashBytes) {
		return fmt.Errorf("decs: invalid HashBytes (supported: %s)", SupportedHashBytesList())
	}
	return nil
}

func (pr *Prover) RootHash() []byte {
	if pr == nil {
		return nil
	}
	if len(pr.rootHash) > 0 {
		return append([]byte(nil), pr.rootHash...)
	}
	return append([]byte(nil), pr.root[:]...)
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
	if len(op.NonceSeed) > 0 {
		op.Nonces = nil
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

// DeriveGamma expands root→η×r matrix Γ with entries uniform in [0,q).
// Uses SHA256(root || ctr) as a PRF and 64-bit rejection sampling for exact uniformity.
func DeriveGamma(root [16]byte, eta, r int, q uint64) [][]uint64 {
	out := make([][]uint64, eta)
	var ctr uint64
	for k := 0; k < eta; k++ {
		out[k] = make([]uint64, r)
		for j := 0; j < r; j++ {
			for {
				var buf [24]byte
				copy(buf[:16], root[:])
				binary.LittleEndian.PutUint64(buf[16:], ctr)
				h := sha256.Sum256(buf[:])
				x := binary.LittleEndian.Uint64(h[:8])
				ctr++
				limit := (^uint64(0) / q) * q
				if x < limit {
					out[k][j] = x % q
					break
				}
			}
		}
	}
	return out
}
