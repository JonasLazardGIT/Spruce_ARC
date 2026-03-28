package decs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

const nonceDeriveLabel = "decs-nonce"

func DeriveNonce(seed []byte, idx int, nonceBytes int) []byte {
	return deriveNonce(seed, idx, nonceBytes)
}

func deriveNonce(seed []byte, idx int, nonceBytes int) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(nonceDeriveLabel))
	_, _ = h.Write(seed)
	var idxBuf [4]byte
	binary.LittleEndian.PutUint32(idxBuf[:], uint32(idx))
	_, _ = h.Write(idxBuf[:])
	hSum := h.Sum(nil)
	if nonceBytes >= len(hSum) {
		out := make([]byte, nonceBytes)
		copy(out, hSum)
		if nonceBytes > len(hSum) {
			// expand deterministically if more bytes required
			var counter byte = 1
			pos := len(hSum)
			for pos < nonceBytes {
				hi := sha256.New()
				_, _ = hi.Write([]byte(nonceDeriveLabel))
				_, _ = hi.Write(seed)
				_, _ = hi.Write(idxBuf[:])
				_, _ = hi.Write([]byte{counter})
				counter++
				chunk := hi.Sum(nil)
				n := copy(out[pos:], chunk)
				if n == 0 {
					break
				}
				pos += n
			}
		}
		return out
	}
	return append([]byte(nil), hSum[:nonceBytes]...)
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

// CommitInit does DECS.Commit step 1: sample M, nonces; build Merkle tree; NTT(P,M).
func (pr *Prover) CommitInit() ([16]byte, error) {
	r := pr.rowCount()
	N := pr.nLeaves
	q := pr.ringQ.Modulus[0]

	// sampler
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

	// 1b) explicit-domain path computes evaluations on demand

	// 1c) build leaves
	leaves := make([][]byte, N)
	if len(pr.nonceSeed) == 0 {
		pr.nonceSeed = make([]byte, pr.params.NonceBytes)
		if _, err := rand.Read(pr.nonceSeed); err != nil {
			return [16]byte{}, err
		}
	} else if len(pr.nonceSeed) != pr.params.NonceBytes {
		return [16]byte{}, fmt.Errorf("decs: nonce seed length mismatch: got=%d want=%d", len(pr.nonceSeed), pr.params.NonceBytes)
	}
	buildLeaf := func(i int) []byte {
		buf := make([]byte, 4*(r+pr.params.Eta)+2+pr.params.NonceBytes)
		off := 0
		x := pr.points[i] % q
		if pr.PFormal != nil {
			for j := 0; j < r; j++ {
				binary.LittleEndian.PutUint32(buf[off:], uint32(evalPoly(pr.PFormal[j], x, q)))
				off += 4
			}
			for k := 0; k < pr.params.Eta; k++ {
				binary.LittleEndian.PutUint32(buf[off:], uint32(evalPoly(pr.MFormal[k], x, q)))
				off += 4
			}
		} else {
			for j := 0; j < r; j++ {
				binary.LittleEndian.PutUint32(buf[off:], uint32(evalPoly(pr.P[j].Coeffs[0], x, q)))
				off += 4
			}
			for k := 0; k < pr.params.Eta; k++ {
				binary.LittleEndian.PutUint32(buf[off:], uint32(evalPoly(pr.M[k].Coeffs[0], x, q)))
				off += 4
			}
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(i))
		off += 2
		rho := deriveNonce(pr.nonceSeed, i, pr.params.NonceBytes)
		copy(buf[off:], rho)
		return buf
	}
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 || N < 128 {
		for i := 0; i < N; i++ {
			leaves[i] = buildLeaf(i)
		}
	} else {
		if workers > N {
			workers = N
		}
		var wg sync.WaitGroup
		wg.Add(workers)
		for worker := 0; worker < workers; worker++ {
			start := worker
			go func() {
				defer wg.Done()
				for i := start; i < N; i += workers {
					leaves[i] = buildLeaf(i)
				}
			}()
		}
		wg.Wait()
	}

	// 1d) Merkle tree
	pr.mt = BuildMerkleTree(leaves)
	pr.root = pr.mt.Root()

	return pr.root, nil
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
			h := pr.mt.layers[lvl][sib][:]
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
	return nil
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

// PackOpening compacts residues and encodes PathIndex into fixed-width bitstreams.
func PackOpening(op *DECSOpening) {
	if op == nil {
		return
	}
	op.packResidues()
	op.packTailIndices()
	op.packFrontier()
	op.packPathIndexBits()
	if len(op.NonceSeed) > 0 {
		op.Nonces = nil
	}
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
		if op.FormatVersion == 1 {
			if op.PColsEncoded > 0 {
				pCols = op.PColsEncoded
			} else if len(op.Pvals) > 0 {
				pCols = len(op.Pvals[0])
				op.PColsEncoded = pCols
			}
		} else {
			op.FormatVersion = 0
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
		width := selectBitWidth(maxMatrixValue(op.Pvals))
		op.PvalsBits = packFlatUintMatrix(op.Pvals, pCols, width)
		op.PvalsBitWidth = uint8(width)
		op.Pvals = nil
	}
	if len(op.Mvals) > 0 {
		if op.Eta <= 0 {
			if len(op.Mvals) > 0 {
				op.Eta = len(op.Mvals[0])
			}
		}
		mCols := op.Eta
		if op.MFormatVersion == 1 {
			if op.MColsEncoded > 0 {
				mCols = op.MColsEncoded
			} else if len(op.Mvals) > 0 {
				mCols = len(op.Mvals[0])
				op.MColsEncoded = mCols
			}
		} else {
			op.MFormatVersion = 0
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
		width := selectBitWidth(maxMatrixValue(op.Mvals))
		op.MvalsBits = packFlatUintMatrix(op.Mvals, mCols, width)
		op.MvalsBitWidth = uint8(width)
		op.Mvals = nil
	}
}

func (op *DECSOpening) packPathIndexBits() {
	if op == nil {
		return
	}
	if len(op.PathIndex) == 0 {
		if len(op.PathBits) == 0 {
			op.PathBitWidth = 0
			op.PathDepth = 0
		}
		return
	}
	depth := len(op.PathIndex[0])
	if depth == 0 {
		op.PathBits = nil
		op.PathBitWidth = 0
		op.PathDepth = 0
		op.PathIndex = nil
		return
	}
	maxID := 0
	for _, row := range op.PathIndex {
		if len(row) != depth {
			// inconsistent depth; keep explicit form
			return
		}
		for _, id := range row {
			if id > maxID {
				maxID = id
			}
		}
	}
	width := pathBitWidth(maxID)
	if width > 32 {
		// packing beyond 32 bits not supported; keep explicit form
		return
	}
	op.PathBits = packPathMatrix(op.PathIndex, depth, width)
	op.PathBitWidth = uint8(width)
	op.PathDepth = depth
	op.PathIndex = nil
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
