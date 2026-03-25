package PIOP

import (
	"fmt"
	"sync"

	"github.com/tuneinsight/lattigo/v4/ring"
)

var transposeNTTCache = struct {
	sync.RWMutex
	colsByRing map[*ring.Ring][][]uint64
}{
	colsByRing: make(map[*ring.Ring][][]uint64),
}

func transposeNTTColumns(ringQ *ring.Ring) [][]uint64 {
	transposeNTTCache.RLock()
	cached := transposeNTTCache.colsByRing[ringQ]
	transposeNTTCache.RUnlock()
	if cached != nil {
		return cached
	}

	N := int(ringQ.N)
	cols := make([][]uint64, N)
	basis := ringQ.NewPoly()
	col := ringQ.NewPoly()
	for j := 0; j < N; j++ {
		if j > 0 {
			basis.Coeffs[0][j-1] = 0
		}
		basis.Coeffs[0][j] = 1
		ringQ.NTT(basis, col)
		coeffs := make([]uint64, N)
		copy(coeffs, col.Coeffs[0][:N])
		cols[j] = coeffs
	}
	if N > 0 {
		basis.Coeffs[0][N-1] = 0
	}

	transposeNTTCache.Lock()
	if ready := transposeNTTCache.colsByRing[ringQ]; ready != nil {
		transposeNTTCache.Unlock()
		return ready
	}
	transposeNTTCache.colsByRing[ringQ] = cols
	transposeNTTCache.Unlock()
	return cols
}

func TransposeNTTVector(ringQ *ring.Ring, r []uint64) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(r) != ringQ.N {
		return nil, fmt.Errorf("transpose NTT: length mismatch (got %d want %d)", len(r), ringQ.N)
	}
	q := ringQ.Modulus[0]
	N := int(ringQ.N)
	vec := make([]uint64, N)
	for i := 0; i < N; i++ {
		v := r[i]
		if v >= q {
			v %= q
		}
		vec[i] = v
	}
	cols := transposeNTTColumns(ringQ)
	res := make([]uint64, N)
	for j := 0; j < N; j++ {
		col := cols[j]
		acc := uint64(0)
		for i := 0; i < N; i++ {
			vi := vec[i]
			if vi == 0 {
				continue
			}
			acc = modAddReduced(acc, modMulReduced(col[i], vi, q), q)
		}
		res[j] = acc
	}
	return res, nil
}
