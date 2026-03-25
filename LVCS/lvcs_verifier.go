package lvcs

import (
	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// VerifierState holds verifier‐side LVCS state.
type VerifierState struct {
	RingQ   *ring.Ring
	r       int
	params  decs.Params
	ncols   int // tail start boundary, supplied by caller
	layout  OracleLayout
	points  []uint64
	nLeaves int

	Root    [16]byte
	Gamma   [][]uint64
	R       []*ring.Poly
	RFormal [][]uint64
}

func NewVerifierWithParamsAndPoints(ringQ *ring.Ring, r int, params decs.Params, ncols int, points []uint64) *VerifierState {
	if len(points) == 0 {
		panic("lvcs: explicit points are required")
	}
	nLeaves := len(points)
	v := &VerifierState{RingQ: ringQ, r: r, params: params, ncols: ncols, points: points, nLeaves: nLeaves}
	v.layout = OracleLayout{
		Witness: LayoutSegment{Offset: 0, Count: r},
		Mask:    LayoutSegment{Offset: r, Count: 0},
	}
	return v
}

// AcceptGamma allows callers to inject an explicit Γ sampled via Fiat–Shamir grinding.
func (v *VerifierState) AcceptGamma(gamma [][]uint64) {
	v.Gamma = gamma
}

// CommitStep2Formal stores formal coefficient rows for R_k and checks the
// configured degree bound.
func (v *VerifierState) CommitStep2Formal(R [][]uint64) bool {
	v.R = nil
	v.RFormal = make([][]uint64, len(R))
	for i := range R {
		row := append([]uint64(nil), R[i]...)
		v.RFormal[i] = row
		for d := v.params.Degree + 1; d < len(row); d++ {
			if row[d]%v.RingQ.Modulus[0] != 0 {
				return false
			}
		}
	}
	return true
}

// EvalStep2 – §4.1 step 4:
// Verify Merkle + low-degree + linear checks, leaking only the ℓ masked positions.
func (v *VerifierState) EvalStep2(
	bar [][]uint64, // prover’s ¯v_k
	E []int, // challenge set (tail-only)
	open *decs.DECSOpening,
	C [][]uint64, // coefficient matrix
	vTargets [][]uint64, // public v_k on Ω
) bool {
	if open == nil {
		return false
	}
	if len(bar) == 0 || len(bar[0]) == 0 {
		return false
	}
	m := len(bar)
	ell := len(bar[0])
	ncols := v.ncols
	N := v.nLeaves
	maskStart := ncols
	maskEnd := ncols + ell
	if maskEnd > N {
		return false
	}
	if len(E) != ell {
		return false
	}
	tailSeen := make(map[int]struct{}, len(E))
	for _, idx := range E {
		if idx < maskEnd || idx >= N {
			return false
		}
		if _, dup := tailSeen[idx]; dup {
			return false
		}
		tailSeen[idx] = struct{}{}
	}
	if len(C) != m {
		return false
	}
	if len(vTargets) != m {
		return false
	}
	for k := 0; k < m; k++ {
		if len(bar[k]) != ell {
			return false
		}
		if len(C[k]) != v.r {
			return false
		}
		if len(vTargets[k]) != ncols {
			return false
		}
	}

	if open.EntryCount() != len(E)+ell {
		return false
	}

	mod := v.RingQ.Modulus[0]
	Qcoefs := make([][]uint64, m)
	for k := 0; k < m; k++ {
		var err error
		Qcoefs[k], err = interpolateRowExplicitCoeffs(vTargets[k], bar[k], ncols, ell, v.points, mod)
		if err != nil {
			return false
		}
	}
	if !prepareOpeningForEvalStep2(open, C, bar, ncols, maskEnd, v.points, Qcoefs, mod) {
		return false
	}
	if err := decs.EnsureMerkleDecoded(open); err != nil {
		return false
	}
	maskOpen := &decs.DECSOpening{
		Indices:    make([]int, 0, ell),
		Pvals:      make([][]uint64, 0, ell),
		Mvals:      make([][]uint64, 0, ell),
		Nodes:      open.Nodes,
		PathIndex:  make([][]int, 0, ell),
		NonceSeed:  append([]byte(nil), open.NonceSeed...),
		NonceBytes: open.NonceBytes,
		R:          open.R,
		Eta:        open.Eta,
	}
	tailOpen := &decs.DECSOpening{
		Indices:    make([]int, 0, len(E)),
		Pvals:      make([][]uint64, 0, len(E)),
		Mvals:      make([][]uint64, 0, len(E)),
		Nodes:      open.Nodes,
		PathIndex:  make([][]int, 0, len(E)),
		NonceSeed:  append([]byte(nil), open.NonceSeed...),
		NonceBytes: open.NonceBytes,
		R:          open.R,
		Eta:        open.Eta,
	}
	maskSeen := make(map[int]struct{}, ell)
	tailSeenOpen := make(map[int]struct{}, len(E))
	allIdx := open.AllIndices()
	for i, idx := range allIdx {
		switch {
		case idx >= maskStart && idx < maskEnd:
			if _, dup := maskSeen[idx]; dup {
				return false
			}
			maskSeen[idx] = struct{}{}
			maskOpen.Indices = append(maskOpen.Indices, idx)
			maskOpen.Pvals = append(maskOpen.Pvals, open.Pvals[i])
			maskOpen.Mvals = append(maskOpen.Mvals, open.Mvals[i])
			maskOpen.PathIndex = append(maskOpen.PathIndex, append([]int(nil), open.PathIndex[i]...))
		case idx >= maskEnd && idx < N:
			if _, dup := tailSeenOpen[idx]; dup {
				return false
			}
			tailSeenOpen[idx] = struct{}{}
			tailOpen.Indices = append(tailOpen.Indices, idx)
			tailOpen.Pvals = append(tailOpen.Pvals, open.Pvals[i])
			tailOpen.Mvals = append(tailOpen.Mvals, open.Mvals[i])
			tailOpen.PathIndex = append(tailOpen.PathIndex, append([]int(nil), open.PathIndex[i]...))
		default:
			return false
		}
	}
	if len(maskOpen.PathIndex) > 0 {
		maskOpen.PathDepth = len(maskOpen.PathIndex[0])
	}
	if len(tailOpen.PathIndex) > 0 {
		tailOpen.PathDepth = len(tailOpen.PathIndex[0])
	}

	if len(maskOpen.Indices) != ell {
		return false
	}
	if len(tailOpen.Indices) != len(E) {
		return false
	}
	if !equalSets(tailOpen.Indices, E) {
		return false
	}

	decv, err := decs.NewVerifierWithParamsAndPointsChecked(v.RingQ, v.r, v.params, v.points)
	if err != nil {
		return false
	}
	maskIdx := make([]int, ell)
	for i := 0; i < ell; i++ {
		maskIdx[i] = ncols + i
	}
	if len(v.RFormal) > 0 {
		if !decv.VerifyEvalAtFormal(v.Root, v.Gamma, v.RFormal, maskOpen, maskIdx) {
			return false
		}
		if !decv.VerifyEvalAtFormal(v.Root, v.Gamma, v.RFormal, tailOpen, E) {
			return false
		}
	} else {
		if !decv.VerifyEvalAt(v.Root, v.Gamma, v.R, maskOpen, maskIdx) {
			return false
		}
		if !decv.VerifyEvalAt(v.Root, v.Gamma, v.R, tailOpen, E) {
			return false
		}
	}

	for t, idx := range maskOpen.Indices {
		maskedPos := idx - ncols
		for k := 0; k < m; k++ {
			if len(maskOpen.Pvals[t]) != v.r {
				return false
			}
			sum := uint64(0)
			for j := 0; j < v.r; j++ {
				sum = MulAddMod64(sum, C[k][j], maskOpen.Pvals[t][j], mod)
			}
			if sum != bar[k][maskedPos] {
				return false
			}
		}
	}

	for t, idx := range tailOpen.Indices {
		if len(tailOpen.Pvals[t]) != v.r {
			return false
		}
		for k := 0; k < m; k++ {
			x := v.points[idx] % mod
			lhs := evalPolyCoeffs(Qcoefs[k], x, mod)
			rhs := uint64(0)
			for j := 0; j < v.r; j++ {
				rhs = MulAddMod64(rhs, C[k][j], tailOpen.Pvals[t][j], mod)
			}
			if lhs != rhs {
				return false
			}
		}
	}

	return true
}

func prepareOpeningForEvalStep2(
	open *decs.DECSOpening,
	C [][]uint64,
	bar [][]uint64,
	ncols int,
	maskEnd int,
	points []uint64,
	qcoefs [][]uint64,
	mod uint64,
) bool {
	if open == nil {
		return false
	}
	n := open.EntryCount()
	if n <= 0 {
		return false
	}
	if !materializeMvals(open, n) {
		return false
	}
	if open.FormatVersion != 1 {
		return materializeLegacyPvals(open, n)
	}
	if open.R <= 0 || len(C) == 0 || len(C[0]) < open.R {
		return false
	}
	omitCols, fullRank := pivotColumnsFullRank(C, open.R, mod)
	if !fullRank || len(omitCols) == 0 {
		return false
	}
	if !equalIntSlicesExact(omitCols, open.POmitCols) {
		return false
	}
	keepCols := complementCols(open.R, omitCols)
	if open.PColsEncoded <= 0 || open.PColsEncoded != len(keepCols) {
		return false
	}
	encodedRows, ok := materializeEncodedPvals(open, n, open.PColsEncoded)
	if !ok {
		return false
	}
	if len(C) != len(omitCols) {
		// The first compressed mode uses full-rank square systems only.
		return false
	}
	a := make([][]uint64, len(C))
	for i := range C {
		a[i] = make([]uint64, len(omitCols))
		for j, col := range omitCols {
			a[i][j] = C[i][col] % mod
		}
	}
	aInv, ok := invertMatrixMod(a, mod)
	if !ok {
		return false
	}
	fullRows := make([][]uint64, n)
	for t := 0; t < n; t++ {
		idx := open.IndexAt(t)
		if idx < 0 || idx >= len(points) {
			return false
		}
		rhs := make([]uint64, len(C))
		switch {
		case idx >= ncols && idx < maskEnd:
			maskPos := idx - ncols
			if maskPos < 0 || maskPos >= len(bar[0]) {
				return false
			}
			for k := 0; k < len(C); k++ {
				rhs[k] = bar[k][maskPos] % mod
			}
		case idx >= maskEnd:
			x := points[idx] % mod
			for k := 0; k < len(C); k++ {
				rhs[k] = evalPolyCoeffs(qcoefs[k], x, mod)
			}
		default:
			return false
		}
		for k := 0; k < len(C); k++ {
			known := uint64(0)
			for j, col := range keepCols {
				known = MulAddMod64(known, C[k][col], encodedRows[t][j], mod)
			}
			rhs[k] = subMod64(rhs[k], known, mod)
		}
		missing := mulMatVecMod(aInv, rhs, mod)
		row := make([]uint64, open.R)
		for j, col := range keepCols {
			row[col] = encodedRows[t][j] % mod
		}
		for j, col := range omitCols {
			row[col] = missing[j] % mod
		}
		fullRows[t] = row
	}
	open.Pvals = fullRows
	return true
}

func materializeLegacyPvals(open *decs.DECSOpening, entryCount int) bool {
	if open == nil || open.R <= 0 {
		return false
	}
	if len(open.Pvals) == entryCount {
		for i := 0; i < entryCount; i++ {
			if len(open.Pvals[i]) != open.R {
				return false
			}
		}
		return true
	}
	if len(open.PvalsBits) == 0 {
		return false
	}
	open.Pvals = make([][]uint64, entryCount)
	for i := 0; i < entryCount; i++ {
		row := make([]uint64, open.R)
		for j := 0; j < open.R; j++ {
			row[j] = decs.GetOpeningPval(open, i, j)
		}
		open.Pvals[i] = row
	}
	return true
}

func materializeEncodedPvals(open *decs.DECSOpening, entryCount, cols int) ([][]uint64, bool) {
	if open == nil || cols <= 0 {
		return nil, false
	}
	if len(open.Pvals) == entryCount {
		for i := 0; i < entryCount; i++ {
			if len(open.Pvals[i]) != cols {
				return nil, false
			}
		}
		return open.Pvals, true
	}
	if len(open.PvalsBits) == 0 {
		return nil, false
	}
	rows := make([][]uint64, entryCount)
	for i := 0; i < entryCount; i++ {
		row := make([]uint64, cols)
		for j := 0; j < cols; j++ {
			row[j] = decs.GetOpeningPval(open, i, j)
		}
		rows[i] = row
	}
	open.Pvals = rows
	return rows, true
}

func materializeMvals(open *decs.DECSOpening, entryCount int) bool {
	if open == nil || open.Eta < 0 {
		return false
	}
	if len(open.Mvals) == entryCount {
		for i := 0; i < entryCount; i++ {
			if len(open.Mvals[i]) != open.Eta {
				return false
			}
		}
		return true
	}
	if open.Eta == 0 {
		open.Mvals = make([][]uint64, entryCount)
		return true
	}
	if len(open.MvalsBits) == 0 {
		return false
	}
	open.Mvals = make([][]uint64, entryCount)
	for i := 0; i < entryCount; i++ {
		row := make([]uint64, open.Eta)
		for j := 0; j < open.Eta; j++ {
			row[j] = decs.GetOpeningMval(open, i, j)
		}
		open.Mvals[i] = row
	}
	return true
}

func equalIntSlicesExact(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func complementCols(total int, omit []int) []int {
	if total <= 0 {
		return nil
	}
	omitSet := make(map[int]struct{}, len(omit))
	for _, col := range omit {
		if col >= 0 && col < total {
			omitSet[col] = struct{}{}
		}
	}
	out := make([]int, 0, total-len(omitSet))
	for col := 0; col < total; col++ {
		if _, drop := omitSet[col]; drop {
			continue
		}
		out = append(out, col)
	}
	return out
}

func pivotColumnsFullRank(C [][]uint64, colCount int, mod uint64) ([]int, bool) {
	m := len(C)
	if m == 0 || colCount <= 0 {
		return nil, false
	}
	a := make([][]uint64, m)
	for i := 0; i < m; i++ {
		if len(C[i]) < colCount {
			return nil, false
		}
		a[i] = make([]uint64, colCount)
		for j := 0; j < colCount; j++ {
			a[i][j] = C[i][j] % mod
		}
	}
	pivots := make([]int, 0, m)
	row := 0
	for col := 0; col < colCount && row < m; col++ {
		pivot := -1
		for r := row; r < m; r++ {
			if a[r][col]%mod != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			continue
		}
		if pivot != row {
			a[row], a[pivot] = a[pivot], a[row]
		}
		invPivot := ring.ModExp(a[row][col]%mod, mod-2, mod)
		for cc := col; cc < colCount; cc++ {
			a[row][cc] = MulMod64(a[row][cc], invPivot, mod)
		}
		for rr := row + 1; rr < m; rr++ {
			f := a[rr][col] % mod
			if f == 0 {
				continue
			}
			for cc := col; cc < colCount; cc++ {
				term := MulMod64(f, a[row][cc], mod)
				a[rr][cc] = subMod64(a[rr][cc], term, mod)
			}
		}
		pivots = append(pivots, col)
		row++
	}
	return pivots, row == m
}

func invertMatrixMod(a [][]uint64, mod uint64) ([][]uint64, bool) {
	n := len(a)
	if n == 0 {
		return nil, false
	}
	aug := make([][]uint64, n)
	for i := 0; i < n; i++ {
		if len(a[i]) != n {
			return nil, false
		}
		aug[i] = make([]uint64, 2*n)
		for j := 0; j < n; j++ {
			aug[i][j] = a[i][j] % mod
		}
		aug[i][n+i] = 1
	}
	for col := 0; col < n; col++ {
		pivot := -1
		for r := col; r < n; r++ {
			if aug[r][col]%mod != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			return nil, false
		}
		if pivot != col {
			aug[col], aug[pivot] = aug[pivot], aug[col]
		}
		invPivot := ring.ModExp(aug[col][col]%mod, mod-2, mod)
		for j := 0; j < 2*n; j++ {
			aug[col][j] = MulMod64(aug[col][j], invPivot, mod)
		}
		for r := 0; r < n; r++ {
			if r == col {
				continue
			}
			f := aug[r][col] % mod
			if f == 0 {
				continue
			}
			for j := 0; j < 2*n; j++ {
				term := MulMod64(f, aug[col][j], mod)
				aug[r][j] = subMod64(aug[r][j], term, mod)
			}
		}
	}
	inv := make([][]uint64, n)
	for i := 0; i < n; i++ {
		inv[i] = make([]uint64, n)
		copy(inv[i], aug[i][n:])
	}
	return inv, true
}

func mulMatVecMod(a [][]uint64, x []uint64, mod uint64) []uint64 {
	out := make([]uint64, len(a))
	for i := range a {
		sum := uint64(0)
		for j := 0; j < len(a[i]) && j < len(x); j++ {
			sum = MulAddMod64(sum, a[i][j], x[j], mod)
		}
		out[i] = sum
	}
	return out
}

func subMod64(a, b, mod uint64) uint64 {
	if a >= mod {
		a %= mod
	}
	if b >= mod {
		b %= mod
	}
	if a >= b {
		return a - b
	}
	return a + mod - b
}

// equalSets checks multisets equality of int slices.
func equalSets(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[int]int, len(a))
	for _, x := range a {
		seen[x]++
	}
	for _, y := range b {
		if seen[y] == 0 {
			return false
		}
		seen[y]--
	}
	return true
}
