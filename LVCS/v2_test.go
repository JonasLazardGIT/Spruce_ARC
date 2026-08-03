package lvcs

import (
	"bytes"
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type lvcsV2Fixture struct {
	ringQ  *ring.Ring
	params decs.Params
	ctx    decs.CommitmentContext
	root   []byte
	pk     *ProverKey
	vrf    *VerifierState
	bar    [][]uint64
	tail   []int
	C      [][]uint64
	vhead  [][]uint64
	ncols  int
	ell    int
}

func newLVCSV2Fixture(t *testing.T, highDegree bool) lvcsV2Fixture {
	t.Helper()
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	q := ringQ.Modulus[0]
	ncols, ell := 3, 2
	points := make([]uint64, 16)
	for i := range points {
		points[i] = uint64(i + 1)
	}
	var rows []RowInput
	degree := ncols + ell - 1
	if highDegree {
		degree = 20
		// Add X^4*prod_{x in E}(X-x) to a degree-4 polynomial. This
		// exercises the formal degree-20 backend while preserving the same
		// evaluations on the complete authentication domain.
		base := []uint64{7, 10, 13, 16, 19}
		vanishing := []uint64{1}
		for _, point := range points {
			next := make([]uint64, len(vanishing)+1)
			for i, value := range vanishing {
				next[i] = (next[i] + q - (value*point)%q) % q
				next[i+1] = (next[i+1] + value) % q
			}
			vanishing = next
		}
		coeffs := make([]uint64, degree+1)
		copy(coeffs, base)
		for i, value := range vanishing {
			coeffs[i+4] = (coeffs[i+4] + value) % q
		}
		head := make([]uint64, ncols)
		for i := range head {
			head[i] = evalPolyCoeffs(coeffs, points[i], q)
		}
		rows = []RowInput{{Head: head, PolyCoeffs: coeffs}}
	} else {
		rows = []RowInput{
			{Head: []uint64{1, 2, 3}, Tail: []uint64{7, 8}},
			{Head: []uint64{4, 5, 6}, Tail: []uint64{9, 10}},
			{Head: []uint64{11, 12, 13}, Tail: []uint64{14, 15}},
		}
	}
	params := decs.Params{Degree: degree, Eta: 2, TapeBytes: 16, HashBytes: 21}
	ctx := decs.CommitmentContext{
		TranscriptVersion: decs.TranscriptVersionV2,
		Role:              decs.CommitmentRoleMain,
		Salt:              bytes.Repeat([]byte{0x42}, 32),
	}
	root, pk, err := CommitInitWithParamsAndPointsV2(ringQ, rows, ell, params, points, ctx, CommitOptions{})
	if err != nil {
		t.Fatalf("CommitInitWithParamsAndPointsV2: %v", err)
	}
	C := make([][]uint64, len(rows))
	for i := range C {
		C[i] = make([]uint64, len(rows))
		C[i][i] = 1
	}
	reqs := make([]EvalRequest, len(C))
	for i := range C {
		reqs[i] = EvalRequest{Coeffs: C[i]}
	}
	bar, err := EvalInitManyChecked(ringQ, pk, reqs)
	if err != nil {
		t.Fatalf("EvalInitManyChecked: %v", err)
	}
	vhead := make([][]uint64, len(C))
	for k := range C {
		vhead[k] = make([]uint64, ncols)
		for j, row := range pk.Rows {
			for col := 0; col < ncols; col++ {
				vhead[k][col] = MulAddMod64(vhead[k][col], C[k][j], row.Head[col], q)
			}
		}
	}
	vrf, err := NewVerifierWithParamsAndPointsV2(ringQ, len(rows), params, ncols, points, ctx)
	if err != nil {
		t.Fatalf("NewVerifierWithParamsAndPointsV2: %v", err)
	}
	vrf.RootHash = append([]byte(nil), root...)
	vrf.AcceptGamma(pk.Gamma)
	if !vrf.CommitStep2Formal(pk.DecsProver.CommitStep2Formal(pk.Gamma)) {
		t.Fatal("CommitStep2Formal rejected v2 R rows")
	}
	return lvcsV2Fixture{
		ringQ: ringQ, params: params, ctx: ctx, root: root,
		pk: pk, vrf: vrf, bar: bar,
		tail: []int{ncols + ell, ncols + ell + 1},
		C:    C, vhead: vhead, ncols: ncols, ell: ell,
	}
}

func (fx lvcsV2Fixture) combinedOpening(t *testing.T) *decs.DECSOpening {
	t.Helper()
	indices := []int{fx.ncols, fx.ncols + 1, fx.tail[0], fx.tail[1]}
	opening, err := EvalFinishV2(fx.pk, indices)
	if err != nil {
		t.Fatalf("EvalFinishV2: %v", err)
	}
	return opening.DECSOpen
}

func cloneLVCSV2Opening(open *decs.DECSOpening) *decs.DECSOpening {
	out := *open
	out.Indices = append([]int(nil), open.Indices...)
	out.Pvals = cloneLVCSV2UintRows(open.Pvals)
	out.Mvals = cloneLVCSV2UintRows(open.Mvals)
	out.Nodes = cloneLVCSV2ByteRows(open.Nodes)
	out.PathIndex = cloneLVCSV2IntRows(open.PathIndex)
	out.Tapes = cloneLVCSV2ByteRows(open.Tapes)
	return &out
}

func cloneLVCSV2UintRows(rows [][]uint64) [][]uint64 {
	out := make([][]uint64, len(rows))
	for i := range rows {
		out[i] = append([]uint64(nil), rows[i]...)
	}
	return out
}

func cloneLVCSV2IntRows(rows [][]int) [][]int {
	out := make([][]int, len(rows))
	for i := range rows {
		out[i] = append([]int(nil), rows[i]...)
	}
	return out
}

func cloneLVCSV2ByteRows(rows [][]byte) [][]byte {
	out := make([][]byte, len(rows))
	for i := range rows {
		out[i] = append([]byte(nil), rows[i]...)
	}
	return out
}

func TestLVCSV2LowAndHighDegreeFormalOpenings(t *testing.T) {
	for _, highDegree := range []bool{false, true} {
		name := "low-degree"
		if highDegree {
			name = "formal-high-degree"
		}
		t.Run(name, func(t *testing.T) {
			fx := newLVCSV2Fixture(t, highDegree)
			open := fx.combinedOpening(t)
			if open.Version != decs.OpeningVersionV2 || open.Role != fx.ctx.Role || len(open.Tapes) != open.EntryCount() {
				t.Fatalf("unexpected v2 opening schema: version=%d role=%q tapes=%d entries=%d", open.Version, open.Role, len(open.Tapes), open.EntryCount())
			}
			if !fx.vrf.EvalStep2(fx.bar, fx.tail, open, fx.C, fx.vhead) {
				t.Fatal("v2 LVCS opening rejected")
			}
		})
	}
}

func TestLVCSV2SplitPreservesTapeAlignmentAndContext(t *testing.T) {
	fx := newLVCSV2Fixture(t, false)
	open := fx.combinedOpening(t)
	tampered := cloneLVCSV2Opening(open)
	tampered.Tapes[len(tampered.Tapes)-1][0] ^= 1
	if fx.vrf.EvalStep2(fx.bar, fx.tail, tampered, fx.C, fx.vhead) {
		t.Fatal("LVCS accepted a changed v2 tape")
	}

	wrongContext := fx.ctx
	wrongContext.Salt = bytes.Repeat([]byte{0x43}, len(fx.ctx.Salt))
	wrongVerifier, err := NewVerifierWithParamsAndPointsV2(fx.ringQ, len(fx.pk.Rows), fx.params, fx.ncols, fx.pk.Points, wrongContext)
	if err != nil {
		t.Fatal(err)
	}
	wrongVerifier.RootHash = append([]byte(nil), fx.root...)
	wrongVerifier.AcceptGamma(fx.pk.Gamma)
	if !wrongVerifier.CommitStep2Formal(fx.pk.DecsProver.CommitStep2Formal(fx.pk.Gamma)) {
		t.Fatal("wrong-context verifier rejected formal rows before Merkle check")
	}
	if wrongVerifier.EvalStep2(fx.bar, fx.tail, cloneLVCSV2Opening(open), fx.C, fx.vhead) {
		t.Fatal("LVCS accepted a changed v2 salt")
	}

	truncated := newLVCSV2Fixture(t, false)
	truncated.vrf.RootHash = append([]byte(nil), truncated.root[:16]...)
	if truncated.vrf.EvalStep2(truncated.bar, truncated.tail, truncated.combinedOpening(t), truncated.C, truncated.vhead) {
		t.Fatal("LVCS accepted a truncated v2 root")
	}
}

func TestLVCSV2StrictOpeningMerge(t *testing.T) {
	fx := newLVCSV2Fixture(t, false)
	mask, err := EvalFinishV2(fx.pk, []int{fx.ncols, fx.ncols + 1})
	if err != nil {
		t.Fatal(err)
	}
	tail, err := EvalFinishV2(fx.pk, fx.tail)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeOpeningsV2(fx.ctx, mask, tail)
	if err != nil {
		t.Fatalf("MergeOpeningsV2: %v", err)
	}
	if !fx.vrf.EvalStep2(fx.bar, fx.tail, merged.DECSOpen, fx.C, fx.vhead) {
		t.Fatal("strictly merged v2 LVCS opening rejected")
	}
	conflict, err := EvalFinishV2(fx.pk, []int{fx.ncols + 1, fx.tail[0]})
	if err != nil {
		t.Fatal(err)
	}
	conflict.DECSOpen.Tapes[0][0] ^= 1
	if _, err := MergeOpeningsV2(fx.ctx, mask, conflict); err == nil {
		t.Fatal("LVCS merged conflicting tapes for the same leaf")
	}
}
