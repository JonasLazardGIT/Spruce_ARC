package lvcs

import (
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type smallField2025Fixture struct {
	vrf      *VerifierState
	bar      [][]uint64
	vhead    [][]uint64
	C        [][]uint64
	tail     []int
	openFull *decs.DECSOpening
	openTail *decs.DECSOpening
	meta     SmallField2025EvalMetadata
}

func TestEvalStep2SmallField2025AcceptsReducedOpening(t *testing.T) {
	fx := newSmallField2025Fixture(t)
	if !fx.vrf.EvalStep2(fx.bar, fx.tail, cloneOpeningForSmallFieldTest(fx.openFull), fx.C, fx.vhead) {
		t.Fatalf("dense EvalStep2 rejected fixture")
	}
	open := omitAllMColumnsForSmallFieldTest(omitPColumnsForSmallFieldTest(fx.openTail, fx.meta.POmitCols), false)
	meta := fx.meta
	meta.POmitCols = nil
	meta.MOmitCols = nil
	if !fx.vrf.EvalStep2SmallField2025(SmallField2025EvalInput{
		VHead:    fx.vhead,
		VBar:     fx.bar,
		Tail:     fx.tail,
		Opening:  open,
		C:        fx.C,
		Metadata: meta,
	}) {
		t.Fatalf("EvalStep2SmallField2025 rejected reduced opening")
	}
}

func TestEvalStep2SmallField2025RejectsSerializedMaskOpening(t *testing.T) {
	fx := newSmallField2025Fixture(t)
	open := omitAllMColumnsForSmallFieldTest(omitPColumnsForSmallFieldTest(fx.openFull, fx.meta.POmitCols), false)
	if fx.vrf.EvalStep2SmallField2025(SmallField2025EvalInput{
		VHead:    fx.vhead,
		VBar:     fx.bar,
		Tail:     fx.tail,
		Opening:  open,
		C:        fx.C,
		Metadata: fx.meta,
	}) {
		t.Fatalf("EvalStep2SmallField2025 accepted an opening with serialized mask rows")
	}
}

func TestEvalStep2SmallField2025RejectsWrongTailEntryCount(t *testing.T) {
	fx := newSmallField2025Fixture(t)
	short := cloneOpeningForSmallFieldTest(fx.openTail)
	short.Indices = short.Indices[:1]
	short.Pvals = short.Pvals[:1]
	short.Mvals = short.Mvals[:1]
	short.PathIndex = short.PathIndex[:1]
	open := omitAllMColumnsForSmallFieldTest(omitPColumnsForSmallFieldTest(short, fx.meta.POmitCols), false)
	if fx.vrf.EvalStep2SmallField2025(SmallField2025EvalInput{
		VHead:    fx.vhead,
		VBar:     fx.bar,
		Tail:     fx.tail,
		Opening:  open,
		C:        fx.C,
		Metadata: fx.meta,
	}) {
		t.Fatalf("EvalStep2SmallField2025 accepted wrong tail entry count")
	}
}

func TestEvalStep2SmallField2025RejectsSingularOmittedColumns(t *testing.T) {
	fx := newSmallField2025Fixture(t)
	open := omitAllMColumnsForSmallFieldTest(omitPColumnsForSmallFieldTest(fx.openTail, fx.meta.POmitCols), false)
	badC := [][]uint64{
		{1, 0, 0, 0, 5, 7},
		{2, 0, 0, 0, 3, 4},
		{0, 0, 1, 0, 0, 0},
		{0, 0, 0, 1, 0, 0},
	}
	if fx.vrf.EvalStep2SmallField2025(SmallField2025EvalInput{
		VHead:    fx.vhead,
		VBar:     fx.bar,
		Tail:     fx.tail,
		Opening:  open,
		C:        badC,
		Metadata: fx.meta,
	}) {
		t.Fatalf("EvalStep2SmallField2025 accepted singular omitted submatrix")
	}
}

func TestEvalStep2SmallField2025RejectsWrongOmitMetadata(t *testing.T) {
	fx := newSmallField2025Fixture(t)
	open := omitAllMColumnsForSmallFieldTest(omitPColumnsForSmallFieldTest(fx.openTail, []int{0, 1, 2, 4}), false)
	meta := fx.meta
	meta.POmitCols = []int{0, 1, 2, 4}
	if fx.vrf.EvalStep2SmallField2025(SmallField2025EvalInput{
		VHead:    fx.vhead,
		VBar:     fx.bar,
		Tail:     fx.tail,
		Opening:  open,
		C:        fx.C,
		Metadata: meta,
	}) {
		t.Fatalf("EvalStep2SmallField2025 accepted non-pivot omitted columns")
	}
}

func TestEvalStep2SmallField2025RejectsTamperedTargets(t *testing.T) {
	fx := newSmallField2025Fixture(t)
	open := omitAllMColumnsForSmallFieldTest(omitPColumnsForSmallFieldTest(fx.openTail, fx.meta.POmitCols), false)
	vhead := cloneMatrixForSmallFieldTest(fx.vhead)
	vhead[0][0] ^= 1
	if fx.vrf.EvalStep2SmallField2025(SmallField2025EvalInput{
		VHead:    vhead,
		VBar:     fx.bar,
		Tail:     fx.tail,
		Opening:  cloneOpeningForSmallFieldTest(open),
		C:        fx.C,
		Metadata: fx.meta,
	}) {
		t.Fatalf("EvalStep2SmallField2025 accepted tampered VHead")
	}
	bar := cloneMatrixForSmallFieldTest(fx.bar)
	bar[0][0] ^= 1
	if fx.vrf.EvalStep2SmallField2025(SmallField2025EvalInput{
		VHead:    fx.vhead,
		VBar:     bar,
		Tail:     fx.tail,
		Opening:  cloneOpeningForSmallFieldTest(open),
		C:        fx.C,
		Metadata: fx.meta,
	}) {
		t.Fatalf("EvalStep2SmallField2025 accepted tampered VBar")
	}
}

func TestEvalStep2SmallField2025RejectsMetadataMismatch(t *testing.T) {
	fx := newSmallField2025Fixture(t)
	open := omitAllMColumnsForSmallFieldTest(omitPColumnsForSmallFieldTest(fx.openTail, fx.meta.POmitCols), false)
	meta := fx.meta
	meta.QueryCount++
	if fx.vrf.EvalStep2SmallField2025(SmallField2025EvalInput{
		VHead:    fx.vhead,
		VBar:     fx.bar,
		Tail:     fx.tail,
		Opening:  open,
		C:        fx.C,
		Metadata: meta,
	}) {
		t.Fatalf("EvalStep2SmallField2025 accepted metadata query-count mismatch")
	}
}

func newSmallField2025Fixture(t *testing.T) smallField2025Fixture {
	t.Helper()
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	q := ringQ.Modulus[0]
	ncols := 3
	ell := 2
	rows := []RowInput{
		{Head: []uint64{1, 2, 3}, Tail: []uint64{7, 8}},
		{Head: []uint64{4, 5, 6}, Tail: []uint64{9, 10}},
		{Head: []uint64{11, 12, 13}, Tail: []uint64{14, 15}},
		{Head: []uint64{16, 17, 18}, Tail: []uint64{19, 20}},
		{Head: []uint64{21, 22, 23}, Tail: []uint64{24, 25}},
		{Head: []uint64{26, 27, 28}, Tail: []uint64{29, 30}},
	}
	points := make([]uint64, 16)
	for i := range points {
		points[i] = uint64(i + 1)
	}
	params := decs.Params{Degree: ncols + ell - 1, Eta: 2, NonceBytes: 16}
	root, pk, err := CommitInitWithParamsAndPoints(ringQ, rows, ell, params, points)
	if err != nil {
		t.Fatalf("CommitInitWithParamsAndPoints: %v", err)
	}
	C := [][]uint64{
		{1, 0, 0, 0, 5, 7},
		{0, 1, 0, 0, 3, 4},
		{0, 0, 1, 0, 0, 0},
		{0, 0, 0, 1, 0, 0},
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
		for j, row := range rows {
			for c := 0; c < ncols; c++ {
				vhead[k][c] = MulAddMod64(vhead[k][c], C[k][j], row.Head[c], q)
			}
		}
	}
	tail := []int{ncols + ell, ncols + ell + 1}
	openIdx := []int{ncols, ncols + 1, tail[0], tail[1]}
	open := EvalFinish(pk, openIdx).DECSOpen
	openTail := EvalFinish(pk, tail).DECSOpen
	vrf := NewVerifierWithParamsAndPoints(ringQ, len(rows), params, ncols, points)
	vrf.Root = root
	vrf.AcceptGamma(pk.Gamma)
	rFormal := pk.DecsProver.CommitStep2Formal(pk.Gamma)
	if !vrf.CommitStep2Formal(rFormal) {
		t.Fatalf("CommitStep2Formal rejected R")
	}
	meta := SmallField2025EvalMetadata{
		Version:          1,
		Mode:             SmallField2025ModeV1,
		HeadDomainMode:   SmallField2025HeadDomainV1,
		ReductionEnabled: true,
		NRows:            len(rows),
		NCols:            ncols,
		Theta:            2,
		WitnessLayers:    1,
		MaskRows:         ell,
		QueryCount:       len(C),
		VHeadRows:        len(vhead),
		VHeadCols:        ncols,
		VBarRows:         len(bar),
		VBarCols:         ell,
		POmitCols:        []int{0, 1, 2, 3},
	}
	return smallField2025Fixture{
		vrf:      vrf,
		bar:      bar,
		vhead:    vhead,
		C:        C,
		tail:     tail,
		openFull: open,
		openTail: openTail,
		meta:     meta,
	}
}

func omitPColumnsForSmallFieldTest(open *decs.DECSOpening, omit []int) *decs.DECSOpening {
	out := cloneOpeningForSmallFieldTest(open)
	omitSet := make(map[int]struct{}, len(omit))
	for _, col := range omit {
		omitSet[col] = struct{}{}
	}
	keep := make([]int, 0, out.R-len(omitSet))
	for col := 0; col < out.R; col++ {
		if _, drop := omitSet[col]; !drop {
			keep = append(keep, col)
		}
	}
	for i := range out.Pvals {
		row := make([]uint64, len(keep))
		for j, col := range keep {
			row[j] = out.Pvals[i][col]
		}
		out.Pvals[i] = row
	}
	out.FormatVersion = decs.OpeningFormatOmitCols
	out.POmitCols = append([]int(nil), omit...)
	out.PColsEncoded = len(keep)
	return out
}

func omitAllMColumnsForSmallFieldTest(open *decs.DECSOpening, includeList bool) *decs.DECSOpening {
	out := cloneOpeningForSmallFieldTest(open)
	eta := out.Eta
	if eta <= 0 && len(out.Mvals) > 0 {
		eta = len(out.Mvals[0])
	}
	out.Eta = eta
	out.MFormatVersion = decs.OpeningFormatOmitCols
	out.MColsEncoded = 0
	out.Mvals = nil
	out.MvalsBits = nil
	out.MvalsBitWidth = 0
	out.MvalsColumnWidths = nil
	out.MOmitCols = nil
	if includeList {
		out.MOmitCols = make([]int, eta)
		for i := range out.MOmitCols {
			out.MOmitCols[i] = i
		}
	}
	return out
}

func cloneOpeningForSmallFieldTest(open *decs.DECSOpening) *decs.DECSOpening {
	if open == nil {
		return nil
	}
	out := *open
	out.Indices = append([]int(nil), open.Indices...)
	out.IndexBits = append([]byte(nil), open.IndexBits...)
	out.Pvals = cloneMatrixForSmallFieldTest(open.Pvals)
	out.Mvals = cloneMatrixForSmallFieldTest(open.Mvals)
	out.PvalsBits = append([]byte(nil), open.PvalsBits...)
	out.MvalsBits = append([]byte(nil), open.MvalsBits...)
	out.PvalsColumnWidths = append([]uint8(nil), open.PvalsColumnWidths...)
	out.MvalsColumnWidths = append([]uint8(nil), open.MvalsColumnWidths...)
	out.POmitCols = append([]int(nil), open.POmitCols...)
	out.MOmitCols = append([]int(nil), open.MOmitCols...)
	out.Nodes = cloneBytesMatrixForSmallFieldTest(open.Nodes)
	out.PathIndex = cloneIntMatrixForSmallFieldTest(open.PathIndex)
	out.PathBits = append([]byte(nil), open.PathBits...)
	out.FrontierRefsBits = append([]byte(nil), open.FrontierRefsBits...)
	out.Nonces = cloneBytesMatrixForSmallFieldTest(open.Nonces)
	out.NonceSeed = append([]byte(nil), open.NonceSeed...)
	out.FrontierNodes = cloneBytesMatrixForSmallFieldTest(open.FrontierNodes)
	out.FrontierProof = append([]byte(nil), open.FrontierProof...)
	out.FrontierLR = append([]byte(nil), open.FrontierLR...)
	return &out
}

func cloneMatrixForSmallFieldTest(mat [][]uint64) [][]uint64 {
	if mat == nil {
		return nil
	}
	out := make([][]uint64, len(mat))
	for i := range mat {
		out[i] = append([]uint64(nil), mat[i]...)
	}
	return out
}

func cloneIntMatrixForSmallFieldTest(mat [][]int) [][]int {
	if mat == nil {
		return nil
	}
	out := make([][]int, len(mat))
	for i := range mat {
		out[i] = append([]int(nil), mat[i]...)
	}
	return out
}

func cloneBytesMatrixForSmallFieldTest(mat [][]byte) [][]byte {
	if mat == nil {
		return nil
	}
	out := make([][]byte, len(mat))
	for i := range mat {
		out[i] = append([]byte(nil), mat[i]...)
	}
	return out
}
