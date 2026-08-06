package PIOP

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/credential"
	kf "vSIS-Signature/internal/kfield"
)

func piopTestRepoRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func chdirForPIOPTest(tb testing.TB, dir string) {
	tb.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		tb.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		tb.Fatalf("chdir %s: %v", dir, err)
	}
	tb.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
}

func TestBuildSmallFieldWitnessRowsFromLiteralInputsPreservesOmegaHeads(t *testing.T) {
	chdirForPIOPTest(t, piopTestRepoRoot(t))
	ringQ, err := credential.LoadRingWithDegree(0)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	omegaWitness := make([]uint64, 8)
	for i := range omegaWitness {
		omegaWitness[i] = uint64(i + 2)
	}
	sf, err := deriveSmallFieldParamsNoRows(ringQ, omegaWitness, 3)
	if err != nil {
		t.Fatalf("small field params: %v", err)
	}
	q := ringQ.Modulus[0]
	logical := make([]lvcs.RowInput, 19)
	for row := range logical {
		head := make([]uint64, len(omegaWitness))
		for j := range head {
			head[j] = uint64((row*31 + j*17 + 9) % int(q))
		}
		pNTT := BuildThetaPrime(ringQ, head, omegaWitness)
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(pNTT, coeff)
		logical[row] = lvcs.RowInput{
			Head:       head,
			PolyCoeffs: trimCoeffsCopy(coeff.Coeffs[0], q),
		}
	}
	pcsNCols := 16
	accepted := q
	randomBytes := make([]byte, len(logical)*sf.K.Theta*8)
	for off := 0; off < len(randomBytes); off += 8 {
		binary.LittleEndian.PutUint64(randomBytes[off:], accepted)
	}
	random := bytes.NewReader(randomBytes)
	rows, err := buildSmallFieldWitnessRowsFromLiteralInputsRandomizedWithReader(ringQ, omegaWitness, pcsNCols, sf.K, sf.OmegaS1, logical, random)
	if err != nil {
		t.Fatalf("literal small-field rows: %v", err)
	}
	layerSize := len(omegaWitness) + sf.K.Theta
	wantRows := ceilDiv(len(logical), pcsNCols) * layerSize
	if len(rows) != wantRows {
		t.Fatalf("rows=%d want %d", len(rows), wantRows)
	}
	for block := 0; block < ceilDiv(len(logical), pcsNCols); block++ {
		base := block * layerSize
		for j := range omegaWitness {
			for col := 0; col < pcsNCols; col++ {
				idx := block*pcsNCols + col
				want := uint64(0)
				if idx < len(logical) {
					want = logical[idx].Head[j] % q
				}
				if rows[base+j][col] != want {
					t.Fatalf("block=%d omega=%d col=%d got=%d want=%d", block, j, col, rows[base+j][col], want)
				}
			}
		}
		for col := 0; col < pcsNCols; col++ {
			idx := block*pcsNCols + col
			if idx >= len(logical) {
				continue
			}
			for coord := 0; coord < sf.K.Theta; coord++ {
				got := rows[base+len(omegaWitness)+coord][col]
				if got != 0 {
					t.Fatalf("omegaS1 randomized limb row=%d coord=%d got=%d want=0", idx, coord, got)
				}
			}
		}
	}
}

func exactWitnessRhoStreamV3(K *kf.Field, count, offset int) ([]byte, []kf.Elem) {
	stream := make([]byte, 0, count*K.Theta*8)
	values := make([]kf.Elem, count)
	for sample := 0; sample < count; sample++ {
		values[sample] = K.Zero()
		for coord := 0; coord < K.Theta; coord++ {
			residue := uint64(offset + 1 + sample*K.Theta + coord)
			values[sample].Limb[coord] = residue
			var word [8]byte
			binary.LittleEndian.PutUint64(word[:], K.Q*uint64(offset+sample*K.Theta+coord+1)+residue)
			stream = append(stream, word[:]...)
		}
	}
	return stream, values
}

func TestSmallFieldWitnessV3FreshRhoPreservesOmegaAndSetsExtraPoint(t *testing.T) {
	chdirForPIOPTest(t, piopTestRepoRoot(t))
	ringQ, err := credential.LoadRingWithDegree(1024)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := kf.LookupSmallWoodFieldProfileV3(ringQ.Modulus[0], 7)
	if !ok {
		t.Fatal("missing theta-7 v3 field profile")
	}
	omega := []uint64{2, 3, 5, 7, 11, 13, 17, 19}
	K, extra, err := profile.Validate(omega)
	if err != nil {
		t.Fatal(err)
	}
	const logicalCount, ncols = 3, 8
	logical := make([]lvcs.RowInput, logicalCount)
	for row := range logical {
		logical[row].Head = make([]uint64, len(omega))
		for j := range omega {
			logical[row].Head[j] = uint64(100*row + 7*j + 3)
		}
	}
	streamA, rhoA := exactWitnessRhoStreamV3(K, logicalCount, 0)
	streamB, rhoB := exactWitnessRhoStreamV3(K, logicalCount, 1000)
	rowsA, err := buildSmallFieldWitnessRowsFromLiteralInputsRandomizedWithReader(
		ringQ, omega, ncols, K, extra, logical, bytes.NewReader(streamA),
	)
	if err != nil {
		t.Fatal(err)
	}
	rowsB, err := buildSmallFieldWitnessRowsFromLiteralInputsRandomizedWithReader(
		ringQ, omega, ncols, K, extra, logical, bytes.NewReader(streamB),
	)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(rowsA, rowsB) {
		t.Fatal("same logical witness produced identical v3 committed-row matrix under fresh rho")
	}
	for j := range omega {
		for logicalRow := range logical {
			if got, want := rowsA[j][logicalRow], logical[logicalRow].Head[j]; got != want {
				t.Fatalf("rho changed Omega head row=%d point=%d: got=%d want=%d", logicalRow, j, got, want)
			}
			if got, want := rowsB[j][logicalRow], logical[logicalRow].Head[j]; got != want {
				t.Fatalf("second rho changed Omega head row=%d point=%d: got=%d want=%d", logicalRow, j, got, want)
			}
		}
	}
	for logicalRow := range logical {
		if elemEqual(K, rhoA[logicalRow], rhoB[logicalRow]) {
			t.Fatalf("logical row %d reused rho", logicalRow)
		}
		for coord := 0; coord < K.Theta; coord++ {
			if got, want := rowsA[len(omega)+coord][logicalRow], rhoA[logicalRow].Limb[coord]; got != want {
				t.Fatalf("split rhoA row=%d coord=%d got=%d want=%d", logicalRow, coord, got, want)
			}
			if got, want := rowsB[len(omega)+coord][logicalRow], rhoB[logicalRow].Limb[coord]; got != want {
				t.Fatalf("split rhoB row=%d coord=%d got=%d want=%d", logicalRow, coord, got, want)
			}
		}
	}

	muInv, err := smallFieldMuDenomInv(K, omega, extra)
	if err != nil {
		t.Fatal(err)
	}
	checkPoint := func(point kf.Elem, expected []kf.Elem) {
		coeffs := buildKPointCoeffMatrix(
			ringQ, K, omega, rowsA, point, extra, muInv, len(rowsA), len(rowsA), 0,
		)
		got := computeVTargets(K.Q, rowsA, coeffs)
		for logicalRow := range logical {
			coords := make([]uint64, K.Theta)
			for coord := range coords {
				coords[coord] = got[coord][logicalRow]
			}
			if value := K.Phi(coords); !elemEqual(K, value, expected[logicalRow]) {
				t.Fatalf("interpolant row=%d at %v got=%v want=%v", logicalRow, point.Limb, value.Limb, expected[logicalRow].Limb)
			}
		}
	}
	for j, point := range omega {
		expected := make([]kf.Elem, logicalCount)
		for logicalRow := range logical {
			expected[logicalRow] = K.EmbedF(logical[logicalRow].Head[j])
		}
		checkPoint(K.EmbedF(point), expected)
	}
	checkPoint(extra, rhoA)

	// Exercise the real DECS commitment boundary as well as the row matrix:
	// committing the same Ω witness under fresh extension values must not reuse
	// a root. Independent DECS tapes add further hiding, but the row payloads
	// already differ in the split rho tail and are both committed here.
	const ell, nLeaves = 2, 64
	_, domainPoints, err := deriveExplicitDomain(K.Q, nLeaves, ncols, ell)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := mainCommitmentContextForTranscript(bytes.Repeat([]byte{0x5a}, 32), TranscriptVersionSmallWood2025V3)
	if err != nil {
		t.Fatal(err)
	}
	commit := func(matrix [][]uint64) []byte {
		t.Helper()
		rows := make([]lvcs.RowInput, len(matrix))
		for i := range matrix {
			rows[i] = lvcs.RowInput{Head: append([]uint64(nil), matrix[i]...)}
		}
		params := decs.Params{
			Degree:    rowOracleDegreeFloor(ringQ, rows, ell),
			Eta:       2,
			TapeBytes: 16,
			HashBytes: 33,
		}
		root, pk, _, err := commitRows(ringQ, rows, ell, params, len(rows), len(rows), 0, domainPoints, ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		pk.DecsProver.ReleaseTapes()
		return root
	}
	if rootA, rootB := commit(rowsA), commit(rowsB); bytes.Equal(rootA, rootB) {
		t.Fatal("same Ω witness with fresh rho produced identical DECS roots")
	}
}
