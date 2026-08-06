package kfield

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"testing"
	"testing/iotest"
)

const testQ = 1017857 // the maintained ~20-bit prover modulus

// refMul independently computes a*b in F_q[X]/(chi) via big.Int, as a check on
// the lazy small-field multiply.
func refMul(q uint64, chi, a, b []uint64) []uint64 {
	theta := len(chi) - 1
	Q := new(big.Int).SetUint64(q)
	res := make([]*big.Int, 2*theta-1)
	for i := range res {
		res[i] = new(big.Int)
	}
	for i := 0; i < theta; i++ {
		ai := new(big.Int).SetUint64(a[i] % q)
		for j := 0; j < theta; j++ {
			t := new(big.Int).Mul(ai, new(big.Int).SetUint64(b[j]%q))
			res[i+j].Add(res[i+j], t)
		}
	}
	// reduce modulo the monic chi: x^theta == -(sum_{j<theta} chi[j] x^j)
	for k := 2*theta - 2; k >= theta; k-- {
		c := new(big.Int).Mod(res[k], Q)
		if c.Sign() == 0 {
			continue
		}
		m := k - theta
		for j := 0; j < theta; j++ {
			t := new(big.Int).Mul(c, new(big.Int).SetUint64(chi[j]%q))
			res[m+j].Sub(res[m+j], t)
		}
		res[k].SetInt64(0)
	}
	out := make([]uint64, theta)
	for i := 0; i < theta; i++ {
		out[i] = new(big.Int).Mod(res[i], Q).Uint64()
	}
	return out
}

func randLimbs(rng *rand.Rand, theta int, q uint64) []uint64 {
	l := make([]uint64, theta)
	for i := range l {
		l[i] = rng.Uint64() % q
	}
	return l
}

func TestMulMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(20260713))
	for _, theta := range []int{2, 3, 5, 7, 16, 24} {
		chi, err := FindIrreducible(testQ, theta, rng)
		if err != nil {
			t.Fatalf("theta=%d FindIrreducible: %v", theta, err)
		}
		f, err := New(testQ, theta, chi)
		if err != nil {
			t.Fatalf("theta=%d New: %v", theta, err)
		}
		for iter := 0; iter < 200; iter++ {
			a := Elem{Limb: randLimbs(rng, theta, testQ)}
			b := Elem{Limb: randLimbs(rng, theta, testQ)}
			got := f.Mul(a, b)
			want := refMul(testQ, chi, a.Limb, b.Limb)
			for i := 0; i < theta; i++ {
				if got.Limb[i] != want[i] {
					t.Fatalf("theta=%d iter=%d limb %d: got %d want %d", theta, iter, i, got.Limb[i], want[i])
				}
			}
		}
	}
}

func TestNewUncheckedMatchesNew(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, theta := range []int{2, 7, 16} {
		chi, err := FindIrreducible(testQ, theta, rng)
		if err != nil {
			t.Fatalf("FindIrreducible: %v", err)
		}
		checked, err := New(testQ, theta, chi)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		unchecked, err := NewUnchecked(testQ, theta, chi)
		if err != nil {
			t.Fatalf("NewUnchecked: %v", err)
		}
		for iter := 0; iter < 100; iter++ {
			a := Elem{Limb: randLimbs(rng, theta, testQ)}
			b := Elem{Limb: randLimbs(rng, theta, testQ)}
			g1 := checked.Mul(a, b)
			g2 := unchecked.Mul(a, b)
			for i := 0; i < theta; i++ {
				if g1.Limb[i] != g2.Limb[i] {
					t.Fatalf("theta=%d checked/unchecked mismatch limb %d: %d vs %d", theta, i, g1.Limb[i], g2.Limb[i])
				}
			}
		}
	}
}

// TestInverseRoundTrip exercises Mul + Inv (a * a^-1 == 1).
func TestInverseRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for _, theta := range []int{2, 5, 16} {
		chi, err := FindIrreducible(testQ, theta, rng)
		if err != nil {
			t.Fatalf("FindIrreducible: %v", err)
		}
		f, err := New(testQ, theta, chi)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		one := f.One()
		for iter := 0; iter < 20; iter++ {
			a := Elem{Limb: randLimbs(rng, theta, testQ)}
			if f.IsZero(a) {
				continue
			}
			inv := f.Inv(a)
			prod := f.Mul(a, inv)
			for i := 0; i < theta; i++ {
				if prod.Limb[i] != one.Limb[i] {
					t.Fatalf("theta=%d a*a^-1 != 1 at limb %d: %d", theta, i, prod.Limb[i])
				}
			}
		}
	}
}

func TestMulNormalizesInputLimbs(t *testing.T) {
	rng := rand.New(rand.NewSource(1234))
	chi, err := FindIrreducible(testQ, 5, rng)
	if err != nil {
		t.Fatalf("FindIrreducible: %v", err)
	}
	f, err := New(testQ, 5, chi)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := Elem{Limb: []uint64{testQ + 1, 2*testQ + 3, 4, 5, 3*testQ + 6}}
	b := Elem{Limb: []uint64{2*testQ + 7, 8, testQ + 9, 10, 11}}
	got := f.Mul(a, b)
	want := refMul(testQ, chi, a.Limb, b.Limb)
	for i := range want {
		if got.Limb[i] != want[i] {
			t.Fatalf("limb %d: got %d want %d", i, got.Limb[i], want[i])
		}
	}
}

func TestMulUsesReducedFallbackOutsideLazyBound(t *testing.T) {
	for _, q := range []uint64{uint64(^uint32(0)), uint64(^uint32(0)) + 16} {
		chi := []uint64{1, 1, 1}
		f, err := NewUnchecked(q, 2, chi)
		if err != nil {
			t.Fatalf("q=%d NewUnchecked: %v", q, err)
		}
		if f.lazyMul {
			t.Fatalf("q=%d unexpectedly selected lazy multiplication", q)
		}
		a := Elem{Limb: []uint64{q - 1, q - 2}}
		b := Elem{Limb: []uint64{q - 3, q - 4}}
		got := f.Mul(a, b)
		want := refMul(q, chi, a.Limb, b.Limb)
		for i := range want {
			if got.Limb[i] != want[i] {
				t.Fatalf("q=%d limb=%d got=%d want=%d", q, i, got.Limb[i], want[i])
			}
		}
	}
}

func TestMulHeapScratchMatchesReference(t *testing.T) {
	const theta = stackMulDeg + 1
	chi := make([]uint64, theta+1)
	for i := 0; i < theta; i++ {
		chi[i] = uint64(i + 1)
	}
	chi[theta] = 1
	f, err := NewUnchecked(testQ, theta, chi)
	if err != nil {
		t.Fatalf("NewUnchecked: %v", err)
	}
	if !f.lazyMul {
		t.Fatal("maintained modulus unexpectedly disabled lazy multiplication")
	}
	rng := rand.New(rand.NewSource(5678))
	a := Elem{Limb: randLimbs(rng, theta, testQ)}
	b := Elem{Limb: randLimbs(rng, theta, testQ)}
	got := f.Mul(a, b)
	want := refMul(testQ, chi, a.Limb, b.Limb)
	for i := range want {
		if got.Limb[i] != want[i] {
			t.Fatalf("limb=%d got=%d want=%d", i, got.Limb[i], want[i])
		}
	}
}

func TestNewUncheckedTrustBoundary(t *testing.T) {
	reducible := []uint64{0, 0, 1}
	if _, err := New(testQ, 2, reducible); err == nil {
		t.Fatal("New accepted a reducible polynomial")
	}
	if _, err := NewUnchecked(testQ, 2, reducible); err != nil {
		t.Fatalf("NewUnchecked rejected structurally valid trusted input: %v", err)
	}
}

func TestRandomElementRejectsBiasedUint64Prefix(t *testing.T) {
	const q = uint64(10)
	f, err := NewUnchecked(q, 2, []uint64{1, 0, 1})
	if err != nil {
		t.Fatalf("NewUnchecked: %v", err)
	}

	// 2^64 mod 10 = 6. Values below 6 must be rejected; 27 and 8 are
	// the first accepted draws for the two limbs.
	var encoded bytes.Buffer
	for _, v := range []uint64{0, 5, 27, 8} {
		if err := binary.Write(&encoded, binary.LittleEndian, v); err != nil {
			t.Fatalf("encode draw: %v", err)
		}
	}
	got, err := f.RandomElement(&encoded)
	if err != nil {
		t.Fatalf("RandomElement: %v", err)
	}
	if len(got.Limb) != 2 || got.Limb[0] != 7 || got.Limb[1] != 8 {
		t.Fatalf("RandomElement limbs=%v want [7 8]", got.Limb)
	}
	if encoded.Len() != 0 {
		t.Fatalf("RandomElement left %d unread bytes", encoded.Len())
	}
}

func TestRandomElementPropagatesReaderErrorAfterRejection(t *testing.T) {
	const q = uint64(10)
	f, err := NewUnchecked(q, 1, []uint64{1, 1})
	if err != nil {
		t.Fatalf("NewUnchecked: %v", err)
	}

	var rejected [8]byte
	binary.LittleEndian.PutUint64(rejected[:], 5) // below 2^64 mod 10
	wantErr := errors.New("entropy unavailable")
	reader := io.MultiReader(bytes.NewReader(rejected[:]), iotest.ErrReader(wantErr))
	if _, err := f.RandomElement(reader); !errors.Is(err, wantErr) {
		t.Fatalf("RandomElement error=%v want wrapped %v", err, wantErr)
	}
}

func testUncheckedField(t *testing.T, theta int) *Field {
	t.Helper()
	chi := make([]uint64, theta+1)
	chi[0] = 1
	chi[theta] = 1
	f, err := NewUnchecked(testQ, theta, chi)
	if err != nil {
		t.Fatalf("NewUnchecked(theta=%d): %v", theta, err)
	}
	return f
}

func equalElemMod(f *Field, a, b Elem) bool {
	if len(a.Limb) != f.Theta || len(b.Limb) != f.Theta {
		return false
	}
	for i := 0; i < f.Theta; i++ {
		if a.Limb[i]%f.Q != b.Limb[i]%f.Q {
			return false
		}
	}
	return true
}

func TestIdentityAndBaseFieldIntoPrimitives(t *testing.T) {
	for _, theta := range []int{7, 13, 33} {
		t.Run(fmt.Sprintf("theta%d", theta), func(t *testing.T) {
			f := testUncheckedField(t, theta)
			srcCoords := make([]uint64, theta)
			for i := range srcCoords {
				srcCoords[i] = testQ*uint64(i+1) + uint64(3*i+2)
			}
			src := Elem{Limb: srcCoords}

			var zero, one, embedded, set, scaled Elem
			f.ZeroInto(&zero)
			f.OneInto(&one)
			f.EmbedFInto(&embedded, testQ+41)
			f.SetInto(&set, src)
			f.ScaleBaseInto(&scaled, src, testQ+17)
			if !equalElemMod(f, zero, f.Zero()) {
				t.Fatal("ZeroInto differs from Zero")
			}
			if !equalElemMod(f, one, f.One()) {
				t.Fatal("OneInto differs from One")
			}
			if !equalElemMod(f, embedded, f.EmbedF(testQ+41)) {
				t.Fatal("EmbedFInto differs from EmbedF")
			}
			if !equalElemMod(f, set, f.Normalize(src)) {
				t.Fatal("SetInto differs from Normalize")
			}
			wantScaled := f.Mul(f.EmbedF(17), f.Normalize(src))
			if !equalElemMod(f, scaled, wantScaled) {
				t.Fatal("ScaleBaseInto differs from embedded multiplication")
			}
			acc := f.Phi(srcCoords)
			gotSub := f.Normalize(acc)
			f.SubMulBaseInto(&gotSub, src, testQ+17)
			wantSub := f.Sub(acc, wantScaled)
			if !equalElemMod(f, gotSub, wantSub) {
				t.Fatal("SubMulBaseInto differs from embedded multiplication")
			}
		})
	}
}

func TestIntoPrimitivesAreSafeForOverlappingViews(t *testing.T) {
	f := testUncheckedField(t, 7)

	setBacking := []uint64{2, 3, 5, 7, 11, 13, 17, 19}
	setSrc := Elem{Limb: setBacking[:7]}
	wantSet := f.Normalize(setSrc)
	setDst := Elem{Limb: setBacking[1:8]}
	f.SetInto(&setDst, setSrc)
	if !equalElemMod(f, setDst, wantSet) {
		t.Fatalf("overlapping SetInto=%v want %v", setDst.Limb, wantSet.Limb)
	}

	scaleBacking := []uint64{23, 29, 31, 37, 41, 43, 47, 53}
	scaleSrc := Elem{Limb: scaleBacking[:7]}
	wantScale := f.Mul(f.EmbedF(59), f.Normalize(scaleSrc))
	scaleDst := Elem{Limb: scaleBacking[1:8]}
	f.ScaleBaseInto(&scaleDst, scaleSrc, 59)
	if !equalElemMod(f, scaleDst, wantScale) {
		t.Fatalf("overlapping ScaleBaseInto=%v want %v", scaleDst.Limb, wantScale.Limb)
	}
}

func TestEvalFPolyAtKIntoMatchesWrapperAndAliasesPoint(t *testing.T) {
	for _, theta := range []int{7, 13, 33} {
		t.Run(fmt.Sprintf("theta%d", theta), func(t *testing.T) {
			f := testUncheckedField(t, theta)
			coords := make([]uint64, theta)
			for i := range coords {
				coords[i] = uint64(2*i + 1)
			}
			coeff := []uint64{testQ + 3, 5, 7, testQ*2 + 11, 13}
			point := f.Phi(coords)
			want := f.EvalFPolyAtK(coeff, point)

			got := Elem{Limb: make([]uint64, theta)}
			f.EvalFPolyAtKInto(&got, coeff, point)
			if !equalElemMod(f, got, want) {
				t.Fatalf("EvalFPolyAtKInto=%v want %v", got.Limb, want.Limb)
			}

			aliased := f.Phi(coords)
			f.EvalFPolyAtKInto(&aliased, coeff, aliased)
			if !equalElemMod(f, aliased, want) {
				t.Fatalf("aliased EvalFPolyAtKInto=%v want %v", aliased.Limb, want.Limb)
			}

			backing := append(append([]uint64(nil), coords...), 0)
			overlapPoint := Elem{Limb: backing[:theta]}
			overlapDst := Elem{Limb: backing[1 : theta+1]}
			f.EvalFPolyAtKInto(&overlapDst, coeff, overlapPoint)
			if !equalElemMod(f, overlapDst, want) {
				t.Fatalf("overlapping EvalFPolyAtKInto=%v want %v", overlapDst.Limb, want.Limb)
			}
		})
	}
}

func TestMaintainedIntoPrimitivesDoNotAllocate(t *testing.T) {
	for _, theta := range []int{7, 13} {
		t.Run(fmt.Sprintf("theta%d", theta), func(t *testing.T) {
			f := testUncheckedField(t, theta)
			src := Elem{Limb: make([]uint64, theta)}
			dst := Elem{Limb: make([]uint64, theta)}
			for i := range src.Limb {
				src.Limb[i] = uint64(i + 1)
			}
			coeff := []uint64{3, 5, 7, 11, 13}
			allocs := testing.AllocsPerRun(1000, func() {
				f.ZeroInto(&dst)
				f.OneInto(&dst)
				f.SetInto(&dst, src)
				f.EmbedFInto(&dst, 17)
				f.ScaleBaseInto(&dst, src, 19)
				f.EvalFPolyAtKInto(&dst, coeff, src)
			})
			if allocs != 0 {
				t.Fatalf("Into primitives allocate %.2f objects/run", allocs)
			}
		})
	}
}

func BenchmarkMul(b *testing.B) {
	for _, theta := range []int{7, 16} {
		b.Run(fmt.Sprintf("theta%d", theta), func(b *testing.B) {
			rng := rand.New(rand.NewSource(int64(theta)))
			chi, err := FindIrreducible(testQ, theta, rng)
			if err != nil {
				b.Fatalf("FindIrreducible: %v", err)
			}
			field, err := New(testQ, theta, chi)
			if err != nil {
				b.Fatalf("New: %v", err)
			}
			a := Elem{Limb: randLimbs(rng, theta, testQ)}
			c := Elem{Limb: randLimbs(rng, theta, testQ)}
			out := field.Zero()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				field.MulInto(&out, a, c)
			}
		})
	}
}
