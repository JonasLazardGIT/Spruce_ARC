package PIOP

import (
	"bytes"
	"math"
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestParseROQueryCapsValidAndInvalid(t *testing.T) {
	got, err := ParseROQueryCaps("0,1,2,3,4")
	if err != nil {
		t.Fatalf("ParseROQueryCaps valid input: %v", err)
	}
	if got != [5]int{0, 1, 2, 3, 4} {
		t.Fatalf("caps=%v", got)
	}

	for _, s := range []string{
		"",
		"1,2,3,4",
		"1,2,3,4,5,6",
		"1,,3,4,5",
		"1,2,-3,4,5",
		"1,2,x,4,5",
	} {
		t.Run(s, func(t *testing.T) {
			if _, err := ParseROQueryCaps(s); err == nil {
				t.Fatalf("ParseROQueryCaps(%q) unexpectedly succeeded", s)
			}
		})
	}
}

func TestDECSCollisionWidthValidationSupportsIntermediateBytes(t *testing.T) {
	if decs.DefaultHashBytes != 18 {
		t.Fatalf("DefaultHashBytes=%d want 18", decs.DefaultHashBytes)
	}
	if got := ResolveDECSCollisionBits(0); got != 144 {
		t.Fatalf("ResolveDECSCollisionBits(0)=%d want 144", got)
	}
	for _, bits := range []int{128, 136, 144, 160, 192, 224, 256} {
		if err := ValidateDECSCollisionBits(bits); err != nil {
			t.Fatalf("ValidateDECSCollisionBits(%d): %v", bits, err)
		}
		if got := ResolveDECSCollisionBits(bits); got != bits {
			t.Fatalf("ResolveDECSCollisionBits(%d)=%d", bits, got)
		}
	}
	for _, bytes := range []int{16, 17, 18, 20, 24, 28, 32} {
		if err := ValidateDECSCollisionBytes(bytes); err != nil {
			t.Fatalf("ValidateDECSCollisionBytes(%d): %v", bytes, err)
		}
	}
	for _, bits := range []int{120, 152, 200, 248} {
		if err := ValidateDECSCollisionBits(bits); err == nil {
			t.Fatalf("ValidateDECSCollisionBits(%d) unexpectedly succeeded", bits)
		}
	}
	for _, bytes := range []int{15, 19, 25, 31} {
		if err := ValidateDECSCollisionBytes(bytes); err == nil {
			t.Fatalf("ValidateDECSCollisionBytes(%d) unexpectedly succeeded", bytes)
		}
	}
}

func TestSoundnessBudgetSeparatesAlgebraicCollisionAndOneProof(t *testing.T) {
	opts := soundnessTestOpts([5]int{1, 1, 1, 1, 1})
	base := computeSoundnessBudget(opts, 12289, 12289, 512, 128, 128, 32, 16, 16, 1, 1, 64, 64, 16)

	if base.AlgebraicTerms != base.TheoremTerms {
		t.Fatalf("algebraic terms=%v theorem terms=%v", base.AlgebraicTerms, base.TheoremTerms)
	}
	if base.AlgebraicBits != base.TheoremBits {
		t.Fatalf("algebraic bits=%v theorem bits=%v", base.AlgebraicBits, base.TheoremBits)
	}
	wantAlgTotal := 0.0
	for _, term := range base.AlgebraicTerms {
		wantAlgTotal += term
	}
	if !closeFloat(base.AlgebraicTotal, wantAlgTotal, 1e-18) {
		t.Fatalf("algebraic total=%g want %g", base.AlgebraicTotal, wantAlgTotal)
	}
	if !closeFloat(base.OneProofTotal, base.AlgebraicTotal+base.Collision, 1e-18) {
		t.Fatalf("one proof=%g algebraic+collision=%g", base.OneProofTotal, base.AlgebraicTotal+base.Collision)
	}
	if base.CollisionSpaceBits != 128 || base.DECSHashBits != 128 || base.DECSTapeBits != 128 {
		t.Fatalf("collision widths: space=%d hash=%d tape=%d", base.CollisionSpaceBits, base.DECSHashBits, base.DECSTapeBits)
	}

	wide := computeSoundnessBudget(soundnessTestOpts([5]int{1024, 1024, 1024, 1024, 1024}), 12289, 12289, 512, 128, 128, 32, 16, 16, 1, 1, 64, 64, 16)
	if got := base.AlgebraicTotalBits - wide.AlgebraicTotalBits; math.Abs(got-10) > 0.01 {
		t.Fatalf("algebraic bits drop=%f want about 10", got)
	}
	if got := base.CollisionBits - wide.CollisionBits; math.Abs(got-20) > 0.01 {
		t.Fatalf("collision bits drop=%f want about 20", got)
	}
	if wide.OneProofTotalBits >= base.OneProofTotalBits {
		t.Fatalf("one-proof bits did not decrease: base=%f wide=%f", base.OneProofTotalBits, wide.OneProofTotalBits)
	}
}

func TestComposeFullGameSoundness(t *testing.T) {
	issuance := SoundnessBudget{
		QueryCaps:          [5]int{1, 2, 3, 4, 5},
		CollisionSpaceBits: 128,
		AlgebraicTotal:     0.001,
		OneProofTotal:      0.002,
	}
	showing := SoundnessBudget{
		QueryCaps:          [5]int{5, 4, 3, 2, 1},
		CollisionSpaceBits: 96,
		AlgebraicTotal:     0.003,
		OneProofTotal:      0.004,
	}
	got := ComposeFullGameSoundness(issuance, showing, 2, 3)

	wantCaps := [5]int{17, 16, 15, 14, 13}
	if got.GlobalQueryCaps != wantCaps {
		t.Fatalf("global query caps=%v want %v", got.GlobalQueryCaps, wantCaps)
	}
	if got.CollisionSpaceBits != 96 {
		t.Fatalf("collision space bits=%d want 96", got.CollisionSpaceBits)
	}
	wantConservative := 2*issuance.OneProofTotal + 3*showing.OneProofTotal
	if !closeFloat(got.ConservativeFullGameError, wantConservative, 1e-18) {
		t.Fatalf("conservative=%g want %g", got.ConservativeFullGameError, wantConservative)
	}
	wantGlobalCollision := collisionError(wantCaps, 96)
	wantGlobal := wantGlobalCollision + 2*issuance.AlgebraicTotal + 3*showing.AlgebraicTotal
	if !closeFloat(got.GlobalCollisionError, wantGlobalCollision, 1e-18) {
		t.Fatalf("global collision=%g want %g", got.GlobalCollisionError, wantGlobalCollision)
	}
	if !closeFloat(got.GlobalCollisionFullGameError, wantGlobal, 1e-18) {
		t.Fatalf("global full game=%g want %g", got.GlobalCollisionFullGameError, wantGlobal)
	}
}

func TestBuildProofReportDetectsDECSCollisionWidths(t *testing.T) {
	ringQ, err := ring.NewRing(1024, []uint64{12289})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	opts := soundnessTestOpts([5]int{1, 1, 1, 1, 1})

	rep128, err := BuildProofReport(soundnessWidthProof(16), opts, ringQ)
	if err != nil {
		t.Fatalf("128-bit proof report: %v", err)
	}
	if rep128.Soundness.DECSHashBits != 128 || rep128.Soundness.DECSTapeBits != 128 || rep128.Soundness.CollisionSpaceBits != 128 {
		t.Fatalf("128-bit widths: hash=%d tape=%d space=%d", rep128.Soundness.DECSHashBits, rep128.Soundness.DECSTapeBits, rep128.Soundness.CollisionSpaceBits)
	}

	rep160, err := BuildProofReport(soundnessWidthProof(20), opts, ringQ)
	if err != nil {
		t.Fatalf("160-bit proof report: %v", err)
	}
	if rep160.Soundness.DECSHashBits != 160 || rep160.Soundness.DECSTapeBits != 160 || rep160.Soundness.CollisionSpaceBits != 160 {
		t.Fatalf("160-bit widths: hash=%d tape=%d space=%d", rep160.Soundness.DECSHashBits, rep160.Soundness.DECSTapeBits, rep160.Soundness.CollisionSpaceBits)
	}

	rep256, err := BuildProofReport(soundnessWidthProof(32), opts, ringQ)
	if err != nil {
		t.Fatalf("256-bit proof report: %v", err)
	}
	if rep256.Soundness.DECSHashBits != 256 || rep256.Soundness.DECSTapeBits != 256 || rep256.Soundness.CollisionSpaceBits != 256 {
		t.Fatalf("256-bit widths: hash=%d tape=%d space=%d", rep256.Soundness.DECSHashBits, rep256.Soundness.DECSTapeBits, rep256.Soundness.CollisionSpaceBits)
	}
}

func soundnessTestOpts(caps [5]int) SimOpts {
	return ResolveSimOptsDefaults(SimOpts{
		RingDegree:        1024,
		NCols:             16,
		LVCSNCols:         16,
		NLeaves:           64,
		Ell:               1,
		EllPrime:          1,
		Rho:               1,
		Theta:             1,
		Eta:               64,
		Kappa:             [4]int{30, 30, 30, 30},
		Lambda:            256,
		ROQueryCaps:       caps,
		ROQueryCapsSet:    true,
		DECSCollisionBits: 128,
	})
}

func soundnessWidthProof(hashBytes int) *Proof {
	var root [16]byte
	copy(root[:], bytes.Repeat([]byte{1}, len(root)))
	var rootHash []byte
	if hashBytes > len(root) {
		rootHash = bytes.Repeat([]byte{1}, hashBytes)
	}
	return &Proof{
		TranscriptVersion: TranscriptVersionSmallWood2025,
		RingDegree:        1024,
		QDegreeBound:      32,
		NLeavesUsed:       64,
		NColsUsed:         16,
		LVCSNColsUsed:     16,
		Theta:             1,
		Kappa:             [4]int{30, 30, 30, 30},
		Salt:              make([]byte, 64),
		Root:              root,
		RootHash:          rootHash,
		PCSOpening: &decs.DECSOpening{
			Indices:    []int{0},
			PvalsBits:  []byte{1},
			MvalsBits:  []byte{2},
			R:          1,
			Eta:        1,
			Nodes:      [][]byte{bytes.Repeat([]byte{2}, hashBytes)},
			PathIndex:  [][]int{{0}},
			NonceSeed:  bytes.Repeat([]byte{3}, hashBytes),
			NonceBytes: hashBytes,
		},
	}
}

func closeFloat(a, b, tol float64) bool {
	if math.IsInf(a, 1) || math.IsInf(b, 1) {
		return math.IsInf(a, 1) && math.IsInf(b, 1)
	}
	return math.Abs(a-b) <= tol
}
