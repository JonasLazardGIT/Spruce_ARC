package PIOP

import (
	"testing"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func BenchmarkIntGenISISProjectedSignatureFormalCoeffsSmallfieldSW90Shape(b *testing.B) {
	ringQ, err := ring.NewRing(256, []uint64{1054721})
	if err != nil {
		b.Fatalf("load ring: %v", err)
	}
	q := ringQ.Modulus[0]
	ncols := 32
	blocks := int(ringQ.N) / ncols
	omega, err := deriveRelationWitnessOmega(q, 4096, ncols, 64, 16, credential.HashRelationBBTran)
	if err != nil {
		b.Fatalf("omega: %v", err)
	}
	omega = omega[:ncols]
	l := &IntGenISISShowingRowLayout{
		LayoutVersion:   intGenISISShowingLayoutVersionProjectionUYHatYViewV2,
		ViewRowsPerPoly: blocks,
		UCount:          2,
		MCount:          1,
		SCount:          2,
		ECount:          1,
		X0Count:         2,
		MuSigCount:      1,
		UViewStart:      0,
		MViewStart:      2 * blocks,
		SViewStart:      3 * blocks,
		EViewStart:      5 * blocks,
		MuSigHatStart:   6 * blocks,
		MuSigHatCount:   blocks,
		X0HatStart:      7 * blocks,
		X0HatCount:      2 * blocks,
		ZHatStart:       9 * blocks,
		ZHatCount:       blocks,
	}
	rowCount := 10 * blocks
	rowsNTT := make([]*ring.Poly, rowCount)
	for i := range rowsNTT {
		p := ringQ.NewPoly()
		for j := 0; j < int(ringQ.N); j++ {
			p.Coeffs[0][j] = uint64((3*i + 5*j + 1) % int(q))
		}
		ringQ.NTT(p, p)
		rowsNTT[i] = p
	}
	rowCache, err := newIntGenISISRowCoeffCache(ringQ, rowsNTT)
	if err != nil {
		b.Fatalf("row cache: %v", err)
	}
	pub := PublicInputs{
		A: [][]*ring.Poly{{
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 2),
		}},
		B: []*ring.Poly{
			intGenISISTestPublicConstNTT(ringQ, 3),
			intGenISISTestPublicConstNTT(ringQ, 4),
			intGenISISTestPublicConstNTT(ringQ, 5),
			intGenISISTestPublicConstNTT(ringQ, 6),
			intGenISISTestPublicConstNTT(ringQ, 7),
		},
		CM: [][]*ring.Poly{{
			intGenISISTestPublicConstNTT(ringQ, 8),
		}},
		AS: [][]*ring.Poly{{
			intGenISISTestPublicConstNTT(ringQ, 9),
			intGenISISTestPublicConstNTT(ringQ, 10),
		}},
	}
	yLinearCache, err := newIntGenISISYLinearMapCache(ringQ, pub, l, omega)
	if err != nil {
		b.Fatalf("Y linear cache: %v", err)
	}
	basis, err := newTransformBridgeBasisCache(ringQ, omega, blocks*ncols, blocks)
	if err != nil {
		b.Fatalf("basis: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := intGenISISProjectedSignatureFormalCoeffs(ringQ, pub, rowsNTT, rowCache, l, basis, omega, yLinearCache, intGenISISMSECompressionSpec{}, nil); err != nil {
			b.Fatalf("projected signature: %v", err)
		}
	}
}

func BenchmarkIntGenISISLinearHForMultiplierSW90Shape(b *testing.B) {
	ringQ, err := ring.NewRing(1024, []uint64{1054721})
	if err != nil {
		b.Fatalf("load ring: %v", err)
	}
	q := ringQ.Modulus[0]
	ncols := 64
	rowsPerPoly := int(ringQ.N) / ncols
	omega, err := deriveRelationWitnessOmega(q, 4096, ncols, 64, 16, credential.HashRelationBBTran)
	if err != nil {
		b.Fatalf("omega: %v", err)
	}
	omega = omega[:ncols]
	multCoeff := make([]uint64, int(ringQ.N))
	for i := range multCoeff {
		multCoeff[i] = uint64((17*i + 23) % int(q))
	}
	lagrange, err := buildLagrangeBasisCoeffs(omega, q)
	if err != nil {
		b.Fatalf("lagrange: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := intGenISISLinearHForMultiplier(ringQ, omega, lagrange, multCoeff, rowsPerPoly, "bench"); err != nil {
			b.Fatalf("linear H: %v", err)
		}
	}
}
