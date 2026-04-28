package PIOP

import (
	"path/filepath"
	"testing"

	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestIntGenISISShowingProofBuildsAndVerifies(t *testing.T) {
	chdirForPIOPIntGenISISTest(t)
	profile := credential.PrimaryIntGenISISProfile()
	ringQ, err := credential.LoadRingWithDegree(profile.N)
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	params, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	opts := ResolveSimOptsDefaults(SimOpts{
		Credential:        true,
		CoeffPacking:      true,
		RingDegree:        profile.N,
		NCols:             16,
		LVCSNCols:         32,
		PostSignLVCSNCols: 32,
		PRFLVCSNCols:      32,
		Ell:               4,
		Eta:               8,
		Rho:               1,
		Theta:             1,
		DomainMode:        DomainModeExplicit,
		NLeaves:           4096,
		PRFGroupRounds:    2,
		PRFCompanionMode:  PRFCompanionModeOutputAudit,
	})

	M := ringQ.NewPoly()
	keyStart := int(ringQ.N) / 2
	for i := 0; i < params.LenKey; i++ {
		M.Coeffs[0][keyStart+i] = uint64(i + 1)
	}
	key, err := ExtractSignedPRFKeyElemsFromMuCoeffs(ringQ, M, opts.NCols, params.LenKey)
	if err != nil {
		t.Fatalf("extract key: %v", err)
	}
	nonce, noncePublic := fixedNonceTest(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}

	zeroCoeff := ringQ.NewPoly()
	oneCoeff := intGenISISTestCoeffConst(ringQ, 1)
	MNTT := intGenISISTestNTT(ringQ, M)
	u0NTT := ringQ.NewPoly()
	for i := 0; i < ringQ.N; i++ {
		u0NTT.Coeffs[0][i] = (MNTT.Coeffs[0][i] + 1) % ringQ.Modulus[0]
	}
	u0 := ringQ.NewPoly()
	ringQ.InvNTT(u0NTT, u0)

	cn := &CoeffNativeShowingWitness{
		Sig:         []*ring.Poly{u0, zeroCoeff.CopyNew()},
		M:           M,
		S:           []*ring.Poly{zeroCoeff.CopyNew(), zeroCoeff.CopyNew()},
		E:           []*ring.Poly{zeroCoeff.CopyNew()},
		MuSig:       []*ring.Poly{zeroCoeff.CopyNew()},
		X0:          []*ring.Poly{zeroCoeff.CopyNew(), zeroCoeff.CopyNew()},
		X1:          zeroCoeff.CopyNew(),
		Z:           oneCoeff,
		PackedNCols: opts.NCols,
	}
	pub := PublicInputs{
		A: [][]*ring.Poly{{
			intGenISISTestPublicConstNTT(ringQ, 1),
			intGenISISTestPublicConstNTT(ringQ, 0),
		}},
		B: []*ring.Poly{
			intGenISISTestPublicConstNTT(ringQ, 0),
			intGenISISTestPublicConstNTT(ringQ, 0),
			intGenISISTestPublicConstNTT(ringQ, 0),
			intGenISISTestPublicConstNTT(ringQ, 0),
			intGenISISTestPublicConstNTT(ringQ, 1),
		},
		CM:           [][]*ring.Poly{{intGenISISTestPublicConstNTT(ringQ, 1)}},
		AS:           [][]*ring.Poly{{intGenISISTestPublicConstNTT(ringQ, 0), intGenISISTestPublicConstNTT(ringQ, 0)}},
		Tag:          lanesFromElemsTest(tag, opts.NCols),
		Nonce:        noncePublic,
		BoundB:       profile.B,
		X0Len:        profile.EllX0,
		RingDegree:   profile.N,
		HashRelation: credential.HashRelationBBTran,
		IntGenISIS:   true,
	}
	proof, err := BuildIntGenISISShowingCombined(pub, WitnessInputs{CoeffNativeShowing: cn}, opts)
	if err != nil {
		t.Fatalf("build showing: %v", err)
	}
	if proof.RowLayout.IntGenISISShowing == nil {
		t.Fatal("missing IntGenISIS showing row layout")
	}
	if got := proof.RowLayout.IntGenISISShowing.CoreRowCount; got != 11 {
		t.Fatalf("core showing rows=%d want 11", got)
	}
	ok, err := VerifyIntGenISISShowing(pub, proof, opts)
	if err != nil || !ok {
		t.Fatalf("verify showing: ok=%v err=%v", ok, err)
	}

	tampered := pub
	tampered.Com = []*ring.Poly{ringQ.NewPoly()}
	ok, err = VerifyIntGenISISShowing(tampered, proof, opts)
	if err == nil && ok {
		t.Fatal("showing verifier accepted forbidden public commitment")
	}

	tampered = pub
	tampered.B = clonePolySliceForIntGenISISTest(ringQ, pub.B)
	tampered.B[0].Coeffs[0][0] ^= 1
	ok, err = VerifyIntGenISISShowing(tampered, proof, opts)
	if err == nil && ok {
		t.Fatal("showing verifier accepted tampered target public data")
	}
}

func intGenISISTestCoeffConst(ringQ *ring.Ring, v uint64) *ring.Poly {
	p := ringQ.NewPoly()
	p.Coeffs[0][0] = v % ringQ.Modulus[0]
	return p
}

func intGenISISTestPublicConstNTT(ringQ *ring.Ring, v uint64) *ring.Poly {
	p := intGenISISTestCoeffConst(ringQ, v)
	ringQ.NTT(p, p)
	return p
}

func intGenISISTestNTT(ringQ *ring.Ring, p *ring.Poly) *ring.Poly {
	out := ringQ.NewPoly()
	ring.Copy(p, out)
	ringQ.NTT(out, out)
	return out
}
