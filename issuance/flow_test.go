package issuance

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	swDomain "vSIS-Signature/internal/domain"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func issuanceTestConstNTT(r *ring.Ring, c uint64) *ring.Poly {
	p := r.NewPoly()
	p.Coeffs[0][0] = c % r.Modulus[0]
	r.NTT(p, p)
	return p
}

func issuanceTestCoeffHead(r *ring.Ring, head []int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	for i := 0; i < len(head) && i < len(p.Coeffs[0]); i++ {
		v := head[i] % q
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func TestApplyChallengeMatchesHashMessageAndProofVerifies(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if filepath.Base(cwd) == "issuance" {
		t.Chdir(filepath.Dir(cwd))
	}

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential: true,
		Theta:      1,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		Ell:        18,
		Eta:        19,
		DomainMode: PIOP.DomainModeExplicit,
		NLeaves:    4096,
	})
	opts.LVCSNCols = 96
	opts.PostSignLVCSNCols = opts.LVCSNCols
	opts.PRFLVCSNCols = opts.LVCSNCols

	dom, err := swDomain.NewDomain(ringQ.Modulus[0], opts.NLeaves, opts.NCols, opts.Ell, nil)
	if err != nil {
		t.Fatalf("derive explicit domain: %v", err)
	}
	omega := append([]uint64(nil), dom.Omega[:opts.NCols]...)

	const bound = int64(1)
	Ac := make([][]*ring.Poly, 5)
	for i := range Ac {
		Ac[i] = make([]*ring.Poly, 5)
		for j := range Ac[i] {
			if i == j {
				Ac[i][j] = issuanceTestConstNTT(ringQ, 1)
			} else {
				Ac[i][j] = ringQ.NewPoly()
			}
		}
	}
	params := &credential.Params{
		Ac:     Ac,
		BPath:  "../Parameters/Bmatrix.json",
		AcPath: "../credential/Ac.json",
		BoundB: bound,
		RingQ:  ringQ,
		LenM1:  1,
		LenM2:  1,
		LenRU0: 1,
		LenRU1: 1,
		LenR:   1,
	}

	inputs := Inputs{
		M1:  []*ring.Poly{issuanceTestCoeffHead(ringQ, []int64{1, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})},
		M2:  []*ring.Poly{issuanceTestCoeffHead(ringQ, []int64{0, 0, 0, 0, 0, 0, 0, 0, 1, -1, 1, 0, -1, 0, 1, 0})},
		RU0: []*ring.Poly{issuanceTestCoeffHead(ringQ, []int64{1, 0, -1, 1, 0, -1, 1, 0, -1, 1, 0, -1, 1, 0, -1, 1})},
		RU1: []*ring.Poly{issuanceTestCoeffHead(ringQ, []int64{0, 1, 0, -1, 1, 0, -1, 1, 0, -1, 1, 0, -1, 1, 0, -1})},
		R:   []*ring.Poly{issuanceTestCoeffHead(ringQ, []int64{-1, 0, 1, 0, -1, 0, 1, 0, -1, 0, 1, 0, -1, 0, 1, 0})},
	}

	rng := rand.New(rand.NewSource(7))
	ch, err := SampleChallenge(ringQ, omega, bound, rng)
	if err != nil {
		t.Fatalf("sample challenge: %v", err)
	}
	com, err := PrepareCommit(params, inputs, omega)
	if err != nil {
		t.Fatalf("prepare commit: %v", err)
	}
	st, err := ApplyChallenge(params, inputs, ch, omega)
	if err != nil {
		t.Fatalf("apply challenge: %v", err)
	}
	surface, err := PIOP.DerivePreSignCarrierAndAliasRows(ringQ, bound, omega, PIOP.DomainModeExplicit, PIOP.PreSignRawRows{
		M1: inputs.M1[0],
		M2: inputs.M2[0],
		R0: st.R0[0],
		R1: st.R1[0],
	})
	if err != nil {
		t.Fatalf("derive canonical target rows: %v", err)
	}
	polyFromAliasOmega := func(coeffs []uint64) *ring.Poly {
		head := make([]uint64, len(omega))
		q := ringQ.Modulus[0]
		for i, w := range omega {
			head[i] = PIOP.EvalPoly(coeffs, w%q, q)
		}
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], head)
		return p
	}
	wantT, err := credential.HashMessage(
		ringQ,
		st.B,
		polyFromAliasOmega(surface.AliasCoeffs[PIOP.PreSignAliasM1]),
		polyFromAliasOmega(surface.AliasCoeffs[PIOP.PreSignAliasM2]),
		polyFromAliasOmega(surface.AliasCoeffs[PIOP.PreSignAliasR0]),
		polyFromAliasOmega(surface.AliasCoeffs[PIOP.PreSignAliasR1]),
	)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}
	if len(st.T) != len(wantT) {
		t.Fatalf("T length=%d want %d", len(st.T), len(wantT))
	}
	for i := range wantT {
		if st.T[i] != wantT[i] {
			t.Fatalf("T[%d]=%d want %d", i, st.T[i], wantT[i])
		}
	}

	proof, err := ProvePreSign(params, ch, com, inputs, st, opts)
	if err != nil {
		t.Fatalf("prove pre-sign: %v", err)
	}
	ok, err := VerifyPreSign(params, ch, com, st, proof, opts)
	if err != nil {
		t.Fatalf("verify pre-sign: %v", err)
	}
	if !ok {
		t.Fatal("pre-sign proof did not verify")
	}
}
