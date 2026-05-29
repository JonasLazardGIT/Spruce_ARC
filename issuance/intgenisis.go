package issuance

import (
	"fmt"
	"math/rand"

	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// IntGenISISInputs are the holder's secret issuance values for the
// committed-message protocol. M is the packed semantic message M := m || k.
// All polynomials are coefficient-domain.
type IntGenISISInputs struct {
	M []*ring.Poly
	// MAttr and K are retained for relation builders that need to prove the
	// semantic packing M=m||k. The commitment equation only consumes M.
	MAttr []*ring.Poly
	K     []*ring.Poly
	S     []*ring.Poly
	E     []*ring.Poly
}

// SignatureHashData is the issuer-sampled BB-tran rational-hash data.
type SignatureHashData struct {
	MuSig []*ring.Poly
	X0    []*ring.Poly
	X1    []*ring.Poly
	Z     []*ring.Poly
}

// IntGenISISTarget carries the issuer-computed target in both domains.
type IntGenISISTarget struct {
	ZCoeff []*ring.Poly
	TNTT   []*ring.Poly
	TCoeff []int64
}

func PrepareIntGenISISCommit(params *credential.Params, in IntGenISISInputs) (commitment.Vector, error) {
	targetParams, err := commitmentParamsFromIssuance(params)
	if err != nil {
		return nil, err
	}
	return commitment.CommitMessage(targetParams, in.M, in.S, in.E)
}

func VerifyIntGenISISCommit(params *credential.Params, c commitment.Vector, in IntGenISISInputs) error {
	targetParams, err := commitmentParamsFromIssuance(params)
	if err != nil {
		return err
	}
	return commitment.VerifyCommitmentOpening(targetParams, c, commitment.TargetOpening{
		M: in.M,
		S: in.S,
		E: in.E,
	})
}

func commitmentParamsFromIssuance(params *credential.Params) (commitment.TargetParams, error) {
	if params == nil {
		return commitment.TargetParams{}, fmt.Errorf("nil params")
	}
	out := commitment.TargetParams{
		RingQ: params.RingQ,
		CM:    params.CM,
		AS:    params.AS,
		EllM:  params.EllM,
		KS:    params.KS,
		NC:    params.NC,
		Bound: params.CommitmentBound,
	}
	if err := out.Validate(); err != nil {
		return commitment.TargetParams{}, err
	}
	return out, nil
}

// SampleIntGenISISCommitmentRandomness samples live IntGenISIS s and e from
// the public bounded range [-B,B]. The proof relation enforces the same bound.
func SampleIntGenISISCommitmentRandomness(params *credential.Params, rng *rand.Rand) (s, e []*ring.Poly, err error) {
	targetParams, err := commitmentParamsFromIssuance(params)
	if err != nil {
		return nil, nil, err
	}
	return commitment.SampleCommitmentRandomness(targetParams, rng)
}

// SampleSignatureHashData samples issuer-side mu_sig, x0, and x1. The current
// implementation uses uniform R_q sampling for these DKLW/BB-tran values and
// resamples x1 until B3-x1 is invertible.
func SampleSignatureHashData(ringQ *ring.Ring, B []*ring.Poly, ellMuSig, ellX0 int, rng *rand.Rand) (SignatureHashData, error) {
	if ringQ == nil {
		return SignatureHashData{}, fmt.Errorf("nil ring")
	}
	if len(B) != 3+ellX0 {
		return SignatureHashData{}, fmt.Errorf("B length=%d want %d", len(B), 3+ellX0)
	}
	if ellMuSig != 1 {
		return SignatureHashData{}, fmt.Errorf("ell_mu_sig=%d want 1", ellMuSig)
	}
	if ellX0 <= 0 {
		return SignatureHashData{}, fmt.Errorf("invalid ell_x0=%d", ellX0)
	}
	if rng == nil {
		return SignatureHashData{}, fmt.Errorf("nil rng")
	}
	muSig := []*ring.Poly{sampleUniformCoeffPoly(ringQ, rng)}
	x0 := make([]*ring.Poly, ellX0)
	for i := range x0 {
		x0[i] = sampleUniformCoeffPoly(ringQ, rng)
	}
	var x1 *ring.Poly
	var zCoeff *ring.Poly
	for attempts := 0; attempts < 1024; attempts++ {
		candidate := sampleUniformCoeffPoly(ringQ, rng)
		zNTT, err := computeInverseNoMutate(ringQ, B[len(B)-1], candidate)
		if err == nil {
			x1 = candidate
			zCoeff = ringQ.NewPoly()
			ring.Copy(zNTT, zCoeff)
			ringQ.InvNTT(zCoeff, zCoeff)
			break
		}
	}
	if x1 == nil {
		return SignatureHashData{}, fmt.Errorf("failed to sample invertible x1")
	}
	return SignatureHashData{
		MuSig: muSig,
		X0:    x0,
		X1:    []*ring.Poly{x1},
		Z:     []*ring.Poly{zCoeff},
	}, nil
}

func sampleUniformCoeffPoly(ringQ *ring.Ring, rng *rand.Rand) *ring.Poly {
	p := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i := 0; i < ringQ.N; i++ {
		p.Coeffs[0][i] = uint64(rng.Int63n(q))
	}
	return p
}

// ComputeIntGenISISTarget computes
//
//	T = B0 + B1 mu_sig + B2 x0 + Z + c
//
// where c is the target-shaped MLWE-hiding commitment.
func ComputeIntGenISISTarget(ringQ *ring.Ring, B []*ring.Poly, c commitment.Vector, data SignatureHashData) (IntGenISISTarget, error) {
	if ringQ == nil {
		return IntGenISISTarget{}, fmt.Errorf("nil ring")
	}
	ellX0 := len(data.X0)
	if ellX0 <= 0 {
		return IntGenISISTarget{}, fmt.Errorf("invalid x0 length=%d", ellX0)
	}
	if len(B) != 3+ellX0 {
		return IntGenISISTarget{}, fmt.Errorf("B length=%d want %d", len(B), 3+ellX0)
	}
	if len(c) != 1 || c[0] == nil {
		return IntGenISISTarget{}, fmt.Errorf("commitment length=%d want 1", len(c))
	}
	if len(data.MuSig) != 1 || len(data.X1) != 1 {
		return IntGenISISTarget{}, fmt.Errorf("invalid signature hash data lengths mu_sig=%d x1=%d", len(data.MuSig), len(data.X1))
	}
	muSig := clonePoly(ringQ, data.MuSig[0])
	x0 := clonePolyVec(ringQ, data.X0)
	x1 := clonePoly(ringQ, data.X1[0])
	b0, b1, b2, b3, err := credential.SplitBBTranB(B, ellX0, 1)
	if err != nil {
		return IntGenISISTarget{}, err
	}
	zNTT, hNTT, err := vsishash.ComputeBBTranTargetVector(ringQ, b0, b1, b2, b3, muSig, x0, x1)
	if err != nil {
		return IntGenISISTarget{}, err
	}
	tNTT := ringQ.NewPoly()
	ring.Copy(hNTT, tNTT)
	ringQ.Add(tNTT, c[0], tNTT)

	zCoeff := ringQ.NewPoly()
	ring.Copy(zNTT, zCoeff)
	ringQ.InvNTT(zCoeff, zCoeff)
	tCoeffPoly := ringQ.NewPoly()
	ring.Copy(tNTT, tCoeffPoly)
	ringQ.InvNTT(tCoeffPoly, tCoeffPoly)
	return IntGenISISTarget{
		ZCoeff: []*ring.Poly{zCoeff},
		TNTT:   []*ring.Poly{tNTT},
		TCoeff: coeffPolyToInt64(ringQ, tCoeffPoly),
	}, nil
}

func VerifyIntGenISISTarget(ringQ *ring.Ring, B []*ring.Poly, c commitment.Vector, data SignatureHashData, tCoeff []int64) error {
	got, err := ComputeIntGenISISTarget(ringQ, B, c, data)
	if err != nil {
		return err
	}
	if len(got.TCoeff) != len(tCoeff) {
		return fmt.Errorf("target length=%d want %d", len(tCoeff), len(got.TCoeff))
	}
	for i := range tCoeff {
		if got.TCoeff[i] != tCoeff[i] {
			return fmt.Errorf("target coefficient %d=%d want %d", i, tCoeff[i], got.TCoeff[i])
		}
	}
	return nil
}

func computeInverseNoMutate(ringQ *ring.Ring, b3, x1Coeff *ring.Poly) (*ring.Poly, error) {
	x1 := clonePoly(ringQ, x1Coeff)
	return vsishash.ComputeBBTranInverse(ringQ, b3, x1)
}

func clonePoly(ringQ *ring.Ring, p *ring.Poly) *ring.Poly {
	out := ringQ.NewPoly()
	if p != nil {
		ring.Copy(p, out)
	}
	return out
}

func clonePolyVec(ringQ *ring.Ring, in []*ring.Poly) []*ring.Poly {
	out := make([]*ring.Poly, len(in))
	for i := range in {
		out[i] = clonePoly(ringQ, in[i])
	}
	return out
}

func coeffPolyToInt64(ringQ *ring.Ring, p *ring.Poly) []int64 {
	out := make([]int64, ringQ.N)
	q := int64(ringQ.Modulus[0])
	half := q / 2
	for i, c := range p.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		out[i] = v
	}
	return out
}
