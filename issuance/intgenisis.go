package issuance

import (
	"fmt"
	"io"

	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	vsishash "vSIS-Signature/internal/hash"
	"vSIS-Signature/internal/sampling"

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

// IntGenISISX1RejectionLimit is the hard protocol cap for issuer-side x1
// rejection sampling. The attempt that succeeds is included in this count.
const IntGenISISX1RejectionLimit = 1024

func PrepareIntGenISISCommit(params *credential.Params, in IntGenISISInputs) (commitment.Vector, error) {
	targetParams, err := commitmentParamsFromIssuance(params)
	if err != nil {
		return nil, err
	}
	return commitment.CommitMessage(targetParams, in.M, in.S, in.E)
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
func SampleIntGenISISCommitmentRandomness(params *credential.Params, random io.Reader) (s, e []*ring.Poly, err error) {
	targetParams, err := commitmentParamsFromIssuance(params)
	if err != nil {
		return nil, nil, err
	}
	return commitment.SampleCommitmentRandomness(targetParams, random)
}

// SampleSignatureHashData samples issuer-side mu_sig, x0, and x1
// coefficient-wise and uniformly from {-1,0,1}. It resamples x1 until B3-x1
// is invertible. Conditioned on success within the hard attempt cap, x1 is the
// bounded uniform distribution conditioned on invertibility. All entropy is
// read from random.
func SampleSignatureHashData(ringQ *ring.Ring, B []*ring.Poly, ellMuSig, ellX0 int, random io.Reader) (SignatureHashData, error) {
	if ringQ == nil {
		return SignatureHashData{}, fmt.Errorf("nil ring")
	}
	if len(B) != 3+ellX0 {
		return SignatureHashData{}, fmt.Errorf("b length=%d want %d", len(B), 3+ellX0)
	}
	if err := validateCanonicalPolyVector(ringQ, "B", B); err != nil {
		return SignatureHashData{}, err
	}
	if ellMuSig != 1 {
		return SignatureHashData{}, fmt.Errorf("ell_mu_sig=%d want 1", ellMuSig)
	}
	if ellX0 <= 0 {
		return SignatureHashData{}, fmt.Errorf("invalid ell_x0=%d", ellX0)
	}
	if random == nil {
		return SignatureHashData{}, fmt.Errorf("nil randomness reader")
	}
	muSigPoly, err := sampleTernaryCoeffPoly(ringQ, random)
	if err != nil {
		return SignatureHashData{}, fmt.Errorf("sample mu_sig: %w", err)
	}
	muSig := []*ring.Poly{muSigPoly}
	x0 := make([]*ring.Poly, ellX0)
	for i := range x0 {
		x0[i], err = sampleTernaryCoeffPoly(ringQ, random)
		if err != nil {
			return SignatureHashData{}, fmt.Errorf("sample x0[%d]: %w", i, err)
		}
	}
	var x1 *ring.Poly
	var zCoeff *ring.Poly
	for attempts := 0; attempts < IntGenISISX1RejectionLimit; attempts++ {
		candidate, err := sampleTernaryCoeffPoly(ringQ, random)
		if err != nil {
			return SignatureHashData{}, fmt.Errorf("sample x1 candidate %d/%d: %w", attempts+1, IntGenISISX1RejectionLimit, err)
		}
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
		return SignatureHashData{}, fmt.Errorf("failed to sample invertible x1 after %d attempts", IntGenISISX1RejectionLimit)
	}
	return SignatureHashData{
		MuSig: muSig,
		X0:    x0,
		X1:    []*ring.Poly{x1},
		Z:     []*ring.Poly{zCoeff},
	}, nil
}

// ValidateSignatureHashData enforces the canonical bounded BB-tran source
// domain before any source is transformed to NTT form. In particular, values
// congruent to a ternary value modulo q but not canonically represented are
// rejected rather than reduced.
func ValidateSignatureHashData(ringQ *ring.Ring, data SignatureHashData, ellMuSig, ellX0 int) error {
	if ringQ == nil || len(ringQ.Modulus) == 0 || ringQ.Modulus[0] == 0 {
		return fmt.Errorf("invalid ring")
	}
	if ellMuSig != 1 {
		return fmt.Errorf("ell_mu_sig=%d want 1", ellMuSig)
	}
	if ellX0 <= 0 {
		return fmt.Errorf("invalid ell_x0=%d", ellX0)
	}
	if len(data.MuSig) != ellMuSig || len(data.X0) != ellX0 || len(data.X1) != 1 {
		return fmt.Errorf("invalid signature hash data lengths mu_sig=%d/%d x0=%d/%d x1=%d/1", len(data.MuSig), ellMuSig, len(data.X0), ellX0, len(data.X1))
	}
	for _, group := range []struct {
		name  string
		polys []*ring.Poly
	}{
		{name: "mu_sig", polys: data.MuSig},
		{name: "x0", polys: data.X0},
		{name: "x1", polys: data.X1},
	} {
		for i, p := range group.polys {
			if err := validateTernaryCoeffPoly(ringQ, fmt.Sprintf("%s[%d]", group.name, i), p); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateTernaryCoeffPoly(ringQ *ring.Ring, name string, p *ring.Poly) error {
	if err := validateCanonicalPoly(ringQ, name, p); err != nil {
		return err
	}
	q := ringQ.Modulus[0]
	for i, coefficient := range p.Coeffs[0] {
		if coefficient != 0 && coefficient != 1 && coefficient != q-1 {
			return fmt.Errorf("%s coefficient %d=%d outside canonical ternary domain {0,1,%d}", name, i, coefficient, q-1)
		}
	}
	return nil
}

func validateCanonicalPolyVector(ringQ *ring.Ring, name string, polys []*ring.Poly) error {
	for i, p := range polys {
		if err := validateCanonicalPoly(ringQ, fmt.Sprintf("%s[%d]", name, i), p); err != nil {
			return err
		}
	}
	return nil
}

func validateCanonicalPoly(ringQ *ring.Ring, name string, p *ring.Poly) error {
	if ringQ == nil || len(ringQ.Modulus) == 0 || ringQ.Modulus[0] == 0 {
		return fmt.Errorf("invalid ring")
	}
	if p == nil || len(p.Coeffs) == 0 {
		return fmt.Errorf("%s is nil", name)
	}
	if len(p.Coeffs[0]) != ringQ.N {
		return fmt.Errorf("%s coefficient length=%d want %d", name, len(p.Coeffs[0]), ringQ.N)
	}
	q := ringQ.Modulus[0]
	for i, coefficient := range p.Coeffs[0] {
		if coefficient >= q {
			return fmt.Errorf("%s coefficient %d=%d is not canonical modulo %d", name, i, coefficient, q)
		}
	}
	return nil
}

func sampleTernaryCoeffPoly(ringQ *ring.Ring, random io.Reader) (*ring.Poly, error) {
	if ringQ == nil || len(ringQ.Modulus) == 0 || ringQ.Modulus[0] == 0 {
		return nil, fmt.Errorf("invalid ring")
	}
	if random == nil {
		return nil, fmt.Errorf("nil randomness reader")
	}
	p := ringQ.NewPoly()
	q := ringQ.Modulus[0]
	for i := 0; i < ringQ.N; i++ {
		value, err := sampling.CenteredInt64(random, credential.IntGenISISHashInputBound)
		if err != nil {
			return nil, fmt.Errorf("coefficient %d: %w", i, err)
		}
		if value < 0 {
			p.Coeffs[0][i] = q - uint64(-value)
		} else {
			p.Coeffs[0][i] = uint64(value)
		}
	}
	return p, nil
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
		return IntGenISISTarget{}, fmt.Errorf("b length=%d want %d", len(B), 3+ellX0)
	}
	if err := validateCanonicalPolyVector(ringQ, "B", B); err != nil {
		return IntGenISISTarget{}, err
	}
	if len(c) != 1 || c[0] == nil {
		return IntGenISISTarget{}, fmt.Errorf("commitment length=%d want 1", len(c))
	}
	if err := validateCanonicalPoly(ringQ, "commitment[0]", c[0]); err != nil {
		return IntGenISISTarget{}, err
	}
	if err := ValidateSignatureHashData(ringQ, data, 1, ellX0); err != nil {
		return IntGenISISTarget{}, err
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

// VerifyIntGenISISTargetRelation checks the inverse witness and the complete
// bounded BB-tran target equation without trusting the target constructor:
//
//	(B3-x1)Z = 1
//	T = c + B0 + B1*mu_sig + B2*x0 + Z.
func VerifyIntGenISISTargetRelation(ringQ *ring.Ring, B []*ring.Poly, c commitment.Vector, data SignatureHashData, target IntGenISISTarget) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	ellX0 := len(data.X0)
	if ellX0 <= 0 || len(B) != 3+ellX0 {
		return fmt.Errorf("invalid B/x0 dimensions b=%d x0=%d", len(B), ellX0)
	}
	if err := validateCanonicalPolyVector(ringQ, "B", B); err != nil {
		return err
	}
	if len(c) != 1 {
		return fmt.Errorf("commitment length=%d want 1", len(c))
	}
	if err := validateCanonicalPoly(ringQ, "commitment[0]", c[0]); err != nil {
		return err
	}
	if err := ValidateSignatureHashData(ringQ, data, 1, ellX0); err != nil {
		return err
	}
	if len(target.ZCoeff) != 1 || len(target.TNTT) != 1 || len(target.TCoeff) != ringQ.N {
		return fmt.Errorf("invalid target dimensions z=%d t_ntt=%d t_coeff=%d/%d", len(target.ZCoeff), len(target.TNTT), len(target.TCoeff), ringQ.N)
	}
	if err := validateCanonicalPoly(ringQ, "target.Z[0]", target.ZCoeff[0]); err != nil {
		return err
	}
	if err := validateCanonicalPoly(ringQ, "target.T[0]", target.TNTT[0]); err != nil {
		return err
	}

	_, b1, b2, b3, err := credential.SplitBBTranB(B, ellX0, 1)
	if err != nil {
		return err
	}
	x1NTT := clonePoly(ringQ, data.X1[0])
	ringQ.NTT(x1NTT, x1NTT)
	denominator := ringQ.NewPoly()
	ringQ.Sub(b3, x1NTT, denominator)
	zNTT := clonePoly(ringQ, target.ZCoeff[0])
	ringQ.NTT(zNTT, zNTT)
	product := ringQ.NewPoly()
	ringQ.MulCoeffs(denominator, zNTT, product)
	oneNTT := ringQ.NewPoly()
	oneNTT.Coeffs[0][0] = 1
	ringQ.NTT(oneNTT, oneNTT)
	if !polyEqualModQ(ringQ, product, oneNTT) {
		return fmt.Errorf("invalid inverse witness: (B3-x1)Z != 1")
	}

	muNTT := clonePoly(ringQ, data.MuSig[0])
	ringQ.NTT(muNTT, muNTT)
	rhs := clonePoly(ringQ, B[0])
	tmp := ringQ.NewPoly()
	ringQ.MulCoeffs(b1, muNTT, tmp)
	ringQ.Add(rhs, tmp, rhs)
	for i := range data.X0 {
		x0NTT := clonePoly(ringQ, data.X0[i])
		ringQ.NTT(x0NTT, x0NTT)
		ringQ.MulCoeffs(b2[i], x0NTT, tmp)
		ringQ.Add(rhs, tmp, rhs)
	}
	ringQ.Add(rhs, zNTT, rhs)
	ringQ.Add(rhs, c[0], rhs)
	if !polyEqualModQ(ringQ, rhs, target.TNTT[0]) {
		return fmt.Errorf("invalid target equation: T != c+B0+B1*mu_sig+B2*x0+Z")
	}
	tCoeff := clonePoly(ringQ, target.TNTT[0])
	ringQ.InvNTT(tCoeff, tCoeff)
	wantCoeff := coeffPolyToInt64(ringQ, tCoeff)
	for i := range wantCoeff {
		if target.TCoeff[i] != wantCoeff[i] {
			return fmt.Errorf("target coefficient %d=%d want %d", i, target.TCoeff[i], wantCoeff[i])
		}
	}
	return nil
}

func polyEqualModQ(ringQ *ring.Ring, a, b *ring.Poly) bool {
	if a == nil || b == nil || len(a.Coeffs) == 0 || len(b.Coeffs) == 0 || len(a.Coeffs[0]) != ringQ.N || len(b.Coeffs[0]) != ringQ.N {
		return false
	}
	q := ringQ.Modulus[0]
	for i := 0; i < ringQ.N; i++ {
		if a.Coeffs[0][i]%q != b.Coeffs[0][i]%q {
			return false
		}
	}
	return true
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
