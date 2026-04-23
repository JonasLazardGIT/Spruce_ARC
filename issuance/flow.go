package issuance

import (
	"fmt"
	"log"
	"math/rand"

	lvcs "vSIS-Signature/LVCS"
	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	"vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Inputs groups the holder's secret values for issuance.
// All polynomials are expected in coefficient form (non-NTT).
type Inputs struct {
	M    []*ring.Poly
	K    []*ring.Poly
	R0H  []*ring.Poly
	R1H  []*ring.Poly
	RBar []*ring.Poly
	// Deprecated aliases retained only so older fixtures/tests can still build.
	M1  []*ring.Poly
	M2  []*ring.Poly
	RU0 []*ring.Poly
	RU1 []*ring.Poly
	R   []*ring.Poly
}

// Challenge carries the public randomness sampled by the issuer.
// All polynomials should be in NTT form (as sampled by credential.NewIssuerChallenge).
type Challenge struct {
	RI0 []*ring.Poly
	RI1 []*ring.Poly
}

// SampleChallenge samples bounded issuer randomness in coefficient form and
// stores it as a public NTT row. The holder and verifier both derive the same
// low-degree Θ polynomial from that row during proof construction.
func SampleChallenge(r *ring.Ring, omega []uint64, bound int64, rng *rand.Rand) (Challenge, error) {
	if r == nil {
		return Challenge{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return Challenge{}, fmt.Errorf("empty omega")
	}
	if rng == nil {
		return Challenge{}, fmt.Errorf("nil rng")
	}
	if bound <= 0 {
		return Challenge{}, fmt.Errorf("invalid bound %d", bound)
	}
	return Challenge{
		RI0: []*ring.Poly{sampleBoundedHeadNTT(r, len(omega), bound, rng)},
		RI1: []*ring.Poly{sampleBoundedHeadNTT(r, len(omega), bound, rng)},
	}, nil
}

// State captures the intermediate objects derived by the holder after receiving
// the issuer challenge.
type State struct {
	Com commitment.Vector // NTT
	R0  []*ring.Poly      // coeff
	R1  []*ring.Poly      // coeff
	K0  []*ring.Poly      // coeff (carry)
	K1  []*ring.Poly      // coeff (carry)
	Z   []*ring.Poly      // coeff
	T   []int64           // coeff
	B   []*ring.Poly      // NTT
}

func headEncodedPublicNTT(r *ring.Ring, head []uint64) *ring.Poly {
	out := r.NewPoly()
	q := r.Modulus[0]
	for i := 0; i < len(head) && i < len(out.Coeffs[0]); i++ {
		out.Coeffs[0][i] = head[i] % q
	}
	return out
}

func normalizeInputs(in Inputs) Inputs {
	if len(in.M) == 0 {
		in.M = in.M1
	}
	if len(in.K) == 0 {
		in.K = in.M2
	}
	if len(in.R0H) == 0 {
		in.R0H = in.RU0
	}
	if len(in.R1H) == 0 {
		in.R1H = in.RU1
	}
	if len(in.RBar) == 0 {
		in.RBar = in.R
	}
	return in
}

func coeffPolyFromHead(r *ring.Ring, head []uint64, omega []uint64) *ring.Poly {
	if len(omega) == len(head) {
		pNTT := PIOP.BuildThetaPrime(r, head, omega)
		out := r.NewPoly()
		r.InvNTT(pNTT, out)
		return out
	}
	pNTT := headEncodedPublicNTT(r, head)
	out := r.NewPoly()
	r.InvNTT(pNTT, out)
	return out
}

func coeffPolyFromNTTHead(r *ring.Ring, head []uint64) *ring.Poly {
	pNTT := headEncodedPublicNTT(r, head)
	out := r.NewPoly()
	r.InvNTT(pNTT, out)
	return out
}

func headFromCoeffPoly(r *ring.Ring, p *ring.Poly, omega []uint64) []uint64 {
	if r == nil || p == nil || len(omega) == 0 {
		return nil
	}
	q := r.Modulus[0]
	coeff := append([]uint64(nil), p.Coeffs[0]...)
	head := make([]uint64, len(omega))
	for i, w := range omega {
		head[i] = PIOP.EvalPoly(coeff, w%q, q)
	}
	return head
}

func thetaCoeffFromHead(r *ring.Ring, head []uint64, omega []uint64) *ring.Poly {
	thetaNTT := PIOP.BuildThetaPrime(r, head, omega)
	out := r.NewPoly()
	r.InvNTT(thetaNTT, out)
	return out
}

func modInverseUint64(x, q uint64) (uint64, bool) {
	if x == 0 || q == 0 {
		return 0, false
	}
	var t, newT int64 = 0, 1
	var r0, newR int64 = int64(q), int64(x % q)
	for newR != 0 {
		quot := r0 / newR
		t, newT = newT, t-quot*newT
		r0, newR = newR, r0-quot*newR
	}
	if r0 != 1 {
		return 0, false
	}
	if t < 0 {
		t += int64(q)
	}
	return uint64(t), true
}

func coeffPolyToInt64(r *ring.Ring, p *ring.Poly) []int64 {
	out := make([]int64, r.N)
	q := int64(r.Modulus[0])
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

// PrepareCommit computes the public commitment rows for the credential pre-sign
// statement using explicit-domain heads over Ω.
// Inputs are provided in coefficient form; the committed witness heads are the
// coefficient slots (not evaluations) to match carrier-compressed rows.
func PrepareCommit(p *credential.Params, in Inputs, omega []uint64) (commitment.Vector, error) {
	log.Printf("[issuance] preparing commitment")
	in = normalizeInputs(in)
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("missing omega")
	}
	ncols := len(omega)
	q := p.RingQ.Modulus[0]
	first := func(rows []*ring.Poly) *ring.Poly {
		if len(rows) == 0 {
			return nil
		}
		return rows[0]
	}
	surface, err := PIOP.DerivePreSignCarrierAndAliasRows(p.RingQ, p.BoundB, omega, PIOP.DomainModeExplicit, PIOP.PreSignRawRows{
		M1:  first(in.M),
		M2:  first(in.K),
		RU0: first(in.R0H),
		RU1: first(in.R1H),
		R:   first(in.RBar),
	})
	if err != nil {
		return nil, fmt.Errorf("derive canonical pre-sign commit rows: %w", err)
	}
	headFromCoeffs := func(coeffs []uint64) []uint64 {
		head := make([]uint64, ncols)
		for i, w := range omega {
			head[i] = PIOP.EvalPoly(coeffs, w%q, q)
		}
		return head
	}
	vecHead := [][]uint64{
		headFromCoeffs(surface.AliasCoeffs[PIOP.PreSignAliasM1]),
		headFromCoeffs(surface.AliasCoeffs[PIOP.PreSignAliasM2]),
		headFromCoeffs(surface.AliasCoeffs[PIOP.PreSignAliasRU0]),
		headFromCoeffs(surface.AliasCoeffs[PIOP.PreSignAliasRU1]),
		headFromCoeffs(surface.AliasCoeffs[PIOP.PreSignAliasR]),
	}
	com := make(commitment.Vector, len(p.Ac))
	for i := range p.Ac {
		if len(p.Ac[i]) != len(vecHead) {
			return nil, fmt.Errorf("Ac row %d length=%d want %d", i, len(p.Ac[i]), len(vecHead))
		}
		head := make([]uint64, ncols)
		for j := range p.Ac[i] {
			if p.Ac[i][j] == nil || vecHead[j] == nil {
				return nil, fmt.Errorf("nil Ac/vector poly at row=%d col=%d", i, j)
			}
			for k := 0; k < ncols; k++ {
				head[k] = lvcs.MulAddMod64(head[k], p.Ac[i][j].Coeffs[0][k]%q, vecHead[j][k]%q, q)
			}
		}
		com[i] = headEncodedPublicNTT(p.RingQ, head)
	}
	log.Printf("[issuance] commitment computed with %d outputs", len(com))
	return com, nil
}

// loadB loads the B-matrix from the configured path and lifts to NTT.
func loadB(r *ring.Ring, path string) ([]*ring.Poly, error) {
	coeffs, err := ntrurio.LoadBMatrixCoeffs(path)
	if err != nil {
		alt := []string{
			"Parameters/Bmatrix.json",
			"../Parameters/Bmatrix.json",
			"../../Parameters/Bmatrix.json",
		}
		for _, pth := range alt {
			coeffs, err = ntrurio.LoadBMatrixCoeffs(pth)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("load B: %w", err)
	}
	out := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		p := r.NewPoly()
		copy(p.Coeffs[0], coeffs[i])
		r.NTT(p, p)
		out[i] = p
	}
	return out, nil
}

// ApplyChallenge computes R0/R1 = center(R*H+RI*), carries K0/K1, and the
// live BB-tran target witness Z/T.
// Inputs M/K/R*H/RBar are coeff; RI* and B are public/NTT.
func ApplyChallenge(p *credential.Params, in Inputs, ch Challenge, omega []uint64) (*State, error) {
	log.Printf("[issuance] applying issuer challenge and hashing to target")
	in = normalizeInputs(in)
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	if len(ch.RI0) == 0 || len(ch.RI1) == 0 {
		return nil, fmt.Errorf("missing RI0/RI1")
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("missing omega")
	}
	r := p.RingQ
	bound := p.BoundB
	q := int64(r.Modulus[0])
	delta := int64(2*bound + 1)
	m := in.M[0]
	k := in.K[0]
	centered := func(v uint64) int64 {
		x := int64(v % uint64(q))
		if x > q/2 {
			x -= q
		}
		return x
	}
	sumCarryCoeff := func(holderPoly, issuerPoly *ring.Poly) (rPoly *ring.Poly, kPoly *ring.Poly, err error) {
		if holderPoly == nil || issuerPoly == nil {
			return nil, nil, fmt.Errorf("nil holder/issuer poly")
		}
		rPoly = r.NewPoly()
		kPoly = r.NewPoly()
		for i := 0; i < len(holderPoly.Coeffs[0]) && i < len(issuerPoly.Coeffs[0]); i++ {
			holderVal := centered(holderPoly.Coeffs[0][i])
			issuerVal := centered(issuerPoly.Coeffs[0][i])
			c, carry, cerr := credential.CenterWithCarry(holderVal+issuerVal, bound)
			if cerr != nil {
				return nil, nil, cerr
			}
			if c < 0 {
				rPoly.Coeffs[0][i] = uint64(c + q)
			} else {
				rPoly.Coeffs[0][i] = uint64(c)
			}
			if carry < 0 {
				kPoly.Coeffs[0][i] = uint64(carry + q)
			} else {
				kPoly.Coeffs[0][i] = uint64(carry)
			}
		}
		return rPoly, kPoly, nil
	}

	r0, k0, err := sumCarryCoeff(in.R0H[0], ch.RI0[0])
	if err != nil {
		return nil, err
	}
	r1, k1, err := sumCarryCoeff(in.R1H[0], ch.RI1[0])
	if err != nil {
		return nil, err
	}

	B, err := loadB(r, p.BPath)
	if err != nil {
		return nil, err
	}
	if len(B) != 4 {
		return nil, fmt.Errorf("B length=%d want 4", len(B))
	}
	relation := credential.NormalizeHashRelation(p.HashRelation)
	var zCoeff *ring.Poly
	var tCoeff []int64
	switch relation {
	case credential.HashRelationBBTran:
		zCoeff, tCoeff, err = credential.ComputeTarget(r, B, m, k, r0, r1)
		if err != nil {
			return nil, err
		}
	case credential.HashRelationBBS:
		tCoeff, err = credential.HashMessage(r, B, relation, m, k, r0, r1)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported hash relation %q", p.HashRelation)
	}

	log.Printf("[issuance] derived R0/R1, Z, and T; bound=%d delta=%d", bound, delta)
	state := &State{
		R0: rPolys(r0),
		R1: rPolys(r1),
		K0: rPolys(k0),
		K1: rPolys(k1),
		T:  tCoeff,
		B:  B,
	}
	if zCoeff != nil {
		state.Z = rPolys(zCoeff)
	}
	return state, nil
}

// ProvePreSign builds the credential pre-sign proof (π_t) with public T.
func ProvePreSign(p *credential.Params, ch Challenge, com commitment.Vector, in Inputs, st *State, opts PIOP.SimOpts) (*PIOP.Proof, error) {
	log.Printf("[issuance] building pre-sign proof (credential mode)")
	in = normalizeInputs(in)
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	pub := PIOP.PublicInputs{
		Com:          com,
		RI0:          ch.RI0,
		RI1:          ch.RI1,
		Ac:           p.Ac,
		B:            st.B,
		T:            st.T,
		BoundB:       p.BoundB,
		HashRelation: p.HashRelation,
	}
	wit := PIOP.WitnessInputs{
		M1:  in.M,
		M2:  in.K,
		RU0: in.R0H,
		RU1: in.R1H,
		R:   in.RBar,
		R0:  st.R0,
		R1:  st.R1,
		K0:  st.K0,
		K1:  st.K1,
		Z:   st.Z,
	}
	opts.Credential = true
	if opts.Theta == 0 {
		opts.Theta = 1
	}
	if opts.NCols == 0 {
		opts.NCols = p.RingQ.N
	}
	builder := PIOP.NewCredentialBuilder(opts)
	proof, err := builder.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		return nil, fmt.Errorf("build proof: %w", err)
	}
	rhoCount := proof.MaskRowCount
	if rhoCount <= 0 && proof.QOpening != nil {
		rhoCount = proof.QOpening.R
	}
	log.Printf("[issuance] pre-sign proof built (rho=%d, dQ=%d)", rhoCount, proof.MaskDegreeBound)
	return proof, nil
}

// VerifyPreSign verifies the credential pre-sign proof (π_t) with public T.
func VerifyPreSign(p *credential.Params, ch Challenge, com commitment.Vector, st *State, proof *PIOP.Proof, opts PIOP.SimOpts) (bool, error) {
	log.Printf("[issuance] verifying pre-sign proof")
	if p == nil || p.RingQ == nil {
		return false, fmt.Errorf("nil params or ring")
	}
	pub := PIOP.PublicInputs{
		Com:          com,
		RI0:          ch.RI0,
		RI1:          ch.RI1,
		Ac:           p.Ac,
		B:            st.B,
		T:            st.T,
		BoundB:       p.BoundB,
		HashRelation: p.HashRelation,
	}
	opts.Credential = true
	builder := PIOP.NewCredentialBuilder(opts)
	ok, err := builder.Verify(pub, proof)
	if err != nil {
		return false, fmt.Errorf("verify: %w", err)
	}
	return ok, nil
}

// SignTargetAndSave signs the provided target coefficients using the stored
// NTRU trapdoor and persists the signature to ./ntru_keys/signature.json.
// maxTrials/opts let callers tune the sampler; defaults are applied when zero.
func SignTargetAndSave(t []int64, maxTrials int, opts ntru.SamplerOpts) (*keys.Signature, error) {
	log.Printf("[issuance] signing target (len=%d) with NTRU trapdoor", len(t))
	if maxTrials == 0 {
		maxTrials = 2048
	}
	if opts.Prec == 0 {
		opts.Prec = 256
	}
	sig, err := signverify.SignTarget(t, maxTrials, opts)
	if err != nil {
		return nil, fmt.Errorf("sign target: %w", err)
	}
	if err := keys.Save(sig); err != nil {
		return nil, fmt.Errorf("save signature: %w", err)
	}
	log.Printf("[issuance] signature saved to ./ntru_keys/signature.json (trials_used=%d rejected=%v)", sig.Signature.TrialsUsed, sig.Signature.Rejected)
	return sig, nil
}

func sampleBoundedHeadNTT(r *ring.Ring, ncols int, bound int64, rng *rand.Rand) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	if ncols <= 0 || ncols > len(pNTT.Coeffs[0]) {
		ncols = len(pNTT.Coeffs[0])
	}
	mod := 2*bound + 1
	for i := 0; i < ncols; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			pNTT.Coeffs[0][i] = uint64(v + q)
		} else {
			pNTT.Coeffs[0][i] = uint64(v)
		}
	}
	return pNTT
}

func thetaPolyFromPublicHead(r *ring.Ring, pNTT *ring.Poly, omega []uint64) *ring.Poly {
	head := append([]uint64(nil), pNTT.Coeffs[0][:len(omega)]...)
	coeffs := PIOP.Interpolate(omega, head, r.Modulus[0])
	out := r.NewPoly()
	copy(out.Coeffs[0], coeffs)
	r.NTT(out, out)
	return out
}

// rPolys wraps a single poly into a slice (for WitnessInputs convenience).
func rPolys(p *ring.Poly) []*ring.Poly {
	return []*ring.Poly{p}
}
