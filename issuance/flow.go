package issuance

import (
	"fmt"
	"log"
	"math/rand"

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
	Mu   []*ring.Poly
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
	return SampleChallengeVector(r, omega, 1, bound, bound, rng)
}

func SampleChallengeVector(r *ring.Ring, omega []uint64, x0Len int, x0Bound int64, r1Bound int64, rng *rand.Rand) (Challenge, error) {
	if r == nil {
		return Challenge{}, fmt.Errorf("nil ring")
	}
	if len(omega) == 0 {
		return Challenge{}, fmt.Errorf("empty omega")
	}
	if rng == nil {
		return Challenge{}, fmt.Errorf("nil rng")
	}
	if x0Len <= 0 {
		return Challenge{}, fmt.Errorf("invalid x0Len=%d", x0Len)
	}
	if x0Bound <= 0 || r1Bound <= 0 {
		return Challenge{}, fmt.Errorf("invalid x0/r1 bounds %d/%d", x0Bound, r1Bound)
	}
	ri0 := make([]*ring.Poly, x0Len)
	for i := range ri0 {
		ri0[i] = sampleBoundedHeadNTT(r, len(omega), x0Bound, rng)
	}
	return Challenge{
		RI0: ri0,
		RI1: []*ring.Poly{sampleBoundedHeadNTT(r, len(omega), r1Bound, rng)},
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
	if len(in.Mu) == 0 && (len(in.M) > 0 || len(in.M1) > 0) {
		m := in.M
		if len(m) == 0 {
			m = in.M1
		}
		k := in.K
		if len(k) == 0 {
			k = in.M2
		}
		if len(m) > 0 && len(k) > 0 && m[0] != nil && k[0] != nil {
			mu := &ring.Poly{Coeffs: make([][]uint64, len(m[0].Coeffs))}
			for level := range m[0].Coeffs {
				mu.Coeffs[level] = append([]uint64(nil), m[0].Coeffs[level]...)
				if level < len(k[0].Coeffs) {
					for i := range mu.Coeffs[level] {
						if i < len(k[0].Coeffs[level]) {
							mu.Coeffs[level][i] += k[0].Coeffs[level][i]
						}
					}
				}
			}
			in.Mu = []*ring.Poly{mu}
		}
	}
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
	first := func(rows []*ring.Poly) *ring.Poly {
		if len(rows) == 0 {
			return nil
		}
		return rows[0]
	}
	toNTT := func(src *ring.Poly, name string) (*ring.Poly, error) {
		if src == nil {
			return nil, fmt.Errorf("nil %s", name)
		}
		out := p.RingQ.NewPoly()
		ring.Copy(src, out)
		p.RingQ.NTT(out, out)
		return out, nil
	}
	vec := make(commitment.Vector, 0, 1+len(in.R0H)+2)
	muNTT, err := toNTT(first(in.Mu), "mu")
	if err != nil {
		return nil, err
	}
	vec = append(vec, muNTT)
	for i, row := range in.R0H {
		rowNTT, err := toNTT(row, fmt.Sprintf("r0h[%d]", i))
		if err != nil {
			return nil, err
		}
		vec = append(vec, rowNTT)
	}
	r1hNTT, err := toNTT(first(in.R1H), "r1h")
	if err != nil {
		return nil, err
	}
	rbarNTT, err := toNTT(first(in.RBar), "rbar")
	if err != nil {
		return nil, err
	}
	vec = append(vec, r1hNTT, rbarNTT)
	com, err := commitment.Commit(p.RingQ, p.Ac, vec)
	if err != nil {
		return nil, err
	}
	log.Printf("[issuance] commitment computed with %d outputs", len(com))
	return com, nil
}

// loadB loads the B-matrix from the configured path and lifts to NTT.
func loadB(r *ring.Ring, path string, x0Len int, targetDim int) ([]*ring.Poly, error) {
	meta, err := ntrurio.LoadBMatrixMetadata(path)
	if err != nil {
		alt := []string{
			"Parameters/Bmatrix.json",
			"../Parameters/Bmatrix.json",
			"../../Parameters/Bmatrix.json",
		}
		for _, pth := range alt {
			meta, err = ntrurio.LoadBMatrixMetadata(pth)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("load B: %w", err)
	}
	if meta.TargetDim != targetDim {
		return nil, fmt.Errorf("B target_dim=%d want %d", meta.TargetDim, targetDim)
	}
	if meta.X0Len != x0Len {
		return nil, fmt.Errorf("B x0_len=%d want %d", meta.X0Len, x0Len)
	}
	coeffs := meta.B
	out := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		if len(coeffs[i]) != int(r.N) {
			return nil, fmt.Errorf("B[%d] coefficient length=%d want ring_degree=%d", i, len(coeffs[i]), r.N)
		}
		p := r.NewPoly()
		copy(p.Coeffs[0], coeffs[i])
		r.NTT(p, p)
		out[i] = p
	}
	return out, nil
}

// ApplyChallenge computes R0/R1 = center(R*H+RI*), carries K0/K1, and the
// live BB-tran target witness Z/T.
// Inputs Mu/R*H/RBar are coeff; RI* and B are public/NTT.
func ApplyChallenge(p *credential.Params, in Inputs, ch Challenge, omega []uint64) (*State, error) {
	log.Printf("[issuance] applying issuer challenge and hashing to target")
	in = normalizeInputs(in)
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	if len(ch.RI0) == 0 || len(ch.RI1) == 0 {
		return nil, fmt.Errorf("missing RI0/RI1")
	}
	if len(ch.RI0) != p.X0Len {
		return nil, fmt.Errorf("RI0 length=%d want %d", len(ch.RI0), p.X0Len)
	}
	if len(in.R0H) != p.X0Len {
		return nil, fmt.Errorf("R0H length=%d want %d", len(in.R0H), p.X0Len)
	}
	if len(omega) == 0 {
		return nil, fmt.Errorf("missing omega")
	}
	r := p.RingQ
	r0Bound := p.X0CoeffBound
	r1Bound := p.BoundB
	q := int64(r.Modulus[0])
	if len(in.Mu) == 0 || in.Mu[0] == nil {
		return nil, fmt.Errorf("missing mu input")
	}
	mu := in.Mu[0]
	centered := func(v uint64) int64 {
		x := int64(v % uint64(q))
		if x > q/2 {
			x -= q
		}
		return x
	}
	sumCarryCoeff := func(holderPoly, issuerPoly *ring.Poly, bound int64) (rPoly *ring.Poly, kPoly *ring.Poly, err error) {
		if holderPoly == nil || issuerPoly == nil {
			return nil, nil, fmt.Errorf("nil holder/issuer poly")
		}
		holderHead := headFromCoeffPoly(r, holderPoly, omega)
		if len(holderHead) == 0 {
			return nil, nil, fmt.Errorf("empty holder head")
		}
		issuerHead := append([]uint64(nil), issuerPoly.Coeffs[0][:len(omega)]...)
		rHead := make([]uint64, len(omega))
		kHead := make([]uint64, len(omega))
		for i := 0; i < len(omega); i++ {
			holderVal := centered(holderHead[i])
			issuerVal := centered(issuerHead[i])
			c, carry, cerr := credential.CenterWithCarry(holderVal+issuerVal, bound)
			if cerr != nil {
				return nil, nil, cerr
			}
			if c < 0 {
				rHead[i] = uint64(c + q)
			} else {
				rHead[i] = uint64(c)
			}
			if carry < 0 {
				kHead[i] = uint64(carry + q)
			} else {
				kHead[i] = uint64(carry)
			}
		}
		return coeffPolyFromHead(r, rHead, omega), coeffPolyFromHead(r, kHead, omega), nil
	}

	r0 := make([]*ring.Poly, p.X0Len)
	k0 := make([]*ring.Poly, p.X0Len)
	var err error
	for i := 0; i < p.X0Len; i++ {
		r0[i], k0[i], err = sumCarryCoeff(in.R0H[i], ch.RI0[i], r0Bound)
		if err != nil {
			return nil, err
		}
	}
	r1, k1, err := sumCarryCoeff(in.R1H[0], ch.RI1[0], r1Bound)
	if err != nil {
		return nil, err
	}

	B, err := loadB(r, p.BPath, p.X0Len, p.TargetDim)
	if err != nil {
		return nil, err
	}
	relation := credential.NormalizeHashRelation(p.HashRelation)
	var zCoeff *ring.Poly
	var tCoeff []int64
	switch relation {
	case credential.HashRelationBBTran:
		if p.TargetDim != 1 {
			return nil, fmt.Errorf("unsupported TargetDim=%d", p.TargetDim)
		}
		zCoeff, tCoeff, err = credential.ComputeTargetVectorFromMu(r, B, mu, r0, r1)
		if err != nil {
			return nil, err
		}
		tPoly := r.NewPoly()
		for i := 0; i < len(tCoeff) && i < len(tPoly.Coeffs[0]); i++ {
			v := tCoeff[i] % q
			if v < 0 {
				v += q
			}
			tPoly.Coeffs[0][i] = uint64(v)
		}
		if err := credential.VerifyTargetRelationVectorFromMu(r, B, mu, r0, r1, zCoeff, tPoly); err != nil {
			return nil, fmt.Errorf("internal target relation check failed: %w", err)
		}
	case credential.HashRelationBBS:
		if len(r0) != 1 {
			return nil, fmt.Errorf("bbs only supports scalar x0")
		}
		tCoeff, err = credential.HashMessageVectorFromMu(r, B, relation, mu, r0, r1)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported hash relation %q", p.HashRelation)
	}

	log.Printf("[issuance] derived R0/R1, Z, and T; x0_len=%d x0_bound=%d r1_bound=%d", p.X0Len, r0Bound, r1Bound)
	state := &State{
		R0: r0,
		R1: rPolys(r1),
		K0: k0,
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
		Com:                com,
		RI0:                ch.RI0,
		RI1:                ch.RI1,
		Ac:                 p.Ac,
		B:                  st.B,
		T:                  st.T,
		BoundB:             p.BoundB,
		X0Len:              p.X0Len,
		X0CoeffBound:       p.X0CoeffBound,
		TargetDim:          p.TargetDim,
		TargetHidingLambda: p.TargetHidingLambda,
		RingDegree:         int(p.RingQ.N),
		HashRelation:       p.HashRelation,
	}
	wit := PIOP.WitnessInputs{
		Mu:  in.Mu,
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
		Com:                com,
		RI0:                ch.RI0,
		RI1:                ch.RI1,
		Ac:                 p.Ac,
		B:                  st.B,
		T:                  st.T,
		BoundB:             p.BoundB,
		X0Len:              p.X0Len,
		X0CoeffBound:       p.X0CoeffBound,
		TargetDim:          p.TargetDim,
		TargetHidingLambda: p.TargetHidingLambda,
		RingDegree:         int(p.RingQ.N),
		HashRelation:       p.HashRelation,
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
	return SignTargetAndSaveWithPaths(t, maxTrials, opts, signverify.SignPaths{})
}

func SignTargetAndSaveWithPaths(t []int64, maxTrials int, opts ntru.SamplerOpts, paths signverify.SignPaths) (*keys.Signature, error) {
	log.Printf("[issuance] signing target (len=%d) with NTRU trapdoor", len(t))
	if maxTrials == 0 {
		maxTrials = 2048
	}
	if opts.Prec == 0 {
		opts.Prec = 256
	}
	sig, err := signTargetWithinBetaWithPaths(t, maxTrials, opts, 16, paths)
	if err != nil {
		return nil, fmt.Errorf("sign target: %w", err)
	}
	signaturePath := paths.SignaturePath
	if signaturePath == "" {
		if err := keys.Save(sig); err != nil {
			return nil, fmt.Errorf("save signature: %w", err)
		}
		signaturePath = "./ntru_keys/signature.json"
	} else if err := keys.SaveSignatureFile(signaturePath, sig); err != nil {
		return nil, fmt.Errorf("save signature: %w", err)
	}
	log.Printf("[issuance] signature saved to %s (trials_used=%d rejected=%v)", signaturePath, sig.Signature.TrialsUsed, sig.Signature.Rejected)
	return sig, nil
}

func signTargetWithinBeta(t []int64, maxTrials int, opts ntru.SamplerOpts, attempts int) (*keys.Signature, error) {
	return signTargetWithinBetaWithPaths(t, maxTrials, opts, attempts, signverify.SignPaths{})
}

func signTargetWithinBetaWithPaths(t []int64, maxTrials int, opts ntru.SamplerOpts, attempts int, paths signverify.SignPaths) (*keys.Signature, error) {
	if attempts <= 0 {
		attempts = 1
	}
	paramsPath := paths.ParamsPath
	if paramsPath == "" {
		paramsPath = "Parameters/Parameters.json"
	}
	par, err := ntrurio.LoadParams(paramsPath, true)
	if err != nil {
		return nil, fmt.Errorf("load signature bound: %w", err)
	}
	if par.N != len(t) {
		return nil, fmt.Errorf("signature params N=%d incompatible with target length=%d", par.N, len(t))
	}
	var lastMax int64
	for attempt := 1; attempt <= attempts; attempt++ {
		sig, err := signverify.SignTargetWithPaths(t, maxTrials, opts, paths)
		if err != nil {
			return nil, err
		}
		lastMax = signatureLInf(sig)
		if uint64(lastMax) <= par.Beta {
			return sig, nil
		}
		log.Printf("[issuance] retrying target signature: max coefficient %d exceeds beta=%d (attempt %d/%d)", lastMax, par.Beta, attempt, attempts)
	}
	return nil, fmt.Errorf("signature shortness blocker after %d attempts: max coefficient %d exceeds beta=%d under q=%d", attempts, lastMax, par.Beta, par.Q)
}

func signatureLInf(sig *keys.Signature) int64 {
	if sig == nil {
		return 0
	}
	maxAbs := int64(0)
	for _, row := range [][]int64{sig.Signature.S1, sig.Signature.S2} {
		for _, v := range row {
			if v < 0 {
				v = -v
			}
			if v > maxAbs {
				maxAbs = v
			}
		}
	}
	return maxAbs
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
