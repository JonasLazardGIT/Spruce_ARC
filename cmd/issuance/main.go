package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/domain"
	"vSIS-Signature/issuance"
	"vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func main() {
	skipPresign := flag.Bool("skip-presign", false, "skip pre-sign proof generation/verification")
	seed := flag.Int64("seed", 1, "fixture RNG seed (default=1)")
	flag.Parse()

	log.Println("[issuance-cli] starting issuance demo")
	log.Printf("[issuance-cli] fixture seed=%d", *seed)

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		log.Fatalf("load ring: %v", err)
	}
	bound := int64(8)
	opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential: true,
		Theta:      1,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		Ell:        18,
		Eta:        19,
		DomainMode: PIOP.DomainModeExplicit,
		NLeaves:    2048,
	})
	prfParams, err := prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	if err != nil {
		log.Fatalf("load prf params: %v", err)
	}
	if opts.NCols < 2*prfParams.LenKey {
		opts.NCols = 2 * prfParams.LenKey
	}
	if opts.NCols%2 != 0 {
		opts.NCols++
	}
	opts.ShowingPreset = PIOP.ShowingPresetCustom
	opts.NLeaves = 4096
	opts.LVCSNCols = 96
	opts.PostSignLVCSNCols = opts.LVCSNCols
	opts.PRFLVCSNCols = opts.LVCSNCols
	lenM1, lenM2, lenRU0, lenRU1, lenR := 1, 1, 1, 1, 1
	cols := lenM1 + lenM2 + lenRU0 + lenRU1 + lenR
	sampleMatrix := func() [][]*ring.Poly {
		mat := make([][]*ring.Poly, cols)
		for i := 0; i < cols; i++ {
			mat[i] = make([]*ring.Poly, cols)
			for j := 0; j < cols; j++ {
				if i == j {
					mat[i][j] = polyConstNTT(ringQ, 1)
					continue
				}
				mat[i][j] = ringQ.NewPoly()
			}
		}
		return mat
	}
	Ac := sampleMatrix()
	if err := saveAcJSON("credential/Ac.json", ringQ, Ac); err != nil {
		log.Printf("[issuance-cli] warning: could not save Ac.json: %v", err)
	}
	if err := saveParamsJSON("credential/params.json", "credential/Ac.json", "Parameters/Bmatrix.json", bound, lenM1, lenM2, lenRU0, lenRU1, lenR); err != nil {
		log.Printf("[issuance-cli] warning: could not save params.json: %v", err)
	}
	params := &credential.Params{
		Ac:     Ac,
		BPath:  "Parameters/Bmatrix.json",
		AcPath: "credential/Ac.json",
		BoundB: bound,
		RingQ:  ringQ,
		LenM1:  lenM1,
		LenM2:  lenM2,
		LenRU0: lenRU0,
		LenRU1: lenRU1,
		LenR:   lenR,
	}

	omega, err := deriveOmegaForIssuanceOpts(ringQ, opts)
	if err != nil {
		log.Fatalf("derive omega: %v", err)
	}
	// Keep fixture rows in the low alphabet for every explicit-domain Ω by
	// sampling the zero polynomial (0 is in {-4..3}) for all non-sign rows.
	m1 := ringQ.NewPoly()
	m2 := ringQ.NewPoly()
	ru0 := ringQ.NewPoly()
	ru1 := ringQ.NewPoly()
	rPoly := ringQ.NewPoly()
	ch := issuance.Challenge{
		RI0: []*ring.Poly{ringQ.NewPoly()},
		RI1: []*ring.Poly{ringQ.NewPoly()},
	}

	inputs := issuance.Inputs{
		M1:  []*ring.Poly{m1},
		M2:  []*ring.Poly{m2},
		RU0: []*ring.Poly{ru0},
		RU1: []*ring.Poly{ru1},
		R:   []*ring.Poly{rPoly},
	}
	com, err := issuance.PrepareCommit(params, inputs, omega)
	if err != nil {
		log.Fatalf("prepare commit: %v", err)
	}
	log.Printf("[issuance-cli] Com rows=%d", len(com))

	state, err := issuance.ApplyChallenge(params, inputs, ch, omega)
	if err != nil {
		log.Fatalf("apply challenge: %v", err)
	}
	log.Printf("[issuance-cli] T[0]=%d", state.T[0])

	if *skipPresign {
		log.Printf("[issuance-cli] skipping pre-sign proof generation/verification")
	} else {
		proofStart := time.Now()
		proof, err := issuance.ProvePreSign(params, ch, com, inputs, state, opts)
		if err != nil {
			log.Fatalf("prove pre-sign: %v", err)
		}
		proofDur := time.Since(proofStart)

		verifyStart := time.Now()
		ok, err := issuance.VerifyPreSign(params, ch, com, state, proof, opts)
		verifyDur := time.Since(verifyStart)
		if err != nil || !ok {
			log.Fatalf("verify pre-sign failed: ok=%v err=%v", ok, err)
		}
		rhoCount := proof.MaskRowCount
		if rhoCount <= 0 && proof.QOpening != nil {
			rhoCount = proof.QOpening.R
		}
		log.Printf("[issuance-cli] pre-sign proof verified; rho=%d", rhoCount)
		printWitnessRowBreakdown("[issuance-cli] ", inputs, state, opts.Rho)
		printProofReport("[issuance-cli] ", proof, opts, ringQ, proofDur, verifyDur)
		printTranscriptBreakdown("[issuance-cli] ", proof)
	}

	sig, err := issuance.SignTargetAndSave(state.T, 2048, ntru.SamplerOpts{})
	if err != nil {
		log.Fatalf("sign target: %v", err)
	}
	par, err := ntrurio.LoadParams(filepath.Join("Parameters", "Parameters.json"), true)
	if err != nil {
		log.Fatalf("load signature bound: %v", err)
	}
	sigState := credential.State{
		SigS1: append([]int64(nil), sig.Signature.S1...),
		SigS2: append([]int64(nil), sig.Signature.S2...),
	}
	_, _, maxSig := sigState.SignatureCoordLinf()
	if uint64(maxSig) > par.Beta {
		log.Fatalf("signature shortness blocker: max(|s1|,|s2|)=%d exceeds beta=%d under q=%d", maxSig, par.Beta, par.Q)
	}
	log.Printf("[issuance-cli] signature trials_used=%d rejected=%v", sig.Signature.TrialsUsed, sig.Signature.Rejected)

	if err := copySignature("ntru_keys/signature.json", "credential/keys/signature.json"); err != nil {
		log.Printf("[issuance-cli] warning: copy signature to credential/keys failed: %v", err)
	} else {
		log.Printf("[issuance-cli] signature copied to credential/keys/signature.json")
	}

	if err := saveCredentialState(params, inputs, state, ch, sig, opts.NCols, "credential/keys/credential_state.json"); err != nil {
		log.Printf("[issuance-cli] warning: save credential state failed: %v", err)
	} else {
		log.Printf("[issuance-cli] credential state saved to credential/keys/credential_state.json")
	}
	_ = copyFile("ntru_keys/public.json", "credential/ntru_keys/public.json")
	_ = copyFile("ntru_keys/private.json", "credential/ntru_keys/private.json")

	fmt.Println("[issuance-cli] done")
}

func copySignature(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func polyConstNTT(r *ring.Ring, v int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	var coeff uint64
	if v >= 0 {
		coeff = uint64(v % q)
	} else {
		coeff = uint64((v+q)%q) % uint64(q)
	}
	for i := 0; i < r.N; i++ {
		p.Coeffs[0][i] = coeff
	}
	return p
}

func printProofReport(prefix string, proof *PIOP.Proof, opts PIOP.SimOpts, ringQ *ring.Ring, proveDur, verifyDur time.Duration) {
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		log.Printf("%sreport: %v", prefix, err)
		return
	}
	fmt.Printf("%sProof size≈%.2f KB (%.0f bytes)\n", prefix, rep.ProofKB, float64(rep.ProofBytes))
	fmt.Printf("%sProver time≈%s\n", prefix, proveDur)
	fmt.Printf("%sVerifier time≈%s\n", prefix, verifyDur)
	fmt.Printf("%sSoundness Eq.(8): eps1=%.2f eps2=%.2f eps3=%.2f eps4=%.2f eq8_total=%.2f\n",
		prefix,
		rep.Soundness.Bits[0], rep.Soundness.Bits[1], rep.Soundness.Bits[2], rep.Soundness.Bits[3],
		displayBits(rep.Soundness.Eq8TotalBits))
	fmt.Printf("%sSoundness Thm.9: collision=%.2f round={%.2f,%.2f,%.2f,%.2f} total=%.2f qcaps=%v\n",
		prefix,
		rep.Soundness.CollisionBits,
		rep.Soundness.TheoremBits[0], rep.Soundness.TheoremBits[1], rep.Soundness.TheoremBits[2], rep.Soundness.TheoremBits[3],
		displayBits(rep.Soundness.TotalBits),
		rep.Soundness.QueryCaps)
	fmt.Printf("%sParams: NCols=%d pcs_ncols=%d ddecs=%d ℓ=%d ℓ'=%d ρ=%d θ=%d η=%d dQ=%d collision_bits=%d\n",
		prefix, rep.NCols, rep.PCSNCols, rep.Soundness.DDECS, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta, rep.DQ, rep.Soundness.CollisionSpaceBits)
	fmt.Printf("%sTable row: %.2f %.3f %.2f %d %d %d %d %d %d\n",
		prefix, rep.ProofKB, proveDur.Seconds(), rep.Soundness.TotalBits,
		rep.NCols, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta)
}

func displayBits(bits float64) float64 {
	if math.Abs(bits) < 0.005 {
		return 0
	}
	return bits
}

func printWitnessRowBreakdown(prefix string, in issuance.Inputs, st *issuance.State, maskRows int) {
	base := 0
	if len(in.M1) > 0 {
		base++
	}
	if len(in.M2) > 0 {
		base++
	}
	if len(in.RU0) > 0 {
		base++
	}
	if len(in.RU1) > 0 {
		base++
	}
	if len(in.R) > 0 {
		base++
	}
	if st != nil {
		if len(st.R0) > 0 {
			base++
		}
		if len(st.R1) > 0 {
			base++
		}
		if len(st.K0) > 0 {
			base++
		}
		if len(st.K1) > 0 {
			base++
		}
	}
	if base == 0 {
		log.Printf("%sno witness rows (base=0)", prefix)
		return
	}
	log.Printf("%sWitness rows: base=%d (100.0%%), prf=0 (0.0%%), total=%d, mask=%d",
		prefix, base, base, maskRows)
}

func printTranscriptBreakdown(prefix string, proof *PIOP.Proof) {
	if proof == nil {
		return
	}
	rep := PIOP.MeasureProofSize(proof)
	if rep.Total == 0 {
		log.Printf("%sproof size breakdown unavailable (total=0)", prefix)
		return
	}
	keys := make([]string, 0, len(rep.Parts))
	for k := range rep.Parts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return rep.Parts[keys[i]] > rep.Parts[keys[j]] })
	log.Printf("%sTranscript size breakdown (bytes, percent of total=%d):", prefix, rep.Total)
	for _, k := range keys {
		v := rep.Parts[k]
		pct := 100.0 * float64(v) / float64(rep.Total)
		log.Printf("%s  %-14s %8d  (%5.1f%%)", prefix, k, v, pct)
	}
}

// saveCredentialState serializes holder secrets, public challenge, and signature to JSON.
func saveCredentialState(
	p *credential.Params,
	in issuance.Inputs,
	st *issuance.State,
	ch issuance.Challenge,
	sig *keys.Signature,
	packedNCols int,
	path string,
) error {
	if p == nil || st == nil {
		return fmt.Errorf("nil params/state")
	}
	r := p.RingQ
	toCoeff := func(poly *ring.Poly) *ring.Poly {
		cp := r.NewPoly()
		ring.Copy(poly, cp)
		return cp
	}
	nttToCoeff := func(poly *ring.Poly) *ring.Poly {
		cp := r.NewPoly()
		ring.Copy(poly, cp)
		r.InvNTT(cp, cp)
		return cp
	}
	polyVec := func(vec []*ring.Poly, ntt bool) [][]int64 {
		out := make([][]int64, len(vec))
		for i, p := range vec {
			if ntt {
				p = nttToCoeff(p)
			} else {
				p = toCoeff(p)
			}
			out[i] = polyToInt64Local(p, r)
		}
		return out
	}
	state := credential.State{
		M1:            polyVec(in.M1, false),
		M2:            polyVec(in.M2, false),
		RU0:           polyVec(in.RU0, false),
		RU1:           polyVec(in.RU1, false),
		R:             polyVec(in.R, false),
		R0:            polyVec(st.R0, false),
		R1:            polyVec(st.R1, false),
		K0:            polyVec(st.K0, false),
		K1:            polyVec(st.K1, false),
		T:             st.T,
		Com:           polyVec(st.Com, true),
		RI0:           polyVec(ch.RI0, true),
		RI1:           polyVec(ch.RI1, true),
		BPath:         p.BPath,
		AcPath:        p.AcPath,
		PRFParamsPath: filepath.Join("prf", "prf_params.json"),
		PackedNCols:   packedNCols,
		B:             polyVec(st.B, true),
		Ac:            matrixToInt64Local(p.Ac, r),
	}
	// If signature is present, persist showing-signature rows (s1,s2).
	// Showing-time coefficient bounds are enforced on s1/s2.
	if sig != nil {
		if len(sig.Signature.S1) > 0 {
			state.SigS1 = append([]int64(nil), sig.Signature.S1...)
		}
		if len(sig.Signature.S2) > 0 {
			state.SigS2 = append([]int64(nil), sig.Signature.S2...)
		}
	}
	// Embed NTRU keys if available.
	if pub, err := loadKeyCoeffs("ntru_keys/public.json"); err == nil {
		state.NTRUPublic = pub
	}
	if priv, err := loadKeyCoeffs("ntru_keys/private.json"); err == nil {
		state.NTRUPrivate = priv
	}
	// Persist JSON.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return credential.SaveState(path, r, state)
}

func matrixToInt64Local(mat [][]*ring.Poly, ringQ *ring.Ring) [][][]int64 {
	if len(mat) == 0 {
		return nil
	}
	rows := len(mat)
	out := make([][][]int64, rows)
	for i := 0; i < rows; i++ {
		out[i] = make([][]int64, len(mat[i]))
		for j := range mat[i] {
			cp := ringQ.NewPoly()
			ring.Copy(mat[i][j], cp)
			ringQ.InvNTT(cp, cp)
			out[i][j] = polyToInt64Local(cp, ringQ)
		}
	}
	return out
}

// polyToInt64Local converts poly coeffs to centered int64.
func polyToInt64Local(p *ring.Poly, ringQ *ring.Ring) []int64 {
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

// saveParamsJSON writes params.json pointing to Ac/B and lengths.
func saveParamsJSON(path, acPath, bPath string, bound int64, lenM1, lenM2, lenRU0, lenRU1, lenR int) error {
	type paramsFile struct {
		AcPath string `json:"AcPath"`
		BPath  string `json:"BPath"`
		BoundB int64  `json:"BoundB"`
		LenM1  int    `json:"LenM1"`
		LenM2  int    `json:"LenM2"`
		LenRU0 int    `json:"LenRU0"`
		LenRU1 int    `json:"LenRU1"`
		LenR   int    `json:"LenR"`
	}
	pf := paramsFile{
		AcPath: acPath,
		BPath:  bPath,
		BoundB: bound,
		LenM1:  lenM1,
		LenM2:  lenM2,
		LenRU0: lenRU0,
		LenRU1: lenRU1,
		LenR:   lenR,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// saveAcJSON writes Ac (NTT) into coeff-domain JSON for reuse.
func saveAcJSON(path string, ringQ *ring.Ring, Ac [][]*ring.Poly) error {
	if len(Ac) == 0 {
		return fmt.Errorf("empty Ac")
	}
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	rows := len(Ac)
	cols := len(Ac[0])
	acOut := make([][][]uint64, rows)
	for i := 0; i < rows; i++ {
		acOut[i] = make([][]uint64, cols)
		for j := 0; j < cols; j++ {
			cp := ringQ.NewPoly()
			ring.Copy(Ac[i][j], cp)
			ringQ.InvNTT(cp, cp)
			acOut[i][j] = make([]uint64, len(cp.Coeffs[0]))
			copy(acOut[i][j], cp.Coeffs[0])
		}
	}
	type acJSON struct {
		Ac [][][]uint64 `json:"Ac"`
	}
	payload := acJSON{Ac: acOut}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// sampleAlphabetEval samples evaluation-domain head values from the provided alphabet
// over Ω and interpolates them into coefficient form.
func sampleAlphabetEval(r *ring.Ring, alphabet []int64, omega []uint64, rng *rand.Rand) *ring.Poly {
	head := sampleAlphabetHead(alphabet, len(omega), rng, r.Modulus[0])
	pNTT := PIOP.BuildThetaPrime(r, head, omega)
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

// samplePackedHalfAlphabetEval zeros the disallowed half over the first ncols eval points and
// samples the allowed half from the provided alphabet on Ω.
func samplePackedHalfAlphabetEval(r *ring.Ring, alphabet []int64, omega []uint64, rng *rand.Rand, keepLower bool) *ring.Poly {
	ncols := len(omega)
	head := sampleAlphabetHead(alphabet, ncols, rng, r.Modulus[0])
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	half := ncols / 2
	if keepLower {
		for i := half; i < ncols; i++ {
			head[i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			head[i] = 0
		}
	}
	pNTT := PIOP.BuildThetaPrime(r, head, omega)
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func sampleAlphabetHead(alphabet []int64, ncols int, rng *rand.Rand, q uint64) []uint64 {
	if ncols <= 0 {
		return nil
	}
	head := make([]uint64, ncols)
	if len(alphabet) == 0 {
		return head
	}
	for i := 0; i < ncols; i++ {
		v := alphabet[rng.Intn(len(alphabet))]
		if v < 0 {
			head[i] = uint64(int64(q) + v)
		} else {
			head[i] = uint64(v)
		}
	}
	return head
}

// loadKeyCoeffs is a no-op stub: NTRU key embedding skipped in this demo.
func loadKeyCoeffs(path string) ([][]int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lower := strings.ToLower(path)
	if strings.Contains(lower, "public") {
		var pk keys.PublicKey
		if err := json.Unmarshal(data, &pk); err != nil {
			return nil, err
		}
		if len(pk.HCoeffs) == 0 {
			return nil, fmt.Errorf("public key missing h_coeffs")
		}
		return [][]int64{pk.HCoeffs}, nil
	}
	var sk keys.PrivateKey
	if err := json.Unmarshal(data, &sk); err != nil {
		return nil, err
	}
	var out [][]int64
	if len(sk.F) > 0 {
		out = append(out, sk.F)
	}
	if len(sk.G) > 0 {
		out = append(out, sk.G)
	}
	if len(sk.Fsmall) > 0 {
		out = append(out, sk.Fsmall)
	}
	if len(sk.Gsmall) > 0 {
		out = append(out, sk.Gsmall)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("private key has no coefficient data")
	}
	return out, nil
}

func deriveOmegaForIssuanceOpts(ringQ *ring.Ring, opts PIOP.SimOpts) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	ncols := opts.NCols
	if ncols <= 0 || ncols > ringQ.N {
		return nil, fmt.Errorf("invalid ncols=%d", ncols)
	}
	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}
	lvcsNCols := opts.LVCSNCols
	if lvcsNCols <= 0 {
		lvcsNCols = ncols
	}
	if lvcsNCols < ncols {
		return nil, fmt.Errorf("invalid lvcs ncols=%d < witness ncols=%d", lvcsNCols, ncols)
	}
	dom, err := domain.NewDomain(ringQ.Modulus[0], nLeaves, lvcsNCols, opts.Ell, nil)
	if err != nil {
		return nil, err
	}
	if len(dom.Omega) < ncols {
		return nil, fmt.Errorf("derived omega len=%d < witness ncols=%d", len(dom.Omega), ncols)
	}
	return append([]uint64(nil), dom.Omega[:ncols]...), nil
}
