package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/domain"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type lineCategory int

const (
	categoryStatus lineCategory = iota
	categorySoundness
	categoryGeometry
	categoryTranscript
	categoryWarning
)

const (
	ansiReset   = "\033[0m"
	ansiCyan    = "\033[36m"
	ansiYellow  = "\033[33m"
	ansiGreen   = "\033[32m"
	ansiMagenta = "\033[35m"
	ansiRed     = "\033[31m"
)

type cliRenderer struct {
	out          io.Writer
	err          io.Writer
	colorEnabled bool
}

var cli = newCLIRenderer(os.Stdout, os.Stderr)

func newCLIRenderer(out, err io.Writer) cliRenderer {
	return cliRenderer{
		out:          out,
		err:          err,
		colorEnabled: stdoutSupportsColor(),
	}
}

func stdoutSupportsColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	term := os.Getenv("TERM")
	if term == "" || term == "dumb" {
		return false
	}
	info, statErr := os.Stdout.Stat()
	if statErr != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func styleMessage(enabled bool, category lineCategory, msg string) string {
	if !enabled {
		return msg
	}
	return colorForCategory(category) + msg + ansiReset
}

func colorForCategory(category lineCategory) string {
	switch category {
	case categoryStatus:
		return ansiCyan
	case categorySoundness:
		return ansiYellow
	case categoryGeometry:
		return ansiGreen
	case categoryTranscript:
		return ansiMagenta
	case categoryWarning:
		return ansiRed
	default:
		return ""
	}
}

func (r cliRenderer) printf(category lineCategory, prefix, format string, args ...interface{}) {
	msg := prefix + fmt.Sprintf(format, args...)
	fmt.Fprintln(r.out, styleMessage(r.colorEnabled, category, msg))
}

func (r cliRenderer) errorf(prefix, format string, args ...interface{}) {
	msg := prefix + fmt.Sprintf(format, args...)
	fmt.Fprintln(r.err, styleMessage(r.colorEnabled, categoryWarning, msg))
}

func (r cliRenderer) fatalf(prefix, format string, args ...interface{}) {
	r.errorf(prefix, format, args...)
	os.Exit(1)
}

func main() {
	const (
		showingDefaultBoundB     = int64(8)
		productionPRFGroupRounds = 2
		productionTheta          = 6
		productionNCols          = 16
		productionLVCSNCols      = 24
		productionEll            = 18
		productionEta            = 31
		productionEllPrime       = 2
		productionRho            = 2
		productionNLeaves        = 2048
	)

	coeffModel := flag.String("coeff-model", "", "optional coeff-native post-sign model override (literal_packed_aggregated_v3 or literal_packed_aggregated_v4_split_prf)")
	flag.Parse()

	resolvedModel := *coeffModel
	if resolvedModel == "" {
		resolvedModel = PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3
	}
	splitDefaults := PIOP.DefaultShowingSplitGeometry()
	effectivePostLVCS := productionLVCSNCols
	effectivePostNLeaves := productionNLeaves
	effectivePRFLVCS := splitDefaults.PRFLVCSNCols
	effectivePRFNLeaves := splitDefaults.PRFNLeaves
	if resolvedModel == PIOP.CoeffNativeSigModelLiteralPackedAggregatedV4SplitPRF {
		effectivePostLVCS = splitDefaults.PostSignLVCSNCols
		effectivePostNLeaves = splitDefaults.PostSignNLeaves
	}

	if wd, err := os.Getwd(); err == nil {
		cli.printf(categoryStatus, "[showing-cli] ", "cwd=%s", wd)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "starting showing demo")
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		cli.fatalf("[showing-cli] ", "load ring: %v", err)
	}
	statePath := filepath.Join("credential", "keys", "credential_state.json")
	state, err := credential.LoadState(statePath)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load credential state: %v", err)
	}
	params, err := loadPRFParamsFromState(state)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load prf params: %v", err)
	}
	opts := PIOP.SimOpts{
		Credential:          true,
		Theta:               productionTheta,
		EllPrime:            productionEllPrime,
		Rho:                 productionRho,
		NCols:               productionNCols,
		Ell:                 productionEll,
		Eta:                 productionEta,
		DomainMode:          PIOP.DomainModeExplicit,
		NLeaves:             effectivePostNLeaves,
		PRFGroupRounds:      productionPRFGroupRounds,
		CoeffPacking:        true,
		CoeffNativeSigModel: resolvedModel,
		PostSignLVCSNCols:   effectivePostLVCS,
		PostSignNLeaves:     effectivePostNLeaves,
		PRFLVCSNCols:        effectivePRFLVCS,
		PRFNLeaves:          effectivePRFNLeaves,
	}
	cli.printf(categoryStatus, "[showing-cli] ", "production showing profile (ell=%d eta=%d ell'=%d rho=%d theta=%d ncols=%d lvcs_ncols=%d prf_group_rounds=%d)",
		opts.Ell, opts.Eta, opts.EllPrime, opts.Rho, opts.Theta, opts.NCols, effectivePostLVCS, opts.PRFGroupRounds)
	if opts.PRFGroupRounds <= 0 {
		cli.fatalf("[showing-cli] ", "invalid fixed PRFGroupRounds=%d", opts.PRFGroupRounds)
	}
	if opts.NCols < 2*params.LenKey {
		cli.fatalf("[showing-cli] ", "production NCols=%d is too small for PRF key width %d", opts.NCols, 2*params.LenKey)
	}
	if opts.NCols%2 != 0 {
		cli.fatalf("[showing-cli] ", "production NCols=%d must be even", opts.NCols)
	}
	opts.LVCSNCols = effectivePostLVCS
	if opts.LVCSNCols < opts.NCols {
		cli.fatalf("[showing-cli] ", "production LVCSNCols=%d must be >= NCols=%d", opts.LVCSNCols, opts.NCols)
	}
	// Clamp ℓ so grouped PRF degree stays below the ring degree.
	if opts.PRFGroupRounds > 1 {
		prfDeg, derr := prf.MaxConstraintDegreeGrouped(params, opts.PRFGroupRounds)
		if derr != nil {
			cli.fatalf("[showing-cli] ", "compute grouped PRF degree: %v", derr)
		}
		maxEll := maxEllForGroupedPRF(int(ringQ.N), opts.NCols, int(prfDeg))
		if maxEll <= 0 {
			cli.fatalf("[showing-cli] ", "invalid grouped PRF parameters: N=%d ncols=%d prfDeg=%d g=%d", ringQ.N, opts.NCols, prfDeg, opts.PRFGroupRounds)
		}
		if opts.Ell > maxEll {
			cli.printf(categoryWarning, "[showing-cli] ", "warning: clamping ℓ from %d to %d for PRFGroupRounds=%d (avoids degree wrap-around)", opts.Ell, maxEll, opts.PRFGroupRounds)
			opts.Ell = maxEll
		}
	}
	omega, err := deriveOmegaForOpts(ringQ, opts)
	if err != nil {
		cli.fatalf("[showing-cli] ", "derive omega: %v", err)
	}
	ncols := len(omega)

	// Build public matrices.
	B, err := loadBFromState(ringQ, state)
	if err != nil {
		cli.fatalf("[showing-cli] ", "load B: %v", err)
	}
	wit, err := buildWitnessFromState(ringQ, state)
	if err != nil {
		cli.fatalf("[showing-cli] ", "build witness: %v", err)
	}
	if wit.CoeffNativeShowing == nil {
		cli.fatalf("[showing-cli] ", "missing coeff-native showing witness in credential state")
	}
	A, err := buildSignatureMatrix(ringQ, state, showingSignatureComponentCount(wit))
	if err != nil {
		cli.fatalf("[showing-cli] ", "build A: %v", err)
	}

	// Active showing uses the semantic coeff-native PRF key witness directly.
	key, err := prfKeyFromSemanticWitness(wit.CoeffNativeShowing)
	if err != nil {
		cli.fatalf("[showing-cli] ", "prf key: %v", err)
	}
	nonce, noncePublic := sampleNonce(params.LenNonce, ncols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		cli.fatalf("[showing-cli] ", "prf tag: %v", err)
	}
	tagPublic := lanesFromElems(tag, ncols)

	x0, err := prf.ConcatKeyNonce(key, nonce, params)
	if err != nil {
		cli.fatalf("[showing-cli] ", "concat key/nonce: %v", err)
	}
	sboxes, _, err := prf.TraceSBoxOutputsGrouped(x0, params, opts.PRFGroupRounds)
	if err != nil {
		cli.fatalf("[showing-cli] ", "prf sbox trace: %v", err)
	}
	sboxRows := elemsToPolys(ringQ, sboxes)
	if wit.Extras == nil {
		wit.Extras = map[string]interface{}{}
	}
	wit.Extras["prf_sbox"] = sboxRows

	pub := PIOP.PublicInputs{
		A:      A,
		B:      B,
		Tag:    tagPublic,
		Nonce:  noncePublic,
		BoundB: showingDefaultBoundB,
	}

	cli.printf(categoryStatus, "[showing-cli] ", "building proof")
	proofStart := time.Now()
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		cli.fatalf("[showing-cli] ", "build showing: %v", err)
	}
	proofDur := time.Since(proofStart)

	verifyStart := time.Now()
	ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential)
	verifyDur := time.Since(verifyStart)
	if err != nil || !ok {
		cli.fatalf("[showing-cli] ", "verify showing failed: ok=%v err=%v", ok, err)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "showing proof verified")
	printLogicalWitnessRowBreakdown("[showing-cli] ", proof)
	printCommittedWitnessRowBreakdown("[showing-cli] ", proof)
	printProofReport("[showing-cli] ", proof, opts, pub.BoundB, ringQ, proofDur, verifyDur)
}

func maxEllForGroupedPRF(ringN, ncols, prfDegree int) int {
	if ringN <= 0 || ncols <= 0 || prfDegree <= 1 {
		return 0
	}
	factor := prfDegree
	// Need: factor*(ncols+ell-1) <= ringN-1  =>  ell <= floor((ringN-1)/factor) - ncols + 1.
	maxDeg0 := (ringN - 1) / factor
	maxEll := maxDeg0 - ncols + 1
	if maxEll < 1 {
		return 0
	}
	return maxEll
}

func loadBFromState(r *ring.Ring, st credential.State) ([]*ring.Poly, error) {
	if len(st.B) > 0 {
		out := make([]*ring.Poly, len(st.B))
		for i := range st.B {
			out[i] = polyFromInt64(r, st.B[i])
			r.NTT(out[i], out[i])
		}
		return out, nil
	}
	if st.BPath == "" {
		return nil, fmt.Errorf("missing B in state")
	}
	coeffs, err := ntrurio.LoadBMatrixCoeffs(st.BPath)
	if err != nil {
		return nil, err
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

func loadPRFParamsFromState(st credential.State) (*prf.Params, error) {
	if st.PRFParamsPath != "" {
		if params, err := prf.LoadParamsFromFile(st.PRFParamsPath); err == nil {
			return params, nil
		}
	}
	return prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
}

func buildSignatureMatrix(r *ring.Ring, st credential.State, uCount int) ([][]*ring.Poly, error) {
	if len(st.NTRUPublic) == 0 {
		pk, err := keys.LoadPublic()
		if err != nil {
			return nil, fmt.Errorf("load public key: %w", err)
		}
		st.NTRUPublic = [][]int64{pk.HCoeffs}
	}
	if uCount <= 1 {
		one := r.NewPoly()
		one.Coeffs[0][0] = 1 % r.Modulus[0]
		r.NTT(one, one)
		return [][]*ring.Poly{{one}}, nil
	}
	hNTT := polyFromInt64(r, st.NTRUPublic[0])
	r.NTT(hNTT, hNTT)
	negHNTT := r.NewPoly()
	r.Neg(hNTT, negHNTT)
	one := r.NewPoly()
	one.Coeffs[0][0] = 1 % r.Modulus[0]
	r.NTT(one, one)
	// Signature rows are loaded as U = [s1, s2] where s2 = h*s1 + t (mod q),
	// hence the post-sign equation is (-h)*s1 + s2 = t.
	return [][]*ring.Poly{{negHNTT, one}}, nil
}

func buildWitnessFromState(r *ring.Ring, st credential.State) (PIOP.WitnessInputs, error) {
	coeffNative, err := buildCoeffNativeShowingWitnessFromState(r, st)
	if err != nil {
		return PIOP.WitnessInputs{}, err
	}
	if coeffNative != nil {
		return PIOP.WitnessInputs{
			CoeffNativeShowing: coeffNative,
		}, nil
	}

	m1 := polysFromInt64(r, st.M1)
	m2 := polysFromInt64(r, st.M2)
	r0 := polysFromInt64(r, st.R0)
	r1 := polysFromInt64(r, st.R1)
	k0 := polysFromInt64(r, st.K0)
	k1 := polysFromInt64(r, st.K1)
	base := r.NewPoly()

	t := st.T
	if len(t) == 0 {
		return PIOP.WitnessInputs{}, fmt.Errorf("missing T in state")
	}
	sigS1 := append([]int64(nil), st.SigS1...)
	sigS2 := append([]int64(nil), st.SigS2...)
	var uRows []*ring.Poly
	if len(sigS1) > 0 && len(sigS2) > 0 {
		uRows = []*ring.Poly{polyFromInt64(r, sigS1), polyFromInt64(r, sigS2)}
	} else {
		return PIOP.WitnessInputs{}, fmt.Errorf("missing sig_s1/sig_s2 in credential state")
	}

	// Ensure required base rows exist (zero-fill if state omitted them).
	if len(m1) == 0 {
		m1 = []*ring.Poly{base}
	}
	if len(m2) == 0 {
		m2 = []*ring.Poly{base}
	}
	if len(r0) == 0 {
		r0 = []*ring.Poly{base}
	}
	if len(r1) == 0 {
		r1 = []*ring.Poly{base}
	}
	if len(k0) == 0 {
		k0 = []*ring.Poly{base}
	}
	if len(k1) == 0 {
		k1 = []*ring.Poly{base}
	}

	return PIOP.WitnessInputs{
		M1:                 m1,
		M2:                 m2,
		RU0:                []*ring.Poly{base},
		RU1:                []*ring.Poly{base},
		R:                  []*ring.Poly{base},
		R0:                 r0,
		R1:                 r1,
		K0:                 k0,
		K1:                 k1,
		T:                  t,
		U:                  uRows,
		CoeffNativeShowing: coeffNative,
	}, nil
}

func buildCoeffNativeShowingWitnessFromState(r *ring.Ring, st credential.State) (*PIOP.CoeffNativeShowingWitness, error) {
	if r == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if st.CoeffNativeShowing == nil {
		return nil, nil
	}
	if err := st.CoeffNativeShowing.Validate(int(r.N)); err != nil {
		return nil, fmt.Errorf("invalid coeff-native showing payload in state: %w", err)
	}
	wit := &PIOP.CoeffNativeShowingWitness{
		Sig:    credentialPolysFromInt64(r, st.CoeffNativeShowing.Sig),
		U:      append([]int64(nil), st.CoeffNativeShowing.U...),
		X0:     append([]int64(nil), st.CoeffNativeShowing.X0...),
		X1:     st.CoeffNativeShowing.X1,
		PRFKey: append([]int64(nil), st.CoeffNativeShowing.PRFKey...),
	}
	if err := wit.Validate(int(r.N)); err != nil {
		return nil, fmt.Errorf("invalid coeff-native showing witness: %w", err)
	}
	return wit, nil
}

func showingSignatureComponentCount(wit PIOP.WitnessInputs) int {
	if wit.CoeffNativeShowing != nil && len(wit.CoeffNativeShowing.Sig) > 0 {
		return len(wit.CoeffNativeShowing.Sig)
	}
	return len(wit.U)
}

func prfKeyFromSemanticWitness(wit *PIOP.CoeffNativeShowingWitness) ([]prf.Elem, error) {
	if wit == nil {
		return nil, fmt.Errorf("missing coeff-native showing witness")
	}
	if len(wit.PRFKey) == 0 {
		return nil, fmt.Errorf("missing coeff-native semantic prf key witness")
	}
	out := make([]prf.Elem, len(wit.PRFKey))
	for i := range wit.PRFKey {
		out[i] = prf.Elem(wit.PRFKey[i])
	}
	return out, nil
}

func credentialPolysFromInt64(r *ring.Ring, vec [][]int64) []*ring.Poly {
	out := make([]*ring.Poly, len(vec))
	for i := range vec {
		out[i] = polyFromInt64(r, vec[i])
	}
	return out
}

func deriveOmegaForOpts(ringQ *ring.Ring, opts PIOP.SimOpts) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if opts.NCols <= 0 || opts.NCols > ringQ.N {
		return nil, fmt.Errorf("invalid ncols=%d", opts.NCols)
	}
	if opts.DomainMode == PIOP.DomainModeExplicit {
		nLeaves := opts.NLeaves
		if nLeaves <= 0 {
			nLeaves = int(ringQ.N)
		}
		lvcsNCols := opts.LVCSNCols
		if lvcsNCols <= 0 {
			lvcsNCols = opts.NCols
		}
		if lvcsNCols < opts.NCols {
			return nil, fmt.Errorf("invalid lvcs ncols=%d < witness ncols=%d", lvcsNCols, opts.NCols)
		}
		dom, err := domain.NewDomain(ringQ.Modulus[0], nLeaves, lvcsNCols, opts.Ell, nil)
		if err != nil {
			return nil, err
		}
		if len(dom.Omega) < opts.NCols {
			return nil, fmt.Errorf("derived omega len=%d < witness ncols=%d", len(dom.Omega), opts.NCols)
		}
		return append([]uint64(nil), dom.Omega[:opts.NCols]...), nil
	}
	px := ringQ.NewPoly()
	px.Coeffs[0][1] = 1
	pts := ringQ.NewPoly()
	ringQ.NTT(px, pts)
	return append([]uint64(nil), pts.Coeffs[0][:opts.NCols]...), nil
}

func sampleNonce(lennonce, ncols int, q uint64) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lennonce)
	public := make([][]int64, lennonce)
	for i := 0; i < lennonce; i++ {
		v := randElem(q)
		nonce[i] = prf.Elem(v)
		public[i] = buildConstLane(ncols, int64(v))
	}
	return nonce, public
}

func randElem(q uint64) uint64 {
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(q))
	if err != nil {
		panic(err)
	}
	return n.Uint64()
}

func lanesFromElems(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = buildConstLane(ncols, int64(v))
	}
	return out
}

func elemsToPolys(r *ring.Ring, elems []prf.Elem) []*ring.Poly {
	rows := make([]*ring.Poly, len(elems))
	for i, v := range elems {
		rows[i] = polyConst(r, int64(v))
	}
	return rows
}

func polyConst(r *ring.Ring, v int64) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	var coeff uint64
	if v >= 0 {
		coeff = uint64(v % q)
	} else {
		coeff = uint64((v+q)%q) % uint64(q)
	}
	for i := 0; i < r.N; i++ {
		pNTT.Coeffs[0][i] = coeff
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func polyFromInt64(r *ring.Ring, coeffs []int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	for i := 0; i < r.N && i < len(coeffs); i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func polysFromInt64(r *ring.Ring, vec [][]int64) []*ring.Poly {
	out := make([]*ring.Poly, len(vec))
	for i := range vec {
		out[i] = polyFromInt64(r, vec[i])
	}
	return out
}

func buildConstLane(ncols int, v int64) []int64 {
	row := make([]int64, ncols)
	for i := range row {
		row[i] = v
	}
	return row
}

type committedWitnessBreakdown = PIOP.CommittedWitnessBreakdown

type logicalWitnessBreakdown = PIOP.LogicalWitnessBreakdown

func committedWitnessRowBreakdownFromProof(proof *PIOP.Proof) committedWitnessBreakdown {
	return PIOP.CommittedWitnessRowBreakdownFromProof(proof)
}

func logicalWitnessRowBreakdownFromProof(proof *PIOP.Proof) logicalWitnessBreakdown {
	return PIOP.LogicalWitnessRowBreakdownFromProof(proof)
}

func printWitnessGeometry(prefix string, geom PIOP.WitnessGeometrySnapshot) {
	if geom.ActualWitnessPolys <= 0 {
		return
	}
	cli.printf(categoryGeometry, prefix, "%s", formatWitnessGeometrySummary(geom))
}

func formatWitnessGeometrySummary(geom PIOP.WitnessGeometrySnapshot) string {
	line := fmt.Sprintf(
		"Geometry: witness=%d (post=%d prf=%d) committed=%d mask=%d blocks=%dx%d occupancy=%.1f%%",
		geom.ActualWitnessPolys,
		geom.ActualPostSignWitnessPolys,
		geom.ActualPRFWitnessPolys,
		geom.WitnessRowsCommitted,
		geom.MaskRowsCommitted,
		geom.PCSBlockCount,
		geom.RowsPerBlock,
		geom.OccupancyPct,
	)
	if geom.FinalBlockSlack > 0 || geom.PostSignPrefixSlack > 0 {
		line += fmt.Sprintf(" slack=%d/%d", geom.FinalBlockSlack, geom.PostSignPrefixSlack)
	}
	if geom.ActualPRFWitnessPolys > 0 || geom.ReplayPRFRows > 0 {
		line += fmt.Sprintf(" prf_replay=%.2fx", geom.ReplayToWitnessExpansion)
	}
	return line
}

func printCommittedWitnessRowBreakdown(prefix string, proof *PIOP.Proof) {
	if proof != nil && proof.ShowingSplit != nil {
		if proof.ShowingSplit.PostSign != nil && proof.ShowingSplit.PostSign.Proof != nil {
			printCommittedWitnessRowBreakdown(prefix+"[post_sign] ", proof.ShowingSplit.PostSign.Proof)
		}
		if proof.ShowingSplit.PRF != nil && proof.ShowingSplit.PRF.Proof != nil {
			printCommittedWitnessRowBreakdown(prefix+"[prf] ", proof.ShowingSplit.PRF.Proof)
		}
		return
	}
	breakdown := committedWitnessRowBreakdownFromProof(proof)
	if breakdown.TotalRows == 0 {
		return
	}
	if breakdown.SharedRows > 0 {
		coeffPct := 100.0 * float64(breakdown.CoeffNativeRows) / float64(breakdown.TotalRows)
		sharedPct := 100.0 * float64(breakdown.SharedRows) / float64(breakdown.TotalRows)
		prfPct := 100.0 * float64(breakdown.PRFRows) / float64(breakdown.TotalRows)
		cli.printf(categoryGeometry, prefix, "Witness rows: coeff_native=%d (%.1f%%), shared=%d (%.1f%%), prf=%d (%.1f%%), total=%d, mask=%d",
			breakdown.CoeffNativeRows,
			coeffPct,
			breakdown.SharedRows,
			sharedPct,
			breakdown.PRFRows,
			prfPct,
			breakdown.TotalRows,
			proof.MaskRowCount)
		return
	}
	coeffPct := 100.0 * float64(breakdown.CoeffNativeRows) / float64(breakdown.TotalRows)
	prfPct := 100.0 * float64(breakdown.PRFRows) / float64(breakdown.TotalRows)
	cli.printf(categoryGeometry, prefix, "Witness rows: coeff_native=%d (%.1f%%), prf=%d (%.1f%%), total=%d, mask=%d",
		breakdown.CoeffNativeRows,
		coeffPct,
		breakdown.PRFRows,
		prfPct,
		breakdown.TotalRows,
		proof.MaskRowCount)
}

func printLogicalWitnessRowBreakdown(prefix string, proof *PIOP.Proof) {
	if proof != nil && proof.ShowingSplit != nil {
		if proof.ShowingSplit.PostSign != nil && proof.ShowingSplit.PostSign.Proof != nil {
			printLogicalWitnessRowBreakdown(prefix+"[post_sign] ", proof.ShowingSplit.PostSign.Proof)
		}
		if proof.ShowingSplit.PRF != nil && proof.ShowingSplit.PRF.Proof != nil {
			printLogicalWitnessRowBreakdown(prefix+"[prf] ", proof.ShowingSplit.PRF.Proof)
		}
		return
	}
	breakdown := logicalWitnessRowBreakdownFromProof(proof)
	if breakdown.TotalRows == 0 {
		return
	}
	if proof != nil && proof.RowLayout.CoeffNativeSig.Model == PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3 {
		cli.printf(categoryGeometry, prefix, "Witness logical rows: sig_primary_limb=%d, post_sign_scalar_projection=%d, post_sign_scalar_certificate=%d, prf_grouped_nonlinear=%d, total=%d",
			breakdown.SigCoreRows,
			breakdown.PostSignProjectionRows,
			breakdown.PostSignCertificateRows,
			breakdown.PRFRows,
			breakdown.TotalRows)
		return
	}
	cli.printf(categoryGeometry, prefix, "Witness logical rows: sig_semantic=%d, sig_shortness=%d, non_sig=%d, prf=%d, total=%d",
		breakdown.SigSemanticRows,
		breakdown.SigShortnessRows,
		breakdown.NonSigRows,
		breakdown.PRFRows,
		breakdown.TotalRows)
}

func printPaperTranscriptBreakdown(prefix string, rep PIOP.ProofReport) {
	if rep.Split != nil {
		if rep.Split.PostSign != nil {
			printPaperTranscriptBreakdown(prefix+"[post_sign] ", *rep.Split.PostSign)
		}
		if rep.Split.PRF != nil {
			printPaperTranscriptBreakdown(prefix+"[prf] ", *rep.Split.PRF)
		}
	}
	if rep.PaperTranscript.OptimizedBytes == 0 {
		cli.printf(categoryWarning, prefix, "paper transcript breakdown unavailable (total=0)")
		return
	}
	cli.printf(categoryTranscript, prefix, "Paper transcript breakdown (optimized, bytes, total=%d):", rep.PaperTranscript.OptimizedBytes)
	for _, row := range orderedPaperTranscriptRows(rep.PaperTranscript) {
		cli.printf(categoryTranscript, prefix, "  %-10s %8d  (%5.1f%%, %.0fb)", row.Label, row.Bytes, row.Percent, row.Bits)
	}
}

func printProofReport(prefix string, proof *PIOP.Proof, opts PIOP.SimOpts, boundB int64, ringQ *ring.Ring, proveDur, verifyDur time.Duration) {
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		cli.printf(categoryWarning, prefix, "report: %v", err)
		return
	}
	sigBase, sigL, _, sigErr := PIOP.ResolveSignatureBoundShapeForOpts(ringQ.Modulus[0], opts)
	nonW, nonL, _, nonErr := PIOP.ResolveNonSigBoundShape(boundB)
	if rep.PaperTranscript.OptimizedBytes > 0 {
		cli.printf(categoryTranscript, prefix, "%s", formatPaperTranscriptSummary(rep))
		cli.printf(categoryTranscript, prefix, "%s", formatPaperTranscriptReductionSummary(rep))
	}
	cli.printf(categoryTranscript, prefix, "Current verifier payload≈%.2f KB (%.0f bytes)", rep.ProofKB, float64(rep.ProofBytes))
	printPaperTranscriptBreakdown(prefix, rep)
	cli.printf(categoryStatus, prefix, "Prover time≈%s", proveDur)
	cli.printf(categoryStatus, prefix, "Verifier time≈%s", verifyDur)
	cli.printf(categorySoundness, prefix, "Soundness Eq.(8): %s %s %s %s eq8_total=%.2f",
		formatSoundnessComponent("eps1", rep.Soundness.RawBits[0], rep.Soundness.Bits[0]),
		formatSoundnessComponent("eps2", rep.Soundness.RawBits[1], rep.Soundness.Bits[1]),
		formatSoundnessComponent("eps3", rep.Soundness.RawBits[2], rep.Soundness.Bits[2]),
		formatSoundnessComponent("eps4", rep.Soundness.RawBits[3], rep.Soundness.Bits[3]),
		displayBits(rep.Soundness.Eq8TotalBits))
	cli.printf(categorySoundness, prefix, "Soundness Thm.9: collision=%.2f round={%.2f,%.2f,%.2f,%.2f} total=%.2f qcaps=%v",
		rep.Soundness.CollisionBits,
		rep.Soundness.TheoremBits[0], rep.Soundness.TheoremBits[1], rep.Soundness.TheoremBits[2], rep.Soundness.TheoremBits[3],
		displayBits(rep.Soundness.TotalBits),
		rep.Soundness.QueryCaps)
	if rep.Derived != nil {
		if rep.Derived.Achievable {
			cli.printf(categorySoundness, prefix, "Derived grinding to 128 bits: kappa=%v total=%.2f (raw=%.2f)",
				rep.Derived.DerivedKappa,
				displayBits(rep.Derived.DerivedTotalBits),
				displayBits(rep.Derived.RawCombinedBits))
		} else {
			cli.printf(categorySoundness, prefix, "Derived grinding to 128 bits: not achievable (collision floor=%.2f)",
				displayBits(rep.Soundness.CollisionBits))
		}
	}
	if rep.Split != nil {
		cli.printf(categoryGeometry, prefix, "Params: split proof NCols(s)=%d ℓ=%d ℓ'=%d ρ=%d θ=%d η=%d dQ=split", rep.NCols, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta)
	} else {
		cli.printf(categoryGeometry, prefix, "Params: NCols(s)=%d pcs_ncols=%d ddecs=%d ℓ=%d ℓ'=%d ρ=%d θ=%d η=%d dQ=%d collision_bits=%d", rep.NCols, rep.PCSNCols, rep.Soundness.DDECS, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta, rep.DQ, rep.Soundness.CollisionSpaceBits)
	}
	printWitnessGeometry(prefix, rep.Geometry)
	if rep.Split != nil {
		if rep.Split.PostSign != nil {
			cli.printf(categoryGeometry, prefix, "Slice post_sign: bytes=%d soundness=%.2f dQ=%d pcs_ncols=%d witness=%d rows=%d mask=%d",
				rep.Split.PostSign.ProofBytes,
				displayBits(rep.Split.PostSign.Soundness.TotalBits),
				rep.Split.PostSign.DQ,
				rep.Split.PostSign.LVCSNCols,
				rep.Split.PostSign.Geometry.ActualWitnessPolys,
				rep.Split.PostSign.Geometry.WitnessRowsCommitted,
				rep.Split.PostSign.Geometry.MaskRowsCommitted)
			printWitnessGeometry(prefix+"[post_sign] ", rep.Split.PostSign.Geometry)
		}
		if rep.Split.PRF != nil {
			cli.printf(categoryGeometry, prefix, "Slice prf:       bytes=%d soundness=%.2f dQ=%d pcs_ncols=%d witness=%d rows=%d mask=%d",
				rep.Split.PRF.ProofBytes,
				displayBits(rep.Split.PRF.Soundness.TotalBits),
				rep.Split.PRF.DQ,
				rep.Split.PRF.LVCSNCols,
				rep.Split.PRF.Geometry.ActualWitnessPolys,
				rep.Split.PRF.Geometry.WitnessRowsCommitted,
				rep.Split.PRF.Geometry.MaskRowsCommitted)
			printWitnessGeometry(prefix+"[prf] ", rep.Split.PRF.Geometry)
		}
	}
	if sigErr == nil && nonErr == nil {
		cli.printf(categoryGeometry, prefix, "Linf chain: sig(R=%d,L=%d) nonSig(W=%d,L=%d)", sigBase, sigL, nonW, nonL)
	} else {
		cli.printf(categoryWarning, prefix, "Linf chain shape resolution warning: sigErr=%v nonSigErr=%v", sigErr, nonErr)
	}
	cli.printf(categoryGeometry, prefix, "Table row: %.2f %.3f %.2f %d %d %d %d %d %d",
		rep.ProofKB, proveDur.Seconds(), rep.Soundness.TotalBits,
		rep.NCols, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta)
}

func displayBits(bits float64) float64 {
	if math.Abs(bits) < 0.005 {
		return 0
	}
	return bits
}

func formatSoundnessComponent(label string, rawBits, bits float64) string {
	if rawBits < bits {
		return fmt.Sprintf("%s=%.2f (raw %.2f)", label, bits, rawBits)
	}
	return fmt.Sprintf("%s=%.2f", label, bits)
}

func formatPaperTranscriptSummary(rep PIOP.ProofReport) string {
	return fmt.Sprintf("Paper transcript≈%.2f KB (%d bytes, optimized)",
		float64(rep.PaperTranscript.OptimizedBytes)/1024.0,
		rep.PaperTranscript.OptimizedBytes)
}

func formatPaperTranscriptReductionSummary(rep PIOP.ProofReport) string {
	return fmt.Sprintf("Paper reductions: R saved=%.0fb Q saved=%.0fb",
		rep.PaperTranscript.R.NaiveBits-rep.PaperTranscript.R.OptimizedBits,
		rep.PaperTranscript.Q.NaiveBits-rep.PaperTranscript.Q.OptimizedBits)
}

type paperTranscriptBreakdownRow struct {
	Label   string
	Bytes   int
	Bits    float64
	Percent float64
	order   int
}

func orderedPaperTranscriptRows(rep PIOP.PaperTranscriptReport) []paperTranscriptBreakdownRow {
	total := rep.OptimizedBytes
	rows := []paperTranscriptBreakdownRow{}
	add := func(label string, bucket PIOP.PaperTranscriptBucket, order int) {
		if bucket.OptimizedBytes <= 0 {
			return
		}
		pct := 0.0
		if total > 0 {
			pct = 100.0 * float64(bucket.OptimizedBytes) / float64(total)
		}
		rows = append(rows, paperTranscriptBreakdownRow{
			Label:   label,
			Bytes:   bucket.OptimizedBytes,
			Bits:    bucket.OptimizedBits,
			Percent: pct,
			order:   order,
		})
	}
	add("Counters", rep.Counters, 0)
	add("SaltRoot", rep.SaltRoot, 1)
	add("ExtraHash", rep.ExtraHash, 2)
	add("R", rep.R, 3)
	add("Q", rep.Q, 4)
	add("VTargets", rep.VTargets, 5)
	add("BarSets", rep.BarSets, 6)
	add("Pdecs", rep.Pdecs, 7)
	add("Mdecs", rep.Mdecs, 8)
	add("Auth", rep.Auth, 9)
	add("Tapes", rep.Tapes, 10)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes != rows[j].Bytes {
			return rows[i].Bytes > rows[j].Bytes
		}
		return rows[i].order < rows[j].order
	})
	return rows
}
