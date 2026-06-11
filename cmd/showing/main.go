package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	vsishash "vSIS-Signature/internal/hash"
	ntrurio "vSIS-Signature/ntru/io"
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

type showingCLIConfig struct {
	StatePath          string
	PublicParamsPath   string
	VerifierKeyPath    string
	Preset             credential.IntGenISISPreset
	PresentationOut    string
	VerifyPresentation string
	VerifierStatePath  string
	ROQueryCaps        [5]int
	ROQueryCapsSet     bool
	DECSCollisionBits  int
}

func parseShowingCLIArgs(args []string) (showingCLIConfig, error) {
	fs := flag.NewFlagSet("showing", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	intGenISISPreset := fs.String("preset", "", "named IntGenISIS preset: n512-compact96, n1024-compact96, or n1024-compact125")
	statePathFlag := fs.String("state-path", "", "credential state path for showing; defaults to the selected maintained profile artifact")
	intGenISISPublicParamsPath := fs.String("public-params", "", "IntGenISIS public params path for standalone presentation verification")
	intGenISISVerifierKeyPath := fs.String("verifier-key", "", "IntGenISIS verifier key path for standalone presentation verification")
	presentationOut := fs.String("presentation-out", "", "IntGenISIS presentation output path")
	verifyPresentation := fs.String("verify-presentation", "", "verify an IntGenISIS presentation artifact instead of proving")
	verifierStatePath := fs.String("verifier-state", "", "persistent IntGenISIS verifier replay-state path")
	roQueryCaps := fs.String("ro-query-caps", "", "SmallWood random-oracle query caps Q0,Q1,Q2,Q3,Q4")
	decsCollisionBits := fs.Int("decs-collision-bits", PIOP.ResolveDECSCollisionBits(0), "DECS collision hash/tape bits: "+PIOP.DECSCollisionBitsUsage())
	decsCollisionBytes := fs.Int("decs-collision-bytes", 0, "DECS collision hash/tape bytes: 16,17,18,20,24,28,32")
	if err := fs.Parse(args); err != nil {
		return showingCLIConfig{}, err
	}
	var queryCaps [5]int
	queryCapsSet := false
	if strings.TrimSpace(*roQueryCaps) != "" {
		var err error
		queryCaps, err = PIOP.ParseROQueryCaps(*roQueryCaps)
		if err != nil {
			return showingCLIConfig{}, err
		}
		queryCapsSet = true
	}
	collisionBits := *decsCollisionBits
	if *decsCollisionBytes > 0 {
		if err := PIOP.ValidateDECSCollisionBytes(*decsCollisionBytes); err != nil {
			return showingCLIConfig{}, fmt.Errorf("-decs-collision-bytes: %w", err)
		}
		collisionBits = 8 * *decsCollisionBytes
	}
	if err := PIOP.ValidateDECSCollisionBits(collisionBits); err != nil {
		return showingCLIConfig{}, fmt.Errorf("-decs-collision-bits: %w", err)
	}
	selectedIntGenISISPreset, err := credential.ResolveIntGenISISPresetSelector(*intGenISISPreset, false)
	if err != nil {
		return showingCLIConfig{}, err
	}
	*intGenISISPreset = selectedIntGenISISPreset
	if strings.TrimSpace(*intGenISISPreset) == "" {
		return showingCLIConfig{}, fmt.Errorf("missing -preset (supported: %s)", strings.Join(credential.IntGenISISPresetNames(), ", "))
	}
	preset, err := credential.MustLookupIntGenISISPreset(*intGenISISPreset)
	if err != nil {
		return showingCLIConfig{}, err
	}
	if *statePathFlag == "" {
		*statePathFlag = filepath.Join("credential", "keys", "credential_state.json")
	}
	return showingCLIConfig{
		StatePath:          *statePathFlag,
		PublicParamsPath:   *intGenISISPublicParamsPath,
		VerifierKeyPath:    *intGenISISVerifierKeyPath,
		Preset:             preset,
		PresentationOut:    *presentationOut,
		VerifyPresentation: *verifyPresentation,
		VerifierStatePath:  *verifierStatePath,
		ROQueryCaps:        queryCaps,
		ROQueryCapsSet:     queryCapsSet,
		DECSCollisionBits:  collisionBits,
	}, nil
}

func main() {
	cfg, err := parseShowingCLIArgs(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			return
		}
		cli.fatalf("[showing-cli] ", "%v", err)
	}
	if err := runIntGenISISShowingCLI(cfg); err != nil {
		cli.fatalf("[showing-cli] ", "%v", err)
	}
}

func runIntGenISISShowingCLI(cfg showingCLIConfig) error {
	statePath := cfg.StatePath
	publicParamsPath := cfg.PublicParamsPath
	verifierKeyPath := cfg.VerifierKeyPath
	preset := cfg.Preset
	presentationOut := cfg.PresentationOut
	verifyPresentationPath := cfg.VerifyPresentation
	verifierStatePath := cfg.VerifierStatePath
	cli.printf(categoryStatus, "[showing-cli] ", "starting IntGenISIS showing preset=%s state=%s", preset.Name, statePath)
	if verifyPresentationPath != "" {
		if publicParamsPath == "" {
			return fmt.Errorf("IntGenISIS presentation verification requires -public-params")
		}
		if verifierKeyPath == "" {
			return fmt.Errorf("IntGenISIS presentation verification requires -verifier-key")
		}
		publicParams, err := credential.LoadPublicParams(publicParamsPath)
		if err != nil {
			return fmt.Errorf("load IntGenISIS public params: %w", err)
		}
		if !publicParams.UsesIntGenISIS() {
			return fmt.Errorf("standalone verifier public params are not IntGenISIS")
		}
		verifierKey, err := credential.LoadIntGenISISVerifierKey(verifierKeyPath)
		if err != nil {
			return err
		}
		if verifierKey.PublicParamsDigest == "" {
			return fmt.Errorf("verifier key missing public params digest")
		}
		digest, err := credential.PublicParamsDigest(publicParams)
		if err != nil {
			return fmt.Errorf("digest IntGenISIS public params: %w", err)
		}
		if verifierKey.PublicParamsDigest != digest {
			return fmt.Errorf("verifier key public params digest mismatch")
		}
		ringQ, err := credential.LoadRingWithDegree(publicParams.RingDegree)
		if err != nil {
			return fmt.Errorf("load ring: %w", err)
		}
		opts := applyShowingCLIAccountingOverrides(intGenISISShowingOpts(publicParams.RingDegree, preset.Showing), cfg)
		return verifyIntGenISISPresentationCLI(verifyPresentationPath, verifierStatePath, verifierKey, publicParams, ringQ, opts)
	}
	st, err := credential.LoadIntGenISISState(statePath)
	if err != nil {
		return fmt.Errorf("load IntGenISIS credential state: %w", err)
	}
	publicParams, err := credential.LoadPublicParams(st.CredentialPublicPath)
	if err != nil {
		return fmt.Errorf("load IntGenISIS public params: %w", err)
	}
	if !publicParams.UsesIntGenISIS() {
		return fmt.Errorf("state references non-IntGenISIS public params")
	}
	profile, ok := credential.LookupIntGenISISProfile(st.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", st.Profile)
	}
	if profile.Name != preset.Profile {
		return fmt.Errorf("credential state profile=%q does not match preset %s profile=%q", profile.Name, preset.Name, preset.Profile)
	}
	ringQ, err := credential.LoadRingWithDegree(st.RingDegree)
	if err != nil {
		return fmt.Errorf("load ring: %w", err)
	}
	params, err := loadPRFParamsFromIntGenISISState(st)
	if err != nil {
		return fmt.Errorf("load prf params: %w", err)
	}
	opts := applyShowingCLIAccountingOverrides(intGenISISShowingOpts(st.RingDegree, preset.Showing), cfg)
	if opts.NCols < params.LenKey {
		return fmt.Errorf("ncols=%d is too small for IntGenISIS PRF key width %d", opts.NCols, params.LenKey)
	}
	if verifyPresentationPath != "" {
		return fmt.Errorf("unreachable IntGenISIS presentation verification branch")
	}
	B, err := loadBForIntGenISISShowing(ringQ, publicParams)
	if err != nil {
		return err
	}
	wit, err := buildIntGenISISWitnessFromState(ringQ, st, B, opts.NCols)
	if err != nil {
		return err
	}
	A, err := buildIntGenISISSignatureMatrix(ringQ, st)
	if err != nil {
		return err
	}
	cm, err := commitment.MatrixFromCoeff(ringQ, publicParams.CM)
	if err != nil {
		return fmt.Errorf("lift C_M: %w", err)
	}
	as, err := commitment.MatrixFromCoeff(ringQ, publicParams.AS)
	if err != nil {
		return fmt.Errorf("lift A_s: %w", err)
	}
	nonce, noncePublic := sampleNonce(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	layout, err := credential.DefaultSemanticMessageLayout(profile, params.LenKey)
	if err != nil {
		return err
	}
	keyScalars, err := credential.PRFKeyFromSemanticMessage(layout, st.M)
	if err != nil {
		return fmt.Errorf("extract IntGenISIS PRF key: %w", err)
	}
	key := make([]prf.Elem, len(keyScalars))
	for i, v := range keyScalars {
		key[i] = intGenISISFieldElemFromSigned(v, ringQ.Modulus[0])
	}
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		return fmt.Errorf("compute IntGenISIS tag: %w", err)
	}
	pub := PIOP.PublicInputs{
		A:            A,
		B:            B,
		CM:           cm,
		AS:           as,
		Tag:          lanesFromElems(tag, opts.NCols),
		Nonce:        noncePublic,
		BoundB:       publicParams.CommitmentBound,
		X0Len:        publicParams.EllX0,
		RingDegree:   int(ringQ.N),
		HashRelation: publicParams.HashRelation,
		IntGenISIS:   true,
		Extras:       intGenISISSignatureBoundExtras(st.SignatureBound),
	}
	proofStart := time.Now()
	proof, err := PIOP.BuildIntGenISISShowingCombined(pub, wit, opts)
	if err != nil {
		return fmt.Errorf("build IntGenISIS showing: %w", err)
	}
	proofDur := time.Since(proofStart)
	verifyStart := time.Now()
	verified, err := PIOP.VerifyIntGenISISShowing(pub, proof, opts)
	verifyDur := time.Since(verifyStart)
	if err != nil || !verified {
		return fmt.Errorf("verify IntGenISIS showing failed: ok=%v err=%v", verified, err)
	}
	if presentationOut != "" {
		proofRaw, err := json.Marshal(proof)
		if err != nil {
			return fmt.Errorf("marshal IntGenISIS proof: %w", err)
		}
		digest, err := credential.PublicParamsDigest(publicParams)
		if err != nil {
			return fmt.Errorf("digest IntGenISIS public params: %w", err)
		}
		pres := credential.IntGenISISPresentation{
			Version:            credential.IntGenISISPresentationVersion,
			Profile:            profile.Name,
			PublicParamsDigest: digest,
			Nonce:              noncePublic,
			Tag:                lanesFromElems(tag, opts.NCols),
			Proof:              proofRaw,
		}
		if err := credential.SaveIntGenISISPresentation(presentationOut, pres); err != nil {
			return fmt.Errorf("save IntGenISIS presentation: %w", err)
		}
		cli.printf(categoryStatus, "[showing-cli] ", "IntGenISIS presentation wrote %s", presentationOut)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "IntGenISIS showing proof verified")
	printLogicalWitnessRowBreakdown("[showing-cli] ", proof)
	printCommittedWitnessRowBreakdown("[showing-cli] ", proof)
	_, _ = printProofReport("[showing-cli] ", proof, opts, publicParams.CommitmentBound, ringQ, proofDur, verifyDur)
	return nil
}

func intGenISISShowingOpts(ringDegree int, tuning credential.IntGenISISTuningPreset) PIOP.SimOpts {
	ncols := tuning.NCols
	lvcsNCols := tuning.LVCSNCols
	if lvcsNCols < ncols {
		lvcsNCols = ncols
	}
	return PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:                 true,
		CoeffPacking:               true,
		RingDegree:                 ringDegree,
		NCols:                      ncols,
		LVCSNCols:                  lvcsNCols,
		PostSignLVCSNCols:          lvcsNCols,
		PRFLVCSNCols:               lvcsNCols,
		NLeaves:                    tuning.NLeaves,
		Ell:                        tuning.Ell,
		EllPrime:                   tuning.EllPrime,
		Eta:                        tuning.Eta,
		Rho:                        tuning.Rho,
		Theta:                      tuning.Theta,
		Kappa:                      tuning.Kappa,
		DomainMode:                 PIOP.DomainModeExplicit,
		PRFGroupRounds:             tuning.PRFGroupRounds,
		PRFCompanionMode:           PIOP.PRFCompanionMode(tuning.PRFCompanionMode),
		PRFCheckpointSamples:       tuning.CheckpointSamples,
		IntGenISISMSECompression:   tuning.CompressedRows,
		IntGenISISReplayProjection: tuning.ReplayProjection,
		SigShortnessRadix:          tuning.SigShortnessRadix,
		SigShortnessL:              tuning.SigShortnessDigits,
		FixedTranscriptSize:        tuning.FixedTranscriptSize,
	})
}

func applyShowingCLIAccountingOverrides(opts PIOP.SimOpts, cfg showingCLIConfig) PIOP.SimOpts {
	if cfg.ROQueryCapsSet {
		opts.ROQueryCaps = cfg.ROQueryCaps
		opts.ROQueryCapsSet = true
	}
	if cfg.DECSCollisionBits > 0 {
		opts.DECSCollisionBits = cfg.DECSCollisionBits
	}
	return PIOP.ResolveSimOptsDefaults(opts)
}

func verifyIntGenISISPresentationCLI(path, verifierStatePath string, verifierKey credential.IntGenISISVerifierKey, publicParams credential.PublicParams, ringQ *ring.Ring, opts PIOP.SimOpts) error {
	pres, err := credential.LoadIntGenISISPresentation(path)
	if err != nil {
		return err
	}
	digest, err := credential.PublicParamsDigest(publicParams)
	if err != nil {
		return fmt.Errorf("digest IntGenISIS public params: %w", err)
	}
	if pres.PublicParamsDigest != digest {
		return fmt.Errorf("presentation public params digest mismatch")
	}
	if pres.Profile != verifierKey.Profile {
		return fmt.Errorf("presentation profile=%q verifier key profile=%q", pres.Profile, verifierKey.Profile)
	}
	var proof PIOP.Proof
	if err := json.Unmarshal(pres.Proof, &proof); err != nil {
		return fmt.Errorf("unmarshal presentation proof: %w", err)
	}
	B, err := loadBForIntGenISISShowing(ringQ, publicParams)
	if err != nil {
		return err
	}
	A, err := buildIntGenISISSignatureMatrixFromRows(ringQ, verifierKey.NTRUPublic)
	if err != nil {
		return err
	}
	cm, err := commitment.MatrixFromCoeff(ringQ, publicParams.CM)
	if err != nil {
		return fmt.Errorf("lift C_M: %w", err)
	}
	as, err := commitment.MatrixFromCoeff(ringQ, publicParams.AS)
	if err != nil {
		return fmt.Errorf("lift A_s: %w", err)
	}
	pub := PIOP.PublicInputs{
		A:            A,
		B:            B,
		CM:           cm,
		AS:           as,
		Tag:          pres.Tag,
		Nonce:        pres.Nonce,
		BoundB:       publicParams.CommitmentBound,
		X0Len:        publicParams.EllX0,
		RingDegree:   int(ringQ.N),
		HashRelation: publicParams.HashRelation,
		IntGenISIS:   true,
		Extras:       intGenISISSignatureBoundExtras(verifierKey.SignatureBound),
	}
	ok, err := PIOP.VerifyIntGenISISShowing(pub, &proof, opts)
	if err != nil || !ok {
		return fmt.Errorf("verify IntGenISIS presentation failed: ok=%v err=%v", ok, err)
	}
	if verifierStatePath != "" {
		state, err := credential.LoadIntGenISISVerifierState(verifierStatePath)
		if err != nil {
			return err
		}
		if err := state.MarkPresentation(pres); err != nil {
			return err
		}
		if err := credential.SaveIntGenISISVerifierState(verifierStatePath, state); err != nil {
			return err
		}
	}
	cli.printf(categoryStatus, "[showing-cli] ", "IntGenISIS presentation verified")
	return nil
}

func intGenISISSignatureBoundExtras(bound int64) map[string]interface{} {
	if bound <= 0 {
		return nil
	}
	return map[string]interface{}{
		"IntGenISIS.signature_bound": []byte(fmt.Sprintf("%d", bound)),
	}
}

func intGenISISFieldElemFromSigned(v int64, q uint64) prf.Elem {
	if v >= 0 {
		return prf.Elem(uint64(v) % q)
	}
	neg := uint64(-v) % q
	if neg == 0 {
		return 0
	}
	return prf.Elem((q - neg) % q)
}

func loadPRFParamsFromIntGenISISState(st credential.IntGenISISState) (*prf.Params, error) {
	if st.PRFParamsPath != "" {
		if params, err := prf.LoadParamsFromFile(st.PRFParamsPath); err == nil {
			return params, nil
		}
	}
	return prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
}

func loadBForIntGenISISShowing(r *ring.Ring, public credential.PublicParams) ([]*ring.Poly, error) {
	if public.BPath == "" {
		return nil, fmt.Errorf("missing B path in IntGenISIS public params")
	}
	meta, err := ntrurio.LoadBMatrixMetadata(public.BPath)
	if err != nil {
		return nil, err
	}
	if meta.TargetDim != public.NC {
		return nil, fmt.Errorf("b target_dim=%d want n_c=%d", meta.TargetDim, public.NC)
	}
	if meta.X0Len != public.EllX0 {
		return nil, fmt.Errorf("b x0_len=%d want ell_x0=%d", meta.X0Len, public.EllX0)
	}
	if meta.RingDegree != int(r.N) {
		return nil, fmt.Errorf("b ring_degree=%d want %d", meta.RingDegree, r.N)
	}
	out := make([]*ring.Poly, len(meta.B))
	for i := range meta.B {
		if len(meta.B[i]) != int(r.N) {
			return nil, fmt.Errorf("b[%d] coefficient length=%d want %d", i, len(meta.B[i]), r.N)
		}
		p := r.NewPoly()
		copy(p.Coeffs[0], meta.B[i])
		r.NTT(p, p)
		out[i] = p
	}
	return out, nil
}

func buildIntGenISISSignatureMatrix(r *ring.Ring, st credential.IntGenISISState) ([][]*ring.Poly, error) {
	return buildIntGenISISSignatureMatrixFromRows(r, st.NTRUPublic)
}

func buildIntGenISISSignatureMatrixFromRows(r *ring.Ring, ntruPublic [][]int64) ([][]*ring.Poly, error) {
	if len(ntruPublic) == 0 || len(ntruPublic[0]) != int(r.N) {
		return nil, fmt.Errorf("intgenisis state missing NTRU public row of length %d", r.N)
	}
	hNTT := polyFromInt64(r, ntruPublic[0])
	r.NTT(hNTT, hNTT)
	negHNTT := r.NewPoly()
	r.Neg(hNTT, negHNTT)
	one := r.NewPoly()
	one.Coeffs[0][0] = 1 % r.Modulus[0]
	r.NTT(one, one)
	return [][]*ring.Poly{{negHNTT, one}}, nil
}

func buildIntGenISISWitnessFromState(r *ring.Ring, st credential.IntGenISISState, B []*ring.Poly, packedNCols int) (PIOP.WitnessInputs, error) {
	if len(st.SigS1) != int(r.N) || len(st.SigS2) != int(r.N) {
		return PIOP.WitnessInputs{}, fmt.Errorf("intgenisis state missing sig_s1/sig_s2 rows")
	}
	x1Rows := polysFromInt64(r, st.X1)
	if len(x1Rows) != 1 {
		return PIOP.WitnessInputs{}, fmt.Errorf("x1 rows=%d want 1", len(x1Rows))
	}
	if len(B) != 3+len(st.X0) {
		return PIOP.WitnessInputs{}, fmt.Errorf("b rows=%d want %d", len(B), 3+len(st.X0))
	}
	x1ForInverse := r.NewPoly()
	ring.Copy(x1Rows[0], x1ForInverse)
	zNTT, err := vsishash.ComputeBBTranInverse(r, B[len(B)-1], x1ForInverse)
	if err != nil {
		return PIOP.WitnessInputs{}, fmt.Errorf("compute Z from x1: %w", err)
	}
	zCoeff := r.NewPoly()
	ring.Copy(zNTT, zCoeff)
	r.InvNTT(zCoeff, zCoeff)
	cn := &PIOP.CoeffNativeShowingWitness{
		Sig:         []*ring.Poly{polyFromInt64(r, st.SigS1), polyFromInt64(r, st.SigS2)},
		M:           polyFromInt64(r, st.M[0]),
		MAttr:       polyFromInt64(r, st.MAttr[0]),
		K:           polyFromInt64(r, st.K[0]),
		S:           polysFromInt64(r, st.S),
		E:           polysFromInt64(r, st.E),
		MuSig:       polysFromInt64(r, st.MuSig),
		X0:          polysFromInt64(r, st.X0),
		X1:          x1Rows[0],
		Z:           zCoeff,
		PackedNCols: packedNCols,
	}
	return PIOP.WitnessInputs{CoeffNativeShowing: cn}, nil
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
	breakdown := logicalWitnessRowBreakdownFromProof(proof)
	if breakdown.TotalRows == 0 {
		return
	}
	cli.printf(categoryGeometry, prefix, "Witness logical rows: sig_replay=%d, sig_shortness=%d, non_sig=%d, prf=%d, total=%d",
		breakdown.SigReplayRows,
		breakdown.SigShortnessRows,
		breakdown.NonSigRows,
		breakdown.PRFRows,
		breakdown.TotalRows)
}

func printPaperTranscriptBreakdown(prefix string, rep PIOP.ProofReport) {
	if rep.PaperTranscript.OptimizedBytes == 0 {
		cli.printf(categoryWarning, prefix, "paper transcript breakdown unavailable (total=0)")
		return
	}
	cli.printf(categoryTranscript, prefix, "Paper transcript breakdown (optimized, bytes, total=%d):", rep.PaperTranscript.OptimizedBytes)
	for _, row := range orderedPaperTranscriptRows(rep.PaperTranscript) {
		cli.printf(categoryTranscript, prefix, "  %-10s %8d  (%5.1f%%, %.0fb)", row.Label, row.Bytes, row.Percent, row.Bits)
	}
}

func printProofReport(prefix string, proof *PIOP.Proof, opts PIOP.SimOpts, boundB int64, ringQ *ring.Ring, proveDur, verifyDur time.Duration) (PIOP.ProofReport, bool) {
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		cli.printf(categoryWarning, prefix, "report: %v", err)
		return PIOP.ProofReport{}, false
	}
	sigBase, sigL, sigRowsPer, sigDegree, sigErr := PIOP.ResolveSignatureShortnessMetricsForOpts(ringQ.Modulus[0], opts)
	if rep.PaperTranscript.OptimizedBytes > 0 {
		cli.printf(categoryTranscript, prefix, "%s", formatPaperTranscriptSummary(rep))
		cli.printf(categoryTranscript, prefix, "%s", formatPaperTranscriptReductionSummary(rep))
	}
	cli.printf(categoryTranscript, prefix, "Current verifier payload≈%.2f KB (%.0f bytes)", rep.ProofKB, float64(rep.ProofBytes))
	printPaperTranscriptBreakdown(prefix, rep)
	printTranscriptOptimizationFocus(prefix, rep)
	printStatementSummary(prefix, rep)
	printSigShortness(prefix, rep)
	printSigLookupShadow(prefix, rep)
	cli.printf(categoryStatus, prefix, "Prover time≈%s", proveDur)
	cli.printf(categoryStatus, prefix, "Verifier time≈%s", verifyDur)
	cli.printf(categorySoundness, prefix, "Soundness Eq.(8): %s %s %s %s eq8_total=%.2f",
		formatSoundnessComponent("eps1", rep.Soundness.RawBits[0], rep.Soundness.Bits[0]),
		formatSoundnessComponent("eps2", rep.Soundness.RawBits[1], rep.Soundness.Bits[1]),
		formatSoundnessComponent("eps3", rep.Soundness.RawBits[2], rep.Soundness.Bits[2]),
		formatSoundnessComponent("eps4", rep.Soundness.RawBits[3], rep.Soundness.Bits[3]),
		displayBits(rep.Soundness.Eq8TotalBits))
	cli.printf(categorySoundness, prefix, "Soundness one-proof: collision_bits=%.2f algebraic_round_bits={%.2f,%.2f,%.2f,%.2f} algebraic_total_bits=%.2f one_proof_total_bits=%.2f ro_query_caps=%v collision_space_bits=%d",
		rep.Soundness.CollisionBits,
		rep.Soundness.AlgebraicBits[0], rep.Soundness.AlgebraicBits[1], rep.Soundness.AlgebraicBits[2], rep.Soundness.AlgebraicBits[3],
		displayBits(rep.Soundness.AlgebraicTotalBits),
		displayBits(rep.Soundness.OneProofTotalBits),
		rep.Soundness.QueryCaps,
		rep.Soundness.CollisionSpaceBits)
	if note := formatSoundnessNotes(rep); note != "" {
		cli.printf(categorySoundness, prefix, "%s", note)
	}
	cli.printf(categoryGeometry, prefix, "Params: ring_degree=%d x0_len=%d NCols(s)=%d pcs_ncols=%d nleaves=%d ddecs=%d ℓ=%d ℓ'=%d ρ=%d θ=%d η=%d κ={%d,%d,%d,%d} dQ=%d collision_bits=%d",
		rep.RingDegree, rep.X0Len, rep.NCols, rep.PCSNCols, rep.NLeaves, rep.Soundness.DDECS, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta,
		rep.Kappa[0], rep.Kappa[1], rep.Kappa[2], rep.Kappa[3], rep.DQ, rep.Soundness.CollisionSpaceBits)
	printWitnessGeometry(prefix, rep.Geometry)
	if sigErr == nil {
		if rep.TranscriptFocus.SigShortnessDegree > 0 {
			sigDegree = rep.TranscriptFocus.SigShortnessDegree
		}
		cli.printf(categoryGeometry, prefix, "Linf chain: sig(profile=%s,R=%d,L=%d,rows=%d,deg=%d) nonSig=carriers", rep.TranscriptFocus.SigShortnessProfile, sigBase, sigL, sigRowsPer, sigDegree)
	} else {
		cli.printf(categoryWarning, prefix, "Linf chain shape resolution warning: sigErr=%v", sigErr)
	}
	paperTranscriptKB := float64(rep.PaperTranscript.OptimizedBytes) / 1024.0
	cli.printf(categoryWarning, prefix, "Table row: %.2f %.3f %.2f %d %d %d %d %d %d",
		paperTranscriptKB, proveDur.Seconds(), rep.Soundness.OneProofTotalBits,
		rep.NCols, rep.Ell, rep.EllPrime, rep.Rho, rep.Theta, rep.Eta)
	return rep, true
}

func displayBits(bits float64) float64 {
	if math.Abs(bits) < 0.005 {
		return 0
	}
	return bits
}

func formatSoundnessComponent(label string, rawBits, bits float64) string {
	if rawBits < bits {
		return fmt.Sprintf("%s=%.2f (clamped from raw %.2f)", label, bits, rawBits)
	}
	return fmt.Sprintf("%s=%.2f", label, bits)
}

func formatSoundnessNotes(rep PIOP.ProofReport) string {
	var notes []string
	for i := 0; i < len(rep.Soundness.Clamped); i++ {
		if rep.Soundness.Clamped[i] {
			notes = append(notes, fmt.Sprintf("eps%d raw term is negative and is paper-clamped to 0 before theorem-level grinding", i+1))
		}
	}
	for _, kappa := range rep.Kappa {
		if kappa > 0 {
			notes = append(notes, "algebraic round bits already include grinding κ; large κ improves theorem terms but increases prover work exponentially")
			break
		}
	}
	return strings.Join(notes, "; ")
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

func printTranscriptOptimizationFocus(prefix string, rep PIOP.ProofReport) {
	if line := formatTranscriptOptimizationSummary(rep); line != "" {
		cli.printf(categoryGeometry, prefix, "%s", line)
	}
	if line := formatTranscriptBucketFocusSummary(rep); line != "" {
		cli.printf(categoryTranscript, prefix, "%s", line)
	}
	printReplayFamilyAudit(prefix, rep)
}

func printStatementSummary(prefix string, rep PIOP.ProofReport) {
	if line := formatStatementSummary(rep); line != "" {
		cli.printf(categoryStatus, prefix, "%s", line)
	}
}

func formatTranscriptOptimizationSummary(rep PIOP.ProofReport) string {
	focus := rep.TranscriptFocus
	if focus.NRows <= 0 {
		return ""
	}
	layout := "unpacked"
	if focus.PRFPacked {
		layout = "packed"
	}
	instances := ""
	if focus.MainLVCSNCols > 0 || focus.MainNLeaves > 0 || focus.PRFLVCSNCols > 0 || focus.PRFNLeaves > 0 || focus.HiddenShortnessLVCSNCols > 0 || focus.HiddenShortnessNLeaves > 0 {
		instances = fmt.Sprintf(
			" main=%d/%d prf=%d/%d hidden=%d/%d",
			focus.MainLVCSNCols,
			focus.MainNLeaves,
			focus.PRFLVCSNCols,
			focus.PRFNLeaves,
			focus.HiddenShortnessLVCSNCols,
			focus.HiddenShortnessNLeaves,
		)
	}
	rowFamilies := fmt.Sprintf(
		" rows(mhat=%d rhat0=%d r0b2=%d target_mr0=%d rhat1=%d zhat=%d that=%d sig=%d mask=%d)",
		focus.ReplayMHatSigmaRows,
		focus.ReplayRHat0Rows,
		focus.ReplayR0B2HatRows,
		focus.ReplayTargetMR0HatRows,
		focus.ReplayRHat1Rows,
		focus.ReplayZHatRows,
		focus.ReplayTHatRows,
		focus.InlinedShortnessRows,
		focus.MaskRows,
	)
	if focus.PackedSigShortnessRows > 0 {
		rowFamilies = fmt.Sprintf(
			" rows(mhat=%d rhat0=%d r0b2=%d target_mr0=%d rhat1=%d zhat=%d that=%d sig=%d(g=%d,w=%d,blocks=%d) mask=%d)",
			focus.ReplayMHatSigmaRows,
			focus.ReplayRHat0Rows,
			focus.ReplayR0B2HatRows,
			focus.ReplayTargetMR0HatRows,
			focus.ReplayRHat1Rows,
			focus.ReplayZHatRows,
			focus.ReplayTHatRows,
			focus.PackedSigShortnessRows,
			focus.PackedSigChainGroupSize,
			focus.PackedSigBlockWidth,
			focus.PackedSigEffectiveBlocks,
			focus.MaskRows,
		)
	}
	aggregateR0 := ""
	if focus.AggregateR0Replay {
		aggregateR0 = " aggregate_r0=true"
	}
	ringDegree := ""
	if focus.RingDegree > 0 {
		ringDegree = fmt.Sprintf(" ring_degree=%d", focus.RingDegree)
	}
	x0Len := ""
	if focus.X0Len > 0 {
		x0Len = fmt.Sprintf(" x0_len=%d", focus.X0Len)
	}
	return fmt.Sprintf(
		"Transcript focus: preset=%s replay=%s%s%s blocks=%d lvcs=%d nleaves=%d rowsBlock=%d maskChunks=%d witness=%d nrows=%d m=%d pcols=%d omitP=%d prf_scalars=%d prf_rows=%d (%s) mu_pack=%d mu_rows=%d mu_blocks=%d entries=%d%s%s%s",
		focus.ShowingPreset,
		focus.ReplayMode,
		ringDegree,
		x0Len,
		focus.ReplayBlocks,
		focus.LVCSNCols,
		focus.NLeaves,
		focus.RowsBlock,
		focus.MaskChunks,
		focus.WitnessRows,
		focus.NRows,
		focus.M,
		focus.PCols,
		focus.OmitP,
		focus.PRFLogicalScalars,
		focus.PRFPackedRows,
		layout,
		focus.MuPackWidth,
		focus.MuCarrierRows,
		focus.MuVirtualBlocks,
		focus.RowOpeningEntries,
		aggregateR0,
		rowFamilies,
		instances,
	)
}

func formatStatementSummary(rep PIOP.ProofReport) string {
	class := rep.TranscriptFocus.StatementClass
	replay := rep.TranscriptFocus.ReplayMode
	shortness := rep.SigShortness.Mode
	if shortness == "" {
		shortness = rep.TranscriptFocus.ShortnessMode
	}
	if class == "" && replay == "" && shortness == "" {
		return ""
	}
	if shortness == "" {
		shortness = PIOP.SigShortnessModeNone
	}
	return fmt.Sprintf("Statement: class=%s replay=%s shortness=%s", class, replay, shortness)
}

func formatTranscriptBucketFocusSummary(rep PIOP.ProofReport) string {
	focus := rep.TranscriptFocus
	if focus.PdecsBytes <= 0 && focus.VTargetsBytes <= 0 && focus.BarSetsBytes <= 0 && focus.QBytes <= 0 && rep.PaperTranscript.SigShortness.OptimizedBytes <= 0 {
		return ""
	}
	return fmt.Sprintf(
		"Bucket focus: Pdecs=%d VTargets=%d BarSets=%d Q=%d SigShortness=%d",
		focus.PdecsBytes,
		focus.VTargetsBytes,
		focus.BarSetsBytes,
		focus.QBytes,
		rep.PaperTranscript.SigShortness.OptimizedBytes,
	)
}

func printSigShortness(prefix string, rep PIOP.ProofReport) {
	sig := rep.SigShortness
	if !sig.Enabled {
		return
	}
	mode := sig.Mode
	if mode == "" {
		mode = fmt.Sprintf("v%d", sig.Version)
	}
	cli.printf(categoryGeometry, prefix, "Sig shortness: %s v%d slots=%d blocks=%d opening=%d total=%d",
		mode,
		sig.Version,
		sig.SupportSlotCount,
		sig.OpenedBlockCount,
		sig.OpeningBytes,
		sig.ProofBytes,
	)
}

func printSigLookupShadow(prefix string, rep PIOP.ProofReport) {
	focus := rep.TranscriptFocus
	if focus.SigLookupShadowMode == "" {
		return
	}
	cli.printf(categoryWarning, prefix, "Sig lookup shadow: mode=%s rows=%d->%d cells=%d table=%d",
		focus.SigLookupShadowMode,
		focus.SigRowsBefore,
		focus.SigRowsAfter,
		focus.SigLookupCells,
		focus.SigLookupTableSize,
	)
	if focus.SigLookupShadowMode == PIOP.SigLookupShadowR121L2Free {
		cli.printf(categoryWarning, prefix, "Sig lookup shadow budget: free_upper_bound=%d max_lookup_budget_for_35500=%d",
			focus.FreeLookupUpperBoundBytes,
			focus.MaxLookupBudgetFor35500,
		)
	}
}

func printReplayFamilyAudit(prefix string, rep PIOP.ProofReport) {
	audit := rep.ReplayAudit
	if len(audit.Families) == 0 {
		return
	}
	cli.printf(categoryGeometry, prefix, "%s", formatReplayFamilyAuditSummary(rep))
	for _, entry := range audit.Families {
		cli.printf(categoryGeometry, prefix, "  replay[%s] selected=%3d/%-3d blocks=%2d/%-2d reduction=%s",
			entry.Family,
			entry.SelectedRowCount,
			entry.LogicalRowCount,
			entry.ActiveBlockCount,
			entry.TotalBlockCount,
			entry.ReductionEffect,
		)
	}
	printReplaySubfamilyAudit(prefix, audit.Subfamilies)
	cli.printf(categoryGeometry, prefix, "Replay audit note: selector-derived rows are authoritative; the family inventory above is intentionally a coarse factual summary.")
}

func printReplaySubfamilyAudit(prefix string, audit PIOP.ReplaySubfamilyAuditReport) {
	if len(audit.Entries) == 0 {
		return
	}
	cli.printf(categoryGeometry, prefix, "%s", formatReplaySubfamilyAuditSummary(audit))
	for _, entry := range audit.Entries {
		if entry.SelectedRowCount == 0 {
			continue
		}
		cli.printf(categoryGeometry, prefix, "  replay_sub[%s] selected=%3d/%-3d blocks=%2d/%-2d consumption=%s",
			entry.Kind,
			entry.SelectedRowCount,
			entry.LogicalRowCount,
			entry.ActiveBlockCount,
			entry.TotalBlockCount,
			entry.Consumption,
		)
	}
}

func formatReplayFamilyAuditSummary(rep PIOP.ProofReport) string {
	audit := rep.ReplayAudit
	if len(audit.Families) == 0 {
		return ""
	}
	selectedFamilies := make([]string, 0, len(audit.Families))
	for _, entry := range audit.Families {
		if entry.SelectedRowCount == 0 {
			continue
		}
		selectedFamilies = append(selectedFamilies, string(entry.Family))
	}
	selectedLabel := "none"
	if len(selectedFamilies) > 0 {
		selectedLabel = strings.Join(selectedFamilies, ", ")
	}
	return fmt.Sprintf(
		"Replay audit: selected=%d/%d rows reduction=%.2f%% activeBlocks=%d/%d selectedFamilies=%s",
		audit.Selector.SelectedRows,
		audit.Selector.WitnessRows,
		audit.Selector.ReductionPct,
		audit.Selector.ActiveBlocks,
		audit.Selector.FullBlocks,
		selectedLabel,
	)
}

func formatReplaySubfamilyAuditSummary(audit PIOP.ReplaySubfamilyAuditReport) string {
	if len(audit.Entries) == 0 {
		return ""
	}
	selected := make([]string, 0, len(audit.Entries))
	for _, entry := range audit.Entries {
		if entry.SelectedRowCount == 0 {
			continue
		}
		selected = append(selected, string(entry.Kind))
	}
	if len(selected) == 0 {
		return "Replay subaudit: selectedSubfamilies=none"
	}
	return fmt.Sprintf("Replay subaudit: selectedSubfamilies=%s", strings.Join(selected, ", "))
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
	add("SigShortness", rep.SigShortness, 5)
	add("VTargets", rep.VTargets, 6)
	add("BarSets", rep.BarSets, 7)
	add("Pdecs", rep.Pdecs, 8)
	add("Mdecs", rep.Mdecs, 9)
	add("Auth", rep.Auth, 10)
	add("Tapes", rep.Tapes, 11)
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bytes != rows[j].Bytes {
			return rows[i].Bytes > rows[j].Bytes
		}
		return rows[i].order < rows[j].order
	})
	return rows
}
