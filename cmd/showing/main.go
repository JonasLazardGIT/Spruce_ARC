package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
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
	StatePath           string
	PublicParamsPath    string
	VerifierKeyPath     string
	ContextFile         string
	ExpectedContextFile string
	HolderUsageState    string
	Preset              credential.IntGenISISPreset
	PresentationOut     string
	VerifyPresentation  string
	VerifierStatePath   string
	ProofOnly           bool
	Verbose             bool
}

func intGenISISPresetHelp() string {
	return strings.Join(credential.IntGenISISDefaultPresetNames(), ", ")
}

func parseShowingCLIArgs(args []string) (showingCLIConfig, error) {
	fs := flag.NewFlagSet("showing", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	intGenISISPreset := fs.String("preset", "", "named IntGenISIS preset: "+intGenISISPresetHelp())
	statePathFlag := fs.String("state-path", "", "credential state path for showing; defaults to the selected preset artifact")
	intGenISISPublicParamsPath := fs.String("public-params", "", "IntGenISIS public params path for standalone presentation verification")
	intGenISISVerifierKeyPath := fs.String("verifier-key", "", "IntGenISIS verifier key path for standalone presentation verification")
	contextFile := fs.String("context-file", "", "required opaque service context for presentation creation")
	expectedContextFile := fs.String("expected-context-file", "", "required independently supplied opaque service context for verification")
	holderUsageState := fs.String("holder-usage-state", "", "required durable holder quota-state path")
	presentationOut := fs.String("presentation-out", "", "IntGenISIS presentation output path")
	verifyPresentation := fs.String("verify-presentation", "", "verify an IntGenISIS presentation artifact instead of proving")
	verifierStatePath := fs.String("verifier-state", "", "persistent IntGenISIS verifier replay-state path")
	proofOnly := fs.Bool("proof-only", false, "verify the proof without evaluating rate-limit acceptance")
	verbose := fs.Bool("verbose", false, "print detailed proof diagnostics")
	if err := fs.Parse(args); err != nil {
		return showingCLIConfig{}, err
	}
	selectedIntGenISISPreset, err := credential.ResolveIntGenISISPresetSelector(*intGenISISPreset, false)
	if err != nil {
		return showingCLIConfig{}, err
	}
	*intGenISISPreset = selectedIntGenISISPreset
	if strings.TrimSpace(*intGenISISPreset) == "" {
		return showingCLIConfig{}, fmt.Errorf("missing -preset (available: %s; run issuance list-presets for descriptions)", intGenISISPresetHelp())
	}
	preset, err := credential.MustLookupIntGenISISPreset(*intGenISISPreset)
	if err != nil {
		return showingCLIConfig{}, err
	}
	artifactDir := filepath.Join("artifacts", "smallwood-salted-v2", preset.CanonicalID)
	if *statePathFlag == "" {
		*statePathFlag = filepath.Join(artifactDir, "credential_state.intgenisis.json")
	}
	if *intGenISISPublicParamsPath == "" {
		*intGenISISPublicParamsPath = filepath.Join(artifactDir, fmt.Sprintf("credential_public.%s.json", preset.Profile))
	}
	if *intGenISISVerifierKeyPath == "" {
		*intGenISISVerifierKeyPath = filepath.Join(artifactDir, "intgenisis_verifier_key.json")
	}
	if *presentationOut == "" && *verifyPresentation == "" {
		*presentationOut = filepath.Join(artifactDir, "presentation.intgenisis.json")
	}
	return showingCLIConfig{
		StatePath:           *statePathFlag,
		PublicParamsPath:    *intGenISISPublicParamsPath,
		VerifierKeyPath:     *intGenISISVerifierKeyPath,
		ContextFile:         *contextFile,
		ExpectedContextFile: *expectedContextFile,
		HolderUsageState:    *holderUsageState,
		Preset:              preset,
		PresentationOut:     *presentationOut,
		VerifyPresentation:  *verifyPresentation,
		VerifierStatePath:   *verifierStatePath,
		ProofOnly:           *proofOnly,
		Verbose:             *verbose,
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
	contextFile := cfg.ContextFile
	expectedContextFile := cfg.ExpectedContextFile
	holderUsageState := cfg.HolderUsageState
	cli.printf(categoryStatus, "[showing-cli] ", "starting IntGenISIS showing preset=%s state=%s", preset.CanonicalID, statePath)
	if preset.Lifecycle != credential.PresetComplete || preset.ClaimScope != credential.ClaimCompleteSystem || !preset.CompleteSystemClaim {
		cli.errorf("[showing-cli] ", "warning: preset %s is %s/%s (%s), not a complete-system deployment preset", preset.CanonicalID, preset.Lifecycle, preset.ClaimScope, preset.SecurityProfile)
	}
	if verifyPresentationPath != "" {
		if publicParamsPath == "" {
			return fmt.Errorf("IntGenISIS presentation verification requires -public-params")
		}
		if verifierKeyPath == "" {
			return fmt.Errorf("IntGenISIS presentation verification requires -verifier-key")
		}
		if expectedContextFile == "" {
			return fmt.Errorf("IntGenISIS presentation verification requires -expected-context-file")
		}
		if !cfg.ProofOnly && verifierStatePath == "" {
			return fmt.Errorf("rate-limited IntGenISIS presentation verification requires -verifier-state (or use -proof-only)")
		}
		if cfg.ProofOnly && verifierStatePath != "" {
			return fmt.Errorf("-proof-only cannot be combined with -verifier-state")
		}
		publicParams, err := credential.LoadPublicParams(publicParamsPath)
		if err != nil {
			return fmt.Errorf("load IntGenISIS public params: %w", err)
		}
		if !publicParams.UsesIntGenISIS() {
			return fmt.Errorf("standalone verifier public params are not IntGenISIS")
		}
		if err := publicParams.ValidateIntGenISISPreset(preset); err != nil {
			return err
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
		if verifierKey.PresetID != publicParams.PresetID || verifierKey.PresetVersion != publicParams.PresetVersion || verifierKey.PresetManifestDigest != publicParams.PresetManifestDigest {
			return fmt.Errorf("verifier key preset binding mismatch")
		}
		ringQ, err := credential.LoadRingWithDegree(publicParams.RingDegree)
		if err != nil {
			return fmt.Errorf("load ring: %w", err)
		}
		opts := intGenISISShowingOpts(publicParams.RingDegree, preset.Showing)
		return verifyIntGenISISPresentationCLI(verifyPresentationPath, expectedContextFile, verifierStatePath, cfg.ProofOnly, verifierKey, publicParams, ringQ, opts)
	}
	if cfg.ProofOnly {
		return fmt.Errorf("-proof-only is only valid with -verify-presentation")
	}
	if contextFile == "" {
		return fmt.Errorf("IntGenISIS presentation creation requires -context-file")
	}
	if holderUsageState == "" {
		return fmt.Errorf("IntGenISIS presentation creation requires -holder-usage-state")
	}
	if verifierKeyPath == "" {
		return fmt.Errorf("IntGenISIS presentation creation requires -verifier-key")
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
	if err := st.ValidateIntGenISISPreset(publicParams, preset); err != nil {
		return err
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
	params, actualPRFParamsDigest, err := loadPRFParamsFromIntGenISISState(st)
	if err != nil {
		return fmt.Errorf("load prf params: %w", err)
	}
	if actualPRFParamsDigest != preset.PRFParamsDigest {
		return fmt.Errorf("loaded PRF parameter digest does not match bound profile %s", preset.PRFProfile)
	}
	wantTag, ok := credential.IntGenISISPRFProfileTagElements(preset.PRFProfile)
	if !ok || params.LenTag != wantTag {
		return fmt.Errorf("loaded PRF tag elements=%d do not match bound profile %s (%d)", params.LenTag, preset.PRFProfile, wantTag)
	}
	opts := intGenISISShowingOpts(st.RingDegree, preset.Showing)
	if st.PRFParamsPath != "" {
		opts.PRFParamsPath = st.PRFParamsPath
	}
	if opts.NCols < params.LenKey {
		return fmt.Errorf("ncols=%d is too small for IntGenISIS PRF key width %d", opts.NCols, params.LenKey)
	}
	if params.LenNonce != credential.IntGenISISContextLaneCount+credential.IntGenISISHiddenSlotLaneCount {
		return fmt.Errorf("PRF input width=%d want %d public context lanes plus one hidden slot", params.LenNonce, credential.IntGenISISContextLaneCount)
	}
	if verifyPresentationPath != "" {
		return fmt.Errorf("unreachable IntGenISIS presentation verification branch")
	}
	verifierKey, err := credential.LoadIntGenISISVerifierKey(verifierKeyPath)
	if err != nil {
		return err
	}
	if err := st.ValidateAgainst(publicParams, verifierKey); err != nil {
		return fmt.Errorf("credential/verifier binding: %w", err)
	}
	rawContext, err := readPresentationContextFile(contextFile)
	if err != nil {
		return err
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
	var proof *PIOP.Proof
	var pub PIOP.PublicInputs
	var proofDur time.Duration
	var verifyDur time.Duration
	pres, err := credential.CreatePresentation(publicParams, verifierKey, st, rawContext, holderUsageState, func(contextBinding credential.PresentationContextBinding, slot uint8) ([]int64, json.RawMessage, error) {
		if wit.CoeffNativeShowing == nil {
			return nil, nil, fmt.Errorf("missing coefficient-native showing witness")
		}
		wit.CoeffNativeShowing.HiddenSlot = uint64(slot)
		for i := range wit.CoeffNativeShowing.HiddenBits {
			wit.CoeffNativeShowing.HiddenBits[i] = uint64(slot>>i) & 1
		}
		contextElems := make([]prf.Elem, len(contextBinding.Lanes))
		for i, value := range contextBinding.Lanes {
			contextElems[i] = prf.Elem(value)
		}
		tag, err := prf.TagContextSlot(key, contextElems, prf.Elem(slot), params)
		if err != nil {
			return nil, nil, fmt.Errorf("compute IntGenISIS tag: %w", err)
		}
		tagScalars := elemsToCanonicalScalars(tag)
		pub = PIOP.PublicInputs{
			A:              A,
			B:              B,
			CM:             cm,
			AS:             as,
			Tag:            tagScalars,
			Context:        append([]int64(nil), contextBinding.Lanes...),
			ContextDigest:  mustDecodeDigest(contextBinding.Digest),
			BoundB:         publicParams.CommitmentBound,
			HashInputBound: publicParams.HashInputBound,
			X0Len:          publicParams.EllX0,
			RingDegree:     int(ringQ.N),
			HashRelation:   publicParams.HashRelation,
			IntGenISIS:     true,
			Extras:         publicParams.PresetTranscriptExtras(intGenISISSignatureBoundExtras(st.SignatureBound)),
		}
		proofStart := time.Now()
		proof, err = PIOP.BuildIntGenISISShowingCombined(pub, wit, opts)
		proofDur = time.Since(proofStart)
		if err != nil {
			return nil, nil, fmt.Errorf("build IntGenISIS showing: %w", err)
		}
		verifyStart := time.Now()
		verified, verifyErr := PIOP.VerifyIntGenISISShowing(pub, proof, opts)
		verifyDur = time.Since(verifyStart)
		if verifyErr != nil || !verified {
			return nil, nil, fmt.Errorf("verify IntGenISIS showing failed: ok=%v err=%v", verified, verifyErr)
		}
		proofRaw, err := json.Marshal(proof)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal IntGenISIS proof: %w", err)
		}
		return tagScalars, proofRaw, nil
	})
	if err != nil {
		return err
	}
	if presentationOut != "" {
		if err := credential.SaveIntGenISISPresentation(presentationOut, pres); err != nil {
			return fmt.Errorf("save IntGenISIS presentation: %w", err)
		}
		cli.printf(categoryStatus, "[showing-cli] ", "IntGenISIS presentation wrote %s", presentationOut)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "IntGenISIS showing proof verified")
	if cfg.Verbose {
		printLogicalWitnessRowBreakdown("[showing-cli] ", proof)
		printCommittedWitnessRowBreakdown("[showing-cli] ", proof)
	}
	_, _ = printProofReport("[showing-cli] ", proof, opts, publicParams.CommitmentBound, ringQ, proofDur, verifyDur, cfg.Verbose)
	return nil
}

func intGenISISShowingOpts(ringDegree int, tuning credential.IntGenISISTuningPreset) PIOP.SimOpts {
	protocol, version, _ := credential.ResolveIntGenISISTranscript(tuning.TranscriptMode)
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
		ROQueryCaps:                tuning.ROQueryCaps,
		ROQueryCapsSet:             tuning.ROQueryCapsSet,
		ROQueryCapBits:             tuning.ROQueryCapBits,
		ROQueryCapBitsSet:          tuning.ROQueryCapBitsSet,
		DECSCollisionBits:          tuning.DECSCollisionBits,
		DECSHashBits:               tuning.DECSHashBits,
		DECSTapeBits:               tuning.DECSTapeBits,
		FSCollisionBits:            tuning.FSCollisionBits,
		SaltBits:                   tuning.SaltBits,
		PRFParamsPath:              tuning.PRFParamsPath,
		DomainMode:                 PIOP.DomainModeExplicit,
		PRFGroupRounds:             tuning.PRFGroupRounds,
		PRFCompanionMode:           PIOP.PRFCompanionMode(tuning.PRFCompanionMode),
		PRFCheckpointSamples:       tuning.CheckpointSamples,
		IntGenISISMSECompression:   tuning.CompressedRows,
		IntGenISISReplayProjection: tuning.ReplayProjection,
		SigShortnessRadix:          tuning.SigShortnessRadix,
		SigShortnessL:              tuning.SigShortnessDigits,
		FixedTranscriptSize:        tuning.FixedTranscriptSize,
		TranscriptOmissionMode:     tuning.TranscriptOmissionMode,
		TranscriptProtocolMode:     protocol,
		TranscriptVersion:          version,
	})
}

func verifyIntGenISISPresentationCLI(path, expectedContextPath, verifierStatePath string, proofOnly bool, verifierKey credential.IntGenISISVerifierKey, publicParams credential.PublicParams, ringQ *ring.Ring, opts PIOP.SimOpts) error {
	pres, err := credential.LoadIntGenISISPresentation(path)
	if err != nil {
		return err
	}
	rawContext, err := readPresentationContextFile(expectedContextPath)
	if err != nil {
		return err
	}
	verifyProof := func(bound credential.IntGenISISPresentation) (bool, error) {
		var proof PIOP.Proof
		if err := decodeStrictPresentationProof(bound.Proof, &proof); err != nil {
			return false, fmt.Errorf("unmarshal presentation proof: %w", err)
		}
		B, err := loadBForIntGenISISShowing(ringQ, publicParams)
		if err != nil {
			return false, err
		}
		A, err := buildIntGenISISSignatureMatrixFromRows(ringQ, verifierKey.NTRUPublic)
		if err != nil {
			return false, err
		}
		cm, err := commitment.MatrixFromCoeff(ringQ, publicParams.CM)
		if err != nil {
			return false, fmt.Errorf("lift C_M: %w", err)
		}
		as, err := commitment.MatrixFromCoeff(ringQ, publicParams.AS)
		if err != nil {
			return false, fmt.Errorf("lift A_s: %w", err)
		}
		pub := PIOP.PublicInputs{
			A:              A,
			B:              B,
			CM:             cm,
			AS:             as,
			Tag:            bound.Tag,
			Context:        append([]int64(nil), bound.Context...),
			ContextDigest:  mustDecodeDigest(bound.ContextDigest),
			BoundB:         publicParams.CommitmentBound,
			HashInputBound: publicParams.HashInputBound,
			X0Len:          publicParams.EllX0,
			RingDegree:     int(ringQ.N),
			HashRelation:   publicParams.HashRelation,
			IntGenISIS:     true,
			Extras:         publicParams.PresetTranscriptExtras(intGenISISSignatureBoundExtras(verifierKey.SignatureBound)),
		}
		return PIOP.VerifyIntGenISISShowing(pub, &proof, opts)
	}
	if proofOnly {
		verified, err := credential.VerifyProof(pres, publicParams, verifierKey, rawContext, verifyProof)
		if err != nil || !verified {
			return fmt.Errorf("verify IntGenISIS presentation failed: ok=%v err=%v", verified, err)
		}
		cli.printf(categoryStatus, "[showing-cli] ", "IntGenISIS proof valid; rate-limit acceptance not evaluated")
		return nil
	}
	accepted, err := credential.VerifyAndAccept(pres, publicParams, verifierKey, rawContext, verifierStatePath, verifyProof)
	if err != nil || !accepted {
		return fmt.Errorf("rate-limit acceptance failed: accepted=%v err=%v", accepted, err)
	}
	cli.printf(categoryStatus, "[showing-cli] ", "IntGenISIS proof valid; rate-limit presentation accepted")
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

func loadPRFParamsFromIntGenISISState(st credential.IntGenISISState) (*prf.Params, string, error) {
	if st.PRFParamsPath != "" {
		return prf.LoadLocalOrBundledParamsWithDigest(st.PRFParamsPath)
	}
	return prf.LoadLocalOrBundledParamsWithDigest(filepath.Join("prf", "prf_params.json"))
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
		for j, coefficient := range meta.B[i] {
			if coefficient >= r.Modulus[0] {
				return nil, fmt.Errorf("b[%d][%d]=%d is not canonical modulo %d", i, j, coefficient, r.Modulus[0])
			}
			p.Coeffs[0][j] = coefficient
		}
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

func elemsToCanonicalScalars(vals []prf.Elem) []int64 {
	out := make([]int64, len(vals))
	for i, v := range vals {
		out[i] = int64(v)
	}
	return out
}

func readPresentationContextFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("missing presentation context file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read presentation context %s: %w", path, err)
	}
	if len(raw) == 0 || len(raw) > credential.IntGenISISMaxContextBytes {
		return nil, fmt.Errorf("presentation context length=%d outside [1,%d]", len(raw), credential.IntGenISISMaxContextBytes)
	}
	return raw, nil
}

func mustDecodeDigest(value string) []byte {
	out, err := hex.DecodeString(value)
	if err != nil || len(out) != 32 {
		panic("validated digest failed to decode")
	}
	return out
}

func decodeStrictPresentationProof(raw []byte, proof *PIOP.Proof) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(proof); err != nil {
		return err
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
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

func printProofReport(prefix string, proof *PIOP.Proof, opts PIOP.SimOpts, boundB int64, ringQ *ring.Ring, proveDur, verifyDur time.Duration, verbose bool) (PIOP.ProofReport, bool) {
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		cli.printf(categoryWarning, prefix, "report: %v", err)
		return PIOP.ProofReport{}, false
	}
	sigBase, sigL, sigRowsPer, sigDegree, sigErr := PIOP.ResolveSignatureShortnessMetricsForOpts(ringQ.Modulus[0], opts)
	if !verbose {
		printConciseProofReport(prefix, rep, proveDur, verifyDur)
		return rep, true
	}
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

func printConciseProofReport(prefix string, rep PIOP.ProofReport, proveDur, verifyDur time.Duration) {
	cli.printf(categoryTranscript, prefix, "paper_transcript_bytes=%d paper_transcript_kb=%.2f theorem_total_bits=%.2f",
		rep.PaperTranscript.OptimizedBytes,
		float64(rep.PaperTranscript.OptimizedBytes)/1024.0,
		displayBits(rep.Soundness.TotalBits),
	)
	if proveDur > 0 || verifyDur > 0 {
		cli.printf(categoryStatus, prefix, "timing prove=%s verify=%s", proveDur, verifyDur)
	}
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
