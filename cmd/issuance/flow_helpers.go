package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	"vSIS-Signature/issuance"
	"vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
	"vSIS-Signature/prf"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

type intGenISISHolderWitnessSpec struct {
	M     [][]int64 `json:"M"`
	MAttr [][]int64 `json:"m,omitempty"`
	K     [][]int64 `json:"k,omitempty"`
	S     [][]int64 `json:"s"`
	E     [][]int64 `json:"e"`
}

type smallWoodTuningSpec struct {
	NCols               int    `json:"ncols,omitempty"`
	LVCSNCols           int    `json:"lvcs_ncols,omitempty"`
	NLeaves             int    `json:"nleaves,omitempty"`
	Ell                 int    `json:"ell,omitempty"`
	EllPrime            int    `json:"ell_prime,omitempty"`
	Eta                 int    `json:"eta,omitempty"`
	Theta               int    `json:"theta,omitempty"`
	Rho                 int    `json:"rho,omitempty"`
	Kappa               [4]int `json:"kappa,omitempty"`
	TranscriptMode      string `json:"transcript_mode,omitempty"`
	FixedTranscriptSize bool   `json:"fixed_transcript_size,omitempty"`
}

type holderSecretFile struct {
	Version              int                          `json:"version"`
	CredentialPublicPath string                       `json:"credential_public_path"`
	PRFParamsPath        string                       `json:"prf_params_path"`
	PackedNCols          int                          `json:"packed_ncols"`
	LVCSNCols            int                          `json:"lvcs_ncols,omitempty"`
	NLeaves              int                          `json:"nleaves,omitempty"`
	SmallWood            *smallWoodTuningSpec         `json:"smallwood,omitempty"`
	Omega                []uint64                     `json:"omega"`
	IntGenISIS           *intGenISISHolderWitnessSpec `json:"intgenisis,omitempty"`
}

type commitRequestFile struct {
	Version              int                  `json:"version"`
	CredentialPublicPath string               `json:"credential_public_path"`
	PackedNCols          int                  `json:"packed_ncols,omitempty"`
	LVCSNCols            int                  `json:"lvcs_ncols,omitempty"`
	NLeaves              int                  `json:"nleaves,omitempty"`
	SmallWood            *smallWoodTuningSpec `json:"smallwood,omitempty"`
	Omega                []uint64             `json:"omega"`
	Com                  [][]int64            `json:"com"`
}

type preSignSubmissionFile struct {
	Version              int         `json:"version"`
	CredentialPublicPath string      `json:"credential_public_path"`
	Proof                *PIOP.Proof `json:"proof"`
}

type issueResponseFile struct {
	Version              int       `json:"version"`
	CredentialPublicPath string    `json:"credential_public_path"`
	T                    []int64   `json:"t,omitempty"`
	MuSig                [][]int64 `json:"mu_sig,omitempty"`
	X0                   [][]int64 `json:"x0,omitempty"`
	X1                   [][]int64 `json:"x1,omitempty"`
	SigS1                []int64   `json:"sig_s1"`
	SigS2                []int64   `json:"sig_s2"`
	NTRUPublic           [][]int64 `json:"ntru_public,omitempty"`
}

type issuanceRuntime struct {
	ringQ      *ring.Ring
	publicPath string
	public     credential.PublicParams
	params     *credential.Params
	prfPath    string
	prfParams  *prf.Params
	opts       PIOP.SimOpts
	omega      []uint64
}

type issuanceRuntimeOverrides struct {
	NCols               int
	LVCSNCols           int
	NLeaves             int
	Ell                 int
	EllPrime            int
	Eta                 int
	Theta               int
	Rho                 int
	Kappa               [4]int
	TranscriptMode      string
	FixedTranscriptSize bool
	RingDegree          int
}

func ntruSigningPaths(paramsPath, publicPath, privatePath, signaturePath string) signverify.SignPaths {
	return signverify.SignPaths{
		ParamsPath:    paramsPath,
		PublicKeyPath: publicPath,
		PrivatePath:   privatePath,
		SignaturePath: signaturePath,
	}
}

const issuanceArtifactVersion = 2

func persistedIssuanceRuntimeOverrides(ncols, lvcsNCols, nLeaves int, omega []uint64) issuanceRuntimeOverrides {
	return persistedIssuanceRuntimeOverridesWithSmallWood(ncols, lvcsNCols, nLeaves, omega, nil)
}

func persistedIssuanceRuntimeOverridesWithSmallWood(ncols, lvcsNCols, nLeaves int, omega []uint64, spec *smallWoodTuningSpec) issuanceRuntimeOverrides {
	if ncols <= 0 && len(omega) > 0 {
		ncols = len(omega)
	}
	out := issuanceRuntimeOverrides{
		NCols:      ncols,
		LVCSNCols:  lvcsNCols,
		NLeaves:    nLeaves,
		RingDegree: 0,
	}
	if spec != nil {
		if spec.NCols > 0 {
			out.NCols = spec.NCols
		}
		if out.NCols <= 0 && len(omega) > 0 {
			out.NCols = len(omega)
		}
		out.LVCSNCols = spec.LVCSNCols
		out.NLeaves = spec.NLeaves
		out.Ell = spec.Ell
		out.EllPrime = spec.EllPrime
		out.Eta = spec.Eta
		out.Theta = spec.Theta
		out.Rho = spec.Rho
		out.Kappa = spec.Kappa
		out.TranscriptMode = spec.TranscriptMode
		out.FixedTranscriptSize = spec.FixedTranscriptSize
	}
	return out
}

func smallWoodTuningSpecFromOpts(opts PIOP.SimOpts) *smallWoodTuningSpec {
	transcriptMode := ""
	if opts.TranscriptProtocolMode == PIOP.TranscriptProtocolSmallField2025V1 {
		transcriptMode = sweepTranscriptModeSmallField2025
	}
	return &smallWoodTuningSpec{
		NCols:               opts.NCols,
		LVCSNCols:           opts.LVCSNCols,
		NLeaves:             opts.NLeaves,
		Ell:                 opts.Ell,
		EllPrime:            opts.EllPrime,
		Eta:                 opts.Eta,
		Theta:               opts.Theta,
		Rho:                 opts.Rho,
		Kappa:               opts.Kappa,
		TranscriptMode:      transcriptMode,
		FixedTranscriptSize: opts.FixedTranscriptSize,
	}
}

func applyIssuanceRuntimeOverrides(opts PIOP.SimOpts, overrides issuanceRuntimeOverrides) PIOP.SimOpts {
	if overrides.NCols > 0 {
		opts.NCols = overrides.NCols
	}
	if overrides.LVCSNCols > 0 {
		opts.LVCSNCols = overrides.LVCSNCols
		opts.PostSignLVCSNCols = overrides.LVCSNCols
		opts.PRFLVCSNCols = overrides.LVCSNCols
	}
	if overrides.NLeaves > 0 {
		opts.NLeaves = overrides.NLeaves
		opts.PostSignNLeaves = overrides.NLeaves
		opts.PRFNLeaves = overrides.NLeaves
	}
	if overrides.Ell > 0 {
		opts.Ell = overrides.Ell
	}
	if overrides.EllPrime > 0 {
		opts.EllPrime = overrides.EllPrime
	}
	if overrides.Eta > 0 {
		opts.Eta = overrides.Eta
	}
	if overrides.Theta > 0 {
		opts.Theta = overrides.Theta
	}
	if overrides.Rho > 0 {
		opts.Rho = overrides.Rho
	}
	if overrides.Kappa != ([4]int{}) {
		opts.Kappa = overrides.Kappa
	}
	if overrides.TranscriptMode != "" {
		opts.TranscriptCodec = intGenISISLiveTranscriptCodecOrDefault(overrides.TranscriptMode)
		opts.TranscriptProtocolMode = intGenISISLiveTranscriptProtocolOrDefault(overrides.TranscriptMode)
		opts.TranscriptVersion = intGenISISLiveTranscriptVersionOrDefault(overrides.TranscriptMode)
	}
	opts.FixedTranscriptSize = overrides.FixedTranscriptSize
	return opts
}

func credentialPublicPathDefault() string {
	return credential.DefaultPublicParamsPath
}

func setupIntGenISISPublic(outPath string, force bool, profileName, bPath string) error {
	profile, ok := credential.LookupIntGenISISProfile(profileName)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", profileName)
	}
	return setupIntGenISISPublicForProfile(outPath, force, profile, bPath)
}

func setupIntGenISISPublicForProfile(outPath string, force bool, profile credential.IntGenISISProfile, bPath string) error {
	ringQ, err := credential.LoadRingWithDegree(profile.N)
	if err != nil {
		return fmt.Errorf("load ring: %w", err)
	}
	if profile.Q != 0 && ringQ.Modulus[0] != profile.Q {
		return fmt.Errorf("profile %s q=%d incompatible with loaded ring q=%d", profile.Name, profile.Q, ringQ.Modulus[0])
	}
	if bPath == "" {
		bPath = filepath.Join(filepath.Dir(outPath), fmt.Sprintf("Bmatrix.%s.json", profile.Name))
	}
	if !force {
		for _, path := range []string{outPath, bPath} {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("refusing to overwrite existing %s without -force", path)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("stat %s: %w", path, err)
			}
		}
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		return fmt.Errorf("new prng: %w", err)
	}
	B, err := vsishash.GenerateBWithX0Len(ringQ, prng, profile.EllX0)
	if err != nil {
		return fmt.Errorf("generate B: %w", err)
	}
	coeffs := make([][]uint64, len(B))
	for i := range B {
		coeffs[i] = append([]uint64(nil), B[i].Coeffs[0]...)
	}
	if err := os.MkdirAll(filepath.Dir(bPath), 0o755); err != nil {
		return fmt.Errorf("mkdir B dir: %w", err)
	}
	if err := ntrurio.SaveBMatrixCoeffs(bPath, coeffs); err != nil {
		return fmt.Errorf("save B matrix: %w", err)
	}
	cm, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.EllM)
	if err != nil {
		return fmt.Errorf("generate C_M: %w", err)
	}
	as, err := commitment.GenerateUniformCoeffMatrix(ringQ, profile.NC, profile.KS)
	if err != nil {
		return fmt.Errorf("generate A_s: %w", err)
	}
	params := credential.PublicParams{
		Version:              credential.PublicParamsVersion,
		Profile:              profile.Name,
		Modulus:              ringQ.Modulus[0],
		HashRelation:         credential.HashRelationBBTran,
		BPath:                bPath,
		BoundB:               profile.B,
		CommitmentBound:      profile.B,
		RingDegree:           profile.N,
		CM:                   cm,
		AS:                   as,
		EllM:                 profile.EllM,
		KS:                   profile.KS,
		NC:                   profile.NC,
		EllMuSig:             profile.EllMuSig,
		EllX0:                profile.EllX0,
		EllX1:                profile.EllX1,
		SignaturePreimageLen: profile.SignaturePreimageLen,
		MLWEHidingBits:       profile.MLWEHidingBits,
		MSISBindingBits:      profile.MSISBindingBits,
		CommitmentSecurity:   profile.CommitmentSecurity.ClonePtr(),
		TargetDim:            profile.NC,
		X0Len:                profile.EllX0,
	}
	if err := credential.SavePublicParams(outPath, params); err != nil {
		return err
	}
	log.Printf("[issuance-cli] wrote IntGenISIS public params to %s", outPath)
	layout, layoutErr := credential.DefaultSemanticMessageLayout(profile, 8)
	if layoutErr == nil {
		log.Printf("[issuance-cli] profile=%s N=%d q=%d ell_M=%d k_s=%d n_c=%d compat_B=%d live_M_s_e_domain=%s live_key_domain=%s live_bound=%d ell_x0=%d", profile.Name, profile.N, profile.Q, profile.EllM, profile.KS, profile.NC, profile.B, layout.MSEDomain, layout.KeyDomain, layout.Bound, profile.EllX0)
	} else {
		log.Printf("[issuance-cli] profile=%s N=%d q=%d ell_M=%d k_s=%d n_c=%d compat_B=%d ell_x0=%d", profile.Name, profile.N, profile.Q, profile.EllM, profile.KS, profile.NC, profile.B, profile.EllX0)
	}
	return nil
}

func setupNTRUKeys(ringDegree int, paramsOut, publicOut, privateOut string, force bool, keygenTrials, attempts int, betaOverride uint64) error {
	ringQ, err := credential.LoadRingWithDegree(ringDegree)
	if err != nil {
		return fmt.Errorf("load ring: %w", err)
	}
	selectedN := int(ringQ.N)
	if selectedN != 1024 && selectedN != 512 {
		return fmt.Errorf("unsupported NTRU ring_degree=%d; maintained degrees are 1024 and 512", selectedN)
	}
	if paramsOut == "" {
		if selectedN == 512 {
			paramsOut = filepath.Join("Parameters", "Parameters.n512.json")
		} else {
			paramsOut = defaultNTRUParamsPath
		}
	}
	if publicOut == "" {
		if selectedN == 512 {
			publicOut = filepath.Join("ntru_keys", "public.n512.json")
		} else {
			publicOut = defaultNTRUPublicKeyPath
		}
	}
	if privateOut == "" {
		if selectedN == 512 {
			privateOut = filepath.Join("ntru_keys", "private.n512.json")
		} else {
			privateOut = defaultNTRUPrivateKeyPath
		}
	}
	if keygenTrials <= 0 {
		return fmt.Errorf("invalid keygen-trials=%d", keygenTrials)
	}
	if attempts <= 0 {
		attempts = 1
	}
	if !force {
		for _, path := range []string{paramsOut, publicOut, privateOut} {
			if _, err := os.Stat(path); err == nil {
				return fmt.Errorf("refusing to overwrite existing %s without -force", path)
			} else if !os.IsNotExist(err) {
				return fmt.Errorf("stat %s: %w", path, err)
			}
		}
	}
	base, err := ntrurio.LoadParams(defaultNTRUParamsPath, true)
	if err != nil {
		return fmt.Errorf("load base NTRU params: %w", err)
	}
	params := ntrurio.SystemParams{
		N:    selectedN,
		Q:    ringQ.Modulus[0],
		Beta: base.Beta,
	}
	if selectedN == 512 && betaOverride == 0 {
		params.Beta = credential.IntGenISISN512SignatureBeta
	}
	if betaOverride > 0 {
		if betaOverride > base.Beta {
			return fmt.Errorf("ntru beta override=%d exceeds base beta=%d", betaOverride, base.Beta)
		}
		params.Beta = betaOverride
	}
	if err := ntrurio.SaveParams(paramsOut, params); err != nil {
		return fmt.Errorf("write NTRU params: %w", err)
	}
	wroteFreshParams := !force
	par, err := ntru.NewParams(selectedN, new(big.Int).SetUint64(params.Q))
	if err != nil {
		return fmt.Errorf("build NTRU params: %w", err)
	}
	kg := ntru.KeygenOpts{
		Prec:      512,
		MaxTrials: keygenTrials,
		Alpha:     1.20,
	}
	if _, _, err := generateIssuanceNTRUKeypairWithRetry(par, kg, attempts, publicOut, privateOut); err != nil {
		if wroteFreshParams {
			_ = os.Remove(paramsOut)
		}
		return fmt.Errorf("generate NTRU keypair: %w", err)
	}
	log.Printf("[issuance-cli] wrote NTRU params to %s", paramsOut)
	log.Printf("[issuance-cli] wrote NTRU public key to %s", publicOut)
	log.Printf("[issuance-cli] wrote NTRU private key to %s", privateOut)
	return nil
}

func generateIssuanceNTRUKeypairWithRetry(par ntru.Params, kg ntru.KeygenOpts, attempts int, publicOut, privateOut string) (*keys.PublicKey, *keys.PrivateKey, error) {
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		pk, sk, err := signverify.GenerateKeypairAnnulusToFiles(par, kg, publicOut, privateOut)
		if err == nil {
			return pk, sk, nil
		}
		lastErr = err
		if attempt < attempts {
			log.Printf("[issuance-cli] retrying annulus keygen after attempt %d/%d failed: %v", attempt, attempts, err)
		}
	}
	return nil, nil, lastErr
}

func holderCommit(publicPath, prfPath, holderSecretPath, commitRequestPath, expertInputPath string, seed int64, overrides issuanceRuntimeOverrides) error {
	rt, err := loadIssuanceRuntime(publicPath, prfPath, overrides)
	if err != nil {
		return err
	}
	if !rt.public.UsesIntGenISIS() {
		return fmt.Errorf("holder-commit supports only IntGenISIS public params")
	}
	return holderCommitIntGenISIS(rt, publicPath, prfPath, holderSecretPath, commitRequestPath, expertInputPath, seed)
}

func holderCommitIntGenISIS(rt *issuanceRuntime, publicPath, prfPath, holderSecretPath, commitRequestPath, expertInputPath string, seed int64) error {
	if expertInputPath != "" {
		return fmt.Errorf("IntGenISIS holder-commit does not accept expert-input artifacts")
	}
	profile, ok := credential.LookupIntGenISISProfile(rt.public.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", rt.public.Profile)
	}
	if rt.public.CommitmentBound > 0 {
		profile.B = rt.public.CommitmentBound
	}
	rng := newLocalRNG(seed)
	layout, err := credential.DefaultSemanticMessageLayout(profile, rt.prfParams.LenKey)
	if err != nil {
		return err
	}
	sampleLive := func() int64 {
		return rng.Int63n(2*layout.Bound+1) - layout.Bound
	}
	key := make([]int64, rt.prfParams.LenKey)
	for i := 0; i < rt.prfParams.LenKey; i++ {
		key[i] = sampleLive()
	}
	attrs := credential.ZeroSemanticAttributes(layout)
	for _, slot := range layout.Attribute {
		attrs[slot.Poly][slot.Coeff] = sampleLive()
	}
	semantic, err := credential.EncodeSemanticMessage(layout, attrs, key)
	if err != nil {
		return fmt.Errorf("encode IntGenISIS semantic message: %w", err)
	}
	M := polysFromInt64(rt.ringQ, semantic.M)[0]
	MAttr := polysFromInt64(rt.ringQ, semantic.MAttr)[0]
	K := polysFromInt64(rt.ringQ, semantic.K)[0]
	s, e, err := issuance.SampleIntGenISISCommitmentRandomness(rt.params, rng)
	if err != nil {
		return fmt.Errorf("sample IntGenISIS commitment randomness: %w", err)
	}
	inputs := issuance.IntGenISISInputs{
		M:     []*ring.Poly{M},
		MAttr: []*ring.Poly{MAttr},
		K:     []*ring.Poly{K},
		S:     s,
		E:     e,
	}
	com, err := issuance.PrepareIntGenISISCommit(rt.params, inputs)
	if err != nil {
		return fmt.Errorf("prepare IntGenISIS commit: %w", err)
	}
	secret := holderSecretFile{
		Version:              issuanceArtifactVersion,
		CredentialPublicPath: publicPath,
		PRFParamsPath:        prfPath,
		PackedNCols:          rt.opts.NCols,
		LVCSNCols:            rt.opts.LVCSNCols,
		NLeaves:              rt.opts.NLeaves,
		SmallWood:            smallWoodTuningSpecFromOpts(rt.opts),
		Omega:                append([]uint64(nil), rt.omega...),
		IntGenISIS: &intGenISISHolderWitnessSpec{
			M:     polyVecToInt64(rt.ringQ, inputs.M, false),
			MAttr: polyVecToInt64(rt.ringQ, inputs.MAttr, false),
			K:     polyVecToInt64(rt.ringQ, inputs.K, false),
			S:     polyVecToInt64(rt.ringQ, inputs.S, false),
			E:     polyVecToInt64(rt.ringQ, inputs.E, false),
		},
	}
	request := commitRequestFile{
		Version:              issuanceArtifactVersion,
		CredentialPublicPath: publicPath,
		PackedNCols:          rt.opts.NCols,
		LVCSNCols:            rt.opts.LVCSNCols,
		NLeaves:              rt.opts.NLeaves,
		SmallWood:            smallWoodTuningSpecFromOpts(rt.opts),
		Omega:                append([]uint64(nil), rt.omega...),
		Com:                  polyVecToInt64(rt.ringQ, com, true),
	}
	if err := writeJSONFile(holderSecretPath, secret, 0o600); err != nil {
		return fmt.Errorf("write IntGenISIS holder secret: %w", err)
	}
	if err := writeJSONFile(commitRequestPath, request, 0o644); err != nil {
		return fmt.Errorf("write IntGenISIS commit request: %w", err)
	}
	log.Printf("[issuance-cli] IntGenISIS holder commit wrote %s and %s", holderSecretPath, commitRequestPath)
	return nil
}

func holderProve(holderSecretPath, challengePath, submissionPath string) error {
	var secret holderSecretFile
	if err := readJSONFile(holderSecretPath, &secret); err != nil {
		return fmt.Errorf("read holder secret: %w", err)
	}
	if secret.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported holder secret version %d", secret.Version)
	}
	rt, err := loadIssuanceRuntime(secret.CredentialPublicPath, secret.PRFParamsPath, persistedIssuanceRuntimeOverridesWithSmallWood(secret.PackedNCols, secret.LVCSNCols, secret.NLeaves, secret.Omega, secret.SmallWood))
	if err != nil {
		return err
	}
	if !rt.public.UsesIntGenISIS() {
		return fmt.Errorf("holder-prove supports only IntGenISIS public params")
	}
	_ = challengePath
	return holderProveIntGenISIS(rt, secret, submissionPath)
}

func holderProveIntGenISIS(rt *issuanceRuntime, secret holderSecretFile, submissionPath string) error {
	inputs, err := intGenISISInputsFromSecret(rt.ringQ, secret)
	if err != nil {
		return err
	}
	com, err := issuance.PrepareIntGenISISCommit(rt.params, inputs)
	if err != nil {
		return fmt.Errorf("prepare IntGenISIS commit: %w", err)
	}
	cm, as, err := intGenISISCommitmentMatricesNTT(rt.ringQ, rt.public)
	if err != nil {
		return err
	}
	pub := PIOP.PublicInputs{
		Com:          com,
		CM:           cm,
		AS:           as,
		BoundB:       rt.public.CommitmentBound,
		X0Len:        rt.public.EllX0,
		RingDegree:   int(rt.ringQ.N),
		HashRelation: rt.public.HashRelation,
		IntGenISIS:   true,
	}
	proof, err := PIOP.BuildIntGenISISPreSign(rt.ringQ, pub, PIOP.WitnessInputs{
		M:     inputs.M,
		MAttr: inputs.MAttr,
		K:     inputs.K,
		S:     inputs.S,
		E:     inputs.E,
	}, rt.opts)
	if err != nil {
		return fmt.Errorf("prove IntGenISIS pre-sign: %w", err)
	}
	out := preSignSubmissionFile{
		Version:              issuanceArtifactVersion,
		CredentialPublicPath: secret.CredentialPublicPath,
		Proof:                proof,
	}
	if err := writeJSONFile(submissionPath, out, 0o644); err != nil {
		return fmt.Errorf("write IntGenISIS submission: %w", err)
	}
	log.Printf("[issuance-cli] IntGenISIS holder prove wrote %s", submissionPath)
	return nil
}

func issuerVerifySign(commitRequestPath, challengePath, submissionPath, responsePath string, maxTrials int, ntruPaths signverify.SignPaths, verifierKeyOut string) error {
	var req commitRequestFile
	if err := readJSONFile(commitRequestPath, &req); err != nil {
		return fmt.Errorf("read commit request: %w", err)
	}
	if req.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported commit request version %d", req.Version)
	}
	var submission preSignSubmissionFile
	if err := readJSONFile(submissionPath, &submission); err != nil {
		return fmt.Errorf("read submission: %w", err)
	}
	if submission.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported pre-sign submission version %d", submission.Version)
	}
	rt, err := loadIssuanceRuntime(req.CredentialPublicPath, defaultPRFParamsPath, persistedIssuanceRuntimeOverridesWithSmallWood(req.PackedNCols, req.LVCSNCols, req.NLeaves, req.Omega, req.SmallWood))
	if err != nil {
		return err
	}
	if !rt.public.UsesIntGenISIS() {
		return fmt.Errorf("issuer-verify-sign supports only IntGenISIS public params")
	}
	_ = challengePath
	return issuerVerifySignIntGenISIS(rt, req, submission, responsePath, maxTrials, ntruPaths, verifierKeyOut)
}

func issuerVerifySignIntGenISIS(rt *issuanceRuntime, req commitRequestFile, submission preSignSubmissionFile, responsePath string, maxTrials int, ntruPaths signverify.SignPaths, verifierKeyOut string) error {
	if submission.Proof == nil {
		return fmt.Errorf("IntGenISIS pre-sign submission missing proof")
	}
	if err := validateInt64RowsExact("commit_request.com", req.Com, int(rt.ringQ.N)); err != nil {
		return err
	}
	com := polyVecFromInt64(rt.ringQ, req.Com, true)
	cm, as, err := intGenISISCommitmentMatricesNTT(rt.ringQ, rt.public)
	if err != nil {
		return err
	}
	pub := PIOP.PublicInputs{
		Com:          com,
		CM:           cm,
		AS:           as,
		BoundB:       rt.public.CommitmentBound,
		X0Len:        rt.public.EllX0,
		RingDegree:   int(rt.ringQ.N),
		HashRelation: rt.public.HashRelation,
		IntGenISIS:   true,
	}
	ok, err := PIOP.VerifyIntGenISISPreSign(pub, submission.Proof, rt.opts)
	if err != nil {
		return fmt.Errorf("verify IntGenISIS pre-sign: %w", err)
	}
	if !ok {
		return fmt.Errorf("verify IntGenISIS pre-sign returned ok=false")
	}
	B, err := loadBAsNTT(rt.ringQ, rt.public.BPath)
	if err != nil {
		return err
	}
	data, err := issuance.SampleSignatureHashData(rt.ringQ, B, rt.public.EllMuSig, rt.public.EllX0, newLocalRNG(0))
	if err != nil {
		return fmt.Errorf("sample IntGenISIS signature hash data: %w", err)
	}
	target, err := issuance.ComputeIntGenISISTarget(rt.ringQ, B, com, data)
	if err != nil {
		return fmt.Errorf("compute IntGenISIS target: %w", err)
	}
	if err := validateNTRUSigningArtifacts(ntruPaths, len(target.TCoeff)); err != nil {
		return err
	}
	ntruParams, err := loadNTRUParamsForBound(ntruPaths.ParamsPath)
	if err != nil {
		return err
	}
	sig, err := issuance.SignTargetAndSaveWithPaths(target.TCoeff, maxTrials, ntru.SamplerOpts{}, ntruPaths)
	if err != nil {
		return fmt.Errorf("sign IntGenISIS target: %w", err)
	}
	if err := signverify.VerifyWithParamsPath(sig, ntruPaths.ParamsPath); err != nil {
		return fmt.Errorf("verify signed IntGenISIS target bundle: %w", err)
	}
	pubPath := ntruPaths.PublicKeyPath
	if pubPath == "" {
		pubPath = defaultNTRUPublicKeyPath
	}
	ntruPub, err := keys.LoadPublicFile(pubPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}
	resp := issueResponseFile{
		Version:              issuanceArtifactVersion,
		CredentialPublicPath: req.CredentialPublicPath,
		MuSig:                polyVecToInt64(rt.ringQ, data.MuSig, false),
		X0:                   polyVecToInt64(rt.ringQ, data.X0, false),
		X1:                   polyVecToInt64(rt.ringQ, data.X1, false),
		SigS1:                append([]int64(nil), sig.Signature.S1...),
		SigS2:                append([]int64(nil), sig.Signature.S2...),
		NTRUPublic:           [][]int64{append([]int64(nil), ntruPub.HCoeffs...)},
	}
	if err := writeJSONFile(responsePath, resp, 0o644); err != nil {
		return fmt.Errorf("write IntGenISIS issuer response: %w", err)
	}
	if verifierKeyOut != "" {
		digest, err := credential.PublicParamsDigest(rt.public)
		if err != nil {
			return fmt.Errorf("digest IntGenISIS public params: %w", err)
		}
		key := credential.IntGenISISVerifierKey{
			Version:            credential.IntGenISISVerifierKeyVersion,
			Profile:            rt.public.Profile,
			RingDegree:         int(rt.ringQ.N),
			PublicParamsDigest: digest,
			NTRUPublic:         [][]int64{append([]int64(nil), ntruPub.HCoeffs...)},
			SignatureBound:     int64(ntruParams.Beta),
		}
		if err := credential.SaveIntGenISISVerifierKey(verifierKeyOut, key); err != nil {
			return err
		}
	}
	log.Printf("[issuance-cli] IntGenISIS issuer verify/sign wrote %s", responsePath)
	return nil
}

func holderFinalize(holderSecretPath, commitRequestPath, challengePath, responsePath, statePath, signaturePath, ntruParamsPath string) error {
	var secretProbe holderSecretFile
	if err := readJSONFile(holderSecretPath, &secretProbe); err != nil {
		return fmt.Errorf("read holder secret: %w", err)
	}
	rtProbe, err := loadIssuanceRuntime(secretProbe.CredentialPublicPath, secretProbe.PRFParamsPath, persistedIssuanceRuntimeOverridesWithSmallWood(secretProbe.PackedNCols, secretProbe.LVCSNCols, secretProbe.NLeaves, secretProbe.Omega, secretProbe.SmallWood))
	if err != nil {
		return err
	}
	if !rtProbe.public.UsesIntGenISIS() {
		return fmt.Errorf("holder-finalize supports only IntGenISIS public params")
	}
	_ = challengePath
	return holderFinalizeIntGenISIS(rtProbe, secretProbe, commitRequestPath, responsePath, statePath, signaturePath, ntruParamsPath)
}

func holderFinalizeIntGenISIS(rt *issuanceRuntime, secret holderSecretFile, commitRequestPath, responsePath, statePath, signaturePath, ntruParamsPath string) error {
	var req commitRequestFile
	if err := readJSONFile(commitRequestPath, &req); err != nil {
		return fmt.Errorf("read commit request: %w", err)
	}
	var resp issueResponseFile
	if err := readJSONFile(responsePath, &resp); err != nil {
		return fmt.Errorf("read issue response: %w", err)
	}
	inputs, err := intGenISISInputsFromSecret(rt.ringQ, secret)
	if err != nil {
		return err
	}
	com, err := issuance.PrepareIntGenISISCommit(rt.params, inputs)
	if err != nil {
		return fmt.Errorf("prepare IntGenISIS commit during finalize: %w", err)
	}
	if !polyRowsEqual(polyVecToInt64(rt.ringQ, com, true), req.Com) {
		return fmt.Errorf("holder-derived IntGenISIS commitment does not match commit request")
	}
	B, err := loadBAsNTT(rt.ringQ, rt.public.BPath)
	if err != nil {
		return err
	}
	data := issuance.SignatureHashData{
		MuSig: polysFromInt64(rt.ringQ, resp.MuSig),
		X0:    polysFromInt64(rt.ringQ, resp.X0),
		X1:    polysFromInt64(rt.ringQ, resp.X1),
	}
	target, err := issuance.ComputeIntGenISISTarget(rt.ringQ, B, com, data)
	if err != nil {
		return fmt.Errorf("recompute IntGenISIS target: %w", err)
	}
	if err := verifyIntGenISISSignatureResponse(rt.ringQ, resp, target.TCoeff); err != nil {
		return fmt.Errorf("verify IntGenISIS signature response: %w", err)
	}
	ntruParams, err := loadNTRUParamsForBound(ntruParamsPath)
	if err != nil {
		return err
	}
	profile, ok := credential.LookupIntGenISISProfile(rt.public.Profile)
	if !ok {
		return fmt.Errorf("unsupported IntGenISIS profile %q", rt.public.Profile)
	}
	state := credential.IntGenISISState{
		Version:              credential.IntGenISISStateVersion,
		Profile:              profile.Name,
		M:                    polyVecToInt64(rt.ringQ, inputs.M, false),
		MAttr:                polyVecToInt64(rt.ringQ, inputs.MAttr, false),
		K:                    polyVecToInt64(rt.ringQ, inputs.K, false),
		S:                    polyVecToInt64(rt.ringQ, inputs.S, false),
		E:                    polyVecToInt64(rt.ringQ, inputs.E, false),
		MuSig:                append([][]int64(nil), resp.MuSig...),
		X0:                   append([][]int64(nil), resp.X0...),
		X1:                   append([][]int64(nil), resp.X1...),
		SigS1:                append([]int64(nil), resp.SigS1...),
		SigS2:                append([]int64(nil), resp.SigS2...),
		RingDegree:           int(rt.ringQ.N),
		PackedNCols:          rt.opts.NCols,
		CredentialPublicPath: secret.CredentialPublicPath,
		HashRelation:         rt.public.HashRelation,
		BPath:                rt.public.BPath,
		PRFParamsPath:        secret.PRFParamsPath,
		NTRUPublic:           append([][]int64(nil), resp.NTRUPublic...),
		SignatureBound:       int64(ntruParams.Beta),
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	if err := credential.SaveIntGenISISState(statePath, state); err != nil {
		return fmt.Errorf("save IntGenISIS credential state: %w", err)
	}
	log.Printf("[issuance-cli] IntGenISIS holder finalize wrote %s", statePath)
	return nil
}

func loadNTRUParamsForBound(paramsPath string) (ntrurio.SystemParams, error) {
	if paramsPath == "" {
		paramsPath = defaultNTRUParamsPath
	}
	params, err := ntrurio.LoadParams(paramsPath, true)
	if err != nil {
		return ntrurio.SystemParams{}, fmt.Errorf("load NTRU params %s: %w", paramsPath, err)
	}
	if params.Beta == 0 {
		return ntrurio.SystemParams{}, fmt.Errorf("NTRU params %s missing beta", paramsPath)
	}
	return params, nil
}

func verifyIntGenISISSignatureResponse(ringQ *ring.Ring, resp issueResponseFile, targetCoeff []int64) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if len(resp.NTRUPublic) != 1 || len(resp.NTRUPublic[0]) != int(ringQ.N) {
		return fmt.Errorf("issuer response missing NTRU public row of length %d", ringQ.N)
	}
	if len(resp.SigS1) != int(ringQ.N) || len(resp.SigS2) != int(ringQ.N) {
		return fmt.Errorf("issuer response signature rows have lengths s1=%d s2=%d want %d", len(resp.SigS1), len(resp.SigS2), ringQ.N)
	}
	if len(targetCoeff) != int(ringQ.N) {
		return fmt.Errorf("target length=%d want %d", len(targetCoeff), ringQ.N)
	}
	h := polyFromInt64(ringQ, resp.NTRUPublic[0])
	s1 := polyFromInt64(ringQ, resp.SigS1)
	s2 := polyFromInt64(ringQ, resp.SigS2)
	target := polyFromInt64(ringQ, targetCoeff)
	ringQ.NTT(h, h)
	ringQ.NTT(s1, s1)
	ringQ.NTT(s2, s2)
	ringQ.NTT(target, target)
	lhs := ringQ.NewPoly()
	ringQ.MulCoeffs(h, s1, lhs)
	ringQ.Neg(lhs, lhs)
	ringQ.Add(lhs, s2, lhs)
	diff := ringQ.NewPoly()
	ringQ.Sub(lhs, target, diff)
	for _, c := range diff.Coeffs[0] {
		if c%ringQ.Modulus[0] != 0 {
			return fmt.Errorf("A u != T")
		}
	}
	return nil
}

func demoLocal(publicPath, prfPath, artifactDir, statePath, signaturePath string, seed int64, maxTrials int, overrides issuanceRuntimeOverrides, ntruPaths signverify.SignPaths) error {
	holderSecretPath := filepath.Join(artifactDir, "holder_secret.json")
	commitRequestPath := filepath.Join(artifactDir, "commit_request.json")
	submissionPath := filepath.Join(artifactDir, "presign_submission.json")
	responsePath := filepath.Join(artifactDir, "issue_response.json")
	if err := holderCommit(publicPath, prfPath, holderSecretPath, commitRequestPath, "", seed, overrides); err != nil {
		return err
	}
	public, err := credential.LoadPublicParams(publicPath)
	if err != nil {
		return err
	}
	if !public.UsesIntGenISIS() {
		return fmt.Errorf("demo-local supports only IntGenISIS public params")
	}
	if err := holderProve(holderSecretPath, "", submissionPath); err != nil {
		return err
	}
	if err := issuerVerifySign(commitRequestPath, "", submissionPath, responsePath, maxTrials, ntruPaths, ""); err != nil {
		return err
	}
	return holderFinalize(holderSecretPath, commitRequestPath, "", responsePath, statePath, signaturePath, ntruPaths.ParamsPath)
}

func loadIssuanceRuntime(publicPath, prfPath string, overrides issuanceRuntimeOverrides) (*issuanceRuntime, error) {
	public, err := credential.LoadPublicParams(publicPath)
	if err != nil {
		return nil, err
	}
	ringDegree := overrides.RingDegree
	if ringDegree == 0 {
		ringDegree = public.RingDegree
	}
	ringQ, err := credential.LoadRingWithDegree(ringDegree)
	if err != nil {
		return nil, fmt.Errorf("load ring: %w", err)
	}
	if public.RingDegree > 0 && public.RingDegree != int(ringQ.N) {
		return nil, fmt.Errorf("public params ring_degree=%d incompatible with selected ring_degree=%d", public.RingDegree, ringQ.N)
	}
	if err := credential.ValidateLiveHashRelation(public.HashRelation); err != nil {
		return nil, err
	}
	params, err := public.ToIssuanceParams(ringQ)
	if err != nil {
		return nil, err
	}
	prfParams, err := prf.LoadLocalOrDefaultParams(prfPath)
	if err != nil {
		return nil, fmt.Errorf("load prf params: %w", err)
	}
	opts := defaultIssuanceOpts(prfParams)
	opts.RingDegree = int(ringQ.N)
	if _, _, err := intGenISISLiveTranscriptConfig(overrides.TranscriptMode); err != nil {
		return nil, err
	}
	opts = applyIssuanceRuntimeOverrides(opts, overrides)
	opts = defaultIssuanceOptsResolved(prfParams, opts)
	omega, err := deriveOmegaForIssuanceOpts(ringQ, public.HashRelation, opts)
	if err != nil {
		return nil, fmt.Errorf("derive omega: %w", err)
	}
	return &issuanceRuntime{
		ringQ:      ringQ,
		publicPath: publicPath,
		public:     public,
		params:     params,
		prfPath:    prfPath,
		prfParams:  prfParams,
		opts:       opts,
		omega:      omega,
	}, nil
}

func intGenISISInputsFromSecret(ringQ *ring.Ring, secret holderSecretFile) (issuance.IntGenISISInputs, error) {
	if secret.IntGenISIS == nil {
		return issuance.IntGenISISInputs{}, fmt.Errorf("holder secret missing IntGenISIS witness")
	}
	spec := secret.IntGenISIS
	if err := validateInt64RowsExact("intgenisis.M", spec.M, int(ringQ.N)); err != nil {
		return issuance.IntGenISISInputs{}, err
	}
	if err := validateInt64RowsExact("intgenisis.m", spec.MAttr, int(ringQ.N)); err != nil {
		return issuance.IntGenISISInputs{}, err
	}
	if err := validateInt64RowsExact("intgenisis.k", spec.K, int(ringQ.N)); err != nil {
		return issuance.IntGenISISInputs{}, err
	}
	if err := validateInt64RowsExact("intgenisis.s", spec.S, int(ringQ.N)); err != nil {
		return issuance.IntGenISISInputs{}, err
	}
	if err := validateInt64RowsExact("intgenisis.e", spec.E, int(ringQ.N)); err != nil {
		return issuance.IntGenISISInputs{}, err
	}
	profile, ok := credential.LookupIntGenISISProfileByRingDegree(int(ringQ.N))
	if !ok {
		return issuance.IntGenISISInputs{}, fmt.Errorf("IntGenISIS semantic message does not support ring_degree=%d", ringQ.N)
	}
	layout, err := credential.DefaultSemanticMessageLayout(profile, 8)
	if err != nil {
		return issuance.IntGenISISInputs{}, err
	}
	if err := credential.ValidateSemanticMessage(layout, credential.SemanticMessage{M: spec.M, MAttr: spec.MAttr, K: spec.K}); err != nil {
		return issuance.IntGenISISInputs{}, fmt.Errorf("semantic message: %w", err)
	}
	return issuance.IntGenISISInputs{
		M:     polysFromInt64(ringQ, spec.M),
		MAttr: polysFromInt64(ringQ, spec.MAttr),
		K:     polysFromInt64(ringQ, spec.K),
		S:     polysFromInt64(ringQ, spec.S),
		E:     polysFromInt64(ringQ, spec.E),
	}, nil
}

func intGenISISCommitmentMatricesNTT(ringQ *ring.Ring, public credential.PublicParams) ([][]*ring.Poly, [][]*ring.Poly, error) {
	cm, err := commitment.MatrixFromCoeff(ringQ, public.CM)
	if err != nil {
		return nil, nil, fmt.Errorf("lift C_M: %w", err)
	}
	as, err := commitment.MatrixFromCoeff(ringQ, public.AS)
	if err != nil {
		return nil, nil, fmt.Errorf("lift A_s: %w", err)
	}
	return cm, as, nil
}

func validateNTRUSigningArtifacts(paths signverify.SignPaths, ringDegree int) error {
	if ringDegree <= 0 {
		return fmt.Errorf("invalid signing target ring_degree=%d", ringDegree)
	}
	paramsPath := paths.ParamsPath
	if paramsPath == "" {
		paramsPath = defaultNTRUParamsPath
	}
	params, err := ntrurio.LoadParams(paramsPath, true)
	if err != nil {
		return fmt.Errorf("load NTRU params %s: %w", paramsPath, err)
	}
	if params.N != ringDegree {
		return fmt.Errorf("NTRU params %s N=%d incompatible with target ring_degree=%d", paramsPath, params.N, ringDegree)
	}
	publicPath := paths.PublicKeyPath
	if publicPath == "" {
		publicPath = defaultNTRUPublicKeyPath
	}
	pk, err := keys.LoadPublicFile(publicPath)
	if err != nil {
		return fmt.Errorf("load NTRU public key %s: %w", publicPath, err)
	}
	if pk.N != ringDegree {
		return fmt.Errorf("NTRU public key %s N=%d incompatible with target ring_degree=%d", publicPath, pk.N, ringDegree)
	}
	if len(pk.HCoeffs) != ringDegree {
		return fmt.Errorf("NTRU public key %s coefficient length=%d want ring_degree=%d", publicPath, len(pk.HCoeffs), ringDegree)
	}
	privatePath := paths.PrivatePath
	if privatePath == "" {
		privatePath = defaultNTRUPrivateKeyPath
	}
	sk, err := keys.LoadPrivateFile(privatePath)
	if err != nil {
		return fmt.Errorf("load NTRU private key %s: %w", privatePath, err)
	}
	if sk.N != ringDegree {
		return fmt.Errorf("NTRU private key %s N=%d incompatible with target ring_degree=%d", privatePath, sk.N, ringDegree)
	}
	for _, check := range []struct {
		name string
		row  []int64
	}{
		{"F", sk.F},
		{"G", sk.G},
		{"f", sk.Fsmall},
		{"g", sk.Gsmall},
	} {
		if len(check.row) != ringDegree {
			return fmt.Errorf("NTRU private key %s %s coefficient length=%d want ring_degree=%d", privatePath, check.name, len(check.row), ringDegree)
		}
	}
	return nil
}

func defaultIssuanceOpts(prfParams *prf.Params) PIOP.SimOpts {
	return defaultIssuanceOptsResolved(prfParams, PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential: true,
		Theta:      1,
		EllPrime:   2,
		Rho:        2,
		NCols:      16,
		LVCSNCols:  96,
		Ell:        18,
		Eta:        19,
		DomainMode: PIOP.DomainModeExplicit,
		NLeaves:    4096,
	}))
}

func defaultIssuanceOptsResolved(prfParams *prf.Params, opts PIOP.SimOpts) PIOP.SimOpts {
	if prfParams != nil && opts.NCols < 2*prfParams.LenKey {
		opts.NCols = 2 * prfParams.LenKey
	}
	if opts.NCols%2 != 0 {
		opts.NCols++
	}
	opts.ShowingPreset = ""
	if opts.LVCSNCols <= 0 {
		opts.LVCSNCols = 96
	}
	if opts.LVCSNCols < opts.NCols {
		opts.LVCSNCols = opts.NCols
	}
	opts.PostSignLVCSNCols = opts.LVCSNCols
	opts.PRFLVCSNCols = opts.LVCSNCols
	if opts.PostSignNLeaves <= 0 {
		opts.PostSignNLeaves = opts.NLeaves
	}
	if opts.PRFNLeaves <= 0 {
		opts.PRFNLeaves = opts.NLeaves
	}
	return opts
}

func deriveOmegaForIssuanceOpts(ringQ *ring.Ring, relation string, opts PIOP.SimOpts) ([]uint64, error) {
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
	omegaWitness, err := PIOP.DeriveRelationWitnessOmega(ringQ.Modulus[0], nLeaves, ncols, lvcsNCols, opts.Ell, relation)
	if err != nil {
		return nil, err
	}
	if len(omegaWitness) < ncols {
		return nil, fmt.Errorf("derived omega len=%d < witness ncols=%d", len(omegaWitness), ncols)
	}
	return append([]uint64(nil), omegaWitness[:ncols]...), nil
}

func newLocalRNG(seed int64) *rand.Rand {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return rand.New(rand.NewSource(seed))
}

func loadBAsNTT(r *ring.Ring, path string) ([]*ring.Poly, error) {
	coeffs, err := ntrurio.LoadBMatrixCoeffs(path)
	if err != nil {
		return nil, fmt.Errorf("load B %s: %w", path, err)
	}
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

func validateInt64RowsExact(label string, rows [][]int64, ringDegree int) error {
	for i := range rows {
		if len(rows[i]) != ringDegree {
			return fmt.Errorf("%s[%d] coefficient length=%d want ring_degree=%d", label, i, len(rows[i]), ringDegree)
		}
	}
	return nil
}

func readJSONFile(path string, out interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func writeJSONFile(path string, value interface{}, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

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

func polyVecToInt64(r *ring.Ring, vec []*ring.Poly, ntt bool) [][]int64 {
	out := make([][]int64, len(vec))
	for i, p := range vec {
		cp := r.NewPoly()
		ring.Copy(p, cp)
		if ntt {
			r.InvNTT(cp, cp)
		}
		out[i] = polyToInt64Local(cp, r)
	}
	return out
}

func polyVecFromInt64(r *ring.Ring, rows [][]int64, ntt bool) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	for i := range rows {
		out[i] = polyFromInt64(r, rows[i])
		if ntt {
			r.NTT(out[i], out[i])
		}
	}
	return out
}

func polyFromInt64(r *ring.Ring, coeffs []int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	for i := 0; i < len(coeffs) && i < r.N; i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func polysFromInt64(r *ring.Ring, rows [][]int64) []*ring.Poly {
	out := make([]*ring.Poly, len(rows))
	for i := range rows {
		out[i] = polyFromInt64(r, rows[i])
	}
	return out
}

func polyRowsEqual(a, b [][]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !int64SliceEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func int64SliceEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func displayBits(bits float64) float64 {
	if math.Abs(bits) < 0.005 {
		return 0
	}
	return bits
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
