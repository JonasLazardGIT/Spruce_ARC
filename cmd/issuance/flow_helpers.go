package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	"vSIS-Signature/internal/domain"
	"vSIS-Signature/issuance"
	"vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type holderWitnessSpec struct {
	M1  [][]int64 `json:"m1"`
	M2  [][]int64 `json:"m2"`
	RU0 [][]int64 `json:"ru0"`
	RU1 [][]int64 `json:"ru1"`
	R   [][]int64 `json:"r"`
}

type holderSecretFile struct {
	CredentialPublicPath string   `json:"credential_public_path"`
	PRFParamsPath        string   `json:"prf_params_path"`
	PackedNCols          int      `json:"packed_ncols"`
	Omega                []uint64 `json:"omega"`
	holderWitnessSpec
}

type commitRequestFile struct {
	CredentialPublicPath string    `json:"credential_public_path"`
	Omega                []uint64  `json:"omega"`
	Com                  [][]int64 `json:"com"`
}

type issueChallengeFile struct {
	CredentialPublicPath string    `json:"credential_public_path"`
	Omega                []uint64  `json:"omega"`
	RI0                  [][]int64 `json:"ri0"`
	RI1                  [][]int64 `json:"ri1"`
}

type preSignSubmissionFile struct {
	CredentialPublicPath string      `json:"credential_public_path"`
	T                    []int64     `json:"t"`
	Proof                *PIOP.Proof `json:"proof"`
}

type issueResponseFile struct {
	CredentialPublicPath string          `json:"credential_public_path"`
	T                    []int64         `json:"t"`
	SigS1                []int64         `json:"sig_s1"`
	SigS2                []int64         `json:"sig_s2"`
	NTRUPublic           [][]int64       `json:"ntru_public,omitempty"`
	Signature            *keys.Signature `json:"signature,omitempty"`
}

type credentialFinalizeInput struct {
	secret    holderSecretFile
	request   commitRequestFile
	challenge issueChallengeFile
	response  issueResponseFile
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

func credentialPublicPathDefault() string {
	return credential.DefaultPublicParamsPath
}

func setupDemoPublic(outPath string, force bool, bPath, hashRelation string) error {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		return fmt.Errorf("load ring: %w", err)
	}
	hashRelation = credential.NormalizeHashRelation(hashRelation)
	if hashRelation == "" {
		hashRelation = credential.HashRelationBBTran
	}
	if bPath == "" {
		switch hashRelation {
		case credential.HashRelationBBTran:
			bPath = filepath.Join("Parameters", "Bmatrix_bb_tran.json")
		default:
			bPath = filepath.Join("Parameters", "Bmatrix.json")
		}
	}
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			return fmt.Errorf("refusing to overwrite existing %s without -force", outPath)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", outPath, err)
		}
	}
	ac, err := commitment.GenerateUniformCoeffMatrix(ringQ, 5, 5)
	if err != nil {
		return fmt.Errorf("generate Ac: %w", err)
	}
	params := credential.PublicParams{
		Ac:           ac,
		HashRelation: hashRelation,
		BPath:        bPath,
		BoundB:       1,
		LenM1:        1,
		LenM2:        1,
		LenRU0:       1,
		LenRU1:       1,
		LenR:         1,
	}
	if err := credential.SavePublicParams(outPath, params); err != nil {
		return err
	}
	log.Printf("[issuance-cli] wrote credential public params to %s", outPath)
	return nil
}

func holderCommit(publicPath, prfPath, holderSecretPath, commitRequestPath, expertInputPath string, seed int64) error {
	rt, err := loadIssuanceRuntime(publicPath, prfPath)
	if err != nil {
		return err
	}
	rng := newLocalRNG(seed)
	var inputs issuance.Inputs
	if expertInputPath != "" {
		spec := holderWitnessSpec{}
		if err := readJSONFile(expertInputPath, &spec); err != nil {
			return fmt.Errorf("read expert input: %w", err)
		}
		inputs, err = inputsFromWitnessSpec(rt.ringQ, rt.public, spec)
		if err != nil {
			return fmt.Errorf("expert witness: %w", err)
		}
	} else {
		inputs, err = sampleHolderInputs(rt.ringQ, rt.public, rt.omega, rng)
		if err != nil {
			return fmt.Errorf("sample holder inputs: %w", err)
		}
	}
	com, err := issuance.PrepareCommit(rt.params, inputs, rt.omega)
	if err != nil {
		return fmt.Errorf("prepare commit: %w", err)
	}
	secret := holderSecretFile{
		CredentialPublicPath: publicPath,
		PRFParamsPath:        prfPath,
		PackedNCols:          rt.opts.NCols,
		Omega:                append([]uint64(nil), rt.omega...),
		holderWitnessSpec:    witnessSpecFromInputs(rt.ringQ, inputs),
	}
	request := commitRequestFile{
		CredentialPublicPath: publicPath,
		Omega:                append([]uint64(nil), rt.omega...),
		Com:                  polyVecToInt64(rt.ringQ, com, true),
	}
	if err := writeJSONFile(holderSecretPath, secret, 0o600); err != nil {
		return fmt.Errorf("write holder secret: %w", err)
	}
	if err := writeJSONFile(commitRequestPath, request, 0o644); err != nil {
		return fmt.Errorf("write commit request: %w", err)
	}
	log.Printf("[issuance-cli] holder commit wrote %s and %s", holderSecretPath, commitRequestPath)
	return nil
}

func issuerChallenge(commitRequestPath, challengePath string, seed int64) error {
	var req commitRequestFile
	if err := readJSONFile(commitRequestPath, &req); err != nil {
		return fmt.Errorf("read commit request: %w", err)
	}
	rt, err := loadIssuanceRuntime(req.CredentialPublicPath, defaultPRFParamsPath)
	if err != nil {
		return err
	}
	if len(req.Omega) == 0 {
		return fmt.Errorf("commit request missing omega")
	}
	rng := newLocalRNG(seed)
	ch, err := issuance.SampleChallenge(rt.ringQ, req.Omega, rt.public.BoundB, rng)
	if err != nil {
		return fmt.Errorf("sample challenge: %w", err)
	}
	out := issueChallengeFile{
		CredentialPublicPath: req.CredentialPublicPath,
		Omega:                append([]uint64(nil), req.Omega...),
		RI0:                  polyVecToInt64(rt.ringQ, ch.RI0, true),
		RI1:                  polyVecToInt64(rt.ringQ, ch.RI1, true),
	}
	if err := writeJSONFile(challengePath, out, 0o644); err != nil {
		return fmt.Errorf("write challenge: %w", err)
	}
	log.Printf("[issuance-cli] issuer challenge wrote %s", challengePath)
	return nil
}

func holderProve(holderSecretPath, challengePath, submissionPath string) error {
	var secret holderSecretFile
	if err := readJSONFile(holderSecretPath, &secret); err != nil {
		return fmt.Errorf("read holder secret: %w", err)
	}
	var challenge issueChallengeFile
	if err := readJSONFile(challengePath, &challenge); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	rt, err := loadIssuanceRuntime(secret.CredentialPublicPath, secret.PRFParamsPath)
	if err != nil {
		return err
	}
	if len(secret.Omega) == 0 {
		return fmt.Errorf("holder secret missing omega")
	}
	inputs, err := inputsFromWitnessSpec(rt.ringQ, rt.public, secret.holderWitnessSpec)
	if err != nil {
		return err
	}
	ch, err := challengeFromFile(rt.ringQ, challenge)
	if err != nil {
		return err
	}
	com, err := issuance.PrepareCommit(rt.params, inputs, secret.Omega)
	if err != nil {
		return fmt.Errorf("prepare commit: %w", err)
	}
	st, err := issuance.ApplyChallenge(rt.params, inputs, ch, secret.Omega)
	if err != nil {
		return fmt.Errorf("apply challenge: %w", err)
	}
	st.Com = com
	proof, err := issuance.ProvePreSign(rt.params, ch, com, inputs, st, rt.opts)
	if err != nil {
		return fmt.Errorf("prove pre-sign: %w", err)
	}
	out := preSignSubmissionFile{
		CredentialPublicPath: secret.CredentialPublicPath,
		T:                    append([]int64(nil), st.T...),
		Proof:                proof,
	}
	if err := writeJSONFile(submissionPath, out, 0o644); err != nil {
		return fmt.Errorf("write submission: %w", err)
	}
	log.Printf("[issuance-cli] holder prove wrote %s", submissionPath)
	return nil
}

func issuerVerifySign(commitRequestPath, challengePath, submissionPath, responsePath string, maxTrials int) error {
	var req commitRequestFile
	if err := readJSONFile(commitRequestPath, &req); err != nil {
		return fmt.Errorf("read commit request: %w", err)
	}
	var challenge issueChallengeFile
	if err := readJSONFile(challengePath, &challenge); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	var submission preSignSubmissionFile
	if err := readJSONFile(submissionPath, &submission); err != nil {
		return fmt.Errorf("read submission: %w", err)
	}
	rt, err := loadIssuanceRuntime(req.CredentialPublicPath, defaultPRFParamsPath)
	if err != nil {
		return err
	}
	com := polyVecFromInt64(rt.ringQ, req.Com, true)
	ch, err := challengeFromFile(rt.ringQ, challenge)
	if err != nil {
		return err
	}
	B, err := loadBAsNTT(rt.ringQ, rt.public.BPath)
	if err != nil {
		return err
	}
	verifyState := &issuance.State{
		T: submission.T,
		B: B,
	}
	ok, err := issuance.VerifyPreSign(rt.params, ch, com, verifyState, submission.Proof, rt.opts)
	if err != nil {
		return fmt.Errorf("verify pre-sign: %w", err)
	}
	if !ok {
		return fmt.Errorf("verify pre-sign returned ok=false")
	}
	sig, err := issuance.SignTargetAndSave(submission.T, maxTrials, ntru.SamplerOpts{})
	if err != nil {
		return fmt.Errorf("sign target: %w", err)
	}
	if err := signverify.Verify(sig); err != nil {
		return fmt.Errorf("verify signed target bundle: %w", err)
	}
	pub, err := keys.LoadPublic()
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}
	resp := issueResponseFile{
		CredentialPublicPath: req.CredentialPublicPath,
		T:                    append([]int64(nil), submission.T...),
		SigS1:                append([]int64(nil), sig.Signature.S1...),
		SigS2:                append([]int64(nil), sig.Signature.S2...),
		NTRUPublic:           [][]int64{append([]int64(nil), pub.HCoeffs...)},
		Signature:            sig,
	}
	if err := writeJSONFile(responsePath, resp, 0o644); err != nil {
		return fmt.Errorf("write issuer response: %w", err)
	}
	log.Printf("[issuance-cli] issuer verify/sign wrote %s", responsePath)
	return nil
}

func holderFinalize(holderSecretPath, commitRequestPath, challengePath, responsePath, statePath, signaturePath string) error {
	in, rt, inputs, derivedState, err := loadFinalizeInput(holderSecretPath, commitRequestPath, challengePath, responsePath)
	if err != nil {
		return err
	}
	if in.response.Signature != nil {
		if err := signverify.Verify(in.response.Signature); err != nil {
			return fmt.Errorf("verify issue response signature: %w", err)
		}
		if !int64SliceEqual(in.response.Signature.Hash.TCoeffs, in.response.T) {
			return fmt.Errorf("issue response signature target does not match response T")
		}
	}
	if !int64SliceEqual(derivedState.T, in.response.T) {
		return fmt.Errorf("holder-derived T does not match issuer response T")
	}
	com, err := issuance.PrepareCommit(rt.params, inputs, in.secret.Omega)
	if err != nil {
		return fmt.Errorf("prepare commit during finalize: %w", err)
	}
	if !polyRowsEqual(polyVecToInt64(rt.ringQ, com, true), in.request.Com) {
		return fmt.Errorf("holder-derived commitment does not match commit request")
	}
	state, err := buildCredentialState(rt, in, inputs, derivedState, com)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	if err := credential.SaveState(statePath, rt.ringQ, state); err != nil {
		return fmt.Errorf("save credential state: %w", err)
	}
	if in.response.Signature != nil {
		if err := keys.SaveSignatureFile(signaturePath, in.response.Signature); err != nil {
			return fmt.Errorf("save credential signature: %w", err)
		}
	}
	log.Printf("[issuance-cli] holder finalize wrote %s", statePath)
	if in.response.Signature != nil {
		log.Printf("[issuance-cli] holder finalize wrote %s", signaturePath)
	}
	return nil
}

func demoLocal(publicPath, prfPath, artifactDir, statePath, signaturePath string, seed int64, maxTrials int) error {
	holderSecretPath := filepath.Join(artifactDir, "holder_secret.json")
	commitRequestPath := filepath.Join(artifactDir, "commit_request.json")
	challengePath := filepath.Join(artifactDir, "issue_challenge.json")
	submissionPath := filepath.Join(artifactDir, "presign_submission.json")
	responsePath := filepath.Join(artifactDir, "issue_response.json")
	challengeSeed := seed
	if seed != 0 {
		challengeSeed = seed + 1
	}
	if err := holderCommit(publicPath, prfPath, holderSecretPath, commitRequestPath, "", seed); err != nil {
		return err
	}
	if err := issuerChallenge(commitRequestPath, challengePath, challengeSeed); err != nil {
		return err
	}
	if err := holderProve(holderSecretPath, challengePath, submissionPath); err != nil {
		return err
	}
	if err := issuerVerifySign(commitRequestPath, challengePath, submissionPath, responsePath, maxTrials); err != nil {
		return err
	}
	return holderFinalize(holderSecretPath, commitRequestPath, challengePath, responsePath, statePath, signaturePath)
}

func loadIssuanceRuntime(publicPath, prfPath string) (*issuanceRuntime, error) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		return nil, fmt.Errorf("load ring: %w", err)
	}
	public, err := credential.LoadPublicParams(publicPath)
	if err != nil {
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
	omega, err := deriveOmegaForIssuanceOpts(ringQ, opts)
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

func defaultIssuanceOpts(prfParams *prf.Params) PIOP.SimOpts {
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
	if prfParams != nil && opts.NCols < 2*prfParams.LenKey {
		opts.NCols = 2 * prfParams.LenKey
	}
	if opts.NCols%2 != 0 {
		opts.NCols++
	}
	opts.ShowingPreset = PIOP.ShowingPresetCustom
	opts.LVCSNCols = 96
	if opts.LVCSNCols < opts.NCols {
		opts.LVCSNCols = opts.NCols
	}
	opts.PostSignLVCSNCols = opts.LVCSNCols
	opts.PRFLVCSNCols = opts.LVCSNCols
	return opts
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

func newLocalRNG(seed int64) *rand.Rand {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return rand.New(rand.NewSource(seed))
}

func sampleHolderInputs(r *ring.Ring, public credential.PublicParams, omega []uint64, rng *rand.Rand) (issuance.Inputs, error) {
	if rng == nil {
		return issuance.Inputs{}, fmt.Errorf("nil rng")
	}
	alphabet := []int64{-1, 0, 1}
	m1 := samplePackedHalfCoeffHeadNonZero(r, alphabet, len(omega), rng, true)
	m2 := samplePackedHalfCoeffHeadNonZero(r, alphabet, len(omega), rng, false)
	ru0 := sampleCoeffHead(r, alphabet, len(omega), rng)
	ru1 := sampleCoeffHead(r, alphabet, len(omega), rng)
	rPoly := sampleCoeffHead(r, alphabet, len(omega), rng)
	return issuance.Inputs{
		M1:  []*ring.Poly{m1},
		M2:  []*ring.Poly{m2},
		RU0: []*ring.Poly{ru0},
		RU1: []*ring.Poly{ru1},
		R:   []*ring.Poly{rPoly},
	}, nil
}

func inputsFromWitnessSpec(r *ring.Ring, public credential.PublicParams, spec holderWitnessSpec) (issuance.Inputs, error) {
	if len(spec.M1) != public.LenM1 || len(spec.M2) != public.LenM2 || len(spec.RU0) != public.LenRU0 || len(spec.RU1) != public.LenRU1 || len(spec.R) != public.LenR {
		return issuance.Inputs{}, fmt.Errorf("expert witness row-count mismatch")
	}
	return issuance.Inputs{
		M1:  polysFromInt64(r, spec.M1),
		M2:  polysFromInt64(r, spec.M2),
		RU0: polysFromInt64(r, spec.RU0),
		RU1: polysFromInt64(r, spec.RU1),
		R:   polysFromInt64(r, spec.R),
	}, nil
}

func witnessSpecFromInputs(r *ring.Ring, in issuance.Inputs) holderWitnessSpec {
	return holderWitnessSpec{
		M1:  polyVecToInt64(r, in.M1, false),
		M2:  polyVecToInt64(r, in.M2, false),
		RU0: polyVecToInt64(r, in.RU0, false),
		RU1: polyVecToInt64(r, in.RU1, false),
		R:   polyVecToInt64(r, in.R, false),
	}
}

func challengeFromFile(r *ring.Ring, in issueChallengeFile) (issuance.Challenge, error) {
	if len(in.RI0) == 0 || len(in.RI1) == 0 {
		return issuance.Challenge{}, fmt.Errorf("challenge file missing RI rows")
	}
	return issuance.Challenge{
		RI0: polyVecFromInt64(r, in.RI0, true),
		RI1: polyVecFromInt64(r, in.RI1, true),
	}, nil
}

func buildCredentialState(rt *issuanceRuntime, in credentialFinalizeInput, inputs issuance.Inputs, st *issuance.State, com commitment.Vector) (credential.State, error) {
	if rt == nil || st == nil {
		return credential.State{}, fmt.Errorf("nil finalize runtime/state")
	}
	out := credential.State{
		M1:                   polyVecToInt64(rt.ringQ, inputs.M1, false),
		M2:                   polyVecToInt64(rt.ringQ, inputs.M2, false),
		RU0:                  polyVecToInt64(rt.ringQ, inputs.RU0, false),
		RU1:                  polyVecToInt64(rt.ringQ, inputs.RU1, false),
		R:                    polyVecToInt64(rt.ringQ, inputs.R, false),
		R0:                   polyVecToInt64(rt.ringQ, st.R0, false),
		R1:                   polyVecToInt64(rt.ringQ, st.R1, false),
		K0:                   polyVecToInt64(rt.ringQ, st.K0, false),
		K1:                   polyVecToInt64(rt.ringQ, st.K1, false),
		T:                    append([]int64(nil), st.T...),
		SigS1:                append([]int64(nil), in.response.SigS1...),
		SigS2:                append([]int64(nil), in.response.SigS2...),
		PackedNCols:          in.secret.PackedNCols,
		Com:                  polyVecToInt64(rt.ringQ, com, true),
		RI0:                  append([][]int64(nil), in.challenge.RI0...),
		RI1:                  append([][]int64(nil), in.challenge.RI1...),
		CredentialPublicPath: in.secret.CredentialPublicPath,
		HashRelation:         rt.public.HashRelation,
		BPath:                rt.public.BPath,
		B:                    polyVecToInt64(rt.ringQ, st.B, true),
		PRFParamsPath:        in.secret.PRFParamsPath,
		NTRUPublic:           cloneRows(in.response.NTRUPublic),
	}
	return out, nil
}

func loadFinalizeInput(holderSecretPath, commitRequestPath, challengePath, responsePath string) (credentialFinalizeInput, *issuanceRuntime, issuance.Inputs, *issuance.State, error) {
	var in credentialFinalizeInput
	if err := readJSONFile(holderSecretPath, &in.secret); err != nil {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("read holder secret: %w", err)
	}
	if err := readJSONFile(commitRequestPath, &in.request); err != nil {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("read commit request: %w", err)
	}
	if err := readJSONFile(challengePath, &in.challenge); err != nil {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("read challenge: %w", err)
	}
	if err := readJSONFile(responsePath, &in.response); err != nil {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("read response: %w", err)
	}
	rt, err := loadIssuanceRuntime(in.secret.CredentialPublicPath, in.secret.PRFParamsPath)
	if err != nil {
		return in, nil, issuance.Inputs{}, nil, err
	}
	inputs, err := inputsFromWitnessSpec(rt.ringQ, rt.public, in.secret.holderWitnessSpec)
	if err != nil {
		return in, nil, issuance.Inputs{}, nil, err
	}
	ch, err := challengeFromFile(rt.ringQ, in.challenge)
	if err != nil {
		return in, nil, issuance.Inputs{}, nil, err
	}
	st, err := issuance.ApplyChallenge(rt.params, inputs, ch, in.secret.Omega)
	if err != nil {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("apply challenge during finalize: %w", err)
	}
	return in, rt, inputs, st, nil
}

func loadBAsNTT(r *ring.Ring, path string) ([]*ring.Poly, error) {
	coeffs, err := ntrurio.LoadBMatrixCoeffs(path)
	if err != nil {
		return nil, fmt.Errorf("load B %s: %w", path, err)
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

func cloneRows(rows [][]int64) [][]int64 {
	out := make([][]int64, len(rows))
	for i := range rows {
		out[i] = append([]int64(nil), rows[i]...)
	}
	return out
}

func samplePackedHalfCoeffHeadNonZero(r *ring.Ring, alphabet []int64, ncols int, rng *rand.Rand, keepLower bool) *ring.Poly {
	for attempt := 0; attempt < 128; attempt++ {
		p := samplePackedHalfCoeffHead(r, alphabet, ncols, rng, keepLower)
		if maxAbsSlice(polyToInt64Local(p, r)) > 0 {
			return p
		}
	}
	panic("failed to sample nonzero packed-half polynomial")
}

func sampleCoeffHead(r *ring.Ring, alphabet []int64, ncols int, rng *rand.Rand) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	for i := 0; i < ncols; i++ {
		v := alphabet[rng.Intn(len(alphabet))]
		if v < 0 {
			p.Coeffs[0][i] = uint64(v + q)
		} else {
			p.Coeffs[0][i] = uint64(v)
		}
	}
	return p
}

func samplePackedHalfCoeffHead(r *ring.Ring, alphabet []int64, ncols int, rng *rand.Rand, keepLower bool) *ring.Poly {
	p := sampleCoeffHead(r, alphabet, ncols, rng)
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	half := ncols / 2
	if keepLower {
		for i := half; i < ncols; i++ {
			p.Coeffs[0][i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			p.Coeffs[0][i] = 0
		}
	}
	return p
}

func maxAbsSlice(vals []int64) int64 {
	var out int64
	for _, v := range vals {
		if v < 0 {
			v = -v
		}
		if v > out {
			out = v
		}
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
