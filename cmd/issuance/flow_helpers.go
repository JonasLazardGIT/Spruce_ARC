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

type holderWitnessSpec struct {
	Mu   [][]int64 `json:"mu"`
	M    [][]int64 `json:"m,omitempty"`
	K    [][]int64 `json:"k,omitempty"`
	R0H  [][]int64 `json:"r0h"`
	R1H  [][]int64 `json:"r1h"`
	RBar [][]int64 `json:"rbar"`
}

type holderSecretFile struct {
	Version              int      `json:"version"`
	CredentialPublicPath string   `json:"credential_public_path"`
	PRFParamsPath        string   `json:"prf_params_path"`
	PackedNCols          int      `json:"packed_ncols"`
	LVCSNCols            int      `json:"lvcs_ncols,omitempty"`
	NLeaves              int      `json:"nleaves,omitempty"`
	Omega                []uint64 `json:"omega"`
	holderWitnessSpec
}

type commitRequestFile struct {
	Version              int       `json:"version"`
	CredentialPublicPath string    `json:"credential_public_path"`
	LVCSNCols            int       `json:"lvcs_ncols,omitempty"`
	NLeaves              int       `json:"nleaves,omitempty"`
	Omega                []uint64  `json:"omega"`
	Com                  [][]int64 `json:"com"`
}

type issueChallengeFile struct {
	Version              int       `json:"version"`
	CredentialPublicPath string    `json:"credential_public_path"`
	Omega                []uint64  `json:"omega"`
	RI0                  [][]int64 `json:"ri0"`
	RI1                  [][]int64 `json:"ri1"`
}

type preSignSubmissionFile struct {
	Version              int         `json:"version"`
	CredentialPublicPath string      `json:"credential_public_path"`
	T                    []int64     `json:"t"`
	Proof                *PIOP.Proof `json:"proof"`
}

type issueResponseFile struct {
	Version              int             `json:"version"`
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

type issuanceRuntimeOverrides struct {
	NCols      int
	LVCSNCols  int
	NLeaves    int
	RingDegree int
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

type x0Profile struct {
	Name         string
	X0Len        int
	X0CoeffBound int64
}

func resolveX0Profile(name string, x0Len int, x0Bound int64) (x0Profile, error) {
	profile := x0Profile{Name: name}
	switch name {
	case "", "lhl_default":
		profile.Name = "lhl_default"
		profile.X0Len = 6
		profile.X0CoeffBound = 5
	case "lhl_alt":
		profile.X0Len = 5
		profile.X0CoeffBound = 8
	case "legacy_scalar":
		profile.X0Len = 1
		profile.X0CoeffBound = 1
	default:
		return x0Profile{}, fmt.Errorf("unsupported x0 profile %q", name)
	}
	if x0Len > 0 {
		profile.X0Len = x0Len
	}
	if x0Bound > 0 {
		profile.X0CoeffBound = x0Bound
	}
	if profile.X0Len <= 0 || profile.X0CoeffBound <= 0 {
		return x0Profile{}, fmt.Errorf("invalid x0 profile len=%d bound=%d", profile.X0Len, profile.X0CoeffBound)
	}
	return profile, nil
}

func persistedIssuanceRuntimeOverrides(ncols, lvcsNCols, nLeaves int, omega []uint64) issuanceRuntimeOverrides {
	if ncols <= 0 && len(omega) > 0 {
		ncols = len(omega)
	}
	return issuanceRuntimeOverrides{
		NCols:      ncols,
		LVCSNCols:  lvcsNCols,
		NLeaves:    nLeaves,
		RingDegree: 0,
	}
}

func credentialPublicPathDefault() string {
	return credential.DefaultPublicParamsPath
}

func setupDemoPublic(outPath string, force bool, bPath, hashRelation, x0ProfileName string, x0Len int, x0Bound int64, ringDegree int) error {
	ringQ, err := credential.LoadRingWithDegree(ringDegree)
	if err != nil {
		return fmt.Errorf("load ring: %w", err)
	}
	profile, err := resolveX0Profile(x0ProfileName, x0Len, x0Bound)
	if err != nil {
		return err
	}
	hashRelation = credential.NormalizeHashRelation(hashRelation)
	if hashRelation == "" {
		hashRelation = credential.HashRelationBBTran
	}
	if bPath == "" {
		switch hashRelation {
		case credential.HashRelationBBTran:
			bPath = filepath.Join(filepath.Dir(outPath), fmt.Sprintf("Bmatrix_bb_tran_x0len%d.json", profile.X0Len))
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
	if hashRelation == credential.HashRelationBBTran {
		prng, err := utils.NewPRNG()
		if err != nil {
			return fmt.Errorf("new prng: %w", err)
		}
		B, err := vsishash.GenerateBWithX0Len(ringQ, prng, profile.X0Len)
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
	}
	commitCols := 1 + profile.X0Len + 1 + 1
	ac, err := commitment.GenerateUniformCoeffMatrix(ringQ, commitCols, commitCols)
	if err != nil {
		return fmt.Errorf("generate Ac: %w", err)
	}
	params := credential.PublicParams{
		Version:            credential.PublicParamsVersion,
		Ac:                 ac,
		HashRelation:       hashRelation,
		BPath:              bPath,
		BoundB:             1,
		X0Len:              profile.X0Len,
		X0CoeffBound:       profile.X0CoeffBound,
		TargetDim:          credential.DefaultTargetDim,
		TargetHidingLambda: credential.DefaultTargetHidingLambda,
		RingDegree:         int(ringQ.N),
		X0Distribution:     credential.X0DistributionUniformInterval,
		LenMu:              1,
		MuLayout:           credential.MuLayoutFullCapacityHalvesV1,
		LenR0H:             profile.X0Len,
		LenR1H:             1,
		LenRBar:            1,
	}
	if err := credential.SavePublicParams(outPath, params); err != nil {
		return err
	}
	issuanceParams, err := params.ToIssuanceParams(ringQ)
	if err != nil {
		return err
	}
	lhl, err := credential.BuildLHLReport(issuanceParams)
	if err != nil {
		return err
	}
	log.Printf("[issuance-cli] wrote credential public params to %s", outPath)
	log.Printf("[issuance-cli] x0 profile=%s len=%d bound=%d lhl_slack_bits=%.2f satisfies=%v", profile.Name, profile.X0Len, profile.X0CoeffBound, lhl.SlackBits, lhl.SatisfiesLHL)
	return nil
}

func setupNTRUKeys(ringDegree int, paramsOut, publicOut, privateOut string, force bool, keygenTrials, attempts int) error {
	ringQ, err := credential.LoadRingWithDegree(ringDegree)
	if err != nil {
		return fmt.Errorf("load ring: %w", err)
	}
	selectedN := int(ringQ.N)
	if paramsOut == "" {
		if selectedN == 512 {
			paramsOut = filepath.Join("Parameters", "Parameters.research_n512.json")
		} else {
			paramsOut = defaultNTRUParamsPath
		}
	}
	if publicOut == "" {
		if selectedN == 512 {
			publicOut = filepath.Join("ntru_keys", "public.research_n512.json")
		} else {
			publicOut = defaultNTRUPublicKeyPath
		}
	}
	if privateOut == "" {
		if selectedN == 512 {
			privateOut = filepath.Join("ntru_keys", "private.research_n512.json")
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
	if selectedN == 512 {
		log.Printf("[issuance-cli] UNSAFE RESEARCH MODE: generating NTRU key material for ring_degree=512")
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
	rng := newLocalRNG(seed)
	var inputs issuance.Inputs
	if expertInputPath != "" {
		spec := holderWitnessSpec{}
		if err := readJSONFile(expertInputPath, &spec); err != nil {
			return fmt.Errorf("read expert input: %w", err)
		}
		inputs, err = inputsFromWitnessSpec(rt.ringQ, rt.public, spec, rt.opts.NCols)
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
		Version:              issuanceArtifactVersion,
		CredentialPublicPath: publicPath,
		PRFParamsPath:        prfPath,
		PackedNCols:          rt.opts.NCols,
		LVCSNCols:            rt.opts.LVCSNCols,
		NLeaves:              rt.opts.NLeaves,
		Omega:                append([]uint64(nil), rt.omega...),
		holderWitnessSpec:    witnessSpecFromInputs(rt.ringQ, inputs),
	}
	request := commitRequestFile{
		Version:              issuanceArtifactVersion,
		CredentialPublicPath: publicPath,
		LVCSNCols:            rt.opts.LVCSNCols,
		NLeaves:              rt.opts.NLeaves,
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
	if req.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported commit request version %d", req.Version)
	}
	rt, err := loadIssuanceRuntime(req.CredentialPublicPath, defaultPRFParamsPath, issuanceRuntimeOverrides{})
	if err != nil {
		return err
	}
	if len(req.Omega) == 0 {
		return fmt.Errorf("commit request missing omega")
	}
	rng := newLocalRNG(seed)
	ch, err := issuance.SampleChallengeVector(rt.ringQ, req.Omega, rt.params.X0Len, rt.params.X0CoeffBound, rt.public.BoundB, rng)
	if err != nil {
		return fmt.Errorf("sample challenge: %w", err)
	}
	out := issueChallengeFile{
		Version:              issuanceArtifactVersion,
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
	if secret.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported holder secret version %d", secret.Version)
	}
	var challenge issueChallengeFile
	if err := readJSONFile(challengePath, &challenge); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	if challenge.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported challenge version %d", challenge.Version)
	}
	rt, err := loadIssuanceRuntime(secret.CredentialPublicPath, secret.PRFParamsPath, persistedIssuanceRuntimeOverrides(secret.PackedNCols, secret.LVCSNCols, secret.NLeaves, secret.Omega))
	if err != nil {
		return err
	}
	if len(secret.Omega) == 0 {
		return fmt.Errorf("holder secret missing omega")
	}
	inputs, err := inputsFromWitnessSpec(rt.ringQ, rt.public, secret.holderWitnessSpec, secret.PackedNCols)
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
		Version:              issuanceArtifactVersion,
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

func issuerVerifySign(commitRequestPath, challengePath, submissionPath, responsePath string, maxTrials int, ntruPaths signverify.SignPaths) error {
	var req commitRequestFile
	if err := readJSONFile(commitRequestPath, &req); err != nil {
		return fmt.Errorf("read commit request: %w", err)
	}
	if req.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported commit request version %d", req.Version)
	}
	var challenge issueChallengeFile
	if err := readJSONFile(challengePath, &challenge); err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	if challenge.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported challenge version %d", challenge.Version)
	}
	var submission preSignSubmissionFile
	if err := readJSONFile(submissionPath, &submission); err != nil {
		return fmt.Errorf("read submission: %w", err)
	}
	if submission.Version != issuanceArtifactVersion {
		return fmt.Errorf("unsupported pre-sign submission version %d", submission.Version)
	}
	rt, err := loadIssuanceRuntime(req.CredentialPublicPath, defaultPRFParamsPath, persistedIssuanceRuntimeOverrides(0, req.LVCSNCols, req.NLeaves, req.Omega))
	if err != nil {
		return err
	}
	if err := validateInt64RowsExact("commit_request.com", req.Com, int(rt.ringQ.N)); err != nil {
		return err
	}
	if len(submission.T) != int(rt.ringQ.N) {
		return fmt.Errorf("presign submission target coefficient length=%d want ring_degree=%d", len(submission.T), rt.ringQ.N)
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
	if err := validateNTRUSigningArtifacts(ntruPaths, len(submission.T)); err != nil {
		return err
	}
	sig, err := issuance.SignTargetAndSaveWithPaths(submission.T, maxTrials, ntru.SamplerOpts{}, ntruPaths)
	if err != nil {
		return fmt.Errorf("sign target: %w", err)
	}
	if err := signverify.VerifyWithParamsPath(sig, ntruPaths.ParamsPath); err != nil {
		return fmt.Errorf("verify signed target bundle: %w", err)
	}
	pubPath := ntruPaths.PublicKeyPath
	if pubPath == "" {
		pubPath = defaultNTRUPublicKeyPath
	}
	pub, err := keys.LoadPublicFile(pubPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}
	resp := issueResponseFile{
		Version:              issuanceArtifactVersion,
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

func holderFinalize(holderSecretPath, commitRequestPath, challengePath, responsePath, statePath, signaturePath, ntruParamsPath string) error {
	in, rt, inputs, derivedState, err := loadFinalizeInput(holderSecretPath, commitRequestPath, challengePath, responsePath)
	if err != nil {
		return err
	}
	if in.response.Signature != nil {
		if err := signverify.VerifyWithParamsPath(in.response.Signature, ntruParamsPath); err != nil {
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

func demoLocal(publicPath, prfPath, artifactDir, statePath, signaturePath string, seed int64, maxTrials int, overrides issuanceRuntimeOverrides, ntruPaths signverify.SignPaths) error {
	holderSecretPath := filepath.Join(artifactDir, "holder_secret.json")
	commitRequestPath := filepath.Join(artifactDir, "commit_request.json")
	challengePath := filepath.Join(artifactDir, "issue_challenge.json")
	submissionPath := filepath.Join(artifactDir, "presign_submission.json")
	responsePath := filepath.Join(artifactDir, "issue_response.json")
	challengeSeed := seed
	if seed != 0 {
		challengeSeed = seed + 1
	}
	if err := holderCommit(publicPath, prfPath, holderSecretPath, commitRequestPath, "", seed, overrides); err != nil {
		return err
	}
	if err := issuerChallenge(commitRequestPath, challengePath, challengeSeed); err != nil {
		return err
	}
	if err := holderProve(holderSecretPath, challengePath, submissionPath); err != nil {
		return err
	}
	if err := issuerVerifySign(commitRequestPath, challengePath, submissionPath, responsePath, maxTrials, ntruPaths); err != nil {
		return err
	}
	return holderFinalize(holderSecretPath, commitRequestPath, challengePath, responsePath, statePath, signaturePath, ntruPaths.ParamsPath)
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
	opts.LVCSNCols = 96
	if opts.LVCSNCols < opts.NCols {
		opts.LVCSNCols = opts.NCols
	}
	opts.PostSignLVCSNCols = opts.LVCSNCols
	opts.PRFLVCSNCols = opts.LVCSNCols
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

func sampleHolderInputs(r *ring.Ring, public credential.PublicParams, omega []uint64, rng *rand.Rand) (issuance.Inputs, error) {
	if rng == nil {
		return issuance.Inputs{}, fmt.Errorf("nil rng")
	}
	alphabet := []int64{-1, 0, 1}
	mu := sampleFullMuCoeff(r, alphabet, rng)
	r0Alphabet := make([]int64, 0, 2*public.X0CoeffBound+1)
	for v := -public.X0CoeffBound; v <= public.X0CoeffBound; v++ {
		r0Alphabet = append(r0Alphabet, v)
	}
	r0h := make([]*ring.Poly, public.X0Len)
	for i := range r0h {
		r0h[i] = sampleCoeffHead(r, r0Alphabet, omega, rng)
	}
	r1h := sampleCoeffHead(r, alphabet, omega, rng)
	rbar := sampleCoeffHead(r, alphabet, omega, rng)
	return issuance.Inputs{
		Mu:   []*ring.Poly{mu},
		R0H:  r0h,
		R1H:  []*ring.Poly{r1h},
		RBar: []*ring.Poly{rbar},
	}, nil
}

func inputsFromWitnessSpec(r *ring.Ring, public credential.PublicParams, spec holderWitnessSpec, packedNCols int) (issuance.Inputs, error) {
	if len(spec.Mu) == 0 && len(spec.M) > 0 && len(spec.K) > 0 {
		m := polysFromInt64(r, spec.M)
		k := polysFromInt64(r, spec.K)
		mu := r.NewPoly()
		ring.Copy(m[0], mu)
		r.Add(mu, k[0], mu)
		spec.Mu = polyVecToInt64(r, []*ring.Poly{mu}, false)
	}
	if len(spec.Mu) != public.LenMu || len(spec.R0H) != public.LenR0H || len(spec.R1H) != public.LenR1H || len(spec.RBar) != public.LenRBar {
		return issuance.Inputs{}, fmt.Errorf("expert witness row-count mismatch")
	}
	_ = packedNCols
	if err := credential.ValidateFullMuPayload(spec.Mu, int(r.N), public.BoundB); err != nil {
		return issuance.Inputs{}, fmt.Errorf("invalid mu payload: %w", err)
	}
	if err := validateInt64RowsExact("r0h", spec.R0H, int(r.N)); err != nil {
		return issuance.Inputs{}, err
	}
	if err := validateInt64RowsExact("r1h", spec.R1H, int(r.N)); err != nil {
		return issuance.Inputs{}, err
	}
	if err := validateInt64RowsExact("rbar", spec.RBar, int(r.N)); err != nil {
		return issuance.Inputs{}, err
	}
	return issuance.Inputs{
		Mu:   polysFromInt64(r, spec.Mu),
		R0H:  polysFromInt64(r, spec.R0H),
		R1H:  polysFromInt64(r, spec.R1H),
		RBar: polysFromInt64(r, spec.RBar),
	}, nil
}

func witnessSpecFromInputs(r *ring.Ring, in issuance.Inputs) holderWitnessSpec {
	return holderWitnessSpec{
		Mu:   polyVecToInt64(r, in.Mu, false),
		R0H:  polyVecToInt64(r, in.R0H, false),
		R1H:  polyVecToInt64(r, in.R1H, false),
		RBar: polyVecToInt64(r, in.RBar, false),
	}
}

func challengeFromFile(r *ring.Ring, in issueChallengeFile) (issuance.Challenge, error) {
	if len(in.RI0) == 0 || len(in.RI1) == 0 {
		return issuance.Challenge{}, fmt.Errorf("challenge file missing RI rows")
	}
	if err := validateInt64RowsExact("ri0", in.RI0, int(r.N)); err != nil {
		return issuance.Challenge{}, err
	}
	if err := validateInt64RowsExact("ri1", in.RI1, int(r.N)); err != nil {
		return issuance.Challenge{}, err
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
		Version:              credential.StateVersion,
		Mu:                   polyVecToInt64(rt.ringQ, inputs.Mu, false),
		MuLayout:             credential.MuLayoutFullCapacityHalvesV1,
		R0:                   polyVecToInt64(rt.ringQ, st.R0, false),
		R1:                   polyVecToInt64(rt.ringQ, st.R1, false),
		Z:                    polyVecToInt64(rt.ringQ, st.Z, false),
		X0Len:                rt.params.X0Len,
		X0CoeffBound:         rt.params.X0CoeffBound,
		TargetDim:            rt.params.TargetDim,
		TargetHidingLambda:   rt.params.TargetHidingLambda,
		RingDegree:           int(rt.ringQ.N),
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
	if in.secret.Version != issuanceArtifactVersion {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("unsupported holder secret version %d", in.secret.Version)
	}
	if err := readJSONFile(commitRequestPath, &in.request); err != nil {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("read commit request: %w", err)
	}
	if in.request.Version != issuanceArtifactVersion {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("unsupported commit request version %d", in.request.Version)
	}
	if err := readJSONFile(challengePath, &in.challenge); err != nil {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("read challenge: %w", err)
	}
	if in.challenge.Version != issuanceArtifactVersion {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("unsupported challenge version %d", in.challenge.Version)
	}
	if err := readJSONFile(responsePath, &in.response); err != nil {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("read response: %w", err)
	}
	if in.response.Version != issuanceArtifactVersion {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("unsupported response version %d", in.response.Version)
	}
	rt, err := loadIssuanceRuntime(in.secret.CredentialPublicPath, in.secret.PRFParamsPath, persistedIssuanceRuntimeOverrides(in.secret.PackedNCols, in.secret.LVCSNCols, in.secret.NLeaves, in.secret.Omega))
	if err != nil {
		return in, nil, issuance.Inputs{}, nil, err
	}
	if err := validateInt64RowsExact("commit_request.com", in.request.Com, int(rt.ringQ.N)); err != nil {
		return in, nil, issuance.Inputs{}, nil, err
	}
	if len(in.response.T) != int(rt.ringQ.N) {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("issue response target coefficient length=%d want ring_degree=%d", len(in.response.T), rt.ringQ.N)
	}
	if len(in.response.SigS1) != int(rt.ringQ.N) {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("issue response sig_s1 coefficient length=%d want ring_degree=%d", len(in.response.SigS1), rt.ringQ.N)
	}
	if len(in.response.SigS2) != int(rt.ringQ.N) {
		return in, nil, issuance.Inputs{}, nil, fmt.Errorf("issue response sig_s2 coefficient length=%d want ring_degree=%d", len(in.response.SigS2), rt.ringQ.N)
	}
	if err := validateInt64RowsExact("issue_response.ntru_public", in.response.NTRUPublic, int(rt.ringQ.N)); err != nil {
		return in, nil, issuance.Inputs{}, nil, err
	}
	inputs, err := inputsFromWitnessSpec(rt.ringQ, rt.public, in.secret.holderWitnessSpec, in.secret.PackedNCols)
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

func cloneRows(rows [][]int64) [][]int64 {
	out := make([][]int64, len(rows))
	for i := range rows {
		out[i] = append([]int64(nil), rows[i]...)
	}
	return out
}

func samplePackedHalfCoeffHeadNonZero(r *ring.Ring, alphabet []int64, omega []uint64, rng *rand.Rand, keepLower bool) *ring.Poly {
	for attempt := 0; attempt < 128; attempt++ {
		p := samplePackedHalfCoeffHead(r, alphabet, omega, rng, keepLower)
		if maxAbsSlice(polyToInt64Local(p, r)) > 0 {
			return p
		}
	}
	panic("failed to sample nonzero packed-half polynomial")
}

func sampleFullMuCoeff(r *ring.Ring, alphabet []int64, rng *rand.Rand) *ring.Poly {
	q := int64(r.Modulus[0])
	for attempt := 0; attempt < 128; attempt++ {
		p := r.NewPoly()
		nonzero := false
		for i := 0; i < r.N; i++ {
			v := alphabet[rng.Intn(len(alphabet))]
			if v != 0 {
				nonzero = true
			}
			if v < 0 {
				p.Coeffs[0][i] = uint64(v + q)
			} else {
				p.Coeffs[0][i] = uint64(v)
			}
		}
		if nonzero {
			return p
		}
	}
	panic("failed to sample nonzero sparse mu polynomial")
}

func sampleHeadValues(alphabet []int64, ncols int, q int64, rng *rand.Rand) []uint64 {
	head := make([]uint64, ncols)
	for i := 0; i < ncols; i++ {
		v := alphabet[rng.Intn(len(alphabet))]
		if v < 0 {
			head[i] = uint64(v + q)
		} else {
			head[i] = uint64(v)
		}
	}
	return head
}

func interpolateHeadToCoeffPoly(r *ring.Ring, omega []uint64, head []uint64) *ring.Poly {
	p := r.NewPoly()
	if len(head) == 0 {
		return p
	}
	copy(p.Coeffs[0], PIOP.Interpolate(omega[:len(head)], head, r.Modulus[0]))
	return p
}

func sampleCoeffHead(r *ring.Ring, alphabet []int64, omega []uint64, rng *rand.Rand) *ring.Poly {
	q := int64(r.Modulus[0])
	ncols := len(omega)
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	head := sampleHeadValues(alphabet, ncols, q, rng)
	return interpolateHeadToCoeffPoly(r, omega, head)
}

func samplePackedHalfCoeffHead(r *ring.Ring, alphabet []int64, omega []uint64, rng *rand.Rand, keepLower bool) *ring.Poly {
	ncols := len(omega)
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	q := int64(r.Modulus[0])
	head := sampleHeadValues(alphabet, ncols, q, rng)
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
	return interpolateHeadToCoeffPoly(r, omega, head)
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
