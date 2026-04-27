package main

import (
	"fmt"
	"log"
	"math"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/issuance"
	"vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const benchmarkX0Version = 2

type benchmarkX0PaperBuckets struct {
	TotalBytes        int `json:"total_bytes"`
	QBytes            int `json:"q_bytes"`
	PdecsBytes        int `json:"pdecs_bytes"`
	RBytes            int `json:"r_bytes"`
	SigShortnessBytes int `json:"sig_shortness_bytes"`
	AuthBytes         int `json:"auth_bytes"`
	VTargetsBytes     int `json:"vtargets_bytes"`
	BarSetsBytes      int `json:"barsets_bytes"`
}

type benchmarkX0Focus struct {
	DQ                        int `json:"dq"`
	LVCSNCols                 int `json:"lvcs_ncols"`
	NLeaves                   int `json:"nleaves"`
	WitnessRows               int `json:"witness_rows"`
	ReplayBlocks              int `json:"replay_blocks"`
	PCols                     int `json:"pcols"`
	RowOpeningEntries         int `json:"row_opening_entries"`
	CarrierSelectedRows       int `json:"carrier_selected_rows"`
	PRFCompanionSelectedRows  int `json:"prf_companion_selected_rows"`
	SourceProductSelectedRows int `json:"source_product_selected_rows"`
}

type benchmarkX0RunReport struct {
	Profile                 string                  `json:"profile"`
	Run                     int                     `json:"run"`
	X0Len                   int                     `json:"x0_len"`
	X0CoeffBound            int64                   `json:"x0_coeff_bound"`
	LHLSlackBits            float64                 `json:"lhl_slack_bits"`
	LHLSatisfies            bool                    `json:"lhl_satisfies"`
	IssuanceProveMS         float64                 `json:"issuance_prove_ms"`
	IssuanceVerifyMS        float64                 `json:"issuance_verify_ms"`
	IssuanceSignMS          float64                 `json:"issuance_sign_ms"`
	IssuanceProofBytes      int                     `json:"issuance_proof_bytes"`
	IssuanceTranscriptBytes int                     `json:"issuance_transcript_bytes"`
	ShowingProveMS          float64                 `json:"showing_prove_ms"`
	ShowingVerifyMS         float64                 `json:"showing_verify_ms"`
	ShowingProofBytes       int                     `json:"showing_proof_bytes"`
	ShowingTranscriptBytes  int                     `json:"showing_transcript_bytes"`
	CommittedWitnessRows    int                     `json:"committed_witness_rows"`
	ReplayWitnessRows       int                     `json:"replay_witness_rows"`
	IssuancePaperBuckets    benchmarkX0PaperBuckets `json:"issuance_paper_buckets"`
	IssuanceFocus           benchmarkX0Focus        `json:"issuance_focus"`
	ShowingPaperBuckets     benchmarkX0PaperBuckets `json:"showing_paper_buckets"`
	ShowingFocus            benchmarkX0Focus        `json:"showing_focus"`
}

type benchmarkX0ProfileSummary struct {
	Profile                 string                 `json:"profile"`
	Runs                    int                    `json:"runs"`
	X0Len                   int                    `json:"x0_len"`
	X0CoeffBound            int64                  `json:"x0_coeff_bound"`
	LHL                     credential.LHLReport   `json:"lhl"`
	AvgIssuanceProveMS      float64                `json:"avg_issuance_prove_ms"`
	AvgIssuanceVerifyMS     float64                `json:"avg_issuance_verify_ms"`
	AvgIssuanceSignMS       float64                `json:"avg_issuance_sign_ms"`
	AvgIssuanceProofBytes   float64                `json:"avg_issuance_proof_bytes"`
	AvgIssuanceTranscript   float64                `json:"avg_issuance_transcript_bytes"`
	AvgShowingProveMS       float64                `json:"avg_showing_prove_ms"`
	AvgShowingVerifyMS      float64                `json:"avg_showing_verify_ms"`
	AvgShowingProofBytes    float64                `json:"avg_showing_proof_bytes"`
	AvgShowingTranscript    float64                `json:"avg_showing_transcript_bytes"`
	AvgCommittedWitnessRows float64                `json:"avg_committed_witness_rows"`
	AvgReplayWitnessRows    float64                `json:"avg_replay_witness_rows"`
	RunReports              []benchmarkX0RunReport `json:"run_reports"`
}

type benchmarkX0Report struct {
	Version   int                         `json:"version"`
	Generated string                      `json:"generated_at"`
	Profiles  []benchmarkX0ProfileSummary `json:"profiles"`
}

func benchmarkPaperBuckets(rep PIOP.ProofReport) benchmarkX0PaperBuckets {
	return benchmarkX0PaperBuckets{
		TotalBytes:        rep.PaperTranscript.OptimizedBytes,
		QBytes:            rep.PaperTranscript.Q.OptimizedBytes,
		PdecsBytes:        rep.PaperTranscript.Pdecs.OptimizedBytes,
		RBytes:            rep.PaperTranscript.R.OptimizedBytes,
		SigShortnessBytes: rep.PaperTranscript.SigShortness.OptimizedBytes,
		AuthBytes:         rep.PaperTranscript.Auth.OptimizedBytes,
		VTargetsBytes:     rep.PaperTranscript.VTargets.OptimizedBytes,
		BarSetsBytes:      rep.PaperTranscript.BarSets.OptimizedBytes,
	}
}

func benchmarkFocus(rep PIOP.ProofReport) benchmarkX0Focus {
	return benchmarkX0Focus{
		DQ:                        rep.DQ,
		LVCSNCols:                 rep.TranscriptFocus.LVCSNCols,
		NLeaves:                   rep.TranscriptFocus.NLeaves,
		WitnessRows:               rep.TranscriptFocus.WitnessRows,
		ReplayBlocks:              rep.TranscriptFocus.ReplayBlocks,
		PCols:                     rep.TranscriptFocus.PCols,
		RowOpeningEntries:         rep.TranscriptFocus.RowOpeningEntries,
		CarrierSelectedRows:       rep.TranscriptFocus.CarrierSelectedRows,
		PRFCompanionSelectedRows:  rep.TranscriptFocus.PRFCompanionSelectedRows,
		SourceProductSelectedRows: rep.TranscriptFocus.SourceProductSelectedRows,
	}
}

func benchmarkX0(profilesCSV string, runs int, jsonOut string) error {
	if runs <= 0 {
		return fmt.Errorf("runs must be > 0")
	}
	profiles, err := parseBenchmarkProfiles(profilesCSV)
	if err != nil {
		return err
	}
	report := benchmarkX0Report{
		Version:   benchmarkX0Version,
		Generated: time.Now().UTC().Format(time.RFC3339),
	}
	for _, profile := range profiles {
		summary, err := runBenchmarkProfile(profile, runs)
		if err != nil {
			return err
		}
		report.Profiles = append(report.Profiles, summary)
		log.Printf("[issuance-cli] benchmark-x0 profile=%s runs=%d x0_len=%d x0_bound=%d lhl_slack_bits=%.2f satisfies=%v avg_issuance_prove=%s avg_issuance_verify=%s avg_issuance_sign=%s avg_showing_prove=%s avg_showing_verify=%s avg_showing_proof_bytes=%.0f avg_showing_transcript_bytes=%.0f avg_committed_rows=%.1f avg_replay_rows=%.1f",
			summary.Profile,
			summary.Runs,
			summary.X0Len,
			summary.X0CoeffBound,
			summary.LHL.SlackBits,
			summary.LHL.SatisfiesLHL,
			msString(summary.AvgIssuanceProveMS),
			msString(summary.AvgIssuanceVerifyMS),
			msString(summary.AvgIssuanceSignMS),
			msString(summary.AvgShowingProveMS),
			msString(summary.AvgShowingVerifyMS),
			summary.AvgShowingProofBytes,
			summary.AvgShowingTranscript,
			summary.AvgCommittedWitnessRows,
			summary.AvgReplayWitnessRows,
		)
	}
	if jsonOut != "" {
		if err := writeJSONFile(jsonOut, report, 0o644); err != nil {
			return fmt.Errorf("write benchmark json: %w", err)
		}
		log.Printf("[issuance-cli] benchmark-x0 wrote %s", jsonOut)
	}
	return nil
}

func parseBenchmarkProfiles(profilesCSV string) ([]string, error) {
	parts := strings.Split(profilesCSV, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if _, err := resolveX0Profile(name, 0, 0); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no benchmark profiles requested")
	}
	return out, nil
}

func runBenchmarkProfile(profileName string, runs int) (benchmarkX0ProfileSummary, error) {
	summary := benchmarkX0ProfileSummary{
		Profile: profileName,
		Runs:    runs,
	}
	for run := 1; run <= runs; run++ {
		runReport, lhl, err := executeBenchmarkRun(profileName, run)
		if err != nil {
			return benchmarkX0ProfileSummary{}, fmt.Errorf("profile %s run %d: %w", profileName, run, err)
		}
		if summary.X0Len == 0 {
			summary.X0Len = runReport.X0Len
			summary.X0CoeffBound = runReport.X0CoeffBound
			summary.LHL = lhl
		}
		summary.RunReports = append(summary.RunReports, runReport)
	}
	for _, run := range summary.RunReports {
		summary.AvgIssuanceProveMS += run.IssuanceProveMS
		summary.AvgIssuanceVerifyMS += run.IssuanceVerifyMS
		summary.AvgIssuanceSignMS += run.IssuanceSignMS
		summary.AvgIssuanceProofBytes += float64(run.IssuanceProofBytes)
		summary.AvgIssuanceTranscript += float64(run.IssuanceTranscriptBytes)
		summary.AvgShowingProveMS += run.ShowingProveMS
		summary.AvgShowingVerifyMS += run.ShowingVerifyMS
		summary.AvgShowingProofBytes += float64(run.ShowingProofBytes)
		summary.AvgShowingTranscript += float64(run.ShowingTranscriptBytes)
		summary.AvgCommittedWitnessRows += float64(run.CommittedWitnessRows)
		summary.AvgReplayWitnessRows += float64(run.ReplayWitnessRows)
	}
	denom := float64(len(summary.RunReports))
	summary.AvgIssuanceProveMS /= denom
	summary.AvgIssuanceVerifyMS /= denom
	summary.AvgIssuanceSignMS /= denom
	summary.AvgIssuanceProofBytes /= denom
	summary.AvgIssuanceTranscript /= denom
	summary.AvgShowingProveMS /= denom
	summary.AvgShowingVerifyMS /= denom
	summary.AvgShowingProofBytes /= denom
	summary.AvgShowingTranscript /= denom
	summary.AvgCommittedWitnessRows /= denom
	summary.AvgReplayWitnessRows /= denom
	return summary, nil
}

func executeBenchmarkRun(profileName string, run int) (benchmarkX0RunReport, credential.LHLReport, error) {
	tmpDir, err := os.MkdirTemp("", "spruce-benchmark-x0-*")
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, fmt.Errorf("mktemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	publicPath := filepath.Join(tmpDir, "credential_public.json")
	holderSecretPath := filepath.Join(tmpDir, "holder_secret.json")
	commitRequestPath := filepath.Join(tmpDir, "commit_request.json")
	challengePath := filepath.Join(tmpDir, "issue_challenge.json")
	submissionPath := filepath.Join(tmpDir, "presign_submission.json")
	responsePath := filepath.Join(tmpDir, "issue_response.json")
	statePath := filepath.Join(tmpDir, "credential_state.json")
	signaturePath := filepath.Join(tmpDir, "signature.json")

	if err := setupDemoPublic(publicPath, true, "", credential.HashRelationBBTran, profileName, 0, 0, 0); err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, fmt.Errorf("load ring: %w", err)
	}
	public, err := credential.LoadPublicParams(publicPath)
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	params, err := public.ToIssuanceParams(ringQ)
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	lhl, err := credential.BuildLHLReport(params)
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	baseSeed := benchmarkSeed(profileName, run)
	if err := holderCommit(publicPath, defaultPRFParamsPath, holderSecretPath, commitRequestPath, "", baseSeed, issuanceRuntimeOverrides{}); err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	if err := issuerChallenge(commitRequestPath, challengePath, baseSeed+1); err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	proveStart := time.Now()
	if err := holderProve(holderSecretPath, challengePath, submissionPath); err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	issuanceProveDur := time.Since(proveStart)

	var secret holderSecretFile
	if err := readJSONFile(holderSecretPath, &secret); err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, fmt.Errorf("read holder secret: %w", err)
	}
	var submission preSignSubmissionFile
	if err := readJSONFile(submissionPath, &submission); err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, fmt.Errorf("read submission: %w", err)
	}
	rt, err := loadIssuanceRuntime(publicPath, secret.PRFParamsPath, persistedIssuanceRuntimeOverrides(secret.PackedNCols, secret.LVCSNCols, secret.NLeaves, secret.Omega))
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	issuanceRep, err := PIOP.BuildProofReport(submission.Proof, rt.opts, rt.ringQ)
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, fmt.Errorf("issuance report: %w", err)
	}

	issuanceVerifyDur, issuanceSignDur, err := benchmarkIssuerVerifyAndSign(commitRequestPath, challengePath, submissionPath, responsePath, 2048)
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	if err := holderFinalize(holderSecretPath, commitRequestPath, challengePath, responsePath, statePath, signaturePath, defaultNTRUParamsPath); err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}
	showingRun, err := benchmarkShowingFromState(statePath, baseSeed+2)
	if err != nil {
		return benchmarkX0RunReport{}, credential.LHLReport{}, err
	}

	runReport := benchmarkX0RunReport{
		Profile:                 profileName,
		Run:                     run,
		X0Len:                   public.X0Len,
		X0CoeffBound:            public.X0CoeffBound,
		LHLSlackBits:            lhl.SlackBits,
		LHLSatisfies:            lhl.SatisfiesLHL,
		IssuanceProveMS:         durationMillis(issuanceProveDur),
		IssuanceVerifyMS:        durationMillis(issuanceVerifyDur),
		IssuanceSignMS:          durationMillis(issuanceSignDur),
		IssuanceProofBytes:      issuanceRep.ProofBytes,
		IssuanceTranscriptBytes: issuanceRep.PaperTranscript.OptimizedBytes,
		ShowingProveMS:          durationMillis(showingRun.ProveDuration),
		ShowingVerifyMS:         durationMillis(showingRun.VerifyDuration),
		ShowingProofBytes:       showingRun.Report.ProofBytes,
		ShowingTranscriptBytes:  showingRun.Report.PaperTranscript.OptimizedBytes,
		CommittedWitnessRows:    showingRun.CommittedRows.TotalRows,
		ReplayWitnessRows:       showingRun.ReplayRows.TotalRows,
		IssuancePaperBuckets:    benchmarkPaperBuckets(issuanceRep),
		IssuanceFocus:           benchmarkFocus(issuanceRep),
		ShowingPaperBuckets:     benchmarkPaperBuckets(showingRun.Report),
		ShowingFocus:            benchmarkFocus(showingRun.Report),
	}
	log.Printf("[issuance-cli] benchmark-x0 run profile=%s run=%d x0_len=%d x0_bound=%d lhl_slack_bits=%.2f issuance_prove=%s issuance_verify=%s issuance_sign=%s showing_prove=%s showing_verify=%s showing_proof_bytes=%d showing_transcript_bytes=%d committed_rows=%d replay_rows=%d",
		runReport.Profile,
		runReport.Run,
		runReport.X0Len,
		runReport.X0CoeffBound,
		runReport.LHLSlackBits,
		msString(runReport.IssuanceProveMS),
		msString(runReport.IssuanceVerifyMS),
		msString(runReport.IssuanceSignMS),
		msString(runReport.ShowingProveMS),
		msString(runReport.ShowingVerifyMS),
		runReport.ShowingProofBytes,
		runReport.ShowingTranscriptBytes,
		runReport.CommittedWitnessRows,
		runReport.ReplayWitnessRows,
	)
	return runReport, lhl, nil
}

func benchmarkIssuerVerifyAndSign(commitRequestPath, challengePath, submissionPath, responsePath string, maxTrials int) (time.Duration, time.Duration, error) {
	var req commitRequestFile
	if err := readJSONFile(commitRequestPath, &req); err != nil {
		return 0, 0, fmt.Errorf("read commit request: %w", err)
	}
	if req.Version != issuanceArtifactVersion {
		return 0, 0, fmt.Errorf("unsupported commit request version %d", req.Version)
	}
	var challenge issueChallengeFile
	if err := readJSONFile(challengePath, &challenge); err != nil {
		return 0, 0, fmt.Errorf("read challenge: %w", err)
	}
	if challenge.Version != issuanceArtifactVersion {
		return 0, 0, fmt.Errorf("unsupported challenge version %d", challenge.Version)
	}
	var submission preSignSubmissionFile
	if err := readJSONFile(submissionPath, &submission); err != nil {
		return 0, 0, fmt.Errorf("read submission: %w", err)
	}
	if submission.Version != issuanceArtifactVersion {
		return 0, 0, fmt.Errorf("unsupported pre-sign submission version %d", submission.Version)
	}
	rt, err := loadIssuanceRuntime(req.CredentialPublicPath, defaultPRFParamsPath, persistedIssuanceRuntimeOverrides(0, req.LVCSNCols, req.NLeaves, req.Omega))
	if err != nil {
		return 0, 0, err
	}
	com := polyVecFromInt64(rt.ringQ, req.Com, true)
	ch, err := challengeFromFile(rt.ringQ, challenge)
	if err != nil {
		return 0, 0, err
	}
	B, err := loadBAsNTT(rt.ringQ, rt.public.BPath)
	if err != nil {
		return 0, 0, err
	}
	verifyState := &issuance.State{
		T: submission.T,
		B: B,
	}
	verifyStart := time.Now()
	ok, err := issuance.VerifyPreSign(rt.params, ch, com, verifyState, submission.Proof, rt.opts)
	verifyDur := time.Since(verifyStart)
	if err != nil {
		return 0, 0, fmt.Errorf("verify pre-sign: %w", err)
	}
	if !ok {
		return 0, 0, fmt.Errorf("verify pre-sign returned ok=false")
	}
	opts := ntru.SamplerOpts{Prec: 256}
	signStart := time.Now()
	sig, err := benchmarkSignTargetWithinBeta(submission.T, maxTrials, opts, 16)
	signDur := time.Since(signStart)
	if err != nil {
		return 0, 0, fmt.Errorf("sign target: %w", err)
	}
	if err := signverify.Verify(sig); err != nil {
		return 0, 0, fmt.Errorf("verify signed target bundle: %w", err)
	}
	pub, err := keys.LoadPublic()
	if err != nil {
		return 0, 0, fmt.Errorf("load public key: %w", err)
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
		return 0, 0, fmt.Errorf("write issuer response: %w", err)
	}
	return verifyDur, signDur, nil
}

func benchmarkSignTargetWithinBeta(t []int64, maxTrials int, opts ntru.SamplerOpts, attempts int) (*keys.Signature, error) {
	if attempts <= 0 {
		attempts = 1
	}
	par, err := ntrurio.LoadParams(filepath.Join("Parameters", "Parameters.json"), true)
	if err != nil {
		return nil, fmt.Errorf("load signature bound: %w", err)
	}
	var lastMax int64
	for attempt := 1; attempt <= attempts; attempt++ {
		sig, err := signverify.SignTarget(t, maxTrials, opts)
		if err != nil {
			return nil, err
		}
		lastMax = benchmarkSignatureLInf(sig)
		if uint64(lastMax) <= par.Beta {
			return sig, nil
		}
		log.Printf("[issuance-cli] benchmark-x0 retrying target signature: max coefficient %d exceeds beta=%d (attempt %d/%d)", lastMax, par.Beta, attempt, attempts)
	}
	return nil, fmt.Errorf("signature shortness blocker after %d attempts: max coefficient %d exceeds beta=%d under q=%d", attempts, lastMax, par.Beta, par.Q)
}

func benchmarkSignatureLInf(sig *keys.Signature) int64 {
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

type benchmarkShowingRun struct {
	ProveDuration  time.Duration
	VerifyDuration time.Duration
	Report         PIOP.ProofReport
	CommittedRows  PIOP.CommittedWitnessBreakdown
	ReplayRows     PIOP.LogicalWitnessBreakdown
}

func benchmarkShowingFromState(statePath string, seed int64) (benchmarkShowingRun, error) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("load ring: %w", err)
	}
	state, err := credential.LoadState(statePath)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("load credential state: %w", err)
	}
	publicParams, err := benchmarkLoadCredentialPublicParamsFromState(state)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("load credential public params: %w", err)
	}
	if state.HashRelation != "" && credential.NormalizeHashRelation(state.HashRelation) != credential.NormalizeHashRelation(publicParams.HashRelation) {
		return benchmarkShowingRun{}, fmt.Errorf("credential state hash relation %q does not match public params relation %q", state.HashRelation, publicParams.HashRelation)
	}
	if err := credential.ValidateLiveHashRelation(publicParams.HashRelation); err != nil {
		return benchmarkShowingRun{}, err
	}
	params, err := benchmarkLoadPRFParamsFromState(state)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("load prf params: %w", err)
	}
	opts, err := benchmarkShowingOpts(ringQ, params)
	if err != nil {
		return benchmarkShowingRun{}, err
	}
	omega, err := deriveOmegaForIssuanceOpts(ringQ, publicParams.HashRelation, opts)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("derive omega: %w", err)
	}
	B, err := benchmarkLoadBForShowing(ringQ, state, publicParams)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("load B: %w", err)
	}
	wit, err := benchmarkBuildWitnessFromState(ringQ, state, B, omega, publicParams.BoundB, publicParams.X0CoeffBound)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("build witness: %w", err)
	}
	A, err := benchmarkBuildSignatureMatrix(ringQ, state, benchmarkShowingSignatureComponentCount(wit))
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("build A: %w", err)
	}
	rng := mrand.New(mrand.NewSource(seed))
	nonce, noncePublic := benchmarkSampleNonce(params.LenNonce, len(omega), ringQ.Modulus[0], rng)
	key, err := benchmarkPRFKeyFromWitnessOnOmega(ringQ, wit, omega, params.LenKey)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("prf key: %w", err)
	}
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("prf tag: %w", err)
	}
	pub := PIOP.PublicInputs{
		A:                  A,
		B:                  B,
		Tag:                benchmarkLanesFromElems(tag, len(omega)),
		Nonce:              noncePublic,
		BoundB:             publicParams.BoundB,
		X0Len:              publicParams.X0Len,
		X0CoeffBound:       publicParams.X0CoeffBound,
		TargetDim:          publicParams.TargetDim,
		TargetHidingLambda: publicParams.TargetHidingLambda,
		HashRelation:       publicParams.HashRelation,
	}
	proveStart := time.Now()
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	proveDur := time.Since(proveStart)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("build showing: %w", err)
	}
	verifySet := PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}
	if proof.PRFCompanion != nil {
		verifySet.PRFCompanionLayout = proof.PRFCompanion.Layout
	}
	verifyStart := time.Now()
	ok, err := PIOP.VerifyWithConstraints(proof, verifySet, pub, opts, PIOP.FSModeCredential)
	verifyDur := time.Since(verifyStart)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("verify showing: %w", err)
	}
	if !ok {
		return benchmarkShowingRun{}, fmt.Errorf("verify showing returned ok=false")
	}
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		return benchmarkShowingRun{}, fmt.Errorf("showing report: %w", err)
	}
	return benchmarkShowingRun{
		ProveDuration:  proveDur,
		VerifyDuration: verifyDur,
		Report:         rep,
		CommittedRows:  PIOP.CommittedWitnessRowBreakdownFromProof(proof),
		ReplayRows:     PIOP.LogicalWitnessRowBreakdownFromProof(proof),
	}, nil
}

func benchmarkShowingOpts(ringQ *ring.Ring, params *prf.Params) (PIOP.SimOpts, error) {
	const (
		productionPRFGroupRounds = 2
		productionNCols          = 16
		productionEll            = 16
	)
	opts := PIOP.SimOpts{
		Credential:           true,
		NCols:                productionNCols,
		Ell:                  productionEll,
		DomainMode:           PIOP.DomainModeExplicit,
		PRFGroupRounds:       productionPRFGroupRounds,
		CoeffPacking:         true,
		CoeffNativeSigModel:  PIOP.CoeffNativeSigModelLiteralPackedAggregatedV3,
		ShowingPreset:        PIOP.ShowingPresetInlineTargetReplayCompactResearch,
		ShowingReplayMode:    PIOP.ShowingReplayModeFull,
		AggregateR0Replay:    true,
		PRFCompanionMode:     PIOP.PRFCompanionModeOutputAudit,
		PRFCheckpointSamples: 8,
	}
	opts = PIOP.ResolveSimOptsDefaults(opts)
	if params != nil && opts.NCols < 2*params.LenKey {
		opts.NCols = 2 * params.LenKey
	}
	if opts.NCols%2 != 0 {
		opts.NCols++
	}
	opts.LVCSNCols = opts.PostSignLVCSNCols
	if opts.LVCSNCols < opts.NCols {
		opts.LVCSNCols = opts.NCols
		opts.PostSignLVCSNCols = opts.LVCSNCols
		opts.PRFLVCSNCols = opts.LVCSNCols
	}
	if opts.PRFGroupRounds > 1 {
		prfDeg, err := prf.MaxConstraintDegreeGrouped(params, opts.PRFGroupRounds)
		if err != nil {
			return PIOP.SimOpts{}, fmt.Errorf("compute grouped PRF degree: %w", err)
		}
		maxEll := benchmarkMaxEllForGroupedPRF(int(ringQ.N), opts.NCols, int(prfDeg))
		if maxEll <= 0 {
			return PIOP.SimOpts{}, fmt.Errorf("invalid grouped PRF parameters: N=%d ncols=%d prfDeg=%d g=%d", ringQ.N, opts.NCols, prfDeg, opts.PRFGroupRounds)
		}
		if opts.Ell > maxEll {
			opts.Ell = maxEll
		}
	}
	return opts, nil
}

func benchmarkMaxEllForGroupedPRF(ringN, ncols, prfDegree int) int {
	if ringN <= 0 || ncols <= 0 || prfDegree <= 1 {
		return 0
	}
	maxDeg0 := (ringN - 1) / prfDegree
	maxEll := maxDeg0 - ncols + 1
	if maxEll < 1 {
		return 0
	}
	return maxEll
}

func benchmarkLoadBForShowing(r *ring.Ring, st credential.State, public credential.PublicParams) ([]*ring.Poly, error) {
	bPath := public.BPath
	if bPath == "" {
		bPath = st.BPath
	}
	if bPath == "" {
		return nil, fmt.Errorf("missing B path in public params/state")
	}
	meta, err := ntrurio.LoadBMatrixMetadata(bPath)
	if err != nil {
		return nil, err
	}
	if meta.TargetDim != public.TargetDim {
		return nil, fmt.Errorf("B target_dim=%d want %d", meta.TargetDim, public.TargetDim)
	}
	if meta.X0Len != public.X0Len {
		return nil, fmt.Errorf("B x0_len=%d want %d", meta.X0Len, public.X0Len)
	}
	out := make([]*ring.Poly, len(meta.B))
	for i := range meta.B {
		p := r.NewPoly()
		copy(p.Coeffs[0], meta.B[i])
		r.NTT(p, p)
		out[i] = p
	}
	return out, nil
}

func benchmarkLoadPRFParamsFromState(st credential.State) (*prf.Params, error) {
	if st.PRFParamsPath != "" {
		if params, err := prf.LoadParamsFromFile(st.PRFParamsPath); err == nil {
			return params, nil
		}
	}
	return prf.LoadLocalOrDefaultParams(defaultPRFParamsPath)
}

func benchmarkLoadCredentialPublicParamsFromState(st credential.State) (credential.PublicParams, error) {
	if st.CredentialPublicPath == "" {
		return credential.PublicParams{}, fmt.Errorf("credential state missing credential_public_path")
	}
	return credential.LoadPublicParams(st.CredentialPublicPath)
}

func benchmarkBuildSignatureMatrix(r *ring.Ring, st credential.State, uCount int) ([][]*ring.Poly, error) {
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
	return [][]*ring.Poly{{negHNTT, one}}, nil
}

func benchmarkBuildWitnessFromState(r *ring.Ring, st credential.State, B []*ring.Poly, omega []uint64, boundB, x0Bound int64) (PIOP.WitnessInputs, error) {
	coeffNative, err := benchmarkBuildCoeffNativeShowingWitnessFromState(r, st, B, omega, boundB, x0Bound)
	if err != nil {
		return PIOP.WitnessInputs{}, err
	}
	return PIOP.WitnessInputs{CoeffNativeShowing: coeffNative}, nil
}

func benchmarkBuildCoeffNativeShowingWitnessFromState(r *ring.Ring, st credential.State, B []*ring.Poly, omega []uint64, boundB, x0Bound int64) (*PIOP.CoeffNativeShowingWitness, error) {
	if len(st.SigS1) == 0 || len(st.SigS2) == 0 {
		return nil, fmt.Errorf("missing sig_s1/sig_s2 in credential state")
	}
	par, err := ntrurio.LoadParams(filepath.Join("Parameters", "Parameters.json"), true)
	if err != nil {
		return nil, fmt.Errorf("load signature bound: %w", err)
	}
	_, _, maxSig := st.SignatureCoordLinf()
	if uint64(maxSig) > par.Beta {
		return nil, fmt.Errorf("signature shortness blocker: max(|sig_s1|,|sig_s2|)=%d exceeds beta=%d under q=%d", maxSig, par.Beta, par.Q)
	}
	if len(st.Mu) == 0 || len(st.R0) == 0 || len(st.R1) == 0 || len(st.Z) == 0 {
		return nil, fmt.Errorf("missing semantic witness rows in credential state")
	}
	x0Len := st.X0Len
	if x0Len <= 0 {
		x0Len = len(st.R0)
	}
	if x0Len <= 0 {
		x0Len = 1
	}
	if len(st.R0) != x0Len {
		return nil, fmt.Errorf("credential state R0 len=%d want x0Len=%d", len(st.R0), x0Len)
	}
	if len(B) < 3+x0Len {
		return nil, fmt.Errorf("missing B matrix for target reconstruction: have %d want at least %d", len(B), 3+x0Len)
	}
	packedNCols, err := PIOP.ResolvePackedNCols(st.PackedNCols, 0, int(r.N))
	if err != nil {
		return nil, fmt.Errorf("resolve packed ncols: %w", err)
	}
	if err := credential.ValidateFullMuPayload(st.Mu, int(r.N), boundB); err != nil {
		return nil, fmt.Errorf("invalid credential mu payload: %w", err)
	}
	muPoly := polyFromInt64(r, st.Mu[0])
	_ = x0Bound
	_ = omega
	r0Polys := polysFromInt64(r, st.R0)
	r1Poly := polyFromInt64(r, st.R1[0])
	zPoly := polyFromInt64(r, st.Z[0])
	_, tCoeffs, err := credential.ComputeTargetVectorFromMu(r, B, muPoly, r0Polys, r1Poly)
	if err != nil {
		return nil, fmt.Errorf("recompute target from credential state: %w", err)
	}
	tPoly := polyFromInt64(r, tCoeffs)
	wit := &PIOP.CoeffNativeShowingWitness{
		Sig: []*ring.Poly{
			polyFromInt64(r, st.SigS1),
			polyFromInt64(r, st.SigS2),
		},
		Mu:          muPoly,
		R0:          r0Polys,
		R1:          r1Poly,
		Z:           zPoly,
		T:           tPoly,
		PackedNCols: packedNCols,
	}
	if err := wit.Validate(int(r.N)); err != nil {
		return nil, fmt.Errorf("invalid coeff-native showing witness: %w", err)
	}
	return wit, nil
}

func benchmarkShowingSignatureComponentCount(wit PIOP.WitnessInputs) int {
	if wit.CoeffNativeShowing != nil && len(wit.CoeffNativeShowing.Sig) > 0 {
		return len(wit.CoeffNativeShowing.Sig)
	}
	return 0
}

func benchmarkPRFKeyFromWitnessOnOmega(r *ring.Ring, wit PIOP.WitnessInputs, omega []uint64, lenKey int) ([]prf.Elem, error) {
	if wit.CoeffNativeShowing == nil || wit.CoeffNativeShowing.Mu == nil {
		return nil, fmt.Errorf("missing coeff-native showing witness Mu")
	}
	return PIOP.ExtractSignedPRFKeyElemsFromMuCoeffs(
		r,
		wit.CoeffNativeShowing.Mu,
		wit.CoeffNativeShowing.PackedNCols,
		lenKey,
	)
}

func benchmarkSampleNonce(lenNonce, ncols int, q uint64, rng *mrand.Rand) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lenNonce)
	public := make([][]int64, lenNonce)
	for i := 0; i < lenNonce; i++ {
		v := rng.Uint64() % q
		nonce[i] = prf.Elem(v)
		public[i] = benchmarkConstLane(ncols, int64(v))
	}
	return nonce, public
}

func benchmarkLanesFromElems(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = benchmarkConstLane(ncols, int64(v))
	}
	return out
}

func benchmarkConstLane(ncols int, v int64) []int64 {
	row := make([]int64, ncols)
	for i := range row {
		row[i] = v
	}
	return row
}

func benchmarkSeed(profile string, run int) int64 {
	var hash int64 = 17
	for _, ch := range profile {
		hash = hash*31 + int64(ch)
	}
	return hash + int64(run)*1009
}

func durationMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func msString(ms float64) string {
	return fmt.Sprintf("%s", time.Duration(math.Round(ms*float64(time.Millisecond))))
}
