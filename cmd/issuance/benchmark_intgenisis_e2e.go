package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	benchmarkIntGenISISE2EVersion     = 1
	intGenISISDefaultMaxNLeaves       = 65536
	intGenISISLeafCapDisabledSentinel = 0
)

type benchmarkIntGenISISE2EConfig struct {
	ArtifactDir       string
	Profile           string
	ProfileBound      int64
	PRFParamsPath     string
	JSONOut           string
	Force             bool
	Seed              int64
	Issuance          intGenISISTuning
	Showing           intGenISISTuning
	NCols             int
	LVCSNCols         int
	NLeaves           int
	Eta               int
	Theta             int
	Rho               int
	Ell               int
	EllPrime          int
	PRFCompanionMode  PIOP.PRFCompanionMode
	PRFGroupRounds    int
	CheckpointSamples int
	KeygenTrials      int
	KeygenAttempts    int
	NTRUBeta          uint64
	MaxTrials         int
	MaxNLeaves        int
}

type intGenISISTuning struct {
	NCols              int                   `json:"ncols"`
	LVCSNCols          int                   `json:"lvcs_ncols"`
	NLeaves            int                   `json:"nleaves"`
	Eta                int                   `json:"eta"`
	Theta              int                   `json:"theta"`
	Rho                int                   `json:"rho"`
	Ell                int                   `json:"ell"`
	EllPrime           int                   `json:"ell_prime"`
	Kappa              [4]int                `json:"kappa"`
	PRFCompanionMode   PIOP.PRFCompanionMode `json:"prf_companion_mode,omitempty"`
	PRFGroupRounds     int                   `json:"prf_group_rounds,omitempty"`
	CheckpointSamples  int                   `json:"prf_checkpoint_samples,omitempty"`
	SigShortnessRadix  int                   `json:"sig_shortness_radix,omitempty"`
	SigShortnessDigits int                   `json:"sig_shortness_digits,omitempty"`
	CompressedRows     int                   `json:"compressed_rows,omitempty"`
	ReplayProjection   string                `json:"replay_projection,omitempty"`
	TranscriptMode     string                `json:"transcript_mode,omitempty"`
}

type benchmarkIntGenISISE2ETimings struct {
	SetupPublicMS    float64 `json:"setup_public_ms"`
	SetupNTRUKeysMS  float64 `json:"setup_ntru_keys_ms"`
	HolderCommitMS   float64 `json:"holder_commit_ms"`
	HolderProveMS    float64 `json:"holder_prove_ms"`
	IssuerSignMS     float64 `json:"issuer_verify_sign_ms"`
	HolderFinalizeMS float64 `json:"holder_finalize_ms"`
}

type benchmarkIntGenISISE2EOptions struct {
	Issuance intGenISISTuning `json:"issuance"`
	Showing  intGenISISTuning `json:"showing"`
}

type benchmarkIntGenISISE2EArtifacts struct {
	PublicParams  string `json:"public_params"`
	BMatrix       string `json:"b_matrix"`
	HolderSecret  string `json:"holder_secret"`
	CommitRequest string `json:"commit_request"`
	Submission    string `json:"presign_submission"`
	Response      string `json:"issue_response"`
	State         string `json:"state"`
	VerifierKey   string `json:"verifier_key"`
	Presentation  string `json:"presentation"`
	VerifierState string `json:"verifier_state"`
	NTRUParams    string `json:"ntru_params"`
	NTRUPublic    string `json:"ntru_public"`
	NTRUPrivate   string `json:"ntru_private"`
	NTRUSignature string `json:"ntru_signature"`
}

type benchmarkIntGenISISE2EReport struct {
	Version        int                             `json:"version"`
	Generated      string                          `json:"generated_at"`
	Profile        string                          `json:"profile"`
	ProfileBound   int64                           `json:"profile_bound,omitempty"`
	ArtifactDir    string                          `json:"artifact_dir"`
	MaxNLeaves     int                             `json:"max_nleaves,omitempty"`
	Options        benchmarkIntGenISISE2EOptions   `json:"options"`
	Timings        benchmarkIntGenISISE2ETimings   `json:"timings"`
	Issuance       benchmarkIntGenISISMetrics      `json:"issuance"`
	Showing        benchmarkIntGenISISMetrics      `json:"showing"`
	Artifacts      benchmarkIntGenISISE2EArtifacts `json:"artifacts"`
	ReplayRejected bool                            `json:"replay_rejected"`
	Notes          []string                        `json:"notes"`
}

func defaultIntGenISISTuning() intGenISISTuning {
	return intGenISISTuning{
		NCols:             16,
		LVCSNCols:         32,
		NLeaves:           4096,
		Eta:               8,
		Theta:             1,
		Rho:               1,
		Ell:               4,
		EllPrime:          4,
		PRFCompanionMode:  PIOP.PRFCompanionModeOutputAudit,
		PRFGroupRounds:    2,
		CheckpointSamples: 8,
	}
}

func intGenISISTuningFromLegacyConfig(cfg benchmarkIntGenISISE2EConfig) intGenISISTuning {
	t := defaultIntGenISISTuning()
	if cfg.NCols > 0 {
		t.NCols = cfg.NCols
	}
	if cfg.LVCSNCols > 0 {
		t.LVCSNCols = cfg.LVCSNCols
	}
	if cfg.NLeaves > 0 {
		t.NLeaves = cfg.NLeaves
	}
	if cfg.Eta > 0 {
		t.Eta = cfg.Eta
	}
	if cfg.Theta > 0 {
		t.Theta = cfg.Theta
	}
	if cfg.Rho > 0 {
		t.Rho = cfg.Rho
	}
	if cfg.Ell > 0 {
		t.Ell = cfg.Ell
	}
	if cfg.EllPrime > 0 {
		t.EllPrime = cfg.EllPrime
	}
	if cfg.PRFCompanionMode != "" {
		t.PRFCompanionMode = cfg.PRFCompanionMode
	}
	if cfg.PRFGroupRounds > 0 {
		t.PRFGroupRounds = cfg.PRFGroupRounds
	}
	if cfg.CheckpointSamples > 0 {
		t.CheckpointSamples = cfg.CheckpointSamples
	}
	return t
}

func normalizeIntGenISISTuning(t, fallback intGenISISTuning, includePRF bool) intGenISISTuning {
	if t.NCols <= 0 {
		t.NCols = fallback.NCols
	}
	if t.LVCSNCols <= 0 {
		t.LVCSNCols = fallback.LVCSNCols
	}
	if t.LVCSNCols < t.NCols {
		t.LVCSNCols = t.NCols
	}
	if t.NLeaves <= 0 {
		t.NLeaves = fallback.NLeaves
	}
	if t.Eta <= 0 {
		t.Eta = fallback.Eta
	}
	if t.Theta <= 0 {
		t.Theta = fallback.Theta
	}
	if t.Rho <= 0 {
		t.Rho = fallback.Rho
	}
	if t.Ell <= 0 {
		t.Ell = fallback.Ell
	}
	if t.EllPrime <= 0 {
		t.EllPrime = fallback.EllPrime
	}
	if includePRF {
		if t.PRFCompanionMode == "" {
			t.PRFCompanionMode = fallback.PRFCompanionMode
		}
		if t.PRFGroupRounds <= 0 {
			if fallback.PRFGroupRounds > 0 {
				t.PRFGroupRounds = fallback.PRFGroupRounds
			} else {
				t.PRFGroupRounds = defaultIntGenISISTuning().PRFGroupRounds
			}
		}
		if t.CheckpointSamples <= 0 {
			t.CheckpointSamples = fallback.CheckpointSamples
		}
		if t.SigShortnessRadix <= 0 {
			t.SigShortnessRadix = fallback.SigShortnessRadix
		}
		if t.SigShortnessDigits <= 0 {
			t.SigShortnessDigits = fallback.SigShortnessDigits
		}
		if t.CompressedRows < 0 {
			t.CompressedRows = 0
		}
		if t.ReplayProjection == "" {
			t.ReplayProjection = fallback.ReplayProjection
		}
		if t.TranscriptMode == "" {
			t.TranscriptMode = fallback.TranscriptMode
		}
	} else {
		t.PRFCompanionMode = ""
		t.PRFGroupRounds = 0
		t.CheckpointSamples = 0
		t.SigShortnessRadix = 0
		t.SigShortnessDigits = 0
		t.ReplayProjection = ""
		t.TranscriptMode = ""
	}
	return t
}

func normalizeIntGenISISMaxNLeaves(maxNLeaves int) int {
	if maxNLeaves < 0 {
		return intGenISISDefaultMaxNLeaves
	}
	return maxNLeaves
}

func validateIntGenISISLeafCap(label string, t intGenISISTuning, maxNLeaves int) error {
	if maxNLeaves == intGenISISLeafCapDisabledSentinel {
		return nil
	}
	if t.NLeaves > maxNLeaves {
		return fmt.Errorf("%s nleaves=%d exceeds max-nleaves=%d; increase ell, lower lvcs-ncols, or pass -max-nleaves 0 for an uncapped research run", label, t.NLeaves, maxNLeaves)
	}
	return nil
}

func intGenISISTuningToIssuanceOverrides(t intGenISISTuning, ringDegree int) issuanceRuntimeOverrides {
	return issuanceRuntimeOverrides{
		NCols:      t.NCols,
		LVCSNCols:  t.LVCSNCols,
		NLeaves:    t.NLeaves,
		Ell:        t.Ell,
		EllPrime:   t.EllPrime,
		Eta:        t.Eta,
		Theta:      t.Theta,
		Rho:        t.Rho,
		Kappa:      t.Kappa,
		RingDegree: ringDegree,
	}
}

func intGenISISTuningToShowingOpts(ringDegree int, t intGenISISTuning) PIOP.SimOpts {
	lvcsNCols := t.LVCSNCols
	if lvcsNCols < t.NCols {
		lvcsNCols = t.NCols
	}
	return PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:                 true,
		CoeffPacking:               true,
		RingDegree:                 ringDegree,
		NCols:                      t.NCols,
		LVCSNCols:                  lvcsNCols,
		PostSignLVCSNCols:          lvcsNCols,
		PRFLVCSNCols:               lvcsNCols,
		NLeaves:                    t.NLeaves,
		Ell:                        t.Ell,
		EllPrime:                   t.EllPrime,
		Eta:                        t.Eta,
		Rho:                        t.Rho,
		Theta:                      t.Theta,
		Kappa:                      t.Kappa,
		DomainMode:                 PIOP.DomainModeExplicit,
		PRFGroupRounds:             t.PRFGroupRounds,
		PRFCompanionMode:           t.PRFCompanionMode,
		PRFCheckpointSamples:       t.CheckpointSamples,
		SigShortnessRadix:          t.SigShortnessRadix,
		SigShortnessL:              t.SigShortnessDigits,
		IntGenISISMSECompression:   t.CompressedRows,
		IntGenISISReplayProjection: t.ReplayProjection,
		TranscriptCodec:            intGenISISLiveTranscriptCodecOrDefault(t.TranscriptMode),
		TranscriptProtocolMode:     intGenISISLiveTranscriptProtocolOrDefault(t.TranscriptMode),
		TranscriptVersion:          intGenISISLiveTranscriptVersionOrDefault(t.TranscriptMode),
	})
}

func intGenISISLiveTranscriptConfig(mode string) (codec, protocol string, err error) {
	normalized, err := normalizeSweepTranscriptMode(mode)
	if err != nil {
		return "", "", err
	}
	switch normalized {
	case sweepTranscriptModeBaseline:
		return "", "", nil
	case sweepTranscriptModeColumnWidths:
		return "", "", fmt.Errorf("transcript mode %q has codec support but is not enabled for live proofs because verifier integration is incomplete", normalized)
	case sweepTranscriptModeSmallField2025:
		return "", PIOP.TranscriptProtocolSmallField2025V1, nil
	default:
		return "", "", fmt.Errorf("transcript mode %q is estimator-only and has no live verifier implementation", normalized)
	}
}

func intGenISISLiveTranscriptCodec(mode string) (string, error) {
	codec, _, err := intGenISISLiveTranscriptConfig(mode)
	return codec, err
}

func intGenISISLiveTranscriptCodecOrDefault(mode string) string {
	codec, err := intGenISISLiveTranscriptCodec(mode)
	if err != nil {
		return ""
	}
	return codec
}

func intGenISISLiveTranscriptProtocolOrDefault(mode string) string {
	_, protocol, err := intGenISISLiveTranscriptConfig(mode)
	if err != nil {
		return ""
	}
	return protocol
}

func intGenISISLiveTranscriptVersionOrDefault(mode string) string {
	normalized, err := normalizeSweepTranscriptMode(mode)
	if err != nil {
		return ""
	}
	if normalized == sweepTranscriptModeSmallField2025 {
		return PIOP.TranscriptVersionSmallWood2025
	}
	return ""
}

func benchmarkIntGenISISE2E(cfg benchmarkIntGenISISE2EConfig) (benchmarkIntGenISISE2EReport, error) {
	if cfg.Profile == "" {
		cfg.Profile = credential.ProfileIntGenISISB
	}
	profile, ok := credential.LookupIntGenISISProfile(cfg.Profile)
	if !ok {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("unsupported IntGenISIS profile %q", cfg.Profile)
	}
	if cfg.ProfileBound < 0 {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("invalid profile bound %d", cfg.ProfileBound)
	}
	if cfg.ProfileBound > 0 {
		profile.B = cfg.ProfileBound
	}
	if cfg.PRFParamsPath == "" {
		cfg.PRFParamsPath = defaultPRFParamsPath
	}
	legacy := intGenISISTuningFromLegacyConfig(cfg)
	cfg.Issuance = normalizeIntGenISISTuning(cfg.Issuance, legacy, false)
	cfg.Showing = normalizeIntGenISISTuning(cfg.Showing, legacy, true)
	cfg.MaxNLeaves = normalizeIntGenISISMaxNLeaves(cfg.MaxNLeaves)
	if err := validateIntGenISISLeafCap("issuance", cfg.Issuance, cfg.MaxNLeaves); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	if err := validateIntGenISISLeafCap("showing", cfg.Showing, cfg.MaxNLeaves); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	if _, _, err := intGenISISLiveTranscriptConfig(cfg.Showing.TranscriptMode); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	switch cfg.Showing.PRFCompanionMode {
	case PIOP.PRFCompanionModeOutputAudit, PIOP.PRFCompanionModeDirectAuth, PIOP.PRFCompanionModeAuxInstance:
	default:
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("unsupported prf companion mode %q", cfg.Showing.PRFCompanionMode)
	}
	if cfg.KeygenTrials <= 0 {
		cfg.KeygenTrials = 10000
	}
	if cfg.KeygenAttempts <= 0 {
		cfg.KeygenAttempts = 4
	}
	if cfg.MaxTrials <= 0 {
		cfg.MaxTrials = 2048
	}
	artifactDir := cfg.ArtifactDir
	if artifactDir == "" {
		tmp, err := os.MkdirTemp("", "spruce-intgenisis-e2e-*")
		if err != nil {
			return benchmarkIntGenISISE2EReport{}, fmt.Errorf("create temp artifact dir: %w", err)
		}
		artifactDir = tmp
	} else if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("mkdir artifact dir: %w", err)
	}

	paths := benchmarkIntGenISISE2EArtifacts{
		PublicParams:  filepath.Join(artifactDir, fmt.Sprintf("credential_public.%s.json", profile.Name)),
		BMatrix:       filepath.Join(artifactDir, fmt.Sprintf("Bmatrix.%s.json", profile.Name)),
		HolderSecret:  filepath.Join(artifactDir, "holder_secret.json"),
		CommitRequest: filepath.Join(artifactDir, "commit_request.json"),
		Submission:    filepath.Join(artifactDir, "presign_submission.json"),
		Response:      filepath.Join(artifactDir, "issue_response.json"),
		State:         filepath.Join(artifactDir, "credential_state.intgenisis.json"),
		VerifierKey:   filepath.Join(artifactDir, "intgenisis_verifier_key.json"),
		Presentation:  filepath.Join(artifactDir, "presentation.intgenisis.json"),
		VerifierState: filepath.Join(artifactDir, "verifier_state.json"),
		NTRUParams:    filepath.Join(artifactDir, "ntru_params.json"),
		NTRUPublic:    filepath.Join(artifactDir, "ntru_public.json"),
		NTRUPrivate:   filepath.Join(artifactDir, "ntru_private.json"),
		NTRUSignature: filepath.Join(artifactDir, "ntru_signature.json"),
	}
	if err := benchmarkIntGenISISE2EOverwriteCheck(paths, cfg.JSONOut, cfg.Force); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	if cfg.Force {
		_ = os.Remove(paths.VerifierState)
	}

	var timings benchmarkIntGenISISE2ETimings
	t0 := time.Now()
	if err := setupIntGenISISPublicForProfile(paths.PublicParams, cfg.Force, profile, paths.BMatrix); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("setup IntGenISIS public params: %w", err)
	}
	timings.SetupPublicMS = millisSince(t0)

	t0 = time.Now()
	if err := setupNTRUKeys(profile.N, paths.NTRUParams, paths.NTRUPublic, paths.NTRUPrivate, cfg.Force, cfg.KeygenTrials, cfg.KeygenAttempts, cfg.NTRUBeta); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("setup NTRU keys: %w", err)
	}
	timings.SetupNTRUKeysMS = millisSince(t0)

	overrides := intGenISISTuningToIssuanceOverrides(cfg.Issuance, profile.N)
	t0 = time.Now()
	if err := holderCommit(paths.PublicParams, cfg.PRFParamsPath, paths.HolderSecret, paths.CommitRequest, "", cfg.Seed, overrides); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("holder commit: %w", err)
	}
	timings.HolderCommitMS = millisSince(t0)

	t0 = time.Now()
	if err := holderProve(paths.HolderSecret, "", paths.Submission); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("holder prove: %w", err)
	}
	holderProveDur := time.Since(t0)
	timings.HolderProveMS = durationMS(holderProveDur)

	issuanceMetrics, err := benchmarkIntGenISISE2EPreSignMetrics(paths.HolderSecret, paths.CommitRequest, paths.Submission, holderProveDur)
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}

	t0 = time.Now()
	if err := issuerVerifySign(paths.CommitRequest, "", paths.Submission, paths.Response, cfg.MaxTrials, ntruSigningPaths(paths.NTRUParams, paths.NTRUPublic, paths.NTRUPrivate, paths.NTRUSignature), paths.VerifierKey); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("issuer verify/sign: %w", err)
	}
	timings.IssuerSignMS = millisSince(t0)

	t0 = time.Now()
	if err := holderFinalize(paths.HolderSecret, paths.CommitRequest, "", paths.Response, paths.State, "", paths.NTRUParams); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("holder finalize: %w", err)
	}
	timings.HolderFinalizeMS = millisSince(t0)

	showingMetrics, replayRejected, err := benchmarkIntGenISISE2EShowing(paths, cfg)
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}

	report := benchmarkIntGenISISE2EReport{
		Version:      benchmarkIntGenISISE2EVersion,
		Generated:    time.Now().UTC().Format(time.RFC3339),
		Profile:      profile.Name,
		ProfileBound: profile.B,
		ArtifactDir:  artifactDir,
		MaxNLeaves:   cfg.MaxNLeaves,
		Options: benchmarkIntGenISISE2EOptions{
			Issuance: cfg.Issuance,
			Showing:  cfg.Showing,
		},
		Timings:        timings,
		Issuance:       issuanceMetrics,
		Showing:        showingMetrics,
		Artifacts:      paths,
		ReplayRejected: replayRejected,
		Notes: []string{
			fmt.Sprintf("semantic layout uses B=%d bounded-range m in coefficients [0,N-8) and B=%d bounded-range PRF key k in coefficients [N-8,N)", profile.B, profile.B),
			fmt.Sprintf("live IntGenISIS M,s,e membership uses the public B=%d range and dQ/masks use the corresponding range-membership degree accounting", profile.B),
			"max_nleaves caps the explicit DECS/LVCS evaluation domain; pass -max-nleaves 0 only for uncapped research sweeps",
			"showing shortness proves the configured signed-radix representable bound; the public signature beta is builder-validated and Fiat-Shamir-bound",
		},
	}
	benchmarkIntGenISISE2EPrintReport(report)
	if cfg.JSONOut != "" {
		if err := writeJSONFile(cfg.JSONOut, report, 0o644); err != nil {
			return benchmarkIntGenISISE2EReport{}, fmt.Errorf("write e2e benchmark json: %w", err)
		}
		log.Printf("[issuance-cli] benchmark-intgenisis-e2e wrote %s", cfg.JSONOut)
	}
	return report, nil
}

func benchmarkIntGenISISE2EOverwriteCheck(paths benchmarkIntGenISISE2EArtifacts, jsonOut string, force bool) error {
	if force {
		return nil
	}
	checks := []string{
		paths.PublicParams, paths.BMatrix, paths.HolderSecret, paths.CommitRequest, paths.Submission,
		paths.Response, paths.State, paths.VerifierKey, paths.Presentation, paths.VerifierState,
		paths.NTRUParams, paths.NTRUPublic, paths.NTRUPrivate, paths.NTRUSignature,
	}
	if jsonOut != "" {
		checks = append(checks, jsonOut)
	}
	for _, path := range checks {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing %s without -force", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", path, err)
		}
	}
	return nil
}

func benchmarkIntGenISISE2EPreSignMetrics(holderSecretPath, commitRequestPath, submissionPath string, proveDur time.Duration) (benchmarkIntGenISISMetrics, error) {
	var secret holderSecretFile
	if err := readJSONFile(holderSecretPath, &secret); err != nil {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("read holder secret for metrics: %w", err)
	}
	var req commitRequestFile
	if err := readJSONFile(commitRequestPath, &req); err != nil {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("read commit request for metrics: %w", err)
	}
	var sub preSignSubmissionFile
	if err := readJSONFile(submissionPath, &sub); err != nil {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("read pre-sign submission for metrics: %w", err)
	}
	if sub.Proof == nil {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("pre-sign submission missing proof")
	}
	rt, err := loadIssuanceRuntime(secret.CredentialPublicPath, secret.PRFParamsPath, persistedIssuanceRuntimeOverridesWithSmallWood(secret.PackedNCols, secret.LVCSNCols, secret.NLeaves, secret.Omega, secret.SmallWood))
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	cm, as, err := intGenISISCommitmentMatricesNTT(rt.ringQ, rt.public)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	pub := PIOP.PublicInputs{
		Com:          polyVecFromInt64(rt.ringQ, req.Com, true),
		CM:           cm,
		AS:           as,
		BoundB:       rt.public.CommitmentBound,
		X0Len:        rt.public.EllX0,
		RingDegree:   int(rt.ringQ.N),
		HashRelation: rt.public.HashRelation,
		IntGenISIS:   true,
	}
	verifyStart := time.Now()
	ok, err := PIOP.VerifyIntGenISISPreSign(pub, sub.Proof, rt.opts)
	verifyDur := time.Since(verifyStart)
	if err != nil || !ok {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("verify e2e pre-sign proof for metrics: ok=%v err=%v", ok, err)
	}
	rep, err := PIOP.BuildProofReport(sub.Proof, rt.opts, rt.ringQ)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("pre-sign proof report: %w", err)
	}
	return intGenISISMetricsFromProof(sub.Proof, rep, pub, rt.opts, proveDur, verifyDur, "e2e_presign"), nil
}

func benchmarkIntGenISISE2EShowing(paths benchmarkIntGenISISE2EArtifacts, cfg benchmarkIntGenISISE2EConfig) (benchmarkIntGenISISMetrics, bool, error) {
	st, err := credential.LoadIntGenISISState(paths.State)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	publicParams, err := credential.LoadPublicParams(paths.PublicParams)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("load IntGenISIS public params: %w", err)
	}
	verifierKey, err := credential.LoadIntGenISISVerifierKey(paths.VerifierKey)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	ringQ, err := credential.LoadRingWithDegree(st.RingDegree)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("load ring: %w", err)
	}
	params, err := prf.LoadLocalOrDefaultParams(cfg.PRFParamsPath)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("load prf params: %w", err)
	}
	opts := benchmarkIntGenISISE2EShowingOpts(st.RingDegree, cfg)
	if opts.NCols < params.LenKey {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("ncols=%d is too small for PRF key width %d", opts.NCols, params.LenKey)
	}
	B, err := loadBAsNTT(ringQ, publicParams.BPath)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	wit, err := benchmarkIntGenISISE2EWitnessFromState(ringQ, st, B, opts.NCols)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	A, err := benchmarkIntGenISISE2ESignatureMatrixFromRows(ringQ, st.NTRUPublic)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	cm, err := commitment.MatrixFromCoeff(ringQ, publicParams.CM)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("lift C_M: %w", err)
	}
	as, err := commitment.MatrixFromCoeff(ringQ, publicParams.AS)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("lift A_s: %w", err)
	}
	profile, ok := credential.LookupIntGenISISProfile(st.Profile)
	if !ok {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("unsupported IntGenISIS profile %q", st.Profile)
	}
	layout, err := credential.DefaultSemanticMessageLayout(profile, params.LenKey)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	keyScalars, err := credential.PRFKeyFromSemanticMessage(layout, st.M)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("extract IntGenISIS PRF key: %w", err)
	}
	key := make([]prf.Elem, len(keyScalars))
	for i, v := range keyScalars {
		key[i] = intGenISISBenchmarkElemFromSigned(v, ringQ.Modulus[0])
	}
	nonce, noncePublic := intGenISISBenchmarkNonce(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("compute IntGenISIS tag: %w", err)
	}
	pub := PIOP.PublicInputs{
		A:            A,
		B:            B,
		CM:           cm,
		AS:           as,
		Tag:          intGenISISBenchmarkLanesFromElems(tag, opts.NCols),
		Nonce:        noncePublic,
		BoundB:       publicParams.CommitmentBound,
		X0Len:        publicParams.EllX0,
		RingDegree:   int(ringQ.N),
		HashRelation: publicParams.HashRelation,
		IntGenISIS:   true,
		Extras:       benchmarkIntGenISISE2ESignatureBoundExtras(st.SignatureBound),
	}
	proveStart := time.Now()
	proof, err := PIOP.BuildIntGenISISShowingCombined(pub, wit, opts)
	proveDur := time.Since(proveStart)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("build IntGenISIS showing: %w", err)
	}
	verifyPub := pub
	verifyPub.A, err = benchmarkIntGenISISE2ESignatureMatrixFromRows(ringQ, verifierKey.NTRUPublic)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	verifyPub.Extras = benchmarkIntGenISISE2ESignatureBoundExtras(verifierKey.SignatureBound)
	verifyStart := time.Now()
	ok, err = PIOP.VerifyIntGenISISShowing(verifyPub, proof, opts)
	verifyDur := time.Since(verifyStart)
	if err != nil || !ok {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("standalone verify IntGenISIS showing: ok=%v err=%v", ok, err)
	}
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("showing proof report: %w", err)
	}
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("marshal IntGenISIS proof: %w", err)
	}
	digest, err := credential.PublicParamsDigest(publicParams)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("digest IntGenISIS public params: %w", err)
	}
	pres := credential.IntGenISISPresentation{
		Version:            credential.IntGenISISPresentationVersion,
		Profile:            st.Profile,
		PublicParamsDigest: digest,
		Nonce:              noncePublic,
		Tag:                intGenISISBenchmarkLanesFromElems(tag, opts.NCols),
		Proof:              proofRaw,
	}
	if err := credential.SaveIntGenISISPresentation(paths.Presentation, pres); err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	state := credential.NewIntGenISISVerifierState()
	if err := state.MarkPresentation(pres); err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	if err := credential.SaveIntGenISISVerifierState(paths.VerifierState, state); err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	replayErr := state.MarkPresentation(pres)
	replayRejected := replayErr != nil
	if !replayRejected {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("verifier replay state accepted repeated nonce/tag")
	}
	return intGenISISMetricsFromProof(proof, rep, verifyPub, opts, proveDur, verifyDur, "e2e_showing_standalone"), replayRejected, nil
}

func benchmarkIntGenISISE2EShowingOpts(ringDegree int, cfg benchmarkIntGenISISE2EConfig) PIOP.SimOpts {
	return intGenISISTuningToShowingOpts(ringDegree, cfg.Showing)
}

func benchmarkIntGenISISE2EWitnessFromState(r *ring.Ring, st credential.IntGenISISState, B []*ring.Poly, packedNCols int) (PIOP.WitnessInputs, error) {
	if len(st.SigS1) != int(r.N) || len(st.SigS2) != int(r.N) {
		return PIOP.WitnessInputs{}, fmt.Errorf("IntGenISIS state missing sig_s1/sig_s2 rows")
	}
	x1Rows := polysFromInt64(r, st.X1)
	if len(x1Rows) != 1 {
		return PIOP.WitnessInputs{}, fmt.Errorf("x1 rows=%d want 1", len(x1Rows))
	}
	if len(B) != 3+len(st.X0) {
		return PIOP.WitnessInputs{}, fmt.Errorf("B rows=%d want %d", len(B), 3+len(st.X0))
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

func benchmarkIntGenISISE2ESignatureMatrixFromRows(r *ring.Ring, ntruPublic [][]int64) ([][]*ring.Poly, error) {
	if len(ntruPublic) == 0 || len(ntruPublic[0]) != int(r.N) {
		return nil, fmt.Errorf("IntGenISIS verifier key missing NTRU public row of length %d", r.N)
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

func benchmarkIntGenISISE2ESignatureBoundExtras(bound int64) map[string]interface{} {
	if bound <= 0 {
		return nil
	}
	return map[string]interface{}{
		"IntGenISIS.signature_bound": []byte(fmt.Sprintf("%d", bound)),
	}
}

func benchmarkIntGenISISE2EPrintReport(report benchmarkIntGenISISE2EReport) {
	log.Printf("[issuance-cli] IntGenISIS e2e artifact_dir=%s profile=%s", report.ArtifactDir, report.Profile)
	benchmarkIntGenISISE2EPrintPhase("issuance", report.Issuance)
	benchmarkIntGenISISE2EPrintPhase("showing", report.Showing)
	log.Printf("[issuance-cli] IntGenISIS e2e replay_rejected=%v", report.ReplayRejected)
}

func benchmarkIntGenISISE2EPrintPhase(label string, m benchmarkIntGenISISMetrics) {
	log.Printf("[issuance-cli] IntGenISIS %s proof_bytes=%d paper_transcript_bytes=%d paper_transcript_kb=%.2f prove_ms=%.2f verify_ms=%.2f rows=%d rows_block=%d audit_rows=%d opening_cols=%d prf_rows=%d bound_rows=%d shortness_rows=%d hat_rows=%d theta=%d rho=%d ell_prime=%d smallfield_replay_rows=%d q_split_rows=%d q_limb_rows=%d dq=%d soundness_eq8_bits=%.2f",
		label,
		m.ProofSizeBytes,
		m.PaperTranscriptBytes,
		m.PaperTranscriptKB,
		m.ProvingMS,
		m.VerificationMS,
		m.TotalRows,
		m.RowsBlock,
		m.AuditRows,
		m.OpeningCols,
		m.PRFRows,
		m.BoundRows,
		m.ShortnessRows,
		m.HatRows,
		m.Theta,
		m.Rho,
		m.EllPrime,
		m.SmallFieldReplayRows,
		m.QSplitRows,
		m.QLimbRows,
		m.DQ,
		displayBits(m.SoundnessEq8Bits),
	)
	log.Printf("[issuance-cli] IntGenISIS %s eq8_round_bits=[%.2f %.2f %.2f %.2f] theorem_total_bits=%.2f ddecs=%d support_cols=%d committed_cols=%d clamped=%v",
		label,
		displayBits(m.RoundBits[0]),
		displayBits(m.RoundBits[1]),
		displayBits(m.RoundBits[2]),
		displayBits(m.RoundBits[3]),
		displayBits(m.TheoremTotalBits),
		m.DDECS,
		m.WitnessSupportCols,
		m.CommittedCols,
		m.Clamped,
	)
	log.Printf("[issuance-cli] IntGenISIS %s degree parallel_alg=%d aggregated_alg=%d dominant=%s paper_conservative_dq=%d mask_degree_bound=%d ternary_rows=%d compressed_rows=%d mse_compression_level=%d pack_width=%d compression_degree=%d replay_projection=%s projected_sig_constraints=%d source_bridge_constraints=%d",
		label,
		m.ParallelAlgDegree,
		m.AggregatedAlgDegree,
		m.DominantDegreeSource,
		m.PaperConservativeDQ,
		m.MaskDegreeBound,
		m.TernaryRows,
		m.CompressedRows,
		m.MSECompressionLevel,
		m.MSECompressionPackWidth,
		m.MSECompressionDegree,
		m.ReplayProjection,
		m.ProjectedSignatureConstraints,
		m.SourceBridgeConstraints,
	)
	log.Printf("[issuance-cli] IntGenISIS %s paper_buckets q=%d r=%d pdecs=%d mdecs=%d auth=%d tapes=%d sig_shortness=%d vtargets=%d barsets=%d pdecs_bit_width=%d vtargets_bit_width=%d",
		label,
		m.QBytes,
		m.RBytes,
		m.PdecsBytes,
		m.MdecsBytes,
		m.AuthBytes,
		m.TapesBytes,
		m.SigShortnessBytes,
		m.VTargetsBytes,
		m.BarSetsBytes,
		m.PDecsBitWidth,
		m.VTargetsBitWidth,
	)
	if m.PaperShapeNRows > 0 || m.PaperShapeQueries > 0 {
		log.Printf("[issuance-cli] IntGenISIS %s paper_shape nrows=%d queries=%d witness_layers=%d mask_rows=%d vhead=%d vbar=%d omit_entries=%d canonical=%v",
			label,
			m.PaperShapeNRows,
			m.PaperShapeQueries,
			m.PaperShapeWitnessLayers,
			m.PaperShapeMaskRows,
			m.PaperShapeVHeadBytes,
			m.PaperShapeVBarBytes,
			m.PaperShapeOpeningOmitEntries,
			m.PaperShapeCanonical,
		)
	}
	if m.TranscriptSecurityStatus != "" {
		log.Printf("[issuance-cli] IntGenISIS %s transcript_status=%s",
			label,
			m.TranscriptSecurityStatus,
		)
	}
	log.Printf("[issuance-cli] IntGenISIS %s audit views total=%d u=%d semantic=%d commitment=%d y=%d issuer=%d constraints fpar_int=%d range=%d shortness=%d y_linear=%d bridge_total=%d bridge_u=%d bridge_commitment=%d bridge_issuer=%d prf_key=%d",
		label,
		m.CoefficientViewRows,
		m.UCoefficientViewRows,
		m.SemanticViewRows,
		m.CommitmentViewRows,
		m.YCoefficientViewRows,
		m.IssuerViewRows,
		m.FparIntConstraints,
		m.RangeConstraints,
		m.ShortnessConstraints,
		m.YLinearConstraints,
		m.SourceBridgeConstraints,
		m.UBridgeConstraints,
		m.CommitmentBridgeConstraints,
		m.IssuerBridgeConstraints,
		m.PRFKeyBridgeConstraints,
	)
}

func millisSince(start time.Time) float64 {
	return durationMS(time.Since(start))
}

func durationMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}
