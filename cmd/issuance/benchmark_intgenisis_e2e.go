package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	vsishash "vSIS-Signature/internal/hash"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	benchmarkIntGenISISE2EVersion     = 2
	intGenISISDefaultMaxNLeaves       = 65536
	intGenISISLeafCapDisabledSentinel = 0
	defaultNTRUKeygenAttempts         = 16
)

type benchmarkIntGenISISE2EConfig struct {
	ArtifactDir          string
	PresetName           string
	CanonicalPresetID    string
	PresetVersion        int
	PresetLifecycle      credential.PresetLifecycle
	ClaimScope           credential.ClaimScope
	PrimitiveProfileID   string
	PresetManifestDigest string
	ThreatModel          credential.PresetThreatModel
	Profile              string
	SecurityProfile      string
	SecurityMode         string
	CoreBitsRequired     float64
	CompleteSystemClaim  bool
	PRFProfile           string
	PRFParamsPath        string
	PRFParamsDigest      string
	JSONOut              string
	Force                bool
	Verbose              bool
	Issuance             intGenISISTuning
	Showing              intGenISISTuning
	KeygenTrials         int
	KeygenAttempts       int
	NTRUBeta             uint64
	MaxTrials            int
	MaxNLeaves           int
}

type intGenISISTuning struct {
	NCols                  int                   `json:"ncols"`
	LVCSNCols              int                   `json:"lvcs_ncols"`
	NLeaves                int                   `json:"nleaves"`
	Eta                    int                   `json:"eta"`
	Theta                  int                   `json:"theta"`
	Rho                    int                   `json:"rho"`
	Ell                    int                   `json:"ell"`
	EllPrime               int                   `json:"ell_prime"`
	DQOverride             int                   `json:"dq_override,omitempty"`
	Kappa                  [4]int                `json:"kappa"`
	ROQueryCaps            [5]int                `json:"ro_query_caps,omitempty"`
	ROQueryCapsSet         bool                  `json:"-"`
	ROQueryCapBits         [5]float64            `json:"ro_query_cap_bits,omitempty"`
	ROQueryCapBitsSet      bool                  `json:"-"`
	DECSCollisionBits      int                   `json:"decs_collision_bits,omitempty"`
	DECSHashBits           int                   `json:"decs_hash_bits,omitempty"`
	DECSTapeBits           int                   `json:"decs_tape_bits,omitempty"`
	FSCollisionBits        int                   `json:"fs_collision_bits,omitempty"`
	SaltBits               int                   `json:"salt_bits,omitempty"`
	PRFProfile             string                `json:"prf_profile,omitempty"`
	PRFParamsPath          string                `json:"prf_params_path,omitempty"`
	PRFCompanionMode       PIOP.PRFCompanionMode `json:"prf_companion_mode,omitempty"`
	PRFGroupRounds         int                   `json:"prf_group_rounds,omitempty"`
	CheckpointSamples      int                   `json:"prf_checkpoint_samples,omitempty"`
	SigShortnessRadix      int                   `json:"sig_shortness_radix,omitempty"`
	SigShortnessDigits     int                   `json:"sig_shortness_digits,omitempty"`
	CompressedRows         int                   `json:"compressed_rows,omitempty"`
	ReplayProjection       string                `json:"replay_projection,omitempty"`
	TranscriptMode         string                `json:"transcript_mode,omitempty"`
	TranscriptOmissionMode string                `json:"transcript_omission_mode,omitempty"`
	FixedTranscriptSize    bool                  `json:"fixed_transcript_size,omitempty"`
	FixedTranscriptSizeSet bool                  `json:"-"`
}

type benchmarkIntGenISISE2ETimings struct {
	SetupPublicMS    float64 `json:"setup_public_ms,omitempty"`
	SetupNTRUKeysMS  float64 `json:"setup_ntru_keys_ms,omitempty"`
	HolderCommitMS   float64 `json:"holder_commit_ms,omitempty"`
	HolderProveMS    float64 `json:"holder_prove_ms,omitempty"`
	IssuerSignMS     float64 `json:"issuer_verify_sign_ms,omitempty"`
	HolderFinalizeMS float64 `json:"holder_finalize_ms,omitempty"`
}

type benchmarkIntGenISISE2EOptions struct {
	Issuance intGenISISTuning `json:"issuance"`
	Showing  intGenISISTuning `json:"showing"`
}

type benchmarkIntGenISISE2EEnvironment struct {
	GoVersion  string `json:"go_version"`
	GOOS       string `json:"goos"`
	GOARCH     string `json:"goarch"`
	NumCPU     int    `json:"num_cpu"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	VCS        string `json:"vcs,omitempty"`
	Commit     string `json:"commit,omitempty"`
	CommitTime string `json:"commit_time,omitempty"`
	Modified   *bool  `json:"modified,omitempty"`
}

type benchmarkIntGenISISE2EArtifacts struct {
	PublicParams     string `json:"public_params"`
	BMatrix          string `json:"b_matrix"`
	HolderSecret     string `json:"holder_secret"`
	CommitRequest    string `json:"commit_request"`
	Submission       string `json:"presign_submission"`
	Response         string `json:"issue_response"`
	State            string `json:"state"`
	VerifierKey      string `json:"verifier_key"`
	Presentation     string `json:"presentation"`
	HolderUsageState string `json:"holder_usage_state"`
	VerifierState    string `json:"verifier_state"`
	NTRUParams       string `json:"ntru_params"`
	NTRUPublic       string `json:"ntru_public"`
	NTRUPrivate      string `json:"ntru_private"`
	NTRUSignature    string `json:"ntru_signature"`
}

type benchmarkIntGenISISE2EReport struct {
	Version                    int                                         `json:"version"`
	Generated                  string                                      `json:"generated_at"`
	Preset                     string                                      `json:"preset,omitempty"`
	CanonicalPresetID          string                                      `json:"canonical_preset_id,omitempty"`
	PresetVersion              int                                         `json:"preset_version,omitempty"`
	PresetLifecycle            credential.PresetLifecycle                  `json:"preset_lifecycle,omitempty"`
	ClaimScope                 credential.ClaimScope                       `json:"claim_scope,omitempty"`
	PrimitiveProfileID         string                                      `json:"primitive_profile_id,omitempty"`
	PresetManifestDigest       string                                      `json:"preset_manifest_digest,omitempty"`
	ThreatModel                credential.PresetThreatModel                `json:"threat_model"`
	Profile                    string                                      `json:"profile"`
	SecurityProfile            string                                      `json:"security_profile,omitempty"`
	SecurityMode               string                                      `json:"security_mode,omitempty"`
	CompleteSystemClaim        bool                                        `json:"complete_system_claim,omitempty"`
	CoreBitsRequired           float64                                     `json:"core_required_bits,omitempty"`
	CoreAvailableBits          float64                                     `json:"core_available_bits,omitempty"`
	PRFProfile                 string                                      `json:"prf_profile,omitempty"`
	PRFParamsPath              string                                      `json:"prf_params_path,omitempty"`
	PRFParamsDigest            string                                      `json:"prf_params_digest,omitempty"`
	LedgerStatus               string                                      `json:"ledger_status,omitempty"`
	LedgerReasons              []string                                    `json:"ledger_rejection_reasons,omitempty"`
	LedgerTerms                []credential.SystemSecurityLedgerTerm       `json:"ledger_terms,omitempty"`
	SoundnessBits              float64                                     `json:"soundness_bits,omitempty"`
	UnlinkabilityBits          float64                                     `json:"unlinkability_bits,omitempty"`
	CorrectnessBits            float64                                     `json:"correctness_bits,omitempty"`
	PrimitiveBits              float64                                     `json:"primitive_bits,omitempty"`
	CompositionBits            float64                                     `json:"composition_bits,omitempty"`
	ZeroKnowledgeBits          float64                                     `json:"zero_knowledge_bits,omitempty"`
	RequiredPhaseAlgebraicBits float64                                     `json:"required_phase_algebraic_bits,omitempty"`
	PhaseAlgebraicSlackBits    float64                                     `json:"phase_algebraic_slack_bits,omitempty"`
	DominantSoundnessLimiter   string                                      `json:"dominant_soundness_limiter,omitempty"`
	TagCollisionBits           float64                                     `json:"tag_collision_bits,omitempty"`
	SaltCollisionBits          float64                                     `json:"salt_collision_bits,omitempty"`
	TapeGuessingBits           float64                                     `json:"tape_guessing_bits,omitempty"`
	ProgrammingBits            float64                                     `json:"programming_conflict_bits,omitempty"`
	ChallengeBiasBits          float64                                     `json:"challenge_bias_bits,omitempty"`
	Modulus                    uint64                                      `json:"q,omitempty"`
	ProfileBound               int64                                       `json:"profile_bound,omitempty"`
	ArtifactDir                string                                      `json:"artifact_dir"`
	MaxNLeaves                 int                                         `json:"max_nleaves,omitempty"`
	Options                    benchmarkIntGenISISE2EOptions               `json:"options"`
	Environment                benchmarkIntGenISISE2EEnvironment           `json:"environment"`
	Timings                    benchmarkIntGenISISE2ETimings               `json:"timings"`
	Issuance                   benchmarkIntGenISISMetrics                  `json:"issuance"`
	Showing                    benchmarkIntGenISISMetrics                  `json:"showing"`
	FullGame                   PIOP.FullGameSoundnessReport                `json:"full_game"`
	SecurityLedger             credential.SystemSecurityLedger             `json:"security_ledger"`
	ParameterAudit             credential.IntGenISISSecurityParameterAudit `json:"parameter_audit"`
	ValidPrefixCost            credential.ValidPrefixCostReport            `json:"valid_prefix_cost,omitempty"`
	Artifacts                  benchmarkIntGenISISE2EArtifacts             `json:"artifacts"`
	ReplayRejected             bool                                        `json:"replay_rejected"`
	Notes                      []string                                    `json:"notes"`
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
		PRFCompanionMode:  PIOP.PRFCompanionModeDirectFull,
		PRFGroupRounds:    2,
		CheckpointSamples: 8,
	}
}

func benchmarkIntGenISISE2EEnvironmentSnapshot() benchmarkIntGenISISE2EEnvironment {
	env := benchmarkIntGenISISE2EEnvironment{
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs":
				env.VCS = setting.Value
			case "vcs.revision":
				env.Commit = setting.Value
			case "vcs.time":
				env.CommitTime = setting.Value
			case "vcs.modified":
				modified := setting.Value == "true"
				env.Modified = &modified
			}
		}
	}
	return env
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
	if t.DQOverride <= 0 {
		t.DQOverride = fallback.DQOverride
	}
	if !t.ROQueryCapsSet && fallback.ROQueryCapsSet {
		t.ROQueryCaps = fallback.ROQueryCaps
		t.ROQueryCapsSet = true
	}
	if !t.ROQueryCapBitsSet && fallback.ROQueryCapBitsSet {
		t.ROQueryCapBits = fallback.ROQueryCapBits
		t.ROQueryCapBitsSet = true
	}
	if t.DECSCollisionBits <= 0 {
		t.DECSCollisionBits = fallback.DECSCollisionBits
	}
	if t.DECSHashBits <= 0 {
		t.DECSHashBits = fallback.DECSHashBits
	}
	if t.DECSTapeBits <= 0 {
		t.DECSTapeBits = fallback.DECSTapeBits
	}
	if t.FSCollisionBits <= 0 {
		t.FSCollisionBits = fallback.FSCollisionBits
	}
	if t.SaltBits <= 0 {
		t.SaltBits = fallback.SaltBits
	}
	if t.PRFParamsPath == "" {
		t.PRFParamsPath = fallback.PRFParamsPath
	}
	if t.PRFProfile == "" {
		t.PRFProfile = fallback.PRFProfile
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
		if t.TranscriptOmissionMode == "" {
			t.TranscriptOmissionMode = fallback.TranscriptOmissionMode
		}
		if !t.FixedTranscriptSizeSet && fallback.FixedTranscriptSize {
			t.FixedTranscriptSize = fallback.FixedTranscriptSize
			t.FixedTranscriptSizeSet = fallback.FixedTranscriptSizeSet
		}
	} else {
		t.PRFCompanionMode = ""
		t.PRFGroupRounds = 0
		t.CheckpointSamples = 0
		t.SigShortnessRadix = 0
		t.SigShortnessDigits = 0
		t.ReplayProjection = ""
		if t.TranscriptMode == "" {
			t.TranscriptMode = fallback.TranscriptMode
		}
		if t.TranscriptOmissionMode == "" {
			t.TranscriptOmissionMode = fallback.TranscriptOmissionMode
		}
		if !t.FixedTranscriptSizeSet && fallback.FixedTranscriptSize {
			t.FixedTranscriptSize = fallback.FixedTranscriptSize
			t.FixedTranscriptSizeSet = fallback.FixedTranscriptSizeSet
		}
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
		return fmt.Errorf("%s nleaves=%d exceeds max-nleaves=%d; increase ell, lower lvcs-ncols, or pass -max-nleaves 0 for an uncapped local run", label, t.NLeaves, maxNLeaves)
	}
	return nil
}

func intGenISISTuningToIssuanceOverrides(t intGenISISTuning, ringDegree int) issuanceRuntimeOverrides {
	return issuanceRuntimeOverrides{
		NCols:                  t.NCols,
		LVCSNCols:              t.LVCSNCols,
		NLeaves:                t.NLeaves,
		Ell:                    t.Ell,
		EllPrime:               t.EllPrime,
		Eta:                    t.Eta,
		Theta:                  t.Theta,
		Rho:                    t.Rho,
		DQOverride:             t.DQOverride,
		Kappa:                  t.Kappa,
		ROQueryCaps:            t.ROQueryCaps,
		ROQueryCapsSet:         t.ROQueryCapsSet,
		ROQueryCapBits:         t.ROQueryCapBits,
		ROQueryCapBitsSet:      t.ROQueryCapBitsSet,
		DECSCollisionBits:      t.DECSCollisionBits,
		DECSHashBits:           t.DECSHashBits,
		DECSTapeBits:           t.DECSTapeBits,
		FSCollisionBits:        t.FSCollisionBits,
		SaltBits:               t.SaltBits,
		TranscriptMode:         t.TranscriptMode,
		TranscriptOmissionMode: t.TranscriptOmissionMode,
		FixedTranscriptSize:    t.FixedTranscriptSize,
		RingDegree:             ringDegree,
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
		DQOverride:                 t.DQOverride,
		Kappa:                      t.Kappa,
		ROQueryCaps:                t.ROQueryCaps,
		ROQueryCapsSet:             t.ROQueryCapsSet,
		ROQueryCapBits:             t.ROQueryCapBits,
		ROQueryCapBitsSet:          t.ROQueryCapBitsSet,
		DECSCollisionBits:          t.DECSCollisionBits,
		DECSHashBits:               t.DECSHashBits,
		DECSTapeBits:               t.DECSTapeBits,
		FSCollisionBits:            t.FSCollisionBits,
		SaltBits:                   t.SaltBits,
		PRFParamsPath:              t.PRFParamsPath,
		DomainMode:                 PIOP.DomainModeExplicit,
		PRFGroupRounds:             t.PRFGroupRounds,
		PRFCompanionMode:           t.PRFCompanionMode,
		PRFCheckpointSamples:       t.CheckpointSamples,
		SigShortnessRadix:          t.SigShortnessRadix,
		SigShortnessL:              t.SigShortnessDigits,
		IntGenISISMSECompression:   t.CompressedRows,
		IntGenISISReplayProjection: t.ReplayProjection,
		TranscriptCodec:            intGenISISLiveTranscriptCodecOrDefault(t.TranscriptMode),
		TranscriptOmissionMode:     t.TranscriptOmissionMode,
		TranscriptProtocolMode:     intGenISISLiveTranscriptProtocolOrDefault(t.TranscriptMode),
		TranscriptVersion:          intGenISISLiveTranscriptVersionOrDefault(t.TranscriptMode),
		FixedTranscriptSize:        t.FixedTranscriptSize,
	})
}

func intGenISISLiveTranscriptConfig(mode string) (codec, protocol string, err error) {
	protocol, _, err = credential.ResolveIntGenISISTranscript(mode)
	return "", protocol, err
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
	_, version, err := credential.ResolveIntGenISISTranscript(mode)
	if err != nil {
		return ""
	}
	return version
}

func benchmarkIntGenISISE2E(cfg benchmarkIntGenISISE2EConfig) (benchmarkIntGenISISE2EReport, error) {
	if preset, ok := credential.LookupIntGenISISPreset(cfg.PresetName); ok {
		if cfg.PRFProfile != "" && cfg.PRFProfile != preset.PRFProfile {
			return benchmarkIntGenISISE2EReport{}, fmt.Errorf("PRF profile %q does not match bound preset profile %q", cfg.PRFProfile, preset.PRFProfile)
		}
		if cfg.PRFProfile == "" {
			cfg.PRFProfile = preset.PRFProfile
		}
		if cfg.PRFParamsPath == "" {
			cfg.PRFParamsPath = preset.PRFParamsPath
		}
		if cfg.CanonicalPresetID == "" {
			cfg.CanonicalPresetID = preset.CanonicalID
			cfg.PresetVersion = preset.PresetVersion
			cfg.PresetLifecycle = preset.Lifecycle
			cfg.ClaimScope = preset.ClaimScope
			cfg.PrimitiveProfileID = preset.PrimitiveProfileID
			cfg.PresetManifestDigest = credential.IntGenISISPresetManifestDigest(preset)
			cfg.ThreatModel = preset.ThreatModel
		}
		if cfg.PRFParamsDigest == "" {
			cfg.PRFParamsDigest = preset.PRFParamsDigest
		} else if cfg.PRFParamsDigest != preset.PRFParamsDigest {
			return benchmarkIntGenISISE2EReport{}, fmt.Errorf("PRF parameter digest does not match bound preset profile %q", preset.PRFProfile)
		}
	}
	if cfg.Profile == "" {
		cfg.Profile = credential.ProfileIntGenISISB
	}
	profile, ok := credential.LookupIntGenISISProfile(cfg.Profile)
	if !ok {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("unsupported IntGenISIS profile %q", cfg.Profile)
	}
	if cfg.PRFParamsPath == "" {
		cfg.PRFParamsPath = defaultPRFParamsPath
	}
	_, actualPRFParamsDigest, err := prf.LoadLocalOrBundledParamsWithDigest(cfg.PRFParamsPath)
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("load PRF params for manifest validation: %w", err)
	}
	if cfg.PRFParamsDigest != "" && actualPRFParamsDigest != cfg.PRFParamsDigest {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("PRF parameter digest mismatch for profile %s", cfg.PRFProfile)
	}
	defaults := defaultIntGenISISTuning()
	cfg.Issuance = normalizeIntGenISISTuning(cfg.Issuance, defaults, false)
	cfg.Showing = normalizeIntGenISISTuning(cfg.Showing, defaults, true)
	if cfg.Issuance.PRFParamsPath == "" {
		cfg.Issuance.PRFParamsPath = cfg.PRFParamsPath
	}
	if cfg.Showing.PRFParamsPath == "" {
		cfg.Showing.PRFParamsPath = cfg.PRFParamsPath
	}
	cfg.MaxNLeaves = normalizeIntGenISISMaxNLeaves(cfg.MaxNLeaves)
	if err := validateIntGenISISLeafCap("issuance", cfg.Issuance, cfg.MaxNLeaves); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	if err := validateIntGenISISLeafCap("showing", cfg.Showing, cfg.MaxNLeaves); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	if _, _, err := intGenISISLiveTranscriptConfig(cfg.Issuance.TranscriptMode); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	if _, _, err := intGenISISLiveTranscriptConfig(cfg.Showing.TranscriptMode); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	if _, err := credential.ResolveIntGenISISTranscriptOmission(cfg.Issuance.TranscriptOmissionMode); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("issuance transcript omission mode: %w", err)
	}
	if _, err := credential.ResolveIntGenISISTranscriptOmission(cfg.Showing.TranscriptOmissionMode); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("showing transcript omission mode: %w", err)
	}
	switch cfg.Showing.PRFCompanionMode {
	case PIOP.PRFCompanionModeDirectFull:
	default:
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("unsupported prf companion mode %q", cfg.Showing.PRFCompanionMode)
	}
	if cfg.KeygenTrials <= 0 {
		cfg.KeygenTrials = 10000
	}
	if cfg.KeygenAttempts <= 0 {
		cfg.KeygenAttempts = defaultNTRUKeygenAttempts
	}
	if cfg.MaxTrials <= 0 {
		cfg.MaxTrials = 2048
	}
	artifactDir := cfg.ArtifactDir
	if artifactDir == "" {
		preset, ok := credential.LookupIntGenISISPreset(cfg.PresetName)
		if !ok {
			return benchmarkIntGenISISE2EReport{}, fmt.Errorf("benchmark output requires a canonical v2 preset")
		}
		artifactDir = intGenISISV2ArtifactDir(preset)
	}
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("mkdir artifact dir: %w", err)
	}

	paths := benchmarkIntGenISISE2EArtifacts{
		PublicParams:     filepath.Join(artifactDir, fmt.Sprintf("credential_public.%s.json", profile.Name)),
		BMatrix:          filepath.Join(artifactDir, fmt.Sprintf("Bmatrix.%s.json", profile.Name)),
		HolderSecret:     filepath.Join(artifactDir, "holder_secret.json"),
		CommitRequest:    filepath.Join(artifactDir, "commit_request.json"),
		Submission:       filepath.Join(artifactDir, "presign_submission.json"),
		Response:         filepath.Join(artifactDir, "issue_response.json"),
		State:            filepath.Join(artifactDir, "credential_state.intgenisis.json"),
		VerifierKey:      filepath.Join(artifactDir, "intgenisis_verifier_key.json"),
		Presentation:     filepath.Join(artifactDir, "presentation.intgenisis.json"),
		HolderUsageState: filepath.Join(artifactDir, "holder_usage_state.json"),
		VerifierState:    filepath.Join(artifactDir, "verifier_state.json"),
		NTRUParams:       filepath.Join(artifactDir, "ntru_params.json"),
		NTRUPublic:       filepath.Join(artifactDir, "ntru_public.json"),
		NTRUPrivate:      filepath.Join(artifactDir, "ntru_private.json"),
		NTRUSignature:    filepath.Join(artifactDir, "ntru_signature.json"),
	}
	if err := benchmarkIntGenISISE2EOverwriteCheck(paths, cfg.JSONOut, cfg.Force); err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	if cfg.Force {
		_ = os.Remove(paths.VerifierState)
		_ = os.Remove(paths.HolderUsageState)
	}

	var timings benchmarkIntGenISISE2ETimings
	t0 := time.Now()
	var selectedPreset *credential.IntGenISISPreset
	if preset, ok := credential.LookupIntGenISISPreset(cfg.PresetName); ok {
		selectedPreset = &preset
	}
	if err := setupIntGenISISPublicForPreset(paths.PublicParams, cfg.Force, profile, paths.BMatrix, selectedPreset); err != nil {
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
	if err := holderCommit(paths.PublicParams, cfg.PRFParamsPath, paths.HolderSecret, paths.CommitRequest, "", overrides); err != nil {
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
	if err := holderFinalize(paths.HolderSecret, paths.CommitRequest, "", paths.Response, paths.State, "", paths.NTRUParams, paths.VerifierKey); err != nil {
		return benchmarkIntGenISISE2EReport{}, fmt.Errorf("holder finalize: %w", err)
	}
	timings.HolderFinalizeMS = millisSince(t0)

	showingMetrics, replayRejected, err := benchmarkIntGenISISE2EShowing(paths, cfg)
	if err != nil {
		return benchmarkIntGenISISE2EReport{}, err
	}
	acceptedIssuance := cfg.ThreatModel.AcceptedIssuance
	acceptedShowing := cfg.ThreatModel.AcceptedShowing
	if acceptedIssuance+acceptedShowing == 0 {
		acceptedIssuance, acceptedShowing = 1, 1
	}
	fullGame := PIOP.ComposeFullGameSoundness(issuanceMetrics.Soundness, showingMetrics.Soundness, acceptedIssuance, acceptedShowing)
	ledger := benchmarkIntGenISISE2ESecurityLedger(cfg, profile, issuanceMetrics, showingMetrics, fullGame, replayRejected)
	issuanceMetrics.ValidPrefixCost = benchmarkValidPrefixCostReportFromBudget(ledger.ROBudgetLogs, issuanceMetrics.PhaseTimings, [4]float64{}, false)
	showingMetrics.ValidPrefixCost = benchmarkValidPrefixCostReportFromBudget(ledger.ROBudgetLogs, showingMetrics.PhaseTimings, [4]float64{}, false)
	requiredPhaseAlgebraicBits := benchmarkRequiredPhaseAlgebraicBits(ledger.TargetBits, fullGame)
	phaseAlgebraicSlackBits := minPositiveFloat64Local(issuanceMetrics.AlgebraicTotalBits, showingMetrics.AlgebraicTotalBits) - requiredPhaseAlgebraicBits

	report := benchmarkIntGenISISE2EReport{
		Version:                    benchmarkIntGenISISE2EVersion,
		Generated:                  time.Now().UTC().Format(time.RFC3339),
		Preset:                     cfg.PresetName,
		CanonicalPresetID:          cfg.CanonicalPresetID,
		PresetVersion:              cfg.PresetVersion,
		PresetLifecycle:            cfg.PresetLifecycle,
		ClaimScope:                 cfg.ClaimScope,
		PrimitiveProfileID:         cfg.PrimitiveProfileID,
		PresetManifestDigest:       cfg.PresetManifestDigest,
		ThreatModel:                cfg.ThreatModel,
		Profile:                    profile.Name,
		SecurityProfile:            cfg.SecurityProfile,
		SecurityMode:               cfg.SecurityMode,
		CompleteSystemClaim:        ledger.CompleteSystemClaim,
		CoreBitsRequired:           ledger.CoreBitsRequired,
		CoreAvailableBits:          ledger.CoreAvailableBits,
		PRFProfile:                 cfg.PRFProfile,
		PRFParamsPath:              cfg.PRFParamsPath,
		PRFParamsDigest:            actualPRFParamsDigest,
		LedgerStatus:               ledger.LedgerStatus,
		LedgerReasons:              ledger.RejectionReasons,
		LedgerTerms:                ledger.Terms,
		SoundnessBits:              ledger.SoundnessBits,
		UnlinkabilityBits:          ledger.UnlinkabilityBits,
		CorrectnessBits:            ledger.CorrectnessBits,
		PrimitiveBits:              ledger.PrimitiveBits,
		CompositionBits:            ledger.CompositionBits,
		ZeroKnowledgeBits:          ledger.ZeroKnowledgeBits,
		RequiredPhaseAlgebraicBits: requiredPhaseAlgebraicBits,
		PhaseAlgebraicSlackBits:    phaseAlgebraicSlackBits,
		DominantSoundnessLimiter:   benchmarkDominantLedgerLimiter(ledger.Terms, credential.SystemLedgerTermSoundness),
		TagCollisionBits:           ledger.TagCollisionBits,
		SaltCollisionBits:          ledger.SaltCollisionBits,
		TapeGuessingBits:           ledger.TapeGuessingBits,
		ProgrammingBits:            ledger.ProgrammingConflictBits,
		ChallengeBiasBits:          ledger.ChallengeBiasBits,
		Modulus:                    profile.Q,
		ProfileBound:               credential.IntGenISISLiveBound,
		ArtifactDir:                artifactDir,
		MaxNLeaves:                 cfg.MaxNLeaves,
		Options:                    benchmarkIntGenISISE2EReportOptions(cfg),
		Environment:                benchmarkIntGenISISE2EEnvironmentSnapshot(),
		Timings:                    timings,
		Issuance:                   issuanceMetrics,
		Showing:                    showingMetrics,
		FullGame:                   fullGame,
		SecurityLedger:             ledger,
		ParameterAudit:             ledger.ParameterAudit,
		ValidPrefixCost:            showingMetrics.ValidPrefixCost,
		Artifacts:                  paths,
		ReplayRejected:             replayRejected,
		Notes: []string{
			fmt.Sprintf("semantic layout uses ternary ordinary coefficients [0,N-%d), a reserved-zero tail prefix, and a %d-coefficient B=%d PRF seed packed into %d Poseidon key lanes", credential.IntGenISISPRFSeedTailReserve, credential.IntGenISISPRFSeedLen, credential.IntGenISISPRFSeedBound, credential.IntGenISISPRFPoseidonKeyLen),
			fmt.Sprintf("live IntGenISIS ordinary M,s,e membership uses public B=%d; only PRF seed-tail rows use B=%d membership", credential.IntGenISISLiveBound, credential.IntGenISISPRFSeedBound),
			"max_nleaves caps the explicit DECS/LVCS evaluation domain; pass -max-nleaves 0 only for uncapped local runs",
			"showing shortness proves the configured signed-radix representable bound; the public signature beta is builder-validated and Fiat-Shamir-bound",
		},
	}
	if cfg.JSONOut != "" {
		if err := writeJSONFile(cfg.JSONOut, report, 0o644); err != nil {
			return benchmarkIntGenISISE2EReport{}, fmt.Errorf("write e2e benchmark json: %w", err)
		}
		log.Printf("[issuance-cli] benchmark-intgenisis-e2e wrote %s", cfg.JSONOut)
	}
	return report, nil
}

func benchmarkIntGenISISE2EReportOptions(cfg benchmarkIntGenISISE2EConfig) benchmarkIntGenISISE2EOptions {
	return benchmarkIntGenISISE2EOptions{
		Issuance: cfg.Issuance,
		Showing:  cfg.Showing,
	}
}

func benchmarkIntGenISISE2EOverwriteCheck(paths benchmarkIntGenISISE2EArtifacts, jsonOut string, force bool) error {
	if force {
		return nil
	}
	checks := []string{
		paths.PublicParams, paths.BMatrix, paths.HolderSecret, paths.CommitRequest, paths.Submission,
		paths.Response, paths.State, paths.VerifierKey, paths.Presentation, paths.HolderUsageState, paths.VerifierState,
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

func benchmarkIntGenISISE2ESecurityLedger(
	cfg benchmarkIntGenISISE2EConfig,
	profile credential.IntGenISISProfile,
	issuanceMetrics benchmarkIntGenISISMetrics,
	showingMetrics benchmarkIntGenISISMetrics,
	fullGame PIOP.FullGameSoundnessReport,
	replayRejected bool,
) credential.SystemSecurityLedger {
	spec, _ := credential.LookupIntGenISISSecurityProfile(cfg.SecurityProfile)
	params, paramsErr := prf.LoadLocalOrBundledParams(cfg.PRFParamsPath)
	prfBits := 0.0
	tagElements := 0
	actualPRFProfile := ""
	if paramsErr == nil && params != nil {
		prfBits = params.SecPermBits
		tagElements = params.LenTag
		if expectedTag, ok := credential.IntGenISISPRFProfileTagElements(cfg.PRFProfile); ok && expectedTag == params.LenTag {
			actualPRFProfile = cfg.PRFProfile
		} else {
			actualPRFProfile = fmt.Sprintf("unrecognized-tag-%d", params.LenTag)
		}
	}
	scope, scopeLogs := credential.AdversaryScopesFromThreatModel(cfg.ThreatModel)
	queryCapBits, queryCapsKnown, queryMismatches := benchmarkActualROQueryCaps(spec.Mode, issuanceMetrics, showingMetrics)
	budgetLogs := credential.ROBudgetLogVectorFromCapBits(queryCapBits[:])
	var capValues []uint64
	if queryCapsKnown {
		capValues = make([]uint64, len(showingMetrics.ROQueryCaps))
		for i, cap := range showingMetrics.ROQueryCaps {
			if cap > 0 {
				capValues[i] = uint64(cap)
			}
		}
	}
	budgets := credential.ROBudgetVectorFromCaps(capValues)
	saltBits := minPositiveIntLocal(issuanceMetrics.SaltBits, showingMetrics.SaltBits)
	phaseCollisionBits := minPositiveFloat64Local(issuanceMetrics.CollisionBits, showingMetrics.CollisionBits)
	globalCollisionBits := fullGame.GlobalCollisionBits
	if globalCollisionBits <= 0 {
		globalCollisionBits = phaseCollisionBits
	}
	proofBits := minPositiveFloat64Local(issuanceMetrics.TheoremTotalBits, showingMetrics.TheoremTotalBits)
	fullGameBits := fullGame.GlobalCollisionFullGameBits
	if fullGameBits <= 0 {
		fullGameBits = minPositiveFloat64Local(proofBits, globalCollisionBits)
	}
	tapeBits := minPositiveIntLocal(issuanceMetrics.DECSTapeBits, showingMetrics.DECSTapeBits)
	tapeGuessingBits := credential.IntGenISISTapeGuessingBitsLog(tapeBits, budgetLogs.GuessTapeLog2)
	if tapeGuessingBits <= 0 {
		tapeGuessingBits = credential.IntGenISISTapeGuessingBits(tapeBits, budgets.GuessTape)
	}
	fsCollisionBits := minPositiveIntLocal(issuanceMetrics.EffectiveLambdaBits, showingMetrics.EffectiveLambdaBits)
	programmingBits := credential.IntGenISISProgrammingConflictBitsLog(fsCollisionBits, budgetLogs.ProgrammingLog2)
	if programmingBits <= 0 {
		programmingBits = credential.IntGenISISProgrammingConflictBits(fsCollisionBits, budgets.Programming)
	}
	if programmingBits <= 0 {
		programmingBits = minPositiveFloat64Local(globalCollisionBits, fullGameBits)
	}
	challengeBiasBits := float64(fsCollisionBits)
	tagCollisionBits := credential.IntGenISISTagCollisionBitsLog(profile.Q, tagElements, scopeLogs.TagsPerContextLog2)
	saltCollisionBits := credential.IntGenISISSaltCollisionBitsLog(saltBits, scopeLogs.ProofsLog2)
	seedEntropyBits := credential.IntGenISISPRFSeedEntropyBits()
	coreAvailableBits := minPositiveFloat64Local(prfBits, profile.MLWEHidingBits, profile.MSISBindingBits, seedEntropyBits)
	scopeBaseBits := minPositiveFloat64Local(fullGameBits, tagCollisionBits, saltCollisionBits, coreAvailableBits)
	multiUserBits := credential.IntGenISISMultiScopeBitsLog(scopeBaseBits, scopeLogs.UsersLog2)
	multiContextBits := credential.IntGenISISMultiScopeBitsLog(scopeBaseBits, scopeLogs.ContextsLog2)
	multiUserRequired := scopeLogs.UsersLog2 > 0
	multiContextRequired := scopeLogs.ContextsLog2 > 0
	actualTranscriptMode := benchmarkActualTranscriptMode(issuanceMetrics.TranscriptMode, showingMetrics.TranscriptMode)
	var actualQueryCapBits []float64
	if queryCapsKnown {
		actualQueryCapBits = append(actualQueryCapBits, queryCapBits[:]...)
	}
	actual := credential.IntGenISISSecurityParameterActuals{
		ROQueryCapLog2Set: queryCapsKnown,
		ROQueryCapLog2:    actualQueryCapBits,
		DECSHashBits:      minPositiveIntLocal(issuanceMetrics.DECSHashBits, showingMetrics.DECSHashBits),
		DECSTapeBits:      tapeBits,
		FSCollisionBits:   fsCollisionBits,
		SaltBits:          saltBits,
		PRFTagElements:    tagElements,
		PRFProfile:        actualPRFProfile,
		TranscriptMode:    actualTranscriptMode,
		Evidence: map[string]string{
			"ro_query_cap_log2": credential.SecurityEvidenceMeasured,
			"decs_hash_bits":    credential.SecurityEvidenceMeasured,
			"decs_tape_bits":    credential.SecurityEvidenceMeasured,
			"fs_collision_bits": credential.SecurityEvidenceMeasured,
			"salt_bits":         credential.SecurityEvidenceMeasured,
			"prf_tag_elements":  credential.SecurityEvidenceLoadedParams,
			"prf_profile":       credential.SecurityEvidenceLoadedParams,
			"transcript_mode":   credential.SecurityEvidenceMeasured,
		},
	}
	if !queryCapsKnown {
		delete(actual.Evidence, "ro_query_cap_log2")
	}
	parameterAudit := credential.AuditIntGenISISSecurityParameters(spec, actual)
	parameterAudit.Mismatches = append(parameterAudit.Mismatches, queryMismatches...)
	expectedTag, knownPRFProfile := credential.IntGenISISPRFProfileTagElements(cfg.PRFProfile)
	if !knownPRFProfile || tagElements != expectedTag {
		parameterAudit.Mismatches = append(parameterAudit.Mismatches, credential.IntGenISISSecurityParameterMismatch{
			Parameter:   "prf_profile",
			Required:    fmt.Sprintf("%s (tag-%d)", cfg.PRFProfile, expectedTag),
			Actual:      fmt.Sprintf("%s (tag-%d)", actualPRFProfile, tagElements),
			Explanation: "the loaded PRF parameter file does not implement the selected preset profile",
		})
	}
	requiredTranscriptMode := benchmarkActualTranscriptMode(cfg.Issuance.TranscriptMode, cfg.Showing.TranscriptMode)
	if requiredTranscriptMode == "" || actualTranscriptMode != requiredTranscriptMode {
		parameterAudit.Mismatches = append(parameterAudit.Mismatches, credential.IntGenISISSecurityParameterMismatch{
			Parameter:   "transcript_mode",
			Required:    requiredTranscriptMode,
			Actual:      actualTranscriptMode,
			Explanation: "the proof transcript mode does not match the selected issuance/showing manifest",
		})
	}
	if len(parameterAudit.MissingActual) > 0 || len(parameterAudit.MissingEvidence) > 0 || len(parameterAudit.Mismatches) > 0 {
		parameterAudit.Status = "rejected"
	}
	fullGameNote := "exact current-theorem composition of accepted issuance/showing extraction terms and global RO collision; remains a real blocker without a simultaneous-extraction theorem"
	programmingNote := "separate programming-conflict accounting from the report resource vector; remains conservative until the theorem path is finalized"
	scopeInactiveNote := "default one-scope accounting has no additional lift; non-default scopes require an explicit theorem/accounting bound"
	multiUserNote := scopeInactiveNote
	if multiUserRequired {
		multiUserNote = "multi-user lift is active for this resource scope and remains conservative until theorem/accounting is finalized"
	}
	multiContextNote := scopeInactiveNote
	if multiContextRequired {
		multiContextNote = "multi-context lift is active for this resource scope and remains conservative until theorem/accounting is finalized"
	}
	return credential.EvaluateIntGenISISSystemSecurityLedger(credential.SystemSecurityLedgerInput{
		SecurityProfile:     cfg.SecurityProfile,
		SecurityMode:        cfg.SecurityMode,
		ROMModel:            cfg.ThreatModel.ROM,
		CompleteSystemClaim: cfg.CompleteSystemClaim,
		TargetBits:          spec.TargetBits,
		CoreBitsRequired:    cfg.CoreBitsRequired,
		CoreAvailableBits:   coreAvailableBits,
		ProofBits:           proofBits,
		FullGameBits:        fullGameBits,
		CollisionBits:       globalCollisionBits,
		TagCollisionBits:    tagCollisionBits,
		SaltCollisionBits:   saltCollisionBits,
		TapeGuessingBits:    tapeGuessingBits,
		ProgrammingBits:     programmingBits,
		ChallengeBiasBits:   challengeBiasBits,
		MultiUserBits:       multiUserBits,
		MultiContextBits:    multiContextBits,
		PRFBits:             prfBits,
		MLWEBits:            profile.MLWEHidingBits,
		MSISBindingBits:     profile.MSISBindingBits,
		SignatureBits:       0,
		SeedEntropyBits:     seedEntropyBits,
		ReplayRejected:      replayRejected,
		ROBudgets:           budgets,
		ROBudgetLogs:        budgetLogs,
		Scope:               scope,
		ScopeLog2:           scopeLogs,
		ParameterAudit:      parameterAudit,
		Terms: []credential.SystemSecurityLedgerTerm{
			credential.LedgerTermWithEvidence(credential.ReportOnlyLedgerTerm(credential.ExactLedgerTerm(credential.SystemLedgerTermSoundness, "proof_theorem", proofBits, true, "proof theorem bits below target")), "benchmark.full_game.proof_theorem", "issuance+showing"),
			credential.LedgerTermWithEvidence(credential.ExactLedgerTerm(credential.SystemLedgerTermSoundness, "issuance_smallwood_extraction", issuanceMetrics.AlgebraicTotalBits, true, "issuance SmallWood extraction bits below target"), "benchmark.issuance.algebraic_total_bits", "issuance"),
			credential.LedgerTermWithEvidence(credential.ExactLedgerTerm(credential.SystemLedgerTermSoundness, "showing_smallwood_extraction", showingMetrics.AlgebraicTotalBits, true, "showing SmallWood extraction bits below target"), "benchmark.showing.algebraic_total_bits", "showing"),
			credential.LedgerTermWithEvidence(credential.ExactLedgerTerm(credential.SystemLedgerTermSoundness, "ro_collision", globalCollisionBits, true, "global RO/Merkle collision bits below target"), "benchmark.full_game.global_collision_bits", "issuance+showing"),
			credential.LedgerTermWithEvidence(credential.LedgerTermWithNote(credential.ReportOnlyLedgerTerm(credential.ExactLedgerTerm(credential.SystemLedgerTermSoundness, "full_game", fullGameBits, true, "full-game bits below target")), fullGameNote), "benchmark.full_game.global_collision_full_game_bits", "issuance+showing"),
			credential.LedgerTermWithEvidence(credential.ConservativeLedgerTerm(credential.SystemLedgerTermSoundness, "challenge_bias", challengeBiasBits, true, "challenge-bias bits below target"), "executed.fs_collision_bits", "all Fiat-Shamir challenges"),
			credential.LedgerTermWithEvidence(credential.ExactLedgerTerm(credential.SystemLedgerTermZeroKnowledge, "tape_guessing", tapeGuessingBits, true, "tape guessing bits below target"), "executed.decs_tape_bits", "raw oracle budget"),
			credential.LedgerTermWithEvidence(credential.LedgerTermWithNote(credential.ConservativeLedgerTerm(credential.SystemLedgerTermZeroKnowledge, "programming_conflict", programmingBits, true, "programming conflict bits below target"), programmingNote), "executed.fs_collision_bits", "raw programming budget"),
			credential.LedgerTermWithEvidence(credential.ExactLedgerTerm(credential.SystemLedgerTermUnlinkability, "tag_collision", tagCollisionBits, true, "tag collision bits below target"), "loaded_prf_params.len_tag", "per domain-separated context"),
			credential.LedgerTermWithEvidence(credential.ExactLedgerTerm(credential.SystemLedgerTermCorrectness, "salt_collision", saltCollisionBits, true, "salt collision bits below target"), "measured.proof.salt", "declared proof volume"),
			credential.LedgerTermWithEvidence(credential.LedgerTermWithNote(credential.ReportOnlyLedgerTerm(credential.ExactLedgerTerm(credential.SystemLedgerTermComposition, "multi_proof_composition", fullGameBits, true, "multi-proof composition bits below target")), fullGameNote), "benchmark.full_game", "declared accepted-proof composition"),
			credential.LedgerTermWithEvidence(credential.LedgerTermWithNote(credential.ConservativeLedgerTerm(credential.SystemLedgerTermComposition, "multi_user", multiUserBits, multiUserRequired, "multi-user lift bits below target"), multiUserNote), "preset.threat_model.max_users_log2", "declared users"),
			credential.LedgerTermWithEvidence(credential.LedgerTermWithNote(credential.ConservativeLedgerTerm(credential.SystemLedgerTermComposition, "multi_context", multiContextBits, multiContextRequired, "multi-context lift bits below target"), multiContextNote), "preset.threat_model.max_contexts_log2", "declared contexts"),
			credential.LedgerTermWithEvidence(credential.EstimatorLedgerTerm(credential.SystemLedgerTermPrimitive, "prf_security", prfBits, true, "PRF bits below primitive requirement"), "loaded_prf_params.sec_perm_bits", cfg.PRFProfile),
			credential.LedgerTermWithEvidence(credential.EstimatorLedgerTerm(credential.SystemLedgerTermPrimitive, "mlwe_hiding", profile.MLWEHidingBits, true, "MLWE bits below primitive requirement"), credential.IntGenISISCommitmentEstimatorName+"@"+credential.IntGenISISCommitmentEstimatorCommit, profile.Name),
			credential.LedgerTermWithEvidence(credential.EstimatorLedgerTerm(credential.SystemLedgerTermPrimitive, "msis_binding", profile.MSISBindingBits, true, "MSIS binding bits below primitive requirement"), "primitive_profile.commitment_security.msis_binding_bits", profile.Name),
			credential.LedgerTermWithEvidence(credential.EstimatorLedgerTerm(credential.SystemLedgerTermPrimitive, "lattice_signature", 0, true, "lattice signature bits below primitive requirement"), "missing:lattice-signature estimator", profile.Name),
			credential.LedgerTermWithEvidence(credential.ExactLedgerTerm(credential.SystemLedgerTermPrimitive, "seed_entropy", seedEntropyBits, true, "seed entropy bits below primitive requirement"), "credential.semantic_seed.crypto_rejection_sampler", "48 independent uniform base-9 symbols"),
			credential.LedgerTermWithEvidence(credential.EstimatorLedgerTerm(credential.SystemLedgerTermPrimitive, "core_available", coreAvailableBits, false, "primitive core below target"), "derived minimum of available primitive estimates", profile.Name),
		},
	})
}

func benchmarkActualROQueryCaps(mode credential.SecurityMode, issuance, showing benchmarkIntGenISISMetrics) ([5]float64, bool, []credential.IntGenISISSecurityParameterMismatch) {
	issuanceBits, issuanceKnown := benchmarkMetricsROQueryCapLog2(issuance)
	showingBits, showingKnown := benchmarkMetricsROQueryCapLog2(showing)
	if mode == credential.SecurityModeSingleCandidate {
		if !issuanceKnown {
			issuanceBits, issuanceKnown = benchmarkMetricsImplicitSingleCandidate(issuance)
		}
		if !showingKnown {
			showingBits, showingKnown = benchmarkMetricsImplicitSingleCandidate(showing)
		}
	}
	var actual [5]float64
	for i := range actual {
		actual[i] = math.Max(issuanceBits[i], showingBits[i])
	}
	mismatches := make([]credential.IntGenISISSecurityParameterMismatch, 0)
	if issuanceKnown && showingKnown {
		for i := range actual {
			if math.Abs(issuanceBits[i]-showingBits[i]) <= 1e-9 {
				continue
			}
			mismatches = append(mismatches, credential.IntGenISISSecurityParameterMismatch{
				Parameter:   fmt.Sprintf("ro_query_cap_log2[%d]", i),
				Required:    fmt.Sprintf("issuance %.0f", issuanceBits[i]),
				Actual:      fmt.Sprintf("showing %.0f", showingBits[i]),
				Explanation: "issuance and showing executed different bounded-query scopes",
			})
		}
	}
	return actual, issuanceKnown && showingKnown, mismatches
}

func benchmarkMetricsImplicitSingleCandidate(metrics benchmarkIntGenISISMetrics) ([5]float64, bool) {
	if metrics.ROQueryCapsSet || metrics.ROQueryCapBitsSet || metrics.ROQueryCapBits != [5]float64{} {
		return [5]float64{}, false
	}
	if metrics.ROQueryCaps != [5]int{1, 1, 1, 1, 1} {
		return [5]float64{}, false
	}
	return [5]float64{}, true
}

func benchmarkMetricsROQueryCapLog2(metrics benchmarkIntGenISISMetrics) ([5]float64, bool) {
	bits := metrics.ROQueryCapBits
	if metrics.ROQueryCapBitsSet {
		for _, bit := range bits {
			if bit < 0 || math.IsNaN(bit) || math.IsInf(bit, 0) {
				return [5]float64{}, false
			}
		}
		return bits, true
	}
	if !metrics.ROQueryCapsSet {
		return [5]float64{}, false
	}
	for i, cap := range metrics.ROQueryCaps {
		if cap <= 0 {
			return [5]float64{}, false
		}
		bits[i] = math.Log2(float64(cap))
	}
	return bits, true
}

func benchmarkActualTranscriptMode(issuance, showing string) string {
	if issuance == "" || showing == "" || issuance != showing {
		return ""
	}
	return showing
}

func benchmarkRequiredPhaseAlgebraicBits(targetBits float64, fullGame PIOP.FullGameSoundnessReport) float64 {
	if targetBits <= 0 {
		return 0
	}
	accepted := fullGame.AcceptedIssuance + fullGame.AcceptedShowing
	if accepted <= 0 {
		return 0
	}
	targetProb := math.Pow(2, -targetBits)
	collisionProb := fullGame.GlobalCollisionError
	if collisionProb <= 0 && fullGame.GlobalCollisionBits > 0 {
		collisionProb = math.Pow(2, -fullGame.GlobalCollisionBits)
	}
	remaining := targetProb - collisionProb
	if remaining <= 0 {
		return 0
	}
	return -math.Log2(remaining / float64(accepted))
}

func benchmarkDominantLedgerLimiter(terms []credential.SystemSecurityLedgerTerm, category string) string {
	var out string
	best := math.Inf(1)
	for _, term := range terms {
		if term.Category != category || !term.Required || term.ActualBits <= 0 || math.IsNaN(term.ActualBits) {
			continue
		}
		if term.ActualBits < best {
			best = term.ActualBits
			out = term.Name
		}
	}
	return out
}

func minPositiveFloat64Local(vals ...float64) float64 {
	out := 0.0
	for _, v := range vals {
		if v <= 0 || math.IsInf(v, -1) || math.IsNaN(v) {
			continue
		}
		if out == 0 || v < out {
			out = v
		}
	}
	return out
}

func minPositiveIntLocal(vals ...int) int {
	out := 0
	for _, v := range vals {
		if v <= 0 {
			continue
		}
		if out == 0 || v < out {
			out = v
		}
	}
	return out
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
	rt.opts.PhaseRecorder = PIOP.NewPhaseRecorder()
	cm, as, err := intGenISISCommitmentMatricesNTT(rt.ringQ, rt.public)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	pub := PIOP.PublicInputs{
		Com:            polyVecFromInt64(rt.ringQ, req.Com, true),
		CM:             cm,
		AS:             as,
		BoundB:         rt.public.CommitmentBound,
		HashInputBound: rt.public.HashInputBound,
		X0Len:          rt.public.EllX0,
		RingDegree:     int(rt.ringQ.N),
		HashRelation:   rt.public.HashRelation,
		IntGenISIS:     true,
		Extras:         rt.public.PresetTranscriptExtras(nil),
	}
	verifyStart := time.Now()
	ok, err := PIOP.VerifyIntGenISISPreSign(pub, sub.Proof, rt.opts)
	verifyDur := time.Since(verifyStart)
	rt.opts.PhaseRecorder.RecordDuration("issuance.verify_total", verifyDur)
	if err != nil || !ok {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("verify e2e pre-sign proof for metrics: ok=%v err=%v", ok, err)
	}
	reportStart := time.Now()
	rep, err := PIOP.BuildProofReport(sub.Proof, rt.opts, rt.ringQ)
	rt.opts.PhaseRecorder.RecordDuration("issuance.report", time.Since(reportStart))
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
	if preset, ok := credential.LookupIntGenISISPreset(cfg.PresetName); ok {
		if err := st.ValidateIntGenISISPreset(publicParams, preset); err != nil {
			return benchmarkIntGenISISMetrics{}, false, err
		}
	}
	if verifierKey.PresetID != publicParams.PresetID || verifierKey.PresetVersion != publicParams.PresetVersion || verifierKey.PresetManifestDigest != publicParams.PresetManifestDigest {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("verifier key preset binding mismatch")
	}
	ringQ, err := credential.LoadRingWithDegree(st.RingDegree)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("load ring: %w", err)
	}
	params, actualPRFParamsDigest, err := prf.LoadLocalOrBundledParamsWithDigest(st.PRFParamsPath)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("load prf params: %w", err)
	}
	if publicParams.HasPresetBinding() {
		preset, ok := credential.LookupIntGenISISPreset(publicParams.PresetID)
		if !ok || actualPRFParamsDigest != preset.PRFParamsDigest {
			return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("showing PRF parameter digest does not match bound preset")
		}
	}
	opts := benchmarkIntGenISISE2EShowingOpts(st.RingDegree, cfg)
	if st.PRFParamsPath != "" {
		opts.PRFParamsPath = st.PRFParamsPath
	}
	opts.PhaseRecorder = PIOP.NewPhaseRecorder()
	if opts.NCols < params.LenKey {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("ncols=%d is too small for PRF key width %d", opts.NCols, params.LenKey)
	}
	B, err := loadBAsNTT(ringQ, publicParams)
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
	publicParamsDigest, err := credential.PublicParamsDigest(publicParams)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("digest IntGenISIS public params: %w", err)
	}
	verifierKeyDigest, err := verifierKey.Digest()
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("digest IntGenISIS verifier key: %w", err)
	}
	contextBinding, err := credential.DerivePresentationContext([]byte("ARC-SPRUCE benchmark context v2"), params.Q, publicParams.PresetManifestDigest, publicParamsDigest, verifierKeyDigest)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("derive benchmark presentation context: %w", err)
	}
	credentialFingerprint, err := credential.IntGenISISCredentialFingerprint(st)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("fingerprint benchmark credential: %w", err)
	}
	slot, err := credential.ReserveIntGenISISSlot(paths.HolderUsageState, publicParamsDigest, publicParams.PresetManifestDigest, credentialFingerprint, contextBinding.Digest)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("reserve benchmark hidden slot: %w", err)
	}
	if wit.CoeffNativeShowing == nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("missing benchmark coefficient-native witness")
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
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("compute IntGenISIS tag: %w", err)
	}
	contextDigest, err := hex.DecodeString(contextBinding.Digest)
	if err != nil || len(contextDigest) != 32 {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("decode benchmark context digest")
	}
	pub := PIOP.PublicInputs{
		A:              A,
		B:              B,
		CM:             cm,
		AS:             as,
		Tag:            intGenISISBenchmarkScalarsFromElems(tag),
		Context:        append([]int64(nil), contextBinding.Lanes...),
		ContextDigest:  contextDigest,
		BoundB:         publicParams.CommitmentBound,
		HashInputBound: publicParams.HashInputBound,
		X0Len:          publicParams.EllX0,
		RingDegree:     int(ringQ.N),
		HashRelation:   publicParams.HashRelation,
		IntGenISIS:     true,
		Extras:         publicParams.PresetTranscriptExtras(benchmarkIntGenISISE2ESignatureBoundExtras(st.SignatureBound)),
	}
	proveStart := time.Now()
	proof, err := PIOP.BuildIntGenISISShowingCombined(pub, wit, opts)
	proveDur := time.Since(proveStart)
	opts.PhaseRecorder.RecordDuration("showing.prove_total", proveDur)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("build IntGenISIS showing: %w", err)
	}
	verifyPub := pub
	verifyPub.A, err = benchmarkIntGenISISE2ESignatureMatrixFromRows(ringQ, verifierKey.NTRUPublic)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	verifyPub.Extras = publicParams.PresetTranscriptExtras(benchmarkIntGenISISE2ESignatureBoundExtras(verifierKey.SignatureBound))
	verifyStart := time.Now()
	ok, err = PIOP.VerifyIntGenISISShowing(verifyPub, proof, opts)
	verifyDur := time.Since(verifyStart)
	opts.PhaseRecorder.RecordDuration("showing.verify_total", verifyDur)
	if err != nil || !ok {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("standalone verify IntGenISIS showing: ok=%v err=%v", ok, err)
	}
	reportStart := time.Now()
	rep, err := PIOP.BuildProofReport(proof, opts, ringQ)
	opts.PhaseRecorder.RecordDuration("showing.report", time.Since(reportStart))
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("showing proof report: %w", err)
	}
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, false, fmt.Errorf("marshal IntGenISIS proof: %w", err)
	}
	pres := credential.IntGenISISPresentation{
		Version:              credential.IntGenISISPresentationVersion,
		PresetManifestDigest: publicParams.PresetManifestDigest,
		PublicParamsDigest:   publicParamsDigest,
		VerifierKeyDigest:    verifierKeyDigest,
		ContextDigest:        contextBinding.Digest,
		Context:              append([]int64(nil), contextBinding.Lanes...),
		Tag:                  intGenISISBenchmarkScalarsFromElems(tag),
		Proof:                proofRaw,
	}
	if err := credential.SaveIntGenISISPresentation(paths.Presentation, pres); err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	if err := credential.CheckAndMarkIntGenISISPresentation(paths.VerifierState, pres); err != nil {
		return benchmarkIntGenISISMetrics{}, false, err
	}
	replayErr := credential.CheckAndMarkIntGenISISPresentation(paths.VerifierState, pres)
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

func benchmarkIntGenISISE2EPrintReport(report benchmarkIntGenISISE2EReport, verbose bool) {
	if !verbose {
		issuanceMS := report.Timings.SetupPublicMS + report.Timings.SetupNTRUKeysMS + report.Timings.HolderCommitMS + report.Timings.HolderProveMS + report.Timings.IssuerSignMS + report.Timings.HolderFinalizeMS
		showingMS := report.Showing.ProvingMS + report.Showing.VerificationMS
		log.Printf("[issuance-cli] benchmark-intgenisis-e2e status=pass preset=%s profile=%s artifact_dir=%s showing.paper_transcript_bytes=%d theorem_total_bits=%.2f replay_rejected=%v issuance_ms=%.2f showing_ms=%.2f",
			report.Preset,
			report.Profile,
			report.ArtifactDir,
			report.Showing.PaperTranscriptBytes,
			displayBits(report.Showing.TheoremTotalBits),
			report.ReplayRejected,
			issuanceMS,
			showingMS,
		)
		return
	}
	log.Printf("[issuance-cli] IntGenISIS e2e artifact_dir=%s profile=%s q=%d", report.ArtifactDir, report.Profile, report.Modulus)
	benchmarkIntGenISISE2EPrintPhase("issuance", report.Issuance)
	benchmarkIntGenISISE2EPrintPhase("showing", report.Showing)
	log.Printf("[issuance-cli] IntGenISIS full_game accepted_issuance=%d accepted_showing=%d conservative_bits=%.2f global_collision_bits=%.2f global_collision_full_game_bits=%.2f global_query_caps=%v collision_space_bits=%d",
		report.FullGame.AcceptedIssuance,
		report.FullGame.AcceptedShowing,
		displayBits(report.FullGame.ConservativeFullGameBits),
		displayBits(report.FullGame.GlobalCollisionBits),
		displayBits(report.FullGame.GlobalCollisionFullGameBits),
		report.FullGame.GlobalQueryCaps,
		report.FullGame.CollisionSpaceBits,
	)
	log.Printf("[issuance-cli] IntGenISIS security_ledger profile=%s mode=%s status=%s full_game_bits=%.2f tag_collision_bits=%.2f core_available_bits=%.2f reasons=%v",
		report.SecurityLedger.SecurityProfile,
		report.SecurityLedger.SecurityMode,
		report.SecurityLedger.LedgerStatus,
		displayBits(report.SecurityLedger.FullGameBits),
		displayBits(report.SecurityLedger.TagCollisionBits),
		displayBits(report.SecurityLedger.CoreAvailableBits),
		report.SecurityLedger.RejectionReasons,
	)
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
	log.Printf("[issuance-cli] IntGenISIS %s eq8_round_bits=[%.2f %.2f %.2f %.2f] algebraic_round_bits=[%.2f %.2f %.2f %.2f] algebraic_total_bits=%.2f collision_bits=%.2f one_proof_total_bits=%.2f ro_query_caps=%v collision_space_bits=%d decs_hash_bits=%d decs_tape_bits=%d theorem_total_bits=%.2f ddecs=%d support_cols=%d committed_cols=%d clamped=%v",
		label,
		displayBits(m.RoundBits[0]),
		displayBits(m.RoundBits[1]),
		displayBits(m.RoundBits[2]),
		displayBits(m.RoundBits[3]),
		displayBits(m.AlgebraicBits[0]),
		displayBits(m.AlgebraicBits[1]),
		displayBits(m.AlgebraicBits[2]),
		displayBits(m.AlgebraicBits[3]),
		displayBits(m.AlgebraicTotalBits),
		displayBits(m.CollisionBits),
		displayBits(m.OneProofTotalBits),
		m.ROQueryCaps,
		m.CollisionSpaceBits,
		m.DECSHashBits,
		m.DECSTapeBits,
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
	if len(m.PhaseTimings) > 0 {
		var b strings.Builder
		for i, ph := range m.PhaseTimings {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(ph.Label)
			b.WriteByte('=')
			b.WriteString(fmt.Sprintf("%.2fms", ph.Milliseconds))
		}
		log.Printf("[issuance-cli] IntGenISIS %s phase_timings %s", label, b.String())
	}
	log.Printf("[issuance-cli] IntGenISIS %s audit views total=%d u=%d u_digit_only=%v semantic=%d commitment=%d y=%d issuer=%d constraints fpar_int=%d range=%d shortness=%d y_linear=%d bridge_total=%d bridge_u=%d bridge_commitment=%d bridge_issuer=%d prf_key=%d",
		label,
		m.CoefficientViewRows,
		m.UCoefficientViewRows,
		m.UDigitOnly,
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
	return float64(d.Nanoseconds()) / 1e6
}
