package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	sweepIntGenISISVersion     = 1
	sweepIntGenISISDefaultGrid = "wide"
)

type sweepIntGenISISConfig struct {
	ArtifactDir    string
	Profile        string
	PRFParamsPath  string
	JSONOut        string
	Grid           string
	Force          bool
	Seed           int64
	TargetEq8      float64
	Margin         float64
	MaxAnalytic    int
	MaxMeasured    int
	KeygenTrials   int
	KeygenAttempts int
	MaxTrials      int
	MaxNLeaves     int
}

type sweepIntGenISISFamily struct {
	Theta    int `json:"theta"`
	Rho      int `json:"rho"`
	EllPrime int `json:"ell_prime"`
}

type sweepIntGenISISShortness struct {
	Radix  int `json:"radix"`
	Digits int `json:"digits"`
}

type sweepIntGenISISGrid struct {
	Name        string
	Families    []sweepIntGenISISFamily
	NCols       []int
	LVCSNCols   []int
	Ell         []int
	NLeavesBase []int
	Shortness   []sweepIntGenISISShortness
	Compression []int
	PRFModes    []PIOP.PRFCompanionMode
	Checkpoints []int
	EtaSlack    int
	MaxEta      int
	Notes       []string
}

type sweepIntGenISISGridSummary struct {
	Name        string                     `json:"name"`
	Families    []sweepIntGenISISFamily    `json:"families"`
	NCols       []int                      `json:"ncols"`
	LVCSNCols   []int                      `json:"lvcs_ncols"`
	Ell         []int                      `json:"ell"`
	NLeavesBase []int                      `json:"nleaves_base"`
	Shortness   []sweepIntGenISISShortness `json:"shortness_shapes"`
	Compression []int                      `json:"mse_compression_levels"`
	PRFModes    []PIOP.PRFCompanionMode    `json:"prf_companion_modes"`
	Checkpoints []int                      `json:"prf_checkpoint_samples"`
	EtaSlack    int                        `json:"eta_slack"`
	MaxEta      int                        `json:"max_eta"`
	Notes       []string                   `json:"notes"`
}

type sweepNLeavesCacheKey struct {
	LVCSNCols      int
	Ell            int
	ThresholdMilli int
	CapLeaves      int
}

type sweepLogCombCacheKey struct {
	N int
	K int
}

type sweepRound4CacheKey struct {
	LVCSNCols int
	Ell       int
	NLeaves   int
}

type sweepRaw3CacheKey struct {
	NCols    int
	Theta    int
	EllPrime int
	DQ       int
}

type sweepAnalyticCache struct {
	NLeaves map[sweepNLeavesCacheKey][]int
	LogComb map[sweepLogCombCacheKey]float64
	Round4  map[sweepRound4CacheKey]float64
	Raw3    map[sweepRaw3CacheKey]float64
}

type sweepIntGenISISCandidate struct {
	ID                 string                     `json:"id"`
	Issuance           intGenISISTuning           `json:"issuance"`
	Showing            intGenISISTuning           `json:"showing"`
	AnalyticIssuance   PIOP.SoundnessBudget       `json:"analytic_issuance"`
	AnalyticShowing    PIOP.SoundnessBudget       `json:"analytic_showing"`
	IssuanceMetrics    benchmarkIntGenISISMetrics `json:"issuance_metrics,omitempty"`
	ShowingMetrics     benchmarkIntGenISISMetrics `json:"showing_metrics,omitempty"`
	Measured           bool                       `json:"measured"`
	Passed             bool                       `json:"passed"`
	Error              string                     `json:"error,omitempty"`
	HeuristicScore     float64                    `json:"heuristic_score"`
	TotalTranscriptB   int                        `json:"total_paper_transcript_bytes,omitempty"`
	ShowingTranscriptB int                        `json:"showing_paper_transcript_bytes,omitempty"`
}

type sweepIntGenISISReport struct {
	Version     int                             `json:"version"`
	Generated   string                          `json:"generated_at"`
	Profile     string                          `json:"profile"`
	TargetEq8   float64                         `json:"target_eq8_bits"`
	Margin      float64                         `json:"margin_bits"`
	Threshold   float64                         `json:"threshold_eq8_bits"`
	MaxNLeaves  int                             `json:"max_nleaves,omitempty"`
	Grid        sweepIntGenISISGridSummary      `json:"grid"`
	ArtifactDir string                          `json:"artifact_dir"`
	Artifacts   benchmarkIntGenISISE2EArtifacts `json:"artifacts"`
	Analytic    []sweepIntGenISISCandidate      `json:"analytic_frontier"`
	Measured    []sweepIntGenISISCandidate      `json:"measured"`
	Best        *sweepIntGenISISCandidate       `json:"best,omitempty"`
	Notes       []string                        `json:"notes"`
}

type sweepIntGenISISPresetsConfig struct {
	ArtifactDir         string
	Profile             string
	PRFParamsPath       string
	JSONOut             string
	PresetJSONOut       string
	Force               bool
	Seed                int64
	SecurityLevels      []float64
	LVCSTargets         []int
	Margin              float64
	MaxAnalyticPerTrack int
	MaxMeasuredPerTrack int
	MaxNLeaves          int
	FallbackMaxNLeaves  int
	KeygenTrials        int
	KeygenAttempts      int
	MaxTrials           int
}

type sweepIntGenISISPresetTrackReport struct {
	ID             string                       `json:"id"`
	TargetEq8      float64                      `json:"target_eq8_bits"`
	Threshold      float64                      `json:"threshold_eq8_bits"`
	LVCSNCols      int                          `json:"lvcs_ncols"`
	MaxNLeaves     int                          `json:"max_nleaves"`
	FallbackUsed   bool                         `json:"fallback_used,omitempty"`
	Grid           sweepIntGenISISGridSummary   `json:"grid"`
	Analytic       []sweepIntGenISISCandidate   `json:"analytic_frontier"`
	Measured       []sweepIntGenISISCandidate   `json:"measured,omitempty"`
	Selected       *sweepIntGenISISCandidate    `json:"selected,omitempty"`
	SelectedPreset *credential.IntGenISISPreset `json:"selected_preset,omitempty"`
	Notes          []string                     `json:"notes,omitempty"`
}

type sweepIntGenISISPresetsReport struct {
	Version             int                                `json:"version"`
	Generated           string                             `json:"generated_at"`
	Profile             string                             `json:"profile"`
	SecurityLevels      []float64                          `json:"security_levels"`
	LVCSTargets         []int                              `json:"lvcs_targets"`
	Margin              float64                            `json:"margin_bits"`
	MaxNLeaves          int                                `json:"max_nleaves"`
	FallbackMaxNLeaves  int                                `json:"fallback_max_nleaves"`
	MaxAnalyticPerTrack int                                `json:"max_analytic_per_track"`
	MaxMeasuredPerTrack int                                `json:"max_measured_per_track"`
	ArtifactDir         string                             `json:"artifact_dir,omitempty"`
	Artifacts           benchmarkIntGenISISE2EArtifacts    `json:"artifacts,omitempty"`
	Tracks              []sweepIntGenISISPresetTrackReport `json:"tracks"`
	SelectedPresets     []credential.IntGenISISPreset      `json:"selected_presets"`
	Notes               []string                           `json:"notes"`
}

func runSweepIntGenISIS(args []string) error {
	fs := flag.NewFlagSet("sweep-intgenisis", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactDir := fs.String("artifact-dir", "", "artifact directory reused across measured candidates; defaults to a temporary directory")
	profile := fs.String("profile", credential.ProfileIntGenISISB, "IntGenISIS profile name")
	prfParamsPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	jsonOut := fs.String("json-out", filepath.Join("credential", "issuance", "intgenisis_sweep.json"), "JSON output path")
	grid := fs.String("grid", sweepIntGenISISDefaultGrid, "sweep grid preset: quick, wide, deep, strata, leafcap64k, pack64, pack128, pack256, or packwide")
	force := fs.Bool("force", false, "overwrite reusable sweep artifacts and JSON output")
	seed := fs.Int64("seed", 11, "holder commitment sampling seed")
	targetEq8 := fs.Float64("target-eq8", 128, "raw Eq. (8) target in bits")
	margin := fs.Float64("margin", 2, "extra raw Eq. (8) margin in bits")
	maxAnalytic := fs.Int("max-analytic", 64, "number of analytic-frontier candidates to keep")
	maxMeasured := fs.Int("max-measured", 8, "number of analytic candidates to measure with real proofs")
	maxNLeaves := fs.Int("max-nleaves", intGenISISDefaultMaxNLeaves, "maximum generated explicit-domain leaves; 0 disables the cap for uncapped research sweeps")
	keygenTrials := fs.Int("keygen-trials", 10000, "maximum annulus keygen trials for reusable setup")
	keygenAttempts := fs.Int("attempts", 4, "annulus keygen attempts for reusable setup")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report, err := sweepIntGenISIS(sweepIntGenISISConfig{
		ArtifactDir:    *artifactDir,
		Profile:        *profile,
		PRFParamsPath:  *prfParamsPath,
		JSONOut:        *jsonOut,
		Grid:           *grid,
		Force:          *force,
		Seed:           *seed,
		TargetEq8:      *targetEq8,
		Margin:         *margin,
		MaxAnalytic:    *maxAnalytic,
		MaxMeasured:    *maxMeasured,
		MaxNLeaves:     *maxNLeaves,
		KeygenTrials:   *keygenTrials,
		KeygenAttempts: *keygenAttempts,
		MaxTrials:      *maxTrials,
	})
	if err != nil {
		return err
	}
	if report.Best != nil {
		log.Printf("[issuance-cli] sweep best id=%s showing_bytes=%d total_bytes=%d issuance_eq8=%.2f showing_eq8=%.2f",
			report.Best.ID,
			report.Best.ShowingTranscriptB,
			report.Best.TotalTranscriptB,
			displayBits(report.Best.IssuanceMetrics.SoundnessEq8Bits),
			displayBits(report.Best.ShowingMetrics.SoundnessEq8Bits),
		)
	}
	return nil
}

func runSweepIntGenISISPresets(args []string) error {
	fs := flag.NewFlagSet("sweep-intgenisis-presets", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	artifactDir := fs.String("artifact-dir", "", "artifact directory reused across measured candidates; defaults to a temporary directory when measuring")
	profile := fs.String("profile", credential.ProfileIntGenISISB, "IntGenISIS profile name")
	prfParamsPath := fs.String("prf-params", defaultPRFParamsPath, "PRF params path")
	jsonOut := fs.String("json-out", filepath.Join("credential", "issuance", "intgenisis_preset_sweep.json"), "full preset sweep JSON output path")
	presetJSONOut := fs.String("preset-json-out", filepath.Join("credential", "issuance", "intgenisis_selected_presets.json"), "compact selected-preset JSON output path")
	force := fs.Bool("force", false, "overwrite reusable sweep artifacts and JSON output")
	seed := fs.Int64("seed", 11, "holder commitment sampling seed")
	securityLevels := fs.String("security-levels", "96,128", "comma-separated raw Eq. (8) targets in bits")
	lvcsTargets := fs.String("lvcs-targets", "32,64,128", "comma-separated fixed LVCS widths to tune")
	margin := fs.Float64("margin", 2, "extra raw Eq. (8) margin in bits")
	maxAnalytic := fs.Int("max-analytic-per-track", 128, "analytic-frontier candidates to keep per fixed-LVCS/security track")
	maxMeasured := fs.Int("max-measured-per-track", 5, "analytic candidates to measure per fixed-LVCS/security track")
	maxNLeaves := fs.Int("max-nleaves", intGenISISDefaultMaxNLeaves, "primary maximum generated explicit-domain leaves")
	fallbackMaxNLeaves := fs.Int("fallback-max-nleaves", 262144, "fallback leaf cap used only for tracks with no primary-cap candidate")
	keygenTrials := fs.Int("keygen-trials", 10000, "maximum annulus keygen trials for reusable setup")
	keygenAttempts := fs.Int("attempts", 4, "annulus keygen attempts for reusable setup")
	maxTrials := fs.Int("max-trials", 2048, "maximum NTRU signer trials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	levels, err := parseFloatCSV(*securityLevels)
	if err != nil {
		return fmt.Errorf("parse -security-levels: %w", err)
	}
	lvcs, err := parseIntCSV(*lvcsTargets)
	if err != nil {
		return fmt.Errorf("parse -lvcs-targets: %w", err)
	}
	report, err := sweepIntGenISISPresets(sweepIntGenISISPresetsConfig{
		ArtifactDir:         *artifactDir,
		Profile:             *profile,
		PRFParamsPath:       *prfParamsPath,
		JSONOut:             *jsonOut,
		PresetJSONOut:       *presetJSONOut,
		Force:               *force,
		Seed:                *seed,
		SecurityLevels:      levels,
		LVCSTargets:         lvcs,
		Margin:              *margin,
		MaxAnalyticPerTrack: *maxAnalytic,
		MaxMeasuredPerTrack: *maxMeasured,
		MaxNLeaves:          *maxNLeaves,
		FallbackMaxNLeaves:  *fallbackMaxNLeaves,
		KeygenTrials:        *keygenTrials,
		KeygenAttempts:      *keygenAttempts,
		MaxTrials:           *maxTrials,
	})
	if err != nil {
		return err
	}
	for _, p := range report.SelectedPresets {
		log.Printf("[issuance-cli] preset candidate %s: issuance={ncols=%d lvcs=%d nleaves=%d eta=%d theta=%d rho=%d ell=%d ell'=%d} showing={ncols=%d lvcs=%d nleaves=%d eta=%d theta=%d rho=%d ell=%d ell'=%d short=%d/%d comp=%d mode=%s samples=%d}",
			p.Name,
			p.Issuance.NCols, p.Issuance.LVCSNCols, p.Issuance.NLeaves, p.Issuance.Eta, p.Issuance.Theta, p.Issuance.Rho, p.Issuance.Ell, p.Issuance.EllPrime,
			p.Showing.NCols, p.Showing.LVCSNCols, p.Showing.NLeaves, p.Showing.Eta, p.Showing.Theta, p.Showing.Rho, p.Showing.Ell, p.Showing.EllPrime,
			p.Showing.SigShortnessRadix, p.Showing.SigShortnessDigits, p.Showing.CompressedRows, p.Showing.PRFCompanionMode, p.Showing.CheckpointSamples,
		)
	}
	return nil
}

func sweepIntGenISIS(cfg sweepIntGenISISConfig) (sweepIntGenISISReport, error) {
	if cfg.Profile == "" {
		cfg.Profile = credential.ProfileIntGenISISB
	}
	profile, ok := credential.LookupIntGenISISProfile(cfg.Profile)
	if !ok {
		return sweepIntGenISISReport{}, fmt.Errorf("unsupported IntGenISIS profile %q", cfg.Profile)
	}
	if profile.Name != credential.ProfileIntGenISISB {
		return sweepIntGenISISReport{}, fmt.Errorf("sweep-intgenisis currently supports only %s", credential.ProfileIntGenISISB)
	}
	if cfg.PRFParamsPath == "" {
		cfg.PRFParamsPath = defaultPRFParamsPath
	}
	if cfg.TargetEq8 <= 0 {
		cfg.TargetEq8 = 128
	}
	if cfg.Margin < 0 {
		cfg.Margin = 0
	}
	if cfg.MaxAnalytic <= 0 {
		cfg.MaxAnalytic = 64
	}
	if cfg.MaxMeasured < 0 {
		cfg.MaxMeasured = 8
	}
	cfg.MaxNLeaves = normalizeIntGenISISMaxNLeaves(cfg.MaxNLeaves)
	if cfg.KeygenTrials <= 0 {
		cfg.KeygenTrials = 10000
	}
	if cfg.KeygenAttempts <= 0 {
		cfg.KeygenAttempts = 4
	}
	if cfg.MaxTrials <= 0 {
		cfg.MaxTrials = 2048
	}
	if cfg.JSONOut != "" && !cfg.Force {
		if _, err := os.Stat(cfg.JSONOut); err == nil {
			return sweepIntGenISISReport{}, fmt.Errorf("refusing to overwrite existing %s without -force", cfg.JSONOut)
		} else if !os.IsNotExist(err) {
			return sweepIntGenISISReport{}, fmt.Errorf("stat %s: %w", cfg.JSONOut, err)
		}
	}
	threshold := cfg.TargetEq8 + cfg.Margin
	grid, err := sweepIntGenISISGridFor(cfg.Grid)
	if err != nil {
		return sweepIntGenISISReport{}, err
	}
	analytic := sweepIntGenISISGenerateCandidates(profile, threshold, grid, cfg.MaxAnalytic, cfg.MaxNLeaves)
	if len(analytic) == 0 {
		return sweepIntGenISISReport{}, fmt.Errorf("analytic sweep found no candidates clearing %.2f raw Eq. (8) bits", threshold)
	}
	if len(analytic) > cfg.MaxAnalytic {
		analytic = analytic[:cfg.MaxAnalytic]
	}
	sweepPopulateAnalyticBudgets(profile, analytic)

	measuredLimit := cfg.MaxMeasured
	if measuredLimit > len(analytic) {
		measuredLimit = len(analytic)
	}
	artifactDir := cfg.ArtifactDir
	var setupReport benchmarkIntGenISISE2EReport
	if measuredLimit > 0 {
		if artifactDir == "" {
			tmp, err := os.MkdirTemp("", "spruce-intgenisis-sweep-*")
			if err != nil {
				return sweepIntGenISISReport{}, fmt.Errorf("create temp artifact dir: %w", err)
			}
			artifactDir = tmp
		}
		setupCfg := benchmarkIntGenISISE2EConfig{
			ArtifactDir:    artifactDir,
			Profile:        profile.Name,
			PRFParamsPath:  cfg.PRFParamsPath,
			Force:          cfg.Force || cfg.ArtifactDir == "",
			Seed:           cfg.Seed,
			Issuance:       defaultIntGenISISTuning(),
			Showing:        defaultIntGenISISTuning(),
			KeygenTrials:   cfg.KeygenTrials,
			KeygenAttempts: cfg.KeygenAttempts,
			MaxTrials:      cfg.MaxTrials,
		}
		log.Printf("[issuance-cli] sweep setup: generating reusable profile-B artifacts in %s", artifactDir)
		setupReport, err = benchmarkIntGenISISE2E(setupCfg)
		if err != nil {
			return sweepIntGenISISReport{}, fmt.Errorf("prepare reusable e2e artifacts: %w", err)
		}
	} else {
		log.Printf("[issuance-cli] sweep analytic-only mode: -max-measured=0, skipping reusable e2e setup")
	}
	measured := make([]sweepIntGenISISCandidate, 0, measuredLimit)
	for i := 0; i < measuredLimit; i++ {
		cand := analytic[i]
		log.Printf("[issuance-cli] sweep measure %d/%d id=%s issuance={ncols=%d lvcs=%d nleaves=%d eta=%d theta=%d rho=%d ell=%d ell'=%d} showing={ncols=%d lvcs=%d nleaves=%d eta=%d theta=%d rho=%d ell=%d ell'=%d mode=%s samples=%d}",
			i+1, measuredLimit, cand.ID,
			cand.Issuance.NCols, cand.Issuance.LVCSNCols, cand.Issuance.NLeaves, cand.Issuance.Eta, cand.Issuance.Theta, cand.Issuance.Rho, cand.Issuance.Ell, cand.Issuance.EllPrime,
			cand.Showing.NCols, cand.Showing.LVCSNCols, cand.Showing.NLeaves, cand.Showing.Eta, cand.Showing.Theta, cand.Showing.Rho, cand.Showing.Ell, cand.Showing.EllPrime, cand.Showing.PRFCompanionMode, cand.Showing.CheckpointSamples,
		)
		pre, err := sweepIntGenISISPreSignMetrics(setupReport.Artifacts, cand.Issuance)
		if err != nil {
			cand.Error = fmt.Sprintf("presign: %v", err)
			measured = append(measured, cand)
			log.Printf("[issuance-cli] sweep candidate %s failed pre-sign: %v", cand.ID, err)
			continue
		}
		cand.IssuanceMetrics = pre
		showCfg := benchmarkIntGenISISE2EConfig{
			PRFParamsPath: cfg.PRFParamsPath,
			Showing:       cand.Showing,
		}
		show, replayRejected, err := benchmarkIntGenISISE2EShowing(setupReport.Artifacts, showCfg)
		if err != nil {
			cand.Error = fmt.Sprintf("showing: %v", err)
			measured = append(measured, cand)
			log.Printf("[issuance-cli] sweep candidate %s failed showing: %v", cand.ID, err)
			continue
		}
		if !replayRejected {
			cand.Error = "showing replay was not rejected"
			measured = append(measured, cand)
			continue
		}
		cand.ShowingMetrics = show
		cand.Measured = true
		cand.Passed = pre.SoundnessEq8Bits >= threshold && show.SoundnessEq8Bits >= threshold
		cand.ShowingTranscriptB = show.PaperTranscriptBytes
		cand.TotalTranscriptB = pre.PaperTranscriptBytes + show.PaperTranscriptBytes
		measured = append(measured, cand)
		log.Printf("[issuance-cli] sweep candidate %s measured pass=%v issuance_eq8=%.2f showing_eq8=%.2f showing_bytes=%d total_bytes=%d",
			cand.ID, cand.Passed, displayBits(pre.SoundnessEq8Bits), displayBits(show.SoundnessEq8Bits), cand.ShowingTranscriptB, cand.TotalTranscriptB)
	}
	sort.SliceStable(measured, func(i, j int) bool {
		a, b := measured[i], measured[j]
		if a.Passed != b.Passed {
			return a.Passed
		}
		if a.ShowingTranscriptB != b.ShowingTranscriptB {
			if a.ShowingTranscriptB == 0 {
				return false
			}
			if b.ShowingTranscriptB == 0 {
				return true
			}
			return a.ShowingTranscriptB < b.ShowingTranscriptB
		}
		if a.TotalTranscriptB != b.TotalTranscriptB {
			if a.TotalTranscriptB == 0 {
				return false
			}
			if b.TotalTranscriptB == 0 {
				return true
			}
			return a.TotalTranscriptB < b.TotalTranscriptB
		}
		return a.HeuristicScore < b.HeuristicScore
	})
	var best *sweepIntGenISISCandidate
	for i := range measured {
		if measured[i].Passed {
			c := measured[i]
			best = &c
			break
		}
	}
	report := sweepIntGenISISReport{
		Version:     sweepIntGenISISVersion,
		Generated:   time.Now().UTC().Format(time.RFC3339),
		Profile:     profile.Name,
		TargetEq8:   cfg.TargetEq8,
		Margin:      cfg.Margin,
		Threshold:   threshold,
		MaxNLeaves:  cfg.MaxNLeaves,
		Grid:        sweepIntGenISISGridSummaryFromGrid(grid),
		ArtifactDir: artifactDir,
		Artifacts:   setupReport.Artifacts,
		Analytic:    analytic,
		Measured:    measured,
		Best:        best,
		Notes: []string{
			"Raw Eq. (8) soundness is the hard pass condition; kappa remains zero in the generated sweep candidates.",
			"Analytic filtering uses relation-aware paper Eq. (3) d_Q estimates with ternary M/s/e and the selected u-shortness radix.",
			"The executable sweep includes theta>1 small-field candidates using literal IntGenISIS row heads on Ω.",
			fmt.Sprintf("nleaves is generated per (lvcs_ncols,ell) from the exact round-4 Eq. (8) threshold and capped at max_nleaves=%d unless disabled.", cfg.MaxNLeaves),
			"Candidate ordering prioritizes recurring showing transcript bytes, then total issuance+showing transcript bytes.",
		},
	}
	if cfg.JSONOut != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.JSONOut), 0o755); err != nil {
			return sweepIntGenISISReport{}, fmt.Errorf("mkdir sweep json dir: %w", err)
		}
		if err := writeJSONFile(cfg.JSONOut, report, 0o644); err != nil {
			return sweepIntGenISISReport{}, fmt.Errorf("write sweep json: %w", err)
		}
		log.Printf("[issuance-cli] sweep-intgenisis wrote %s", cfg.JSONOut)
	}
	return report, nil
}

func sweepIntGenISISPresets(cfg sweepIntGenISISPresetsConfig) (sweepIntGenISISPresetsReport, error) {
	if cfg.Profile == "" {
		cfg.Profile = credential.ProfileIntGenISISB
	}
	profile, ok := credential.LookupIntGenISISProfile(cfg.Profile)
	if !ok {
		return sweepIntGenISISPresetsReport{}, fmt.Errorf("unsupported IntGenISIS profile %q", cfg.Profile)
	}
	if profile.Name != credential.ProfileIntGenISISB {
		return sweepIntGenISISPresetsReport{}, fmt.Errorf("sweep-intgenisis-presets currently supports only %s", credential.ProfileIntGenISISB)
	}
	if cfg.PRFParamsPath == "" {
		cfg.PRFParamsPath = defaultPRFParamsPath
	}
	if len(cfg.SecurityLevels) == 0 {
		cfg.SecurityLevels = []float64{96, 128}
	}
	if len(cfg.LVCSTargets) == 0 {
		cfg.LVCSTargets = []int{32, 64, 128}
	}
	if cfg.Margin < 0 {
		cfg.Margin = 0
	}
	if cfg.MaxAnalyticPerTrack <= 0 {
		cfg.MaxAnalyticPerTrack = 128
	}
	if cfg.MaxMeasuredPerTrack < 0 {
		cfg.MaxMeasuredPerTrack = 5
	}
	cfg.MaxNLeaves = normalizeIntGenISISMaxNLeaves(cfg.MaxNLeaves)
	if cfg.FallbackMaxNLeaves < cfg.MaxNLeaves {
		cfg.FallbackMaxNLeaves = cfg.MaxNLeaves
	}
	cfg.FallbackMaxNLeaves = normalizeIntGenISISMaxNLeaves(cfg.FallbackMaxNLeaves)
	if cfg.KeygenTrials <= 0 {
		cfg.KeygenTrials = 10000
	}
	if cfg.KeygenAttempts <= 0 {
		cfg.KeygenAttempts = 4
	}
	if cfg.MaxTrials <= 0 {
		cfg.MaxTrials = 2048
	}
	for _, path := range []string{cfg.JSONOut, cfg.PresetJSONOut} {
		if path == "" || cfg.Force {
			continue
		}
		if _, err := os.Stat(path); err == nil {
			return sweepIntGenISISPresetsReport{}, fmt.Errorf("refusing to overwrite existing %s without -force", path)
		} else if !os.IsNotExist(err) {
			return sweepIntGenISISPresetsReport{}, fmt.Errorf("stat %s: %w", path, err)
		}
	}

	tracks := make([]sweepIntGenISISPresetTrackReport, 0, len(cfg.SecurityLevels)*len(cfg.LVCSTargets))
	for _, target := range uniqueSortedFloat64s(cfg.SecurityLevels) {
		if target <= 0 {
			return sweepIntGenISISPresetsReport{}, fmt.Errorf("invalid security target %.2f", target)
		}
		threshold := target + cfg.Margin
		for _, lvcs := range uniqueSortedInts(append([]int(nil), cfg.LVCSTargets...)) {
			grid, err := sweepIntGenISISPresetGrid(target, lvcs)
			if err != nil {
				return sweepIntGenISISPresetsReport{}, err
			}
			analytic := sweepIntGenISISGenerateCandidates(profile, threshold, grid, cfg.MaxAnalyticPerTrack, cfg.MaxNLeaves)
			fallbackUsed := false
			trackMaxLeaves := cfg.MaxNLeaves
			if len(analytic) == 0 && cfg.FallbackMaxNLeaves > cfg.MaxNLeaves {
				analytic = sweepIntGenISISGenerateCandidates(profile, threshold, grid, cfg.MaxAnalyticPerTrack, cfg.FallbackMaxNLeaves)
				fallbackUsed = len(analytic) > 0
				if fallbackUsed {
					trackMaxLeaves = cfg.FallbackMaxNLeaves
				}
			}
			if len(analytic) > cfg.MaxAnalyticPerTrack {
				analytic = analytic[:cfg.MaxAnalyticPerTrack]
			}
			sweepPopulateAnalyticBudgets(profile, analytic)
			track := sweepIntGenISISPresetTrackReport{
				ID:           intGenISISPresetTrackID(target, lvcs),
				TargetEq8:    target,
				Threshold:    threshold,
				LVCSNCols:    lvcs,
				MaxNLeaves:   trackMaxLeaves,
				FallbackUsed: fallbackUsed,
				Grid:         sweepIntGenISISGridSummaryFromGrid(grid),
				Analytic:     analytic,
			}
			if len(analytic) == 0 {
				track.Notes = append(track.Notes, "no analytic candidates cleared the raw Eq. (8) threshold under the primary or fallback leaf cap")
			}
			tracks = append(tracks, track)
		}
	}

	needsMeasurement := cfg.MaxMeasuredPerTrack > 0
	var setupReport benchmarkIntGenISISE2EReport
	artifactDir := cfg.ArtifactDir
	if needsMeasurement {
		if artifactDir == "" {
			tmp, err := os.MkdirTemp("", "spruce-intgenisis-preset-sweep-*")
			if err != nil {
				return sweepIntGenISISPresetsReport{}, fmt.Errorf("create temp artifact dir: %w", err)
			}
			artifactDir = tmp
		}
		log.Printf("[issuance-cli] preset sweep setup: generating reusable profile-B artifacts in %s", artifactDir)
		var err error
		setupReport, err = benchmarkIntGenISISE2E(benchmarkIntGenISISE2EConfig{
			ArtifactDir:    artifactDir,
			Profile:        profile.Name,
			PRFParamsPath:  cfg.PRFParamsPath,
			Force:          cfg.Force || cfg.ArtifactDir == "",
			Seed:           cfg.Seed,
			Issuance:       defaultIntGenISISTuning(),
			Showing:        defaultIntGenISISTuning(),
			KeygenTrials:   cfg.KeygenTrials,
			KeygenAttempts: cfg.KeygenAttempts,
			MaxTrials:      cfg.MaxTrials,
		})
		if err != nil {
			return sweepIntGenISISPresetsReport{}, fmt.Errorf("prepare reusable e2e artifacts: %w", err)
		}
	} else {
		log.Printf("[issuance-cli] preset sweep analytic-only mode: -max-measured-per-track=0, skipping reusable e2e setup")
	}

	selected := make([]credential.IntGenISISPreset, 0, len(tracks))
	for ti := range tracks {
		track := &tracks[ti]
		threshold := track.Threshold
		measuredLimit := cfg.MaxMeasuredPerTrack
		if measuredLimit > len(track.Analytic) {
			measuredLimit = len(track.Analytic)
		}
		for i := 0; i < measuredLimit; i++ {
			cand := track.Analytic[i]
			log.Printf("[issuance-cli] preset sweep %s measure %d/%d id=%s", track.ID, i+1, measuredLimit, cand.ID)
			cand = sweepMeasureIntGenISISCandidate(cand, setupReport, cfg.PRFParamsPath, threshold)
			track.Measured = append(track.Measured, cand)
		}
		sort.SliceStable(track.Measured, func(i, j int) bool {
			a, b := track.Measured[i], track.Measured[j]
			if a.Passed != b.Passed {
				return a.Passed
			}
			if a.ShowingTranscriptB != b.ShowingTranscriptB {
				if a.ShowingTranscriptB == 0 {
					return false
				}
				if b.ShowingTranscriptB == 0 {
					return true
				}
				return a.ShowingTranscriptB < b.ShowingTranscriptB
			}
			if a.TotalTranscriptB != b.TotalTranscriptB {
				if a.TotalTranscriptB == 0 {
					return false
				}
				if b.TotalTranscriptB == 0 {
					return true
				}
				return a.TotalTranscriptB < b.TotalTranscriptB
			}
			return sweepCandidateLess(a, b)
		})
		var chosen *sweepIntGenISISCandidate
		for i := range track.Measured {
			if track.Measured[i].Passed {
				c := track.Measured[i]
				chosen = &c
				break
			}
		}
		if chosen == nil && len(track.Analytic) > 0 {
			c := track.Analytic[0]
			chosen = &c
			track.Notes = append(track.Notes, "selected candidate is analytic-only; run with -max-measured-per-track > 0 before promotion")
		}
		if chosen != nil {
			track.Selected = chosen
			preset := sweepCandidateToCredentialPreset(track.ID, profile.Name, track.TargetEq8, track.LVCSNCols, track.MaxNLeaves, track.FallbackUsed, *chosen)
			track.SelectedPreset = &preset
			selected = append(selected, preset)
		}
	}

	report := sweepIntGenISISPresetsReport{
		Version:             sweepIntGenISISVersion,
		Generated:           time.Now().UTC().Format(time.RFC3339),
		Profile:             profile.Name,
		SecurityLevels:      uniqueSortedFloat64s(cfg.SecurityLevels),
		LVCSTargets:         uniqueSortedInts(append([]int(nil), cfg.LVCSTargets...)),
		Margin:              cfg.Margin,
		MaxNLeaves:          cfg.MaxNLeaves,
		FallbackMaxNLeaves:  cfg.FallbackMaxNLeaves,
		MaxAnalyticPerTrack: cfg.MaxAnalyticPerTrack,
		MaxMeasuredPerTrack: cfg.MaxMeasuredPerTrack,
		ArtifactDir:         artifactDir,
		Artifacts:           setupReport.Artifacts,
		Tracks:              tracks,
		SelectedPresets:     selected,
		Notes: []string{
			"Each track fixes lvcs_ncols and requires issuance and showing raw Eq. (8) bits to clear target+margin.",
			"Analytic filtering uses the current relation-aware conservative d_Q model before measuring real proofs.",
			"Selected presets are sorted by recurring showing transcript bytes when measured data is available.",
			"Static CLI presets are seeds; copy measured selected_presets into the registry only after reviewing the JSON frontier.",
		},
	}
	if cfg.JSONOut != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.JSONOut), 0o755); err != nil {
			return sweepIntGenISISPresetsReport{}, fmt.Errorf("mkdir preset sweep json dir: %w", err)
		}
		if err := writeJSONFile(cfg.JSONOut, report, 0o644); err != nil {
			return sweepIntGenISISPresetsReport{}, fmt.Errorf("write preset sweep json: %w", err)
		}
		log.Printf("[issuance-cli] sweep-intgenisis-presets wrote %s", cfg.JSONOut)
	}
	if cfg.PresetJSONOut != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.PresetJSONOut), 0o755); err != nil {
			return sweepIntGenISISPresetsReport{}, fmt.Errorf("mkdir preset json dir: %w", err)
		}
		if err := writeJSONFile(cfg.PresetJSONOut, selected, 0o644); err != nil {
			return sweepIntGenISISPresetsReport{}, fmt.Errorf("write selected preset json: %w", err)
		}
		log.Printf("[issuance-cli] sweep-intgenisis-presets wrote %s", cfg.PresetJSONOut)
	}
	return report, nil
}

func sweepIntGenISISPresetGrid(target float64, lvcs int) (sweepIntGenISISGrid, error) {
	if lvcs != 32 && lvcs != 64 && lvcs != 128 {
		return sweepIntGenISISGrid{}, fmt.Errorf("preset sweep lvcs_ncols=%d unsupported; use 32, 64, or 128", lvcs)
	}
	ncols := []int{32}
	switch lvcs {
	case 32:
		ncols = []int{16, 32}
	case 64:
		ncols = []int{32, 64}
	case 128:
		ncols = []int{32, 64, 128}
	}
	families := []sweepIntGenISISFamily{
		{Theta: 5, Rho: 1, EllPrime: 1},
		{Theta: 6, Rho: 1, EllPrime: 1},
		{Theta: 7, Rho: 1, EllPrime: 1},
		{Theta: 3, Rho: 2, EllPrime: 1},
		{Theta: 4, Rho: 2, EllPrime: 1},
	}
	ell := []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24}
	if target >= 128 {
		families = []sweepIntGenISISFamily{
			{Theta: 7, Rho: 1, EllPrime: 1},
			{Theta: 8, Rho: 1, EllPrime: 1},
			{Theta: 9, Rho: 1, EllPrime: 1},
			{Theta: 10, Rho: 1, EllPrime: 1},
			{Theta: 4, Rho: 2, EllPrime: 1},
			{Theta: 5, Rho: 2, EllPrime: 1},
			{Theta: 3, Rho: 3, EllPrime: 1},
		}
		ell = []int{10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 26, 28, 30, 32}
	}
	return sweepIntGenISISGrid{
		Name:        intGenISISPresetTrackID(target, lvcs),
		Families:    families,
		NCols:       ncols,
		LVCSNCols:   []int{lvcs},
		Ell:         ell,
		NLeavesBase: []int{4096, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144},
		Shortness: []sweepIntGenISISShortness{
			{Radix: 11, Digits: 4},
			{Radix: 7, Digits: 5},
			{Radix: 5, Digits: 6},
		},
		Compression: []int{0, 1, 2},
		PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth},
		Checkpoints: []int{2},
		EtaSlack:    2,
		MaxEta:      128,
		Notes: []string{
			"Preset grid fixes lvcs_ncols and searches only paper-faithful theta>1 families.",
			"Direct-auth PRF with two checkpoint samples is used as the primary compact presentation mode.",
			"M/s/e compression levels 0, 1, and 2 are analytic candidates; high-degree level 3 is excluded from defaults.",
		},
	}, nil
}

func sweepMeasureIntGenISISCandidate(cand sweepIntGenISISCandidate, setupReport benchmarkIntGenISISE2EReport, prfParamsPath string, threshold float64) sweepIntGenISISCandidate {
	pre, err := sweepIntGenISISPreSignMetrics(setupReport.Artifacts, cand.Issuance)
	if err != nil {
		cand.Error = fmt.Sprintf("presign: %v", err)
		log.Printf("[issuance-cli] sweep candidate %s failed pre-sign: %v", cand.ID, err)
		return cand
	}
	cand.IssuanceMetrics = pre
	showCfg := benchmarkIntGenISISE2EConfig{
		PRFParamsPath: prfParamsPath,
		Showing:       cand.Showing,
	}
	show, replayRejected, err := benchmarkIntGenISISE2EShowing(setupReport.Artifacts, showCfg)
	if err != nil {
		cand.Error = fmt.Sprintf("showing: %v", err)
		log.Printf("[issuance-cli] sweep candidate %s failed showing: %v", cand.ID, err)
		return cand
	}
	if !replayRejected {
		cand.Error = "showing replay was not rejected"
		return cand
	}
	cand.ShowingMetrics = show
	cand.Measured = true
	cand.Passed = pre.SoundnessEq8Bits >= threshold && show.SoundnessEq8Bits >= threshold
	cand.ShowingTranscriptB = show.PaperTranscriptBytes
	cand.TotalTranscriptB = pre.PaperTranscriptBytes + show.PaperTranscriptBytes
	log.Printf("[issuance-cli] sweep candidate %s measured pass=%v issuance_eq8=%.2f showing_eq8=%.2f showing_bytes=%d total_bytes=%d",
		cand.ID, cand.Passed, displayBits(pre.SoundnessEq8Bits), displayBits(show.SoundnessEq8Bits), cand.ShowingTranscriptB, cand.TotalTranscriptB)
	return cand
}

func sweepCandidateToCredentialPreset(name, profileName string, target float64, lvcs, maxLeaves int, fallbackUsed bool, cand sweepIntGenISISCandidate) credential.IntGenISISPreset {
	p := credential.IntGenISISPreset{
		Name:          name,
		Description:   fmt.Sprintf("profile-B %.0f-bit Eq. (8) preset candidate with lvcs_ncols=%d", target, lvcs),
		Profile:       profileName,
		TargetEq8Bits: target,
		LVCSNCols:     lvcs,
		MaxNLeaves:    maxLeaves,
		Issuance:      intGenISISTuningPresetFromTuning(cand.Issuance, target),
		Showing:       intGenISISTuningPresetFromTuning(cand.Showing, target),
		Notes: []string{
			"Generated by sweep-intgenisis-presets; review measured frontier before promotion into the static registry.",
		},
	}
	if fallbackUsed {
		p.ResearchLargeDomain = maxLeaves > intGenISISDefaultMaxNLeaves
		p.Notes = append(p.Notes, "track required the fallback leaf cap")
	}
	return p
}

func intGenISISPresetTrackID(target float64, lvcs int) string {
	return fmt.Sprintf("sw%.0f-lvcs%d", target, lvcs)
}

func parseIntCSV(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty integer list")
	}
	return uniqueSortedInts(out), nil
}

func parseFloatCSV(s string) ([]float64, error) {
	parts := strings.Split(s, ",")
	out := make([]float64, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty float list")
	}
	return uniqueSortedFloat64s(out), nil
}

func uniqueSortedFloat64s(vals []float64) []float64 {
	if len(vals) == 0 {
		return nil
	}
	sort.Float64s(vals)
	out := vals[:0]
	lastSet := false
	last := 0.0
	for _, v := range vals {
		if v <= 0 {
			continue
		}
		if lastSet && math.Abs(v-last) < 1e-9 {
			continue
		}
		out = append(out, v)
		last = v
		lastSet = true
	}
	return out
}

func sweepIntGenISISGridFor(name string) (sweepIntGenISISGrid, error) {
	switch name {
	case "", "wide":
		return sweepIntGenISISGrid{
			Name: "wide",
			Families: []sweepIntGenISISFamily{
				{Theta: 7, Rho: 1, EllPrime: 1},
				{Theta: 8, Rho: 1, EllPrime: 1},
				{Theta: 9, Rho: 1, EllPrime: 1},
				{Theta: 10, Rho: 1, EllPrime: 1},
				{Theta: 4, Rho: 2, EllPrime: 1},
				{Theta: 4, Rho: 2, EllPrime: 2},
				{Theta: 5, Rho: 2, EllPrime: 1},
				{Theta: 5, Rho: 2, EllPrime: 2},
				{Theta: 6, Rho: 2, EllPrime: 1},
				{Theta: 6, Rho: 2, EllPrime: 2},
				{Theta: 3, Rho: 3, EllPrime: 1},
				{Theta: 3, Rho: 3, EllPrime: 2},
				{Theta: 4, Rho: 3, EllPrime: 1},
				{Theta: 4, Rho: 3, EllPrime: 2},
				{Theta: 2, Rho: 4, EllPrime: 2},
				{Theta: 2, Rho: 4, EllPrime: 3},
				{Theta: 1, Rho: 7, EllPrime: 12},
				{Theta: 1, Rho: 7, EllPrime: 13},
				{Theta: 1, Rho: 8, EllPrime: 10},
				{Theta: 1, Rho: 8, EllPrime: 11},
				{Theta: 1, Rho: 9, EllPrime: 9},
			},
			NCols:       []int{8, 16, 32, 64, 128},
			LVCSNCols:   []int{8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 112, 128, 160, 192, 224, 256},
			Ell:         []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 26, 28},
			NLeavesBase: []int{4096, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144, 393216, 524288, 786432, 983040, 1048576},
			Shortness: []sweepIntGenISISShortness{
				{Radix: 11, Digits: 4},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
			},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeOutputAudit, PIOP.PRFCompanionModeDirectAuth},
			Compression: []int{0, 1, 2},
			Checkpoints: []int{2, 4, 8},
			EtaSlack:    3,
			MaxEta:      96,
			Notes: []string{
				"Wide grid searches ncols divisors of N up to 128 and includes theta>1 small-field families plus theta=1 baselines.",
				"nleaves candidates are generated near the exact round-4 boundary for each (lvcs_ncols, ell), then augmented with nearby powers/round values.",
			},
		}, nil
	case "quick":
		return sweepIntGenISISGrid{
			Name: "quick",
			Families: []sweepIntGenISISFamily{
				{Theta: 7, Rho: 1, EllPrime: 1},
				{Theta: 8, Rho: 1, EllPrime: 1},
				{Theta: 5, Rho: 2, EllPrime: 1},
				{Theta: 1, Rho: 7, EllPrime: 13},
				{Theta: 1, Rho: 8, EllPrime: 10},
			},
			NCols:       []int{16, 32, 64},
			LVCSNCols:   []int{32, 48, 64, 80, 96, 128},
			Ell:         []int{10, 11, 12, 14, 16, 20},
			NLeavesBase: []int{32768, 65536, 131072, 196608, 393216, 524288},
			Shortness: []sweepIntGenISISShortness{
				{Radix: 11, Digits: 4},
				{Radix: 7, Digits: 5},
			},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth, PIOP.PRFCompanionModeOutputAudit},
			Compression: []int{0, 1},
			Checkpoints: []int{2, 8},
			EtaSlack:    1,
			MaxEta:      72,
			Notes: []string{
				"Quick grid is a smoke-test subset of the wide grid and is not intended to find the global transcript minimum.",
			},
		}, nil
	case "strata", "stratified":
		return sweepIntGenISISGrid{
			Name: "strata",
			Families: []sweepIntGenISISFamily{
				{Theta: 7, Rho: 1, EllPrime: 1},
				{Theta: 8, Rho: 1, EllPrime: 1},
				{Theta: 9, Rho: 1, EllPrime: 1},
			},
			NCols:       []int{32, 64},
			LVCSNCols:   []int{32, 48, 64, 80, 96, 128, 160},
			Ell:         []int{8, 9, 10, 11, 12, 13, 14},
			NLeavesBase: []int{524288, 786432, 917504, 1048576},
			Shortness: []sweepIntGenISISShortness{
				{Radix: 11, Digits: 4},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
			},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth},
			Compression: []int{0, 1, 2, 3},
			Checkpoints: []int{2},
			EtaSlack:    1,
			MaxEta:      80,
			Notes: []string{
				"Stratified grid forces the transcript-reduction region: ncols 32/64, wider LVCS strata, theta 7/8/9, direct_auth PRF, and R11/L4 vs R7/L5 vs R5/L6 shortness.",
				"Use this after row pruning to measure whether lower shortness degree can offset extra digit rows.",
			},
		}, nil
	case "leafcap", "leafcap64k", "lowleaves", "low-leaves":
		return sweepIntGenISISGrid{
			Name: "leafcap64k",
			Families: []sweepIntGenISISFamily{
				{Theta: 7, Rho: 1, EllPrime: 1},
				{Theta: 8, Rho: 1, EllPrime: 1},
				{Theta: 9, Rho: 1, EllPrime: 1},
				{Theta: 10, Rho: 1, EllPrime: 1},
				{Theta: 5, Rho: 2, EllPrime: 1},
				{Theta: 6, Rho: 2, EllPrime: 1},
				{Theta: 4, Rho: 3, EllPrime: 1},
				{Theta: 1, Rho: 7, EllPrime: 12},
				{Theta: 1, Rho: 8, EllPrime: 10},
			},
			NCols:       []int{32, 64, 128},
			LVCSNCols:   []int{32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256},
			Ell:         []int{13, 14, 15, 16, 18, 20, 22, 24, 26, 28, 30, 32},
			NLeavesBase: []int{4096, 8192, 12288, 16384, 24576, 32768, 49152, 65536},
			Shortness: []sweepIntGenISISShortness{
				{Radix: 11, Digits: 4},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
			},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth},
			Compression: []int{1, 2, 3},
			Checkpoints: []int{2},
			EtaSlack:    2,
			MaxEta:      128,
			Notes: []string{
				"Leaf-cap grid forces the Eq. (8) round-4 tradeoff into larger ell rather than very large explicit domains.",
				"Use with the default -max-nleaves=65536, or set a stricter cap such as 32768 to search smaller Merkle domains.",
				"The grid assumes the optimized ternary M/s/e relation and prioritizes direct_auth with M/s/e compression.",
			},
		}, nil
	case "deep":
		return sweepIntGenISISDeepGrid()
	case "pack64", "ncols64", "wide64", "deep64":
		return sweepIntGenISISPackingGrid("pack64", []int{64}, []int{64, 72, 80, 96, 112, 128, 144, 160, 192, 224, 256, 288, 320, 384, 448, 512}, "Focused deep-style packing grid for ncols=64.")
	case "pack128", "ncols128", "wide128", "deep128":
		return sweepIntGenISISPackingGrid("pack128", []int{128}, []int{128, 144, 160, 192, 224, 256, 288, 320, 384, 448, 512}, "Focused deep-style packing grid for ncols=128.")
	case "pack256", "ncols256", "wide256", "deep256":
		return sweepIntGenISISPackingGrid("pack256", []int{256}, []int{256, 288, 320, 384, 448, 512}, "Focused deep-style packing grid for ncols=256.")
	case "packwide", "packing", "packing-deep", "deep-packing":
		return sweepIntGenISISPackingGrid("packwide", []int{64, 128, 256}, []int{64, 72, 80, 96, 112, 128, 144, 160, 192, 224, 256, 288, 320, 384, 448, 512}, "Combined deep-style packing grid for ncols=64/128/256.")
	case "pack96", "ncols96", "wide96", "deep96":
		return sweepIntGenISISGrid{}, fmt.Errorf("ncols=96 is not supported by the current profile-B IntGenISIS row layout because ring degree 512 is not divisible by 96; use pack64, pack128, pack256, or implement padded final-block packing first")
	default:
		return sweepIntGenISISGrid{}, fmt.Errorf("unknown IntGenISIS sweep grid %q (valid: quick, wide, deep, strata, leafcap64k, pack64, pack128, pack256, packwide)", name)
	}
}

func sweepIntGenISISDeepGrid() (sweepIntGenISISGrid, error) {
	g, _ := sweepIntGenISISGridFor("wide")
	g.Name = "deep"
	g.Families = append(g.Families,
		sweepIntGenISISFamily{Theta: 11, Rho: 1, EllPrime: 1},
		sweepIntGenISISFamily{Theta: 12, Rho: 1, EllPrime: 1},
		sweepIntGenISISFamily{Theta: 7, Rho: 2, EllPrime: 1},
		sweepIntGenISISFamily{Theta: 8, Rho: 2, EllPrime: 1},
		sweepIntGenISISFamily{Theta: 5, Rho: 3, EllPrime: 1},
		sweepIntGenISISFamily{Theta: 5, Rho: 3, EllPrime: 2},
		sweepIntGenISISFamily{Theta: 1, Rho: 7, EllPrime: 14},
		sweepIntGenISISFamily{Theta: 1, Rho: 8, EllPrime: 12},
		sweepIntGenISISFamily{Theta: 1, Rho: 9, EllPrime: 10},
	)
	g.Ell = []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 26, 28, 30, 32}
	g.LVCSNCols = []int{8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 112, 128, 144, 160, 192, 224, 256, 320}
	g.NLeavesBase = append(g.NLeavesBase, 589824, 655360, 917504)
	g.Compression = []int{0, 1, 2, 3}
	g.EtaSlack = 4
	g.MaxEta = 128
	g.Notes = append(g.Notes, "Deep grid adds high-theta, high-rho, and finer large-domain probes; expect a substantially larger analytic search.")
	return g, nil
}

func sweepIntGenISISPackingGrid(name string, ncols, lvcs []int, note string) (sweepIntGenISISGrid, error) {
	g, err := sweepIntGenISISDeepGrid()
	if err != nil {
		return sweepIntGenISISGrid{}, err
	}
	g.Name = name
	g.NCols = append([]int(nil), ncols...)
	g.LVCSNCols = append([]int(nil), lvcs...)
	g.PRFModes = []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth, PIOP.PRFCompanionModeOutputAudit}
	g.Checkpoints = []int{2, 4, 8}
	g.Notes = append(g.Notes,
		note,
		"Packing grids keep the deep theta/rho/ell_prime and ell coverage but force large ncols strata to expose DECS layer-boundary effects.",
		"ncols=96 is intentionally absent: current IntGenISIS coefficient/hat block layouts require ncols to divide ring degree 512.",
	)
	return g, nil
}

func sweepIntGenISISGridSummaryFromGrid(g sweepIntGenISISGrid) sweepIntGenISISGridSummary {
	return sweepIntGenISISGridSummary{
		Name:        g.Name,
		Families:    append([]sweepIntGenISISFamily(nil), g.Families...),
		NCols:       append([]int(nil), g.NCols...),
		LVCSNCols:   append([]int(nil), g.LVCSNCols...),
		Ell:         append([]int(nil), g.Ell...),
		NLeavesBase: append([]int(nil), g.NLeavesBase...),
		Shortness:   append([]sweepIntGenISISShortness(nil), g.Shortness...),
		Compression: append([]int(nil), g.Compression...),
		PRFModes:    append([]PIOP.PRFCompanionMode(nil), g.PRFModes...),
		Checkpoints: append([]int(nil), g.Checkpoints...),
		EtaSlack:    g.EtaSlack,
		MaxEta:      g.MaxEta,
		Notes:       append([]string(nil), g.Notes...),
	}
}

func sweepIntGenISISGenerateCandidates(profile credential.IntGenISISProfile, threshold float64, grid sweepIntGenISISGrid, limit int, maxNLeaves int) []sweepIntGenISISCandidate {
	if grid.EtaSlack < 0 {
		grid.EtaSlack = 0
	}
	if grid.MaxEta <= 0 {
		grid.MaxEta = 96
	}
	out := make([]sweepIntGenISISCandidate, 0, 256)
	cache := newSweepAnalyticCache()
	shortnessShapes := append([]sweepIntGenISISShortness(nil), grid.Shortness...)
	if len(shortnessShapes) == 0 {
		shortnessShapes = []sweepIntGenISISShortness{{Radix: 11, Digits: 4}}
	}
	compressionLevels := append([]int(nil), grid.Compression...)
	if len(compressionLevels) == 0 {
		compressionLevels = []int{0}
	}
	id := 0
	for _, fam := range grid.Families {
		for _, ncols := range grid.NCols {
			if profile.N%ncols != 0 {
				continue
			}
			issuanceNCols := ncols
			if issuanceNCols < 16 {
				issuanceNCols = 16
			}
			for _, lvcs := range grid.LVCSNCols {
				if lvcs < ncols || lvcs < issuanceNCols {
					continue
				}
				for _, ell := range grid.Ell {
					nLeavesList := sweepCachedNLeavesCandidates(profile, grid, lvcs, ell, threshold, maxNLeaves, cache)
					for _, nLeaves := range nLeavesList {
						baseIssuance := intGenISISTuning{
							NCols:     issuanceNCols,
							LVCSNCols: lvcs,
							NLeaves:   nLeaves,
							Theta:     fam.Theta,
							Rho:       fam.Rho,
							Ell:       ell,
							EllPrime:  fam.EllPrime,
						}
						baseShowing := intGenISISTuning{
							NCols:             ncols,
							LVCSNCols:         lvcs,
							NLeaves:           nLeaves,
							Theta:             fam.Theta,
							Rho:               fam.Rho,
							Ell:               ell,
							EllPrime:          fam.EllPrime,
							PRFCompanionMode:  PIOP.PRFCompanionModeOutputAudit,
							CheckpointSamples: 8,
						}
						minEta := sweepMinEta(profile, baseIssuance, threshold, grid.MaxEta, cache)
						if minEta <= 0 || minEta > grid.MaxEta {
							continue
						}
						for eta := minEta; eta <= minEta+grid.EtaSlack && eta <= grid.MaxEta; eta++ {
							issuance := baseIssuance
							showing := baseShowing
							issuance.Eta = eta
							showing.Eta = eta
							if sweepAnalyticEq8Bits(profile, issuance, "issuance", cache) < threshold {
								continue
							}
							for _, shape := range shortnessShapes {
								showingWithShape := showing
								showingWithShape.SigShortnessRadix = shape.Radix
								showingWithShape.SigShortnessDigits = shape.Digits
								if sweepAnalyticEq8Bits(profile, showingWithShape, "showing", cache) < threshold {
									continue
								}
								for _, mode := range grid.PRFModes {
									for _, samples := range grid.Checkpoints {
										for _, compression := range compressionLevels {
											showingWithPRF := showingWithShape
											showingWithPRF.PRFCompanionMode = mode
											showingWithPRF.CheckpointSamples = samples
											showingWithPRF.CompressedRows = compression
											if sweepAnalyticEq8Bits(profile, showingWithPRF, "showing", cache) < threshold {
												continue
											}
											id++
											out = append(out, sweepIntGenISISCandidate{
												ID:             fmt.Sprintf("cand_%05d", id),
												Issuance:       issuance,
												Showing:        showingWithPRF,
												HeuristicScore: sweepHeuristicScore(issuance, showingWithPRF),
											})
										}
									}
								}
							}
							out = sweepPruneCandidateFrontier(out, limit)
						}
					}
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return sweepCandidateLess(out[i], out[j]) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func newSweepAnalyticCache() *sweepAnalyticCache {
	return &sweepAnalyticCache{
		NLeaves: make(map[sweepNLeavesCacheKey][]int),
		LogComb: make(map[sweepLogCombCacheKey]float64),
		Round4:  make(map[sweepRound4CacheKey]float64),
		Raw3:    make(map[sweepRaw3CacheKey]float64),
	}
}

func sweepPruneCandidateFrontier(candidates []sweepIntGenISISCandidate, limit int) []sweepIntGenISISCandidate {
	if limit <= 0 || len(candidates) <= limit*8 {
		return candidates
	}
	sort.SliceStable(candidates, func(i, j int) bool { return sweepCandidateLess(candidates[i], candidates[j]) })
	return candidates[:limit]
}

func sweepCandidateLess(a, b sweepIntGenISISCandidate) bool {
	if a.HeuristicScore != b.HeuristicScore {
		return a.HeuristicScore < b.HeuristicScore
	}
	if a.Showing.LVCSNCols != b.Showing.LVCSNCols {
		return a.Showing.LVCSNCols < b.Showing.LVCSNCols
	}
	return a.Showing.NLeaves < b.Showing.NLeaves
}

func sweepPopulateAnalyticBudgets(profile credential.IntGenISISProfile, candidates []sweepIntGenISISCandidate) {
	for i := range candidates {
		candidates[i].AnalyticIssuance = sweepAnalyticSoundness(profile, candidates[i].Issuance, "issuance")
		candidates[i].AnalyticShowing = sweepAnalyticSoundness(profile, candidates[i].Showing, "showing")
	}
}

func sweepCachedNLeavesCandidates(profile credential.IntGenISISProfile, grid sweepIntGenISISGrid, lvcs, ell int, threshold float64, maxNLeaves int, cache *sweepAnalyticCache) []int {
	capLeaves := sweepMaxNLeaves(profile, maxNLeaves)
	key := sweepNLeavesCacheKey{
		LVCSNCols:      lvcs,
		Ell:            ell,
		ThresholdMilli: int(math.Round(threshold * 1000)),
		CapLeaves:      capLeaves,
	}
	if vals, ok := cache.NLeaves[key]; ok {
		return vals
	}
	vals := sweepNLeavesCandidates(profile, grid, lvcs, ell, threshold, capLeaves, cache)
	cache.NLeaves[key] = vals
	return vals
}

func sweepNLeavesCandidates(profile credential.IntGenISISProfile, grid sweepIntGenISISGrid, lvcs, ell int, threshold float64, capLeaves int, cache *sweepAnalyticCache) []int {
	minLeaves := sweepMinNLeavesForRound4(profile, lvcs, ell, threshold, capLeaves, cache)
	if minLeaves <= 0 {
		return nil
	}
	vals := make([]int, 0, 16)
	add := func(v int) {
		if v < minLeaves || v > capLeaves {
			return
		}
		vals = append(vals, v)
	}
	for _, factor := range []float64{1, 1.03, 1.06, 1.10, 1.18, 1.25, 1.50, 2.00} {
		add(roundUpInt(int(math.Ceil(float64(minLeaves)*factor)), 64))
	}
	add(roundUpInt(minLeaves, 1024))
	add(roundUpInt(minLeaves, 4096))
	for _, base := range grid.NLeavesBase {
		if base >= minLeaves && base <= capLeaves && base <= minLeaves*3 {
			add(base)
		}
	}
	if capLeaves <= minLeaves*2 {
		add(capLeaves)
	}
	return uniqueSortedInts(vals)
}

func sweepMaxNLeaves(profile credential.IntGenISISProfile, configuredMax int) int {
	capLeaves := int(profile.Q) - 1
	if capLeaves <= 0 {
		return 0
	}
	if capLeaves > 1<<20 {
		// Profile B has q=1054721. Keep generated domains below q while using the
		// tested 2^20 explicit-domain ceiling for large-boundary probes.
		capLeaves = 1 << 20
	}
	if configuredMax > 0 && configuredMax < capLeaves {
		capLeaves = configuredMax
	}
	return capLeaves
}

func sweepMinNLeavesForRound4(profile credential.IntGenISISProfile, lvcs, ell int, threshold float64, capLeaves int, cache *sweepAnalyticCache) int {
	if capLeaves <= 0 || ell <= 0 {
		return 0
	}
	lo := lvcs + ell
	if lo < ell+1 {
		lo = ell + 1
	}
	if lo < 2 {
		lo = 2
	}
	if lo > capLeaves {
		return 0
	}
	if sweepRound4Bits(profile, lvcs, ell, capLeaves, cache) < threshold {
		return 0
	}
	hi := capLeaves
	for lo < hi {
		mid := lo + (hi-lo)/2
		if sweepRound4Bits(profile, lvcs, ell, mid, cache) >= threshold {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

func sweepRound4Bits(profile credential.IntGenISISProfile, lvcs, ell, nLeaves int, cache *sweepAnalyticCache) float64 {
	_ = profile
	key := sweepRound4CacheKey{LVCSNCols: lvcs, Ell: ell, NLeaves: nLeaves}
	if cache != nil {
		if bits, ok := cache.Round4[key]; ok {
			return bits
		}
	}
	bits := sweepLogComb2Cached(cache, nLeaves, ell) - sweepLogComb2Cached(cache, lvcs+ell-1, ell)
	if cache != nil {
		cache.Round4[key] = bits
	}
	return bits
}

func uniqueSortedInts(vals []int) []int {
	if len(vals) == 0 {
		return nil
	}
	sort.Ints(vals)
	out := vals[:0]
	last := -1
	for _, v := range vals {
		if v <= 0 || v == last {
			continue
		}
		out = append(out, v)
		last = v
	}
	return out
}

func roundUpInt(v, multiple int) int {
	if multiple <= 1 {
		return v
	}
	rem := v % multiple
	if rem == 0 {
		return v
	}
	return v + multiple - rem
}

func sweepMinEta(profile credential.IntGenISISProfile, tuning intGenISISTuning, threshold float64, maxEta int, cache *sweepAnalyticCache) int {
	if maxEta <= 0 {
		maxEta = 128
	}
	qLog := math.Log2(float64(profile.Q))
	if qLog <= 0 {
		return 0
	}
	comb := sweepLogComb2Cached(cache, tuning.NLeaves, tuning.LVCSNCols+tuning.Ell+1)
	if math.IsInf(comb, -1) {
		return 0
	}
	eta := int(math.Ceil((threshold + comb) / qLog))
	if eta < 1 {
		eta = 1
	}
	for eta > 1 && sweepRound1Bits(profile, tuning, eta-1, cache) >= threshold {
		eta--
	}
	for eta <= maxEta && sweepRound1Bits(profile, tuning, eta, cache) < threshold {
		eta++
	}
	if eta > maxEta {
		return 0
	}
	return eta
}

func sweepRound1Bits(profile credential.IntGenISISProfile, tuning intGenISISTuning, eta int, cache *sweepAnalyticCache) float64 {
	if eta <= 0 {
		return math.Inf(-1)
	}
	return float64(eta)*math.Log2(float64(profile.Q)) - sweepLogComb2Cached(cache, tuning.NLeaves, tuning.LVCSNCols+tuning.Ell+1)
}

func sweepAnalyticEq8Bits(profile credential.IntGenISISProfile, tuning intGenISISTuning, kind string, cache *sweepAnalyticCache) float64 {
	ncols := tuning.NCols
	if ncols <= 0 {
		ncols = 16
	}
	lvcs := tuning.LVCSNCols
	if lvcs < ncols {
		lvcs = ncols
	}
	nLeaves := tuning.NLeaves
	if nLeaves <= 0 {
		nLeaves = ncols
	}
	ell := tuning.Ell
	if ell <= 0 {
		ell = 1
	}
	eta := tuning.Eta
	if eta <= 0 {
		eta = 1
	}
	rho := tuning.Rho
	if rho <= 0 {
		rho = 1
	}
	theta := tuning.Theta
	if theta <= 0 {
		theta = 1
	}
	ellPrime := tuning.EllPrime
	if ellPrime <= 0 {
		ellPrime = 1
	}
	qLog := math.Log2(float64(profile.Q))
	raw1 := float64(eta)*qLog - sweepLogComb2Cached(cache, nLeaves, lvcs+ell+1)
	raw2 := float64(rho) * qLog
	if theta > 1 {
		raw2 = float64(theta*rho) * qLog
	}
	analyticDQ := sweepAnalyticDQ(tuning, kind)
	raw3 := math.Inf(1)
	if analyticDQ >= ellPrime {
		raw3 = sweepRaw3Bits(profile, ncols, theta, ellPrime, analyticDQ, cache)
		if math.IsInf(raw3, -1) {
			raw3 = math.Inf(1)
		}
	}
	raw4 := sweepRound4Bits(profile, lvcs, ell, nLeaves, cache)
	total := sweepBitsToProbability(raw1) + sweepBitsToProbability(raw2) + sweepBitsToProbability(raw3) + sweepBitsToProbability(raw4)
	if total <= 0 {
		total = math.SmallestNonzeroFloat64
	}
	if total > 1 {
		total = 1
	}
	return -math.Log2(total)
}

func sweepRaw3Bits(profile credential.IntGenISISProfile, ncols, theta, ellPrime, analyticDQ int, cache *sweepAnalyticCache) float64 {
	key := sweepRaw3CacheKey{NCols: ncols, Theta: theta, EllPrime: ellPrime, DQ: analyticDQ}
	if cache != nil {
		if bits, ok := cache.Raw3[key]; ok {
			return bits
		}
	}
	fieldSize := float64(profile.Q)
	if theta > 1 {
		fieldSize = math.Pow(float64(profile.Q), float64(theta))
	}
	sSize := fieldSize - float64(ncols)
	if sSize < 1 {
		sSize = 1
	}
	bits := sweepLogComb2(sSize, ellPrime) - sweepLogComb2Cached(cache, analyticDQ, ellPrime)
	if cache != nil {
		cache.Raw3[key] = bits
	}
	return bits
}

func sweepBitsToProbability(rawBits float64) float64 {
	if math.IsInf(rawBits, 1) {
		return 0
	}
	if math.IsInf(rawBits, -1) || rawBits < 0 {
		rawBits = 0
	}
	return math.Pow(2, -rawBits)
}

func sweepLogComb2Cached(cache *sweepAnalyticCache, n, k int) float64 {
	key := sweepLogCombCacheKey{N: n, K: k}
	if cache != nil {
		if bits, ok := cache.LogComb[key]; ok {
			return bits
		}
	}
	bits := sweepLogComb2(float64(n), k)
	if cache != nil {
		cache.LogComb[key] = bits
	}
	return bits
}

func sweepLogComb2(n float64, k int) float64 {
	if k < 0 || float64(k) > n {
		return math.Inf(-1)
	}
	if k == 0 || float64(k) == n {
		return 0
	}
	if k <= 64 {
		sum := 0.0
		for i := 0; i < k; i++ {
			sum += math.Log2(n-float64(i)) - math.Log2(float64(i+1))
		}
		return sum
	}
	lgN, signN := math.Lgamma(n + 1)
	lgK, signK := math.Lgamma(float64(k) + 1)
	lgNK, signNK := math.Lgamma(n - float64(k) + 1)
	if signN <= 0 || signK <= 0 || signNK <= 0 {
		return math.Inf(-1)
	}
	return (lgN - lgK - lgNK) / math.Ln2
}

func sweepAnalyticSoundness(profile credential.IntGenISISProfile, tuning intGenISISTuning, kind string) PIOP.SoundnessBudget {
	ncols := tuning.NCols
	if ncols <= 0 {
		ncols = 16
	}
	lvcs := tuning.LVCSNCols
	if lvcs < ncols {
		lvcs = ncols
	}
	rows := 0
	inv, err := PIOP.BuildIntGenISISRowInventory(profile.Name, ncols)
	if err == nil {
		switch kind {
		case "issuance":
			rows = inv.PreSignRows
		case "showing":
			rowsPerPoly := profile.N / ncols
			shortDigits := tuning.SigShortnessDigits
			if shortDigits <= 0 {
				shortDigits = 4
			}
			mseSourceRows := (profile.EllM + profile.KS + profile.NC) * rowsPerPoly
			mseRows := mseSourceRows
			if tuning.CompressedRows > 0 {
				pack := tuning.CompressedRows + 1
				mseRows = 0
				for _, sourceRows := range []int{profile.EllM * rowsPerPoly, profile.KS * rowsPerPoly, profile.NC * rowsPerPoly} {
					mseRows += (sourceRows + pack - 1) / pack
				}
			}
			coeffViewRows := profile.SignaturePreimageLen*rowsPerPoly + mseRows + rowsPerPoly
			hatPolys := profile.SignaturePreimageLen + 1 + profile.EllMuSig + profile.EllX0 + profile.EllX1 + 1
			rows = coeffViewRows + hatPolys*rowsPerPoly + profile.SignaturePreimageLen*rowsPerPoly*shortDigits + 7
		}
	}
	if rows <= 0 {
		rows = profile.N / ncols
	}
	opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential: true,
		RingDegree: profile.N,
		NCols:      ncols,
		LVCSNCols:  lvcs,
		NLeaves:    tuning.NLeaves,
		Ell:        tuning.Ell,
		EllPrime:   tuning.EllPrime,
		Eta:        tuning.Eta,
		Theta:      tuning.Theta,
		Rho:        tuning.Rho,
		Kappa:      tuning.Kappa,
		DomainMode: PIOP.DomainModeExplicit,
	})
	analyticDQ := sweepAnalyticDQ(tuning, kind)
	return PIOP.ComputeSoundnessBudgetForParams(opts, profile.Q, analyticDQ, ncols, lvcs, tuning.NLeaves, rows)
}

func sweepAnalyticDQ(tuning intGenISISTuning, kind string) int {
	ncols := tuning.NCols
	if ncols <= 0 {
		ncols = 16
	}
	ell := tuning.Ell
	if ell <= 0 {
		ell = 1
	}
	par, agg := sweepRelationDegrees(tuning, kind)
	return sweepComputeDQFromDegrees(par, agg, ncols, ell)
}

func sweepRelationDegrees(tuning intGenISISTuning, kind string) (parallel, aggregated int) {
	switch kind {
	case "issuance":
		return 3, 1
	case "showing":
		radix := tuning.SigShortnessRadix
		if radix <= 0 {
			radix = 11
		}
		compressionMembership := 3
		compressionDecode := 0
		if tuning.CompressedRows > 0 {
			pack := tuning.CompressedRows + 1
			alphabet := 1
			for i := 0; i < pack; i++ {
				alphabet *= 3
			}
			compressionMembership = alphabet
			compressionDecode = alphabet - 1
		}
		return maxIntMain(maxIntMain(maxIntMain(2, 3), radix), compressionMembership), maxIntMain(2, compressionDecode)
	default:
		return 3, 1
	}
}

func sweepComputeDQFromDegrees(d, dPrime, s, ell int) int {
	if s <= 0 {
		s = 1
	}
	if ell <= 0 {
		ell = 1
	}
	span := ell + s - 1
	c1 := d*span + (s - 1)
	c2 := dPrime * span
	if c1 >= c2 {
		return c1
	}
	return c2
}

func maxIntMain(a, b int) int {
	if a >= b {
		return a
	}
	return b
}

func sweepHeuristicScore(issuance, showing intGenISISTuning) float64 {
	modePenalty := 0.0
	if showing.PRFCompanionMode == PIOP.PRFCompanionModeDirectAuth {
		modePenalty = -20
	}
	shortDigits := showing.SigShortnessDigits
	if shortDigits <= 0 {
		shortDigits = 4
	}
	shortRadix := showing.SigShortnessRadix
	if shortRadix <= 0 {
		shortRadix = 11
	}
	shortnessPenalty := float64(shortDigits-4)*600 - float64(11-shortRadix)*120
	widthPenalty := float64(512/showing.NCols) * 450
	if showing.NCols > 32 {
		widthPenalty += float64(showing.NCols-32) * 180
	}
	compressionPenalty := 0.0
	if showing.CompressedRows > 0 {
		pack := showing.CompressedRows + 1
		compressionPenalty = -float64(512/showing.NCols) * float64(pack-1) * 240
		if pack >= 3 {
			compressionPenalty += float64(pack*pack) * 400
		}
	}
	showDQ := sweepAnalyticDQ(showing, "showing")
	issuanceDQ := sweepAnalyticDQ(issuance, "issuance")
	dqPenalty := float64(showDQ)*7 + float64(issuanceDQ)*0.75
	return float64(showing.LVCSNCols)*5 +
		float64(showing.NLeaves)/4096 +
		float64(showing.Ell)*250 +
		float64(showing.EllPrime)*250 +
		float64(showing.Theta*showing.Rho)*80 +
		widthPenalty +
		shortnessPenalty +
		compressionPenalty +
		dqPenalty +
		float64(showing.CheckpointSamples)*25 +
		float64(issuance.LVCSNCols)*0.5 +
		modePenalty
}

func sweepIntGenISISPreSignMetrics(paths benchmarkIntGenISISE2EArtifacts, tuning intGenISISTuning) (benchmarkIntGenISISMetrics, error) {
	var secret holderSecretFile
	if err := readJSONFile(paths.HolderSecret, &secret); err != nil {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("read holder secret: %w", err)
	}
	var req commitRequestFile
	if err := readJSONFile(paths.CommitRequest, &req); err != nil {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("read commit request: %w", err)
	}
	rt, err := loadIssuanceRuntime(secret.CredentialPublicPath, secret.PRFParamsPath, intGenISISTuningToIssuanceOverrides(tuning, 0))
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	inputs, err := intGenISISInputsFromSecret(rt.ringQ, secret)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	com, err := issuanceCommitFromRequest(rt.ringQ, req)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	cm, as, err := intGenISISCommitmentMatricesNTT(rt.ringQ, rt.public)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
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
	proveStart := time.Now()
	proof, err := PIOP.BuildIntGenISISPreSign(rt.ringQ, pub, PIOP.WitnessInputs{
		M:     inputs.M,
		MAttr: inputs.MAttr,
		K:     inputs.K,
		S:     inputs.S,
		E:     inputs.E,
	}, rt.opts)
	proveDur := time.Since(proveStart)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	verifyStart := time.Now()
	ok, err := PIOP.VerifyIntGenISISPreSign(pub, proof, rt.opts)
	verifyDur := time.Since(verifyStart)
	if err != nil || !ok {
		return benchmarkIntGenISISMetrics{}, fmt.Errorf("verify measured pre-sign: ok=%v err=%v", ok, err)
	}
	rep, err := PIOP.BuildProofReport(proof, rt.opts, rt.ringQ)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	return intGenISISMetricsFromProof(proof, rep, pub, rt.opts, proveDur, verifyDur, "sweep_presign"), nil
}

func issuanceCommitFromRequest(ringQ *ring.Ring, req commitRequestFile) ([]*ring.Poly, error) {
	if err := validateInt64RowsExact("commit_request.com", req.Com, int(ringQ.N)); err != nil {
		return nil, err
	}
	return polyVecFromInt64(ringQ, req.Com, true), nil
}
