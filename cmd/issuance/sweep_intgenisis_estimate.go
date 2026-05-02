package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"
)

const (
	sweepIntGenISISEstimateVersion = 1
	sweepEstimateDefaultGrid       = "estimate-deep"
	sweepEstimateDefaultMinBits    = 88.0
	sweepEstimateMaxKappaPerRound  = 0
	sweepEstimateMaxRecordedTuples = 2000
	sweepEstimatePRFGroupRounds    = 2
)

var sweepEstimatePRFParamsCache struct {
	once   sync.Once
	params *prf.Params
	err    error
}

type sweepIntGenISISEstimateConfig struct {
	Profiles         []string
	Grid             string
	OutDir           string
	Force            bool
	SoundnessMin     float64
	SoundnessMax     float64
	MaxShowingBytes  int
	MaxNLeaves       int
	TopK             int
	Progress         bool
	ProgressEvery    int
	CheckpointEvery  int
	MaxKappaPerRound int

	NCols          []int
	LVCSNCols      []int
	Ell            []int
	NLeavesBase    []int
	Families       []sweepIntGenISISFamily
	Shortness      []sweepIntGenISISShortness
	Compression    []int
	Projection     []string
	PRFModes       []PIOP.PRFCompanionMode
	PRFGroupRounds []int
	Checkpoints    []int
	Kappa          [][4]int
}

type sweepIntGenISISEstimateCandidate struct {
	ID                     string                     `json:"id"`
	Profile                string                     `json:"profile"`
	RingDegree             int                        `json:"ring_degree"`
	Q                      uint64                     `json:"q"`
	Issuance               intGenISISTuning           `json:"issuance"`
	Showing                intGenISISTuning           `json:"showing"`
	IssuanceMetrics        benchmarkIntGenISISMetrics `json:"issuance_metrics"`
	ShowingMetrics         benchmarkIntGenISISMetrics `json:"showing_metrics"`
	CandidateTheoremBits   float64                    `json:"candidate_theorem_bits"`
	CandidateEq8Bits       float64                    `json:"candidate_eq8_bits"`
	ShowingTranscriptBytes int                        `json:"showing_paper_transcript_bytes"`
	TotalTranscriptBytes   int                        `json:"total_paper_transcript_bytes"`
}

type sweepIntGenISISEstimateRejectedCounts struct {
	InvalidGeometry     int `json:"invalid_geometry"`
	RadixCapacity       int `json:"radix_capacity"`
	NLeavesCap          int `json:"nleaves_cap"`
	SoundnessLow        int `json:"soundness_low"`
	SoundnessHigh       int `json:"soundness_high"`
	TranscriptCap       int `json:"transcript_cap"`
	EstimatorError      int `json:"estimator_error"`
	GeneratedCandidates int `json:"generated_candidates"`
	AcceptedCandidates  int `json:"accepted_candidates"`
}

type sweepIntGenISISEstimateReport struct {
	Version           int                                     `json:"version"`
	Generated         string                                  `json:"generated_at"`
	Grid              sweepIntGenISISGridSummary              `json:"grid"`
	Profiles          []string                                `json:"profiles"`
	SoundnessMetric   string                                  `json:"soundness_metric"`
	SoundnessMin      float64                                 `json:"soundness_min_bits"`
	SoundnessMax      float64                                 `json:"soundness_max_bits"`
	MaxShowingBytes   int                                     `json:"max_showing_paper_transcript_bytes"`
	MaxNLeaves        int                                     `json:"max_nleaves"`
	AcceptedCount     int                                     `json:"accepted_count"`
	Rejected          sweepIntGenISISEstimateRejectedCounts   `json:"rejected_counts"`
	FrontierAll       []sweepIntGenISISEstimateCandidate      `json:"frontier_all"`
	Frontier96        []sweepIntGenISISEstimateCandidate      `json:"frontier_96"`
	Frontier128       []sweepIntGenISISEstimateCandidate      `json:"frontier_128"`
	EstimatorNotes    []string                                `json:"estimator_notes"`
	ValidationTargets []sweepIntGenISISEstimatorValidationRef `json:"validation_targets"`
}

type sweepIntGenISISEstimatorValidationRef struct {
	Name                 string  `json:"name"`
	ExpectedShowingBytes int     `json:"expected_showing_bytes,omitempty"`
	ExpectedDQ           int     `json:"expected_dq,omitempty"`
	ExpectedTheoremBits  float64 `json:"expected_theorem_bits,omitempty"`
	Notes                string  `json:"notes,omitempty"`
}

type sweepIntGenISISEstimateProgress struct {
	StartedAt           string                                `json:"started_at"`
	UpdatedAt           string                                `json:"updated_at"`
	ElapsedSeconds      float64                               `json:"elapsed_seconds"`
	OutDir              string                                `json:"out_dir"`
	Current             string                                `json:"current,omitempty"`
	OuterDone           int                                   `json:"outer_done"`
	OuterTotal          int                                   `json:"outer_total"`
	Percent             float64                               `json:"percent"`
	GeneratedCandidates int                                   `json:"generated_candidates"`
	AcceptedCandidates  int                                   `json:"accepted_candidates"`
	RejectedCounts      sweepIntGenISISEstimateRejectedCounts `json:"rejected_counts"`
	CandidatesPerSecond float64                               `json:"candidates_per_second"`
	Best                *sweepIntGenISISEstimateCandidate     `json:"best,omitempty"`
}

type sweepEstimateGeometry struct {
	Rows                  int
	PRFRows               int
	BoundRows             int
	ShortnessRows         int
	HatRows               int
	CoefficientViewRows   int
	UCoefficientViewRows  int
	SemanticViewRows      int
	CommitmentViewRows    int
	YCoefficientViewRows  int
	IssuerViewRows        int
	YHatRows              int
	SourceBridge          int
	UBridge               int
	CommitmentBridge      int
	YLinear               int
	IssuerBridge          int
	ProjectedSignature    int
	PRFKeyBridge          int
	FparInt               int
	Range                 int
	ShortnessConstraints  int
	TernaryRows           int
	CompressedRows        int
	MSECompressionLevel   int
	MSECompressionPack    int
	MSECompressionDegree  int
	SmallFieldReplayRows  int
	MaskRows              int
	QSplitRows            int
	QLimbRows             int
	DDECS                 int
	ParallelAlgDegree     int
	AggregatedAlgDegree   int
	DominantDegreeSource  string
	PaperConservativeDQ   int
	MaskDegreeBound       int
	ProofReportBucketHint int
}

func runSweepIntGenISISEstimate(args []string) error {
	fs := flag.NewFlagSet("sweep-intgenisis-estimate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profilesCSV := fs.String("profiles", credential.ProfileIntGenISISA+","+credential.ProfileIntGenISISB, "comma-separated IntGenISIS profiles to estimate")
	gridName := fs.String("grid", sweepEstimateDefaultGrid, "estimate grid preset")
	outDir := fs.String("out-dir", filepath.Join("credential", "issuance", "intgenisis_estimate_sweeps", "run_"+time.Now().UTC().Format("20060102_150405")), "directory for estimate artifacts")
	force := fs.Bool("force", false, "overwrite files in out-dir")
	soundnessMin := fs.Float64("soundness-min", sweepEstimateDefaultMinBits, "minimum candidate Theorem 9 bits, using min(issuance, showing)")
	soundnessMax := fs.Float64("soundness-max", 135, "maximum candidate Theorem 9 bits, using min(issuance, showing)")
	maxShowingBytes := fs.Int("max-showing-bytes", 50000, "maximum estimated showing paper transcript bytes")
	maxNLeaves := fs.Int("max-nleaves", 1<<20, "maximum generated explicit-domain leaves; 0 disables the cap below q")
	topK := fs.Int("top-k", 500, "number of candidates to keep in each frontier output")
	maxKappaPerRound := fs.Int("max-kappa-per-round", sweepEstimateMaxKappaPerRound, "maximum grinding bits per SmallWood theorem round; estimate sweeps default to zero-grinding candidates only")
	progress := fs.Bool("progress", true, "print a terminal progress bar while estimating")
	progressInterval := fs.Int("progress-interval", 1000, "outer grid points between terminal progress updates; 0 disables terminal progress")
	checkpointInterval := fs.Int("checkpoint-interval", 5000, "outer grid points between progressive checkpoint writes; 0 disables checkpoints except final")
	ncolsCSV := fs.String("ncols", "", "optional comma-separated ncols override")
	lvcsCSV := fs.String("lvcs-ncols", "", "optional comma-separated lvcs_ncols override")
	ellCSV := fs.String("ell", "", "optional comma-separated ell override")
	nleavesCSV := fs.String("nleaves", "", "optional comma-separated nleaves base override")
	thetaCSV := fs.String("theta", "", "optional comma-separated theta override; used with rho and ell-prime cross product")
	rhoCSV := fs.String("rho", "", "optional comma-separated rho override; used with theta and ell-prime cross product")
	ellPrimeCSV := fs.String("ell-prime", "", "optional comma-separated ell-prime override; used with theta and rho cross product")
	shortnessCSV := fs.String("shortness", "11/4,7/5,5/6", "comma-separated signed-radix shapes R/L")
	compressionCSV := fs.String("compression-levels", "", "optional comma-separated M/s/e compression levels")
	projectionCSV := fs.String("projection-modes", "", "optional comma-separated projection modes")
	prfModesCSV := fs.String("prf-companion-modes", string(PIOP.PRFCompanionModeDirectAuth), "comma-separated PRF companion modes: direct_auth, output_audit, aux_instance")
	prfGroupRoundsCSV := fs.String("prf-group-rounds", strconv.Itoa(sweepEstimatePRFGroupRounds), "comma-separated grouped PRF round counts")
	checkpointSamplesCSV := fs.String("prf-checkpoint-samples", "2", "comma-separated PRF companion checkpoint sample counts")
	kappaCSV := fs.String("kappa-tuples", "", "optional comma-separated kappa tuples k1/k2/k3/k4")
	if err := fs.Parse(args); err != nil {
		return err
	}
	profiles, err := parseStringCSV(*profilesCSV)
	if err != nil {
		return fmt.Errorf("parse -profiles: %w", err)
	}
	grid, err := sweepIntGenISISEstimateGridFor(*gridName)
	if err != nil {
		return err
	}
	if *ncolsCSV != "" {
		grid.NCols, err = parseIntCSV(*ncolsCSV)
		if err != nil {
			return fmt.Errorf("parse -ncols: %w", err)
		}
	}
	if *lvcsCSV != "" {
		grid.LVCSNCols, err = parseIntCSV(*lvcsCSV)
		if err != nil {
			return fmt.Errorf("parse -lvcs-ncols: %w", err)
		}
	}
	if *ellCSV != "" {
		grid.Ell, err = parseIntCSV(*ellCSV)
		if err != nil {
			return fmt.Errorf("parse -ell: %w", err)
		}
	}
	if *nleavesCSV != "" {
		grid.NLeavesBase, err = parseIntCSV(*nleavesCSV)
		if err != nil {
			return fmt.Errorf("parse -nleaves: %w", err)
		}
	}
	if *thetaCSV != "" || *rhoCSV != "" || *ellPrimeCSV != "" {
		thetas := []int{1}
		rhos := []int{1}
		ellPrimes := []int{1}
		if *thetaCSV != "" {
			thetas, err = parseIntCSV(*thetaCSV)
			if err != nil {
				return fmt.Errorf("parse -theta: %w", err)
			}
		}
		if *rhoCSV != "" {
			rhos, err = parseIntCSV(*rhoCSV)
			if err != nil {
				return fmt.Errorf("parse -rho: %w", err)
			}
		}
		if *ellPrimeCSV != "" {
			ellPrimes, err = parseIntCSV(*ellPrimeCSV)
			if err != nil {
				return fmt.Errorf("parse -ell-prime: %w", err)
			}
		}
		grid.Families = sweepFamiliesFromAxes(thetas, rhos, ellPrimes)
	}
	grid.Shortness, err = parseSweepShortnessCSV(*shortnessCSV)
	if err != nil {
		return fmt.Errorf("parse -shortness: %w", err)
	}
	if *compressionCSV != "" {
		grid.Compression, err = parseNonNegativeIntCSV(*compressionCSV)
		if err != nil {
			return fmt.Errorf("parse -compression-levels: %w", err)
		}
	}
	projectionModes := []string{PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2}
	if *projectionCSV != "" {
		projectionModes, err = parseStringCSV(*projectionCSV)
		if err != nil {
			return fmt.Errorf("parse -projection-modes: %w", err)
		}
	}
	prfModes, err := parsePRFCompanionModeCSV(*prfModesCSV)
	if err != nil {
		return fmt.Errorf("parse -prf-companion-modes: %w", err)
	}
	prfGroupRounds, err := parseIntCSV(*prfGroupRoundsCSV)
	if err != nil {
		return fmt.Errorf("parse -prf-group-rounds: %w", err)
	}
	checkpoints, err := parseIntCSV(*checkpointSamplesCSV)
	if err != nil {
		return fmt.Errorf("parse -prf-checkpoint-samples: %w", err)
	}
	kappas := defaultSweepEstimateKappas()
	if *kappaCSV != "" {
		kappas, err = parseKappaTuplesCSV(*kappaCSV)
		if err != nil {
			return fmt.Errorf("parse -kappa-tuples: %w", err)
		}
	}
	if *maxKappaPerRound < 0 || *maxKappaPerRound > sweepEstimateMaxKappaPerRound {
		return fmt.Errorf("-max-kappa-per-round must be in [0,%d]", sweepEstimateMaxKappaPerRound)
	}
	if err := validateSweepKappas(kappas, *maxKappaPerRound); err != nil {
		return err
	}
	cfg := sweepIntGenISISEstimateConfig{
		Profiles:         profiles,
		Grid:             grid.Name,
		OutDir:           *outDir,
		Force:            *force,
		SoundnessMin:     *soundnessMin,
		SoundnessMax:     *soundnessMax,
		MaxShowingBytes:  *maxShowingBytes,
		MaxNLeaves:       *maxNLeaves,
		TopK:             *topK,
		Progress:         *progress,
		ProgressEvery:    *progressInterval,
		CheckpointEvery:  *checkpointInterval,
		MaxKappaPerRound: *maxKappaPerRound,
		NCols:            grid.NCols,
		LVCSNCols:        grid.LVCSNCols,
		Ell:              grid.Ell,
		NLeavesBase:      grid.NLeavesBase,
		Families:         grid.Families,
		Shortness:        grid.Shortness,
		Compression:      grid.Compression,
		Projection:       projectionModes,
		PRFModes:         prfModes,
		PRFGroupRounds:   prfGroupRounds,
		Checkpoints:      checkpoints,
		Kappa:            kappas,
	}
	report, err := sweepIntGenISISEstimate(cfg)
	if err != nil {
		return err
	}
	if len(report.FrontierAll) > 0 {
		best := report.FrontierAll[0]
		fmt.Printf("[issuance-cli] estimate sweep best profile=%s bits=%.2f showing_bytes=%d ncols=%d lvcs=%d nleaves=%d theta=%d rho=%d ell=%d ell'=%d short=%d/%d comp=%d projection=%s prf_mode=%s prf_group_rounds=%d prf_samples=%d\n",
			best.Profile,
			displayBits(best.CandidateTheoremBits),
			best.ShowingTranscriptBytes,
			best.Showing.NCols,
			best.Showing.LVCSNCols,
			best.Showing.NLeaves,
			best.Showing.Theta,
			best.Showing.Rho,
			best.Showing.Ell,
			best.Showing.EllPrime,
			best.Showing.SigShortnessRadix,
			best.Showing.SigShortnessDigits,
			best.Showing.CompressedRows,
			best.Showing.ReplayProjection,
			best.Showing.PRFCompanionMode,
			best.Showing.PRFGroupRounds,
			best.Showing.CheckpointSamples,
		)
	}
	return nil
}

func sweepIntGenISISEstimate(cfg sweepIntGenISISEstimateConfig) (sweepIntGenISISEstimateReport, error) {
	if cfg.SoundnessMin <= 0 {
		cfg.SoundnessMin = sweepEstimateDefaultMinBits
	}
	if cfg.SoundnessMax <= 0 {
		cfg.SoundnessMax = 135
	}
	if cfg.SoundnessMax < cfg.SoundnessMin {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("soundness-max %.2f below soundness-min %.2f", cfg.SoundnessMax, cfg.SoundnessMin)
	}
	if cfg.MaxShowingBytes <= 0 {
		cfg.MaxShowingBytes = 50000
	}
	if cfg.TopK <= 0 {
		cfg.TopK = 500
	}
	if cfg.TopK > sweepEstimateMaxRecordedTuples {
		cfg.TopK = sweepEstimateMaxRecordedTuples
	}
	if cfg.ProgressEvery < 0 {
		cfg.ProgressEvery = 0
	}
	if cfg.CheckpointEvery < 0 {
		cfg.CheckpointEvery = 0
	}
	if cfg.MaxKappaPerRound == 0 && len(cfg.Kappa) == 0 {
		cfg.MaxKappaPerRound = sweepEstimateMaxKappaPerRound
	}
	if cfg.MaxKappaPerRound < 0 {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("max kappa per round must be non-negative")
	}
	if cfg.MaxKappaPerRound > sweepEstimateMaxKappaPerRound {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("max kappa per round %d exceeds IntGenISIS cap %d", cfg.MaxKappaPerRound, sweepEstimateMaxKappaPerRound)
	}
	if err := validateSweepKappas(cfg.Kappa, cfg.MaxKappaPerRound); err != nil {
		return sweepIntGenISISEstimateReport{}, err
	}
	if len(cfg.PRFGroupRounds) == 0 {
		cfg.PRFGroupRounds = []int{sweepEstimatePRFGroupRounds}
	}
	if len(cfg.PRFModes) == 0 {
		cfg.PRFModes = []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth}
	}
	for _, mode := range cfg.PRFModes {
		if !validSweepPRFCompanionMode(mode) {
			return sweepIntGenISISEstimateReport{}, fmt.Errorf("invalid PRF companion mode=%q", mode)
		}
	}
	for _, groupRounds := range cfg.PRFGroupRounds {
		if groupRounds < 2 {
			return sweepIntGenISISEstimateReport{}, fmt.Errorf("invalid PRF group rounds=%d: live IntGenISIS showing requires grouped PRF rounds >=2", groupRounds)
		}
	}
	if len(cfg.Checkpoints) == 0 {
		cfg.Checkpoints = []int{2}
	}
	for _, samples := range cfg.Checkpoints {
		if samples <= 0 {
			return sweepIntGenISISEstimateReport{}, fmt.Errorf("invalid PRF checkpoint samples=%d", samples)
		}
	}
	if cfg.OutDir == "" {
		cfg.OutDir = filepath.Join("credential", "issuance", "intgenisis_estimate_sweeps", "run_"+time.Now().UTC().Format("20060102_150405"))
	}
	if err := prepareEstimateOutDir(cfg.OutDir, cfg.Force); err != nil {
		return sweepIntGenISISEstimateReport{}, err
	}

	grid := sweepIntGenISISGrid{
		Name:        cfg.Grid,
		Families:    cfg.Families,
		NCols:       cfg.NCols,
		LVCSNCols:   cfg.LVCSNCols,
		Ell:         cfg.Ell,
		NLeavesBase: cfg.NLeavesBase,
		Shortness:   cfg.Shortness,
		Compression: cfg.Compression,
		PRFModes:    append([]PIOP.PRFCompanionMode(nil), cfg.PRFModes...),
		PRFGroups:   append([]int(nil), cfg.PRFGroupRounds...),
		Checkpoints: append([]int(nil), cfg.Checkpoints...),
		EtaSlack:    4,
		MaxEta:      160,
		Notes: []string{
			"Estimate-only grid: no proof generation, no key generation, no mutable issuance artifacts.",
			"Filtering uses SmallWood Theorem 9 with candidate_bits=min(issuance,showing).",
		},
	}
	gridConfig := sweepIntGenISISGridSummaryFromGrid(grid)
	gridConfigPayload := struct {
		sweepIntGenISISGridSummary
		Profiles          []string `json:"profiles"`
		ProjectionModes   []string `json:"projection_modes"`
		KappaTuples       []string `json:"kappa_tuples"`
		MaxKappaPerRound  int      `json:"max_kappa_per_round"`
		SoundnessMetric   string   `json:"soundness_metric"`
		SoundnessMinBits  float64  `json:"soundness_min_bits"`
		SoundnessMaxBits  float64  `json:"soundness_max_bits"`
		MaxShowingBytes   int      `json:"max_showing_paper_transcript_bytes"`
		Progress          bool     `json:"progress"`
		ProgressEvery     int      `json:"progress_interval_outer_points"`
		CheckpointEvery   int      `json:"checkpoint_interval_outer_points"`
		NoProofGeneration bool     `json:"no_proof_generation"`
		KappaSelection    string   `json:"kappa_selection"`
	}{
		sweepIntGenISISGridSummary: gridConfig,
		Profiles:                   append([]string(nil), cfg.Profiles...),
		ProjectionModes:            append([]string(nil), cfg.Projection...),
		KappaTuples:                kappaTupleStrings(cfg.Kappa),
		MaxKappaPerRound:           cfg.MaxKappaPerRound,
		SoundnessMetric:            "smallwood_theorem9_min_issuance_showing",
		SoundnessMinBits:           cfg.SoundnessMin,
		SoundnessMaxBits:           cfg.SoundnessMax,
		MaxShowingBytes:            cfg.MaxShowingBytes,
		Progress:                   cfg.Progress,
		ProgressEvery:              cfg.ProgressEvery,
		CheckpointEvery:            cfg.CheckpointEvery,
		NoProofGeneration:          true,
		KappaSelection:             "zero_grinding_only_v1",
	}
	if err := writeJSONFile(filepath.Join(cfg.OutDir, "grid_config.json"), gridConfigPayload, 0o644); err != nil {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("write grid_config.json: %w", err)
	}

	rejected := sweepIntGenISISEstimateRejectedCounts{}
	accepted := make([]sweepIntGenISISEstimateCandidate, 0, cfg.TopK)
	cache := newSweepAnalyticCache()
	id := 0
	maxKappa1, maxKappa4 := maxKappaByRound(cfg.Kappa)
	leafThreshold := math.Max(1, cfg.SoundnessMin-float64(maxKappa4))
	etaThreshold := math.Max(1, cfg.SoundnessMin-float64(maxKappa1))
	started := time.Now()
	outerTotal := estimateOuterGridTotal(cfg)
	outerDone := 0
	progressCurrent := ""
	writeCheckpoint := func(final bool) error {
		if !final && cfg.CheckpointEvery == 0 {
			return nil
		}
		if !final && cfg.CheckpointEvery > 0 && outerDone%cfg.CheckpointEvery != 0 {
			return nil
		}
		return writeEstimateProgressCheckpoint(cfg.OutDir, accepted, rejected, outerDone, outerTotal, started, progressCurrent, cfg.TopK)
	}
	printProgress := func(final bool) {
		if !cfg.Progress || cfg.ProgressEvery == 0 {
			return
		}
		if !final && outerDone%cfg.ProgressEvery != 0 {
			return
		}
		writeEstimateProgressBar(os.Stderr, rejected, outerDone, outerTotal, started, progressCurrent, final)
	}
	stepOuter := func(current string) error {
		outerDone++
		progressCurrent = current
		printProgress(false)
		return writeCheckpoint(false)
	}

	for _, profileName := range cfg.Profiles {
		profile, ok := credential.LookupIntGenISISProfile(profileName)
		if !ok {
			return sweepIntGenISISEstimateReport{}, fmt.Errorf("unsupported IntGenISIS profile %q", profileName)
		}
		for _, fam := range cfg.Families {
			for _, ncols := range cfg.NCols {
				issuanceNCols := ncols
				if issuanceNCols < 16 && profile.N%16 == 0 {
					issuanceNCols = 16
				}
				for _, lvcs := range cfg.LVCSNCols {
					for _, ell := range cfg.Ell {
						currentOuter := fmt.Sprintf("profile=%s N=%d theta=%d rho=%d ell'=%d ncols=%d lvcs=%d ell=%d",
							profile.Name, profile.N, fam.Theta, fam.Rho, fam.EllPrime, ncols, lvcs, ell)
						if ncols <= 0 || profile.N%ncols != 0 || lvcs < ncols || lvcs < issuanceNCols {
							rejected.InvalidGeometry++
							if err := stepOuter(currentOuter); err != nil {
								return sweepIntGenISISEstimateReport{}, err
							}
							continue
						}
						leafGrid := grid
						leafGrid.NLeavesBase = cfg.NLeavesBase
						nLeavesList := sweepCachedNLeavesCandidates(profile, leafGrid, lvcs, ell, leafThreshold, cfg.MaxNLeaves, cache)
						if len(nLeavesList) == 0 {
							rejected.NLeavesCap++
							if err := stepOuter(currentOuter); err != nil {
								return sweepIntGenISISEstimateReport{}, err
							}
							continue
						}
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
							minEta := sweepMinEta(profile, baseIssuance, etaThreshold, grid.MaxEta, cache)
							if minEta <= 0 {
								rejected.SoundnessLow++
								continue
							}
							for eta := minEta; eta <= minEta+grid.EtaSlack && eta <= grid.MaxEta; eta++ {
								issuance := baseIssuance
								issuance.Eta = eta
								issuance.Kappa = [4]int{}
								issuanceMetricsBase, err := estimateIntGenISISMetrics(profile, issuance, "issuance")
								if err != nil {
									rejected.EstimatorError++
									continue
								}
								for _, shape := range cfg.Shortness {
									if !sweepShortnessCoversSignatureBound(shape, sweepEstimateSignatureBound(profile)) {
										rejected.RadixCapacity++
										continue
									}
									for _, compression := range cfg.Compression {
										for _, projection := range cfg.Projection {
											for _, prfMode := range cfg.PRFModes {
												for _, groupRounds := range cfg.PRFGroupRounds {
													for _, samples := range cfg.Checkpoints {
														showing := intGenISISTuning{
															NCols:              ncols,
															LVCSNCols:          lvcs,
															NLeaves:            nLeaves,
															Eta:                eta,
															Theta:              fam.Theta,
															Rho:                fam.Rho,
															Ell:                ell,
															EllPrime:           fam.EllPrime,
															Kappa:              [4]int{},
															PRFCompanionMode:   prfMode,
															PRFGroupRounds:     groupRounds,
															CheckpointSamples:  samples,
															SigShortnessRadix:  shape.Radix,
															SigShortnessDigits: shape.Digits,
															CompressedRows:     compression,
															ReplayProjection:   projection,
														}
														rejected.GeneratedCandidates++
														showingMetricsBase, err := estimateIntGenISISMetrics(profile, showing, "showing")
														if err != nil {
															rejected.EstimatorError++
															continue
														}
														if showingMetricsBase.PaperTranscriptBytes > cfg.MaxShowingBytes {
															rejected.TranscriptCap++
															continue
														}
														kappa, issuanceMetrics, showingMetrics, candBits, ok, high := selectSweepKappaTopup(issuanceMetricsBase, showingMetricsBase, cfg.Kappa, cfg.SoundnessMin, cfg.SoundnessMax)
														if !ok {
															if high {
																rejected.SoundnessHigh++
															} else {
																rejected.SoundnessLow++
															}
															continue
														}
														issuance.Kappa = kappa
														showing.Kappa = kappa
														id++
														cand := sweepIntGenISISEstimateCandidate{
															ID:                     fmt.Sprintf("est_%06d", id),
															Profile:                profile.Name,
															RingDegree:             profile.N,
															Q:                      profile.Q,
															Issuance:               issuance,
															Showing:                showing,
															IssuanceMetrics:        issuanceMetrics,
															ShowingMetrics:         showingMetrics,
															CandidateTheoremBits:   candBits,
															CandidateEq8Bits:       math.Min(issuanceMetrics.SoundnessEq8Bits, showingMetrics.SoundnessEq8Bits),
															ShowingTranscriptBytes: showingMetrics.PaperTranscriptBytes,
															TotalTranscriptBytes:   issuanceMetrics.PaperTranscriptBytes + showingMetrics.PaperTranscriptBytes,
														}
														accepted = append(accepted, cand)
														rejected.AcceptedCandidates++
														accepted = pruneEstimateFrontier(accepted, cfg.TopK)
													}
												}
											}
										}
									}
								}
							}
						}
						if err := stepOuter(currentOuter); err != nil {
							return sweepIntGenISISEstimateReport{}, err
						}
					}
				}
			}
		}
	}
	progressCurrent = "finalizing"
	if err := writeCheckpoint(true); err != nil {
		return sweepIntGenISISEstimateReport{}, err
	}
	printProgress(true)

	accepted = efficientEstimateFrontier(accepted, cfg.TopK)
	sortEstimateCandidates(accepted, 0)
	frontierAll := limitEstimateCandidates(accepted, cfg.TopK)
	frontier96 := estimateTargetFrontier(accepted, 96, cfg.TopK)
	frontier128 := estimateTargetFrontier(accepted, 128, cfg.TopK)
	report := sweepIntGenISISEstimateReport{
		Version:         sweepIntGenISISEstimateVersion,
		Generated:       time.Now().UTC().Format(time.RFC3339),
		Grid:            gridConfig,
		Profiles:        cfg.Profiles,
		SoundnessMetric: "smallwood_theorem9_min_issuance_showing",
		SoundnessMin:    cfg.SoundnessMin,
		SoundnessMax:    cfg.SoundnessMax,
		MaxShowingBytes: cfg.MaxShowingBytes,
		MaxNLeaves:      cfg.MaxNLeaves,
		AcceptedCount:   rejected.AcceptedCandidates,
		Rejected:        rejected,
		FrontierAll:     frontierAll,
		Frontier96:      frontier96,
		Frontier128:     frontier128,
		EstimatorNotes: []string{
			"This is an estimate-only report: no proofs, signatures, verifier states, or presentations were generated.",
			"The sweep records only bounded efficient frontiers; all accepted candidates are counted but not streamed to disk.",
			"Q and R buckets use the same closed-form paper formulas as the live report.",
			"Pdecs/Auth/VTargets/BarSets are deterministic conservative estimates calibrated to current IntGenISIS measured geometry; use benchmark-intgenisis-e2e for final promotion.",
			"Candidate bits are min(issuance theorem_total_bits, showing theorem_total_bits); raw Eq. (8) bits are recorded but not used as the filter.",
		},
		ValidationTargets: []sweepIntGenISISEstimatorValidationRef{
			{Name: "n256-sw96", Notes: "Run benchmark-intgenisis-e2e -preset n256-sw96 to validate estimator drift for profile A."},
			{Name: "n256-sw128", Notes: "Run benchmark-intgenisis-e2e -preset n256-sw128 to validate estimator drift for profile A."},
			{Name: "sw96-lvcs64 projected default", ExpectedShowingBytes: 31232, ExpectedDQ: 482, ExpectedTheoremBits: 96.50, Notes: "Current compact profile-B R11/L4 V2 reference."},
			{Name: "projected R11/L4 best", ExpectedShowingBytes: 31232, ExpectedDQ: 482, ExpectedTheoremBits: 96.50, Notes: "Reference from measured retuning snapshot."},
		},
	}
	summary := report
	summary.FrontierAll = nil
	summary.Frontier96 = nil
	summary.Frontier128 = nil
	if err := writeJSONFile(filepath.Join(cfg.OutDir, "summary.json"), summary, 0o644); err != nil {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("write summary.json: %w", err)
	}
	if err := writeJSONFile(filepath.Join(cfg.OutDir, "frontier_all.json"), frontierAll, 0o644); err != nil {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("write frontier_all.json: %w", err)
	}
	if err := writeJSONFile(filepath.Join(cfg.OutDir, "frontier_96.json"), frontier96, 0o644); err != nil {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("write frontier_96.json: %w", err)
	}
	if err := writeJSONFile(filepath.Join(cfg.OutDir, "frontier_128.json"), frontier128, 0o644); err != nil {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("write frontier_128.json: %w", err)
	}
	if err := writeJSONFile(filepath.Join(cfg.OutDir, "rejected_counts.json"), rejected, 0o644); err != nil {
		return sweepIntGenISISEstimateReport{}, fmt.Errorf("write rejected_counts.json: %w", err)
	}
	if err := writeEstimateCSV(filepath.Join(cfg.OutDir, "frontier_all.csv"), frontierAll); err != nil {
		return sweepIntGenISISEstimateReport{}, err
	}
	if err := writeEstimateCSV(filepath.Join(cfg.OutDir, "frontier_96.csv"), frontier96); err != nil {
		return sweepIntGenISISEstimateReport{}, err
	}
	if err := writeEstimateCSV(filepath.Join(cfg.OutDir, "frontier_128.csv"), frontier128); err != nil {
		return sweepIntGenISISEstimateReport{}, err
	}
	fmt.Printf("[issuance-cli] sweep-intgenisis-estimate wrote %s accepted=%d generated=%d\n", cfg.OutDir, rejected.AcceptedCandidates, rejected.GeneratedCandidates)
	return report, nil
}

func sweepIntGenISISEstimateGridFor(name string) (sweepIntGenISISGrid, error) {
	switch strings.TrimSpace(strings.ToLower(name)) {
	case "", sweepEstimateDefaultGrid, "deep", "wide":
		families := []sweepIntGenISISFamily{
			// Primary theta>1 path. For q≈2^20, theta*rho in {5,6,7}
			// covers the 96/128 theorem bands with much lower Q cost than
			// broad high-rho families.
			{Theta: 5, Rho: 1, EllPrime: 1},
			{Theta: 6, Rho: 1, EllPrime: 1},
			{Theta: 7, Rho: 1, EllPrime: 1},
			{Theta: 8, Rho: 1, EllPrime: 1},
			{Theta: 9, Rho: 1, EllPrime: 1},
			// Low-theta comparison families retained for the rho/ell' tradeoff
			// seen in compact measured N=256/N=512 showings.
			{Theta: 2, Rho: 3, EllPrime: 3},
			{Theta: 2, Rho: 3, EllPrime: 4},
			{Theta: 2, Rho: 4, EllPrime: 3},
			{Theta: 2, Rho: 4, EllPrime: 4},
			{Theta: 3, Rho: 2, EllPrime: 2},
			{Theta: 3, Rho: 2, EllPrime: 3},
			{Theta: 4, Rho: 2, EllPrime: 1},
			{Theta: 4, Rho: 2, EllPrime: 2},
			{Theta: 4, Rho: 2, EllPrime: 3},
			{Theta: 5, Rho: 2, EllPrime: 1},
			{Theta: 5, Rho: 2, EllPrime: 2},
			{Theta: 3, Rho: 3, EllPrime: 2},
			{Theta: 3, Rho: 3, EllPrime: 3},
			{Theta: 4, Rho: 3, EllPrime: 1},
			// Theta=1 baselines are restricted to rho and ell' values that can
			// plausibly clear 94/128-bit Theorem 9 without the old huge grid.
			{Theta: 1, Rho: 5, EllPrime: 9},
			{Theta: 1, Rho: 5, EllPrime: 10},
			{Theta: 1, Rho: 6, EllPrime: 9},
			{Theta: 1, Rho: 6, EllPrime: 10},
			{Theta: 1, Rho: 7, EllPrime: 11},
			{Theta: 1, Rho: 7, EllPrime: 12},
			{Theta: 1, Rho: 7, EllPrime: 13},
		}
		return sweepIntGenISISGrid{
			Name:        sweepEstimateDefaultGrid,
			Families:    families,
			NCols:       []int{8, 16, 32, 64, 128},
			LVCSNCols:   []int{16, 24, 32, 40, 48, 56, 60, 64, 66, 68, 70, 72, 74, 76, 80, 84, 88, 96, 112, 128, 144, 160, 192, 224, 256},
			Ell:         []int{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30, 32},
			NLeavesBase: []int{768, 896, 1024, 1152, 1280, 1408, 1536, 1664, 1792, 2048, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 42000, 49152, 61056, 65536, 98304, 131072, 180000, 196608, 262144},
			Shortness: []sweepIntGenISISShortness{
				{Radix: 11, Digits: 4},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
			},
			Compression: []int{0, 1, 2},
			EtaSlack:    4,
			MaxEta:      160,
			Notes: []string{
				"Estimate-deep searches both profile-A N=256 and profile-B N=512 through the calling command.",
				"The default grid is pre-pruned to remove round-2-impossible theta/rho pairs, dominated high-rho/high-theta families, ncols>=256, lvcs_ncols>256, ell>32, nleaves bases above 262144, compression level 3, and non-projected layouts.",
				"All pruned axes remain available through explicit -theta/-rho/-ell-prime/-ncols/-lvcs-ncols/-ell/-nleaves/-compression-levels/-projection-modes overrides.",
				"The grid intentionally spans 88-to-135-bit Theorem 9 candidates with zero grinding, rather than a single raw Eq. (8) target.",
			},
		}, nil
	default:
		return sweepIntGenISISGrid{}, fmt.Errorf("unknown IntGenISIS estimate grid %q", name)
	}
}

func estimateIntGenISISMetrics(profile credential.IntGenISISProfile, tuning intGenISISTuning, kind string) (benchmarkIntGenISISMetrics, error) {
	geom, err := estimateIntGenISISGeometry(profile, tuning, kind)
	if err != nil {
		return benchmarkIntGenISISMetrics{}, err
	}
	opts := PIOP.ResolveSimOptsDefaults(PIOP.SimOpts{
		Credential:                 true,
		CoeffPacking:               true,
		RingDegree:                 profile.N,
		NCols:                      tuning.NCols,
		LVCSNCols:                  tuning.LVCSNCols,
		PostSignLVCSNCols:          tuning.LVCSNCols,
		PRFLVCSNCols:               tuning.LVCSNCols,
		NLeaves:                    tuning.NLeaves,
		Ell:                        tuning.Ell,
		EllPrime:                   tuning.EllPrime,
		Eta:                        tuning.Eta,
		Rho:                        tuning.Rho,
		Theta:                      tuning.Theta,
		Kappa:                      tuning.Kappa,
		DomainMode:                 PIOP.DomainModeExplicit,
		PRFGroupRounds:             estimatePRFGroupRounds(tuning),
		PRFCompanionMode:           tuning.PRFCompanionMode,
		PRFCheckpointSamples:       tuning.CheckpointSamples,
		SigShortnessRadix:          tuning.SigShortnessRadix,
		SigShortnessL:              tuning.SigShortnessDigits,
		IntGenISISMSECompression:   tuning.CompressedRows,
		IntGenISISReplayProjection: tuning.ReplayProjection,
	})
	sb := PIOP.ComputeSoundnessBudgetForParams(opts, profile.Q, geom.PaperConservativeDQ, tuning.NCols, tuning.LVCSNCols, tuning.NLeaves, geom.Rows)
	paper := estimatePaperTranscript(profile, tuning, geom)
	return benchmarkIntGenISISMetrics{
		ProofSizeBytes:                0,
		PaperTranscriptBytes:          paper.total,
		PaperTranscriptKB:             float64(paper.total) / 1024.0,
		QBytes:                        paper.q,
		RBytes:                        paper.r,
		PdecsBytes:                    paper.pdecs,
		AuthBytes:                     paper.auth,
		SigShortnessBytes:             0,
		VTargetsBytes:                 paper.vtargets,
		BarSetsBytes:                  paper.barsets,
		TotalRows:                     geom.Rows,
		PRFRows:                       geom.PRFRows,
		CoefficientViewRows:           geom.CoefficientViewRows,
		UCoefficientViewRows:          geom.UCoefficientViewRows,
		SemanticViewRows:              geom.SemanticViewRows,
		CommitmentViewRows:            geom.CommitmentViewRows,
		YCoefficientViewRows:          geom.YCoefficientViewRows,
		IssuerViewRows:                geom.IssuerViewRows,
		BoundRows:                     geom.BoundRows,
		ShortnessRows:                 geom.ShortnessRows,
		ShortnessConstraints:          geom.ShortnessConstraints,
		HatRows:                       geom.HatRows,
		YHatRows:                      geom.YHatRows,
		SourceBridgeConstraints:       geom.SourceBridge,
		UBridgeConstraints:            geom.UBridge,
		CommitmentBridgeConstraints:   geom.CommitmentBridge,
		YLinearConstraints:            geom.YLinear,
		ProjectedSignatureConstraints: geom.ProjectedSignature,
		ReplayProjection:              tuning.ReplayProjection,
		IssuerBridgeConstraints:       geom.IssuerBridge,
		PRFKeyBridgeConstraints:       geom.PRFKeyBridge,
		FparIntConstraints:            geom.FparInt,
		RangeConstraints:              geom.Range,
		ParallelDegree:                geom.ParallelAlgDegree,
		AggregatedDegree:              geom.AggregatedAlgDegree,
		ParallelAlgDegree:             geom.ParallelAlgDegree,
		AggregatedAlgDegree:           geom.AggregatedAlgDegree,
		PaperConservativeDQ:           geom.PaperConservativeDQ,
		MaskDegreeBound:               geom.MaskDegreeBound,
		DominantDegreeSource:          geom.DominantDegreeSource,
		TernaryRows:                   geom.TernaryRows,
		CompressedRows:                geom.CompressedRows,
		MSECompressionLevel:           geom.MSECompressionLevel,
		MSECompressionPackWidth:       geom.MSECompressionPack,
		MSECompressionDegree:          geom.MSECompressionDegree,
		RoundBits:                     sb.Bits,
		RawRoundBits:                  sb.RawBits,
		TheoremBits:                   sb.TheoremBits,
		TheoremTotalBits:              sb.TotalBits,
		CollisionBits:                 sb.CollisionBits,
		Clamped:                       sb.Clamped,
		SoundnessEq8Bits:              sb.Eq8TotalBits,
		DQ:                            geom.PaperConservativeDQ,
		DDECS:                         geom.DDECS,
		WitnessSupportCols:            tuning.NCols,
		CommittedCols:                 tuning.LVCSNCols,
		ProofReportBuckets:            geom.ProofReportBucketHint,
		Theta:                         tuning.Theta,
		Rho:                           tuning.Rho,
		EllPrime:                      tuning.EllPrime,
		SmallFieldReplayRows:          geom.SmallFieldReplayRows,
		MaskRows:                      geom.MaskRows,
		QSplitRows:                    geom.QSplitRows,
		QLimbRows:                     geom.QLimbRows,
		MeasurementStatus:             "estimated_no_proof",
	}, nil
}

func estimateIntGenISISGeometry(profile credential.IntGenISISProfile, tuning intGenISISTuning, kind string) (sweepEstimateGeometry, error) {
	ncols := tuning.NCols
	if ncols <= 0 {
		ncols = 16
	}
	if profile.N%ncols != 0 {
		return sweepEstimateGeometry{}, fmt.Errorf("profile %s ring degree %d not divisible by ncols=%d", profile.Name, profile.N, ncols)
	}
	lvcs := tuning.LVCSNCols
	if lvcs < ncols {
		lvcs = ncols
	}
	ell := tuning.Ell
	if ell <= 0 {
		ell = 1
	}
	theta := tuning.Theta
	if theta <= 0 {
		theta = 1
	}
	rho := tuning.Rho
	if rho <= 0 {
		rho = 1
	}
	blocks := profile.N / ncols
	par, agg := sweepRelationDegrees(tuning, kind)
	dq := sweepComputeDQFromDegrees(par, agg, ncols, ell)
	geom := sweepEstimateGeometry{
		DDECS:                 lvcs + ell - 1,
		ParallelAlgDegree:     par,
		AggregatedAlgDegree:   agg,
		DominantDegreeSource:  estimateDominantDegreeSource(tuning, kind),
		PaperConservativeDQ:   dq,
		MaskDegreeBound:       dq,
		QLimbRows:             theta,
		QSplitRows:            rho,
		ProofReportBucketHint: 8,
	}
	if theta > 1 {
		geom.QSplitRows = rho * theta
	}
	if kind == "issuance" {
		polys := profile.EllM + profile.EllM + profile.EllM + profile.KS + profile.NC
		geom.BoundRows = polys * blocks
		geom.TernaryRows = geom.BoundRows
		geom.Rows = polys + geom.BoundRows
		geom.Range = geom.BoundRows
		geom.FparInt = polys
		geom.ProofReportBucketHint = 6
	} else {
		shortDigits := tuning.SigShortnessDigits
		if shortDigits <= 0 {
			shortDigits = 4
		}
		mode := tuning.ReplayProjection
		if mode == "" {
			mode = PIOP.IntGenISISReplayProjectionNone
		}
		uRows := profile.SignaturePreimageLen * blocks
		shortRows := profile.SignaturePreimageLen * blocks * shortDigits
		mRows := profile.EllM * blocks
		sRows := profile.KS * blocks
		eRows := profile.NC * blocks
		mseRows := mRows + sRows + eRows
		packWidth := 1
		compressionDegree := 0
		if tuning.CompressedRows > 0 {
			packWidth = tuning.CompressedRows + 1
			compressionDegree = powInt(3, packWidth)
			mseRows = ceilDivMain(mRows, packWidth) + ceilDivMain(sRows, packWidth) + ceilDivMain(eRows, packWidth)
		}
		yViewRows := blocks
		if mode == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 {
			yViewRows = 0
		}
		uHatRows := profile.SignaturePreimageLen * blocks
		yHatRows := blocks
		if mode == PIOP.IntGenISISReplayProjectionProjectUYHatV1 || mode == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 {
			uHatRows = 0
			yHatRows = 0
		}
		issuerHatRows := (profile.EllMuSig + profile.EllX0 + profile.EllX1 + 1) * blocks
		prfRows, prfKeyBridge, err := estimatePRFGeometry(tuning)
		if err != nil {
			return sweepEstimateGeometry{}, err
		}
		baseRows := uRows + shortRows + mseRows + yViewRows + uHatRows + yHatRows + issuerHatRows + prfRows
		bridgeStripeRows := 0
		if estimatePRFCompanionMode(tuning) == PIOP.PRFCompanionModeAuxInstance {
			bridgeStripeRows = estimatePRFBridgeStripeRows(baseRows, lvcs, prfRows)
		}
		geom.Rows = baseRows + bridgeStripeRows
		geom.PRFRows = prfRows
		geom.BoundRows = mseRows
		geom.TernaryRows = mseRows
		geom.CompressedRows = 0
		if tuning.CompressedRows > 0 {
			geom.CompressedRows = mseRows
		}
		geom.MSECompressionLevel = tuning.CompressedRows
		geom.MSECompressionPack = packWidth
		geom.MSECompressionDegree = compressionDegree
		geom.ShortnessRows = shortRows
		geom.ShortnessConstraints = uRows * (1 + shortDigits)
		geom.HatRows = uHatRows + yHatRows + issuerHatRows
		geom.YHatRows = yHatRows
		geom.CoefficientViewRows = uRows + mseRows + yViewRows
		geom.UCoefficientViewRows = uRows
		geom.SemanticViewRows = mRows
		geom.CommitmentViewRows = sRows + eRows
		geom.YCoefficientViewRows = yViewRows
		geom.Range = mseRows
		geom.PRFKeyBridge = prfKeyBridge
		if mode == PIOP.IntGenISISReplayProjectionProjectUYHatV1 || mode == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 {
			geom.ProjectedSignature = blocks * ncols
			geom.FparInt = blocks
		} else {
			geom.UBridge = uHatRows * ncols
			geom.CommitmentBridge = yHatRows * ncols
			geom.FparInt = 2 * blocks
		}
		if yViewRows > 0 {
			geom.YLinear = yViewRows * ncols
		}
		geom.SourceBridge = geom.UBridge + geom.CommitmentBridge + geom.YLinear + geom.ProjectedSignature + geom.IssuerBridge
	}
	rowsBlock := ceilDivMain(geom.Rows, lvcs)
	if theta > 1 {
		geom.SmallFieldReplayRows = rowsBlock * (ncols + theta)
		geom.MaskRows = (dq/lvcs + 1) * theta * rho
	} else {
		geom.SmallFieldReplayRows = geom.Rows
		geom.MaskRows = (dq/lvcs + 1) * rho
	}
	return geom, nil
}

type estimatePaperBuckets struct {
	total    int
	q        int
	r        int
	pdecs    int
	auth     int
	vtargets int
	barsets  int
}

func estimatePaperTranscript(profile credential.IntGenISISProfile, tuning intGenISISTuning, geom sweepEstimateGeometry) estimatePaperBuckets {
	qLog := math.Log2(float64(profile.Q))
	qBits := estimateFieldElementBitWidth(profile.Q)
	qTheta := 1
	if tuning.Theta > 1 {
		qTheta = tuning.Theta
	}
	rho := tuning.Rho
	if rho <= 0 {
		rho = 1
	}
	ellPrime := tuning.EllPrime
	if ellPrime <= 0 {
		ellPrime = 1
	}
	ell := tuning.Ell
	if ell <= 0 {
		ell = 1
	}
	theta := tuning.Theta
	if theta <= 0 {
		theta = 1
	}
	ncols := tuning.NCols
	if ncols <= 0 {
		ncols = 16
	}
	lvcs := tuning.LVCSNCols
	if lvcs < ncols {
		lvcs = ncols
	}
	rBytes := bitsToBytesMain(float64(tuning.Eta) * float64(maxIntMain(geom.DDECS+1-ell, 0)) * qLog)
	qBytes := bitsToBytesMain(float64(rho*maxIntMain(geom.PaperConservativeDQ-(ellPrime+1), 0)*qTheta) * qLog)
	authBytes := bitsToBytesMain(float64(ell)*math.Log2(float64(maxIntMain(tuning.NLeaves, 2)))*32 + 12000)
	rowsBlock := ceilDivMain(geom.Rows, lvcs)
	auditRows := rowsBlock * ellPrime
	if theta > 1 {
		auditRows *= theta
	}
	pdecsBytes := estimateRowOpeningPdecsBytes(tuning, geom, auditRows, qBits)
	vtargetsBytes := estimatePackedMatrixBytes(auditRows, lvcs, qBits)
	barsetsBytes := estimatePackedMatrixBytes(auditRows, ell, qBits)
	fixedBytes := 16 + 64 + 32
	total := fixedBytes + qBytes + rBytes + pdecsBytes + authBytes + vtargetsBytes + barsetsBytes
	return estimatePaperBuckets{total: total, q: qBytes, r: rBytes, pdecs: pdecsBytes, auth: authBytes, vtargets: vtargetsBytes, barsets: barsetsBytes}
}

func estimateFieldElementBitWidth(q uint64) int {
	if q <= 1 {
		return 1
	}
	return bits.Len64(q - 1)
}

func estimatePackedMatrixBytes(rows, cols, bitWidth int) int {
	if rows <= 0 || cols <= 0 || bitWidth <= 0 {
		return 0
	}
	return 10 + ceilDivInt64ToInt(int64(rows)*int64(cols)*int64(bitWidth), 8)
}

func estimatePackedPayloadBytes(rows, cols, bitWidth int) int {
	if rows <= 0 || cols <= 0 || bitWidth <= 0 {
		return 0
	}
	return ceilDivInt64ToInt(int64(rows)*int64(cols)*int64(bitWidth), 8)
}

func estimateRowOpeningPdecsBytes(tuning intGenISISTuning, geom sweepEstimateGeometry, auditRows, qBits int) int {
	ell := tuning.Ell
	if ell <= 0 {
		ell = 1
	}
	theta := tuning.Theta
	if theta <= 0 {
		theta = 1
	}
	rho := tuning.Rho
	if rho <= 0 {
		rho = 1
	}
	if theta > 1 {
		openingCols := geom.SmallFieldReplayRows + geom.MaskRows - auditRows
		if openingCols <= 0 {
			return 0
		}
		rows := ell * theta
		payload := estimatePackedPayloadBytes(rows, openingCols, qBits)
		metadata := 1 + varintSizeMain(openingCols) + estimateSmallFieldPOmitColsVarintBytes(tuning, geom, auditRows) + 1
		return payload + metadata
	}
	openingCols := geom.Rows + rho
	rows := 2 * ell
	payload := estimatePackedPayloadBytes(rows, openingCols, qBits)
	if payload == 0 {
		return 0
	}
	// Format 0 row openings carry the P residue stream plus its bit-width byte.
	return payload + 1
}

func estimateSmallFieldPOmitColsVarintBytes(tuning intGenISISTuning, geom sweepEstimateGeometry, auditRows int) int {
	if auditRows <= 0 {
		return 0
	}
	ncols := tuning.NCols
	if ncols <= 0 {
		ncols = 16
	}
	lvcs := tuning.LVCSNCols
	if lvcs < ncols {
		lvcs = ncols
	}
	theta := tuning.Theta
	if theta <= 1 {
		return 0
	}
	ellPrime := tuning.EllPrime
	if ellPrime <= 0 {
		ellPrime = 1
	}
	rowsBlock := ceilDivMain(geom.Rows, lvcs)
	perBlock := theta * ellPrime
	if rowsBlock <= 0 || perBlock <= 0 || rowsBlock*perBlock != auditRows {
		total := 0
		for col := 0; col < auditRows; col++ {
			total += varintSizeMain(col)
		}
		return total
	}
	stride := ncols + theta
	total := 0
	for block := 0; block < rowsBlock; block++ {
		base := block * stride
		for i := 0; i < perBlock; i++ {
			total += varintSizeMain(base + i)
		}
	}
	return total
}

func estimateDominantDegreeSource(t intGenISISTuning, kind string) string {
	if kind == "issuance" {
		return "ternary"
	}
	radix := t.SigShortnessRadix
	if radix <= 0 {
		radix = 11
	}
	compressionDegree := 3
	if t.CompressedRows > 0 {
		compressionDegree = powInt(3, t.CompressedRows+1)
	}
	if compressionDegree > radix && compressionDegree >= 3 {
		return "compression"
	}
	if radix >= compressionDegree && radix >= 3 {
		return "shortness"
	}
	return "signature"
}

func estimatePRFRows(t intGenISISTuning) (int, error) {
	rows, _, err := estimatePRFGeometry(t)
	return rows, err
}

func estimatePRFGeometry(t intGenISISTuning) (rows int, keyBridge int, err error) {
	ncols := t.NCols
	if ncols <= 0 {
		ncols = 16
	}
	params, err := loadSweepEstimatePRFParams()
	if err != nil {
		return 0, 0, err
	}
	if ncols < params.LenKey {
		return 0, 0, fmt.Errorf("estimate PRF rows: ncols=%d < lenkey=%d", ncols, params.LenKey)
	}
	groupRounds := estimatePRFGroupRounds(t)
	checkpoints, err := prf.SBoxOutputCountGrouped(params, groupRounds)
	if err != nil {
		return 0, 0, fmt.Errorf("estimate PRF rows: grouped sbox count: %w", err)
	}
	keyRows := ceilDivMain(params.LenKey, ncols)
	traceRows := ceilDivMain(checkpoints+params.LenTag, ncols)
	return keyRows + traceRows, params.LenKey, nil
}

func estimatePRFGroupRounds(t intGenISISTuning) int {
	if t.PRFGroupRounds > 0 {
		return t.PRFGroupRounds
	}
	return sweepEstimatePRFGroupRounds
}

func estimatePRFCompanionMode(t intGenISISTuning) PIOP.PRFCompanionMode {
	switch t.PRFCompanionMode {
	case PIOP.PRFCompanionModeDirectAuth, PIOP.PRFCompanionModeOutputAudit, PIOP.PRFCompanionModeAuxInstance:
		return t.PRFCompanionMode
	case "":
		return PIOP.PRFCompanionModeOutputAudit
	default:
		return PIOP.PRFCompanionModeOutputAudit
	}
}

func estimatePRFBridgeStripeRows(currentWitnessRows, pcsNCols, sourceRows int) int {
	if currentWitnessRows < 0 || pcsNCols <= 0 || sourceRows <= 0 {
		return 0
	}
	targetSlots := minIntMain(4, sourceRows)
	baseBlock := ceilDivMain(currentWitnessRows, pcsNCols)
	lastPhysical := (baseBlock+(sourceRows-1)/targetSlots)*pcsNCols + ((sourceRows - 1) % targetSlots)
	if lastPhysical < currentWitnessRows {
		return sourceRows
	}
	return lastPhysical - currentWitnessRows + 1
}

func loadSweepEstimatePRFParams() (*prf.Params, error) {
	sweepEstimatePRFParamsCache.once.Do(func() {
		sweepEstimatePRFParamsCache.params, sweepEstimatePRFParamsCache.err = prf.LoadLocalOrDefaultParams(filepath.Join("prf", "prf_params.json"))
	})
	if sweepEstimatePRFParamsCache.err != nil {
		return nil, fmt.Errorf("load PRF params for estimate: %w", sweepEstimatePRFParamsCache.err)
	}
	return sweepEstimatePRFParamsCache.params, nil
}

func sweepShortnessCoversSignatureBound(shape sweepIntGenISISShortness, beta int64) bool {
	if shape.Radix <= 1 || shape.Digits <= 0 {
		return false
	}
	digitBound := (shape.Radix - 1) / 2
	capacity := int64(0)
	pow := int64(1)
	for i := 0; i < shape.Digits; i++ {
		capacity += int64(digitBound) * pow
		pow *= int64(shape.Radix)
	}
	return capacity >= beta
}

func sweepEstimateSignatureBound(_ credential.IntGenISISProfile) int64 {
	// Estimate-only sweeps do not load NTRU artifacts. Current live N=256/N=512
	// presets both use the calibrated research beta persisted by setup-ntru-keys.
	return 6142
}

func prepareEstimateOutDir(outDir string, force bool) error {
	if outDir == "" {
		return fmt.Errorf("empty output directory")
	}
	if st, err := os.Stat(outDir); err == nil {
		if !st.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", outDir)
		}
		entries, err := os.ReadDir(outDir)
		if err != nil {
			return fmt.Errorf("read output dir: %w", err)
		}
		if len(entries) > 0 && !force {
			return fmt.Errorf("refusing to write into non-empty %s without -force", outDir)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat output dir: %w", err)
	}
	return os.MkdirAll(outDir, 0o755)
}

func pruneEstimateFrontier(candidates []sweepIntGenISISEstimateCandidate, limit int) []sweepIntGenISISEstimateCandidate {
	if limit <= 0 || len(candidates) <= limit*2 {
		return candidates
	}
	return efficientEstimateFrontier(candidates, limit)
}

func efficientEstimateFrontier(candidates []sweepIntGenISISEstimateCandidate, limit int) []sweepIntGenISISEstimateCandidate {
	if len(candidates) == 0 {
		return nil
	}
	sorted := append([]sweepIntGenISISEstimateCandidate(nil), candidates...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.ShowingTranscriptBytes != b.ShowingTranscriptBytes {
			return a.ShowingTranscriptBytes < b.ShowingTranscriptBytes
		}
		if a.TotalTranscriptBytes != b.TotalTranscriptBytes {
			return a.TotalTranscriptBytes < b.TotalTranscriptBytes
		}
		if math.Abs(a.CandidateTheoremBits-b.CandidateTheoremBits) > 1e-9 {
			return a.CandidateTheoremBits > b.CandidateTheoremBits
		}
		return a.ID < b.ID
	})
	frontier := make([]sweepIntGenISISEstimateCandidate, 0, minIntMain(len(sorted), maxIntMain(limit, 1)))
	for _, cand := range sorted {
		dominated := false
		for _, kept := range frontier {
			if estimateCandidateDominates(kept, cand) {
				dominated = true
				break
			}
		}
		if dominated {
			continue
		}
		dst := frontier[:0]
		for _, kept := range frontier {
			if !estimateCandidateDominates(cand, kept) {
				dst = append(dst, kept)
			}
		}
		frontier = append(dst, cand)
	}
	sortEstimateCandidates(frontier, 0)
	return limitEstimateCandidates(frontier, limit)
}

func estimateCandidateDominates(a, b sweepIntGenISISEstimateCandidate) bool {
	const eps = 1e-9
	if a.ShowingTranscriptBytes > b.ShowingTranscriptBytes {
		return false
	}
	if a.TotalTranscriptBytes > b.TotalTranscriptBytes {
		return false
	}
	if a.CandidateTheoremBits+eps < b.CandidateTheoremBits {
		return false
	}
	return a.ShowingTranscriptBytes < b.ShowingTranscriptBytes ||
		a.TotalTranscriptBytes < b.TotalTranscriptBytes ||
		a.CandidateTheoremBits > b.CandidateTheoremBits+eps ||
		a.ID < b.ID
}

func sortEstimateCandidates(candidates []sweepIntGenISISEstimateCandidate, target float64) {
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.ShowingTranscriptBytes != b.ShowingTranscriptBytes {
			return a.ShowingTranscriptBytes < b.ShowingTranscriptBytes
		}
		if target > 0 {
			da := math.Abs(a.CandidateTheoremBits - target)
			db := math.Abs(b.CandidateTheoremBits - target)
			if math.Abs(da-db) > 1e-9 {
				return da < db
			}
		}
		if a.TotalTranscriptBytes != b.TotalTranscriptBytes {
			return a.TotalTranscriptBytes < b.TotalTranscriptBytes
		}
		if a.Showing.NLeaves != b.Showing.NLeaves {
			return a.Showing.NLeaves < b.Showing.NLeaves
		}
		return a.ID < b.ID
	})
}

func limitEstimateCandidates(candidates []sweepIntGenISISEstimateCandidate, limit int) []sweepIntGenISISEstimateCandidate {
	if limit <= 0 || len(candidates) <= limit {
		return append([]sweepIntGenISISEstimateCandidate(nil), candidates...)
	}
	return append([]sweepIntGenISISEstimateCandidate(nil), candidates[:limit]...)
}

func estimateOuterGridTotal(cfg sweepIntGenISISEstimateConfig) int {
	total := len(cfg.Profiles) * len(cfg.Families) * len(cfg.NCols) * len(cfg.LVCSNCols) * len(cfg.Ell)
	if total < 0 {
		return 0
	}
	return total
}

func writeEstimateProgressCheckpoint(outDir string, accepted []sweepIntGenISISEstimateCandidate, rejected sweepIntGenISISEstimateRejectedCounts, done, total int, started time.Time, current string, topK int) error {
	now := time.Now()
	elapsed := now.Sub(started).Seconds()
	if elapsed <= 0 {
		elapsed = 1e-9
	}
	sorted := efficientEstimateFrontier(accepted, topK)
	sortEstimateCandidates(sorted, 0)
	frontierAll := limitEstimateCandidates(sorted, topK)
	frontier96 := estimateTargetFrontier(sorted, 96, topK)
	frontier128 := estimateTargetFrontier(sorted, 128, topK)
	var best *sweepIntGenISISEstimateCandidate
	if len(frontierAll) > 0 {
		b := frontierAll[0]
		best = &b
	}
	percent := 0.0
	if total > 0 {
		percent = 100 * float64(done) / float64(total)
		if percent > 100 {
			percent = 100
		}
	}
	progress := sweepIntGenISISEstimateProgress{
		StartedAt:           started.UTC().Format(time.RFC3339),
		UpdatedAt:           now.UTC().Format(time.RFC3339),
		ElapsedSeconds:      elapsed,
		OutDir:              outDir,
		Current:             current,
		OuterDone:           done,
		OuterTotal:          total,
		Percent:             percent,
		GeneratedCandidates: rejected.GeneratedCandidates,
		AcceptedCandidates:  rejected.AcceptedCandidates,
		RejectedCounts:      rejected,
		CandidatesPerSecond: float64(rejected.GeneratedCandidates) / elapsed,
		Best:                best,
	}
	if err := writeJSONFile(filepath.Join(outDir, "progress.json"), progress, 0o644); err != nil {
		return fmt.Errorf("write progress.json: %w", err)
	}
	if err := writeJSONFile(filepath.Join(outDir, "rejected_counts.json"), rejected, 0o644); err != nil {
		return fmt.Errorf("write rejected_counts.json: %w", err)
	}
	if err := writeJSONFile(filepath.Join(outDir, "frontier_all.json"), frontierAll, 0o644); err != nil {
		return fmt.Errorf("write frontier_all.json: %w", err)
	}
	if err := writeEstimateCSV(filepath.Join(outDir, "frontier_all.csv"), frontierAll); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(outDir, "frontier_96.json"), frontier96, 0o644); err != nil {
		return fmt.Errorf("write frontier_96.json: %w", err)
	}
	if err := writeEstimateCSV(filepath.Join(outDir, "frontier_96.csv"), frontier96); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(outDir, "frontier_128.json"), frontier128, 0o644); err != nil {
		return fmt.Errorf("write frontier_128.json: %w", err)
	}
	if err := writeEstimateCSV(filepath.Join(outDir, "frontier_128.csv"), frontier128); err != nil {
		return err
	}
	return nil
}

func writeEstimateProgressBar(w io.Writer, rejected sweepIntGenISISEstimateRejectedCounts, done, total int, started time.Time, current string, final bool) {
	if w == nil {
		return
	}
	elapsed := time.Since(started).Seconds()
	if elapsed <= 0 {
		elapsed = 1e-9
	}
	percent := 0.0
	if total > 0 {
		percent = float64(done) / float64(total)
		if percent > 1 {
			percent = 1
		}
	}
	const width = 32
	filled := int(math.Round(percent * width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
	current = compactProgressCurrent(current, 72)
	rate := float64(rejected.GeneratedCandidates) / elapsed
	fmt.Fprintf(w, "\r[%-*s] %6.2f%% outer=%d/%d gen=%d acc=%d rej=%d %.0f cand/s %s",
		width,
		bar,
		percent*100,
		done,
		total,
		rejected.GeneratedCandidates,
		rejected.AcceptedCandidates,
		estimateRejectedTotal(rejected),
		rate,
		current,
	)
	if final {
		fmt.Fprintln(w)
	}
}

func compactProgressCurrent(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func estimateRejectedTotal(r sweepIntGenISISEstimateRejectedCounts) int {
	return r.InvalidGeometry + r.RadixCapacity + r.NLeavesCap + r.SoundnessLow + r.SoundnessHigh + r.TranscriptCap + r.EstimatorError
}

func estimateTargetFrontier(candidates []sweepIntGenISISEstimateCandidate, target float64, limit int) []sweepIntGenISISEstimateCandidate {
	filtered := make([]sweepIntGenISISEstimateCandidate, 0, len(candidates))
	lo, hi := target-8, target+8
	if target >= 128 {
		lo, hi = 118, 135
	}
	for _, c := range candidates {
		if c.CandidateTheoremBits >= lo && c.CandidateTheoremBits <= hi {
			filtered = append(filtered, c)
		}
	}
	sortEstimateCandidates(filtered, target)
	return limitEstimateCandidates(filtered, limit)
}

func writeEstimateCSV(path string, candidates []sweepIntGenISISEstimateCandidate) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	header := []string{
		"id", "profile", "N", "candidate_theorem_bits", "candidate_eq8_bits", "showing_bytes", "total_bytes",
		"ncols", "lvcs_ncols", "nleaves", "eta", "theta", "rho", "ell", "ell_prime",
		"issuance_ncols", "prf_mode", "prf_group_rounds", "prf_checkpoint_samples",
		"kappa", "projection", "compression", "shortness_radix", "shortness_digits",
		"issuance_theorem", "showing_theorem", "issuance_eq8", "showing_eq8",
		"showing_rows", "showing_prf_rows", "showing_replay_rows", "showing_mask_rows", "showing_dq", "showing_ddecs",
		"q_bytes", "r_bytes", "pdecs_bytes", "auth_bytes", "vtargets_bytes", "barsets_bytes",
	}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("write csv header %s: %w", path, err)
	}
	for _, c := range candidates {
		row := []string{
			c.ID,
			c.Profile,
			strconv.Itoa(c.RingDegree),
			fmt.Sprintf("%.4f", c.CandidateTheoremBits),
			fmt.Sprintf("%.4f", c.CandidateEq8Bits),
			strconv.Itoa(c.ShowingTranscriptBytes),
			strconv.Itoa(c.TotalTranscriptBytes),
			strconv.Itoa(c.Showing.NCols),
			strconv.Itoa(c.Showing.LVCSNCols),
			strconv.Itoa(c.Showing.NLeaves),
			strconv.Itoa(c.Showing.Eta),
			strconv.Itoa(c.Showing.Theta),
			strconv.Itoa(c.Showing.Rho),
			strconv.Itoa(c.Showing.Ell),
			strconv.Itoa(c.Showing.EllPrime),
			strconv.Itoa(c.Issuance.NCols),
			string(c.Showing.PRFCompanionMode),
			strconv.Itoa(c.Showing.PRFGroupRounds),
			strconv.Itoa(c.Showing.CheckpointSamples),
			kappaTupleString(c.Showing.Kappa),
			c.Showing.ReplayProjection,
			strconv.Itoa(c.Showing.CompressedRows),
			strconv.Itoa(c.Showing.SigShortnessRadix),
			strconv.Itoa(c.Showing.SigShortnessDigits),
			fmt.Sprintf("%.4f", c.IssuanceMetrics.TheoremTotalBits),
			fmt.Sprintf("%.4f", c.ShowingMetrics.TheoremTotalBits),
			fmt.Sprintf("%.4f", c.IssuanceMetrics.SoundnessEq8Bits),
			fmt.Sprintf("%.4f", c.ShowingMetrics.SoundnessEq8Bits),
			strconv.Itoa(c.ShowingMetrics.TotalRows),
			strconv.Itoa(c.ShowingMetrics.PRFRows),
			strconv.Itoa(c.ShowingMetrics.SmallFieldReplayRows),
			strconv.Itoa(c.ShowingMetrics.MaskRows),
			strconv.Itoa(c.ShowingMetrics.DQ),
			strconv.Itoa(c.ShowingMetrics.DDECS),
			strconv.Itoa(c.ShowingMetrics.QBytes),
			strconv.Itoa(c.ShowingMetrics.RBytes),
			strconv.Itoa(c.ShowingMetrics.PdecsBytes),
			strconv.Itoa(c.ShowingMetrics.AuthBytes),
			strconv.Itoa(c.ShowingMetrics.VTargetsBytes),
			strconv.Itoa(c.ShowingMetrics.BarSetsBytes),
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("write csv row %s: %w", path, err)
		}
	}
	return w.Error()
}

func parseStringCSV(s string) ([]string, error) {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !seen[part] {
			out = append(out, part)
			seen[part] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty string list")
	}
	return out, nil
}

func parsePRFCompanionModeCSV(s string) ([]PIOP.PRFCompanionMode, error) {
	parts, err := parseStringCSV(s)
	if err != nil {
		return nil, err
	}
	out := make([]PIOP.PRFCompanionMode, 0, len(parts))
	seen := make(map[PIOP.PRFCompanionMode]bool, len(parts))
	for _, part := range parts {
		mode := PIOP.PRFCompanionMode(strings.TrimSpace(part))
		if !validSweepPRFCompanionMode(mode) {
			return nil, fmt.Errorf("unsupported PRF companion mode %q", part)
		}
		if !seen[mode] {
			out = append(out, mode)
			seen[mode] = true
		}
	}
	return out, nil
}

func validSweepPRFCompanionMode(mode PIOP.PRFCompanionMode) bool {
	switch mode {
	case PIOP.PRFCompanionModeDirectAuth, PIOP.PRFCompanionModeOutputAudit, PIOP.PRFCompanionModeAuxInstance:
		return true
	default:
		return false
	}
}

func parseSweepShortnessCSV(s string) ([]sweepIntGenISISShortness, error) {
	parts := strings.Split(s, ",")
	out := make([]sweepIntGenISISShortness, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		rl := strings.Split(part, "/")
		if len(rl) != 2 {
			return nil, fmt.Errorf("shortness shape %q must be R/L", part)
		}
		r, err := strconv.Atoi(strings.TrimSpace(rl[0]))
		if err != nil {
			return nil, err
		}
		l, err := strconv.Atoi(strings.TrimSpace(rl[1]))
		if err != nil {
			return nil, err
		}
		out = append(out, sweepIntGenISISShortness{Radix: r, Digits: l})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty shortness list")
	}
	return out, nil
}

func parseKappaTuplesCSV(s string) ([][4]int, error) {
	parts := strings.Split(s, ",")
	out := make([][4]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ks := strings.Split(part, "/")
		if len(ks) != 4 {
			return nil, fmt.Errorf("kappa tuple %q must be k1/k2/k3/k4", part)
		}
		var k [4]int
		for i := 0; i < 4; i++ {
			v, err := strconv.Atoi(strings.TrimSpace(ks[i]))
			if err != nil {
				return nil, err
			}
			if v < 0 {
				return nil, fmt.Errorf("negative kappa in %q", part)
			}
			k[i] = v
		}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty kappa tuple list")
	}
	return out, nil
}

func defaultSweepEstimateKappas() [][4]int {
	return [][4]int{{0, 0, 0, 0}}
}

func validateSweepKappas(kappas [][4]int, maxPerRound int) error {
	if len(kappas) == 0 {
		return fmt.Errorf("empty kappa tuple list")
	}
	for _, k := range kappas {
		for round, v := range k {
			if v < 0 {
				return fmt.Errorf("negative kappa in tuple %s", kappaTupleString(k))
			}
			if v > maxPerRound {
				return fmt.Errorf("kappa%d=%d in tuple %s exceeds max per-round cap %d", round+1, v, kappaTupleString(k), maxPerRound)
			}
		}
	}
	return nil
}

func selectSweepKappaTopup(issuanceBase, showingBase benchmarkIntGenISISMetrics, kappas [][4]int, minBits, maxBits float64) ([4]int, benchmarkIntGenISISMetrics, benchmarkIntGenISISMetrics, float64, bool, bool) {
	var bestKappa [4]int
	var bestIssuance benchmarkIntGenISISMetrics
	var bestShowing benchmarkIntGenISISMetrics
	bestBits := 0.0
	bestSum := math.MaxInt
	bestMax := math.MaxInt
	found := false
	for _, kappa := range kappas {
		issuance := applySweepKappaToMetrics(issuanceBase, kappa)
		showing := applySweepKappaToMetrics(showingBase, kappa)
		bits := math.Min(issuance.TheoremTotalBits, showing.TheoremTotalBits)
		if bits < minBits || bits > maxBits {
			continue
		}
		sum := kappaSum(kappa)
		maxRound := kappaMax(kappa)
		if !found ||
			sum < bestSum ||
			(sum == bestSum && maxRound < bestMax) ||
			(sum == bestSum && maxRound == bestMax && bits < bestBits) {
			found = true
			bestKappa = kappa
			bestIssuance = issuance
			bestShowing = showing
			bestBits = bits
			bestSum = sum
			bestMax = maxRound
		}
	}
	if found {
		return bestKappa, bestIssuance, bestShowing, bestBits, true, false
	}
	zeroBits := math.Min(issuanceBase.TheoremTotalBits, showingBase.TheoremTotalBits)
	return [4]int{}, benchmarkIntGenISISMetrics{}, benchmarkIntGenISISMetrics{}, 0, false, zeroBits > maxBits
}

func applySweepKappaToMetrics(base benchmarkIntGenISISMetrics, kappa [4]int) benchmarkIntGenISISMetrics {
	out := base
	total := bitsToProbability(base.CollisionBits)
	for i := 0; i < 4; i++ {
		out.TheoremBits[i] = addBits(base.TheoremBits[i], float64(kappa[i]))
		total += bitsToProbability(out.TheoremBits[i])
	}
	out.TheoremTotalBits = probabilityToBits(total)
	return out
}

func addBits(bits, extra float64) float64 {
	if math.IsInf(bits, 1) {
		return bits
	}
	if math.IsInf(bits, -1) {
		return bits
	}
	return bits + extra
}

func bitsToProbability(bits float64) float64 {
	if math.IsInf(bits, 1) {
		return 0
	}
	if math.IsInf(bits, -1) || bits <= 0 {
		return 1
	}
	return math.Pow(2, -bits)
}

func probabilityToBits(p float64) float64 {
	if p <= 0 {
		return math.Inf(1)
	}
	if p >= 1 {
		return 0
	}
	return -math.Log2(p)
}

func kappaSum(k [4]int) int {
	return k[0] + k[1] + k[2] + k[3]
}

func kappaMax(k [4]int) int {
	max := k[0]
	for i := 1; i < 4; i++ {
		if k[i] > max {
			max = k[i]
		}
	}
	return max
}

func maxKappaByRound(kappas [][4]int) (round1 int, round4 int) {
	for _, k := range kappas {
		if k[0] > round1 {
			round1 = k[0]
		}
		if k[3] > round4 {
			round4 = k[3]
		}
	}
	return round1, round4
}

func sweepFamiliesFromAxes(thetas, rhos, ellPrimes []int) []sweepIntGenISISFamily {
	out := make([]sweepIntGenISISFamily, 0, len(thetas)*len(rhos)*len(ellPrimes))
	for _, theta := range thetas {
		for _, rho := range rhos {
			for _, ellPrime := range ellPrimes {
				out = append(out, sweepIntGenISISFamily{Theta: theta, Rho: rho, EllPrime: ellPrime})
			}
		}
	}
	return out
}

func kappaTupleString(k [4]int) string {
	return fmt.Sprintf("%d/%d/%d/%d", k[0], k[1], k[2], k[3])
}

func kappaTupleStrings(kappas [][4]int) []string {
	out := make([]string, len(kappas))
	for i, k := range kappas {
		out[i] = kappaTupleString(k)
	}
	return out
}

func bitsToBytesMain(bits float64) int {
	if bits <= 0 || math.IsNaN(bits) {
		return 0
	}
	return int(math.Ceil(bits / 8))
}

func ceilDivInt64ToInt(a, b int64) int {
	if b <= 0 || a <= 0 {
		return 0
	}
	return int((a + b - 1) / b)
}

func varintSizeMain(x int) int {
	if x < 0 {
		x = -x
	}
	ux := uint64(x)
	size := 1
	for ux >= 0x80 {
		size++
		ux >>= 7
	}
	return size
}

func powInt(base, exp int) int {
	if exp <= 0 {
		return 1
	}
	out := 1
	for i := 0; i < exp; i++ {
		out *= base
	}
	return out
}

func ceilDivMain(a, b int) int {
	if b <= 0 {
		return 0
	}
	if a <= 0 {
		return 0
	}
	return (a + b - 1) / b
}

func minIntMain(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
