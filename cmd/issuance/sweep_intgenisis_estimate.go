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
	sweepIntGenISISEstimateVersion         = 1
	sweepEstimateDefaultGrid               = "estimate-deep"
	sweepEstimateRuntime96Grid             = "runtime96"
	sweepEstimateRuntime96DeepGrid         = "runtime96-deep"
	sweepEstimateN1024TernaryDeepGrid      = "n1024-ternary-deep"
	sweepEstimateN1024TernaryLowLeavesGrid = "n1024-ternary-lowleaves"
	sweepEstimateN1024StrictSmallFieldGrid = "n1024-strict-smallfield-deep"
	sweepEstimateObjectiveFrontier         = "frontier"
	sweepEstimateObjectiveTranscript       = "transcript"
	sweepEstimateObjectiveRuntime          = "runtime96"
	sweepTranscriptModeBaseline            = "baseline"
	sweepTranscriptModeColumnWidths        = "column_widths_v1"
	sweepTranscriptModeSmallField2025      = "smallfield_2025_1085_v1"
	sweepTranscriptModeShortnessLookup     = "shortness_lookup_r25_l3"
	sweepTranscriptModeMSELookupPack2      = "mse_lookup_pack2"
	sweepEstimateDefaultMinBits            = 88.0
	sweepRuntime96TargetBits               = 96.0
	sweepRuntime96MaxShowingBytes          = 35000
	sweepEstimateDefaultMaxKappaPerRound   = 0
	sweepEstimateMaxKappaPerRound          = 12
	sweepEstimateMaxRecordedTuples         = 2000
	sweepEstimatePRFGroupRounds            = 2
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
	Objective        string

	NCols            []int
	LVCSNCols        []int
	Ell              []int
	NLeavesBase      []int
	ExhaustiveLeaves bool
	Families         []sweepIntGenISISFamily
	Shortness        []sweepIntGenISISShortness
	Compression      []int
	TranscriptModes  []string
	Projection       []string
	PRFModes         []PIOP.PRFCompanionMode
	PRFGroupRounds   []int
	Checkpoints      []int
	Kappa            [][4]int
	EtaSlack         int
	MaxEta           int
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
	RuntimeScore           float64                    `json:"runtime_score,omitempty"`
	RuntimeLog2NLeaves     float64                    `json:"runtime_log2_nleaves,omitempty"`
	TranscriptMode         string                     `json:"transcript_mode,omitempty"`
	SecurityStatus         string                     `json:"security_status,omitempty"`
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
	Version            int                                     `json:"version"`
	Generated          string                                  `json:"generated_at"`
	Grid               sweepIntGenISISGridSummary              `json:"grid"`
	Profiles           []string                                `json:"profiles"`
	SoundnessMetric    string                                  `json:"soundness_metric"`
	SoundnessMin       float64                                 `json:"soundness_min_bits"`
	SoundnessMax       float64                                 `json:"soundness_max_bits"`
	MaxShowingBytes    int                                     `json:"max_showing_paper_transcript_bytes"`
	MaxNLeaves         int                                     `json:"max_nleaves"`
	Objective          string                                  `json:"objective"`
	RuntimeScoreMetric string                                  `json:"runtime_score_metric,omitempty"`
	AcceptedCount      int                                     `json:"accepted_count"`
	Rejected           sweepIntGenISISEstimateRejectedCounts   `json:"rejected_counts"`
	FrontierAll        []sweepIntGenISISEstimateCandidate      `json:"frontier_all"`
	Frontier96         []sweepIntGenISISEstimateCandidate      `json:"frontier_96"`
	Frontier128        []sweepIntGenISISEstimateCandidate      `json:"frontier_128"`
	FrontierRuntime96  []sweepIntGenISISEstimateCandidate      `json:"frontier_runtime96,omitempty"`
	EstimatorNotes     []string                                `json:"estimator_notes"`
	ValidationTargets  []sweepIntGenISISEstimatorValidationRef `json:"validation_targets"`
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
	UDigitOnly            bool
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
	maxKappaPerRound := fs.Int("max-kappa-per-round", sweepEstimateDefaultMaxKappaPerRound, "maximum grinding bits per SmallWood theorem round; estimate sweeps default to zero-grinding candidates only")
	objectiveFlag := fs.String("objective", sweepEstimateObjectiveFrontier, "candidate ordering objective: frontier, transcript, or runtime96")
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
	shortnessCSV := fs.String("shortness", "", "comma-separated signed-radix shapes R/L; default uses the selected grid preset")
	compressionCSV := fs.String("compression-levels", "", "optional comma-separated M/s/e compression levels")
	projectionCSV := fs.String("projection-modes", "", "optional comma-separated projection modes")
	prfModesCSV := fs.String("prf-companion-modes", "", "comma-separated PRF companion modes: direct_auth, output_audit, aux_instance")
	prfGroupRoundsCSV := fs.String("prf-group-rounds", "", "comma-separated grouped PRF round counts; default uses the selected grid preset")
	checkpointSamplesCSV := fs.String("prf-checkpoint-samples", "", "comma-separated PRF companion checkpoint sample counts; default uses the selected grid preset")
	kappaCSV := fs.String("kappa-tuples", "", "optional comma-separated kappa tuples k1/k2/k3/k4")
	transcriptModesCSV := fs.String("transcript-modes", "", "comma-separated paper transcript modes: baseline,column_widths_v1,smallfield_2025_1085_v1,shortness_lookup_r25_l3,mse_lookup_pack2")
	etaSlack := fs.Int("eta-slack", 0, "eta values above the minimum to test; 0 uses the selected grid preset")
	maxEta := fs.Int("max-eta", 0, "maximum eta to test; 0 uses the selected grid preset")
	if err := fs.Parse(args); err != nil {
		return err
	}
	objective, err := normalizeSweepEstimateObjective(*objectiveFlag)
	if err != nil {
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
	if *shortnessCSV != "" {
		grid.Shortness, err = parseSweepShortnessCSV(*shortnessCSV)
		if err != nil {
			return fmt.Errorf("parse -shortness: %w", err)
		}
	} else if len(grid.Shortness) == 0 {
		grid.Shortness = []sweepIntGenISISShortness{
			{Radix: 11, Digits: 4},
			{Radix: 7, Digits: 5},
			{Radix: 5, Digits: 6},
		}
	}
	if *compressionCSV != "" {
		grid.Compression, err = parseNonNegativeIntCSV(*compressionCSV)
		if err != nil {
			return fmt.Errorf("parse -compression-levels: %w", err)
		}
	}
	if *projectionCSV != "" {
		grid.Projection, err = parseStringCSV(*projectionCSV)
		if err != nil {
			return fmt.Errorf("parse -projection-modes: %w", err)
		}
	} else if len(grid.Projection) == 0 {
		grid.Projection = []string{PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2}
	}
	projectionModes := append([]string(nil), grid.Projection...)
	var prfModes []PIOP.PRFCompanionMode
	if *prfModesCSV != "" {
		prfModes, err = parsePRFCompanionModeCSV(*prfModesCSV)
		if err != nil {
			return fmt.Errorf("parse -prf-companion-modes: %w", err)
		}
	} else if len(grid.PRFModes) > 0 {
		prfModes = append([]PIOP.PRFCompanionMode(nil), grid.PRFModes...)
	} else {
		prfModes = []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth}
	}
	var prfGroupRounds []int
	if *prfGroupRoundsCSV != "" {
		prfGroupRounds, err = parseIntCSV(*prfGroupRoundsCSV)
		if err != nil {
			return fmt.Errorf("parse -prf-group-rounds: %w", err)
		}
	} else if len(grid.PRFGroups) > 0 {
		prfGroupRounds = append([]int(nil), grid.PRFGroups...)
	} else {
		prfGroupRounds = []int{sweepEstimatePRFGroupRounds}
	}
	var checkpoints []int
	if *checkpointSamplesCSV != "" {
		checkpoints, err = parseIntCSV(*checkpointSamplesCSV)
		if err != nil {
			return fmt.Errorf("parse -prf-checkpoint-samples: %w", err)
		}
	} else if len(grid.Checkpoints) > 0 {
		checkpoints = append([]int(nil), grid.Checkpoints...)
	} else {
		checkpoints = []int{2}
	}
	kappas := defaultSweepEstimateKappas()
	if *kappaCSV != "" {
		kappas, err = parseKappaTuplesCSV(*kappaCSV)
		if err != nil {
			return fmt.Errorf("parse -kappa-tuples: %w", err)
		}
	} else if *maxKappaPerRound > 0 {
		kappas = generatedSweepEstimateKappas(*maxKappaPerRound)
	}
	if *maxKappaPerRound < 0 || *maxKappaPerRound > sweepEstimateMaxKappaPerRound {
		return fmt.Errorf("-max-kappa-per-round must be in [0,%d]", sweepEstimateMaxKappaPerRound)
	}
	if err := validateSweepKappas(kappas, *maxKappaPerRound); err != nil {
		return err
	}
	if *etaSlack < 0 {
		return fmt.Errorf("-eta-slack must be non-negative")
	}
	if *maxEta < 0 {
		return fmt.Errorf("-max-eta must be non-negative")
	}
	if *etaSlack > 0 {
		grid.EtaSlack = *etaSlack
	}
	if *maxEta > 0 {
		grid.MaxEta = *maxEta
	}
	if grid.EtaSlack <= 0 {
		grid.EtaSlack = 4
	}
	if grid.MaxEta <= 0 {
		grid.MaxEta = 160
	}
	transcriptModes := []string{sweepTranscriptModeBaseline}
	if *transcriptModesCSV != "" {
		transcriptModes, err = parseSweepTranscriptModeCSV(*transcriptModesCSV)
		if err != nil {
			return fmt.Errorf("parse -transcript-modes: %w", err)
		}
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
		Objective:        objective,
		NCols:            grid.NCols,
		LVCSNCols:        grid.LVCSNCols,
		Ell:              grid.Ell,
		NLeavesBase:      grid.NLeavesBase,
		ExhaustiveLeaves: grid.ExhaustiveNLeaves,
		Families:         grid.Families,
		Shortness:        grid.Shortness,
		Compression:      grid.Compression,
		TranscriptModes:  transcriptModes,
		Projection:       projectionModes,
		PRFModes:         prfModes,
		PRFGroupRounds:   prfGroupRounds,
		Checkpoints:      checkpoints,
		Kappa:            kappas,
		EtaSlack:         grid.EtaSlack,
		MaxEta:           grid.MaxEta,
	}
	report, err := sweepIntGenISISEstimate(cfg)
	if err != nil {
		return err
	}
	if len(report.FrontierAll) > 0 {
		best := report.FrontierAll[0]
		fmt.Printf("[issuance-cli] estimate sweep best objective=%s score=%.2f profile=%s bits=%.2f showing_bytes=%d ncols=%d lvcs=%d nleaves=%d theta=%d rho=%d ell=%d ell'=%d short=%d/%d comp=%d projection=%s prf_mode=%s prf_group_rounds=%d prf_samples=%d\n",
			report.Objective,
			sweepEstimateObjectiveScore(report.Objective, best),
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

func runSweepIntGenISISRuntime96(args []string) error {
	defaultArgs := []string{
		"-profiles", credential.ProfileIntGenISISA,
		"-grid", sweepEstimateRuntime96Grid,
		"-soundness-min", strconv.FormatFloat(sweepRuntime96TargetBits, 'f', 0, 64),
		"-soundness-max", "135",
		"-max-showing-bytes", strconv.Itoa(sweepRuntime96MaxShowingBytes),
		"-objective", sweepEstimateObjectiveRuntime,
		"-prf-companion-modes", string(PIOP.PRFCompanionModeDirectAuth),
		"-prf-group-rounds", strconv.Itoa(sweepEstimatePRFGroupRounds),
		"-prf-checkpoint-samples", "2",
		"-out-dir", filepath.Join("credential", "issuance", "intgenisis_runtime96_sweeps", "run_"+time.Now().UTC().Format("20060102_150405")),
	}
	return runSweepIntGenISISEstimate(append(defaultArgs, args...))
}

func runSweepIntGenISISRuntime96Deep(args []string) error {
	defaultArgs := []string{
		"-profiles", credential.ProfileIntGenISISA,
		"-grid", sweepEstimateRuntime96DeepGrid,
		"-soundness-min", strconv.FormatFloat(sweepRuntime96TargetBits, 'f', 0, 64),
		"-soundness-max", "135",
		"-max-showing-bytes", strconv.Itoa(sweepRuntime96MaxShowingBytes),
		"-objective", sweepEstimateObjectiveRuntime,
		"-top-k", "1000",
		"-prf-companion-modes", string(PIOP.PRFCompanionModeDirectAuth),
		"-prf-group-rounds", strconv.Itoa(sweepEstimatePRFGroupRounds),
		"-prf-checkpoint-samples", "2,4",
		"-out-dir", filepath.Join("credential", "issuance", "intgenisis_runtime96_deep_sweeps", "run_"+time.Now().UTC().Format("20060102_150405")),
	}
	return runSweepIntGenISISEstimate(append(defaultArgs, args...))
}

func runSweepIntGenISISN1024TernaryDeep(args []string) error {
	defaultArgs := []string{
		"-profiles", credential.ProfileIntGenISISC,
		"-grid", sweepEstimateN1024TernaryDeepGrid,
		"-soundness-min", "96",
		"-soundness-max", "180",
		"-max-showing-bytes", "90000",
		"-max-nleaves", "0",
		"-objective", sweepEstimateObjectiveTranscript,
		"-top-k", strconv.Itoa(sweepEstimateMaxRecordedTuples),
		"-progress-interval", "1",
		"-checkpoint-interval", "250",
		"-out-dir", filepath.Join("credential", "issuance", "intgenisis_n1024_ternary_deep_sweeps", "run_"+time.Now().UTC().Format("20060102_150405")),
	}
	return runSweepIntGenISISEstimate(append(defaultArgs, args...))
}

func runSweepIntGenISISN1024TernaryLowLeaves(args []string) error {
	defaultArgs := []string{
		"-profiles", credential.ProfileIntGenISISC,
		"-grid", sweepEstimateN1024TernaryLowLeavesGrid,
		"-soundness-min", "96",
		"-soundness-max", "140",
		"-max-showing-bytes", "70000",
		"-max-nleaves", "262144",
		"-objective", sweepEstimateObjectiveRuntime,
		"-top-k", "1000",
		"-progress-interval", "1",
		"-checkpoint-interval", "250",
		"-out-dir", filepath.Join("credential", "issuance", "intgenisis_n1024_ternary_lowleaves_sweeps", "run_"+time.Now().UTC().Format("20060102_150405")),
	}
	return runSweepIntGenISISEstimate(append(defaultArgs, args...))
}

func runSweepIntGenISISN1024StrictSmallField90Zero(args []string) error {
	return runSweepIntGenISISN1024StrictSmallFieldZero(90, args)
}

func runSweepIntGenISISN1024StrictSmallField115Zero(args []string) error {
	return runSweepIntGenISISN1024StrictSmallFieldZero(115, args)
}

func runSweepIntGenISISN1024StrictSmallFieldZero(targetBits float64, args []string) error {
	defaultArgs := sweepIntGenISISN1024StrictSmallFieldZeroArgs(targetBits)
	return runSweepIntGenISISEstimate(append(defaultArgs, args...))
}

func sweepIntGenISISN1024StrictSmallFieldZeroArgs(targetBits float64) []string {
	target := strconv.FormatFloat(targetBits, 'f', 0, 64)
	maxBits := strconv.FormatFloat(math.Max(135, targetBits+35), 'f', 0, 64)
	targetTag := strings.ReplaceAll(target, ".", "p")
	return []string{
		"-profiles", credential.ProfileIntGenISISC,
		"-grid", sweepEstimateN1024StrictSmallFieldGrid,
		"-soundness-min", target,
		"-soundness-max", maxBits,
		"-max-showing-bytes", "60000",
		"-max-nleaves", "0",
		"-objective", sweepEstimateObjectiveTranscript,
		"-top-k", strconv.Itoa(sweepEstimateMaxRecordedTuples),
		"-progress-interval", "1",
		"-checkpoint-interval", "250",
		"-transcript-modes", sweepTranscriptModeSmallField2025,
		"-kappa-tuples", "0/0/0/0",
		"-max-kappa-per-round", "0",
		"-projection-modes", PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2,
		"-prf-companion-modes", string(PIOP.PRFCompanionModeDirectAuth),
		"-out-dir", filepath.Join("credential", "issuance", "intgenisis_n1024_strict_smallfield_zero_grinding", "sw"+targetTag+"_run_"+time.Now().UTC().Format("20060102_150405")),
	}
}

func sweepIntGenISISEstimate(cfg sweepIntGenISISEstimateConfig) (sweepIntGenISISEstimateReport, error) {
	objective, err := normalizeSweepEstimateObjective(cfg.Objective)
	if err != nil {
		return sweepIntGenISISEstimateReport{}, err
	}
	cfg.Objective = objective
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
	if len(cfg.TranscriptModes) == 0 {
		cfg.TranscriptModes = []string{sweepTranscriptModeBaseline}
	}
	for i, mode := range cfg.TranscriptModes {
		normalized, err := normalizeSweepTranscriptMode(mode)
		if err != nil {
			return sweepIntGenISISEstimateReport{}, err
		}
		cfg.TranscriptModes[i] = normalized
	}
	if cfg.OutDir == "" {
		cfg.OutDir = filepath.Join("credential", "issuance", "intgenisis_estimate_sweeps", "run_"+time.Now().UTC().Format("20060102_150405"))
	}
	if cfg.EtaSlack <= 0 {
		cfg.EtaSlack = 4
	}
	if cfg.MaxEta <= 0 {
		cfg.MaxEta = 160
	}
	if err := prepareEstimateOutDir(cfg.OutDir, cfg.Force); err != nil {
		return sweepIntGenISISEstimateReport{}, err
	}

	grid := sweepIntGenISISGrid{
		Name:              cfg.Grid,
		Families:          cfg.Families,
		NCols:             cfg.NCols,
		LVCSNCols:         cfg.LVCSNCols,
		Ell:               cfg.Ell,
		NLeavesBase:       cfg.NLeavesBase,
		ExhaustiveNLeaves: cfg.ExhaustiveLeaves,
		Shortness:         cfg.Shortness,
		Compression:       cfg.Compression,
		Projection:        append([]string(nil), cfg.Projection...),
		PRFModes:          append([]PIOP.PRFCompanionMode(nil), cfg.PRFModes...),
		PRFGroups:         append([]int(nil), cfg.PRFGroupRounds...),
		Checkpoints:       append([]int(nil), cfg.Checkpoints...),
		EtaSlack:          cfg.EtaSlack,
		MaxEta:            cfg.MaxEta,
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
		TranscriptModes   []string `json:"transcript_modes"`
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
		Objective         string   `json:"objective"`
		RuntimeScore      string   `json:"runtime_score_metric,omitempty"`
	}{
		sweepIntGenISISGridSummary: gridConfig,
		Profiles:                   append([]string(nil), cfg.Profiles...),
		ProjectionModes:            append([]string(nil), cfg.Projection...),
		TranscriptModes:            append([]string(nil), cfg.TranscriptModes...),
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
		KappaSelection:             sweepEstimateKappaSelectionLabel(cfg),
		Objective:                  cfg.Objective,
		RuntimeScore:               sweepRuntimeScoreMetric(cfg.Objective),
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
	if cfg.Progress {
		fmt.Fprintf(os.Stderr, "[issuance-cli] estimate sweep starting grid=%s profiles=%s outer=%d out=%s axes={families=%d ncols=%d lvcs=%d ell=%d leaves=%d short=%d comp=%d transcript_modes=%d projection=%d prf_modes=%d groups=%d checkpoints=%d eta_slack=%d max_eta=%d}\n",
			cfg.Grid,
			strings.Join(cfg.Profiles, ","),
			outerTotal,
			cfg.OutDir,
			len(cfg.Families),
			len(cfg.NCols),
			len(cfg.LVCSNCols),
			len(cfg.Ell),
			len(cfg.NLeavesBase),
			len(cfg.Shortness),
			len(cfg.Compression),
			len(cfg.TranscriptModes),
			len(cfg.Projection),
			len(cfg.PRFModes),
			len(cfg.PRFGroupRounds),
			len(cfg.Checkpoints),
			cfg.EtaSlack,
			cfg.MaxEta,
		)
	}
	outerDone := 0
	progressCurrent := ""
	writeCheckpoint := func(final bool) error {
		if !final && cfg.CheckpointEvery == 0 {
			return nil
		}
		if !final && cfg.CheckpointEvery > 0 && outerDone%cfg.CheckpointEvery != 0 {
			return nil
		}
		return writeEstimateProgressCheckpoint(cfg.OutDir, accepted, rejected, outerDone, outerTotal, started, progressCurrent, cfg.TopK, cfg.Objective)
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
														for _, transcriptMode := range cfg.TranscriptModes {
															if !sweepTranscriptModeApplies(transcriptMode, showing) {
																continue
															}
															showingMode := showing
															showingMode.TranscriptMode = transcriptMode
															rejected.GeneratedCandidates++
															showingMetricsBase, err := estimateIntGenISISMetrics(profile, showingMode, "showing")
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
															showingMode.Kappa = kappa
															runtimeScore, runtimeLog2Leaves := sweepRuntimeScore(showingMetrics.PaperTranscriptBytes, showingMode.NLeaves)
															id++
															cand := sweepIntGenISISEstimateCandidate{
																ID:                     fmt.Sprintf("est_%06d", id),
																Profile:                profile.Name,
																RingDegree:             profile.N,
																Q:                      profile.Q,
																Issuance:               issuance,
																Showing:                showingMode,
																IssuanceMetrics:        issuanceMetrics,
																ShowingMetrics:         showingMetrics,
																CandidateTheoremBits:   candBits,
																CandidateEq8Bits:       math.Min(issuanceMetrics.SoundnessEq8Bits, showingMetrics.SoundnessEq8Bits),
																ShowingTranscriptBytes: showingMetrics.PaperTranscriptBytes,
																TotalTranscriptBytes:   issuanceMetrics.PaperTranscriptBytes + showingMetrics.PaperTranscriptBytes,
																RuntimeScore:           runtimeScore,
																RuntimeLog2NLeaves:     runtimeLog2Leaves,
																TranscriptMode:         transcriptMode,
																SecurityStatus:         sweepTranscriptSecurityStatus(transcriptMode),
															}
															accepted = append(accepted, cand)
															rejected.AcceptedCandidates++
															accepted = pruneEstimateCandidates(accepted, cfg.TopK, cfg.Objective)
														}
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

	targetPool := append([]sweepIntGenISISEstimateCandidate(nil), accepted...)
	accepted = selectEstimateCandidates(accepted, cfg.TopK, cfg.Objective)
	sortEstimateCandidatesForObjective(accepted, 0, cfg.Objective)
	frontierAll := limitEstimateCandidates(accepted, cfg.TopK)
	frontier96 := estimateTargetFrontier(targetPool, 96, cfg.TopK, cfg.Objective)
	frontier128 := estimateTargetFrontier(targetPool, 128, cfg.TopK, cfg.Objective)
	var frontierRuntime96 []sweepIntGenISISEstimateCandidate
	if cfg.Objective == sweepEstimateObjectiveRuntime {
		frontierRuntime96 = estimateRuntimeTargetFrontier(accepted, sweepRuntime96TargetBits, cfg.TopK)
	}
	report := sweepIntGenISISEstimateReport{
		Version:            sweepIntGenISISEstimateVersion,
		Generated:          time.Now().UTC().Format(time.RFC3339),
		Grid:               gridConfig,
		Profiles:           cfg.Profiles,
		SoundnessMetric:    "smallwood_theorem9_min_issuance_showing",
		SoundnessMin:       cfg.SoundnessMin,
		SoundnessMax:       cfg.SoundnessMax,
		MaxShowingBytes:    cfg.MaxShowingBytes,
		MaxNLeaves:         cfg.MaxNLeaves,
		Objective:          cfg.Objective,
		RuntimeScoreMetric: sweepRuntimeScoreMetric(cfg.Objective),
		AcceptedCount:      rejected.AcceptedCandidates,
		Rejected:           rejected,
		FrontierAll:        frontierAll,
		Frontier96:         frontier96,
		Frontier128:        frontier128,
		FrontierRuntime96:  frontierRuntime96,
		EstimatorNotes: []string{
			"This is an estimate-only report: no proofs, signatures, verifier states, or presentations were generated.",
			"The sweep records only bounded efficient frontiers or transcript-only leaderboards; all accepted candidates are counted but not streamed to disk.",
			"Q and R buckets use the same closed-form paper formulas as the live report.",
			"Pdecs/Auth/VTargets/BarSets are deterministic conservative estimates calibrated to current IntGenISIS measured geometry; use benchmark-intgenisis-e2e for final promotion.",
			"Candidate bits are min(issuance theorem_total_bits, showing theorem_total_bits); raw Eq. (8) bits are recorded but not used as the filter.",
			"Transcript modes labelled protocol_change_estimate are estimator-only research models and are not security-preserving live proof modes until verifier support is added.",
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
	summary.FrontierRuntime96 = nil
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
	if cfg.Objective == sweepEstimateObjectiveRuntime {
		if err := writeJSONFile(filepath.Join(cfg.OutDir, "frontier_runtime96.json"), frontierRuntime96, 0o644); err != nil {
			return sweepIntGenISISEstimateReport{}, fmt.Errorf("write frontier_runtime96.json: %w", err)
		}
		if err := writeEstimateCSV(filepath.Join(cfg.OutDir, "frontier_runtime96.csv"), frontierRuntime96); err != nil {
			return sweepIntGenISISEstimateReport{}, err
		}
	}
	fmt.Printf("[issuance-cli] sweep-intgenisis-estimate wrote %s accepted=%d generated=%d\n", cfg.OutDir, rejected.AcceptedCandidates, rejected.GeneratedCandidates)
	return report, nil
}

func sweepRuntime96Families(deep bool) []sweepIntGenISISFamily {
	families := []sweepIntGenISISFamily{
		{Theta: 2, Rho: 3, EllPrime: 3},
		{Theta: 2, Rho: 3, EllPrime: 4},
		{Theta: 2, Rho: 4, EllPrime: 3},
		{Theta: 2, Rho: 4, EllPrime: 4},
		{Theta: 3, Rho: 2, EllPrime: 2},
		{Theta: 3, Rho: 2, EllPrime: 3},
		{Theta: 4, Rho: 2, EllPrime: 1},
		{Theta: 4, Rho: 2, EllPrime: 2},
		{Theta: 5, Rho: 1, EllPrime: 1},
		{Theta: 6, Rho: 1, EllPrime: 1},
		{Theta: 7, Rho: 1, EllPrime: 1},
		{Theta: 1, Rho: 5, EllPrime: 9},
		{Theta: 1, Rho: 6, EllPrime: 9},
		{Theta: 1, Rho: 6, EllPrime: 10},
		{Theta: 1, Rho: 7, EllPrime: 11},
		{Theta: 1, Rho: 7, EllPrime: 12},
	}
	if !deep {
		return families
	}
	add := func(theta, rho, ellPrime int) {
		family := sweepIntGenISISFamily{Theta: theta, Rho: rho, EllPrime: ellPrime}
		for _, existing := range families {
			if existing == family {
				return
			}
		}
		families = append(families, family)
	}
	for rho := 3; rho <= 5; rho++ {
		for ellPrime := 2; ellPrime <= 5; ellPrime++ {
			add(2, rho, ellPrime)
		}
	}
	for _, rho := range []int{2, 3} {
		for ellPrime := 1; ellPrime <= 4; ellPrime++ {
			add(3, rho, ellPrime)
		}
	}
	for _, rho := range []int{2, 3} {
		for ellPrime := 1; ellPrime <= 3; ellPrime++ {
			add(4, rho, ellPrime)
		}
	}
	for _, theta := range []int{5, 6} {
		for _, rho := range []int{1, 2} {
			for ellPrime := 1; ellPrime <= 2; ellPrime++ {
				add(theta, rho, ellPrime)
			}
		}
	}
	for _, rho := range []int{1, 2} {
		add(7, rho, 1)
	}
	for _, theta := range []int{8, 9} {
		add(theta, 1, 1)
	}
	for rho := 4; rho <= 9; rho++ {
		for ellPrime := 8; ellPrime <= 15; ellPrime++ {
			add(1, rho, ellPrime)
		}
	}
	return families
}

func sweepN1024TernaryFamilies() []sweepIntGenISISFamily {
	families := make([]sweepIntGenISISFamily, 0, 64)
	add := func(theta, rho, ellPrime int) {
		if theta <= 0 || rho <= 0 || ellPrime <= 0 {
			return
		}
		family := sweepIntGenISISFamily{Theta: theta, Rho: rho, EllPrime: ellPrime}
		for _, existing := range families {
			if existing == family {
				return
			}
		}
		families = append(families, family)
	}
	for _, fam := range []sweepIntGenISISFamily{
		// Theta=1 high-rho baselines preserve the rho/ell' maxima but only
		// sample logarithmic interior points.
		{Theta: 1, Rho: 3, EllPrime: 4},
		{Theta: 1, Rho: 8, EllPrime: 16},
		{Theta: 1, Rho: 10, EllPrime: 18},
		{Theta: 1, Rho: 14, EllPrime: 24},
		// Low-theta families are the likely sweet-spot band.
		{Theta: 2, Rho: 1, EllPrime: 1},
		{Theta: 2, Rho: 2, EllPrime: 2},
		{Theta: 2, Rho: 2, EllPrime: 3},
		{Theta: 2, Rho: 2, EllPrime: 4},
		{Theta: 2, Rho: 3, EllPrime: 2},
		{Theta: 2, Rho: 3, EllPrime: 3},
		{Theta: 2, Rho: 3, EllPrime: 4},
		{Theta: 2, Rho: 3, EllPrime: 5},
		{Theta: 2, Rho: 4, EllPrime: 2},
		{Theta: 2, Rho: 4, EllPrime: 3},
		{Theta: 2, Rho: 4, EllPrime: 4},
		{Theta: 2, Rho: 4, EllPrime: 5},
		{Theta: 2, Rho: 6, EllPrime: 6},
		{Theta: 2, Rho: 10, EllPrime: 12},
		{Theta: 3, Rho: 1, EllPrime: 1},
		{Theta: 3, Rho: 2, EllPrime: 2},
		{Theta: 3, Rho: 2, EllPrime: 3},
		{Theta: 3, Rho: 2, EllPrime: 4},
		{Theta: 3, Rho: 3, EllPrime: 2},
		{Theta: 3, Rho: 3, EllPrime: 3},
		{Theta: 3, Rho: 3, EllPrime: 4},
		{Theta: 3, Rho: 8, EllPrime: 10},
		// Higher-theta strata keep min/interior/max representatives.
		{Theta: 4, Rho: 1, EllPrime: 1},
		{Theta: 4, Rho: 2, EllPrime: 2},
		{Theta: 4, Rho: 5, EllPrime: 8},
		{Theta: 6, Rho: 1, EllPrime: 1},
		{Theta: 6, Rho: 2, EllPrime: 2},
		{Theta: 8, Rho: 1, EllPrime: 1},
		{Theta: 8, Rho: 3, EllPrime: 4},
		{Theta: 10, Rho: 1, EllPrime: 1},
		{Theta: 10, Rho: 2, EllPrime: 2},
		{Theta: 12, Rho: 1, EllPrime: 1},
		{Theta: 12, Rho: 2, EllPrime: 3},
		{Theta: 16, Rho: 1, EllPrime: 1},
		{Theta: 16, Rho: 2, EllPrime: 3},
		{Theta: 24, Rho: 1, EllPrime: 1},
		{Theta: 24, Rho: 2, EllPrime: 3},
	} {
		add(fam.Theta, fam.Rho, fam.EllPrime)
	}
	return families
}

func sweepN1024TernaryNLeavesBase() []int {
	return []int{
		64, 256, 1024, 4096, 16384, 65536, 262144,
		524288, 786432, 819200, 884736, 917504, 950272,
		983040, 1015808, 1048576, 1054720,
	}
}

func sweepN1024TernaryEll() []int {
	return []int{
		4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 24, 32, 48, 64, 96, 160,
	}
}

func sweepN1024TernaryLowLeavesFamilies() []sweepIntGenISISFamily {
	families := make([]sweepIntGenISISFamily, 0, 128)
	add := func(theta, rho, ellPrime int) {
		if theta <= 0 || rho <= 0 || ellPrime <= 0 {
			return
		}
		family := sweepIntGenISISFamily{Theta: theta, Rho: rho, EllPrime: ellPrime}
		for _, existing := range families {
			if existing == family {
				return
			}
		}
		families = append(families, family)
	}
	for theta := 1; theta <= 6; theta++ {
		for rho := 2; rho <= 6; rho++ {
			for ellPrime := 2; ellPrime <= 8; ellPrime++ {
				add(theta, rho, ellPrime)
			}
		}
	}
	for _, fam := range []sweepIntGenISISFamily{
		{Theta: 1, Rho: 6, EllPrime: 8},
		{Theta: 1, Rho: 8, EllPrime: 12},
		{Theta: 1, Rho: 10, EllPrime: 16},
		{Theta: 2, Rho: 6, EllPrime: 6},
		{Theta: 2, Rho: 8, EllPrime: 10},
		{Theta: 3, Rho: 6, EllPrime: 6},
		{Theta: 3, Rho: 8, EllPrime: 10},
		{Theta: 4, Rho: 6, EllPrime: 6},
		{Theta: 4, Rho: 8, EllPrime: 10},
		{Theta: 6, Rho: 2, EllPrime: 3},
		{Theta: 6, Rho: 3, EllPrime: 4},
		{Theta: 6, Rho: 6, EllPrime: 8},
		{Theta: 8, Rho: 2, EllPrime: 3},
		{Theta: 8, Rho: 3, EllPrime: 4},
		{Theta: 8, Rho: 4, EllPrime: 6},
		{Theta: 10, Rho: 2, EllPrime: 3},
		{Theta: 10, Rho: 3, EllPrime: 4},
		{Theta: 12, Rho: 2, EllPrime: 4},
		{Theta: 12, Rho: 3, EllPrime: 5},
	} {
		add(fam.Theta, fam.Rho, fam.EllPrime)
	}
	return families
}

func sweepN1024TernaryLowLeavesNLeavesBase() []int {
	return []int{
		64, 128, 256, 512, 768, 1024, 1536, 2048, 3072, 4096,
		6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536,
		81920, 98304, 131072, 180000, 196608, 262144, 327680,
		393216,
	}
}

func sweepN1024TernaryLowLeavesEll() []int {
	return []int{
		12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72, 80, 96, 112, 128, 160, 192, 224, 256,
	}
}

func sweepN1024StrictSmallFieldFamilies() []sweepIntGenISISFamily {
	families := make([]sweepIntGenISISFamily, 0, 15)
	for theta := 2; theta <= 16; theta++ {
		families = append(families, sweepIntGenISISFamily{Theta: theta, Rho: 1, EllPrime: 1})
	}
	return families
}

func sweepN1024StrictSmallFieldNLeavesBase() []int {
	return []int{
		64, 256, 1024, 4096, 16384, 32768, 65536, 98304,
		116864, 131072, 180000, 196608, 262144, 327680,
		393216, 524288, 786432, 950272, 1048576, 1054720,
	}
}

func sweepN1024StrictSmallFieldEll() []int {
	return []int{
		5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		18, 20, 24, 28, 32, 40, 48, 64,
	}
}

func sweepIntGenISISEstimateGridFor(name string) (sweepIntGenISISGrid, error) {
	switch strings.TrimSpace(strings.ToLower(name)) {
	case sweepEstimateN1024StrictSmallFieldGrid, "n1024-strict-smallfield", "n1024-smallfield-deep", "n1024-sw-smallfield-deep", "strict-smallfield1024":
		return sweepIntGenISISGrid{
			Name:              sweepEstimateN1024StrictSmallFieldGrid,
			Families:          sweepN1024StrictSmallFieldFamilies(),
			NCols:             []int{16, 32, 64, 128, 256, 512, 1024},
			LVCSNCols:         []int{16, 24, 32, 36, 40, 44, 48, 52, 56, 60, 64, 72, 80, 88, 96, 112, 128, 160, 192, 224, 256, 384, 512, 768, 1024},
			Ell:               sweepN1024StrictSmallFieldEll(),
			NLeavesBase:       sweepN1024StrictSmallFieldNLeavesBase(),
			ExhaustiveNLeaves: false,
			Shortness: []sweepIntGenISISShortness{
				{Radix: 111, Digits: 2},
				{Radix: 25, Digits: 3},
				{Radix: 17, Digits: 4},
				{Radix: 13, Digits: 4},
				{Radix: 11, Digits: 4},
				{Radix: 9, Digits: 5},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
				{Radix: 3, Digits: 9},
			},
			Compression: []int{0, 1, 2},
			Projection:  []string{PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth},
			PRFGroups:   []int{2, 3, 5, 8},
			Checkpoints: []int{1, 2, 4, 8},
			EtaSlack:    6,
			MaxEta:      240,
			Notes: []string{
				"N=1024 strict small-field grid fixes profile-C, rho=1, ell'=1, and is intended for smallfield_2025_1085_v1 transcript sweeps.",
				"The dedicated zero-grinding wrappers force kappa=0/0/0/0; use the generic estimate command with -max-kappa-per-round only for separate grinding studies.",
				"Theta is scanned from 2 through 16 because strict smallfield requires theta>1 and the 90/115-bit bands typically sit in the theta=5..8 neighborhood.",
				"LVCS and ell axes are dense around the known strict-smallfield basin lvcs=40..64 and ell=6..10, while retaining wider 1024-degree probes for row-block threshold effects.",
				"Compression levels 0, 1, and 2 are estimate-visible for ternary B=1; live promotion still requires benchmark-intgenisis-e2e verification and honest dQ accounting.",
				"Shortness shapes include high-radix row reducers and low-degree R7/L5/R5/L6 baselines so the sweep exposes transcript-vs-degree tradeoffs without selected replay.",
			},
		}, nil
	case sweepEstimateN1024TernaryDeepGrid, "n1024-deep", "n1024-b1-deep", "n1024-ternary", "ternary1024-deep":
		return sweepIntGenISISGrid{
			Name:              sweepEstimateN1024TernaryDeepGrid,
			Families:          sweepN1024TernaryFamilies(),
			NCols:             []int{16, 32, 64, 128, 256, 512, 1024},
			LVCSNCols:         []int{16, 32, 48, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 72, 80, 96, 128, 256, 512, 1024},
			Ell:               sweepN1024TernaryEll(),
			NLeavesBase:       sweepN1024TernaryNLeavesBase(),
			ExhaustiveNLeaves: false,
			Shortness: []sweepIntGenISISShortness{
				{Radix: 111, Digits: 2},
				{Radix: 25, Digits: 3},
				{Radix: 17, Digits: 4},
				{Radix: 11, Digits: 4},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
				{Radix: 3, Digits: 9},
			},
			Compression: []int{0, 1, 2, 3, 4},
			Projection:  []string{PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth},
			PRFGroups:   []int{2, 5},
			Checkpoints: []int{1, 8},
			EtaSlack:    3,
			MaxEta:      320,
			Notes: []string{
				"N=1024 ternary grid fixes profile-C (B=1) and uses degree-3 live membership in the estimator.",
				"The grid is transcript-first: frontier_96 and frontier_128 are sorted by showing paper transcript bytes, with total bytes as the tie-breaker.",
				"Transcript-only nleaves generation keeps the 64..q-1 grid endpoints for override/refinement visibility, but generated candidates stay near the exact lower leaf bound for each (lvcs, ell).",
				"The low-theta neighborhood includes theta=2/rho=3/ell'=3 and theta=2/rho=3/ell'=4 because those are the current transcript sweet spots for uncompressed and one-row ternary compression variants.",
				"Aggressive shortness shapes include R111/L2 and R25/L3; R121/L2 is intentionally omitted because the live showing path rejects that shadow profile.",
				"Compression levels keep 0..4 because ternary M/s/e carrier logic is valid for B=1; measured promotion still needs benchmark-intgenisis-e2e.",
				"Axes preserve the same min/max ranges as the wide N=1024 pass while adding dense lvcs=51..64, ell=5..12, and high-leaf basin probes around the sub-39 kB candidates.",
			},
		}, nil
	case sweepEstimateN1024TernaryLowLeavesGrid, "n1024-lowleaves", "n1024-low-leaves", "n1024-b1-lowleaves", "ternary1024-lowleaves":
		return sweepIntGenISISGrid{
			Name:              sweepEstimateN1024TernaryLowLeavesGrid,
			Families:          sweepN1024TernaryLowLeavesFamilies(),
			NCols:             []int{16, 32, 64, 128, 256, 512},
			LVCSNCols:         []int{16, 24, 32, 40, 48, 56, 57, 64, 72, 80, 96, 112, 128, 160, 192, 224, 256, 384, 512},
			Ell:               sweepN1024TernaryLowLeavesEll(),
			NLeavesBase:       sweepN1024TernaryLowLeavesNLeavesBase(),
			ExhaustiveNLeaves: true,
			Shortness: []sweepIntGenISISShortness{
				{Radix: 111, Digits: 2},
				{Radix: 25, Digits: 3},
				{Radix: 17, Digits: 4},
				{Radix: 13, Digits: 4},
				{Radix: 11, Digits: 4},
				{Radix: 9, Digits: 5},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
				{Radix: 3, Digits: 9},
			},
			Compression: []int{0, 1, 2, 3, 4},
			Projection:  []string{PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth},
			PRFGroups:   []int{2, 3, 5, 8},
			Checkpoints: []int{1, 2, 4, 8},
			EtaSlack:    8,
			MaxEta:      640,
			Notes: []string{
				"N=1024 ternary low-leaf grid ranks by showing_bytes*log2(nleaves) through the dedicated command, so low explicit-domain sizes remain visible even when their transcript is larger.",
				"The default command caps nleaves at 262144; the grid also includes 327680 and 393216 bases for override runs with -max-nleaves raised.",
				"ExhaustiveNLeaves is enabled so explicit low bases, cap endpoints, and local multiples survive candidate generation instead of only sampling near the soundness minimum.",
				"Higher ell values are included to trade Merkle path count for lower nleaves, while theta/rho/ell' and shortness/compression axes probe several DQ and row-count regimes.",
				"High-theta and high-ell' strata are intentionally included to compensate for low nleaves; PRF group rounds start at 2 because live IntGenISIS rejects grouped PRF rounds below 2.",
			},
		}, nil
	case sweepEstimateRuntime96DeepGrid, "runtime-96-deep", "low-leaves-96-deep", "no-precompute-96-deep":
		return sweepIntGenISISGrid{
			Name:        sweepEstimateRuntime96DeepGrid,
			Families:    sweepRuntime96Families(true),
			NCols:       []int{16, 32, 64, 128},
			LVCSNCols:   []int{16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 70, 72, 76, 80, 88, 96, 104, 112, 120, 128, 144, 160},
			Ell:         []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 34, 36, 38, 40, 44, 48, 52, 56, 60, 64, 72, 80},
			NLeavesBase: []int{768, 896, 1024, 1280, 1536, 1792, 2048, 2304, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192, 10240, 12288, 14336, 16384, 20480, 24576, 32768, 49152, 65536, 98304, 131072, 180000, 196608, 262144},
			Shortness: []sweepIntGenISISShortness{
				{Radix: 11, Digits: 4},
				{Radix: 9, Digits: 5},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
			},
			Compression: []int{0},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth},
			PRFGroups:   []int{2},
			Checkpoints: []int{2, 4},
			EtaSlack:    6,
			MaxEta:      192,
			Notes: []string{
				"Runtime-96 deep grid broadens the no-precomputation profile-A search around low-leaf and low-transcript candidates.",
				"Candidate ranking should use objective=runtime96, score=showing_paper_transcript_bytes*log2(nleaves), with showing bytes capped below 35000 by the wrapper command.",
				"The deep grid adds sub-2048 leaf bases, denser LVCS/ell neighborhoods, wider theta/rho/ell' families, R9/L5 shortness, checkpoint samples 2 and 4, and a larger eta window.",
			},
		}, nil
	case sweepEstimateRuntime96Grid, "runtime-96", "low-leaves-96", "no-precompute-96":
		return sweepIntGenISISGrid{
			Name:        sweepEstimateRuntime96Grid,
			Families:    sweepRuntime96Families(false),
			NCols:       []int{16, 32, 64, 128},
			LVCSNCols:   []int{16, 24, 32, 36, 40, 48, 56, 64, 70, 80, 96, 112, 128},
			Ell:         []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 26, 28, 30, 32, 36, 40, 44, 48, 56, 64},
			NLeavesBase: []int{1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 180000, 196608, 262144},
			Shortness: []sweepIntGenISISShortness{
				{Radix: 11, Digits: 4},
				{Radix: 7, Digits: 5},
				{Radix: 5, Digits: 6},
			},
			Compression: []int{0},
			PRFModes:    []PIOP.PRFCompanionMode{PIOP.PRFCompanionModeDirectAuth},
			PRFGroups:   []int{2},
			Checkpoints: []int{2},
			EtaSlack:    4,
			MaxEta:      160,
			Notes: []string{
				"Runtime-96 grid searches profile-A-friendly low-leaf candidates for no-precomputation presentations.",
				"Candidate ranking should use objective=runtime96, score=showing_paper_transcript_bytes*log2(nleaves), with showing bytes capped below 35000 by the wrapper command.",
				"The grid keeps V2 projection by default through the command parser and disables M/s/e compression for the bounded-range path.",
			},
		}, nil
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
			Compression: []int{0},
			EtaSlack:    4,
			MaxEta:      160,
			Notes: []string{
				"Estimate-deep searches both profile-A N=256 and profile-B N=512 through the calling command.",
				"The default grid is pre-pruned to remove round-2-impossible theta/rho pairs, dominated high-rho/high-theta families, ncols>=256, lvcs_ncols>256, ell>32, nleaves bases above 262144, compressed M/s/e layouts, and non-projected layouts.",
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
		MdecsBytes:                    paper.mdecs,
		AuthBytes:                     paper.auth,
		TapesBytes:                    paper.tapes,
		SigShortnessBytes:             0,
		VTargetsBytes:                 paper.vtargets,
		BarSetsBytes:                  paper.barsets,
		TotalRows:                     geom.Rows,
		RowsBlock:                     paper.rowsBlock,
		AuditRows:                     paper.auditRows,
		OpeningCols:                   paper.openingCols,
		PRFRows:                       geom.PRFRows,
		CoefficientViewRows:           geom.CoefficientViewRows,
		UCoefficientViewRows:          geom.UCoefficientViewRows,
		UDigitOnly:                    geom.UDigitOnly,
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
		SmallFieldReplayRows:          paper.replayRows,
		MaskRows:                      geom.MaskRows,
		QSplitRows:                    geom.QSplitRows,
		QLimbRows:                     geom.QLimbRows,
		PDecsBitWidth:                 paper.qBits,
		VTargetsBitWidth:              paper.qBits,
		PaperShapeNRows:               paper.paperNRows,
		PaperShapeQueries:             paper.paperQueries,
		PaperShapeWitnessLayers:       paper.paperWitnessLayers,
		PaperShapeMaskRows:            paper.paperMaskRows,
		PaperShapeVHeadBytes:          paper.paperVHead,
		PaperShapeVBarBytes:           paper.paperVBar,
		PaperShapeOpeningOmitEntries:  paper.paperOmitEntries,
		PaperShapeCanonical:           paper.paperCanonical,
		TranscriptSecurityStatus:      sweepTranscriptSecurityStatus(tuning.TranscriptMode),
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
	par, agg := sweepRelationDegreesForBound(tuning, kind, profile.B)
	dq := sweepComputeDQFromDegrees(par, agg, ncols, ell)
	geom := sweepEstimateGeometry{
		DDECS:                 lvcs + ell - 1,
		ParallelAlgDegree:     par,
		AggregatedAlgDegree:   agg,
		DominantDegreeSource:  estimateDominantDegreeSource(tuning, kind, profile.B),
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
		digitOnlyU := mode == PIOP.IntGenISISReplayProjectionProjectUDigitsYViewV3 || mode == PIOP.IntGenISISReplayProjectionProjectUDigitsYSourceLinearV4 || mode == PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5
		wResidual := mode == PIOP.IntGenISISReplayProjectionProjectUDigitsYWResidualV5
		uRows := profile.SignaturePreimageLen * blocks
		if digitOnlyU {
			uRows = 0
		}
		shortRows := profile.SignaturePreimageLen * blocks * shortDigits
		mRows := profile.EllM * blocks
		sRows := profile.KS * blocks
		eRows := profile.NC * blocks
		mseRows := mRows + sRows + eRows
		packWidth := 1
		compressionDegree := 0
		if tuning.CompressedRows > 0 {
			packWidth = tuning.CompressedRows + 1
			compressionDegree = powInt(sweepMembershipDegreeForBound(profile.B), packWidth)
			mseRows = ceilDivMain(mRows, packWidth) + ceilDivMain(sRows, packWidth) + ceilDivMain(eRows, packWidth)
		}
		yViewRows := blocks
		if mode == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 || digitOnlyU {
			yViewRows = 0
		}
		uHatRows := profile.SignaturePreimageLen * blocks
		yHatRows := blocks
		if mode == PIOP.IntGenISISReplayProjectionProjectUYHatV1 || mode == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 || digitOnlyU {
			uHatRows = 0
			yHatRows = 0
		}
		issuerHatRows := (profile.EllMuSig + profile.EllX0 + profile.EllX1 + 1) * blocks
		if wResidual {
			issuerHatRows = (1 + profile.EllX1 + 1) * blocks
		}
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
		geom.ShortnessConstraints = shortRows
		if !digitOnlyU {
			geom.ShortnessConstraints += profile.SignaturePreimageLen * blocks
		}
		geom.HatRows = uHatRows + yHatRows + issuerHatRows
		geom.YHatRows = yHatRows
		geom.CoefficientViewRows = uRows + mseRows + yViewRows
		geom.UCoefficientViewRows = uRows
		geom.UDigitOnly = digitOnlyU
		geom.SemanticViewRows = mRows
		geom.CommitmentViewRows = sRows + eRows
		geom.YCoefficientViewRows = yViewRows
		geom.Range = mseRows
		geom.PRFKeyBridge = prfKeyBridge
		if mode == PIOP.IntGenISISReplayProjectionProjectUYHatV1 || mode == PIOP.IntGenISISReplayProjectionProjectUYHatYViewV2 || digitOnlyU {
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
	total              int
	q                  int
	r                  int
	pdecs              int
	mdecs              int
	auth               int
	tapes              int
	vtargets           int
	barsets            int
	rowsBlock          int
	auditRows          int
	openingCols        int
	replayRows         int
	qBits              int
	paperNRows         int
	paperQueries       int
	paperWitnessLayers int
	paperMaskRows      int
	paperVHead         int
	paperVBar          int
	paperOmitEntries   int
	paperCanonical     bool
}

func estimatePaperTranscript(profile credential.IntGenISISProfile, tuning intGenISISTuning, geom sweepEstimateGeometry) estimatePaperBuckets {
	if tuning.TranscriptMode == sweepTranscriptModeSmallField2025 && sweepSmallField2025Canonical(tuning) {
		return estimateSmallField2025Transcript(profile, tuning, geom)
	}
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
	eta := tuning.Eta
	if eta <= 0 {
		eta = 1
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
	rBytes := bitsToBytesMain(float64(eta) * float64(maxIntMain(geom.DDECS+1-ell, 0)) * qLog)
	qBytes := bitsToBytesMain(float64(rho*maxIntMain(geom.PaperConservativeDQ-(ellPrime+1), 0)*qTheta) * qLog)
	authBytes := bitsToBytesMain(float64(ell)*math.Log2(float64(maxIntMain(tuning.NLeaves, 2)))*32 + 12000)
	rowsBlock := ceilDivMain(geom.Rows, lvcs)
	auditRows := rowsBlock * ellPrime
	if theta > 1 {
		auditRows *= theta
	}
	openingCols := estimateRowOpeningCols(tuning, geom, auditRows)
	vtargetsCols := estimateVTargetsCols(tuning, geom, lvcs)
	replayRows := estimateEffectiveSmallFieldReplayRows(tuning, geom, rowsBlock)
	pdecsBytes := estimateRowOpeningPdecsBytes(tuning, geom, auditRows, qBits)
	pdecsBytes += estimateProtocolLookupBudgetBytes(tuning, geom, qBits)
	vtargetsBytes := estimatePackedMatrixBytes(auditRows, vtargetsCols, qBits)
	barsetsBytes := estimatePackedMatrixBytes(auditRows, ell, qBits)
	fixedBytes := 16 + 64 + 32
	total := fixedBytes + qBytes + rBytes + pdecsBytes + authBytes + vtargetsBytes + barsetsBytes
	return estimatePaperBuckets{total: total, q: qBytes, r: rBytes, pdecs: pdecsBytes, auth: authBytes, vtargets: vtargetsBytes, barsets: barsetsBytes, rowsBlock: rowsBlock, auditRows: auditRows, openingCols: openingCols, replayRows: replayRows, qBits: qBits}
}

func estimateSmallField2025Transcript(profile credential.IntGenISISProfile, tuning intGenISISTuning, geom sweepEstimateGeometry) estimatePaperBuckets {
	qLog := math.Log2(float64(profile.Q))
	qBits := estimateFieldElementBitWidth(profile.Q)
	ell := tuning.Ell
	if ell <= 0 {
		ell = 1
	}
	eta := tuning.Eta
	if eta <= 0 {
		eta = 1
	}
	theta := tuning.Theta
	if theta <= 1 {
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
	rowsBlock := ceilDivMain(geom.Rows, lvcs)
	maskRows := 0
	if theta > 1 {
		maskRows = (geom.PaperConservativeDQ/lvcs + 1) * theta
	} else {
		maskRows = geom.PaperConservativeDQ/lvcs + 1
	}
	paperNRows := rowsBlock*(ncols+theta) + maskRows
	paperQueries := (rowsBlock + 1) * theta
	if theta <= 1 {
		paperQueries = rowsBlock + 1
	}
	openingCols := paperNRows - paperQueries
	if openingCols < 0 {
		openingCols = 0
	}
	rBytes := bitsToBytesMain(float64(eta) * float64(maxIntMain(geom.DDECS+1-ell, 0)) * qLog)
	qBytes := bitsToBytesMain(float64(maxIntMain(geom.PaperConservativeDQ-2, 0)*theta) * qLog)
	vHeadBytes := bitsToBytesMain(float64((geom.Rows+lvcs)*theta) * qLog)
	if theta <= 1 {
		vHeadBytes = bitsToBytesMain(float64(geom.Rows+lvcs) * qLog)
	}
	vBarBytes := bitsToBytesMain(float64(paperQueries*ell) * qLog)
	pdecsBytes := bitsToBytesMain(float64(ell*openingCols) * qLog)
	mdecsBytes := bitsToBytesMain(float64(ell*eta) * qLog)
	authOnlyBytes := bitsToBytesMain(float64(ell) * math.Log2(float64(maxIntMain(tuning.NLeaves, 2))) * 32)
	tapesBytes := bitsToBytesMain(float64(ell * 128))
	fixedBytes := 16 + 64 + 32
	total := fixedBytes + qBytes + rBytes + pdecsBytes + mdecsBytes + authOnlyBytes + tapesBytes + vHeadBytes + vBarBytes
	canonical := sweepSmallField2025Canonical(tuning)
	return estimatePaperBuckets{
		total:              total,
		q:                  qBytes,
		r:                  rBytes,
		pdecs:              pdecsBytes,
		mdecs:              mdecsBytes,
		auth:               authOnlyBytes,
		tapes:              tapesBytes,
		vtargets:           vHeadBytes,
		barsets:            vBarBytes,
		rowsBlock:          rowsBlock,
		auditRows:          paperQueries,
		openingCols:        openingCols,
		replayRows:         rowsBlock * (ncols + theta),
		qBits:              qBits,
		paperNRows:         paperNRows,
		paperQueries:       paperQueries,
		paperWitnessLayers: rowsBlock,
		paperMaskRows:      maskRows,
		paperVHead:         vHeadBytes,
		paperVBar:          vBarBytes,
		paperOmitEntries:   paperQueries * ell,
		paperCanonical:     canonical,
	}
}

func sweepSmallField2025Canonical(tuning intGenISISTuning) bool {
	return tuning.Theta > 1 && tuning.Rho == 1 && tuning.EllPrime == 1
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
		openingCols := estimateRowOpeningCols(tuning, geom, auditRows)
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

func estimateRowOpeningCols(tuning intGenISISTuning, geom sweepEstimateGeometry, auditRows int) int {
	theta := tuning.Theta
	if theta <= 0 {
		theta = 1
	}
	rho := tuning.Rho
	if rho <= 0 {
		rho = 1
	}
	if theta > 1 {
		ncols := tuning.NCols
		if ncols <= 0 {
			ncols = 16
		}
		lvcs := tuning.LVCSNCols
		if lvcs < ncols {
			lvcs = ncols
		}
		rowsBlock := ceilDivMain(geom.Rows, lvcs)
		cols := estimateEffectiveSmallFieldReplayRows(tuning, geom, rowsBlock) + geom.MaskRows - auditRows
		if cols < 0 {
			return 0
		}
		return cols
	}
	return geom.Rows + rho
}

func estimateEffectiveSmallFieldReplayRows(tuning intGenISISTuning, geom sweepEstimateGeometry, rowsBlock int) int {
	_ = rowsBlock
	return geom.SmallFieldReplayRows
}

func estimateVTargetsCols(tuning intGenISISTuning, geom sweepEstimateGeometry, lvcs int) int {
	if lvcs <= 0 {
		lvcs = tuning.LVCSNCols
	}
	if lvcs <= 0 {
		lvcs = tuning.NCols
	}
	return lvcs
}

func estimateProtocolLookupBudgetBytes(tuning intGenISISTuning, geom sweepEstimateGeometry, qBits int) int {
	switch tuning.TranscriptMode {
	case sweepTranscriptModeShortnessLookup:
		return 512 + estimatePackedMatrixBytes(maxIntMain(geom.ShortnessRows, 1), 2, qBits)
	case sweepTranscriptModeMSELookupPack2:
		packedRows := ceilDivMain(maxIntMain(geom.TernaryRows, 1), 2)
		return 512 + estimatePackedMatrixBytes(packedRows, 2, qBits)
	default:
		return 0
	}
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

func estimateDominantDegreeSource(t intGenISISTuning, kind string, bound int64) string {
	if kind == "issuance" {
		return "bounded_range"
	}
	radix := t.SigShortnessRadix
	if radix <= 0 {
		radix = 11
	}
	membershipDegree := sweepMembershipDegreeForBound(bound)
	if t.TranscriptMode == sweepTranscriptModeShortnessLookup && t.SigShortnessRadix == 25 && t.SigShortnessDigits == 3 && 5 >= membershipDegree {
		return "shortness_lookup"
	}
	if t.CompressedRows > 0 {
		if t.TranscriptMode == sweepTranscriptModeMSELookupPack2 && t.CompressedRows == 1 {
			return "mse_lookup"
		}
		compressionDegree := powInt(membershipDegree, t.CompressedRows+1)
		if compressionDegree > radix && compressionDegree >= membershipDegree {
			return "compression"
		}
	}
	if radix >= membershipDegree {
		return "shortness"
	}
	return "bounded_range"
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

func normalizeSweepEstimateObjective(objective string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(objective)) {
	case "", sweepEstimateObjectiveFrontier, "transcript_frontier":
		return sweepEstimateObjectiveFrontier, nil
	case sweepEstimateObjectiveTranscript, "transcript-only", "transcript_only", "showing-bytes", "showing_bytes":
		return sweepEstimateObjectiveTranscript, nil
	case sweepEstimateObjectiveRuntime, "runtime-96", "low-leaves", "low_leaves", "no-precompute", "no_precompute":
		return sweepEstimateObjectiveRuntime, nil
	default:
		return "", fmt.Errorf("unknown estimate objective %q (supported: frontier, transcript, runtime96)", objective)
	}
}

func normalizeSweepTranscriptMode(mode string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "", sweepTranscriptModeBaseline:
		return sweepTranscriptModeBaseline, nil
	case sweepTranscriptModeColumnWidths, "column-widths", "column_widths":
		return sweepTranscriptModeColumnWidths, nil
	case sweepTranscriptModeSmallField2025, "smallfield-2025-1085-v1", "smallwood-2025-1085-smallfield", "paper-smallfield":
		return sweepTranscriptModeSmallField2025, nil
	case sweepTranscriptModeShortnessLookup, "shortness-lookup-r25-l3", "r25_l3_lookup":
		return sweepTranscriptModeShortnessLookup, nil
	case sweepTranscriptModeMSELookupPack2, "mse-lookup-pack2", "mse_pack2_lookup":
		return sweepTranscriptModeMSELookupPack2, nil
	default:
		return "", fmt.Errorf("unknown transcript mode %q (supported: baseline, column_widths_v1, smallfield_2025_1085_v1, shortness_lookup_r25_l3, mse_lookup_pack2)", mode)
	}
}

func parseSweepTranscriptModeCSV(s string) ([]string, error) {
	parts, err := parseStringCSV(s)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool)
	for _, part := range parts {
		mode, err := normalizeSweepTranscriptMode(part)
		if err != nil {
			return nil, err
		}
		if !seen[mode] {
			out = append(out, mode)
			seen[mode] = true
		}
	}
	if len(out) == 0 {
		out = append(out, sweepTranscriptModeBaseline)
	}
	return out, nil
}

func sweepTranscriptSecurityStatus(mode string) string {
	switch mode {
	case sweepTranscriptModeBaseline, sweepTranscriptModeColumnWidths:
		return "smallwood_theorem"
	case sweepTranscriptModeSmallField2025:
		return "smallwood_2025_1085_formula_estimate"
	default:
		return "protocol_change_estimate"
	}
}

func sweepTranscriptModeApplies(mode string, tuning intGenISISTuning) bool {
	switch mode {
	case sweepTranscriptModeSmallField2025:
		return sweepSmallField2025Canonical(tuning)
	case sweepTranscriptModeShortnessLookup:
		return tuning.SigShortnessRadix == 25 && tuning.SigShortnessDigits == 3
	case sweepTranscriptModeMSELookupPack2:
		return tuning.CompressedRows == 1
	default:
		return true
	}
}

func sweepEstimateObjectiveScore(objective string, cand sweepIntGenISISEstimateCandidate) float64 {
	switch objective {
	case sweepEstimateObjectiveRuntime:
		return cand.RuntimeScore
	default:
		return float64(cand.ShowingTranscriptBytes)
	}
}

func sweepRuntimeScoreMetric(objective string) string {
	if objective != sweepEstimateObjectiveRuntime {
		return ""
	}
	return "showing_paper_transcript_bytes*log2(nleaves)"
}

func sweepRuntimeScore(showingTranscriptBytes, nLeaves int) (score, log2Leaves float64) {
	if showingTranscriptBytes <= 0 || nLeaves <= 1 {
		return math.Inf(1), 0
	}
	log2Leaves = math.Log2(float64(nLeaves))
	return float64(showingTranscriptBytes) * log2Leaves, log2Leaves
}

func pruneEstimateCandidates(candidates []sweepIntGenISISEstimateCandidate, limit int, objective string) []sweepIntGenISISEstimateCandidate {
	switch objective {
	case sweepEstimateObjectiveRuntime:
		if limit <= 0 || len(candidates) <= limit*4 {
			return candidates
		}
		sortRuntimeEstimateCandidates(candidates, 0)
		return candidates[:limit*4]
	case sweepEstimateObjectiveTranscript:
		return pruneTranscriptEstimateCandidates(candidates, limit)
	default:
		return pruneEstimateFrontier(candidates, limit)
	}
}

func pruneEstimateFrontier(candidates []sweepIntGenISISEstimateCandidate, limit int) []sweepIntGenISISEstimateCandidate {
	if limit <= 0 || len(candidates) <= limit*2 {
		return candidates
	}
	return efficientEstimateFrontier(candidates, limit)
}

func selectEstimateCandidates(candidates []sweepIntGenISISEstimateCandidate, limit int, objective string) []sweepIntGenISISEstimateCandidate {
	switch objective {
	case sweepEstimateObjectiveRuntime:
		sorted := append([]sweepIntGenISISEstimateCandidate(nil), candidates...)
		sortRuntimeEstimateCandidates(sorted, 0)
		return limitEstimateCandidates(sorted, limit)
	case sweepEstimateObjectiveTranscript:
		sorted := append([]sweepIntGenISISEstimateCandidate(nil), candidates...)
		sortTranscriptEstimateCandidates(sorted)
		return limitEstimateCandidates(sorted, limit)
	default:
		return efficientEstimateFrontier(candidates, limit)
	}
}

func pruneTranscriptEstimateCandidates(candidates []sweepIntGenISISEstimateCandidate, limit int) []sweepIntGenISISEstimateCandidate {
	if limit <= 0 || len(candidates) <= limit*6 {
		return candidates
	}
	kept := make(map[string]sweepIntGenISISEstimateCandidate, limit*6)
	addTop := func(src []sweepIntGenISISEstimateCandidate, n int) {
		if len(src) == 0 || n <= 0 {
			return
		}
		sorted := append([]sweepIntGenISISEstimateCandidate(nil), src...)
		sortTranscriptEstimateCandidates(sorted)
		if len(sorted) > n {
			sorted = sorted[:n]
		}
		for _, cand := range sorted {
			kept[cand.ID] = cand
		}
	}
	addTop(candidates, limit*3)
	candidates128 := make([]sweepIntGenISISEstimateCandidate, 0, limit*2)
	for _, cand := range candidates {
		if cand.CandidateTheoremBits+1e-9 >= 128 {
			candidates128 = append(candidates128, cand)
		}
	}
	addTop(candidates128, limit*2)
	out := make([]sweepIntGenISISEstimateCandidate, 0, len(kept))
	for _, cand := range kept {
		out = append(out, cand)
	}
	sortTranscriptEstimateCandidates(out)
	return limitEstimateCandidates(out, limit*6)
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

func sortEstimateCandidatesForObjective(candidates []sweepIntGenISISEstimateCandidate, target float64, objective string) {
	if objective == sweepEstimateObjectiveRuntime {
		sortRuntimeEstimateCandidates(candidates, target)
		return
	}
	if objective == sweepEstimateObjectiveTranscript {
		sortTranscriptEstimateCandidates(candidates)
		return
	}
	sortEstimateCandidates(candidates, target)
}

func sortTranscriptEstimateCandidates(candidates []sweepIntGenISISEstimateCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.ShowingTranscriptBytes != b.ShowingTranscriptBytes {
			return a.ShowingTranscriptBytes < b.ShowingTranscriptBytes
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

func sortRuntimeEstimateCandidates(candidates []sweepIntGenISISEstimateCandidate, target float64) {
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if math.Abs(a.RuntimeScore-b.RuntimeScore) > 1e-9 {
			return a.RuntimeScore < b.RuntimeScore
		}
		if a.Showing.NLeaves != b.Showing.NLeaves {
			return a.Showing.NLeaves < b.Showing.NLeaves
		}
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

func writeEstimateProgressCheckpoint(outDir string, accepted []sweepIntGenISISEstimateCandidate, rejected sweepIntGenISISEstimateRejectedCounts, done, total int, started time.Time, current string, topK int, objective string) error {
	now := time.Now()
	elapsed := now.Sub(started).Seconds()
	if elapsed <= 0 {
		elapsed = 1e-9
	}
	targetPool := append([]sweepIntGenISISEstimateCandidate(nil), accepted...)
	sorted := selectEstimateCandidates(accepted, topK, objective)
	sortEstimateCandidatesForObjective(sorted, 0, objective)
	frontierAll := limitEstimateCandidates(sorted, topK)
	frontier96 := estimateTargetFrontier(targetPool, 96, topK, objective)
	frontier128 := estimateTargetFrontier(targetPool, 128, topK, objective)
	var frontierRuntime96 []sweepIntGenISISEstimateCandidate
	if objective == sweepEstimateObjectiveRuntime {
		frontierRuntime96 = estimateRuntimeTargetFrontier(sorted, sweepRuntime96TargetBits, topK)
	}
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
	if objective == sweepEstimateObjectiveRuntime {
		if err := writeJSONFile(filepath.Join(outDir, "frontier_runtime96.json"), frontierRuntime96, 0o644); err != nil {
			return fmt.Errorf("write frontier_runtime96.json: %w", err)
		}
		if err := writeEstimateCSV(filepath.Join(outDir, "frontier_runtime96.csv"), frontierRuntime96); err != nil {
			return err
		}
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

func estimateTargetFrontier(candidates []sweepIntGenISISEstimateCandidate, target float64, limit int, objective string) []sweepIntGenISISEstimateCandidate {
	filtered := make([]sweepIntGenISISEstimateCandidate, 0, len(candidates))
	lo, hi := target-8, target+8
	if target >= 128 {
		lo, hi = target, target+8
	}
	for _, c := range candidates {
		if c.CandidateTheoremBits >= lo && c.CandidateTheoremBits <= hi {
			filtered = append(filtered, c)
		}
	}
	sortEstimateCandidatesForObjective(filtered, target, objective)
	return limitEstimateCandidates(filtered, limit)
}

func estimateRuntimeTargetFrontier(candidates []sweepIntGenISISEstimateCandidate, target float64, limit int) []sweepIntGenISISEstimateCandidate {
	filtered := make([]sweepIntGenISISEstimateCandidate, 0, len(candidates))
	for _, c := range candidates {
		if c.CandidateTheoremBits+1e-9 >= target {
			filtered = append(filtered, c)
		}
	}
	sortRuntimeEstimateCandidates(filtered, target)
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
		"runtime_score", "runtime_log2_nleaves", "transcript_mode", "security_status",
		"ncols", "lvcs_ncols", "nleaves", "eta", "theta", "rho", "ell", "ell_prime",
		"issuance_ncols", "prf_mode", "prf_group_rounds", "prf_checkpoint_samples",
		"kappa", "projection", "compression", "shortness_radix", "shortness_digits",
		"issuance_theorem", "showing_theorem", "issuance_eq8", "showing_eq8",
		"showing_rows", "showing_rows_block", "showing_audit_rows", "showing_opening_cols", "showing_prf_rows", "showing_replay_rows", "showing_mask_rows", "showing_dq", "showing_ddecs",
		"q_bytes", "r_bytes", "pdecs_bytes", "mdecs_bytes", "auth_bytes", "tapes_bytes", "vtargets_bytes", "barsets_bytes", "pdecs_bit_width", "vtargets_bit_width",
		"paper_shape_nrows", "paper_shape_queries", "paper_shape_witness_layers", "paper_shape_mask_rows", "paper_shape_vhead_bytes", "paper_shape_vbar_bytes", "paper_shape_opening_omit_entries", "paper_shape_canonical",
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
			fmt.Sprintf("%.4f", c.RuntimeScore),
			fmt.Sprintf("%.4f", c.RuntimeLog2NLeaves),
			c.TranscriptMode,
			c.SecurityStatus,
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
			strconv.Itoa(c.ShowingMetrics.RowsBlock),
			strconv.Itoa(c.ShowingMetrics.AuditRows),
			strconv.Itoa(c.ShowingMetrics.OpeningCols),
			strconv.Itoa(c.ShowingMetrics.PRFRows),
			strconv.Itoa(c.ShowingMetrics.SmallFieldReplayRows),
			strconv.Itoa(c.ShowingMetrics.MaskRows),
			strconv.Itoa(c.ShowingMetrics.DQ),
			strconv.Itoa(c.ShowingMetrics.DDECS),
			strconv.Itoa(c.ShowingMetrics.QBytes),
			strconv.Itoa(c.ShowingMetrics.RBytes),
			strconv.Itoa(c.ShowingMetrics.PdecsBytes),
			strconv.Itoa(c.ShowingMetrics.MdecsBytes),
			strconv.Itoa(c.ShowingMetrics.AuthBytes),
			strconv.Itoa(c.ShowingMetrics.TapesBytes),
			strconv.Itoa(c.ShowingMetrics.VTargetsBytes),
			strconv.Itoa(c.ShowingMetrics.BarSetsBytes),
			strconv.Itoa(c.ShowingMetrics.PDecsBitWidth),
			strconv.Itoa(c.ShowingMetrics.VTargetsBitWidth),
			strconv.Itoa(c.ShowingMetrics.PaperShapeNRows),
			strconv.Itoa(c.ShowingMetrics.PaperShapeQueries),
			strconv.Itoa(c.ShowingMetrics.PaperShapeWitnessLayers),
			strconv.Itoa(c.ShowingMetrics.PaperShapeMaskRows),
			strconv.Itoa(c.ShowingMetrics.PaperShapeVHeadBytes),
			strconv.Itoa(c.ShowingMetrics.PaperShapeVBarBytes),
			strconv.Itoa(c.ShowingMetrics.PaperShapeOpeningOmitEntries),
			strconv.FormatBool(c.ShowingMetrics.PaperShapeCanonical),
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

func generatedSweepEstimateKappas(maxPerRound int) [][4]int {
	if maxPerRound <= 0 {
		return defaultSweepEstimateKappas()
	}
	out := make([][4]int, 0, (maxPerRound+1)*(maxPerRound+1))
	for k1 := 0; k1 <= maxPerRound; k1++ {
		for k4 := 0; k4 <= maxPerRound; k4++ {
			out = append(out, [4]int{k1, 0, 0, k4})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ki, kj := out[i], out[j]
		si, sj := kappaSum(ki), kappaSum(kj)
		if si != sj {
			return si < sj
		}
		mi, mj := kappaMax(ki), kappaMax(kj)
		if mi != mj {
			return mi < mj
		}
		if ki[0] != kj[0] {
			return ki[0] < kj[0]
		}
		return ki[3] < kj[3]
	})
	return out
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

func sweepEstimateKappaSelectionLabel(cfg sweepIntGenISISEstimateConfig) string {
	if cfg.MaxKappaPerRound <= 0 {
		return "zero_grinding_only_v1"
	}
	return "bounded_grinding_k1_k4_v1"
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
